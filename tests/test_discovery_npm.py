"""Tests for npm dependency discovery."""

from __future__ import annotations

import json

from licenseal.discovery.npm.package_json import (
    detect_project_license_package_json,
    discover_npm_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem


class TestNpmDiscovery:
    def test_basic_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "myproject",
                    "dependencies": {
                        "react": "^18.2.0",
                        "lodash": "^4.17.21",
                    },
                    "devDependencies": {
                        "jest": "^29.0.0",
                    },
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        assert len(deps) == 3

        prod = [d for d in deps if d.group == DependencyGroup.PROD]
        dev = [d for d in deps if d.group == DependencyGroup.DEV]
        assert len(prod) == 2
        assert len(dev) == 1

        react = next(d for d in deps if d.name == "react")
        assert react.version_constraint == "^18.2.0"
        assert react.ecosystem == Ecosystem.NPM

    def test_peer_dependencies(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "mylib",
                    "peerDependencies": {
                        "react": ">=16.8.0",
                    },
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD

    def test_optional_dependencies(self, tmp_path):
        # `optionalDependencies` are installed by default — they end up in
        # node_modules and the project is using them under their license.
        # Without this branch licenseal silently dropped platform-specific
        # native bindings (better-sqlite3, sharp, fsevents) and their entire
        # transitive trees from npm scans.
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "mylib",
                    "dependencies": {"commander": "^14.0.0"},
                    "optionalDependencies": {
                        "better-sqlite3": "^11.0.0",
                        "fsevents": "~2.3.0",
                    },
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name: d for d in deps}
        assert set(names) == {"commander", "better-sqlite3", "fsevents"}
        assert names["better-sqlite3"].group == DependencyGroup.PROD
        assert names["fsevents"].group == DependencyGroup.PROD
        assert names["better-sqlite3"].version_constraint == "^11.0.0"

    def test_optional_dependencies_skip_workspace_local(self, tmp_path):
        # Same workspace-local guard applied to dependencies/peerDependencies
        # has to apply here too — pnpm/yarn `workspace:` and `file:` specs are
        # not published artifacts.
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "mylib",
                    "optionalDependencies": {
                        "real-pkg": "^1.0.0",
                        "workspace-pkg": "workspace:*",
                        "linked-pkg": "file:./local",
                    },
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        assert [d.name for d in deps] == ["real-pkg"]

    def test_nested_package_json(self, tmp_path):
        # Nested, non-root package.json (a framework-integration sub-package)
        theme_dir = tmp_path / "theme" / "static_src"
        theme_dir.mkdir(parents=True)
        (theme_dir / "package.json").write_text(
            json.dumps(
                {
                    "name": "theme",
                    "dependencies": {"tailwindcss": "^3.0"},
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "tailwindcss"

    def test_skips_node_modules(self, tmp_path):
        # Root package.json
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "root", "dependencies": {"express": "^4.0"}})
        )
        # node_modules package.json (should be skipped)
        nm_dir = tmp_path / "node_modules" / "express"
        nm_dir.mkdir(parents=True)
        (nm_dir / "package.json").write_text(
            json.dumps(
                {
                    "name": "express",
                    "dependencies": {"body-parser": "^1.0"},
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "express"

    def test_no_package_json(self, tmp_path):
        deps, _ = discover_npm_dependencies(tmp_path)
        assert deps == []

    def test_multiple_package_jsons(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.0"}}))
        sub = tmp_path / "frontend"
        sub.mkdir()
        (sub / "package.json").write_text(json.dumps({"dependencies": {"react": "^18.0"}}))
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "express" in names
        assert "react" in names

    def test_skips_name_based_dirs(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0"}}))
        skip_dirs = [
            ".git",
            "__pycache__",
            "node_modules",
            "vendor",
            ".next",
            ".nuxt",
            ".svelte-kit",
            ".yarn",
            "bower_components",
            "jspm_packages",
            "__pypackages__",
            ".pdm-build",
        ]
        for skip_dir in skip_dirs:
            d = tmp_path / skip_dir
            d.mkdir()
            (d / "package.json").write_text(json.dumps({"dependencies": {"hidden": "1.0"}}))
        deps, _ = discover_npm_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "a"

    def test_skips_dirs_with_pyvenv_cfg_marker(self, tmp_path):
        # Marker-based virtualenv skip catches any name, conventional or not.
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0"}}))
        for venv_name in [".venv", "venv", "env", "env-3.11", ".venv-dev"]:
            d = tmp_path / venv_name
            d.mkdir()
            (d / "pyvenv.cfg").write_text("home = /usr/bin\n")
            (d / "package.json").write_text(json.dumps({"dependencies": {"hidden": "1.0"}}))
        deps, _ = discover_npm_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "a"


class TestWorkspaceFiltering:
    def _write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    def test_unpacks_npm_alias_at_discovery(self, tmp_path):
        # ``"slash3": "npm:slash@^3.0.0"`` records the dep under the local
        # alias ``slash3``. The alias has no npm registry entry; only ``slash``
        # does. Discovery must unpack the alias just like the transitive walker
        # does, or every direct alias surfaces as UNKNOWN with empty version.
        self._write(
            tmp_path / "package.json",
            {
                "name": "host",
                "dependencies": {
                    "slash3": "npm:slash@^3.0.0",
                    "slash5": "npm:slash@^5.1.0",
                    "scoped-alias": "npm:@scope/pkg@^1.0",
                    "lodash": "^4.17.21",
                },
            },
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        by_pair = {(d.name, d.version_constraint) for d in deps}
        # Both aliases collapse to the canonical target name with their
        # underlying spec — two entries with the same name at different
        # ranges (correct: those are two different versions to license-check).
        assert ("slash", "^3.0.0") in by_pair
        assert ("slash", "^5.1.0") in by_pair
        assert ("@scope/pkg", "^1.0") in by_pair
        assert ("lodash", "^4.17.21") in by_pair
        # Alias names never leak through.
        names = {d.name for d in deps}
        assert "slash3" not in names
        assert "slash5" not in names

    def test_skips_workspace_local_specs(self, tmp_path):
        """``file:``, ``link:``, ``workspace:`` specs are workspace-local —
        there's no registry artifact to license-check. The local-name filter
        catches them when the workspace-local package.json is reachable, but
        when it lives under a fixtures/ or examples/ tree (which the walker
        skips), the consuming package.json's reference is the only thing
        left. Skipping at emit prevents a noisy UNKNOWN row per fixture.
        Real external deps (incl. ``git+`` URLs) are unaffected."""
        self._write(
            tmp_path / "__tests__" / "package.json",
            {
                "name": "test-host",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "@org/fixture-dep": "file:./fixtures/dep",
                    "@org/sibling": "link:../sibling",
                    "@org/ws-sib": "workspace:*",
                    "react-fork": "git+https://github.com/foo/react.git",
                },
            },
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"lodash", "react-fork"}

    def test_workspace_internal_refs_filtered(self, tmp_path):
        """Cross-package workspace deps shouldn't appear as external — they
        aren't published to npm. Real external deps still pass through."""
        self._write(
            tmp_path / "package.json",
            {"name": "@example/root", "private": True, "workspaces": ["packages/*"]},
        )
        self._write(
            tmp_path / "packages" / "pkg-a" / "package.json",
            {
                "name": "@example/pkg-a",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "@example/pkg-b": "workspace:*",
                },
            },
        )
        self._write(
            tmp_path / "packages" / "pkg-b" / "package.json",
            {
                "name": "@example/pkg-b",
                "dependencies": {"chalk": "^5.3.0", "@example/pkg-a": "workspace:*"},
            },
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "lodash" in names
        assert "chalk" in names
        # Workspace cross-refs filtered out
        assert "@example/pkg-a" not in names
        assert "@example/pkg-b" not in names

    def test_self_named_dep_is_preserved(self, tmp_path):
        """A package.json that declares its own ``name`` as a dep is the
        published-registry package, not a workspace alias. Standalone
        scratch / script projects sometimes share their directory name with
        a CLI tool dep — e.g. a ``script/danger/`` folder with
        ``"name": "danger"`` listing ``"danger": "13.0.7"`` as a devDep. The
        old workspace-local-name filter dropped the dep (plus its whole
        transitive subtree) as if it were a self-reference."""
        self._write(
            tmp_path / "script" / "tool" / "package.json",
            {
                "name": "tool",
                "private": True,
                "devDependencies": {
                    "tool": "13.0.7",
                    "tool-plugin": "0.7.1",
                },
            },
        )
        deps, filtered = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"tool", "tool-plugin"}
        assert filtered == 0

    def test_self_name_only_exempts_owning_file(self, tmp_path):
        """The self-name carve-out is scoped to the owning package.json. A
        sibling package.json depending on the same name still hits the
        workspace-local filter — workspaces resolve such bare-name deps
        locally first."""
        self._write(
            tmp_path / "packages" / "tool" / "package.json",
            {"name": "tool", "version": "1.0.0"},
        )
        self._write(
            tmp_path / "packages" / "consumer" / "package.json",
            {"name": "consumer", "dependencies": {"tool": "^1.0.0"}},
        )
        deps, filtered = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "tool" not in names
        assert filtered == 1

    def test_empty_when_no_workspace(self, tmp_path):
        """No package.json files anywhere → no deps, nothing filtered."""
        assert discover_npm_dependencies(tmp_path) == ([], 0)

    def test_examples_dir_is_skipped(self, tmp_path):
        # Many projects ship demo apps under `examples/` with their own
        # package.json. Their deps belong to the example, not to the
        # project being audited — skip them.
        self._write(
            tmp_path / "package.json",
            {"name": "real", "dependencies": {"react": "^18.0.0"}},
        )
        self._write(
            tmp_path / "examples" / "demo" / "package.json",
            {"name": "example-demo", "dependencies": {"should-not-appear": "^1.0.0"}},
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"react"}

    def test_test_fixture_package_jsons_are_skipped(self, tmp_path):
        """`tests/fixtures/*/package.json` and `__fixtures__/*/package.json`
        hold fake-project scaffolding for the project's own test suite, not
        real source. Without this guard, fixture projects can inflate the
        dep tree with phantom react/react-dom-style deps."""
        self._write(
            tmp_path / "package.json",
            {"name": "real-root", "dependencies": {"lodash": "^4.17.21"}},
        )
        # `tests/fixtures/*` and `__fixtures__/*` — by convention not real
        # project source, should be ignored even though they contain
        # well-formed package.json files.
        self._write(
            tmp_path / "tests" / "fixtures" / "fake-app" / "package.json",
            {"name": "fake-app", "dependencies": {"react": "^18.0.0"}},
        )
        self._write(
            tmp_path / "packages" / "tool" / "__fixtures__" / "demo" / "package.json",
            {"name": "demo", "dependencies": {"webpack": "^5.0.0"}},
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"lodash"}


class TestProjectLicensePackageJson:
    def test_string_license(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "mylib", "license": "MIT"}))
        assert detect_project_license_package_json(tmp_path) == "MIT"

    def test_dict_license(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "mylib", "license": {"type": "Apache-2.0"}})
        )
        assert detect_project_license_package_json(tmp_path) == "Apache-2.0"

    def test_no_license(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "mylib"}))
        assert detect_project_license_package_json(tmp_path) == ""

    def test_no_package_json(self, tmp_path):
        assert detect_project_license_package_json(tmp_path) == ""

    def test_non_string_non_dict_license(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "mylib", "license": 42}))
        assert detect_project_license_package_json(tmp_path) == ""

    def test_nested_package_json_license_when_no_root(self, tmp_path):
        # Monorepo with no root package.json — license declared in a nested
        # workspace package must still be picked up (mirrors pyproject/cargo
        # walk-the-tree behavior).
        nested = tmp_path / "packages" / "core"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "core", "license": "ISC"}))
        assert detect_project_license_package_json(tmp_path) == "ISC"

    def test_root_license_wins_over_nested(self, tmp_path):
        # Walk order is root-first, so a root license takes precedence over
        # nested ones (same convention as pyproject discovery).
        (tmp_path / "package.json").write_text(json.dumps({"name": "root", "license": "MIT"}))
        nested = tmp_path / "packages" / "core"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "core", "license": "Apache-2.0"}))
        assert detect_project_license_package_json(tmp_path) == "MIT"

    def test_dict_license_missing_type_falls_through_to_next(self, tmp_path):
        # Walker keeps going when a package.json has license={} (or a dict
        # without a usable `type`) — next manifest in walk order wins.
        (tmp_path / "package.json").write_text(json.dumps({"name": "root", "license": {}}))
        nested = tmp_path / "packages" / "core"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"name": "core", "license": "ISC"}))
        assert detect_project_license_package_json(tmp_path) == "ISC"


class TestWorkspaceLocalDevAndPeerDepsSkipped:
    def test_workspace_local_devdep_skipped(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "host",
                    "devDependencies": {
                        "shared-tooling": "workspace:*",
                        "real-tool": "^1.0",
                    },
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "shared-tooling" not in names
        assert "real-tool" in names

    def test_workspace_local_peerdep_skipped(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "host",
                    "peerDependencies": {
                        "internal-peer": "workspace:^1",
                        "external-peer": "^2.0",
                    },
                }
            )
        )
        deps, _ = discover_npm_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "internal-peer" not in names
        assert "external-peer" in names


class TestMalformedPackageJson:
    def test_malformed_package_json_discovery(self, tmp_path):
        """Malformed package.json should not crash discovery."""
        (tmp_path / "package.json").write_text("not valid json {{{")

        deps, _ = discover_npm_dependencies(tmp_path)
        assert deps == []

        license_str = detect_project_license_package_json(tmp_path)
        assert license_str == ""
