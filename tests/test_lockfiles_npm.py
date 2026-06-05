"""Tests for npm lockfile parsers (package-lock.json, pnpm-lock.yaml, yarn.lock)."""

from __future__ import annotations

import json
import textwrap

import pytest

from licenseal.discovery.npm.lockfiles import (
    _is_in_test_dir,
    _parse_bun_resolved_id,
    _yarn_alias_descriptor_name,
    _yarn_alias_target,
    _yarn_name_from_descriptor,
    find_npm_lockfiles,
    parse_bun_lock,
    parse_npm_lockfile,
    parse_package_lock_json,
    parse_pnpm_lock,
    parse_yarn_lock,
)
from licenseal.models import DependencyGroup, Ecosystem


class TestFindNpmLockfilesSkipTest:
    """Lockfiles inside ``test``/``tests`` directories are typically
    test-fixture sub-projects with their own pinned versions that differ
    from the real project's deps. Left in, their pins win the
    ``_drop_phantom_unresolved`` race against the root's unpinned spec and
    silently overwrite the root project's resolved versions with a
    fixture-only value."""

    def test_skips_lockfile_inside_test_dir(self, tmp_path):
        (tmp_path / "package-lock.json").write_text("{}")
        test_lock = tmp_path / "test" / "fixture-app" / "package-lock.json"
        test_lock.parent.mkdir(parents=True)
        test_lock.write_text("{}")
        from licenseal.discovery.npm.lockfiles import find_npm_lockfiles

        found = find_npm_lockfiles(tmp_path)
        # Only the root lockfile survives.
        assert len(found) == 1
        assert found[0].parent == tmp_path

    def test_skips_lockfile_inside_tests_dir(self, tmp_path):
        (tmp_path / "package-lock.json").write_text("{}")
        nested_lock = tmp_path / "tests" / "integration" / "yarn.lock"
        nested_lock.parent.mkdir(parents=True)
        nested_lock.write_text("")
        from licenseal.discovery.npm.lockfiles import find_npm_lockfiles

        found = find_npm_lockfiles(tmp_path)
        assert len(found) == 1
        assert found[0].name == "package-lock.json"

    def test_keeps_workspace_lockfile_not_in_test_dir(self, tmp_path):
        # Real workspace members in non-test paths must still be picked up.
        (tmp_path / "package-lock.json").write_text("{}")
        ws_lock = tmp_path / "packages" / "client" / "pnpm-lock.yaml"
        ws_lock.parent.mkdir(parents=True)
        ws_lock.write_text("lockfileVersion: '6.0'\n")
        from licenseal.discovery.npm.lockfiles import find_npm_lockfiles

        found = find_npm_lockfiles(tmp_path)
        assert len(found) == 2


class TestFindNpmLockfiles:
    """Tree-wide lockfile discovery — needed for monorepos that ship more
    than one lockfile (e.g. a root one plus per-app nested ones, or a
    vendored subproject next to a different stack)."""

    def test_returns_empty_when_no_lockfile(self, tmp_path):
        assert find_npm_lockfiles(tmp_path) == []

    def test_returns_root_only_when_no_nested(self, tmp_path):
        (tmp_path / "package-lock.json").write_text("{}")
        found = find_npm_lockfiles(tmp_path)
        assert [p.name for p in found] == ["package-lock.json"]

    def test_returns_root_plus_nested(self, tmp_path):
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "apps" / "cli").mkdir(parents=True)
        (tmp_path / "apps" / "cli" / "package-lock.json").write_text("{}")
        (tmp_path / "apps" / "web").mkdir(parents=True)
        (tmp_path / "apps" / "web" / "pnpm-lock.yaml").write_text("")
        found = {p.relative_to(tmp_path).as_posix() for p in find_npm_lockfiles(tmp_path)}
        assert found == {
            "package-lock.json",
            "apps/cli/package-lock.json",
            "apps/web/pnpm-lock.yaml",
        }

    def test_priority_within_single_dir(self, tmp_path):
        # Mixed-format dir (project mid-migration): only the highest-priority
        # lockfile is selected for that directory.
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "yarn.lock").write_text("")
        found = find_npm_lockfiles(tmp_path)
        assert [p.name for p in found] == ["package-lock.json"]

    def test_honors_exclude_paths(self, tmp_path):
        # ``--exclude-dirs`` is plumbed through to lockfile discovery so the
        # flag's effect is consistent across discovery + transitive resolution.
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "package-lock.json").write_text("{}")
        excluded = frozenset({(tmp_path / "vendor").resolve()})
        result = find_npm_lockfiles(tmp_path, exclude_paths=excluded)
        found = {p.relative_to(tmp_path).as_posix() for p in result}
        assert found == {"package-lock.json"}


class TestParsePackageLockJson:
    def _write(self, tmp_path, data):
        path = tmp_path / "package-lock.json"
        path.write_text(json.dumps(data))
        return path

    def test_parses_simple_lock(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "myapp", "version": "1.0.0"},
                    "node_modules/react": {
                        "version": "18.2.0",
                        "dependencies": {"scheduler": "^0.23.0"},
                    },
                    "node_modules/react/node_modules/scheduler": {"version": "0.23.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name: d for d in deps}
        assert names["react"].depth == 0
        assert names["react"].version_constraint == "==18.2.0"
        assert names["scheduler"].depth >= 1
        assert names["scheduler"].is_transitive

    def test_skips_dev_when_no_include_dev(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "myapp", "version": "1.0.0"},
                    "node_modules/react": {"version": "18.2.0"},
                    "node_modules/jest": {"version": "29.0.0", "dev": True},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert {d.name for d in deps} == {"react"}

    def test_includes_dev_when_flag_set(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react": {"version": "18.2.0"},
                    "node_modules/jest": {"version": "29.0.0", "dev": True},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"react"}, dev_root_names={"jest"}, include_dev=True
        )
        assert {d.name for d in deps} == {"react", "jest"}
        groups = {d.name: d.group for d in deps}
        assert groups["jest"] == DependencyGroup.DEV

    def test_skips_non_node_modules_workspace_entries(self, tmp_path):
        """Workspace lockfiles include metadata-only entries keyed by
        workspace-relative paths (``packages/foo``) or out-of-tree refs
        (``../sibling/pkg``). These are sibling-workspace records whose
        ``name`` field is the workspace's own package name, NOT a published
        registry dep — emitting them poisons resolution (the published-name
        twin gets cross-pinned to the workspace's old version). Only keys
        that traverse ``node_modules/`` represent installed deps."""
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "myapp", "version": "1.0.0"},
                    "packages/sibling": {"name": "sibling-pkg", "version": "0.1.0"},
                    "../external/extra": {
                        "name": "external-pkg",
                        "version": "1.673.0",
                        "extraneous": True,
                    },
                    "node_modules/external-pkg": {"version": "1.695.0"},
                    "node_modules/react": {"version": "18.2.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path,
            prod_root_names={"react", "external-pkg"},
            dev_root_names=set(),
            include_dev=False,
        )
        by_name: dict[str, list[str]] = {}
        for d in deps:
            by_name.setdefault(d.name, []).append(d.version_constraint)
        # Sibling workspace records are filtered.
        assert "sibling-pkg" not in by_name
        # The published external-pkg keeps its installed version — the
        # out-of-tree workspace ref's 1.673.0 must NOT leak as a second pin.
        assert by_name.get("external-pkg") == ["==1.695.0"]

    def test_handles_invalid_json(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text("not json at all {{{")
        assert (
            parse_package_lock_json(
                path, prod_root_names=set(), dev_root_names=set(), include_dev=False
            )
            == []
        )

    def test_handles_missing_packages_map(self, tmp_path):
        path = self._write(tmp_path, {"lockfileVersion": 3})
        assert (
            parse_package_lock_json(
                path, prod_root_names=set(), dev_root_names=set(), include_dev=False
            )
            == []
        )

    def test_handles_non_object_root(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text("[]")
        assert (
            parse_package_lock_json(
                path, prod_root_names=set(), dev_root_names=set(), include_dev=False
            )
            == []
        )

    def test_handles_packages_not_a_dict(self, tmp_path):
        path = self._write(tmp_path, {"packages": "oops"})
        assert (
            parse_package_lock_json(
                path, prod_root_names=set(), dev_root_names=set(), include_dev=False
            )
            == []
        )

    def test_dedupes_same_name_version(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react": {"version": "18.2.0"},
                    "node_modules/foo/node_modules/react": {"version": "18.2.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        names = [d.name for d in deps]
        assert names.count("react") == 1

    def test_skips_non_dict_package_entries(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "": "ignored",
                    "node_modules/bad": "not-a-dict",
                    "node_modules/valid": {"version": "1.0.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_skips_entries_missing_version(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/no-version": {"resolved": "https://example.com"},
                    "node_modules/valid": {"version": "1.0.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_skips_entry_with_empty_extracted_name(self, tmp_path):
        # A trailing-slash key would parse to an empty name segment.
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/": {"version": "1.0.0"},
                    "node_modules/valid": {"version": "1.0.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_dev_root_dropped_without_include_dev(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react": {"version": "18.2.0"},
                    "node_modules/jest": {"version": "29.0.0", "dev": True},
                },
            },
        )
        deps = parse_package_lock_json(
            path,
            prod_root_names={"react"},
            dev_root_names={"jest"},
            include_dev=False,
        )
        assert {d.name for d in deps} == {"react"}

    def test_dev_only_transitive_attributed_via_dev_path(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react": {"version": "18.2.0"},
                    "node_modules/jest": {
                        "version": "29.0.0",
                        "dependencies": {"chalk": "^5"},
                    },
                    "node_modules/chalk": {"version": "5.0.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path,
            prod_root_names={"react"},
            dev_root_names={"jest"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["chalk"].group == DependencyGroup.DEV
        assert by_name["chalk"].direct_ancestors == ("jest",)

    def test_prod_wins_when_reachable_from_both_groups(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react": {
                        "version": "18.2.0",
                        "dependencies": {"shared": "^1"},
                    },
                    "node_modules/jest": {
                        "version": "29.0.0",
                        "dependencies": {"shared": "^1"},
                    },
                    "node_modules/shared": {"version": "1.0.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path,
            prod_root_names={"react"},
            dev_root_names={"jest"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["shared"].group == DependencyGroup.PROD

    def test_root_not_present_in_lockfile_ignored(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react": {"version": "18.2.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path,
            prod_root_names={"react", "absent-prod"},
            dev_root_names={"absent-dev"},
            include_dev=True,
        )
        assert {d.name for d in deps} == {"react"}

    def test_populates_direct_ancestors_from_dep_fields(self, tmp_path):
        path = self._write(
            tmp_path,
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "myapp", "version": "1.0.0"},
                    "node_modules/express": {
                        "version": "4.18.0",
                        "dependencies": {"body-parser": "^1.20.0"},
                    },
                    "node_modules/body-parser": {
                        "version": "1.20.0",
                        "dependencies": {"depd": "2.0.0"},
                    },
                    "node_modules/depd": {"version": "2.0.0"},
                },
            },
        )
        deps = parse_package_lock_json(
            path, prod_root_names={"express"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["express"].direct_ancestors == ()
        assert by_name["body-parser"].direct_ancestors == ("express",)
        assert by_name["depd"].direct_ancestors == ("express",)

    def test_npm_alias_uses_canonical_name(self, tmp_path):
        # An ``node_modules/<alias>`` entry whose meta dict carries a
        # different ``name`` field is an npm package-alias resolution. We
        # must emit the dep under the canonical name from ``meta["name"]``;
        # looking up the alias name in the registry 404s and the dep
        # surfaces as UNKNOWN instead.
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "root"},
                        "node_modules/glob": {
                            "version": "10.0.0",
                            "dependencies": {"string-width-cjs": "npm:string-width@^4.2.0"},
                        },
                        "node_modules/string-width-cjs": {
                            "name": "string-width",
                            "version": "4.2.3",
                        },
                    },
                }
            )
        )
        deps = parse_package_lock_json(
            path,
            prod_root_names={"glob"},
            dev_root_names=set(),
            include_dev=False,
        )
        names = {d.name: d for d in deps}
        # Emitted under canonical name.
        assert "string-width" in names
        assert names["string-width"].version_constraint == "==4.2.3"
        # Alias name does NOT leak through as a phantom dep.
        assert "string-width-cjs" not in names
        # Reachability survived alias rewriting: glob → string-width.
        assert names["string-width"].direct_ancestors == ("glob",)

    def test_normal_name_field_does_not_rename(self, tmp_path):
        # When meta["name"] equals the key-derived name, behavior is unchanged
        # — this is the non-alias common case.
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/react": {
                            "name": "react",
                            "version": "18.2.0",
                        }
                    },
                }
            )
        )
        deps = parse_package_lock_json(
            path,
            prod_root_names={"react"},
            dev_root_names=set(),
            include_dev=False,
        )
        assert deps[0].name == "react"


class TestParsePnpmLock:
    def _write(self, tmp_path, content):
        path = tmp_path / "pnpm-lock.yaml"
        path.write_text(textwrap.dedent(content))
        return path

    def test_skips_non_registry_specs(self, tmp_path):
        # pnpm encodes the source spec after `@` for non-registry deps:
        # local tarballs (``file:``), workspace links (``link:`` /
        # ``workspace:``), git, HTTP. None of these are resolvable on npmjs.org.
        # The version-extracting regex truncates the spec at the first ``/``
        # (``file:../../tmp/x-0.0.0.tgz`` → ``file:..``) and would emit a
        # phantom-pinned Dependency whose ``==file:..`` constraint masks a
        # genuine unresolved entry of the same name from being dropped.
        path = self._write(
            tmp_path,
            """\
            lockfileVersion: '9.0'
            packages:
              '@scope/tarball-pkg@file:../../tmp/tarball-pkg-0.0.0.tgz':
                resolution: { tarball: file:../../tmp/tarball-pkg-0.0.0.tgz }
              'mypkg@link:../sibling':
                resolution: { directory: ../sibling, type: directory }
              'wkpkg@workspace:^1.0':
                resolution: { directory: packages/wkpkg, type: directory }
              'git-pkg@git+ssh://git@github.com/foo/bar.git#sha':
                resolution: { type: git }
              'real@1.0.0':
                resolution: { integrity: sha512-... }
            """,
        )
        deps = parse_pnpm_lock(
            path,
            prod_root_names={"real"},
            dev_root_names=set(),
            include_dev=False,
        )
        names = {d.name for d in deps}
        # Only the genuine registry entry survives.
        assert names == {"real"}
        # Phantom-pinned constraints (==file:.., ==link:.., …) must NOT leak.
        constraints = {d.version_constraint for d in deps}
        assert not any(
            c.startswith(("==file:", "==link:", "==workspace:", "==git", "==http"))
            for c in constraints
        )

    def test_parses_simple_lock(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            lockfileVersion: '6.0'
            packages:
              /react@18.2.0:
                version: 18.2.0
              /scheduler@0.23.0:
                version: 0.23.0
                dev: true
            """,
        )
        deps = parse_pnpm_lock(
            path,
            prod_root_names={"react"},
            dev_root_names={"scheduler"},
            include_dev=True,
        )
        names = {d.name for d in deps}
        assert names == {"react", "scheduler"}

    def test_skips_dev_when_flag_off(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            packages:
              /react@18.2.0:
                version: 18.2.0
              /jest@29.0.0:
                version: 29.0.0
                dev: true
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert {d.name for d in deps} == {"react"}

    def test_handles_scoped_packages(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            packages:
              /@types/node@20.10.0:
                version: 20.10.0
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"@types/node"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "@types/node"

    def test_handles_invalid_yaml(self, tmp_path):
        path = tmp_path / "pnpm-lock.yaml"
        path.write_text(":\n:\nbad: : : yaml")
        assert (
            parse_pnpm_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_missing_packages(self, tmp_path):
        path = self._write(tmp_path, "lockfileVersion: '6.0'\n")
        assert (
            parse_pnpm_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_unparseable_key(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            packages:
              not-a-valid-key:
                version: 1.0.0
            """,
        )
        assert (
            parse_pnpm_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_non_dict_root(self, tmp_path):
        path = tmp_path / "pnpm-lock.yaml"
        path.write_text("- item\n- item2\n")
        assert (
            parse_pnpm_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_packages_not_a_dict(self, tmp_path):
        path = self._write(tmp_path, "packages:\n  - foo\n  - bar\n")
        assert (
            parse_pnpm_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_dedupes_same_name_version(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            packages:
              /react@18.2.0:
                version: 18.2.0
              /react@18.2.0(scheduler@0.23.0):
                version: 18.2.0
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert len([d for d in deps if d.name == "react"]) == 1

    def test_skips_non_string_keys_and_non_dict_entries(self, tmp_path):
        path = tmp_path / "pnpm-lock.yaml"
        # Hand-craft YAML with a non-string key and non-dict entry.
        path.write_text("packages:\n  42: not-a-dict\n  /valid@1.0.0:\n    version: 1.0.0\n")
        deps = parse_pnpm_lock(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_skips_non_string_dependency_keys(self, tmp_path):
        # YAML can produce non-string keys (e.g., `42:`); they must be skipped.
        path = self._write(
            tmp_path,
            """\
            packages:
              /react@18.2.0:
                version: 18.2.0
                dependencies:
                  ? 42
                  : "1.0.0"
                  loose-envify: 1.4.0
              /loose-envify@1.4.0:
                version: 1.4.0
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["loose-envify"].direct_ancestors == ("react",)

    def test_populates_direct_ancestors(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            packages:
              /react@18.2.0:
                version: 18.2.0
                dependencies:
                  loose-envify: 1.4.0
              /loose-envify@1.4.0:
                version: 1.4.0
                dependencies:
                  js-tokens: 4.0.0
              /js-tokens@4.0.0:
                version: 4.0.0
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["react"].direct_ancestors == ()
        assert by_name["loose-envify"].direct_ancestors == ("react",)
        assert by_name["js-tokens"].direct_ancestors == ("react",)

    def test_parses_v9_snapshots_for_edges(self, tmp_path):
        # pnpm-lock v9: `packages:` holds only resolution metadata; the
        # dependency edges live in a separate `snapshots:` block. The parser
        # must read both, otherwise transitives have no reachability from
        # roots and `_finalize` drops them.
        path = self._write(
            tmp_path,
            """\
            lockfileVersion: '9.0'
            packages:
              root@1.0.0:
                resolution: {integrity: sha512-fake==}
              child@2.0.0:
                resolution: {integrity: sha512-fake==}
            snapshots:
              root@1.0.0:
                dependencies:
                  child: 2.0.0
              child@2.0.0: {}
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"root"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert set(by_name) == {"root", "child"}
        assert by_name["child"].group == DependencyGroup.PROD
        assert by_name["child"].direct_ancestors == ("root",)

    def test_parses_v9_peer_suffixed_snapshot_keys(self, tmp_path):
        # v9 snapshots can carry a `(peer@version)` suffix on the key to
        # disambiguate peer-resolved variants of the same package. The
        # existing `_PNPM_KEY_RE` already strips this suffix; edges across
        # all variants union via `setdefault(...).update(...)`.
        path = self._write(
            tmp_path,
            """\
            lockfileVersion: '9.0'
            packages:
              ajv-formats@2.1.1:
                resolution: {integrity: sha512-fake==}
              ajv@8.18.0:
                resolution: {integrity: sha512-fake==}
              ajv@7.0.0:
                resolution: {integrity: sha512-fake==}
            snapshots:
              ajv-formats@2.1.1(ajv@8.18.0):
                dependencies:
                  ajv: 8.18.0
              ajv-formats@2.1.1(ajv@7.0.0):
                dependencies:
                  ajv: 7.0.0
              ajv@8.18.0: {}
              ajv@7.0.0: {}
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"ajv-formats"}, dev_root_names=set(), include_dev=False
        )
        ajv_entries = [d for d in deps if d.name == "ajv"]
        assert {d.version_constraint for d in ajv_entries} == {"==8.18.0", "==7.0.0"}
        assert all(d.group == DependencyGroup.PROD for d in ajv_entries)

    def test_v9_transitive_peer_dependencies_create_edges(self, tmp_path):
        # `transitivePeerDependencies` in v9 snapshots is a list[str] of peer
        # names that propagate through the resolution closure. They ship with
        # the package so their licenses apply — the parser must extract them
        # as edges despite the field's shape differing from
        # dependencies/peerDependencies/optionalDependencies (which are dicts).
        path = self._write(
            tmp_path,
            """\
            lockfileVersion: '9.0'
            packages:
              pkg@1.0.0:
                resolution: {integrity: sha512-fake==}
              peer-x@2.0.0:
                resolution: {integrity: sha512-fake==}
            snapshots:
              pkg@1.0.0:
                transitivePeerDependencies:
                  - peer-x
              peer-x@2.0.0: {}
            """,
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"pkg"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert "peer-x" in by_name
        assert by_name["peer-x"].group == DependencyGroup.PROD

    def test_v9_snapshots_defensive_guards(self, tmp_path):
        # Malformed snapshot entries shouldn't crash the parser:
        #   * non-string keys (YAML allows integer keys)
        #   * non-dict values
        #   * unparseable snapshot keys (no ``@``)
        #   * `transitivePeerDependencies` entries that aren't strings
        # All four guarded paths must skip cleanly without affecting the
        # valid entries' edges.
        path = tmp_path / "pnpm-lock.yaml"
        path.write_text(
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            "  good@1.0.0:\n"
            "    resolution: {integrity: sha512-fake==}\n"
            "  child@2.0.0:\n"
            "    resolution: {integrity: sha512-fake==}\n"
            "snapshots:\n"
            "  42: not-a-dict\n"  # non-string key + non-dict value
            "  unparseable-key:\n"  # parseable type, but no @version
            "    dependencies:\n"
            "      something: 1.0.0\n"
            "  good@1.0.0:\n"
            "    dependencies:\n"
            "      child: 2.0.0\n"
            "    transitivePeerDependencies:\n"
            "      - real-peer\n"
            "      - 42\n"  # non-string tpd entry
            "  child@2.0.0: {}\n"
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"good"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        # `good` and `child` survive; nothing crashed on the bad entries.
        assert "good" in by_name
        assert by_name["child"].direct_ancestors == ("good",)


class TestParseYarnLock:
    def test_empty_or_comments_only_file_routes_to_v1(self, tmp_path):
        # File with only blank lines and comments has no content line to
        # signal Berry vs v1. The format dispatcher exits its scan loop
        # without breaking and falls through to the v1 parser (which then
        # finds no dep descriptors and returns an empty list).
        path = tmp_path / "yarn.lock"
        path.write_text("# yarn lockfile v1\n# This file is generated by yarn install.\n\n")
        deps = parse_yarn_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
        assert deps == []

    def test_parses_v1(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                # yarn lockfile v1

                react@^18.0, react@18.2.0:
                  version "18.2.0"
                  resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz"
                  dependencies:
                    scheduler "^0.23.0"

                scheduler@^0.23.0:
                  version "0.23.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name: d for d in deps}
        assert "react" in names
        assert names["react"].version_constraint == "==18.2.0"
        assert names["react"].depth == 0
        assert names["scheduler"].depth == 1

    def test_parses_v1_scoped_package(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                "@types/node@^20.0.0":
                  version "20.10.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"@types/node"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "@types/node"

    def test_parses_berry(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6
                  cacheKey: 8

                "react@npm:18.2.0, react@npm:^18.0":
                  version: 18.2.0
                  resolution: "react@npm:18.2.0"
                  dependencies:
                    scheduler: ^0.23.0

                "scheduler@npm:0.23.0":
                  version: 0.23.0
                  resolution: "scheduler@npm:0.23.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name for d in deps}
        assert names == {"react", "scheduler"}

    def test_parses_berry_npm_alias(self, tmp_path):
        # Berry alias form: `alias@npm:target@spec`. The dep must be emitted
        # under the canonical target name AND child references from other
        # packages must rewrite the alias to the canonical name so
        # reachability attribution works.
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "glob@npm:^10.0":
                  version: 10.0.0
                  dependencies:
                    string-width-cjs: "npm:string-width@^4.2.0"

                "string-width-cjs@npm:string-width@^4.2.0":
                  version: 4.2.3
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"glob"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name: d for d in deps}
        assert "string-width" in names
        assert "string-width-cjs" not in names
        assert names["string-width"].direct_ancestors == ("glob",)

    def test_parses_v1_npm_alias(self, tmp_path):
        # Yarn v1 alias entry: same alias→canonical handling needed in the
        # custom non-YAML format.
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                # yarn lockfile v1

                glob@^10.0.0:
                  version "10.0.0"
                  dependencies:
                    string-width-cjs "npm:string-width@^4.2.0"

                "string-width-cjs@npm:string-width@^4.2.0":
                  version "4.2.3"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"glob"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name: d for d in deps}
        assert "string-width" in names
        assert "string-width-cjs" not in names
        assert names["string-width"].direct_ancestors == ("glob",)

    def test_parses_berry_when_file_starts_with_comments(self, tmp_path):
        # Real Yarn 2/Berry lockfiles (and the canonical ``yarn install``
        # output) open with two comment lines before the ``__metadata`` key.
        # The format dispatcher must skip the comment block before checking
        # for the Berry marker, otherwise the file routes to the v1 parser
        # and produces zero deps.
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                # This file is generated by running "yarn install" inside your project.
                # Manual changes might be lost - proceed with caution!

                __metadata:
                  version: 8
                  cacheKey: 10

                "react@npm:18.2.0":
                  version: 18.2.0
                  resolution: "react@npm:18.2.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert {d.name for d in deps} == {"react"}

    def test_berry_handles_invalid_yaml(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text("__metadata:\n:\n:\n: : invalid")
        assert (
            parse_yarn_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_berry_handles_yaml_returning_a_list(self, tmp_path):
        path = tmp_path / "yarn.lock"
        # Starts with __metadata so dispatcher routes to berry parser, but
        # the YAML body is a list (after metadata key) — root won't be a dict.
        path.write_text("__metadata\n- 1\n- 2\n")
        assert (
            parse_yarn_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_berry_handles_non_dict_root(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text("__metadata: just-a-string\n")
        assert (
            parse_yarn_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_v1_dedupes_same_name_version(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                react@^18.0:
                  version "18.2.0"

                react@18.2.0:
                  version "18.2.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert len([d for d in deps if d.name == "react"]) == 1

    def test_v1_skips_malformed_version_line(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                broken@^1.0:
                  version garbage
                """
            )
        )
        assert (
            parse_yarn_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_berry_skips_metadata_and_non_dict_entries(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "non-dict-entry": just-a-string

                "valid@npm:1.0.0":
                  version: 1.0.0
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_berry_skips_entries_without_string_version(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "no-version@npm:1.0":
                  resolution: "no-version@npm:1.0.0"

                "valid@npm:1.0":
                  version: 1.0.0
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_berry_dedupes_same_name_version(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "react@npm:18.2.0":
                  version: 18.2.0

                "react@npm:^18.0":
                  version: 18.2.0
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert len([d for d in deps if d.name == "react"]) == 1

    def test_berry_dedupe_via_seen_set_yields_single_entry(self, tmp_path):
        # Two different descriptor keys both resolving to the same (name, version)
        # — the seen-set branch in the loop body skips the duplicate.
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "react@npm:18.2.0, react@npm:^18.0":
                  version: 18.2.0

                "react@npm:18.2.0":
                  version: 18.2.0
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert len([d for d in deps if d.name == "react"]) == 1

    def test_v1_ignores_indented_lines_before_first_header(self, tmp_path):
        # An indented line at the top of the file (before any header) has no
        # current_name; the parser should skip it cleanly.
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                  orphan-line "before any header"

                react@^18.0:
                  version "18.2.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert {d.name for d in deps} == {"react"}

    def test_v1_exits_deps_block_on_unmatched_line(self, tmp_path):
        # After a `dependencies:` block, the next 2-space-indented section
        # (e.g. another resolved/integrity line) doesn't match the dep regex;
        # the parser must exit the deps block cleanly.
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                react@^18.0:
                  version "18.2.0"
                  dependencies:
                    loose-envify "^1.1.0"
                  optionalDependencies:
                    object-assign "^4.0.0"

                loose-envify@^1.1.0:
                  version "1.4.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        # Only `loose-envify` (under `dependencies:`) is captured as an edge.
        # `object-assign` falls under optionalDependencies which we don't track
        # as graph edges in v1 (only `dependencies:` is parsed).
        assert by_name["loose-envify"].direct_ancestors == ("react",)

    def test_berry_handles_non_dict_dependencies_field(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "react@npm:18.2.0":
                  version: 18.2.0
                  dependencies: "oops"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert {d.name for d in deps} == {"react"}

    def test_berry_skips_non_string_dependency_keys(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "react@npm:18.2.0":
                  version: 18.2.0
                  dependencies:
                    ? 42
                    : "1.0.0"
                    "loose-envify": 1.4.0

                "loose-envify@npm:1.4.0":
                  version: 1.4.0
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["loose-envify"].direct_ancestors == ("react",)

    def test_v1_populates_direct_ancestors(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                react@^18.0:
                  version "18.2.0"
                  dependencies:
                    loose-envify "^1.1.0"

                loose-envify@^1.1.0:
                  version "1.4.0"
                  dependencies:
                    js-tokens "^3.0.0 || ^4.0.0"

                js-tokens@^3.0.0 || ^4.0.0:
                  version "4.0.0"
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["react"].direct_ancestors == ()
        assert by_name["loose-envify"].direct_ancestors == ("react",)
        assert by_name["js-tokens"].direct_ancestors == ("react",)

    def test_berry_populates_direct_ancestors(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                "react@npm:18.2.0":
                  version: 18.2.0
                  dependencies:
                    loose-envify: ^1.1.0

                "loose-envify@npm:1.4.0":
                  version: 1.4.0
                  dependencies:
                    js-tokens: ^4.0.0

                "js-tokens@npm:4.0.0":
                  version: 4.0.0
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["react"].direct_ancestors == ()
        assert by_name["loose-envify"].direct_ancestors == ("react",)
        assert by_name["js-tokens"].direct_ancestors == ("react",)

    def test_berry_skips_empty_descriptor_first_segment(self, tmp_path):
        # A leading comma in the descriptor list yields an empty first segment,
        # which `_yarn_name_from_descriptor("")` returns as empty → the entry
        # is skipped via `if not name: continue`.
        path = tmp_path / "yarn.lock"
        path.write_text(
            textwrap.dedent(
                """\
                __metadata:
                  version: 6

                ",valid@npm:1.0":
                  version: 1.0.0

                "real@npm:1.0":
                  version: 1.0.0
                """
            )
        )
        deps = parse_yarn_lock(
            path, prod_root_names={"real"}, dev_root_names=set(), include_dev=False
        )
        # ",valid@npm:1.0" parses to first="" → skipped. Only "real" survives.
        assert {d.name for d in deps} == {"real"}


class TestParseBunLock:
    """Bun's text lockfile (``bun.lock``) replaced the binary ``bun.lockb``
    in late 2024 specifically so license/audit tools can read it. The format
    is JSONC (JSON-with-trailing-commas) — Python's ``json`` module rejects
    those, so the parser strips them before parsing."""

    def _write(self, tmp_path, content):
        path = tmp_path / "bun.lock"
        path.write_text(textwrap.dedent(content))
        return path

    def test_parses_basic_lock(self, tmp_path):
        # Note the trailing commas — characteristic of bun.lock's JSONC.
        path = self._write(
            tmp_path,
            """\
            {
              "lockfileVersion": 1,
              "workspaces": {
                "": {
                  "name": "host",
                  "dependencies": {
                    "react": "^18.0.0",
                  },
                },
              },
              "packages": {
                "react": ["react@18.2.0", "",
                          { "dependencies": { "scheduler": "^0.23.0" } },
                          "sha512-..."],
                "scheduler": ["scheduler@0.23.0", "", {}, "sha512-..."],
              },
            }
            """,
        )
        deps = parse_bun_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name: d for d in deps}
        assert "react" in names
        assert names["react"].version_constraint == "==18.2.0"
        assert "scheduler" in names
        assert names["scheduler"].direct_ancestors == ("react",)

    def test_parses_scoped_package(self, tmp_path):
        # Scoped names have multiple `@`; the resolved id split must use
        # the LAST `@` not the first.
        path = self._write(
            tmp_path,
            """\
            {
              "lockfileVersion": 1,
              "workspaces": {
                "": { "name": "host", "dependencies": { "@types/node": "^20.0.0" } }
              },
              "packages": {
                "@types/node": ["@types/node@20.10.0", "", {}, "sha512-..."],
              },
            }
            """,
        )
        deps = parse_bun_lock(
            path, prod_root_names={"@types/node"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "@types/node"
        assert deps[0].version_constraint == "==20.10.0"

    def test_jsonc_trailing_commas_accepted(self, tmp_path):
        # Stripping trailing commas must not be regex-greedy in a way that
        # collapses legitimate JSON structure. Lots of trailing-comma cases.
        path = self._write(
            tmp_path,
            """\
            {
              "lockfileVersion": 1,
              "workspaces": {
                "": {
                  "name": "host",
                  "dependencies": { "a": "^1.0", "b": "^2.0", },
                  "devDependencies": { "c": "^3.0", },
                },
              },
              "packages": {
                "a": ["a@1.0.0", "", {}, "sha512-..."],
                "b": ["b@2.0.0", "", {}, "sha512-..."],
                "c": ["c@3.0.0", "", {}, "sha512-..."],
              },
            }
            """,
        )
        deps = parse_bun_lock(
            path,
            prod_root_names={"a", "b"},
            dev_root_names={"c"},
            include_dev=False,
        )
        names = {d.name for d in deps}
        assert names == {"a", "b"}

    def test_malformed_returns_empty(self, tmp_path):
        path = self._write(tmp_path, "this is not json")
        assert (
            parse_bun_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_dispatcher_routes_to_bun(self, tmp_path):
        # ``parse_npm_lockfile`` must dispatch ``bun.lock`` to the bun parser.
        path = self._write(
            tmp_path,
            """\
            {
              "lockfileVersion": 1,
              "workspaces": { "": { "name": "host", "dependencies": { "react": "^18.0.0" } } },
              "packages": {
                "react": ["react@18.2.0", "", {}, "sha512-..."],
              },
            }
            """,
        )
        deps = parse_npm_lockfile(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "react"


class TestYarnDescriptorParser:
    """Direct tests of `_yarn_name_from_descriptor`."""

    def test_empty_descriptor_returns_empty(self):
        assert _yarn_name_from_descriptor("") == ""

    def test_unaliased_descriptor(self):
        # Plain Berry resolution: `name@npm:<spec>` — not an alias, the post-
        # marker portion is just a version spec.
        assert _yarn_name_from_descriptor("react@npm:18.2.0") == "react"
        assert _yarn_name_from_descriptor("react@npm:^18.0") == "react"
        assert _yarn_name_from_descriptor("@types/node@npm:18.0") == "@types/node"

    def test_npm_alias_descriptor_returns_canonical_target(self):
        # Alias form: `alias@npm:target@spec`. The local alias has no registry
        # entry; the license belongs to the target.
        assert (
            _yarn_name_from_descriptor("string-width-cjs@npm:string-width@^4.2.0") == "string-width"
        )
        assert _yarn_name_from_descriptor("react-is-18@npm:react-is@^18") == "react-is"

    def test_npm_alias_with_scoped_target(self):
        assert _yarn_name_from_descriptor("alias@npm:@scope/pkg@^1.0") == "@scope/pkg"


class TestParseNpmLockfileDispatch:
    def test_dispatches_to_package_lock(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/react": {"version": "18.2.0"}},
                }
            )
        )
        deps = parse_npm_lockfile(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].ecosystem == Ecosystem.NPM

    def test_dispatches_to_pnpm(self, tmp_path):
        path = tmp_path / "pnpm-lock.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                packages:
                  /react@18.2.0:
                    version: 18.2.0
                """
            )
        )
        deps = parse_npm_lockfile(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "react"

    def test_dispatches_to_yarn(self, tmp_path):
        path = tmp_path / "yarn.lock"
        path.write_text('react@^18.0:\n  version "18.2.0"\n')
        deps = parse_npm_lockfile(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "react"

    def test_unsupported_filename_raises(self, tmp_path):
        path = tmp_path / "Pipfile.lock"
        path.write_text("{}")
        with pytest.raises(ValueError, match="Unsupported"):
            parse_npm_lockfile(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)


class TestLockfileVersion1:
    def _write_v1_lockfile(self, tmp_path):
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "name": "legacy-app",
                    "version": "0.1.0",
                    "lockfileVersion": 1,
                    "requires": True,
                    "dependencies": {
                        "lodash": {"version": "4.17.21"},
                        "mocha": {
                            "version": "10.7.0",
                            "dev": True,
                            "requires": {"ms": "2.1.3"},
                        },
                        "ms": {"version": "2.1.3", "dev": True},
                    },
                }
            )
        )
        return path

    def test_parses_v1_flat(self, tmp_path):
        path = self._write_v1_lockfile(tmp_path)
        deps = parse_npm_lockfile(
            path,
            prod_root_names={"lodash"},
            dev_root_names={"mocha"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert "lodash" in by_name
        assert "mocha" in by_name
        assert "ms" in by_name
        assert by_name["lodash"].version_constraint == "==4.17.21"
        # mocha → ms via `requires`; reachability puts ms in DEV group
        assert by_name["ms"].group == DependencyGroup.DEV
        assert "mocha" in by_name["ms"].direct_ancestors

    def test_parses_v1_nested_dependencies(self, tmp_path):
        """v1 nests sub-resolved versions under a parent's `dependencies`
        block when npm couldn't dedupe. Walker should recurse and emit
        the nested entries with their own (name, version)."""
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "left-pad": {"version": "1.3.0"},
                        "parent-pkg": {
                            "version": "2.0.0",
                            "requires": {"left-pad": "1.2.0"},
                            "dependencies": {
                                "left-pad": {"version": "1.2.0"},
                            },
                        },
                    },
                }
            )
        )
        deps = parse_npm_lockfile(
            path,
            prod_root_names={"left-pad", "parent-pkg"},
            dev_root_names=set(),
            include_dev=False,
        )
        left_pads = sorted(d.version_constraint for d in deps if d.name == "left-pad")
        # Both versions surface as distinct entries.
        assert left_pads == ["==1.2.0", "==1.3.0"]

    def test_v1_include_dev_false_drops_dev_chain(self, tmp_path):
        path = self._write_v1_lockfile(tmp_path)
        deps = parse_npm_lockfile(
            path,
            prod_root_names={"lodash"},
            dev_root_names={"mocha"},
            include_dev=False,
        )
        names = {d.name for d in deps}
        assert "lodash" in names
        assert "mocha" not in names
        assert "ms" not in names

    def test_v1_skips_malformed_entries(self, tmp_path):
        # Defensive: real lockfiles have been seen with non-dict values or
        # missing/non-string `version` fields. The walker must skip those
        # entries rather than crash. Includes a same-(name, version) duplicate
        # to exercise the seen-set short-circuit.
        path = tmp_path / "package-lock.json"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "good-pkg": {"version": "1.0.0"},
                        "string-value": "not-a-dict",
                        "missing-version": {"name": "no-version-field"},
                        "non-string-version": {"version": 123},
                        "duplicate-parent": {
                            "version": "1.0.0",
                            "dependencies": {
                                # Same (name, version) as the outer good-pkg —
                                # the seen-set must skip the second emission.
                                "good-pkg": {"version": "1.0.0"},
                            },
                        },
                    },
                }
            )
        )
        deps = parse_npm_lockfile(
            path,
            prod_root_names={"good-pkg", "duplicate-parent"},
            dev_root_names=set(),
            include_dev=False,
        )
        names = [d.name for d in deps]
        assert names.count("good-pkg") == 1
        assert "string-value" not in names
        assert "missing-version" not in names
        assert "non-string-version" not in names


class TestNpmLockfileHelperEdges:
    def test_is_in_test_dir_outside_project_returns_false(self, tmp_path):
        # _is_in_test_dir handles paths that don't resolve relative to the
        # project — treats them as "not in test dir" rather than raising.
        outside = tmp_path.parent / "elsewhere" / "package-lock.json"
        assert _is_in_test_dir(outside, tmp_path) is False

    def test_yarn_alias_descriptor_name_scoped_alias(self):
        # Scoped alias form: `@scope/alias@npm:target@^1`. The alias name to
        # surface is the local `@scope/alias`, not the target.
        assert _yarn_alias_descriptor_name("@scope/alias@npm:target@^1.0") == "@scope/alias"

    def test_yarn_alias_descriptor_name_returns_empty_for_non_alias(self):
        assert _yarn_alias_descriptor_name("react@npm:18.0.0") == ""

    def test_yarn_alias_target_scoped_target_without_version_returns_none(self):
        # `alias@npm:@scope/pkg` — the post-marker body has no inner '@',
        # so it can't be the alias form.
        assert _yarn_alias_target("alias@npm:@scope/pkg") is None

    def test_parse_bun_resolved_id_empty_returns_empty(self):
        assert _parse_bun_resolved_id("", fallback_key="") == ("", "")

    def test_parse_bun_resolved_id_scoped_without_version(self):
        # Scoped name with no version separator — rfind returns 0 (the
        # leading "@"), so the function returns (text, "").
        assert _parse_bun_resolved_id("@scope/foo", fallback_key="") == ("@scope/foo", "")

    def test_parse_bun_resolved_id_unscoped_without_version(self):
        assert _parse_bun_resolved_id("plain-name", fallback_key="plain-name") == (
            "plain-name",
            "",
        )


class TestParsePnpmLockMalformedScopedKey:
    def test_scoped_key_without_slash_does_not_crash_parser(self, tmp_path):
        # A pnpm packages-map key like `@scopeOnly@1.0.0` (no `/` between
        # scope and name) is malformed — the parser must keep going on the
        # well-formed entries rather than blow up on the bad key.
        path = tmp_path / "pnpm-lock.yaml"
        path.write_text(
            textwrap.dedent(
                """\
                packages:
                  '@scopeOnly@1.0.0':
                    version: 1.0.0
                  /react@18.2.0:
                    version: 18.2.0
                """
            )
        )
        deps = parse_pnpm_lock(
            path, prod_root_names={"react"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name for d in deps}
        assert "react" in names


class TestParseBunLockMalformedInput:
    def _write(self, tmp_path, content: str):
        path = tmp_path / "bun.lock"
        path.write_text(textwrap.dedent(content))
        return path

    def test_missing_file_returns_empty(self, tmp_path):
        missing = tmp_path / "does-not-exist" / "bun.lock"
        assert (
            parse_bun_lock(
                missing,
                prod_root_names=set(),
                dev_root_names=set(),
                include_dev=False,
            )
            == []
        )

    def test_non_dict_json_root_returns_empty(self, tmp_path):
        path = self._write(tmp_path, "[]")
        assert (
            parse_bun_lock(
                path,
                prod_root_names=set(),
                dev_root_names=set(),
                include_dev=False,
            )
            == []
        )

    def test_non_dict_packages_field_returns_empty(self, tmp_path):
        path = self._write(tmp_path, '{ "lockfileVersion": 1, "packages": "junk" }')
        assert (
            parse_bun_lock(
                path,
                prod_root_names=set(),
                dev_root_names=set(),
                include_dev=False,
            )
            == []
        )

    def test_invalid_entries_skipped(self, tmp_path):
        # Mix of malformed package entries (empty list, non-list value) —
        # parser must skip them and continue on valid ones.
        path = self._write(
            tmp_path,
            """\
            {
              "lockfileVersion": 1,
              "packages": {
                "react": ["react@18.2.0", "", {}, "sha512-..."],
                "bad-empty-list": [],
                "bad-non-list": "junk",
              },
            }
            """,
        )
        deps = parse_bun_lock(
            path,
            prod_root_names={"react"},
            dev_root_names=set(),
            include_dev=False,
        )
        assert [d.name for d in deps] == ["react"]

    def test_unparseable_resolved_id_skipped(self, tmp_path):
        # `resolved_id` empty AND fallback_key empty — _parse_bun_resolved_id
        # returns ("", "") and the entry is skipped.
        path = self._write(
            tmp_path,
            """\
            {
              "lockfileVersion": 1,
              "packages": {
                "react": ["react@18.2.0", "", {}, "sha512-..."],
                "": ["", "", {}, ""],
              },
            }
            """,
        )
        deps = parse_bun_lock(
            path,
            prod_root_names={"react"},
            dev_root_names=set(),
            include_dev=False,
        )
        assert [d.name for d in deps] == ["react"]

    def test_duplicate_name_version_entry_deduped(self, tmp_path):
        # Two packages keys resolving to the same (name, version) — the
        # second is skipped to avoid duplicating the Dependency.
        path = self._write(
            tmp_path,
            """\
            {
              "lockfileVersion": 1,
              "packages": {
                "react": ["react@18.2.0", "", {}, "sha512-aaa"],
                "react-dup": ["react@18.2.0", "", {}, "sha512-bbb"],
              },
            }
            """,
        )
        deps = parse_bun_lock(
            path,
            prod_root_names={"react"},
            dev_root_names=set(),
            include_dev=False,
        )
        assert sum(1 for d in deps if d.name == "react") == 1
