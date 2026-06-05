"""Tests for the transitive dependency orchestrator (`licenseal.transitive`)."""

from __future__ import annotations

import json
import textwrap

import httpx
import respx

from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.maven_central import _MAX_PARENT_DEPTH
from licenseal.transitive import (
    _MAX_BOM_DEPTH,
    _dedupe,
    _resolve_java_transitive,
    _resolve_version,
    resolve_transitive,
)
from tests._helpers import _java_dep


def _seed(name: str, ecosystem: Ecosystem, version: str = "") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=f"=={version}" if version else "",
        ecosystem=ecosystem,
        group=DependencyGroup.PROD,
    )


# ----------------------------------------------------------------------- helpers


def _pypi_version(name: str, version: str, requires_dist: list[str] | None = None) -> dict:
    return {
        "info": {
            "name": name,
            "version": version,
            "license": "MIT",
            "classifiers": [],
            "requires_dist": requires_dist or [],
        }
    }


def _pypi_project(name: str, latest: str) -> dict:
    return {
        "info": {"name": name, "version": latest, "classifiers": []},
        "releases": {latest: []},
    }


def _npm_version(
    name: str,
    version: str,
    dependencies: dict | None = None,
    peer: dict | None = None,
    optional: dict | None = None,
) -> dict:
    payload = {"name": name, "version": version, "license": "MIT"}
    if dependencies:
        payload["dependencies"] = dependencies
    if peer:
        payload["peerDependencies"] = peer
    if optional:
        payload["optionalDependencies"] = optional
    return payload


# --------------------------------------------------------------------- lockfile path


class TestLockfileFirstPath:
    def test_uses_python_lockfile_when_present(self, tmp_path):
        (tmp_path / "uv.lock").write_text(
            textwrap.dedent(
                """\
                version = 1

                [[package]]
                name = "click"
                version = "8.3.3"
                dependencies = [
                    { name = "colorama" },
                ]

                [[package]]
                name = "colorama"
                version = "0.4.6"
                """
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("click", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"click", "colorama"}
        # No registry calls were needed — lockfile was the source.

    def test_uses_php_lockfile_when_present(self, tmp_path):
        # composer.lock embeds the full edge graph + explicit dev flag —
        # the PHP transitive path uses it without any registry calls.
        (tmp_path / "composer.json").write_text(
            json.dumps(
                {
                    "require": {"acme/lib": "^1.0"},
                    "require-dev": {"acme/test-tool": "^2.0"},
                }
            )
        )
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "acme/lib",
                            "version": "1.2.3",
                            "license": ["MIT"],
                            "require": {"acme/transitive": "^4.0"},
                        },
                        {
                            "name": "acme/transitive",
                            "version": "4.5.6",
                            "license": ["MIT"],
                        },
                    ],
                    "packages-dev": [
                        {
                            "name": "acme/test-tool",
                            "version": "2.0.0",
                            "license": ["MIT"],
                            "dev": True,
                        }
                    ],
                }
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [
                    _seed("acme/lib", Ecosystem.PHP),
                    Dependency(
                        name="acme/test-tool",
                        version_constraint="",
                        ecosystem=Ecosystem.PHP,
                        group=DependencyGroup.DEV,
                    ),
                ],
                tmp_path,
                include_dev=True,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"acme/lib", "acme/transitive", "acme/test-tool"}
        # The transitive entry carries its ancestor attribution.
        transitive_dep = next(d for d in deps if d.name == "acme/transitive")
        assert transitive_dep.depth == 1
        assert transitive_dep.direct_ancestors == ("acme/lib",)
        # Test tool is DEV-attributed.
        test_tool = next(d for d in deps if d.name == "acme/test-tool")
        assert test_tool.group == DependencyGroup.DEV

    def test_php_lockfile_direct_dep_without_source_is_preserved(self, tmp_path):
        # When a direct PHP dep has no `source` attribute (e.g., comes from
        # a separate code path that didn't stamp it), the lockfile entry
        # still surfaces — we just don't overwrite the (empty) source.
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"acme/lib": "^1.0"}}))
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "acme/lib",
                            "version": "1.0.0",
                            "license": ["MIT"],
                        }
                    ]
                }
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [
                    # Direct dep with no source — lockfile entry just passes
                    # through as-is (source stays empty).
                    Dependency(
                        name="acme/lib",
                        version_constraint="^1.0",
                        ecosystem=Ecosystem.PHP,
                        group=DependencyGroup.PROD,
                        source="",
                    )
                ],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"acme/lib"}
        lib = next(d for d in deps if d.name == "acme/lib")
        assert lib.source == ""

    @respx.mock
    def test_php_manifest_only_falls_back_to_packagist(self, tmp_path):
        # No composer.lock — the walker must hit Packagist for each direct
        # dep's transitive ``require`` map.
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"acme/lib": "^1.0"}}))
        respx.get("https://repo.packagist.org/p2/acme/lib.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "packages": {
                        "acme/lib": [
                            {
                                "version": "1.2.3",
                                "license": ["MIT"],
                                "require": {
                                    "acme/transitive": "^4.0",
                                    "php": "^8.0",
                                },
                            }
                        ]
                    }
                },
            )
        )
        respx.get("https://repo.packagist.org/p2/acme/transitive.json").mock(
            return_value=httpx.Response(
                200,
                json={"packages": {"acme/transitive": [{"version": "4.5.6", "license": ["MIT"]}]}},
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [
                    Dependency(
                        name="acme/lib",
                        version_constraint="^1.0",
                        ecosystem=Ecosystem.PHP,
                        group=DependencyGroup.PROD,
                    )
                ],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        # Manifest-only walker pulls the direct dep AND its transitive.
        assert names == {"acme/lib", "acme/transitive"}

    def test_uses_npm_lockfile_when_present(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/react": {
                            "version": "18.2.0",
                            "dependencies": {"scheduler": "^0.23.0"},
                        },
                        "node_modules/scheduler": {"version": "0.23.0"},
                    },
                }
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("react", Ecosystem.NPM)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"react", "scheduler"}


class TestLockfileCoveragePartial:
    """Direct deps declared in nested manifests that aren't covered by the
    root lockfile (e.g. ``container/agent-runner/package.json`` next to a
    root-only ``pnpm-lock.yaml``) used to be silently dropped: the lockfile
    parser only emits entries from the lockfile and the registry-walk
    fallback was skipped once ``handled.add(ecosystem)`` ran. After the fix,
    direct deps not covered by the lockfile get their own ``_walk_registry``
    BFS so their licenses and transitives are resolved.
    """

    @respx.mock
    def test_npm_lockfile_covers_some_directs_others_walked(self, tmp_path):
        # Lockfile covers `react` only; `zod` is a direct dep declared in a
        # nested package.json the lockfile never saw — must be walked.
        # Use empty version spec on `zod` (mirrors the existing npm-walker
        # test) so resolution goes through the ``/zod/latest`` path.
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/react": {"version": "18.2.0"},
                    },
                }
            )
        )
        respx.get("https://registry.npmjs.org/zod/latest").mock(
            return_value=httpx.Response(200, json=_npm_version("zod", "3.22.0"))
        )
        respx.get("https://registry.npmjs.org/zod/3.22.0").mock(
            return_value=httpx.Response(
                200, json=_npm_version("zod", "3.22.0", dependencies={"tslib": "^2.0"})
            )
        )
        respx.get("https://registry.npmjs.org/tslib").mock(
            return_value=httpx.Response(
                200, json={"versions": {"2.6.0": _npm_version("tslib", "2.6.0")}}
            )
        )
        respx.get("https://registry.npmjs.org/tslib/2.6.0").mock(
            return_value=httpx.Response(200, json=_npm_version("tslib", "2.6.0"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("react", Ecosystem.NPM), _seed("zod", Ecosystem.NPM)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names_by_depth = {(d.name, d.depth) for d in deps}
        # react from lockfile (depth 0), zod from walk (depth 0), tslib walked
        # as zod's transitive child (depth >= 1) proves the supplemental walk
        # actually ran the BFS, not just stamped zod at depth 0.
        assert ("react", 0) in names_by_depth
        assert ("zod", 0) in names_by_depth
        assert any(name == "tslib" and depth >= 1 for name, depth in names_by_depth)

    @respx.mock
    def test_python_lockfile_covers_some_directs_others_walked(self, tmp_path):
        # uv.lock covers `click` only; `anyio` is declared in a nested
        # pyproject.toml the lockfile never saw.
        (tmp_path / "uv.lock").write_text(
            textwrap.dedent(
                """\
                version = 1

                [[package]]
                name = "click"
                version = "8.3.3"
                """
            )
        )
        respx.get("https://pypi.org/pypi/anyio/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "4.0.0", "classifiers": []},
                    "releases": {"4.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/anyio/4.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("anyio", "4.0.0", requires_dist=["sniffio>=1.0"])
            )
        )
        respx.get("https://pypi.org/pypi/sniffio/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.3.0", "classifiers": []},
                    "releases": {"1.3.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/sniffio/1.3.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("sniffio", "1.3.0"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("click", Ecosystem.PYTHON), _seed("anyio", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names_by_depth = {(d.name, d.depth) for d in deps}
        assert ("click", 0) in names_by_depth
        assert ("anyio", 0) in names_by_depth
        assert any(name == "sniffio" and depth >= 1 for name, depth in names_by_depth)

    def test_npm_multiple_nested_lockfiles_each_contribute(self, tmp_path):
        # Polyglot monorepo pattern: root has no lockfile, two subdirs each
        # carry their own. Each lockfile must be parsed; together they cover
        # all the discovered directs.
        (tmp_path / "apps" / "cli").mkdir(parents=True)
        (tmp_path / "apps" / "cli" / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/react": {"version": "18.2.0"}},
                }
            )
        )
        (tmp_path / "apps" / "web").mkdir(parents=True)
        (tmp_path / "apps" / "web" / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/zod": {"version": "3.22.0"}},
                }
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("react", Ecosystem.NPM), _seed("zod", Ecosystem.NPM)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names_by_depth = {(d.name, d.depth) for d in deps}
        assert ("react", 0) in names_by_depth
        assert ("zod", 0) in names_by_depth

    @respx.mock
    def test_exclude_paths_blocks_lockfile_discovery(self, tmp_path):
        # ``--exclude-dirs`` must be honored at all levels — including
        # lockfile discovery inside resolve_transitive. A lockfile inside an
        # excluded subtree must not contribute to the result.
        (tmp_path / "vendor-snapshot").mkdir()
        (tmp_path / "vendor-snapshot" / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/excluded-pkg": {"version": "9.9.9"}},
                }
            )
        )
        # Stub the registry so the uncovered-walk on the seed gets a 404
        # (no version resolves; dep keeps its original spec). This isolates
        # the assertion to the exclude-paths behavior.
        respx.get("https://registry.npmjs.org/excluded-pkg/latest").mock(
            return_value=httpx.Response(404)
        )
        excluded = frozenset({(tmp_path / "vendor-snapshot").resolve()})
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("excluded-pkg", Ecosystem.NPM)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
                exclude_paths=excluded,
            )
        # If exclude_paths were ignored, the lockfile would pin ``excluded-pkg``
        # to ``==9.9.9``. Since the lockfile was correctly skipped, the dep
        # keeps its original empty spec (uncovered-walk got a 404 from the
        # mocked registry).
        assert not any(d.version_constraint == "==9.9.9" for d in deps)

    def test_rust_nested_cargo_lock_parsed(self, tmp_path):
        # Polyglot setup: Cargo.lock sits under ``tauri/src-tauri/``, not at
        # project root. Before multi-lockfile detection this scenario fell
        # through to the registry walk; now the nested lockfile is parsed.
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        (tmp_path / "tauri" / "src-tauri").mkdir(parents=True)
        (tmp_path / "tauri" / "src-tauri" / "Cargo.lock").write_text(
            textwrap.dedent(
                f"""\
                version = 3

                [[package]]
                name = "serde"
                version = "1.0.193"
                source = "{registry}"
                dependencies = [
                    "serde_derive",
                ]

                [[package]]
                name = "serde_derive"
                version = "1.0.193"
                source = "{registry}"
                """
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("serde", Ecosystem.RUST)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        # Nested lockfile drove resolution — no network calls needed for the
        # serde_derive transitive (no respx mock above).
        assert {d.name for d in deps} == {"serde", "serde_derive"}

    @respx.mock
    def test_rust_lockfile_covers_some_directs_others_walked(self, tmp_path):
        # Cargo.lock covers `serde` only; `tokio` declared in a nested
        # Cargo.toml the lockfile never saw.
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        (tmp_path / "Cargo.lock").write_text(
            textwrap.dedent(
                f"""\
                version = 3

                [[package]]
                name = "serde"
                version = "1.0.193"
                source = "{registry}"
                """
            )
        )
        respx.get("https://crates.io/api/v1/crates/tokio").mock(
            return_value=httpx.Response(200, json={"crate": {"max_stable_version": "1.35.0"}})
        )
        respx.get("https://crates.io/api/v1/crates/tokio/1.35.0/dependencies").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": [
                        {"crate_id": "pin-project-lite", "kind": "normal", "req": "^0.2"}
                    ]
                },
            )
        )
        respx.get("https://crates.io/api/v1/crates/pin-project-lite").mock(
            return_value=httpx.Response(200, json={"crate": {"max_stable_version": "0.2.13"}})
        )
        respx.get("https://crates.io/api/v1/crates/pin-project-lite/0.2.13/dependencies").mock(
            return_value=httpx.Response(200, json={"dependencies": []})
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("serde", Ecosystem.RUST), _seed("tokio", Ecosystem.RUST, "^1.0")],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names_by_depth = {(d.name, d.depth) for d in deps}
        assert ("serde", 0) in names_by_depth
        assert ("tokio", 0) in names_by_depth
        assert any(name == "pin-project-lite" and depth >= 1 for name, depth in names_by_depth)


# ------------------------------------------------------------------ recursion path


class TestRegistryRecursionPath:
    @respx.mock
    def test_walks_python_transitive_graph(self, tmp_path):
        respx.get("https://pypi.org/pypi/foo/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0", "classifiers": []},
                    "releases": {"1.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("foo", "1.0.0", requires_dist=["bar>=1.0"])
            )
        )
        respx.get("https://pypi.org/pypi/bar/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "2.0.0", "classifiers": []},
                    "releases": {"2.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/bar/2.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("bar", "2.0.0"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("foo", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"foo", "bar"}

    @respx.mock
    def test_walks_rust_transitive_graph(self, tmp_path):
        # serde (^1.0) → /serde for version selection, then /serde/1.0.193/dependencies
        respx.get("https://crates.io/api/v1/crates/serde").mock(
            return_value=httpx.Response(200, json={"crate": {"max_stable_version": "1.0.193"}})
        )
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193/dependencies").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": [{"crate_id": "serde_derive", "kind": "normal", "req": "^1.0"}]
                },
            )
        )
        respx.get("https://crates.io/api/v1/crates/serde_derive").mock(
            return_value=httpx.Response(200, json={"crate": {"max_stable_version": "1.0.193"}})
        )
        respx.get("https://crates.io/api/v1/crates/serde_derive/1.0.193/dependencies").mock(
            return_value=httpx.Response(200, json={"dependencies": []})
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("serde", Ecosystem.RUST, "^1.0")],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"serde", "serde_derive"}

    @respx.mock
    def test_rust_pinned_skips_version_lookup(self, tmp_path):
        # `==1.0.193` (lockfile-style pin) bypasses the /crates/{name} lookup
        # and goes straight to the deps endpoint.
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193/dependencies").mock(
            return_value=httpx.Response(200, json={"dependencies": []})
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("serde", Ecosystem.RUST, "1.0.193")],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert any(d.name == "serde" for d in deps)

    @respx.mock
    def test_rust_unresolvable_seed_kept(self, tmp_path):
        respx.get("https://crates.io/api/v1/crates/missing").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("missing", Ecosystem.RUST, "^1.0")],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert any(d.name == "missing" for d in deps)

    def test_uses_rust_lockfile_when_present(self, tmp_path):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        (tmp_path / "Cargo.lock").write_text(
            textwrap.dedent(
                f"""\
                version = 3

                [[package]]
                name = "serde"
                version = "1.0.193"
                source = "{registry}"
                dependencies = [
                    "serde_derive",
                ]

                [[package]]
                name = "serde_derive"
                version = "1.0.193"
                source = "{registry}"
                """
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("serde", Ecosystem.RUST)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert {d.name for d in deps} == {"serde", "serde_derive"}

    @respx.mock
    def test_walks_npm_transitive_graph(self, tmp_path):
        # foo (empty spec) → fetches /foo/latest for version, then /foo/1.0.0 for deps
        respx.get("https://registry.npmjs.org/foo/latest").mock(
            return_value=httpx.Response(200, json=_npm_version("foo", "1.0.0"))
        )
        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200, json=_npm_version("foo", "1.0.0", dependencies={"bar": "^1.0"})
            )
        )
        # bar (spec=^1.0) → /bar for version selection, then /bar/1.5.0 for deps
        respx.get("https://registry.npmjs.org/bar").mock(
            return_value=httpx.Response(
                200,
                json={"versions": {"1.5.0": _npm_version("bar", "1.5.0")}},
            )
        )
        respx.get("https://registry.npmjs.org/bar/1.5.0").mock(
            return_value=httpx.Response(200, json=_npm_version("bar", "1.5.0"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("foo", Ecosystem.NPM)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"foo", "bar"}

    @respx.mock
    def test_max_depth_caps_walk_and_warns(self, tmp_path, capsys):
        # Real chain a -> b -> c -> d. With max_depth=1, b's depth=1 hits the cap.
        for name in ("a", "b", "c", "d"):
            respx.get(f"https://pypi.org/pypi/{name}/json").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "info": {"version": "1.0.0", "classifiers": []},
                        "releases": {"1.0.0": []},
                    },
                )
            )
        respx.get("https://pypi.org/pypi/a/1.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("a", "1.0.0", requires_dist=["b"]))
        )
        respx.get("https://pypi.org/pypi/b/1.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("b", "1.0.0", requires_dist=["c"]))
        )
        with httpx.Client() as client:
            resolve_transitive(
                [_seed("a", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=1,
                client=client,
            )
        captured = capsys.readouterr()
        assert "max-depth=1" in captured.err

    @respx.mock
    def test_cycle_dedupes_via_visited_set(self, tmp_path):
        # foo -> bar -> foo. Walker must terminate via visited set.
        respx.get("https://pypi.org/pypi/foo/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0", "classifiers": []},
                    "releases": {"1.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("foo", "1.0.0", requires_dist=["bar"])
            )
        )
        respx.get("https://pypi.org/pypi/bar/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0", "classifiers": []},
                    "releases": {"1.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/bar/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("bar", "1.0.0", requires_dist=["foo"])
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("foo", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        # Both should appear once each.
        names = [d.name for d in deps]
        assert names.count("foo") == 1
        assert names.count("bar") == 1

    @respx.mock
    def test_unresolvable_dep_is_kept_as_seed(self, tmp_path):
        # Empty spec: walker queries /json for the version, registry says 404 →
        # _resolve_version returns "" → the dep is emitted unresolved.
        respx.get("https://pypi.org/pypi/notfound/json").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("notfound", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert any(d.name == "notfound" for d in deps)

    @respx.mock
    def test_preserves_version_multiplicity(self, tmp_path):
        """Two paths to the same name with specs that resolve to different
        versions must both appear in the output. Regression for the parallel
        walker's wave-dedup keying on name only, which silently dropped the
        second version. A license scanner needs to see all versions because
        the same package can ship under different licenses across majors."""
        # parent-a → shared@^4 → resolves to 4.5.0
        respx.get("https://pypi.org/pypi/parent-a/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent-a/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("parent-a", "1.0.0", requires_dist=["shared>=4,<5"])
            )
        )
        # parent-b → shared@^3 → resolves to 3.10.0
        respx.get("https://pypi.org/pypi/parent-b/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent-b/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("parent-b", "1.0.0", requires_dist=["shared>=3,<4"])
            )
        )
        # `shared` publishes both 4.5.0 and 3.10.0
        respx.get("https://pypi.org/pypi/shared/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "4.5.0", "classifiers": []},
                    "releases": {"3.10.0": [], "4.5.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/shared/4.5.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("shared", "4.5.0"))
        )
        respx.get("https://pypi.org/pypi/shared/3.10.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("shared", "3.10.0"))
        )

        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("parent-a", Ecosystem.PYTHON), _seed("parent-b", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        shared_versions = sorted(d.version_constraint for d in deps if d.name == "shared")
        assert shared_versions == ["==3.10.0", "==4.5.0"], (
            f"both versions of shared must surface; got {shared_versions}"
        )

    @respx.mock
    def test_two_specs_resolving_to_same_version_emit_once(self, tmp_path):
        """Two different specs that happen to resolve to the same concrete
        version must not produce duplicate dep entries. The wave-dedup keys
        on (name, spec) so both specs survive into resolution; the visited
        set keys on (name, resolved_version) and short-circuits the second.
        """
        respx.get("https://pypi.org/pypi/parent-a/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent-a/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("parent-a", "1.0.0", requires_dist=["shared>=4,<5"])
            )
        )
        respx.get("https://pypi.org/pypi/parent-b/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent-b/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("parent-b", "1.0.0", requires_dist=["shared~=4.5.0"])
            )
        )
        # Different specs (^4 vs ~=4.5.0) but only one version published —
        # both resolve to 4.5.0.
        respx.get("https://pypi.org/pypi/shared/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "4.5.0", "classifiers": []}, "releases": {"4.5.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/shared/4.5.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("shared", "4.5.0"))
        )

        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("parent-a", Ecosystem.PYTHON), _seed("parent-b", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        shared_entries = [d for d in deps if d.name == "shared"]
        assert len(shared_entries) == 1
        assert shared_entries[0].version_constraint == "==4.5.0"


# ------------------------------------------------------------- direct-ancestor BFS


class TestAncestorAttribution:
    @respx.mock
    def test_single_ancestor_chain(self, tmp_path):
        # foo -> mid -> leaf. Both mid and leaf should attribute to foo.
        for name in ("foo", "mid", "leaf"):
            respx.get(f"https://pypi.org/pypi/{name}/json").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "info": {"version": "1.0.0", "classifiers": []},
                        "releases": {"1.0.0": []},
                    },
                )
            )
        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("foo", "1.0.0", requires_dist=["mid"])
            )
        )
        respx.get("https://pypi.org/pypi/mid/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("mid", "1.0.0", requires_dist=["leaf"])
            )
        )
        respx.get("https://pypi.org/pypi/leaf/1.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("leaf", "1.0.0"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("foo", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        by_name = {d.name: d for d in deps}
        assert by_name["foo"].direct_ancestors == ()
        assert by_name["mid"].direct_ancestors == ("foo",)
        assert by_name["leaf"].direct_ancestors == ("foo",)

    @respx.mock
    def test_two_seeds_share_a_transitive(self, tmp_path):
        # a -> shared, b -> shared. shared.direct_ancestors == ("a", "b").
        for name in ("a", "b", "shared"):
            respx.get(f"https://pypi.org/pypi/{name}/json").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "info": {"version": "1.0.0", "classifiers": []},
                        "releases": {"1.0.0": []},
                    },
                )
            )
        respx.get("https://pypi.org/pypi/a/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("a", "1.0.0", requires_dist=["shared"])
            )
        )
        respx.get("https://pypi.org/pypi/b/1.0.0/json").mock(
            return_value=httpx.Response(
                200, json=_pypi_version("b", "1.0.0", requires_dist=["shared"])
            )
        )
        respx.get("https://pypi.org/pypi/shared/1.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("shared", "1.0.0"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("a", Ecosystem.PYTHON), _seed("b", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        by_name = {d.name: d for d in deps}
        assert by_name["shared"].direct_ancestors == ("a", "b")


class TestTransitiveGroupAttribution:
    """Each transitive's group is decided by reachability, not BFS order.

    PROD wins over DEV when a dep is reachable through both — a copyleft
    transitive pulled in by a dev tool *and* a runtime dep is still a
    runtime risk.
    """

    @respx.mock
    def test_dev_only_transitive_inherits_dev(self, tmp_path):
        # A transitive reachable only from a dev seed must be marked dev.
        respx.get("https://registry.npmjs.org/runtime-lib").mock(
            return_value=httpx.Response(
                200, json={"versions": {"1.0.0": _npm_version("runtime-lib", "1.0.0")}}
            )
        )
        respx.get("https://registry.npmjs.org/runtime-lib/1.0.0").mock(
            return_value=httpx.Response(200, json=_npm_version("runtime-lib", "1.0.0"))
        )
        respx.get("https://registry.npmjs.org/dev-tool").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versions": {
                        "1.0.0": _npm_version(
                            "dev-tool", "1.0.0", dependencies={"dev-only-pkg": "^1.0"}
                        )
                    }
                },
            )
        )
        respx.get("https://registry.npmjs.org/dev-tool/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json=_npm_version("dev-tool", "1.0.0", dependencies={"dev-only-pkg": "^1.0"}),
            )
        )
        respx.get("https://registry.npmjs.org/dev-only-pkg").mock(
            return_value=httpx.Response(
                200, json={"versions": {"1.0.0": _npm_version("dev-only-pkg", "1.0.0")}}
            )
        )
        respx.get("https://registry.npmjs.org/dev-only-pkg/1.0.0").mock(
            return_value=httpx.Response(200, json=_npm_version("dev-only-pkg", "1.0.0"))
        )
        prod_seed = Dependency(
            name="runtime-lib",
            version_constraint="^1.0.0",
            ecosystem=Ecosystem.NPM,
            group=DependencyGroup.PROD,
        )
        dev_seed = Dependency(
            name="dev-tool",
            version_constraint="^1.0.0",
            ecosystem=Ecosystem.NPM,
            group=DependencyGroup.DEV,
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [prod_seed, dev_seed],
                tmp_path,
                include_dev=True,
                max_depth=50,
                client=client,
            )
        by_name = {d.name: d for d in deps}
        assert by_name["dev-only-pkg"].group == DependencyGroup.DEV

    @respx.mock
    def test_shared_transitive_attributed_prod(self, tmp_path):
        # `shared` is reached via both a prod chain and a dev chain. The walk
        # must classify it as PROD — being reachable from a prod root means
        # it ships, even if a dev path also pulls it.
        respx.get("https://registry.npmjs.org/prod-root").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versions": {
                        "1.0.0": _npm_version("prod-root", "1.0.0", dependencies={"shared": "^1.0"})
                    }
                },
            )
        )
        respx.get("https://registry.npmjs.org/prod-root/1.0.0").mock(
            return_value=httpx.Response(
                200, json=_npm_version("prod-root", "1.0.0", dependencies={"shared": "^1.0"})
            )
        )
        respx.get("https://registry.npmjs.org/dev-root").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versions": {
                        "1.0.0": _npm_version("dev-root", "1.0.0", dependencies={"shared": "^1.0"})
                    }
                },
            )
        )
        respx.get("https://registry.npmjs.org/dev-root/1.0.0").mock(
            return_value=httpx.Response(
                200, json=_npm_version("dev-root", "1.0.0", dependencies={"shared": "^1.0"})
            )
        )
        respx.get("https://registry.npmjs.org/shared").mock(
            return_value=httpx.Response(
                200, json={"versions": {"1.0.0": _npm_version("shared", "1.0.0")}}
            )
        )
        respx.get("https://registry.npmjs.org/shared/1.0.0").mock(
            return_value=httpx.Response(200, json=_npm_version("shared", "1.0.0"))
        )
        prod_seed = Dependency(
            name="prod-root",
            version_constraint="^1.0.0",
            ecosystem=Ecosystem.NPM,
            group=DependencyGroup.PROD,
        )
        dev_seed = Dependency(
            name="dev-root",
            version_constraint="^1.0.0",
            ecosystem=Ecosystem.NPM,
            group=DependencyGroup.DEV,
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [prod_seed, dev_seed],
                tmp_path,
                include_dev=True,
                max_depth=50,
                client=client,
            )
        by_name = {d.name: d for d in deps}
        assert by_name["shared"].group == DependencyGroup.PROD

    @respx.mock
    def test_npm_alias_resolves_through_target(self, tmp_path):
        # A parent declares ``<alias>: npm:<target>@<spec>``. Without
        # unpacking the walker hits ``/<alias>`` (404) and the dep surfaces
        # UNKNOWN. The alias must rewrite to ``/<target>`` so the actual
        # license resolves.
        respx.get("https://registry.npmjs.org/parent").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versions": {
                        "1.0.0": _npm_version(
                            "parent",
                            "1.0.0",
                            dependencies={"react-is-18": "npm:react-is@^18"},
                        )
                    }
                },
            )
        )
        respx.get("https://registry.npmjs.org/parent/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json=_npm_version(
                    "parent",
                    "1.0.0",
                    dependencies={"react-is-18": "npm:react-is@^18"},
                ),
            )
        )
        respx.get("https://registry.npmjs.org/react-is").mock(
            return_value=httpx.Response(
                200, json={"versions": {"18.2.0": _npm_version("react-is", "18.2.0")}}
            )
        )
        respx.get("https://registry.npmjs.org/react-is/18.2.0").mock(
            return_value=httpx.Response(200, json=_npm_version("react-is", "18.2.0"))
        )
        # Guard: this URL must NOT be hit — failure here proves the alias is
        # being unpacked at emit time.
        respx.get("https://registry.npmjs.org/react-is-18").mock(return_value=httpx.Response(404))
        seed = Dependency(
            name="parent",
            version_constraint="^1.0.0",
            ecosystem=Ecosystem.NPM,
            group=DependencyGroup.PROD,
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [seed], tmp_path, include_dev=False, max_depth=50, client=client
            )
        names = {d.name for d in deps}
        assert "react-is" in names
        assert "react-is-18" not in names


class TestRegistrySeedFiltering:
    def test_skips_ecosystem_when_only_dev_seeds_and_no_dev(self, tmp_path):
        # Only a dev dep in this ecosystem; with include_dev=False, registry walk
        # is skipped entirely (no seeds → no walk, no calls).
        dev_seed = Dependency(
            name="ruff",
            version_constraint="==0.1.0",
            ecosystem=Ecosystem.PYTHON,
            group=DependencyGroup.DEV,
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [dev_seed],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert deps == []


# ----------------------------------------------------------------------- _dedupe


class TestResolveVersion:
    """Cover the per-spec branches of `_resolve_version` not exercised elsewhere."""

    @respx.mock
    def test_python_pinned_skips_registry_lookup(self, tmp_path):
        # Pinned spec → version is extracted without hitting /json. Only the
        # version-specific deps URL is needed.
        respx.get("https://pypi.org/pypi/click/8.3.3/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("click", "8.3.3"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [
                    Dependency(
                        name="click",
                        version_constraint="==8.3.3",
                        ecosystem=Ecosystem.PYTHON,
                    )
                ],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert any(d.name == "click" for d in deps)

    @respx.mock
    def test_python_range_query_returns_empty_when_404(self, tmp_path):
        respx.get("https://pypi.org/pypi/missing/json").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            deps = resolve_transitive(
                [
                    Dependency(
                        name="missing",
                        version_constraint=">=1.0",
                        ecosystem=Ecosystem.PYTHON,
                    )
                ],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        # Unresolvable seed kept for downstream license resolver.
        assert any(d.name == "missing" for d in deps)

    @respx.mock
    def test_npm_pinned_skips_registry_lookup(self, tmp_path):
        # Pinned version (npm uses bare "X.Y.Z", no `==` prefix) → version
        # extraction succeeds and skips the lookup; only the deps fetch happens.
        respx.get("https://registry.npmjs.org/lodash/4.17.21").mock(
            return_value=httpx.Response(200, json=_npm_version("lodash", "4.17.21"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [
                    Dependency(
                        name="lodash",
                        version_constraint="4.17.21",
                        ecosystem=Ecosystem.NPM,
                    )
                ],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert any(d.name == "lodash" for d in deps)

    @respx.mock
    def test_npm_empty_spec_returns_empty_when_404(self, tmp_path):
        respx.get("https://registry.npmjs.org/missing/latest").mock(
            return_value=httpx.Response(404)
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("missing", Ecosystem.NPM)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert any(d.name == "missing" for d in deps)

    @respx.mock
    def test_npm_range_returns_empty_when_404(self, tmp_path):
        respx.get("https://registry.npmjs.org/missing").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            deps = resolve_transitive(
                [
                    Dependency(
                        name="missing",
                        version_constraint="^1.0",
                        ecosystem=Ecosystem.NPM,
                    )
                ],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert any(d.name == "missing" for d in deps)


class TestDedupe:
    def test_keeps_lowest_depth_for_duplicates(self):
        d_direct = Dependency(
            name="foo",
            version_constraint="==1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=0,
        )
        d_trans = Dependency(
            name="foo",
            version_constraint="==1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=2,
            direct_ancestors=("bar",),
        )
        # Direct must win regardless of order.
        for order in ([d_trans, d_direct], [d_direct, d_trans]):
            result = _dedupe(order)
            assert len(result) == 1
            assert result[0].depth == 0
            assert result[0].direct_ancestors == ()

    def test_merges_ancestors_for_transitive_duplicates(self):
        d_a = Dependency(
            name="shared",
            version_constraint="==1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=2,
            direct_ancestors=("a",),
        )
        d_b = Dependency(
            name="shared",
            version_constraint="==1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=3,
            direct_ancestors=("b",),
        )
        result = _dedupe([d_a, d_b])
        assert len(result) == 1
        assert result[0].depth == 2
        assert result[0].direct_ancestors == ("a", "b")

    def test_keeps_distinct_versions(self):
        d1 = Dependency(name="x", version_constraint="==1.0", ecosystem=Ecosystem.NPM)
        d2 = Dependency(name="x", version_constraint="==2.0", ecosystem=Ecosystem.NPM)
        result = _dedupe([d1, d2])
        assert {d.version_constraint for d in result} == {"==1.0", "==2.0"}

    def test_python_pep503_name_normalization_folds_dash_underscore(self):
        # PEP 503 folds dash/underscore/dot variants of the same Python
        # distribution name. Discovery may surface either spelling depending
        # on which manifest the dep came from; dedupe must fold them so the
        # report doesn't double-count and the unresolved spelling collides
        # with the lockfile-pinned spelling for phantom-drop.
        d_dash = Dependency(
            name="mypy-extensions",
            version_constraint="==1.1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=0,
        )
        d_under = Dependency(
            name="mypy_extensions",
            version_constraint="==1.1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=2,
            direct_ancestors=("transitive-parent",),
        )
        result = _dedupe([d_under, d_dash])
        assert len(result) == 1
        # Direct wins; its original spelling is preserved.
        assert result[0].depth == 0

    def test_python_pep503_drops_phantom_when_pinned_spelling_differs(self):
        # A discovery-emitted unresolved entry spelled with an underscore
        # must be dropped when the lockfile pinned the same distribution
        # spelled with a dash (and vice versa) — PEP 503 folds them.
        unresolved = Dependency(
            name="mypy_extensions",
            version_constraint=">=1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=0,
        )
        pinned = Dependency(
            name="mypy-extensions",
            version_constraint="==1.1.0",
            ecosystem=Ecosystem.PYTHON,
            depth=0,
        )
        result = _dedupe([unresolved, pinned])
        assert len(result) == 1
        assert result[0].version_constraint == "==1.1.0"

    def test_npm_name_normalization_does_not_fold_dash_underscore(self):
        # npm names are case-insensitive but underscore vs dash are different
        # packages. Don't apply PEP 503 to non-Python.
        d1 = Dependency(name="my-pkg", version_constraint="==1.0", ecosystem=Ecosystem.NPM)
        d2 = Dependency(name="my_pkg", version_constraint="==1.0", ecosystem=Ecosystem.NPM)
        result = _dedupe([d1, d2])
        assert len(result) == 2

    def test_drops_phantom_unresolved_when_resolved_exists(self):
        """When the walker resolves one path of `express` but fails another
        (e.g. ^4 || ^5 from a peerDep returns 404), the unresolved entry is
        a phantom of the resolved one and must be dropped — not rendered as
        a separate UNKNOWN row in the report."""
        resolved = Dependency(
            name="express",
            version_constraint="==5.2.1",
            ecosystem=Ecosystem.NPM,
            depth=1,
            direct_ancestors=("my-app",),
        )
        phantom = Dependency(
            name="express",
            version_constraint="^4 || ^5",  # unresolved, raw spec
            ecosystem=Ecosystem.NPM,
            depth=2,
            direct_ancestors=("express-rate-limit",),
        )
        result = _dedupe([resolved, phantom])
        assert len(result) == 1
        assert result[0].version_constraint == "==5.2.1"
        # Ancestors from the phantom entry are merged into the resolved one
        # so the user can still see *every* direct dep that pulls express in.
        assert set(result[0].direct_ancestors) == {"my-app", "express-rate-limit"}

    def test_keeps_all_unresolved_when_no_resolved_exists(self):
        """If no entry for the name resolves, keep them all (best effort)."""
        a = Dependency(name="mystery", version_constraint="^4", ecosystem=Ecosystem.NPM, depth=1)
        b = Dependency(name="mystery", version_constraint="^5", ecosystem=Ecosystem.NPM, depth=1)
        result = _dedupe([a, b])
        assert len(result) == 2
        assert {d.version_constraint for d in result} == {"^4", "^5"}


class TestWalkProgressCallback:
    """`on_wave` is called once per BFS level with the cumulative count of
    distinct deps resolved so far. The CLI uses it to drive an in-place
    progress indicator during long walks."""

    @respx.mock
    def test_on_wave_callback_fires_per_bfs_level(self, tmp_path):
        # parent → child chain across two waves.
        respx.get("https://pypi.org/pypi/parent/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json=_pypi_version("parent", "1.0.0", requires_dist=["child"]),
            )
        )
        respx.get("https://pypi.org/pypi/child/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "2.0.0", "classifiers": []}, "releases": {"2.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/child/2.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("child", "2.0.0"))
        )

        wave_counts: list[int] = []

        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("parent", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
                on_wave=wave_counts.append,
            )
        # Two waves: parent resolved (count 1), then child resolved (count 2).
        assert wave_counts == [1, 2]
        assert {d.name for d in deps} == {"parent", "child"}

    def test_no_callback_works_unchanged(self, tmp_path):
        # Callback is optional — omitting it must not break the walk.
        with httpx.Client() as client:
            deps = resolve_transitive([], tmp_path, include_dev=False, max_depth=50, client=client)
        assert deps == []

    @respx.mock
    def test_on_wave_cumulative_count_across_levels(self, tmp_path):
        # Tree: parent → [child_a, child_b], child_a → grandchild. Verifies
        # the callback fires once per BFS level with the cumulative resolved
        # count: 1 after the parent wave, 3 after the two-children wave,
        # 4 after the grandchild wave. (A streaming variant of the walker
        # would yield 4 fires of [1,2,3,4]; we measured streaming to be
        # slower on real registries due to rate-limit pressure and reverted.)
        for name, version, requires in [
            ("parent", "1.0.0", ["child_a", "child_b"]),
            ("child_a", "1.0.0", ["grandchild"]),
            ("child_b", "1.0.0", []),
            ("grandchild", "1.0.0", []),
        ]:
            respx.get(f"https://pypi.org/pypi/{name}/json").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "info": {"version": version, "classifiers": []},
                        "releases": {version: []},
                    },
                )
            )
            respx.get(f"https://pypi.org/pypi/{name}/{version}/json").mock(
                return_value=httpx.Response(
                    200, json=_pypi_version(name, version, requires_dist=requires)
                )
            )

        wave_counts: list[int] = []
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("parent", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
                on_wave=wave_counts.append,
            )
        assert {d.name for d in deps} == {
            "parent",
            "child_a",
            "child_b",
            "grandchild",
        }
        assert wave_counts == [1, 3, 4]


class TestPythonExtrasPropagation:
    """End-to-end: walker propagates per-edge extras requests through the
    BFS, so a `pkg[feature]` direct dep activates `pkg`'s feature-gated
    transitives while a bare `pkg` doesn't."""

    @respx.mock
    def test_default_install_skips_extras_gated_transitives(self, tmp_path):
        # parent has a benign runtime dep and a noisy extras-only dep.
        # Default install (no extras) → only the runtime dep walked.
        respx.get("https://pypi.org/pypi/parent/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "requires_dist": [
                            "runtime-child>=1",
                            "dev-child; extra == 'dev'",
                            "test-child; extra == 'test'",
                            "docs-child; extra == 'docs'",
                        ],
                        "classifiers": [],
                    }
                },
            )
        )
        respx.get("https://pypi.org/pypi/runtime-child/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/runtime-child/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json=_pypi_version("runtime-child", "1.0.0"),
            )
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("parent", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        # parent and its sole runtime child; dev/test/docs extras filtered.
        assert names == {"parent", "runtime-child"}
        assert "dev-child" not in names
        assert "test-child" not in names
        assert "docs-child" not in names

    @respx.mock
    def test_explicit_extras_activates_gated_transitives(self, tmp_path):
        # When the project requests `parent[socks]`, parent's
        # `pysocks; extra == 'socks'` requires_dist entry activates.
        respx.get("https://pypi.org/pypi/parent/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "requires_dist": [
                            "runtime-child>=1",
                            "pysocks; extra == 'socks'",
                            "dev-child; extra == 'dev'",
                        ],
                        "classifiers": [],
                    }
                },
            )
        )
        for name in ["runtime-child", "pysocks"]:
            respx.get(f"https://pypi.org/pypi/{name}/json").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "info": {"version": "1.0.0", "classifiers": []},
                        "releases": {"1.0.0": []},
                    },
                )
            )
            respx.get(f"https://pypi.org/pypi/{name}/1.0.0/json").mock(
                return_value=httpx.Response(200, json=_pypi_version(name, "1.0.0"))
            )

        parent_with_socks = Dependency(
            name="parent",
            version_constraint="",
            ecosystem=Ecosystem.PYTHON,
            group=DependencyGroup.PROD,
            extras=frozenset({"socks"}),
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [parent_with_socks],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps}
        assert names == {"parent", "runtime-child", "pysocks"}
        assert "dev-child" not in names  # 'dev' extra wasn't requested

    @respx.mock
    def test_per_edge_extras_propagate_to_grandchildren(self, tmp_path):
        # `parent` requires `child[feature]>=1`. Walker resolves child with
        # extras={"feature"}, so child's `grandchild; extra == 'feature'`
        # activates. Without per-edge extras propagation, grandchild would
        # be missed.
        respx.get("https://pypi.org/pypi/parent/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "requires_dist": ["child[feature]>=1"],
                        "classifiers": [],
                    }
                },
            )
        )
        respx.get("https://pypi.org/pypi/child/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/child/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "requires_dist": ["grandchild; extra == 'feature'"],
                        "classifiers": [],
                    }
                },
            )
        )
        respx.get("https://pypi.org/pypi/grandchild/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/grandchild/1.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("grandchild", "1.0.0"))
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("parent", Ecosystem.PYTHON)],
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        assert {d.name for d in deps} == {"parent", "child", "grandchild"}


class TestAttributedGroupAncestorFallback:
    @respx.mock
    def test_falls_back_to_bfs_group_when_ancestors_missing(self, monkeypatch, tmp_path):
        # _attributed_group's defensive branch: when compute_direct_ancestors
        # returns an empty map (cycle artifacts, disconnected sub-graph), the
        # BFS-assigned group must be preserved rather than silently demoted
        # to DEV. Patching the symbol to return {} for every dep forces
        # the closure to take the `return transitive.group` path.
        import licenseal.transitive as transitive_mod

        monkeypatch.setattr(transitive_mod, "compute_direct_ancestors", lambda edges, roots: {})

        respx.get("https://pypi.org/pypi/parent/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json=_pypi_version("parent", "1.0.0", requires_dist=["child>=1"]),
            )
        )
        respx.get("https://pypi.org/pypi/parent/json").mock(
            return_value=httpx.Response(200, json=_pypi_project("parent", "1.0.0"))
        )
        respx.get("https://pypi.org/pypi/child/json").mock(
            return_value=httpx.Response(200, json=_pypi_project("child", "1.0.0"))
        )
        respx.get("https://pypi.org/pypi/child/1.0.0/json").mock(
            return_value=httpx.Response(200, json=_pypi_version("child", "1.0.0"))
        )

        with httpx.Client() as client:
            deps = resolve_transitive(
                [_seed("parent", Ecosystem.PYTHON, version="1.0.0")],
                tmp_path,
                include_dev=True,
                client=client,
                max_depth=3,
            )
        # The child transitive must still carry the BFS-assigned PROD group,
        # not be silently demoted because ancestor info was missing.
        child_groups = [d.group for d in deps if d.name == "child"]
        assert child_groups
        assert all(g == DependencyGroup.PROD for g in child_groups)


class TestGoEdgeAwareResolution:
    """Go transitive resolution: parse go.sum for the pinned-module universe,
    fetch each module's go.mod from proxy.golang.org concurrently to build
    the edge graph, then reverse-BFS for direct_ancestors + reachability-based
    PROD/DEV attribution (the ``tool`` directive marks direct deps as DEV).
    """

    @staticmethod
    def _go_mod_fetcher(graph: dict[str, dict[str, str]]):
        """Build a stub go-mod fetcher returning text from a `{module: go.mod-text}` map.

        Production calls ``fetch_go_mod_text`` directly; the test injects a
        stub via ``_resolve_go_transitive``'s ``go_mod_fetcher`` kwarg.
        """

        def fetcher(url, _client):
            # URL shape: https://proxy.golang.org/<encoded-module>/@v/<version>.mod
            # Reverse-extract the module path (lowercase form already since the
            # case-encoding is `!<lc>`; tests use lowercase paths to avoid that).
            tail = url.split("/@v/", 1)[0]
            module_path = tail.split("https://proxy.golang.org/", 1)[1]
            text = graph.get(module_path)
            if text is None:
                return None
            return {"text": text}

        return fetcher

    def test_full_edge_attribution_via_proxy(self, tmp_path):
        # cobra (direct) requires pflag and mousetrap (both transitives).
        # Stubbed proxy fetcher provides the edge data; reverse-BFS attributes
        # both transitives to cobra.
        (tmp_path / "go.sum").write_text(
            "github.com/spf13/cobra v1.10.1 h1:h\n"
            "github.com/spf13/cobra v1.10.1/go.mod h1:h\n"
            "github.com/spf13/pflag v1.0.9 h1:h\n"
            "github.com/spf13/pflag v1.0.9/go.mod h1:h\n"
            "github.com/inconshreveable/mousetrap v1.1.0 h1:h\n"
            "github.com/inconshreveable/mousetrap v1.1.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        graph = {
            "github.com/spf13/cobra": (
                "module github.com/spf13/cobra\n"
                "go 1.15\n"
                "require (\n"
                "    github.com/spf13/pflag v1.0.9\n"
                "    github.com/inconshreveable/mousetrap v1.1.0\n"
                ")\n"
            ),
            "github.com/spf13/pflag": "module github.com/spf13/pflag\n",
            "github.com/inconshreveable/mousetrap": "module github.com/inconshreveable/mousetrap\n",
        }
        seed = Dependency(
            name="github.com/spf13/cobra",
            version_constraint="v1.10.1",
            ecosystem=Ecosystem.GO,
            group=DependencyGroup.PROD,
        )
        with httpx.Client() as client:
            from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

            deps = _resolve_go_transitive(
                direct_go_deps=[seed],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,  # JSON fetcher unused for Go
                go_mod_fetcher=self._go_mod_fetcher(graph),
            )
        by_name = {d.name: d for d in deps}
        assert by_name["github.com/spf13/cobra"].depth == 0
        assert by_name["github.com/spf13/cobra"].direct_ancestors == ()
        assert by_name["github.com/spf13/pflag"].depth == 1
        assert by_name["github.com/spf13/pflag"].direct_ancestors == ("github.com/spf13/cobra",)
        assert by_name["github.com/inconshreveable/mousetrap"].depth == 1
        assert by_name["github.com/inconshreveable/mousetrap"].direct_ancestors == (
            "github.com/spf13/cobra",
        )

    def test_tool_dep_dev_attribution_and_filtering(self, tmp_path):
        # A direct tool dep (stringer) is marked DEV by discovery. Its
        # transitives are reachable only from stringer → also DEV.
        # --no-dev (include_dev=False) drops the whole dev chain.
        (tmp_path / "go.sum").write_text(
            "golang.org/x/tools v0.20.0 h1:h\n"
            "golang.org/x/tools v0.20.0/go.mod h1:h\n"
            "golang.org/x/mod v0.17.0 h1:h\n"
            "golang.org/x/mod v0.17.0/go.mod h1:h\n"
            "github.com/runtime/dep v1.0.0 h1:h\n"
            "github.com/runtime/dep v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        graph = {
            "golang.org/x/tools": ("module golang.org/x/tools\nrequire golang.org/x/mod v0.17.0\n"),
            "golang.org/x/mod": "module golang.org/x/mod\n",
            "github.com/runtime/dep": "module github.com/runtime/dep\n",
        }
        direct = [
            Dependency(
                name="golang.org/x/tools",
                version_constraint="v0.20.0",
                ecosystem=Ecosystem.GO,
                group=DependencyGroup.DEV,  # marked by tool directive at discovery
            ),
            Dependency(
                name="github.com/runtime/dep",
                version_constraint="v1.0.0",
                ecosystem=Ecosystem.GO,
                group=DependencyGroup.PROD,
            ),
        ]
        with httpx.Client() as client:
            from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

            deps_dev = _resolve_go_transitive(
                direct_go_deps=direct,
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher(graph),
            )
            deps_nodev = _resolve_go_transitive(
                direct_go_deps=direct,
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher(graph),
            )

        names_dev = {d.name: d for d in deps_dev}
        names_nodev = {d.name for d in deps_nodev}

        # include_dev=True: all three present, tool and its transitive are DEV.
        assert names_dev["golang.org/x/tools"].group == DependencyGroup.DEV
        assert names_dev["golang.org/x/mod"].group == DependencyGroup.DEV
        assert names_dev["golang.org/x/mod"].direct_ancestors == ("golang.org/x/tools",)
        assert names_dev["github.com/runtime/dep"].group == DependencyGroup.PROD
        # include_dev=False: tool + its transitive dropped; only runtime dep.
        assert names_nodev == {"github.com/runtime/dep"}

    def test_orphan_module_fallback_to_prod(self, tmp_path):
        # If a transitive's parent's go.mod fetch fails (returns None), the
        # transitive becomes unreachable from any root → falls back to PROD
        # rather than being dropped. Conservative: don't silently lose deps
        # on a partial proxy fetch.
        (tmp_path / "go.sum").write_text(
            "github.com/parent v1.0.0 h1:h\n"
            "github.com/parent v1.0.0/go.mod h1:h\n"
            "github.com/orphan v1.0.0 h1:h\n"
            "github.com/orphan v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        # parent's fetch fails → no edges → orphan has no ancestor.
        graph: dict[str, str] = {}
        with httpx.Client() as client:
            from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

            deps = _resolve_go_transitive(
                direct_go_deps=[_seed("github.com/parent", Ecosystem.GO, "v1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher(graph),
            )
        by_name = {d.name: d for d in deps}
        assert by_name["github.com/orphan"].group == DependencyGroup.PROD
        assert by_name["github.com/orphan"].direct_ancestors == ()

    def test_no_go_sum_emits_direct_deps_only(self, tmp_path):
        # No go.sum present. Direct deps come back as-is.
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[_seed("github.com/direct", Ecosystem.GO, "v1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher({"github.com/direct": ""}),
            )
        assert [d.name for d in deps] == ["github.com/direct"]
        assert deps[0].depth == 0

    def test_no_entries_at_all_returns_empty(self, tmp_path):
        # No go.sum AND no direct deps — defensive return-empty.
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher({}),
            )
        assert deps == []

    def test_proxy_text_replaces_are_followed_in_child_modules(self, tmp_path):
        # A transitive's own go.mod may contain a ``replace`` rewriting
        # one of its required modules — the edge graph should reflect the
        # post-replace target.
        (tmp_path / "go.sum").write_text(
            "github.com/parent v1.0.0 h1:h\n"
            "github.com/parent v1.0.0/go.mod h1:h\n"
            "github.com/new/target v2.0.0 h1:h\n"
            "github.com/new/target v2.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        graph = {
            "github.com/parent": (
                "module github.com/parent\n"
                "require github.com/old/x v1.0.0\n"
                "replace github.com/old/x v1.0.0 => github.com/new/target v2.0.0\n"
            ),
            "github.com/new/target": "",
        }
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[_seed("github.com/parent", Ecosystem.GO, "v1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher(graph),
            )
        by_name = {d.name: d for d in deps}
        assert by_name["github.com/new/target"].direct_ancestors == ("github.com/parent",)

    def test_proxy_fetch_returning_non_dict_treated_as_no_edges(self, tmp_path):
        # Defensive: go_mod_fetcher returning a non-dict (e.g. None on
        # transport failure) → treat as leaf, no edges contributed.
        (tmp_path / "go.sum").write_text(
            "github.com/x v1.0.0 h1:h\ngithub.com/x v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )

        def fetcher_returns_none(_url, _client):
            return None

        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[_seed("github.com/x", Ecosystem.GO, "v1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=fetcher_returns_none,
            )
        assert [d.name for d in deps] == ["github.com/x"]

    def test_proxy_fetch_returning_dict_with_non_string_text(self, tmp_path):
        # Defensive: dict but ``text`` is not a string (corrupt response).
        (tmp_path / "go.sum").write_text(
            "github.com/x v1.0.0 h1:h\ngithub.com/x v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )

        def fetcher_bad_text(_url, _client):
            return {"text": 12345}  # not a string

        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[_seed("github.com/x", Ecosystem.GO, "v1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=fetcher_bad_text,
            )
        assert [d.name for d in deps] == ["github.com/x"]

    def test_direct_dep_source_preserved(self, tmp_path):
        # The walker stamps the manifest-source onto depth-0 entries from
        # the matching direct-dep input. Verify it works for Go.
        (tmp_path / "go.sum").write_text(
            "github.com/direct v1.0.0 h1:h\ngithub.com/direct v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        seed = Dependency(
            name="github.com/direct",
            version_constraint="v1.0.0",
            ecosystem=Ecosystem.GO,
            group=DependencyGroup.PROD,
            source="cli/go.mod",
        )
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[seed],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher({"github.com/direct": ""}),
            )
        assert deps[0].source == "cli/go.mod"

    def test_duplicate_entries_across_nested_go_sums_deduped(self, tmp_path):
        # A monorepo with nested go.mod modules may list the same (module,
        # version) in multiple go.sum files. The walker dedupes by
        # (module_path, version) to avoid double-fetching and double-counting.
        (tmp_path / "go.sum").write_text(
            "github.com/shared v1.0.0 h1:h\ngithub.com/shared v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        (tmp_path / "cli").mkdir()
        (tmp_path / "cli" / "go.sum").write_text(
            "github.com/shared v1.0.0 h1:h\ngithub.com/shared v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher({"github.com/shared": ""}),
            )
        # Exactly one entry — duplicates collapsed.
        assert [d.name for d in deps] == ["github.com/shared"]

    def test_direct_deps_dedupe_against_go_sum_when_no_lockfile(self, tmp_path):
        # No go.sum, but direct_go_deps has the same (module, version) twice
        # (e.g. nested go.mod files declaring the same dep). The fallback path
        # dedupes via the same ``seen_entries`` set.
        seed_a = _seed("github.com/dup", Ecosystem.GO, "v1.0.0")
        seed_b = _seed("github.com/dup", Ecosystem.GO, "v1.0.0")
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[seed_a, seed_b],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher({"github.com/dup": ""}),
            )
        assert [d.name for d in deps] == ["github.com/dup"]

    def test_transitive_module_replace_to_local_path_skipped(self, tmp_path):
        # A child module's go.mod can include ``replace ... => ../local``
        # (no version) — the child's requirement is satisfied locally, so
        # the edge doesn't contribute a registry-resolvable child.
        (tmp_path / "go.sum").write_text(
            "github.com/parent v1.0.0 h1:h\ngithub.com/parent v1.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        graph = {
            "github.com/parent": (
                "module github.com/parent\n"
                "require github.com/swapped v1.0.0\n"
                "replace github.com/swapped v1.0.0 => ../localdir\n"
            ),
        }
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[_seed("github.com/parent", Ecosystem.GO, "v1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher(graph),
            )
        # The local-replaced child is NOT added to the edge graph, so no
        # extra deps appear.
        assert [d.name for d in deps] == ["github.com/parent"]

    def test_workspace_local_modules_filtered_from_go_sum(self, tmp_path):
        # Multi-module workspaces (go.work + per-directory go.mod) leave
        # entries in go.sum for sibling modules because the toolchain
        # populated them while resolving cross-module requires before the
        # workspace was set up — or because one sibling imports another via
        # a versioned require. The discovery side already filters these
        # workspace-local module paths from direct-dep emission; the
        # transitive walker must apply the same filter when iterating
        # go.sum, otherwise the leaked entries get registry-resolved as
        # though they were public modules (404s, wasted requests, and noise
        # in the report). Real-world observation: grafana's go.sum contains
        # entries for github.com/grafana/grafana/apps/dashboard and three
        # similar paths that are workspace-local; without this filter they
        # leak into the report and get UNKNOWN-classified.
        (tmp_path / "go.mod").write_text(
            "module example.com/root\ngo 1.22\nrequire example.com/extdep v1.0.0\n",
            encoding="utf-8",
        )
        # go.work `use` directives point at workspace-internal directories.
        (tmp_path / "go.work").write_text(
            "go 1.22\nuse (\n    .\n    ./apps/dashboard\n)\n",
            encoding="utf-8",
        )
        (tmp_path / "apps").mkdir()
        (tmp_path / "apps" / "dashboard").mkdir()
        (tmp_path / "apps" / "dashboard" / "go.mod").write_text(
            "module example.com/root/apps/dashboard\ngo 1.22\n",
            encoding="utf-8",
        )
        # go.sum contains entries for BOTH the external require AND for the
        # workspace-internal sibling — mirroring grafana's actual go.sum
        # shape. The workspace-local entry must be filtered out.
        (tmp_path / "go.sum").write_text(
            "example.com/extdep v1.0.0 h1:h\n"
            "example.com/extdep v1.0.0/go.mod h1:h\n"
            "example.com/root/apps/dashboard v0.0.1 h1:h\n"
            "example.com/root/apps/dashboard v0.0.1/go.mod h1:h\n",
            encoding="utf-8",
        )
        graph = {
            "example.com/extdep": "module example.com/extdep\n",
        }
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[
                    _seed("example.com/extdep", Ecosystem.GO, "v1.0.0"),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher(graph),
            )
        names = [d.name for d in deps]
        # The external dep survives. The workspace-local sibling
        # (example.com/root/apps/dashboard) MUST NOT appear in the output.
        assert "example.com/extdep" in names
        assert "example.com/root/apps/dashboard" not in names

    def test_workspace_local_filter_on_no_lockfile_path(self, tmp_path):
        # Symmetric: when there's no go.sum and the walker falls back to the
        # direct-deps universe, the workspace-local filter must still apply
        # so direct deps named after workspace-local modules don't slip
        # through. (Discovery normally drops these before they reach the
        # transitive walker, but defense-in-depth: the walker itself filters.)
        (tmp_path / "go.mod").write_text(
            "module example.com/root\ngo 1.22\n",
            encoding="utf-8",
        )
        (tmp_path / "go.work").write_text(
            "go 1.22\nuse (\n    .\n    ./apps/dashboard\n)\n",
            encoding="utf-8",
        )
        (tmp_path / "apps").mkdir()
        (tmp_path / "apps" / "dashboard").mkdir()
        (tmp_path / "apps" / "dashboard" / "go.mod").write_text(
            "module example.com/root/apps/dashboard\ngo 1.22\n",
            encoding="utf-8",
        )
        # No go.sum — walker falls back to direct deps.
        from licenseal.transitive import _resolve_go_transitive  # noqa: PLC2701

        with httpx.Client() as client:
            deps = _resolve_go_transitive(
                direct_go_deps=[
                    _seed(
                        "example.com/root/apps/dashboard",
                        Ecosystem.GO,
                        "v0.0.1",
                    ),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                go_mod_fetcher=self._go_mod_fetcher({}),
            )
        # The workspace-local dep is filtered out → empty output.
        assert deps == []


class TestJavaTransitiveResolution:
    """Java transitive resolution: lockfile-first (Gradle), else deps.dev
    ``:dependencies`` walk per direct Maven/Gradle dep, with
    reachability-based PROD/DEV attribution and a multi-module
    workspace-local filter."""

    @staticmethod
    def _stub_deps_fetcher(
        graph: dict[tuple[str, str], tuple[list[tuple[str, str]], list[tuple[str, str, str, str]]]],
    ):
        """Build a stub ``(name, version) -> (nodes, edges)`` fetcher.

        ``graph`` maps each ``(direct_name, direct_version)`` to the
        deps.dev :dependencies response shape — the list of (name,
        version) child nodes plus the list of edge tuples
        ``(from_name, from_version, to_name, to_version)``.
        """

        def fetcher(name: str, version: str, _client: httpx.Client, **_kwargs):
            return graph.get((name, version), ([], []))

        return fetcher

    def test_gradle_lockfile_path_used_when_present(self, tmp_path):
        # gradle.lockfile entries are emitted as depth=0 with
        # classpath-based group attribution. No deps.dev calls for
        # lockfile-covered deps.
        (tmp_path / "gradle.lockfile").write_text(
            "org.springframework:spring-core:5.3.20=compileClasspath,runtimeClasspath\n"
            "junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n",
            encoding="utf-8",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[
                    _java_dep("org.springframework:spring-core", "5.3.20"),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        names = {d.name for d in deps}
        assert names == {"org.springframework:spring-core", "junit:junit"}
        spring = next(d for d in deps if d.name == "org.springframework:spring-core")
        junit = next(d for d in deps if d.name == "junit:junit")
        assert spring.group == DependencyGroup.PROD
        assert junit.group == DependencyGroup.DEV
        # ``==X.Y.Z`` form lets ``_drop_phantom_unresolved`` collapse
        # any discovery-side phantom unresolved entries against these.
        assert spring.version_constraint == "==5.3.20"

    def test_gradle_lockfile_no_dev_drops_test_classpaths(self, tmp_path):
        (tmp_path / "gradle.lockfile").write_text(
            "junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n",
            encoding="utf-8",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # Lockfile entry is DEV-only; --no-dev drops it.
        assert deps == []

    def test_deps_dev_path_walks_uncovered_direct_deps(self, tmp_path):
        # No Gradle lockfile → all direct deps go through deps.dev.
        # Direct dep pulls in a transitive via the deps.dev graph.
        graph = {
            ("org.springframework:spring-core", "5.3.20"): (
                [("org.springframework:spring-jcl", "5.3.20")],
                [
                    (
                        "org.springframework:spring-core",
                        "5.3.20",
                        "org.springframework:spring-jcl",
                        "5.3.20",
                    )
                ],
            )
        }
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[
                    _java_dep(
                        "org.springframework:spring-core",
                        "5.3.20",
                        source="pom.xml",
                    ),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
        by_name = {d.name: d for d in deps}
        assert "org.springframework:spring-core" in by_name
        assert "org.springframework:spring-jcl" in by_name
        # Direct is depth=0, ancestors empty.
        spring_core = by_name["org.springframework:spring-core"]
        assert spring_core.depth == 0
        assert spring_core.version_constraint == "==5.3.20"
        assert spring_core.source == "pom.xml"
        # Transitive is depth=1, reaches via the direct dep.
        spring_jcl = by_name["org.springframework:spring-jcl"]
        assert spring_jcl.depth == 1
        assert spring_jcl.direct_ancestors == ("org.springframework:spring-core",)
        assert spring_jcl.group == DependencyGroup.PROD

    def test_orphan_transitive_falls_back_to_prod(self, tmp_path):
        # Node returned by deps.dev with no incoming edge from any root —
        # treat as PROD (conservative) rather than silently drop.
        graph = {
            ("g:a", "1.0"): (
                [("g:transitive", "1.0"), ("g:orphan", "2.0")],
                # Edge only from a→transitive, not a→orphan; orphan has
                # no inbound edge from any root.
                [("g:a", "1.0", "g:transitive", "1.0")],
            )
        }
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[_java_dep("g:a", "1.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
        orphan = next(d for d in deps if d.name == "g:orphan")
        assert orphan.group == DependencyGroup.PROD
        assert orphan.direct_ancestors == ()

    def test_dev_root_transitive_inherits_dev_filtered_by_no_dev(self, tmp_path):
        # A DEV direct dep pulling in a transitive — the transitive
        # inherits DEV by reachability. --no-dev drops it.
        graph = {
            ("g:test-only", "1.0"): (
                [("g:test-utils", "1.0")],
                [("g:test-only", "1.0", "g:test-utils", "1.0")],
            )
        }
        with httpx.Client() as client:
            deps_with_dev = _resolve_java_transitive(
                direct_java_deps=[_java_dep("g:test-only", "1.0", group=DependencyGroup.DEV)],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
            deps_no_dev = _resolve_java_transitive(
                direct_java_deps=[_java_dep("g:test-only", "1.0", group=DependencyGroup.DEV)],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
        # With --dev: both DEV deps surface.
        names_dev = {d.name for d in deps_with_dev}
        assert names_dev == {"g:test-only", "g:test-utils"}
        for d in deps_with_dev:
            assert d.group == DependencyGroup.DEV
        # --no-dev: direct DEV dep is excluded before walking, transitive
        # never gets reached.
        assert deps_no_dev == []

    def test_unparseable_version_passes_through_unchanged(self, tmp_path):
        # A direct dep with a version expression that ``_extract_pinned_version_maven``
        # can't parse (range syntax) gets emitted as-is so the license
        # resolver still sees it. No deps.dev walk attempted.
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[_java_dep("g:a", "[1.0,2.0)")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        assert len(deps) == 1
        # Version preserved unchanged — the license resolver will route
        # this to UNKNOWN itself.
        assert deps[0].version_constraint == "[1.0,2.0)"

    def test_workspace_local_artifact_filtered_from_transitive_output(self, tmp_path):
        # Multi-module Maven project: ``com.example:parent`` declares
        # ``<modules>core</modules>`` and the ``core`` submodule has its
        # own pom.xml. A transitive sweep that surfaces ``com.example:core``
        # must NOT include it (in-tree, not published to Central).
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <modules>
        <module>core</module>
    </modules>
</project>
""",
            encoding="utf-8",
        )
        (tmp_path / "core").mkdir()
        (tmp_path / "core" / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
    </parent>
    <artifactId>core</artifactId>
</project>
""",
            encoding="utf-8",
        )
        # deps.dev returns the workspace-local artifact as a transitive
        # (in a real scan this would come up because the artifact is
        # published — but in our in-tree multi-module case it's a
        # sibling, not a real dep). The filter must drop it.
        graph = {
            ("org.external:lib", "1.0"): (
                [("com.example:core", "1.0.0")],
                [("org.external:lib", "1.0", "com.example:core", "1.0.0")],
            )
        }
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[_java_dep("org.external:lib", "1.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
        names = {d.name for d in deps}
        assert "org.external:lib" in names
        assert "com.example:core" not in names

    def test_workspace_local_direct_dep_filtered(self, tmp_path):
        # Symmetric: a discovery-side direct dep matching a workspace-
        # local artifact MUST NOT slip through the transitive walker.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
</project>
""",
            encoding="utf-8",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[_java_dep("com.example:parent", "1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        assert deps == []

    def test_mixed_lockfile_and_deps_dev_path(self, tmp_path):
        # gradle.lockfile covers one direct dep; the other direct
        # (Maven-side) goes through deps.dev. Both surface in the
        # output, neither double-emitted.
        (tmp_path / "gradle.lockfile").write_text(
            "org.gradle:from-lockfile:1.0=compileClasspath\n",
            encoding="utf-8",
        )
        graph = {
            ("com.example:from-pom", "2.0"): (
                [("com.example:from-pom-dep", "3.0")],
                [
                    (
                        "com.example:from-pom",
                        "2.0",
                        "com.example:from-pom-dep",
                        "3.0",
                    )
                ],
            )
        }
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[
                    _java_dep("org.gradle:from-lockfile", "1.0"),
                    _java_dep("com.example:from-pom", "2.0"),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
        names = {d.name for d in deps}
        # All three (lockfile dep + pom-side direct + its transitive).
        assert "org.gradle:from-lockfile" in names
        assert "com.example:from-pom" in names
        assert "com.example:from-pom-dep" in names

    def test_no_direct_no_lockfile_returns_empty(self, tmp_path):
        # Defensive: no Java deps, no lockfile → empty output without
        # any deps.dev calls.
        called: list[tuple[str, str]] = []

        def tracking_fetcher(name: str, version: str, _client: httpx.Client, **_kwargs):
            called.append((name, version))
            return ([], [])

        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=tracking_fetcher,
            )
        assert deps == []
        assert called == []

    def test_gradle_lockfile_workspace_local_entry_filtered(self, tmp_path):
        # If gradle.lockfile happens to contain a coord that matches a
        # workspace-local artifact (e.g. a published-sibling rebuild in
        # a monorepo lockfile), the workspace-local filter still drops
        # it — same posture as the deps.dev path.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>core</artifactId>
    <version>1.0.0</version>
</project>
""",
            encoding="utf-8",
        )
        (tmp_path / "gradle.lockfile").write_text(
            "com.example:core:1.0.0=compileClasspath\norg.real:lib:2.0.0=compileClasspath\n",
            encoding="utf-8",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        names = {d.name for d in deps}
        # Workspace-local filtered out, the other survives.
        assert "com.example:core" not in names
        assert "org.real:lib" in names

    def test_deps_dev_node_matching_direct_not_double_emitted(self, tmp_path):
        # deps.dev's :dependencies response includes the SELF root by
        # convention; we already strip that in ``fetch_maven_dependencies``.
        # But a real-world response can ALSO list the same artifact as
        # a non-SELF node when it appears in a diamond shape (e.g.
        # another direct dep depends on it). The walker must not
        # double-emit it at depth=1 — the depth=0 emission is canonical.
        graph = {
            ("g:a", "1.0"): (
                # Includes g:b which is ALSO a direct (next entry).
                [("g:b", "2.0")],
                [("g:a", "1.0", "g:b", "2.0")],
            ),
            ("g:b", "2.0"): ([], []),
        }
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[
                    _java_dep("g:a", "1.0"),
                    _java_dep("g:b", "2.0"),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
        b_entries = [d for d in deps if d.name == "g:b"]
        # ``g:b`` appears once (the depth=0 direct), not twice.
        assert len(b_entries) == 1
        assert b_entries[0].depth == 0

    def test_orphan_node_filtered_when_dev_disabled(self, tmp_path):
        # An orphan node that the conservative fallback would assign
        # PROD is emitted regardless of ``include_dev``. But a transitive
        # whose only reachability is via a DEV root, with include_dev=False,
        # must be dropped before the emit. Construct a scenario where a
        # transitive's ancestors are exclusively DEV roots.
        graph = {
            # PROD root with no transitives.
            ("g:prod-root", "1.0"): ([], []),
            # DEV root pulling in one transitive.
            ("g:dev-root", "1.0"): (
                [("g:dev-transitive", "1.0")],
                [("g:dev-root", "1.0", "g:dev-transitive", "1.0")],
            ),
        }
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[
                    _java_dep("g:prod-root", "1.0"),
                    _java_dep("g:dev-root", "1.0", group=DependencyGroup.DEV),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,  # drop DEV
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(graph),
            )
        names = {d.name for d in deps}
        # DEV root and its DEV transitive both filtered.
        assert "g:dev-root" not in names
        assert "g:dev-transitive" not in names
        assert "g:prod-root" in names

    def test_parent_chain_dm_resolves_version(self, tmp_path):
        # BOM-consumer pattern: child POM declares a dep without version;
        # the parent POM's <dependencyManagement> supplies it. The
        # transitive walker should fetch the parent POM (via Maven
        # Central) and surface the managed version, then walk the
        # transitive graph for the resolved dep.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.parent</groupId>
        <artifactId>parent-bom</artifactId>
        <version>1.0.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        # Stub pom_fetcher: returns the parent POM that declares the
        # managed version for the dep.
        def pom_fetcher(url, _client):
            if "com/parent/parent-bom/1.0.0/parent-bom-1.0.0.pom" in url:
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.parent</groupId>
    <artifactId>parent-bom</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>5.0.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        # Direct dep declared without version (would normally be UNKNOWN).
        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "5.0.0"): ([], []),
                    }
                ),
            )
        # Parent DM resolved the version; the dep is emitted at the
        # resolved version, ready for license lookup.
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==5.0.0"

    def test_parent_chain_dm_via_bom_import(self, tmp_path):
        # BOM-import pattern: parent's <dependencyManagement> imports
        # another BOM (<scope>import</scope>); the imported BOM holds
        # the managed version. Standard ``-dependencies`` BOM pattern.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.bom</groupId>
                <artifactId>my-bom</artifactId>
                <version>2.0.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/bom/my-bom/2.0.0/my-bom-2.0.0.pom" in url:
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.bom</groupId>
    <artifactId>my-bom</artifactId>
    <version>2.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>7.7.7</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "7.7.7"): ([], []),
                    }
                ),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==7.7.7"

    def test_dm_walk_bom_of_bom_recurses_to_find_coord(self, tmp_path):
        # BOM-of-BOM pattern: source's DM imports an outer BOM whose own
        # DM imports an inner BOM that holds the managed version. The
        # walker MUST recurse past depth 1 to find it. Cap is
        # _MAX_BOM_DEPTH; here we exercise depth 2 with success.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.bom</groupId>
                <artifactId>outer-bom</artifactId>
                <version>1.0.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/bom/outer-bom/1.0.0/outer-bom-1.0.0.pom" in url:
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.bom</groupId>
    <artifactId>outer-bom</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.bom</groupId>
                <artifactId>inner-bom</artifactId>
                <version>1.5.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            if "com/bom/inner-bom/1.5.0/inner-bom-1.5.0.pom" in url:
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.bom</groupId>
    <artifactId>inner-bom</artifactId>
    <version>1.5.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>9.9.9</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "9.9.9"): ([], []),
                    }
                ),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==9.9.9"

    def test_dm_walk_bom_chain_exhausts_max_depth(self, tmp_path):
        # BOM-of-BOM chain longer than _MAX_BOM_DEPTH: the walker stops
        # recursing and the coord stays unresolved. Counterpart to the
        # success-path BOM-of-BOM test above; this proves the cap fires.
        # Build N nested BOMs (N > _MAX_BOM_DEPTH); each imports the
        # next; the LAST holds the coord. Source POM imports BOM 0.
        bom_count = _MAX_BOM_DEPTH + 2
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.bom</groupId>
                <artifactId>b0</artifactId>
                <version>1.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            for i in range(bom_count):
                if f"com/bom/b{i}/1.0/b{i}-1.0.pom" in url:
                    if i == bom_count - 1:
                        return {
                            "text": f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.bom</groupId>
    <artifactId>b{i}</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>5.5.5</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                        }
                    return {
                        "text": f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.bom</groupId>
    <artifactId>b{i}</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.bom</groupId>
                <artifactId>b{i + 1}</artifactId>
                <version>1.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                    }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # Cap exhausted before reaching the last BOM with the coord.
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == ""

    def test_dm_walk_parent_property_inherited_for_dep_version(self, tmp_path):
        # Parent-property inheritance for DEP VERSIONS: grandparent's
        # <properties> defines ``lib.ver``; parent's DM uses
        # ``<version>${lib.ver}</version>``; child omits version. The
        # walker must walk grandparent → parent to compute the
        # property dict that resolves parent's DM-version-token.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>p1</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/x/p1/1.0/p1-1.0.pom" in url:
                # Parent: DM references ${lib.ver} but does NOT define it.
                # The property lives in p2 (grandparent).
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>p2</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>p1</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>${lib.ver}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            if "com/x/p2/1.0/p2-1.0.pom" in url:
                # Grandparent: defines the property used by p1's DM
                # version token. Walker must inherit it into p1's
                # property dict for the version to resolve.
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>p2</artifactId>
    <version>1.0</version>
    <properties>
        <lib.ver>4.4.4</lib.ver>
    </properties>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "4.4.4"): ([], []),
                    }
                ),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==4.4.4"

    def test_property_token_in_dep_version_resolves_via_parent(self, tmp_path):
        # Pattern B: source POM declares <version>${some.version}</version>
        # but the property is defined in the parent's <properties> block,
        # not the child's. Discovery's local-only expansion leaves the
        # literal in place; the walker must accumulate parent properties
        # and re-expand.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>p</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/x/p/1.0/p-1.0.pom" in url:
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>p</artifactId>
    <version>1.0</version>
    <properties>
        <some.version>9.9.9</some.version>
    </properties>
</project>
"""
                }
            return None

        prop_token_dep = Dependency(
            name="com.example:lib",
            version_constraint="${some.version}",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[prop_token_dep],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "9.9.9"): ([], []),
                    }
                ),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==9.9.9"

    def test_property_token_resolves_via_grandparent(self, tmp_path):
        # Pattern B at depth 2: ${revision} defined in grandparent, not
        # in the immediate parent. The walk must traverse multiple levels.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>p1</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/x/p1/1.0/p1-1.0.pom" in url:
                # Mid parent — no properties of its own, just chains to p2.
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>p2</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>p1</artifactId>
    <version>1.0</version>
</project>
"""
                }
            if "com/x/p2/1.0/p2-1.0.pom" in url:
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>p2</artifactId>
    <version>1.0</version>
    <properties>
        <revision>7.7.7</revision>
    </properties>
</project>
"""
                }
            return None

        dep = Dependency(
            name="com.example:lib",
            version_constraint="${revision}",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[dep],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "7.7.7"): ([], []),
                    }
                ),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==7.7.7"

    def test_property_token_unreadable_source_pom_keeps_dep_versionless(self, tmp_path):
        # Defensive: source pom path doesn't exist (typo, deleted between
        # discovery and resolution). _resolve_property_in_version returns
        # empty; dep flows through with the literal token intact.
        dep = Dependency(
            name="com.example:lib",
            version_constraint="${some.version}",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="does-not-exist.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[dep],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "${some.version}"

    def test_property_token_unresolvable_keeps_dep_versionless(self, tmp_path):
        # Pattern B failure path: ${unknown.prop} not defined anywhere in
        # the parent chain. The dep should flow through with the literal
        # token untouched — license resolver will UNKNOWN it (correct
        # signal: we couldn't determine which version applies).
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        dep = Dependency(
            name="com.example:lib",
            version_constraint="${unknown.prop}",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[dep],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        # Literal token preserved — no fake version invented from thin air.
        assert lib.version_constraint == "${unknown.prop}"

    def test_property_token_project_version_resolves_locally(self, tmp_path):
        # Pattern B with the special ${project.version} token: refers to
        # the local POM's own version. _project_properties exposes it,
        # so the resolution doesn't even need to fetch parent POMs.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>3.5.2</version>
</project>
""",
            encoding="utf-8",
        )

        dep = Dependency(
            name="com.example:lib",
            version_constraint="${project.version}",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )

        # Asserting no pom_fetcher calls would over-specify (the helper
        # is allowed to walk for parent properties even when not needed);
        # the key invariant is that ${project.version} resolves to the
        # local pom's version without external fetches required for
        # this case.
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[dep],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "3.5.2"): ([], []),
                    }
                ),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==3.5.2"

    def test_concrete_version_passes_through_unchanged(self, tmp_path):
        # Defensive: a dep with a concrete version (no ${...} and not
        # empty) must NOT trigger either walk path — it's already
        # resolved and we shouldn't waste a network round-trip.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>1.0</version>
</project>
""",
            encoding="utf-8",
        )
        called: list[str] = []

        def pom_fetcher(url, _client):
            called.append(url)
            return None

        dep = Dependency(
            name="com.example:lib",
            version_constraint="2.5.0",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[dep],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher(
                    {
                        ("com.example:lib", "2.5.0"): ([], []),
                    }
                ),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==2.5.0"
        # No pom_fetcher calls — concrete version short-circuits both
        # the DM walk (Pattern A) and the property-token walk (Pattern B).
        assert called == []

    def test_parent_dm_walk_failure_passes_through_versionless(self, tmp_path):
        # When the parent chain is unreachable / no DM match found,
        # the dep flows through with empty version (current UNKNOWN
        # behavior). Defense: no crash, no infinite walk.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.missing</groupId>
        <artifactId>missing-parent</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(_url, _client):
            return None  # All parent fetches fail

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # The version-less dep flows through untouched.
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == ""

    def test_dm_resolution_skipped_when_source_missing(self, tmp_path):
        # Defensive: if a dep has no source field (e.g., synthesized
        # somewhere upstream), the DM walk has no anchor POM to start
        # from. Pass through unchanged.
        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="",  # no source
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        assert len(deps) == 1
        assert deps[0].version_constraint == ""

    def test_dm_walk_unreadable_source_pom_returns_empty(self, tmp_path):
        # When the dep's source file can't be read (typo, deleted,
        # encoding issue), _resolve_managed_version returns empty and
        # the dep passes through unchanged.
        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="does-not-exist.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        assert deps[0].version_constraint == ""

    def test_dm_walk_unresolved_parent_version_stops(self, tmp_path):
        # If a parent's <version> is itself ${...} and the property
        # isn't defined locally, we can't fetch the parent POM —
        # stop the walk cleanly, dep passes through unresolved.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>parent</artifactId>
        <version>${revision}</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )
        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,  # not called
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        assert deps[0].version_constraint == ""

    def test_dm_walk_skips_dm_entry_with_empty_coords(self, tmp_path):
        # Malformed DM entries (missing groupId or artifactId) must be
        # skipped silently; they shouldn't poison the lookup or crash.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId></groupId>
                <artifactId>orphan</artifactId>
                <version>1.0</version>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>3.0.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )
        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({("com.example:lib", "3.0.0"): ([], [])}),
            )
        # Discovery now fills in version from the local DM block —
        # confirming the dm-walk path's _search_dm_for_coord skips the
        # orphan and matches the second entry.
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==3.0.0"

    def test_dm_walk_dm_entry_with_unresolved_property_skipped(self, tmp_path):
        # Discovery's local-DM path skips entries whose version is
        # ${...} unresolved; the transitive walker's _search_dm_for_coord
        # must do the same so it doesn't return a literal "${revision}".
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.parent</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/parent/parent/1.0.0/parent-1.0.0.pom" in url:
                # Parent declares the dep but with unresolved ${revision}.
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.parent</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>${revision}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # Unresolved ${revision} → no match → dep stays version-less.
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == ""

    def test_dm_walk_bom_fetch_failure_continues_to_parent(self, tmp_path):
        # When a BOM import fetch fails, the walker continues to the
        # parent chain rather than crashing or stopping.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.parent</groupId>
        <artifactId>parent</artifactId>
        <version>2.0.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.unreachable</groupId>
                <artifactId>missing-bom</artifactId>
                <version>1.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "missing-bom" in url:
                return None  # BOM fetch fails
            if "com/parent/parent/2.0.0/parent-2.0.0.pom" in url:
                return {
                    "text": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.parent</groupId>
    <artifactId>parent</artifactId>
    <version>2.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>9.0.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({("com.example:lib", "9.0.0"): ([], [])}),
            )
        # BOM fetch failed → walker proceeded to parent → resolved.
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==9.0.0"

    def test_dm_walk_bom_returns_no_match_continues_to_parent(self, tmp_path):
        # BOM POM fetched successfully but doesn't contain the coord.
        # Walker should keep going to the parent chain.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.parent</groupId>
        <artifactId>parent</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.unrelated</groupId>
                <artifactId>unrelated-bom</artifactId>
                <version>1.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "unrelated-bom" in url:
                return {
                    "text": """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.unrelated</groupId>
    <artifactId>unrelated-bom</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.other</groupId>
                <artifactId>other</artifactId>
                <version>9.9</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            if "com/parent/parent/1.0/parent-1.0.pom" in url:
                return {
                    "text": """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.parent</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>4.4.4</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({("com.example:lib", "4.4.4"): ([], [])}),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==4.4.4"

    def test_dm_walk_parent_dm_property_expands_to_empty(self, tmp_path):
        # Edge case: a parent POM's DM entry references a property
        # that's defined as an empty string. _parse_pom keeps the entry
        # (non-empty literal ${...} input), but _expand_properties
        # collapses it to "" — the guard at line 484 of transitive.py
        # then drops the entry instead of yielding a coord-less search.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.parent</groupId>
        <artifactId>parent</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/parent/parent/1.0/parent-1.0.pom" in url:
                # The DM has one entry whose groupId is ``${empty.prop}``
                # AND the parent defines that property as the empty
                # string. Expansion produces "" → guard skip. The
                # second entry resolves the coord normally.
                return {
                    "text": """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.parent</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
    <properties>
        <empty.prop></empty.prop>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>${empty.prop}</groupId>
                <artifactId>collapsed</artifactId>
                <version>1.0</version>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>5.5</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({("com.example:lib", "5.5"): ([], [])}),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==5.5"

    def test_dm_walk_parent_with_malformed_dm_entries(self, tmp_path):
        # Parent POM's DM contains malformed entries (empty groupId, a
        # mixed import-and-regular pair). The walker must skip them and
        # find the real coord further down the list. This exercises the
        # _search_dm_for_coord paths that discovery's local-DM
        # short-circuit can hide.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.parent</groupId>
        <artifactId>parent</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/parent/parent/1.0/parent-1.0.pom" in url:
                # Parent POM: orphan first (empty group → skipped),
                # then a BOM-import entry (sets has_bom=True), then the
                # real coord (returned with has_bom flag preserved).
                return {
                    "text": """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.parent</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId></groupId>
                <artifactId>orphan</artifactId>
                <version>1.0</version>
            </dependency>
            <dependency>
                <groupId>com.bom</groupId>
                <artifactId>side-bom</artifactId>
                <version>1.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>6.6.6</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({("com.example:lib", "6.6.6"): ([], [])}),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==6.6.6"

    def test_dm_walk_iter_bom_imports_skips_non_imports_and_malformed(self, tmp_path):
        # _iter_bom_imports must skip both non-import DM entries (so it
        # yields only ``<scope>import</scope>`` shaped entries) AND
        # import entries with malformed coords (empty fields, unresolved
        # ${…} in version). Set up a parent POM whose DM contains:
        # 1. A non-import entry (skipped)
        # 2. An import with unresolved ${version} (skipped)
        # 3. A valid import that resolves the coord.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.parent</groupId>
        <artifactId>parent</artifactId>
        <version>1.0</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )

        def pom_fetcher(url, _client):
            if "com/parent/parent/1.0/parent-1.0.pom" in url:
                # Parent has NO direct match for com.example:lib, but
                # has BOM imports — forcing _iter_bom_imports to be
                # called. The first entry is non-import (skipped); the
                # second is an import with unresolved ${...} (skipped);
                # the third is a valid import.
                return {
                    "text": """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.parent</groupId>
    <artifactId>parent</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.unrelated</groupId>
                <artifactId>plain-dep</artifactId>
                <version>1.0</version>
            </dependency>
            <dependency>
                <groupId>com.junk</groupId>
                <artifactId>junk-bom</artifactId>
                <version>${unresolved}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
            <dependency>
                <groupId>com.real</groupId>
                <artifactId>real-bom</artifactId>
                <version>2.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            if "com/real/real-bom/2.0/real-bom-2.0.pom" in url:
                return {
                    "text": """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.real</groupId>
    <artifactId>real-bom</artifactId>
    <version>2.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>8.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({("com.example:lib", "8.0"): ([], [])}),
            )
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == "==8.0"

    def test_dm_walk_exhausts_max_depth(self, tmp_path):
        # Construct a parent chain longer than _MAX_PARENT_DEPTH; the
        # walker stops and returns empty for the coord.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>p0</artifactId>
        <version>1</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )
        # Build a chain of N parents (N > _MAX_PARENT_DEPTH); each
        # points to the next; the LAST has the coord. Walker should
        # exhaust depth before reaching the last.
        chain = [f"p{i}" for i in range(_MAX_PARENT_DEPTH + 3)]

        def pom_fetcher(url, _client):
            for i, name in enumerate(chain):
                if f"com/x/{name}/1/{name}-1.pom" in url:
                    if i == len(chain) - 1:
                        return {
                            "text": f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>{name}</artifactId>
    <version>1</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>2.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
                        }
                    return {
                        "text": f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>{chain[i + 1]}</artifactId>
        <version>1</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>{name}</artifactId>
    <version>1</version>
</project>
"""
                    }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # Max depth exhausted; version stays empty.
        lib = next(d for d in deps if d.name == "com.example:lib")
        assert lib.version_constraint == ""

    def test_dm_walk_parent_depth_cap_bounds_fetch_count(self, tmp_path):
        # The depth cap must actually bound network traffic — without an
        # explicit fetch-count assertion, a regression that walks the
        # full chain but discards the late-arriving result would still
        # produce empty version and pass test_dm_walk_exhausts_max_depth.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>p0</artifactId>
        <version>1</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>child</artifactId>
    <version>0.1</version>
</project>
""",
            encoding="utf-8",
        )
        # Build a chain twice as deep as the cap. Late entries MUST NOT
        # be touched — that's what "the cap fires" actually means.
        chain = [f"p{i}" for i in range(_MAX_PARENT_DEPTH * 2 + 2)]
        fetched: set[str] = set()

        def pom_fetcher(url, _client):
            for i, name in enumerate(chain):
                if f"com/x/{name}/1/{name}-1.pom" in url:
                    fetched.add(name)
                    # Blank parent pointing onward; none holds the coord.
                    if i == len(chain) - 1:
                        return {
                            "text": f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.x</groupId>
    <artifactId>{name}</artifactId>
    <version>1</version>
</project>
"""
                        }
                    return {
                        "text": f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.x</groupId>
        <artifactId>{chain[i + 1]}</artifactId>
        <version>1</version>
    </parent>
    <groupId>com.x</groupId>
    <artifactId>{name}</artifactId>
    <version>1</version>
</project>
"""
                    }
            return None

        version_less = Dependency(
            name="com.example:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # The walker may touch chain entries up to the parent + property-
        # accumulation cap (_MAX_PARENT_DEPTH per direction, applied at
        # each step of the outer parent walk that also caps at the same
        # depth). It MUST NOT touch entries past 2 * _MAX_PARENT_DEPTH —
        # a regression that walks the full chain would reach the final
        # entry. The boundary entry being unfetched is the cap-firing
        # invariant.
        late_entries = {chain[-1], chain[-2]}
        assert not (late_entries & fetched), (
            f"Walker touched late chain entries past the cap: {late_entries & fetched}"
        )

    def test_dm_walk_workspace_local_parent_read_from_disk(self, tmp_path):
        # The reactor-multi-module pattern: the submodule's <parent>
        # is the reactor root, which is itself a workspace-local POM
        # (NOT published to Maven Central). The walker must read the
        # parent from disk; trying to fetch it via the network would
        # 404. This is the common multi-module-reactor shape that was
        # the primary source of the ~30% no-version UNKNOWN rate
        # before this fix.
        # Reactor root: holds the DM block with the managed version.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>reactor</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>
    <modules>
        <module>submodule</module>
    </modules>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.external</groupId>
                <artifactId>extdep</artifactId>
                <version>7.7.7</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )
        # Submodule: declares extdep without version; parent is the
        # workspace-local reactor.
        (tmp_path / "submodule").mkdir()
        (tmp_path / "submodule" / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.example</groupId>
        <artifactId>reactor</artifactId>
        <version>1.0.0</version>
    </parent>
    <artifactId>submodule</artifactId>
    <dependencies>
        <dependency>
            <groupId>org.external</groupId>
            <artifactId>extdep</artifactId>
        </dependency>
    </dependencies>
</project>
""",
            encoding="utf-8",
        )

        # pom_fetcher must NOT be called for the reactor root — it's
        # workspace-local. If the walker calls the network for it, we
        # flag that here.
        network_calls: list[str] = []

        def pom_fetcher(url, _client):
            network_calls.append(url)
            return None

        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        java_deps = [d for d in direct_deps if d.ecosystem == Ecosystem.JAVA]
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=java_deps,
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({("org.external:extdep", "7.7.7"): ([], [])}),
            )
        extdep = next(d for d in deps if d.name == "org.external:extdep")
        # Resolved via the on-disk reactor root.
        assert extdep.version_constraint == "==7.7.7"
        # No network fetch attempted for the workspace-local reactor.
        assert not any("com/example/reactor" in u for u in network_calls)

    def test_dm_walk_workspace_local_bom_read_from_disk(self, tmp_path):
        # Symmetric: a BOM import in a parent's DM may itself point at
        # a workspace-local artifact (a monorepo that publishes its own
        # BOM module). Read it from disk rather than try the network.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>internal-bom</artifactId>
                <version>1.0.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )
        (tmp_path / "bom" / "pom.xml").parent.mkdir(exist_ok=True)
        (tmp_path / "bom" / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>internal-bom</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.external</groupId>
                <artifactId>extdep</artifactId>
                <version>9.9.9</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
""",
            encoding="utf-8",
        )

        network_calls: list[str] = []

        def pom_fetcher(url, _client):
            network_calls.append(url)
            return None

        version_less = Dependency(
            name="org.external:extdep",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=pom_fetcher,
                deps_fetcher=self._stub_deps_fetcher({("org.external:extdep", "9.9.9"): ([], [])}),
            )
        extdep = next(d for d in deps if d.name == "org.external:extdep")
        assert extdep.version_constraint == "==9.9.9"
        # No network fetch for the workspace-local BOM.
        assert not any("com/example/internal-bom" in u for u in network_calls)

    def test_dm_walk_workspace_local_parent_unreadable_returns_empty(self, tmp_path, monkeypatch):
        # Defensive: if a workspace-local parent's pom becomes unreadable
        # between discovery time and walk time (file deleted, encoding
        # corruption, race condition on a live filesystem), the walk
        # terminates cleanly rather than crashing. Monkey-patch
        # ``_read_local_pom`` so the read fails for the parent path
        # specifically — testing the actual race is operationally hard.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>flaky-parent</artifactId>
        <version>1.0.0</version>
    </parent>
</project>
""",
            encoding="utf-8",
        )
        (tmp_path / "flaky" / "pom.xml").parent.mkdir(exist_ok=True)
        (tmp_path / "flaky" / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>flaky-parent</artifactId>
    <version>1.0.0</version>
</project>
""",
            encoding="utf-8",
        )

        import licenseal.transitive as transitive_module

        original = transitive_module._read_local_pom
        flaky_path = (tmp_path / "flaky" / "pom.xml").resolve()

        def flaky_read(p):
            if p.resolve() == flaky_path:
                return None  # simulate read race
            return original(p)

        monkeypatch.setattr(transitive_module, "_read_local_pom", flaky_read)

        version_less = Dependency(
            name="org.external:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # Read failure → walk terminates cleanly; dep unresolved.
        assert deps[0].version_constraint == ""

    def test_dm_walk_parent_block_without_version_terminates(self, tmp_path):
        # Defensive: a <parent> block that declares groupId + artifactId
        # but omits <version>, AND the parent isn't workspace-local —
        # we can't fetch the parent without a version, so the walk
        # stops cleanly at line 608 of transitive.py.
        (tmp_path / "pom.xml").write_text(
            """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <parent>
        <groupId>org.somewhere</groupId>
        <artifactId>some-parent</artifactId>
    </parent>
</project>
""",
            encoding="utf-8",
        )
        version_less = Dependency(
            name="org.external:lib",
            version_constraint="",
            ecosystem=Ecosystem.JAVA,
            group=DependencyGroup.PROD,
            source="pom.xml",
        )
        with httpx.Client() as client:
            deps = _resolve_java_transitive(
                direct_java_deps=[version_less],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda u, c: None,
                pom_fetcher=lambda u, c: None,
                deps_fetcher=self._stub_deps_fetcher({}),
            )
        # No version on parent, not workspace-local → can't fetch →
        # walk stops, dep unresolved.
        assert deps[0].version_constraint == ""

    def test_walk_through_resolve_transitive_uses_java_branch(self, tmp_path):
        # End-to-end through the public ``resolve_transitive`` entry
        # point: a Java direct dep → ``_resolve_java_transitive`` runs.
        # No lockfile so the deps.dev path fires.
        respx.start()
        try:
            respx.get(
                "https://api.deps.dev/v3/systems/MAVEN/packages/"
                "com.example%3Aa/versions/1.0:dependencies"
            ).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "nodes": [
                            {
                                "versionKey": {
                                    "system": "MAVEN",
                                    "name": "com.example:a",
                                    "version": "1.0",
                                },
                                "relation": "SELF",
                            },
                            {
                                "versionKey": {
                                    "system": "MAVEN",
                                    "name": "com.example:b",
                                    "version": "2.0",
                                },
                                "relation": "DIRECT",
                            },
                        ],
                        "edges": [{"fromNode": 0, "toNode": 1}],
                    },
                )
            )
            with httpx.Client() as client:
                deps = resolve_transitive(
                    direct_deps=[_java_dep("com.example:a", "1.0")],
                    project_path=tmp_path,
                    include_dev=True,
                    max_depth=10,
                    client=client,
                )
            names = {d.name for d in deps}
            assert names == {"com.example:a", "com.example:b"}
        finally:
            respx.stop()


# ===========================================================================
# .NET transitive walker
# ===========================================================================


def _dotnet_dep(
    name: str,
    version: str = "",
    *,
    group: DependencyGroup = DependencyGroup.PROD,
    source: str = "App.csproj",
) -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.DOTNET,
        group=group,
        source=source,
    )


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestResolveDotnetTransitive:
    """Direct tests of ``_resolve_dotnet_transitive`` via injected fetchers."""

    def test_nuget_lockfile_first_covers_direct(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "Newtonsoft.Json": {
                                "type": "Direct",
                                "resolved": "13.0.1",
                            },
                            "System.Text.Json": {
                                "type": "Transitive",
                                "resolved": "8.0.0",
                                "dependencies": {},
                            },
                        }
                    },
                }
            ),
        )

        def deps_fetcher_unused(*args, **kwargs):
            raise AssertionError("Lockfile should cover direct deps")

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Newtonsoft.Json", "13.0.1")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=deps_fetcher_unused,
            )
        names = {d.name for d in out}
        assert "Newtonsoft.Json" in names
        assert "System.Text.Json" in names

    def test_lockfile_dev_dep_filtered_when_no_dev(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {"net8.0": {"xunit": {"type": "Direct", "resolved": "2.6.1"}}},
                }
            ),
        )
        # Direct dep marked DEV; lockfile entry matches by name.
        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("xunit", "2.6.1", group=DependencyGroup.DEV)],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        assert {d.name for d in out} == set()

    def test_paket_lockfile_path(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "paket.lock",
            "NUGET\n  remote: https://api.nuget.org/v3/index.json\n"
            "    Newtonsoft.Json (13.0.1)\n"
            "    Serilog (3.1.1)\n",
        )
        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Newtonsoft.Json", "13.0.1")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        names = {d.name for d in out}
        assert names == {"Newtonsoft.Json", "Serilog"}

    def test_paket_dev_filtered_when_no_dev(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "paket.lock",
            "NUGET\n  remote: https://api.nuget.org/v3/index.json\n"
            "    KeepMe (1.0)\n"
            "GROUP Test\n"
            "NUGET\n  remote: https://api.nuget.org/v3/index.json\n"
            "    TestOnly (2.0)\n",
        )
        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=False,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        names = {d.name for d in out}
        assert "KeepMe" in names
        assert "TestOnly" not in names

    def test_deps_dev_walk_for_uncovered_direct(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        # No lockfile present; deps.dev returns one transitive child.
        calls: list[tuple[str, str]] = []

        def deps_fetcher(name, version, client, *, fetcher):
            calls.append((name, version))
            return (
                [("System.Text.Json", "8.0.0")],
                [("Newtonsoft.Json", "13.0.1", "System.Text.Json", "8.0.0")],
            )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Newtonsoft.Json", "13.0.1")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=deps_fetcher,
            )
        assert calls == [("Newtonsoft.Json", "13.0.1")]
        names = {d.name for d in out}
        assert "Newtonsoft.Json" in names
        assert "System.Text.Json" in names
        # Transitive is at depth=1.
        trans = next(d for d in out if d.name == "System.Text.Json")
        assert trans.depth == 1
        # Reachability puts it under the prod root.
        assert trans.direct_ancestors == ("Newtonsoft.Json",)

    def test_unparseable_version_emitted_without_walk(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Lib", "$(NotResolved)")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: _unreachable(),
            )
        # Dep flows through with the literal version, no walk attempted.
        assert len(out) == 1
        assert out[0].version_constraint == "$(NotResolved)"

    def test_workspace_local_project_id_filtered(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        # An in-tree project shares its name with what would otherwise
        # be a NuGet PackageReference; the workspace-local filter drops it.
        _write(
            tmp_path / "Shared.Lib" / "Shared.Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk" />""",
        )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Shared.Lib", "1.0.0")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        assert out == []

    def test_orphan_transitive_falls_back_to_prod(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        def deps_fetcher(name, version, client, *, fetcher):
            # Return a node with NO incoming edge — orphaned from any root.
            return (
                [("OrphanDep", "9.0.0")],
                [],
            )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Newtonsoft.Json", "13.0.1")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=deps_fetcher,
            )
        orphan = next(d for d in out if d.name == "OrphanDep")
        assert orphan.group == DependencyGroup.PROD
        assert orphan.direct_ancestors == ()

    def test_no_walkable_direct_returns_no_extras(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        # All directs have unparseable versions; walkable list is empty.
        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[
                    _dotnet_dep("Lib1", "$(X)"),
                    _dotnet_dep("Lib2", ""),
                ],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: _unreachable(),
            )
        # Both directs flow through as-is.
        assert len(out) == 2
        assert all(d.depth == 0 for d in out)

    def test_workspace_local_node_in_subgraph_filtered(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "Local.Module" / "Local.Module.csproj",
            """<Project Sdk="Microsoft.NET.Sdk" />""",
        )

        def deps_fetcher(name, version, client, *, fetcher):
            return (
                [("Local.Module", "1.0"), ("RealDep", "2.0")],
                [
                    ("Newtonsoft.Json", "13.0.1", "Local.Module", "1.0"),
                    ("Newtonsoft.Json", "13.0.1", "RealDep", "2.0"),
                ],
            )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Newtonsoft.Json", "13.0.1")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=deps_fetcher,
            )
        names = {d.name for d in out}
        assert "Local.Module" not in names
        assert "RealDep" in names

    def test_paket_lockfile_dedup_with_workspace_local(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "Local.Lib" / "Local.Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk" />""",
        )
        _write(
            tmp_path / "paket.lock",
            "NUGET\n  remote: https://api.nuget.org/v3/index.json\n"
            "    Local.Lib (1.0)\n"
            "    Real.Lib (2.0)\n",
        )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        names = {d.name for d in out}
        assert "Local.Lib" not in names
        assert "Real.Lib" in names

    def test_lockfile_transitive_emitted_as_depth_one_prod(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "TransitiveOnly": {
                                "type": "Transitive",
                                "resolved": "5.0.0",
                            }
                        }
                    },
                }
            ),
        )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        trans = next(d for d in out if d.name == "TransitiveOnly")
        assert trans.depth == 1
        assert trans.group == DependencyGroup.PROD


def _unreachable():
    raise AssertionError("deps_fetcher should not be called in this test")


class TestResolveDotnetTransitiveEdgeBranches:
    """Targeted tests for less-traveled branches in ``_resolve_dotnet_transitive``."""

    def test_nuget_lockfile_entry_with_workspace_local_name_filtered(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "Shared.Lib" / "Shared.Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk" />""",
        )
        _write(
            tmp_path / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "Shared.Lib": {"type": "Direct", "resolved": "1.0"},
                            "RealDep": {"type": "Transitive", "resolved": "2.0"},
                        }
                    },
                }
            ),
        )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        names = {d.name for d in out}
        assert "Shared.Lib" not in names
        assert "RealDep" in names

    def test_paket_entry_dedup_against_nuget_lockfile_entry(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        _write(
            tmp_path / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {"net8.0": {"Shared": {"type": "Direct", "resolved": "1.0"}}},
                }
            ),
        )
        # Paket lockfile also mentions Shared; the second entry must
        # be deduped (covered_names already contains "shared").
        _write(
            tmp_path / "paket.lock",
            "NUGET\n  remote: https://api.nuget.org/v3/index.json\n"
            "    Shared (2.0)\n"
            "    OnlyPaket (3.0)\n",
        )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=lambda *a, **kw: ([], []),
            )
        names = {d.name for d in out}
        assert "Shared" in names
        # The NuGet lockfile's Shared @ 1.0 wins; the Paket entry is deduped.
        shared = next(d for d in out if d.name == "Shared")
        assert shared.version_constraint == "1.0"
        assert "OnlyPaket" in names

    def test_subgraph_node_overlapping_direct_skipped(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        # deps.dev returns a node that's already a direct dep (self-edge
        # or back-reference). The walker already emitted the direct above,
        # so the merged-nodes loop must skip re-emitting at depth=1.
        def deps_fetcher(name, version, client, *, fetcher):
            return (
                [("Newtonsoft.Json", "13.0.1"), ("OtherDep", "5.0")],
                [("Newtonsoft.Json", "13.0.1", "OtherDep", "5.0")],
            )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("Newtonsoft.Json", "13.0.1")],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=deps_fetcher,
            )
        # Direct emitted once (at depth=0) + OtherDep transitive at depth=1.
        newtonsoft_entries = [d for d in out if d.name == "Newtonsoft.Json"]
        assert len(newtonsoft_entries) == 1
        assert newtonsoft_entries[0].depth == 0

    def test_dev_only_reachable_transitive_attributed_dev(self, tmp_path):
        from licenseal.transitive import _resolve_dotnet_transitive

        # Direct dep is DEV; its transitive subgraph carries a node not
        # reachable from any PROD root → dev_anc branch.
        def deps_fetcher(name, version, client, *, fetcher):
            return (
                [("DevTransitive", "1.0")],
                [("xunit", "2.6.1", "DevTransitive", "1.0")],
            )

        with httpx.Client() as client:
            out = _resolve_dotnet_transitive(
                direct_dotnet_deps=[_dotnet_dep("xunit", "2.6.1", group=DependencyGroup.DEV)],
                project_path=tmp_path,
                exclude_paths=frozenset(),
                include_dev=True,
                client=client,
                max_workers=4,
                fetcher=lambda url, c: None,
                deps_fetcher=deps_fetcher,
            )
        dev_trans = next(d for d in out if d.name == "DevTransitive")
        assert dev_trans.group == DependencyGroup.DEV
        assert dev_trans.direct_ancestors == ("xunit",)


class TestResolveTransitiveDotnetDispatch:
    """Verify resolve_transitive wires .NET deps through _resolve_dotnet_transitive."""

    def test_dispatch_routes_dotnet_deps(self, tmp_path):
        _write(
            tmp_path / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}}
                    },
                }
            ),
        )
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps=[_dotnet_dep("Newtonsoft.Json", "13.0.1")],
                project_path=tmp_path,
                include_dev=True,
                max_depth=10,
                client=client,
            )
        names = {d.name for d in deps if d.ecosystem == Ecosystem.DOTNET}
        assert "Newtonsoft.Json" in names


class TestResolveVersionPhp:
    """Direct unit tests for _resolve_version PHP branches.

    Mirrors the npm/Python branches' coverage shape: the BFS walker calls
    _resolve_version once per node, and PHP requires specific tests because
    Packagist's response shape differs from npm's (no dist-tags, descending
    list of version entries).
    """

    def _dep(self, name: str = "acme/lib", spec: str = "^1.0"):
        return Dependency(
            name=name,
            version_constraint=spec,
            ecosystem=Ecosystem.PHP,
            group=DependencyGroup.PROD,
        )

    def _packagist_url(self, name: str) -> str:
        return f"https://repo.packagist.org/p2/{name}.json"

    @respx.mock
    def test_pinned_returns_immediately(self):
        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(spec="==2.5.0"),
                Ecosystem.PHP,
                client,
                fetcher=httpx.AsyncClient,  # type: ignore[arg-type]  # not called for pinned
            )
        assert v == "2.5.0"

    @respx.mock
    def test_pinned_v_prefix_stripped(self):
        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(spec="==v2.5.0"),
                Ecosystem.PHP,
                client,
                fetcher=httpx.AsyncClient,  # type: ignore[arg-type]
            )
        assert v == "2.5.0"

    @respx.mock
    def test_fetcher_failure_returns_empty(self):
        respx.get(self._packagist_url("acme/lib")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            from licenseal.resolvers.http import fetch_registry_json

            v = _resolve_version(
                self._dep(spec="^1.0"),
                Ecosystem.PHP,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == ""

    @respx.mock
    def test_no_entries_returns_empty(self):
        respx.get(self._packagist_url("acme/lib")).mock(
            return_value=httpx.Response(200, json={"packages": {"acme/lib": []}})
        )
        with httpx.Client() as client:
            from licenseal.resolvers.http import fetch_registry_json

            v = _resolve_version(
                self._dep(spec="^1.0"),
                Ecosystem.PHP,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == ""

    @respx.mock
    def test_empty_spec_returns_latest_version(self):
        # Empty spec → take the first entry (descending order = newest).
        respx.get(self._packagist_url("acme/lib")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "packages": {
                        "acme/lib": [
                            {"version": "v3.0.0"},
                            {"version": "2.0.0"},
                        ]
                    }
                },
            )
        )
        with httpx.Client() as client:
            from licenseal.resolvers.http import fetch_registry_json

            v = _resolve_version(
                self._dep(spec=""),
                Ecosystem.PHP,
                client,
                fetcher=fetch_registry_json,
            )
        # ``v`` prefix stripped.
        assert v == "3.0.0"

    @respx.mock
    def test_star_spec_returns_latest_version(self):
        respx.get(self._packagist_url("acme/lib")).mock(
            return_value=httpx.Response(
                200,
                json={"packages": {"acme/lib": [{"version": "3.0.0"}, {"version": "2.0.0"}]}},
            )
        )
        with httpx.Client() as client:
            from licenseal.resolvers.http import fetch_registry_json

            v = _resolve_version(
                self._dep(spec="*"),
                Ecosystem.PHP,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == "3.0.0"

    @respx.mock
    def test_empty_spec_with_non_string_version_returns_empty(self):
        # Defensive: the first entry's version isn't a string.
        respx.get(self._packagist_url("acme/lib")).mock(
            return_value=httpx.Response(200, json={"packages": {"acme/lib": [{"version": 1}]}})
        )
        with httpx.Client() as client:
            from licenseal.resolvers.http import fetch_registry_json

            v = _resolve_version(
                self._dep(spec=""),
                Ecosystem.PHP,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == ""

    @respx.mock
    def test_range_skips_non_string_versions_in_published_list(self):
        respx.get(self._packagist_url("acme/lib")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "packages": {
                        "acme/lib": [
                            {"version": None},
                            {"version": "3.0.0"},
                            {"version": "2.0.0"},
                        ]
                    }
                },
            )
        )
        with httpx.Client() as client:
            from licenseal.resolvers.http import fetch_registry_json

            v = _resolve_version(
                self._dep(spec="^3.0"),
                Ecosystem.PHP,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == "3.0.0"


class TestRubyLockfileFirstPath:
    """End-to-end Ruby resolution: Gemfile + Gemfile.lock → lockfile-driven graph."""

    def test_lockfile_drives_deps_with_edge_attribution(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\n'
            'gem "acme-lib", "~> 1.0"\n'
            "group :test do\n"
            '  gem "acme-test-tool"\n'
            "end\n"
        )
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    acme-lib (1.2.3)\n"
            "      acme-transitive (= 4.5.6)\n"
            "    acme-transitive (4.5.6)\n"
            "    acme-test-tool (2.0.0)\n"
            "\n"
            "DEPENDENCIES\n"
            "  acme-lib (~> 1.0)\n"
            "  acme-test-tool\n"
            "\n"
        )
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps,
                tmp_path,
                include_dev=True,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps if d.ecosystem == Ecosystem.RUBY}
        assert names == {"acme-lib", "acme-transitive", "acme-test-tool"}
        transitive = next(d for d in deps if d.name == "acme-transitive")
        assert transitive.depth == 1
        assert transitive.direct_ancestors == ("acme-lib",)
        test_tool = next(d for d in deps if d.name == "acme-test-tool")
        assert test_tool.group == DependencyGroup.DEV

    def test_off_registry_dev_gem_attributed_dev_and_depth0(self, tmp_path):
        # Regression: a git-sourced gem in a :development group must be
        # attributed DEV (the group lives only in the Gemfile) and kept at
        # depth 0. Previously the Gemfile parser dropped off-registry gems
        # before attribution, so it leaked in as a depth-1 PROD entry and
        # showed up under --no-dev.
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\n'
            'gem "acme-lib"\n'
            "group :development do\n"
            '  gem "acme-dev", git: "https://github.com/example/acme-dev.git"\n'
            "end\n"
        )
        (tmp_path / "Gemfile.lock").write_text(
            "GIT\n"
            "  remote: https://github.com/example/acme-dev.git\n"
            "  revision: abc123\n"
            "  specs:\n"
            "    acme-dev (0.1.0)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    acme-lib (1.0.0)\n"
            "\n"
            "DEPENDENCIES\n"
            "  acme-dev!\n"
            "  acme-lib\n"
            "\n"
        )
        from licenseal.discovery import discover_all_dependencies
        from licenseal.discovery.ruby.lockfiles import is_off_registry_marker

        direct_deps, _ = discover_all_dependencies(tmp_path)
        # include_dev=True: acme-dev present at depth 0, DEV, off-registry.
        with httpx.Client() as client:
            with_dev = resolve_transitive(
                direct_deps, tmp_path, include_dev=True, max_depth=50, client=client
            )
        acme_dev = next(d for d in with_dev if d.name == "acme-dev")
        assert acme_dev.depth == 0
        assert acme_dev.group == DependencyGroup.DEV
        assert is_off_registry_marker(acme_dev.source)
        # include_dev=False: acme-dev dropped — no longer leaks in as PROD.
        with httpx.Client() as client:
            prod_only = resolve_transitive(
                direct_deps, tmp_path, include_dev=False, max_depth=50, client=client
            )
        assert "acme-dev" not in {d.name for d in prod_only}

    @respx.mock
    def test_ruby_manifest_only_falls_back_to_rubygems(self, tmp_path):
        # No Gemfile.lock — walker hits rubygems.org per direct dep.
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "acme-lib"\n')
        respx.get("https://rubygems.org/api/v1/gems/acme-lib.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "acme-lib",
                    "version": "1.2.3",
                    "licenses": ["MIT"],
                    "dependencies": {
                        "runtime": [{"name": "acme-transitive", "requirements": "= 4.5.6"}],
                        "development": [],
                    },
                },
            )
        )
        respx.get("https://rubygems.org/api/v2/rubygems/acme-lib/versions/1.2.3.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "acme-lib",
                    "number": "1.2.3",
                    "licenses": ["MIT"],
                    "dependencies": {
                        "runtime": [{"name": "acme-transitive", "requirements": "= 4.5.6"}],
                        "development": [],
                    },
                },
            )
        )
        respx.get("https://rubygems.org/api/v2/rubygems/acme-transitive/versions/4.5.6.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "acme-transitive",
                    "number": "4.5.6",
                    "licenses": ["MIT"],
                    "dependencies": {"runtime": [], "development": []},
                },
            )
        )
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps,
                tmp_path,
                include_dev=False,
                max_depth=50,
                client=client,
            )
        names = {d.name for d in deps if d.ecosystem == Ecosystem.RUBY}
        assert names == {"acme-lib", "acme-transitive"}


class TestResolveVersionRuby:
    """Direct unit tests for _resolve_version Ruby branches."""

    def _dep(self, name: str = "rails", spec: str = "~> 7.1", source: str = ""):
        return Dependency(
            name=name,
            version_constraint=spec,
            ecosystem=Ecosystem.RUBY,
            group=DependencyGroup.PROD,
            source=source,
        )

    def test_pinned_returns_immediately(self):
        from licenseal.resolvers.http import fetch_registry_json

        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(spec="==7.1.3"),
                Ecosystem.RUBY,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == "7.1.3"

    def test_off_registry_short_circuits(self):
        from licenseal.discovery.ruby.lockfiles import _OFF_REGISTRY_MARKER
        from licenseal.resolvers.http import fetch_registry_json

        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(spec="==1.0", source=_OFF_REGISTRY_MARKER),
                Ecosystem.RUBY,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == ""

    @respx.mock
    def test_unpinned_uses_v1_endpoint(self):
        from licenseal.resolvers.http import fetch_registry_json

        respx.get("https://rubygems.org/api/v1/gems/rails.json").mock(
            return_value=httpx.Response(
                200,
                json={"name": "rails", "version": "7.1.3", "licenses": ["MIT"]},
            )
        )
        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(spec=""),
                Ecosystem.RUBY,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == "7.1.3"

    @respx.mock
    def test_v1_404_returns_empty(self):
        from licenseal.resolvers.http import fetch_registry_json

        respx.get("https://rubygems.org/api/v1/gems/missing.json").mock(
            return_value=httpx.Response(404)
        )
        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(name="missing", spec=""),
                Ecosystem.RUBY,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == ""

    @respx.mock
    def test_v1_non_string_version_returns_empty(self):
        from licenseal.resolvers.http import fetch_registry_json

        respx.get("https://rubygems.org/api/v1/gems/x.json").mock(
            return_value=httpx.Response(200, json={"name": "x", "version": None})
        )
        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(name="x", spec=""),
                Ecosystem.RUBY,
                client,
                fetcher=fetch_registry_json,
            )
        assert v == ""


class TestWalkOneInnerRuby:
    """Ruby branch in _walk_one_inner — calls fetch_rubygems_dependencies."""

    @respx.mock
    def test_ruby_walker_returns_runtime_children(self):
        from licenseal.resolvers.http import fetch_registry_json
        from licenseal.transitive import _walk_one_inner

        respx.get("https://rubygems.org/api/v2/rubygems/rails/versions/7.1.3.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "rails",
                    "number": "7.1.3",
                    "licenses": ["MIT"],
                    "dependencies": {
                        "runtime": [{"name": "rack", "requirements": ">= 2.0"}],
                        "development": [],
                    },
                },
            )
        )
        dep = Dependency(
            name="rails",
            version_constraint="==7.1.3",
            ecosystem=Ecosystem.RUBY,
            group=DependencyGroup.PROD,
        )
        with httpx.Client() as client:
            _, ver, children = _walk_one_inner(
                dep,
                Ecosystem.RUBY,
                50,
                client,
                fetch_registry_json,
            )
        assert ver == "7.1.3"
        assert [c.name for c in children] == ["rack"]


_HEX_MIX_EXS = (
    "defmodule App.MixProject do\n"
    "  use Mix.Project\n"
    "  def project, do: [app: :app, deps: deps()]\n"
    "  defp deps do\n"
    "    [\n"
    '      {:phoenix, "~> 1.7"},\n'
    '      {:dev_tool, "~> 1.0", only: [:dev, :test]},\n'
    '      {:my_fork, github: "me/my_fork"}\n'
    "    ]\n"
    "  end\n"
    "end\n"
)

_HEX_MIX_LOCK = (
    "%{\n"
    '  "phoenix": {:hex, :phoenix, "1.7.10", "h", [:mix], '
    '[{:plug, "~> 1.14", []}], "hexpm", "h2"},\n'
    '  "plug": {:hex, :plug, "1.15.0", "h", [:mix], [], "hexpm", "h2"},\n'
    '  "dev_tool": {:hex, :dev_tool, "1.0.0", "h", [:mix], [], "hexpm", "h2"},\n'
    '  "my_fork": {:git, "https://github.com/me/my_fork.git", "sha", []},\n'
    "}\n"
)


class TestHexLockfileFirstPath:
    """End-to-end Hex resolution: mix.exs + mix.lock → lockfile-driven graph."""

    def test_lockfile_drives_deps_with_edge_attribution(self, tmp_path):
        (tmp_path / "mix.exs").write_text(_HEX_MIX_EXS)
        (tmp_path / "mix.lock").write_text(_HEX_MIX_LOCK)
        from licenseal.discovery import discover_all_dependencies
        from licenseal.discovery.hex.mix_lock import is_off_registry_marker

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=True, max_depth=50, client=client
            )
        by_name = {d.name: d for d in deps if d.ecosystem == Ecosystem.HEX}
        assert set(by_name) == {"phoenix", "plug", "dev_tool", "my_fork"}
        assert by_name["plug"].depth == 1
        assert by_name["plug"].direct_ancestors == ("phoenix",)
        assert by_name["dev_tool"].group == DependencyGroup.DEV
        # git-sourced direct dep: depth 0, off-registry marker preserved.
        assert by_name["my_fork"].depth == 0
        assert is_off_registry_marker(by_name["my_fork"].source)

    def test_dev_only_chain_dropped_under_no_dev(self, tmp_path):
        (tmp_path / "mix.exs").write_text(_HEX_MIX_EXS)
        (tmp_path / "mix.lock").write_text(_HEX_MIX_LOCK)
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=False, max_depth=50, client=client
            )
        names = {d.name for d in deps if d.ecosystem == Ecosystem.HEX}
        assert "dev_tool" not in names
        assert {"phoenix", "plug", "my_fork"} <= names

    @respx.mock
    def test_manifest_only_falls_back_to_hex_pm(self, tmp_path):
        # No mix.lock — Hex is unhandled, so the registry-recursion fallback
        # walks each direct dep against hex.pm.
        (tmp_path / "mix.exs").write_text(
            "defmodule M.MixProject do\n"
            "  def project, do: [app: :m, deps: deps()]\n"
            '  defp deps, do: [{:jason, "~> 1.4"}]\n'
            "end\n"
        )
        respx.get("https://hex.pm/api/packages/jason").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"licenses": ["Apache-2.0"], "links": {}},
                    "latest_stable_version": "1.4.4",
                },
            )
        )
        respx.get("https://hex.pm/api/packages/jason/releases/1.4.4").mock(
            return_value=httpx.Response(200, json={"requirements": {}})
        )
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=False, max_depth=50, client=client
            )
        jason = next(d for d in deps if d.name == "jason")
        assert jason.ecosystem == Ecosystem.HEX

    def test_rebar_lock_drives_deps_level_based(self, tmp_path):
        # Erlang path: rebar.config (profiles → dev) + rebar.lock (levels →
        # depth, no edges). Lock covers every config dep so nothing is walked.
        (tmp_path / "rebar.config").write_text(
            '{deps, [{cowlib, "2.12.1"}, {jsx, {git, "https://x/y.git", {tag, "v3"}}}]}.\n'
            '{profiles, [{test, [{deps, [{meck, "0.9.2"}]}]}]}.\n'
        )
        (tmp_path / "rebar.lock").write_text(
            '{"1.2.0",\n'
            '[{<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>},0},\n'
            ' {<<"meck">>,{pkg,<<"meck">>,<<"0.9.2">>},0},\n'
            ' {<<"telemetry">>,{pkg,<<"telemetry">>,<<"1.2.1">>},1},\n'
            ' {<<"jsx">>,{git,"https://x/y.git",{ref,"abc"}},0}]}.\n'
        )
        from licenseal.discovery import discover_all_dependencies
        from licenseal.discovery.hex.mix_lock import is_off_registry_marker

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=True, max_depth=50, client=client
            )
        by_name = {d.name: d for d in deps if d.ecosystem == Ecosystem.HEX}
        assert set(by_name) == {"cowlib", "meck", "telemetry", "jsx"}
        assert by_name["meck"].group == DependencyGroup.DEV  # test profile
        assert by_name["telemetry"].depth == 1  # level-1 transitive, PROD
        assert by_name["telemetry"].group == DependencyGroup.PROD
        assert is_off_registry_marker(by_name["jsx"].source)
        # --no-dev drops the test-profile dep.
        with httpx.Client() as client:
            prod_only = resolve_transitive(
                direct_deps, tmp_path, include_dev=False, max_depth=50, client=client
            )
        assert "meck" not in {d.name for d in prod_only}


class TestResolveVersionHex:
    """Direct unit tests for the _resolve_version Hex branch."""

    def _dep(self, name="phoenix", spec="~> 1.7", source=""):
        return Dependency(
            name=name,
            version_constraint=spec,
            ecosystem=Ecosystem.HEX,
            group=DependencyGroup.PROD,
            source=source,
        )

    def test_pinned_returns_immediately(self):
        from licenseal.resolvers.http import fetch_registry_json

        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(spec="==1.7.10"), Ecosystem.HEX, client, fetch_registry_json
            )
        assert v == "1.7.10"

    def test_off_registry_short_circuits(self):
        from licenseal.discovery.hex.mix_lock import _OFF_REGISTRY_MARKER
        from licenseal.resolvers.http import fetch_registry_json

        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(spec="==1.0", source=_OFF_REGISTRY_MARKER),
                Ecosystem.HEX,
                client,
                fetch_registry_json,
            )
        assert v == ""

    @respx.mock
    def test_unpinned_uses_latest_stable(self):
        from licenseal.resolvers.http import fetch_registry_json

        respx.get("https://hex.pm/api/packages/phoenix").mock(
            return_value=httpx.Response(200, json={"latest_stable_version": "1.7.14", "meta": {}})
        )
        with httpx.Client() as client:
            v = _resolve_version(self._dep(spec=""), Ecosystem.HEX, client, fetch_registry_json)
        assert v == "1.7.14"

    @respx.mock
    def test_unpinned_non_dict_returns_empty(self):
        from licenseal.resolvers.http import fetch_registry_json

        respx.get("https://hex.pm/api/packages/x").mock(
            return_value=httpx.Response(200, json=[1, 2])
        )
        with httpx.Client() as client:
            v = _resolve_version(
                self._dep(name="x", spec=""), Ecosystem.HEX, client, fetch_registry_json
            )
        assert v == ""


class TestWalkOneInnerHex:
    @respx.mock
    def test_hex_walker_returns_required_children(self):
        from licenseal.resolvers.http import fetch_registry_json
        from licenseal.transitive import _walk_one_inner

        respx.get("https://hex.pm/api/packages/phoenix/releases/1.7.10").mock(
            return_value=httpx.Response(
                200,
                json={
                    "requirements": {
                        "plug": {"app": "plug", "optional": False, "requirement": "~> 1.14"}
                    }
                },
            )
        )
        dep = Dependency(
            name="phoenix",
            version_constraint="==1.7.10",
            ecosystem=Ecosystem.HEX,
            group=DependencyGroup.PROD,
        )
        with httpx.Client() as client:
            _, ver, children = _walk_one_inner(dep, Ecosystem.HEX, 50, client, fetch_registry_json)
        assert ver == "1.7.10"
        assert [c.name for c in children] == ["plug"]


# ---------------------------------------------------------------------- R / CRAN

_R_DESCRIPTION = "Package: myproj\nLicense: MIT\nImports: ggplot2\nSuggests: testthat\n"

_RENV_LOCK_JSON = json.dumps(
    {
        "Packages": {
            "ggplot2": {
                "Package": "ggplot2",
                "Version": "3.4.0",
                "Source": "Repository",
                "Repository": "CRAN",
                "Requirements": ["cli"],
            },
            "cli": {
                "Package": "cli",
                "Version": "3.6.0",
                "Source": "Repository",
                "Repository": "CRAN",
            },
            "testthat": {
                "Package": "testthat",
                "Version": "3.1.0",
                "Source": "Repository",
                "Repository": "CRAN",
            },
            "myfork": {"Package": "myfork", "Version": "0.1.0", "Source": "GitHub"},
        }
    }
)


class TestRLockfileFirstPath:
    """End-to-end R resolution: DESCRIPTION + renv.lock → lockfile-driven graph."""

    def test_renv_lock_drives_deps_with_edge_attribution(self, tmp_path):
        (tmp_path / "DESCRIPTION").write_text(_R_DESCRIPTION)
        (tmp_path / "renv.lock").write_text(_RENV_LOCK_JSON)
        from licenseal.discovery import discover_all_dependencies
        from licenseal.discovery.r._lock import is_off_registry_marker

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=True, max_depth=50, client=client
            )
        by_name = {d.name: d for d in deps if d.ecosystem == Ecosystem.R}
        assert {"ggplot2", "cli", "testthat", "myfork"} <= set(by_name)
        assert by_name["ggplot2"].depth == 0
        assert by_name["cli"].depth == 1
        assert by_name["cli"].direct_ancestors == ("ggplot2",)
        assert by_name["testthat"].group == DependencyGroup.DEV
        # GitHub-sourced package: off-registry marker preserved.
        assert is_off_registry_marker(by_name["myfork"].source)

    def test_renv_lock_only_no_description(self, tmp_path):
        # renv.lock with NO DESCRIPTION (analysis-project / Shiny-app layout):
        # the lockfile branch must NOT be gated on DESCRIPTION discovery, or
        # these projects yield zero deps. Graph roots become the direct set.
        # All versions are pinned → lockfile-first → no registry calls.
        (tmp_path / "renv.lock").write_text(
            json.dumps(
                {
                    "Packages": {
                        "app": {
                            "Package": "app",
                            "Version": "1.0.0",
                            "Source": "Repository",
                            "Repository": "CRAN",
                            "Requirements": ["helper"],
                        },
                        "helper": {
                            "Package": "helper",
                            "Version": "2.0.0",
                            "Source": "Repository",
                            "Repository": "CRAN",
                        },
                    }
                }
            )
        )
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        assert not any(d.ecosystem == Ecosystem.R for d in direct_deps)  # no manifest deps
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=False, max_depth=50, client=client
            )
        by_name = {d.name: d for d in deps if d.ecosystem == Ecosystem.R}
        assert set(by_name) == {"app", "helper"}
        assert by_name["app"].depth == 0  # graph root → direct
        assert by_name["helper"].direct_ancestors == ("app",)

    def test_dev_only_dropped_under_no_dev(self, tmp_path):
        (tmp_path / "DESCRIPTION").write_text(_R_DESCRIPTION)
        (tmp_path / "renv.lock").write_text(_RENV_LOCK_JSON)
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=False, max_depth=50, client=client
            )
        names = {d.name for d in deps if d.ecosystem == Ecosystem.R}
        assert "testthat" not in names
        assert {"ggplot2", "cli"} <= names

    def test_packrat_lock_drives_deps(self, tmp_path):
        (tmp_path / "DESCRIPTION").write_text("Package: myproj\nImports: ggplot2\n")
        (tmp_path / "packrat").mkdir()
        (tmp_path / "packrat" / "packrat.lock").write_text(
            "PackratFormat: 1.4\nRVersion: 4.3.1\n\n"
            "Package: ggplot2\nSource: CRAN\nVersion: 3.4.0\nRequires: cli\n\n"
            "Package: cli\nSource: CRAN\nVersion: 3.6.0\n"
        )
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=True, max_depth=50, client=client
            )
        by_name = {d.name: d for d in deps if d.ecosystem == Ecosystem.R}
        assert set(by_name) == {"ggplot2", "cli"}
        assert by_name["cli"].direct_ancestors == ("ggplot2",)

    @respx.mock
    @respx.mock
    def test_manifest_only_uses_cran_index(self, tmp_path):
        # No lockfile — the manifest-only closure is walked locally over the
        # official CRAN PACKAGES index (one fetch), not per-package.
        (tmp_path / "DESCRIPTION").write_text("Package: myproj\nImports: ggplot2\n")
        respx.get("https://cran.r-project.org/src/contrib/PACKAGES").mock(
            return_value=httpx.Response(
                200,
                text=(
                    "Package: ggplot2\nVersion: 3.4.0\nImports: cli, rlang\n"
                    "License: MIT + file LICENSE\n\n"
                    "Package: cli\nVersion: 3.6.0\nLicense: MIT + file LICENSE\n\n"
                    "Package: rlang\nVersion: 1.1.0\nLicense: MIT + file LICENSE\n"
                ),
            )
        )
        from licenseal.discovery import discover_all_dependencies

        direct_deps, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct_deps, tmp_path, include_dev=False, max_depth=50, client=client
            )
        by_name = {d.name: d for d in deps if d.ecosystem == Ecosystem.R}
        assert {"ggplot2", "cli", "rlang"} <= set(by_name)
        assert by_name["ggplot2"].depth == 0  # direct
        assert by_name["cli"].depth == 1  # transitive via the index edges
        assert by_name["cli"].direct_ancestors == ("ggplot2",)


class TestRIndexClosure:
    """Direct unit tests for the CRAN-index transitive closure walk."""

    def test_diamond_and_off_index_node(self):
        from licenseal.transitive import _r_index_closure

        # a → b, c ; b → d ; c → d (diamond — d reached twice) ; d → offcran
        # (offcran absent from the index → off-CRAN leaf).
        index = {
            "a": {"Package": "a", "Version": "1.0", "Imports": "b, c", "License": "MIT"},
            "b": {"Package": "b", "Version": "1.0", "Imports": "d", "License": "MIT"},
            "c": {"Package": "c", "Version": "1.0", "Imports": "d", "License": "MIT"},
            "d": {"Package": "d", "Version": "1.0", "Imports": "offcran", "License": "MIT"},
        }
        deps = _r_index_closure([_seed("a", Ecosystem.R)], index, include_dev=True)
        by_name = {d.name: d for d in deps}
        assert set(by_name) == {"a", "b", "c", "d", "offcran"}
        assert by_name["a"].depth == 0
        assert by_name["d"].depth == 1  # diamond child, reached via b and c
        # Off-index node still surfaces (resolves UNKNOWN at the license stage)
        # with no version.
        assert by_name["offcran"].version_constraint == ""
