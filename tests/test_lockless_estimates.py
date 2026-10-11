"""A scan without a lockfile is an estimate, and says so.

Two things mark it. Each row whose version licenseal picked from a registry
is ``version_estimated``: every transitive a registry walk adds, and a direct
dependency declared with a range or with no constraint. And each manifest
that declares a direct dependency resolved without a lockfile gets one
diagnostic, a gap unless ``--no-require-lockfile`` accepts it.

What must stay unmarked: a row a lockfile supplies, an exact pin in a
manifest, and every Go version.
"""

from __future__ import annotations

import io
import json
import sys
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import (
    ReadDiagnostic,
    collect_read_diagnostics,
    record_missing_lockfile,
)
from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers.http import RegistryCache
from licenseal.transitive import (
    _dedupe,
    _record_missing_lockfiles,
    declares_exact_version,
    flag_version_estimate,
    resolve_transitive,
)
from tests._helpers import _check_json, _mock_npm, _mock_pypi, _write

_MISSING = (
    "declares dependencies that no lockfile covers; their versions and "
    "transitive dependencies are estimated from the registry"
)
_UNRECORDED = (
    "declares off-registry dependencies that no lockfile records; "
    "what they depend on is not in this report"
)


def _scan(project: Path, *, include_dev: bool = True) -> tuple[dict[str, tuple[str, bool]], list]:
    """Discover and expand ``project`` against the mocked registries.

    Goes through a real ``RegistryCache``, as the CLI does. Returns the rows
    as ``{name: (version_constraint, version_estimated)}`` and the manifests
    recorded as lacking a lockfile, project-relative.
    """
    cache = RegistryCache()
    with collect_read_diagnostics() as diags, httpx.Client() as client:
        direct, _ = discover_all_dependencies(project)
        deps = resolve_transitive(
            direct,
            project,
            include_dev=include_dev,
            max_depth=50,
            client=client,
            fetcher=cache.fetch,
            pom_fetcher=cache.fetch_text,
        )
    assert all(
        d.is_gap and d.missing_lockfile and d.reason in (_MISSING, _UNRECORDED) for d in diags
    )
    rows = {d.name: (d.version_constraint, d.version_estimated) for d in deps}
    assert len(rows) == len(deps)
    return rows, sorted(d.path.relative_to(project).as_posix() for d in diags)


def _json(url: str, payload: dict) -> None:
    respx.get(url).mock(return_value=httpx.Response(200, json=payload))


def _text(url: str, body: str) -> None:
    respx.get(url).mock(return_value=httpx.Response(200, text=body))


def _dep(
    ecosystem: Ecosystem, constraint: str, *, name: str = "pkg", source: str = "manifest"
) -> Dependency:
    return Dependency(name=name, version_constraint=constraint, ecosystem=ecosystem, source=source)


class TestExactVersion:
    @pytest.mark.parametrize(
        ("ecosystem", "constraint"),
        [
            (Ecosystem.PYTHON, "==2.28.1"),
            (Ecosystem.PYTHON, "===2.28.1"),
            (Ecosystem.NPM, "18.2.0"),
            (Ecosystem.NPM, "==18.2.0"),
            (Ecosystem.NPM, "=18.2.0"),
            (Ecosystem.NPM, "= 18.2.0"),
            (Ecosystem.NPM, "v18.2.0"),
            (Ecosystem.NPM, "=v18.2.0"),
            (Ecosystem.RUST, "=1.0.193"),
            (Ecosystem.RUST, "==1.0.193"),
            (Ecosystem.JAVA, "1.0.0"),
            (Ecosystem.JAVA, "==33.0.0-jre"),
            (Ecosystem.DOTNET, "13.0.1"),
            (Ecosystem.DOTNET, "[13.0.1]"),
            (Ecosystem.DOTNET, "==13.0.1"),
            (Ecosystem.PHP, "==3.5.0"),
            (Ecosystem.RUBY, "= 7.0.0"),
            (Ecosystem.RUBY, "==7.0.0"),
            (Ecosystem.HEX, "== 1.7.0"),
            (Ecosystem.R, "==1.6-1"),
            # Whatever go.mod and go.sum hold is an exact version.
            (Ecosystem.GO, "v1.2.3"),
            (Ecosystem.GO, ""),
        ],
    )
    def test_exact_constraint_is_not_an_estimate(self, ecosystem, constraint):
        dep = _dep(ecosystem, constraint)
        assert declares_exact_version(dep)
        assert flag_version_estimate(dep) is dep

    @pytest.mark.parametrize(
        ("ecosystem", "constraint"),
        [
            (Ecosystem.PYTHON, ">=2.0"),
            (Ecosystem.PYTHON, "~=2.28"),
            (Ecosystem.PYTHON, "==2.*"),
            (Ecosystem.PYTHON, ""),
            (Ecosystem.NPM, "^18.2.0"),
            (Ecosystem.NPM, "=18.2"),
            (Ecosystem.NPM, ">=18.2.0"),
            (Ecosystem.NPM, "=18.2.0 || =19.0.0"),
            (Ecosystem.NPM, "latest"),
            (Ecosystem.NPM, ""),
            (Ecosystem.RUST, "1.0"),
            (Ecosystem.RUST, "^1.0"),
            (Ecosystem.RUST, ""),
            (Ecosystem.JAVA, "[1.0,2.0)"),
            (Ecosystem.JAVA, ""),
            (Ecosystem.JAVA, "${managed.version}"),
            (Ecosystem.DOTNET, "[1.0.0,2.0.0)"),
            (Ecosystem.DOTNET, "(1.0.0,)"),
            (Ecosystem.DOTNET, "1.*"),
            (Ecosystem.DOTNET, ""),
            (Ecosystem.PHP, "^3.5"),
            (Ecosystem.PHP, ""),
            (Ecosystem.RUBY, "~> 7.0"),
            (Ecosystem.RUBY, ""),
            (Ecosystem.HEX, "~> 1.7"),
            (Ecosystem.HEX, ""),
            (Ecosystem.R, ">= 1.0"),
            (Ecosystem.R, ""),
        ],
    )
    def test_range_or_no_constraint_is_an_estimate(self, ecosystem, constraint):
        dep = _dep(ecosystem, constraint)
        assert not declares_exact_version(dep)
        flagged = flag_version_estimate(dep)
        assert flagged.version_estimated
        assert flagged.version_constraint == constraint

    def test_dependency_with_an_origin_is_never_an_estimate(self):
        # No registry is asked about it, so no version is picked for it,
        # whatever its constraint reads.
        for ecosystem in Ecosystem:
            dep = replace(_dep(ecosystem, ""), origin="git+https://example.invalid/pkg.git")
            assert flag_version_estimate(dep) is dep

    def test_every_ecosystem_but_go_has_an_exact_pin_check(self):
        # A new ecosystem without one would read every constraint as exact.
        unchecked = [
            ecosystem for ecosystem in Ecosystem if declares_exact_version(_dep(ecosystem, ""))
        ]
        assert unchecked == [Ecosystem.GO]


class TestRecordMissingLockfiles:
    def _recorded(self, tmp_path: Path, deps: list[Dependency]) -> list[str]:
        with collect_read_diagnostics() as diags:
            _record_missing_lockfiles(tmp_path, deps)
        return [d.path.relative_to(tmp_path).as_posix() for d in diags]

    def test_one_diagnostic_per_manifest(self, tmp_path: Path):
        deps = [
            _dep(Ecosystem.NPM, "^1", name="a", source="web/package.json"),
            _dep(Ecosystem.NPM, "^1", name="b", source="web/package.json"),
            _dep(Ecosystem.NPM, "^1", name="c", source="package.json"),
        ]
        assert self._recorded(tmp_path, deps) == ["package.json", "web/package.json"]

    @pytest.mark.parametrize(
        "source",
        [
            "pom.xml",
            "services/api/pom.xml",
            "packages.config",
            "legacy/packages.config",
            "Makefile",
        ],
    )
    def test_manifest_of_a_tool_with_no_lockfile_format_is_not_recorded(
        self, tmp_path: Path, source
    ):
        assert self._recorded(tmp_path, [_dep(Ecosystem.JAVA, "1.0", source=source)]) == []

    def test_dependency_without_a_manifest_path_is_not_recorded(self, tmp_path: Path):
        assert self._recorded(tmp_path, [_dep(Ecosystem.RUBY, "", source="")]) == []

    def test_dependency_with_an_origin_is_recorded_with_a_reason_of_its_own(self, tmp_path: Path):
        # Nothing is fetched for it, so without a lockfile what it depends
        # on is listed nowhere. A registry gem beside it is the other reason.
        forked = replace(
            _dep(Ecosystem.RUBY, "", name="forked", source="Gemfile"),
            origin="git+https://example.invalid/forked.git",
        )
        other = replace(forked, name="other-fork")
        published = _dep(Ecosystem.RUBY, "", name="published", source="Gemfile")
        with collect_read_diagnostics() as diags:
            _record_missing_lockfiles(tmp_path, [forked, published, other])
        assert diags == [
            ReadDiagnostic(tmp_path / "Gemfile", _MISSING, is_gap=True, missing_lockfile=True),
            ReadDiagnostic(tmp_path / "Gemfile", _UNRECORDED, is_gap=True, missing_lockfile=True),
        ]

    def test_manifest_with_no_lockfile_format_is_not_recorded_for_an_origin_either(
        self, tmp_path: Path
    ):
        local_jar = replace(
            _dep(Ecosystem.JAVA, "1.0", source="pom.xml"), origin="${basedir}/lib/local.jar"
        )
        assert self._recorded(tmp_path, [local_jar]) == []

    def test_diagnostic_is_a_gap_marked_as_missing_lockfile(self, tmp_path: Path):
        with collect_read_diagnostics() as diags:
            record_missing_lockfile(tmp_path / "package.json")
        assert diags == [
            ReadDiagnostic(
                path=tmp_path / "package.json",
                reason=_MISSING,
                is_gap=True,
                missing_lockfile=True,
            )
        ]


class TestDedupe:
    def _row(self, *, estimated: bool, depth: int = 1) -> Dependency:
        return Dependency(
            name="shared",
            version_constraint="==1.0.0",
            ecosystem=Ecosystem.NPM,
            depth=depth,
            version_estimated=estimated,
        )

    @pytest.mark.parametrize("order", [(True, False), (False, True)])
    def test_version_a_lockfile_also_fixes_is_not_an_estimate(self, order):
        # One copy from a registry walk, one from a lockfile, in either order.
        merged = _dedupe([self._row(estimated=flag) for flag in order])
        assert [d.version_estimated for d in merged] == [False]

    def test_version_only_walks_found_stays_an_estimate(self):
        merged = _dedupe([self._row(estimated=True), self._row(estimated=True, depth=2)])
        assert [d.version_estimated for d in merged] == [True]


class TestRegistryWalkPerEcosystem:
    """No lockfile: the direct deps are walked, and the rows say what was picked."""

    @respx.mock
    def test_npm(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"ranged": "^1.0.0", "pinned": "2.0.0"}})
        )
        _json(
            "https://registry.npmjs.org/ranged",
            {"versions": {"1.0.0": {"version": "1.0.0"}, "1.5.0": {"version": "1.5.0"}}},
        )
        _json(
            "https://registry.npmjs.org/ranged/1.5.0",
            {"version": "1.5.0", "dependencies": {"child": "1.0.0"}},
        )
        _json("https://registry.npmjs.org/pinned/2.0.0", {"version": "2.0.0"})
        _json("https://registry.npmjs.org/child/1.0.0", {"version": "1.0.0"})

        rows, missing = _scan(tmp_path)
        assert rows == {
            "ranged": ("==1.5.0", True),
            "pinned": ("==2.0.0", False),
            # Pinned exactly by its parent, but the parent's version is a pick.
            "child": ("==1.0.0", True),
        }
        assert missing == ["package.json"]

    @pytest.mark.parametrize("spec", ["2.0.0", "=2.0.0", "= 2.0.0", "v2.0.0", "=v2.0.0"])
    @respx.mock
    def test_npm_exact_version_in_any_spelling(self, tmp_path: Path, spec: str):
        # One exact version, bare or behind ``=`` or ``v``: the registry is
        # asked for that version (the package's version list is not served
        # here), and the row is not an estimate. Its child is: the walk
        # picked it, which is also why the manifest is still recorded as
        # having no lockfile, exactly as for the bare spelling.
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"pinned": spec}}))
        _json(
            "https://registry.npmjs.org/pinned/2.0.0",
            {"version": "2.0.0", "dependencies": {"child": "^1.0.0"}},
        )
        _json("https://registry.npmjs.org/child", {"versions": {"1.2.0": {"version": "1.2.0"}}})
        _json("https://registry.npmjs.org/child/1.2.0", {"version": "1.2.0"})

        rows, missing = _scan(tmp_path)
        assert rows == {"pinned": ("==2.0.0", False), "child": ("==1.2.0", True)}
        assert missing == ["package.json"]

    @respx.mock
    def test_python(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("ranged>=1.0\npinned==2.0.0\nbare\n")

        def release(name: str, version: str, requires: list[str]) -> None:
            _json(
                f"https://pypi.org/pypi/{name}/{version}/json",
                {"info": {"version": version, "requires_dist": requires}},
            )

        _json(
            "https://pypi.org/pypi/ranged/json",
            {"info": {"version": "1.2.0"}, "releases": {"1.0.0": [], "1.2.0": []}},
        )
        release("ranged", "1.2.0", ["child==3.0.0"])
        release("pinned", "2.0.0", [])
        _json("https://pypi.org/pypi/bare/json", {"info": {"version": "4.0.0"}, "releases": {}})
        release("bare", "4.0.0", [])
        release("child", "3.0.0", [])

        rows, missing = _scan(tmp_path)
        assert rows == {
            "ranged": ("==1.2.0", True),
            "pinned": ("==2.0.0", False),
            "bare": ("==4.0.0", True),
            "child": ("==3.0.0", True),
        }
        assert missing == ["requirements.txt"]

    @respx.mock
    def test_rust(self, tmp_path: Path):
        _write(
            tmp_path / "Cargo.toml",
            """\
            [package]
            name = "app"
            version = "0.1.0"

            [dependencies]
            caret = "1.0"
            exact = "=2.0.0"
            """,
        )
        crates = "https://crates.io/api/v1/crates"
        _json(f"{crates}/caret", {"crate": {"max_stable_version": "1.4.0"}})
        _json(
            f"{crates}/caret/1.4.0/dependencies",
            {"dependencies": [{"crate_id": "child", "kind": "normal", "req": "^1"}]},
        )
        _json(f"{crates}/child", {"crate": {"max_stable_version": "1.0.1"}})
        _json(f"{crates}/child/1.0.1/dependencies", {"dependencies": []})
        _json(f"{crates}/exact/2.0.0/dependencies", {"dependencies": []})

        rows, missing = _scan(tmp_path)
        assert rows == {
            "caret": ("==1.4.0", True),
            "exact": ("==2.0.0", False),
            "child": ("==1.0.1", True),
        }
        assert missing == ["Cargo.toml"]

    @respx.mock
    def test_php(self, tmp_path: Path):
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/ranged": "^1.0"}}))
        _json(
            "https://repo.packagist.org/p2/vendor/ranged.json",
            {
                "packages": {
                    "vendor/ranged": [
                        {"version": "1.2.0", "require": {"vendor/child": "^2.0"}},
                        {"version": "1.0.0"},
                    ]
                }
            },
        )
        _json(
            "https://repo.packagist.org/p2/vendor/child.json",
            {"packages": {"vendor/child": [{"version": "2.1.0"}]}},
        )

        rows, missing = _scan(tmp_path)
        assert rows == {"vendor/ranged": ("==1.2.0", True), "vendor/child": ("==2.1.0", True)}
        assert missing == ["composer.json"]

    @respx.mock
    def test_ruby(self, tmp_path: Path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\ngem "ranged", "~> 1.0"\ngem "exact", "= 2.0.0"\n'
        )
        gems = "https://rubygems.org/api"
        _json(f"{gems}/v1/gems/ranged.json", {"version": "1.3.0"})
        _json(
            f"{gems}/v2/rubygems/ranged/versions/1.3.0.json",
            {"dependencies": {"runtime": [{"name": "child", "requirements": ">= 0"}]}},
        )
        _json(f"{gems}/v1/gems/child.json", {"version": "0.5.0"})
        _json(f"{gems}/v2/rubygems/child/versions/0.5.0.json", {"dependencies": {"runtime": []}})
        _json(f"{gems}/v2/rubygems/exact/versions/2.0.0.json", {"dependencies": {"runtime": []}})

        rows, missing = _scan(tmp_path)
        assert rows == {
            "ranged": ("==1.3.0", True),
            "exact": ("==2.0.0", False),
            "child": ("==0.5.0", True),
        }
        assert missing == ["Gemfile"]

    @respx.mock
    def test_off_registry_gem_alone_is_no_estimate_and_still_lacks_a_lockfile(self, tmp_path: Path):
        # A git gem is not looked up on the registry: no version is picked
        # for it, so it is not an estimate. What it requires is listed only
        # by a lockfile, so the Gemfile is recorded all the same.
        (tmp_path / "Gemfile").write_text('gem "forked", git: "https://example.invalid/f.git"\n')
        rows, missing = _scan(tmp_path)
        assert rows == {"forked": ("", False)}
        assert missing == ["Gemfile"]

    def _mock_hex(self) -> None:
        hexpm = "https://hex.pm/api/packages"
        _json(f"{hexpm}/ranged", {"latest_stable_version": "1.2.0"})
        _json(
            f"{hexpm}/ranged/releases/1.2.0",
            {"requirements": {"child": {"requirement": "~> 0.1", "optional": False}}},
        )
        _json(f"{hexpm}/child", {"latest_stable_version": "0.1.5"})
        _json(f"{hexpm}/child/releases/0.1.5", {"requirements": {}})
        _json(f"{hexpm}/exact/releases/2.0.0", {"requirements": {}})

    @respx.mock
    def test_hex_mix(self, tmp_path: Path):
        _write(
            tmp_path / "mix.exs",
            """\
            defmodule App.MixProject do
              use Mix.Project

              defp deps do
                [
                  {:ranged, "~> 1.0"},
                  {:exact, "== 2.0.0"}
                ]
              end
            end
            """,
        )
        self._mock_hex()
        rows, missing = _scan(tmp_path)
        assert rows == {
            "ranged": ("==1.2.0", True),
            "exact": ("==2.0.0", False),
            "child": ("==0.1.5", True),
        }
        assert missing == ["mix.exs"]

    @respx.mock
    def test_hex_rebar(self, tmp_path: Path):
        (tmp_path / "rebar.config").write_text('{deps, [{ranged, "~> 1.0"}]}.\n')
        self._mock_hex()
        rows, missing = _scan(tmp_path)
        assert rows == {"ranged": ("==1.2.0", True), "child": ("==0.1.5", True)}
        assert missing == ["rebar.config"]

    @respx.mock
    def test_erlang_mk_has_no_lockfile_to_ask_for(self, tmp_path: Path):
        # The rows are estimates all the same; only the diagnostic is withheld.
        (tmp_path / "Makefile").write_text(
            "PROJECT = app\nDEPS = ranged exact\ndep_exact = hex 2.0.0\ninclude erlang.mk\n"
        )
        self._mock_hex()
        rows, missing = _scan(tmp_path)
        assert rows == {
            "ranged": ("==1.2.0", True),
            "exact": ("==2.0.0", False),
            "child": ("==0.1.5", True),
        }
        assert missing == []

    @respx.mock
    def test_r(self, tmp_path: Path):
        (tmp_path / "DESCRIPTION").write_text("Package: app\nImports: ranged (>= 1.0)\n")
        _text(
            "https://cran.r-project.org/src/contrib/PACKAGES",
            "Package: ranged\nVersion: 1.4\nImports: child\nLicense: MIT\n\n"
            "Package: child\nVersion: 0.3\nLicense: GPL-2\n",
        )
        rows, missing = _scan(tmp_path)
        # The index holds current versions only, so every row is its pick.
        assert rows == {"ranged": ("==1.4", True), "child": ("==0.3", True)}
        assert missing == ["DESCRIPTION"]

    def _mock_maven_graph(self) -> None:
        def node(name: str, version: str, relation: str) -> dict:
            return {
                "versionKey": {"system": "MAVEN", "name": name, "version": version},
                "relation": relation,
            }

        _json(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Alib/versions/1.0.0"
            ":dependencies",
            {
                "nodes": [
                    node("com.example:lib", "1.0.0", "SELF"),
                    node("com.example:child", "2.0.0", "DIRECT"),
                ],
                "edges": [{"fromNode": 0, "toNode": 1}],
            },
        )

    @respx.mock
    def test_gradle_build_file(self, tmp_path: Path):
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n    implementation 'com.example:lib:1.0.0'\n}\n"
        )
        self._mock_maven_graph()
        rows, missing = _scan(tmp_path)
        assert rows == {
            "com.example:lib": ("==1.0.0", False),
            "com.example:child": ("==2.0.0", True),
        }
        assert missing == ["build.gradle"]

    @respx.mock
    def test_maven_has_no_lockfile_to_ask_for(self, tmp_path: Path):
        _write(
            tmp_path / "pom.xml",
            """\
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <groupId>com.example</groupId>
              <artifactId>app</artifactId>
              <version>1.0.0</version>
              <dependencies>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>lib</artifactId>
                  <version>1.0.0</version>
                </dependency>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>ranged</artifactId>
                  <version>[1.0,2.0)</version>
                </dependency>
              </dependencies>
            </project>
            """,
        )
        self._mock_maven_graph()
        rows, missing = _scan(tmp_path)
        assert rows == {
            "com.example:lib": ("==1.0.0", False),
            "com.example:ranged": ("[1.0,2.0)", True),
            "com.example:child": ("==2.0.0", True),
        }
        assert missing == []

    def _mock_nuspecs(self) -> None:
        def nuspec(package_id: str, version: str, dependencies: str = "") -> None:
            lowered = package_id.lower()
            _text(
                f"https://api.nuget.org/v3-flatcontainer/{lowered}/{version}/{lowered}.nuspec",
                f"<package><metadata><id>{package_id}</id><version>{version}</version>"
                f"<dependencies>{dependencies}</dependencies></metadata></package>",
            )

        nuspec("Exact", "1.0.0", '<dependency id="Child" version="1.5.0" />')
        nuspec("Ranged", "2.0.0")
        nuspec("Child", "1.5.0")

    @respx.mock
    def test_dotnet_project_file(self, tmp_path: Path):
        _write(
            tmp_path / "App.csproj",
            """\
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Exact" Version="1.0.0" />
                <PackageReference Include="Ranged" Version="[2.0.0,3.0.0)" />
                <PackageReference Include="Floating" Version="1.*" />
                <PackageReference Include="Unlisted" Version="1.*" />
              </ItemGroup>
            </Project>
            """,
        )
        self._mock_nuspecs()
        # A floating version is resolved against the package's version list;
        # with no list served, the row keeps what the project declares.
        _text(
            "https://api.nuget.org/v3-flatcontainer/floating/index.json",
            '{"versions": ["1.0.0", "1.3.0", "2.0.0"]}',
        )
        _text(
            "https://api.nuget.org/v3-flatcontainer/floating/1.3.0/floating.nuspec",
            "<package><metadata><id>Floating</id><version>1.3.0</version></metadata></package>",
        )
        respx.get("https://api.nuget.org/v3-flatcontainer/unlisted/index.json").respond(404)
        rows, missing = _scan(tmp_path)
        assert rows == {
            "Exact": ("==1.0.0", False),
            "Ranged": ("==2.0.0", True),
            "Floating": ("==1.3.0", True),
            "Unlisted": ("1.*", True),
            "Child": ("==1.5.0", True),
        }
        assert missing == ["App.csproj"]

    @respx.mock
    def test_packages_config_has_no_lockfile_to_ask_for(self, tmp_path: Path):
        (tmp_path / "packages.config").write_text(
            '<packages><package id="Exact" version="1.0.0" /></packages>'
        )
        self._mock_nuspecs()
        rows, missing = _scan(tmp_path)
        assert rows == {"Exact": ("==1.0.0", False), "Child": ("==1.5.0", True)}
        assert missing == []

    @respx.mock
    def test_paket_dependencies_without_paket_lock(self, tmp_path: Path):
        (tmp_path / "paket.dependencies").write_text(
            "source https://api.nuget.org/v3/index.json\nnuget Exact 1.0.0\n"
        )
        self._mock_nuspecs()
        rows, missing = _scan(tmp_path)
        assert rows == {"Exact": ("==1.0.0", False), "Child": ("==1.5.0", True)}
        assert missing == ["paket.dependencies"]

    @respx.mock
    def test_go_versions_are_exact_and_nothing_is_recorded(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\ngo 1.22\n\nrequire example.com/lib v1.2.3\n"
        )
        _text("https://proxy.golang.org/example.com/lib/@v/v1.2.3.mod", "module example.com/lib\n")
        rows, missing = _scan(tmp_path)
        assert rows == {"example.com/lib": ("v1.2.3", False)}
        assert missing == []


class TestLockfileCoverage:
    _LOCK = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"locked": "^1.0.0"}},
            "node_modules/locked": {"version": "1.0.0", "dependencies": {"inner": "^1.0.0"}},
            "node_modules/inner": {"version": "1.1.0"},
        },
    }

    def _locked_project(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"locked": "^1.0.0"}}))
        (tmp_path / "package-lock.json").write_text(json.dumps(self._LOCK))

    def test_fully_locked_project_has_no_estimate(self, tmp_path: Path):
        self._locked_project(tmp_path)
        rows, missing = _scan(tmp_path)
        assert rows == {"locked": ("==1.0.0", False), "inner": ("==1.1.0", False)}
        assert missing == []

    @respx.mock
    def test_direct_dependency_a_present_lockfile_does_not_cover(self, tmp_path: Path):
        # A nested manifest outside the root install: the lockfile has no
        # entry for what it declares, so that one is walked.
        self._locked_project(tmp_path)
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "package.json").write_text(
            json.dumps({"dependencies": {"extra": "^2.0.0"}})
        )
        _json("https://registry.npmjs.org/extra", {"versions": {"2.3.0": {"version": "2.3.0"}}})
        _json("https://registry.npmjs.org/extra/2.3.0", {"version": "2.3.0"})

        rows, missing = _scan(tmp_path)
        assert rows == {
            "locked": ("==1.0.0", False),
            "inner": ("==1.1.0", False),
            "extra": ("==2.3.0", True),
        }
        assert missing == ["tools/package.json"]

    def test_uncovered_dev_dependency_is_not_walked_without_dev(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"tool": "^1"}}))
        rows, missing = _scan(tmp_path, include_dev=False)
        assert rows == {}
        assert missing == []

    @respx.mock
    def test_walked_version_a_lockfile_also_pins_is_exact(self, tmp_path: Path):
        # The uncovered manifest's dependency resolves to the very version
        # the lockfile pins for the root: one row, and the lockfile fixes it.
        self._locked_project(tmp_path)
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "package.json").write_text(
            json.dumps({"dependencies": {"extra": "^2.0.0"}})
        )
        _json("https://registry.npmjs.org/extra", {"versions": {"2.3.0": {"version": "2.3.0"}}})
        _json(
            "https://registry.npmjs.org/extra/2.3.0",
            {"version": "2.3.0", "dependencies": {"inner": "1.1.0"}},
        )
        _json("https://registry.npmjs.org/inner/1.1.0", {"version": "1.1.0"})

        rows, missing = _scan(tmp_path)
        assert rows["inner"] == ("==1.1.0", False)
        assert rows["extra"] == ("==2.3.0", True)
        assert missing == ["tools/package.json"]


class TestCheckCommand:
    """The diagnostic is a gap by default and an accepted estimate on request."""

    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "package.json").write_text(
            json.dumps({"license": "MIT", "dependencies": {"ranged": "^1.0.0", "pinned": "1.0.0"}})
        )
        _mock_npm("ranged", "MIT")
        _mock_npm("pinned", "MIT")
        return tmp_path

    @respx.mock
    def test_default_is_a_gap_that_fails_strict(self, tmp_path: Path):
        result, data = _check_json(self._project(tmp_path))
        assert result.exit_code == 1
        assert data["summary"]["gaps"] == 1
        assert data["summary"]["ok"] == 2
        assert data["diagnostics"] == [
            {"path": "package.json", "reason": _MISSING, "severity": "gap"}
        ]
        assert f"Warning: package.json: {_MISSING}" in result.output
        assert "1 manifest(s) could not be fully analyzed" in result.output
        assert "(fails --strict)" in result.output
        # The two ways out.
        assert (
            "Warning: 1 manifest(s) declare dependencies that no lockfile covers, so the "
            "report is an estimate for them. Commit a lockfile, or pass "
            "--no-require-lockfile to accept the estimate." in result.output
        )

    @respx.mock
    def test_explicit_require_lockfile_is_the_default(self, tmp_path: Path):
        result, data = _check_json(self._project(tmp_path), "--require-lockfile")
        assert result.exit_code == 1
        assert data["diagnostics"][0]["severity"] == "gap"

    @respx.mock
    def test_no_require_lockfile_reports_an_estimate_and_passes(self, tmp_path: Path):
        result, data = _check_json(self._project(tmp_path), "--no-require-lockfile")
        assert result.exit_code == 0
        assert data["summary"]["gaps"] == 0
        assert data["diagnostics"] == [
            {"path": "package.json", "reason": _MISSING, "severity": "estimate"}
        ]
        assert f"Warning: package.json: {_MISSING}" in result.output
        assert "could not be fully analyzed" not in result.output
        assert (
            "report is an estimate for them (accepted by --no-require-lockfile). Commit a "
            "lockfile for an exact report." in result.output
        )

    @respx.mock
    def test_no_strict_passes_with_the_gap_still_counted(self, tmp_path: Path):
        result, data = _check_json(self._project(tmp_path), "--no-strict")
        assert result.exit_code == 0
        assert data["summary"]["gaps"] == 1
        assert data["diagnostics"][0]["severity"] == "gap"
        assert "(fails --strict)" not in result.output
        assert "pass --no-require-lockfile to accept the estimate" in result.output

    @respx.mock
    def test_json_marks_the_estimated_versions(self, tmp_path: Path):
        _, data = _check_json(self._project(tmp_path), "--no-require-lockfile")
        assert {d["name"]: d["estimated"] for d in data["dependencies"]} == {
            "ranged": ["version"],
            "pinned": [],
        }

    @respx.mock
    def test_no_transitive_labels_rows_and_records_nothing(self, tmp_path: Path):
        # No lockfile is consulted and no graph is claimed, so there is no
        # gap; the range still resolves to a version the registry picked.
        result, data = _check_json(self._project(tmp_path), "--no-transitive")
        assert result.exit_code == 0
        assert data["diagnostics"] == []
        assert data["summary"]["gaps"] == 0
        assert "no lockfile covers" not in result.output
        assert {d["name"]: d["estimated"] for d in data["dependencies"]} == {
            "ranged": ["version"],
            "pinned": [],
        }

    @respx.mock
    def test_no_transitive_ignores_a_lockfile_that_is_present(self, tmp_path: Path):
        project = self._project(tmp_path)
        (project / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"ranged": "^1.0.0", "pinned": "1.0.0"}},
                        "node_modules/ranged": {"version": "1.0.0"},
                        "node_modules/pinned": {"version": "1.0.0"},
                    },
                }
            )
        )
        _, direct_only = _check_json(project, "--no-transitive")
        assert {d["name"]: d["estimated"] for d in direct_only["dependencies"]} == {
            "ranged": ["version"],
            "pinned": [],
        }
        # The same project with its lockfile read: nothing is estimated.
        locked, data = _check_json(project)
        assert locked.exit_code == 0
        assert [d["estimated"] for d in data["dependencies"]] == [[], []]
        assert data["diagnostics"] == []

    @respx.mock
    def test_unresolved_dependency_has_no_version_to_mark(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"gone": "^1.0.0"}}))
        respx.get("https://registry.npmjs.org/gone").mock(return_value=httpx.Response(404))
        (tmp_path / "requirements.txt").write_text("found\n")
        _mock_pypi("found", "MIT")
        _, data = _check_json(tmp_path, "--no-strict")
        rows = {d["name"]: (d["resolved_version"], d["estimated"]) for d in data["dependencies"]}
        assert rows == {"gone": ("", []), "found": ("1.0.0", ["version"])}

    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    @pytest.mark.parametrize("spec", ["=1.0.0", "= 1.0.0", "v1.0.0"])
    @respx.mock
    def test_npm_version_behind_an_equals_sign_is_not_marked(
        self, tmp_path: Path, mode: str, spec: str
    ):
        # ``=1.0.0`` names one version, as ``1.0.0`` does. Only that version
        # is served: the package's version list is never asked for.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": {"pinned": spec}})
        )
        _json("https://registry.npmjs.org/pinned/1.0.0", {"version": "1.0.0", "license": "MIT"})
        result, data = _check_json(tmp_path, mode, "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        (row,) = data["dependencies"]
        assert (row["name"], row["resolved_version"], row["license"], row["estimated"]) == (
            "pinned",
            "1.0.0",
            "MIT",
            [],
        )

    @respx.mock
    def test_pinned_release_missing_from_pypi_keeps_its_version(self, tmp_path: Path):
        # A lockfile pins a build published on another index. PyPI has no
        # metadata for it or for the public release of that number, so the
        # license is the latest release's. The version is still the locked
        # one, which is no estimate.
        _write(
            tmp_path / "pyproject.toml",
            """\
            [project]
            name = "app"
            version = "0.1.0"
            license = "MIT"
            dependencies = ["accelerated"]
            """,
        )
        _write(
            tmp_path / "uv.lock",
            """\
            version = 1

            [[package]]
            name = "app"
            version = "0.1.0"
            source = { virtual = "." }
            dependencies = [{ name = "accelerated" }]

            [[package]]
            name = "accelerated"
            version = "2.1.0+local"
            source = { registry = "https://example.invalid/simple" }
            """,
        )
        for missing in ("2.1.0+local", "2.1.0"):
            respx.get(f"https://pypi.org/pypi/accelerated/{missing}/json").mock(
                return_value=httpx.Response(404)
            )
        _json(
            "https://pypi.org/pypi/accelerated/json",
            {"info": {"version": "2.5.0", "license": "MIT"}, "releases": {"2.5.0": []}},
        )
        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert data["diagnostics"] == []
        (row,) = data["dependencies"]
        assert (row["resolved_version"], row["license"], row["estimated"]) == (
            "2.1.0+local",
            "MIT",
            ["license"],
        )


class TestReportFormats:
    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "package.json").write_text(
            json.dumps({"license": "MIT", "dependencies": {"ranged": "^1.0.0", "pinned": "1.0.0"}})
        )
        _mock_npm("ranged", "MIT")
        _mock_npm("pinned", "MIT")
        return tmp_path

    def _render(self, project: Path, fmt: str, *flags: str) -> str:
        out = project / f"report.{fmt}"
        CliRunner().invoke(
            main, ["check", "--path", str(project), *flags, "-f", fmt, "-o", str(out)]
        )
        return out.read_text(encoding="utf-8")

    @respx.mock
    def test_markdown_marks_the_version_and_adds_one_legend_line(self, tmp_path: Path):
        md = self._render(self._project(tmp_path), "markdown")
        assert "[ranged (~1.0.0)](https://www.npmjs.com/package/ranged)" in md
        assert "[pinned (1.0.0)](https://www.npmjs.com/package/pinned)" in md
        legend = (
            "`~` marks an estimate: a version picked from the registry (not locked or pinned), "
            "or a license read from metadata for another release"
        )
        lines = md.splitlines()
        assert lines.count(legend) == 1
        # Its own paragraph between the table and the summary.
        at = lines.index(legend)
        assert lines[at - 1] == "" and lines[at + 1] == ""
        assert lines[at - 2].startswith("|")
        assert lines[at + 2].startswith("**Summary:**")

    @respx.mock
    def test_markdown_lists_the_gap_by_default(self, tmp_path: Path):
        md = self._render(self._project(tmp_path), "markdown")
        assert "**Summary:** 0 violations, 0 warnings, 0 unknown, 2 ok, 1 analysis gap" in md
        assert "## Analysis gaps" in md
        assert f"|[package.json](package.json)|{_MISSING}|" in md
        assert "## Estimates" not in md

    @respx.mock
    def test_markdown_lists_an_accepted_estimate_in_its_own_section(self, tmp_path: Path):
        md = self._render(self._project(tmp_path), "markdown", "--no-require-lockfile")
        assert "**Summary:** 0 violations, 0 warnings, 0 unknown, 2 ok, 1 estimated manifest" in md
        assert "## Analysis gaps" not in md
        section = md[md.index("## Estimates") :]
        assert (
            "These manifests were scanned without a lockfile; the versions and transitive "
            "dependencies reported for them are estimates." in section
        )
        assert f"|[package.json](package.json)|{_MISSING}|" in section

    @respx.mock
    def test_table_marks_the_version_and_adds_one_legend_line(self, tmp_path: Path):
        table = self._render(self._project(tmp_path), "table")
        assert "ranged (~1.0.0)" in table
        assert "pinned (1.0.0)" in table
        legend = (
            "~ marks an estimate: a version picked from the registry (not locked or pinned), "
            "or a license read from metadata for another release\n"
        )
        assert table.count(legend) == 1
        assert "1 analysis gap" in table
        assert "Analysis gaps" in table
        assert f"package.json: {_MISSING}" in " ".join(table.split())
        assert "Estimates" not in table

    @respx.mock
    def test_table_lists_an_accepted_estimate_in_its_own_section(self, tmp_path: Path):
        table = self._render(self._project(tmp_path), "table", "--no-require-lockfile")
        assert "2 ok, 1 estimated manifest" in table
        assert "Analysis gaps" not in table
        flat = " ".join(table.split())
        assert (
            "Estimates (the versions and transitive dependencies reported for them are "
            "estimates):" in flat
        )
        assert f"package.json: {_MISSING}" in flat

    @respx.mock
    def test_locked_project_has_no_mark_and_no_legend(self, tmp_path: Path):
        project = self._project(tmp_path)
        (project / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"ranged": "^1.0.0", "pinned": "1.0.0"}},
                        "node_modules/ranged": {"version": "1.0.0"},
                        "node_modules/pinned": {"version": "1.0.0"},
                    },
                }
            )
        )
        for fmt in ("markdown", "table"):
            report = self._render(project, fmt)
            assert "~" not in report
            assert "estimate" not in report.lower()

    @respx.mock
    @pytest.mark.parametrize("fmt", ["table", "markdown"])
    def test_mark_survives_a_stdout_that_cannot_encode_the_report_glyphs(
        self, tmp_path: Path, fmt, monkeypatch
    ):
        # cp1252 has no check mark, so the glyphs fall back to ASCII; the
        # mark is ASCII already and is written as it is.
        project = self._project(tmp_path)
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="cp1252", newline="\n")
        monkeypatch.setattr(sys, "stdout", stream)
        with pytest.raises(SystemExit) as exit_info:
            main.main(
                ["check", "--path", str(project), "-f", fmt, "--no-require-lockfile"],
                standalone_mode=True,
            )
        assert exit_info.value.code == 0
        stream.flush()
        printed = buffer.getvalue().decode("cp1252")
        assert "ranged (~1.0.0)" in printed
        assert "~" in printed.replace("ranged (~1.0.0)", "")  # the legend
        assert "OK" in printed and "✓" not in printed


class TestInitReviewFile:
    @respx.mock
    def test_scan_of_a_project_without_a_lockfile_still_scaffolds(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"odd": "^1.0.0"}}))
        _mock_npm("odd", "")
        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        # The scan is the one `check` runs, so the manifest is named as
        # lacking a lockfile. That is said once and fails nothing here.
        assert result.output.count(f"Warning: package.json: {_MISSING}") == 1
        assert "could not be fully analyzed" not in result.output
        assert 'package = "odd"' in (tmp_path / "licenseal.review.toml").read_text()

    @respx.mock
    def test_from_report_reads_a_report_with_estimates(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"odd": "^1.0.0"}}))
        _mock_npm("odd", "")
        scan, data = _check_json(tmp_path, "--no-require-lockfile", "--no-strict")
        assert scan.exit_code == 0
        assert data["diagnostics"][0]["severity"] == "estimate"
        assert data["dependencies"][0]["estimated"] == ["version"]

        result = CliRunner().invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(tmp_path / "report.json"),
            ],
        )
        assert result.exit_code == 0
        review = (tmp_path / "licenseal.review.toml").read_text()
        assert 'package = "odd"' in review and 'version = "1.0.0"' in review
