"""A dependency list the registry did not give is a gap, not an empty list.

A registry walk asks the registry for each package's dependencies. When that
answer does not come (the request fails, the response is not shaped as the
registry documents it, the package has no version to ask about), whatever the
package requires is missing from the scan, even if its own license resolved.
The walk records it on the manifest that declares the direct dependency it
was reached from, and ``--strict`` fails.

A package that really has no dependencies records nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import collect_read_diagnostics, record_unread_dependencies
from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers import nuget
from licenseal.resolvers.http import RegistryCache
from licenseal.transitive import _record_unread_dependencies, _walk_registry, resolve_transitive
from tests._helpers import _check_json, _file_diagnostics, _write


def _unread(package: str) -> str:
    return (
        f"the dependencies of {package} could not be read from the registry; "
        "its transitive dependencies may be missing"
    )


def _scan(project: Path, *, max_depth: int = 50) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Discover and expand ``project`` against the mocked registries.

    Goes through a real ``RegistryCache``, as the CLI does. Returns the rows
    as ``{name: version_constraint}`` and the gaps recorded, as
    ``(project-relative path, reason)``, without the missing-lockfile ones.
    """
    cache = RegistryCache()
    with collect_read_diagnostics() as diags, httpx.Client() as client:
        direct, _ = discover_all_dependencies(project)
        deps = resolve_transitive(
            direct,
            project,
            include_dev=True,
            max_depth=max_depth,
            client=client,
            fetcher=cache.fetch,
            pom_fetcher=cache.fetch_text,
        )
    gaps = [diag for diag in diags if not diag.missing_lockfile]
    assert all(diag.is_gap for diag in gaps)
    rows = {dep.name: dep.version_constraint for dep in deps}
    return rows, [(diag.path.relative_to(project).as_posix(), diag.reason) for diag in gaps]


def _json(url: str, payload: dict) -> None:
    respx.get(url).mock(return_value=httpx.Response(200, json=payload))


def _text(url: str, body: str) -> None:
    respx.get(url).mock(return_value=httpx.Response(200, text=body))


def _missing(url: str) -> None:
    respx.get(url).mock(return_value=httpx.Response(404))


def _npm_manifest(path: Path, **dependencies: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"dependencies": dependencies}))


def _npm(name: str, **dependencies: str) -> None:
    """Serve version 1.0.0 of an npm package with the given dependencies."""
    _json(
        f"https://registry.npmjs.org/{name}/1.0.0",
        {"version": "1.0.0", "dependencies": dependencies},
    )


class TestRecording:
    def test_reason_names_the_package_and_its_version(self, tmp_path: Path):
        with collect_read_diagnostics() as diags:
            record_unread_dependencies(tmp_path / "package.json", "left-pad", "1.3.0")
            record_unread_dependencies(tmp_path / "App.csproj", "Floating", "")
        assert [(d.path.name, d.reason, d.is_gap, d.missing_lockfile) for d in diags] == [
            ("package.json", _unread("left-pad 1.3.0"), True, False),
            # A package with no version is named without one.
            ("App.csproj", _unread("Floating"), True, False),
        ]

    def test_package_reached_twice_is_recorded_once(self, tmp_path: Path):
        with collect_read_diagnostics() as diags:
            _record_unread_dependencies(
                tmp_path, "package.json", [("b", "1.0.0"), ("a", "2.0.0"), ("b", "1.0.0")]
            )
        assert [d.reason for d in diags] == [_unread("a 2.0.0"), _unread("b 1.0.0")]

    def test_nothing_is_recorded_without_a_manifest_path(self, tmp_path: Path):
        with collect_read_diagnostics() as diags:
            _record_unread_dependencies(tmp_path, "", [("a", "1.0.0")])
        assert diags == []


class TestNpmWalk:
    @respx.mock
    def test_dependency_with_an_origin_is_not_a_gap(self, tmp_path: Path):
        # A git dependency is not asked about on the registry (nothing here
        # serves it), so there is no dependency list that could go unread.
        _npm_manifest(
            tmp_path / "package.json",
            forked="git+https://example.invalid/team/forked.git",
            parent="1.0.0",
        )
        _npm("parent")
        rows, gaps = _scan(tmp_path)
        assert set(rows) == {"forked", "parent"}
        assert gaps == []

    @respx.mock
    def test_direct_dependency_whose_metadata_is_not_served(self, tmp_path: Path):
        _npm_manifest(tmp_path / "package.json", parent="1.0.0")
        _missing("https://registry.npmjs.org/parent/1.0.0")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0"}
        assert gaps == [("package.json", _unread("parent 1.0.0"))]

    @respx.mock
    def test_range_whose_packument_is_served_and_whose_version_is_not(self, tmp_path: Path):
        # The packument resolves the range, and even lists the child; the
        # second, per-version request is the one the walk reads edges from.
        _npm_manifest(tmp_path / "package.json", parent="^1.0.0")
        _json(
            "https://registry.npmjs.org/parent",
            {"versions": {"1.0.0": {"version": "1.0.0", "dependencies": {"child": "1.0.0"}}}},
        )
        _missing("https://registry.npmjs.org/parent/1.0.0")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0"}
        assert gaps == [("package.json", _unread("parent 1.0.0"))]

    @respx.mock
    def test_transitive_is_recorded_on_the_manifest_of_its_direct_dependency(self, tmp_path: Path):
        _npm_manifest(tmp_path / "package.json", parent="1.0.0", sibling="1.0.0")
        _npm("parent", middle="1.0.0")
        _npm("sibling")
        _missing("https://registry.npmjs.org/middle/1.0.0")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0", "sibling": "==1.0.0", "middle": "==1.0.0"}
        assert gaps == [("package.json", _unread("middle 1.0.0"))]

    @respx.mock
    def test_package_reached_from_several_directs_is_one_diagnostic_per_manifest(
        self, tmp_path: Path
    ):
        # ``shared`` is reached from two direct deps of one manifest and from
        # one of another; a third manifest does not reach it.
        _npm_manifest(tmp_path / "web" / "package.json", one="1.0.0", two="1.0.0")
        _npm_manifest(tmp_path / "api" / "package.json", three="1.0.0")
        _npm_manifest(tmp_path / "cli" / "package.json", clean="1.0.0")
        for name in ("one", "two", "three"):
            _npm(name, shared="1.0.0")
        _npm("clean")
        _missing("https://registry.npmjs.org/shared/1.0.0")
        rows, gaps = _scan(tmp_path)
        assert set(rows) == {"one", "two", "three", "clean", "shared"}
        assert gaps == [
            ("api/package.json", _unread("shared 1.0.0")),
            ("web/package.json", _unread("shared 1.0.0")),
        ]

    @respx.mock
    def test_dependency_field_of_the_wrong_type(self, tmp_path: Path):
        # The field that could be read still is.
        _npm_manifest(tmp_path / "package.json", parent="1.0.0")
        _json(
            "https://registry.npmjs.org/parent/1.0.0",
            {"version": "1.0.0", "dependencies": ["child"], "peerDependencies": {"peer": "1.0.0"}},
        )
        _npm("peer")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0", "peer": "==1.0.0"}
        assert gaps == [("package.json", _unread("parent 1.0.0"))]

    @respx.mock
    def test_package_without_dependencies_records_nothing(self, tmp_path: Path):
        _npm_manifest(tmp_path / "package.json", parent="1.0.0", bare="1.0.0")
        _npm("parent", child="1.0.0")
        _npm("child")
        # No dependency field at all, and a null one: both declare nothing.
        _json("https://registry.npmjs.org/bare/1.0.0", {"version": "1.0.0", "dependencies": None})
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0", "bare": "==1.0.0", "child": "==1.0.0"}
        assert gaps == []

    @respx.mock
    def test_package_at_the_depth_cap_is_not_expanded_and_is_not_a_gap(
        self, tmp_path: Path, capsys
    ):
        # ``--max-depth`` stops the walk on purpose and says so; the package
        # at the cap is not asked for its dependencies.
        _npm_manifest(tmp_path / "package.json", parent="1.0.0")
        _npm("parent", child="1.0.0")
        child = respx.get("https://registry.npmjs.org/child/1.0.0").mock(
            return_value=httpx.Response(404)
        )
        rows, gaps = _scan(tmp_path, max_depth=1)
        assert rows == {"parent": "==1.0.0", "child": "==1.0.0"}
        assert gaps == []
        assert not child.called
        assert "hit max-depth=1" in capsys.readouterr().err

    @respx.mock
    def test_seed_without_a_manifest_records_nothing(self, tmp_path: Path):
        # A dependency handed to the walk with no source has no manifest to
        # carry the gap; the walk itself still completes.
        _missing("https://registry.npmjs.org/parent/1.0.0")
        seed = Dependency(name="parent", version_constraint="1.0.0", ecosystem=Ecosystem.NPM)
        with collect_read_diagnostics() as diags, httpx.Client() as client:
            walked = _walk_registry(
                [seed],
                Ecosystem.NPM,
                project_path=tmp_path,
                max_depth=50,
                client=client,
                fetcher=RegistryCache().fetch,
            )
        assert [dep.version_constraint for dep in walked] == ["==1.0.0"]
        assert diags == []


class TestOtherRegistryWalks:
    @respx.mock
    def test_python_release_metadata_not_served(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("parent==1.0.0\n")
        _missing("https://pypi.org/pypi/parent/1.0.0/json")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0"}
        assert gaps == [("requirements.txt", _unread("parent 1.0.0"))]

    @respx.mock
    def test_python_requirement_the_parser_rejects(self, tmp_path: Path):
        # The entries beside it are followed; the list is still incomplete.
        (tmp_path / "requirements.txt").write_text("parent==1.0.0\n")
        _json(
            "https://pypi.org/pypi/parent/1.0.0/json",
            {"info": {"version": "1.0.0", "requires_dist": ["child==2.0.0", "###not-a-name"]}},
        )
        _json(
            "https://pypi.org/pypi/child/2.0.0/json",
            {"info": {"version": "2.0.0", "requires_dist": None}},
        )
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0", "child": "==2.0.0"}
        assert gaps == [("requirements.txt", _unread("parent 1.0.0"))]

    @respx.mock
    def test_rust_dependencies_endpoint_not_served(self, tmp_path: Path):
        _write(
            tmp_path / "Cargo.toml",
            """\
            [package]
            name = "app"
            version = "0.1.0"

            [dependencies]
            parent = "=1.0.0"
            """,
        )
        _missing("https://crates.io/api/v1/crates/parent/1.0.0/dependencies")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.0.0"}
        assert gaps == [("Cargo.toml", _unread("parent 1.0.0"))]

    @respx.mock
    def test_php_requirements_of_the_wrong_type(self, tmp_path: Path):
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/parent": "^1.0"}}))
        _json(
            "https://repo.packagist.org/p2/vendor/parent.json",
            {"packages": {"vendor/parent": [{"version": "1.2.0", "require": "vendor/child"}]}},
        )
        rows, gaps = _scan(tmp_path)
        assert rows == {"vendor/parent": "==1.2.0"}
        assert gaps == [("composer.json", _unread("vendor/parent 1.2.0"))]

    @respx.mock
    def test_ruby_version_metadata_not_served(self, tmp_path: Path):
        (tmp_path / "Gemfile").write_text('gem "parent"\n')
        _json("https://rubygems.org/api/v1/gems/parent.json", {"version": "1.3.0"})
        _missing("https://rubygems.org/api/v2/rubygems/parent/versions/1.3.0.json")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.3.0"}
        assert gaps == [("Gemfile", _unread("parent 1.3.0"))]

    @respx.mock
    def test_hex_release_not_served(self, tmp_path: Path):
        (tmp_path / "rebar.config").write_text('{deps, [{parent, "~> 1.0"}]}.\n')
        _json("https://hex.pm/api/packages/parent", {"latest_stable_version": "1.2.0"})
        _missing("https://hex.pm/api/packages/parent/releases/1.2.0")
        rows, gaps = _scan(tmp_path)
        assert rows == {"parent": "==1.2.0"}
        assert gaps == [("rebar.config", _unread("parent 1.2.0"))]


_MAVEN_GRAPH_URL = (
    "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Alib/versions/1.0.0:dependencies"
)


def _maven_node(name: str, version: str, relation: str) -> dict:
    return {
        "versionKey": {"system": "MAVEN", "name": name, "version": version},
        "relation": relation,
    }


class TestJavaGraph:
    _POM = """\
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
          </dependencies>
        </project>
        """

    @respx.mock
    def test_maven_graph_deps_dev_does_not_know(self, tmp_path: Path):
        # Maven has no lockfile to ask for, but a hole in its graph is a gap
        # like any other.
        _write(tmp_path / "pom.xml", self._POM)
        _missing(_MAVEN_GRAPH_URL)
        rows, gaps = _scan(tmp_path)
        assert rows == {"com.example:lib": "==1.0.0"}
        assert gaps == [("pom.xml", _unread("com.example:lib 1.0.0"))]

    @respx.mock
    def test_maven_graph_returned_with_an_error(self, tmp_path: Path):
        # The nodes that did resolve are reported; the cache keeps the error.
        _write(tmp_path / "pom.xml", self._POM)
        _json(
            _MAVEN_GRAPH_URL,
            {
                "nodes": [
                    _maven_node("com.example:lib", "1.0.0", "SELF"),
                    _maven_node("com.example:child", "2.0.0", "DIRECT"),
                ],
                "edges": [{"fromNode": 0, "toNode": 1}],
                "error": "could not resolve com.example:missing",
            },
        )
        rows, gaps = _scan(tmp_path)
        assert rows == {"com.example:lib": "==1.0.0", "com.example:child": "==2.0.0"}
        assert gaps == [("pom.xml", _unread("com.example:lib 1.0.0"))]

    @respx.mock
    def test_gradle_build_file(self, tmp_path: Path):
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n    implementation 'com.example:lib:1.0.0'\n}\n"
        )
        _missing(_MAVEN_GRAPH_URL)
        rows, gaps = _scan(tmp_path)
        assert rows == {"com.example:lib": "==1.0.0"}
        assert gaps == [("build.gradle", _unread("com.example:lib 1.0.0"))]

    @respx.mock
    def test_graph_read_in_full_records_nothing(self, tmp_path: Path):
        _write(tmp_path / "pom.xml", self._POM)
        _json(_MAVEN_GRAPH_URL, {"nodes": [_maven_node("com.example:lib", "1.0.0", "SELF")]})
        rows, gaps = _scan(tmp_path)
        assert rows == {"com.example:lib": "==1.0.0"}
        assert gaps == []


class TestNuspecWalk:
    @staticmethod
    def _project(tmp_path: Path) -> None:
        _write(
            tmp_path / "App.csproj",
            """\
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Root" Version="1.0.0" />
              </ItemGroup>
            </Project>
            """,
        )

    @staticmethod
    def _nuspec(package_id: str, version: str, dependencies: str = "") -> None:
        lowered = package_id.lower()
        _text(
            f"https://api.nuget.org/v3-flatcontainer/{lowered}/{version}/{lowered}.nuspec",
            f"<package><metadata><id>{package_id}</id><version>{version}</version>"
            f"<dependencies>{dependencies}</dependencies></metadata></package>",
        )

    @respx.mock
    def test_child_nuspec_not_served(self, tmp_path: Path):
        self._project(tmp_path)
        self._nuspec("Root", "1.0.0", '<dependency id="Child" version="2.0.0" />')
        _missing("https://api.nuget.org/v3-flatcontainer/child/2.0.0/child.nuspec")
        rows, gaps = _scan(tmp_path)
        assert rows == {"Root": "==1.0.0", "Child": "==2.0.0"}
        assert gaps == [("App.csproj", _unread("Child 2.0.0"))]

    @respx.mock
    def test_root_nuspec_not_served(self, tmp_path: Path):
        self._project(tmp_path)
        _missing("https://api.nuget.org/v3-flatcontainer/root/1.0.0/root.nuspec")
        rows, gaps = _scan(tmp_path)
        assert rows == {"Root": "==1.0.0"}
        assert gaps == [("App.csproj", _unread("Root 1.0.0"))]

    @respx.mock
    def test_child_without_a_pinnable_version_is_reported_without_one(self, tmp_path: Path):
        # Not dropped: the package is a row with no version, which resolves
        # UNKNOWN, and what it requires is recorded as unread.
        self._project(tmp_path)
        self._nuspec(
            "Root",
            "1.0.0",
            '<dependency id="Floating" version="1.*" /><dependency id="Unversioned" />'
            '<dependency id="Pinned" version="3.0.0" />',
        )
        self._nuspec("Pinned", "3.0.0")
        rows, gaps = _scan(tmp_path)
        assert rows == {"Root": "==1.0.0", "Floating": "", "Unversioned": "", "Pinned": "==3.0.0"}
        assert gaps == [
            ("App.csproj", _unread("Floating")),
            ("App.csproj", _unread("Unversioned")),
        ]

    @respx.mock
    def test_package_at_the_depth_limit_is_a_gap(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(nuget, "_NUSPEC_WALK_MAX_DEPTH", 1)
        self._project(tmp_path)
        self._nuspec("Root", "1.0.0", '<dependency id="Deep" version="2.0.0" />')
        deeper = respx.get("https://api.nuget.org/v3-flatcontainer/deep/2.0.0/deep.nuspec").mock(
            return_value=httpx.Response(404)
        )
        rows, gaps = _scan(tmp_path)
        assert rows == {"Root": "==1.0.0", "Deep": "==2.0.0"}
        assert gaps == [("App.csproj", _unread("Deep 2.0.0"))]
        assert not deeper.called

    @respx.mock
    def test_package_of_the_project_itself_is_not_recorded(self, tmp_path: Path):
        # A sibling project is not published, so its nuspec is never served;
        # it is not a row, and not a hole in the graph either.
        self._project(tmp_path)
        _write(tmp_path / "Sibling" / "Sibling.csproj", '<Project Sdk="Microsoft.NET.Sdk" />\n')
        self._nuspec("Root", "1.0.0", '<dependency id="Sibling" version="1.0.0" />')
        _missing("https://api.nuget.org/v3-flatcontainer/sibling/1.0.0/sibling.nuspec")
        rows, gaps = _scan(tmp_path)
        assert rows == {"Root": "==1.0.0"}
        assert gaps == []


def _batch_of_mit(system: str, name: str, version: str) -> dict:
    key = {"system": system, "name": name, "version": version}
    return {
        "responses": [
            {
                "request": {"versionKey": key},
                "version": {"versionKey": key, "licenses": ["MIT"], "links": []},
            }
        ]
    }


@pytest.mark.no_default_deps_dev_mock
class TestCheckCommand:
    """The parent's license resolves; the scan still does not pass as complete."""

    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "package.json").write_text(
            json.dumps({"license": "MIT", "dependencies": {"parent": "1.0.0"}})
        )
        # The batch supplies the license, so nothing else about the parent
        # is unknown.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json=_batch_of_mit("NPM", "parent", "1.0.0"))
        )
        return tmp_path

    def _assert_one_gap(self, project: Path) -> None:
        gap = {"path": "package.json", "reason": _unread("parent 1.0.0"), "severity": "gap"}

        # Accepting the missing lockfile does not accept this.
        strict, data = _check_json(project, "--strict", "--no-require-lockfile")
        assert strict.exit_code == 1
        assert [(d["name"], d["license"], d["verdict"]) for d in data["dependencies"]] == [
            ("parent", "MIT", "compatible")
        ]
        assert (data["summary"]["unknown"], data["summary"]["gaps"]) == (0, 1)
        assert _file_diagnostics(data) == [gap]
        assert f"Warning: package.json: {gap['reason']}" in strict.output
        assert "1 manifest(s) could not be fully analyzed" in strict.output

        # With the lockfile required it is one manifest with two gaps.
        default, data = _check_json(project)
        assert default.exit_code == 1
        assert data["summary"]["gaps"] == 1
        assert [d["severity"] for d in data["diagnostics"]] == ["gap", "gap"]

        lenient, data = _check_json(project, "--no-strict", "--no-require-lockfile")
        assert lenient.exit_code == 0
        assert _file_diagnostics(data) == [gap]

    @respx.mock
    def test_child_metadata_not_found(self, tmp_path: Path):
        project = self._project(tmp_path)
        _missing("https://registry.npmjs.org/parent/1.0.0")
        self._assert_one_gap(project)

    @respx.mock
    def test_child_metadata_fails_until_the_retries_run_out(
        self, tmp_path: Path, fake_registry_clock
    ):
        project = self._project(tmp_path)
        route = respx.get("https://registry.npmjs.org/parent/1.0.0").mock(
            return_value=httpx.Response(503)
        )
        self._assert_one_gap(project)
        # Three attempts per scan, three scans.
        assert route.call_count == 9

    @respx.mock
    def test_control_child_metadata_served(self, tmp_path: Path):
        project = self._project(tmp_path)
        _npm("parent")
        result, data = _check_json(project, "--strict", "--no-require-lockfile")
        assert result.exit_code == 0
        assert data["summary"]["gaps"] == 0
        assert _file_diagnostics(data) == []

    @respx.mock
    def test_markdown_report_lists_the_gap(self, tmp_path: Path):
        project = self._project(tmp_path)
        _missing("https://registry.npmjs.org/parent/1.0.0")
        out = project / "report.md"
        CliRunner().invoke(
            main,
            [
                "check",
                "-p",
                str(project),
                "--no-require-lockfile",
                "-f",
                "markdown",
                "-o",
                str(out),
            ],
        )
        report = out.read_text(encoding="utf-8")
        assert "1 ok, 1 analysis gap, 1 estimated manifest" in report
        assert f"|[package.json](package.json)|{_unread('parent 1.0.0')}|" in report
