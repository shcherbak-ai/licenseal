"""A ``pom.xml`` dependency has one version, with or without the transitive stage.

A POM can leave a dependency's version to its parent chain: to a
``<dependencyManagement>`` entry of a parent, to a BOM a parent imports, or to
a ``${property}`` a parent defines. A scan reports the version the chain
supplies, and reads that version's license, whether or not it then walks the
dependency's own graph. ``--no-transitive`` requests the parent and BOM POMs
it needs for that and nothing more: no dependency graph, and no row beyond the
direct dependencies.

Every scan reads a tree from disk against mocked registries. A request to an
endpoint a test does not mock fails the test.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from licenseal.discovery import discover_all_dependencies
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.transitive import resolve_declared_versions
from tests._helpers import _check_json, _write

_MODES = pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
_CENTRAL = "https://repo.maven.apache.org/maven2"
_UNRESOLVED = ("", "UNKNOWN", [])


def _dependency(artifact: str, version: str = "", scope: str = "") -> str:
    lines = [f"<groupId>com.example</groupId><artifactId>{artifact}</artifactId>"]
    if version:
        lines.append(f"<version>{version}</version>")
    if scope:
        lines.append(f"<scope>{scope}</scope>")
    return f"<dependency>{''.join(lines)}</dependency>"


def _pom(coordinates: str, body: str = "") -> str:
    return f'<project xmlns="http://maven.apache.org/POM/4.0.0">{coordinates}{body}</project>\n'


def _parent_block(artifact: str = "parent", group: str = "com.example") -> str:
    return (
        f"<parent><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        "<version>1.0.0</version></parent>"
    )


def _managed(*entries: str) -> str:
    listed = "".join(entries)
    return f"<dependencyManagement><dependencies>{listed}</dependencies></dependencyManagement>"


def _coordinates(artifact: str, group: str = "com.example") -> str:
    return f"<groupId>{group}</groupId><artifactId>{artifact}</artifactId><version>1.0.0</version>"


def _reactor(tmp_path: Path, *, root_body: str, module_dependencies: str) -> None:
    """A reactor root and one module whose parent is the root."""
    _write(
        tmp_path / "pom.xml",
        _pom(
            _coordinates("parent") + "<packaging>pom</packaging>",
            f"<modules><module>app</module></modules>{root_body}",
        ),
    )
    _write(
        tmp_path / "app" / "pom.xml",
        _pom(
            _parent_block() + "<artifactId>app</artifactId>",
            f"<dependencies>{module_dependencies}</dependencies>",
        ),
    )


def _serve_pom(group_path: str, artifact: str, version: str, body: str) -> respx.Route:
    return respx.get(f"{_CENTRAL}/{group_path}/{artifact}/{version}/{artifact}-{version}.pom").mock(
        return_value=httpx.Response(200, text=body)
    )


def _serve_artifact(artifact: str, version: str, license_id: str) -> respx.Route:
    """Serve ``com.example:<artifact>`` at ``version`` with its own license."""
    return _serve_pom(
        "com/example",
        artifact,
        version,
        _pom(
            f"<groupId>com.example</groupId><artifactId>{artifact}</artifactId>"
            f"<version>{version}</version>",
            f"<licenses><license><name>{license_id}</name></license></licenses>",
        ),
    )


def _serve_graph(artifact: str, version: str, *children: tuple[str, str]) -> respx.Route:
    """Serve the deps.dev dependency graph of ``com.example:<artifact>`` at ``version``."""

    def node(name: str, number: str, relation: str) -> dict:
        return {
            "versionKey": {"system": "MAVEN", "name": name, "version": number},
            "relation": relation,
        }

    name = f"com.example:{artifact}"
    return respx.get(
        f"https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3A{artifact}/"
        f"versions/{version}:dependencies"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "nodes": [
                    node(name, version, "SELF"),
                    *(node(f"com.example:{child}", number, "DIRECT") for child, number in children),
                ],
                "edges": [{"fromNode": 0, "toNode": i + 1} for i in range(len(children))],
            },
        )
    )


def _rows(report: dict) -> dict[str, tuple[str, str, list[str]]]:
    return {
        dep["name"]: (dep["resolved_version"], dep["license"], dep["estimated"])
        for dep in report["dependencies"]
    }


def _scan(tmp_path: Path, mode: str, *flags: str) -> dict:
    result, report = _check_json(tmp_path, mode, "--no-strict", *flags)
    assert result.exit_code == 0, result.output
    return report


def _requested() -> list[str]:
    return [str(call.request.url) for call in respx.calls]


class TestBothScansReportTheManagedVersion:
    @_MODES
    @respx.mock
    def test_version_managed_by_an_in_tree_parent(self, tmp_path: Path, mode: str):
        _reactor(
            tmp_path,
            root_body=_managed(_dependency("lib", "5.0.0")),
            module_dependencies=_dependency("lib"),
        )
        _serve_artifact("lib", "5.0.0", "MIT")
        graph = _serve_graph("lib", "5.0.0", ("child", "3.0.0"))
        _serve_artifact("child", "3.0.0", "ISC")

        rows = _rows(_scan(tmp_path, mode))
        # The managed version is exact: the manifest fixes it.
        assert rows.pop("com.example:lib") == ("5.0.0", "MIT", [])
        if mode == "--transitive":
            assert rows == {"com.example:child": ("3.0.0", "ISC", ["version"])}
        else:
            # No dependency graph is asked for, and no row is added.
            assert rows == {}
            assert graph.call_count == 0

    @_MODES
    @respx.mock
    def test_version_written_as_a_property_the_parent_defines(self, tmp_path: Path, mode: str):
        _reactor(
            tmp_path,
            root_body="<properties><lib.version>5.1.0</lib.version></properties>",
            module_dependencies=_dependency("lib", "${lib.version}"),
        )
        _serve_artifact("lib", "5.1.0", "Apache-2.0")
        if mode == "--transitive":
            _serve_graph("lib", "5.1.0")
        assert _rows(_scan(tmp_path, mode)) == {"com.example:lib": ("5.1.0", "Apache-2.0", [])}

    @_MODES
    @respx.mock
    def test_version_managed_by_a_published_parent(self, tmp_path: Path, mode: str):
        # The parent is not in the tree: its POM is read from the registry.
        _write(
            tmp_path / "pom.xml",
            _pom(
                _parent_block("platform", "org.platform") + _coordinates("app"),
                f"<dependencies>{_dependency('lib')}</dependencies>",
            ),
        )
        parent = _serve_pom(
            "org/platform",
            "platform",
            "1.0.0",
            _pom(_coordinates("platform", "org.platform"), _managed(_dependency("lib", "5.2.0"))),
        )
        _serve_artifact("lib", "5.2.0", "BSD-3-Clause")
        if mode == "--transitive":
            _serve_graph("lib", "5.2.0")
        assert _rows(_scan(tmp_path, mode)) == {"com.example:lib": ("5.2.0", "BSD-3-Clause", [])}
        assert parent.call_count == 1

    @_MODES
    @respx.mock
    def test_version_managed_by_a_bom_the_parent_imports(self, tmp_path: Path, mode: str):
        bom_import = (
            "<dependency><groupId>org.platform</groupId><artifactId>bom</artifactId>"
            "<version>2.0.0</version><type>pom</type><scope>import</scope></dependency>"
        )
        _reactor(tmp_path, root_body=_managed(bom_import), module_dependencies=_dependency("lib"))
        _serve_pom(
            "org/platform",
            "bom",
            "2.0.0",
            _pom(
                "<groupId>org.platform</groupId><artifactId>bom</artifactId>"
                "<version>2.0.0</version>",
                _managed(_dependency("lib", "5.3.0")),
            ),
        )
        _serve_artifact("lib", "5.3.0", "Zlib")
        if mode == "--transitive":
            _serve_graph("lib", "5.3.0")
        assert _rows(_scan(tmp_path, mode)) == {"com.example:lib": ("5.3.0", "Zlib", [])}

    @_MODES
    @respx.mock
    def test_dev_scope_dependency_is_resolved_the_same_way(self, tmp_path: Path, mode: str):
        _reactor(
            tmp_path,
            root_body=_managed(_dependency("lib", "5.0.0")),
            module_dependencies=_dependency("lib", scope="test"),
        )
        _serve_artifact("lib", "5.0.0", "MIT")
        if mode == "--transitive":
            _serve_graph("lib", "5.0.0")
        report = _scan(tmp_path, mode, "--dev")
        assert _rows(report) == {"com.example:lib": ("5.0.0", "MIT", [])}
        assert [dep["group"] for dep in report["dependencies"]] == ["dev"]
        # Without ``--dev`` the dependency is left out, and nothing is asked for it.
        respx.reset()
        assert _rows(_scan(tmp_path, mode)) == {}
        assert _requested() == []

    @_MODES
    @respx.mock
    def test_version_nothing_manages_stays_unresolved(self, tmp_path: Path, mode: str):
        _reactor(
            tmp_path,
            root_body=_managed(_dependency("other", "1.0.0")),
            module_dependencies=_dependency("lib") + _dependency("tokened", "${undefined.version}"),
        )
        assert _rows(_scan(tmp_path, mode)) == {
            "com.example:lib": _UNRESOLVED,
            "com.example:tokened": _UNRESOLVED,
        }
        assert _requested() == []


class TestDirectOnlyScanRequestsNoGraph:
    @respx.mock
    def test_only_the_parent_chain_and_the_artifact_are_requested(self, tmp_path: Path):
        _write(
            tmp_path / "pom.xml",
            _pom(
                _parent_block("platform", "org.platform") + _coordinates("app"),
                "<dependencies>"
                + _dependency("lib")
                + _dependency("stated", "2.0.0")
                + "</dependencies>",
            ),
        )
        _serve_pom(
            "org/platform",
            "platform",
            "1.0.0",
            _pom(_coordinates("platform", "org.platform"), _managed(_dependency("lib", "5.2.0"))),
        )
        _serve_artifact("lib", "5.2.0", "MIT")
        _serve_artifact("stated", "2.0.0", "ISC")

        assert _rows(_scan(tmp_path, "--no-transitive")) == {
            "com.example:lib": ("5.2.0", "MIT", []),
            "com.example:stated": ("2.0.0", "ISC", []),
        }
        gets = sorted(url for url in _requested() if "versionbatch" not in url)
        assert gets == [
            f"{_CENTRAL}/com/example/lib/5.2.0/lib-5.2.0.pom",
            f"{_CENTRAL}/com/example/stated/2.0.0/stated-2.0.0.pom",
            f"{_CENTRAL}/org/platform/platform/1.0.0/platform-1.0.0.pom",
        ]

    @respx.mock
    def test_project_without_a_managed_version_requests_no_parent(self, tmp_path: Path):
        # Every version is stated, so the parent chain is not read at all:
        # the parent's POM is not served here.
        _write(
            tmp_path / "pom.xml",
            _pom(
                _parent_block("platform", "org.platform") + _coordinates("app"),
                f"<dependencies>{_dependency('stated', '2.0.0')}</dependencies>",
            ),
        )
        _serve_artifact("stated", "2.0.0", "ISC")
        assert _rows(_scan(tmp_path, "--no-transitive")) == {
            "com.example:stated": ("2.0.0", "ISC", [])
        }


class TestResolveDeclaredVersions:
    """The step of a direct-only scan, on the dependencies discovery hands it."""

    @staticmethod
    def _resolve(tmp_path: Path, deps: list[Dependency]) -> list[Dependency]:
        with httpx.Client() as client:
            return resolve_declared_versions(deps, tmp_path, client=client)

    @respx.mock
    def test_only_pom_dependencies_without_a_stated_version_change(self, tmp_path: Path):
        _reactor(
            tmp_path,
            root_body=_managed(_dependency("lib", "5.0.0")),
            module_dependencies=_dependency("lib") + _dependency("stated", "2.0.0"),
        )
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n    implementation 'com.example:bare'\n}\n", encoding="utf-8"
        )
        (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
        direct, _ = discover_all_dependencies(tmp_path)

        resolved = self._resolve(tmp_path, direct)
        assert [(d.name, d.version_constraint) for d in resolved] == [
            (d.name, "5.0.0" if d.name == "com.example:lib" else d.version_constraint)
            for d in direct
        ]
        # Same dependencies, in the same order, and nothing was requested.
        assert sorted(d.name for d in resolved) == [
            "com.example:bare",
            "com.example:lib",
            "com.example:stated",
            "requests",
        ]
        assert _requested() == []

    @respx.mock
    def test_dependency_with_an_origin_is_left_as_it_is(self, tmp_path: Path):
        # A system-scoped dependency is a local file: no managed version is
        # looked up for it, though the parent manages one.
        _reactor(
            tmp_path,
            root_body=_managed(_dependency("lib", "5.0.0")),
            module_dependencies=(
                "<dependency><groupId>com.example</groupId><artifactId>lib</artifactId>"
                "<scope>system</scope><systemPath>${basedir}/libs/lib.jar</systemPath>"
                "</dependency>"
            ),
        )
        direct, _ = discover_all_dependencies(tmp_path)
        assert [bool(d.origin) for d in direct] == [True]
        assert self._resolve(tmp_path, direct) == direct

    def test_no_pom_dependency_reads_no_file(self, tmp_path: Path):
        # Nothing to resolve: the tree is not walked for POMs.
        dep = Dependency(
            name="requests",
            version_constraint="",
            ecosystem=Ecosystem.PYTHON,
            group=DependencyGroup.PROD,
            source="requirements.txt",
        )
        assert self._resolve(tmp_path / "missing", [dep]) == [dep]

    @respx.mock
    def test_excluded_parent_directory_is_not_read(self, tmp_path: Path):
        # The in-tree parent sits in an excluded directory, so it is not one
        # of the scan's POMs; it is not published either, and the version
        # stays unresolved.
        _write(
            tmp_path / "platform" / "pom.xml",
            _pom(_coordinates("parent"), _managed(_dependency("lib", "5.0.0"))),
        )
        _write(
            tmp_path / "app" / "pom.xml",
            _pom(
                _parent_block() + "<artifactId>app</artifactId>",
                f"<dependencies>{_dependency('lib')}</dependencies>",
            ),
        )
        respx.get(url__regex=rf"{_CENTRAL}/com/example/parent/.*").mock(
            return_value=httpx.Response(404)
        )
        respx.get(url__regex=r"https://(dl\.google\.com|repo\.jenkins-ci\.org)/.*").mock(
            return_value=httpx.Response(404)
        )
        excluded = frozenset({(tmp_path / "platform").resolve()})
        direct, _ = discover_all_dependencies(tmp_path, exclude_paths=excluded)
        with httpx.Client() as client:
            resolved = resolve_declared_versions(
                direct, tmp_path, client=client, exclude_paths=excluded
            )
        assert [(d.name, d.version_constraint) for d in resolved] == [("com.example:lib", "")]

        # Control: with the directory in the scan, the parent supplies the version.
        with_parent, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            resolved = resolve_declared_versions(with_parent, tmp_path, client=client)
        assert [(d.name, d.version_constraint) for d in resolved] == [("com.example:lib", "5.0.0")]
