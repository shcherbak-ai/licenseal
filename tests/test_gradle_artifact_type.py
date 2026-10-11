"""A Gradle coordinate's artifact type is not part of its version.

``group:artifact:1.0@aar`` asks for the ``aar`` file of version ``1.0``. The
type that ends a string coordinate, like the ``ext`` key of the map notation,
says which file of the module the build uses. The dependency is the module
at that version: it is reported at ``1.0``, its license is that of ``1.0``,
and it is the same dependency as the coordinate written without a type.

The scans read a build file from disk against mocked registries. A request to
an endpoint a test does not mock fails the test, so a request that carried
the type would fail it.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.discovery.java.build_gradle import (
    _parse_build_gradle,
    discover_build_gradle_dependencies,
)
from licenseal.models import DependencyGroup
from tests._helpers import _check_json

_MODES = pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
_CENTRAL = "https://repo.maven.apache.org/maven2"
_BATCH = "https://api.deps.dev/v3alpha/versionbatch"
_LIB = ("com.example", "lib")


def _coordinates(text: str) -> list[tuple[str, str, str]]:
    return [(group, artifact, version) for group, artifact, version, _ in _parse_build_gradle(text)]


class TestDeclarationForms:
    @pytest.mark.parametrize(
        "declaration",
        [
            # Groovy and Kotlin string notation, with and without parentheses.
            "implementation 'com.example:lib:1.0@aar'",
            'implementation "com.example:lib:1.0@aar"',
            "implementation('com.example:lib:1.0@aar')",
            'implementation("com.example:lib:1.0@aar")',
            "api 'com.example:lib:1.0@jar'",
            # With a configuration closure after the coordinate.
            "implementation('com.example:lib:1.0@aar') { transitive = true }",
            'implementation("com.example:lib:1.0@aar") { isTransitive = false }',
            # A classifier before the type.
            "implementation 'com.example:lib:1.0:sources@jar'",
            # Map notation: the type is the ``ext`` key.
            "implementation group: 'com.example', name: 'lib', version: '1.0', ext: 'aar'",
            'implementation(group = "com.example", name = "lib", version = "1.0", ext = "aar")',
            "implementation group: 'com.example', name: 'lib', version: '1.0', "
            "classifier: 'sources', ext: 'jar'",
            # Control: no type.
            "implementation 'com.example:lib:1.0'",
        ],
    )
    def test_version_is_read_without_the_type(self, declaration: str):
        assert _coordinates(declaration) == [(*_LIB, "1.0")]

    @pytest.mark.parametrize(
        ("declaration", "version"),
        [
            # What is left is the version as written, concrete or not.
            ("implementation 'com.example:lib:1.+@aar'", "1.+"),
            ("implementation 'com.example:lib:[1.0,2.0)@aar'", "[1.0,2.0)"),
            ("implementation 'com.example:lib:1.0!!@aar'", "1.0!!"),
            ("implementation 'com.example:lib:1.0-rc1@aar'", "1.0-rc1"),
            # No version at all: the type is still not one.
            ("implementation 'com.example:lib@aar'", ""),
            ('implementation("com.example:lib@aar")', ""),
            ("implementation group: 'com.example', name: 'lib', ext: 'aar'", ""),
            # Gradle takes what follows the last ``@`` as the type, and only
            # when it holds no colon and is not empty.
            ("implementation 'com.example:lib:1.0@aar@zip'", "1.0@aar"),
            ("implementation 'com.example:lib:1.0@a:b'", "1.0@a"),
            ("implementation 'com.example:lib:1.0@'", "1.0@"),
        ],
    )
    def test_what_remains_is_the_version_as_written(self, declaration: str, version: str):
        assert _coordinates(declaration) == [(*_LIB, version)]

    @pytest.mark.parametrize(
        "declaration",
        [
            # A variable is not resolved, with a type or without one.
            "implementation 'com.example:lib:$libVersion@aar'",
            # Not a coordinate.
            "implementation 'someone@example.com:lib:1.0'",
            "implementation name: 'lib', ext: 'aar'",
        ],
    )
    def test_not_a_static_coordinate(self, declaration: str):
        assert _coordinates(declaration) == []


class TestOneDependency:
    def test_with_and_without_the_type(self, tmp_path: Path):
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n"
            "    implementation 'com.example:lib:1.0@aar'\n"
            "    implementation 'com.example:lib:1.0'\n"
            "    implementation 'com.example:lib:1.0@jar'\n"
            "    implementation group: 'com.example', name: 'lib', version: '1.0', ext: 'aar'\n"
            "}\n",
            encoding="utf-8",
        )
        deps, _ = discover_build_gradle_dependencies(tmp_path)
        assert [(d.name, d.version_constraint, d.group) for d in deps] == [
            ("com.example:lib", "1.0", DependencyGroup.PROD)
        ]

    def test_test_scoped_type_beside_a_shipped_one_is_production(self, tmp_path: Path):
        (tmp_path / "build.gradle.kts").write_text(
            "dependencies {\n"
            '    testImplementation("com.example:lib:1.0@aar")\n'
            '    implementation("com.example:lib:1.0")\n'
            "}\n",
            encoding="utf-8",
        )
        deps, _ = discover_build_gradle_dependencies(tmp_path)
        assert [(d.name, d.version_constraint, d.group) for d in deps] == [
            ("com.example:lib", "1.0", DependencyGroup.PROD)
        ]


def _pom(artifact: str, version: str, license_id: str) -> respx.Route:
    return respx.get(f"{_CENTRAL}/com/example/{artifact}/{version}/{artifact}-{version}.pom").mock(
        return_value=httpx.Response(
            200,
            text=(
                '<project xmlns="http://maven.apache.org/POM/4.0.0">'
                f"<groupId>com.example</groupId><artifactId>{artifact}</artifactId>"
                f"<version>{version}</version>"
                f"<licenses><license><name>{license_id}</name></license></licenses></project>"
            ),
        )
    )


def _graph(version: str, *children: tuple[str, str]) -> respx.Route:
    """Serve the deps.dev dependency graph of ``com.example:lib`` at ``version``."""

    def node(name: str, number: str, relation: str) -> dict:
        return {
            "versionKey": {"system": "MAVEN", "name": name, "version": number},
            "relation": relation,
        }

    return respx.get(
        "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Alib/"
        f"versions/{version}:dependencies"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "nodes": [
                    node("com.example:lib", version, "SELF"),
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


def _sent() -> list[str]:
    """Every request made: its URL, and its body when it has one."""
    return [str(call.request.url) + call.request.content.decode("utf-8") for call in respx.calls]


class TestScan:
    @_MODES
    @pytest.mark.parametrize(
        ("filename", "declaration"),
        [
            ("build.gradle", "implementation 'com.example:lib:1.0@aar'"),
            ("build.gradle", "implementation('com.example:lib:1.0@aar') { transitive = true }"),
            ("build.gradle", "api 'com.example:lib:1.0@jar'"),
            ("build.gradle.kts", 'implementation("com.example:lib:1.0@aar")'),
            (
                "build.gradle",
                "implementation group: 'com.example', name: 'lib', version: '1.0', ext: 'aar'",
            ),
            (
                "build.gradle.kts",
                'implementation(group = "com.example", name = "lib", version = "1.0", ext = "aar")',
            ),
        ],
    )
    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_row_has_the_version_and_its_license(
        self, tmp_path: Path, mode: str, filename: str, declaration: str
    ):
        (tmp_path / filename).write_text(
            f"dependencies {{\n    {declaration}\n}}\n", encoding="utf-8"
        )
        _pom("lib", "1.0", "MIT")
        batch = respx.post(_BATCH).mock(return_value=httpx.Response(200, json={"responses": []}))
        expected = {"com.example:lib": ("1.0", "MIT", [])}
        if mode == "--transitive":
            _graph("1.0", ("child", "3.0.0"))
            _pom("child", "3.0.0", "ISC")
            expected["com.example:child"] = ("3.0.0", "ISC", ["version"])

        result, report = _check_json(tmp_path, mode, "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == expected
        # The version is asked for as ``1.0``, in the batch lookup too.
        batched = [
            item["versionKey"]
            for call in batch.calls
            for item in json.loads(call.request.content)["requests"]
        ]
        assert {"system": "MAVEN", "name": "com.example:lib", "version": "1.0"} in batched
        assert not [request for request in _sent() if "@" in request or "aar" in request]

    @_MODES
    @respx.mock
    def test_two_spellings_of_one_coordinate_are_one_row(self, tmp_path: Path, mode: str):
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n"
            "    implementation 'com.example:lib:1.0@aar'\n"
            "    testImplementation 'com.example:lib:1.0'\n"
            "}\n",
            encoding="utf-8",
        )
        _pom("lib", "1.0", "MIT")
        if mode == "--transitive":
            _graph("1.0")
        result, report = _check_json(tmp_path, mode, "--dev", "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("1.0", "MIT", [])}
        assert [dep["group"] for dep in report["dependencies"]] == ["prod"]

    @_MODES
    @respx.mock
    def test_coordinate_with_a_type_and_no_version_is_estimated(self, tmp_path: Path, mode: str):
        # Like any coordinate declared with no version: reported at the
        # artifact's latest release, marked as an estimate.
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n    implementation 'com.example:lib@aar'\n}\n", encoding="utf-8"
        )
        respx.get(f"{_CENTRAL}/com/example/lib/maven-metadata.xml").mock(
            return_value=httpx.Response(
                200,
                text=(
                    "<metadata><versioning><versions><version>1.0</version>"
                    "<version>2.0</version></versions></versioning></metadata>"
                ),
            )
        )
        _pom("lib", "2.0", "Apache-2.0")
        if mode == "--transitive":
            _graph("2.0")
        result, report = _check_json(tmp_path, mode, "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("2.0", "Apache-2.0", ["version"])}

    @respx.mock
    def test_lockfile_covers_a_declaration_written_with_a_type(self, tmp_path: Path):
        # The locked version is the declared one, so the lockfile's row is
        # the direct dependency: no registry estimate, and no second row.
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n    implementation 'com.example:lib:1.0@aar'\n}\n", encoding="utf-8"
        )
        (tmp_path / "gradle.lockfile").write_text(
            "com.example:lib:1.0=compileClasspath,runtimeClasspath\n", encoding="utf-8"
        )
        _pom("lib", "1.0", "MIT")
        result, report = _check_json(tmp_path)
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("1.0", "MIT", [])}
        assert [dep["source"] for dep in report["dependencies"]] == ["build.gradle"]
        assert report["diagnostics"] == []
