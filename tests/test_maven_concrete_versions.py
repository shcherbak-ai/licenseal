"""One reading of whether a Maven or Gradle version string names one version.

A stated version is resolved whatever it looks like: a release-train name, a
version that starts with a letter, a hard requirement written ``[1.0]``. A
string that names several versions or none (a range, a dynamic version,
Maven's ``RELEASE`` / ``LATEST``, an unresolved property) is never put into
a request: not into a POM URL, not into the deps.dev batch, not into a
dependency-graph lookup.

The scans read a ``pom.xml`` or a ``build.gradle`` from disk against mocked
registries, with and without the transitive stage. A request to an endpoint a
test does not mock fails the test.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers.deps_dev import _version_extractor_for
from licenseal.resolvers.maven_central import resolve_maven_central_license
from licenseal.resolvers.version_selection import concrete_maven_version
from licenseal.transitive import declares_exact_version
from tests._helpers import _check_json, _write

_MODES = pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
_CENTRAL = "https://repo.maven.apache.org/maven2"
_BATCH = "https://api.deps.dev/v3alpha/versionbatch"
_UNRESOLVED = ("", "UNKNOWN", [])

# What a manifest writes, and the version it names.
_CONCRETE = [
    ("1.0.0", "1.0.0"),
    ("3.0", "3.0"),
    ("7", "7"),
    ("1.0.0-SNAPSHOT", "1.0.0-SNAPSHOT"),
    ("5.3.20.RELEASE", "5.3.20.RELEASE"),
    ("2.0.0.Final", "2.0.0.Final"),
    ("33.0.0-jre", "33.0.0-jre"),
    ("3.0.0-M1", "3.0.0-M1"),
    ("1.0.0+build.7", "1.0.0+build.7"),
    ("1.0.0+sha.abc", "1.0.0+sha.abc"),
    ("1.0_01", "1.0_01"),
    ("20040616", "20040616"),
    # A release-train name, and a version that starts with a letter.
    ("Aster.SR12", "Aster.SR12"),
    ("r09", "r09"),
    ("v1.0", "v1.0"),
    # A hard requirement on one version, in Maven's and in Gradle's spelling.
    ("[1.0]", "1.0"),
    ("[ 1.0 ]", "1.0"),
    ("[Aster.SR12]", "Aster.SR12"),
    ("1.0!!", "1.0"),
    # The form a resolved row is written in.
    ("==1.2.3", "1.2.3"),
    ("==  1.2.3  ", "1.2.3"),
    ("==[1.0]", "1.0"),
    (" 1.0.0 ", "1.0.0"),
    # Maven's markers are upper case; any other spelling is a version's text.
    ("release", "release"),
    ("1.0.RELEASE", "1.0.RELEASE"),
]

_NOT_CONCRETE = [
    # Ranges.
    "[1.0,2.0)",
    "[1.0,2.0]",
    "(1.0,2.0)",
    "[1.0,)",
    "(,1.0]",
    "[1.0],[2.0]",
    "(,1.0],[1.2,)",
    "==[1.0,2.0)",
    # Gradle dynamic versions.
    "1.+",
    "1.2.+",
    "1+",
    "+",
    "latest.release",
    "latest.integration",
    "[1.+]",
    "==1.+",
    "1.+!!",
    # Maven's markers.
    "RELEASE",
    "LATEST",
    "[RELEASE]",
    "==LATEST",
    # Unresolved properties.
    "${lib.version}",
    "1.0-${revision}",
    "==${lib.version}",
    # Nothing, and text that is not a version.
    "",
    "   ",
    "==",
    "[]",
    "(1.0)",
    "[1.0",
    "1.0]",
    "1.0 2.0",
    "1.0,2.0",
    "1.0@aar",
    "+1",
    ".5",
    "@version@",
    "1.0/../2.0",
]


class TestConcreteMavenVersion:
    @pytest.mark.parametrize(("written", "named"), _CONCRETE)
    def test_names_one_version(self, written: str, named: str):
        assert concrete_maven_version(written) == named

    @pytest.mark.parametrize("written", _NOT_CONCRETE)
    def test_names_no_single_version(self, written: str):
        assert concrete_maven_version(written) is None

    @pytest.mark.parametrize(("written", "named"), _CONCRETE)
    def test_every_reader_takes_the_same_version(self, written: str, named: str):
        # The deps.dev batch, and the test that decides the estimate mark.
        assert _version_extractor_for("MAVEN")(written) == named
        dep = Dependency(name="g:a", version_constraint=written, ecosystem=Ecosystem.JAVA)
        assert declares_exact_version(dep) is True

    @pytest.mark.parametrize("written", _NOT_CONCRETE)
    def test_every_reader_rejects_the_same_strings(self, written: str):
        assert _version_extractor_for("MAVEN")(written) is None
        dep = Dependency(name="g:a", version_constraint=written, ecosystem=Ecosystem.JAVA)
        assert declares_exact_version(dep) is False

    @pytest.mark.parametrize("written", [w for w in _NOT_CONCRETE if w.strip()])
    @respx.mock
    def test_license_resolver_requests_nothing_for_a_rejected_string(self, written: str):
        dep = Dependency(
            name="com.example:lib", version_constraint=written, ecosystem=Ecosystem.JAVA
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(dep, client)
        assert (info.license_id, info.resolved_version) == ("UNKNOWN", "")
        assert respx.calls.call_count == 0


def _pom_file(tmp_path: Path, version: str) -> None:
    _write(
        tmp_path / "pom.xml",
        f"""\
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <groupId>com.example</groupId>
          <artifactId>app</artifactId>
          <version>1.0.0</version>
          <dependencies>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>lib</artifactId>
              <version>{version}</version>
            </dependency>
          </dependencies>
        </project>
        """,
    )


def _gradle_file(tmp_path: Path, version: str) -> None:
    (tmp_path / "build.gradle").write_text(
        f"dependencies {{\n    implementation 'com.example:lib:{version}'\n}}\n", encoding="utf-8"
    )


def _registry(version: str) -> None:
    """Serve ``com.example:lib`` at ``version`` (MIT), which depends on ``child`` 3.0.0 (ISC)."""
    for artifact, number, license_id in (("lib", version, "MIT"), ("child", "3.0.0", "ISC")):
        respx.get(f"{_CENTRAL}/com/example/{artifact}/{number}/{artifact}-{number}.pom").mock(
            return_value=httpx.Response(
                200,
                text=(
                    '<project xmlns="http://maven.apache.org/POM/4.0.0">'
                    f"<groupId>com.example</groupId><artifactId>{artifact}</artifactId>"
                    f"<version>{number}</version>"
                    f"<licenses><license><name>{license_id}</name></license></licenses></project>"
                ),
            )
        )

    def node(name: str, number: str, relation: str) -> dict:
        return {
            "versionKey": {"system": "MAVEN", "name": name, "version": number},
            "relation": relation,
        }

    respx.get(
        "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Alib/"
        f"versions/{version}:dependencies"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "nodes": [
                    node("com.example:lib", version, "SELF"),
                    node("com.example:child", "3.0.0", "DIRECT"),
                ],
                "edges": [{"fromNode": 0, "toNode": 1}],
            },
        )
    )


def _rows(report: dict) -> dict[str, tuple[str, str, list[str]]]:
    return {
        dep["name"]: (dep["resolved_version"], dep["license"], dep["estimated"])
        for dep in report["dependencies"]
    }


def _batched(batch: respx.Route) -> list[tuple[str, str]]:
    """The ``(name, version)`` pairs sent to the deps.dev batch lookup."""
    return [
        (item["versionKey"]["name"], item["versionKey"]["version"])
        for call in batch.calls
        for item in json.loads(call.request.content)["requests"]
    ]


_STATED = pytest.mark.parametrize(
    ("declared", "version"),
    [
        ("Aster.SR12", "Aster.SR12"),
        ("r09", "r09"),
        ("v1.0", "v1.0"),
        ("[1.0]", "1.0"),
        ("1.0.0", "1.0.0"),
    ],
)


class TestStatedVersionIsResolved:
    @_MODES
    @_STATED
    @pytest.mark.parametrize("manifest", [_pom_file, _gradle_file])
    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_row_has_the_stated_version_and_its_license(
        self, tmp_path: Path, mode: str, declared: str, version: str, manifest
    ):
        manifest(tmp_path, declared)
        _registry(version)
        batch = respx.post(_BATCH).mock(return_value=httpx.Response(200, json={"responses": []}))

        result, report = _check_json(tmp_path, mode, "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        expected = {"com.example:lib": (version, "MIT", [])}
        if mode == "--transitive":
            # The version is one the dependency graph can be asked for.
            expected["com.example:child"] = ("3.0.0", "ISC", ["version"])
        assert _rows(report) == expected
        assert ("com.example:lib", version) in _batched(batch)

    @_STATED
    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_batch_answer_is_used_for_it(self, tmp_path: Path, declared: str, version: str):
        _pom_file(tmp_path, declared)
        key = {"system": "MAVEN", "name": "com.example:lib", "version": version}
        respx.post(_BATCH).mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {"versionKey": key},
                            "version": {"versionKey": key, "licenses": ["Apache-2.0"], "links": []},
                        }
                    ]
                },
            )
        )
        result, report = _check_json(tmp_path, "--no-transitive")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": (version, "Apache-2.0", [])}


class TestRejectedStringIsNeverRequested:
    @_MODES
    @pytest.mark.parametrize(
        "declared",
        ["RELEASE", "LATEST", "[1.0,2.0)", "(,1.0],[1.2,)", "1.+", "latest.release"],
    )
    @pytest.mark.parametrize("manifest", [_pom_file, _gradle_file])
    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_row_is_unknown_and_no_request_is_made(
        self, tmp_path: Path, mode: str, declared: str, manifest
    ):
        manifest(tmp_path, declared)
        result, report = _check_json(tmp_path, mode, "--no-strict", "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": _UNRESOLVED}
        # Not the batch lookup, not a POM, not a dependency graph.
        assert respx.calls.call_count == 0

    @_MODES
    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_unresolved_property_is_never_requested(self, tmp_path: Path, mode: str):
        _pom_file(tmp_path, "${lib.version}")
        result, report = _check_json(tmp_path, mode, "--no-strict")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": _UNRESOLVED}
        assert respx.calls.call_count == 0
