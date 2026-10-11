"""A Gradle coordinate declared with no version is read at its latest release.

A build that leaves versions to a BOM or to a dependency-management plugin
declares bare ``group:artifact`` coordinates. Only a ``gradle.lockfile``
records the version the build selects. Without one, the scan reports the
artifact's latest release, marked as an estimate, expands its transitive
dependencies like those of any other direct dependency, and records the build
file as lacking a lockfile. When no latest release can be determined the row
stays UNKNOWN with no version.

Every scan here reads a build file from disk against mocked registries. Each
version is served with a license of its own, so a wrong pick shows in the
license. A request to an endpoint a test does not mock fails the test, which
is how the absence of a request is asserted.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers.http import (
    _MAVEN_METADATA_KEEP_TAGS,
    _MAVEN_VERSIONING_KEEP_TAGS,
    RegistryCache,
    _trim_for_cache,
    _trim_maven_metadata,
)
from licenseal.resolvers.maven_central import (
    _VERSION_LIST_URLS,
    _versions_from_metadata,
    estimate_gradle_version,
    resolve_maven_central_license,
)
from tests._helpers import _check_json, _write

_CENTRAL = "https://repo.maven.apache.org/maven2"
_GOOGLE = "https://dl.google.com/dl/android/maven2"
_JENKINS = "https://repo.jenkins-ci.org/public"
_REGISTRIES = (_CENTRAL, _GOOGLE, _JENKINS)

_MISSING_LOCKFILE = (
    "declares dependencies that no lockfile covers; their versions and transitive "
    "dependencies are estimated from the registry"
)
_ESTIMATED = ["version"]
_UNRESOLVED = ("", "UNKNOWN", [])

_LICENSES = {"2.1.0-rc1": "Apache-2.0", "2.0.0": "MIT", "1.9.0": "BSD-3-Clause"}


def _metadata_url(registry: str = _CENTRAL, artifact: str = "lib") -> str:
    return f"{registry}/com/example/{artifact}/maven-metadata.xml"


def _metadata(*versions: str, release: str = "") -> str:
    """A version list as the registries serve it, ``<release>`` and all."""
    listed = "".join(f"<version>{version}</version>" for version in versions)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<metadata><groupId>com.example</groupId><artifactId>lib</artifactId>"
        f"<versioning><latest>{release}</latest><release>{release}</release>"
        f"<versions>{listed}</versions><lastUpdated>20240101000000</lastUpdated>"
        "</versioning></metadata>"
    )


def _text(url: str, body: str) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(200, text=body))


def _missing(url: str) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(404))


def _pom(artifact: str, version: str, license_id: str, registry: str = _CENTRAL) -> respx.Route:
    return _text(
        f"{registry}/com/example/{artifact}/{version}/{artifact}-{version}.pom",
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        f"<groupId>com.example</groupId><artifactId>{artifact}</artifactId>"
        f"<version>{version}</version>"
        f"<licenses><license><name>{license_id}</name></license></licenses></project>",
    )


def _graph(name: str, version: str, *children: tuple[str, str]) -> respx.Route:
    """Serve the deps.dev dependency graph of ``name`` at ``version``."""

    def node(node_name: str, node_version: str, relation: str) -> dict:
        return {
            "versionKey": {"system": "MAVEN", "name": node_name, "version": node_version},
            "relation": relation,
        }

    encoded = name.replace(":", "%3A")
    return respx.get(
        f"https://api.deps.dev/v3/systems/MAVEN/packages/{encoded}/versions/{version}:dependencies"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "nodes": [node(name, version, "SELF"), *(node(*c, "DIRECT") for c in children)],
                "edges": [{"fromNode": 0, "toNode": i + 1} for i in range(len(children))],
            },
        )
    )


def _registry() -> respx.Route:
    """Serve ``com.example:lib``; return the route of its version list.

    The newest version is a release candidate, and it is what ``<release>``
    names; the latest release is 2.0.0, which depends on ``child`` 3.0.0.
    """
    for version, license_id in _LICENSES.items():
        _pom("lib", version, license_id)
    _pom("child", "3.0.0", "ISC")
    _graph("com.example:lib", "2.0.0", ("com.example:child", "3.0.0"))
    return _text(_metadata_url(), _metadata("1.9.0", "2.0.0", "2.1.0-rc1", release="2.1.0-rc1"))


def _groovy(tmp_path: Path, *declarations: str) -> Path:
    body = "".join(f"    {declaration}\n" for declaration in declarations)
    path = tmp_path / "build.gradle"
    path.write_text(f"dependencies {{\n{body}}}\n", encoding="utf-8")
    return path


def _rows(report: dict) -> dict[str, tuple[str, str, list[str]]]:
    return {
        dep["name"]: (dep["resolved_version"], dep["license"], dep["estimated"])
        for dep in report["dependencies"]
    }


class TestScan:
    @pytest.mark.parametrize(
        ("filename", "declaration"),
        [
            ("build.gradle", "implementation 'com.example:lib'"),
            ("build.gradle", "implementation group: 'com.example', name: 'lib'"),
            ("build.gradle.kts", 'implementation("com.example:lib")'),
        ],
    )
    @respx.mock
    def test_latest_release_is_reported_and_expanded(
        self, tmp_path: Path, filename: str, declaration: str
    ):
        (tmp_path / filename).write_text(f"dependencies {{\n    {declaration}\n}}\n")
        listing = _registry()

        result, report = _check_json(tmp_path, "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        # The latest release, not the release candidate ``<release>`` names,
        # and the dependency that release pulls in.
        assert _rows(report) == {
            "com.example:lib": ("2.0.0", "MIT", _ESTIMATED),
            "com.example:child": ("3.0.0", "ISC", _ESTIMATED),
        }
        child = next(d for d in report["dependencies"] if d["name"] == "com.example:child")
        assert child["direct_ancestors"] == ["com.example:lib"]
        assert report["diagnostics"] == [
            {"path": filename, "reason": _MISSING_LOCKFILE, "severity": "estimate"}
        ]
        assert listing.call_count == 1

    @respx.mock
    def test_build_file_without_a_lockfile_is_a_gap(self, tmp_path: Path):
        _groovy(tmp_path, "implementation 'com.example:lib'")
        _registry()
        result, report = _check_json(tmp_path)
        assert result.exit_code == 1
        assert report["summary"]["unknown"] == 0
        assert report["summary"]["gaps"] == 1
        assert report["diagnostics"] == [
            {"path": "build.gradle", "reason": _MISSING_LOCKFILE, "severity": "gap"}
        ]

    @respx.mock
    def test_direct_only_scan_reports_the_same_version(self, tmp_path: Path):
        _groovy(tmp_path, "implementation 'com.example:lib'")
        listing = _registry()
        result, report = _check_json(tmp_path, "--no-transitive")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("2.0.0", "MIT", _ESTIMATED)}
        assert listing.call_count == 1

    @respx.mock
    def test_table_marks_the_version_as_estimated(self, tmp_path: Path):
        _groovy(tmp_path, "implementation 'com.example:lib'")
        _registry()
        result = CliRunner().invoke(
            main, ["check", "--path", str(tmp_path), "--no-require-lockfile"]
        )
        assert result.exit_code == 0, result.output
        assert "com.example:lib (~2.0.0)" in result.output
        assert "marks an estimated version" in result.output

    @respx.mock
    def test_dev_configuration_is_estimated_the_same_way(self, tmp_path: Path):
        _groovy(tmp_path, "testImplementation 'com.example:lib'")
        _registry()
        result, report = _check_json(tmp_path, "--dev", "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert {(d["name"], d["resolved_version"], d["group"]) for d in report["dependencies"]} == {
            ("com.example:lib", "2.0.0", "dev"),
            ("com.example:child", "3.0.0", "dev"),
        }

    @respx.mock
    def test_declared_version_is_not_replaced(self, tmp_path: Path):
        # A stated version is used as it is, and the version list is not
        # requested: nothing mocks it here.
        _groovy(tmp_path, "implementation 'com.example:lib:1.9.0'")
        _pom("lib", "1.9.0", "BSD-3-Clause")
        _graph("com.example:lib", "1.9.0")
        result, report = _check_json(tmp_path, "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("1.9.0", "BSD-3-Clause", [])}

    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    @pytest.mark.parametrize(
        "declaration",
        [
            # A version that is stated but cannot be resolved is not a
            # missing version.
            "implementation group: 'com.example', name: 'lib', version: '${libVersion}'",
            "implementation 'com.example:lib:latest.release'",
            "implementation 'com.example:lib:[1.0,2.0)'",
        ],
    )
    @respx.mock
    def test_unresolvable_declared_version_stays_unknown(
        self, tmp_path: Path, mode: str, declaration: str
    ):
        _groovy(tmp_path, declaration)
        result, report = _check_json(tmp_path, mode, "--no-strict", "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": _UNRESOLVED}

    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    @pytest.mark.parametrize(
        "version", ["1.+", "1.2.+", "+", "latest.release", "latest.integration"]
    )
    @respx.mock
    def test_dynamic_version_is_unknown_and_nothing_is_requested_for_it(
        self, tmp_path: Path, mode: str, version: str
    ):
        # A prefix or a ``latest.*`` version names a set of versions, not
        # one. No registry is asked for the literal text, the row has no
        # version, and no dependency list is recorded as unread for it.
        _groovy(tmp_path, f"implementation 'com.example:lib:{version}'")
        result, report = _check_json(tmp_path, mode, "--no-strict", "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": _UNRESOLVED}
        assert [d for d in report["diagnostics"] if d["severity"] != "estimate"] == []
        assert respx.calls.call_count == 0

    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    @respx.mock
    def test_maven_dependency_with_no_version_is_not_estimated(self, tmp_path: Path, mode: str):
        # A POM gets a missing version from its parent chain or from nowhere.
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
                </dependency>
              </dependencies>
            </project>
            """,
        )
        result, report = _check_json(tmp_path, mode, "--no-strict")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": _UNRESOLVED}

    @respx.mock
    def test_locked_version_is_not_replaced(self, tmp_path: Path):
        _groovy(tmp_path, "implementation 'com.example:lib'")
        (tmp_path / "gradle.lockfile").write_text(
            "com.example:lib:1.9.0=compileClasspath,runtimeClasspath\n"
        )
        _pom("lib", "1.9.0", "BSD-3-Clause")
        result, report = _check_json(tmp_path)
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("1.9.0", "BSD-3-Clause", [])}
        assert report["diagnostics"] == []


class TestLatestRelease:
    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    @respx.mock
    def test_artifact_published_on_a_fallback_registry(self, tmp_path: Path, mode: str):
        # The registries are asked in the order their POMs are: the first
        # one that lists the artifact answers.
        _groovy(tmp_path, "implementation 'com.example:lib'")
        _missing(_metadata_url(_CENTRAL))
        _text(_metadata_url(_GOOGLE), _metadata("1.0.0", "1.1.0"))
        _missing(f"{_CENTRAL}/com/example/lib/1.1.0/lib-1.1.0.pom")
        _pom("lib", "1.1.0", "MIT", registry=_GOOGLE)
        _graph("com.example:lib", "1.1.0")
        result, report = _check_json(tmp_path, mode, "--no-require-lockfile")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("1.1.0", "MIT", _ESTIMATED)}

    @respx.mock
    def test_artifact_published_only_as_prereleases(self, tmp_path: Path):
        # The highest of them stands in; a snapshot is not a published version.
        _groovy(tmp_path, "implementation 'com.example:lib'")
        _text(_metadata_url(), _metadata("1.0.0-alpha01", "1.0.0-beta02", "1.0.0-SNAPSHOT"))
        _pom("lib", "1.0.0-beta02", "MIT")
        result, report = _check_json(tmp_path, "--no-transitive")
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"com.example:lib": ("1.0.0-beta02", "MIT", _ESTIMATED)}

    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    @pytest.mark.parametrize(
        "body",
        [
            None,  # not served at all
            "<metadata><versioning>",  # not XML
            "<metadata><groupId>com.example</groupId></metadata>",
            _metadata(),
            # Nothing a POM could be fetched for.
            _metadata("${revision}", "RELEASE", " ", "1.0.0-SNAPSHOT"),
        ],
    )
    @respx.mock
    def test_no_latest_release_leaves_the_row_unknown(
        self, tmp_path: Path, mode: str, body: str | None
    ):
        # ``other`` states its version and resolves, so the scan as a whole
        # is not one in which every lookup failed.
        _groovy(
            tmp_path, "implementation 'com.example:lib'", "implementation 'com.example:other:1.0.0'"
        )
        _pom("other", "1.0.0", "MIT")
        _graph("com.example:other", "1.0.0")
        for registry in _REGISTRIES:
            if body is None:
                _missing(_metadata_url(registry))
            else:
                _text(_metadata_url(registry), body)

        lenient, report = _check_json(tmp_path, mode, "--no-strict", "--no-require-lockfile")
        assert lenient.exit_code == 0, lenient.output
        assert _rows(report) == {
            "com.example:lib": _UNRESOLVED,
            "com.example:other": ("1.0.0", "MIT", []),
        }

        strict, report = _check_json(tmp_path, mode, "--no-require-lockfile")
        assert strict.exit_code == 1
        assert report["summary"]["unknown"] == 1

    @respx.mock
    def test_version_list_urls_follow_the_pom_registries(self):
        assert (
            tuple(
                f"{registry}/{{group_path}}/{{artifact}}/maven-metadata.xml"
                for registry in _REGISTRIES
            )
            == _VERSION_LIST_URLS
        )

    @pytest.mark.parametrize(
        "dep",
        [
            Dependency("com.example:lib", "1.0.0", Ecosystem.JAVA, source="build.gradle"),
            Dependency("com.example:lib", "", Ecosystem.JAVA, source="pom.xml"),
            Dependency("com.example:lib", "", Ecosystem.JAVA, source=""),
            Dependency("lib", "", Ecosystem.JAVA, source="build.gradle"),
            Dependency(":lib", "", Ecosystem.JAVA, source="app/build.gradle.kts"),
            Dependency("com.example:", "", Ecosystem.JAVA, source="build.gradle"),
            # A dependency with an origin is not a registry artifact.
            Dependency(
                "com.example:lib",
                "",
                Ecosystem.JAVA,
                source="build.gradle",
                origin="libs/lib-1.0.jar",
            ),
        ],
    )
    @respx.mock
    def test_nothing_is_requested_for_any_other_dependency(self, dep: Dependency):
        with httpx.Client() as client:
            assert estimate_gradle_version(dep, client, RegistryCache().fetch_text) is None

    @respx.mock
    def test_resolver_marks_the_version_it_estimates(self):
        _registry()
        dep = Dependency("com.example:lib", "", Ecosystem.JAVA, source="app/build.gradle")
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                dep, client, fetcher=cache.fetch_text, json_fetcher=cache.fetch
            )
        assert (info.license_id, info.resolved_version) == ("MIT", "2.0.0")
        assert info.dependency.version_estimated is True


class TestVersionListCache:
    @respx.mock
    def test_version_list_is_cached_as_its_versions_only(self):
        listing = _registry()
        dep = Dependency("com.example:lib", "", Ecosystem.JAVA, source="build.gradle")
        cache = RegistryCache()
        with httpx.Client() as client:
            picks = [estimate_gradle_version(dep, client, cache.fetch_text) for _ in range(2)]
            cached = cache.fetch_text(_metadata_url(), client)
        assert picks == ["2.0.0", "2.0.0"]
        assert listing.call_count == 1
        assert cached is not None
        assert _versions_from_metadata(cached["text"]) == ["1.9.0", "2.0.0", "2.1.0-rc1"]
        for dropped in ("groupId", "latest", "release", "lastUpdated"):
            assert dropped not in cached["text"]

    def test_keep_sets_documented(self):
        assert frozenset({"versioning"}) == _MAVEN_METADATA_KEEP_TAGS
        assert frozenset({"versions"}) == _MAVEN_VERSIONING_KEEP_TAGS

    @pytest.mark.parametrize("registry", _REGISTRIES)
    def test_version_list_is_not_trimmed_as_a_pom(self, registry: str):
        # The POM trim keeps nothing of a version list.
        trimmed = _trim_for_cache(_metadata_url(registry), {"text": _metadata("1.0.0", "1.1.0")})
        assert trimmed is not None
        assert _versions_from_metadata(trimmed["text"]) == ["1.0.0", "1.1.0"]

    def test_namespaced_version_list_is_read(self):
        body = (
            '<metadata xmlns="http://maven.apache.org/METADATA/1.1.0"><versioning>'
            "<versions><version>1.0.0</version></versions></versioning></metadata>"
        )
        assert _versions_from_metadata(_trim_maven_metadata({"text": body})["text"]) == ["1.0.0"]

    def test_body_that_is_not_a_version_list_is_cached_as_given(self):
        for data in ({"text": ""}, {"text": None}, {"text": "<metadata><versioning>"}):
            assert _trim_maven_metadata(data) == data

    def test_entity_expansion_is_not_cached(self):
        bomb = (
            '<?xml version="1.0"?><!DOCTYPE metadata [<!ENTITY a "aaaa">]>'
            "<metadata><versioning><versions><version>&a;</version></versions>"
            "</versioning></metadata>"
        )
        assert _trim_maven_metadata({"text": bomb}) == {"text": ""}
        assert _versions_from_metadata(bomb) == []
