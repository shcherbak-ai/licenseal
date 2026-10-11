"""A declared version range resolves to a version inside it.

A Rust, Ruby, Hex, PHP, .NET, or npm manifest with no lockfile declares each
dependency with a range. The scan reports the version the range selects among
those the registry publishes, with that version's license. It never reports
the registry's latest release when the range excludes it. A range that no
published version satisfies, and a constraint that cannot be read, are UNKNOWN
with no version.

Every scan here reads a project from disk against mocked registries, once with
``--transitive`` and once with ``--no-transitive``: the walk and the license
resolver report the same version for the same declaration. Each registry
serves a different license for each version, so a wrong pick shows in the
license as well as in the version. A request to an endpoint a test does not
mock fails the test, which is how the absence of a request is asserted.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers.hex import resolve_hex_license
from licenseal.resolvers.http import RegistryCache
from licenseal.resolvers.nuget import _resolve_version as _resolve_nuget_version
from licenseal.resolvers.nuget import resolve_nuget_license
from licenseal.resolvers.rubygems import resolve_ruby_license
from tests._helpers import _check_json, _write

_MODES = ("--transitive", "--no-transitive")

# What a row looks like when its range selects a version, and when it does not.
_ESTIMATED = ["version"]
_UNRESOLVED = ("", "UNKNOWN", [])


def _row(project: Path, mode: str, name: str = "lib") -> tuple[str, str, list[str]]:
    """Scan ``project`` and return ``name``'s ``(version, license, estimated)``."""
    result, report = _check_json(project, mode, "--no-strict", "--no-require-lockfile")
    assert result.exit_code == 0, result.output
    rows = {
        dep["name"]: (dep["resolved_version"], dep["license"], dep["estimated"])
        for dep in report["dependencies"]
    }
    assert list(rows) == [name]
    return rows[name]


def _json(url: str, payload: object) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(200, json=payload))


def _text(url: str, body: str) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(200, text=body))


class TestCargo:
    _CRATE = "https://crates.io/api/v1/crates/lib"
    _LICENSES = {
        "2.0.0": "Apache-2.0",
        "1.9.0": "Zlib",
        "1.4.0": "MIT",
        "1.2.0": "BSD-3-Clause",
        "0.9.0": "ISC",
    }

    @staticmethod
    def _project(tmp_path: Path, requirement: str) -> None:
        _write(
            tmp_path / "Cargo.toml",
            f"""\
            [package]
            name = "app"
            version = "0.1.0"

            [dependencies]
            lib = "{requirement}"
            """,
        )

    def _registry(self) -> respx.Route:
        """Serve the crate, latest release 2.0.0; 1.9.0 is yanked."""
        versions = [{"num": "2.1.0-rc.1", "yanked": False}]
        for version, license_id in self._LICENSES.items():
            versions.append({"num": version, "yanked": version == "1.9.0"})
            _json(f"{self._CRATE}/{version}", {"version": {"num": version, "license": license_id}})
            _json(f"{self._CRATE}/{version}/dependencies", {"dependencies": []})
        return _json(
            self._CRATE,
            {
                "crate": {"max_stable_version": "2.0.0", "newest_version": "2.1.0-rc.1"},
                "versions": versions,
            },
        )

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("requirement", "version"),
        [
            # A bare requirement is a caret requirement.
            ("1.2", "1.4.0"),
            ("^1.2", "1.4.0"),
            ("~1.2", "1.2.0"),
            ("1.*", "1.4.0"),
            (">=1.0, <1.3", "1.2.0"),
            ("<1.0", "0.9.0"),
            ("*", "2.0.0"),
            # ``=`` before a version that stops early covers what it prefixes.
            ("=1.2", "1.2.0"),
            ("= 1.2", "1.2.0"),
            ("=1", "1.4.0"),
            ("=0", "0.9.0"),
        ],
    )
    @respx.mock
    def test_range_selects_the_highest_version_inside_it(
        self, tmp_path: Path, mode: str, requirement: str, version: str
    ):
        self._project(tmp_path, requirement)
        crate = self._registry()
        assert _row(tmp_path, mode) == (version, self._LICENSES[version], _ESTIMATED)
        # The versions come with the crate response the latest release is
        # read from: one request, range or not.
        assert crate.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_exact_requirement_is_not_an_estimate(self, tmp_path: Path, mode: str):
        self._project(tmp_path, "=1.2.0")
        self._registry()
        assert _row(tmp_path, mode) == ("1.2.0", "BSD-3-Clause", [])

    @pytest.mark.no_default_deps_dev_mock
    @pytest.mark.parametrize(
        ("requirement", "batched"),
        [
            ("=1.2.0", ["1.2.0"]),
            # A version that stops early is no version to ask a registry for.
            ("=1.2", []),
            ("=1", []),
        ],
    )
    @respx.mock
    def test_batch_lookup_carries_exact_versions_only(
        self, tmp_path: Path, requirement: str, batched: list[str]
    ):
        self._project(tmp_path, requirement)
        self._registry()
        batch = respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []})
        )
        _row(tmp_path, "--no-transitive")
        sent = [
            item["versionKey"]["version"]
            for call in batch.calls
            for item in json.loads(call.request.content)["requests"]
        ]
        assert sent == batched

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        "requirement",
        [
            "3",  # nothing published is that new
            "^1.9",  # the one version inside is yanked
            "not a requirement",
            "1.0 || 2.0",  # not Cargo syntax
        ],
    )
    @respx.mock
    def test_range_that_selects_nothing_is_unknown(
        self, tmp_path: Path, mode: str, requirement: str
    ):
        self._project(tmp_path, requirement)
        self._registry()
        assert _row(tmp_path, mode) == _UNRESOLVED


class TestRubyGems:
    _API = "https://rubygems.org/api"
    _LICENSES = {
        "2.0.0": "Apache-2.0",
        "1.4.0": "MIT",
        "1.2.0": "BSD-3-Clause",
        "0.9.0": "ISC",
    }

    @staticmethod
    def _project(tmp_path: Path, requirement: str) -> None:
        (tmp_path / "Gemfile").write_text(
            f'source "https://rubygems.org"\ngem "lib", {requirement}\n'
        )

    def _registry(self, listing: httpx.Response | None = None) -> tuple[respx.Route, respx.Route]:
        """Serve the gem, latest release 2.0.0; return the latest and list routes.

        ``listing`` replaces the version list the registry answers with.
        """
        for version, license_id in self._LICENSES.items():
            _json(
                f"{self._API}/v2/rubygems/lib/versions/{version}.json",
                {"version": version, "licenses": [license_id], "dependencies": {"runtime": []}},
            )
        latest = _json(
            f"{self._API}/v1/gems/lib.json",
            {
                "version": "2.0.0",
                "licenses": [self._LICENSES["2.0.0"]],
                "dependencies": {"runtime": []},
            },
        )
        if listing is None:
            # One entry per version and platform, each with far more than the
            # number.
            listing = httpx.Response(
                200,
                json=[
                    {"number": number, "platform": platform, "summary": "A gem.", "sha": "0" * 64}
                    for number in ("2.1.0.rc1", *self._LICENSES)
                    for platform in ("ruby", "java")
                ],
            )
        return latest, respx.get(f"{self._API}/v1/versions/lib.json").mock(return_value=listing)

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("requirement", "version"),
        [
            ('"~> 1.2"', "1.4.0"),
            ('"~> 1.2.0"', "1.2.0"),
            ('">= 1.0", "< 1.3"', "1.2.0"),
            ('"< 1"', "0.9.0"),
            # The newest version is a prerelease; a release is preferred.
            ('"!= 2.0.0"', "1.4.0"),
        ],
    )
    @respx.mock
    def test_latest_release_outside_the_range(
        self, tmp_path: Path, mode: str, requirement: str, version: str
    ):
        self._project(tmp_path, requirement)
        _, listing = self._registry()
        assert _row(tmp_path, mode) == (version, self._LICENSES[version], _ESTIMATED)
        assert listing.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("requirement", ['">= 1.0"', '"~> 2.0"', '"> 0.9", "!= 1.4.0"'])
    @respx.mock
    def test_latest_release_inside_the_range_needs_no_version_list(
        self, tmp_path: Path, mode: str, requirement: str
    ):
        self._project(tmp_path, requirement)
        _, listing = self._registry()
        assert _row(tmp_path, mode) == ("2.0.0", "Apache-2.0", _ESTIMATED)
        assert not listing.called

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_selected_release_with_no_document_of_its_own_is_read_from_the_latest_response(
        self, tmp_path: Path, mode: str
    ):
        # The range selects the latest release, whose own endpoint answers
        # 404. The latest-release response describes that very release.
        self._project(tmp_path, '">= 1.0"')
        self._registry()
        respx.get(f"{self._API}/v2/rubygems/lib/versions/2.0.0.json").mock(
            return_value=httpx.Response(404)
        )
        assert _row(tmp_path, mode) == ("2.0.0", "Apache-2.0", _ESTIMATED)

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("status", [500, 503, 429])
    @respx.mock
    def test_failed_lookup_of_the_selected_release_is_unknown(
        self, tmp_path: Path, mode: str, status: int, fake_registry_clock
    ):
        self._project(tmp_path, '">= 1.0"')
        self._registry()
        respx.get(f"{self._API}/v2/rubygems/lib/versions/2.0.0.json").mock(
            return_value=httpx.Response(status)
        )
        assert _row(tmp_path, mode) == _UNRESOLVED

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_older_release_with_no_document_of_its_own_is_unknown(self, tmp_path: Path, mode: str):
        # The latest-release response describes 2.0.0, not the selected 1.4.0:
        # nothing the registry served is that release's metadata.
        self._project(tmp_path, '"~> 1.2"')
        self._registry()
        respx.get(f"{self._API}/v2/rubygems/lib/versions/1.4.0.json").mock(
            return_value=httpx.Response(404)
        )
        assert _row(tmp_path, mode) == _UNRESOLVED

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("requirement", ['"1.2.0"', '"= 1.2.0"'])
    @respx.mock
    def test_exact_requirement_is_not_an_estimate(
        self, tmp_path: Path, mode: str, requirement: str
    ):
        self._project(tmp_path, requirement)
        latest, listing = self._registry()
        assert _row(tmp_path, mode) == ("1.2.0", "BSD-3-Clause", [])
        assert not latest.called
        assert not listing.called

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_range_no_published_version_satisfies_is_unknown(self, tmp_path: Path, mode: str):
        self._project(tmp_path, '"~> 3.0"')
        _, listing = self._registry()
        assert _row(tmp_path, mode) == _UNRESOLVED
        assert listing.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_requirement_that_cannot_be_read_is_unknown(self, tmp_path: Path, mode: str):
        # Nothing to look for in the version list, so it is not requested.
        self._project(tmp_path, '"=> 1.0"')
        _, listing = self._registry()
        assert _row(tmp_path, mode) == _UNRESOLVED
        assert not listing.called

    @pytest.mark.parametrize(
        "body",
        [
            httpx.Response(404),
            httpx.Response(200, text="not json"),
            httpx.Response(200, json={"error": "not a list"}),
            httpx.Response(200, json=["2.0.0", {"number": 1.4}, {"platform": "ruby"}]),
        ],
    )
    @respx.mock
    def test_version_list_that_cannot_be_read_selects_nothing(self, body: httpx.Response):
        latest, _ = self._registry(body)
        dep = Dependency(name="lib", version_constraint="~> 1.2", ecosystem=Ecosystem.RUBY)
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_ruby_license(
                dep, client, fetcher=cache.fetch, text_fetcher=cache.fetch_text
            )
        assert (info.license_id, info.resolved_version) == ("UNKNOWN", "")
        assert latest.call_count == 1

    @respx.mock
    def test_latest_response_that_names_no_version_selects_nothing(self):
        _json(f"{self._API}/v1/gems/lib.json", {"licenses": ["MIT"]})
        dep = Dependency(name="lib", version_constraint="~> 1.2", ecosystem=Ecosystem.RUBY)
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_ruby_license(
                dep, client, fetcher=cache.fetch, text_fetcher=cache.fetch_text
            )
        assert (info.license_id, info.resolved_version) == ("UNKNOWN", "")

    @respx.mock
    def test_version_list_is_cached_as_version_numbers_only(self):
        _, listing = self._registry()
        dep = Dependency(name="lib", version_constraint="~> 1.2", ecosystem=Ecosystem.RUBY)
        cache = RegistryCache()
        with httpx.Client() as client:
            for _ in range(2):
                info = resolve_ruby_license(
                    dep, client, fetcher=cache.fetch, text_fetcher=cache.fetch_text
                )
                assert (info.license_id, info.resolved_version) == ("MIT", "1.4.0")
            cached = cache.fetch_text(f"{self._API}/v1/versions/lib.json", client)
        assert listing.call_count == 1
        assert cached is not None
        assert {frozenset(entry) for entry in json.loads(cached["text"])} == {frozenset({"number"})}


class TestHex:
    _PACKAGE = "https://hex.pm/api/packages/lib"
    _PUBLISHED = ("2.1.0-rc.1", "2.0.0", "1.4.0", "1.2.0", "0.9.0")

    @staticmethod
    def _project(tmp_path: Path, requirement: str) -> None:
        _write(
            tmp_path / "mix.exs",
            f"""\
            defmodule App.MixProject do
              use Mix.Project

              defp deps do
                [
                  {{:lib, "{requirement}"}}
                ]
              end
            end
            """,
        )

    @classmethod
    def _releases(cls) -> list[dict[str, str]]:
        """The published releases as the package response lists them.

        Each one was published a year after the one below it, so the
        prerelease is the release published last.
        """
        return [
            {"version": version, "inserted_at": f"{2025 - age}-03-01T10:00:00.000000Z"}
            for age, version in enumerate(cls._PUBLISHED)
        ]

    def _registry(self) -> respx.Route:
        """Serve the package, latest stable release 2.0.0.

        Its license is per package: the one of the release published last.
        """
        for version in self._PUBLISHED:
            _json(f"{self._PACKAGE}/releases/{version}", {"requirements": {}})
        return _json(
            self._PACKAGE,
            {
                "meta": {"licenses": ["MIT"], "links": {}},
                "latest_stable_version": "2.0.0",
                "latest_version": "2.1.0-rc.1",
                "releases": [
                    {**release, "url": f"{self._PACKAGE}/releases/{release['version']}"}
                    for release in self._releases()
                ],
            },
        )

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("requirement", "version", "estimated"),
        [
            # The package's one license belongs to another release than the
            # selected one, so it is an estimate beside the version.
            ("~> 1.2", "1.4.0", ["license", "version"]),
            ("~> 1.2.0", "1.2.0", ["license", "version"]),
            (">= 1.0.0 and < 1.3.0", "1.2.0", ["license", "version"]),
            ("~> 0.9 or ~> 1.2.0", "1.2.0", ["license", "version"]),
            ("< 1.0.0", "0.9.0", ["license", "version"]),
            (">= 1.0.0", "2.0.0", ["license", "version"]),
            # A prerelease is selected only by a requirement that names one.
            # It is the release published last: the license is its own.
            ("~> 2.1.0-rc", "2.1.0-rc.1", _ESTIMATED),
        ],
    )
    @respx.mock
    def test_range_selects_the_highest_release_inside_it(
        self, tmp_path: Path, mode: str, requirement: str, version: str, estimated: list[str]
    ):
        self._project(tmp_path, requirement)
        package = self._registry()
        assert _row(tmp_path, mode) == (version, "MIT", estimated)
        # The releases come with the package response the license is read from.
        assert package.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("requirement", ["1.2.0", "== 1.2.0"])
    @respx.mock
    def test_exact_requirement_is_not_a_version_estimate(
        self, tmp_path: Path, mode: str, requirement: str
    ):
        # The version is the declared one. The license is the package's,
        # which is that of 2.1.0-rc.1.
        self._project(tmp_path, requirement)
        self._registry()
        assert _row(tmp_path, mode) == ("1.2.0", "MIT", ["license"])

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        "requirement", ["~> 3.0", ">= 1.5.0 and < 2.0.0", "~> 1.2 xor 3", "^1.2"]
    )
    @respx.mock
    def test_range_that_selects_nothing_is_unknown(
        self, tmp_path: Path, mode: str, requirement: str
    ):
        self._project(tmp_path, requirement)
        self._registry()
        assert _row(tmp_path, mode) == _UNRESOLVED

    @respx.mock
    def test_releases_survive_the_cache(self):
        # The release list is read from the cached package response, so it
        # must be among the fields the cache keeps, with each release's
        # publication time.
        package = self._registry()
        dep = Dependency(name="lib", version_constraint="~> 1.2", ecosystem=Ecosystem.HEX)
        cache = RegistryCache()
        with httpx.Client() as client:
            for _ in range(2):
                info = resolve_hex_license(dep, client, fetcher=cache.fetch)
                assert (info.license_id, info.resolved_version) == ("MIT", "1.4.0")
            cached = cache.fetch(self._PACKAGE, client)
        assert package.call_count == 1
        assert cached is not None
        assert cached["releases"] == self._releases()

    @pytest.mark.parametrize("releases", [None, "wrong", ["wrong", {"version": 2}, {"url": "u"}]])
    @respx.mock
    def test_release_list_that_cannot_be_read_leaves_the_latest_release(self, releases: object):
        # The latest stable release is still a candidate: selected when it
        # is inside the range, and never when it is outside.
        _json(
            self._PACKAGE,
            {"meta": {"licenses": ["MIT"]}, "latest_stable_version": "2.0.0", "releases": releases},
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            inside = resolve_hex_license(
                Dependency(name="lib", version_constraint="~> 2.0", ecosystem=Ecosystem.HEX),
                client,
                fetcher=cache.fetch,
            )
            outside = resolve_hex_license(
                Dependency(name="lib", version_constraint="~> 1.2", ecosystem=Ecosystem.HEX),
                client,
                fetcher=cache.fetch,
            )
        assert (inside.license_id, inside.resolved_version) == ("MIT", "2.0.0")
        assert (outside.license_id, outside.resolved_version) == ("UNKNOWN", "")
        assert outside.from_registry is False


class TestComposer:
    _PACKAGE = "https://repo.packagist.org/p2/vendor/lib.json"
    _LICENSES = {
        "v2.0.0": "Apache-2.0",
        "v1.4.0": "MIT",
        "v1.2.0": "BSD-3-Clause",
        "v0.9.0": "ISC",
    }

    @staticmethod
    def _project(tmp_path: Path, constraint: str) -> None:
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/lib": constraint}}))

    def _registry(self) -> respx.Route:
        """Serve the package newest first, behind a branch and a prerelease."""
        entries = [
            {"version": "dev-main", "license": ["Unlicense"]},
            {"version": "v2.1.0-RC1", "license": ["Zlib"]},
            *({"version": v, "license": [lic]} for v, lic in self._LICENSES.items()),
        ]
        return _json(self._PACKAGE, {"packages": {"vendor/lib": entries}})

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("constraint", "version"),
        [
            ("^1.2", "1.4.0"),
            ("~1.2", "1.4.0"),
            ("~1.2.0", "1.2.0"),
            ("1.2.*", "1.2.0"),
            (">=1.0 <1.3", "1.2.0"),
            (">=1.0,<1.3", "1.2.0"),
            ("^0.9 || ^1.2", "1.4.0"),
            ("^0.9|~1.2.0", "1.2.0"),
            ("1.0 - 1.3", "1.2.0"),
            ("<1.0", "0.9.0"),
            ("^v1.2", "1.4.0"),
            ("*", "2.0.0"),
            (">=1.0", "2.0.0"),
            # A stability flag admits the prerelease, which is selected when
            # no release is inside the range.
            (">=2.0@RC", "2.0.0"),
            (">2.0@RC", "2.1.0-RC1"),
        ],
    )
    @respx.mock
    def test_range_selects_the_highest_version_inside_it(
        self, tmp_path: Path, mode: str, constraint: str, version: str
    ):
        self._project(tmp_path, constraint)
        package = self._registry()
        license_id = "Zlib" if version == "2.1.0-RC1" else self._LICENSES[f"v{version}"]
        assert _row(tmp_path, mode, "vendor/lib") == (version, license_id, _ESTIMATED)
        assert package.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("constraint", ["1.2.0", "v1.2.0", "=1.2.0", "1.2.0.0"])
    @respx.mock
    def test_exact_version_is_not_an_estimate(self, tmp_path: Path, mode: str, constraint: str):
        self._project(tmp_path, constraint)
        self._registry()
        assert _row(tmp_path, mode, "vendor/lib") == ("1.2.0", "BSD-3-Clause", [])

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        "constraint",
        [
            "^3.0",  # nothing published is that new
            ">2.0",  # only a prerelease is, and nothing admits it
            "1.3.0",  # an exact version that was never published
            "dev-main",  # a branch, not a range of versions
            "1.x-dev",
            "not a constraint",
        ],
    )
    @respx.mock
    def test_constraint_that_selects_nothing_is_unknown(
        self, tmp_path: Path, mode: str, constraint: str
    ):
        self._project(tmp_path, constraint)
        self._registry()
        assert _row(tmp_path, mode, "vendor/lib") == _UNRESOLVED

    @respx.mock
    def test_locked_version_the_registry_does_not_list_is_unknown(self, tmp_path: Path):
        # The lockfile pins a version the response does not carry. The first
        # entry is another release, with a license of its own.
        self._project(tmp_path, "^1.2")
        (tmp_path / "composer.lock").write_text(
            json.dumps({"packages": [{"name": "vendor/lib", "version": "1.3.0"}]})
        )
        self._registry()
        result, report = _check_json(tmp_path, "--transitive", "--no-strict")
        assert result.exit_code == 0, result.output
        assert [
            (dep["name"], dep["resolved_version"], dep["license"]) for dep in report["dependencies"]
        ] == [("vendor/lib", "", "UNKNOWN")]


class TestNuGet:
    _FLAT = "https://api.nuget.org/v3-flatcontainer/lib"
    _LICENSES = {
        "0.9.0": "ISC",
        "1.0.0": "Zlib",
        "1.1.0": "MIT",
        "1.5.0": "BSD-3-Clause",
        "2.0.0": "Apache-2.0",
        "3.0.0": "0BSD",
    }

    @staticmethod
    def _project(tmp_path: Path, version: str) -> None:
        _write(
            tmp_path / "App.csproj",
            f"""\
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Lib" Version="{version}" />
              </ItemGroup>
            </Project>
            """,
        )

    def _registry(self) -> respx.Route:
        """Serve the package's nuspecs; return the route of its version list."""
        for version, license_id in self._LICENSES.items():
            _text(
                f"{self._FLAT}/{version}/lib.nuspec",
                f"<package><metadata><id>Lib</id><version>{version}</version>"
                f'<license type="expression">{license_id}</license></metadata></package>',
            )
        # Ascending, as the registry lists them, with a prerelease among them.
        versions = ["0.9.0", "1.0.0", "1.1.0", "1.5.0", "2.0.0-beta.1", "2.0.0", "3.0.0"]
        return _text(f"{self._FLAT}/index.json", json.dumps({"versions": versions}))

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("declared", "version"),
        [
            # An interval restores the lowest version inside it.
            ("(1.0.0,2.0.0]", "1.1.0"),
            ("(1.0.0,)", "1.1.0"),
            ("(,1.0.0]", "0.9.0"),
            ("(1.5.0,2.0.0]", "2.0.0"),
            # A floating version restores the highest version it matches.
            ("1.*", "1.5.0"),
            ("1.1.*", "1.1.0"),
            ("*", "3.0.0"),
        ],
    )
    @respx.mock
    def test_range_is_resolved_against_the_published_versions(
        self, tmp_path: Path, mode: str, declared: str, version: str
    ):
        self._project(tmp_path, declared)
        index = self._registry()
        assert _row(tmp_path, mode, "Lib") == (version, self._LICENSES[version], _ESTIMATED)
        assert index.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("declared", "version", "estimated"),
        [
            ("1.5.0", "1.5.0", []),
            ("[1.5.0]", "1.5.0", []),
            ("[1.0.0,2.0.0)", "1.0.0", _ESTIMATED),
            ("[1.1.0,)", "1.1.0", _ESTIMATED),
        ],
    )
    @respx.mock
    def test_inclusive_lower_bound_needs_no_version_list(
        self, tmp_path: Path, mode: str, declared: str, version: str, estimated: list[str]
    ):
        self._project(tmp_path, declared)
        index = self._registry()
        assert _row(tmp_path, mode, "Lib") == (version, self._LICENSES[version], estimated)
        assert not index.called

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("declared", ["(3.0.0,)", "(1.1.0,1.5.0)", "[2.0.0,1.0.0]", "4.*"])
    @respx.mock
    def test_range_no_published_version_satisfies_is_unknown(
        self, tmp_path: Path, mode: str, declared: str
    ):
        self._project(tmp_path, declared)
        index = self._registry()
        assert _row(tmp_path, mode, "Lib") == _UNRESOLVED
        assert index.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("declared", ["^1.0.0", "[1.0.0", "1.0.0,2.0.0", "(1.0.0)"])
    @respx.mock
    def test_version_that_is_not_a_range_is_unknown(self, tmp_path: Path, mode: str, declared: str):
        self._project(tmp_path, declared)
        index = self._registry()
        assert _row(tmp_path, mode, "Lib") == _UNRESOLVED
        assert not index.called

    @pytest.mark.parametrize(
        "body",
        [
            httpx.Response(404),
            httpx.Response(200, text="not json"),
            httpx.Response(200, json=["1.1.0"]),
            httpx.Response(200, json={"versions": "1.1.0"}),
            httpx.Response(200, json={"versions": [1.1, None]}),
        ],
    )
    @respx.mock
    def test_version_list_that_cannot_be_read_selects_nothing(self, body: httpx.Response):
        respx.get(f"{self._FLAT}/index.json").mock(return_value=body)
        dep = Dependency(name="Lib", version_constraint="(1.0.0,2.0.0]", ecosystem=Ecosystem.DOTNET)
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_nuget_license(
                dep, client, fetcher=cache.fetch_text, json_fetcher=cache.fetch
            )
        assert (info.license_id, info.resolved_version) == ("UNKNOWN", "")

    @respx.mock
    def test_version_list_is_read_through_the_cache(self):
        index = self._registry()
        cache = RegistryCache()
        with httpx.Client() as client:
            picks = [
                _resolve_nuget_version("Lib", declared, client, cache.fetch_text)
                for declared in ("(1.0.0,2.0.0]", "1.*", "(1.0.0,2.0.0]")
            ]
        assert picks == ["1.1.0", "1.5.0", "1.1.0"]
        assert index.call_count == 1


class TestNpm:
    """The version a range selects is looked up at its own endpoint, with the
    walk and without it. The package document the range was resolved on lists
    that version with its metadata, and answers when the endpoint has no
    document.
    """

    _PACKAGE = "https://registry.npmjs.org/lib"
    _LICENSES = {"2.0.0": "Apache-2.0", "1.5.0": "MIT", "1.2.0": "ISC"}

    @staticmethod
    def _project(tmp_path: Path, declared: str) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lib": declared}}))

    def _registry(self, *, own_endpoint: httpx.Response | None = None) -> respx.Route:
        """Serve the package, latest release 2.0.0; return the package-document route.

        ``own_endpoint`` is what the endpoint of 1.5.0 answers in place of
        that version's document.
        """
        metadata = {
            number: {"version": number, "license": license_id}
            for number, license_id in self._LICENSES.items()
        }
        for number, entry in metadata.items():
            answer = httpx.Response(200, json=entry)
            if number == "1.5.0" and own_endpoint is not None:
                answer = own_endpoint
            respx.get(f"{self._PACKAGE}/{number}").mock(return_value=answer)
        return _json(
            self._PACKAGE,
            {"dist-tags": {"latest": "2.0.0", "stable": "1.2.0"}, "versions": metadata},
        )

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("declared", "version"),
        [("^1.0.0", "1.5.0"), ("~1.2.0", "1.2.0"), ("*", "2.0.0"), ("stable", "1.2.0")],
    )
    @respx.mock
    def test_range_selects_the_highest_version_inside_it(
        self, tmp_path: Path, mode: str, declared: str, version: str
    ):
        self._project(tmp_path, declared)
        package = self._registry()
        assert _row(tmp_path, mode) == (version, self._LICENSES[version], _ESTIMATED)
        assert package.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_version_with_no_document_of_its_own_is_read_from_the_package_document(
        self, tmp_path: Path, mode: str
    ):
        self._project(tmp_path, "^1.0.0")
        package = self._registry(own_endpoint=httpx.Response(404))
        # The entry is that version's own metadata: the license is no estimate.
        assert _row(tmp_path, mode) == ("1.5.0", "MIT", _ESTIMATED)
        assert package.call_count == 1

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("status", [500, 503, 429])
    @respx.mock
    def test_failed_lookup_of_the_selected_version_is_unknown(
        self, tmp_path: Path, mode: str, status: int, fake_registry_clock
    ):
        self._project(tmp_path, "^1.0.0")
        self._registry(own_endpoint=httpx.Response(status))
        exact = respx.get("https://api.deps.dev/v3/systems/NPM/packages/lib/versions/1.5.0").mock(
            return_value=httpx.Response(404)
        )
        # Not the license of the latest release, and not the package
        # document's either: the lookup of this version failed.
        assert _row(tmp_path, mode) == ("1.5.0", "UNKNOWN", _ESTIMATED)
        assert exact.called

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_range_no_published_version_satisfies_is_unknown(self, tmp_path: Path, mode: str):
        self._project(tmp_path, "^3.0.0")
        self._registry()
        assert _row(tmp_path, mode) == _UNRESOLVED


class TestPrereleaseLowerBound:
    """A range from a release candidate up to its release stops short of the release.

    ``>=2.0.0-rc.1 <2.0.0`` resolves to the newest candidate published, in
    npm and in Cargo. Each registry lists the candidates, the release, and a
    version on either side.
    """

    _LICENSES = {
        "1.9.0": "ISC",
        "2.0.0-rc.1": "MIT",
        "2.0.0-rc.2": "BSD-3-Clause",
        "2.0.0": "Apache-2.0",
        "2.1.0": "Zlib",
    }

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("declared", "version"),
        [
            (">=2.0.0-rc.1 <2.0.0", "2.0.0-rc.2"),
            (">=2.0.0-rc.1 <=2.0.0", "2.0.0"),
            # The candidates of 2.0.0 are not below it for a range that names none.
            ("<2.0.0", "1.9.0"),
        ],
    )
    @respx.mock
    def test_npm(self, tmp_path: Path, mode: str, declared: str, version: str):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lib": declared}}))
        metadata = {
            number: {"version": number, "license": license_id}
            for number, license_id in self._LICENSES.items()
        }
        _json("https://registry.npmjs.org/lib", {"versions": metadata})
        for number, entry in metadata.items():
            _json(f"https://registry.npmjs.org/lib/{number}", entry)
        assert _row(tmp_path, mode) == (version, self._LICENSES[version], _ESTIMATED)

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(
        ("requirement", "version"),
        [
            (">=2.0.0-rc.1, <2.0.0", "2.0.0-rc.2"),
            (">=2.0.0-rc.1, <=2.0.0", "2.0.0"),
            ("<2.0.0", "1.9.0"),
        ],
    )
    @respx.mock
    def test_cargo(self, tmp_path: Path, mode: str, requirement: str, version: str):
        TestCargo._project(tmp_path, requirement)
        crate = "https://crates.io/api/v1/crates/lib"
        for number, license_id in self._LICENSES.items():
            _json(f"{crate}/{number}", {"version": {"num": number, "license": license_id}})
            _json(f"{crate}/{number}/dependencies", {"dependencies": []})
        _json(
            crate,
            {
                "crate": {"max_stable_version": "2.1.0", "newest_version": "2.1.0"},
                "versions": [{"num": number, "yanked": False} for number in self._LICENSES],
            },
        )
        assert _row(tmp_path, mode) == (version, self._LICENSES[version], _ESTIMATED)
