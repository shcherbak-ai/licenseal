"""An exact pin names the release the registry publishes, however it is spelled.

A manifest can write one version with fewer or more segments than the
registry lists it under: ``1.2`` for a release published as ``1.2.0``.
RubyGems and NuGet read both as one version, and both registries answer only
for the spelling they list. A scan reports the release under the published
spelling, with that release's license, and does not mark the version as an
estimate: the manifest fixes it.

Each scan reads a manifest from disk against mocked registries, with and
without the transitive stage. A registry answers 404 for a spelling it does
not list, as the real ones do; a request to an endpoint a test does not mock
fails the test.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers.http import RegistryCache
from licenseal.resolvers.nuget import _extract_pinned_version_nuget
from licenseal.resolvers.rubygems import resolve_ruby_license
from licenseal.resolvers.version_selection import satisfies
from tests._helpers import _check_json, _write

_MODES = pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
_ESTIMATED = ["version"]


def _rows(report: dict) -> dict[str, tuple[str, str, list[str]]]:
    return {
        dep["name"]: (dep["resolved_version"], dep["license"], dep["estimated"])
        for dep in report["dependencies"]
    }


def _scan(tmp_path: Path, *flags: str) -> dict:
    result, report = _check_json(tmp_path, *flags, "--no-strict", "--no-require-lockfile")
    assert result.exit_code == 0, result.output
    return report


def _gaps(report: dict) -> list[dict]:
    return [diag for diag in report["diagnostics"] if diag["severity"] == "gap"]


def _requested(fragment: str) -> list[str]:
    return [str(call.request.url) for call in respx.calls if fragment in str(call.request.url)]


class TestRubyGems:
    _API = "https://rubygems.org/api"

    @staticmethod
    def _gemfile(tmp_path: Path, requirement: str) -> None:
        (tmp_path / "Gemfile").write_text(
            f'source "https://rubygems.org"\ngem "lib", "{requirement}"\n', encoding="utf-8"
        )

    def _version(self, gem: str, number: str, license_id: str, *runtime: dict) -> respx.Route:
        return respx.get(f"{self._API}/v2/rubygems/{gem}/versions/{number}.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "number": number,
                    "licenses": [license_id],
                    "dependencies": {"runtime": list(runtime)},
                },
            )
        )

    def _unlisted(self, gem: str, spelling: str) -> respx.Route:
        return respx.get(f"{self._API}/v2/rubygems/{gem}/versions/{spelling}.json").mock(
            return_value=httpx.Response(404)
        )

    def _listing(self, gem: str, *numbers: str) -> respx.Route:
        return respx.get(f"{self._API}/v1/versions/{gem}.json").mock(
            return_value=httpx.Response(200, json=[{"number": number} for number in numbers])
        )

    @_MODES
    @pytest.mark.parametrize(
        ("requirement", "literal"),
        [("1.2", "1.2"), ("= 1.2", "1.2"), ("1.2.0.0", "1.2.0.0"), ("= 1.2.0.0", "1.2.0.0")],
    )
    @respx.mock
    def test_pin_with_other_segments_is_the_published_release(
        self, tmp_path: Path, mode: str, requirement: str, literal: str
    ):
        self._gemfile(tmp_path, requirement)
        missed = self._unlisted("lib", literal)
        listing = self._listing("lib", "1.1.0", "1.2.0", "1.2.1", "1.3.0.rc1")
        self._version("lib", "1.2.0", "MIT")

        report = _scan(tmp_path, mode)
        # The published spelling, that release's license, and no estimate mark.
        assert _rows(report) == {"lib": ("1.2.0", "MIT", [])}
        assert _gaps(report) == []
        # One request for the spelling as written, then one for the list.
        assert (missed.call_count, listing.call_count) == (1, 1)

    @respx.mock
    def test_requirement_a_gem_declares_is_resolved_the_same_way(self, tmp_path: Path):
        # The walk reads ``= 3.0`` from the registry, for a gem published as 3.0.0.
        self._gemfile(tmp_path, "1.2.0")
        self._version("lib", "1.2.0", "MIT", {"name": "child", "requirements": "= 3.0"})
        self._unlisted("child", "3.0")
        self._listing("child", "2.9.0", "3.0.0", "3.0.1")
        self._version("child", "3.0.0", "ISC")

        report = _scan(tmp_path, "--transitive")
        assert _rows(report) == {
            "lib": ("1.2.0", "MIT", []),
            "child": ("3.0.0", "ISC", _ESTIMATED),
        }
        assert _gaps(report) == []

    @_MODES
    @respx.mock
    def test_pin_spelled_as_published_costs_no_version_list(self, tmp_path: Path, mode: str):
        # The version list is not served: asking for it would fail the test.
        self._gemfile(tmp_path, "1.2.0")
        release = self._version("lib", "1.2.0", "MIT")
        assert _rows(_scan(tmp_path, mode)) == {"lib": ("1.2.0", "MIT", [])}
        assert release.call_count == 1

    @_MODES
    @respx.mock
    def test_pin_no_published_version_equals_is_unknown(self, tmp_path: Path, mode: str):
        self._gemfile(tmp_path, "1.5")
        self._unlisted("lib", "1.5")
        listing = self._listing("lib", "1.4.0", "1.5.1", "1.50.0")
        rows = _rows(_scan(tmp_path, mode))
        assert rows["lib"][1:] == ("UNKNOWN", [])
        assert listing.call_count == 1

    @_MODES
    @pytest.mark.parametrize(
        "listing",
        [
            httpx.Response(404),
            httpx.Response(200, text="not json"),
            httpx.Response(200, json=[]),
        ],
    )
    @respx.mock
    def test_version_list_that_cannot_be_read_leaves_the_pin_unknown(
        self, tmp_path: Path, mode: str, listing: httpx.Response
    ):
        # A second gem resolves, so the scan is not one that reached no registry.
        self._gemfile(tmp_path, "1.2")
        with (tmp_path / "Gemfile").open("a", encoding="utf-8") as gemfile:
            gemfile.write('gem "other", "1.0.0"\n')
        self._version("other", "1.0.0", "MIT")
        self._unlisted("lib", "1.2")
        respx.get(f"{self._API}/v1/versions/lib.json").mock(return_value=listing)
        rows = _rows(_scan(tmp_path, mode))
        assert rows["lib"][1:] == ("UNKNOWN", [])
        assert rows["other"] == ("1.0.0", "MIT", [])

    @respx.mock
    def test_locked_version_is_not_looked_up_under_another_spelling(self, tmp_path: Path):
        # A lockfile records the version as published. One the registry does
        # not have stays UNKNOWN, and the version list is not asked for.
        self._gemfile(tmp_path, "~> 9.0")
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    lib (9.9)\n    other (1.0.0)\n\n"
            "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  lib (~> 9.0)\n  other\n",
            encoding="utf-8",
        )
        with (tmp_path / "Gemfile").open("a", encoding="utf-8") as gemfile:
            gemfile.write('gem "other"\n')
        self._unlisted("lib", "9.9")
        self._version("other", "1.0.0", "MIT")
        rows = _rows(_scan(tmp_path, "--transitive"))
        assert rows["lib"][1:] == ("UNKNOWN", [])
        assert rows["other"] == ("1.0.0", "MIT", [])
        assert _requested("/v1/versions/") == []

    @respx.mock
    def test_lockfile_covers_a_pin_spelled_with_fewer_segments(self, tmp_path: Path):
        self._gemfile(tmp_path, "1.2")
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    lib (1.2.0)\n\n"
            "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  lib (= 1.2)\n",
            encoding="utf-8",
        )
        self._version("lib", "1.2.0", "MIT")
        result, report = _check_json(tmp_path)
        assert result.exit_code == 0, result.output
        assert _rows(report) == {"lib": ("1.2.0", "MIT", [])}
        assert [dep["source"] for dep in report["dependencies"]] == ["Gemfile"]
        assert report["diagnostics"] == []

    @respx.mock
    def test_resolver_asks_once_for_a_pin_spelled_as_published(self):
        release = self._version("lib", "1.2.0", "MIT")
        dep = Dependency(name="lib", version_constraint="= 1.2.0", ecosystem=Ecosystem.RUBY)
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_ruby_license(
                dep, client, fetcher=cache.fetch, text_fetcher=cache.fetch_text
            )
        assert (info.license_id, info.resolved_version) == ("MIT", "1.2.0")
        assert release.call_count == 1


class TestNuGet:
    _FLAT = "https://api.nuget.org/v3-flatcontainer"
    _BATCH = "https://api.deps.dev/v3alpha/versionbatch"

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

    def _nuspec(self, package: str, version: str, license_id: str, *deps: str) -> respx.Route:
        """Serve one nuspec; ``deps`` are ``id=version`` pairs it depends on."""
        declared = "".join(
            '<dependency id="{}" version="{}" />'.format(*dep.split("=")) for dep in deps
        )
        return respx.get(f"{self._FLAT}/{package.lower()}/{version}/{package.lower()}.nuspec").mock(
            return_value=httpx.Response(
                200,
                text=(
                    f"<package><metadata><id>{package}</id><version>{version}</version>"
                    f'<license type="expression">{license_id}</license>'
                    f"<dependencies>{declared}</dependencies></metadata></package>"
                ),
            )
        )

    @_MODES
    @pytest.mark.parametrize(
        ("declared", "estimated"),
        [
            ("1.5", []),
            ("1.5.0.0", []),
            ("[1.5]", []),
            ("01.05.0", []),
            ("1.5.0+build.7", []),
            # A range restores its lower bound, under the published spelling too.
            ("[1.5,2.0)", _ESTIMATED),
            # Control: the spelling nuget.org lists.
            ("1.5.0", []),
        ],
    )
    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_version_is_asked_for_under_its_published_spelling(
        self, tmp_path: Path, mode: str, declared: str, estimated: list[str]
    ):
        # Only ``1.5.0`` and ``2.0.0`` are served: a request that carried
        # another spelling of either would fail the test.
        self._project(tmp_path, declared)
        self._nuspec("Lib", "1.5.0", "BSD-3-Clause", "Child=2.0")
        batch = respx.post(self._BATCH).mock(
            return_value=httpx.Response(200, json={"responses": []})
        )
        expected = {"Lib": ("1.5.0", "BSD-3-Clause", estimated)}
        if mode == "--transitive":
            # The dependency a nuspec declares as ``2.0`` is version 2.0.0.
            self._nuspec("Child", "2.0.0", "MIT")
            expected["Child"] = ("2.0.0", "MIT", _ESTIMATED)

        report = _scan(tmp_path, mode)
        assert _rows(report) == expected
        assert _gaps(report) == []
        batched = {
            (item["versionKey"]["name"], item["versionKey"]["version"])
            for call in batch.calls
            for item in json.loads(call.request.content)["requests"]
        }
        assert ("Lib", "1.5.0") in batched
        assert {version for _, version in batched} <= {"1.5.0", "2.0.0"}

    @respx.mock
    def test_two_spellings_of_one_version_are_one_row(self, tmp_path: Path):
        # Two packages depend on one version of a third, each spelling it its
        # own way.
        _write(
            tmp_path / "App.csproj",
            """\
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="First" Version="1.0.0" />
                <PackageReference Include="Second" Version="1.0.0" />
              </ItemGroup>
            </Project>
            """,
        )
        self._nuspec("First", "1.0.0", "MIT", "Shared=2.0")
        self._nuspec("Second", "1.0.0", "MIT", "Shared=2.0.0.0")
        shared = self._nuspec("Shared", "2.0.0", "ISC")

        report = _scan(tmp_path, "--transitive")
        assert _rows(report)["Shared"] == ("2.0.0", "ISC", _ESTIMATED)
        assert sum(dep["name"] == "Shared" for dep in report["dependencies"]) == 1
        ancestors = next(d for d in report["dependencies"] if d["name"] == "Shared")
        assert ancestors["direct_ancestors"] == ["First", "Second"]
        assert shared.call_count == 1

    @pytest.mark.parametrize(
        ("declared", "published"),
        [
            ("1.2", "1.2.0"),
            ("1", "1.0.0"),
            ("1.2.3", "1.2.3"),
            ("1.2.3.0", "1.2.3"),
            # A fourth segment that is not zero is part of the version.
            ("1.2.3.4", "1.2.3.4"),
            ("01.002.3", "1.2.3"),
            ("1.2.3+sha.abc", "1.2.3"),
            # The prerelease label is kept as written.
            ("1.2-Beta.1", "1.2.0-Beta.1"),
            ("[1.2]", "1.2.0"),
            ("==1.2.0.0", "1.2.0"),
            ("[1.2,2.0)", "1.2.0"),
            ("[ 1.2.0.0 , )", "1.2.0"),
        ],
    )
    def test_published_spelling(self, declared: str, published: str):
        assert _extract_pinned_version_nuget(declared) == published


class TestRegistriesThatReadEverySpelling:
    """PyPI and Packagist need nothing done: the lookup is by version, not by text."""

    @_MODES
    @pytest.mark.parametrize("pinned", ["1.2", "1.2.0", "1.2.0.0"])
    @respx.mock
    def test_python_pin_is_reported_at_the_version_pypi_names(
        self, tmp_path: Path, mode: str, pinned: str
    ):
        # PyPI answers the per-version endpoint for any PEP 440 spelling of a
        # release, and names the release in the response.
        (tmp_path / "requirements.txt").write_text(f"lib=={pinned}\n", encoding="utf-8")
        respx.get(f"https://pypi.org/pypi/lib/{pinned}/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "name": "lib",
                        "version": "1.2.0",
                        "license": "MIT",
                        "classifiers": [],
                        "requires_dist": [],
                    }
                },
            )
        )
        assert _rows(_scan(tmp_path, mode)) == {"lib": ("1.2.0", "MIT", [])}

    @_MODES
    @pytest.mark.parametrize("constraint", ["1.2", "1.2.0", "1.2.0.0", "v1.2"])
    @respx.mock
    def test_composer_pin_is_matched_as_a_version(self, tmp_path: Path, mode: str, constraint: str):
        (tmp_path / "composer.json").write_text(
            json.dumps({"require": {"vendor/lib": constraint}}), encoding="utf-8"
        )
        entries = [
            {"version": "v1.3.0", "license": ["Apache-2.0"]},
            {"version": "v1.2.0", "license": ["MIT"]},
        ]
        respx.get("https://repo.packagist.org/p2/vendor/lib.json").mock(
            return_value=httpx.Response(200, json={"packages": {"vendor/lib": entries}})
        )
        assert _rows(_scan(tmp_path, mode)) == {"vendor/lib": ("1.2.0", "MIT", [])}


class TestLockCoverage:
    """``satisfies`` compares versions, so a lockfile covers a pin in any spelling."""

    @pytest.mark.parametrize(
        ("ecosystem", "locked", "declared"),
        [
            (Ecosystem.RUBY, "1.2.0", "1.2"),
            (Ecosystem.RUBY, "1.2.0", "= 1.2"),
            (Ecosystem.RUBY, "1.2", "= 1.2.0.0"),
            (Ecosystem.DOTNET, "1.2.0", "[1.2]"),
            (Ecosystem.DOTNET, "1.2.0", "[1.2.0.0]"),
            (Ecosystem.DOTNET, "1.2.0", "1.2"),
            (Ecosystem.PHP, "1.2.0", "1.2"),
            (Ecosystem.PHP, "v1.2.0", "1.2.0.0"),
            (Ecosystem.PYTHON, "1.2.0", "==1.2"),
            (Ecosystem.PYTHON, "1.2", "==1.2.0.0"),
        ],
    )
    def test_locked_version_meets_a_pin_in_another_spelling(
        self, ecosystem: Ecosystem, locked: str, declared: str
    ):
        assert satisfies(ecosystem, locked, declared) is True

    @pytest.mark.parametrize(
        ("ecosystem", "locked", "declared"),
        [
            (Ecosystem.RUBY, "1.2.1", "1.2"),
            (Ecosystem.DOTNET, "1.2.1", "[1.2]"),
            (Ecosystem.PHP, "1.2.1", "1.2"),
            (Ecosystem.PYTHON, "1.2.1", "==1.2"),
        ],
    )
    def test_another_version_does_not(self, ecosystem: Ecosystem, locked: str, declared: str):
        assert satisfies(ecosystem, locked, declared) is False
