"""Tests for the Hex (hex.pm) license resolver."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.analysis.compatibility import check_compatibility
from licenseal.models import CompatibilityVerdict, Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.hex import (
    _described_version,
    _extract_homepage_url,
    _extract_pinned_version,
    _extract_repository_url,
    _hex_package_url,
    _hex_release_url,
    _latest_version,
    _license_entries,
    fetch_hex_dependencies,
    resolve_hex_license,
)
from licenseal.resolvers.http import (
    _HEX_PACKAGE_KEEP,
    _HEX_PACKAGE_RELEASE_KEEP,
    _HEX_RELEASE_KEEP,
    RegistryCache,
    _trim_for_cache,
    _trim_hex_package,
    _trim_hex_release,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "registry-responses" / "hex"


def _hex_dep(
    name: str = "phoenix",
    version: str = "==1.7.10",
    group: DependencyGroup = DependencyGroup.PROD,
    source: str = "",
) -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.HEX,
        group=group,
        source=source,
    )


class TestExtractPinnedVersion:
    def test_double_equals(self):
        assert _extract_pinned_version("==1.7.10") == "1.7.10"

    def test_range_returns_none(self):
        assert _extract_pinned_version("~> 1.7") is None
        assert _extract_pinned_version(">= 1.0.0") is None

    def test_multi_constraint_returns_none(self):
        assert _extract_pinned_version("~> 1.0, < 2.0") is None

    def test_empty_returns_none(self):
        assert _extract_pinned_version("") is None
        assert _extract_pinned_version("==") is None

    def test_internal_space_returns_none(self):
        assert _extract_pinned_version("==1 0") is None


class TestUrls:
    def test_package_url(self):
        assert _hex_package_url("phoenix") == "https://hex.pm/api/packages/phoenix"

    def test_release_url(self):
        assert (
            _hex_release_url("phoenix", "1.7.10")
            == "https://hex.pm/api/packages/phoenix/releases/1.7.10"
        )


class TestLicenseEntries:
    def test_array_single(self):
        assert _license_entries(["MIT"]) == ["MIT"]

    def test_array_multi_keeps_every_entry(self):
        assert _license_entries(["MIT", " Apache-2.0 "]) == ["MIT", "Apache-2.0"]

    def test_empty_array(self):
        assert _license_entries([]) == []

    def test_bare_string(self):
        assert _license_entries("MIT") == ["MIT"]

    def test_blank_and_non_string_entries_are_skipped(self):
        assert _license_entries(["", "  ", 5, None, "MIT"]) == ["MIT"]

    def test_unsupported_type(self):
        assert _license_entries(None) == []
        assert _license_entries(42) == []


class TestExtractUrls:
    def test_repository_from_vcs_label(self):
        links = {"GitHub": "https://github.com/x/y", "Website": "https://x.dev"}
        assert _extract_repository_url(links) == "https://github.com/x/y"

    def test_repository_missing_returns_empty(self):
        assert _extract_repository_url({"Website": "https://x.dev"}) == ""

    def test_repository_non_dict_returns_empty(self):
        assert _extract_repository_url(None) == ""

    def test_homepage_first_non_repo_link(self):
        links = {"GitHub": "https://github.com/x/y", "Website": "https://x.dev"}
        assert _extract_homepage_url(links) == "https://x.dev"

    def test_homepage_only_repo_returns_empty(self):
        assert _extract_homepage_url({"GitHub": "https://github.com/x/y"}) == ""

    def test_homepage_non_dict_returns_empty(self):
        assert _extract_homepage_url("nope") == ""

    def test_homepage_skips_blank_url(self):
        assert _extract_homepage_url({"Website": "   ", "Docs": "https://d"}) == "https://d"


class TestLatestVersion:
    def test_prefers_stable(self):
        assert (
            _latest_version({"latest_stable_version": "1.7.14", "latest_version": "1.8.0-rc.0"})
            == "1.7.14"
        )

    def test_falls_back_to_latest(self):
        assert _latest_version({"latest_version": "1.8.0-rc.0"}) == "1.8.0-rc.0"

    def test_both_missing(self):
        assert _latest_version({}) == ""


class TestDescribedVersion:
    """The package-level ``meta`` is that of the release published last."""

    def test_release_published_last_not_the_highest_version(self):
        releases = [
            {"version": "2.0.0", "inserted_at": "2024-03-01T10:00:00.000000Z"},
            {"version": "1.9.1", "inserted_at": "2024-05-01T10:00:00.000000Z"},
            {"version": "1.9.0", "inserted_at": "2024-01-01T10:00:00.000000Z"},
        ]
        assert _described_version({"releases": releases}) == "1.9.1"

    def test_single_release(self):
        releases = [{"version": "0.1.0", "inserted_at": "2024-01-01T10:00:00.000000Z"}]
        assert _described_version({"releases": releases}) == "0.1.0"

    @pytest.mark.parametrize(
        "releases",
        [
            None,
            "1.0.0",
            {"1.0.0": "2024-01-01T10:00:00.000000Z"},
            [],
            ["1.0.0"],
            [{"version": "1.0.0"}],
            [{"inserted_at": "2024-01-01T10:00:00.000000Z"}],
            [{"version": 1, "inserted_at": "2024-01-01T10:00:00.000000Z"}],
            [{"version": "1.0.0", "inserted_at": 1704103200}],
            # One undated entry is enough: it may be the one published last.
            [
                {"version": "2.0.0", "inserted_at": "2024-03-01T10:00:00.000000Z"},
                {"version": "1.9.1"},
            ],
        ],
    )
    def test_releases_that_are_not_all_dated_describe_none(self, releases):
        assert _described_version({"releases": releases}) == ""

    def test_no_releases_key(self):
        assert _described_version({}) == ""


class TestResolveHexLicense:
    @respx.mock
    def test_pinned_extracts_license_and_links(self):
        respx.get(_hex_package_url("phoenix")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "package.json").read_text())
            )
        )
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("phoenix", "==1.7.10"), client)
        assert info.license_id == "MIT"
        assert info.license_raw == "MIT"
        assert info.resolved_version == "1.7.10"  # the lockfile pin
        assert info.repository_url == "https://github.com/phoenixframework/phoenix"
        assert info.homepage_url == "https://www.phoenixframework.org"
        assert info.from_registry is True
        # The license is the one of 1.8.0-rc.0, the release published last.
        assert info.license_estimated is True

    @respx.mock
    def test_release_published_last_has_its_own_license(self):
        respx.get(_hex_package_url("phoenix")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "package.json").read_text())
            )
        )
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("phoenix", "==1.8.0-rc.0"), client)
        assert info.license_id == "MIT"
        assert info.resolved_version == "1.8.0-rc.0"
        assert info.license_estimated is False

    @respx.mock
    def test_renamed_dep_resolves_under_registry_name(self):
        # A `hex:`-renamed dep carries the local app name in `name` and the
        # published package in `registry_name`; resolution must hit the hex.pm
        # endpoint for registry_name, not the alias. Only the real package URL
        # is mocked — a request to the alias would raise (no matching route).
        dep = Dependency(
            name="my_dep",
            version_constraint="==1.0.0",
            ecosystem=Ecosystem.HEX,
            registry_name="real_pkg",
        )
        respx.get(_hex_package_url("real_pkg")).mock(
            return_value=httpx.Response(200, json={"meta": {"licenses": ["MIT"], "links": {}}})
        )
        with httpx.Client() as client:
            info = resolve_hex_license(dep, client)
        assert info.license_id == "MIT"
        assert info.dependency.name == "my_dep"  # display/graph name unchanged

    @respx.mock
    def test_unpinned_uses_latest_stable(self):
        respx.get(_hex_package_url("phoenix")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "package.json").read_text())
            )
        )
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("phoenix", ""), client)
        assert info.resolved_version == "1.7.14"  # latest_stable_version
        # A prerelease was published after it, and the license is that one's.
        assert info.license_estimated is True

    @staticmethod
    def _resolve_licenses(licenses):
        respx.get(_hex_package_url("multi")).mock(
            return_value=httpx.Response(200, json={"meta": {"licenses": licenses, "links": {}}})
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            return resolve_hex_license(_hex_dep("multi", "==1.0.0"), client, fetcher=cache.fetch)

    @respx.mock
    def test_two_licenses_whose_readings_agree_report_the_choice(self):
        # ``meta.licenses`` does not say whether its entries are
        # alternatives; both readings are kept, and here they agree.
        info = self._resolve_licenses(["MIT", "Apache-2.0"])
        assert info.license_id == "Apache-2.0 OR MIT"
        assert info.all_apply_license_id == "Apache-2.0 AND MIT"
        assert info.license_raw == "MIT, Apache-2.0"
        assert check_compatibility("MIT", info).verdict == CompatibilityVerdict.COMPATIBLE

    @respx.mock
    def test_two_licenses_whose_readings_differ_are_unknown(self):
        info = self._resolve_licenses(["Apache-2.0", "GPL-3.0-only"])
        assert info.license_id == "Apache-2.0 OR GPL-3.0-only"
        assert info.all_apply_license_id == "Apache-2.0 AND GPL-3.0-only"
        result = check_compatibility("MIT", info)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "without stating whether they are alternatives" in result.reason
        # Under a project that can take every entry, the readings agree.
        assert check_compatibility("GPL-3.0-only", info).verdict == (
            CompatibilityVerdict.COMPATIBLE
        )

    @respx.mock
    def test_single_license_has_one_reading(self):
        info = self._resolve_licenses(["GPL-3.0-only"])
        assert info.license_id == "GPL-3.0-only"
        assert info.all_apply_license_id == ""
        assert check_compatibility("MIT", info).verdict == CompatibilityVerdict.INCOMPATIBLE

    @respx.mock
    def test_empty_licenses_unknown_from_registry(self):
        respx.get(_hex_package_url("vendor")).mock(
            return_value=httpx.Response(200, json={"meta": {"licenses": [], "links": {}}})
        )
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("vendor", "==1.0.0"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is True

    @respx.mock
    def test_meta_non_dict_unknown_from_registry(self):
        respx.get(_hex_package_url("weird")).mock(
            return_value=httpx.Response(
                200, json={"meta": "not-a-dict", "latest_stable_version": "2.0.0"}
            )
        )
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("weird", ""), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is True
        assert info.resolved_version == "2.0.0"

    @respx.mock
    def test_404_returns_unknown(self):
        respx.get(_hex_package_url("nope")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("nope", "==1.0.0"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_non_dict_data_returns_unknown(self):
        respx.get(_hex_package_url("arr")).mock(return_value=httpx.Response(200, json=[1, 2]))
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("arr", "==1.0.0"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False


class TestFetchHexDependencies:
    @respx.mock
    def test_extracts_required_skips_optional(self):
        respx.get(_hex_release_url("phoenix", "1.7.10")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "1.7.10.json").read_text())
            )
        )
        with httpx.Client() as client:
            children, complete = fetch_hex_dependencies("phoenix", "1.7.10", client, parent_depth=0)
            assert complete is True
        names = {c.name for c in children}
        # jason is optional → skipped.
        assert names == {"plug", "telemetry"}
        for c in children:
            assert c.ecosystem == Ecosystem.HEX
            assert c.depth == 1
            assert c.group == DependencyGroup.PROD
        plug = next(c for c in children if c.name == "plug")
        assert plug.version_constraint == "~> 1.14"

    @respx.mock
    def test_404_is_an_unread_list(self):
        respx.get(_hex_release_url("x", "1.0")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            assert fetch_hex_dependencies("x", "1.0", client, parent_depth=0) == ([], False)

    @respx.mock
    def test_no_requirements_field(self):
        respx.get(_hex_release_url("x", "1.0")).mock(
            return_value=httpx.Response(200, json={"version": "1.0"})
        )
        with httpx.Client() as client:
            assert fetch_hex_dependencies("x", "1.0", client, parent_depth=0) == ([], True)

    @respx.mock
    def test_non_dict_requirements(self):
        respx.get(_hex_release_url("x", "1.0")).mock(
            return_value=httpx.Response(200, json={"requirements": "wrong"})
        )
        with httpx.Client() as client:
            assert fetch_hex_dependencies("x", "1.0", client, parent_depth=0) == ([], False)

    @respx.mock
    def test_skips_blank_names_and_non_dict_spec(self):
        respx.get(_hex_release_url("x", "1.0")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "requirements": {
                        "plug": {"app": "plug", "optional": False, "requirement": ">= 1.0"},
                        "  ": {"requirement": "1.0"},  # blank name
                        "bare": "not-a-dict",  # spec non-dict → empty constraint
                    }
                },
            )
        )
        with httpx.Client() as client:
            children, complete = fetch_hex_dependencies("x", "1.0", client, parent_depth=2)
        # A requirement without a name is one the list could not give.
        assert complete is False
        by_name = {c.name: c for c in children}
        assert set(by_name) == {"plug", "bare"}
        assert by_name["bare"].version_constraint == ""
        assert by_name["plug"].depth == 3  # parent_depth + 1


class TestRegistryCacheTrim:
    def test_package_keep_set_documented(self):
        assert (
            frozenset({"meta", "latest_stable_version", "latest_version", "releases"})
            == _HEX_PACKAGE_KEEP
        )

    def test_release_keep_set_documented(self):
        assert frozenset({"version", "requirements"}) == _HEX_RELEASE_KEEP

    def test_package_release_keep_set_documented(self):
        assert frozenset({"version", "inserted_at"}) == _HEX_PACKAGE_RELEASE_KEEP

    def test_trim_package_drops_extra_and_reduces_meta(self):
        raw = json.loads((_FIXTURES / "phoenix" / "package.json").read_text())
        trimmed = _trim_hex_package(raw)
        assert "downloads" not in trimmed
        assert "html_url" not in trimmed
        assert set(trimmed["meta"]) == {"licenses", "links"}
        assert trimmed["latest_stable_version"] == "1.7.14"
        # The published-version list is what a declared range is matched
        # against, and its publication times tell which release ``meta``
        # describes: each release is kept, reduced to those two fields.
        assert trimmed["releases"] == [
            {"version": "1.8.0-rc.0", "inserted_at": "2025-01-23T17:12:40.509482Z"},
            {"version": "1.7.14", "inserted_at": "2024-06-18T19:53:11.482915Z"},
            {"version": "1.7.10", "inserted_at": "2023-11-03T21:02:57.103774Z"},
        ]

    def test_trim_package_release_list_of_the_wrong_shape(self):
        # A list that is not a list is cached as given; an entry that is not
        # an object names no version and is dropped.
        assert _trim_hex_package({"releases": "wrong"})["releases"] == "wrong"
        assert _trim_hex_package({"releases": ["wrong", {"version": "1.0.0", "url": "u"}]}) == {
            "releases": [{"version": "1.0.0"}]
        }

    def test_trim_package_no_meta(self):
        trimmed = _trim_hex_package({"latest_stable_version": "1.0", "downloads": 5})
        assert "downloads" not in trimmed
        assert "meta" not in trimmed

    def test_trim_package_non_dict_meta_left(self):
        trimmed = _trim_hex_package({"meta": "wrong"})
        assert trimmed["meta"] == "wrong"  # non-dict meta untouched

    def test_trim_release_reduces_requirements(self):
        raw = json.loads((_FIXTURES / "phoenix" / "1.7.10.json").read_text())
        trimmed = _trim_hex_release(raw)
        assert "downloads" not in trimmed
        assert set(trimmed["requirements"]["plug"]) == {"requirement", "optional", "app"}

    def test_trim_release_non_dict_entry_kept_as_it_is(self):
        # The walker emits such a requirement with no constraint; dropping it
        # here would lose the package on the cached path only.
        trimmed = _trim_hex_release({"requirements": {"a": {"app": "a", "x": 1}, "b": "non-dict"}})
        assert trimmed["requirements"] == {"a": {"app": "a"}, "b": "non-dict"}

    def test_trim_release_no_requirements(self):
        assert _trim_hex_release({"version": "1.0"}) == {"version": "1.0"}

    def test_dispatch_routes_package(self):
        trimmed = _trim_for_cache(
            _hex_package_url("phoenix"), {"meta": {"licenses": ["MIT"]}, "downloads": 1}
        )
        assert "downloads" not in trimmed  # type: ignore[operator]

    def test_dispatch_routes_release(self):
        trimmed = _trim_for_cache(
            _hex_release_url("phoenix", "1.7.10"),
            {"requirements": {}, "downloads": 1},
        )
        assert "downloads" not in trimmed  # type: ignore[operator]

    @respx.mock
    def test_resolver_works_through_registry_cache(self):
        # Critical regression test (AGENTS.md / feedback_resolver_cache_keep_set):
        # route the resolver through RegistryCache.fetch so the trim runs in the
        # production path. If the keep-set drops nested meta.licenses, this would
        # surface UNKNOWN instead of MIT.
        respx.get(_hex_package_url("phoenix")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "package.json").read_text())
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("phoenix", "==1.7.10"), client, fetcher=cache.fetch)
        assert info.license_id == "MIT"
        assert info.repository_url == "https://github.com/phoenixframework/phoenix"
        assert info.resolved_version == "1.7.10"

    @pytest.mark.parametrize(
        ("spec", "estimated"),
        [("==1.8.0-rc.0", False), ("==1.7.14", True), ("==1.7.10", True)],
    )
    @respx.mock
    def test_publication_times_survive_the_cache_trim(self, spec, estimated):
        # Dropping ``inserted_at`` in the trim would make every release an
        # estimate on the cached path only.
        respx.get(_hex_package_url("phoenix")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "package.json").read_text())
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("phoenix", spec), client, fetcher=cache.fetch)
        assert info.license_id == "MIT"
        assert info.license_estimated is estimated

    @respx.mock
    def test_fetch_dependencies_through_registry_cache(self):
        # Same cache-trim guard for the release endpoint's requirements.
        respx.get(_hex_release_url("phoenix", "1.7.10")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "1.7.10.json").read_text())
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            children, complete = fetch_hex_dependencies(
                "phoenix", "1.7.10", client, parent_depth=0, fetcher=cache.fetch
            )
            assert complete is True
        assert {c.name for c in children} == {"plug", "telemetry"}
