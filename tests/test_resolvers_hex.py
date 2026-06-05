"""Tests for the Hex (hex.pm) license resolver."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from licenseal.discovery.hex.mix_lock import _OFF_REGISTRY_MARKER
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.hex import (
    _extract_homepage_url,
    _extract_pinned_version,
    _extract_repository_url,
    _hex_package_url,
    _hex_release_url,
    _latest_version,
    _license_field_to_raw,
    fetch_hex_dependencies,
    resolve_hex_license,
)
from licenseal.resolvers.http import (
    _HEX_PACKAGE_KEEP,
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


class TestLicenseFieldToRaw:
    def test_array_single(self):
        assert _license_field_to_raw(["MIT"]) == "MIT"

    def test_array_multi_or_joined(self):
        assert _license_field_to_raw(["MIT", "Apache-2.0"]) == "MIT OR Apache-2.0"

    def test_empty_array(self):
        assert _license_field_to_raw([]) == ""

    def test_bare_string(self):
        assert _license_field_to_raw("MIT") == "MIT"

    def test_unsupported_type(self):
        assert _license_field_to_raw(None) == ""
        assert _license_field_to_raw(42) == ""


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

    @respx.mock
    def test_dual_license_or_joined(self):
        respx.get(_hex_package_url("dual")).mock(
            return_value=httpx.Response(
                200, json={"meta": {"licenses": ["MIT", "Apache-2.0"], "links": {}}}
            )
        )
        with httpx.Client() as client:
            info = resolve_hex_license(_hex_dep("dual", "==1.0.0"), client)
        assert info.license_raw == "MIT OR Apache-2.0"

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

    def test_off_registry_short_circuits(self):
        # No HTTP mock — off-registry must not fetch.
        dep = _hex_dep("edge", "==0.0.1", source=_OFF_REGISTRY_MARKER)
        with httpx.Client() as client:
            info = resolve_hex_license(dep, client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False
        assert info.dependency.source == ""  # internal marker dropped


class TestFetchHexDependencies:
    @respx.mock
    def test_extracts_required_skips_optional(self):
        respx.get(_hex_release_url("phoenix", "1.7.10")).mock(
            return_value=httpx.Response(
                200, json=json.loads((_FIXTURES / "phoenix" / "1.7.10.json").read_text())
            )
        )
        with httpx.Client() as client:
            children = fetch_hex_dependencies("phoenix", "1.7.10", client, parent_depth=0)
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
    def test_404_returns_empty(self):
        respx.get(_hex_release_url("x", "1.0")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            assert fetch_hex_dependencies("x", "1.0", client, parent_depth=0) == []

    @respx.mock
    def test_no_requirements_field(self):
        respx.get(_hex_release_url("x", "1.0")).mock(
            return_value=httpx.Response(200, json={"version": "1.0"})
        )
        with httpx.Client() as client:
            assert fetch_hex_dependencies("x", "1.0", client, parent_depth=0) == []

    @respx.mock
    def test_non_dict_requirements(self):
        respx.get(_hex_release_url("x", "1.0")).mock(
            return_value=httpx.Response(200, json={"requirements": "wrong"})
        )
        with httpx.Client() as client:
            assert fetch_hex_dependencies("x", "1.0", client, parent_depth=0) == []

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
            children = fetch_hex_dependencies("x", "1.0", client, parent_depth=2)
        by_name = {c.name: c for c in children}
        assert set(by_name) == {"plug", "bare"}
        assert by_name["bare"].version_constraint == ""
        assert by_name["plug"].depth == 3  # parent_depth + 1


class TestRegistryCacheTrim:
    def test_package_keep_set_documented(self):
        assert frozenset({"meta", "latest_stable_version", "latest_version"}) == _HEX_PACKAGE_KEEP

    def test_release_keep_set_documented(self):
        assert frozenset({"version", "requirements"}) == _HEX_RELEASE_KEEP

    def test_trim_package_drops_extra_and_reduces_meta(self):
        raw = json.loads((_FIXTURES / "phoenix" / "package.json").read_text())
        trimmed = _trim_hex_package(raw)
        assert "releases" not in trimmed
        assert "downloads" not in trimmed
        assert "html_url" not in trimmed
        assert set(trimmed["meta"]) == {"licenses", "links"}
        assert trimmed["latest_stable_version"] == "1.7.14"

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

    def test_trim_release_non_dict_entry_skipped(self):
        trimmed = _trim_hex_release({"requirements": {"a": {"app": "a"}, "b": "non-dict"}})
        assert set(trimmed["requirements"]) == {"a"}

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
            children = fetch_hex_dependencies(
                "phoenix", "1.7.10", client, parent_depth=0, fetcher=cache.fetch
            )
        assert {c.name for c in children} == {"plug", "telemetry"}
