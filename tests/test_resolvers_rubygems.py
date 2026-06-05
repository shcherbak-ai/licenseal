"""Tests for the RubyGems license resolver."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from licenseal.discovery.ruby.lockfiles import _OFF_REGISTRY_MARKER
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.http import (
    _RUBYGEMS_GEM_KEEP,
    _RUBYGEMS_VERSION_KEEP,
    RegistryCache,
    _trim_for_cache,
    _trim_rubygems_gem,
    _trim_rubygems_version,
)
from licenseal.resolvers.rubygems import (
    _extract_homepage_url,
    _extract_pinned_version,
    _extract_repository_url,
    _license_field_to_raw,
    _rubygems_gem_url,
    _rubygems_version_url,
    fetch_rubygems_dependencies,
    resolve_ruby_license,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "registry-responses" / "rubygems"


def _ruby_dep(
    name: str = "rails",
    version: str = "==7.1.3",
    group: DependencyGroup = DependencyGroup.PROD,
    source: str = "",
) -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.RUBY,
        group=group,
        source=source,
    )


class TestExtractPinnedVersion:
    def test_double_equals_form(self):
        assert _extract_pinned_version("==7.1.3") == "7.1.3"

    def test_no_v_stripping(self):
        # RubyGems versions do not carry a v prefix; if a constraint has
        # one it's preserved verbatim (callers would have errored upstream).
        assert _extract_pinned_version("==v7.1.3") == "v7.1.3"

    def test_unpinned_returns_none(self):
        assert _extract_pinned_version("~> 7.1.0") is None
        assert _extract_pinned_version(">= 1.0") is None

    def test_multi_constraint_returns_none(self):
        assert _extract_pinned_version("~> 7.1.0, >= 7.1.2") is None

    def test_empty_returns_none(self):
        assert _extract_pinned_version("") is None
        assert _extract_pinned_version("==") is None

    def test_single_equals_empty_returns_none(self):
        # ``=`` alone (or with only whitespace after) is not a valid pin.
        assert _extract_pinned_version("=") is None

    def test_single_equals_form_extracts(self):
        # Gem::Requirement's native exact-pin form, propagated by the
        # registry walker from ``dependencies.runtime.requirements``.
        assert _extract_pinned_version("= 4.5.6") == "4.5.6"


class TestUrls:
    def test_version_url_shape(self):
        assert (
            _rubygems_version_url("rails", "7.1.3")
            == "https://rubygems.org/api/v2/rubygems/rails/versions/7.1.3.json"
        )

    def test_gem_url_shape(self):
        assert _rubygems_gem_url("rails") == "https://rubygems.org/api/v1/gems/rails.json"


class TestLicenseFieldToRaw:
    def test_array_single(self):
        assert _license_field_to_raw(["MIT"]) == "MIT"

    def test_array_multi_joined(self):
        assert _license_field_to_raw(["MIT", "Apache-2.0"]) == "MIT OR Apache-2.0"

    def test_bare_string(self):
        # Defensive: rubygems.org always emits arrays, but the helper
        # accepts strings for shape parity with PHP.
        assert _license_field_to_raw("MIT") == "MIT"

    def test_empty_array(self):
        assert _license_field_to_raw([]) == ""

    def test_unsupported_type(self):
        assert _license_field_to_raw(None) == ""
        assert _license_field_to_raw({"x": 1}) == ""


class TestExtractUrls:
    def test_source_code_uri(self):
        assert (
            _extract_repository_url({"source_code_uri": "https://github.com/r/r"})
            == "https://github.com/r/r"
        )

    def test_missing_source_returns_empty(self):
        assert _extract_repository_url({}) == ""

    def test_non_string_source_returns_empty(self):
        assert _extract_repository_url({"source_code_uri": 42}) == ""

    def test_homepage(self):
        assert (
            _extract_homepage_url({"homepage_uri": "https://example.com"}) == "https://example.com"
        )

    def test_blank_homepage_returns_empty(self):
        assert _extract_homepage_url({"homepage_uri": "   "}) == ""

    def test_non_string_homepage_returns_empty(self):
        assert _extract_homepage_url({"homepage_uri": 99}) == ""


class TestResolveRubyLicensePinned:
    @respx.mock
    def test_pinned_v2_extract_license(self):
        respx.get(_rubygems_version_url("rails", "7.1.3")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "rails" / "7.1.3.json").read_text()),
            )
        )
        dep = _ruby_dep("rails", "==7.1.3")
        with httpx.Client() as client:
            info = resolve_ruby_license(dep, client)
        assert info.license_id == "MIT"
        assert info.license_raw == "MIT"
        assert info.resolved_version == "7.1.3"
        assert info.repository_url == "https://github.com/rails/rails/tree/v7.1.3"
        assert info.homepage_url == "https://rubyonrails.org"
        assert info.from_registry is True

    @respx.mock
    def test_lgpl_license_path(self):
        respx.get(_rubygems_version_url("sidekiq", "7.3.0")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "sidekiq" / "7.3.0.json").read_text()),
            )
        )
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("sidekiq", "==7.3.0"), client)
        assert info.license_id == "LGPL-3.0-only"  # SPDX normalization

    @respx.mock
    def test_ruby_spdx_path(self):
        respx.get(_rubygems_version_url("json", "2.7.0")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "json" / "2.7.0.json").read_text()),
            )
        )
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("json", "==2.7.0"), client)
        # 'Ruby' is a valid SPDX identifier, but normalize_license maps it
        # canonically — assert the raw at least passes through.
        assert info.license_raw == "Ruby"

    @respx.mock
    def test_404_returns_unknown(self):
        respx.get(_rubygems_version_url("nope", "1.0.0")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("nope", "==1.0.0"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_empty_licenses_array_returns_unknown_from_registry(self):
        respx.get(_rubygems_version_url("vendor", "1.0.0")).mock(
            return_value=httpx.Response(
                200,
                json={"name": "vendor", "number": "1.0.0", "licenses": []},
            )
        )
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("vendor", "==1.0.0"), client)
        assert info.license_id == "UNKNOWN"
        # Registry confirmed "empty licenses field" — that's still a real
        # registry response, distinct from "network failed".
        assert info.from_registry is True


class TestResolveRubyLicenseUnpinned:
    @respx.mock
    def test_unpinned_uses_v1_endpoint(self):
        respx.get(_rubygems_gem_url("rails")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "rails" / "latest.json").read_text()),
            )
        )
        dep = _ruby_dep("rails", "")  # no constraint → latest fallback
        with httpx.Client() as client:
            info = resolve_ruby_license(dep, client)
        assert info.license_id == "MIT"
        assert info.resolved_version == "8.1.3"
        assert info.from_registry is True

    @respx.mock
    def test_unpinned_404_unknown(self):
        respx.get(_rubygems_gem_url("missing")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("missing", ""), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False


class TestResolveRubyLicenseOffRegistry:
    def test_off_registry_short_circuits(self):
        # No HTTP mock set up — if the resolver tries to fetch, the test
        # would hang or hit a real network. Off-registry short-circuits
        # bypass that entirely.
        dep = _ruby_dep("edge", "==0.0.1", source=_OFF_REGISTRY_MARKER)
        with httpx.Client() as client:
            info = resolve_ruby_license(dep, client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False
        # The internal marker is dropped so it doesn't reach the report.
        assert info.dependency.source == ""


class TestFetchRubygemsDependencies:
    @respx.mock
    def test_extracts_runtime_children_only(self):
        respx.get(_rubygems_version_url("rails", "7.1.3")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "rails" / "7.1.3.json").read_text()),
            )
        )
        with httpx.Client() as client:
            children = fetch_rubygems_dependencies("rails", "7.1.3", client, parent_depth=0)
        names = {c.name for c in children}
        assert names == {"actionpack", "activesupport"}
        for c in children:
            assert c.ecosystem == Ecosystem.RUBY
            assert c.depth == 1
            assert c.group == DependencyGroup.PROD

    @respx.mock
    def test_404_returns_empty(self):
        respx.get(_rubygems_version_url("missing", "1.0")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            children = fetch_rubygems_dependencies("missing", "1.0", client, parent_depth=0)
        assert children == []

    @respx.mock
    def test_no_dependencies_field(self):
        respx.get(_rubygems_version_url("x", "1.0")).mock(
            return_value=httpx.Response(200, json={"name": "x", "number": "1.0"})
        )
        with httpx.Client() as client:
            children = fetch_rubygems_dependencies("x", "1.0", client, parent_depth=0)
        assert children == []

    @respx.mock
    def test_non_dict_dependencies(self):
        respx.get(_rubygems_version_url("x", "1.0")).mock(
            return_value=httpx.Response(
                200,
                json={"name": "x", "number": "1.0", "dependencies": "wrong-shape"},
            )
        )
        with httpx.Client() as client:
            children = fetch_rubygems_dependencies("x", "1.0", client, parent_depth=0)
        assert children == []

    @respx.mock
    def test_non_list_runtime(self):
        respx.get(_rubygems_version_url("x", "1.0")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "x",
                    "number": "1.0",
                    "dependencies": {"runtime": "not-list"},
                },
            )
        )
        with httpx.Client() as client:
            children = fetch_rubygems_dependencies("x", "1.0", client, parent_depth=0)
        assert children == []

    @respx.mock
    def test_skips_non_dict_entries_and_dedupes(self):
        respx.get(_rubygems_version_url("x", "1.0")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "x",
                    "number": "1.0",
                    "dependencies": {
                        "runtime": [
                            "not-a-dict",
                            {"name": "rack", "requirements": ">= 2.0"},
                            {"name": "Rack", "requirements": ">= 3.0"},  # case-dupe
                            {"name": "  ", "requirements": "x"},  # empty name
                            {"name": "no-req"},
                        ],
                        "development": [{"name": "rspec"}],
                    },
                },
            )
        )
        with httpx.Client() as client:
            children = fetch_rubygems_dependencies(
                "x",
                "1.0",
                client,
                parent_depth=0,
            )
        names = sorted(c.name for c in children)
        assert names == ["no-req", "rack"]
        rack = next(c for c in children if c.name == "rack")
        assert rack.version_constraint == ">= 2.0"
        no_req = next(c for c in children if c.name == "no-req")
        assert no_req.version_constraint == ""


class TestRegistryCacheTrim:
    def test_version_keep_set_documented(self):
        assert (
            frozenset(
                {"name", "number", "licenses", "homepage_uri", "source_code_uri", "dependencies"}
            )
            == _RUBYGEMS_VERSION_KEEP
        )

    def test_gem_keep_set_documented(self):
        assert (
            frozenset(
                {"name", "version", "licenses", "homepage_uri", "source_code_uri", "dependencies"}
            )
            == _RUBYGEMS_GEM_KEEP
        )

    def test_trim_version_drops_extra_fields(self):
        raw = {
            "name": "rails",
            "number": "7.1.3",
            "licenses": ["MIT"],
            "homepage_uri": "https://x",
            "source_code_uri": "https://y",
            "dependencies": {
                "runtime": [{"name": "rack", "requirements": ">= 2.0", "extra_key": 1}],
                "development": [{"name": "rspec", "requirements": "~> 3"}],
            },
            "downloads": 1000,
            "metadata": {"x": "y"},
            "authors": "Anon",
        }
        trimmed = _trim_rubygems_version(raw)
        assert "downloads" not in trimmed
        assert "metadata" not in trimmed
        assert "authors" not in trimmed
        assert "extra_key" not in trimmed["dependencies"]["runtime"][0]
        # Only runtime is read transitively; development is dropped at trim time.
        assert "development" not in trimmed["dependencies"]

    def test_trim_version_non_list_runtime_dropped(self):
        raw = {"licenses": ["MIT"], "dependencies": {"runtime": "wrong"}}
        trimmed = _trim_rubygems_version(raw)
        assert trimmed["dependencies"] == {}

    def test_trim_non_dict_dependencies_dropped(self):
        # A non-dict ``dependencies`` value is reduced to an empty map rather
        # than cached as-is.
        trimmed = _trim_rubygems_version({"licenses": ["MIT"], "dependencies": "wrong-shape"})
        assert trimmed["dependencies"] == {}

    def test_trim_version_non_dict_entry_skipped(self):
        raw = {
            "licenses": ["MIT"],
            "dependencies": {"runtime": ["wrong", {"name": "rack"}]},
        }
        trimmed = _trim_rubygems_version(raw)
        assert trimmed["dependencies"]["runtime"] == [{"name": "rack"}]

    def test_trim_gem_drops_extra_fields(self):
        raw = {
            "name": "rails",
            "version": "8.1.3",
            "licenses": ["MIT"],
            "homepage_uri": "https://x",
            "source_code_uri": "https://y",
            "dependencies": {"runtime": [{"name": "rack", "extra": 1}], "development": []},
            "yanked": False,
            "info": "x",
        }
        trimmed = _trim_rubygems_gem(raw)
        assert "yanked" not in trimmed
        assert "info" not in trimmed
        assert "extra" not in trimmed["dependencies"]["runtime"][0]

    def test_trim_gem_non_list_dropped(self):
        raw = {"licenses": ["MIT"], "dependencies": {"runtime": "wrong"}}
        trimmed = _trim_rubygems_gem(raw)
        assert trimmed["dependencies"] == {}

    def test_trim_gem_non_dict_entry_skipped(self):
        raw = {
            "licenses": ["MIT"],
            "dependencies": {"runtime": ["wrong", {"name": "rack"}], "development": []},
        }
        trimmed = _trim_rubygems_gem(raw)
        assert trimmed["dependencies"]["runtime"] == [{"name": "rack"}]

    def test_dispatch_routes_v2(self):
        url = _rubygems_version_url("rails", "7.1.3")
        trimmed = _trim_for_cache(url, {"licenses": ["MIT"], "extra": "drop"})
        assert "extra" not in trimmed  # type: ignore[operator]

    def test_dispatch_routes_v1(self):
        url = _rubygems_gem_url("rails")
        trimmed = _trim_for_cache(url, {"licenses": ["MIT"], "info": "drop"})
        assert "info" not in trimmed  # type: ignore[operator]

    @respx.mock
    def test_resolver_works_through_registry_cache(self):
        # Critical regression test (per AGENTS.md / feedback_resolver_cache_keep_set):
        # route the resolver fetcher through RegistryCache.fetch so the
        # cache trim runs in the production path. If the keep-set drops a
        # field the resolver reads (licenses, source_code_uri, …), this
        # test would surface UNKNOWN instead of MIT.
        respx.get(_rubygems_version_url("rails", "7.1.3")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "rails" / "7.1.3.json").read_text()),
            )
        )
        cache = RegistryCache()
        dep = _ruby_dep("rails", "==7.1.3")
        with httpx.Client() as client:
            info = resolve_ruby_license(dep, client, fetcher=cache.fetch)
        assert info.license_id == "MIT"
        assert info.resolved_version == "7.1.3"
        assert info.repository_url == "https://github.com/rails/rails/tree/v7.1.3"
        assert info.homepage_url == "https://rubyonrails.org"

    @respx.mock
    def test_unpinned_resolver_through_cache(self):
        # Same cache-trim check for the v1 endpoint.
        respx.get(_rubygems_gem_url("rails")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "rails" / "latest.json").read_text()),
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("rails", ""), client, fetcher=cache.fetch)
        assert info.license_id == "MIT"
        assert info.resolved_version == "8.1.3"


class TestResolverNonDictData:
    @respx.mock
    def test_pinned_non_dict_returns_unknown(self):
        respx.get(_rubygems_version_url("x", "1.0")).mock(
            return_value=httpx.Response(200, json=[1, 2, 3])
        )
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("x", "==1.0"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_unpinned_non_dict_returns_unknown(self):
        respx.get(_rubygems_gem_url("x")).mock(return_value=httpx.Response(200, json=[]))
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("x", ""), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False


class TestResolvedVersionFallbacks:
    @respx.mock
    def test_response_carries_no_number_uses_pinned(self):
        respx.get(_rubygems_version_url("x", "1.0")).mock(
            return_value=httpx.Response(
                200,
                # missing 'number' AND 'version' → resolved_version falls back to pinned
                json={"licenses": ["MIT"]},
            )
        )
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("x", "==1.0"), client)
        assert info.resolved_version == "1.0"

    @respx.mock
    def test_v2_response_with_version_field_instead_of_number(self):
        # If a future RubyGems response uses 'version' on v2 (defensive),
        # the resolver still extracts it.
        respx.get(_rubygems_version_url("x", "1.0")).mock(
            return_value=httpx.Response(
                200,
                json={"licenses": ["MIT"], "version": "1.0.1"},
            )
        )
        with httpx.Client() as client:
            info = resolve_ruby_license(_ruby_dep("x", "==1.0"), client)
        assert info.resolved_version == "1.0.1"
