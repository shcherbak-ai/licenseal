"""Tests for license resolvers."""

from __future__ import annotations

import contextlib
import json
from unittest.mock import call, patch

import httpx
import respx

from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.crates_io import (
    _extract_pinned_version as extract_rust_pinned_version,
)
from licenseal.resolvers.crates_io import fetch_rust_dependencies, resolve_rust_license
from licenseal.resolvers.deps_dev import (
    _extract_pinned_version as extract_go_pinned_version,
)
from licenseal.resolvers.deps_dev import (
    _license_info_from_version_object,
    _licenses_to_spdx,
    _repo_url_from_links,
    bulk_resolve_go_licenses,
    fetch_maven_dependencies,
    resolve_go_license,
)
from licenseal.resolvers.http import (
    _INITIAL_BACKOFF_SECONDS,
    _MAX_RETRY_AFTER_SECONDS,
    RegistryCache,
    _jittered_backoff,
    _parse_pep658_headers,
    _retry_delay_seconds,
    _trim_deps_dev_dependencies,
    _trim_deps_dev_v3,
    _trim_for_cache,
    _trim_npm_project,
    _trim_npm_version,
    _trim_pypi,
    encode_module_proxy_path,
    fetch_go_mod_text,
    fetch_pep658_metadata,
    fetch_registry_json,
    fetch_registry_json_post,
    fetch_registry_text,
)
from licenseal.resolvers.npm_registry import (
    _extract_homepage_url as extract_npm_homepage_url,
)
from licenseal.resolvers.npm_registry import (
    _extract_legacy_licenses,
    fetch_npm_dependencies,
    resolve_npm_license,
)
from licenseal.resolvers.npm_registry import (
    _extract_pinned_version as extract_npm_pinned_version,
)
from licenseal.resolvers.npm_registry import (
    _extract_repository_url as extract_npm_repository_url,
)
from licenseal.resolvers.npm_registry import (
    _normalize_repository_url as normalize_npm_repository_url,
)
from licenseal.resolvers.pypi import (
    _compare_strings,
    _eval_markers,
    _extract_raw_license,
    _extract_wheel_url,
    fetch_python_dependencies,
    resolve_python_license,
)
from licenseal.resolvers.pypi import _extract_homepage_url as extract_python_homepage_url
from licenseal.resolvers.pypi import _extract_pinned_version as extract_python_pinned_version
from licenseal.resolvers.pypi import _extract_repository_url as extract_python_repository_url
from licenseal.resolvers.pypi import _normalize_repository_url as normalize_python_repository_url
from licenseal.resolvers.version_selection import select_npm_version, select_python_version


def _python_dep(name: str = "requests", version: str = "") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.PYTHON,
        group=DependencyGroup.PROD,
    )


def _npm_dep(name: str = "react", version: str = "") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.NPM,
        group=DependencyGroup.PROD,
    )


class TestRegistryHttpHelper:
    @respx.mock
    def test_retries_retry_after_then_succeeds(self):
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": "0"}, request=request)
            return httpx.Response(200, json={"ok": True}, request=request)

        respx.get("https://example.com/data").mock(side_effect=handler)
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1) as uniform,
            patch("licenseal.resolvers.http.time.sleep") as sleep,
            httpx.Client() as client,
        ):
            data = fetch_registry_json("https://example.com/data", client)
        assert data == {"ok": True}
        assert attempts == 2
        # Retry-After: 0 is honored as a floor (capped at 0), then a small
        # upward jitter from [0, _INITIAL_BACKOFF_SECONDS] is added — we never
        # sleep less than the server asked.
        uniform.assert_called_once_with(0.0, 0.25)
        sleep.assert_called_once_with(0.1)

    @respx.mock
    def test_retries_request_error_then_succeeds(self):
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise httpx.ConnectError("boom", request=request)
            return httpx.Response(200, json={"ok": True}, request=request)

        respx.get("https://example.com/data").mock(side_effect=handler)
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1) as uniform,
            patch("licenseal.resolvers.http.time.sleep") as sleep,
            httpx.Client() as client,
        ):
            data = fetch_registry_json("https://example.com/data", client)
        assert data == {"ok": True}
        assert attempts == 2
        # Connection error → full jitter over the [0, delay] backoff window.
        uniform.assert_called_once_with(0.0, 0.25)
        sleep.assert_called_once_with(0.1)

    @respx.mock
    def test_retryable_status_exhaustion_returns_none(self):
        respx.get("https://example.com/data").mock(return_value=httpx.Response(503))
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1) as uniform,
            patch("licenseal.resolvers.http.time.sleep") as sleep,
            httpx.Client() as client,
        ):
            data = fetch_registry_json("https://example.com/data", client)
        assert data is None
        # _MAX_ATTEMPTS=3: sleep between attempts 0->1 and 1->2, then exhaust.
        # No Retry-After on a 503, so each sleep full-jitters the backoff —
        # and the jitter *ceiling* still doubles 0.25 → 0.5.
        assert uniform.call_args_list == [call(0.0, 0.25), call(0.0, 0.5)]
        assert sleep.call_args_list == [call(0.1), call(0.1)]

    def test_zero_attempts_returns_none(self):
        with (
            patch("licenseal.resolvers.http._MAX_ATTEMPTS", 0),
            httpx.Client() as client,
        ):
            data = fetch_registry_json("https://example.com/data", client)
        assert data is None


class TestRegistryHttpPostHelper:
    """``fetch_registry_json_post`` shares the GET helper's retry loop but
    issues POSTs. Same retryable-status set, same backoff curve, same
    Retry-After handling. These tests mirror the GET-side coverage.
    """

    @respx.mock
    def test_post_retries_retry_after_then_succeeds(self):

        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": "0"}, request=request)
            return httpx.Response(200, json={"ok": True}, request=request)

        respx.post("https://example.com/batch").mock(side_effect=handler)
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1) as uniform,
            patch("licenseal.resolvers.http.time.sleep") as sleep,
            httpx.Client() as client,
        ):
            data = fetch_registry_json_post("https://example.com/batch", {"x": 1}, client)
        assert data == {"ok": True}
        assert attempts == 2
        # Retry-After: 0 honored as a floor, plus the small upward jitter.
        uniform.assert_called_once_with(0.0, 0.25)
        sleep.assert_called_once_with(0.1)

    @respx.mock
    def test_post_retries_request_error_then_succeeds(self):

        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise httpx.ConnectError("boom", request=request)
            return httpx.Response(200, json={"ok": True}, request=request)

        respx.post("https://example.com/batch").mock(side_effect=handler)
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1) as uniform,
            patch("licenseal.resolvers.http.time.sleep") as sleep,
            httpx.Client() as client,
        ):
            data = fetch_registry_json_post("https://example.com/batch", {"x": 1}, client)
        assert data == {"ok": True}
        assert attempts == 2
        # Connection error → full jitter over the [0, delay] backoff window.
        uniform.assert_called_once_with(0.0, 0.25)
        sleep.assert_called_once_with(0.1)

    @respx.mock
    def test_post_retryable_status_exhaustion_returns_none(self):

        respx.post("https://example.com/batch").mock(return_value=httpx.Response(503))
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1) as uniform,
            patch("licenseal.resolvers.http.time.sleep") as sleep,
            httpx.Client() as client,
        ):
            data = fetch_registry_json_post("https://example.com/batch", {"x": 1}, client)
        assert data is None
        assert uniform.call_args_list == [call(0.0, 0.25), call(0.0, 0.5)]
        assert sleep.call_args_list == [call(0.1), call(0.1)]

    @respx.mock
    def test_post_request_error_exhaustion_returns_none(self):

        respx.post("https://example.com/batch").mock(side_effect=httpx.ConnectError("boom"))
        with patch("licenseal.resolvers.http.time.sleep"), httpx.Client() as client:
            data = fetch_registry_json_post("https://example.com/batch", {"x": 1}, client)
        assert data is None

    @respx.mock
    def test_post_non_retryable_4xx_returns_none(self):

        respx.post("https://example.com/batch").mock(return_value=httpx.Response(400))
        with httpx.Client() as client:
            data = fetch_registry_json_post("https://example.com/batch", {"x": 1}, client)
        assert data is None

    @respx.mock
    def test_post_invalid_json_returns_none(self):

        respx.post("https://example.com/batch").mock(
            return_value=httpx.Response(200, text="<<not-json>>")
        )
        with httpx.Client() as client:
            data = fetch_registry_json_post("https://example.com/batch", {"x": 1}, client)
        assert data is None

    def test_post_zero_attempts_returns_none(self):
        # Symmetric with the GET helper: _MAX_ATTEMPTS=0 → the retry loop
        # body never runs → the trailing ``return None`` after the loop is
        # what surfaces. Same shape as test_zero_attempts_returns_none above.
        with (
            patch("licenseal.resolvers.http._MAX_ATTEMPTS", 0),
            httpx.Client() as client,
        ):
            data = fetch_registry_json_post("https://example.com/batch", {"x": 1}, client)
        assert data is None


class TestResponseSizeCap:
    """Decompression-bomb guard. ``_read_capped_bytes`` / ``_read_capped_text``
    abort once a streamed body crosses ``_MAX_RESPONSE_BYTES``, and every fetch
    helper surfaces that abort as ``None``. The ceiling is patched to a few
    bytes so the test never has to materialize a real over-cap body.
    """

    @respx.mock
    def test_json_get_over_cap_returns_none(self):
        respx.get("https://example.com/data").mock(
            return_value=httpx.Response(200, content=b'{"ok": true}')
        )
        with (
            patch("licenseal.resolvers.http._MAX_RESPONSE_BYTES", 4),
            httpx.Client() as client,
        ):
            assert fetch_registry_json("https://example.com/data", client) is None

    @respx.mock
    def test_json_post_over_cap_returns_none(self):
        respx.post("https://example.com/batch").mock(
            return_value=httpx.Response(200, content=b'{"ok": true}')
        )
        with (
            patch("licenseal.resolvers.http._MAX_RESPONSE_BYTES", 4),
            httpx.Client() as client,
        ):
            assert fetch_registry_json_post("https://example.com/batch", {"x": 1}, client) is None

    @respx.mock
    def test_text_over_cap_returns_none(self):
        respx.get("https://example.com/pom.xml").mock(
            return_value=httpx.Response(200, text="<project></project>")
        )
        with (
            patch("licenseal.resolvers.http._MAX_RESPONSE_BYTES", 4),
            httpx.Client() as client,
        ):
            assert fetch_registry_text("https://example.com/pom.xml", client) is None

    @respx.mock
    def test_pep658_over_cap_returns_none(self):
        respx.get("https://example.com/pkg.whl.metadata").mock(
            return_value=httpx.Response(200, text="License-Expression: MIT")
        )
        with (
            patch("licenseal.resolvers.http._MAX_RESPONSE_BYTES", 4),
            httpx.Client() as client,
        ):
            assert fetch_pep658_metadata("https://example.com/pkg.whl.metadata", client) is None


class TestRetryJitter:
    """Backoff jitter desynchronizes the worker pool under shared throttling.

    The unit under test is the delay computation, independent of which fetch
    helper calls it. These lock the guarantees the timing tests above only
    exercise with a stubbed RNG: bounds, the Retry-After floor, and the cap.
    """

    def test_jittered_backoff_stays_within_window(self):
        for delay in (0.25, 0.5, 1.0):
            for _ in range(200):
                assert 0.0 <= _jittered_backoff(delay) <= delay

    def test_jittered_backoff_actually_spreads_concurrent_retriers(self):
        # The behavioral point of jitter: identical inputs must produce a
        # spread of sleeps, not one synchronized value that re-creates the
        # burst. A continuous uniform draw collapsing to a single rounded
        # value across 50 samples is effectively impossible.
        draws = {round(_jittered_backoff(1.0), 6) for _ in range(50)}
        assert len(draws) > 1

    def test_retry_after_is_a_floor_plus_small_upward_jitter(self):
        resp = httpx.Response(429, headers={"Retry-After": "2"})
        for _ in range(200):
            delay = _retry_delay_seconds(resp, 0.25)
            # Never below the server's ask; jitter only adds, bounded by the
            # initial backoff window.
            assert 2.0 <= delay <= 2.0 + _INITIAL_BACKOFF_SECONDS

    def test_retry_after_cap_is_the_floor_when_server_asks_for_more(self):
        resp = httpx.Response(503, headers={"Retry-After": "3600"})
        for _ in range(200):
            delay = _retry_delay_seconds(resp, 0.25)
            assert (
                _MAX_RETRY_AFTER_SECONDS
                <= delay
                <= _MAX_RETRY_AFTER_SECONDS + _INITIAL_BACKOFF_SECONDS
            )

    def test_no_retry_after_full_jitters_the_default_backoff(self):
        resp = httpx.Response(503)
        for _ in range(200):
            assert 0.0 <= _retry_delay_seconds(resp, 0.5) <= 0.5


class TestVersionSelection:
    def test_select_python_version_chooses_highest_matching_release(self):
        selected = select_python_version(">=2.0,<3.0", ["1.9", "2.0", "2.5", "3.0"])
        assert selected == "2.5"

    def test_select_python_version_ignores_invalid_release_keys(self):
        selected = select_python_version(">=2.0", ["1.0", "bad", "2.4"])
        assert selected == "2.4"

    def test_select_python_version_invalid_spec_returns_none(self):
        assert select_python_version("^1.0", ["1.0", "2.0"]) is None

    def test_select_python_version_empty_constraint_returns_none(self):
        assert select_python_version("", ["1.0"]) is None

    def test_select_python_version_direct_url_returns_none(self):
        assert select_python_version("https://example.com/pkg.whl", ["1.0"]) is None

    def test_select_python_version_prefers_stable_over_prerelease(self):
        selected = select_python_version(">=0.27", ["0.28.1", "1.0.dev3"])
        assert selected == "0.28.1"

    def test_select_python_version_all_invalid_release_keys_returns_none(self):
        assert select_python_version(">=1.0", ["bad", "also-bad"]) is None

    def test_select_npm_version_chooses_highest_matching_release(self):
        selected = select_npm_version("^18.0.0", ["17.0.2", "18.2.0", "19.0.0"])
        assert selected == "18.2.0"

    def test_select_npm_version_ignores_invalid_release_keys(self):
        selected = select_npm_version("^1.0.0", ["invalid", "1.0.1", "1.2.0"])
        assert selected == "1.2.0"

    def test_select_npm_version_unsupported_spec_returns_none(self):
        assert select_npm_version("workspace:*", ["1.0.0"]) is None

    def test_select_npm_version_invalid_spec_returns_none(self):
        assert select_npm_version("latest", ["1.0.0"]) is None

    def test_select_npm_version_accepts_space_after_operator(self):
        # Real npm accepts whitespace between comparison operators and the
        # version (`">= 1.0.0"`); the underlying NpmSpec parser does not.
        # Surfaced in real registry data by safer-buffer transitives that
        # declare `">= 2.1.2 < 3.0.0"`.
        assert select_npm_version(">= 1.0.0", ["0.9.0", "1.2.0"]) == "1.2.0"
        assert select_npm_version("~ 1.2.3", ["1.2.4", "1.3.0"]) == "1.2.4"
        assert select_npm_version("^ 1.0.0", ["0.9.0", "1.5.0", "2.0.0"]) == "1.5.0"

    def test_select_npm_version_accepts_space_separated_range(self):
        # `">= 2.1.2 < 3.0.0"` — operators followed by space, terms separated
        # by space. Both must round-trip into NpmSpec.
        assert (
            select_npm_version(">= 2.1.2 < 3.0.0", ["2.1.1", "2.1.2", "2.5.0", "3.0.0"]) == "2.5.0"
        )

    def test_select_npm_version_collapses_run_of_whitespace(self):
        # Multiple spaces between range terms (rare but seen) must still parse.
        assert select_npm_version(">=1.0.0   <2.0.0", ["0.9", "1.0.0", "1.5.0", "2.0.0"]) == "1.5.0"


class TestResolveNpmSpecDistTags:
    """``resolve_npm_spec`` adds npm dist-tag handling on top of semver-range
    resolution. ``"latest"``, ``"next"``, ``"beta"``, and any custom tag the
    publisher set in ``dist-tags`` resolves to the tagged version; anything
    not in ``dist-tags`` falls through to ``select_npm_version`` against the
    ``versions`` map."""

    def test_latest_tag_resolves_to_tagged_version(self):
        from licenseal.resolvers.version_selection import resolve_npm_spec

        package_data = {
            "dist-tags": {"latest": "1.5.0", "next": "2.0.0-beta.1"},
            "versions": {"1.0.0": {}, "1.5.0": {}, "2.0.0-beta.1": {}},
        }
        assert resolve_npm_spec(package_data, "latest") == "1.5.0"

    def test_custom_dist_tag_resolves(self):
        from licenseal.resolvers.version_selection import resolve_npm_spec

        package_data = {
            "dist-tags": {"latest": "1.5.0", "canary": "3.0.0-canary.5"},
            "versions": {"1.5.0": {}, "3.0.0-canary.5": {}},
        }
        assert resolve_npm_spec(package_data, "canary") == "3.0.0-canary.5"

    def test_semver_range_used_when_spec_not_a_dist_tag(self):
        from licenseal.resolvers.version_selection import resolve_npm_spec

        package_data = {
            "dist-tags": {"latest": "1.5.0"},
            "versions": {"1.0.0": {}, "1.5.0": {}, "2.0.0": {}},
        }
        assert resolve_npm_spec(package_data, "^1.0.0") == "1.5.0"

    def test_unknown_tag_returns_empty(self):
        # Spec doesn't match any dist-tag and isn't a valid semver range —
        # caller treats empty return as UNKNOWN.
        from licenseal.resolvers.version_selection import resolve_npm_spec

        package_data = {
            "dist-tags": {"latest": "1.5.0"},
            "versions": {"1.5.0": {}},
        }
        assert resolve_npm_spec(package_data, "unknowable-tag") == ""

    def test_missing_dist_tags_field_falls_through_to_semver(self):
        from licenseal.resolvers.version_selection import resolve_npm_spec

        package_data = {"versions": {"1.0.0": {}, "2.0.0": {}}}
        assert resolve_npm_spec(package_data, "^1.0.0") == "1.0.0"

    def test_non_string_tag_value_falls_through(self):
        # Malformed response where dist-tags has a non-string value: ignore
        # the entry and try semver instead.
        from licenseal.resolvers.version_selection import resolve_npm_spec

        package_data = {
            "dist-tags": {"latest": None},
            "versions": {"1.0.0": {}},
        }
        assert resolve_npm_spec(package_data, "^1.0.0") == "1.0.0"

    def test_non_dict_dist_tags_field_falls_through(self):
        # Defensive: malformed response where ``dist-tags`` itself is not a
        # dict (publisher error or proxy munging). Skip the tag check and
        # proceed with semver-range resolution.
        from licenseal.resolvers.version_selection import resolve_npm_spec

        package_data = {
            "dist-tags": ["latest"],
            "versions": {"1.0.0": {}},
        }
        assert resolve_npm_spec(package_data, "^1.0.0") == "1.0.0"


class TestPyPIResolver:
    def test_exact_constraint_counts_as_pinned(self):
        assert extract_python_pinned_version("==2.28.1") == "2.28.1"
        assert extract_python_pinned_version("===2.28.1") == "2.28.1"
        assert extract_python_pinned_version("2.28.1") == "2.28.1"
        assert extract_python_pinned_version("==v2.28.1") == "2.28.1"
        assert extract_python_pinned_version("==2.6.0+cu124") == "2.6.0+cu124"
        assert extract_python_pinned_version("==1!2.0") == "1!2.0"

    def test_non_exact_constraint_does_not_count_as_pinned(self):
        assert extract_python_pinned_version(">=2.28") is None
        assert extract_python_pinned_version("2.*") is None
        assert extract_python_pinned_version("=2.28.1") is None
        assert extract_python_pinned_version("==final") is None
        assert extract_python_pinned_version("==v") is None

    def test_malformed_dot_chain_does_not_count_as_pinned(self):
        assert extract_python_pinned_version("==9.9" + ".0" * 1000 + "@") is None

    def test_normalize_repository_url_variants(self):
        assert normalize_python_repository_url("git+https://github.com/org/repo.git") == (
            "https://github.com/org/repo"
        )
        assert normalize_python_repository_url("git://github.com/org/repo.git#main") == (
            "https://github.com/org/repo"
        )
        assert normalize_python_repository_url("") == ""

    def test_extract_repository_url_variants(self):
        assert (
            extract_python_repository_url(
                {"project_urls": {"Source Code": "https://gitlab.com/org/repo.git"}}
            )
            == "https://gitlab.com/org/repo"
        )
        assert (
            extract_python_repository_url(
                {"project_urls": {"Sources": "https://github.com/org/repo.git"}}
            )
            == "https://github.com/org/repo"
        )
        assert (
            extract_python_repository_url(
                {"project_urls": {"Homepage": "https://github.com/org/repo.git"}}
            )
            == "https://github.com/org/repo"
        )
        assert (
            extract_python_repository_url(
                {
                    "project_urls": {"Docs": "https://example.com"},
                    "home_page": "https://example.com",
                }
            )
            == ""
        )
        assert (
            extract_python_repository_url(
                {"project_urls": [], "home_page": "https://codeberg.org/org/repo.git#readme"}
            )
            == "https://codeberg.org/org/repo"
        )

    def test_extract_homepage_url_prefers_home_page_field(self):
        # `home_page` is the legacy PyPI metadata field; takes precedence over
        # any `project_urls.homepage` entry.
        assert (
            extract_python_homepage_url(
                {
                    "home_page": "https://example.com/p",
                    "project_urls": {"Homepage": "https://other.example.com"},
                }
            )
            == "https://example.com/p"
        )

    def test_extract_homepage_url_falls_back_to_project_urls(self):
        assert (
            extract_python_homepage_url(
                {"home_page": "", "project_urls": {"Homepage": "https://example.com/p"}}
            )
            == "https://example.com/p"
        )

    def test_extract_homepage_url_case_insensitive_project_urls_key(self):
        assert (
            extract_python_homepage_url({"project_urls": {"homepage": "https://example.com/p"}})
            == "https://example.com/p"
        )

    def test_extract_homepage_url_empty_when_no_field(self):
        assert extract_python_homepage_url({"name": "p"}) == ""

    @respx.mock
    def test_resolve_from_license_field(self):
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "Apache 2.0",
                        "project_urls": {"Source": "https://github.com/psf/requests"},
                        "version": "2.31.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = _python_dep()
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "Apache-2.0"
        assert li.license_raw == "Apache 2.0"
        assert li.repository_url == "https://github.com/psf/requests"
        assert li.resolved_version == "2.31.0"
        assert li.from_registry is True

    @respx.mock
    def test_resolve_from_classifier(self):
        respx.get("https://pypi.org/pypi/click/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "",
                        "version": "8.1.7",
                        "classifiers": [
                            "License :: OSI Approved :: BSD License",
                        ],
                    }
                },
            )
        )
        dep = _python_dep("click")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "BSD-3-Clause"

    @respx.mock
    def test_resolve_unknown_license_field(self):
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "UNKNOWN",
                        "version": "1.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = _python_dep("pkg")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"

    @respx.mock
    def test_resolve_license_field_just_license_word(self):
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "License",
                        "version": "1.0",
                        "classifiers": [
                            "License :: OSI Approved :: MIT License",
                        ],
                    }
                },
            )
        )
        dep = _python_dep("pkg")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "MIT"

    @respx.mock
    def test_resolve_http_error(self):
        respx.get("https://pypi.org/pypi/nonexistent/json").mock(return_value=httpx.Response(404))
        dep = _python_dep("nonexistent")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_timeout(self):
        respx.get("https://pypi.org/pypi/slow/json").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        dep = _python_dep("slow")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_none_license(self):
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": None,
                        "version": "1.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = _python_dep("pkg")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"

    @respx.mock
    def test_resolve_exact_pinned_version(self):
        respx.get("https://pypi.org/pypi/requests/2.28.1/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "Apache 2.0",
                        "version": "2.28.1",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = _python_dep(version="==2.28.1")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "Apache-2.0"
        assert li.resolved_version == "2.28.1"

    @respx.mock
    def test_resolve_range_to_highest_matching_version(self):
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "3.0.0"},
                    "releases": {"2.28.0": [], "2.28.1": [], "3.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/requests/2.28.1/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "Apache 2.0",
                        "version": "2.28.1",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = _python_dep(version=">=2.28,<3.0")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "Apache-2.0"
        assert li.resolved_version == "2.28.1"

    @respx.mock
    def test_resolve_range_with_no_match_returns_unknown(self):
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "3.0.0"},
                    "releases": {"3.0.0": []},
                },
            )
        )
        dep = _python_dep(version=">=2.0,<3.0")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_invalid_python_spec_returns_unknown(self):
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "3.0.0"},
                    "releases": {"2.28.1": []},
                },
            )
        )
        dep = _python_dep(version="^2.28")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_range_project_metadata_failure_returns_unknown(self):
        respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(500))
        dep = _python_dep(version=">=2.28,<3.0")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_repository_from_home_page(self):
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "MIT",
                        "home_page": "https://github.com/example/pkg.git",
                        "version": "1.0.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = _python_dep("pkg")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.repository_url == "https://github.com/example/pkg"

    @respx.mock
    def test_resolve_populates_homepage_url(self):
        # homepage_url is its own field even when repository_url is also set.
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "MIT",
                        "project_urls": {"Source": "https://github.com/example/pkg"},
                        "home_page": "https://example.com/pkg",
                        "version": "1.0.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = _python_dep("pkg")
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.repository_url == "https://github.com/example/pkg"
        assert li.homepage_url == "https://example.com/pkg"


class TestNpmRegistryResolver:
    def test_non_exact_constraint_does_not_count_as_pinned(self):
        assert extract_npm_pinned_version("^18.0.0") is None
        assert extract_npm_pinned_version("workspace:*") is None

    def test_normalize_repository_url_variants(self):
        assert normalize_npm_repository_url("git+https://github.com/org/repo.git#main") == (
            "https://github.com/org/repo"
        )
        assert normalize_npm_repository_url("git://github.com/org/repo.git") == (
            "https://github.com/org/repo"
        )
        assert normalize_npm_repository_url("github:org/repo") == "https://github.com/org/repo"
        assert normalize_npm_repository_url("gitlab:org/repo") == "https://gitlab.com/org/repo"
        assert normalize_npm_repository_url("bitbucket:org/repo") == (
            "https://bitbucket.org/org/repo"
        )
        assert normalize_npm_repository_url("org/repo") == "https://github.com/org/repo"

    def test_extract_repository_url_variants(self):
        assert extract_npm_repository_url(
            {"repository": {"url": "git+https://gitlab.com/org/repo.git"}}
        ) == ("https://gitlab.com/org/repo")
        assert extract_npm_repository_url({"repository": {"url": 1}}) == ""
        assert extract_npm_repository_url({"repository": 1}) == ""

    def test_extract_homepage_url(self):
        assert (
            extract_npm_homepage_url({"homepage": "https://example.com/p"})
            == "https://example.com/p"
        )
        # Non-string homepage → empty.
        assert extract_npm_homepage_url({"homepage": 1}) == ""
        # Missing → empty.
        assert extract_npm_homepage_url({}) == ""

    @respx.mock
    def test_resolve_top_level_license(self):
        respx.get("https://registry.npmjs.org/react/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    "license": "MIT",
                    "repository": {"url": "git+https://github.com/facebook/react.git"},
                    "homepage": "https://react.dev",
                    "version": "18.2.0",
                },
            )
        )
        dep = _npm_dep()
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "MIT"
        assert li.repository_url == "https://github.com/facebook/react"
        assert li.homepage_url == "https://react.dev"
        assert li.resolved_version == "18.2.0"
        assert li.from_registry is True

    @respx.mock
    def test_resolve_latest_dist_tag_via_versions_endpoint(self):
        # Real-world case: ``package.json`` declares ``"foo": "latest"``.
        # Previously fell through to NpmSpec("latest") which raises and
        # produced an UNKNOWN with empty resolved_version. Now resolved via
        # dist-tags on the per-package endpoint.
        respx.get("https://registry.npmjs.org/foo").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dist-tags": {"latest": "2.4.1", "beta": "3.0.0-beta.2"},
                    "versions": {
                        "2.4.1": {"license": "Apache-2.0", "version": "2.4.1"},
                        "3.0.0-beta.2": {"license": "Apache-2.0", "version": "3.0.0-beta.2"},
                    },
                },
            )
        )
        dep = _npm_dep(name="foo", version="latest")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "Apache-2.0"
        assert li.resolved_version == "2.4.1"
        assert li.from_registry is True

    @respx.mock
    def test_resolve_custom_dist_tag(self):
        respx.get("https://registry.npmjs.org/foo").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dist-tags": {"latest": "1.0.0", "canary": "2.0.0-canary.5"},
                    "versions": {
                        "1.0.0": {"license": "MIT", "version": "1.0.0"},
                        "2.0.0-canary.5": {"license": "MIT", "version": "2.0.0-canary.5"},
                    },
                },
            )
        )
        dep = _npm_dep(name="foo", version="canary")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.resolved_version == "2.0.0-canary.5"
        assert li.from_registry is True

    @respx.mock
    def test_resolve_unknown_dist_tag_returns_unknown(self):
        respx.get("https://registry.npmjs.org/foo").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dist-tags": {"latest": "1.0.0"},
                    "versions": {"1.0.0": {"license": "MIT", "version": "1.0.0"}},
                },
            )
        )
        dep = _npm_dep(name="foo", version="nonexistent-tag")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_range_to_highest_matching_version(self):
        respx.get("https://registry.npmjs.org/react").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versions": {
                        "17.0.2": {"license": "MIT", "version": "17.0.2"},
                        "18.2.0": {"license": "MIT", "version": "18.2.0"},
                        "19.0.0": {"license": "ISC", "version": "19.0.0"},
                    }
                },
            )
        )
        dep = _npm_dep(version="^18.0.0")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "MIT"
        assert li.resolved_version == "18.2.0"
        assert li.from_registry is True

    @respx.mock
    def test_resolve_range_with_no_match_returns_unknown(self):
        respx.get("https://registry.npmjs.org/react").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versions": {
                        "19.0.0": {"license": "MIT", "version": "19.0.0"},
                    }
                },
            )
        )
        dep = _npm_dep(version="^18.0.0")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_unsupported_npm_spec_returns_unknown(self):
        respx.get("https://registry.npmjs.org/react").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versions": {
                        "18.2.0": {"license": "MIT", "version": "18.2.0"},
                    }
                },
            )
        )
        dep = _npm_dep(version="workspace:*")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_range_package_metadata_failure_returns_unknown(self):
        respx.get("https://registry.npmjs.org/react").mock(return_value=httpx.Response(500))
        dep = _npm_dep(version="^18.0.0")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_dict_license(self):
        respx.get("https://registry.npmjs.org/old-pkg/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    "license": {"type": "ISC"},
                    "version": "1.0.0",
                },
            )
        )
        dep = _npm_dep("old-pkg")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "ISC"

    @respx.mock
    def test_resolve_legacy_plural_licenses_array(self):
        # Pre-modern npm packages publish license info under the `licenses`
        # array instead of the modern `license` string. Falling through to
        # UNKNOWN here would silently misclassify a long tail of still-
        # popular old packages.
        respx.get("https://registry.npmjs.org/busboy/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    "licenses": [{"type": "MIT", "url": "https://example.com/LICENSE"}],
                    "version": "1.6.0",
                },
            )
        )
        dep = _npm_dep("busboy")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "MIT"
        assert li.resolved_version == "1.6.0"

    @respx.mock
    def test_resolve_legacy_plural_licenses_bare_dict(self):
        # Some packages omit the array and publish `licenses` as a bare dict.
        respx.get("https://registry.npmjs.org/qrcode-terminal/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    # Non-SPDX spelling ("Apache 2.0") to also exercise that
                    # the normalizer picks it up — the legacy field would be
                    # useless if we extracted but didn't normalize.
                    "licenses": {"type": "Apache 2.0"},
                    "version": "0.12.0",
                },
            )
        )
        dep = _npm_dep("qrcode-terminal")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "Apache-2.0"

    @respx.mock
    def test_resolve_legacy_plural_licenses_multi_entry_is_or(self):
        # Multiple entries in `licenses` express dual-licensing: consumer
        # picks any. Translate to SPDX `OR`.
        respx.get("https://registry.npmjs.org/dual/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    "licenses": [
                        {"type": "MIT"},
                        {"type": "Apache-2.0"},
                    ],
                    "version": "1.0.0",
                },
            )
        )
        dep = _npm_dep("dual")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_raw == "(MIT OR Apache-2.0)"

    @respx.mock
    def test_resolve_modern_license_takes_precedence_over_legacy(self):
        # Packages that have both fields should honor the modern one; the
        # legacy fallback only activates when modern is empty.
        respx.get("https://registry.npmjs.org/hybrid/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    "license": "BSD-3-Clause",
                    "licenses": [{"type": "MIT"}],
                    "version": "1.0.0",
                },
            )
        )
        dep = _npm_dep("hybrid")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "BSD-3-Clause"

    @respx.mock
    def test_resolve_http_error(self):
        respx.get("https://registry.npmjs.org/nonexistent/latest").mock(
            return_value=httpx.Response(404)
        )
        dep = _npm_dep("nonexistent")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False

    @respx.mock
    def test_resolve_timeout(self):
        respx.get("https://registry.npmjs.org/slow/latest").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        dep = _npm_dep("slow")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"

    @respx.mock
    def test_resolve_no_license(self):
        respx.get("https://registry.npmjs.org/empty-pkg/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    "version": "1.0.0",
                },
            )
        )
        dep = _npm_dep("empty-pkg")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"

    @respx.mock
    def test_resolve_exact_pinned_version(self):
        respx.get("https://registry.npmjs.org/react/18.2.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "license": "MIT",
                    "repository": "facebook/react",
                    "version": "18.2.0",
                },
            )
        )
        dep = _npm_dep(version="18.2.0")
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "MIT"
        assert li.repository_url == "https://github.com/facebook/react"
        assert li.resolved_version == "18.2.0"


class TestFetchPythonDependencies:
    @respx.mock
    def test_returns_empty_when_404(self):

        respx.get("https://pypi.org/pypi/missing/1.0.0/json").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            assert fetch_python_dependencies("missing", "1.0.0", client, parent_depth=0) == []

    @respx.mock
    def test_returns_empty_when_no_requires_dist(self):

        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(200, json={"info": {}})
        )
        with httpx.Client() as client:
            assert fetch_python_dependencies("foo", "1.0.0", client, parent_depth=0) == []

    @respx.mock
    def test_returns_empty_when_requires_dist_not_list(self):

        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(200, json={"info": {"requires_dist": "oops, not a list"}})
        )
        with httpx.Client() as client:
            assert fetch_python_dependencies("foo", "1.0.0", client, parent_depth=0) == []

    @respx.mock
    def test_skips_invalid_requirement_strings(self):

        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "requires_dist": [
                            "valid-pkg>=1.0",
                            "###bad-syntax!!!",
                            42,  # non-string
                        ]
                    }
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies("foo", "1.0.0", client, parent_depth=2)
        assert [d.name for d in deps] == ["valid-pkg"]
        assert deps[0].depth == 3
        assert deps[0].direct_ancestors == ()

    @respx.mock
    def test_children_inherit_parent_group(self):
        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"requires_dist": ["pkg>=1.0"]}},
            )
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                parent_group=DependencyGroup.DEV,
            )
        assert deps[0].group == DependencyGroup.DEV


class TestFetchNpmDependencies:
    @respx.mock
    def test_returns_empty_when_404(self):

        respx.get("https://registry.npmjs.org/missing/1.0.0").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            assert fetch_npm_dependencies("missing", "1.0.0", client, parent_depth=0) == []

    @respx.mock
    def test_collects_all_three_dep_groups(self):

        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "foo",
                    "version": "1.0.0",
                    "dependencies": {"a": "^1.0"},
                    "peerDependencies": {"b": "^2.0"},
                    "optionalDependencies": {"c": "^3.0"},
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_npm_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert {d.name for d in deps} == {"a", "b", "c"}

    @respx.mock
    def test_excludes_peer_and_optional_when_disabled(self):

        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": {"a": "^1.0"},
                    "peerDependencies": {"b": "^2.0"},
                    "optionalDependencies": {"c": "^3.0"},
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_npm_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                include_peer=False,
                include_optional=False,
            )
        assert {d.name for d in deps} == {"a"}

    @respx.mock
    def test_skips_non_dict_dep_groups(self):

        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": "not-a-dict",
                    "peerDependencies": ["also", "not", "a", "dict"],
                    "optionalDependencies": {"c": "^3.0"},
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_npm_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert [d.name for d in deps] == ["c"]

    @respx.mock
    def test_skips_dupes_across_groups(self):

        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": {"a": "^1.0"},
                    "peerDependencies": {"a": "^2.0"},
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_npm_dependencies("foo", "1.0.0", client, parent_depth=0)
        # First-encountered wins (deps before peerDeps).
        assert len(deps) == 1
        assert deps[0].version_constraint == "^1.0"

    @respx.mock
    def test_unpacks_npm_alias_syntax(self):
        # `npm:<target>@<spec>` is npm's package-alias syntax. The alias
        # name has no registry entry; only the target does. Without
        # unpacking, every alias 404s and the dep surfaces as UNKNOWN.
        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": {
                        "string-width-cjs": "npm:string-width@^4.2.0",
                        "react-is-18": "npm:react-is@^18",
                        "scoped-alias": "npm:@scope/pkg@^1.0",
                        # Non-alias forms must pass through untouched.
                        "normal-pkg": "^1.0.0",
                    },
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_npm_dependencies("foo", "1.0.0", client, parent_depth=0)
        by_orig = {d.name: d.version_constraint for d in deps}
        assert by_orig == {
            "string-width": "^4.2.0",
            "react-is": "^18",
            "@scope/pkg": "^1.0",
            "normal-pkg": "^1.0.0",
        }

    @respx.mock
    def test_children_inherit_parent_group(self):
        # When the parent is dev (e.g. a transitive of a devDep root), the
        # children must inherit dev — otherwise dev-only transitives get
        # misclassified as prod and lose the dev → warning downgrade.
        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json={"dependencies": {"a": "^1.0", "b": "^2.0"}},
            )
        )
        with httpx.Client() as client:
            deps = fetch_npm_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                parent_group=DependencyGroup.DEV,
            )
        assert {d.group for d in deps} == {DependencyGroup.DEV}

    @respx.mock
    def test_children_default_to_prod_when_unspecified(self):
        # Back-compat: existing callers (and tests) that don't pass
        # parent_group should keep PROD-defaulting behavior.
        respx.get("https://registry.npmjs.org/foo/1.0.0").mock(
            return_value=httpx.Response(
                200,
                json={"dependencies": {"a": "^1.0"}},
            )
        )
        with httpx.Client() as client:
            deps = fetch_npm_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert deps[0].group == DependencyGroup.PROD


def _rust_dep(name: str = "serde", version: str = "") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.RUST,
        group=DependencyGroup.PROD,
    )


class TestCratesIoResolver:
    def test_extract_pinned_version_accepts_eq_form(self):
        assert extract_rust_pinned_version("=1.2.3") == "1.2.3"
        assert extract_rust_pinned_version("= 1.2.3") == "1.2.3"

    def test_extract_pinned_version_accepts_double_eq_form(self):
        # Internal lockfile output uses `==X.Y.Z`.
        assert extract_rust_pinned_version("==1.2.3") == "1.2.3"

    def test_extract_pinned_version_rejects_ranges_and_bare(self):
        for spec in ("1.2.3", "^1.2", "~1.2", ">=1.0", "*", "", "==garbage"):
            assert extract_rust_pinned_version(spec) is None

    @respx.mock
    def test_resolve_pinned_version(self):

        respx.get("https://crates.io/api/v1/crates/serde/1.0.193").mock(
            return_value=httpx.Response(
                200,
                json={"version": {"num": "1.0.193", "license": "MIT OR Apache-2.0"}},
            )
        )
        respx.get("https://crates.io/api/v1/crates/serde").mock(
            return_value=httpx.Response(
                200,
                json={"crate": {"repository": "https://github.com/serde-rs/serde"}},
            )
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("serde", "==1.0.193"), client)
        assert info.from_registry is True
        assert info.resolved_version == "1.0.193"
        assert info.license_id == "Apache-2.0 OR MIT"
        assert info.repository_url == "https://github.com/serde-rs/serde"

    @respx.mock
    def test_resolve_unpinned_uses_max_stable_version(self):

        respx.get("https://crates.io/api/v1/crates/serde").mock(
            return_value=httpx.Response(
                200,
                json={"crate": {"max_stable_version": "1.0.193", "repository": ""}},
            )
        )
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193").mock(
            return_value=httpx.Response(
                200,
                json={"version": {"num": "1.0.193", "license": "MIT OR Apache-2.0"}},
            )
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("serde", "^1.0"), client)
        assert info.resolved_version == "1.0.193"
        assert info.license_id == "Apache-2.0 OR MIT"

    @respx.mock
    def test_resolve_falls_back_to_newest_when_no_stable(self):

        respx.get("https://crates.io/api/v1/crates/preview").mock(
            return_value=httpx.Response(
                200,
                json={"crate": {"newest_version": "0.1.0-alpha"}},
            )
        )
        respx.get("https://crates.io/api/v1/crates/preview/0.1.0-alpha").mock(
            return_value=httpx.Response(
                200,
                json={"version": {"num": "0.1.0-alpha", "license": "MIT"}},
            )
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("preview", "*"), client)
        assert info.resolved_version == "0.1.0-alpha"

    @respx.mock
    def test_resolve_returns_unknown_when_crate_not_found(self):

        respx.get("https://crates.io/api/v1/crates/missing").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("missing"), client)
        assert info.from_registry is False
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_resolve_returns_unknown_when_max_stable_missing(self):

        respx.get("https://crates.io/api/v1/crates/missing").mock(
            return_value=httpx.Response(200, json={"crate": {}})
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("missing"), client)
        assert info.from_registry is False
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_resolve_returns_unknown_when_version_endpoint_fails(self):
        # crates.io 500s after the HTTP-retry budget is exhausted; the
        # resilience fallback then hits deps.dev's stable v3 GET, which
        # also returns 404 here. With both registries unable to help,
        # we surface UNKNOWN with from_registry=False.
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193").mock(
            return_value=httpx.Response(500)
        )
        respx.get("https://api.deps.dev/v3/systems/CARGO/packages/serde/versions/1.0.193").mock(
            return_value=httpx.Response(404)
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("serde", "==1.0.193"), client)
        assert info.from_registry is False
        assert info.license_id == "UNKNOWN"
        assert info.resolved_version == "1.0.193"

    @respx.mock
    def test_resolve_handles_missing_or_non_string_license(self):

        respx.get("https://crates.io/api/v1/crates/x/1.0.0").mock(
            return_value=httpx.Response(200, json={"version": {"num": "1.0.0"}})
        )
        respx.get("https://crates.io/api/v1/crates/x").mock(
            return_value=httpx.Response(200, json={"crate": {}})
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("x", "==1.0.0"), client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_resolve_handles_non_string_license_field(self):

        # Defensive: pretend the registry returned a non-string license.
        respx.get("https://crates.io/api/v1/crates/x/1.0.0").mock(
            return_value=httpx.Response(200, json={"version": {"license": 42}})
        )
        respx.get("https://crates.io/api/v1/crates/x").mock(
            return_value=httpx.Response(200, json={"crate": {}})
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("x", "==1.0.0"), client)
        assert info.license_id == "UNKNOWN"
        assert info.license_raw == ""

    @respx.mock
    def test_resolve_skips_repo_metadata_when_unavailable(self):

        respx.get("https://crates.io/api/v1/crates/x/1.0.0").mock(
            return_value=httpx.Response(200, json={"version": {"license": "MIT"}})
        )
        respx.get("https://crates.io/api/v1/crates/x").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("x", "==1.0.0"), client)
        assert info.license_id == "MIT"
        assert info.repository_url == ""
        assert info.homepage_url == ""

    @respx.mock
    def test_resolve_splits_repository_and_homepage(self):
        # Both fields populated → both surfaced on their own fields.
        respx.get("https://crates.io/api/v1/crates/x/1.0.0").mock(
            return_value=httpx.Response(200, json={"version": {"license": "MIT"}})
        )
        respx.get("https://crates.io/api/v1/crates/x").mock(
            return_value=httpx.Response(
                200,
                json={
                    "crate": {
                        "repository": "https://github.com/example/x",
                        "homepage": "https://example.com/x",
                    }
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("x", "==1.0.0"), client)
        assert info.repository_url == "https://github.com/example/x"
        assert info.homepage_url == "https://example.com/x"

    @respx.mock
    def test_resolve_homepage_only_no_longer_populates_repository_url(self):
        # Behavior change: previously the resolver fell back to homepage when
        # repository was empty. Now repository_url stays empty and the
        # homepage surfaces as `homepage_url` instead.
        respx.get("https://crates.io/api/v1/crates/x/1.0.0").mock(
            return_value=httpx.Response(200, json={"version": {"license": "MIT"}})
        )
        respx.get("https://crates.io/api/v1/crates/x").mock(
            return_value=httpx.Response(
                200,
                json={"crate": {"homepage": "https://example.com/x"}},
            )
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("x", "==1.0.0"), client)
        assert info.repository_url == ""
        assert info.homepage_url == "https://example.com/x"


class TestFetchRustDependencies:
    @respx.mock
    def test_returns_empty_when_404(self):

        respx.get("https://crates.io/api/v1/crates/missing/1.0.0/dependencies").mock(
            return_value=httpx.Response(404)
        )
        with httpx.Client() as client:
            assert fetch_rust_dependencies("missing", "1.0.0", client, parent_depth=0) == []

    @respx.mock
    def test_returns_normal_and_build_drops_dev(self):

        respx.get("https://crates.io/api/v1/crates/serde/1.0.193/dependencies").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": [
                        {"crate_id": "serde_derive", "kind": "normal", "req": "^1.0"},
                        {"crate_id": "syn", "kind": "build", "req": "1"},
                        {"crate_id": "criterion", "kind": "dev", "req": "^0.4"},
                    ]
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_rust_dependencies("serde", "1.0.193", client, parent_depth=2)
        names = {d.name for d in deps}
        assert names == {"serde_derive", "syn"}
        assert deps[0].depth == 3

    @respx.mock
    def test_handles_non_list_dependencies_field(self):

        respx.get("https://crates.io/api/v1/crates/foo/1.0.0/dependencies").mock(
            return_value=httpx.Response(200, json={"dependencies": "oops"})
        )
        with httpx.Client() as client:
            assert fetch_rust_dependencies("foo", "1.0.0", client, parent_depth=0) == []

    @respx.mock
    def test_children_inherit_parent_group(self):
        respx.get("https://crates.io/api/v1/crates/foo/1.0.0/dependencies").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": [
                        {"crate_id": "a", "kind": "normal", "req": "^1.0"},
                    ]
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_rust_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                parent_group=DependencyGroup.DEV,
            )
        assert deps[0].group == DependencyGroup.DEV

    @respx.mock
    def test_skips_non_dict_entries_and_missing_fields(self):

        respx.get("https://crates.io/api/v1/crates/foo/1.0.0/dependencies").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dependencies": [
                        42,
                        {"kind": "normal"},  # missing crate_id
                        {"crate_id": 123, "kind": "normal"},  # non-string crate_id
                        {"crate_id": "good", "kind": "normal"},
                    ]
                },
            )
        )
        with httpx.Client() as client:
            deps = fetch_rust_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert [d.name for d in deps] == ["good"]

    @respx.mock
    def test_uses_empty_spec_when_req_is_non_string(self):

        respx.get("https://crates.io/api/v1/crates/foo/1.0.0/dependencies").mock(
            return_value=httpx.Response(
                200,
                json={"dependencies": [{"crate_id": "bar", "kind": "normal", "req": 42}]},
            )
        )
        with httpx.Client() as client:
            deps = fetch_rust_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert deps[0].name == "bar"
        assert deps[0].version_constraint == ""


class TestResolvePythonLicenseFallback:
    """The wrapper's project-level fallback path: pinned per-version fetch
    succeeds but the response is sparse, so we re-hit the project endpoint
    to fill in the license. Both branches of the fallback path get tested
    here."""

    @respx.mock
    def test_pinned_falls_back_to_project_when_per_version_sparse(self):
        # Pinned per-version succeeds but has no license info.
        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        # Project-level supplies the license.
        respx.get("https://pypi.org/pypi/foo/json").mock(
            return_value=httpx.Response(200, json={"info": {"license_expression": "MIT"}})
        )
        dep = _python_dep("foo", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "MIT"

    @respx.mock
    def test_pinned_sparse_and_project_fallback_also_404(self):
        # Pinned per-version succeeds but is sparse; project-level fallback
        # 404s. Result: UNKNOWN (no fabrication).
        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get("https://pypi.org/pypi/foo/json").mock(return_value=httpx.Response(404))
        dep = _python_dep("foo", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_pinned_per_version_404_falls_back_to_project(self):
        # Custom-index versions (CUDA/ROCm GPU builds, internal mirrors,
        # PEP 440 local-version segments like ``+cu124``) are pinned in
        # the lockfile but published outside PyPI — the per-version URL
        # 404s. The project DOES exist on PyPI under other versions with
        # the canonical license. Without this fallback, every such dep
        # surfaces as UNKNOWN despite being a well-known licensed project.
        respx.get("https://pypi.org/pypi/torch/2.6.0%2Bcu124/json").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://pypi.org/pypi/torch/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "2.7.1",
                        "license": "BSD-3-Clause",
                    }
                },
            )
        )
        dep = _python_dep("torch", version="==2.6.0+cu124")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "BSD-3-Clause"

    @respx.mock
    def test_pinned_per_version_404_and_project_404_returns_unknown(self):
        # Both PyPI endpoints 404 (typo, yank, etc.); deps.dev's
        # resilience fallback also 404s. No source has the package, so
        # we surface UNKNOWN.
        respx.get("https://pypi.org/pypi/nonexistent/1.0.0/json").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://pypi.org/pypi/nonexistent/json").mock(return_value=httpx.Response(404))
        respx.get("https://api.deps.dev/v3/systems/PYPI/packages/nonexistent/versions/1.0.0").mock(
            return_value=httpx.Response(404)
        )
        dep = _python_dep("nonexistent", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "UNKNOWN"


class TestResilienceFallbackToDepsDev:
    """Per-ecosystem resilience fallback: when the official registry's
    HTTP-retry budget is exhausted (5xx storm / partial outage), per-package
    license resolution falls through to deps.dev's stable v3 single-version
    GET. Independent infrastructure (Google API gateway vs PyPI Fastly /
    npm Cloudflare / crates.io Heroku) makes correlated outages unlikely.

    Each test mocks the official registry as 500ing and the deps.dev
    fallback as returning a real license — verifying both that the
    fallback fires and that its result reaches the user instead of UNKNOWN.
    """

    @respx.mock
    def test_pypi_outage_recovers_via_deps_dev(self):
        # PyPI per-version + project-level both 500 (real outage shape);
        # deps.dev stable GET returns the license.
        respx.get("https://pypi.org/pypi/requests/2.32.3/json").mock(
            return_value=httpx.Response(500)
        )
        respx.get("https://pypi.org/pypi/requests/json").mock(return_value=httpx.Response(500))
        respx.get("https://api.deps.dev/v3/systems/PYPI/packages/requests/versions/2.32.3").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {"system": "PYPI", "name": "requests", "version": "2.32.3"},
                    "licenses": ["Apache-2.0"],
                    "links": [],
                },
            )
        )
        dep = _python_dep("requests", version="==2.32.3")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_npm_outage_recovers_via_deps_dev(self):
        respx.get("https://registry.npmjs.org/lodash/4.17.21").mock(
            return_value=httpx.Response(500)
        )
        respx.get("https://api.deps.dev/v3/systems/NPM/packages/lodash/versions/4.17.21").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {"system": "NPM", "name": "lodash", "version": "4.17.21"},
                    "licenses": ["MIT"],
                    "links": [],
                },
            )
        )
        from licenseal.resolvers.npm_registry import resolve_npm_license

        dep = Dependency(name="lodash", version_constraint="4.17.21", ecosystem=Ecosystem.NPM)
        with httpx.Client() as client:
            info = resolve_npm_license(dep, client)
        assert info.license_id == "MIT"
        assert info.from_registry is True

    @respx.mock
    def test_crates_io_outage_recovers_via_deps_dev(self):
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193").mock(
            return_value=httpx.Response(500)
        )
        respx.get("https://api.deps.dev/v3/systems/CARGO/packages/serde/versions/1.0.193").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {"system": "CARGO", "name": "serde", "version": "1.0.193"},
                    "licenses": ["Apache-2.0 OR MIT"],
                    "links": [],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_rust_license(_rust_dep("serde", "==1.0.193"), client)
        assert info.license_id == "Apache-2.0 OR MIT"
        assert info.from_registry is True

    @respx.mock
    def test_pypi_unpinned_failure_does_not_attempt_deps_dev(self):
        # Range spec whose PyPI project-level lookup fails has no concrete
        # version for deps.dev's URL path. Must surface UNKNOWN without
        # an attempted deps.dev fetch (respx would raise if one happened).
        respx.get("https://pypi.org/pypi/somepkg/json").mock(return_value=httpx.Response(500))
        dep = _python_dep("somepkg", version=">=1.0,<2.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False


class TestRegistryCache:
    """The per-scan URL cache that dedupes registry fetches. Walker hits and
    license-resolution hits share one cache; popular URLs only travel the
    wire once. See `licenseal.resolvers.http.RegistryCache`."""

    @respx.mock
    def test_repeat_url_served_from_memory(self):
        route = respx.get("https://pypi.org/pypi/numpy/json").mock(
            return_value=httpx.Response(
                200, json={"info": {"version": "2.0.0", "classifiers": []}, "releases": {}}
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            first = cache.fetch("https://pypi.org/pypi/numpy/json", client)
            second = cache.fetch("https://pypi.org/pypi/numpy/json", client)
            third = cache.fetch("https://pypi.org/pypi/numpy/json", client)
        assert first == second == third
        # Three calls, one network round-trip.
        assert route.call_count == 1

    @respx.mock
    def test_pypi_response_trimmed_to_used_fields(self):
        # Big upstream response with junk fields the resolvers never read.
        # The cache should drop them, keeping the cache small enough to
        # survive 12k-dep scans without blowing through RAM.
        respx.get("https://pypi.org/pypi/foo/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "license_expression": "MIT",
                        "classifiers": ["License :: OSI Approved :: MIT"],
                        "project_urls": {"Source": "https://github.com/x/y"},
                        "home_page": "https://x.com",
                        "requires_dist": ["dep>=1"],
                        "description": "A" * 100_000,  # readme — must be dropped
                        "author_email": "you@example.com",  # not used — must be dropped
                    },
                    "releases": {
                        "1.0.0": [
                            {
                                # file metadata — none of this should survive
                                "url": "https://files.pythonhosted.org/.../foo-1.0.0.whl",
                                "size": 12345,
                                "md5_digest": "deadbeef",
                            }
                        ]
                    },
                    "urls": [{"url": "..."}],  # top-level field — must be dropped
                },
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            data = cache.fetch("https://pypi.org/pypi/foo/json", client)
        assert data is not None
        # Fields the resolvers read are preserved.
        assert data["info"]["license"] == "MIT"
        assert data["info"]["license_expression"] == "MIT"
        assert data["info"]["requires_dist"] == ["dep>=1"]
        assert data["info"]["project_urls"] == {"Source": "https://github.com/x/y"}
        # Releases collapse to a list[str] of version strings — that's all
        # `_resolve_version` and `resolve_python_license` read out of them.
        # Storing this as a dict[str, []] would add per-entry dict-slot
        # plus empty-list overhead per version, which dominates the cache
        # for nightly-build packages with thousands of historical versions.
        assert data["releases"] == ["1.0.0"]
        # Heavy fields are gone.
        assert "description" not in data["info"]
        assert "author_email" not in data["info"]
        assert "urls" not in data

    @respx.mock
    def test_npm_version_cache_preserves_legacy_licenses_field(self):
        # The npm version-cache trim must keep `licenses` (plural) alongside
        # the modern `license` field — pre-modern packages publish ONLY the
        # plural form, and dropping it here regresses them to UNKNOWN even
        # though the resolver knows how to read it.
        respx.get("https://registry.npmjs.org/busboy/1.6.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "version": "1.6.0",
                    "licenses": [{"type": "MIT", "url": "https://example.com/LICENSE"}],
                    "readme": "x" * 5000,  # heavy field — must be dropped
                },
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            data = cache.fetch("https://registry.npmjs.org/busboy/1.6.0", client)
        assert data is not None
        assert data["licenses"] == [{"type": "MIT", "url": "https://example.com/LICENSE"}]
        assert "readme" not in data

    @respx.mock
    def test_npm_version_cache_preserves_homepage(self):
        # The npm version-cache trim must keep ``homepage`` — the resolver
        # reads it for the dep's actionability link (``homepage_url``).
        # Dropping it empties homepage_url on the cached production path while
        # resolver unit tests (direct fetcher, bypassing the trim) still pass.
        respx.get("https://registry.npmjs.org/left-pad/1.3.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "version": "1.3.0",
                    "license": "MIT",
                    "homepage": "https://example.com/left-pad",
                    "readme": "x" * 5000,  # heavy field — must be dropped
                },
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            data = cache.fetch("https://registry.npmjs.org/left-pad/1.3.0", client)
        assert data is not None
        assert data["homepage"] == "https://example.com/left-pad"
        assert "readme" not in data

    @respx.mock
    def test_npm_project_cache_preserves_dist_tags(self):
        # The npm-project cache trim must keep ``dist-tags`` — the spec
        # resolver reads them to handle deps like ``"foo": "latest"``. A
        # missed ``dist-tags`` here regresses to UNKNOWN with empty version.
        respx.get("https://registry.npmjs.org/foo").mock(
            return_value=httpx.Response(
                200,
                json={
                    "dist-tags": {"latest": "2.0.0", "beta": "3.0.0-beta.1"},
                    "versions": {
                        "1.0.0": {"license": "MIT", "version": "1.0.0"},
                        "2.0.0": {"license": "MIT", "version": "2.0.0"},
                        "3.0.0-beta.1": {"license": "MIT", "version": "3.0.0-beta.1"},
                    },
                    "readme": "x" * 100_000,  # heavy field — must be dropped
                },
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            data = cache.fetch("https://registry.npmjs.org/foo", client)
        assert data is not None
        assert data["dist-tags"] == {"latest": "2.0.0", "beta": "3.0.0-beta.1"}
        # versions still trimmed to the keep-set
        assert set(data["versions"]) == {"1.0.0", "2.0.0", "3.0.0-beta.1"}
        assert "readme" not in data

    @respx.mock
    def test_failed_fetch_not_cached_so_retry_can_recover(self):
        # First call hits a 500. fetch_registry_json retries _MAX_ATTEMPTS
        # times then returns None. We deliberately don't cache the None
        # because a *next* call might find the registry healthy again.
        # (Within a single scan this rarely matters, but it keeps semantics
        # clean.)
        respx.get("https://pypi.org/pypi/transient/json").mock(
            side_effect=[
                httpx.Response(500),
                httpx.Response(500),
                httpx.Response(500),
                httpx.Response(500),
                httpx.Response(500),  # exhausts MAX_ATTEMPTS, returns None
                httpx.Response(200, json={"info": {"version": "1.0.0"}, "releases": {"1.0.0": []}}),
            ]
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            first = cache.fetch("https://pypi.org/pypi/transient/json", client)
            # First call cached the None response — the cache treats that as
            # a final answer, so the second call also returns None without
            # re-fetching. This matches fetch_registry_json's own behavior:
            # 4xx/5xx are "no data" and the caller routes around it.
            second = cache.fetch("https://pypi.org/pypi/transient/json", client)
        assert first is None
        assert second is None

    @respx.mock
    def test_exception_clears_inflight_slot_so_caller_can_retry(self):
        # If the fetch raises (not a 4xx/5xx — those are caught and return
        # None — but e.g. tethered.EgressBlocked propagating through), the
        # cache must NOT cache the failure and must clear the in-flight slot
        # so a re-attempt is possible.
        call_count = {"n": 0}

        def flaky_get(request):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("simulated transport error")
            return httpx.Response(200, json={"info": {"version": "1.0.0"}, "releases": {}})

        respx.get("https://pypi.org/pypi/flaky/json").mock(side_effect=flaky_get)
        cache = RegistryCache()
        with httpx.Client() as client:
            # First call raises and exits without populating the cache.
            with contextlib.suppress(RuntimeError):
                cache.fetch("https://pypi.org/pypi/flaky/json", client)
            # Second call enters as a fresh owner and succeeds.
            data = cache.fetch("https://pypi.org/pypi/flaky/json", client)
        assert data is not None
        assert data["info"]["version"] == "1.0.0"


class TestPythonExtrasMarkerEvaluation:
    """The walker calls fetch_python_dependencies with the requested extras
    set; entries gated behind unrequested extras must be filtered out. Env
    markers (python_version, sys_platform, …) stay always-true per the
    long-standing 'license obligations don't depend on platform' policy."""

    def _mock_version_metadata(self, name: str, version: str, requires_dist: list[str]) -> None:
        respx.get(f"https://pypi.org/pypi/{name}/{version}/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": version,
                        "license_expression": "MIT",
                        "requires_dist": requires_dist,
                        "classifiers": [],
                    }
                },
            )
        )

    @respx.mock
    def test_no_marker_always_included(self):
        self._mock_version_metadata("foo", "1.0.0", ["plain-child>=1"])
        with httpx.Client() as client:
            deps = fetch_python_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert [d.name for d in deps] == ["plain-child"]

    @respx.mock
    def test_pure_env_marker_included_regardless_of_platform(self):
        # Env-only markers stay always-true (preserves license-coverage
        # policy for platform-gated deps).
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["win-only-child; sys_platform == 'win32'"],
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert [d.name for d in deps] == ["win-only-child"]

    @respx.mock
    def test_extras_marker_excluded_when_extras_not_requested(self):
        # Default install path: no extras requested → extras-gated deps
        # are skipped.
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            [
                "runtime-child>=1",
                "dev-only-child; extra == 'dev'",
            ],
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert [d.name for d in deps] == ["runtime-child"]

    @respx.mock
    def test_extras_marker_included_when_extras_matches(self):
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["dev-only-child; extra == 'dev'"],
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                requested_extras=frozenset({"dev"}),
            )
        assert [d.name for d in deps] == ["dev-only-child"]

    @respx.mock
    def test_extras_marker_excluded_when_other_extra_requested(self):
        # `extra == 'dev'` doesn't activate when only 'test' is requested.
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["dev-only-child; extra == 'dev'"],
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                requested_extras=frozenset({"test"}),
            )
        assert deps == []

    @respx.mock
    def test_compound_and_marker_requires_extras_match(self):
        # `python_version >= "3.10" and extra == "dev"` → env-side is True
        # under our env-as-true policy, so the AND reduces to the extras
        # condition.
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["dev-py310-child; python_version >= '3.10' and extra == 'dev'"],
        )
        with httpx.Client() as client:
            without = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                requested_extras=frozenset(),
            )
            with_dev = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                requested_extras=frozenset({"dev"}),
            )
        assert without == []
        assert [d.name for d in with_dev] == ["dev-py310-child"]

    @respx.mock
    def test_compound_or_marker_passes_when_env_side_true(self):
        # `extra == "dev" or sys_platform == "win32"` → env-side is True
        # under env-as-true, so OR is always True → include even without
        # the extra. Conservative for license coverage of Windows users.
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["maybe-child; extra == 'dev' or sys_platform == 'win32'"],
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                requested_extras=frozenset(),
            )
        assert [d.name for d in deps] == ["maybe-child"]

    @respx.mock
    def test_or_of_two_extras_includes_when_either_requested(self):
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["dev-or-test-child; extra == 'dev' or extra == 'test'"],
        )
        with httpx.Client() as client:
            none = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                requested_extras=frozenset(),
            )
            with_test = fetch_python_dependencies(
                "foo",
                "1.0.0",
                client,
                parent_depth=0,
                requested_extras=frozenset({"test"}),
            )
        assert none == []
        assert [d.name for d in with_test] == ["dev-or-test-child"]

    @respx.mock
    def test_child_inherits_extras_from_parent_requires_dist(self):
        # `pkg-x[feature]>=1` in requires_dist → child Dep carries
        # extras={"feature"} so when the walker recurses into pkg-x,
        # pkg-x's `extra == 'feature'` deps activate correctly.
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["pkg-x[feature]>=1"],
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert len(deps) == 1
        assert deps[0].name == "pkg-x"
        assert deps[0].extras == frozenset({"feature"})

    @respx.mock
    def test_invalid_marker_falls_through_safely(self):
        # Invalid requirement strings are skipped; valid ones with weird-
        # but-parseable markers shouldn't crash. We test the unparseable
        # entry skip path here.
        self._mock_version_metadata(
            "foo",
            "1.0.0",
            ["valid>=1", "###bad!!!"],
        )
        with httpx.Client() as client:
            deps = fetch_python_dependencies("foo", "1.0.0", client, parent_depth=0)
        assert [d.name for d in deps] == ["valid"]


class TestPyPIHomepageNonDictProjectUrls:
    def test_returns_empty_when_project_urls_is_not_a_dict(self):
        # Defensive: a registry that returns project_urls as a non-dict
        # (string, list, …) shouldn't crash the homepage extractor.
        assert extract_python_homepage_url({"home_page": "", "project_urls": "not a dict"}) == ""


class TestPyPIVersionFallbackToProjectMetadata:
    @respx.mock
    def test_homepage_preserved_when_version_data_already_has_it(self):
        # Version-level metadata supplies the homepage but no license; the
        # fallback to project-level metadata fills in the license, but the
        # already-populated homepage must not be overwritten.
        respx.get("https://pypi.org/pypi/proj/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "2.0.0", "license": "MIT", "classifiers": []},
                    "releases": {"2.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/proj/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license": "",
                        "license_expression": "",
                        "classifiers": [],
                        "home_page": "https://github.com/example/proj",
                    }
                },
            )
        )
        dep = Dependency(
            name="proj",
            version_constraint="==1.0.0",
            ecosystem=Ecosystem.PYTHON,
        )
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.homepage_url == "https://github.com/example/proj"


class TestPyPIMarkerComparisonOps:
    def test_not_equal(self):
        assert _compare_strings("dev", "!=", "test") is True
        assert _compare_strings("dev", "!=", "dev") is False

    def test_in_and_not_in(self):
        assert _compare_strings("ab", "in", "abc") is True
        assert _compare_strings("xy", "in", "abc") is False
        assert _compare_strings("xy", "not in", "abc") is True
        assert _compare_strings("ab", "not in", "abc") is False

    def test_unmodeled_op_returns_true(self):
        # PEP 440 ordering ops aren't meaningful for extras strings; the
        # helper conservatively returns True so the dep isn't silently
        # dropped on a marker shape the model doesn't cover.
        assert _compare_strings("a", ">", "b") is True


class TestPyPIEvalMarkers:
    def test_or_splits_into_groups(self):
        # `extra == 'a' or extra == 'b'` produces a flat list with an
        # "or" splitter — exercises the groups.append([]) branch.
        from packaging.markers import Marker

        marker = Marker("extra == 'a' or extra == 'b'")
        nodes = marker._markers  # noqa: SLF001
        assert _eval_markers(nodes, extra_value="a") is True
        assert _eval_markers(nodes, extra_value="b") is True
        assert _eval_markers(nodes, extra_value="c") is False

    def test_nested_group_via_parens(self):
        # Parens yield a nested list inside _markers — only the
        # `isinstance(item, list)` recursive branch fires here.
        from packaging.markers import Marker

        marker = Marker("(extra == 'a' or extra == 'b') and python_version > '3.0'")
        nodes = marker._markers  # noqa: SLF001
        assert _eval_markers(nodes, extra_value="a") is True
        assert _eval_markers(nodes, extra_value="c") is False

    def test_extras_variable_on_rhs(self):
        # PEP 508 allows `'name' == variable` (value-first form). The
        # _eval_leaf branch where the extras variable is on the RHS only
        # fires when the marker is parsed in that order.
        from packaging.markers import Marker

        marker = Marker("'dev' == extra")
        nodes = marker._markers  # noqa: SLF001
        assert _eval_markers(nodes, extra_value="dev") is True
        assert _eval_markers(nodes, extra_value="test") is False


class TestNpmLegacyLicensesField:
    def test_non_dict_entries_skipped(self):
        # Pre-modern `licenses` array sometimes mixes shapes — non-dict
        # entries must be silently skipped, not crash the resolver.
        assert (
            _extract_legacy_licenses([{"type": "MIT"}, "stray-string", {"type": "Apache-2.0"}])
            == "(MIT OR Apache-2.0)"
        )

    def test_entries_with_empty_or_missing_type_skipped(self):
        # Dict entries lacking a non-empty string `type` are skipped.
        assert (
            _extract_legacy_licenses([{"type": ""}, {"type": "   "}, {"url": "no type here"}]) == ""
        )


class TestRegistryCacheTrimEdges:
    def test_trim_pypi_releases_already_a_list(self):
        # _trim_for_cache may run on data that was already trimmed (the
        # cache stores releases as a list[str]); a second trim pass must
        # preserve the list shape.
        trimmed = _trim_pypi({"info": {"version": "1.0.0"}, "releases": ["1.0.0", "2.0.0"]})
        assert trimmed["releases"] == ["1.0.0", "2.0.0"]

    def test_trim_pypi_releases_unexpected_type(self):
        # Defensive: registry response with a string in `releases` (wrong
        # shape entirely) — must yield empty rather than blow up.
        trimmed = _trim_pypi({"info": {}, "releases": "junk"})
        assert trimmed["releases"] == []

    def test_trim_npm_project_versions_not_a_dict(self):
        # Malformed registry response where `versions` is a string.
        trimmed = _trim_npm_project({"versions": "junk", "dist-tags": {"latest": "1.0.0"}})
        assert trimmed == {"versions": {}, "dist-tags": {"latest": "1.0.0"}}

    def test_trim_npm_project_skips_non_string_keys(self):
        # JSON technically forbids non-string keys, but Python dicts can
        # carry them after a transformation; the trim must filter them out.
        trimmed = _trim_npm_project(
            {"versions": {"1.0.0": {"license": "MIT", "version": "1.0.0"}, 42: {}}}
        )
        assert set(trimmed["versions"]) == {"1.0.0"}

    def test_trim_npm_project_handles_non_dict_value(self):
        # If a version key maps to a non-dict (corrupted response), keep an
        # empty placeholder so callers don't KeyError.
        trimmed = _trim_npm_project({"versions": {"1.0.0": "junk"}})
        assert trimmed["versions"] == {"1.0.0": {}}

    def test_trim_for_cache_passthrough_for_unknown_host(self):
        # crates.io etc. — bypasses trimming.
        data = {"crate": {"name": "x"}}
        assert _trim_for_cache("https://crates.io/api/v1/crates/x", data) is data

    def test_trim_for_cache_returns_none_for_none_input(self):
        assert _trim_for_cache("https://pypi.org/pypi/x/json", None) is None

    def test_trim_npm_version_drops_unkept_fields(self):
        assert _trim_npm_version({"version": "1.0.0", "readme": "x" * 100}) == {"version": "1.0.0"}


class TestRegistryCacheInflight:
    def test_waiter_branch_observes_existing_event_and_waits(self, monkeypatch):
        # RegistryCache.fetch's waiter path — `is_owner = False` followed by
        # `event.wait()` — is reachable only when a second caller observes
        # an in-flight Event already in the cache. Driving this with a real
        # second thread works at runtime but isn't observable to
        # coverage.py 7.14 + Python 3.13 (the worker's executed lines
        # aren't recorded). Instead, exercise the path entirely from the
        # main thread by pre-seeding the in-flight slot and hooking
        # threading.Event.wait to publish the cached result the moment
        # fetch enters the wait — the next loop iteration then sees `_done`
        # and returns the value through the regular cached-hit path.
        import threading

        cache = RegistryCache()
        url = "https://pypi.org/pypi/seeded/json"
        seeded_event = threading.Event()
        seeded_event.set()  # so the hooked wait returns without blocking
        cache._events[url] = seeded_event  # noqa: SLF001

        expected = {"info": {"version": "1.0.0"}, "releases": []}
        original_wait = threading.Event.wait

        def publishing_wait(self, *args, **kwargs):
            # The moment fetch reaches event.wait(), the phantom owner
            # "completes" by publishing the result + setting _done.
            if self is seeded_event:
                cache._results[url] = expected  # noqa: SLF001
                cache._done.add(url)  # noqa: SLF001
            return original_wait(self, *args, **kwargs)

        monkeypatch.setattr(threading.Event, "wait", publishing_wait)

        with httpx.Client() as client:
            result = cache.fetch(url, client)
        # The waiter loop saw `_done` on its second iteration and served the
        # value from the in-memory result — no network call was issued.
        assert result == expected


class TestPep658MetadataFallback:
    """PEP 658 ``.metadata`` sidecar fallback for the minority of PyPI packages
    whose JSON ``license`` / ``license_expression`` / classifiers all come back
    null even though the wheel METADATA carries clean license data.
    """

    _WHEEL_URL = "https://files.pythonhosted.org/packages/aa/bb/pkg_a-1.0.0-py3-none-any.whl"
    _PYPI_JSON_NO_LICENSE = {
        "info": {"version": "1.0.0"},
        "urls": [{"packagetype": "bdist_wheel", "url": _WHEEL_URL}],
    }

    @respx.mock
    def test_license_expression_from_sidecar_resolves(self):
        respx.get("https://pypi.org/pypi/pkg-a/1.0.0/json").mock(
            return_value=httpx.Response(200, json=self._PYPI_JSON_NO_LICENSE)
        )
        # Project-level fallback (existing pre-PEP-658 path) also empty;
        # PEP 658 sidecar is what supplies the license.
        respx.get("https://pypi.org/pypi/pkg-a/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get(self._WHEEL_URL + ".metadata").mock(
            return_value=httpx.Response(
                200,
                text=(
                    "Metadata-Version: 2.4\n"
                    "Name: pkg-a\n"
                    "Version: 1.0.0\n"
                    "License-Expression: MIT\n"
                    "License-File: LICENSE\n"
                    "\n"
                    "The description body lives down here.\n"
                ),
            )
        )
        dep = _python_dep("pkg-a", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "MIT"
        assert info.license_raw == "MIT"

    @respx.mock
    def test_legacy_short_license_field_accepted(self):
        # The legacy `License:` field (pre-PEP-639, deprecated by it but
        # still widely used by maintainers who haven't migrated) can carry
        # a short SPDX-shaped value. Accept it as long as it's single-line
        # and short — the same shape `_extract_raw_license` already accepts
        # from the JSON path's legacy `license` field.
        respx.get("https://pypi.org/pypi/pkg-legacy/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/x/pkg_legacy-1.0.0.whl",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/pkg-legacy/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get("https://files.pythonhosted.org/packages/x/pkg_legacy-1.0.0.whl.metadata").mock(
            return_value=httpx.Response(
                200,
                text="Metadata-Version: 2.4\nName: pkg-legacy\nLicense: MIT License\n\n",
            )
        )
        dep = _python_dep("pkg-legacy", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "MIT"

    @respx.mock
    def test_short_legacy_license_with_prose_marker_rejected(self):
        # A short single-line ``License:`` value can still be prose, not a
        # clean identifier (e.g., "Copyright 2024 ACME, see LICENSE").
        # ``_is_junk_license`` catches these via the same prose-marker filter
        # the JSON-side resolver uses, keeping parity between the two paths.
        respx.get("https://pypi.org/pypi/pkg/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/q/pkg.whl",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get("https://files.pythonhosted.org/packages/q/pkg.whl.metadata").mock(
            return_value=httpx.Response(
                200,
                text="Metadata-Version: 2.4\nLicense: Copyright 2024 ACME, see LICENSE\n\n",
            )
        )
        dep = _python_dep("pkg", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_long_legacy_license_text_rejected(self):
        # A maintainer who pastes the full MIT text into the legacy `License:`
        # field is doing prose. Stays UNKNOWN — extraction from license bodies
        # is banned. ``_parse_pep658_headers`` already skips continuation lines
        # so a multi-line body never reaches the resolver, but the length
        # guard adds a second belt against single-line bodies.
        long_blob = "MIT License " + "x " * 50  # > 60 chars, single line
        respx.get("https://pypi.org/pypi/pkg-longtext/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/y/pkg_longtext-1.0.0.whl",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/pkg-longtext/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get("https://files.pythonhosted.org/packages/y/pkg_longtext-1.0.0.whl.metadata").mock(
            return_value=httpx.Response(
                200,
                text=f"Metadata-Version: 2.4\nName: pkg-longtext\nLicense: {long_blob}\n\n",
            )
        )
        dep = _python_dep("pkg-longtext", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_license_ref_proprietary_routes_through_existing_proprietary_path(self):
        # PEP 639 LicenseRef-* syntax marks a custom/proprietary license. The
        # existing spdx normalizer routes it to ``Proprietary`` (existing
        # ``_LICENSE_REF_RE`` rule), which the compatibility checker flags
        # for manual review. Whole pipeline verified end-to-end so the
        # PEP 658 path properly feeds vendor-proprietary LicenseRef strings
        # through normalization.
        respx.get("https://pypi.org/pypi/pkg-licenseref/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/n/pkg_licenseref-1.0.0.whl",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/pkg-licenseref/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get(
            "https://files.pythonhosted.org/packages/n/pkg_licenseref-1.0.0.whl.metadata"
        ).mock(
            return_value=httpx.Response(
                200,
                text=(
                    "Metadata-Version: 2.4\n"
                    "Name: pkg-licenseref\n"
                    "Version: 1.0.0\n"
                    "License-Expression: LicenseRef-Custom-Proprietary\n"
                    "\n"
                ),
            )
        )
        dep = _python_dep("pkg-licenseref", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "Proprietary"
        assert info.license_raw == "LicenseRef-Custom-Proprietary"

    @respx.mock
    def test_no_wheel_url_skips_pep658(self):
        # Project has only an sdist (no bdist_wheel) — there's no `.metadata`
        # sidecar to fetch. Stay UNKNOWN without issuing the second request.
        respx.get("https://pypi.org/pypi/sdistonly/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {
                            "packagetype": "sdist",
                            "url": "https://files.pythonhosted.org/.../x.tar.gz",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/sdistonly/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        # No /.../x.tar.gz.metadata mock — if the resolver attempts it, respx fails the test.
        dep = _python_dep("sdistonly", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_sidecar_404_stays_unknown(self):
        # Older wheels may predate PEP 658 and lack a `.metadata` sibling.
        # The fetch helper returns None; resolver stays at UNKNOWN.
        respx.get("https://pypi.org/pypi/oldwheel/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/z/oldwheel.whl",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/oldwheel/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get("https://files.pythonhosted.org/packages/z/oldwheel.whl.metadata").mock(
            return_value=httpx.Response(404)
        )
        dep = _python_dep("oldwheel", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_sidecar_used_when_json_license_is_unparseable_unknown(self):
        # JSON-side license is present but doesn't normalize (publisher set
        # `license: "see file"` style). Fall back to the sidecar's
        # ``License-Expression``.
        respx.get("https://pypi.org/pypi/pkg/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                # `"mystery"` is non-empty but doesn't normalize to any SPDX
                # ID (and isn't matched by the file-pointer / proprietary-signal
                # rules). The resolver's raw extraction surfaces it, then the
                # PEP 658 fallback kicks in because normalize_license == UNKNOWN.
                json={
                    "info": {"version": "1.0.0", "license": "mystery"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/p/pkg.whl",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get("https://files.pythonhosted.org/packages/p/pkg.whl.metadata").mock(
            return_value=httpx.Response(
                200,
                text="Metadata-Version: 2.4\nLicense-Expression: Apache-2.0\n\n",
            )
        )
        dep = _python_dep("pkg", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "Apache-2.0"

    @respx.mock
    def test_sidecar_skipped_when_json_license_is_clean(self):
        # JSON has a clean SPDX license — no PEP 658 fetch should fire even
        # if a wheel URL is present.
        respx.get("https://pypi.org/pypi/clean/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0", "license_expression": "BSD-3-Clause"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/c/clean.whl",
                        }
                    ],
                },
            )
        )
        # No metadata mock — respx will fail the test if the resolver hits it.
        dep = _python_dep("clean", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert info.license_id == "BSD-3-Clause"


class TestPep658FetcherAndHeaders:
    """Direct tests of the PEP 658 helpers — retry behaviour and parser edges."""

    @respx.mock
    def test_fetch_metadata_retries_on_retry_after_then_succeeds(self):
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, text="Metadata-Version: 2.4\nLicense-Expression: MIT\n\n")

        respx.get("https://files.pythonhosted.org/test.whl.metadata").mock(side_effect=handler)
        with httpx.Client() as client:
            result = fetch_pep658_metadata(
                "https://files.pythonhosted.org/test.whl.metadata", client
            )
        assert result == {
            "Metadata-Version": "2.4",
            "License-Expression": "MIT",
        }

    @respx.mock
    def test_fetch_metadata_request_error_then_succeeds(self):
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="License-Expression: ISC\n\n")

        respx.get("https://files.pythonhosted.org/test.whl.metadata").mock(side_effect=handler)
        with httpx.Client() as client:
            result = fetch_pep658_metadata(
                "https://files.pythonhosted.org/test.whl.metadata", client
            )
        assert result == {"License-Expression": "ISC"}

    @respx.mock
    def test_fetch_metadata_request_error_exhausts_returns_none(self):
        respx.get("https://files.pythonhosted.org/x.whl.metadata").mock(
            side_effect=httpx.ConnectError("permanent")
        )
        with httpx.Client() as client:
            result = fetch_pep658_metadata("https://files.pythonhosted.org/x.whl.metadata", client)
        assert result is None

    @respx.mock
    def test_fetch_metadata_retryable_status_exhausts_returns_none(self):
        respx.get("https://files.pythonhosted.org/x.whl.metadata").mock(
            return_value=httpx.Response(503)
        )
        with httpx.Client() as client:
            result = fetch_pep658_metadata("https://files.pythonhosted.org/x.whl.metadata", client)
        assert result is None

    @respx.mock
    def test_fetch_metadata_non_retryable_4xx_returns_none(self):
        respx.get("https://files.pythonhosted.org/x.whl.metadata").mock(
            return_value=httpx.Response(404)
        )
        with httpx.Client() as client:
            result = fetch_pep658_metadata("https://files.pythonhosted.org/x.whl.metadata", client)
        assert result is None

    def test_parse_headers_stops_at_blank_line(self):
        text = (
            "Metadata-Version: 2.4\n"
            "License-Expression: MIT\n"
            "\n"
            "License-Expression: SHOULD-BE-IGNORED\n"
        )
        headers = _parse_pep658_headers(text)
        assert headers == {"Metadata-Version": "2.4", "License-Expression": "MIT"}

    def test_parse_headers_skips_continuation_and_no_colon_lines(self):
        # Continuation (space-indented) lines extend the prior header in RFC 5322;
        # we deliberately drop them so a multi-line License: body doesn't surface.
        # No-colon lines aren't headers — also dropped.
        text = (
            "License: MIT License\n"
            "  continuation that should be ignored\n"
            "Junk-no-colon-line\n"
            "Author: somebody\n"
            "\n"
        )
        headers = _parse_pep658_headers(text)
        assert headers == {"License": "MIT License", "Author": "somebody"}

    def test_parse_headers_caps_iteration_on_oversized_header_section(self):
        # Adversarial: never-blank header section. Cap stops iteration so
        # memory stays bounded.
        text = "".join(f"X-Filler-{i}: v\n" for i in range(500))
        headers = _parse_pep658_headers(text)
        assert len(headers) <= 200

    def test_parse_headers_empty_text(self):
        # Empty input: loop iterates zero times; returns empty dict.
        assert _parse_pep658_headers("") == {}

    def test_fetch_metadata_zero_attempts_returns_none(self, monkeypatch):
        # Force the retry loop to skip every iteration so execution falls
        # through to the trailing ``return None``. Same defensive-exit pattern
        # the JSON fetcher exercises.
        from licenseal.resolvers import http as http_module

        monkeypatch.setattr(http_module, "_MAX_ATTEMPTS", 0)
        with httpx.Client() as client:
            assert (
                fetch_pep658_metadata("https://files.pythonhosted.org/x.whl.metadata", client)
                is None
            )


class TestExtractWheelUrl:
    """Direct branches of ``_extract_wheel_url`` that the integration tests
    don't reach: the uncached path (raw ``urls`` list iteration) when the
    cached ``wheel_url`` flat field is absent or empty.
    """

    def test_prefers_flattened_wheel_url(self):
        # Cached path: ``_trim_pypi`` set ``wheel_url`` — take it verbatim
        # and don't walk ``urls``.
        assert (
            _extract_wheel_url({"wheel_url": "https://files.pythonhosted.org/x.whl", "urls": []})
            == "https://files.pythonhosted.org/x.whl"
        )

    def test_urls_not_a_list_returns_empty(self):
        # Defensive: corrupt response with ``urls`` as a non-list shape.
        assert _extract_wheel_url({"urls": "junk"}) == ""

    def test_skips_non_dict_entries_in_urls(self):
        # ``urls`` list contains a non-dict element (corrupt response) — skip
        # it and look at the next entry.
        assert (
            _extract_wheel_url(
                {
                    "urls": [
                        "not-a-dict",
                        {"packagetype": "bdist_wheel", "url": "https://example.com/y.whl"},
                    ]
                }
            )
            == "https://example.com/y.whl"
        )

    def test_skips_empty_string_url_keeps_looking(self):
        # The first bdist_wheel entry has an empty ``url`` — must continue to
        # the next entry rather than return ``""`` early.
        assert (
            _extract_wheel_url(
                {
                    "urls": [
                        {"packagetype": "bdist_wheel", "url": ""},
                        {"packagetype": "bdist_wheel", "url": "https://example.com/z.whl"},
                    ]
                }
            )
            == "https://example.com/z.whl"
        )

    def test_no_bdist_wheel_returns_empty(self):
        # Only sdists in ``urls``: no PEP 658 fetch target.
        assert _extract_wheel_url({"urls": [{"packagetype": "sdist", "url": "x.tar.gz"}]}) == ""

    def test_legacy_license_field_non_string_value_skipped(self):
        # The legacy ``License:`` field value isn't a string (corrupt input).
        # ``_license_from_pep658`` must skip it rather than crash. Exercised
        # via the resolver path with a malformed sidecar; we test the
        # extractor directly by inspecting the function under the hood.
        from licenseal.resolvers.pypi import _license_from_pep658

        def stub_fetcher(url, client):
            return {"License-Expression": "", "License": 12345}  # int, not str

        with httpx.Client() as client:
            result = _license_from_pep658(
                {"wheel_url": "https://example.com/x.whl"},
                client,
                stub_fetcher,
            )
        assert result == ""


class TestPep658CacheIntegration:
    """Cache path: ``_trim_pypi`` must preserve the wheel URL through trimming
    so the resolver can drive the PEP 658 fallback against cached PyPI data
    (which is the production path through ``RegistryCache.fetch``).
    """

    def test_trim_pypi_preserves_first_bdist_wheel_url(self):
        trimmed = _trim_pypi(
            {
                "info": {"version": "1.0.0"},
                "releases": {},
                "urls": [
                    {"packagetype": "sdist", "url": "https://files.pythonhosted.org/x.tar.gz"},
                    {"packagetype": "bdist_wheel", "url": "https://files.pythonhosted.org/x.whl"},
                    {"packagetype": "bdist_wheel", "url": "https://files.pythonhosted.org/y.whl"},
                ],
            }
        )
        assert trimmed["wheel_url"] == "https://files.pythonhosted.org/x.whl"

    def test_trim_pypi_no_wheel_yields_empty_url(self):
        trimmed = _trim_pypi(
            {
                "info": {"version": "1.0.0"},
                "releases": {},
                "urls": [
                    {"packagetype": "sdist", "url": "https://files.pythonhosted.org/x.tar.gz"},
                ],
            }
        )
        assert trimmed["wheel_url"] == ""

    def test_trim_pypi_urls_field_missing(self):
        trimmed = _trim_pypi({"info": {"version": "1.0.0"}, "releases": []})
        assert trimmed["wheel_url"] == ""

    def test_trim_pypi_urls_field_wrong_shape(self):
        # Defensive: a non-list urls value (corrupt response) must not crash.
        trimmed = _trim_pypi({"info": {}, "releases": [], "urls": "junk"})
        assert trimmed["wheel_url"] == ""

    def test_trim_pypi_urls_entries_non_dict_or_missing_fields(self):
        # Each entry must be a dict; non-dict entries are skipped. A dict
        # entry without `url` (or with non-string `url`) also skipped.
        trimmed = _trim_pypi(
            {
                "info": {},
                "releases": [],
                "urls": [
                    "not-a-dict",
                    {"packagetype": "bdist_wheel"},
                    {"packagetype": "bdist_wheel", "url": 123},
                    {"packagetype": "bdist_wheel", "url": ""},
                    {"packagetype": "bdist_wheel", "url": "https://example.com/x.whl"},
                ],
            }
        )
        assert trimmed["wheel_url"] == "https://example.com/x.whl"

    @respx.mock
    def test_resolver_drives_pep658_through_registry_cache(self):
        # End-to-end through ``RegistryCache.fetch``: the cache trims the
        # PyPI JSON (drops ``urls`` list) but preserves ``wheel_url``, so
        # the PEP 658 fallback still has what it needs. Resolver passes the
        # cache's ``fetch`` as the ``fetcher``; the PEP 658 helper uses the
        # default ``fetch_pep658_metadata`` (not cache-routed). Both legs
        # must work together.
        respx.get("https://pypi.org/pypi/pkg-cached/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {
                            "packagetype": "bdist_wheel",
                            "url": "https://files.pythonhosted.org/packages/a/pkg_cached-1.0.0.whl",
                        }
                    ],
                },
            )
        )
        respx.get("https://pypi.org/pypi/pkg-cached/json").mock(
            return_value=httpx.Response(200, json={"info": {"version": "1.0.0"}})
        )
        respx.get("https://files.pythonhosted.org/packages/a/pkg_cached-1.0.0.whl.metadata").mock(
            return_value=httpx.Response(
                200, text="Metadata-Version: 2.4\nLicense-Expression: MIT\n\n"
            )
        )
        cache = RegistryCache()
        dep = _python_dep("pkg-cached", version="==1.0.0")
        with httpx.Client() as client:
            info = resolve_python_license(dep, client, fetcher=cache.fetch)
        assert info.license_id == "MIT"


def _go_dep(name: str = "github.com/foo/bar", version: str = "v1.0.0") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.GO,
        group=DependencyGroup.PROD,
    )


class TestDepsDevExtractPinnedVersion:
    def test_standard_semver(self):
        assert extract_go_pinned_version("v1.2.3") == "v1.2.3"

    def test_pseudo_version(self):
        assert (
            extract_go_pinned_version("v0.0.0-20240101000000-abcdef123456")
            == "v0.0.0-20240101000000-abcdef123456"
        )

    def test_prerelease_with_build_metadata(self):
        assert extract_go_pinned_version("v1.2.3-beta.1+build.5") == "v1.2.3-beta.1+build.5"

    def test_strips_double_equals_prefix(self):
        # licenseal-internal lockfile output may wrap versions as ``==v1.2.3``.
        assert extract_go_pinned_version("==v1.2.3") == "v1.2.3"

    def test_empty_returns_none(self):
        assert extract_go_pinned_version("") is None
        assert extract_go_pinned_version("   ") is None

    def test_missing_v_prefix_returns_none(self):
        # Go versions always start with ``v``; anything else is malformed.
        assert extract_go_pinned_version("1.2.3") is None

    def test_just_v_returns_none(self):
        # Bare ``v`` with nothing after is malformed.
        assert extract_go_pinned_version("v") is None

    def test_v_followed_by_non_digit_returns_none(self):
        assert extract_go_pinned_version("vlatest") is None


class TestDepsDevLicensesToSpdx:
    def test_single_license(self):
        assert _licenses_to_spdx(["MIT"]) == "MIT"

    def test_multiple_licenses_joined_with_and(self):
        # Multi-LICENSE module (e.g. dual-licensed). Conservative AND
        # semantics — see resolver docstring.
        assert _licenses_to_spdx(["MIT", "Apache-2.0"]) == "MIT AND Apache-2.0"

    def test_duplicate_entries_collapsed(self):
        # deps.dev sometimes returns the same SPDX expression multiple times
        # when a module has redundant LICENSE files; we collapse to unique.
        assert _licenses_to_spdx(["MIT", "MIT", "Apache-2.0"]) == "MIT AND Apache-2.0"

    def test_non_list_returns_empty(self):
        assert _licenses_to_spdx(None) == ""
        assert _licenses_to_spdx("garbage") == ""
        assert _licenses_to_spdx({}) == ""

    def test_skips_non_string_entries(self):
        assert _licenses_to_spdx([123, "MIT", None]) == "MIT"

    def test_empty_string_skipped(self):
        assert _licenses_to_spdx(["", "MIT"]) == "MIT"

    def test_only_empty_or_non_string_entries_returns_empty(self):
        # Every entry is filtered → ``collected`` stays empty → "" return path.
        assert _licenses_to_spdx(["", None, 123]) == ""

    def test_non_standard_filtered_out(self):
        # deps.dev's ``"non-standard"`` signal is "I can't classify this",
        # NOT "the package is proprietary". Filter it out so the
        # downstream ``normalize_license`` doesn't alias it to Proprietary
        # (correct alias for publisher-authored "non-standard" in
        # ``Cargo.toml``; semantically wrong for the deps.dev source).
        # When it's the only entry, the resolver surfaces UNKNOWN, which
        # accurately reflects "deps.dev couldn't classify".
        assert _licenses_to_spdx(["non-standard"]) == ""

    def test_non_standard_case_insensitive(self):
        # Match the filter case-insensitively against the leading/trailing
        # whitespace too — defends against future deps.dev response shapes.
        assert _licenses_to_spdx(["Non-Standard"]) == ""
        assert _licenses_to_spdx(["  non-standard  "]) == ""

    def test_non_standard_filtered_alongside_real_license(self):
        # When deps.dev returns both a real SPDX and "non-standard", the
        # real one wins.
        assert _licenses_to_spdx(["MIT", "non-standard"]) == "MIT"

    def test_rubygems_uses_or_for_multi_element(self):
        # RubyGems' gemspec ``licenses = [...]`` convention is disjunctive
        # (consumer picks one), same as Composer. Multi-element arrays
        # should join with OR for the ``RUBYGEMS`` system.
        assert (
            _licenses_to_spdx(["BSD-2-Clause", "Ruby"], system="RUBYGEMS") == "BSD-2-Clause OR Ruby"
        )

    def test_rubygems_single_element_unchanged(self):
        # Single-element arrays don't trigger the join — RUBYGEMS behaves
        # identically to other systems.
        assert _licenses_to_spdx(["MIT"], system="RUBYGEMS") == "MIT"

    def test_non_rubygems_keeps_and_default(self):
        # Default AND semantics for every non-RubyGems system.
        assert _licenses_to_spdx(["MIT", "Apache-2.0"], system="PYPI") == "MIT AND Apache-2.0"
        assert _licenses_to_spdx(["non-standard", "Apache-2.0"]) == "Apache-2.0"


class TestDepsDevRepoUrlFromLinks:
    def test_returns_source_repo_url(self):

        assert (
            _repo_url_from_links([{"label": "SOURCE_REPO", "url": "https://github.com/x/y"}])
            == "https://github.com/x/y"
        )

    def test_skips_non_dict_entries(self):

        assert (
            _repo_url_from_links(
                [
                    "garbage",
                    {"label": "SOURCE_REPO", "url": "https://github.com/x/y"},
                ]
            )
            == "https://github.com/x/y"
        )

    def test_skips_non_source_repo_labels(self):

        assert (
            _repo_url_from_links(
                [
                    {"label": "HOMEPAGE", "url": "https://example.com"},
                    {"label": "ISSUE_TRACKER", "url": "https://example.com/issues"},
                ]
            )
            == ""
        )

    def test_non_list_returns_empty(self):

        assert _repo_url_from_links(None) == ""
        assert _repo_url_from_links("garbage") == ""

    def test_empty_or_non_string_url_skipped(self):
        # A SOURCE_REPO entry whose ``url`` is empty or wrong-typed should not
        # be returned — the loop continues to the next entry.

        assert (
            _repo_url_from_links(
                [
                    {"label": "SOURCE_REPO", "url": ""},
                    {"label": "SOURCE_REPO", "url": 123},
                    {"label": "SOURCE_REPO", "url": "https://github.com/x/y"},
                ]
            )
            == "https://github.com/x/y"
        )


class TestDepsDevLicenseInfoFromVersionObject:
    def test_none_version_object_yields_unknown_not_from_registry(self):
        # Direct exercise of the None-version_object branch (the resolver
        # entry points filter this case before they call the helper, so this
        # is the only way to hit that branch).

        info = _license_info_from_version_object(_go_dep(), "v1.0.0", None)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    def test_versionkey_with_non_string_version_falls_back_to_pinned(self):
        # When the response's versionKey.version is wrong-typed (or empty),
        # the helper should fall back to the pinned input.

        info = _license_info_from_version_object(
            _go_dep(),
            "v1.2.3",
            {"versionKey": {"version": 123}, "licenses": ["MIT"]},
        )
        assert info.resolved_version == "v1.2.3"


class TestResolveGoLicenseSingleFallback:
    """Single-version fallback via deps.dev's stable ``v3`` GET endpoint.

    Used only when the batch POST itself fails (network / 5xx). The batch
    path is the primary; these tests exercise the path that runs per-dep
    when the bulk pre-pass yielded no cache entry for this ``(name, version)``.
    """

    @respx.mock
    def test_resolves_via_deps_dev_v3_single(self):
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/foo/bar",
                        "version": "v1.0.0",
                    },
                    "licenses": ["MIT"],
                    "links": [{"label": "SOURCE_REPO", "url": "https://github.com/foo/bar"}],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep(), client)
        assert info.license_id == "MIT"
        assert info.license_raw == "MIT"
        assert info.repository_url == "https://github.com/foo/bar"
        assert info.resolved_version == "v1.0.0"
        assert info.from_registry is True

    @respx.mock
    def test_dual_licensed_module(self):
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/foo/bar",
                        "version": "v1.0.0",
                    },
                    "licenses": ["Apache-2.0", "MIT"],
                    "links": [{"label": "SOURCE_REPO", "url": "https://github.com/foo/bar"}],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep(), client)
        assert info.license_raw == "Apache-2.0 AND MIT"
        assert info.license_id == "Apache-2.0 AND MIT"

    @respx.mock
    def test_404_returns_unknown(self):
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Fmissing%2Fx/versions/v1.0.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep("github.com/missing/x"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_incompatible_version_is_url_encoded(self):
        # Go's ``+incompatible`` versions contain a literal ``+`` which would
        # otherwise parse as a space on api.deps.dev's URL router. Verify the
        # resolver encodes it to ``%2B`` so the request lands at the right URL.
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/"
            "github.com%2Fdocker%2Fcli/versions/v29.5.2%2Bincompatible"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/docker/cli",
                        "version": "v29.5.2+incompatible",
                    },
                    "licenses": ["Apache-2.0"],
                    "links": [{"label": "SOURCE_REPO", "url": "https://github.com/docker/cli"}],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_go_license(
                _go_dep("github.com/docker/cli", version="v29.5.2+incompatible"),
                client,
            )
        assert info.license_id == "Apache-2.0"
        assert info.resolved_version == "v29.5.2+incompatible"

    def test_invalid_version_short_circuits_without_fetch(self):
        # ``_extract_pinned_version`` returns None → no HTTP fetch happens.
        # If it did, respx (not arming any mock here) would fail.
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep(version=""), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_missing_licenses_field_returns_unknown(self):
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/foo/bar",
                        "version": "v1.0.0",
                    },
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep(), client)
        assert info.license_id == "UNKNOWN"
        # Still ``from_registry=True`` — registry confirmed empty (distinct
        # from a network failure).
        assert info.from_registry is True

    @respx.mock
    def test_non_string_response_fields_handled_defensively(self):
        # A corrupt response with wrong-typed fields shouldn't crash.
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": 123,
                    "licenses": "not-a-list",
                    "links": "not-a-list",
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep(), client)
        assert info.license_id == "UNKNOWN"
        assert info.repository_url == ""

    @respx.mock
    def test_no_source_repo_link_yields_empty_repository_url(self):
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/foo/bar",
                        "version": "v1.0.0",
                    },
                    "licenses": ["MIT"],
                    # No SOURCE_REPO entry — other label types exist for some
                    # modules (HOMEPAGE, ISSUE_TRACKER) but we only pull SOURCE_REPO.
                    "links": [{"label": "HOMEPAGE", "url": "https://example.com"}],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep(), client)
        assert info.license_id == "MIT"
        assert info.repository_url == ""


class TestBulkResolveGoLicenses:
    """Batch POST to deps.dev's ``/v3alpha/versionbatch``.

    This is the primary Go license-resolution path: one or two POSTs per
    scan instead of N single GETs. Tests cover the three-state result
    encoding (present / confirmed-missing / batch-failed), chunking, dedup,
    and request shape.
    """

    @respx.mock
    def test_batch_round_trip_populates_cache(self):
        captured: dict[str, dict] = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.0.0",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.0.0",
                                },
                                "licenses": ["MIT"],
                                "links": [
                                    {
                                        "label": "SOURCE_REPO",
                                        "url": "https://github.com/foo/bar",
                                    }
                                ],
                            },
                        }
                    ],
                    "nextPageToken": "",
                },
            )

        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(side_effect=handler)
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses([_go_dep()], client, max_workers=4)
        assert ("github.com/foo/bar", "v1.0.0") in cache
        info = cache[("github.com/foo/bar", "v1.0.0")]
        assert info is not None
        assert info.license_id == "MIT"
        assert info.repository_url == "https://github.com/foo/bar"
        # Request shape: ``requests[].versionKey`` with system=GO.
        assert captured["body"] == {
            "requests": [
                {
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/foo/bar",
                        "version": "v1.0.0",
                    }
                }
            ]
        }

    @respx.mock
    def test_missing_version_object_records_none(self):
        # When deps.dev can't find a (name, version), the response entry has
        # ``request`` but no ``version`` field. The cache records ``None`` so
        # the resolver skips the single-version fallback for this dep.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/missing/x",
                                    "version": "v1.0.0",
                                }
                            }
                            # no ``version`` key
                        }
                    ],
                    "nextPageToken": "",
                },
            )
        )
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses(
                [_go_dep("github.com/missing/x")], client, max_workers=4
            )
        assert cache[("github.com/missing/x", "v1.0.0")] is None

    @respx.mock
    def test_whole_batch_failure_returns_empty_dict(self):
        # 5xx that exhausts retries → cache is empty. Caller routes affected
        # deps to single-version GET fallback.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(503)
        )
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses([_go_dep()], client, max_workers=4)
        assert cache == {}

    @respx.mock
    def test_unparseable_versions_excluded_from_batch(self):
        # Deps with empty/malformed version strings shouldn't enter the
        # batch body — they'd waste a slot and the response can't bind back
        # to a meaningful (name, version) key.
        captured: dict[str, dict] = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"responses": [], "nextPageToken": ""})

        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(side_effect=handler)
        with httpx.Client() as client:
            bulk_resolve_go_licenses(
                [_go_dep(version=""), _go_dep("github.com/x/y", version="v1.0.0")],
                client,
                max_workers=4,
            )
        assert captured["body"]["requests"] == [
            {
                "versionKey": {
                    "system": "GO",
                    "name": "github.com/x/y",
                    "version": "v1.0.0",
                }
            }
        ]

    @respx.mock
    def test_chunking_splits_large_input(self):
        # With ``chunk_size=2`` and 5 unique deps, the batch should fire
        # 3 separate POSTs (2+2+1). Each entry round-trips intact.
        call_count = 0

        def handler(request):
            nonlocal call_count
            call_count += 1
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": entry,
                            "version": {
                                "versionKey": entry["versionKey"],
                                "licenses": ["MIT"],
                            },
                        }
                        for entry in body["requests"]
                    ],
                    "nextPageToken": "",
                },
            )

        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(side_effect=handler)
        deps = [_go_dep(f"github.com/x/m{i}", version=f"v1.0.{i}") for i in range(5)]
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses(deps, client, chunk_size=2, max_workers=4)
        assert call_count == 3
        assert len(cache) == 5
        for i in range(5):
            entry = cache[(f"github.com/x/m{i}", f"v1.0.{i}")]
            assert entry is not None
            assert entry.license_id == "MIT"

    @respx.mock
    def test_deduplicates_repeated_name_version(self):
        # The same (name, version) appearing N times in the input should
        # produce a single batch entry, not N (the per-dep cache lookup
        # rebinds at the call site).
        captured: dict[str, dict] = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.0.0",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.0.0",
                                },
                                "licenses": ["MIT"],
                            },
                        }
                    ],
                    "nextPageToken": "",
                },
            )

        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(side_effect=handler)
        with httpx.Client() as client:
            bulk_resolve_go_licenses([_go_dep(), _go_dep(), _go_dep()], client, max_workers=4)
        assert len(captured["body"]["requests"]) == 1

    def test_empty_input_makes_no_request(self):
        # Nothing armed in respx — if a POST were attempted, the test
        # framework would error.
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses([], client, max_workers=4)
        assert cache == {}

    def test_all_versions_unparseable_returns_empty(self):
        # Every dep has an empty/malformed version → the early-exit after
        # the build-requests loop fires and no POST is made.
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses(
                [_go_dep(version=""), _go_dep("github.com/x/y", version="bad")],
                client,
                max_workers=4,
            )
        assert cache == {}

    @respx.mock
    def test_malformed_response_top_level_returns_empty(self):
        # Whole-response body of the wrong shape (responses is not a list) →
        # _fetch_chunk's defensive guard returns an empty mapping for the
        # chunk rather than crashing.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": "not-a-list"})
        )
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses([_go_dep()], client, max_workers=4)
        assert cache == {}

    @respx.mock
    def test_malformed_response_entries_are_skipped(self):
        # A response with a mix of garbage and one valid entry — the
        # defensive guards should drop everything but the valid one.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        "not-a-dict",
                        {},  # missing request
                        {"request": "not-a-dict"},
                        {"request": {}},  # missing versionKey
                        {"request": {"versionKey": "not-a-dict"}},
                        {"request": {"versionKey": {}}},  # name/version absent
                        {"request": {"versionKey": {"name": 123, "version": "v1"}}},
                        # The one valid entry:
                        {
                            "request": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.0.0",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.0.0",
                                },
                                "licenses": ["MIT"],
                            },
                        },
                    ],
                    "nextPageToken": "",
                },
            )
        )
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses([_go_dep()], client, max_workers=4)
        # Only the one valid entry survived.
        assert len(cache) == 1
        info = cache[("github.com/foo/bar", "v1.0.0")]
        assert info is not None
        assert info.license_id == "MIT"

    @respx.mock
    def test_response_entry_for_unknown_request_is_skipped(self):
        # deps.dev returned a (name, version) we never asked about — the
        # ``sentinel is None`` branch fires and the entry is dropped.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/we/never-asked",
                                    "version": "v1.0.0",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/we/never-asked",
                                    "version": "v1.0.0",
                                },
                                "licenses": ["MIT"],
                            },
                        }
                    ],
                    "nextPageToken": "",
                },
            )
        )
        with httpx.Client() as client:
            cache = bulk_resolve_go_licenses([_go_dep()], client, max_workers=4)
        assert cache == {}

    @respx.mock
    def test_batch_concurrency_capped_at_batch_max_workers(self):
        # The batch endpoint is rate-limit-sensitive, so concurrent POSTs are
        # capped at _BATCH_MAX_WORKERS even when --max-workers is higher; a
        # lower --max-workers still throttles the batch DOWN (it's a ceiling,
        # not a floor). worker_count = min(chunks, max_workers, cap).
        from licenseal.resolvers.deps_dev import _BATCH_MAX_WORKERS

        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": [], "nextPageToken": ""})
        )
        seen: list[int] = []

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                seen.append(max_workers)

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                return False

            def map(self, func, *iterables):
                return [func(*args) for args in zip(*iterables, strict=True)]

        # chunk_size=1 → one chunk per dep → 20 chunks, well above the cap.
        deps = [_go_dep(f"github.com/x/m{i}") for i in range(20)]
        # (max_workers, expected worker_count): high is clamped to the cap;
        # below-cap is respected verbatim.
        for max_workers, expected in [(_BATCH_MAX_WORKERS + 8, _BATCH_MAX_WORKERS), (2, 2)]:
            seen.clear()
            with (
                patch("licenseal._concurrency.ThreadPoolExecutor", FakeExecutor),
                httpx.Client() as client,
            ):
                bulk_resolve_go_licenses(deps, client, chunk_size=1, max_workers=max_workers)
            assert seen == [expected], f"max_workers={max_workers}"


class TestDepsDevCacheTrim:
    def test_trim_keeps_versionkey_licenses_and_links(self):
        # The resolver reads ``versionKey``, ``licenses`` (string array),
        # and ``links[].label == "SOURCE_REPO"``. Everything else
        # (``advisoryKeys``, ``slsaProvenances``, ``attestations``,
        # ``relatedProjects``, ``upstreamIdentifiers``, ``publishedAt``,
        # ``isDefault``, …) is dropped — it multiplies cache footprint
        # without being read.
        trimmed = _trim_deps_dev_v3(
            {
                "versionKey": {
                    "system": "GO",
                    "name": "github.com/foo/bar",
                    "version": "v1.0.0",
                },
                "licenses": ["MIT"],
                "links": [
                    {"label": "SOURCE_REPO", "url": "https://github.com/foo/bar"},
                    {"label": "HOMEPAGE", "url": "https://example.com"},
                ],
                "publishedAt": "2024-01-01T00:00:00Z",  # dropped
                "isDefault": True,  # dropped
                "advisoryKeys": [{"id": "GHSA-x"}],  # dropped
                "slsaProvenances": [{"x": "y"}],  # dropped
            }
        )
        assert trimmed["versionKey"]["name"] == "github.com/foo/bar"
        assert trimmed["licenses"] == ["MIT"]
        # Links survive; per-link extra fields drop. Both SOURCE_REPO and
        # HOMEPAGE are kept because the trim is structural — selection by
        # label happens at the resolver layer, not at trim time.
        assert {entry["label"] for entry in trimmed["links"]} == {
            "SOURCE_REPO",
            "HOMEPAGE",
        }
        # Other top-level fields dropped.
        assert "publishedAt" not in trimmed
        assert "isDefault" not in trimmed
        assert "advisoryKeys" not in trimmed
        assert "slsaProvenances" not in trimmed

    def test_trim_missing_licenses_yields_empty_list(self):
        trimmed = _trim_deps_dev_v3({"versionKey": {"name": "x"}})
        assert trimmed["licenses"] == []

    def test_trim_non_list_links_yields_empty(self):
        trimmed = _trim_deps_dev_v3({"links": "junk"})
        assert trimmed["links"] == []

    def test_trim_non_dict_link_entry_skipped(self):
        trimmed = _trim_deps_dev_v3(
            {"links": ["junk", {"label": "SOURCE_REPO", "url": "https://x"}]}
        )
        assert trimmed["links"] == [{"label": "SOURCE_REPO", "url": "https://x"}]

    def test_trim_for_cache_dispatch_deps_dev_v3_url(self):
        data = {
            "versionKey": {"name": "github.com/x", "version": "v1.0.0"},
            "licenses": ["MIT"],
            "links": [{"label": "SOURCE_REPO", "url": "https://github.com/x"}],
            "advisoryKeys": [{"id": "GHSA-x"}],
        }
        trimmed = _trim_for_cache(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Fx/versions/v1.0.0",
            data,
        )
        assert "advisoryKeys" not in trimmed
        assert trimmed["licenses"] == ["MIT"]
        assert trimmed["links"][0]["url"] == "https://github.com/x"

    @respx.mock
    def test_single_resolver_drives_deps_dev_through_registry_cache(self):
        # Per the cache-keep-set memory rule: any resolver field read must be
        # tested through ``RegistryCache.fetch`` to verify the trim keeps it.
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/foo/bar",
                        "version": "v1.0.0",
                    },
                    "licenses": ["MIT"],
                    "links": [
                        {
                            "label": "SOURCE_REPO",
                            "url": "https://github.com/foo/bar",
                        }
                    ],
                    "advisoryKeys": [{"id": "GHSA-x"}],
                },
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_go_license(_go_dep(), client, fetcher=cache.fetch)
        # Through the cache, ``advisoryKeys`` is trimmed but everything the
        # resolver reads (versionKey, licenses, links) survives.
        assert info.license_id == "MIT"
        assert info.repository_url == "https://github.com/foo/bar"
        assert info.resolved_version == "v1.0.0"


class TestEncodeModuleProxyPath:
    def test_no_uppercase_unchanged(self):
        assert encode_module_proxy_path("github.com/foo/bar") == "github.com/foo/bar"

    def test_uppercase_escaped_with_bang(self):
        # Per the Go modules reference: every uppercase letter is replaced
        # with ``!<lowercase>`` to avoid case-insensitive-filesystem collisions
        # on the proxy side.
        assert encode_module_proxy_path("github.com/MyOrg/MyMod") == "github.com/!my!org/!my!mod"

    def test_mixed_case_partially_encoded(self):
        assert encode_module_proxy_path("github.com/Foo/barBaz") == "github.com/!foo/bar!baz"


class TestFetchGoModText:
    @respx.mock
    def test_returns_text_wrapped_in_dict(self):
        respx.get("https://proxy.golang.org/example/@v/v1.0.0.mod").mock(
            return_value=httpx.Response(200, text="module example\ngo 1.22\n")
        )
        with httpx.Client() as client:
            result = fetch_go_mod_text("https://proxy.golang.org/example/@v/v1.0.0.mod", client)
        assert result == {"text": "module example\ngo 1.22\n"}

    @respx.mock
    def test_retries_retry_after_then_succeeds(self):
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, text="module x\n")

        respx.get("https://proxy.golang.org/x/@v/v1.mod").mock(side_effect=handler)
        with httpx.Client() as client:
            result = fetch_go_mod_text("https://proxy.golang.org/x/@v/v1.mod", client)
        assert result == {"text": "module x\n"}

    @respx.mock
    def test_request_error_then_succeeds(self):
        attempts = 0

        def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="module x\n")

        respx.get("https://proxy.golang.org/x/@v/v1.mod").mock(side_effect=handler)
        with httpx.Client() as client:
            result = fetch_go_mod_text("https://proxy.golang.org/x/@v/v1.mod", client)
        assert result == {"text": "module x\n"}

    @respx.mock
    def test_request_error_exhausts_returns_none(self):
        respx.get("https://proxy.golang.org/x/@v/v1.mod").mock(
            side_effect=httpx.ConnectError("permanent")
        )
        with httpx.Client() as client:
            result = fetch_go_mod_text("https://proxy.golang.org/x/@v/v1.mod", client)
        assert result is None

    @respx.mock
    def test_retryable_status_exhausts_returns_none(self):
        respx.get("https://proxy.golang.org/x/@v/v1.mod").mock(return_value=httpx.Response(503))
        with httpx.Client() as client:
            result = fetch_go_mod_text("https://proxy.golang.org/x/@v/v1.mod", client)
        assert result is None

    @respx.mock
    def test_non_retryable_4xx_returns_none(self):
        respx.get("https://proxy.golang.org/x/@v/v1.mod").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            result = fetch_go_mod_text("https://proxy.golang.org/x/@v/v1.mod", client)
        assert result is None

    def test_zero_attempts_returns_none(self, monkeypatch):
        from licenseal.resolvers import http as http_module

        monkeypatch.setattr(http_module, "_MAX_ATTEMPTS", 0)
        with httpx.Client() as client:
            assert fetch_go_mod_text("https://proxy.golang.org/x/@v/v1.mod", client) is None


class TestFetchMavenDependencies:
    """``fetch_maven_dependencies`` hits deps.dev's MAVEN
    ``:dependencies`` endpoint and parses (nodes, edges)."""

    @respx.mock
    def test_returns_nodes_and_edges_skipping_self(self):
        # The SELF node (the requested artifact) must NOT appear in
        # the returned nodes list — the caller already has that as
        # the direct dep object. DIRECT and INDIRECT both flow through.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        {
                            "versionKey": {
                                "system": "MAVEN",
                                "name": "com.example:a",
                                "version": "1.0",
                            },
                            "relation": "SELF",
                        },
                        {
                            "versionKey": {
                                "system": "MAVEN",
                                "name": "com.example:b",
                                "version": "2.0",
                            },
                            "relation": "DIRECT",
                        },
                        {
                            "versionKey": {
                                "system": "MAVEN",
                                "name": "com.example:c",
                                "version": "3.0",
                            },
                            "relation": "INDIRECT",
                        },
                    ],
                    "edges": [
                        {"fromNode": 0, "toNode": 1},
                        {"fromNode": 1, "toNode": 2},
                    ],
                },
            )
        )
        with httpx.Client() as client:
            nodes, edges = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert nodes == [("com.example:b", "2.0"), ("com.example:c", "3.0")]
        # Edges reference the actual (name, version) pairs, not indices.
        assert edges == [
            ("com.example:a", "1.0", "com.example:b", "2.0"),
            ("com.example:b", "2.0", "com.example:c", "3.0"),
        ]

    @respx.mock
    def test_returns_empty_on_fetch_failure(self):
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(return_value=httpx.Response(503))
        with httpx.Client() as client:
            nodes, edges = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert nodes == []
        assert edges == []

    @respx.mock
    def test_returns_empty_when_nodes_field_missing(self):
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(return_value=httpx.Response(200, json={}))
        with httpx.Client() as client:
            nodes, edges = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert nodes == []
        assert edges == []

    @respx.mock
    def test_returns_empty_when_nodes_field_wrong_type(self):
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(return_value=httpx.Response(200, json={"nodes": "junk"}))
        with httpx.Client() as client:
            nodes, edges = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert nodes == []
        assert edges == []

    @respx.mock
    def test_skips_malformed_node_entries(self):
        # Adversarial / malformed entries must not raise and must not
        # taint the output.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        "not a dict",
                        {"versionKey": "wrong type"},
                        {"versionKey": {"name": 42, "version": "1.0"}},
                        {"versionKey": {"name": "g:a", "version": None}},
                        {
                            "versionKey": {
                                "system": "MAVEN",
                                "name": "com.example:good",
                                "version": "1.0",
                            },
                            "relation": "DIRECT",
                        },
                    ],
                    "edges": [],
                },
            )
        )
        with httpx.Client() as client:
            nodes, _ = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert nodes == [("com.example:good", "1.0")]

    @respx.mock
    def test_skips_malformed_edge_entries(self):
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        {
                            "versionKey": {
                                "name": "com.example:a",
                                "version": "1.0",
                            },
                            "relation": "SELF",
                        },
                        {
                            "versionKey": {
                                "name": "com.example:b",
                                "version": "2.0",
                            },
                            "relation": "DIRECT",
                        },
                    ],
                    "edges": [
                        "not a dict",
                        {"fromNode": "junk", "toNode": 1},
                        {"fromNode": 0, "toNode": "junk"},
                        {"fromNode": -1, "toNode": 1},
                        {"fromNode": 0, "toNode": 999},
                        {"fromNode": 0, "toNode": 1},  # valid
                    ],
                },
            )
        )
        with httpx.Client() as client:
            _, edges = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert edges == [
            ("com.example:a", "1.0", "com.example:b", "2.0"),
        ]

    @respx.mock
    def test_edges_field_non_list_yields_empty(self):
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        {
                            "versionKey": {
                                "name": "com.example:a",
                                "version": "1.0",
                            },
                            "relation": "SELF",
                        },
                    ],
                    "edges": "garbage",
                },
            )
        )
        with httpx.Client() as client:
            _, edges = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert edges == []

    @respx.mock
    def test_edge_references_skipped_node_dropped(self):
        # A node entry that failed validation gets a ``None`` slot in
        # the node table. Edges that reference that slot must be
        # silently dropped (no IndexError, no half-attached edge).
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        {
                            "versionKey": {
                                "name": "com.example:a",
                                "version": "1.0",
                            },
                            "relation": "SELF",
                        },
                        "not a dict",  # slot 1 → None in node_table
                        {
                            "versionKey": {
                                "name": "com.example:b",
                                "version": "2.0",
                            },
                            "relation": "DIRECT",
                        },
                    ],
                    "edges": [
                        {"fromNode": 0, "toNode": 1},  # references None slot
                        {"fromNode": 0, "toNode": 2},  # valid
                    ],
                },
            )
        )
        with httpx.Client() as client:
            _, edges = fetch_maven_dependencies("com.example:a", "1.0", client)
        assert edges == [
            ("com.example:a", "1.0", "com.example:b", "2.0"),
        ]

    @respx.mock
    def test_through_registry_cache_trims_extra_fields(self):
        # Per the cache-keep-set memory rule: fields the resolver reads
        # must survive trimming. Both ``versionKey`` (on nodes) and
        # ``fromNode``/``toNode`` (on edges) are required for the
        # walker; any other field is dropped.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Aa/versions/1.0:dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        {
                            "versionKey": {
                                "name": "com.example:a",
                                "version": "1.0",
                            },
                            "relation": "SELF",
                            "errors": [],  # dropped by trim
                            "bundled": False,  # dropped by trim
                        },
                        {
                            "versionKey": {
                                "name": "com.example:b",
                                "version": "2.0",
                            },
                            "relation": "DIRECT",
                        },
                    ],
                    "edges": [
                        {"fromNode": 0, "toNode": 1, "requirement": "2.0"},
                    ],
                    "error": "",  # dropped by trim
                },
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            nodes, edges = fetch_maven_dependencies(
                "com.example:a", "1.0", client, fetcher=cache.fetch
            )
        # Walker-read fields survived.
        assert nodes == [("com.example:b", "2.0")]
        assert edges == [
            ("com.example:a", "1.0", "com.example:b", "2.0"),
        ]


class TestTrimDepsDevDependencies:
    def test_keeps_node_versionkey_and_relation(self):
        trimmed = _trim_deps_dev_dependencies(
            {
                "nodes": [
                    {
                        "versionKey": {"name": "g:a", "version": "1"},
                        "relation": "SELF",
                        "errors": [{"x": 1}],  # dropped
                        "bundled": True,  # dropped
                    }
                ],
                "edges": [],
            }
        )
        assert trimmed == {
            "nodes": [
                {
                    "versionKey": {"name": "g:a", "version": "1"},
                    "relation": "SELF",
                }
            ],
            "edges": [],
        }

    def test_keeps_edge_from_to_node(self):
        trimmed = _trim_deps_dev_dependencies(
            {
                "nodes": [],
                "edges": [
                    {
                        "fromNode": 0,
                        "toNode": 1,
                        "requirement": "1.0",  # dropped
                    }
                ],
            }
        )
        assert trimmed == {
            "nodes": [],
            "edges": [{"fromNode": 0, "toNode": 1}],
        }

    def test_missing_nodes_field(self):
        # Missing or non-list nodes → empty list (defensive).
        assert _trim_deps_dev_dependencies({}) == {"nodes": [], "edges": []}

    def test_non_list_nodes_field(self):
        assert _trim_deps_dev_dependencies({"nodes": "junk"}) == {
            "nodes": [],
            "edges": [],
        }

    def test_non_list_edges_field(self):
        assert _trim_deps_dev_dependencies({"nodes": [], "edges": "junk"}) == {
            "nodes": [],
            "edges": [],
        }

    def test_skips_non_dict_node_entries(self):
        trimmed = _trim_deps_dev_dependencies({"nodes": ["junk", {"versionKey": {}}], "edges": []})
        assert trimmed["nodes"] == [{"versionKey": {}}]

    def test_skips_non_dict_edge_entries(self):
        trimmed = _trim_deps_dev_dependencies(
            {"nodes": [], "edges": ["junk", {"fromNode": 0, "toNode": 1}]}
        )
        assert trimmed["edges"] == [{"fromNode": 0, "toNode": 1}]

    def test_trim_for_cache_routes_dependencies_url(self):
        data = {
            "nodes": [
                {
                    "versionKey": {"name": "g:a", "version": "1"},
                    "relation": "SELF",
                    "errors": [],
                }
            ],
            "edges": [],
            "error": "",
        }
        trimmed = _trim_for_cache(
            "https://api.deps.dev/v3/systems/MAVEN/packages/g%3Aa/versions/1:dependencies",
            data,
        )
        # The :dependencies trim ran (not the plain v3 version trim) —
        # the "errors" field is dropped from nodes.
        assert "errors" not in trimmed["nodes"][0]

    def test_trim_for_cache_plain_v3_url_routes_to_v3_trim(self):
        # Without ``:dependencies`` suffix, the plain v3 trim runs.
        data = {
            "versionKey": {"name": "g:a", "version": "1"},
            "licenses": ["MIT"],
            "links": [],
            "advisoryKeys": [{"id": "GHSA"}],  # dropped by v3 trim
        }
        trimmed = _trim_for_cache(
            "https://api.deps.dev/v3/systems/MAVEN/packages/g%3Aa/versions/1",
            data,
        )
        assert "advisoryKeys" not in trimmed
        assert trimmed["licenses"] == ["MIT"]


class TestExtractMavenPinnedVersion:
    """Edge cases in ``deps_dev._extract_maven_pinned_version``."""

    def test_empty_returns_none(self):
        from licenseal.resolvers.deps_dev import _extract_maven_pinned_version

        assert _extract_maven_pinned_version("") is None
        assert _extract_maven_pinned_version("   ") is None

    def test_bracketed_exact_pin_unwraps(self):
        from licenseal.resolvers.deps_dev import _extract_maven_pinned_version

        # Maven strict pin: ``[1.2.3]`` — the brackets demand the exact
        # version. We strip the brackets and treat as bare pin.
        assert _extract_maven_pinned_version("[1.2.3]") == "1.2.3"

    def test_open_range_returns_none(self):
        from licenseal.resolvers.deps_dev import _extract_maven_pinned_version

        # ``[1.0,)`` / ``(1.0,2.0)`` / ``(,2.0]`` are version ranges; we
        # don't pick a value for them, the per-package POM walker does.
        assert _extract_maven_pinned_version("[1.0,)") is None
        assert _extract_maven_pinned_version("(1.0,2.0)") is None

    def test_property_substitution_returns_none(self):
        from licenseal.resolvers.deps_dev import _extract_maven_pinned_version

        # ``${spring.version}`` — unresolved Maven property; can't pin.
        assert _extract_maven_pinned_version("${spring.version}") is None

    def test_whitespace_in_value_returns_none(self):
        from licenseal.resolvers.deps_dev import _extract_maven_pinned_version

        assert _extract_maven_pinned_version("1.0 2.0") is None

    def test_paren_prefixed_value_returns_none(self):
        from licenseal.resolvers.deps_dev import _extract_maven_pinned_version

        # ``(1.0)`` style version literals aren't a Maven idiom we know
        # how to interpret as a single pin — defensive reject.
        assert _extract_maven_pinned_version("(1.0)") is None


class TestDependenciesFromNuspec:
    """Edge cases in ``resolvers.nuget._dependencies_from_nuspec``."""

    def test_malformed_xml_returns_empty(self):
        from licenseal.resolvers.nuget import _dependencies_from_nuspec

        assert _dependencies_from_nuspec("<not really xml") == []

    def test_no_metadata_block_returns_empty(self):
        from licenseal.resolvers.nuget import _dependencies_from_nuspec

        # Well-formed XML but missing the ``<metadata>`` envelope —
        # nothing to parse.
        assert _dependencies_from_nuspec("<package><other/></package>") == []

    def test_missing_id_or_version_attribute_skipped(self):
        from licenseal.resolvers.nuget import _dependencies_from_nuspec

        # ``<dependency>`` without both ``id`` and ``version`` is dropped
        # — there's no useful (name, version) to emit.
        body = (
            "<package><metadata><dependencies>"
            '<dependency id="OnlyId" />'
            '<dependency version="1.0.0" />'
            '<dependency id="" version="1.0.0" />'
            '<dependency id="Good" version="1.0.0" />'
            "</dependencies></metadata></package>"
        )
        assert _dependencies_from_nuspec(body) == [("Good", "1.0.0")]

    def test_unparseable_version_skipped(self):
        from licenseal.resolvers.nuget import _dependencies_from_nuspec

        # Floating versions and MSBuild property tokens have no concrete
        # pin so ``_extract_pinned_version_nuget`` returns ``None`` and
        # the nuspec parser drops them. Bracket ranges ``[1.0,2.0)`` DO
        # resolve to the lower bound (conservative lockfile-equivalent
        # behavior — see :func:`_extract_pinned_version_nuget`'s
        # docstring) and are NOT dropped.
        body = (
            "<package><metadata><dependencies>"
            '<dependency id="Floating" version="1.*" />'
            '<dependency id="Token" version="$(Var)" />'
            '<dependency id="Good" version="2.0.0" />'
            "</dependencies></metadata></package>"
        )
        assert _dependencies_from_nuspec(body) == [("Good", "2.0.0")]

    def test_unknown_tags_inside_dependencies_skipped(self):
        from licenseal.resolvers.nuget import _dependencies_from_nuspec

        # Some publishers nest non-standard elements (``<reference>``,
        # ``<contentFiles>``) alongside ``<dependency>``. The parser
        # walks only ``<dependency>`` and ``<group>`` children directly
        # under ``<dependencies>``, and only ``<dependency>`` inside a
        # ``<group>``. Anything else is silently ignored.
        body = (
            "<package><metadata><dependencies>"
            '<reference id="StrayRef" version="1.0.0" />'
            '<group targetFramework="net8.0">'
            '<contentFiles include="*" />'
            '<dependency id="Real" version="3.0.0" />'
            "</group>"
            "</dependencies></metadata></package>"
        )
        assert _dependencies_from_nuspec(body) == [("Real", "3.0.0")]


class TestNuspecWalkerDepthCap:
    """Defensive cap on recursion depth — should never trigger in real graphs."""

    @respx.mock
    def test_depth_cap_terminates_walk(self, monkeypatch):
        from licenseal.resolvers import nuget as nuget_mod

        # Lower the cap so we don't have to mock 32 chained packages.
        monkeypatch.setattr(nuget_mod, "_NUSPEC_WALK_MAX_DEPTH", 2)

        def _url(name: str) -> str:
            lowered = name.lower()
            return f"https://api.nuget.org/v3-flatcontainer/{lowered}/1.0.0/{lowered}.nuspec"

        def _nuspec(name: str, child: str | None = None) -> str:
            dep = f'<dependency id="{child}" version="1.0.0" />' if child else ""
            return (
                f"<package><metadata><id>{name}</id>"
                f"<dependencies>{dep}</dependencies></metadata></package>"
            )

        # A → B → C → D. Cap=2 means we walk A's children (B) and B's
        # children (C), but stop before fetching C's nuspec.
        respx.get(_url("A")).respond(text=_nuspec("A", "B"))
        respx.get(_url("B")).respond(text=_nuspec("B", "C"))
        # C and D nuspecs intentionally NOT mocked — if the cap fails,
        # respx would raise AllMockedAssertionError.

        with httpx.Client() as client:
            nodes, _ = nuget_mod.fetch_nuget_dependencies("A", "1.0.0", client)

        # Both B and C surface as nodes; D never gets requested because
        # the cap fires before C's nuspec is fetched.
        assert ("B", "1.0.0") in nodes
        assert ("C", "1.0.0") in nodes
        assert ("D", "1.0.0") not in nodes


class TestBulkResolveNugetLicenses:
    """``bulk_resolve_nuget_licenses`` mirrors the Go bulk path with ``system="NUGET"``."""

    @respx.mock
    def test_batch_returns_license_info_for_resolved_versions(self):
        from licenseal.resolvers.deps_dev import bulk_resolve_nuget_licenses

        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "NUGET",
                                    "name": "Newtonsoft.Json",
                                    "version": "13.0.1",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "NUGET",
                                    "name": "Newtonsoft.Json",
                                    "version": "13.0.1",
                                },
                                "licenses": ["MIT"],
                                "links": [],
                            },
                        }
                    ]
                },
            )
        )
        dep = Dependency(
            name="Newtonsoft.Json",
            version_constraint="13.0.1",
            ecosystem=Ecosystem.DOTNET,
            group=DependencyGroup.PROD,
        )
        with httpx.Client() as client:
            cache = bulk_resolve_nuget_licenses([dep], client, max_workers=4)
        key = ("Newtonsoft.Json", "13.0.1")
        assert key in cache
        info = cache[key]
        assert info is not None
        assert info.license_id == "MIT"

    @respx.mock
    def test_unparseable_version_excluded_from_batch(self):
        from licenseal.resolvers.deps_dev import bulk_resolve_nuget_licenses

        # respx will fail loudly if a POST is made when no deps are walkable.
        dep = Dependency(
            name="X",
            version_constraint="$(NotResolved)",
            ecosystem=Ecosystem.DOTNET,
            group=DependencyGroup.PROD,
        )
        with httpx.Client() as client:
            cache = bulk_resolve_nuget_licenses([dep], client, max_workers=4)
        assert cache == {}


class TestFetchNugetDependencies:
    """Nuspec-based NuGet transitive walker (``resolvers.nuget.fetch_nuget_dependencies``).

    The previous implementation called deps.dev's NUGET
    ``GetDependencies`` endpoint, which always 404s (per deps.dev docs:
    only npm / Cargo / Maven / PyPI are supported). The current
    implementation reads each ``.nuspec``'s ``<dependencies>`` block
    from the NuGet flatcontainer and walks the subgraph recursively.
    """

    @staticmethod
    def _nuspec_url(name: str, version: str) -> str:
        lowered = name.lower()
        return f"https://api.nuget.org/v3-flatcontainer/{lowered}/{version}/{lowered}.nuspec"

    @staticmethod
    def _nuspec(package_id: str, *children: tuple[str, str]) -> str:
        deps_xml = "".join(f'<dependency id="{cid}" version="{cver}" />' for cid, cver in children)
        # Wrap in a single TFM group so we exercise the group-walking path
        # (the older flat-list shape is exercised by separate unit tests).
        return (
            f"<package><metadata><id>{package_id}</id>"
            f'<dependencies><group targetFramework="net8.0">{deps_xml}</group>'
            f"</dependencies></metadata></package>"
        )

    @respx.mock
    def test_walks_recursive_subgraph(self):
        from licenseal.resolvers.nuget import fetch_nuget_dependencies

        # Root → A → B chain; verify both nodes + both edges surface.
        respx.get(self._nuspec_url("Root", "1.0.0")).respond(
            text=self._nuspec("Root", ("A", "1.0.0"))
        )
        respx.get(self._nuspec_url("A", "1.0.0")).respond(text=self._nuspec("A", ("B", "2.0.0")))
        respx.get(self._nuspec_url("B", "2.0.0")).respond(text=self._nuspec("B"))

        with httpx.Client() as client:
            nodes, edges = fetch_nuget_dependencies("Root", "1.0.0", client)

        assert set(nodes) == {("A", "1.0.0"), ("B", "2.0.0")}
        assert ("Root", "1.0.0", "A", "1.0.0") in edges
        assert ("A", "1.0.0", "B", "2.0.0") in edges

    @respx.mock
    def test_returns_empty_on_root_fetch_failure(self):
        from licenseal.resolvers.nuget import fetch_nuget_dependencies

        respx.get(self._nuspec_url("Missing", "0.0.0")).respond(404)
        with httpx.Client() as client:
            nodes, edges = fetch_nuget_dependencies("Missing", "0.0.0", client)
        assert nodes == []
        assert edges == []

    @respx.mock
    def test_cycle_does_not_recurse_forever(self):
        from licenseal.resolvers.nuget import fetch_nuget_dependencies

        # A → B → A (cycle); should emit each node once, walker terminates.
        respx.get(self._nuspec_url("A", "1.0.0")).respond(text=self._nuspec("A", ("B", "1.0.0")))
        respx.get(self._nuspec_url("B", "1.0.0")).respond(text=self._nuspec("B", ("A", "1.0.0")))

        with httpx.Client() as client:
            nodes, edges = fetch_nuget_dependencies("A", "1.0.0", client)

        # Only B emerges as a node (A is the SELF root). The edge back to
        # A is recorded but A is not re-walked.
        assert set(nodes) == {("B", "1.0.0")}
        # Both edges present: A→B and B→A.
        assert set(edges) == {
            ("A", "1.0.0", "B", "1.0.0"),
            ("B", "1.0.0", "A", "1.0.0"),
        }

    @respx.mock
    def test_flat_dependencies_list_without_tfm_groups(self):
        from licenseal.resolvers.nuget import fetch_nuget_dependencies

        # Older nuspec packages declare <dependency> directly under
        # <dependencies>, no <group> wrappers. Must still parse.
        respx.get(self._nuspec_url("LegacyRoot", "1.0.0")).respond(
            text=(
                "<package><metadata><id>LegacyRoot</id>"
                "<dependencies>"
                '<dependency id="LegacyChild" version="2.0.0" />'
                "</dependencies></metadata></package>"
            )
        )
        respx.get(self._nuspec_url("LegacyChild", "2.0.0")).respond(
            text=self._nuspec("LegacyChild")
        )

        with httpx.Client() as client:
            nodes, edges = fetch_nuget_dependencies("LegacyRoot", "1.0.0", client)

        assert nodes == [("LegacyChild", "2.0.0")]
        assert edges == [("LegacyRoot", "1.0.0", "LegacyChild", "2.0.0")]

    @respx.mock
    def test_union_across_multiple_tfm_groups(self):
        from licenseal.resolvers.nuget import fetch_nuget_dependencies

        # Two TFM groups with overlapping + distinct deps. The walker
        # should union: every dep across every group surfaces once.
        respx.get(self._nuspec_url("Multi", "1.0.0")).respond(
            text=(
                "<package><metadata><id>Multi</id>"
                "<dependencies>"
                '  <group targetFramework="net8.0">'
                '    <dependency id="Shared" version="1.0.0" />'
                '    <dependency id="NetOnly" version="1.0.0" />'
                "  </group>"
                '  <group targetFramework="netstandard2.0">'
                '    <dependency id="Shared" version="1.0.0" />'
                '    <dependency id="StandardOnly" version="2.0.0" />'
                "  </group>"
                "</dependencies></metadata></package>"
            )
        )
        for child_name, child_ver in [
            ("Shared", "1.0.0"),
            ("NetOnly", "1.0.0"),
            ("StandardOnly", "2.0.0"),
        ]:
            respx.get(self._nuspec_url(child_name, child_ver)).respond(
                text=self._nuspec(child_name)
            )

        with httpx.Client() as client:
            nodes, _ = fetch_nuget_dependencies("Multi", "1.0.0", client)

        assert set(nodes) == {
            ("Shared", "1.0.0"),
            ("NetOnly", "1.0.0"),
            ("StandardOnly", "2.0.0"),
        }


def _ruby_dep(name: str = "rails", version: str = "==7.1.3") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.RUBY,
        group=DependencyGroup.PROD,
    )


class TestBulkResolveRubyLicenses:
    """Batch POST to deps.dev's ``/v3alpha/versionbatch`` for RUBYGEMS."""

    @respx.mock
    def test_batch_request_uses_rubygems_system(self):
        captured: dict[str, dict] = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "RUBYGEMS",
                                    "name": "rails",
                                    "version": "7.1.3",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "RUBYGEMS",
                                    "name": "rails",
                                    "version": "7.1.3",
                                },
                                "licenses": ["MIT"],
                                "links": [
                                    {
                                        "label": "SOURCE_REPO",
                                        "url": "https://github.com/rails/rails",
                                    }
                                ],
                            },
                        }
                    ],
                    "nextPageToken": "",
                },
            )

        from licenseal.resolvers.deps_dev import bulk_resolve_ruby_licenses

        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(side_effect=handler)
        with httpx.Client() as client:
            cache = bulk_resolve_ruby_licenses([_ruby_dep()], client, max_workers=4)
        assert ("rails", "7.1.3") in cache
        info = cache[("rails", "7.1.3")]
        assert info is not None
        assert info.license_id == "MIT"
        assert captured["body"]["requests"][0]["versionKey"]["system"] == "RUBYGEMS"

    @respx.mock
    def test_unpinned_dep_skipped(self):
        # ``==`` extraction returns None for a range constraint; the dep
        # never enters the batch. Empty input → no POST issued.
        from licenseal.resolvers.deps_dev import bulk_resolve_ruby_licenses

        with httpx.Client() as client:
            cache = bulk_resolve_ruby_licenses(
                [_ruby_dep(version="~> 7.0")],
                client,
                max_workers=4,
            )
        assert cache == {}

    def test_empty_input_no_request(self):
        from licenseal.resolvers.deps_dev import bulk_resolve_ruby_licenses

        with httpx.Client() as client:
            cache = bulk_resolve_ruby_licenses([], client, max_workers=4)
        assert cache == {}


class TestNpmRegistryEdgeCases:
    @respx.mock
    def test_dict_license_from_latest(self):
        """License field as dict with type key."""
        respx.get("https://registry.npmjs.org/pkg/latest").mock(
            return_value=httpx.Response(
                200,
                json={
                    "license": {"type": "ISC"},
                    "version": "1.0.0",
                },
            )
        )
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.NPM)
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "ISC"

    @respx.mock
    def test_malformed_json_response(self):
        """Non-JSON response from npm registry should return UNKNOWN."""
        respx.get("https://registry.npmjs.org/bad/latest").mock(
            return_value=httpx.Response(200, text="<html>error</html>")
        )
        dep = Dependency(name="bad", version_constraint="", ecosystem=Ecosystem.NPM)
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False


class TestNpmRegistryLatestEndpoint:
    @respx.mock
    def test_no_license_field(self):
        """No license field in /latest response."""
        respx.get("https://registry.npmjs.org/pkg/latest").mock(
            return_value=httpx.Response(
                200,
                json={"version": "1.0.0"},
            )
        )
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.NPM)
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "UNKNOWN"

    @respx.mock
    def test_no_version_field(self):
        """No version field in /latest response — resolved_version should be empty."""
        respx.get("https://registry.npmjs.org/pkg2/latest").mock(
            return_value=httpx.Response(
                200,
                json={"license": "MIT"},
            )
        )
        dep = Dependency(name="pkg2", version_constraint="", ecosystem=Ecosystem.NPM)
        with httpx.Client() as client:
            li = resolve_npm_license(dep, client)
        assert li.license_id == "MIT"
        assert li.resolved_version == ""


class TestPyPIEdgeCases:
    @respx.mock
    def test_classifier_no_license_prefix(self):
        """Classifiers that don't start with the license prefix are skipped."""
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "",
                        "version": "1.0",
                        "classifiers": [
                            "Programming Language :: Python :: 3",
                        ],
                    }
                },
            )
        )
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"


class TestPyPIMalformedJson:
    @respx.mock
    def test_malformed_json_response(self):
        """Non-JSON response from PyPI should return UNKNOWN."""
        respx.get("https://pypi.org/pypi/bad/json").mock(
            return_value=httpx.Response(200, text="<html>error</html>")
        )
        dep = Dependency(name="bad", version_constraint="", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "UNKNOWN"
        assert li.from_registry is False


class TestPyPIExtractRawLicenseGuard:
    def test_non_dict_input_returns_empty(self):
        # Defensive guard for malformed PyPI responses where `info` is missing
        # or arrives as a non-object JSON value.
        assert _extract_raw_license(None) == ""  # type: ignore[arg-type]
        assert _extract_raw_license("not a dict") == ""  # type: ignore[arg-type]
        assert _extract_raw_license([]) == ""  # type: ignore[arg-type]
