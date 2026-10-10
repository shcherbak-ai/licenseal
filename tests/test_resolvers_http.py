from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx
import pytest
import respx
import tethered

from licenseal.resolvers import http as registry_http
from tests._helpers import _DEEP


class TestHostRateLimiter:
    def test_serializes_request_start_times(self, monkeypatch):
        now = [10.0]
        sleeps: list[float] = []

        def fake_monotonic() -> float:
            return now[0]

        def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        monkeypatch.setattr(registry_http.time, "monotonic", fake_monotonic)
        monkeypatch.setattr(registry_http.time, "sleep", fake_sleep)

        limiter = registry_http._HostRateLimiter(1.0)  # noqa: SLF001

        limiter.acquire()
        now[0] = 10.25
        limiter.acquire()
        now[0] = 12.5
        limiter.acquire()

        assert sleeps == [0.75]

    def test_only_crates_io_is_limited(self, monkeypatch):
        acquired: list[str] = []

        class ProbeLimiter:
            def acquire(self) -> None:
                acquired.append("crates.io")

        monkeypatch.setitem(
            registry_http._HOST_RATE_LIMITERS,  # noqa: SLF001
            "crates.io",
            ProbeLimiter(),
        )

        registry_http._respect_host_rate_limit("https://crates.io/api/v1/crates/serde")  # noqa: SLF001
        registry_http._respect_host_rate_limit("https://pypi.org/pypi/click/json")  # noqa: SLF001
        registry_http._respect_host_rate_limit("not-a-url")  # noqa: SLF001

        assert acquired == ["crates.io"]

    @respx.mock
    def test_json_fetch_applies_rate_limit_before_request(self, monkeypatch):
        calls: list[str] = []

        def probe_rate_limit(url: str) -> None:
            calls.append(url)

        monkeypatch.setattr(registry_http, "_respect_host_rate_limit", probe_rate_limit)
        url = "https://crates.io/api/v1/crates/serde"
        respx.get(url).mock(return_value=httpx.Response(200, json={"crate": {"name": "serde"}}))

        with httpx.Client() as client:
            result = registry_http.fetch_registry_json(url, client)

        assert result == {"crate": {"name": "serde"}}
        assert calls == ["https://crates.io/api/v1/crates/serde"]


def _window(
    *, max_pause: float = 65.0, max_total: float = 650.0, max_stalled: int = 3
) -> registry_http._HostRateLimitWindow:  # noqa: SLF001
    return registry_http._HostRateLimitWindow(max_pause, max_total, max_stalled)  # noqa: SLF001


def _rate_limited(clock, *, reset_in: int) -> httpx.Response:
    """A 429 whose window resets ``reset_in`` seconds from the fake clock's now."""
    return httpx.Response(429, headers={"x-ratelimit-reset": str(int(clock.time()) + reset_in)})


class TestHostRateLimitWindow:
    def test_429_pauses_requests_until_the_reported_reset(self, fake_registry_clock):
        window = _window()

        assert window.defer(_rate_limited(fake_registry_clock, reset_in=30)) is True
        window.acquire()
        # Reset time plus the one-second margin; once it has passed, requests
        # go straight through.
        assert fake_registry_clock.sleeps == [31.0]
        window.acquire()
        assert fake_registry_clock.sleeps == [31.0]

    def test_no_pause_before_any_rate_limited_response(self, fake_registry_clock):
        window = _window()
        window.acquire()
        assert window.defer(httpx.Response(200)) is False
        assert window.defer(httpx.Response(503)) is False
        window.acquire()
        assert fake_registry_clock.sleeps == []

    @pytest.mark.parametrize(
        "headers",
        [
            {},  # header absent
            {"x-ratelimit-reset": "soon"},  # not a number
            {"x-ratelimit-reset": "1"},  # long past by the local clock
            {"x-ratelimit-reset": "99999999999"},  # further off than a window lasts
        ],
    )
    def test_unusable_reset_time_waits_out_one_whole_window(self, fake_registry_clock, headers):
        window = _window()

        assert window.defer(httpx.Response(429, headers=headers)) is True
        window.acquire()
        assert fake_registry_clock.sleeps == [65.0]

    def test_workers_rate_limited_together_share_one_pause(self, fake_registry_clock):
        # A full pool of workers draws 429s for the same window at the same
        # moment. All of them must be told to wait, but only one pause may be
        # opened and charged to the budget.
        window = _window()
        workers = 16
        start = threading.Barrier(workers)
        responses = [_rate_limited(fake_registry_clock, reset_in=30) for _ in range(workers)]

        def hit_limit(response: httpx.Response) -> bool:
            start.wait()
            return window.defer(response)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            deferred = list(pool.map(hit_limit, responses))

        assert deferred == [True] * workers
        assert window._stalled_pauses == 1  # noqa: SLF001
        assert window._remaining_seconds == 650.0 - 31.0  # noqa: SLF001

    def test_host_that_never_lifts_its_limit_stops_being_waited_on(self, fake_registry_clock):
        window = _window(max_stalled=3)

        for _ in range(3):
            assert window.defer(_rate_limited(fake_registry_clock, reset_in=59)) is True
            window.acquire()
        # Three windows waited out with nothing but 429s in between: decline,
        # so the caller's ordinary retry budget takes over.
        assert window.defer(_rate_limited(fake_registry_clock, reset_in=59)) is False
        window.acquire()
        assert fake_registry_clock.sleeps == [60.0, 60.0, 60.0]

        # Any non-429 response shows the limit lifted; waiting is allowed again.
        assert window.defer(httpx.Response(404)) is False
        assert window.defer(_rate_limited(fake_registry_clock, reset_in=59)) is True

    def test_total_pausing_is_bounded_even_while_the_host_makes_progress(self, fake_registry_clock):
        # A host that lets a little through every window never trips the
        # consecutive-pause bound. The total budget still ends the waiting.
        window = _window(max_total=150.0)

        granted = 0
        for _ in range(10):
            if window.defer(_rate_limited(fake_registry_clock, reset_in=59)):
                granted += 1
                window.acquire()
            assert window.defer(httpx.Response(200)) is False

        assert granted == 2
        assert sum(fake_registry_clock.sleeps) == 120.0

    def test_only_hex_pm_has_a_rate_limit_window(self, monkeypatch, fake_registry_clock):
        assert set(registry_http._HOST_RATE_LIMIT_WINDOWS) == {"hex.pm"}  # noqa: SLF001
        probe = _window()
        monkeypatch.setitem(registry_http._HOST_RATE_LIMIT_WINDOWS, "hex.pm", probe)  # noqa: SLF001
        limited = _rate_limited(fake_registry_clock, reset_in=30)

        defer = registry_http._defer_to_rate_limit_window  # noqa: SLF001
        assert defer("https://pypi.org/pypi/pkg-a/json", limited) is False
        assert defer("https://crates.io/api/v1/crates/pkg-a", limited) is False
        assert defer("not-a-url", limited) is False
        assert probe._stalled_pauses == 0  # noqa: SLF001

        assert defer("https://HEX.pm/api/packages/pkg_a", limited) is True
        # The pause holds back every later request to the host — and only it.
        registry_http._respect_host_rate_limit("https://pypi.org/pypi/pkg-a/json")  # noqa: SLF001
        assert fake_registry_clock.sleeps == []
        registry_http._respect_host_rate_limit("https://hex.pm/api/packages/pkg_b")  # noqa: SLF001
        assert fake_registry_clock.sleeps == [31.0]


class TestHexPmRateLimitedFetch:
    """``fetch_registry_json`` against a hex.pm that answers 429."""

    _URL = "https://hex.pm/api/packages/pkg_a"

    @staticmethod
    def _serve(clock, statuses: list[int]):
        """Answer successive requests with ``statuses``; 429s report a reset."""
        remaining = iter(statuses)

        def handler(request: httpx.Request) -> httpx.Response:
            status = next(remaining)
            if status == 429:
                return httpx.Response(
                    429, headers={"x-ratelimit-reset": str(int(clock.time() + 59))}
                )
            return httpx.Response(status, json={"meta": {"licenses": ["MIT"]}})

        return handler

    @respx.mock
    def test_waits_out_the_window_instead_of_giving_up(self, fake_registry_clock):
        # Three 429s would exhaust the ordinary three-attempt budget. Each one
        # is waited out to the window reset instead, and the fourth request
        # gets through.
        route = respx.get(self._URL).mock(
            side_effect=self._serve(fake_registry_clock, [429, 429, 429, 200])
        )
        with httpx.Client() as client:
            data = registry_http.fetch_registry_json(self._URL, client)

        assert data == {"meta": {"licenses": ["MIT"]}}
        assert route.call_count == 4
        assert fake_registry_clock.sleeps == [60.0, 60.0, 60.0]

    @respx.mock
    def test_rate_limit_wait_does_not_spend_a_retry_attempt(self, fake_registry_clock):
        # One rate-limit wait, then two server errors, then success. The two
        # errors use two of the three attempts; had the 429 used one as well,
        # the second error would have been the last attempt.
        route = respx.get(self._URL).mock(
            side_effect=self._serve(fake_registry_clock, [429, 503, 503, 200])
        )
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1),
            httpx.Client() as client,
        ):
            data = registry_http.fetch_registry_json(self._URL, client)

        assert data == {"meta": {"licenses": ["MIT"]}}
        assert route.call_count == 4
        assert fake_registry_clock.sleeps == [60.0, 0.1, 0.1]

    @respx.mock
    def test_host_stuck_at_429_ends_in_the_ordinary_retry_budget(self, fake_registry_clock):
        # The host never lifts the limit. After the bounded number of window
        # waits the ordinary budget applies: three more attempts, then failure.
        route = respx.get(self._URL).mock(return_value=httpx.Response(429))
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1),
            httpx.Client() as client,
        ):
            data = registry_http.fetch_registry_json(self._URL, client)

        assert data is None
        assert route.call_count == 3 + 3
        assert fake_registry_clock.sleeps == [65.0, 65.0, 65.0, 0.1, 0.1]

    @respx.mock
    def test_pool_of_workers_rate_limited_together_all_recover(self, fake_registry_clock):
        # A full pool of workers, each fetching a different package through the
        # per-scan cache, all land in a window that is already spent. The host
        # answers 429 until its reset time. Every worker must come back with
        # data, and none may wait longer than one window allows.
        reset_at = int(fake_registry_clock.time()) + 30

        def handler(request: httpx.Request) -> httpx.Response:
            if fake_registry_clock.time() < reset_at:
                return httpx.Response(429, headers={"x-ratelimit-reset": str(reset_at)})
            return httpx.Response(200, json={"meta": {"licenses": ["MIT"]}})

        respx.get(url__regex=r"^https://hex\.pm/api/packages/pkg_\d+$").mock(side_effect=handler)
        urls = [f"https://hex.pm/api/packages/pkg_{i}" for i in range(16)]
        cache = registry_http.RegistryCache()
        with httpx.Client() as client, ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda url: cache.fetch(url, client), urls))

        assert results == [{"meta": {"licenses": ["MIT"]}}] * 16
        assert max(fake_registry_clock.sleeps) <= 65.0

    @respx.mock
    def test_other_hosts_keep_the_ordinary_retry_budget(self, fake_registry_clock):
        # The same headers from a host without a rate-limit window change
        # nothing: three attempts with the short backoff, then failure.
        url = "https://example.com/data"
        route = respx.get(url).mock(
            return_value=httpx.Response(
                429, headers={"x-ratelimit-reset": str(int(fake_registry_clock.time() + 59))}
            )
        )
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1),
            httpx.Client() as client,
        ):
            data = registry_http.fetch_registry_json(url, client)

        assert data is None
        assert route.call_count == 3
        assert fake_registry_clock.sleeps == [0.1, 0.1]


# One URL per JSON endpoint licenseal reads, so each cache trim is exercised.
_JSON_ENDPOINTS = [
    "https://pypi.org/pypi/pkg-a/json",
    "https://pypi.org/pypi/pkg-a/1.0.0/json",
    "https://registry.npmjs.org/pkg-a",
    "https://registry.npmjs.org/pkg-a/1.0.0",
    "https://crates.io/api/v1/crates/pkg-a",
    "https://crates.io/api/v1/crates/pkg-a/1.0.0/dependencies",
    "https://api.deps.dev/v3/systems/GO/packages/example.com%2Fpkg-a/versions/v1.0.0",
    "https://api.deps.dev/v3/systems/MAVEN/packages/g%3Apkg-a/versions/1.0.0:dependencies",
    "https://repo.packagist.org/p2/vendor/pkg-a.json",
    "https://rubygems.org/api/v2/rubygems/pkg-a/versions/1.0.0.json",
    "https://rubygems.org/api/v1/gems/pkg-a.json",
    "https://hex.pm/api/packages/pkg_a",
    "https://hex.pm/api/packages/pkg_a/releases/1.0.0",
]

_NOT_A_JSON_OBJECT = [
    pytest.param(b"[]", id="empty-list"),
    pytest.param(b'[{"info": {"license": "MIT"}}]', id="list-of-objects"),
    pytest.param(b'"MIT"', id="string"),
    pytest.param(b"5", id="number"),
    pytest.param(b"true", id="boolean"),
    pytest.param(b"null", id="null"),
    pytest.param(b"[" * _DEEP + b"]" * _DEEP, id="lists-nested-too-deeply"),
    pytest.param(b'{"a":' * _DEEP + b"1" + b"}" * _DEEP, id="objects-nested-too-deeply"),
]


class TestBodyThatIsNotAJsonObject:
    """An HTTP 200 whose body is valid JSON of the wrong type, or JSON nested
    too deeply to parse, is a failed lookup. The fetch helpers settle that
    before any cache trim or resolver sees the body.
    """

    @respx.mock
    @pytest.mark.parametrize("body", _NOT_A_JSON_OBJECT)
    def test_get_through_the_cache_is_a_failed_lookup(self, body):
        routes = {
            url: respx.get(url).mock(return_value=httpx.Response(200, content=body))
            for url in _JSON_ENDPOINTS
        }
        cache = registry_http.RegistryCache()
        with httpx.Client() as client:
            for url in _JSON_ENDPOINTS:
                assert cache.fetch(url, client) is None, url
                # Cached like any other failed lookup: not requested again.
                assert cache.fetch(url, client) is None, url
        assert {url: route.call_count for url, route in routes.items()} == dict.fromkeys(
            _JSON_ENDPOINTS, 1
        )
        assert (cache.fetches_attempted, cache.fetches_succeeded) == (len(_JSON_ENDPOINTS), 0)

    @respx.mock
    @pytest.mark.parametrize("body", _NOT_A_JSON_OBJECT)
    def test_post_is_a_failed_lookup(self, body):
        url = "https://example.com/batch"
        route = respx.post(url).mock(return_value=httpx.Response(200, content=body))
        with httpx.Client() as client:
            assert registry_http.fetch_registry_json_post(url, {"requests": []}, client) is None
        assert route.call_count == 1

    @respx.mock
    def test_an_object_is_still_returned(self):
        url = "https://crates.io/api/v1/crates/pkg-a"
        respx.get(url).mock(return_value=httpx.Response(200, content=b'{"crate": {}}'))
        respx.post("https://example.com/batch").mock(
            return_value=httpx.Response(200, content=b'{"responses": []}')
        )
        with httpx.Client() as client:
            assert registry_http.RegistryCache().fetch(url, client) == {"crate": {}}
            assert registry_http.fetch_registry_json_post(
                "https://example.com/batch", {"requests": []}, client
            ) == {"responses": []}


def _post(url: str, client: httpx.Client) -> dict | None:
    return registry_http.fetch_registry_json_post(url, {"requests": []}, client)


# The GET helpers put a dependency's name and version in the URL. The POST
# helper is only ever given the fixed batch endpoint; the names travel in its
# body.
_GET_FETCHERS = {
    "json-get": registry_http.fetch_registry_json,
    "text": registry_http.fetch_registry_text,
    "pep658": registry_http.fetch_pep658_metadata,
}
# The four fetch helpers every registry request goes through.
_FETCHERS = {**_GET_FETCHERS, "json-post": _post}


class TestUrlTheClientRefusesToBuild:
    """A dependency name or version can hold a character no URL may carry. The
    client rejects such a URL before sending anything; that is a failed lookup
    for the one URL, not an error and not something to retry.
    """

    @respx.mock
    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("https://pypi.org/pypi/pkg\x01a/json", id="control-character"),
            pytest.param("https://pypi.org/pypi/pkg\na/json", id="newline"),
            pytest.param("https://pypi.org/pypi/pkg\ta/json", id="tab"),
            pytest.param("https://pypi.org/pypi/pkg\x7fa/json", id="delete"),
            pytest.param("https://pypi.org/pypi/" + "a" * 70_000 + "/json", id="over-long"),
        ],
    )
    def test_is_a_failed_lookup_with_no_request_and_no_retry(self, url, fake_registry_clock):
        with httpx.Client() as client:
            for name, fetch in _GET_FETCHERS.items():
                assert fetch(url, client) is None, name
        assert respx.calls.call_count == 0
        assert fake_registry_clock.sleeps == []

    @respx.mock
    def test_through_the_cache_it_is_a_cached_failed_lookup(self):
        json_url = "https://registry.npmjs.org/pkg\x01a/1.0.0"
        text_url = "https://proxy.golang.org/example.com/pkg\x01a/@v/v1.0.0.mod"
        cache = registry_http.RegistryCache()
        with httpx.Client() as client:
            assert cache.fetch(json_url, client) is None
            assert cache.fetch(json_url, client) is None
            assert cache.fetch_text(text_url, client) is None
        assert respx.calls.call_count == 0
        assert (cache.fetches_attempted, cache.fetches_succeeded) == (2, 0)

    @respx.mock
    def test_link_with_an_unparseable_authority_is_a_failed_lookup(self):
        # A registry-supplied link (the wheel URL a sidecar fetch is built on)
        # whose authority neither the rate-limit lookup nor the client can
        # parse.
        url = "https://files\uff0fexample.invalid/pkg_a-1.0.0-py3-none-any.whl.metadata"
        with httpx.Client() as client:
            assert registry_http.fetch_pep658_metadata(url, client) is None
        assert respx.calls.call_count == 0


class TestBlockedEgressStillPropagates:
    """The fetch helpers turn failed lookups into ``None``. A blocked egress is
    not one of them: it must reach the caller so the scan aborts.
    """

    @pytest.mark.parametrize("fetcher", sorted(_FETCHERS))
    def test_fetch_helper_does_not_swallow_it(self, fetcher):
        with httpx.Client() as client, pytest.raises(tethered.EgressBlocked):
            _FETCHERS[fetcher]("https://example.invalid/data", client)

    def test_cache_does_not_record_it_as_a_failed_lookup(self):
        url = "https://example.invalid/data"
        cache = registry_http.RegistryCache()
        with httpx.Client() as client:
            with pytest.raises(tethered.EgressBlocked):
                cache.fetch(url, client)
            with pytest.raises(tethered.EgressBlocked):
                cache.fetch_text(url, client)
        assert cache.fetches_attempted == 0


class TestRetryAfterThatIsNotANumber:
    """``Retry-After`` is honored only when it is a plain decimal number."""

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(b"\xb2", id="superscript-two-latin1"),
            pytest.param("\u00b2".encode(), id="superscript-two-utf8"),
            pytest.param("\u2460".encode(), id="circled-digit-one"),
            pytest.param(b"1.5", id="fraction"),
            pytest.param(b"-1", id="negative"),
            pytest.param(b"Wed, 21 Oct 2026 07:28:00 GMT", id="http-date"),
        ],
    )
    def test_falls_back_to_the_jittered_backoff(self, value):
        response = httpx.Response(429, headers={"Retry-After": value})
        with patch("licenseal.resolvers.http.random.uniform", return_value=0.1) as uniform:
            assert registry_http._retry_delay_seconds(response, 0.5) == 0.1  # noqa: SLF001
        uniform.assert_called_once_with(0.0, 0.5)

    def test_non_ascii_decimal_digits_are_a_number(self):
        response = httpx.Response(429, headers={"Retry-After": "\u0663".encode()})
        with patch("licenseal.resolvers.http.random.uniform", return_value=0.1):
            assert registry_http._retry_delay_seconds(response, 0.5) == 3.1  # noqa: SLF001

    @respx.mock
    def test_fetch_helpers_retry_instead_of_raising(self, fake_registry_clock):
        url = "https://example.com/data"
        answers = [
            httpx.Response(429, headers={"Retry-After": b"\xb2"}),
            httpx.Response(200, content=b'{"ok": true}'),
        ] * len(_FETCHERS)
        route = respx.route(url=url).mock(side_effect=answers)
        with (
            patch("licenseal.resolvers.http.random.uniform", return_value=0.1),
            httpx.Client() as client,
        ):
            for name, fetch in _FETCHERS.items():
                assert fetch(url, client) is not None, name
        assert route.call_count == 2 * len(_FETCHERS)
        assert fake_registry_clock.sleeps == [0.1] * len(_FETCHERS)


class TestTextBodyCharset:
    """The text fetchers decode with the charset the response declares. One
    that names a codec which can't decode text is a failed lookup.
    """

    _POM_URL = "https://repo.maven.apache.org/maven2/g/pkg-a/1.0.0/pkg-a-1.0.0.pom"

    @respx.mock
    @pytest.mark.parametrize(
        "charset", ["zlib", "hex", "rot13", "base64", "bz2", "quopri", "idna", "undefined"]
    )
    def test_charset_that_cannot_decode_text_is_a_failed_lookup(self, charset):
        headers = {"Content-Type": f"text/xml; charset={charset}"}
        respx.get(self._POM_URL).mock(
            return_value=httpx.Response(200, content=b"<project/>", headers=headers)
        )
        sidecar = "https://files.pythonhosted.org/packages/pkg_a-1.0.0-py3-none-any.whl.metadata"
        respx.get(sidecar).mock(
            return_value=httpx.Response(200, content=b"License-Expression: MIT\n", headers=headers)
        )
        cache = registry_http.RegistryCache()
        with httpx.Client() as client:
            assert cache.fetch_text(self._POM_URL, client) is None
            assert registry_http.fetch_pep658_metadata(sidecar, client) is None
        assert (cache.fetches_attempted, cache.fetches_succeeded) == (1, 0)

    @respx.mock
    def test_utf16_charset_on_a_body_without_a_bom_does_not_raise(self):
        respx.get(self._POM_URL).mock(
            return_value=httpx.Response(
                200,
                content="<project/>".encode("utf-16-le"),
                headers={"Content-Type": "text/xml; charset=utf-16"},
            )
        )
        with httpx.Client() as client:
            result = registry_http.fetch_registry_text(self._POM_URL, client)
        assert result is not None
        assert isinstance(result["text"], str)

    @respx.mock
    @pytest.mark.parametrize(
        ("content_type", "content", "text"),
        [
            pytest.param(
                "text/xml; charset=iso-8859-1",
                "<name>caf\u00e9</name>".encode("iso-8859-1"),
                "<name>caf\u00e9</name>",
                id="declared-charset",
            ),
            pytest.param(
                "text/xml",
                "<name>caf\u00e9</name>".encode(),
                "<name>caf\u00e9</name>",
                id="no-charset-is-utf8",
            ),
            pytest.param(
                "text/xml; charset=no-such-charset",
                "<name>caf\u00e9</name>".encode(),
                "<name>caf\u00e9</name>",
                id="unknown-charset-is-utf8",
            ),
            pytest.param(
                "text/xml", b"<name>caf\xe9</name>", "<name>caf\ufffd</name>", id="malformed-utf8"
            ),
        ],
    )
    def test_well_formed_bodies_decode_as_before(self, content_type, content, text):
        url = "https://example.com/data"
        respx.get(url).mock(
            return_value=httpx.Response(
                200, content=content, headers={"Content-Type": content_type}
            )
        )
        with httpx.Client() as client:
            assert registry_http.fetch_registry_text(url, client) == {"text": text}


class TestXmlTooDeepToSerialize:
    """The cache re-serializes a trimmed POM / nuspec. Serialization recurses
    once per element level; the parser does not. A document nested past the
    recursion limit inside a kept element is cached as an empty body.
    """

    @staticmethod
    def _nested(prefix: str, suffix: str) -> str:
        levels = sys.getrecursionlimit() + 100
        return prefix + "<a>" * levels + "</a>" * levels + suffix

    @respx.mock
    def test_pom(self):
        url = "https://repo.maven.apache.org/maven2/g/pkg-a/1.0.0/pkg-a-1.0.0.pom"
        body = self._nested("<project><properties>", "</properties></project>")
        respx.get(url).mock(return_value=httpx.Response(200, text=body))
        cache = registry_http.RegistryCache()
        with httpx.Client() as client:
            assert cache.fetch_text(url, client) == {"text": ""}

    @respx.mock
    def test_nuspec(self):
        url = "https://api.nuget.org/v3-flatcontainer/pkg-a/1.0.0/pkg-a.nuspec"
        body = self._nested(
            "<package><metadata><dependencies>", "</dependencies></metadata></package>"
        )
        respx.get(url).mock(return_value=httpx.Response(200, text=body))
        cache = registry_http.RegistryCache()
        with httpx.Client() as client:
            assert cache.fetch_text(url, client) == {"text": ""}

    @respx.mock
    def test_nesting_inside_a_dropped_element_is_trimmed_away(self):
        url = "https://repo.maven.apache.org/maven2/g/pkg-a/1.0.0/pkg-a-1.0.0.pom"
        body = self._nested(
            "<project><licenses><license><name>MIT</name></license></licenses><build>",
            "</build></project>",
        )
        respx.get(url).mock(return_value=httpx.Response(200, text=body))
        cache = registry_http.RegistryCache()
        with httpx.Client() as client:
            cached = cache.fetch_text(url, client)
        assert cached is not None
        assert "<name>MIT</name>" in cached["text"]
        assert "<build" not in cached["text"]
