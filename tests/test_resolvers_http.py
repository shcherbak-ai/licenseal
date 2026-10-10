from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx
import pytest
import respx

from licenseal.resolvers import http as registry_http


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
