from __future__ import annotations

import httpx
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
