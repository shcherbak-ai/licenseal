"""Global test configuration — block all network egress and harden CliRunner."""

from __future__ import annotations

import threading
import urllib.request

import click
import httpx
import pytest
import respx
import tethered
from click.testing import CliRunner

tethered.activate(allow=[])


@pytest.fixture(autouse=True)
def _pin_terminal_environment(monkeypatch):
    """Run every test as if the output were an 80-column pipe, whatever the host is.

    The CLI builds its consoles from the environment, so a host that sets
    ``FORCE_COLOR``, ``NO_COLOR``, ``TERM=dumb``, or a terminal size would
    otherwise change the output the tests capture. A test that needs a
    different terminal sets its own values on top of these.

    ``LINES`` is removed rather than set: with both dimensions fixed, Rich
    reports a legacy Windows console as one column narrower than the width it
    was given.
    """
    for name in ("TERM", "FORCE_COLOR", "NO_COLOR", "LINES", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "80")


@pytest.fixture(autouse=True)
def _pin_proxy_settings(monkeypatch):
    """Run every test as if no proxy were set, whatever the host is.

    The CLI takes its proxy from the environment and, on Windows and macOS, from
    the system's proxy settings; either would change the client and the allow
    list of every scan. A test that needs a proxy sets its own on top of this.
    """
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setattr(urllib.request, "getproxies", urllib.request.getproxies_environment)


@pytest.fixture(autouse=True)
def _default_deps_dev_batch_mock(request):
    """Pre-register an empty deps.dev batch response on the global respx router.

    The CLI's Mode-C resolution path issues a POST to
    ``api.deps.dev/v3alpha/versionbatch`` for every scan with Python /
    npm / Rust / Go / NuGet deps. Tests that exercise the CLI but only
    care about the per-package fallback path (the vast majority) don't
    want to mock that POST explicitly — they're testing PyPI / npm /
    crates.io behavior. Registering an empty batch response here makes
    those tests fall through to the per-package mocks they already have,
    unchanged.

    Tests that exercise the batch-hit path mark themselves with
    ``@pytest.mark.no_default_deps_dev_mock`` and register their own
    POST response. (Respx matches routes in registration order, so the
    conftest default would otherwise win and the test's batch response
    would never fire.)
    """
    if request.node.get_closest_marker("no_default_deps_dev_mock"):
        yield
        return
    respx.mock.post("https://api.deps.dev/v3alpha/versionbatch").mock(
        return_value=httpx.Response(200, json={"responses": []})
    )
    yield


@pytest.fixture(autouse=True)
def _disable_registry_host_rate_limits(monkeypatch):
    """Keep mocked registry tests fast; limiter behavior is tested directly."""
    from licenseal.resolvers import http as registry_http

    for limiter in registry_http._HOST_RATE_LIMITERS.values():  # noqa: SLF001
        monkeypatch.setattr(limiter, "_interval_seconds", 0.0)  # noqa: SLF001
        monkeypatch.setattr(limiter, "_next_allowed_at", 0.0)  # noqa: SLF001
    # Rate-limit windows are process-wide state. Pin each one's state for the
    # test so a pause or a spent budget left by one test is undone at teardown
    # instead of leaking into the next.
    for window in registry_http._HOST_RATE_LIMIT_WINDOWS.values():  # noqa: SLF001
        monkeypatch.setattr(window, "_resume_at", 0.0)  # noqa: SLF001
        monkeypatch.setattr(window, "_stalled_pauses", 0)  # noqa: SLF001
        monkeypatch.setattr(window, "_remaining_seconds", window._remaining_seconds)  # noqa: SLF001
    yield


class FakeRegistryClock:
    """Stand-in for the ``time`` module inside ``licenseal.resolvers.http``.

    ``sleep`` advances the clock instead of blocking, so rate-limit waits and
    retry backoffs cost no wall-clock time and every wait is recorded. The
    epoch and monotonic readings are far apart, so code that mixes the two
    clocks up computes a visibly wrong wait.
    """

    def __init__(self) -> None:
        self._elapsed = 0.0
        self._lock = threading.Lock()
        self.sleeps: list[float] = []

    def time(self) -> float:
        with self._lock:
            return 1_700_000_000.0 + self._elapsed

    def monotonic(self) -> float:
        with self._lock:
            return 500.0 + self._elapsed

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.sleeps.append(seconds)
            self._elapsed += seconds


@pytest.fixture
def fake_registry_clock(monkeypatch):
    """Replace the registry HTTP layer's clock and sleep with a fake."""
    from licenseal.resolvers import http as registry_http

    clock = FakeRegistryClock()
    monkeypatch.setattr(registry_http, "time", clock)
    return clock


@pytest.fixture(autouse=True)
def _restore_tethered_baseline():
    """Restore the conftest's empty-allow tethered baseline after every test.

    ``tethered.activate`` is process-global state with no built-in test
    isolation. A handful of tests intentionally mutate it (call activate
    with a different allowlist, or deactivate) to exercise the CLI's
    handling of various host policies. Without this fixture each such
    test would have to remember a ``try/finally`` that restores
    ``activate(allow=[])``; the previous bug where the finally called
    ``deactivate()`` (leaving the process unarmed) instead of
    ``activate(allow=[])`` is exactly the class of mistake this prevents
    structurally.
    """
    yield
    tethered.activate(allow=[])


# Click's CliRunner.invoke captures any exception raised by the command and
# stashes it on result.exception, then sets exit_code=1. Tests that only check
# `exit_code` cannot tell a legitimate non-zero exit (SystemExit/ClickException)
# from a CLI crash (RuntimeError, TypeError, etc.) — both produce exit_code=1.
# This monkey-patch makes any unhandled Python exception fail the test loudly.
_original_cli_invoke = CliRunner.invoke


def _strict_invoke(self, *args, **kwargs):
    result = _original_cli_invoke(self, *args, **kwargs)
    exc = result.exception
    if exc is not None and not isinstance(exc, (SystemExit, click.ClickException)):
        raise AssertionError(
            f"CLI crashed with unhandled {type(exc).__name__}: {exc}\n"
            f"--- captured output ---\n{result.output}"
        ) from exc
    return result


CliRunner.invoke = _strict_invoke  # type: ignore[method-assign]
