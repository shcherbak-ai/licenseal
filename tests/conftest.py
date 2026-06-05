"""Global test configuration — block all network egress and harden CliRunner."""

from __future__ import annotations

import click
import httpx
import pytest
import respx
import tethered
from click.testing import CliRunner

tethered.activate(allow=[])


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
    yield


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
