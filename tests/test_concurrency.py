"""Egress-policy thread-propagation regression tests.

licenseal restricts network egress with ``tethered.scope()``, whose policy
lives in a ``contextvars.ContextVar``. ContextVars do NOT cross thread
boundaries (PEP 567), so a registry fetch issued from a bare
``ThreadPoolExecutor`` worker runs with an empty context and tethered's audit
hook silently allows it (fail-open). Every fetching pool must therefore
propagate the caller's context into its workers via
:func:`licenseal._concurrency.map_with_context`.

These tests prove enforcement actually reaches the worker threads. They use a
``socket.getaddrinfo`` probe rather than respx: respx mocks httpx's transport,
so no real socket is created and tethered's hook never fires — only a genuine
``getaddrinfo`` exercises the audit path. ``conftest`` installs a process-wide
``tethered.activate(allow=[])`` that would block on *every* thread regardless of
propagation (it is the global ``_config``, not a scope), so each test drops it
with ``tethered.deactivate()`` first; the autouse ``_restore_tethered_baseline``
fixture re-arms the baseline at teardown.
"""

from __future__ import annotations

import socket
import threading

import httpx
import tethered

from licenseal._concurrency import map_with_context
from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers import deps_dev
from licenseal.transitive import _fetch_go_edge_graph

_BLOCKED_HOST = "blocked.invalid"
_ALLOWED_RULE = "allowed.test:443"


def _egress_verdict() -> str:
    """Return "enforced" when an active tethered scope blocks egress here.

    Attempts a DNS lookup for a host that is *not* in the scope's allow list.
    With the scope active in this thread, tethered's audit hook raises
    ``EgressBlocked`` before any real resolution. Without it, the lookup runs
    for real and fails with ``OSError`` (``.invalid`` is a reserved NXDOMAIN
    TLD) — meaning the scope did not reach this thread.
    """
    try:
        socket.getaddrinfo(_BLOCKED_HOST, 443)
    except tethered.EgressBlocked:
        return "enforced"
    except OSError:
        return "not-enforced"
    return "not-enforced"


class TestMapWithContext:
    """Unit tests for the context-propagating pool helper."""

    def test_propagates_tethered_scope_into_workers(self):
        tethered.deactivate()  # standalone shape: scope() is the only policy
        with tethered.scope(allow=[_ALLOWED_RULE], label="probe"):
            verdicts = map_with_context(lambda _i: _egress_verdict(), [1, 2, 3, 4], max_workers=4)
        assert verdicts == ["enforced"] * 4

    def test_empty_items_returns_empty_without_starting_a_pool(self):
        assert map_with_context(lambda _i: _egress_verdict(), [], max_workers=4) == []

    def test_results_are_in_input_order(self):
        assert map_with_context(lambda x: x * 2, [1, 2, 3], max_workers=2) == [2, 4, 6]

    def test_more_items_than_workers_all_run(self):
        result = map_with_context(lambda x: x + 1, list(range(20)), max_workers=4)
        assert result == [x + 1 for x in range(20)]


class TestEgressScopeReachesFetchPools:
    """The real fetching pools must enforce the egress scope in their workers."""

    def test_deps_dev_batch_pool_propagates_scope(self, monkeypatch):
        """The deps.dev batch POST pool runs on the default ``check`` path."""
        observed: list[str] = []
        lock = threading.Lock()

        def probe_post(url, body, client):
            verdict = _egress_verdict()
            with lock:
                observed.append(verdict)
            return {"responses": []}

        monkeypatch.setattr(deps_dev, "fetch_registry_json_post", probe_post)
        # chunk_size=1 with 3 deps forces 3 chunks → the multi-chunk pool path.
        deps = [
            Dependency(name=f"mod{i}", version_constraint="v1.0.0", ecosystem=Ecosystem.GO)
            for i in range(3)
        ]
        tethered.deactivate()
        with httpx.Client() as client, tethered.scope(allow=[_ALLOWED_RULE], label="probe"):
            deps_dev.bulk_resolve_go_licenses(deps, client, chunk_size=1, max_workers=4)

        assert observed, "batch pool never invoked the (patched) fetcher"
        assert all(v == "enforced" for v in observed), observed

    def test_transitive_go_edge_pool_propagates_scope(self):
        """The Go transitive go.mod edge-fetch pool."""
        observed: list[str] = []
        lock = threading.Lock()

        def probe_fetcher(url, client):
            verdict = _egress_verdict()
            with lock:
                observed.append(verdict)
            return {"text": ""}

        entries = [("github.com/a/b", "v1.0.0"), ("github.com/c/d", "v2.0.0")]
        tethered.deactivate()
        with httpx.Client() as client, tethered.scope(allow=[_ALLOWED_RULE], label="probe"):
            _fetch_go_edge_graph(entries, client, max_workers=4, go_mod_fetcher=probe_fetcher)

        assert observed, "edge pool never invoked the (patched) fetcher"
        assert all(v == "enforced" for v in observed), observed
