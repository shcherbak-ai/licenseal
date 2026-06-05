"""Thread-pool fan-out that carries the caller's context into every worker.

licenseal restricts outbound network egress with ``tethered.scope()``, whose
policy lives in a :class:`contextvars.ContextVar`. Per PEP 567 a freshly
spawned thread starts in an *empty* context — it does **not** inherit the
submitting thread's ContextVars — so a worker that issues a registry request
inside a bare ``ThreadPoolExecutor`` runs with no active scope, and tethered's
audit hook silently allows the call (fail-open). That would punch a hole in the
egress policy for every pool that fetches in parallel.

:func:`map_with_context` closes that hole: it snapshots the active context once
per item on the calling thread and runs each task inside its own snapshot, so
the full host-plus-licenseal scope stack is enforced in the worker. One
snapshot per item (rather than one shared snapshot) is required because a single
:class:`contextvars.Context` cannot be entered by more than one thread at a
time — ``Context.run`` raises "cannot enter context: is already entered" on the
second concurrent use.

This mirrors the inline snapshot pattern in :mod:`licenseal.cli` (the
license-resolution loop, which stays inline because it interleaves progress-bar
updates per result) and the transitive wave-walker. Any *new* fetching pool
should route through here so the propagation can't be forgotten.
"""

from __future__ import annotations

import contextvars
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

_T = TypeVar("_T")
_R = TypeVar("_R")

__all__ = ["map_with_context"]


def map_with_context(
    fn: Callable[[_T], _R],
    items: list[_T],
    max_workers: int,
) -> list[_R]:
    """Run ``fn`` over ``items`` concurrently, propagating the caller's context.

    Returns results in input order (like :meth:`ThreadPoolExecutor.map`). Each
    task executes inside an independent snapshot of the calling thread's context,
    so an active ``tethered.scope()`` (and any enclosing host policy) is enforced
    on the worker's network calls. ``max_workers`` is clamped to
    ``[1, len(items)]`` — an empty ``items`` returns ``[]`` without starting a
    pool.
    """
    if not items:
        return []
    worker_count = max(1, min(len(items), max_workers))
    snapshots = [contextvars.copy_context() for _ in items]
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        return list(pool.map(lambda ctx, item: ctx.run(fn, item), snapshots, items))
