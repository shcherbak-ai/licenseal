"""Enumerate ``go.sum`` entries (the cryptographic-hash lockfile).

``go.sum`` carries no per-package dependency edges — it's a flat list of
``<module> <version> h1:<hash>`` triples for supply-chain integrity. Each
module appears twice (once for the ``.zip`` archive, once for the
``/go.mod`` file); we dedupe to a single ``(module_path, version)`` entry
per package.

Edge data lives in each module's own ``go.mod``, hosted on the Go module
proxy (``proxy.golang.org/<module>/@v/<version>.mod``). The walker in
``transitive.py`` fetches those concurrently to build the edge graph for
``direct_ancestors`` attribution.
"""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files


def find_go_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``go.sum`` in the project tree."""
    return walk_project_files(project_path, "go.sum", exclude_paths=exclude_paths)


def parse_go_sum_entries(path: Path) -> list[tuple[str, str]]:
    """Parse a ``go.sum`` into a deduplicated list of ``(module_path, version)``.

    Drops the ``/go.mod``-suffixed rows (paired with each ``.zip`` row) and
    dedupes by ``(module, version)``. Returns the entries in the order they
    first appear in the file.
    """
    text = decode_text(path)
    if text is None:
        return []

    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        module_path, version = parts[0], parts[1]
        # ``<module> <version>/go.mod <h1:...>`` rows carry the suffix on the
        # version field. Skip — they pair with the ``.zip`` row above.
        if version.endswith("/go.mod"):
            continue
        key = (module_path, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out
