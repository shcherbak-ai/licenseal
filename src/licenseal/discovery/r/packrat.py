"""``packrat/packrat.lock`` parser (the legacy R lockfile; DCF format).

A packrat.lock is DCF: a header record (``PackratFormat`` / ``RVersion`` /
``Repos`` …) followed by one record per package::

    Package: ggplot2
    Source: CRAN
    Version: 3.4.0
    Hash: ...
    Requires: digest, gtable, plyr, scales

``Requires`` is the dependency-edge list (names only) → reverse-BFS group
attribution. ``Source: CRAN`` is on-registry; ``github`` / ``bitbucket`` /
``Bioconductor`` / ``source`` (local) can't be resolved on CRAN and are marked
off-registry. The header record (no ``Package`` field) is skipped.
"""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.r._dcf import parse_dcf, parse_package_list
from licenseal.discovery.r._lock import SpecInfo, build_lock_dependencies
from licenseal.models import Dependency


def find_packrat_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``packrat.lock`` in the project tree (under ``packrat/``)."""
    return walk_project_files(project_path, "packrat.lock", exclude_paths=exclude_paths)


def parse_packrat_lock(
    path: Path,
    *,
    direct_names: set[str],
    dev_direct_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse ``packrat.lock`` into Dependencies with edge-aware group attribution."""
    text = decode_text(path)
    if text is None:
        return []

    spec_info: SpecInfo = {}
    edges: dict[str, set[str]] = {}
    for record in parse_dcf(text):
        name = record.get("Package", "").strip()
        if not name:
            # Header record (PackratFormat / RVersion / Repos) — no Package.
            continue
        normalized = name.lower()
        version = record.get("Version", "").strip()
        # packrat Source values: CRAN, github, bitbucket, Bioconductor, source.
        off_registry = record.get("Source", "").strip().lower() != "cran"
        child_names = [child for child, _c in parse_package_list(record.get("Requires", ""))]
        spec_info.setdefault(normalized, (name, version, off_registry))
        edges.setdefault(normalized, set()).update(c.lower() for c in child_names)

    return build_lock_dependencies(
        spec_info,
        edges,
        direct_names=direct_names,
        dev_direct_names=dev_direct_names,
        include_dev=include_dev,
    )
