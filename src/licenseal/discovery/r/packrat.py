"""``packrat/packrat.lock`` parser (the legacy R lockfile; DCF format).

A packrat.lock is DCF: a header record (``PackratFormat`` / ``RVersion`` /
``Repos`` …) followed by one record per package::

    Package: ggplot2
    Source: CRAN
    Version: 3.4.0
    Hash: ...
    Requires: digest, gtable, plyr, scales

``Requires`` is the dependency-edge list (names only) → reverse-BFS group
attribution. ``Source: CRAN`` is on-registry. Every other source is not in the
CRAN index and gets an ``origin``: the repository and commit for ``github`` /
``gitlab`` / ``bitbucket``, the ``SourcePath`` for ``source`` (local), and the
source label alone (``Bioconductor``) when the record holds no locator. The
header record (no ``Package`` field) is skipped.
"""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._origin import path_origin
from licenseal.discovery._read import (
    check_lockfile_version,
    decode_lockfile_text,
    record_unread_entries,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.r._dcf import parse_dcf, parse_package_list
from licenseal.discovery.r._lock import (
    SpecInfo,
    build_lock_dependencies,
    hosted_origin,
    source_label_origin,
)
from licenseal.models import Dependency, Ecosystem

# Key of a package name in the name sets and graphs below (see
# ``Ecosystem.identity``).
_key = Ecosystem.R.identity

# The major ``PackratFormat`` versions this parser was written for. A lockfile
# that declares another one is still read, with a diagnostic that is not a gap.
_PACKRAT_FORMATS = frozenset({1})


def find_packrat_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``packrat.lock`` in the project tree (under ``packrat/``)."""
    return walk_project_files(project_path, "packrat.lock", exclude_paths=exclude_paths)


def _record_origin(record: dict[str, str], lock_dir: Path, scan_root: Path) -> str | None:
    """Origin of a package record; empty for ``Source: CRAN``.

    ``None`` is a ``Source: source`` package whose ``SourcePath`` is inside
    the scanned directory.
    """

    def field(*names: str) -> str:
        return next((record[name].strip() for name in names if record.get(name)), "")

    source = field("Source")
    if source.lower() == "cran":
        return ""
    hosted = hosted_origin(
        source,
        field("GithubUsername", "RemoteUsername"),
        field("GithubRepo", "RemoteRepo"),
        field("GithubSha1", "RemoteSha", "GithubRef", "RemoteRef"),
        field("RemoteHost"),
    )
    if hosted:
        return hosted
    source_path = field("SourcePath")
    if source_path and source.lower() == "source":
        return path_origin(source_path, lock_dir, scan_root)
    return source_label_origin(source)


def parse_packrat_lock(
    path: Path,
    *,
    direct_names: set[str],
    dev_direct_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Parse ``packrat.lock`` into Dependencies with edge-aware group attribution.

    ``scan_root`` is the scanned directory, the lockfile's own directory when
    omitted. A local package at a path that the scan reads gets no row.
    """
    text = decode_lockfile_text(path)
    if text is None:
        return []
    # The lockfile sits in the project's ``packrat/`` directory; a relative
    # ``SourcePath`` is relative to the project.
    project_dir = path.parent.parent if path.parent.name == "packrat" else path.parent
    scan_root = scan_root or project_dir
    records = parse_dcf(text)
    # The header record is the one that names the format; every other
    # record is where a package goes.
    headers = [record for record in records if "PackratFormat" in record]
    declared = headers[0]["PackratFormat"] if headers else None
    check_lockfile_version(path, declared, _PACKRAT_FORMATS)

    spec_info: SpecInfo = {}
    edges: dict[str, set[str]] = {}
    for record in records:
        name = record.get("Package", "").strip()
        if not name:
            # Header record (PackratFormat / RVersion / Repos) — no Package.
            continue
        normalized = _key(name)
        version = record.get("Version", "").strip()
        # packrat Source values: CRAN, github, bitbucket, Bioconductor, source.
        origin = _record_origin(record, project_dir, scan_root)
        child_names = [child for child, _c in parse_package_list(record.get("Requires", ""))]
        spec_info.setdefault(normalized, (name, version, origin))
        edges.setdefault(normalized, set()).update(_key(c) for c in child_names)
    record_unread_entries(path, len(records) - len(headers), len(spec_info))

    return build_lock_dependencies(
        spec_info,
        edges,
        direct_names=direct_names,
        dev_direct_names=dev_direct_names,
        include_dev=include_dev,
    )
