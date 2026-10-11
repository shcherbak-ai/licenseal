"""``renv.lock`` parser (the modern R lockfile).

``renv.lock`` is JSON::

    {
      "R": {"Version": "4.3.1", "Repositories": [...]},
      "Packages": {
        "ggplot2": {
          "Package": "ggplot2", "Version": "3.4.0",
          "Source": "Repository", "Repository": "CRAN",
          "Requirements": ["cli", "glue", "rlang", ...]
        },
        "myfork": {"Package": "myfork", "Source": "GitHub", ...}
      }
    }

``Requirements`` is the dependency-edge list (names only) → reverse-BFS group
attribution. ``Source: Repository`` on a CRAN mirror is on-registry. Every other
source is not in the CRAN index and gets an ``origin``: the repository and
``RemoteSha`` for ``GitHub`` / ``GitLab`` / ``Bitbucket`` / ``git``, the
``RemoteUrl`` for ``URL`` and ``Local``, and the source label alone
(``Bioconductor``, ``unknown``) when the entry records no locator.
"""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._origin import git_origin, path_origin, url_origin
from licenseal.discovery._read import (
    load_json,
    record_unexpected_type,
    record_unread_entries,
    root_table,
    typed_field,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.r._lock import (
    SpecInfo,
    build_lock_dependencies,
    hosted_origin,
    source_label_origin,
)
from licenseal.models import Dependency


def find_renv_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``renv.lock`` in the project tree."""
    return walk_project_files(project_path, "renv.lock", exclude_paths=exclude_paths)


# What a gap names when an entry of ``Packages``, or a field inside one, is
# not the type the lockfile format defines.
_PACKAGES_ENTRY = 'an entry of "Packages"'

# The fields of an entry that are read as strings.
_ENTRY_STRINGS = (
    "Package",
    "Version",
    "Source",
    "Repository",
    "RemoteHost",
    "RemoteUsername",
    "RemoteRepo",
    "RemoteSha",
    "RemoteRef",
    "RemoteUrl",
)


def _entry_origin(entry: dict[str, str], lock_dir: Path, scan_root: Path) -> str | None:
    """Origin of a renv ``Packages`` entry; empty when it resolves against the CRAN index.

    ``entry`` holds the entry's string fields, stripped. ``None`` is a
    ``Local`` package that the scan reads.
    """
    source = entry["Source"]
    repo = entry["Repository"]
    # Bioconductor lives in its own registry, not the CRAN PACKAGES index. CRAN,
    # RSPM, and other CRAN mirrors all list the same packages the index does.
    if repo == "Bioconductor" or repo.startswith("BioC") or source == "Bioconductor":
        return "Bioconductor"
    if source == "Repository":
        return ""
    revision = entry["RemoteSha"] or entry["RemoteRef"]
    hosted = hosted_origin(
        source, entry["RemoteUsername"], entry["RemoteRepo"], revision, entry["RemoteHost"]
    )
    if hosted:
        return hosted
    url = entry["RemoteUrl"]
    if url and source == "git":
        return git_origin(url, revision)
    if url and source == "URL":
        return url_origin(url)
    if url and source == "Local":
        return path_origin(url, lock_dir, scan_root)
    return source_label_origin(source)


def parse_renv_lock(
    path: Path,
    *,
    direct_names: set[str],
    dev_direct_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Parse ``renv.lock`` into Dependencies with edge-aware group attribution.

    A value of a type the format does not define is recorded as a gap and
    read as absent: a package without a usable ``Version`` is unpinned, one
    without a usable ``Source`` is not a CRAN package.

    ``scan_root`` is the scanned directory, the lockfile's own directory when
    omitted. A ``Local`` package at a path that the scan reads gets no row.
    """
    data = root_table(path, load_json(path))
    if data is None:
        return []
    scan_root = scan_root or path.parent
    packages = typed_field(path, data, "Packages", dict, '"Packages"') or {}

    spec_info: SpecInfo = {}
    edges: dict[str, set[str]] = {}
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            record_unexpected_type(path, _PACKAGES_ENTRY)
            continue
        strings = {
            field: (typed_field(path, entry, field, str, _PACKAGES_ENTRY) or "").strip()
            for field in _ENTRY_STRINGS
        }
        name = strings["Package"] or key.strip()
        if not name:
            continue
        normalized = name.lower()
        version = strings["Version"]
        origin = _entry_origin(strings, path.parent, scan_root)
        reqs = typed_field(path, entry, "Requirements", list, _PACKAGES_ENTRY) or []
        if not all(isinstance(r, str) for r in reqs):
            record_unexpected_type(path, _PACKAGES_ENTRY)
        child_names = [r.strip() for r in reqs if isinstance(r, str) and r.strip()]
        spec_info.setdefault(normalized, (name, version, origin))
        edges.setdefault(normalized, set()).update(c.lower() for c in child_names)
    record_unread_entries(path, len(packages), len(spec_info))

    return build_lock_dependencies(
        spec_info,
        edges,
        direct_names=direct_names,
        dev_direct_names=dev_direct_names,
        include_dev=include_dev,
    )
