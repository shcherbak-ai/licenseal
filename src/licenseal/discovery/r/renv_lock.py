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
attribution. ``Source: Repository`` on a CRAN mirror is on-registry; ``GitHub``
/ ``Bioconductor`` / ``Local`` / ``URL`` sources can't be resolved on CRAN and
are marked off-registry.
"""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import load_json
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.r._lock import SpecInfo, build_lock_dependencies
from licenseal.models import Dependency


def find_renv_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``renv.lock`` in the project tree."""
    return walk_project_files(project_path, "renv.lock", exclude_paths=exclude_paths)


def _is_on_cran(entry: dict) -> bool:
    """True when a renv ``Packages`` entry resolves against the CRAN index."""
    if str(entry.get("Source", "")).strip() != "Repository":
        # GitHub / GitLab / Bitbucket / Local / URL / git → off-registry.
        return False
    repo = str(entry.get("Repository", "")).strip()
    # Bioconductor lives in its own registry, not the CRAN PACKAGES index. CRAN,
    # RSPM, and other CRAN mirrors all list the same packages the index does.
    return repo != "Bioconductor" and not repo.startswith("BioC")


def parse_renv_lock(
    path: Path,
    *,
    direct_names: set[str],
    dev_direct_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse ``renv.lock`` into Dependencies with edge-aware group attribution."""
    data = load_json(path)
    if not isinstance(data, dict):
        return []
    packages = data.get("Packages")
    if not isinstance(packages, dict):
        return []

    spec_info: SpecInfo = {}
    edges: dict[str, set[str]] = {}
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("Package") or key).strip()
        if not name:
            continue
        normalized = name.lower()
        version = str(entry.get("Version", "")).strip()
        off_registry = not _is_on_cran(entry)
        reqs = entry.get("Requirements")
        child_names = (
            [r.strip() for r in reqs if isinstance(r, str) and r.strip()]
            if isinstance(reqs, list)
            else []
        )
        spec_info.setdefault(normalized, (name, version, off_registry))
        edges.setdefault(normalized, set()).update(c.lower() for c in child_names)

    return build_lock_dependencies(
        spec_info,
        edges,
        direct_names=direct_names,
        dev_direct_names=dev_direct_names,
        include_dev=include_dev,
    )
