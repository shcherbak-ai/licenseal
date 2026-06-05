"""R / CRAN dependency discovery (DESCRIPTION manifest + renv/packrat lockfiles)."""

from __future__ import annotations

from licenseal.discovery.r._lock import attach_direct_sources, is_off_registry_marker
from licenseal.discovery.r.description import (
    collect_dev_direct_names,
    detect_project_license_description,
    discover_description_dependencies,
    workspace_r_names,
)
from licenseal.discovery.r.packrat import find_packrat_lockfiles, parse_packrat_lock
from licenseal.discovery.r.renv_lock import find_renv_lockfiles, parse_renv_lock

__all__ = [
    "attach_direct_sources",
    "collect_dev_direct_names",
    "detect_project_license_description",
    "discover_description_dependencies",
    "find_packrat_lockfiles",
    "find_renv_lockfiles",
    "is_off_registry_marker",
    "parse_packrat_lock",
    "parse_renv_lock",
    "workspace_r_names",
]
