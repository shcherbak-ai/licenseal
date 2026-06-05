"""PHP / Composer dependency discovery."""

from __future__ import annotations

from licenseal.discovery.php.composer_json import (
    detect_project_license_composer_json,
    discover_composer_dependencies,
)
from licenseal.discovery.php.lockfiles import (
    extract_composer_lock_licenses,
    find_composer_lockfiles,
    parse_composer_lockfile,
)

__all__ = [
    "detect_project_license_composer_json",
    "discover_composer_dependencies",
    "extract_composer_lock_licenses",
    "find_composer_lockfiles",
    "parse_composer_lockfile",
]
