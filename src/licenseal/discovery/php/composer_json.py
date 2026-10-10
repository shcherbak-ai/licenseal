"""Discover PHP dependencies from composer.json files.

composer.json carries production deps under ``require`` and development deps
under ``require-dev``. Both maps are ``{vendor/package: version-constraint}``.

Platform pseudo-packages (``php``, ``php-64bit``, ``ext-*``, ``lib-*``,
``hhvm``, ``composer-plugin-api``, …) are filtered out — they aren't published
artifacts on Packagist (any HTTP fetch would 404), they're the runtime / engine
the project requires. They are recognized by having no ``/``: an installable
package is always ``vendor/package``, so a vendor that merely starts with
``php-`` / ``ext-`` / ``lib-`` is a real package.

``replace`` and ``provides`` are out of scope for the initial PHP ecosystem
landing — a small fraction of real projects fulfill another package via
``replace`` (e.g. shim packages for deprecated names). The lockfile-first
resolver path masks the most common cases because composer.lock records the
real replacement; manifest-only mode may emit a phantom dep that resolves
UNKNOWN until the package is reviewed away.

Private Composer registries (``repositories: [{"type": "composer"}]``) and
custom VCS / path sources are also out of scope — those package names won't
resolve via Packagist, but we can't tell at manifest-parse time which named
deps come from those sources (Composer learns it at install). The 404 →
UNKNOWN path absorbs them; users can override via ``licenseal.review.toml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from licenseal.discovery._read import (
    load_json,
    record_unexpected_type,
    root_table,
    typed_field,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _license_field_to_raw(value: object) -> str:
    """Normalize composer's license field shape into a single raw string.

    composer schema accepts either a single string (``"MIT"``) or an array
    of strings (``["MIT", "Apache-2.0"]``). Per the Composer documentation
    the array form expresses *disjunctive* licensing — the consumer may
    choose either license — so we join with ``OR`` to preserve that intent
    when the value flows through :func:`analysis.spdx.normalize_license`.
    Empty / non-string entries are dropped; bare-string passes through.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        items: list[str] = [v.strip() for v in value if isinstance(v, str) and v.strip()]
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        return " OR ".join(items)
    return ""


def composer_map(path: Path, table: dict[str, Any], key: str, what: str = "") -> dict[str, Any]:
    """Return the ``key`` map of a Composer document, empty when absent.

    PHP serialises an empty map as an empty array, so ``[]`` is an empty map
    here. Any other value that is not an object is recorded as a gap named
    ``what`` (the quoted key when omitted).
    """
    if table.get(key) == []:
        return {}
    return typed_field(path, table, key, dict, what or f'"{key}"') or {}


def _parse_composer_json(filepath: Path, source: str) -> list[Dependency]:
    """Parse a single composer.json file into direct Dependencies.

    A section that is not a map, and a constraint that is not a string, are
    recorded as gaps and read as absent: the section declares nothing, the
    package is unconstrained. The other section is still read.
    """
    deps: list[Dependency] = []
    data = root_table(filepath, load_json(filepath))
    if data is None:
        return deps

    for field_name, group in (
        ("require", DependencyGroup.PROD),
        ("require-dev", DependencyGroup.DEV),
    ):
        for name, spec in composer_map(filepath, data, field_name).items():
            # No ``/`` means a platform pseudo-package (or a malformed name),
            # never an installable ``vendor/package``.
            if "/" not in name:
                continue
            if not isinstance(spec, str):
                record_unexpected_type(filepath, f'an entry of "{field_name}"')
                spec = ""
            deps.append(
                Dependency(
                    name=name,
                    version_constraint=spec,
                    ecosystem=Ecosystem.PHP,
                    group=group,
                    source=source,
                )
            )
    return deps


def discover_composer_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover all PHP dependencies from composer.json files in the tree.

    Returns ``(deps, filtered_count)``. The filter count is currently always
    zero — composer.json carries no analogue to npm's workspace-local refs
    that we can identify at manifest-parse time without additional install-
    side context. Kept in the return shape for parity with the other
    ecosystems' aggregator wiring.
    """
    composer_files = walk_project_files(project_path, "composer.json", exclude_paths=exclude_paths)
    deps: list[Dependency] = []
    for cj in composer_files:
        source = cj.relative_to(project_path).as_posix()
        deps.extend(_parse_composer_json(cj, source))
    return deps, 0


def detect_project_license_composer_json(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Detect the project's own license from composer.json files in the tree.

    Walks the tree so monorepo layouts without a root composer.json still
    surface a declared license. Returns the first non-empty ``license`` value
    in walk order. Array values are joined with ``OR`` per Composer's
    disjunctive-array convention; a downstream normalizer maps that through
    SPDX canonicalization.
    """
    for cj in walk_project_files(project_path, "composer.json", exclude_paths=exclude_paths):
        data = root_table(cj, load_json(cj))
        if data is None:
            continue
        raw = _license_field_to_raw(data.get("license", ""))
        if raw:
            return raw
    return ""
