"""R ``DESCRIPTION`` manifest parser.

A DESCRIPTION is a single DCF record. Direct dependencies live in five fields:
``Depends`` / ``Imports`` / ``LinkingTo`` (runtime / build → PROD) and
``Suggests`` / ``Enhances`` (optional / test / vignette → DEV). The project's
own license is the ``License:`` field; ``Package:`` names the package (used for
the multi-package workspace-internal filter).

Two R-specific filters apply: the ``R`` language pseudo-package
(``Depends: R (>= 4.1)``) and the base-priority packages bundled with R itself.
Neither is published to CRAN, so a registry lookup would 404. Recommended
packages (MASS, Matrix, lattice, …) *are* on CRAN and pass through.
"""

from __future__ import annotations

from pathlib import Path

from licenseal.analysis.spdx import normalize_r_license
from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.r._dcf import parse_dcf, parse_package_list
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_PROD_FIELDS = ("Depends", "Imports", "LinkingTo")
_DEV_FIELDS = ("Suggests", "Enhances")

# Fields whose presence marks a DCF record as an R DESCRIPTION (rather than an
# unrelated file that happens to be named DESCRIPTION). Guards both dependency
# discovery and project-license detection against stray files.
_R_DESCRIPTION_MARKERS = (
    "Package",
    "Type",
    "Depends",
    "Imports",
    "Suggests",
    "LinkingTo",
    "Enhances",
)

# Base-priority packages bundled with R (``installed.packages(priority="base")``)
# plus the ``R`` language pseudo-package. None are published to CRAN, so they're
# filtered before any CRAN lookup. Compared case-insensitively for safety
# (R package names are case-sensitive, but no CRAN package collides with a base
# name under case folding).
_R_BASE_PACKAGES = frozenset(
    name.lower()
    for name in (
        "R",
        "base",
        "compiler",
        "datasets",
        "grDevices",
        "graphics",
        "grid",
        "methods",
        "parallel",
        "splines",
        "stats",
        "stats4",
        "tcltk",
        "tools",
        "translations",
        "utils",
    )
)


def is_base_package(name: str) -> bool:
    """True for the R language pseudo-package and base-priority packages.

    These ship with R and aren't published to CRAN, so discovery and the
    registry walker must skip them (they aren't in the CRAN PACKAGES index).
    """
    return name.lower() in _R_BASE_PACKAGES


def _is_r_description(record: dict[str, str]) -> bool:
    return any(marker in record for marker in _R_DESCRIPTION_MARKERS)


def _parse_description_deps(record: dict[str, str], source: str) -> list[Dependency]:
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for fields, group in (
        (_PROD_FIELDS, DependencyGroup.PROD),
        (_DEV_FIELDS, DependencyGroup.DEV),
    ):
        for field in fields:
            value = record.get(field)
            if not value:
                continue
            for name, constraint in parse_package_list(value):
                if is_base_package(name):
                    continue
                key = (name.lower(), group.value)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Dependency(
                        name=name,
                        version_constraint=constraint,
                        ecosystem=Ecosystem.R,
                        group=group,
                        source=source,
                    )
                )
    return out


def discover_description_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    workspace_names: frozenset[str] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct deps from every ``DESCRIPTION`` in the tree.

    ``workspace_names`` is the lowercased set of in-tree package names; sibling
    references (multi-package R repos) are filtered before any registry lookup.
    The filter count is returned alongside.
    """
    out: list[Dependency] = []
    filtered = 0
    for desc in walk_project_files(project_path, "DESCRIPTION", exclude_paths=exclude_paths):
        text = decode_text(desc)
        if text is None:
            continue
        records = parse_dcf(text)
        if not records or not _is_r_description(records[0]):
            continue
        source = desc.relative_to(project_path).as_posix()
        for dep in _parse_description_deps(records[0], source):
            if dep.name.lower() in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered


def collect_dev_direct_names(deps: list[Dependency]) -> set[str]:
    """Return the lowercased R dep names whose only declaration is dev.

    A dep declared PROD anywhere (``Imports``/``Depends``/``LinkingTo``)
    outranks a DEV (``Suggests``/``Enhances``) declaration. Used as the DEV-root
    set for reverse-BFS group propagation through the lockfile.
    """
    prod_names: set[str] = set()
    dev_names: set[str] = set()
    for dep in deps:
        if dep.ecosystem != Ecosystem.R:
            continue
        if dep.group == DependencyGroup.DEV:
            dev_names.add(dep.name.lower())
        else:
            prod_names.add(dep.name.lower())
    return dev_names - prod_names


def detect_project_license_description(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Return the first DESCRIPTION's ``License:`` field, SPDX-normalized.

    The raw value uses R's license grammar (``GPL (>= 2)``, ``MIT + file
    LICENSE``), so it's translated here via :func:`normalize_r_license` — the
    downstream generic normalizer would mis-handle ``GPL-2``-style tokens.
    An undeterminable license (bare ``file LICENSE``, ``Unlimited``) returns
    ``""`` so the caller's "no license → Proprietary" default applies.
    """
    for desc in walk_project_files(project_path, "DESCRIPTION", exclude_paths=exclude_paths):
        text = decode_text(desc)
        if text is None:
            continue
        records = parse_dcf(text)
        if not records or not _is_r_description(records[0]):
            continue
        raw = records[0].get("License", "").strip()
        if not raw:
            continue
        normalized = normalize_r_license(raw)
        if normalized != "UNKNOWN":
            return normalized
    return ""


def workspace_r_names(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> frozenset[str]:
    """Return the lowercased set of in-tree DESCRIPTION ``Package:`` names.

    Used to filter sibling references in multi-package R repositories before
    any registry lookup.
    """
    names: set[str] = set()
    for desc in walk_project_files(project_path, "DESCRIPTION", exclude_paths=exclude_paths):
        text = decode_text(desc)
        if text is None:
            continue
        records = parse_dcf(text)
        if records and records[0].get("Package"):
            names.add(records[0]["Package"].strip().lower())
    return frozenset(names)
