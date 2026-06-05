"""Shared edge-attribution helpers for R lockfiles (renv.lock, packrat.lock).

Both R lockfiles enumerate the pinned package set with per-package requirement
edges but carry no prod/dev marker — group attribution comes from the
``DESCRIPTION`` (``Imports``/``Depends``/``LinkingTo`` = prod roots,
``Suggests``/``Enhances`` = dev roots) via the same reverse-BFS the Hex /
Bundler paths use. Off-registry packages (GitHub / Bioconductor / Local) can't
be resolved on CRAN, so they carry the off-registry source marker the resolver
short-circuits on.
"""

from __future__ import annotations

from dataclasses import replace

from licenseal._graph import compute_direct_ancestors
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Source marker the resolver checks to short-circuit registry fetches on
# GitHub / Bioconductor / Local-sourced packages. The transitive walker
# overwrites ``source`` with the human-readable manifest path for registry-
# backed direct deps; the marker only survives on entries whose origin is
# not CRAN.
_OFF_REGISTRY_MARKER = "__off_registry__"

# name_lower -> (orig_name, version, off_registry)
SpecInfo = dict[str, "tuple[str, str, bool]"]


def is_off_registry_marker(source: str) -> bool:
    """True for the off-registry source marker emitted by the lock parsers."""
    return source == _OFF_REGISTRY_MARKER


def _reachable(edges: dict[str, set[str]], roots: set[str]) -> set[str]:
    """Return every node reachable from any node in ``roots`` (BFS)."""
    if not roots:
        return set()
    reachable: set[str] = set(roots)
    front: set[str] = set(roots)
    while front:
        new_front: set[str] = set()
        for node in front:
            for child in edges.get(node, ()):
                if child in reachable:
                    continue
                reachable.add(child)
                new_front.add(child)
        front = new_front
    return reachable


def build_lock_dependencies(
    spec_info: SpecInfo,
    edges: dict[str, set[str]],
    *,
    direct_names: set[str],
    dev_direct_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Turn parsed lock specs + edges into Dependencies with group attribution.

    ``direct_names`` is the lowercased set of dep names declared in any
    DESCRIPTION; ``dev_direct_names`` is the subset declared only in
    ``Suggests`` / ``Enhances``. A package reachable from any PROD root is
    PROD; otherwise from a DEV root is DEV; an orphan (no path from any root)
    is PROD by conservative default. With ``include_dev=False`` the
    DEV-attributed entries are filtered out.
    """
    if not spec_info:
        return []

    # renv.lock / packrat.lock carry no explicit "direct dependency" marker.
    # When the project also declares no direct deps (a lock-only layout with no
    # DESCRIPTION — common for analysis projects / Shiny apps), fall back to the
    # lockfile's own graph roots — packages not required by any other package in
    # the lock — as the direct set, so depth / group / ancestor attribution
    # stays meaningful instead of collapsing every package to an orphan.
    if not direct_names:
        required = {child for children in edges.values() for child in children}
        direct_names = {name for name in spec_info if name not in required}

    name_case = {lower: orig for lower, (orig, _ver, _off) in spec_info.items()}
    prod_root_names = direct_names - dev_direct_names
    dev_root_names = dev_direct_names & direct_names
    prod_reachable = _reachable(edges, prod_root_names)
    dev_reachable = _reachable(edges, dev_root_names) - prod_reachable

    roots_for_attribution = {n: name_case[n] for n in direct_names if n in name_case}
    ancestors = compute_direct_ancestors(edges, roots_for_attribution)

    out: list[Dependency] = []
    for normalized, (orig_name, version, off_registry) in spec_info.items():
        is_direct = normalized in direct_names
        if normalized in dev_reachable:
            group = DependencyGroup.DEV
        elif normalized in prod_reachable:
            group = DependencyGroup.PROD
        elif is_direct:  # pragma: no cover - direct deps are always reachable from their own root
            group = DependencyGroup.DEV if normalized in dev_root_names else DependencyGroup.PROD
        else:
            # Orphan transitive (no path from any root) — conservative PROD,
            # matching the Hex / Bundler / Go orphan posture.
            group = DependencyGroup.PROD

        if group == DependencyGroup.DEV and not include_dev:
            continue

        out.append(
            Dependency(
                name=orig_name,
                version_constraint=f"=={version}" if version else "",
                ecosystem=Ecosystem.R,
                group=group,
                depth=0 if is_direct else 1,
                direct_ancestors=() if is_direct else ancestors.get(normalized, ()),
                source="" if not off_registry else _OFF_REGISTRY_MARKER,
            )
        )
    return out


def attach_direct_sources(
    deps: list[Dependency],
    direct_source_by_name: dict[str, str],
) -> list[Dependency]:
    """Stamp the discovery source path onto depth-0 lock-derived deps.

    Mirrors the Hex / Bundler path: depth-0 entries get the matching
    ``DESCRIPTION`` source filename from discovery. Off-registry entries keep
    the off-registry marker.
    """
    out: list[Dependency] = []
    for dep in deps:
        if dep.depth != 0 or is_off_registry_marker(dep.source):
            out.append(dep)
            continue
        source = direct_source_by_name.get(dep.name.lower(), "")
        out.append(replace(dep, source=source) if source else dep)
    return out
