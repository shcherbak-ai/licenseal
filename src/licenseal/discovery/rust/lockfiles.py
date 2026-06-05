"""Lockfile parser for Rust (Cargo.lock).

Cargo.lock encodes the actually-resolved graph as a flat list of `[[package]]`
blocks with `name`, `version`, optional `source`, and `dependencies = [...]`.
A registry-sourced crate has `source = "registry+https://github.com/rust-lang/crates.io-index"`.
The local crate(s) being scanned have no `source` field; path/git deps have
non-registry source URIs. Both are skipped — there's no crates.io license to
resolve for them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_REGISTRY_PREFIX = "registry+https://github.com/rust-lang/crates.io-index"


def find_rust_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every Cargo.lock in the project tree.

    Polyglot setups commonly nest a Rust workspace (e.g. ``tauri/src-tauri/
    Cargo.lock``) next to JS / Python code that has its own ecosystem
    lockfiles. The nested Cargo.lock is the ground truth for that subtree
    and must be parsed alongside any root-level one.
    """
    return walk_project_files(project_path, "Cargo.lock", exclude_paths=exclude_paths)


def _attribute(
    edges: dict[str, set[str]],
    name_case: dict[str, str],
    prod_root_names: set[str],
    dev_root_names: set[str],
) -> tuple[
    dict[str, DependencyGroup],
    dict[str, tuple[str, ...]],
]:
    """Reachability-based group + ancestor attribution.

    PROD if reachable from any prod root, else DEV if reachable from a dev
    root, else absent (orphan, dropped by caller).
    """
    prod_roots = {n: name_case[n] for n in prod_root_names if n in name_case}
    dev_roots = {n: name_case[n] for n in dev_root_names if n in name_case}
    prod_anc = compute_direct_ancestors(edges, prod_roots)
    dev_anc = compute_direct_ancestors(edges, dev_roots)

    group_by_name: dict[str, DependencyGroup] = {}
    ancestors_by_name: dict[str, tuple[str, ...]] = {}
    for n in prod_root_names:
        if n in name_case:
            group_by_name[n] = DependencyGroup.PROD
            ancestors_by_name[n] = ()
    for n in dev_root_names:
        if n in name_case and n not in group_by_name:
            group_by_name[n] = DependencyGroup.DEV
            ancestors_by_name[n] = ()
    for n, ancestors in prod_anc.items():
        group_by_name[n] = DependencyGroup.PROD
        ancestors_by_name[n] = ancestors
    for n, ancestors in dev_anc.items():
        if n not in group_by_name:
            group_by_name[n] = DependencyGroup.DEV
            ancestors_by_name[n] = ancestors
    return group_by_name, ancestors_by_name


def parse_cargo_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> tuple[list[Dependency], set[str]]:
    """Parse a `Cargo.lock` into ``(deps_list, all_known_names)``.

    Reverse-BFS from prod and dev root sets attributes group + direct
    ancestors per crate.

    ``all_known_names`` is the lowercased names of every package in the
    lockfile, registry-sourced or not. Callers in ``transitive.py`` use
    this to decide which discovery-emitted direct deps need a
    registry-walk fallback: a dep that's in the lockfile under a git or
    path source (commonly via ``[patch.crates-io]``) appears in this set
    but not in ``deps_list``, and re-fetching it from crates.io would
    pull a different version than what's actually built. Without this
    set, ``_walk_uncovered`` would treat patched deps as uncovered and
    pull phantom transitives from the registry-latest version — bug
    seen on polars (3 patched deps -> phantom ``aws-lc-sys@0.41.0``
    chain), brush (``wgpu`` patch -> phantom ``av-scenechange@0.23.0``).

    Crates with no ``source`` field (the local workspace crate) and
    crates whose source isn't the crates.io registry index (path / git /
    [patch] deps) are excluded from the output list — there's no
    crates.io entry to license-resolve. BUT they're still tracked in the
    edge graph so the BFS can traverse through them to their resolved
    children, and they're included in ``all_known_names`` so the
    coverage check upstream is correct.
    """
    data = load_toml(path)
    if data is None:
        return [], set()

    packages = data.get("package", [])
    if not isinstance(packages, list):
        return [], set()

    raw_pkgs: list[tuple[str, str]] = []
    name_case: dict[str, str] = {}
    edges: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    all_known_names: set[str] = set()
    for raw in packages:
        if not isinstance(raw, dict):
            continue
        pkg = cast("dict[str, Any]", raw)
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue

        normalized = name.lower()
        all_known_names.add(normalized)

        if (normalized, version) in seen:
            continue
        seen.add((normalized, version))

        deps_field = pkg.get("dependencies", [])
        children: list[str] = []
        if isinstance(deps_field, list):
            for entry in deps_field:
                if not isinstance(entry, str):
                    continue
                # Entries are either "name", "name 1.2.3", or "name 1.2.3 (registry+...)"
                child_name = entry.split(" ", 1)[0]
                if child_name:
                    children.append(child_name.lower())

        # Always populate edges + name_case so BFS can traverse through git /
        # path / local crates to their registry-sourced children. Only
        # registry-sourced crates land in ``raw_pkgs`` (the output list) —
        # everything else has no crates.io license to resolve.
        name_case[normalized] = name
        edges.setdefault(normalized, set()).update(children)

        source = pkg.get("source")
        is_registry = isinstance(source, str) and source.startswith(_REGISTRY_PREFIX)
        if is_registry:
            raw_pkgs.append((name, version))

    group_by_name, ancestors_by_name = _attribute(edges, name_case, prod_root_names, dev_root_names)

    out: list[Dependency] = []
    for name, version in raw_pkgs:
        normalized = name.lower()
        group = group_by_name.get(normalized)
        if group is None:
            continue
        if group == DependencyGroup.DEV and not include_dev:
            continue
        is_root = normalized in prod_root_names or normalized in dev_root_names
        out.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}",
                ecosystem=Ecosystem.RUST,
                group=group,
                depth=0 if is_root else 1,
                direct_ancestors=() if is_root else ancestors_by_name.get(normalized, ()),
            )
        )
    return out, all_known_names
