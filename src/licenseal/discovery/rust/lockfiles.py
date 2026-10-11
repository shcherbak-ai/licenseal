"""Lockfile parser for Rust (Cargo.lock).

Cargo.lock encodes the actually-resolved graph as a flat list of `[[package]]`
blocks with `name`, `version`, optional `source`, and `dependencies = [...]`.
A registry-sourced crate has `source = "registry+https://github.com/rust-lang/crates.io-index"`
(or the `registry+` / `sparse+` URL of another registry, which is still a
registry row). A git dependency has `source = "git+<url>?<ref>#<commit>"`: it
is a row with the repository and the locked commit as its origin. A crate
built from a path has no `source` field at all, and neither have the crates
of the scanned workspace; the lockfile does not say which is which, so such a
crate is a row only when a Cargo.toml of the scan declares it from a path
outside the scanned directory. Every crate stays in the edge graph, row or
not, so the registry crates only it pulls in are attributed to it.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._origin import git_origin, url_origin
from licenseal.discovery._read import load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# A ``source`` that names a registry: crates.io, or another one. Either way
# the crate is looked up on crates.io by name.
_REGISTRY_PREFIXES = ("registry+", "sparse+")


def find_rust_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every Cargo.lock in the project tree.

    Polyglot setups commonly nest a Rust workspace (e.g. ``desktop/native/
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

    When no root is in the lockfile at all, reachability says nothing about
    it: every package is PROD with no ancestors.
    """
    if name_case.keys().isdisjoint(prod_root_names | dev_root_names):
        # None of the direct deps discovery found is in this lockfile: its
        # manifest is missing, or declares its dependencies in a form
        # discovery does not read. Dropping every package as an orphan would
        # report nothing, so keep them all, conservatively as PROD.
        return dict.fromkeys(name_case, DependencyGroup.PROD), {}
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
    origins: Mapping[str, str | None] | None = None,
) -> tuple[list[Dependency], set[str]]:
    """Parse a `Cargo.lock` into ``(deps_list, all_known_names)``.

    Reverse-BFS from prod and dev root sets attributes group + direct
    ancestors per crate. A crate no root reaches is dropped, unless the
    lockfile contains none of the roots at all: then every crate with a row
    is kept as PROD with no ancestors. A root need not have a row: a path
    dependency inside the scanned directory has none, and the registry
    crates it reaches name it in ``direct_ancestors``.

    ``origins`` maps a lowercased crate name to the origin a Cargo.toml of
    the scan declares for it (see ``cargo_sources``). It decides the crates
    the lockfile gives no ``source``: one it maps to a path is a row with
    that origin, and any other one (a crate of the scanned workspace, a path
    inside the scanned directory, a path dependency of a crate outside it)
    is no row.

    ``all_known_names`` is the lowercased names of every package in the
    lockfile, registry-sourced or not. Callers in ``transitive.py`` use
    this to decide which discovery-emitted direct deps need a
    registry-walk fallback: a dep that's in the lockfile under a git or
    path source (commonly via ``[patch.crates-io]``) appears in this set
    but not in ``deps_list``, and re-fetching it from crates.io would
    pull a different version than what's actually built. Without this
    set, ``_walk_uncovered`` would treat patched deps as uncovered and
    pull phantom transitives from the registry-latest version: chains
    of crates the patched build never compiles. Cargo workspaces that
    patch registry crates are where this shows up.

    A crate with no row is still tracked in the edge graph, so the BFS can
    traverse through it to its resolved children, and is included in
    ``all_known_names`` so the coverage check upstream is correct.
    """
    data = load_toml(path)
    if data is None:
        return [], set()

    packages = data.get("package", [])
    if not isinstance(packages, list):
        return [], set()

    raw_pkgs: list[tuple[str, str, str]] = []  # (name, version, origin)
    name_case: dict[str, str] = {}
    edges: dict[str, set[str]] = {}
    seen: set[tuple[str, str, str]] = set()
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

        # One version of a crate can be locked from two sources (the
        # registry release beside a git fork of it): each is an entry.
        source = pkg.get("source")
        source = source if isinstance(source, str) else ""
        if (normalized, version, source) in seen:
            continue
        seen.add((normalized, version, source))

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
        # path / local crates to their registry-sourced children.
        name_case[normalized] = name
        edges.setdefault(normalized, set()).update(children)

        origin: str | None
        if not source:
            # Built from a path: a row only when a manifest says the path is
            # outside the scanned directory.
            origin = (origins or {}).get(normalized)
        elif source.startswith(_REGISTRY_PREFIXES):
            origin = ""
        elif source.startswith("git+"):
            # ``git+<url>?<branch|tag|rev>=…#<commit>``
            location, _, commit = source.partition("#")
            origin = git_origin(location, commit)
        else:
            origin = url_origin(source)
        if origin is not None:
            raw_pkgs.append((name, version, origin))

    group_by_name, ancestors_by_name = _attribute(edges, name_case, prod_root_names, dev_root_names)

    out: list[Dependency] = []
    for name, version, origin in raw_pkgs:
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
                origin=origin,
            )
        )
    return out, all_known_names
