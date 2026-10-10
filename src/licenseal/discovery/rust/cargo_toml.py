"""Discover Rust dependencies from Cargo.toml files."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from licenseal.discovery._read import load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _is_off_registry(spec: Any) -> bool:
    """True for a dependency declared with ``path`` or ``git``.

    There is no crates.io release to look up for it, so it is not emitted as
    a dependency. With a Cargo.lock it is still a root of the locked graph:
    see :func:`cargo_off_registry_root_names`.
    """
    return isinstance(spec, dict) and ("path" in spec or "git" in spec)


def _spec_to_version(spec: Any) -> str | None:
    """Extract a version constraint from a cargo dep spec.

    Returns None for path/git deps (no registry license to look up; skip).
    A spec is either:
      - a bare string (the version)
      - a table with `version` (and possibly other fields)
      - a table without `version` (path/git/workspace) — skip
    """
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict) and not _is_off_registry(spec):
        version = cast("dict[str, Any]", spec).get("version")
        if isinstance(version, str):
            return version
    return None


def _canonical_crate_name(name: str, spec: Any) -> str:
    """Resolve Cargo's rename-package syntax to the published crate name.

    A dep can be declared under a local alias while the actual published
    crate name lives in the ``package`` key of the spec table: ``my_alias =
    { package = "real_crate", version = "0.4" }``. Cargo.lock records the
    canonical name, so the lockfile path is fine; in registry-walk-only
    paths (no Cargo.lock, or workspace member uncovered by the root
    lockfile) we must use the canonical name or every alias 404s on
    crates.io.
    """
    if isinstance(spec, dict):
        renamed = cast("dict[str, Any]", spec).get("package")
        if isinstance(renamed, str) and renamed:
            return renamed
    return name


def _emit_deps(
    section: Any,
    group: DependencyGroup,
    source: str,
    out: list[Dependency],
    ws_refs: list[tuple[str, DependencyGroup]],
    off_registry: list[tuple[str, DependencyGroup]],
) -> None:
    """Append Dependency objects from a `[dependencies]`-style table.

    ``dep = { workspace = true }`` entries are not dependencies by
    themselves — they opt in to the version declared in the enclosing
    workspace's ``[workspace.dependencies]`` catalog. They are recorded in
    ``ws_refs`` (alias name + table group) for the caller to stitch against
    the catalog.

    A path/git entry is not emitted; its crate name and the table's group
    are recorded in ``off_registry``.
    """
    if not isinstance(section, dict):
        return
    # tomllib guarantees string keys, so no per-key isinstance check.
    for name, spec in cast("dict[str, str | dict[str, Any]]", section).items():
        if isinstance(spec, dict) and spec.get("workspace") is True:
            ws_refs.append((name, group))
            continue
        version = _spec_to_version(spec)
        if version is None:
            if _is_off_registry(spec):
                off_registry.append((_canonical_crate_name(name, spec), group))
            continue
        out.append(
            Dependency(
                name=_canonical_crate_name(name, spec),
                version_constraint=version,
                ecosystem=Ecosystem.RUST,
                group=group,
                source=source,
            )
        )


def _parse_cargo_deps(
    data: dict[str, Any], source: str
) -> tuple[list[Dependency], list[tuple[str, DependencyGroup]], list[tuple[str, DependencyGroup]]]:
    """Extract dependencies and workspace-catalog references from one Cargo.toml.

    Returns ``(deps, ws_refs, off_registry)``: inline-version dependencies,
    the ``{ workspace = true }`` references this file makes into its
    workspace's ``[workspace.dependencies]`` catalog (stitched by the
    caller), and the crate name and group of each path/git dependency.
    """
    deps: list[Dependency] = []
    ws_refs: list[tuple[str, DependencyGroup]] = []
    off_registry: list[tuple[str, DependencyGroup]] = []

    # Top-level dependency tables, then the target-specific ones:
    # [target.<cfg>.dependencies] etc. Cfg gates platform/feature, not legal
    # obligations — flatten with the matching group, mirroring how PEP 508
    # markers are ignored elsewhere.
    tables: list[dict[str, Any]] = [data]
    target = data.get("target")
    if isinstance(target, dict):
        tables.extend(
            cast("dict[str, Any]", cfg_section)
            for cfg_section in cast("dict[str, Any]", target).values()
            if isinstance(cfg_section, dict)
        )
    for table in tables:
        for key, group in (
            ("dependencies", DependencyGroup.PROD),
            ("build-dependencies", DependencyGroup.PROD),
            ("dev-dependencies", DependencyGroup.DEV),
        ):
            _emit_deps(table.get(key), group, source, deps, ws_refs, off_registry)

    return deps, ws_refs, off_registry


def _workspace_catalog(data: dict[str, Any]) -> dict[str, Any] | None:
    """Return the ``[workspace.dependencies]`` table, if this file declares one."""
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        table = cast("dict[str, Any]", workspace).get("dependencies")
        if isinstance(table, dict):
            return cast("dict[str, Any]", table)
    return None


def _nearest_catalog_dir(start: Path, catalog_dirs: set[Path], project_path: Path) -> Path | None:
    """Closest ancestor directory (including ``start``) holding a catalog.

    Mirrors the closest-ancestor chain used for .NET Directory.Build.props:
    a member's ``workspace = true`` reference resolves against its own
    workspace root, not a sibling workspace elsewhere in the tree.
    """
    d = start
    while True:
        if d in catalog_dirs:
            return d
        if d == project_path or d.parent == d:
            return None
        d = d.parent


def _stitch_workspace_refs(
    refs: list[tuple[Path, str, DependencyGroup]],
    catalogs: dict[Path, tuple[str, dict[str, Any]]],
    project_path: Path,
    off_registry: list[tuple[str, DependencyGroup]],
) -> list[Dependency]:
    """Emit one Dependency per catalog entry that some member actually uses.

    ``[workspace.dependencies]`` is a version catalog, not a dependency
    list — the Cargo analogue of .NET's Central Package Management
    ``<PackageVersion>`` table. An entry becomes a dependency only when a
    workspace member opts in with ``dep = { workspace = true }``; an
    unreferenced entry is inert and must not be emitted (it is often absent
    from Cargo.lock entirely, and emitting it sends the transitive resolver
    on a registry walk of a dependency tree the project never builds).

    Group attribution comes from the referencing tables: referenced from any
    prod-side table → PROD, referenced only from dev-dependencies → DEV.

    A referenced path/git catalog entry is not emitted; its crate name and
    group are appended to ``off_registry``.
    """
    chosen: dict[tuple[Path, str], DependencyGroup] = {}
    catalog_dirs = set(catalogs)
    for file_dir, alias, group in refs:
        cat_dir = _nearest_catalog_dir(file_dir, catalog_dirs, project_path)
        if cat_dir is None or alias not in catalogs[cat_dir][1]:
            continue
        key = (cat_dir, alias)
        prev = chosen.get(key)
        if prev is None or prev == DependencyGroup.DEV:
            chosen[key] = group

    out: list[Dependency] = []
    for cat_dir, alias in sorted(chosen, key=lambda k: (str(k[0]), k[1])):
        source, table = catalogs[cat_dir]
        spec = table[alias]
        version = _spec_to_version(spec)
        if version is None:
            # path/git catalog entry — no registry lookup.
            if _is_off_registry(spec):
                off_registry.append((_canonical_crate_name(alias, spec), chosen[(cat_dir, alias)]))
            continue
        out.append(
            Dependency(
                name=_canonical_crate_name(alias, spec),
                version_constraint=version,
                ecosystem=Ecosystem.RUST,
                group=chosen[(cat_dir, alias)],
                source=source,
            )
        )
    return out


def discover_cargo_toml_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover Rust dependencies from every Cargo.toml in the project tree.

    Cargo workspaces declare `[workspace] members = [...]` at the root and
    per-crate deps in nested Cargo.toml files. Walk the tree, parse each,
    and filter workspace-internal references (path/git deps are already
    filtered by `_spec_to_version`; this catches version-bare crate-name
    refs that match a local crate `[package].name`).

    ``[workspace.dependencies]`` tables are treated as version catalogs:
    entries are emitted only when some workspace member references them via
    ``dep = { workspace = true }`` (see :func:`_stitch_workspace_refs`).

    Returns ``(deps, filtered_count)`` where ``filtered_count`` is the number
    of deps removed because their name matched a workspace-local crate.
    """
    deps, _off_registry, local_names = _scan_cargo_tomls(project_path, exclude_paths)
    kept = [d for d in deps if d.name not in local_names]
    return kept, len(deps) - len(kept)


def cargo_off_registry_root_names(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[set[str], set[str]]:
    """Lowercased names of the dependencies declared with ``git`` or ``path``.

    Returned as ``(prod, dev)``, by the table that declares them. Such a
    dependency is not emitted by :func:`discover_cargo_toml_dependencies`,
    but a Cargo.lock records the registry crates it pulls in. The lockfile
    pass takes these names as roots beside the discovered direct deps, so
    that closure is attributed instead of dropped as unreachable.

    A ``path`` dependency on a crate of this tree is left out. That crate's
    own Cargo.toml is scanned, so its dependencies are roots already, split
    into prod and dev. Cargo.lock lists a workspace member's
    dev-dependencies among its dependencies; walking the graph through the
    member would make every one of them a production dependency.
    """
    _deps, off_registry, local_names = _scan_cargo_tomls(project_path, exclude_paths)
    roots = [(name.lower(), group) for name, group in off_registry if name not in local_names]
    return (
        {name for name, group in roots if group == DependencyGroup.PROD},
        {name for name, group in roots if group == DependencyGroup.DEV},
    )


def _scan_cargo_tomls(
    project_path: Path, exclude_paths: frozenset[Path]
) -> tuple[list[Dependency], list[tuple[str, DependencyGroup]], set[str]]:
    """Parse every Cargo.toml in the tree.

    Returns ``(deps, off_registry, local_names)``: the registry dependencies
    (workspace-catalog references stitched, workspace-local names not yet
    filtered), the crate name and group of each path/git dependency, and
    the ``[package].name`` of every crate in the tree.
    """
    parsed: list[tuple[Path, dict[str, Any]]] = []
    for ct in walk_project_files(project_path, "Cargo.toml", exclude_paths=exclude_paths):
        data = load_toml(ct)
        if data is not None:
            parsed.append((ct, data))

    deps: list[Dependency] = []
    off_registry: list[tuple[str, DependencyGroup]] = []
    catalogs: dict[Path, tuple[str, dict[str, Any]]] = {}
    pending_refs: list[tuple[Path, str, DependencyGroup]] = []
    for ct, data in parsed:
        source = ct.relative_to(project_path).as_posix()
        file_deps, ws_refs, file_off_registry = _parse_cargo_deps(data, source)
        deps.extend(file_deps)
        off_registry.extend(file_off_registry)
        pending_refs.extend((ct.parent, alias, group) for alias, group in ws_refs)
        catalog = _workspace_catalog(data)
        if catalog is not None:
            catalogs[ct.parent] = (source, catalog)

    deps.extend(_stitch_workspace_refs(pending_refs, catalogs, project_path, off_registry))
    return deps, off_registry, _collect_local_rust_names(parsed)


def _collect_local_rust_names(parsed: list[tuple[Path, dict[str, Any]]]) -> set[str]:
    names: set[str] = set()
    for _ct, data in parsed:
        package = data.get("package")
        if isinstance(package, dict):
            name = cast("dict[str, Any]", package).get("name")
            if isinstance(name, str) and name:
                names.add(name)
    return names


def detect_project_license_cargo_toml(cargo_toml: Path) -> str:
    """Return the license one ``Cargo.toml`` declares, or ``""``.

    Reads ``[package].license`` (per-crate declaration) and falls back to
    ``[workspace.package].license`` (Cargo workspace inheritance — the
    workspace's ``Cargo.toml`` declares the canonical license and member
    crates set ``license.workspace = true`` to inherit).
    """
    data = load_toml(cargo_toml)
    if data is None:
        return ""
    package = data.get("package")
    if isinstance(package, dict):
        license_val = cast("dict[str, Any]", package).get("license")
        if isinstance(license_val, str) and license_val:
            return license_val
    # Cargo workspace inheritance: the root Cargo.toml of a workspace
    # may declare the license under [workspace.package] (no [package]
    # of its own), with member crates inheriting via license.workspace.
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        ws_package = cast("dict[str, Any]", workspace).get("package")
        if isinstance(ws_package, dict):
            ws_license = cast("dict[str, Any]", ws_package).get("license")
            if isinstance(ws_license, str):
                return ws_license
    return ""
