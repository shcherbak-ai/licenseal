"""Discover Rust dependencies from Cargo.toml files.

A dependency declared with ``git``, or with a ``path`` that the scan does not
read, is not a crates.io release: it is emitted with an origin and is
never looked up. So is a registry dependency that a ``[patch]`` or
``[replace]`` entry redirects to git or to such a path. A ``path`` the scan
reads (a directory of the scanned tree that the walk enters) is the project's
own code and is not a dependency. A ``registry = "…"`` key names another
registry: that dependency stays a registry one.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Any, NamedTuple, cast

from licenseal.discovery._origin import UNRECORDED, git_origin, path_origin
from licenseal.discovery._read import load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Key of a package name in the name sets and graphs below (see
# ``Ecosystem.identity``).
_key = Ecosystem.RUST.identity

# The keys that say which revision of a git dependency to take, most
# specific first.
_REVISION_KEYS = ("rev", "tag", "branch")
# What ends the crate name in a ``[replace]`` key (``name:1.0.0``, ``name@1.0.0``).
_PACKAGE_ID_VERSION_RE = re.compile(r"[:@]")


def _is_off_registry(spec: Any) -> bool:
    """True for a dependency declared with ``path`` or ``git``.

    There is no crates.io release to look up for it.
    """
    return isinstance(spec, dict) and ("path" in spec or "git" in spec)


def _spec_origin(spec: dict[str, Any], manifest_dir: Path, scan_root: Path) -> str | None:
    """Origin of a dependency spec that has ``git`` or ``path``.

    ``git`` is the repository plus ``rev``, ``tag``, or ``branch``. ``path``
    is relative to ``manifest_dir``; ``None`` when it is inside
    ``scan_root``. A value that is not a string leaves the source unrecorded.
    """
    if "git" in spec:
        git = spec["git"]
        if not isinstance(git, str) or not git:
            return UNRECORDED
        revision = next(
            (spec[k] for k in _REVISION_KEYS if isinstance(spec.get(k), str) and spec[k]), ""
        )
        return git_origin(git, revision)
    path = spec["path"]
    if not isinstance(path, str) or not path:
        return UNRECORDED
    return path_origin(path, manifest_dir, scan_root)


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


def _emit_off_registry(
    name: str,
    spec: dict[str, Any],
    group: DependencyGroup,
    source: str,
    manifest_dir: Path,
    scan_root: Path,
    out: list[Dependency],
    own: list[tuple[str, DependencyGroup]],
) -> None:
    """Emit a git / path dependency with its origin, or record it as own code.

    A path that the scan reads is a crate of the project: its name and
    group go to ``own`` and it is not a dependency.
    """
    crate = _canonical_crate_name(name, spec)
    origin = _spec_origin(spec, manifest_dir, scan_root)
    if origin is None:
        own.append((crate, group))
        return
    out.append(
        Dependency(
            name=crate,
            version_constraint="",
            ecosystem=Ecosystem.RUST,
            group=group,
            source=source,
            origin=origin,
        )
    )


def _emit_deps(
    section: Any,
    group: DependencyGroup,
    source: str,
    out: list[Dependency],
    ws_refs: list[tuple[str, DependencyGroup]],
    own: list[tuple[str, DependencyGroup]],
    manifest_dir: Path,
    scan_root: Path,
) -> None:
    """Append Dependency objects from a `[dependencies]`-style table.

    ``dep = { workspace = true }`` entries are not dependencies by
    themselves — they opt in to the version declared in the enclosing
    workspace's ``[workspace.dependencies]`` catalog. They are recorded in
    ``ws_refs`` (alias name + table group) for the caller to stitch against
    the catalog.

    A git entry, and a path entry that the scan does not read, is emitted
    with its origin. A path entry that it reads is recorded in ``own``.
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
            if isinstance(spec, dict) and _is_off_registry(spec):
                _emit_off_registry(name, spec, group, source, manifest_dir, scan_root, out, own)
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
    data: dict[str, Any], source: str, manifest_dir: Path, scan_root: Path
) -> tuple[list[Dependency], list[tuple[str, DependencyGroup]], list[tuple[str, DependencyGroup]]]:
    """Extract dependencies and workspace-catalog references from one Cargo.toml.

    Returns ``(deps, ws_refs, own)``: the dependencies (registry ones with
    their version, git ones and unread path ones with their origin), the
    ``{ workspace = true }`` references this file makes into its workspace's
    ``[workspace.dependencies]`` catalog (stitched by the caller), and the
    crate name and group of each path dependency that the scan
    reads.
    """
    deps: list[Dependency] = []
    ws_refs: list[tuple[str, DependencyGroup]] = []
    own: list[tuple[str, DependencyGroup]] = []

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
            _emit_deps(table.get(key), group, source, deps, ws_refs, own, manifest_dir, scan_root)

    return deps, ws_refs, own


def _patch_origins(
    data: dict[str, Any], manifest_dir: Path, scan_root: Path
) -> dict[str, str | None]:
    """Crates this manifest redirects to git or a path, with the origin of each.

    Reads ``[patch.<registry>]`` and ``[replace]``. The origin is ``None``
    for a path that the scan reads: that crate is the project's own code.
    An entry that only pins another registry version is not a redirect.
    """
    tables: list[dict[str, Any]] = []
    patch = data.get("patch")
    if isinstance(patch, dict):
        tables.extend(t for t in cast("dict[str, Any]", patch).values() if isinstance(t, dict))
    replaced = data.get("replace")
    if isinstance(replaced, dict):
        # A key is a package id (``name:1.0.0``, ``<registry>#name@1.0.0``).
        tables.append(
            {
                _PACKAGE_ID_VERSION_RE.split(key.rsplit("#", 1)[-1], maxsplit=1)[0]: spec
                for key, spec in cast("dict[str, Any]", replaced).items()
            }
        )
    origins: dict[str, str | None] = {}
    for table in tables:
        for name, spec in table.items():
            if isinstance(spec, dict) and _is_off_registry(spec):
                origins[_canonical_crate_name(name, spec)] = _spec_origin(
                    spec, manifest_dir, scan_root
                )
    return origins


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
    own: list[tuple[str, DependencyGroup]],
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

    A referenced git catalog entry, and a path one that the scan does not
    read, is emitted with its origin; a catalog path is relative to the
    catalog's own directory. A path entry that the scan reads is
    appended to ``own``.
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
            if isinstance(spec, dict) and _is_off_registry(spec):
                _emit_off_registry(
                    alias, spec, chosen[(cat_dir, alias)], source, cat_dir, project_path, out, own
                )
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
    and filter workspace-internal references (a path dep the scan reads is
    never emitted; this catches version-bare crate-name refs that match a
    local crate `[package].name`).

    A dependency declared with ``git``, or with a ``path`` outside the
    scanned directory, is returned with its origin and no version
    constraint, and so is a registry dependency that a ``[patch]`` or
    ``[replace]`` entry of any Cargo.toml in the tree redirects there.

    ``[workspace.dependencies]`` tables are treated as version catalogs:
    entries are emitted only when some workspace member references them via
    ``dep = { workspace = true }`` (see :func:`_stitch_workspace_refs`).

    Returns ``(deps, filtered_count)`` where ``filtered_count`` is the number
    of deps removed because their name matched a workspace-local crate.
    """
    deps, _own, _patches, local_names = _scan_cargo_tomls(project_path, exclude_paths)
    kept = [d for d in deps if d.name not in local_names]
    return kept, len(deps) - len(kept)


class CargoSources(NamedTuple):
    """What the Cargo.toml files say about crates that are not registry releases."""

    # Lowercased names of the path dependencies on a directory the scan
    # walks that holds no Cargo.toml of a crate of that name, by the table
    # that declares them. They have no row, and are roots of a Cargo.lock
    # graph.
    prod_roots: set[str]
    dev_roots: set[str]
    # Lowercased crate name → origin, for every crate declared from, or
    # redirected to, git or a path. ``None`` for a path that the scan reads.
    origins: dict[str, str | None]
    # The subset a ``[patch]`` or ``[replace]`` entry redirects: these apply
    # to a crate wherever it appears in the graph, not only where it is
    # declared.
    patches: dict[str, str | None]


def cargo_sources(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> CargoSources:
    """Collect the git / path sources the Cargo.toml files of the tree declare.

    A Cargo.lock records no location for a crate that is built from a path,
    and a registry walk knows nothing of a ``[patch]``; both read it here.

    ``prod_roots`` / ``dev_roots``: a path dependency that the scan
    reads is the project's own code and has no row, but the Cargo.lock
    records the registry crates it pulls in. The lockfile pass takes its
    name as a root beside the discovered direct deps, so that closure is
    attributed instead of dropped as unreachable. A path dependency on a
    crate whose Cargo.toml is scanned is left out: its dependencies are
    roots already, split into prod and dev. Cargo.lock lists a workspace
    member's dev-dependencies among its dependencies; walking the graph
    through the member would make every one of them a production
    dependency.
    """
    deps, own, patches, local_names = _scan_cargo_tomls(project_path, exclude_paths)
    roots = [(_key(name), group) for name, group in own if name not in local_names]
    redirected = {_key(name): origin for name, origin in patches.items()}
    origins: dict[str, str | None] = dict(redirected)
    origins.update((dep.identity, dep.origin) for dep in deps if dep.origin)
    return CargoSources(
        prod_roots={name for name, group in roots if group == DependencyGroup.PROD},
        dev_roots={name for name, group in roots if group == DependencyGroup.DEV},
        origins=origins,
        patches=redirected,
    )


def _scan_cargo_tomls(
    project_path: Path, exclude_paths: frozenset[Path]
) -> tuple[list[Dependency], list[tuple[str, DependencyGroup]], dict[str, str | None], set[str]]:
    """Parse every Cargo.toml in the tree.

    Returns ``(deps, own, patches, local_names)``: the dependencies
    (workspace-catalog references stitched, ``[patch]`` / ``[replace]``
    redirects applied, workspace-local names not yet filtered); the crate
    name and group of each dependency that is a path that the scan
    reads; the crates some manifest redirects to git or a path, with
    the origin of each; and the ``[package].name`` of every crate in the
    tree.
    """
    parsed: list[tuple[Path, dict[str, Any]]] = []
    for ct in walk_project_files(project_path, "Cargo.toml", exclude_paths=exclude_paths):
        data = load_toml(ct)
        if data is not None:
            parsed.append((ct, data))

    declared: list[Dependency] = []
    own: list[tuple[str, DependencyGroup]] = []
    patches: dict[str, str | None] = {}
    catalogs: dict[Path, tuple[str, dict[str, Any]]] = {}
    pending_refs: list[tuple[Path, str, DependencyGroup]] = []
    for ct, data in parsed:
        source = ct.relative_to(project_path).as_posix()
        file_deps, ws_refs, file_own = _parse_cargo_deps(data, source, ct.parent, project_path)
        declared.extend(file_deps)
        own.extend(file_own)
        patches.update(_patch_origins(data, ct.parent, project_path))
        pending_refs.extend((ct.parent, alias, group) for alias, group in ws_refs)
        catalog = _workspace_catalog(data)
        if catalog is not None:
            catalogs[ct.parent] = (source, catalog)

    declared.extend(_stitch_workspace_refs(pending_refs, catalogs, project_path, own))

    # A registry dependency that a [patch] or [replace] entry redirects is
    # built from that git repository or path, not from the registry.
    deps: list[Dependency] = []
    for dep in declared:
        if dep.origin or dep.name not in patches:
            deps.append(dep)
            continue
        origin = patches[dep.name]
        if origin is None:
            own.append((dep.name, dep.group))
        else:
            deps.append(replace(dep, origin=origin, version_constraint=""))
    return deps, own, patches, _collect_local_rust_names(parsed)


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
