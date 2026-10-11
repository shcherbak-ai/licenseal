"""Lockfile parsers for npm (package-lock.json, yarn.lock, pnpm-lock.yaml).

Each parser returns a flat list of `Dependency` objects pinned to exact
versions. Group attribution is reachability-based: a transitive is `prod`
iff reachable from a `prod` direct dep through the lockfile's edge graph,
otherwise `dev` if reachable from a `dev` direct dep, otherwise dropped as
an orphan. The exception is a lockfile that contains none of the roots:
nothing in it can be attributed, so every package is kept as `prod` with no
ancestors.

`yarn.lock` v1 uses a custom format; v2 (Berry) uses YAML. Both are handled.
`pnpm-lock.yaml` is YAML with importer-scoped packages map.

A package a lockfile records as fetched from a git repository, a tarball URL
that is not a registry's, or a path that the scan does not read is not a
registry release. Its row carries an ``origin`` and is never looked up. A
package fetched from another registry is still a registry row. A workspace
member, and a path that the scan reads, is the project's own code:
it stays in the edge graph and gets no row.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

import yaml

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._origin import git_origin, path_origin, url_origin
from licenseal.discovery._read import (
    check_lockfile_version,
    decode_lockfile_text,
    decode_text,
    load_json,
    load_yaml,
    record_parse_failure,
    record_unexpected_type,
    record_unread_entries,
    root_table,
    typed_field,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.npm._specs import (
    git_spec_origin,
    npm_resolved_origin,
    npm_spec_origin,
    path_spec,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_NPM_LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")

# Key of a package name in the edge graphs and name sets below. npm names are
# compared as written: two that differ only in case are two packages.
_key = Ecosystem.NPM.identity


def find_npm_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every npm lockfile in the project tree, one per directory.

    Monorepos commonly ship multiple lockfiles — a root one plus per-app
    nested ones, or vendored subprojects (e.g. a desktop shell next to a web
    front-end). Each lockfile is the ground truth for its own subtree, so
    we must parse all of them rather than only the root. When a single
    directory contains more than one supported lockfile (project
    transitioning between package managers), the highest-priority wins for
    that directory: package-lock.json > pnpm-lock.yaml > yarn.lock.

    Skips lockfiles that live inside a ``test``/``tests`` directory: those
    are usually test-fixture sub-projects with their own pinned versions
    that differ from the real project's deps. Left in, their pins win the
    ``_drop_phantom_unresolved`` race against the root's unpinned spec and
    silently overwrite the root project's resolved versions with a stale
    fixture-only value. package.json/pyproject.toml/Cargo.toml discovery
    still reads test deps for license-checking; only the lockfile-derived
    version pins from test directories are filtered out.
    """
    chosen: dict[Path, Path] = {}
    for name in _NPM_LOCKFILES:
        for path in walk_project_files(project_path, name, exclude_paths=exclude_paths):
            if _is_in_test_dir(path, project_path):
                continue
            chosen.setdefault(path.parent, path)
    return list(chosen.values())


_TEST_DIR_NAMES: frozenset[str] = frozenset({"test", "tests"})


def _is_in_test_dir(lockfile_path: Path, project_path: Path) -> bool:
    """Return True if ``lockfile_path`` lives under a test/tests directory."""
    try:
        rel = lockfile_path.relative_to(project_path)
    except ValueError:
        return False
    return any(seg in _TEST_DIR_NAMES for seg in rel.parts[:-1])


def parse_npm_lockfile(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Dispatch to the appropriate parser based on filename.

    ``scan_root`` is the scanned directory, the lockfile's own directory when
    omitted. A package the lockfile takes from a path that the scan reads is
    the project's own code and gets no row.
    """
    scan_root = scan_root or path.parent
    if path.name == "package-lock.json":
        return parse_package_lock_json(
            path, prod_root_names, dev_root_names, include_dev, scan_root
        )
    if path.name == "pnpm-lock.yaml":
        return parse_pnpm_lock(path, prod_root_names, dev_root_names, include_dev, scan_root)
    if path.name == "yarn.lock":
        return parse_yarn_lock(path, prod_root_names, dev_root_names, include_dev, scan_root)
    if path.name == "bun.lock":
        return parse_bun_lock(path, prod_root_names, dev_root_names, include_dev, scan_root)
    raise ValueError(f"Unsupported npm lockfile: {path.name}")


def _attribute(
    edges: dict[str, set[str]],
    name_case: dict[str, str],
    prod_root_names: set[str],
    dev_root_names: set[str],
) -> tuple[
    dict[str, DependencyGroup],
    dict[str, tuple[str, ...]],
]:
    """Reachability-based group + direct_ancestors attribution.

    A package reachable from any prod root is PROD; otherwise if reachable
    from a dev root, DEV; otherwise absent (treated as orphan by callers).

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


def _finalize(
    deps: list[Dependency],
    edges: dict[str, set[str]],
    name_case: dict[str, str],
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Apply reachability-based group + ancestor stamping; drop orphans + dev (if not included)."""
    group_by_name, ancestors_by_name = _attribute(edges, name_case, prod_root_names, dev_root_names)
    out: list[Dependency] = []
    for dep in deps:
        normalized = _key(dep.name)
        group = group_by_name.get(normalized)
        if group is None:
            continue
        if group == DependencyGroup.DEV and not include_dev:
            continue
        is_root = normalized in prod_root_names or normalized in dev_root_names
        out.append(
            replace(
                dep,
                group=group,
                depth=0 if is_root else dep.depth or 1,
                direct_ancestors=() if is_root else ancestors_by_name.get(normalized, ()),
            )
        )
    return out


# What a gap names when an entry of a lockfile's package map, or a field inside
# one, is not the type the lockfile format defines.
_PACKAGES_ENTRY = 'an entry of "packages"'

# The major lockfile versions each parser was written for. A lockfile that
# declares another one is still read, with a diagnostic that is not a gap;
# only a version known to be laid out differently is skipped (see
# ``_PNPM_UNREADABLE_BELOW``).
_PACKAGE_LOCK_VERSIONS = frozenset({1, 2, 3})
_PNPM_LOCK_VERSIONS = frozenset({6, 9})
_YARN_CLASSIC_VERSIONS = frozenset({1})
_YARN_BERRY_VERSIONS = frozenset({4, 5, 6, 7, 8, 9, 10})
_BUN_LOCK_VERSIONS = frozenset({0, 1})

# pnpm lockfiles before version 6 key their packages as ``/name/version``,
# which matches none of the key forms the parser reads.
_PNPM_UNREADABLE_BELOW = 6


def _collect_npm_edge_children(
    path: Path, meta: dict[str, Any], what: str, *, pnpm_references: bool = False
) -> list[str]:
    """Union dependencies + peerDependencies + optionalDependencies (as graph keys).

    Also captures ``transitivePeerDependencies`` (pnpm-lock v9 ``snapshots:``
    convention — peers consumed deeper in the tree that propagate to the
    consumer's resolution closure). This field is shaped as a ``list[str]``
    rather than a name-keyed dict like the other three.

    ``pnpm_references`` is set for pnpm-lock maps, whose values can name the
    real package behind an alias key — see :func:`_pnpm_edge_target`.

    A field of another type holds edges that cannot be read: it is recorded
    as a gap on ``path``, named ``what``. So is a pnpm map value that is
    neither a string nor empty, since it cannot say which package it means;
    the edge then points at its key.
    """
    children: list[str] = []
    for field_name in ("dependencies", "peerDependencies", "optionalDependencies"):
        deps_dict = typed_field(path, meta, field_name, dict, what) or {}
        for child_name, value in deps_dict.items():
            if isinstance(child_name, str):
                if pnpm_references:
                    if value is not None and not isinstance(value, str):
                        record_unexpected_type(path, what)
                    child_name = _pnpm_edge_target(child_name, value)
                children.append(_key(child_name))
    for child_name in typed_field(path, meta, "transitivePeerDependencies", list, what) or []:
        if isinstance(child_name, str):
            children.append(_key(child_name))
    return children


# ---------------------------------------------------------------- package-lock


def parse_package_lock_json(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Parse a ``package-lock.json`` into a flat dep list.

    Handles both lockfile shapes:
    - **lockfileVersion >= 2**: flat ``packages`` map keyed by node_modules path.
    - **lockfileVersion 1**: nested ``dependencies`` tree where each entry can
      itself contain a nested ``dependencies`` map for sub-resolved versions.

    An entry whose ``resolved`` is a git URL, a tarball URL outside any
    registry, or a path outside ``scan_root`` is a row with an origin; so is
    a version 1 entry whose ``version`` is such a spec.
    """
    scan_root = scan_root or path.parent
    data = root_table(path, load_json(path))
    if data is None:
        return []
    check_lockfile_version(path, data.get("lockfileVersion"), _PACKAGE_LOCK_VERSIONS)

    if "packages" not in data:
        tree = typed_field(path, data, "dependencies", dict, '"dependencies"') or {}
        try:
            return _parse_package_lock_v1(
                path, tree, prod_root_names, dev_root_names, include_dev, scan_root
            )
        except RecursionError:
            # The tree walk recurses once per nesting level, so a tree the JSON
            # parser accepted can still be too deep to walk.
            record_parse_failure(path, "JSON")
            return []

    packages = typed_field(path, data, "packages", dict, '"packages"') or {}

    # First pass: build the alias→canonical map. npm uses an alias when a dep
    # is declared as ``"alias": "npm:target@spec"``; the entry's key path
    # carries the alias name (``node_modules/<alias>``) but the meta dict's
    # ``name`` field carries the canonical package. Without this map, child
    # references to the alias name (other packages' ``dependencies`` blocks)
    # point at a node that doesn't exist after we rename, breaking
    # reachability attribution.
    alias_to_canonical: dict[str, str] = {}
    for key, raw in packages.items():
        if key == "" or not isinstance(raw, dict):
            continue
        meta = cast("dict[str, Any]", raw)
        key_name = key.rsplit("node_modules/", 1)[-1]
        declared = meta.get("name")
        if isinstance(declared, str) and declared and _key(declared) != _key(key_name):
            alias_to_canonical[_key(key_name)] = declared

    def _resolve_alias(child: str) -> str:
        return _key(alias_to_canonical.get(_key(child), child))

    deps: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    read = 0
    for key, raw in packages.items():
        if key == "":
            # The empty-string key holds the project's own metadata; skip.
            continue
        if not isinstance(raw, dict):
            record_unexpected_type(path, _PACKAGES_ENTRY)
            continue
        meta = cast("dict[str, Any]", raw)
        resolved = typed_field(path, meta, "resolved", str, _PACKAGES_ENTRY) or ""
        origin: str | None
        if "link" in meta:
            # ``node_modules/<name>`` linked to a directory. One the scan
            # reads is a workspace member: read, and not a row. Any other is
            # a path dependency, at the version the directory's own entry
            # records.
            read += 1
            origin = path_origin(resolved, path.parent, scan_root) if resolved else None
            target = packages.get(resolved)
            linked_version = target.get("version") if isinstance(target, dict) else None
            version = linked_version if isinstance(linked_version, str) else ""
        else:
            entry_version = typed_field(path, meta, "version", str, _PACKAGES_ENTRY)
            if entry_version is None:
                # A workspace member can carry no version: that entry is
                # read, it is just not a row.
                read += "node_modules/" not in key
                continue
            read += 1
            version = entry_version
            integrity = typed_field(path, meta, "integrity", str, _PACKAGES_ENTRY) or ""
            origin = npm_resolved_origin(resolved, integrity, path.parent, scan_root)

        # Only `node_modules/<name>` keys are installed-from-registry. Other
        # shapes are workspace metadata:
        #   - `packages/foo`        — workspace member (npm/pnpm workspaces).
        #   - `../path/to/pkg`      — out-of-tree workspace ref or `file:` dep.
        #   - `apps/web` etc.       — any non-prefixed relative path.
        # Their declared `name` is the workspace's own name, NOT a registry
        # package; emitting them treats a local sibling as a published dep and
        # poisons resolution. Each workspace member also appears under its own
        # `node_modules/<name>` entry where applicable, so this filter drops
        # only the metadata duplicates, not the genuine installs.
        if "node_modules/" not in key:
            continue
        # Key is "node_modules/<name>" or nested "node_modules/<a>/node_modules/<b>".
        key_name = key.rsplit("node_modules/", 1)[-1]
        if not key_name:
            continue
        # Prefer the declared canonical name when present (npm aliases).
        name = typed_field(path, meta, "name", str, _PACKAGES_ENTRY) or key_name

        normalized = _key(name)
        edges.setdefault(normalized, set()).update(
            _resolve_alias(c) for c in _collect_npm_edge_children(path, meta, _PACKAGES_ENTRY)
        )
        name_case.setdefault(normalized, name)

        # The project's own code stays in the graph and is not a row.
        if origin is None or (normalized, version, origin) in seen:
            continue
        seen.add((normalized, version, origin))

        deps.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}" if version else "",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,  # overwritten by reachability in _finalize
                depth=_depth_from_key(key),
                origin=origin,
            )
        )
    record_unread_entries(path, len(packages) - ("" in packages), read)
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


def _depth_from_key(key: str) -> int:
    """Approximate depth by counting `node_modules/` segments after the first."""
    return max(1, key.count("node_modules/"))


def _parse_package_lock_v1(
    path: Path,
    deps_map: dict[str, Any],
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path,
) -> list[Dependency]:
    """Walk the legacy lockfileVersion=1 nested ``dependencies`` tree.

    Each entry exposes ``version`` (pinned), an optional ``requires`` map of
    edge children, and an optional nested ``dependencies`` map for
    deeper-installed copies (npm's old conflict resolution). Recurses
    depth-first; reachability attribution is delegated to ``_finalize``.

    For a package that is not a registry release, ``version`` holds the spec
    it was installed from (``git+ssh://…#<commit>``, ``github:user/repo#…``,
    a tarball URL, ``file:../dir``) instead of a version: that entry is a
    row with an origin and no version.
    """
    deps: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    entry_of = 'an entry of "dependencies"'
    read = 0

    def _walk(current: dict[str, Any], depth: int) -> None:
        nonlocal read
        for name, raw in current.items():
            if not isinstance(raw, dict):
                record_unexpected_type(path, entry_of)
                continue
            meta = cast("dict[str, Any]", raw)
            version = typed_field(path, meta, "version", str, entry_of)
            if version is None:
                continue
            read += 1

            normalized = _key(name)
            name_case.setdefault(normalized, name)

            requires = typed_field(path, meta, "requires", dict, entry_of) or {}
            edges.setdefault(normalized, set()).update(_key(n) for n in requires)

            origin: str | None
            spec_path = path_spec(version)
            if spec_path is not None:
                origin, version = path_origin(spec_path, path.parent, scan_root), ""
            elif npm_spec_origin(version):
                origin, version = npm_spec_origin(version), ""
            else:
                resolved = typed_field(path, meta, "resolved", str, entry_of) or ""
                integrity = typed_field(path, meta, "integrity", str, entry_of) or ""
                origin = npm_resolved_origin(resolved, integrity, path.parent, scan_root)

            # The project's own code stays in the graph and is not a row.
            if origin is not None and (normalized, version, origin) not in seen:
                seen.add((normalized, version, origin))
                deps.append(
                    Dependency(
                        name=name,
                        version_constraint=f"=={version}" if version else "",
                        ecosystem=Ecosystem.NPM,
                        group=DependencyGroup.PROD,  # overwritten by reachability
                        depth=depth,
                        origin=origin,
                    )
                )

            nested = typed_field(path, meta, "dependencies", dict, entry_of)
            if nested:
                _walk(nested, depth + 1)

    _walk(deps_map, 1)
    record_unread_entries(path, len(deps_map), read)
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


# ---------------------------------------------------------------- pnpm


def parse_pnpm_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Parse a `pnpm-lock.yaml` into a flat dep list.

    Written for ``lockfileVersion`` 6 (``/name@version`` keys) and 9
    (``name@version`` keys, edges in ``snapshots``). Version 5 keys its
    packages as ``/name/version``, which this parser does not read: such a
    lockfile is a gap, by its declared version or, failing that, because
    none of its keys can be read. Any other version is read as it stands.

    A package that does not come from the registry (a git repository, a
    tarball URL, a directory or archive outside ``scan_root``) is a row with
    an origin, read from its ``resolution``; it is never looked up. One
    that the scan reads, or linked from the workspace, is the project's own
    code and gets no row.
    """
    scan_root = scan_root or path.parent
    data = root_table(path, load_yaml(path))
    if data is None or not check_lockfile_version(
        path,
        data.get("lockfileVersion"),
        _PNPM_LOCK_VERSIONS,
        unreadable_below=_PNPM_UNREADABLE_BELOW,
    ):
        return []

    packages = typed_field(path, data, "packages", dict, '"packages"') or {}

    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    non_registry = 0
    seen_off_registry: set[tuple[str, str, str]] = set()
    for key, raw in packages.items():
        # A package key always holds an ``@``, so YAML never reads a real one
        # as anything but a string.
        if not isinstance(key, str) or not isinstance(raw, dict):
            record_unexpected_type(path, _PACKAGES_ENTRY)
            continue
        meta = cast("dict[str, Any]", raw)
        # pnpm-lock keys for non-registry deps embed the spec after the `@`:
        # ``'pkg@file:../tmp/pkg-0.0.0.tgz'``, ``'pkg@link:../sibling'``,
        # ``'pkg@workspace:^1'``, ``'pkg@git+ssh://...'``. These resolve to a
        # local tarball / sibling / workspace pkg / git repo, NOT a registry
        # version — there's no package on npmjs.org under that name+version.
        # Such a package is a row of its own, with an origin, or no row at
        # all when it is the project's own code.
        off_registry = _pnpm_off_registry_package(path, key, meta, scan_root)
        if off_registry is not None:
            non_registry += 1
            name, version, origin = off_registry
            # Its edges stay in the graph either way: the registry packages
            # it depends on are reached through it.
            edges.setdefault(_key(name), set()).update(
                _collect_npm_edge_children(path, meta, _PACKAGES_ENTRY, pnpm_references=True)
            )
            if origin is not None and (_key(name), version, origin) not in seen_off_registry:
                seen_off_registry.add((_key(name), version, origin))
                name_case.setdefault(_key(name), name)
                deps.append(
                    Dependency(
                        name=name,
                        version_constraint=f"=={version}" if version else "",
                        ecosystem=Ecosystem.NPM,
                        group=DependencyGroup.PROD,
                        depth=1,
                        origin=origin,
                    )
                )
            continue

        name, version = _parse_pnpm_package_key(key)
        if not name or not version:
            continue

        normalized = _key(name)
        edges.setdefault(normalized, set()).update(
            _collect_npm_edge_children(path, meta, _PACKAGES_ENTRY, pnpm_references=True)
        )
        name_case.setdefault(normalized, name)

        if (normalized, version) in seen:
            continue
        seen.add((normalized, version))

        deps.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,
                depth=1,
            )
        )
    record_unread_entries(path, len(packages), len(seen) + non_registry)

    # pnpm-lock v9 split dependency edges out of ``packages:`` into a separate
    # ``snapshots:`` block. v6/v8 lockfiles don't have this block, so this loop
    # is a no-op for them. Snapshot keys may carry a ``(peer@version)`` suffix
    # that ``_PNPM_KEY_RE`` already strips. Union edges across peer-resolved
    # variants of the same package: for license scanning we want every
    # transitive that any variant reached.
    snapshots_entry = 'an entry of "snapshots"'
    snapshots = typed_field(path, data, "snapshots", dict, '"snapshots"') or {}
    for snap_key, snap_raw in snapshots.items():
        if not isinstance(snap_key, str) or not isinstance(snap_raw, dict):
            record_unexpected_type(path, snapshots_entry)
            continue
        snap_name, _ = _parse_pnpm_package_key(snap_key)
        if not snap_name:
            continue
        edges.setdefault(_key(snap_name), set()).update(
            _collect_npm_edge_children(path, snap_raw, snapshots_entry, pnpm_references=True)
        )

    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


_PNPM_KEY_RE = re.compile(r"^/?(?P<name>(?:@[^/]+/)?[^/@]+)@(?P<version>[^()/]+)")

# Spec prefixes pnpm embeds after the `@` for non-registry sources. Entries
# matching these aren't fetchable from npmjs.org — the package is either a
# local tarball, workspace sibling, git repo, or HTTP URL. The version
# regex truncates these specs at the first ``/`` and emits a phantom-pinned
# Dependency that breaks downstream resolution.
_PNPM_NON_REGISTRY_PREFIXES = (
    "file:",
    "link:",
    "workspace:",
    "git+",
    "git:",
    "github:",
    "http:",
    "https:",
    "tarball:",
)


def _pnpm_key_spec(key: str) -> tuple[str, str]:
    """Split a pnpm packages-map key into ``(name, spec)``; empty when it has no ``@``."""
    # Strip leading slash (pnpm v6 prefix) and the name segment; what's left
    # after the rightmost `@` (before any peer-qualifier paren) is the spec.
    head = key[1:] if key.startswith("/") else key
    # Skip a leading scope (@scope/name) so the next `@` separates name@spec.
    scope_end = head.find("/") + 1 if head.startswith("@") else 0
    sep = head.find("@", scope_end)
    if sep < 0 or (head.startswith("@") and not scope_end):
        return "", ""
    spec = head[sep + 1 :]
    paren = spec.find("(")
    if paren >= 0:
        spec = spec[:paren]
    return head[:sep], spec


# Key specs that name the project's own code: a workspace member or a link.
_PNPM_OWN_PREFIXES = ("link:", "workspace:")


def _pnpm_off_registry_package(
    path: Path, key: str, meta: dict[str, Any], scan_root: Path
) -> tuple[str, str, str | None] | None:
    """Read a pnpm ``packages`` entry that does not come from the registry.

    Returns ``(name, version, origin)``, with a ``None`` origin for the
    project's own code, or ``None`` when the entry is a registry package.

    Such an entry is recognised by the spec its key embeds
    (``pkg@git+https://…``, ``pkg@https://…/pkg.tgz``, ``pkg@file:../pkg``),
    or, when the key holds no ``name@`` at all (``github.com/user/repo/<sha>``),
    by a ``name`` field beside a ``resolution`` that names a repository or a
    tarball. The origin comes from ``resolution`` (the repository and commit,
    the tarball URL and integrity, the directory) and from the key's spec
    when ``resolution`` holds none of those.
    """
    name, spec = _pnpm_key_spec(key)
    resolution = meta.get("resolution")
    resolution = cast("dict[str, Any]", resolution) if isinstance(resolution, dict) else {}
    repo, commit = resolution.get("repo"), resolution.get("commit")
    tarball, directory = resolution.get("tarball"), resolution.get("directory")
    if not spec.startswith(_PNPM_NON_REGISTRY_PREFIXES):
        declared = meta.get("name")
        located = isinstance(repo, str) or isinstance(tarball, str)
        if name or not (isinstance(declared, str) and declared and located):
            return None
        name = declared
    version = meta.get("version")
    version = version if isinstance(version, str) else ""
    if spec.startswith(_PNPM_OWN_PREFIXES):
        return name, version, None
    if isinstance(repo, str) and repo:
        return name, version, git_origin(repo, commit if isinstance(commit, str) else "")
    if isinstance(directory, str) and directory:
        return name, version, path_origin(directory, path.parent, scan_root)
    if isinstance(tarball, str) and tarball.startswith("file:"):
        return name, version, path_origin(tarball, path.parent, scan_root)
    if isinstance(tarball, str) and tarball:
        integrity = resolution.get("integrity")
        return name, version, url_origin(tarball, integrity if isinstance(integrity, str) else "")
    if spec.startswith("file:"):
        return name, version, path_origin(spec, path.parent, scan_root)
    return name, version, npm_spec_origin(spec) or url_origin(spec)


def _parse_pnpm_package_key(key: str) -> tuple[str, str]:
    """Parse a pnpm packages-map key into (name, version).

    Examples:
        /react@18.2.0 -> ("react", "18.2.0")
        /@types/node@20.10.0 -> ("@types/node", "20.10.0")
        /react@18.2.0(react-dom@18.2.0) -> ("react", "18.2.0")
    """
    m = _PNPM_KEY_RE.match(key)
    if not m:
        return "", ""
    return m.group("name"), m.group("version")


# A dependency-map value that is the resolved version itself, with or without
# a peer suffix.
_PNPM_PLAIN_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


def _pnpm_edge_target(child_name: str, value: object) -> str:
    """Return the package a pnpm dependency-map entry points at.

    The value is normally the resolved version (``1.0.0``, possibly with a
    ``(peer@version)`` suffix) and the entry points at its key. For an npm
    alias the key is the alias, which has no ``packages`` entry of its own,
    and the value references the real package: ``real@1.0.0`` (v9),
    ``/real@1.0.0`` (v6), ``@scope/real@2.0.0``, each optionally peer-suffixed.
    The edge must then point at the real package or it is dropped as an
    orphan.

    Anything that is not such a reference keeps pointing at the key: plain
    versions, ``link:`` / ``file:`` / ``workspace:`` specs, and URLs.
    """
    if (
        not isinstance(value, str)
        or value.startswith(_PNPM_NON_REGISTRY_PREFIXES)
        or _PNPM_PLAIN_VERSION_RE.match(value)
    ):
        return child_name
    name, version = _parse_pnpm_package_key(value.split("(", 1)[0])
    if name and version[:1].isdigit():
        return name
    return child_name


# ---------------------------------------------------------------- yarn


_YARN_VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"')
_YARN_RESOLVED_RE = re.compile(r'^  resolved\s+"?(?P<resolved>[^"\s]+)"?\s*$')
_YARN_INTEGRITY_RE = re.compile(r"^  integrity\s+(?P<integrity>\S+)\s*$")
# The commit a Berry resolution pins a repository to: ``…#commit=<sha>``.
_BERRY_COMMIT_RE = re.compile(r"(?:^|&)commit=(?P<commit>[^&]+)")
_YARN_DEP_RE = re.compile(r'^\s{4}"?([^"\s]+)"?\s+"[^"]*"\s*$')
# The comment a v1 lockfile opens with: ``# yarn lockfile v1``.
_YARN_CLASSIC_HEADER_RE = re.compile(r"^# yarn lockfile v(\S+)", re.MULTILINE)


def _yarn_descriptor_spec(descriptor: str) -> str:
    """The spec of a ``name@spec`` descriptor, ``@scope/name@spec`` included."""
    unscoped = descriptor[1:] if descriptor.startswith("@") else descriptor
    return unscoped.partition("@")[2]


def _yarn_spec_origin(spec: str, lock_dir: Path, scan_root: Path) -> str | None:
    """Origin the spec of a Yarn Classic descriptor declares.

    Empty for a registry spec (a range, a tag, an ``npm:`` alias); ``None``
    for a path that the scan reads.
    """
    spec_path = path_spec(spec)
    if spec_path is not None:
        return path_origin(spec_path, lock_dir, scan_root)
    return npm_spec_origin(spec)


def _berry_origin(spec: str, checksum: str, lock_dir: Path, scan_root: Path) -> str | None:
    """Origin of a Yarn Berry resolution, from the protocol after ``name@``.

    ``npm:``, and a spec with no protocol, is a registry release. ``patch:``
    is a locally patched package and resolves like the package it patches.
    ``file:`` / ``portal:`` / ``link:`` are a path, ``None`` when inside
    ``scan_root``. A resolution with a ``#commit=`` is a repository at that
    commit, and so is a git URL without one. Any other
    spec is a direct URL, with ``checksum`` as its hash, or a protocol this
    parser does not know; both are origins as written.
    """
    if spec.startswith("npm:") or not spec:
        return ""
    if spec.startswith("patch:"):
        patched = unquote(spec[len("patch:") :].partition("#")[0])
        return _berry_origin(_yarn_descriptor_spec(patched), checksum, lock_dir, scan_root)
    location, _, fragment = spec.partition("#")
    spec_path = path_spec(location.partition("::")[0])
    if spec_path is not None:
        return path_origin(spec_path, lock_dir, scan_root)
    if ":" not in location:
        # No protocol at all: a plain version or range.
        return ""
    commit = _BERRY_COMMIT_RE.search(fragment)
    if commit:
        return git_origin(location, commit.group("commit"))
    return git_spec_origin(location) or url_origin(location, checksum)


def parse_yarn_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Parse `yarn.lock` (v1 custom format or v2/Berry YAML) into a flat dep list.

    A lockfile with merge-conflict markers, and one whose entries cannot be
    read at all, are each recorded as a gap and yield nothing. One that
    declares a format version this parser was not written for is read all
    the same, and the unknown version is recorded without being a gap.

    An entry resolved from a git repository, a tarball URL outside any
    registry, or a path outside ``scan_root`` is a row with an origin.
    """
    scan_root = scan_root or path.parent
    text = decode_lockfile_text(path)
    if text is None:
        return []
    # Both v1 and Berry lockfiles open with a comment header; skip those
    # so the format check looks at the first real content line. Berry's
    # first non-comment line is always ``__metadata:`` — anything else
    # means v1 (where the first non-comment line is a dep descriptor like
    # ``"@types/node@^18.0.0":``).
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("__metadata"):
            return _parse_yarn_berry(
                text, path, prod_root_names, dev_root_names, include_dev, scan_root
            )
        break
    header = _YARN_CLASSIC_HEADER_RE.search(text)
    check_lockfile_version(path, header and header.group(1), _YARN_CLASSIC_VERSIONS)
    return _parse_yarn_v1(text, path, prod_root_names, dev_root_names, include_dev, scan_root)


def _parse_yarn_berry(
    text: str,
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path,
) -> list[Dependency]:
    try:
        data = root_table(path, yaml.safe_load(text))
    except (yaml.YAMLError, RecursionError):
        record_parse_failure(path, "YAML")
        return []
    if data is None:
        return []
    metadata = typed_field(path, data, "__metadata", dict, "__metadata") or {}
    check_lockfile_version(path, metadata.get("version"), _YARN_BERRY_VERSIONS)
    entry = "a package entry"

    # First pass: collect alias→canonical mappings from any aliased descriptor.
    alias_to_canonical: dict[str, str] = {}
    for key in data:
        if key == "__metadata" or not isinstance(key, str):
            continue
        for descriptor in key.split(","):
            descriptor = descriptor.strip()
            alias = _yarn_alias_descriptor_name(descriptor)
            target = _yarn_alias_target(descriptor)
            if alias and target:
                alias_to_canonical[_key(alias)] = target

    def _resolve_alias(child: str) -> str:
        return _key(alias_to_canonical.get(_key(child), child))

    deps: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    workspaces = 0
    for key, raw in data.items():
        if key == "__metadata":
            continue
        # A descriptor key always holds an ``@``, so YAML never reads a real
        # one as anything but a string.
        if not isinstance(key, str) or not isinstance(raw, dict):
            record_unexpected_type(path, entry)
            continue
        meta = cast("dict[str, Any]", raw)
        version = typed_field(path, meta, "version", str, entry)
        if version is None:
            continue
        # Berry keys: "react@npm:^18, react@npm:18.2.0"
        first = key.split(",")[0].strip()
        name = _yarn_name_from_descriptor(first)
        if not name:
            continue
        normalized = _key(name)

        deps_field = typed_field(path, meta, "dependencies", dict, entry) or {}
        children = [_resolve_alias(child) for child in deps_field if isinstance(child, str)]
        edges.setdefault(normalized, set()).update(children)
        name_case.setdefault(normalized, name)

        # ``name@workspace:path`` is one of the project's own packages, not a
        # registry package: its edges stay in the graph, but it is no row.
        # So is a package resolved from a path that the scan reads.
        resolution = typed_field(path, meta, "resolution", str, entry) or first
        checksum = typed_field(path, meta, "checksum", str, entry) or ""
        origin = (
            None
            if "@workspace:" in first
            else _berry_origin(_yarn_descriptor_spec(resolution), checksum, path.parent, scan_root)
        )
        if origin is None:
            workspaces += 1
            continue
        if (normalized, version, origin) in seen:
            continue
        seen.add((normalized, version, origin))
        deps.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,
                depth=1,
                origin=origin,
            )
        )
    record_unread_entries(path, len(data) - ("__metadata" in data), len(deps) + workspaces)
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


def _parse_yarn_v1(
    text: str,
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path,
) -> list[Dependency]:
    """Parse the legacy yarn v1 format (custom, not YAML).

    Where an entry comes from is read from its ``resolved`` line, and from
    the spec in its header (``name@github:user/repo``, ``name@file:../dir``)
    when ``resolved`` does not say.
    """
    # First pass: scan entry headers for alias→canonical mappings.
    alias_to_canonical: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith(" "):
            continue
        stripped = line.rstrip(":")
        for descriptor in stripped.split(","):
            descriptor = descriptor.strip().strip('"')
            alias = _yarn_alias_descriptor_name(descriptor)
            target = _yarn_alias_target(descriptor)
            if alias and target:
                alias_to_canonical[_key(alias)] = target

    def _resolve_alias(child: str) -> str:
        return _key(alias_to_canonical.get(_key(child), child))

    deps: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    current_name: str | None = None
    current_version: str | None = None
    current_spec = ""
    current_resolved = ""
    current_integrity = ""
    in_deps_block = False
    pending_deps: list[str] = []
    entries = 0
    read = 0

    def flush_entry() -> None:
        nonlocal read
        if current_name is None or current_version is None:
            return
        read += 1
        normalized = _key(current_name)
        edges.setdefault(normalized, set()).update(pending_deps)
        name_case.setdefault(normalized, current_name)
        origin = npm_resolved_origin(current_resolved, current_integrity, path.parent, scan_root)
        if origin == "":
            origin = _yarn_spec_origin(current_spec, path.parent, scan_root)
        # The project's own code stays in the graph and is not a row.
        if origin is None or (normalized, current_version, origin) in seen:
            return
        seen.add((normalized, current_version, origin))
        deps.append(
            Dependency(
                name=current_name,
                version_constraint=f"=={current_version}",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,
                depth=1,
                origin=origin,
            )
        )

    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            flush_entry()
            entries += 1
            stripped = line.rstrip(":")
            first = stripped.split(",")[0].strip().strip('"')
            current_name = _yarn_name_from_descriptor(first)
            current_spec = _yarn_descriptor_spec(first)
            current_version = None
            current_resolved = current_integrity = ""
            in_deps_block = False
            pending_deps = []
            continue
        if current_name is None:
            continue
        if line.startswith("  version"):
            m = _YARN_VERSION_RE.match(line)
            if m:
                current_version = m.group(1)
            in_deps_block = False
            continue
        located = _YARN_RESOLVED_RE.match(line) or _YARN_INTEGRITY_RE.match(line)
        if located:
            current_resolved = located.groupdict().get("resolved", current_resolved)
            current_integrity = located.groupdict().get("integrity", current_integrity)
            in_deps_block = False
            continue
        # Optional dependencies are installed too (platform-specific builds
        # are usually declared this way), so both blocks are edges.
        if line.startswith(("  dependencies:", "  optionalDependencies:")):
            in_deps_block = True
            continue
        if in_deps_block:
            m = _YARN_DEP_RE.match(line)
            if m:
                pending_deps.append(_resolve_alias(m.group(1)))
            else:
                in_deps_block = False
    flush_entry()
    # Every line that starts in the first column is an entry header; one
    # that is not followed by a version line was not read as a package.
    record_unread_entries(path, entries, read)
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


def _yarn_name_from_descriptor(descriptor: str) -> str:
    """Extract the package name from a Yarn descriptor.

    Handles `react@^18.0`, `@types/node@npm:18.0`, etc. For npm package
    aliases (`alias@npm:target@spec`), returns the canonical target name —
    the alias is the consumer's local naming choice and has no registry
    entry; the license belongs to the underlying package.
    """
    target = _yarn_alias_target(descriptor)
    if target is not None:
        return target
    if descriptor.startswith("@"):
        # Scoped: @scope/name@spec
        head, _, _ = descriptor[1:].partition("@")
        return "@" + head
    # Unscoped: name@spec
    return descriptor.split("@", 1)[0]


def _yarn_alias_descriptor_name(descriptor: str) -> str:
    """For alias descriptors (`alias@npm:target@spec`), return the alias name.

    Used to seed the alias→canonical map from a yarn lockfile so child
    references to the alias name elsewhere in the lockfile resolve to the
    canonical package node.
    """
    target = _yarn_alias_target(descriptor)
    if target is None:
        return ""
    if descriptor.startswith("@"):
        head, _, _ = descriptor[1:].partition("@")
        return "@" + head
    return descriptor.split("@", 1)[0]


def _yarn_alias_target(descriptor: str) -> str | None:
    """If ``descriptor`` is an npm alias form, return the target name; else None.

    Distinguishes the alias form (``alias@npm:target@spec``) from Berry's
    plain version-resolution form (``name@npm:^1.2.3``). The marker ``@npm:``
    appears in both — only the alias form has an additional ``@`` separating
    a target name from a version spec in the post-marker portion.
    """
    marker = "@npm:"
    idx = descriptor.find(marker, 1)  # start at 1 to skip leading "@" of scoped names
    if idx < 0:
        return None
    rest = descriptor[idx + len(marker) :]
    if rest.startswith("@"):
        # Scoped target: "@scope/name@spec". Must have an inner '@' after the
        # scope/name to qualify as alias (vs. e.g. bare "@scope/name").
        body = rest[1:]
        if "@" not in body:
            return None
        return "@" + body.split("@", 1)[0]
    # Unscoped target: "name@spec". Without an inner '@' the post-marker
    # portion is just a version spec (e.g. "18.2.0" or "^18 || ^17"),
    # which means this is plain Berry resolution, not an alias.
    if "@" not in rest:
        return None
    return rest.split("@", 1)[0]


# ---------------------------------------------------------------- bun


# Bun's text lockfile (replaced the binary ``bun.lockb`` in late 2024) is JSONC:
# JSON-with-trailing-commas. Python's stdlib ``json`` doesn't accept those, so
# strip them before parsing. The regex matches a ``,`` followed by whitespace
# and a closing ``}`` or ``]``. JSON strings don't legitimately contain that
# sequence (a comma inside a string is followed by more string content, not a
# closing bracket), so it's safe to apply globally.
_BUN_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def parse_bun_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Parse a ``bun.lock`` (JSONC) into a flat dep list.

    Bun's lockfile shape::

        {
          "lockfileVersion": 1,
          "workspaces": { "": { "name": "...", "dependencies": {...}, ... } },
          "packages": {
            "<name>": ["<name>@<version>", "", { "dependencies": {...} }, "sha512-..."],
            ...
          },
        }

    Each ``packages`` entry is a tuple where index 0 is the resolved
    ``name@version`` string and index 2 is a metadata dict carrying
    ``dependencies`` / ``peerDependencies`` / ``optionalDependencies``
    (whose values are version constraints). The dict at index 2 is what
    drives the edge graph for reachability attribution.

    For a package that is not a registry release, what follows ``name@`` is
    the spec it was installed from (``github:user/repo#<commit>``, a git or
    tarball URL, ``file:../dir``): that entry is a row with an origin and no
    version, or no row when the scan reads the path.
    """
    scan_root = scan_root or path.parent
    raw_text = decode_text(path)
    if raw_text is None:
        return []
    cleaned = _BUN_TRAILING_COMMA_RE.sub(r"\1", raw_text)
    try:
        data = root_table(path, json.loads(cleaned))
    except (json.JSONDecodeError, RecursionError):
        record_parse_failure(path, "JSON")
        return []
    if data is None:
        return []
    check_lockfile_version(path, data.get("lockfileVersion"), _BUN_LOCK_VERSIONS)

    packages = typed_field(path, data, "packages", dict, '"packages"') or {}

    deps: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    workspaces = 0
    for key, raw in packages.items():
        # First element is the resolved "name@version" id; second is URL or
        # empty; third is the meta dict; fourth is the integrity hash. An
        # entry that is not a registry release has no URL element, so its
        # meta dict comes second. Only the id must be a string; the meta
        # dict is read wherever it is.
        if not isinstance(raw, list) or not raw or not isinstance(raw[0], str):
            record_unexpected_type(path, _PACKAGES_ENTRY)
            continue
        meta = next((item for item in raw[1:] if isinstance(item, dict)), {})

        name, version = _parse_bun_resolved_id(raw[0], fallback_key=key)
        if not name or not version:
            continue

        normalized = _key(name)
        edges.setdefault(normalized, set()).update(
            _collect_npm_edge_children(path, meta, _PACKAGES_ENTRY)
        )
        name_case.setdefault(normalized, name)

        # ``name@workspace:path`` is one of the project's own packages, not a
        # registry package: its edges stay in the graph, but it is no row.
        # So is a package installed from a path that the scan reads.
        origin: str | None
        spec_path = path_spec(version)
        if version.startswith("workspace:"):
            origin = None
        elif spec_path is not None:
            origin, version = path_origin(spec_path, path.parent, scan_root), ""
        elif npm_spec_origin(version):
            origin, version = npm_spec_origin(version), ""
        else:
            origin = ""
        if origin is None:
            workspaces += 1
            continue
        if (normalized, version, origin) in seen:
            continue
        seen.add((normalized, version, origin))

        deps.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}" if version else "",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,  # overwritten by reachability in _finalize
                depth=1,
                origin=origin,
            )
        )

    record_unread_entries(path, len(packages), len(deps) + workspaces)
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


def _parse_bun_resolved_id(resolved_id: str, *, fallback_key: str) -> tuple[str, str]:
    """Parse Bun's ``"name@version"`` resolved id into (name, version).

    For scoped names (``@scope/name@1.2.3``) the split must occur at the
    second ``@``, not the first; an ``@`` further along belongs to what
    follows the name (``@scope/name@git+ssh://git@host/…``). Falls back to
    the packages-map key when the resolved id is empty or malformed.
    """
    text = resolved_id or fallback_key
    if not text:
        return "", ""
    # Scoped: @scope/name@version → split at the @ that follows the name.
    if text.startswith("@"):
        name_end = text.find("@", 1)
        if name_end < 0:
            return text, ""
        return text[:name_end], text[name_end + 1 :]
    # Unscoped: name@version → split at the only @.
    name, sep, version = text.partition("@")
    if not sep:
        return name, ""
    return name, version
