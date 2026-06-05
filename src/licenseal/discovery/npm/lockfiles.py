"""Lockfile parsers for npm (package-lock.json, yarn.lock, pnpm-lock.yaml).

Each parser returns a flat list of `Dependency` objects pinned to exact
versions. Group attribution is reachability-based: a transitive is `prod`
iff reachable from a `prod` direct dep through the lockfile's edge graph,
otherwise `dev` if reachable from a `dev` direct dep, otherwise dropped as
an orphan.

`yarn.lock` v1 uses a custom format; v2 (Berry) uses YAML. Both are handled.
`pnpm-lock.yaml` is YAML with importer-scoped packages map.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import yaml

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import (
    decode_text,
    load_json,
    load_yaml,
    record_parse_failure,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_NPM_LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")


def find_npm_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every npm lockfile in the project tree, one per directory.

    Monorepos commonly ship multiple lockfiles — a root one plus per-app
    nested ones, or vendored subprojects (e.g. ``tauri/`` next to a web
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
) -> list[Dependency]:
    """Dispatch to the appropriate parser based on filename."""
    if path.name == "package-lock.json":
        return parse_package_lock_json(path, prod_root_names, dev_root_names, include_dev)
    if path.name == "pnpm-lock.yaml":
        return parse_pnpm_lock(path, prod_root_names, dev_root_names, include_dev)
    if path.name == "yarn.lock":
        return parse_yarn_lock(path, prod_root_names, dev_root_names, include_dev)
    if path.name == "bun.lock":
        return parse_bun_lock(path, prod_root_names, dev_root_names, include_dev)
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
        normalized = dep.name.lower()
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


def _collect_npm_edge_children(meta: dict[str, Any]) -> list[str]:
    """Union dependencies + peerDependencies + optionalDependencies (lowercased names).

    Also captures ``transitivePeerDependencies`` (pnpm-lock v9 ``snapshots:``
    convention — peers consumed deeper in the tree that propagate to the
    consumer's resolution closure). This field is shaped as a ``list[str]``
    rather than a name-keyed dict like the other three.
    """
    children: list[str] = []
    for field_name in ("dependencies", "peerDependencies", "optionalDependencies"):
        deps_dict = meta.get(field_name)
        if isinstance(deps_dict, dict):
            for child_name in deps_dict:
                if isinstance(child_name, str):
                    children.append(child_name.lower())
    tpd = meta.get("transitivePeerDependencies")
    if isinstance(tpd, list):
        for child_name in tpd:
            if isinstance(child_name, str):
                children.append(child_name.lower())
    return children


# ---------------------------------------------------------------- package-lock


def parse_package_lock_json(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse a ``package-lock.json`` into a flat dep list.

    Handles both lockfile shapes:
    - **lockfileVersion >= 2**: flat ``packages`` map keyed by node_modules path.
    - **lockfileVersion 1**: nested ``dependencies`` tree where each entry can
      itself contain a nested ``dependencies`` map for sub-resolved versions.
    """
    data = load_json(path)
    if not isinstance(data, dict):
        return []

    if "packages" not in data and isinstance(data.get("dependencies"), dict):
        return _parse_package_lock_v1(
            data["dependencies"], prod_root_names, dev_root_names, include_dev
        )

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

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
        if isinstance(declared, str) and declared and declared.lower() != key_name.lower():
            alias_to_canonical[key_name.lower()] = declared

    def _resolve_alias(child: str) -> str:
        return alias_to_canonical.get(child.lower(), child).lower()

    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    for key, raw in packages.items():
        if key == "" or not isinstance(raw, dict):
            # The empty-string key holds the project's own metadata; skip.
            continue
        meta = cast("dict[str, Any]", raw)
        version = meta.get("version")
        if not isinstance(version, str):
            continue

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
        declared = meta.get("name")
        name = declared if isinstance(declared, str) and declared else key_name

        normalized = name.lower()
        edges.setdefault(normalized, set()).update(
            _resolve_alias(c) for c in _collect_npm_edge_children(meta)
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
                group=DependencyGroup.PROD,  # overwritten by reachability in _finalize
                depth=_depth_from_key(key),
            )
        )
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


def _depth_from_key(key: str) -> int:
    """Approximate depth by counting `node_modules/` segments after the first."""
    return max(1, key.count("node_modules/"))


def _parse_package_lock_v1(
    deps_map: dict[str, Any],
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Walk the legacy lockfileVersion=1 nested ``dependencies`` tree.

    Each entry exposes ``version`` (pinned), an optional ``requires`` map of
    edge children, and an optional nested ``dependencies`` map for
    deeper-installed copies (npm's old conflict resolution). Recurses
    depth-first; reachability attribution is delegated to ``_finalize``.
    """
    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}

    def _walk(current: dict[str, Any], depth: int) -> None:
        for name, raw in current.items():
            if not isinstance(name, str) or not isinstance(raw, dict):
                continue
            meta = cast("dict[str, Any]", raw)
            version = meta.get("version")
            if not isinstance(version, str):
                continue

            normalized = name.lower()
            name_case.setdefault(normalized, name)

            requires = meta.get("requires")
            if isinstance(requires, dict):
                edges.setdefault(normalized, set()).update(
                    n.lower() for n in requires if isinstance(n, str)
                )

            if (normalized, version) not in seen:
                seen.add((normalized, version))
                deps.append(
                    Dependency(
                        name=name,
                        version_constraint=f"=={version}",
                        ecosystem=Ecosystem.NPM,
                        group=DependencyGroup.PROD,  # overwritten by reachability
                        depth=depth,
                    )
                )

            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                _walk(nested, depth + 1)

    _walk(deps_map, 1)
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


# ---------------------------------------------------------------- pnpm


def parse_pnpm_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse a `pnpm-lock.yaml` into a flat dep list."""
    data = load_yaml(path)
    if not isinstance(data, dict):
        return []

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    for key, raw in packages.items():
        if not isinstance(key, str) or not isinstance(raw, dict):
            continue
        # pnpm-lock keys for non-registry deps embed the spec after the `@`:
        # ``'pkg@file:../tmp/pkg-0.0.0.tgz'``, ``'pkg@link:../sibling'``,
        # ``'pkg@workspace:^1'``, ``'pkg@git+ssh://...'``. These resolve to a
        # local tarball / sibling / workspace pkg / git repo, NOT a registry
        # version — there's no package on npmjs.org under that name+version.
        # Emitting them creates a phantom-pinned dep that the resolver 404s
        # on, and worse blocks ``_drop_phantom_unresolved`` from dropping the
        # genuine unresolved entry of the same name (which IS resolvable
        # from another path).
        if _is_non_registry_pnpm_key(key):
            continue

        name, version = _parse_pnpm_package_key(key)
        if not name or not version:
            continue

        meta = cast("dict[str, Any]", raw)
        normalized = name.lower()
        edges.setdefault(normalized, set()).update(_collect_npm_edge_children(meta))
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

    # pnpm-lock v9 split dependency edges out of ``packages:`` into a separate
    # ``snapshots:`` block. v6/v8 lockfiles don't have this block, so this loop
    # is a no-op for them. Snapshot keys may carry a ``(peer@version)`` suffix
    # that ``_PNPM_KEY_RE`` already strips. Union edges across peer-resolved
    # variants of the same package: for license scanning we want every
    # transitive that any variant reached.
    snapshots = data.get("snapshots")
    if isinstance(snapshots, dict):
        for snap_key, snap_raw in snapshots.items():
            if not isinstance(snap_key, str) or not isinstance(snap_raw, dict):
                continue
            snap_name, _ = _parse_pnpm_package_key(snap_key)
            if not snap_name:
                continue
            edges.setdefault(snap_name.lower(), set()).update(_collect_npm_edge_children(snap_raw))

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


def _is_non_registry_pnpm_key(key: str) -> bool:
    """Return True if ``key`` is a pnpm-lock entry for a non-registry source."""
    # Strip leading slash (pnpm v6 prefix) and the name segment; what's left
    # after the rightmost `@` (before any peer-qualifier paren) is the spec.
    head = key[1:] if key.startswith("/") else key
    # Strip a leading scope (@scope/name) so the next `@` separates name@spec.
    if head.startswith("@"):
        slash_at = head.find("/")
        if slash_at < 0:
            return False
        head = head[slash_at + 1 :]
    sep = head.find("@")
    if sep < 0:
        return False
    spec = head[sep + 1 :]
    paren = spec.find("(")
    if paren >= 0:
        spec = spec[:paren]
    return spec.startswith(_PNPM_NON_REGISTRY_PREFIXES)


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


# ---------------------------------------------------------------- yarn


# The trailing descriptors use ``[^",]*`` (not ``[^"]*``) so each repetition is
# anchored to exactly one comma-separated descriptor. ``[^"]*`` matches commas,
# which makes the boundary between repetitions ambiguous and the pattern
# catastrophically backtrack on a long un-terminated header line (ReDoS) — a
# malicious yarn.lock could otherwise hang the scan.
_YARN_HEADER_RE = re.compile(r'^"?([^"@]+(?:@[^"@]+)?)"?(?:,\s*"?[^",]*"?)*\s*:$')
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"')
_YARN_DEP_RE = re.compile(r'^\s{4}"?([^"\s]+)"?\s+"[^"]*"\s*$')


def parse_yarn_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse `yarn.lock` (v1 custom format or v2/Berry YAML) into a flat dep list."""
    text = decode_text(path)
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
            return _parse_yarn_berry(text, path, prod_root_names, dev_root_names, include_dev)
        break
    return _parse_yarn_v1(text, prod_root_names, dev_root_names, include_dev)


def _parse_yarn_berry(
    text: str,
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        record_parse_failure(path, "YAML")
        return []
    if not isinstance(data, dict):
        return []

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
                alias_to_canonical[alias.lower()] = target

    def _resolve_alias(child: str) -> str:
        return alias_to_canonical.get(child.lower(), child).lower()

    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    for key, raw in data.items():
        if key == "__metadata" or not isinstance(raw, dict):
            continue
        meta = cast("dict[str, Any]", raw)
        version = meta.get("version")
        if not isinstance(version, str):
            continue
        # Berry keys: "react@npm:^18, react@npm:18.2.0"
        first = key.split(",")[0].strip()
        name = _yarn_name_from_descriptor(first)
        if not name:
            continue
        normalized = name.lower()

        deps_field = meta.get("dependencies", {})
        children: list[str] = []
        if isinstance(deps_field, dict):
            for child_name in deps_field:
                if isinstance(child_name, str):
                    children.append(_resolve_alias(child_name))
        edges.setdefault(normalized, set()).update(children)
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
    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


def _parse_yarn_v1(
    text: str,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse the legacy yarn v1 format (custom, not YAML)."""
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
                alias_to_canonical[alias.lower()] = target

    def _resolve_alias(child: str) -> str:
        return alias_to_canonical.get(child.lower(), child).lower()

    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    current_name: str | None = None
    current_version: str | None = None
    in_deps_block = False
    pending_deps: list[str] = []

    def flush_entry() -> None:
        if current_name is None or current_version is None:
            return
        normalized = current_name.lower()
        edges.setdefault(normalized, set()).update(pending_deps)
        name_case.setdefault(normalized, current_name)
        if (normalized, current_version) in seen:
            return
        seen.add((normalized, current_version))
        deps.append(
            Dependency(
                name=current_name,
                version_constraint=f"=={current_version}",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,
                depth=1,
            )
        )

    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            flush_entry()
            stripped = line.rstrip(":")
            first = stripped.split(",")[0].strip().strip('"')
            current_name = _yarn_name_from_descriptor(first)
            current_version = None
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
        if line.startswith("  dependencies:"):
            in_deps_block = True
            continue
        if in_deps_block:
            m = _YARN_DEP_RE.match(line)
            if m:
                pending_deps.append(_resolve_alias(m.group(1)))
            else:
                in_deps_block = False
    flush_entry()
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
    """
    raw_text = decode_text(path)
    if raw_text is None:
        return []
    cleaned = _BUN_TRAILING_COMMA_RE.sub(r"\1", raw_text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        record_parse_failure(path, "JSON")
        return []
    if not isinstance(data, dict):
        return []

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    for key, raw in packages.items():
        if not isinstance(key, str) or not isinstance(raw, list) or not raw:
            continue
        # First element is the resolved "name@version" id; second is URL or
        # empty; third is the meta dict; fourth is the integrity hash.
        resolved_id = raw[0] if isinstance(raw[0], str) else ""
        meta = raw[2] if len(raw) > 2 and isinstance(raw[2], dict) else {}

        name, version = _parse_bun_resolved_id(resolved_id, fallback_key=key)
        if not name or not version:
            continue

        normalized = name.lower()
        edges.setdefault(normalized, set()).update(_collect_npm_edge_children(meta))
        name_case.setdefault(normalized, name)

        if (normalized, version) in seen:
            continue
        seen.add((normalized, version))

        deps.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,  # overwritten by reachability in _finalize
                depth=1,
            )
        )

    return _finalize(deps, edges, name_case, prod_root_names, dev_root_names, include_dev)


def _parse_bun_resolved_id(resolved_id: str, *, fallback_key: str) -> tuple[str, str]:
    """Parse Bun's ``"name@version"`` resolved id into (name, version).

    For scoped names (``@scope/name@1.2.3``) the split must occur at the
    LAST ``@``, not the first. Falls back to the packages-map key when the
    resolved id is empty or malformed.
    """
    text = resolved_id or fallback_key
    if not text:
        return "", ""
    # Scoped: @scope/name@version → split at the last @ (which separates the
    # version from the name).
    if text.startswith("@"):
        last_at = text.rfind("@")
        if last_at <= 0:
            return text, ""
        return text[:last_at], text[last_at + 1 :]
    # Unscoped: name@version → split at the only @.
    name, sep, version = text.partition("@")
    if not sep:
        return name, ""
    return name, version
