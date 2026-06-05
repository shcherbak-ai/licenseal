"""Discover npm dependencies from package.json files."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import load_json
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.npm_registry import _unpack_npm_alias  # noqa: PLC2701

# Specs that point at a workspace-local resource, not a published package:
# pnpm/yarn ``workspace:^1``, npm ``file:./path``, yarn berry ``link:./path``.
# There's no registry artifact to license-check, and the workspace's own code
# is what's being scanned anyway. Skipping them at discovery prevents a noisy
# UNKNOWN row per fixture/playground sub-package — the only way they show up
# is when the workspace-local package's own package.json lives under a
# fixtures/ or examples/ tree that BASE_SKIP_DIRS hides (so the local-name
# filter can't catch the dep by name match).
_WORKSPACE_LOCAL_PREFIXES = ("file:", "link:", "workspace:")


def _is_workspace_local_spec(spec: object) -> bool:
    return isinstance(spec, str) and spec.startswith(_WORKSPACE_LOCAL_PREFIXES)


def _emit_dep(
    name: str,
    spec: str,
    group: DependencyGroup,
    source: str,
    out: list[Dependency],
) -> None:
    """Emit a Dependency, unpacking ``npm:`` aliases to the canonical target.

    Mirrors the transitive walker's alias handling: ``"slash3": "npm:slash@^3"``
    is recorded as ``slash`` so the registry lookup hits the real package, not
    the consumer's local alias name (which 404s).
    """
    target_name, target_spec = _unpack_npm_alias(name, spec)
    out.append(
        Dependency(
            name=target_name,
            version_constraint=target_spec,
            ecosystem=Ecosystem.NPM,
            group=group,
            source=source,
        )
    )


def _parse_package_json(filepath: Path, source: str) -> tuple[list[Dependency], str]:
    """Parse a single package.json file for dependencies.

    Returns ``(deps, owner_name)`` — ``owner_name`` is the package's own
    ``name`` field (empty string if missing). Callers use it to skip
    self-referential workspace-local filtering: a package.json declaring its
    own name as a dep is the published-registry package, not a workspace ref.
    """
    deps: list[Dependency] = []

    data = load_json(filepath)
    if not isinstance(data, dict):
        return deps, ""

    owner_name = data.get("name") if isinstance(data.get("name"), str) else ""

    # Production dependencies
    for name, version in data.get("dependencies", {}).items():
        if _is_workspace_local_spec(version):
            continue
        _emit_dep(name, version, DependencyGroup.PROD, source, deps)

    # Dev dependencies
    for name, version in data.get("devDependencies", {}).items():
        if _is_workspace_local_spec(version):
            continue
        _emit_dep(name, version, DependencyGroup.DEV, source, deps)

    # Peer dependencies (treat as prod)
    for name, version in data.get("peerDependencies", {}).items():
        if _is_workspace_local_spec(version):
            continue
        _emit_dep(name, version, DependencyGroup.PROD, source, deps)

    # Optional dependencies. npm installs them by default; failure to install
    # is tolerated, but anything that lands in node_modules at runtime is in
    # use under its license. Group PROD: consumers running `npm install` with
    # no flags get them. Common case is platform-specific native bindings
    # (better-sqlite3, sharp, fsevents, esbuild's per-platform binaries).
    for name, version in data.get("optionalDependencies", {}).items():
        if _is_workspace_local_spec(version):
            continue
        _emit_dep(name, version, DependencyGroup.PROD, source, deps)

    return deps, owner_name


def discover_npm_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover all npm dependencies from package.json files in project.

    Filters out workspace-internal references: when a package.json in the
    project tree declares ``name``, that name is treated as a local package
    and any dep matching it is excluded from the result. Workspace packages
    aren't published to the npm registry, so attempting to resolve them
    produces noise (404 → UNKNOWN) without adding signal.

    Self-referential exception: a package.json that lists its own ``name`` as
    a dep is depending on the published-registry version of itself (commonly a
    standalone scratch project sharing a name with one of its dependencies),
    not a workspace alias — that dep is preserved.

    Returns ``(deps, filtered_count)`` where ``filtered_count`` is the number
    of deps removed because their name matched a workspace-local package.
    """
    package_jsons = walk_project_files(project_path, "package.json", exclude_paths=exclude_paths)
    local_names = _collect_local_names(package_jsons)

    deps: list[Dependency] = []
    owners: list[str] = []
    for pj in package_jsons:
        # All paths are under project_path by construction (os.walk root), so
        # relative_to is safe.
        source = pj.relative_to(project_path).as_posix()
        pj_deps, owner_name = _parse_package_json(pj, source)
        deps.extend(pj_deps)
        owners.extend([owner_name] * len(pj_deps))

    if not local_names:
        return deps, 0
    kept = [
        d
        for d, owner in zip(deps, owners, strict=True)
        if d.name not in local_names or d.name == owner
    ]
    return kept, len(deps) - len(kept)


def _collect_local_names(paths: list[Path]) -> set[str]:
    names: set[str] = set()
    for pj in paths:
        data = load_json(pj)
        if not isinstance(data, dict):
            continue
        name = data.get("name")
        if isinstance(name, str) and name:
            names.add(name)
    return names


def detect_project_license_package_json(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Detect the project's own license from package.json files in the tree.

    Walks the tree (mirroring pyproject and cargo discovery) so monorepo
    layouts without a root package.json still surface a declared license.
    Returns the first non-empty ``license`` field in walk order — root first
    when present, then nested packages depth-first.
    """
    for pj in walk_project_files(project_path, "package.json", exclude_paths=exclude_paths):
        data = load_json(pj)
        if not isinstance(data, dict):
            continue
        license_val = data.get("license", "")
        if isinstance(license_val, str) and license_val:
            return license_val
        if isinstance(license_val, dict):
            license_type = license_val.get("type", "")
            if isinstance(license_type, str) and license_type:
                return license_type
    return ""
