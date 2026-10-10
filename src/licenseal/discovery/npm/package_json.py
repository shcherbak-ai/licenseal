"""Discover npm dependencies from package.json files."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import (
    load_json,
    record_unexpected_type,
    root_table,
    typed_field,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.npm._specs import npm_spec_origin
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

# The sections that declare dependencies, in the order they are read. Peer
# dependencies are treated as prod. So are optional dependencies: npm installs
# them by default and tolerates a failed install, but anything that lands in
# node_modules at runtime is in use under its license. The common case is a
# platform-specific native binding.
_DEPENDENCY_SECTIONS = (
    ("dependencies", DependencyGroup.PROD),
    ("devDependencies", DependencyGroup.DEV),
    ("peerDependencies", DependencyGroup.PROD),
    ("optionalDependencies", DependencyGroup.PROD),
)


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

    A spec that points at a git repository or a tarball URL is not a registry
    spec: the dependency carries its origin and no version constraint, and is
    never looked up.
    """
    target_name, target_spec = _unpack_npm_alias(name, spec)
    origin = npm_spec_origin(target_spec)
    out.append(
        Dependency(
            name=target_name,
            version_constraint="" if origin else target_spec,
            ecosystem=Ecosystem.NPM,
            group=group,
            source=source,
            origin=origin,
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

    data = root_table(filepath, load_json(filepath))
    if data is None:
        return deps, ""

    declared_name = data.get("name")
    owner_name = declared_name if isinstance(declared_name, str) else ""

    for section, group in _DEPENDENCY_SECTIONS:
        entries = typed_field(filepath, data, section, dict, f'"{section}"') or {}
        for name, spec in entries.items():
            if not isinstance(spec, str):
                # The name is still declared, so it stays in the scan with
                # no constraint rather than disappearing with its spec.
                record_unexpected_type(filepath, f'an entry of "{section}"')
                spec = ""
            if _is_workspace_local_spec(spec):
                continue
            _emit_dep(name, spec, group, source, deps)

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
        data = root_table(pj, load_json(pj))
        if data is None:
            continue
        name = data.get("name")
        if isinstance(name, str) and name:
            names.add(name)
    return names


def detect_project_license_package_json(package_json: Path) -> str:
    """Return the license one ``package.json`` declares for its package, or ``""``.

    Reads the ``license`` string, or the ``type`` of the legacy
    ``{"type": ..., "url": ...}`` object form.
    """
    data = root_table(package_json, load_json(package_json))
    if data is None:
        return ""
    license_val = data.get("license", "")
    if isinstance(license_val, dict):
        license_val = license_val.get("type", "")
    return license_val if isinstance(license_val, str) else ""
