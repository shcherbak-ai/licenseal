"""Discover Rust dependencies from Cargo.toml files."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from licenseal.discovery._read import load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem


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
    if isinstance(spec, dict):
        spec_dict = cast("dict[str, Any]", spec)
        if "path" in spec_dict or "git" in spec_dict:
            return None
        version = spec_dict.get("version")
        if isinstance(version, str):
            return version
    return None


def _emit_deps(section: Any, group: DependencyGroup, source: str, out: list[Dependency]) -> None:
    """Append Dependency objects from a `[dependencies]`-style table."""
    if not isinstance(section, dict):
        return
    # tomllib guarantees string keys, so no per-key isinstance check.
    for name, spec in cast("dict[str, str | dict[str, Any]]", section).items():
        version = _spec_to_version(spec)
        if version is None:
            continue
        # Cargo's rename-package syntax declares a dep under a local alias
        # while the actual published crate name lives in the ``package`` key
        # of the spec table: ``my_alias = { package = "real_crate", version
        # = "0.4" }``. Cargo.lock records the canonical name, so the
        # lockfile path is fine; in registry-walk-only paths (no Cargo.lock,
        # or workspace member uncovered by the root lockfile) we must use
        # the canonical name or every alias 404s on crates.io.
        canonical = name
        if isinstance(spec, dict):
            renamed = spec.get("package")
            if isinstance(renamed, str) and renamed:
                canonical = renamed
        out.append(
            Dependency(
                name=canonical,
                version_constraint=version,
                ecosystem=Ecosystem.RUST,
                group=group,
                source=source,
            )
        )


def _parse_cargo_deps(data: dict[str, Any], source: str) -> list[Dependency]:
    """Extract dependencies from a single parsed Cargo.toml data dict."""
    deps: list[Dependency] = []

    # Top-level dependency tables.
    _emit_deps(data.get("dependencies"), DependencyGroup.PROD, source, deps)
    _emit_deps(data.get("build-dependencies"), DependencyGroup.PROD, source, deps)
    _emit_deps(data.get("dev-dependencies"), DependencyGroup.DEV, source, deps)

    # Target-specific tables: [target.<cfg>.dependencies] etc.
    # Cfg gates platform/feature, not legal obligations — flatten with the
    # matching group, mirroring how PEP 508 markers are ignored elsewhere.
    target = data.get("target")
    if isinstance(target, dict):
        for cfg_section in cast("dict[str, Any]", target).values():
            if not isinstance(cfg_section, dict):
                continue
            cfg = cast("dict[str, Any]", cfg_section)
            _emit_deps(cfg.get("dependencies"), DependencyGroup.PROD, source, deps)
            _emit_deps(cfg.get("build-dependencies"), DependencyGroup.PROD, source, deps)
            _emit_deps(cfg.get("dev-dependencies"), DependencyGroup.DEV, source, deps)

    # Workspace-shared deps: [workspace.dependencies]. Treat as PROD.
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        ws = cast("dict[str, Any]", workspace)
        _emit_deps(ws.get("dependencies"), DependencyGroup.PROD, source, deps)

    return deps


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

    Returns ``(deps, filtered_count)`` where ``filtered_count`` is the number
    of deps removed because their name matched a workspace-local crate.
    """
    cargo_tomls = walk_project_files(project_path, "Cargo.toml", exclude_paths=exclude_paths)
    if not cargo_tomls:
        return [], 0

    local_names = _collect_local_rust_names(cargo_tomls)

    deps: list[Dependency] = []
    for ct in cargo_tomls:
        data = load_toml(ct)
        if data is None:
            continue
        source = ct.relative_to(project_path).as_posix()
        deps.extend(_parse_cargo_deps(data, source))

    if not local_names:
        return deps, 0
    kept = [d for d in deps if d.name not in local_names]
    return kept, len(deps) - len(kept)


def _collect_local_rust_names(paths: list[Path]) -> set[str]:
    names: set[str] = set()
    for ct in paths:
        data = load_toml(ct)
        if data is None:
            continue
        package = data.get("package")
        if isinstance(package, dict):
            name = cast("dict[str, Any]", package).get("name")
            if isinstance(name, str) and name:
                names.add(name)
    return names


def detect_project_license_cargo_toml(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Detect the project's own license from a Cargo.toml.

    Reads ``[package].license`` (per-crate declaration) and falls back to
    ``[workspace.package].license`` (Cargo workspace inheritance — root
    Cargo.toml declares the canonical license and member crates set
    ``license.workspace = true`` to inherit). Walks the tree for workspace
    layouts; returns the first non-empty license in walk order (root first).
    """
    for ct in walk_project_files(project_path, "Cargo.toml", exclude_paths=exclude_paths):
        data = load_toml(ct)
        if data is None:
            continue
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
                if isinstance(ws_license, str) and ws_license:
                    return ws_license
    return ""
