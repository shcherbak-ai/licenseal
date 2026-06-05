"""Parse NuGet lockfiles (``packages.lock.json`` and ``project.assets.json``).

NuGet's resolved-graph lockfiles come in two shapes, both produced by
``dotnet restore``:

* **``packages.lock.json``** — committed lockfile, opt-in via
  ``<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>``
  in the ``.csproj`` (NuGet 4.9+). Modern projects opt in for
  reproducible builds.
* **``project.assets.json``** — always emitted into the project's
  ``obj/`` directory after a successful restore. Typically gitignored
  but present in container scans (Dockerfiles often run
  ``dotnet restore`` before the COPY-into-runtime stage).

Both files have the resolved graph keyed by **target framework moniker
(TFM)**. A single project can target multiple TFMs simultaneously
(``net8.0``, ``net8.0-windows``, ``netstandard2.0``); each TFM gets its
own resolved subgraph because conditional ``<PackageReference
Condition="..." />`` entries and platform-specific transitives differ.

This parser **unions across all TFMs** (per the locked-in plan
decision): every package that appears in ANY TFM's resolved graph is
surfaced. The conservative posture is correct for license-scanning —
a GPL'd Windows-only library on a project that also targets Android
still matters for license-compliance even if Android builds skip it.

Edge data carried by both formats lets the transitive walker run
``_graph.compute_direct_ancestors`` for reachability-based group
attribution. Direct entries (``type: "Direct"`` in ``packages.lock.json``)
become roots; Transitive entries carry their ``dependencies`` list as
edges back to the roots.

Group attribution:

* The lockfile itself does NOT carry dev/prod metadata — that lives in
  the source ``.csproj``. The transitive walker takes the dev/prod set
  from the discovery layer and propagates via reachability. This module
  emits everything as PROD; the walker is responsible for the
  dev-reachability downgrade.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from licenseal.discovery._read import decode_text, record_parse_failure
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_PACKAGES_LOCK = "packages.lock.json"
_PROJECT_ASSETS = "project.assets.json"


@dataclass
class _LockEntry:
    """One resolved entry from a NuGet lockfile.

    ``edges`` carries the names of this package's direct dependencies
    (lowercased, per NuGet case-insensitivity). Empty for direct-from-
    project entries that have no further outbound deps.
    """

    name: str
    version: str
    is_direct: bool
    edges: tuple[str, ...] = field(default_factory=tuple)


def find_nuget_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``packages.lock.json`` and ``project.assets.json`` under ``project_path``.

    Both filenames are returned in walk order. Callers may filter for
    one shape or the other when the difference matters; both formats
    carry the same kind of resolved-graph information at the
    representation this module exposes.
    """
    out: list[Path] = []
    out.extend(walk_project_files(project_path, _PACKAGES_LOCK, exclude_paths=exclude_paths))
    out.extend(walk_project_files(project_path, _PROJECT_ASSETS, exclude_paths=exclude_paths))
    return out


def parse_packages_lock_json(text: str) -> list[_LockEntry] | None:
    """Parse one ``packages.lock.json`` content into a list of :class:`_LockEntry`.

    Returns ``None`` on malformed JSON. Returns an empty list on a valid
    but empty file. Format:

    .. code-block:: json

        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": {
                "type": "Direct",
                "requested": "[13.0.1, )",
                "resolved": "13.0.1",
                "contentHash": "...",
                "dependencies": {}
              },
              "System.Text.Json": {
                "type": "Transitive",
                "resolved": "8.0.0",
                "dependencies": {
                  "System.Memory": "4.5.5"
                }
              }
            },
            "net8.0-windows": { ... }
          }
        }

    The outer ``dependencies`` object's keys are TFMs; each inner value
    is a ``{package_name → entry}`` map. We union across all TFMs and
    dedupe on ``(name_lower, version)``: if the same package@version
    appears in multiple TFMs (the common case for cross-platform deps),
    one entry covers them all.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return []
    return list(_iter_packages_lock_entries(data))


def _iter_packages_lock_entries(data: dict) -> Iterable[_LockEntry]:
    """Yield deduped ``_LockEntry`` from a parsed ``packages.lock.json``."""
    seen: set[tuple[str, str]] = set()
    deps_by_tfm = data.get("dependencies")
    if not isinstance(deps_by_tfm, dict):
        return
    for tfm_value in deps_by_tfm.values():
        if not isinstance(tfm_value, dict):
            continue
        for package_name, entry in tfm_value.items():
            if not isinstance(package_name, str) or not isinstance(entry, dict):
                continue
            version = str(entry.get("resolved") or "").strip()
            if not version:
                continue
            key = (package_name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            entry_type = str(entry.get("type") or "").strip().lower()
            is_direct = entry_type in ("direct", "directreference")
            edges = _extract_edges(entry.get("dependencies"))
            yield _LockEntry(
                name=package_name,
                version=version,
                is_direct=is_direct,
                edges=edges,
            )


def _extract_edges(raw: object) -> tuple[str, ...]:
    """Return outbound-edge names (lowercased) from an entry's ``dependencies`` map.

    ``packages.lock.json`` shape: ``{"Sub.Dep": "1.0.0", ...}`` — keys are
    package names, values are version constraints. We only need the names
    for graph attribution; the version of the inbound transitive comes
    from its own entry in the TFM map.
    """
    if not isinstance(raw, dict):
        return ()
    return tuple(name.lower() for name in raw if isinstance(name, str))


def parse_project_assets_json(text: str) -> list[_LockEntry] | None:
    """Parse one ``project.assets.json`` content into a list of :class:`_LockEntry`.

    Returns ``None`` on malformed JSON. Format (simplified):

    .. code-block:: json

        {
          "version": 3,
          "targets": {
            "net8.0": {
              "Newtonsoft.Json/13.0.1": {
                "type": "package",
                "dependencies": {}
              },
              "System.Text.Json/8.0.0": {
                "type": "package",
                "dependencies": { "System.Memory": "4.5.5" }
              }
            }
          },
          "project": {
            "frameworks": {
              "net8.0": {
                "dependencies": {
                  "Newtonsoft.Json": { "version": "[13.0.1, )" }
                }
              }
            }
          }
        }

    The ``targets.{tfm}`` map keys are ``"PackageName/Version"`` strings;
    we split on ``/`` to get the parts. ``project.frameworks.{tfm}.dependencies``
    lists the direct deps (no version-pinning info there beyond range
    constraints; the resolved version lives in ``targets``).

    Same TFM-union + ``(name_lower, version)`` dedup as
    ``packages.lock.json``.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return []
    direct_names = _collect_assets_direct_names(data)
    return list(_iter_assets_entries(data, direct_names=direct_names))


def _collect_assets_direct_names(data: dict) -> set[str]:
    """Return the union of direct-dep names declared across all framework sections."""
    project = data.get("project")
    if not isinstance(project, dict):
        return set()
    frameworks = project.get("frameworks")
    if not isinstance(frameworks, dict):
        return set()
    names: set[str] = set()
    for fw_value in frameworks.values():
        if not isinstance(fw_value, dict):
            continue
        deps = fw_value.get("dependencies")
        if not isinstance(deps, dict):
            continue
        names.update(name.lower() for name in deps)
    return names


def _iter_assets_entries(data: dict, *, direct_names: set[str]) -> Iterable[_LockEntry]:
    """Yield deduped ``_LockEntry`` from a parsed ``project.assets.json``."""
    seen: set[tuple[str, str]] = set()
    targets = data.get("targets")
    if not isinstance(targets, dict):
        return
    for tfm_value in targets.values():
        if not isinstance(tfm_value, dict):
            continue
        for coord, entry in tfm_value.items():
            if not isinstance(coord, str) or "/" not in coord:
                continue
            if not isinstance(entry, dict):
                continue
            # ``project.assets.json`` also lists "project" type entries
            # for in-repo project references; those are NOT NuGet packages.
            entry_type = str(entry.get("type") or "").strip().lower()
            if entry_type and entry_type != "package":
                continue
            name, _, version = coord.partition("/")
            if not name or not version:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            edges = _extract_edges(entry.get("dependencies"))
            yield _LockEntry(
                name=name,
                version=version,
                is_direct=name.lower() in direct_names,
                edges=edges,
            )


def _entries_to_dependencies(
    entries: Iterable[_LockEntry],
    *,
    source: str,
) -> list[Dependency]:
    """Convert :class:`_LockEntry` items into :class:`Dependency` rows.

    All entries emerge as PROD; the transitive walker applies dev-
    reachability downgrades based on the source ``.csproj``'s group
    attribution.
    """
    out: list[Dependency] = []
    for entry in entries:
        out.append(
            Dependency(
                name=entry.name,
                version_constraint=entry.version,
                ecosystem=Ecosystem.DOTNET,
                group=DependencyGroup.PROD,
                source=source,
            )
        )
    return out


def discover_nuget_lockfile_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover deps from every NuGet lockfile under ``project_path``.

    Returns ``(deps, filtered_count)``. ``filtered_count`` is always 0
    here — workspace-local filtering happens at the .csproj layer (a
    lockfile's resolved graph never contains in-tree project references
    as packages since those have ``"type": "project"`` in
    ``project.assets.json`` and are filtered during parse).

    Dedup across lockfiles is by ``(name_lower, version, source)``: each
    lockfile is its own source-of-truth (a multi-project workspace can
    have one lockfile per project, all pulling overlapping deps; we
    keep each manifestation tied to its origin so the report carries the
    right ``source`` field).
    """
    out: list[Dependency] = []
    for lock_path in find_nuget_lockfiles(project_path, exclude_paths=exclude_paths):
        text = decode_text(lock_path)
        if text is None:
            continue
        if lock_path.name == _PACKAGES_LOCK:
            entries = parse_packages_lock_json(text)
        else:
            entries = parse_project_assets_json(text)
        if entries is None:
            record_parse_failure(lock_path, "JSON")
            continue
        source = lock_path.relative_to(project_path).as_posix()
        out.extend(_entries_to_dependencies(entries, source=source))
    return out, 0
