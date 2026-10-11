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

Both formats carry each package's ``dependencies`` map. That is the edge
graph :func:`parse_nuget_lockfile` runs ``_graph.compute_direct_ancestors``
over for reachability-based group and ancestor attribution.

Group attribution:

* The lockfile itself does NOT carry dev/prod metadata — that lives in
  the source ``.csproj``. The transitive walker passes in the names of the
  PROD and DEV direct dependencies discovery found, and those are the
  roots. A lockfile's own ``type: "Direct"`` marker is parsed but adds no
  roots.
* A package reachable from a PROD root is PROD. That includes a DEV root
  (``PrivateAssets="all"``) that a production package also depends on. A
  package reachable only from DEV roots is DEV. A package reachable from
  no root is PROD with no ancestors.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import decode_text, record_parse_failure
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Key of a package name in the name sets and graphs below (see
# ``Ecosystem.identity``).
_key = Ecosystem.DOTNET.identity

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

    Returns ``None`` on malformed JSON, or JSON nested too deeply to parse.
    Returns an empty list on a valid but empty file. Format:

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
    one entry covers them all, carrying the edges of every TFM.
    """
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError subclass
        return None
    if not isinstance(data, dict):
        return []
    return list(_iter_packages_lock_entries(data))


def _add_entry(entries: dict[tuple[str, str], _LockEntry], entry: _LockEntry) -> None:
    """Record ``entry``, merging it into an earlier sighting of the same package@version.

    A package resolved under several target frameworks can depend on
    different packages in each, so the edges are unioned (and the entry is
    direct if any sighting is). Keeping only the first sighting would leave
    the other frameworks' children with no inbound edge.
    """
    key = (_key(entry.name), entry.version)
    seen = entries.get(key)
    if seen is None:
        entries[key] = entry
        return
    seen.is_direct = seen.is_direct or entry.is_direct
    seen.edges = tuple(dict.fromkeys((*seen.edges, *entry.edges)))


def _iter_packages_lock_entries(data: dict) -> Iterable[_LockEntry]:
    """Return deduped ``_LockEntry`` from a parsed ``packages.lock.json``."""
    entries: dict[tuple[str, str], _LockEntry] = {}
    deps_by_tfm = data.get("dependencies")
    if not isinstance(deps_by_tfm, dict):
        return ()
    for tfm_value in deps_by_tfm.values():
        if not isinstance(tfm_value, dict):
            continue
        for package_name, entry in tfm_value.items():
            if not isinstance(package_name, str) or not isinstance(entry, dict):
                continue
            version = str(entry.get("resolved") or "").strip()
            if not version:
                continue
            entry_type = str(entry.get("type") or "").strip().lower()
            is_direct = entry_type in ("direct", "directreference")
            edges = _extract_edges(entry.get("dependencies"))
            _add_entry(
                entries,
                _LockEntry(
                    name=package_name,
                    version=version,
                    is_direct=is_direct,
                    edges=edges,
                ),
            )
    return entries.values()


def _extract_edges(raw: object) -> tuple[str, ...]:
    """Return outbound-edge names (lowercased) from an entry's ``dependencies`` map.

    ``packages.lock.json`` shape: ``{"Sub.Dep": "1.0.0", ...}`` — keys are
    package names, values are version constraints. We only need the names
    for graph attribution; the version of the inbound transitive comes
    from its own entry in the TFM map.
    """
    if not isinstance(raw, dict):
        return ()
    return tuple(_key(name) for name in raw if isinstance(name, str))


def parse_project_assets_json(text: str) -> list[_LockEntry] | None:
    """Parse one ``project.assets.json`` content into a list of :class:`_LockEntry`.

    Returns ``None`` on malformed JSON, or JSON nested too deeply to parse.
    Format (simplified):

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
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError subclass
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
        names.update(_key(name) for name in deps)
    return names


def _iter_assets_entries(data: dict, *, direct_names: set[str]) -> Iterable[_LockEntry]:
    """Return deduped ``_LockEntry`` from a parsed ``project.assets.json``."""
    entries: dict[tuple[str, str], _LockEntry] = {}
    targets = data.get("targets")
    if not isinstance(targets, dict):
        return ()
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
            edges = _extract_edges(entry.get("dependencies"))
            _add_entry(
                entries,
                _LockEntry(
                    name=name,
                    version=version,
                    is_direct=_key(name) in direct_names,
                    edges=edges,
                ),
            )
    return entries.values()


def parse_nuget_lockfile(
    path: Path,
    *,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse one NuGet lockfile into dependencies with group + ancestor attribution.

    ``prod_root_names`` / ``dev_root_names`` are the lowercased names of the
    direct dependencies discovery found across the whole scan. The
    lockfile's edges decide every package's group by reachability:

    * a PROD root, or reachable from one → PROD. A DEV root that a PROD
      root reaches is PROD too: production wins.
    * otherwise a DEV root, or reachable from one → DEV, dropped when
      ``include_dev`` is false.
    * reachable from no root → PROD with no ancestors, the conservative
      default.

    A root is depth 0 with no ancestors. Any other package is depth 1 and
    lists the roots of its own group that reach it. Edges are keyed by name,
    so they are unioned across the versions of a package the lockfile holds.

    An unreadable file yields nothing; an unparseable one is also recorded
    as an analysis gap.
    """
    text = decode_text(path)
    if text is None:
        return []
    if path.name == _PACKAGES_LOCK:
        entries = parse_packages_lock_json(text)
    else:
        entries = parse_project_assets_json(text)
    if entries is None:
        record_parse_failure(path, "JSON")
        return []

    name_case: dict[str, str] = {}
    edges: dict[str, set[str]] = {}
    for entry in entries:
        lower = _key(entry.name)
        name_case.setdefault(lower, entry.name)
        edges.setdefault(lower, set()).update(entry.edges)
    prod_anc = compute_direct_ancestors(
        edges, {n: name_case[n] for n in prod_root_names if n in name_case}
    )
    dev_anc = compute_direct_ancestors(
        edges, {n: name_case[n] for n in dev_root_names if n in name_case}
    )

    out: list[Dependency] = []
    for entry in entries:
        lower = _key(entry.name)
        is_root = lower in prod_root_names or lower in dev_root_names
        if lower in prod_root_names or lower in prod_anc:
            group = DependencyGroup.PROD
            ancestors = prod_anc.get(lower, ())
        elif is_root or lower in dev_anc:
            group = DependencyGroup.DEV
            ancestors = dev_anc.get(lower, ())
        else:
            group = DependencyGroup.PROD
            ancestors = ()

        if group == DependencyGroup.DEV and not include_dev:
            continue

        out.append(
            Dependency(
                name=entry.name,
                version_constraint=entry.version,
                ecosystem=Ecosystem.DOTNET,
                group=group,
                depth=0 if is_root else 1,
                direct_ancestors=() if is_root else ancestors,
            )
        )
    return out
