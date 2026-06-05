"""composer.lock parser.

composer.lock is unique among lockfiles licenseal handles in two ways:

1. It carries an explicit ``dev: true`` flag per package — group attribution
   is canonical, no reachability re-inference needed (Composer is single-tool
   so there's no cross-package-manager attribution drift to defend against).
2. Each entry embeds a structured SPDX ``license`` field — same shape as
   composer.json's: bare string or array (array semantics are disjunctive
   per the Composer schema). This means most license resolutions can answer
   from the lockfile without any HTTP request to Packagist.

Edges live in each entry's ``require`` map (transitive children). We extract
them for ancestor attribution via :func:`_graph.compute_direct_ancestors`,
matching the Go / npm / Java lockfile paths.

Entries with ``dist.type == "path"`` are local source references (workspace
sibling, vendored fork, monorepo internal) — never published, never license-
resolvable via Packagist; they're filtered out.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import load_json
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Lockfile lookup key for the per-package license map produced during parse.
# Lowercased package name + exact resolved version — the Packagist resolver
# consults this before any HTTP fetch when the dep's constraint pins to one
# of these versions.
LockfileLicenseMap = dict[tuple[str, str], str]


def find_composer_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every composer.lock in the project tree.

    Monorepos sometimes ship multiple lockfiles (one per nested PHP project),
    so we walk the full tree rather than looking only at the root.
    """
    return walk_project_files(project_path, "composer.lock", exclude_paths=exclude_paths)


def _license_array_to_raw(value: object) -> str:
    """Same shape rule as composer.json: array → ``OR``-joined disjunction.

    composer.lock can carry ``"license": "MIT"`` (legacy bare string),
    ``"license": ["MIT"]`` (modern single-entry array), or ``"license":
    ["MIT", "Apache-2.0"]`` (multi-entry, disjunctive per the Composer
    schema). The ``"proprietary"`` placeholder passes through to the SPDX
    normalizer which maps it to the Proprietary sentinel.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        items: list[str] = [v.strip() for v in value if isinstance(v, str) and v.strip()]
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        return " OR ".join(items)
    return ""


def _is_path_source(meta: dict[str, Any]) -> bool:
    """Return True for path-type dist entries (workspace siblings)."""
    dist = meta.get("dist")
    if isinstance(dist, dict) and dist.get("type") == "path":
        return True
    source = meta.get("source")
    return isinstance(source, dict) and source.get("type") == "path"


def _is_platform_require(name: str) -> bool:
    """Skip platform requirements in a package's ``require`` edge map."""
    lowered = name.lower()
    if lowered in {"php", "hhvm", "composer-plugin-api", "composer-runtime-api"}:
        return True
    return lowered.startswith(("ext-", "lib-", "php-"))


def parse_composer_lockfile(
    path: Path,
    *,
    direct_names: set[str],
    include_dev: bool,
) -> tuple[list[Dependency], LockfileLicenseMap]:
    """Parse ``composer.lock`` into ``(deps, license_map)``.

    ``direct_names`` is the lowercased set of package names declared in
    composer.json (across both ``require`` and ``require-dev``). It's used
    to mark entries as depth=0 vs depth=1, and as roots for direct-ancestor
    attribution via the lockfile's ``require`` edges.

    Group attribution trusts the lockfile's per-entry ``dev`` boolean flag
    (set when the package only appears via ``require-dev``). With
    ``include_dev=False``, dev entries are filtered out.

    Returns:
        * ``deps`` — Dependency entries with pinned versions (``==X.Y.Z``)
          and direct-ancestor attribution for transitives.
        * ``license_map`` — ``{(name_lower, resolved_version): raw_license}``
          extracted from each entry's structured ``license`` field. Empty
          string values are kept (signals "lockfile knew this entry but
          had no license" → resolver falls back to Packagist).
    """
    data = load_json(path)
    if not isinstance(data, dict):
        return [], {}

    raw_packages: list[dict[str, Any]] = []
    # Pre-compute the names that live in ``packages-dev`` so older lockfiles
    # without per-entry ``dev: true`` flags can still be attributed in
    # O(1) per entry rather than O(N) via ``_entry_in_packages_dev``.
    dev_names_set: set[str] = set()
    dev_entries = data.get("packages-dev")
    if isinstance(dev_entries, list):
        for entry in dev_entries:
            if isinstance(entry, dict):
                n = entry.get("name")
                if isinstance(n, str):
                    dev_names_set.add(n)
    for field_name in ("packages", "packages-dev"):
        entries = data.get(field_name)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                raw_packages.append(cast("dict[str, Any]", entry))

    license_map: LockfileLicenseMap = {}
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()
    pending: list[tuple[Dependency, bool]] = []

    for entry in raw_packages:
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if _is_path_source(entry):
            continue

        # Canonicalize the version by stripping the decorative ``v`` prefix
        # so license-map keys and the pinned-version extractor agree on the
        # same shape regardless of how the publisher tagged the release.
        canonical_version = version.lstrip("v")
        normalized = name.lower()
        name_case.setdefault(normalized, name)

        # Edge map (lowercased child names) — drop platform requires;
        # they're not Packagist packages.
        require = entry.get("require")
        if isinstance(require, dict):
            children: set[str] = set()
            for child_name in require:
                if isinstance(child_name, str) and not _is_platform_require(child_name):
                    children.add(child_name.lower())
            edges.setdefault(normalized, set()).update(children)

        license_map[(normalized, canonical_version)] = _license_array_to_raw(entry.get("license"))

        if (normalized, canonical_version) in seen:
            continue
        seen.add((normalized, canonical_version))

        is_dev = bool(entry.get("dev", False)) or name in dev_names_set
        is_direct = normalized in direct_names

        if is_dev and not include_dev:
            continue

        dep = Dependency(
            name=name,
            version_constraint=f"=={canonical_version}",
            ecosystem=Ecosystem.PHP,
            group=DependencyGroup.DEV if is_dev else DependencyGroup.PROD,
            depth=0 if is_direct else 1,
        )
        pending.append((dep, is_direct))

    if not pending:
        return [], license_map

    # Direct-ancestor attribution for transitives: BFS from each direct root
    # through the edge graph, matching the Go / npm / Java patterns.
    roots = {n: name_case[n] for n in direct_names if n in name_case}
    ancestors = compute_direct_ancestors(edges, roots)

    out: list[Dependency] = []
    for dep, is_direct in pending:
        if is_direct:
            out.append(dep)
            continue
        out.append(
            Dependency(
                name=dep.name,
                version_constraint=dep.version_constraint,
                ecosystem=dep.ecosystem,
                group=dep.group,
                depth=dep.depth,
                direct_ancestors=ancestors.get(dep.name.lower(), ()),
            )
        )
    return out, license_map


def extract_composer_lock_licenses(path: Path) -> LockfileLicenseMap:
    """Parse only the license map from a composer.lock, ignoring graph data.

    The CLI uses this to pre-populate a lockfile-license cache that the
    Packagist resolver consults before any HTTP fetch. Returns an empty
    map on read / parse failure.
    """
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    out: LockfileLicenseMap = {}
    for field_name in ("packages", "packages-dev"):
        entries = data.get(field_name)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            out[(name.lower(), version.lstrip("v"))] = _license_array_to_raw(entry.get("license"))
    return out
