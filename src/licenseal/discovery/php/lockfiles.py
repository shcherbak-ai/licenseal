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
from licenseal.discovery._read import (
    load_json,
    record_unexpected_type,
    record_unread_entries,
    root_table,
    typed_field,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.php.composer_json import composer_map
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# What a gap names when an entry of ``packages`` / ``packages-dev``, or a
# field inside one, is not the type the lockfile format defines.
_PACKAGES_ENTRY = 'an entry of "packages"'

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
    """Skip platform requirements in a package's ``require`` edge map.

    Platform names never contain a ``/``, so a ``vendor/package`` edge is kept
    even when its vendor starts with ``php-`` / ``ext-`` / ``lib-``.
    """
    lowered = name.lower()
    if "/" in lowered:
        return False
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
    data = root_table(path, load_json(path))
    if data is None:
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
    total = read = 0
    for field_name in ("packages", "packages-dev"):
        section = typed_field(path, data, field_name, list, f'"{field_name}"') or []
        total += len(section)
        for entry in section:
            if isinstance(entry, dict):
                raw_packages.append(cast("dict[str, Any]", entry))
            else:
                record_unexpected_type(path, _PACKAGES_ENTRY)

    license_map: LockfileLicenseMap = {}
    edges: dict[str, set[str]] = {}
    name_case: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()
    pending: list[tuple[Dependency, bool]] = []

    for entry in raw_packages:
        name = typed_field(path, entry, "name", str, _PACKAGES_ENTRY)
        version = typed_field(path, entry, "version", str, _PACKAGES_ENTRY)
        if name is None or version is None:
            continue
        read += 1
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
        require = composer_map(path, entry, "require", _PACKAGES_ENTRY)
        edges.setdefault(normalized, set()).update(
            child.lower() for child in require if not _is_platform_require(child)
        )

        license_map[(normalized, canonical_version)] = _license_array_to_raw(entry.get("license"))

        if (normalized, canonical_version) in seen:
            continue
        seen.add((normalized, canonical_version))

        # A ``dev`` flag that is not a boolean is not trusted to move a
        # package out of the production set.
        dev_flag = typed_field(path, entry, "dev", bool, _PACKAGES_ENTRY)
        is_dev = bool(dev_flag) or name in dev_names_set
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

    record_unread_entries(path, total, read)
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
