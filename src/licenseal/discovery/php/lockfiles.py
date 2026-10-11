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

An entry with ``dist.type == "path"`` is a local source reference. A path the
scan reads is the project's own code (workspace sibling, monorepo internal)
and gets no row; any other is a row with the path as origin.

An entry Composer took from a version-control repository looks, in the
lockfile, like one it took from Packagist: both carry a ``source`` (the
repository) and a ``dist``. The lockfile alone does not tell them apart, so
the composer.json beside it is consulted. An entry is not a Packagist package
when its ``source.url`` is the URL of a ``vcs`` repository that composer.json
declares, or when its name is one a ``package`` repository there defines; its
origin is then the repository plus the locked ``source.reference``. An entry
with no ``source`` whose ``dist.url`` is a filesystem path is an archive from
an ``artifact`` repository: the dist of a registry package is always a URL.
Every other entry is a registry row, including one from a ``composer``
repository (another registry).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._origin import UNRECORDED, path_origin, repository_key
from licenseal.discovery._read import (
    load_json,
    record_unexpected_type,
    record_unread_entries,
    root_table,
    typed_field,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.php.composer_json import (
    VCS_REPOSITORY_TYPES,
    composer_map,
    composer_repositories,
    inline_package_origins,
    package_origin,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Key of a package name in the name sets and graphs below (see
# ``Ecosystem.identity``).
_key = Ecosystem.PHP.identity

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
    """Return True for path-type dist entries."""
    dist = meta.get("dist")
    if isinstance(dist, dict) and dist.get("type") == "path":
        return True
    source = meta.get("source")
    return isinstance(source, dict) and source.get("type") == "path"


def _declared_off_registry(lock: Path, scan_root: Path) -> tuple[set[str], dict[str, str | None]]:
    """What the composer.json beside ``lock`` declares outside Packagist.

    Returns ``(vcs_keys, inline)``: the comparable URLs of its ``vcs``
    repositories, and the packages its ``package`` repositories define.
    Both are empty when there is no readable composer.json there.
    """
    manifest = lock.parent / "composer.json"
    data = root_table(manifest, load_json(manifest)) if manifest.is_file() else None
    if data is None:
        return set(), {}
    repositories = composer_repositories(data)
    vcs_keys = {
        repository_key(repo["url"])
        for repo in repositories
        if repo.get("type") in VCS_REPOSITORY_TYPES and isinstance(repo.get("url"), str)
    }
    return vcs_keys, inline_package_origins(repositories, lock.parent, scan_root)


def _entry_origin(
    entry: dict[str, Any],
    name: str,
    lock_dir: Path,
    scan_root: Path,
    vcs_keys: set[str],
    inline: dict[str, str | None],
) -> str | None:
    """Origin of a lock entry: empty for a registry package, ``None`` for own code."""
    if _is_path_source(entry):
        for table in (entry.get("dist"), entry.get("source")):
            if isinstance(table, dict) and table.get("type") == "path":
                url = table.get("url")
                if isinstance(url, str) and url:
                    return path_origin(url, lock_dir, scan_root)
        # A path entry that records no path is not shown to be inside the
        # scanned directory.
        return UNRECORDED
    source = entry.get("source")
    source_url = source.get("url") if isinstance(source, dict) else None
    from_vcs = isinstance(source_url, str) and repository_key(source_url) in vcs_keys
    if from_vcs or _key(name) in inline:
        return package_origin(entry, lock_dir, scan_root)
    # An archive on the local filesystem, as an ``artifact`` repository
    # provides: the dist of a registry package is always a URL.
    dist = entry.get("dist")
    dist_url = dist.get("url") if isinstance(dist, dict) else None
    local_archive = isinstance(dist_url, str) and dist_url and "://" not in dist_url
    if local_archive and not isinstance(source_url, str):
        return path_origin(dist_url, lock_dir, scan_root)
    return ""


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
    scan_root: Path | None = None,
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
          had no license" → resolver falls back to Packagist). Every entry
          the lockfile holds is in the map, the project's own path packages
          included: its keys are the names the lockfile covers.

    ``scan_root`` is the scanned directory, the lockfile's own directory when
    omitted. A path entry that the scan reads gets no row.
    """
    scan_root = scan_root or path.parent
    data = root_table(path, load_json(path))
    if data is None:
        return [], {}
    vcs_keys, inline = _declared_off_registry(path, scan_root)

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

        # Canonicalize the version by stripping the decorative ``v`` prefix
        # so license-map keys and the pinned-version extractor agree on the
        # same shape regardless of how the publisher tagged the release.
        canonical_version = version.lstrip("v")
        normalized = _key(name)
        license_map[(normalized, canonical_version)] = _license_array_to_raw(entry.get("license"))
        origin = _entry_origin(entry, name, path.parent, scan_root, vcs_keys, inline)
        if origin is None:
            continue
        name_case.setdefault(normalized, name)

        # Edge map (lowercased child names) — drop platform requires;
        # they're not Packagist packages.
        require = composer_map(path, entry, "require", _PACKAGES_ENTRY)
        edges.setdefault(normalized, set()).update(
            _key(child) for child in require if not _is_platform_require(child)
        )

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
            origin=origin,
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
                direct_ancestors=ancestors.get(dep.identity, ()),
                origin=dep.origin,
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
            out[(_key(name), version.lstrip("v"))] = _license_array_to_raw(entry.get("license"))
    return out
