"""Lockfile parsers for Python (uv.lock, poetry.lock, Pipfile.lock).

Lockfiles represent the actually-resolved dependency graph and are the ground
truth for transitive scanning. Each parser returns a flat list of `Dependency`
objects pinned to exact versions, with `depth`, `group`, and
`direct_ancestors` populated.

For uv.lock / poetry.lock, group attribution is reachability-based: a
transitive is `prod` iff it can be reached (via the lockfile's edge graph)
from a `prod` direct dep, otherwise `dev` if reachable from a `dev` direct
dep. Anything reachable from neither is dropped — these are typically
dev-tool chains that no longer have a live root, or stale lockfile entries.

uv.lock keeps the dependencies behind an extra (``django[argon2]`` →
``argon2-cffi``) in a separate ``[package.optional-dependencies]`` table.
Those edges count for every extra that is requested somewhere in the lock,
by the project or by another package; without them, packages reachable only
through an extra would be dropped as orphans.

Pipfile.lock has no per-package dependency graph (each entry only carries
``version`` / ``hashes`` / ``markers``), so its attribution falls back to
the section the entry lives in: ``default`` is PROD, ``develop`` is DEV.
Without edges, transitive ancestors stay empty for that format.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from packaging.utils import canonicalize_name

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import load_json, load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _canon_name(name: str) -> str:
    """PEP 503 canonical distribution name.

    Folds runs of ``-``, ``_``, ``.`` to a single ``-`` and lowercases, so
    ``zope.interface`` / ``zope-interface`` / ``zope_interface`` collapse to
    one graph node. Package nodes, edge endpoints, and the incoming root sets
    must all pass through this; otherwise a lockfile that spells a name one way
    in ``[[package]] name`` and another in a parent's ``dependencies`` table
    fails to connect the edge and the dep is dropped as an orphan *before*
    ``transitive._canonical_name`` (which normalizes the same way) can recover
    it. ``str()`` keeps the result a plain ``str`` for the ``set[str]`` /
    ``dict[str, ...]`` annotations below.
    """
    return str(canonicalize_name(name))


_PYTHON_LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock")


def find_python_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every Python lockfile in the project tree, one per directory.

    Polyglot monorepos commonly nest Python lockfiles under a service or
    package subdir (e.g. ``machine-learning/uv.lock`` next to a JS root).
    Each lockfile is the ground truth for its own subtree, so we parse them
    all. When a directory has both supported lockfile types (transitional
    state), the higher-priority one wins for that directory: uv.lock >
    poetry.lock > Pipfile.lock.
    """
    chosen: dict[Path, Path] = {}
    for name in _PYTHON_LOCKFILES:
        for path in walk_project_files(project_path, name, exclude_paths=exclude_paths):
            chosen.setdefault(path.parent, path)
    return list(chosen.values())


def parse_python_lockfile(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Dispatch to the appropriate parser based on filename."""
    if path.name == "uv.lock":
        return parse_uv_lock(path, prod_root_names, dev_root_names, include_dev)
    if path.name == "poetry.lock":
        return parse_poetry_lock(path, prod_root_names, dev_root_names, include_dev)
    if path.name == "Pipfile.lock":
        return parse_pipfile_lock(path, prod_root_names, dev_root_names, include_dev)
    raise ValueError(f"Unsupported Python lockfile: {path.name}")


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file; return ``{}`` on parse or IO error.

    Scan targets ship malformed test-fixture lockfiles (e.g. a deliberately
    broken ``uv.lock`` containing a literal ``!``) that the walker picks up
    by name. A parse failure on one such file must not crash the whole scan
    — return an empty dict and let the caller decide whether the absence
    of expected keys is an actionable error.

    The failure is *not* silent, though: ``load_toml`` records the unreadable /
    unparseable file as an analysis gap on the active read-diagnostics sink
    (surfaced on stderr and failing ``--strict``), because a lockfile we
    couldn't read is a set of dependencies we couldn't vouch for. The empty
    dict here only keeps the parse loop from crashing.
    """
    return cast("dict[str, Any]", load_toml(path) or {})


def _attribute(
    edges: dict[str, set[str]],
    name_case: dict[str, str],
    prod_root_names: set[str],
    dev_root_names: set[str],
) -> tuple[
    dict[str, DependencyGroup],
    dict[str, tuple[str, ...]],
]:
    """Compute per-package group + direct_ancestors via reverse-BFS from each root set.

    A package is PROD if reachable from any prod root, else DEV if reachable
    from any dev root, else absent (orphan).
    """
    prod_roots = {n: name_case[n] for n in prod_root_names if n in name_case}
    dev_roots = {n: name_case[n] for n in dev_root_names if n in name_case}
    prod_anc = compute_direct_ancestors(edges, prod_roots)
    dev_anc = compute_direct_ancestors(edges, dev_roots)

    group_by_name: dict[str, DependencyGroup] = {}
    ancestors_by_name: dict[str, tuple[str, ...]] = {}
    # Roots themselves are reachable from themselves; record them too.
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


_Entry = tuple[str, tuple[str, ...]]  # (canonical name, requested extras)


def _entries(field: object) -> list[_Entry]:
    """Parse a uv.lock dependency list such as ``[{ name = "django", extra = ["argon2"] }]``.

    Malformed entries are skipped.
    """
    if not isinstance(field, list):
        return []
    out: list[_Entry] = []
    for raw in field:
        if not isinstance(raw, dict):
            continue
        entry = cast("dict[str, Any]", raw)
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        extras = entry.get("extra")
        requested = (
            tuple(e for e in extras if isinstance(e, str)) if isinstance(extras, list) else ()
        )
        out.append((_canon_name(name), requested))
    return out


def _entries_by_key(field: object) -> dict[str, list[_Entry]]:
    """``_entries`` for each key of an extras or dependency-groups table."""
    if not isinstance(field, dict):
        return {}
    table = cast("dict[str, Any]", field)
    return {key: _entries(value) for key, value in table.items()}


def parse_uv_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse a `uv.lock` file into a flat dependency list.

    uv.lock encodes parent → child edges as
    `dependencies = [{ name = "..." }, ...]` per `[[package]]` block, plus
    `[package.optional-dependencies]` for the children behind each extra; we
    harvest those (the latter only for extras requested somewhere in the
    lock), then run reverse-BFS from prod and dev root sets to determine each
    package's group and direct ancestors. Packages reachable from neither root
    set are dropped (orphans / stale).
    """
    prod_root_names = {_canon_name(n) for n in prod_root_names}
    dev_root_names = {_canon_name(n) for n in dev_root_names}
    data = _load_toml(path)
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return []

    raw_pkgs: list[tuple[str, str]] = []  # (name, version)
    name_case: dict[str, str] = {}
    edges: dict[str, set[str]] = {}
    optional: dict[str, dict[str, list[_Entry]]] = {}  # package → extra → entries
    requested: list[tuple[str, str]] = []  # (package, extra) pairs the lock installs
    seen: set[tuple[str, str]] = set()
    for raw in packages:
        if not isinstance(raw, dict):
            continue
        pkg = cast("dict[str, Any]", raw)
        entries = _entries(pkg.get("dependencies"))

        # uv.lock includes the project being scanned as a [[package]] entry
        # itself: source = { editable = "." } for an installable project,
        # source = { virtual = "." } for a non-package project, and the same
        # with the member's path for workspace members. They are not external
        # deps to license-check, but their dependency tables (including extras
        # and dependency groups) say which extras of their deps get installed.
        source = pkg.get("source", {})
        if isinstance(source, dict) and ("virtual" in source or "editable" in source):
            for table in ("optional-dependencies", "dev-dependencies"):
                for group_entries in _entries_by_key(pkg.get(table)).values():
                    entries += group_entries
            requested += [(child, extra) for child, extras in entries for extra in extras]
            continue

        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue

        normalized = _canon_name(name)
        if (normalized, version) in seen:
            continue
        seen.add((normalized, version))

        requested += [(child, extra) for child, extras in entries for extra in extras]
        for extra, extra_entries in _entries_by_key(pkg.get("optional-dependencies")).items():
            optional.setdefault(normalized, {}).setdefault(extra, []).extend(extra_entries)

        name_case[normalized] = name
        edges.setdefault(normalized, set()).update(child for child, _ in entries)
        raw_pkgs.append((name, version))

    # Follow each requested extra into the package's optional dependencies,
    # which can request further extras of their own.
    expanded: set[tuple[str, str]] = set()
    while requested:
        package, extra = requested.pop()
        if (package, extra) in expanded:
            continue
        expanded.add((package, extra))
        for child, extras in optional.get(package, {}).get(extra, []):
            edges.setdefault(package, set()).add(child)
            requested += [(child, e) for e in extras]

    group_by_name, ancestors_by_name = _attribute(edges, name_case, prod_root_names, dev_root_names)

    out: list[Dependency] = []
    for name, version in raw_pkgs:
        normalized = _canon_name(name)
        group = group_by_name.get(normalized)
        if group is None:
            continue  # orphan: not reachable from any root
        if group == DependencyGroup.DEV and not include_dev:
            continue
        is_root = normalized in prod_root_names or normalized in dev_root_names
        out.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}",
                ecosystem=Ecosystem.PYTHON,
                group=group,
                depth=0 if is_root else 1,
                direct_ancestors=() if is_root else ancestors_by_name.get(normalized, ()),
            )
        )
    return out


def parse_poetry_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse a `poetry.lock` file into a flat dependency list.

    Edges come from each `[[package]]`'s `[package.dependencies]` table whose
    keys are dep names; we union those into the edge graph and reverse-BFS
    from each root set to determine group + direct ancestors.

    poetry.lock entries also carry a per-package `category = "main"|"dev"`
    field, but we let reachability be authoritative — a dep marked
    `category = "main"` that's only reachable from a dev root still gets
    classified DEV (it's how it actually reaches the install graph).
    """
    prod_root_names = {_canon_name(n) for n in prod_root_names}
    dev_root_names = {_canon_name(n) for n in dev_root_names}
    data = _load_toml(path)
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return []

    raw_pkgs: list[tuple[str, str]] = []
    name_case: dict[str, str] = {}
    edges: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    for raw in packages:
        if not isinstance(raw, dict):
            continue
        pkg = cast("dict[str, Any]", raw)
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue

        normalized = _canon_name(name)
        if (normalized, version) in seen:
            continue
        seen.add((normalized, version))

        deps_field = pkg.get("dependencies", {})
        children: list[str] = []
        if isinstance(deps_field, dict):
            # tomllib guarantees string keys, so no per-key isinstance check.
            children = [_canon_name(k) for k in deps_field]

        name_case[normalized] = name
        edges.setdefault(normalized, set()).update(children)
        raw_pkgs.append((name, version))

    group_by_name, ancestors_by_name = _attribute(edges, name_case, prod_root_names, dev_root_names)

    out: list[Dependency] = []
    for name, version in raw_pkgs:
        normalized = _canon_name(name)
        group = group_by_name.get(normalized)
        if group is None:
            continue
        if group == DependencyGroup.DEV and not include_dev:
            continue
        is_root = normalized in prod_root_names or normalized in dev_root_names
        out.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}",
                ecosystem=Ecosystem.PYTHON,
                group=group,
                depth=0 if is_root else 1,
                direct_ancestors=() if is_root else ancestors_by_name.get(normalized, ()),
            )
        )
    return out


_PIPFILE_NON_REGISTRY_KEYS = ("git", "path", "file")


def parse_pipfile_lock(
    path: Path,
    prod_root_names: set[str],
    dev_root_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse a ``Pipfile.lock`` (Pipenv) into a flat dep list.

    Pipfile.lock is JSON with two top-level sections — ``default`` (PROD)
    and ``develop`` (DEV). Each entry's ``version`` field is already in
    PEP 440 specifier form (``"==2.31.0"``) — used as-is.

    Unlike uv.lock / poetry.lock, Pipfile.lock entries don't list their
    own dependencies, so there's no edge graph to BFS over. Group comes
    straight from the section; transitives get ``direct_ancestors = ()``
    because the lockfile doesn't tell us which root pulled them in.
    Direct deps (matched against ``prod_root_names`` / ``dev_root_names``)
    are still depth=0; everything else is depth=1.

    Entries whose source is git / path / file have no PyPI metadata and
    are skipped.
    """
    prod_root_names = {_canon_name(n) for n in prod_root_names}
    dev_root_names = {_canon_name(n) for n in dev_root_names}
    data = load_json(path)
    if not isinstance(data, dict):
        return []

    out: list[Dependency] = []
    for section, group in (
        ("default", DependencyGroup.PROD),
        ("develop", DependencyGroup.DEV),
    ):
        if group == DependencyGroup.DEV and not include_dev:
            continue
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            continue
        for name, raw in entries.items():
            if not isinstance(name, str) or not isinstance(raw, dict):
                continue
            meta = cast("dict[str, Any]", raw)
            if any(k in meta for k in _PIPFILE_NON_REGISTRY_KEYS):
                continue
            version = meta.get("version")
            if not isinstance(version, str) or not version:
                continue
            normalized = _canon_name(name)
            is_root = normalized in prod_root_names or normalized in dev_root_names
            out.append(
                Dependency(
                    name=name,
                    version_constraint=version,
                    ecosystem=Ecosystem.PYTHON,
                    group=group,
                    depth=0 if is_root else 1,
                    direct_ancestors=(),
                )
            )
    return out
