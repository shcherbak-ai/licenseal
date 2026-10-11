"""Discover Python dependencies from pyproject.toml files."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, NamedTuple, cast

from licenseal.discovery._read import load_toml, record_unexpected_type, typed_field
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python import (
    DEV_GROUP_NAMES,
    requirement_dependency,
    source_table_origin,
    table_spec,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# PEP 503: collapse runs of `-`, `_`, `.` to a single `-` and lowercase.
_pep503_normalize = Ecosystem.PYTHON.identity


def _project_table(filepath: Path, data: dict) -> dict:
    """The PEP 621 ``[project]`` table, empty when absent or not a table."""
    return typed_field(filepath, data, "project", dict) or {}


def _poetry_table(filepath: Path, data: dict) -> dict:
    """The ``[tool.poetry]`` table, empty when absent or not a table."""
    tool = typed_field(filepath, data, "tool", dict) or {}
    return typed_field(filepath, tool, "poetry", dict, "tool.poetry") or {}


def _string_list(filepath: Path, value: object, section: str, *, entry: bool = False) -> list[str]:
    """Return the strings of a manifest array of requirement strings.

    ``value`` is ``section`` itself, or one of its entries when ``entry`` is
    set (the list behind one extra). A value that is not an array, and an
    item that is not a string, are recorded as gaps: iterating a string here
    would yield one requirement per character.
    """
    entry_of = f"an entry of {section}"
    if value is None:
        return []
    if not isinstance(value, list):
        record_unexpected_type(filepath, entry_of if entry else section)
        return []
    strings = [item for item in value if isinstance(item, str)]
    if len(strings) != len(value):
        record_unexpected_type(filepath, entry_of)
    return strings


def _extract_deps(
    dep_list: list[str], group: DependencyGroup, source: str, base_dir: Path, scan_root: Path
) -> list[Dependency]:
    """Convert a list of PEP 508 strings to Dependency objects.

    A direct reference (``name @ <url>``) is a dependency with an origin; one
    to a path that the scan reads is the project's own code and is left out.
    """
    deps = []
    for dep_str in dep_list:
        dep = requirement_dependency(dep_str, group, source, base_dir, scan_root)
        if dep is not None:
            deps.append(dep)
    return deps


def _tables_origin(
    filepath: Path, spec: object, what: str, base_dir: Path, scan_root: Path
) -> str | None:
    """Origin a Poetry dependency spec or a uv source declares.

    ``spec`` is one table, or a list holding one table per environment. In
    a list, the first table that names a source outside the registry decides:
    the dependency does not come from the registry everywhere. Empty when no
    table names one; ``None`` for the project's own code.
    """
    for table in spec if isinstance(spec, list) else [spec]:
        if not isinstance(table, dict):
            continue
        origin = source_table_origin(
            filepath, cast("dict[str, Any]", table), what, base_dir, scan_root
        )
        if origin != "":
            return origin
    return ""


def _poetry_deps(
    filepath: Path,
    table: dict,
    section: str,
    group: DependencyGroup,
    source: str,
    scan_root: Path,
    own: list[str],
) -> list[Dependency]:
    """Convert a Poetry dependency table (name → spec) to Dependency objects.

    A spec with ``git``, ``url``, or ``path`` is a dependency with an origin
    and no version constraint. The name of one whose path is inside
    ``scan_root`` is appended to ``own`` instead: it is the project's own code.
    """
    deps = []
    for name, spec in table.items():
        what = f"an entry of {section}"
        origin = _tables_origin(filepath, spec, what, filepath.parent, scan_root)
        if origin is None:
            own.append(name)
            continue
        # A list holds one constraint table per environment: a valid form
        # with no single version, read as unconstrained.
        version, extras = (
            ("", frozenset())
            if isinstance(spec, list)
            else table_spec(filepath, spec, f"an entry of {section}")
        )
        deps.append(
            Dependency(
                name=name,
                version_constraint="" if origin else version,
                ecosystem=Ecosystem.PYTHON,
                group=group,
                source=source,
                origin=origin,
                extras=extras,
            )
        )
    return deps


def _uv_sources(filepath: Path, data: dict) -> dict[str, object]:
    """The ``[tool.uv.sources]`` table, keyed by PEP 503 name; empty when absent."""
    tool = typed_field(filepath, data, "tool", dict) or {}
    uv = typed_field(filepath, tool, "uv", dict, "tool.uv") or {}
    sources = typed_field(filepath, uv, "sources", dict, "tool.uv.sources") or {}
    return {_pep503_normalize(name): spec for name, spec in sources.items()}


class _UvWorkspace(NamedTuple):
    """What a uv workspace root says about the projects below it."""

    # The ``members`` and ``exclude`` globs of ``[tool.uv.workspace]``, each
    # split into its path components.
    members: list[list[str]]
    exclude: list[list[str]]
    # The root's ``[tool.uv.sources]`` table, keyed by PEP 503 name.
    sources: dict[str, object]


def _glob_components(filepath: Path, value: object, section: str) -> list[list[str]]:
    """The globs of a ``[tool.uv.workspace]`` array, each as path components."""
    return [
        [part for part in glob.replace("\\", "/").split("/") if part not in {"", "."}]
        for glob in _string_list(filepath, value, section)
    ]


def _uv_workspace(filepath: Path, data: dict) -> _UvWorkspace | None:
    """The uv workspace this pyproject.toml is the root of; ``None`` when it declares none."""
    tool = typed_field(filepath, data, "tool", dict) or {}
    uv = typed_field(filepath, tool, "uv", dict, "tool.uv") or {}
    workspace = uv.get("workspace")
    if not isinstance(workspace, dict):
        return None
    return _UvWorkspace(
        members=_glob_components(filepath, workspace.get("members"), "tool.uv.workspace.members"),
        exclude=_glob_components(filepath, workspace.get("exclude"), "tool.uv.workspace.exclude"),
        sources=_uv_sources(filepath, data),
    )


def _matches_glob(parts: Sequence[str], glob: Sequence[str]) -> bool:
    """Whether a relative path matches a glob, both given as path components.

    ``*``, ``?``, and ``[…]`` stay inside one component, as they do when uv
    expands a ``members`` glob. A ``**`` component stands for any number of
    directories, none included.
    """
    if not glob:
        return not parts
    if glob[0] == "**":
        return any(_matches_glob(parts[skip:], glob[1:]) for skip in range(len(parts) + 1))
    return bool(parts) and fnmatchcase(parts[0], glob[0]) and _matches_glob(parts[1:], glob[1:])


def _workspace_sources(
    project_dir: Path, workspaces: dict[Path, _UvWorkspace]
) -> dict[str, object] | None:
    """The ``[tool.uv.sources]`` a project inherits from its uv workspace root.

    The root is the nearest directory above ``project_dir`` that declares a
    workspace. The project is a member of it when its directory matches one
    of the root's ``members`` globs and none of its ``exclude`` globs. Any
    other project below the root is a project of its own and inherits
    nothing.
    """
    root = next((d for d in project_dir.parents if d in workspaces), None)
    if root is None:
        return None
    workspace = workspaces[root]
    parts = project_dir.relative_to(root).parts
    if not any(_matches_glob(parts, glob) for glob in workspace.members):
        return None
    if any(_matches_glob(parts, glob) for glob in workspace.exclude):
        return None
    return workspace.sources


def _parse_pyproject_deps(
    filepath: Path,
    data: dict,
    source: str,
    scan_root: Path,
    inherited_sources: dict[str, object] | None = None,
) -> tuple[list[Dependency], list[str]]:
    """Extract dependencies from a single parsed pyproject.toml data dict.

    A section or an entry that is not the type its format defines is
    recorded as a gap on ``filepath`` and read as absent; every other section
    is still read.

    Returns ``(deps, own)``. ``own`` names the dependencies that are the
    project's own code: a path that the scan reads, or a uv workspace
    member. ``inherited_sources`` is the ``[tool.uv.sources]`` table of the
    uv workspace root this file's project is a member of; this file's own
    entries override it.
    """
    deps: list[Dependency] = []
    own: list[str] = []
    base_dir = filepath.parent

    # PEP 621: [project.dependencies]
    project = _project_table(filepath, data)
    prod_deps = _string_list(filepath, project.get("dependencies"), "project.dependencies")
    deps.extend(_extract_deps(prod_deps, DependencyGroup.PROD, source, base_dir, scan_root))

    # PEP 621: [project.optional-dependencies]
    optional_section = "project.optional-dependencies"
    optional = typed_field(filepath, project, "optional-dependencies", dict, optional_section) or {}
    for group_name, group_deps in optional.items():
        group = (
            DependencyGroup.DEV if group_name.lower() in DEV_GROUP_NAMES else DependencyGroup.PROD
        )
        extra_deps = _string_list(filepath, group_deps, optional_section, entry=True)
        deps.extend(_extract_deps(extra_deps, group, source, base_dir, scan_root))

    # PEP 735: [dependency-groups] (uv, pdm). Two-pass to resolve
    # ``{ include-group = "<other>" }`` directives correctly:
    #   1. Split each group's entries into plain PEP 508 strings vs include
    #      references. Inline dev classification by group name alone is
    #      unsafe — a group named ``dev`` whose entries are only
    #      ``include-group`` refs (cf. uv's recommended layout) would
    #      contribute zero deps, while the included groups (``build-test``,
    #      ``type-stubs``, …) get misclassified as PROD because their own
    #      names aren't in DEV_GROUP_NAMES.
    #   2. BFS from every DEV_GROUP_NAMES-matched group through the
    #      include edges, building the closure of dev-reachable groups.
    #   3. Classify each group's plain entries as DEV iff its name is in
    #      that closure; everything else stays PROD.
    dep_groups = typed_field(filepath, data, "dependency-groups", dict)
    if dep_groups:
        group_strings: dict[str, list[str]] = {}
        include_edges: dict[str, set[str]] = {}
        for group_name, entries in dep_groups.items():
            if not isinstance(entries, list):
                record_unexpected_type(filepath, "an entry of dependency-groups")
                continue
            normalized = group_name.lower()
            strings: list[str] = []
            includes: set[str] = set()
            for entry in entries:
                inc = entry.get("include-group") if isinstance(entry, dict) else None
                if isinstance(entry, str):
                    strings.append(entry)
                elif isinstance(inc, str):
                    includes.add(inc.lower())
                else:
                    record_unexpected_type(filepath, "an entry of dependency-groups")
            group_strings[normalized] = strings
            include_edges[normalized] = includes
        dev_reachable: set[str] = set()
        queue = [g for g in group_strings if g in DEV_GROUP_NAMES]
        while queue:
            current = queue.pop()
            if current in dev_reachable:
                continue
            dev_reachable.add(current)
            queue.extend(include_edges.get(current, set()) - dev_reachable)
        for normalized, strings in group_strings.items():
            group = DependencyGroup.DEV if normalized in dev_reachable else DependencyGroup.PROD
            deps.extend(_extract_deps(strings, group, source, base_dir, scan_root))

    # uv: [tool.uv.sources] says where a requirement declared above comes
    # from. ``git`` / ``url`` / ``path`` take it off the registry; ``index``
    # leaves it a registry requirement; ``workspace = true`` and a path
    # that the scan reads make it the project's own code.
    sources = (inherited_sources or {}) | _uv_sources(filepath, data)
    if sources:
        declared, deps = deps, []
        for dep in declared:
            spec = sources.get(_pep503_normalize(dep.name))
            origin = (
                dep.origin
                if dep.origin or spec is None
                else _tables_origin(
                    filepath, spec, "an entry of tool.uv.sources", base_dir, scan_root
                )
            )
            if origin is None:
                own.append(dep.name)
            elif origin and not dep.origin:
                deps.append(replace(dep, origin=origin, version_constraint=""))
            else:
                deps.append(dep)

    # Poetry: [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies]
    poetry = _poetry_table(filepath, data)
    poetry_section = "tool.poetry.dependencies"
    poetry_deps = typed_field(filepath, poetry, "dependencies", dict, poetry_section) or {}
    # ``python`` is the interpreter constraint, not a package.
    poetry_deps = {name: spec for name, spec in poetry_deps.items() if name.lower() != "python"}
    deps.extend(
        _poetry_deps(
            filepath, poetry_deps, poetry_section, DependencyGroup.PROD, source, scan_root, own
        )
    )

    # Poetry groups
    groups_section = "tool.poetry.group"
    poetry_groups = typed_field(filepath, poetry, "group", dict, groups_section) or {}
    for group_name, group_data in poetry_groups.items():
        group = (
            DependencyGroup.DEV if group_name.lower() in DEV_GROUP_NAMES else DependencyGroup.PROD
        )
        entry_of = f"an entry of {groups_section}"
        if not isinstance(group_data, dict):
            record_unexpected_type(filepath, entry_of)
            continue
        group_deps_dict = typed_field(filepath, group_data, "dependencies", dict, entry_of) or {}
        deps.extend(
            _poetry_deps(filepath, group_deps_dict, groups_section, group, source, scan_root, own)
        )

    return deps, own


def discover_pyproject_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover dependencies from every pyproject.toml in the project tree.

    Python monorepos (uv workspaces, poetry workspaces, ad-hoc multi-package
    layouts such as a ``libs/*`` tree) declare deps in nested pyproject.toml
    files. Walk the tree, parse each, and filter out workspace-internal
    references (deps whose name matches another pyproject in the project).

    Self-referential exception: a pyproject that lists its own ``name`` as a
    dep targets the published-registry version of itself (e.g. doc builds
    pulling the installed wheel), not a workspace alias — that dep is
    preserved.

    A dependency declared from a path that the scan reads, or as
    a uv workspace member, is the project's own code and is not returned.

    Returns ``(deps, filtered_count)`` where ``filtered_count`` is the number
    of deps removed because their name matched a workspace-local package.
    """
    pyprojects = walk_project_files(project_path, "pyproject.toml", exclude_paths=exclude_paths)
    if not pyprojects:
        return [], 0

    local_names = _collect_local_python_names(pyprojects)

    parsed = [(pj, data) for pj in pyprojects if (data := load_toml(pj)) is not None]
    # A uv workspace root's ``[tool.uv.sources]`` applies to its members.
    workspaces = {
        pj.parent: workspace
        for pj, data in parsed
        if (workspace := _uv_workspace(pj, data)) is not None
    }

    deps: list[Dependency] = []
    owners: list[str] = []
    own: list[str] = []
    for pj, data in parsed:
        # Paths come from the walker rooted at project_path, so relative_to
        # is safe. ``as_posix`` keeps the JSON output cross-platform.
        source = pj.relative_to(project_path).as_posix()
        inherited = _workspace_sources(pj.parent, workspaces)
        pj_deps, pj_own = _parse_pyproject_deps(pj, data, source, project_path, inherited)
        owner = _pyproject_owner_name(pj, data)
        deps.extend(pj_deps)
        owners.extend([owner] * len(pj_deps))
        own.extend(pj_own)

    if not local_names:
        return deps, 0
    kept = [
        d
        for d, owner in zip(deps, owners, strict=True)
        if _pep503_normalize(d.name) not in local_names
        or (owner and _pep503_normalize(d.name) == owner)
    ]
    own_local = sum(_pep503_normalize(name) in local_names for name in own)
    return kept, len(deps) - len(kept) + own_local


def _pyproject_owner_name(filepath: Path, data: dict) -> str:
    """Return the PEP 503-normalized name a pyproject.toml declares for itself.

    PEP 621 ``[project].name`` takes precedence; Poetry's ``[tool.poetry].name``
    is the legacy form still seen on older packages.
    """
    for table in (_project_table(filepath, data), _poetry_table(filepath, data)):
        name = table.get("name")
        if isinstance(name, str) and name:
            return _pep503_normalize(name)
    return ""


def _collect_local_python_names(paths: list[Path]) -> set[str]:
    names: set[str] = set()
    for pj in paths:
        data = load_toml(pj)
        if data is None:
            continue
        name = _pyproject_owner_name(pj, data)
        if name:
            names.add(name)
    return names


def detect_project_license_pyproject(pyproject: Path) -> str:
    """Return the license one ``pyproject.toml`` declares for its project, or ``""``."""
    data = load_toml(pyproject)
    return "" if data is None else _detect_license_in_data(pyproject, data)


def _detect_license_in_data(filepath: Path, data: dict) -> str:
    """Read the project's license from one parsed pyproject.toml.

    The license fields describe the project, not a dependency: one of the
    wrong type reads as absent, which leaves the project at the strictest
    default rather than losing anything from the scan.
    """
    project = _project_table(filepath, data)

    # PEP 639: license field can be a string (SPDX) or dict with text/file
    license_val = project.get("license")
    if isinstance(license_val, str) and license_val:
        return license_val
    if isinstance(license_val, dict):
        text = license_val.get("text", "")
        if isinstance(text, str) and text:
            return text

    # Fallback: check classifiers
    classifiers = project.get("classifiers")
    for classifier in classifiers if isinstance(classifiers, list) else []:
        if isinstance(classifier, str) and classifier.startswith("License :: OSI Approved ::"):
            return classifier.split("::")[-1].strip()

    # Legacy Poetry layout: license lives under [tool.poetry] with no PEP 621.
    poetry_license = _poetry_table(filepath, data).get("license")
    if isinstance(poetry_license, str) and poetry_license:
        return poetry_license

    return ""
