"""Discover Python dependencies from pyproject.toml files."""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import load_toml, record_unexpected_type, typed_field
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python import DEV_GROUP_NAMES, parse_pep508_dep, table_spec
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# PEP 503: collapse runs of `-`, `_`, `.` to a single `-` and lowercase.
_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")


def _pep503_normalize(name: str) -> str:
    return _PEP503_NORMALIZE_RE.sub("-", name).lower()


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


def _extract_deps(dep_list: list[str], group: DependencyGroup, source: str) -> list[Dependency]:
    """Convert a list of PEP 508 strings to Dependency objects."""
    deps = []
    for dep_str in dep_list:
        name, version, extras = parse_pep508_dep(dep_str)
        if name:
            deps.append(
                Dependency(
                    name=name,
                    version_constraint=version,
                    ecosystem=Ecosystem.PYTHON,
                    group=group,
                    source=source,
                    extras=extras,
                )
            )
    return deps


def _poetry_deps(
    filepath: Path, table: dict, section: str, group: DependencyGroup, source: str
) -> list[Dependency]:
    """Convert a Poetry dependency table (name → spec) to Dependency objects."""
    deps = []
    for name, spec in table.items():
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
                version_constraint=version,
                ecosystem=Ecosystem.PYTHON,
                group=group,
                source=source,
                extras=extras,
            )
        )
    return deps


def _parse_pyproject_deps(filepath: Path, data: dict, source: str) -> list[Dependency]:
    """Extract dependencies from a single parsed pyproject.toml data dict.

    A section or an entry that is not the type its format defines is
    recorded as a gap on ``filepath`` and read as absent; every other section
    is still read.
    """
    deps: list[Dependency] = []

    # PEP 621: [project.dependencies]
    project = _project_table(filepath, data)
    prod_deps = _string_list(filepath, project.get("dependencies"), "project.dependencies")
    deps.extend(_extract_deps(prod_deps, DependencyGroup.PROD, source))

    # PEP 621: [project.optional-dependencies]
    optional_section = "project.optional-dependencies"
    optional = typed_field(filepath, project, "optional-dependencies", dict, optional_section) or {}
    for group_name, group_deps in optional.items():
        group = (
            DependencyGroup.DEV if group_name.lower() in DEV_GROUP_NAMES else DependencyGroup.PROD
        )
        extra_deps = _string_list(filepath, group_deps, optional_section, entry=True)
        deps.extend(_extract_deps(extra_deps, group, source))

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
            deps.extend(_extract_deps(strings, group, source))

    # Poetry: [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies]
    poetry = _poetry_table(filepath, data)
    poetry_section = "tool.poetry.dependencies"
    poetry_deps = typed_field(filepath, poetry, "dependencies", dict, poetry_section) or {}
    # ``python`` is the interpreter constraint, not a package.
    poetry_deps = {name: spec for name, spec in poetry_deps.items() if name.lower() != "python"}
    deps.extend(_poetry_deps(filepath, poetry_deps, poetry_section, DependencyGroup.PROD, source))

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
        deps.extend(_poetry_deps(filepath, group_deps_dict, groups_section, group, source))

    return deps


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

    Returns ``(deps, filtered_count)`` where ``filtered_count`` is the number
    of deps removed because their name matched a workspace-local package.
    """
    pyprojects = walk_project_files(project_path, "pyproject.toml", exclude_paths=exclude_paths)
    if not pyprojects:
        return [], 0

    local_names = _collect_local_python_names(pyprojects)

    deps: list[Dependency] = []
    owners: list[str] = []
    for pj in pyprojects:
        data = load_toml(pj)
        if data is None:
            continue
        # Paths come from the walker rooted at project_path, so relative_to
        # is safe. ``as_posix`` keeps the JSON output cross-platform.
        source = pj.relative_to(project_path).as_posix()
        pj_deps = _parse_pyproject_deps(pj, data, source)
        owner = _pyproject_owner_name(pj, data)
        deps.extend(pj_deps)
        owners.extend([owner] * len(pj_deps))

    if not local_names:
        return deps, 0
    kept = [
        d
        for d, owner in zip(deps, owners, strict=True)
        if _pep503_normalize(d.name) not in local_names
        or (owner and _pep503_normalize(d.name) == owner)
    ]
    return kept, len(deps) - len(kept)


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


def detect_project_license_pyproject(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Detect the project's own license from pyproject.toml.

    Walks the tree for monorepo layouts; returns the first non-empty license
    found in walk order (root first, then sub-packages depth-first).
    """
    for pj in walk_project_files(project_path, "pyproject.toml", exclude_paths=exclude_paths):
        data = load_toml(pj)
        if data is None:
            continue
        license_str = _detect_license_in_data(pj, data)
        if license_str:
            return license_str
    return ""


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
