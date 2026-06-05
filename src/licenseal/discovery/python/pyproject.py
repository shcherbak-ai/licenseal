"""Discover Python dependencies from pyproject.toml files."""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python import DEV_GROUP_NAMES, parse_pep508_dep
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# PEP 503: collapse runs of `-`, `_`, `.` to a single `-` and lowercase.
_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")


def _pep503_normalize(name: str) -> str:
    return _PEP503_NORMALIZE_RE.sub("-", name).lower()


def _poetry_version(spec: str | dict[str, str]) -> str:
    """Extract version constraint from a Poetry dependency spec."""
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return spec.get("version", "")
    return ""


def _poetry_extras(spec: str | dict) -> frozenset[str]:
    """Extract extras from a Poetry dependency spec.

    Poetry's structured form ``{"version" = "^2", "extras" = ["socks"]}``
    carries extras explicitly. String specs (``"^2.0"``) carry none.
    """
    if isinstance(spec, dict):
        extras = spec.get("extras")
        if isinstance(extras, list):
            return frozenset(e for e in extras if isinstance(e, str))
    return frozenset()


def _extract_deps(dep_list: list[str], group: DependencyGroup, source: str) -> list[Dependency]:
    """Convert a list of PEP 508 strings to Dependency objects."""
    deps = []
    for dep_str in dep_list:
        if not isinstance(dep_str, str):
            continue
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


def _parse_pyproject_deps(data: dict, source: str) -> list[Dependency]:
    """Extract dependencies from a single parsed pyproject.toml data dict."""
    deps: list[Dependency] = []

    # PEP 621: [project.dependencies]
    project = data.get("project", {})
    deps.extend(_extract_deps(project.get("dependencies", []), DependencyGroup.PROD, source))

    # PEP 621: [project.optional-dependencies]
    optional = project.get("optional-dependencies", {})
    for group_name, group_deps in optional.items():
        group = (
            DependencyGroup.DEV if group_name.lower() in DEV_GROUP_NAMES else DependencyGroup.PROD
        )
        deps.extend(_extract_deps(group_deps, group, source))

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
    dep_groups = data.get("dependency-groups", {})
    if isinstance(dep_groups, dict) and dep_groups:
        group_strings: dict[str, list[str]] = {}
        include_edges: dict[str, set[str]] = {}
        for group_name, entries in dep_groups.items():
            if not isinstance(group_name, str) or not isinstance(entries, list):
                continue
            normalized = group_name.lower()
            strings: list[str] = []
            includes: set[str] = set()
            for entry in entries:
                if isinstance(entry, str):
                    strings.append(entry)
                elif isinstance(entry, dict):
                    inc = entry.get("include-group")
                    if isinstance(inc, str):
                        includes.add(inc.lower())
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
    tool = data.get("tool", {})
    poetry = tool.get("poetry", {})
    poetry_deps = poetry.get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        deps.append(
            Dependency(
                name=name,
                version_constraint=_poetry_version(spec),
                ecosystem=Ecosystem.PYTHON,
                group=DependencyGroup.PROD,
                source=source,
                extras=_poetry_extras(spec),
            )
        )

    # Poetry groups
    poetry_groups = poetry.get("group", {})
    for group_name, group_data in poetry_groups.items():
        group = (
            DependencyGroup.DEV if group_name.lower() in DEV_GROUP_NAMES else DependencyGroup.PROD
        )
        group_deps_dict = group_data.get("dependencies", {})
        for name, spec in group_deps_dict.items():
            deps.append(
                Dependency(
                    name=name,
                    version_constraint=_poetry_version(spec),
                    ecosystem=Ecosystem.PYTHON,
                    group=group,
                    source=source,
                    extras=_poetry_extras(spec),
                )
            )

    return deps


def discover_pyproject_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover dependencies from every pyproject.toml in the project tree.

    Python monorepos (uv workspaces, poetry workspaces, ad-hoc multi-package
    layouts like LangChain's libs/*) declare deps in nested pyproject.toml
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
        pj_deps = _parse_pyproject_deps(data, source)
        owner = _pyproject_owner_name(data)
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


def _pyproject_owner_name(data: dict) -> str:
    """Return the PEP 503-normalized name a pyproject.toml declares for itself."""
    project = data.get("project") or {}
    name = project.get("name") if isinstance(project, dict) else None
    if not (isinstance(name, str) and name):
        poetry = (data.get("tool") or {}).get("poetry") or {}
        name = poetry.get("name") if isinstance(poetry, dict) else None
    if isinstance(name, str) and name:
        return _pep503_normalize(name)
    return ""


def _collect_local_python_names(paths: list[Path]) -> set[str]:
    names: set[str] = set()
    for pj in paths:
        data = load_toml(pj)
        if data is None:
            continue
        # PEP 621 [project].name takes precedence; Poetry's [tool.poetry].name
        # is the legacy form still seen on older packages.
        project = data.get("project") or {}
        name = project.get("name") if isinstance(project, dict) else None
        if not (isinstance(name, str) and name):
            poetry = (data.get("tool") or {}).get("poetry") or {}
            name = poetry.get("name") if isinstance(poetry, dict) else None
        if isinstance(name, str) and name:
            names.add(_pep503_normalize(name))
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
        license_str = _detect_license_in_data(data)
        if license_str:
            return license_str
    return ""


def _detect_license_in_data(data: dict) -> str:
    project = data.get("project", {})

    # PEP 639: license field can be a string (SPDX) or dict with text/file
    license_val = project.get("license")
    if isinstance(license_val, str) and license_val:
        return license_val
    if isinstance(license_val, dict):
        text = license_val.get("text", "")
        if text:
            return text

    # Fallback: check classifiers
    classifiers = project.get("classifiers", [])
    for classifier in classifiers:
        if classifier.startswith("License :: OSI Approved ::"):
            return classifier.split("::")[-1].strip()

    # Legacy Poetry layout: license lives under [tool.poetry] with no PEP 621.
    poetry = data.get("tool", {}).get("poetry", {})
    poetry_license = poetry.get("license")
    if isinstance(poetry_license, str) and poetry_license:
        return poetry_license

    return ""
