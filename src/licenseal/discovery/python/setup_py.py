"""Discover Python dependencies from setup.py files via AST inspection.

setup.py is Python *code*, but we only need a small slice of it — the literal
arguments handed to ``setup(...)``. We parse via ``ast.parse`` (no ``exec``,
no ``eval``) and extract:

* ``setup(license=<literal string>)`` — or a module-level Name resolving to
  one (``__license__ = "MIT"`` style).
* ``setup(install_requires=<literal list of strings>)`` — or a Name that
  resolves to a module-level literal list of strings, or ``list(<name>)``
  wrapping such a list.
* ``setup(install_requires=[deps["a"], deps["b"], ...])`` — list of subscript
  expressions against a literal dict. We resolve ``deps`` first in setup.py
  itself, then in sibling ``*dependency_versions_table*.py``-style files
  (a common convention for factoring pinned versions out of setup.py into
  a generated file).
* ``setup(extras_require=<literal dict>)`` — with the same name-and-subscript
  resolution applied to each dict value.

Non-literal constructs (DictComp, function calls, conditional logic) are
treated as unresolvable: the parser returns whatever it could resolve and
silently skips the rest rather than guess.
"""

from __future__ import annotations

import ast
from pathlib import Path

from licenseal.discovery._read import read_bytes
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python import DEV_GROUP_NAMES, parse_pep508_dep
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Sibling-file filename patterns checked when a `deps["x"]` subscript cannot
# be resolved within setup.py itself. Matches the common
# ``dependency_versions_table.py`` convention plus close variants.
_SIBLING_DEPS_FILE_PATTERNS = (
    "dependency_versions_table.py",
    "dependency_versions.py",
    "deps_table.py",
    "deps.py",
)


def _parse_ast(path: Path) -> ast.Module | None:
    """Parse a Python file to an AST. Returns None on any failure."""
    source = read_bytes(path)
    if source is None:
        return None
    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError:
        return None


def _module_assignments(tree: ast.Module) -> dict[str, ast.AST]:
    """Map of top-level `name = value` assignments → the value node."""
    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assignments[node.target.id] = node.value
    return assignments


def _extract_literal_dicts(tree: ast.Module) -> dict[str, dict[str, str]]:
    """Find every top-level `<name> = {literal str→str dict}` assignment.

    Non-literal dicts (DictComp, dicts with non-string keys/values) are
    excluded — we never speculate, only collect cleanly-typed registries.
    """
    out: dict[str, dict[str, str]] = {}
    for name, value in _module_assignments(tree).items():
        if not isinstance(value, ast.Dict):
            continue
        d: dict[str, str] = {}
        clean = True
        for k_node, v_node in zip(value.keys, value.values, strict=True):
            if not (
                isinstance(k_node, ast.Constant)
                and isinstance(k_node.value, str)
                and isinstance(v_node, ast.Constant)
                and isinstance(v_node.value, str)
            ):
                clean = False
                break
            d[k_node.value] = v_node.value
        if clean and d:
            out[name] = d
    return out


def _gather_dict_registry(setup_py: Path, tree: ast.Module) -> dict[str, dict[str, str]]:
    """Collect literal dicts visible to setup.py for subscript resolution.

    Pulls from setup.py itself first, then falls back to sibling files
    matching common deps-table naming conventions (``dependency_versions_table.py``,
    etc.) — a pattern several large Python packages use to factor pinned
    version strings into an auto-generated file.
    """
    registry = _extract_literal_dicts(tree)
    # Search siblings of setup.py and one level below `src/` for known
    # deps-table filenames. Bounded scan — no general .py walk.
    for sibling_pattern in _SIBLING_DEPS_FILE_PATTERNS:
        for candidate in setup_py.parent.glob(f"**/{sibling_pattern}"):
            if not candidate.is_file():
                continue
            sibling_tree = _parse_ast(candidate)
            if sibling_tree is None:
                continue
            for k, v in _extract_literal_dicts(sibling_tree).items():
                registry.setdefault(k, v)
    return registry


def _resolve_to_list_of_strings(
    node: ast.AST,
    module: dict[str, ast.AST],
    dict_registry: dict[str, dict[str, str]],
) -> list[str] | None:
    """Try to resolve an AST node to a list of string literals.

    Handles:
      * ``ast.List`` of string ``Constant``s — direct literal.
      * ``ast.List`` of ``Subscript(Name(id='deps'), Constant(key))`` —
        resolved through ``dict_registry``.
      * ``ast.Name`` — re-resolved via module-level assignments.
      * ``ast.Call`` whose func is ``list`` and the only arg resolves to a
        list of strings (the ``install_requires=list(install_requires)``
        idiom seen in some large Python packages).

    Returns None if the node can't be resolved cleanly.
    """
    if isinstance(node, ast.List):
        out: list[str] = []
        for elt in node.elts:
            value = _resolve_string(elt, dict_registry)
            if value is None:
                continue  # skip individual unresolvable elements, keep rest
            out.append(value)
        return out
    if isinstance(node, ast.Name):
        target = module.get(node.id)
        if target is None:
            return None
        return _resolve_to_list_of_strings(target, module, dict_registry)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "list"
        and len(node.args) == 1
    ):
        return _resolve_to_list_of_strings(node.args[0], module, dict_registry)
    return None


def _resolve_string(node: ast.AST, dict_registry: dict[str, dict[str, str]]) -> str | None:
    """Resolve a single AST node to a string literal. Returns None if dynamic."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        key_node = node.slice
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            dct = dict_registry.get(node.value.id)
            if dct is not None and key_node.value in dct:
                return dct[key_node.value]
    return None


def _resolve_to_string(
    node: ast.AST, module: dict[str, ast.AST], dict_registry: dict[str, dict[str, str]]
) -> str | None:
    """Resolve an AST node to a string, following Name references one level."""
    direct = _resolve_string(node, dict_registry)
    if direct is not None:
        return direct
    if isinstance(node, ast.Name):
        target = module.get(node.id)
        if target is not None:
            return _resolve_string(target, dict_registry)
    return None


def _resolve_to_dict_of_lists(
    node: ast.AST,
    module: dict[str, ast.AST],
    dict_registry: dict[str, dict[str, str]],
) -> dict[str, list[str]] | None:
    """Resolve a node to a ``dict[str, list[str]]`` (for extras_require).

    Only literal Dict nodes with string keys are extracted. Values may be
    literal lists, Name references to literal lists, or subscript-resolved
    lists — same machinery as ``install_requires`` resolution. Non-literal
    entries are silently skipped (so a partially dynamic extras dict still
    yields whatever it could resolve).
    """
    if isinstance(node, ast.Name):
        target = module.get(node.id)
        if target is None:
            return None
        return _resolve_to_dict_of_lists(target, module, dict_registry)
    if not isinstance(node, ast.Dict):
        return None
    out: dict[str, list[str]] = {}
    for k_node, v_node in zip(node.keys, node.values, strict=True):
        if not (isinstance(k_node, ast.Constant) and isinstance(k_node.value, str)):
            continue
        values = _resolve_to_list_of_strings(v_node, module, dict_registry)
        if values is None:
            continue
        out[k_node.value] = values
    return out


def _find_setup_call(tree: ast.Module) -> ast.Call | None:
    """Locate the ``setup(...)`` call at module level. Returns None if absent."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Direct `setup(...)` after `from setuptools import setup`.
        if isinstance(func, ast.Name) and func.id == "setup":
            return node
        # Attribute form: `setuptools.setup(...)`.
        if isinstance(func, ast.Attribute) and func.attr == "setup":
            return node
    return None


def _emit_deps(
    strings: list[str], group: DependencyGroup, source: str, out: list[Dependency]
) -> None:
    for raw in strings:
        name, version, extras = parse_pep508_dep(raw)
        if not name:
            continue
        out.append(
            Dependency(
                name=name,
                version_constraint=version,
                ecosystem=Ecosystem.PYTHON,
                group=group,
                source=source,
                extras=extras,
            )
        )


def _extract_setup_py(path: Path, source: str) -> tuple[list[Dependency], str]:
    """Return ``(deps, license_str)`` extracted from a single setup.py file."""
    tree = _parse_ast(path)
    if tree is None:
        return [], ""
    setup_call = _find_setup_call(tree)
    if setup_call is None:
        return [], ""

    module = _module_assignments(tree)
    dict_registry = _gather_dict_registry(path, tree)

    deps: list[Dependency] = []
    license_str = ""
    classifiers: list[str] | None = None

    for kw in setup_call.keywords:
        if kw.arg == "license":
            resolved = _resolve_to_string(kw.value, module, dict_registry)
            if resolved:
                license_str = resolved
        elif kw.arg == "classifiers":
            classifiers = _resolve_to_list_of_strings(kw.value, module, dict_registry)
        elif kw.arg == "install_requires":
            resolved_list = _resolve_to_list_of_strings(kw.value, module, dict_registry)
            if resolved_list is not None:
                _emit_deps(resolved_list, DependencyGroup.PROD, source, deps)
        elif kw.arg == "extras_require":
            resolved_dict = _resolve_to_dict_of_lists(kw.value, module, dict_registry)
            if resolved_dict is not None:
                for extra_name, extra_deps in resolved_dict.items():
                    group = (
                        DependencyGroup.DEV
                        if extra_name.lower() in DEV_GROUP_NAMES
                        else DependencyGroup.PROD
                    )
                    _emit_deps(extra_deps, group, source, deps)

    # Fallback to the trove ``License :: OSI Approved :: ...`` classifier when
    # there is no explicit ``license=`` kwarg. Mirrors the pyproject.toml
    # detection path so setup.py-based projects that publish their license via
    # classifiers (the historical legacy pattern) aren't misclassified as
    # Proprietary.
    if not license_str and classifiers is not None:
        for classifier in classifiers:
            if classifier.startswith("License :: OSI Approved ::"):
                license_str = classifier.split("::")[-1].strip()
                break

    return deps, license_str


def discover_setup_py_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Dependency]:
    """Discover Python dependencies from every setup.py in the project tree.

    Walks recursively (mirroring the pyproject.toml walker) so monorepo
    layouts with nested setup.py files are covered.
    """
    deps: list[Dependency] = []
    for setup_py in walk_project_files(project_path, "setup.py", exclude_paths=exclude_paths):
        source = setup_py.relative_to(project_path).as_posix()
        file_deps, _ = _extract_setup_py(setup_py, source)
        deps.extend(file_deps)
    return deps


def detect_project_license_setup_py(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Detect the project's own license from setup.py's ``setup(license=...)``."""
    for setup_py in walk_project_files(project_path, "setup.py", exclude_paths=exclude_paths):
        source = setup_py.relative_to(project_path).as_posix()
        _, license_str = _extract_setup_py(setup_py, source)
        if license_str:
            return license_str
    return ""
