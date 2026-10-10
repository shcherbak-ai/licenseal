"""Static ``rebar.config`` parser (Erlang / rebar3).

``rebar.config`` is an Erlang-terms file — licenseal never executes it. The
load-bearing terms are::

    {deps, [cowlib, {ranch, "1.8.0"}, {jsx, {git, "...", {tag, "v3.1.0"}}}]}.
    {profiles, [{test, [{deps, [{meck, "0.9.2"}]}]}, {prod, [{deps, [...]}]}]}.

The top-level ``{deps, [...]}`` lists production dependencies. Deps inside a
``test`` / ``dev`` profile are development dependencies (the rebar3
convention); deps inside any other profile are production. Only top-level
terms are read: a ``{deps, [...]}`` nested in another term (an ``overrides``
entry that rewrites one dependency's own configuration) is not the project's
dependency list.

Dep entries come as a bare atom, ``{name, "version"}``, ``{name, "version",
[opts]}``, ``{name, {pkg, hexname, "version"}}`` (hex package rename), or
``{name, {git, ...}}`` (also ``git_subdir`` and ``hg``). The source-control
forms are emitted with an ``origin`` and never looked up; the others resolve
from hex.pm.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.hex.mix_lock import (  # noqa: PLC2701
    _split_top_level,
    _strip_line_comments,
)
from licenseal.discovery.hex.rebar_lock import _balanced_braces, scm_origin  # noqa: PLC2701
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Leading lowercase atom (a dep name or the ``pkg`` hex-rename target).
_ATOM_RE = re.compile(r"[a-z][a-zA-Z0-9_]*")
# ``{pkg, hexname, ...}`` — the real hex package name to resolve.
_PKG_NAME_RE = re.compile(r"\{\s*pkg\s*,\s*([a-z][a-zA-Z0-9_]*)")
_STRING_RE = re.compile(r'"([^"]*)"')
# A source-control source inside a dep entry: ``{git, …}``, ``{git_subdir, …}``,
# ``{hg, …}``.
_SCM_RE = re.compile(r"\{\s*(?:git|git_subdir|hg)\s*,")
# rebar3 profiles whose deps are development-only.
_DEV_PROFILES = ("test", "dev")


def _top_level_terms(text: str) -> list[str]:
    """Return every top-level ``{...}`` term of an Erlang-terms file, braces included.

    Stops at a term whose braces never close (a truncated file).
    """
    terms: list[str] = []
    pos = 0
    while (start := text.find("{", pos)) != -1:
        body = _balanced_braces(text, start)
        if body is None:
            break
        pos = start + len(body) + 2
        terms.append(text[start:pos])
    return terms


def _elements(term: str, brackets: str) -> list[str]:
    """Return the top-level elements of the ``[...]`` or ``{...}`` literal ``term``.

    ``brackets`` is the pair expected around it. A term of any other shape has
    no elements.
    """
    term = term.strip()
    if not (term.startswith(brackets[0]) and term.endswith(brackets[1])):
        return []
    return _split_top_level(term[1:-1])


def _values_for(terms: list[str], key: str) -> list[str]:
    """Return ``Value`` from every ``{key, Value}`` 2-tuple among ``terms``."""
    out: list[str] = []
    for term in terms:
        elements = _elements(term, "{}")
        if len(elements) == 2 and elements[0] == key:
            out.append(elements[1])
    return out


def _parse_dep(entry: str) -> tuple[str, str, str]:
    """Parse one dep entry → (name, version, origin); the origin is empty for hex.pm."""
    entry = entry.strip()
    if not entry:
        return "", "", ""
    scm = _SCM_RE.search(entry)
    origin = scm_origin(entry[scm.start() :]) if scm else ""
    if not entry.startswith("{"):
        # Bare atom dep, e.g. ``cowlib`` (latest).
        m = _ATOM_RE.match(entry)
        return (m.group(0), "", "") if m else ("", "", "")
    pkg = _PKG_NAME_RE.search(entry)
    if pkg:
        name = pkg.group(1)  # hex-rename target
    else:
        m = _ATOM_RE.match(entry[1:].strip())
        name = m.group(0) if m else ""
    if not name:
        return "", "", ""
    version = ""
    if not origin:
        sm = _STRING_RE.search(entry)
        version = sm.group(1).strip() if sm else ""
    return name, version, origin


def _parse_dep_list(dep_list: str, group: DependencyGroup, source: str) -> list[Dependency]:
    """Parse the ``[...]`` value of a ``{deps, [...]}`` term into Dependencies."""
    out: list[Dependency] = []
    for entry in _elements(dep_list, "[]"):
        name, version, origin = _parse_dep(entry)
        if not name:
            continue
        out.append(
            Dependency(
                name=name,
                version_constraint=version,
                ecosystem=Ecosystem.HEX,
                group=group,
                source=source,
                origin=origin,
            )
        )
    return out


def _parse_rebar_config_text(text: str, source: str) -> list[Dependency]:
    """Parse a ``rebar.config`` body into direct Dependencies."""
    terms = _top_level_terms(_strip_line_comments(text, "%"))

    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()

    def _emit(deps: list[Dependency]) -> None:
        for dep in deps:
            key = (dep.name.lower(), dep.group.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(dep)

    for dep_list in _values_for(terms, "deps"):
        _emit(_parse_dep_list(dep_list, DependencyGroup.PROD, source))
    for profiles in _values_for(terms, "profiles"):
        for profile in _elements(profiles, "[]"):
            # ``{Name, [Options]}``. Only ``test`` / ``dev`` are development
            # profiles; every other name is a production profile.
            elements = _elements(profile, "{}")
            if len(elements) != 2:
                continue
            group = DependencyGroup.DEV if elements[0] in _DEV_PROFILES else DependencyGroup.PROD
            for dep_list in _values_for(_elements(elements[1], "[]"), "deps"):
                _emit(_parse_dep_list(dep_list, group, source))
    return out


def discover_rebar_config_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    workspace_names: frozenset[str] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct deps from every ``rebar.config`` in the tree."""
    out: list[Dependency] = []
    filtered = 0
    for rebar_config in walk_project_files(
        project_path, "rebar.config", exclude_paths=exclude_paths
    ):
        text = decode_text(rebar_config)
        if text is None:
            continue
        source = rebar_config.relative_to(project_path).as_posix()
        for dep in _parse_rebar_config_text(text, source):
            if dep.name.lower() in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered
