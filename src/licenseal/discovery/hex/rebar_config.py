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
``{name, Source}`` with a source tuple, optionally after a version pattern.
Every source tuple but ``{pkg, …}`` is emitted with an ``origin`` and never
looked up: ``{git, …}`` (also ``git_subdir``, ``hg``, and any other tuple
that holds a location string) with the repository, ``{path, …}`` with the
path, and a tuple that holds no location as an unrecorded source. A
``{path, …}`` that the scan reads is the project's own code and is not a
dependency. The other entries resolve from hex.pm.
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
from licenseal.discovery.hex.rebar_lock import _balanced_braces, source_origin  # noqa: PLC2701
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Key of a package name in the name sets below (see ``Ecosystem.identity``).
_key = Ecosystem.HEX.identity

# Leading lowercase atom (a dep name or the ``pkg`` hex-rename target).
_ATOM_RE = re.compile(r"[a-z][a-zA-Z0-9_]*")
# ``{pkg, hexname, ...}`` — the real hex package name to resolve.
_PKG_NAME_RE = re.compile(r"\{\s*pkg\s*,\s*([a-z][a-zA-Z0-9_]*)")
_STRING_RE = re.compile(r'"([^"]*)"')
# The one source tuple that names a hex.pm package.
_HEX_SOURCE_RE = re.compile(r"\{\s*pkg\b")
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


def _parse_dep(entry: str, config_dir: Path, scan_root: Path) -> tuple[str, str, str | None]:
    """Parse one dep entry of a ``rebar.config`` in ``config_dir`` → (name, version, origin).

    The origin is empty for a hex.pm package and ``None`` for a ``{path, …}``
    source that the scan reads.
    """
    entry = entry.strip()
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
    # The source is the tuple after the name, or after the version pattern
    # that an entry can put between the two.
    source = next((e for e in _elements(entry, "{}")[1:] if e.startswith("{")), "")
    if source and not _HEX_SOURCE_RE.match(source):
        return name, "", source_origin(source, config_dir, scan_root)
    sm = _STRING_RE.search(entry)
    return name, sm.group(1).strip() if sm else "", ""


def _parse_rebar_config_text(
    text: str, source: str, config_dir: Path, scan_root: Path
) -> tuple[list[Dependency], list[str]]:
    """Parse the body of a ``rebar.config`` in ``config_dir`` into direct Dependencies.

    Returns ``(deps, own)``: ``own`` names the entries whose source is a path
    that the scan reads, which are the project's own code.
    """
    terms = _top_level_terms(_strip_line_comments(text, "%"))

    out: list[Dependency] = []
    own: list[str] = []
    seen: set[tuple[str, str]] = set()

    def _emit(dep_list: str, group: DependencyGroup) -> None:
        """Add the entries of one ``{deps, [...]}`` value, each once per group."""
        for entry in _elements(dep_list, "[]"):
            name, version, origin = _parse_dep(entry, config_dir, scan_root)
            key = (_key(name), group.value)
            if not name or key in seen:
                continue
            seen.add(key)
            if origin is None:
                own.append(name)
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

    for dep_list in _values_for(terms, "deps"):
        _emit(dep_list, DependencyGroup.PROD)
    for profiles in _values_for(terms, "profiles"):
        for profile in _elements(profiles, "[]"):
            # ``{Name, [Options]}``. Only ``test`` / ``dev`` are development
            # profiles; every other name is a production profile.
            elements = _elements(profile, "{}")
            if len(elements) != 2:
                continue
            group = DependencyGroup.DEV if elements[0] in _DEV_PROFILES else DependencyGroup.PROD
            for dep_list in _values_for(_elements(elements[1], "[]"), "deps"):
                _emit(dep_list, group)
    return out, own


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
        deps, own = _parse_rebar_config_text(text, source, rebar_config.parent, project_path)
        filtered += sum(_key(name) in workspace_names for name in own)
        for dep in deps:
            if dep.identity in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered
