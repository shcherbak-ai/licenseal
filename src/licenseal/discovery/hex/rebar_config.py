"""Static ``rebar.config`` parser (Erlang / rebar3).

``rebar.config`` is an Erlang-terms file — licenseal never executes it. The
load-bearing terms are::

    {deps, [cowlib, {ranch, "1.8.0"}, {jsx, {git, "...", {tag, "v3.1.0"}}}]}.
    {profiles, [{test, [{deps, [{meck, "0.9.2"}]}]}, {dev, [{deps, [...]}]}]}.

The top-level ``{deps, [...]}`` lists production dependencies; deps inside a
``test`` / ``dev`` profile are development dependencies (the rebar3 convention).
Dep entries come as a bare atom, ``{name, "version"}``, ``{name, "version",
[opts]}``, ``{name, {pkg, hexname, "version"}}`` (hex package rename), or
``{name, {git, ...}}`` (off-registry). All resolve from hex.pm.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.hex.mix_lock import (  # noqa: PLC2701
    _OFF_REGISTRY_MARKER,
    _split_top_level,
    _strip_line_comments,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Leading lowercase atom (a dep name or the ``pkg`` hex-rename target).
_ATOM_RE = re.compile(r"[a-z][a-zA-Z0-9_]*")
# ``{pkg, hexname, ...}`` — the real hex package name to resolve.
_PKG_NAME_RE = re.compile(r"\{\s*pkg\s*,\s*([a-z][a-zA-Z0-9_]*)")
_STRING_RE = re.compile(r'"([^"]*)"')
# rebar3 profiles whose deps are development-only.
_DEV_PROFILES = ("test", "dev")


def _extract_braced_list_value(text: str, key: str) -> str | None:
    """Return the body of the ``[...]`` following ``{key,`` in ``text``."""
    m = re.search(r"\{\s*" + re.escape(key) + r"\s*,", text)
    if m is None:
        return None
    start = text.find("[", m.end())
    if start == -1:
        return None  # pragma: no cover - {key,...} is always followed by a list
    depth = 0
    in_str = False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[start + 1 : j]
    return None  # pragma: no cover - unbalanced brackets don't occur in valid configs


def _parse_dep(entry: str) -> tuple[str, str, bool]:
    """Parse one dep entry → (name, version, off_registry)."""
    entry = entry.strip()
    if not entry:
        return "", "", False
    off_registry = "{git" in entry  # covers {git, ...} and {git_subdir, ...}
    if not entry.startswith("{"):
        # Bare atom dep, e.g. ``cowlib`` (latest).
        m = _ATOM_RE.match(entry)
        return (m.group(0), "", False) if m else ("", "", False)
    pkg = _PKG_NAME_RE.search(entry)
    if pkg:
        name = pkg.group(1)  # hex-rename target
    else:
        m = _ATOM_RE.match(entry[1:].strip())
        name = m.group(0) if m else ""
    if not name:
        return "", "", False
    version = ""
    if not off_registry:
        sm = _STRING_RE.search(entry)
        version = sm.group(1).strip() if sm else ""
    return name, version, off_registry


def _parse_dep_list(body: str, group: DependencyGroup, source: str) -> list[Dependency]:
    out: list[Dependency] = []
    for entry in _split_top_level(body):
        name, version, off_registry = _parse_dep(entry)
        if not name:
            continue
        out.append(
            Dependency(
                name=name,
                version_constraint=version,
                ecosystem=Ecosystem.HEX,
                group=group,
                source=_OFF_REGISTRY_MARKER if off_registry else source,
            )
        )
    return out


def _parse_rebar_config_text(text: str, source: str) -> list[Dependency]:
    """Parse a ``rebar.config`` body into direct Dependencies."""
    text = _strip_line_comments(text, "%")
    profiles_body = _extract_braced_list_value(text, "profiles")

    # Isolate the top-level deps from any profile deps before the lookup.
    prod_text = text.replace(profiles_body, "") if profiles_body is not None else text
    prod_body = _extract_braced_list_value(prod_text, "deps")

    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()

    def _emit(deps: list[Dependency]) -> None:
        for dep in deps:
            key = (dep.name.lower(), dep.group.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(dep)

    if prod_body is not None:
        _emit(_parse_dep_list(prod_body, DependencyGroup.PROD, source))
    if profiles_body is not None:
        for profile in _DEV_PROFILES:
            profile_body = _extract_braced_list_value(profiles_body, profile)
            if profile_body is None:
                continue
            deps_body = _extract_braced_list_value(profile_body, "deps")
            if deps_body is not None:
                _emit(_parse_dep_list(deps_body, DependencyGroup.DEV, source))
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
