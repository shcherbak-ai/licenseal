"""mix.lock parser.

Elixir's ``mix.lock`` is a static Elixir map literal — licenseal never executes
it (same rule that applies to every scan target). ``mix deps.get`` writes one
entry per line::

    %{
      "phoenix" => {:hex, :phoenix, "1.7.10", "innerhash", [:mix],
                    [{:plug, "~> 1.14", [...]}, ...], "hexpm", "outerhash"},
      "my_fork" => {:git, "https://github.com/me/dep.git", "commitsha", [branch: "main"]},
    }

A ``:hex`` tuple is a registry dep; its version is the third element and its
child-dependency edges are the bracketed list of ``{:child, "req", [opts]}``
tuples (the second ``[...]`` element, after the ``[:mix]`` build-tools list).
``:git`` / ``:path`` tuples are off-registry — they can't be resolved against
hex.pm, so the resolver short-circuits them to UNKNOWN.

``mix.lock`` carries no license and no dev/prod env — both live in ``mix.exs``.
So group attribution mirrors the Bundler model: the Mix-discovered dev-name set
is the DEV-root for reverse-BFS propagation through the lock's edge graph (a dep
reachable from any PROD root is PROD; otherwise from a DEV root is DEV;
otherwise — an orphan — PROD by conservative default).
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Source marker the resolver checks to short-circuit registry fetches on
# git/path-sourced deps. The transitive walker overwrites ``source`` with the
# human-readable manifest path for registry-backed direct deps; the marker only
# survives on entries whose origin is non-hex.pm.
_OFF_REGISTRY_MARKER = "__off_registry__"

# A top-level lock entry on one line. ``mix deps.get`` emits the keyword-style
# ``"name": {<tuple>}``; the equivalent map-literal ``"name" => {<tuple>}`` form
# is accepted too. The greedy body capture takes everything up to the final
# ``}`` on the line, tolerating a trailing comma.
_ENTRY_RE = re.compile(r'^\s*"(?P<name>[^"]+)"\s*(?::|=>)\s*\{(?P<body>.*)\}\s*,?\s*$')

_ATOM_RE = re.compile(r":(\w+)")
_STRING_RE = re.compile(r'"([^"]*)"')


def is_off_registry_marker(source: str) -> bool:
    """True for the off-registry source marker emitted by the lock parser."""
    return source == _OFF_REGISTRY_MARKER


def find_mix_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``mix.lock`` in the project tree (umbrella roots ship one)."""
    return walk_project_files(project_path, "mix.lock", exclude_paths=exclude_paths)


def _split_top_level(body: str) -> list[str]:
    """Split a tuple/list body on top-level commas.

    Respects nesting of ``() [] {}`` and double-quoted strings, so the commas
    inside a child-dep's ``[opts]`` list or a nested tuple don't fragment the
    split. Returns the stripped element substrings.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_str = False
    for ch in body:
        if in_str:
            current.append(ch)
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_line_comments(text: str, comment_char: str) -> str:
    """Drop ``<comment_char> ...`` line comments, preserving the marker in strings.

    Shared by the Elixir (``#``) and Erlang (``%``) manifest parsers. A
    ``comment_char`` inside a double-quoted string (a URL fragment, ``#{}``
    interpolation) is kept; comments are stripped before any bracket scan so a
    bracket inside a comment can't corrupt parsing.
    """
    out: list[str] = []
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif ch == comment_char:
            while i < n and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _first_atom(text: str) -> str:
    """Return the first ``:atom`` name in ``text`` (the leading tuple atom)."""
    m = _ATOM_RE.search(text)
    return m.group(1) if m else ""


def _unquote(text: str) -> str:
    """Strip surrounding double quotes from a string-literal element."""
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped[1:-1]
    return stripped


def _extract_edges(elements: list[str]) -> list[str]:
    """Return child dependency names from a ``:hex`` tuple's edge list.

    A ``:hex`` tuple has two bracketed-list elements: the build-tools list
    (``[:mix]``, bare atoms) and the dependency-edge list (``[{:child, ...}]``,
    tuples). The edge list is identified by content (its entries start with
    ``{``); a positional fallback (the second list element) covers the rare
    case where both are empty. This is robust to the tuple-arity variation
    across Elixir versions (older locks omit the trailing ``repo`` element).
    """
    list_elems = [e for e in elements if e.startswith("[")]
    edges_elem: str | None = None
    for elem in list_elems:
        inner = elem[1:-1].strip()
        if inner.startswith("{"):
            edges_elem = elem
            break
    if edges_elem is None and len(list_elems) >= 2:
        edges_elem = list_elems[1]
    if edges_elem is None:
        return []
    names: list[str] = []
    for child in _split_top_level(edges_elem[1:-1]):
        atom = _first_atom(child)
        if atom:
            names.append(atom)
    return names


def _parse_lock_tuple(body: str) -> tuple[str, str, list[str], bool]:
    """Parse a lock entry's ``{...}`` body → (hex_name, version, child_names, off_registry).

    ``{:hex, :name, "ver", ...}`` → registry dep. The 2nd element is the hex.pm
    *package* name (which differs from the lock key when the dep was renamed via
    ``hex:`` in mix.exs), the 3rd is the version, and the edges are the bracketed
    child-tuple list.
    ``{:git, ...}`` / ``{:path, ...}`` → off-registry (no registry version/edges).
    """
    elements = _split_top_level(body)
    if not elements:
        return "", "", [], False
    if elements[0] != ":hex":
        return "", "", [], True
    hex_name = _first_atom(elements[1]) if len(elements) > 1 else ""
    version = _unquote(elements[2]) if len(elements) > 2 else ""
    return hex_name, version, _extract_edges(elements), False


def _reachable(edges: dict[str, set[str]], roots: set[str]) -> set[str]:
    """Return every node reachable from any node in ``roots`` (BFS)."""
    if not roots:
        return set()
    reachable: set[str] = set(roots)
    front: set[str] = set(roots)
    while front:
        new_front: set[str] = set()
        for node in front:
            for child in edges.get(node, ()):
                if child in reachable:
                    continue
                reachable.add(child)
                new_front.add(child)
        front = new_front
    return reachable


def parse_mix_lock(
    path: Path,
    *,
    direct_names: set[str],
    dev_direct_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse ``mix.lock`` into Dependencies with edge-aware group attribution.

    ``direct_names`` is the lowercased set of dep names declared at the top
    level of any ``mix.exs`` in the project; ``dev_direct_names`` is the subset
    declared only in ``:dev`` / ``:test`` (``only:``) envs. Both feed the
    reverse-BFS that attributes group + direct ancestors per package. With
    ``include_dev=False`` the DEV-attributed entries are filtered out.
    """
    text = decode_text(path)
    if text is None:
        return []

    # name_lower -> (orig_name, registry_name, version, off_registry)
    spec_info: dict[str, tuple[str, str, str, bool]] = {}
    edges: dict[str, set[str]] = {}
    for raw_line in text.splitlines():
        m = _ENTRY_RE.match(raw_line)
        if m is None:
            continue
        name = m.group("name")
        normalized = name.lower()
        hex_name, version, child_names, off_registry = _parse_lock_tuple(m.group("body"))
        # A `:hex` tuple's 2nd element is the real hex.pm package name; it
        # differs from the lock key only when the dep was renamed (`hex:` in
        # mix.exs). The graph + display stay keyed on the lock key (the app
        # name) — edges and the mix.exs direct/dev root sets all reference it,
        # and `_walk_uncovered` covers it — while the dep carries the hex name
        # as `registry_name` so license resolution targets the right package.
        # Empty when not renamed (byte-identical output for the common case).
        reg_name = (
            hex_name if hex_name and not off_registry and hex_name.lower() != normalized else ""
        )
        spec_info.setdefault(normalized, (name, reg_name, version, off_registry))
        edges.setdefault(normalized, set()).update(c.lower() for c in child_names)

    if not spec_info:
        return []

    name_case = {lower: orig for lower, (orig, _reg, _ver, _off) in spec_info.items()}
    prod_root_names = direct_names - dev_direct_names
    dev_root_names = dev_direct_names & direct_names
    prod_reachable = _reachable(edges, prod_root_names)
    dev_reachable = _reachable(edges, dev_root_names) - prod_reachable

    roots_for_attribution = {n: name_case[n] for n in direct_names if n in name_case}
    ancestors = compute_direct_ancestors(edges, roots_for_attribution)

    out: list[Dependency] = []
    for normalized, (orig_name, reg_name, version, off_registry) in spec_info.items():
        is_direct = normalized in direct_names
        if normalized in dev_reachable:
            group = DependencyGroup.DEV
        elif normalized in prod_reachable:
            group = DependencyGroup.PROD
        elif is_direct:  # pragma: no cover - direct deps are always reachable from their own root
            group = DependencyGroup.DEV if normalized in dev_root_names else DependencyGroup.PROD
        else:
            # Orphan transitive (no path from any root) — conservative PROD,
            # matching the Bundler / Go orphan posture.
            group = DependencyGroup.PROD

        if group == DependencyGroup.DEV and not include_dev:
            continue

        out.append(
            Dependency(
                name=orig_name,
                version_constraint=f"=={version}" if version else "",
                ecosystem=Ecosystem.HEX,
                group=group,
                depth=0 if is_direct else 1,
                direct_ancestors=() if is_direct else ancestors.get(normalized, ()),
                source="" if not off_registry else _OFF_REGISTRY_MARKER,
                registry_name=reg_name,
            )
        )
    return out


def attach_direct_sources(
    deps: list[Dependency],
    direct_source_by_name: dict[str, str],
) -> list[Dependency]:
    """Stamp the discovery source path onto depth-0 lock-derived deps.

    Mirrors the Bundler path: depth-0 entries get the matching ``mix.exs`` /
    ``rebar.config`` source filename from discovery. Off-registry entries keep
    the off-registry marker.
    """
    out: list[Dependency] = []
    for dep in deps:
        if dep.depth != 0 or is_off_registry_marker(dep.source):
            out.append(dep)
            continue
        source = direct_source_by_name.get(dep.name.lower(), "")
        out.append(replace(dep, source=source) if source else dep)
    return out
