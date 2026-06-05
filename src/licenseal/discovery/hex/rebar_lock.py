"""rebar.lock parser (Erlang / rebar3).

``rebar.lock`` is an Erlang-terms file. Unlike Elixir's ``mix.lock`` it carries
a per-entry **depth level** but **no parent→child edges**, so attribution is
level/section-based (the Pipfile.lock shape), not edge-aware:

    {"1.2.0",
    [{<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>},0},
     {<<"meck">>,{pkg,<<"meck">>,<<"0.9.2">>},1}]}.
    [{pkg_hash,[{<<"cowlib">>,<<"...">>}]},{pkg_hash_ext,[...]}].

Each lock entry is ``{<<"name">>, <source>, Level}`` — a 3-tuple whose last
element is the integer dependency level (0 = direct, ≥1 = transitive). The
2-tuple ``{<<"name">>,<<"hash">>}`` entries in the trailing ``pkg_hash``
sections are distinguished by arity and skipped. ``{pkg, …}`` sources are
registry-backed; ``{git, …}`` sources are off-registry.

Group attribution: level-0 (direct) entries are PROD unless the name is in the
``rebar.config`` test/dev-profile set; level-≥1 transitives default to PROD with
no ancestors (no edge data — same conservative posture as Pipfile.lock).
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

_BINARY_RE = re.compile(r'<<"([^"]*)">>')


def find_rebar_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``rebar.lock`` in the project tree."""
    return walk_project_files(project_path, "rebar.lock", exclude_paths=exclude_paths)


def _balanced_braces(text: str, start: int) -> str | None:
    """Return the inner text of the ``{...}`` beginning at ``start``.

    Respects nested ``() [] {}`` and double-quoted strings. Returns None on an
    unbalanced (truncated) tuple.
    """
    depth = 0
    in_str = False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : j]
    return None


def _parse_lock_entry(elements: list[str]) -> tuple[str, str, int, bool]:
    """``[<<"name">>, <source>, Level]`` → (name, version, level, off_registry)."""
    level = int(elements[2].strip())
    # elements[0] is always a ``<<"name">>`` binary (the entry only reaches here
    # via the ``{<<"`` scan), so the name is always recoverable.
    entry_name = _BINARY_RE.findall(elements[0])[0]
    source = elements[1].strip()
    if source.startswith("{pkg"):
        # {pkg, <<"hexname">>, <<"version">>[, <<"hash">>]} — the hex package
        # name is the first binary, the version the second.
        bins = _BINARY_RE.findall(source)
        name = bins[0] if bins else entry_name
        version = bins[1] if len(bins) > 1 else ""
        return name, version, level, False
    # {git, ...} / other → off-registry, keyed by the entry name.
    return entry_name, "", level, True


def parse_rebar_lock(
    path: Path,
    *,
    dev_direct_names: set[str],
    include_dev: bool,
) -> list[Dependency]:
    """Parse ``rebar.lock`` into Dependencies (level/section-based attribution).

    ``dev_direct_names`` is the lowercased set of names declared in a
    ``rebar.config`` test/dev profile; a level-0 entry in that set is DEV.
    Level-≥1 transitives are PROD (no edge data to attribute them otherwise),
    with empty ``direct_ancestors``.
    """
    text = decode_text(path)
    if text is None:
        return []
    text = _strip_line_comments(text, "%")

    out: list[Dependency] = []
    for match in re.finditer(r'\{<<"', text):
        body = _balanced_braces(text, match.start())
        if body is None:
            continue
        elements = _split_top_level(body)
        # A lock entry is a 3-tuple ending in the integer level; the 2-tuple
        # ``{<<"name">>,<<"hash">>}`` hash entries are skipped by arity.
        if len(elements) != 3 or not elements[2].strip().isdigit():
            continue
        name, version, level, off_registry = _parse_lock_entry(elements)
        is_direct = level == 0
        if is_direct and name.lower() in dev_direct_names:
            group = DependencyGroup.DEV
        else:
            group = DependencyGroup.PROD
        if group == DependencyGroup.DEV and not include_dev:
            continue
        out.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}" if version else "",
                ecosystem=Ecosystem.HEX,
                group=group,
                depth=0 if is_direct else 1,
                direct_ancestors=(),
                source="" if not off_registry else _OFF_REGISTRY_MARKER,
            )
        )
    return out
