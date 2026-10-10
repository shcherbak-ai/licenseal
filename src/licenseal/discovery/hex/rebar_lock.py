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
registry-backed. Any other source (``{git, …}``, ``{git_subdir, …}``,
``{hg, …}``) is emitted with an ``origin`` (the repository URL plus the
locked ``{ref, …}``) and is never looked up.

Group attribution: level-0 (direct) entries are PROD unless the name is in the
``rebar.config`` test/dev-profile set; level-≥1 transitives default to PROD with
no ancestors (no edge data — same conservative posture as Pipfile.lock).
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._origin import UNRECORDED, git_origin
from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.hex.mix_lock import (  # noqa: PLC2701
    _split_top_level,
    _strip_line_comments,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_BINARY_RE = re.compile(r'<<"([^"]*)">>')
# A dependency level: ASCII digits only, and few of them. ``str.isdigit`` also
# accepts characters ``int()`` rejects, and ``int()`` refuses very long digit
# strings.
_LEVEL_RE = re.compile(r"[0-9]{1,9}")
# A source-control source: ``{git, "url", …}``, ``{git_subdir, "url", …}``,
# ``{hg, "url", …}``.
_SCM_SOURCE_RE = re.compile(r'\{\s*(?P<scm>[a-z][a-z0-9_]*)\s*,\s*"(?P<url>[^"]*)"')
# The revision of one: ``{ref, "sha"}``, ``{tag, "v1"}``, ``{branch, "main"}``.
_SCM_REVISION_RE = re.compile(r'\{\s*(?:ref|tag|branch)\s*,\s*"(?P<revision>[^"]*)"\s*\}')


def scm_origin(source: str) -> str:
    """Origin of an Erlang-terms source-control source such as ``{git, "url", {ref, "sha"}}``.

    ``git_subdir`` is a git repository; any other SCM keeps its own name.
    When the term holds no URL string the origin says only that the source
    is not recorded.
    """
    scm = _SCM_SOURCE_RE.search(source)
    if scm is None or not scm.group("url"):
        return UNRECORDED
    revision = _SCM_REVISION_RE.search(source)
    vcs = "git" if scm.group("scm").startswith("git") else scm.group("scm")
    return git_origin(scm.group("url"), revision.group("revision") if revision else "", vcs=vcs)


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


def _parse_lock_entry(elements: list[str]) -> tuple[str, str, int, str]:
    """``[<<"name">>, <source>, Level]`` → (name, version, level, origin).

    The origin is empty for a ``{pkg, …}`` source.
    """
    level = int(elements[2].strip())
    # The caller has checked that elements[0] holds a complete ``<<"name">>``
    # binary, so the name is always recoverable.
    entry_name = _BINARY_RE.findall(elements[0])[0]
    source = elements[1].strip()
    if source.startswith("{pkg"):
        # {pkg, <<"hexname">>, <<"version">>[, <<"hash">>]} — the hex package
        # name is the first binary, the version the second.
        bins = _BINARY_RE.findall(source)
        name = bins[0] if bins else entry_name
        version = bins[1] if len(bins) > 1 else ""
        return name, version, level, ""
    # {git, ...} / other → not a hex.pm package, keyed by the entry name.
    return entry_name, "", level, scm_origin(source)


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
        # A lock entry is a 3-tuple that starts with a ``<<"name">>`` binary and
        # ends in the integer level; the 2-tuple ``{<<"name">>,<<"hash">>}``
        # hash entries are skipped by arity. The ``{<<"`` scan matches an
        # unterminated binary too, so the name is checked here.
        if (
            len(elements) != 3
            or not _BINARY_RE.search(elements[0])
            or not _LEVEL_RE.fullmatch(elements[2].strip())
        ):
            continue
        name, version, level, origin = _parse_lock_entry(elements)
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
                origin=origin,
            )
        )
    return out
