"""Static Gemfile parser.

Bundler's ``Gemfile`` is Ruby source code evaluated at install time. licenseal
must not execute it — same rule that applies to every scan target. We parse
the source statically with a line-oriented regex + a small state machine for
``group :development do ... end`` blocks (with a block-nesting counter so a
nested ``platforms do`` / ``if`` block doesn't lose the enclosing group).

``git:`` / ``github:`` / ``path:`` gems are emitted with an off-registry source
marker rather than skipped. They can't be resolved against rubygems.org (the
resolver short-circuits them to UNKNOWN), but emitting them keeps their group
and direct-ness — so a git-sourced dev tool is still attributed DEV and dropped
under ``--no-dev`` instead of leaking in as a PROD UNKNOWN. ``Gemfile.lock``
carries no group of its own, so the Gemfile is the only place that signal
exists.

Group attribution is the load-bearing reason to parse the Gemfile at all —
``Gemfile.lock`` carries no dev/prod marker, only the Gemfile does (via
``group :development`` / ``group :test`` blocks or per-line ``group:`` kwargs).
A gem is DEV only when every group it belongs to is ``development`` or
``test``; any other group (``production``, ``staging``, a custom one) puts it
in a deployed bundle, so it is PROD. A group name is read from a ``:symbol``,
a quoted string, or a ``%i[...]`` / ``%w[...]`` word list; a name written any
other way (a constant, a method call) is unreadable and keeps the gem PROD.
The lockfile parser uses the dev-name set emitted here as roots for
reverse-BFS group propagation.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.ruby.lockfiles import _OFF_REGISTRY_MARKER  # noqa: PLC2701
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# A bare ``gem`` call: ``gem "name"`` or ``gem 'name'``, followed by an
# optional comma-separated list of version constraints and options.
_GEM_LINE_RE = re.compile(
    r"""
    ^\s*gem\s+
    (?P<quote>['"])
    (?P<name>[^'"]+)
    (?P=quote)
    (?P<rest>.*)$
    """,
    re.VERBOSE,
)

# Version constraints follow as additional quoted positional args, e.g.
# ``gem "mygem", "~> 7.1.0", ">= 7.1.2"``.
_VERSION_ARG_RE = re.compile(r"""^\s*,\s*(['"])([^'"]+)\1""")

# Block-form group header: ``group :development, :test do``, with trailing
# options (``group :test, optional: true do``). ``args`` keeps the call's own
# parentheses when it has them; the parser strips that pair.
_GROUP_BLOCK_RE = re.compile(r"^group\b\s*(?P<args>.*?)\s*\bdo\b\s*(?:\|[^|]*\|)?\s*$")

# A ``%i[...]`` / ``%w[...]`` word list, in any of Ruby's bracket delimiters.
_WORD_LIST = r"%[iIwW](?:\[[^\]]*\]|\([^)]*\)|\{[^}]*\}|<[^>]*>)"

# Per-line group option, keyword or hash-rocket form: ``group: :test``,
# ``groups: [:development, :test]``, ``:group => :test``, ``:groups => [...]``.
# The value is a word list, a bracketed list, or a single comma-free token. A
# word list that an operator or method call continues is not the whole value,
# so it is left to the single-token branch and stays unreadable.
_INLINE_GROUP_RE = re.compile(
    r"(?<![\w:])(?:groups?:|:groups?\s*=>)\s*"
    rf"(?P<value>{_WORD_LIST}(?!\s*[-+*|&.<\[])|\[[^\]]*\]|[^,\s]*)"
)

# One argument of a ``group`` call or one element of a ``groups`` list: a
# ``:symbol`` or a quoted string names one group, a word list (splatted in a
# ``group`` call) names one per word.
_GROUP_NAME_RE = re.compile(r""":(\w+)|(['"])(\w+)\2""")
_WORD_LIST_ARG_RE = re.compile(rf"\*?({_WORD_LIST})")
_KEYWORD_OPTION_RE = re.compile(r"\w+:(?!:)|:\w+\s*=>")

# Off-registry source kwargs — gems carrying one are emitted with the
# off-registry marker (the lockfile parser is the authority for what
# actually shipped, but the Gemfile is the only place the gem's group lives).
_OFF_REGISTRY_KWARGS = ("git:", "github:", "path:", "gist:", "bitbucket:")

# Block-opener detection for nesting balance. A line opens a ``...end`` block
# when it ends with ``do`` (optionally ``do |args|``) — covers ``platforms``,
# ``source`` / ``git`` / ``path`` / ``install_if`` / ``env`` blocks and
# ``while x do`` — or when it starts with a Ruby control-flow keyword that
# opens a block. The leading-keyword check excludes statement modifiers
# (``gem "x" if cond`` starts with ``gem``). ``group ... do`` is matched
# separately by ``_GROUP_BLOCK_RE`` and handled before this fires.
_BLOCK_OPEN_DO_RE = re.compile(r"\bdo\b\s*(?:\|[^|]*\|)?\s*$")
_BLOCK_OPEN_KEYWORD_RE = re.compile(r"^(?:if|unless|case|while|until|begin|def|class|module|for)\b")


def _opens_block(line: str) -> bool:
    """True when ``line`` opens a ``...end`` block other than ``group``."""
    return bool(_BLOCK_OPEN_DO_RE.search(line) or _BLOCK_OPEN_KEYWORD_RE.match(line))


# The only groups that keep a gem out of a deployed bundle. Every other group
# — ``default``, ``production``, ``staging``, or a custom one for a database
# adapter, app server, or asset pipeline — ships.
_DEV_GROUPS: frozenset[str] = frozenset({"development", "test"})


def _strip_comment(line: str) -> str:
    """Drop ``#...`` to end-of-line. Naive — does not understand strings."""
    # We don't try to handle ``#`` inside strings; Gemfile authors rarely
    # put ``#`` in gem names or version constraints, and the failure mode
    # is a discarded version constraint (not a dropped dep).
    return line.split("#", 1)[0]


def _is_dev_group(groups: tuple[str, ...]) -> bool:
    """Return True when the gem is in a group and every group is dev/test.

    A gem in no group is in Bundler's implicit ``default`` group (PROD), and
    one non-dev group in a mixed list is enough to install it outside
    development.
    """
    return bool(groups) and all(g in _DEV_GROUPS for g in groups)


def _group_names(args: str) -> tuple[str, ...]:
    """Parse comma-separated ``group`` arguments into group names.

    A ``:symbol`` or a quoted string is a group name, and each word of a
    ``%i[...]`` / ``%w[...]`` list is one. A keyword option (``optional:
    true``, ``:optional => true``) is not a group and is skipped. Any other
    argument is kept verbatim: it names a group this parser can't read, which
    keeps the gem out of the dev-only bucket.
    """
    names: list[str] = []
    for raw in args.split(","):
        arg = raw.strip()
        if not arg or _KEYWORD_OPTION_RE.match(arg):
            continue
        name = _GROUP_NAME_RE.fullmatch(arg)
        word_list = _WORD_LIST_ARG_RE.fullmatch(arg)
        if name:
            names.append(name.group(1) or name.group(3))
        elif word_list:
            # Drop the ``%w`` prefix and the two delimiters.
            names.extend(word_list.group(1)[3:-1].split())
        else:
            names.append(arg)
    return tuple(names)


def _parse_inline_groups(rest: str) -> tuple[str, ...]:
    """Extract the gem line's own ``group`` / ``groups`` option.

    Returns an empty tuple when the option isn't present. An option that is
    present but names no readable group (an empty or unterminated list)
    yields its raw value, so the gem is not classified from the enclosing
    block alone.
    """
    m = _INLINE_GROUP_RE.search(rest)
    if m is None:
        return ()
    value = m.group("value")
    inner = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    return _group_names(inner) or (value,)


def _has_off_registry_source(rest: str) -> bool:
    """True when the gem line declares a non-rubygems source."""
    return any(token in rest for token in _OFF_REGISTRY_KWARGS)


def _join_continuations(lines: list[str]) -> list[str]:
    """Glue together ``gem "x", \\`` continuations into single logical lines.

    A Gemfile line that ends with a backslash or a comma (after comment
    stripping) continues onto the next physical line. We collapse the
    sequence so the per-line regex sees the whole call at once.
    """
    out: list[str] = []
    pending = ""
    for raw in lines:
        clean = _strip_comment(raw).rstrip()
        if not clean and not pending:
            out.append(raw)
            continue
        clean_no_trail = clean.rstrip("\\").rstrip()
        combined = pending + " " + clean_no_trail.lstrip() if pending else clean_no_trail
        if clean.endswith("\\") or clean.endswith(","):
            pending = combined
            continue
        out.append(combined)
        pending = ""
    if pending:
        out.append(pending)
    return out


def _parse_gemfile_text(text: str, source: str) -> list[Dependency]:
    """Parse Gemfile text into Dependencies.

    ``source`` is the lockfile-style relative path used to attribute the
    dep's origin in the report.
    """
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    # ``block_depth`` counts every open ``...end`` block; ``group_frames``
    # records the (depth-at-open, group-symbols) of each enclosing ``group``
    # block. Tracking total nesting lets a nested non-group block's ``end``
    # (``platforms do``, an ``if`` guard, …) close without popping the group.
    block_depth = 0
    group_frames: list[tuple[int, tuple[str, ...]]] = []

    physical_lines = text.splitlines()
    for line in _join_continuations(physical_lines):
        stripped = _strip_comment(line).strip()
        if not stripped:
            continue

        # ``group :x do`` — push a group frame at the current nesting depth.
        block = _GROUP_BLOCK_RE.match(stripped)
        if block is not None:
            args = block.group("args")
            if args.startswith("(") and args.endswith(")"):
                args = args[1:-1]
            group_frames.append((block_depth, _group_names(args)))
            block_depth += 1
            continue
        # ``end`` — close the innermost block; drop any group frame it closed.
        if stripped == "end":
            if block_depth > 0:
                block_depth -= 1
                while group_frames and group_frames[-1][0] >= block_depth:
                    group_frames.pop()
            continue
        # Any other block opener (``platforms do``, ``source ... do``, an
        # ``if`` / ``case`` guard, …) — track its depth so its ``end`` is
        # balanced, but it carries no group context of its own.
        if _opens_block(stripped):
            block_depth += 1
            continue

        m = _GEM_LINE_RE.match(stripped)
        if m is None:
            continue
        name = m.group("name").strip()
        if not name:
            continue
        rest = m.group("rest") or ""

        # Collect version constraints (each is a quoted positional arg
        # after the name; the comma + quote pattern is anchored to the
        # remaining text, so we consume them in order).
        constraints: list[str] = []
        remaining = rest
        while True:
            v = _VERSION_ARG_RE.match(remaining)
            if v is None:
                break
            constraints.append(v.group(2).strip())
            remaining = remaining[v.end() :]
        version_constraint = ", ".join(constraints)

        # Bundler adds the gem to every enclosing ``group`` block plus its
        # own per-line groups, so the whole list decides.
        current = tuple(name for _depth, names in group_frames for name in names)
        current += _parse_inline_groups(rest)
        group = DependencyGroup.DEV if _is_dev_group(current) else DependencyGroup.PROD

        # Git / path / github gems can't be resolved against rubygems.org;
        # tag them off-registry so the resolver short-circuits to UNKNOWN
        # while their group + direct-ness still feed attribution.
        dep_source = _OFF_REGISTRY_MARKER if _has_off_registry_source(rest) else source

        key = (name.lower(), group.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Dependency(
                name=name,
                version_constraint=version_constraint,
                ecosystem=Ecosystem.RUBY,
                group=group,
                source=dep_source,
            )
        )
    return out


def discover_gemfile_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    workspace_names: frozenset[str] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover Ruby dependencies declared in ``Gemfile`` files.

    ``workspace_names`` is the lowercased set of gem names declared by
    in-tree gemspecs — those are workspace-internal references (the rails
    monorepo case) and get filtered. The filter count is returned as the
    int in the tuple.
    """
    out: list[Dependency] = []
    filtered = 0
    for gemfile in walk_project_files(project_path, "Gemfile", exclude_paths=exclude_paths):
        text = decode_text(gemfile)
        if text is None:
            continue
        source = gemfile.relative_to(project_path).as_posix()
        for dep in _parse_gemfile_text(text, source):
            if dep.name.lower() in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered


def collect_dev_direct_names(deps: list[Dependency]) -> set[str]:
    """Return the lowercased set of Ruby dep names whose only declaration is DEV.

    A gem can appear in two groups across nested Gemfiles (or even on two
    lines of the same Gemfile); a single PROD declaration outranks any DEV
    one. The lockfile parser uses this set as the DEV-root for reverse-BFS
    group propagation.
    """
    prod_names: set[str] = set()
    dev_names: set[str] = set()
    for dep in deps:
        if dep.ecosystem != Ecosystem.RUBY:
            continue
        if dep.group == DependencyGroup.DEV:
            dev_names.add(dep.name.lower())
        else:
            prod_names.add(dep.name.lower())
    return dev_names - prod_names
