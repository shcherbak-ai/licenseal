"""Static ``mix.exs`` parser.

An Elixir ``mix.exs`` is a ``Mix.Project`` module — Ruby-style, it is *code*,
and licenseal never executes it. We regex over the source for the load-bearing
pieces:

* the ``deps`` function's returned list of ``{:name, "constraint", opts}`` tuples
  (direct dependencies), with ``only: :dev|:test`` marking dev/test deps and
  ``git:`` / ``github:`` / ``path:`` / ``in_umbrella:`` marking non-hex.pm sources;
* the ``package`` config's ``licenses: ["X", "Y"]`` (the project's own license);
* each project's ``app: :name`` atom (for the umbrella workspace-internal filter).

``deps`` is a flat list literal, so — unlike the Gemfile — there is no nested
``group do ... end`` block state to track. Non-literal forms (a version built
from a module attribute, deps assembled by a private function) are skipped and
backfilled from ``mix.lock`` / the registry.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.hex.mix_lock import (  # noqa: PLC2701
    _OFF_REGISTRY_MARKER,
    _first_atom,
    _split_top_level,
    _strip_line_comments,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# The ``deps`` function header: ``def deps do`` / ``defp deps(env) do`` /
# ``defp deps, do: [...]``. We only need to locate it; the list body is found
# by a bracket scan from the match onward.
_DEPS_FN_RE = re.compile(r"defp?\s+deps\b[^\n]*\bdo\b")

# ``app: :my_app`` inside ``def project``.
_APP_RE = re.compile(r"\bapp:\s*:(?P<app>\w+)")

# ``licenses: ["MIT", "Apache-2.0"]`` inside ``def package``.
_LICENSES_RE = re.compile(r"\blicenses:\s*\[(?P<body>[^\]]*)\]")

# ``only: :dev`` (single) or ``only: [:dev, :test]`` (list).
_ONLY_RE = re.compile(r"\bonly:\s*(?::(?P<single>\w+)|\[(?P<multi>[^\]]*)\])")

# ``hex: :real_pkg`` renames a dep to a differently-named published hex.pm
# package — the first tuple atom is the local app name, this is the package.
_HEX_RENAME_RE = re.compile(r"\bhex:\s*:(?P<hexname>\w+)")

_STRING_RE = re.compile(r'"([^"]*)"')

# Source kwargs that take a dep off the hex.pm registry. ``in_umbrella:`` and a
# sibling ``path:`` resolve to a workspace-internal app (dropped by the
# workspace filter); an external ``git:`` / ``github:`` / ``path:`` stays
# off-registry.
_OFF_REGISTRY_KWARGS = ("git:", "github:", "path:", "in_umbrella:")


def _strip_comments(text: str) -> str:
    """Drop Elixir ``# ...`` line comments (see :func:`_strip_line_comments`)."""
    return _strip_line_comments(text, "#")


def _extract_deps_list_body(text: str) -> str | None:
    """Return the inner text of the ``deps`` function's ``[...]`` list, or None.

    Scans from the ``deps`` header to the first ``[`` and returns the body up to
    its matching ``]`` (respecting nested brackets and strings).
    """
    header = _DEPS_FN_RE.search(text)
    if header is None:
        return None
    start = text.find("[", header.end())
    if start == -1:
        return None
    depth = 0
    in_str = False
    for i in range(start, len(text)):
        ch = text[i]
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
                return text[start + 1 : i]
    return None  # pragma: no cover - unbalanced brackets don't occur in valid mix.exs


def _is_dev_only(entry: str) -> bool:
    """True when a dep tuple's ``only:`` restricts it to non-prod envs.

    ``only: :dev`` / ``only: [:dev, :test]`` → dev; ``only: :prod`` or any
    ``only:`` that includes ``:prod`` → prod; no ``only:`` → prod (all envs).
    """
    m = _ONLY_RE.search(entry)
    if m is None:
        return False
    if m.group("single"):
        envs = {m.group("single")}
    else:
        envs = set(re.findall(r":(\w+)", m.group("multi")))
    return "prod" not in envs


def _has_off_registry_source(entry: str) -> bool:
    """True when a dep tuple declares a non-hex.pm source kwarg."""
    return any(token in entry for token in _OFF_REGISTRY_KWARGS)


def _parse_mix_exs_text(text: str, source: str) -> list[Dependency]:
    """Extract direct Dependencies from a ``mix.exs`` ``deps`` list."""
    body = _extract_deps_list_body(_strip_comments(text))
    if body is None:
        return []
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for entry in _split_top_level(body):
        if not entry.startswith("{"):
            continue
        name = _first_atom(entry)
        if not name:
            continue
        off_registry = _has_off_registry_source(entry)
        # The version constraint is the first string literal in the tuple (the
        # element right after the name atom). Off-registry deps have no
        # registry version — their first string is a URL / path, so skip it.
        version = ""
        if not off_registry:
            vm = _STRING_RE.search(entry)
            version = vm.group(1).strip() if vm else ""
        group = DependencyGroup.DEV if _is_dev_only(entry) else DependencyGroup.PROD
        # ``hex: :real_pkg`` publishes under a different hex.pm package name; the
        # first atom (``name``) is the local app name kept for the graph / dev
        # attribution / display / workspace filter, while resolution targets the
        # hex name via registry_name. Empty when absent or off-registry.
        rename = _HEX_RENAME_RE.search(entry)
        registry_name = (
            rename.group("hexname")
            if rename and not off_registry and rename.group("hexname").lower() != name.lower()
            else ""
        )
        key = (name.lower(), group.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Dependency(
                name=name,
                version_constraint=version,
                ecosystem=Ecosystem.HEX,
                group=group,
                source=_OFF_REGISTRY_MARKER if off_registry else source,
                registry_name=registry_name,
            )
        )
    return out


def discover_mix_exs_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    workspace_names: frozenset[str] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct deps from every ``mix.exs`` in the tree.

    ``workspace_names`` is the lowercased set of in-tree umbrella app names;
    sibling references are filtered before any registry lookup. The filter
    count is returned alongside.
    """
    out: list[Dependency] = []
    filtered = 0
    for mix_exs in walk_project_files(project_path, "mix.exs", exclude_paths=exclude_paths):
        text = decode_text(mix_exs)
        if text is None:
            continue
        source = mix_exs.relative_to(project_path).as_posix()
        for dep in _parse_mix_exs_text(text, source):
            if dep.name.lower() in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered


def collect_dev_direct_names(deps: list[Dependency]) -> set[str]:
    """Return the lowercased Hex dep names whose only declaration is dev/test.

    A dep declared PROD anywhere outranks a DEV declaration. Used as the
    DEV-root set for reverse-BFS group propagation through ``mix.lock``.
    """
    prod_names: set[str] = set()
    dev_names: set[str] = set()
    for dep in deps:
        if dep.ecosystem != Ecosystem.HEX:
            continue
        if dep.group == DependencyGroup.DEV:
            dev_names.add(dep.name.lower())
        else:
            prod_names.add(dep.name.lower())
    return dev_names - prod_names


def _license_array_body_to_raw(body: str) -> str:
    """``"MIT", "Apache-2.0"`` → ``MIT OR Apache-2.0`` (disjunctive, like RubyGems)."""
    items = [m.group(1).strip() for m in _STRING_RE.finditer(body)]
    items = [item for item in items if item]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return " OR ".join(items)


def detect_project_license_mix_exs(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Return the first ``package``'s ``licenses: [...]`` value from a mix.exs."""
    for mix_exs in walk_project_files(project_path, "mix.exs", exclude_paths=exclude_paths):
        text = decode_text(mix_exs)
        if text is None:
            continue
        m = _LICENSES_RE.search(_strip_comments(text))
        if m is not None:
            raw = _license_array_body_to_raw(m.group("body"))
            if raw:
                return raw
    return ""


def workspace_mix_names(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> frozenset[str]:
    """Return the lowercased set of in-tree ``app: :name`` atoms.

    Used to filter umbrella sibling references (``in_umbrella: true`` or a
    ``path:`` to an in-tree app) before any registry lookup.
    """
    names: set[str] = set()
    for mix_exs in walk_project_files(project_path, "mix.exs", exclude_paths=exclude_paths):
        text = decode_text(mix_exs)
        if text is None:
            continue
        m = _APP_RE.search(_strip_comments(text))
        if m is not None:
            names.add(m.group("app").lower())
    return frozenset(names)
