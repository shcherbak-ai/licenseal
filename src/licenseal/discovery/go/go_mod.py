"""Parse ``go.mod`` files into direct Dependency entries.

Go modules declare their direct deps in ``go.mod``'s ``require`` block(s).
The format is line-based, lightly structured:

    module example.com/myproject

    go 1.22

    require (
        github.com/foo/bar v1.2.3
        github.com/baz/qux v0.4.5 // indirect
    )

    require github.com/single/dep v1.0.0

    replace github.com/old/path => github.com/new/path v2.0.0
    replace github.com/local/dep => ../local-dir

    exclude github.com/bad/dep v9.9.9

    // Go 1.24+: development tools
    tool (
        golang.org/x/tools/cmd/stringer
        example.com/build/cmd/generator
    )

The ``// indirect`` marker on a ``require`` line means Go's tooling added the
entry because a transitive needed it but no direct code references it — still
a real dependency the project ships. It is NOT a dev marker.

The ``tool`` directive (Go 1.24+) IS the dev marker: it lists *import paths*
of developer tools used at build / test time but not bundled into the main
binary. Each tool import path is a sub-path of a module path that also
appears in ``require``; we match each tool entry to its module by
longest-prefix lookup and mark that direct dep as ``DependencyGroup.DEV``.

``replace`` directives rewrite a module reference. A ``replace`` to another
module/version is followed (the dep is resolved under the replacement's
identity). A ``replace`` to a local filesystem path (no version) means the
dep is satisfied locally and has no canonical registry license — drop it.

``exclude`` directives drop a specific module@version from the build. The
resolver wouldn't see it anyway (it's not in ``require``); ignored here.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_REQUIRE_LINE_RE = re.compile(r"^\s*(?P<path>\S+)\s+(?P<version>\S+)(?:\s*//\s*indirect\b)?\s*$")
_REPLACE_LINE_RE = re.compile(
    r"^\s*replace\s+"
    r"(?P<old>\S+)(?:\s+\S+)?"  # optional old version
    r"\s*=>\s*"
    r"(?P<new>\S+)(?:\s+(?P<new_version>\S+))?"
    r"\s*$"
)
_TOOL_LINE_RE = re.compile(r"^\s*(?P<path>\S+)\s*$")


def _parse_go_mod(
    text: str,
) -> tuple[list[tuple[str, str]], dict[str, tuple[str, str] | None], list[str]]:
    """Return (requires, replaces, tools).

    ``requires`` is a list of ``(module_path, version)`` from all ``require``
    blocks (both bracketed and single-line). The ``// indirect`` marker is
    preserved as part of the line scan but discarded — we don't surface it
    on ``Dependency`` (Go's PROD/DEV distinction comes from the ``tool``
    directive, not from ``indirect``).

    ``replaces`` maps old-path → either ``(new_path, new_version)`` for a
    module replacement or ``None`` for a local-path replacement (drop the
    dep — no registry license).

    ``tools`` is a list of import paths from any ``tool`` block(s) — used
    by the discovery layer to mark the corresponding require'd modules as
    ``DependencyGroup.DEV``.
    """
    requires: list[tuple[str, str]] = []
    replaces: dict[str, tuple[str, str] | None] = {}
    tools: list[str] = []
    in_require_block = False
    in_tool_block = False
    for raw in text.splitlines():
        line = _strip_line_comment_with_marker(raw)
        stripped = line.strip()
        if not stripped:
            continue

        if in_require_block:
            if stripped == ")":
                in_require_block = False
                continue
            m = _REQUIRE_LINE_RE.match(line)
            if m:
                requires.append((m.group("path"), m.group("version")))
            continue

        if in_tool_block:
            if stripped == ")":
                in_tool_block = False
                continue
            m = _TOOL_LINE_RE.match(line)
            if m:
                tools.append(m.group("path"))
            continue

        if stripped.startswith("require ("):
            in_require_block = True
            continue

        if stripped.startswith("require "):
            # Single-line require: "require <path> <version>"
            rest = stripped[len("require ") :].strip()
            parts = rest.split()
            if len(parts) >= 2:
                requires.append((parts[0], parts[1]))
            continue

        if stripped.startswith("tool ("):
            in_tool_block = True
            continue

        if stripped.startswith("tool "):
            # Single-line tool: "tool <import-path>". The ``startswith("tool ")``
            # match guarantees at least one char follows the keyword + space,
            # so ``rest`` is always non-empty after lstrip.
            tools.append(stripped[len("tool ") :].strip())
            continue

        if stripped.startswith("replace "):
            m = _REPLACE_LINE_RE.match(line)
            if not m:
                continue
            old = m.group("old")
            new = m.group("new")
            new_version = m.group("new_version")
            if new_version is None:
                # Local path replacement (``=> ../some-dir``) — no version.
                replaces[old] = None
            else:
                replaces[old] = (new, new_version)

    return requires, replaces, tools


def _strip_line_comment_with_marker(line: str) -> str:
    """Strip ``// ...`` except preserve ``// indirect`` for the require-line regex.

    The require regex consumes ``// indirect`` itself; only strip *other*
    comments. Detect ``// indirect`` as a whole token (case-sensitive per
    the Go spec) and leave it in place.
    """
    idx = line.find("//")
    if idx < 0:
        return line
    tail = line[idx:].strip()
    if tail == "// indirect" or tail.startswith("// indirect "):
        # Keep the marker so the require regex can match it.
        return line
    return line[:idx]


def _extract_module_declaration(text: str) -> str | None:
    """Return the module path declared on the ``module <path>`` line, or None.

    Handles bare and quoted forms (``module "github.com/foo/bar"`` is valid).
    """
    for raw in text.splitlines():
        stripped = _strip_line_comment_with_marker(raw).strip()
        if stripped.startswith("module "):
            value = stripped[len("module ") :].strip()
            # Quoted form: ``module "github.com/foo/bar"``.
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            return value or None
    return None


def _parse_go_work_use_directories(text: str) -> list[str]:
    """Return directory paths from go.work's ``use`` directive(s).

    ``go.work`` syntax mirrors go.mod's. ``use ./dir`` is single-line;
    ``use ( ... )`` is the bracketed block form. ``replace`` directives
    in go.work are ignored — licenseal's workspace-local filter only
    needs to know which directories are part of the workspace, not how
    individual deps are rewritten.
    """
    out: list[str] = []
    in_use_block = False
    for raw in text.splitlines():
        stripped = _strip_line_comment_with_marker(raw).strip()
        if not stripped:
            continue
        if in_use_block:
            if stripped == ")":
                in_use_block = False
                continue
            # Each line is a directory path; may be quoted. Empty strings
            # (e.g. ``use ( "" )``, pathological) flow through and resolve
            # to ``project_path`` itself downstream — already covered by
            # the in-tree walk, so harmless.
            out.append(stripped.strip('"'))
            continue
        if stripped.startswith("use ("):
            in_use_block = True
            continue
        if stripped.startswith("use "):
            out.append(stripped[len("use ") :].strip().strip('"'))
            continue
    return out


def _is_test_fixture_go_mod(gm_path: Path) -> bool:
    """True if ``gm_path`` lives under a Go ``testdata/`` fixtures directory.

    Go convention: any path component named ``testdata`` holds ancillary
    data for tests and is ignored by the Go toolchain itself (``go build``
    skips it). Tools that parse ``go.mod`` for their own test suite ship
    fixture ``go.mod`` files declaring fake or intentionally-colliding
    module paths inside ``testdata/`` — when those declarations get added
    to the workspace-local set they shadow real third-party requires of
    the same path and the dep silently disappears from the report.
    """
    return "testdata" in gm_path.parts


def _discover_workspace_local_module_paths(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> set[str]:
    """Return module paths that are locally-developed inside this workspace.

    A module is workspace-local if it satisfies either of:

    1. Its ``module <path>`` declaration appears in any ``go.mod`` inside
       the project tree (covers implicit-monorepo layouts — multiple
       ``go.mod`` files declaring sibling modules — even without an explicit
       go.work file).
    2. The repo root has a ``go.work`` whose ``use ./dir`` directive points
       at a directory containing a ``go.mod`` (covers explicit multi-module
       workspaces, including ``use ../sibling`` targets outside the project
       tree).

    These modules are filtered from registry resolution: licenseal can't
    fetch their license from deps.dev because they aren't published
    publicly. Without this filter, every cross-module require in a monorepo
    would surface as UNKNOWN.

    ``go.mod`` files under ``testdata/`` are excluded — see
    :func:`_is_test_fixture_go_mod`.
    """
    local: set[str] = set()

    for gm in walk_project_files(project_path, "go.mod", exclude_paths=exclude_paths):
        if _is_test_fixture_go_mod(gm):
            continue
        text = decode_text(gm)
        if text is None:
            continue
        module_path = _extract_module_declaration(text)
        if module_path:
            local.add(module_path)

    go_work = project_path / "go.work"
    if go_work.is_file():
        work_text = decode_text(go_work)
        if work_text is None:
            return local
        for use_dir in _parse_go_work_use_directories(work_text):
            target = (project_path / use_dir).resolve()
            gm = target / "go.mod"
            if not gm.is_file():
                continue
            text = decode_text(gm)
            if text is None:
                continue
            module_path = _extract_module_declaration(text)
            if module_path:
                local.add(module_path)

    return local


def _module_for_tool_path(tool_path: str, module_paths: list[str]) -> str | None:
    """Match a tool import path to the longest-prefix module path.

    Tool entries in ``go.mod`` are *import paths* like
    ``golang.org/x/tools/cmd/stringer``; the corresponding require'd entry
    is the *module path* ``golang.org/x/tools``. Longest-prefix wins so
    that a tool from a sub-module routes to the most-specific parent
    module that's actually in the require list.

    Returns the module path or None if no require entry matches.
    """
    best: str | None = None
    for mp in module_paths:
        if (tool_path == mp or tool_path.startswith(mp + "/")) and (
            best is None or len(mp) > len(best)
        ):
            best = mp
    return best


def discover_go_mod_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct dependencies from every ``go.mod`` in the project tree.

    Returns ``(deps, filtered_count)``. ``deps`` is a flat list of
    ``Dependency`` entries (one per ``require`` directive, after applying
    ``replace`` rewrites). ``filtered_count`` is the number of require
    entries dropped because their name matches a workspace-local module
    path (sibling go.mod in a monorepo, or a target of a ``go.work``
    ``use`` directive — see :func:`_discover_workspace_local_module_paths`).

    Tool deps (matched via the ``tool`` directive's import path → require'd
    module path) surface as ``DependencyGroup.DEV``; everything else is
    ``DependencyGroup.PROD``.

    Polyglot setups commonly nest Go modules (e.g. ``cli/go.mod`` next to a
    web frontend's ``package.json``); each nested ``go.mod`` is the truth
    for its own subtree, so all are walked.
    """
    workspace_local = _discover_workspace_local_module_paths(
        project_path, exclude_paths=exclude_paths
    )

    out: list[Dependency] = []
    filtered = 0
    for gm in walk_project_files(project_path, "go.mod", exclude_paths=exclude_paths):
        text = decode_text(gm)
        if text is None:
            continue
        requires, replaces, tools = _parse_go_mod(text)
        source = gm.relative_to(project_path).as_posix()

        # Resolve replace rewrites first so the tool-to-module match runs
        # against the post-replace module paths.
        resolved: list[tuple[str, str]] = []
        for path, version in requires:
            target = replaces.get(path, (path, version))
            if target is None:
                continue  # local replacement — drop
            resolved.append(target)

        resolved_paths = [r[0] for r in resolved]
        tool_modules = {mp for t in tools if (mp := _module_for_tool_path(t, resolved_paths))}

        for new_path, new_version in resolved:
            if new_path in workspace_local:
                filtered += 1
                continue
            group = DependencyGroup.DEV if new_path in tool_modules else DependencyGroup.PROD
            out.append(
                Dependency(
                    name=new_path,
                    version_constraint=new_version,
                    ecosystem=Ecosystem.GO,
                    group=group,
                    source=source,
                )
            )
    return out, filtered
