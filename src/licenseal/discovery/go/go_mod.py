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

    replace (
        github.com/pinned/dep v1.0.0 => github.com/fork/dep v1.0.1
        github.com/other/local => ../other-dir
    )

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

``replace`` directives rewrite a module reference, in the single-line and the
``replace ( ... )`` block form. A ``replace`` to another module/version is
followed (the dep is resolved under the replacement's identity). A ``replace``
to a local filesystem path (no version) means the dep is satisfied locally:
nothing is looked up for it. When the scan reads that path (a directory of the
scanned tree that the walk enters) the module is the project's own code, its
own ``go.mod`` is scanned, and it is no dependency. Any other path makes the
module a dependency with that path as its origin. A version after the module path on
the left of ``=>`` restricts the replacement to a requirement on that version;
without one it covers every version. Go honours ``replace`` only in the main
module, so the directives of a dependency's own ``go.mod`` are never applied.

A ``go.work`` in the scanned directory can hold ``replace`` directives too.
They apply to the modules it lists with ``use`` and, as in Go, override the
``go.mod`` directives of those modules: one that names a module, at the
required version or at every version, decides that requirement. A local path
in ``go.work`` is relative to the directory of ``go.work``.

``exclude`` directives drop a specific module@version from the build. The
resolver wouldn't see it anyway (it's not in ``require``); ignored here.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._origin import path_origin
from licenseal.discovery._read import decode_text, rejected_path_reference
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_REQUIRE_LINE_RE = re.compile(r"^\s*(?P<path>\S+)\s+(?P<version>\S+)(?:\s*//\s*indirect\b)?\s*$")
_REPLACE_SPEC_RE = re.compile(
    r"^\s*(?P<old>\S+)(?:\s+(?P<old_version>\S+))?"
    r"\s*=>\s*"
    r"(?P<new>\S+)(?:\s+(?P<new_version>\S+))?"
    r"\s*$"
)
_TOOL_LINE_RE = re.compile(r"^\s*(?P<path>\S+)\s*$")

# ``(old_path, old_version)`` → ``(new_path, new_version)``; ``new_version`` is
# ``None`` for a local-path replacement, where ``new_path`` is that path.
# ``old_version`` is ``None`` when the directive names no version and so covers
# every version of the module.
_Replaces = dict[tuple[str, str | None], tuple[str, str | None]]

# The ``replace`` directives of ``go.work``, keyed by the resolved ``go.mod`` of
# each module they apply to.
WorkReplaces = dict[Path, _Replaces]


def _record_replace(spec: str, replaces: _Replaces) -> None:
    """Add one ``old [version] => new [version]`` spec to ``replaces``.

    A spec that does not have that shape is skipped.
    """
    m = _REPLACE_SPEC_RE.match(spec)
    if not m:
        return
    # A replacement with no version is a local path (``=> ../some-dir``).
    replaces[m.group("old"), m.group("old_version")] = (m.group("new"), m.group("new_version"))


def _parse_go_mod(
    text: str,
) -> tuple[list[tuple[str, str]], _Replaces, list[str]]:
    """Return (requires, replaces, tools).

    ``requires`` is a list of ``(module_path, version)`` from all ``require``
    blocks (both bracketed and single-line). The ``// indirect`` marker is
    preserved as part of the line scan but discarded — we don't surface it
    on ``Dependency`` (Go's PROD/DEV distinction comes from the ``tool``
    directive, not from ``indirect``).

    ``replaces`` maps ``(old_path, old_version)`` → ``(new_path,
    new_version)``, from both single-line directives and ``replace ( ... )``
    blocks. ``new_version`` is ``None`` for a local-path replacement, whose
    ``new_path`` is the path. ``old_version`` is ``None`` for a directive
    without one, which covers every version.

    ``tools`` is a list of import paths from any ``tool`` block(s) — used
    by the discovery layer to mark the corresponding require'd modules as
    ``DependencyGroup.DEV``.
    """
    requires: list[tuple[str, str]] = []
    replaces: _Replaces = {}
    tools: list[str] = []
    in_require_block = False
    in_tool_block = False
    in_replace_block = False
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

        if in_replace_block:
            if stripped == ")":
                in_replace_block = False
                continue
            _record_replace(line, replaces)
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

        if stripped.startswith("replace ("):
            in_replace_block = True
            continue

        if stripped.startswith("replace "):
            _record_replace(stripped[len("replace ") :], replaces)

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


# The ``go`` directive names a Go version: ``go 1.22``, ``go 1.21.0``,
# ``go 1.21rc1``. Its major and minor decide how much a ``go.mod`` lists. Both
# are bounded, so a run of digits no interpreter will convert is simply not a
# version.
_GO_DIRECTIVE_RE = re.compile(r"^go\s+(\d{1,9})\.(\d{1,9})(?!\d)")

# First Go version at which ``go.mod`` lists every module needed to build the
# main module's packages and tests, indirect requirements included.
_LISTS_ALL_REQUIREMENTS_SINCE = (1, 17)


def lists_all_requirements(text: str) -> bool:
    """Whether a ``go.mod`` lists every module its packages and tests need.

    From ``go 1.17`` on it does: there is a ``require`` for each module that
    provides a package the main module's packages or tests import, directly
    or not. At ``go 1.16`` and below it lists direct requirements only, and a
    file with no ``go`` directive is read as ``go 1.16``. A directive that is
    not a version is treated like a missing one.
    """
    for raw in text.splitlines():
        m = _GO_DIRECTIVE_RE.match(_strip_line_comment_with_marker(raw).strip())
        if m:
            return (int(m.group(1)), int(m.group(2))) >= _LISTS_ALL_REQUIREMENTS_SINCE
    return False


def _replacement(
    path: str, version: str, replaces: _Replaces, work_replaces: _Replaces
) -> tuple[str, str | None, bool]:
    """Return what the requirement ``path`` at ``version`` is replaced by.

    ``replaces`` holds the directives of the requiring ``go.mod`` and
    ``work_replaces`` those of the ``go.work`` that applies to it, if any.
    ``go.work`` is consulted first: a directive there that names the module,
    at the required version or at every version, overrides the ``go.mod``
    directives for it, as in Go. Within one file a directive naming the
    required version takes precedence over one covering every version.

    The returned version is ``None`` when the requirement is replaced by a
    local path, which is then returned in place of the module path. The flag
    is True when the directive is one of ``work_replaces``, whose local paths
    are relative to the directory of ``go.work``.
    """
    for from_work, directives in ((True, work_replaces), (False, replaces)):
        for key in ((path, version), (path, None)):
            if key in directives:
                return (*directives[key], from_work)
    return path, version, False


def apply_replaces(
    requires: list[tuple[str, str]], replaces: _Replaces, work_replaces: _Replaces
) -> list[tuple[str, str]]:
    """Return the ``(module, version)`` requirements once the directives are applied.

    ``replaces`` and ``work_replaces`` are read as in :func:`_replacement`.
    A requirement replaced by another module becomes that module and version;
    one replaced by a local path is dropped, having no registry identity.
    """
    resolved: list[tuple[str, str]] = []
    for path, version in requires:
        new_path, new_version, _ = _replacement(path, version, replaces, work_replaces)
        if new_version is not None:
            resolved.append((new_path, new_version))
    return resolved


def _parse_go_work_use_directories(text: str) -> list[str]:
    """Return directory paths from go.work's ``use`` directive(s).

    ``go.work`` syntax mirrors go.mod's. ``use ./dir`` is single-line;
    ``use ( ... )`` is the bracketed block form. The ``replace``
    directives of ``go.work`` are read by :func:`_parse_go_mod`.
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


def read_go_workspace(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[set[str], WorkReplaces]:
    """Return the workspace-local module paths and the ``go.work`` ``replace`` directives.

    The first item holds the module paths that are locally-developed inside
    this workspace. A module is workspace-local if it satisfies either of:

    1. Its ``module <path>`` declaration appears in any ``go.mod`` inside
       the project tree (covers implicit-monorepo layouts — multiple
       ``go.mod`` files declaring sibling modules — even without an explicit
       go.work file).
    2. The repo root has a ``go.work`` whose ``use ./dir`` directive points
       at a directory containing a ``go.mod`` (covers explicit multi-module
       workspaces, including ``use ../sibling`` targets outside the project
       tree). Only relative ``use`` directories are followed: a rooted,
       drive-qualified, UNC or device path is recorded as a gap on
       ``go.work`` and never reaches the filesystem.

    These modules are filtered from registry resolution: licenseal can't
    fetch their license from deps.dev because they aren't published
    publicly. Without this filter, every cross-module require in a monorepo
    would surface as UNKNOWN.

    ``go.mod`` files under ``testdata/`` are excluded — see
    :func:`_is_test_fixture_go_mod`.

    The second item maps the ``go.mod`` of each ``use`` directory, resolved,
    to the ``replace`` directives of ``go.work``: the files those directives
    apply to (see :func:`work_replaces_for`). It is empty when ``go.work``
    holds no ``replace``.
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
    work_text = decode_text(go_work) if go_work.is_file() else None
    if work_text is None:
        return local, {}
    used: list[Path] = []
    for use_dir in _parse_go_work_use_directories(work_text):
        # Only relative ``use`` directories are followed. The check is
        # lexical and precedes ``resolve()``, which is itself filesystem I/O.
        if rejected_path_reference(go_work, use_dir):
            continue
        target = (project_path / use_dir).resolve()
        gm = target / "go.mod"
        if not gm.is_file():
            continue
        used.append(gm)
        text = decode_text(gm)
        if text is None:
            continue
        module_path = _extract_module_declaration(text)
        if module_path:
            local.add(module_path)

    _, work_replaces, _ = _parse_go_mod(work_text)
    return local, dict.fromkeys(used, work_replaces) if work_replaces else {}


def work_replaces_for(go_mod: Path, work_replaces: WorkReplaces) -> _Replaces:
    """Return the ``go.work`` ``replace`` directives that apply to ``go_mod``.

    ``work_replaces`` is the second item of :func:`read_go_workspace`. The
    directives apply to the modules ``go.work`` lists with ``use``, and to no
    other ``go.mod`` of the scanned tree.
    """
    return work_replaces.get(go_mod.resolve(), {}) if work_replaces else {}


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
    ``replace`` rewrites). A requirement replaced by a local path that the
    scan reads is not a dependency; replaced by any other local path it is
    one with that path as its origin and no version. ``filtered_count`` is the number of require
    entries dropped because their name matches a workspace-local module
    path (sibling go.mod in a monorepo, or a target of a ``go.work``
    ``use`` directive — see :func:`read_go_workspace`). The ``replace``
    directives of ``go.work`` are applied to the modules it lists with ``use``.

    Tool deps (matched via the ``tool`` directive's import path → require'd
    module path) surface as ``DependencyGroup.DEV``; everything else is
    ``DependencyGroup.PROD``.

    Polyglot setups commonly nest Go modules (e.g. ``cli/go.mod`` next to a
    web frontend's ``package.json``); each nested ``go.mod`` is the truth
    for its own subtree, so all are walked.
    """
    workspace_local, work_replaces = read_go_workspace(project_path, exclude_paths=exclude_paths)

    out: list[Dependency] = []
    filtered = 0
    for gm in walk_project_files(project_path, "go.mod", exclude_paths=exclude_paths):
        text = decode_text(gm)
        if text is None:
            continue
        requires, replaces, tools = _parse_go_mod(text)
        from_work = work_replaces_for(gm, work_replaces)
        source = gm.relative_to(project_path).as_posix()

        # Resolve replace rewrites first so the tool-to-module match runs
        # against the post-replace module paths.
        resolved: list[tuple[str, str, str]] = []  # (module, version, origin)
        for path, version in requires:
            new_path, new_version, in_go_work = _replacement(path, version, replaces, from_work)
            if new_version is not None:
                resolved.append((new_path, new_version, ""))
                continue
            # Replaced by a local path, relative to the file that holds the
            # directive. One the scan reads is the project's own module; any
            # other is a dependency no registry describes.
            base_dir = project_path if in_go_work else gm.parent
            origin = path_origin(new_path, base_dir, project_path)
            if origin is not None:
                resolved.append((path, "", origin))

        resolved_paths = [r[0] for r in resolved]
        tool_modules = {mp for t in tools if (mp := _module_for_tool_path(t, resolved_paths))}

        for module, module_version, origin in resolved:
            if module in workspace_local:
                filtered += 1
                continue
            group = DependencyGroup.DEV if module in tool_modules else DependencyGroup.PROD
            out.append(
                Dependency(
                    name=module,
                    version_constraint=module_version,
                    ecosystem=Ecosystem.GO,
                    group=group,
                    source=source,
                    origin=origin,
                )
            )
    return out, filtered
