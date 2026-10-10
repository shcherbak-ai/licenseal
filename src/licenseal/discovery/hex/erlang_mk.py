"""Static erlang.mk (Makefile) parser.

erlang.mk projects declare dependencies in the project ``Makefile``, which
``include``s the vendored ``erlang.mk`` build system. licenseal parses the
project Makefile but never ``erlang.mk`` itself — that file is the huge
generated package index (hundreds of ``dep_*`` entries) and would flood
discovery with false positives. Dependencies live in Make variables::

    PROJECT = myapp
    DEPS = foo bar
    TEST_DEPS = baz
    LOCAL_DEPS = crypto ssl                  # OTP apps — skipped
    dep_foo = hex 2.12.1                      # hex package + exact version
    dep_bar = git https://github.com/example/bar 1.8.1   # off-registry

A ``DEPS`` entry with no ``dep_<name>`` line resolves through erlang.mk's
package index — for our purposes a hex package looked up by name. ``hex VER``
pins an exact version (``==VER``). Every other fetch method is not a hex.pm
package: the dep is emitted with an ``origin`` (the repository URL plus the
commit-ish for ``git``, the path for ``cp`` / ``ln``) and never looked up. A
``cp`` / ``ln`` path inside the scanned directory is the project's own code.
There is no erlang.mk lockfile, so resolution is manifest-only (the registry
walk against hex.pm). All deps are :class:`~licenseal.models.Ecosystem.HEX`.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._origin import UNRECORDED, git_origin, path_origin
from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.hex.mix_exs import workspace_mix_names
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# A project Makefile is treated as erlang.mk only when it includes the build
# system — guards against parsing unrelated (C / generic) Makefiles.
_INCLUDE_RE = re.compile(r"include\s+\S*erlang\.mk")

_ASSIGN = r"\s*[:+?]?=\s*"  # =, :=, ?=, +=
_DEPS_VAR_RE = re.compile(
    r"^(?P<var>DEPS|REL_DEPS|TEST_DEPS|BUILD_DEPS|DOC_DEPS|SHELL_DEPS|LOCAL_DEPS)"
    + _ASSIGN
    + r"(?P<val>.*)$"
)
_PROJECT_RE = re.compile(r"^PROJECT" + _ASSIGN + r"(?P<val>\S+)")
_DEP_DEF_RE = re.compile(r"^dep_(?P<name>[a-z0-9_]+)" + _ASSIGN + r"(?P<val>.*)$")
# A valid Erlang application name (filters Make-function tokens like
# ``$(if $(CI),x)`` out of a DEPS value).
_APP_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

_PROD_VARS = frozenset({"DEPS", "REL_DEPS"})
# TEST / BUILD / DOC / SHELL deps are dev-time. LOCAL_DEPS lists OTP
# applications (crypto, ssl, …) which aren't external packages — skipped.


def _is_erlang_mk(text: str) -> bool:
    return _INCLUDE_RE.search(text) is not None


def _logical_lines(text: str) -> list[str]:
    """Strip ``#`` comments and join ``\\``-continuations into logical lines."""
    no_comments = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    out: list[str] = []
    pending = ""
    for raw in no_comments.splitlines():
        if raw.rstrip().endswith("\\"):
            pending += raw.rstrip()[:-1] + " "
        else:
            out.append(pending + raw)
            pending = ""
    if pending:
        out.append(pending)
    return out


def _app_tokens(value: str) -> list[str]:
    """Return the valid app-name tokens in a DEPS-variable value."""
    return [t for t in value.split() if _APP_NAME_RE.match(t)]


# erlang.mk fetch methods that clone a repository, and the VCS each one uses.
_VCS_METHODS = {"git": "git", "git-subfolder": "git", "hg": "hg", "svn": "svn"}
# Fetch methods that copy or link a local directory.
_PATH_METHODS = frozenset({"cp", "ln"})


def _parse_dep_def(
    value: str, makefile_dir: Path, scan_root: Path
) -> tuple[str | None, str, str | None]:
    """A ``dep_X`` value → (hex_name_override | None, version, origin).

    The origin is empty for a ``hex`` dep and ``None`` for a ``cp`` / ``ln``
    path inside the scanned directory. A value in the legacy
    ``<repository> <commit>`` form, with no fetch method, is a git
    repository. Anything else (``git-submodule``, ``fail``, a computed or
    empty value) is not resolvable against hex.pm and records no source.
    """
    tokens = value.split()
    if tokens and tokens[0] == "hex":
        version = tokens[1] if len(tokens) > 1 else ""
        override = tokens[2] if len(tokens) > 2 else None
        return override, version, ""
    method, args = (tokens[0], tokens[1:]) if tokens else ("", [])
    if method in _PATH_METHODS and args:
        return None, "", path_origin(args[0], makefile_dir, scan_root)
    if "://" in method or method.startswith("git@"):
        method, args = "git", tokens
    if method in _VCS_METHODS and args:
        revision = args[1] if len(args) > 1 else ""
        return None, "", git_origin(args[0], revision, vcs=_VCS_METHODS[method])
    return None, "", UNRECORDED


def _parse_makefile_text(
    text: str, source: str, makefile_dir: Path, scan_root: Path
) -> tuple[list[Dependency], list[str]]:
    """Extract direct Dependencies from an erlang.mk project Makefile.

    Returns ``(deps, own)``: ``own`` names the deps copied or linked from a
    path inside the scanned directory, which are the project's own code.
    """
    if not _is_erlang_mk(text):
        return [], []
    prod_apps: list[str] = []
    dev_apps: list[str] = []
    dep_defs: dict[str, str] = {}
    for line in _logical_lines(text):
        m = _DEPS_VAR_RE.match(line)
        if m is not None:
            var = m.group("var")
            if var == "LOCAL_DEPS":
                continue
            (prod_apps if var in _PROD_VARS else dev_apps).extend(_app_tokens(m.group("val")))
            continue
        d = _DEP_DEF_RE.match(line)
        if d is not None:
            dep_defs[d.group("name")] = d.group("val")

    out: list[Dependency] = []
    own: list[str] = []
    seen: set[tuple[str, str]] = set()
    for apps, group in ((prod_apps, DependencyGroup.PROD), (dev_apps, DependencyGroup.DEV)):
        for app in apps:
            key = (app, group.value)
            if key in seen:
                continue
            seen.add(key)
            override, version, origin = (None, "", "")
            if app in dep_defs:
                override, version, origin = _parse_dep_def(dep_defs[app], makefile_dir, scan_root)
            if origin is None:
                own.append(app)
                continue
            out.append(
                Dependency(
                    name=override or app,
                    version_constraint=f"=={version}" if version else "",
                    ecosystem=Ecosystem.HEX,
                    group=group,
                    source=source,
                    origin=origin,
                )
            )
    return out, own


def discover_erlang_mk_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    workspace_names: frozenset[str] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct deps from every erlang.mk project Makefile in the tree."""
    out: list[Dependency] = []
    filtered = 0
    for makefile in walk_project_files(project_path, "Makefile", exclude_paths=exclude_paths):
        text = decode_text(makefile)
        if text is None:
            continue
        source = makefile.relative_to(project_path).as_posix()
        deps, own = _parse_makefile_text(text, source, makefile.parent, project_path)
        filtered += sum(name.lower() in workspace_names for name in own)
        for dep in deps:
            if dep.name.lower() in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered


def workspace_erlang_mk_project_names(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> frozenset[str]:
    """Return the lowercased ``PROJECT`` names of every in-tree erlang.mk app.

    Used (unioned with the Mix umbrella app names) to filter monorepo sibling
    references — e.g. in a large erlang.mk monorepo a sub-app's ``DEPS`` lists
    both external hex packages and dozens of internal ``deps/*`` apps.
    """
    names: set[str] = set()
    for makefile in walk_project_files(project_path, "Makefile", exclude_paths=exclude_paths):
        text = decode_text(makefile)
        if text is None:
            continue
        if not _is_erlang_mk(text):
            continue
        for line in _logical_lines(text):
            m = _PROJECT_RE.match(line)
            if m is not None:
                names.add(m.group("val").lower())
                break
    return frozenset(names)


def workspace_hex_names(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> frozenset[str]:
    """All in-tree Hex workspace app names: Mix umbrella apps ∪ erlang.mk PROJECTs."""
    return workspace_mix_names(
        project_path, exclude_paths=exclude_paths
    ) | workspace_erlang_mk_project_names(project_path, exclude_paths=exclude_paths)
