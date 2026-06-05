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
pins an exact version (``==VER``); ``git`` / ``cp`` / etc. are off-registry.
There is no erlang.mk lockfile, so resolution is manifest-only (the registry
walk against hex.pm). All deps are :class:`~licenseal.models.Ecosystem.HEX`.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.hex.mix_exs import workspace_mix_names
from licenseal.discovery.hex.mix_lock import _OFF_REGISTRY_MARKER  # noqa: PLC2701
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


def _parse_dep_def(value: str) -> tuple[str | None, str, bool]:
    """A ``dep_X`` value → (hex_name_override | None, version, off_registry)."""
    tokens = value.split()
    if tokens and tokens[0] == "hex":
        version = tokens[1] if len(tokens) > 1 else ""
        override = tokens[2] if len(tokens) > 2 else None
        return override, version, False
    # git / git-subfolder / cp / ln / hg / svn / … (or empty / computed) →
    # not resolvable against hex.pm.
    return None, "", True


def _parse_makefile_text(text: str, source: str) -> list[Dependency]:
    """Extract direct Dependencies from an erlang.mk project Makefile."""
    if not _is_erlang_mk(text):
        return []
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
    seen: set[tuple[str, str]] = set()
    for apps, group in ((prod_apps, DependencyGroup.PROD), (dev_apps, DependencyGroup.DEV)):
        for app in apps:
            key = (app, group.value)
            if key in seen:
                continue
            seen.add(key)
            override, version, off_registry = (None, "", False)
            if app in dep_defs:
                override, version, off_registry = _parse_dep_def(dep_defs[app])
            out.append(
                Dependency(
                    name=override or app,
                    version_constraint=f"=={version}" if version else "",
                    ecosystem=Ecosystem.HEX,
                    group=group,
                    source=_OFF_REGISTRY_MARKER if off_registry else source,
                )
            )
    return out


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
        for dep in _parse_makefile_text(text, source):
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
    references — e.g. a rabbitmq sub-app's ``DEPS`` lists both external hex
    packages and dozens of internal ``deps/*`` apps.
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
