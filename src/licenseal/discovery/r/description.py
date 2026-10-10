"""R ``DESCRIPTION`` manifest parser.

A DESCRIPTION is a single DCF record. Direct dependencies live in five fields:
``Depends`` / ``Imports`` / ``LinkingTo`` (runtime / build → PROD) and
``Suggests`` / ``Enhances`` (optional / test / vignette → DEV). The project's
own license is the ``License:`` field; ``Package:`` names the package (used for
the multi-package workspace-internal filter).

Two R-specific filters apply: the ``R`` language pseudo-package
(``Depends: R (>= 4.1)``) and the base-priority packages bundled with R itself.
Neither is published to CRAN, so a registry lookup would 404. Recommended
packages (MASS, Matrix, lattice, …) *are* on CRAN and pass through.

The ``Remotes`` field says where a dependency is installed from when that is
not CRAN (``user/repo``, ``gitlab::user/repo``, ``git::<url>``, ``url::<url>``,
``local::<path>``, ``bioc::<package>``). A dependency it names is emitted with
an ``origin`` and is never looked up in the CRAN index; a ``local::`` path
inside the scanned directory is the project's own code and is not a
dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._origin import git_origin, hosted_git_origin, path_origin, url_origin
from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.r._dcf import parse_dcf, parse_package_list
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_PROD_FIELDS = ("Depends", "Imports", "LinkingTo")
_DEV_FIELDS = ("Suggests", "Enhances")

# Fields whose presence marks a DCF record as an R DESCRIPTION (rather than an
# unrelated file that happens to be named DESCRIPTION). Guards both dependency
# discovery and project-license detection against stray files.
_R_DESCRIPTION_MARKERS = (
    "Package",
    "Type",
    "Depends",
    "Imports",
    "Suggests",
    "LinkingTo",
    "Enhances",
)

# Base-priority packages bundled with R (``installed.packages(priority="base")``)
# plus the ``R`` language pseudo-package. None are published to CRAN, so they're
# filtered before any CRAN lookup. Compared case-insensitively for safety
# (R package names are case-sensitive, but no CRAN package collides with a base
# name under case folding).
_R_BASE_PACKAGES = frozenset(
    name.lower()
    for name in (
        "R",
        "base",
        "compiler",
        "datasets",
        "grDevices",
        "graphics",
        "grid",
        "methods",
        "parallel",
        "splines",
        "stats",
        "stats4",
        "tcltk",
        "tools",
        "translations",
        "utils",
    )
)


def is_base_package(name: str) -> bool:
    """True for the R language pseudo-package and base-priority packages.

    These ship with R and aren't published to CRAN, so discovery and the
    registry walker must skip them (they aren't in the CRAN PACKAGES index).
    """
    return name.lower() in _R_BASE_PACKAGES


def _is_r_description(record: dict[str, str]) -> bool:
    return any(marker in record for marker in _R_DESCRIPTION_MARKERS)


# One ``Remotes`` entry: ``[<package>=][<type>::]<spec>``. Without a type the
# spec is a GitHub ``user/repo``.
_REMOTE_RE = re.compile(
    r"(?:(?P<name>[A-Za-z][A-Za-z0-9.]*)=)?(?:(?P<type>[a-z]+)::)?(?P<spec>\S+)"
)

# The git hosting sites a remote type names, and their hosts.
_REMOTE_HOSTS = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}

# What follows the package name in the file name of an archive or a checkout.
_REMOTE_NAME_SUFFIX_RE = re.compile(r"(?:_[^/]*)?(?:\.git|\.tar\.gz|\.tgz|\.zip)?$")


def _remote_basename(location: str) -> str:
    """Package name a remote's last path segment stands for (``pkg_1.0.tar.gz`` → ``pkg``)."""
    return _REMOTE_NAME_SUFFIX_RE.sub("", location.rstrip("/").rsplit("/", 1)[-1])


def _remote_origins(value: str, desc_dir: Path, scan_root: Path) -> dict[str, str | None]:
    """Read a ``Remotes`` field into ``{lowercased package name: origin}``.

    The package a remote provides is the name written before ``=`` when the
    entry has one, and otherwise the repository, archive, or directory name,
    which is how the field is read when no name is given. An origin of
    ``None`` is a ``local::`` path inside the scanned directory. An entry of
    a type that is not a source outside CRAN (``cran::``, or one this parser
    does not know) names nothing.
    """
    origins: dict[str, str | None] = {}
    for raw in value.split(","):
        entry = _REMOTE_RE.fullmatch(raw.strip())
        if entry is None:
            continue
        kind = entry.group("type") or "github"
        spec = entry.group("spec")
        origin: str | None
        if kind in _REMOTE_HOSTS:
            # ``user/repo[/subdir][@ref][#pull]``
            repository, _, revision = spec.partition("#")[0].partition("@")
            segments = repository.split("/")
            if len(segments) < 2:
                continue
            provided = segments[1]
            origin = hosted_git_origin(_REMOTE_HOSTS[kind], "/".join(segments[:2]), revision)
        elif kind in ("git", "svn"):
            # ``<url>[@ref]``: an ``@`` after the last ``/`` starts the revision.
            url, at, revision = spec.rpartition("@")
            if not at or "/" in revision:
                url, revision = spec, ""
            provided = _remote_basename(url)
            origin = git_origin(url, revision, vcs=kind)
        elif kind == "url":
            provided = _remote_basename(spec.partition("?")[0])
            origin = url_origin(spec)
        elif kind == "local":
            provided = _remote_basename(spec)
            origin = path_origin(spec, desc_dir, scan_root)
        elif kind == "bioc":
            # ``[user:password@][release/]package[#commit]``
            provided = spec.rpartition("@")[2].partition("#")[0].rsplit("/", 1)[-1]
            origin = "Bioconductor"
        else:
            continue
        origins[(entry.group("name") or provided).lower()] = origin
    return origins


def _parse_description_deps(
    record: dict[str, str], source: str, desc_dir: Path, scan_root: Path
) -> tuple[list[Dependency], list[str]]:
    """Read the dependency fields of a DESCRIPTION record.

    Returns ``(deps, own)``: ``own`` names the dependencies a ``Remotes``
    entry places inside the scanned directory, which are the project's own
    code.
    """
    remotes = _remote_origins(record.get("Remotes", ""), desc_dir, scan_root)
    out: list[Dependency] = []
    own: list[str] = []
    seen: set[tuple[str, str]] = set()
    for fields, group in (
        (_PROD_FIELDS, DependencyGroup.PROD),
        (_DEV_FIELDS, DependencyGroup.DEV),
    ):
        for field in fields:
            value = record.get(field)
            if not value:
                continue
            for name, constraint in parse_package_list(value):
                if is_base_package(name):
                    continue
                key = (name.lower(), group.value)
                if key in seen:
                    continue
                seen.add(key)
                origin = remotes.get(name.lower(), "")
                if origin is None:
                    own.append(name)
                    continue
                out.append(
                    Dependency(
                        name=name,
                        version_constraint="" if origin else constraint,
                        ecosystem=Ecosystem.R,
                        group=group,
                        source=source,
                        origin=origin,
                    )
                )
    return out, own


def discover_description_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    workspace_names: frozenset[str] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct deps from every ``DESCRIPTION`` in the tree.

    ``workspace_names`` is the lowercased set of in-tree package names; sibling
    references (multi-package R repos) are filtered before any registry lookup.
    The filter count is returned alongside.
    """
    out: list[Dependency] = []
    filtered = 0
    for desc in walk_project_files(project_path, "DESCRIPTION", exclude_paths=exclude_paths):
        text = decode_text(desc)
        if text is None:
            continue
        records = parse_dcf(text)
        if not records or not _is_r_description(records[0]):
            continue
        source = desc.relative_to(project_path).as_posix()
        deps, own = _parse_description_deps(records[0], source, desc.parent, project_path)
        filtered += sum(name.lower() in workspace_names for name in own)
        for dep in deps:
            if dep.name.lower() in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered


def collect_dev_direct_names(deps: list[Dependency]) -> set[str]:
    """Return the lowercased R dep names whose only declaration is dev.

    A dep declared PROD anywhere (``Imports``/``Depends``/``LinkingTo``)
    outranks a DEV (``Suggests``/``Enhances``) declaration. Used as the DEV-root
    set for reverse-BFS group propagation through the lockfile.
    """
    prod_names: set[str] = set()
    dev_names: set[str] = set()
    for dep in deps:
        if dep.ecosystem != Ecosystem.R:
            continue
        if dep.group == DependencyGroup.DEV:
            dev_names.add(dep.name.lower())
        else:
            prod_names.add(dep.name.lower())
    return dev_names - prod_names


def detect_project_license_description(description: Path) -> str:
    """Return the ``License:`` field of one R ``DESCRIPTION``, or ``""``.

    The value is returned as declared, in R's license grammar (``GPL (>= 2)``,
    ``MIT + file LICENSE``). ``analysis.spdx.normalize_r_license`` is what
    turns it into SPDX: the generic normalizer would mis-handle ``GPL-2``-style
    tokens.
    """
    text = decode_text(description)
    if text is None:
        return ""
    records = parse_dcf(text)
    if not records or not _is_r_description(records[0]):
        return ""
    return records[0].get("License", "").strip()


def workspace_r_names(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> frozenset[str]:
    """Return the lowercased set of in-tree DESCRIPTION ``Package:`` names.

    Used to filter sibling references in multi-package R repositories before
    any registry lookup.
    """
    names: set[str] = set()
    for desc in walk_project_files(project_path, "DESCRIPTION", exclude_paths=exclude_paths):
        text = decode_text(desc)
        if text is None:
            continue
        records = parse_dcf(text)
        if records and records[0].get("Package"):
            names.add(records[0]["Package"].strip().lower())
    return frozenset(names)
