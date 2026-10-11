"""Discover PHP dependencies from composer.json files.

composer.json carries production deps under ``require`` and development deps
under ``require-dev``. Both maps are ``{vendor/package: version-constraint}``.

Platform pseudo-packages (``php``, ``php-64bit``, ``ext-*``, ``lib-*``,
``hhvm``, ``composer-plugin-api``, …) are filtered out — they aren't published
artifacts on Packagist (any HTTP fetch would 404), they're the runtime / engine
the project requires. They are recognized by having no ``/``: an installable
package is always ``vendor/package``, so a vendor that merely starts with
``php-`` / ``ext-`` / ``lib-`` is a real package.

``replace`` and ``provides`` are out of scope for the initial PHP ecosystem
landing — a small fraction of real projects fulfill another package via
``replace`` (e.g. shim packages for deprecated names). The lockfile-first
resolver path masks the most common cases because composer.lock records the
real replacement; manifest-only mode may emit a phantom dep that resolves
UNKNOWN until the package is reviewed away.

``repositories`` says where a package comes from when that is not Packagist.
What composer.json alone lets us determine:

* a ``package`` repository defines a package inline, with its ``source`` or
  ``dist``: a requirement of that name is not a Packagist package and is
  emitted with that origin;
* a ``path`` repository inside the scanned directory holds the project's own
  packages: a requirement that names one (by the ``name`` of a composer.json
  found there) is not a dependency.

What it does not: which requirements a ``vcs`` repository, or a ``path``
repository outside the scanned directory, provides. Composer learns that by
reading the repository. Those names are looked up on Packagist unless a
composer.lock says where each package came from. A ``composer`` repository
is another registry: its packages are looked up on Packagist by name.
"""

from __future__ import annotations

import os
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, cast

from licenseal.discovery._origin import UNRECORDED, git_origin, path_origin, url_origin
from licenseal.discovery._read import (
    load_json,
    record_unexpected_type,
    root_table,
    typed_field,
)
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _license_field_to_raw(value: object) -> str:
    """Normalize composer's license field shape into a single raw string.

    composer schema accepts either a single string (``"MIT"``) or an array
    of strings (``["MIT", "Apache-2.0"]``). Per the Composer documentation
    the array form expresses *disjunctive* licensing — the consumer may
    choose either license — so we join with ``OR`` to preserve that intent
    when the value flows through :func:`analysis.spdx.normalize_license`.
    Empty / non-string entries are dropped; bare-string passes through.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        items: list[str] = [v.strip() for v in value if isinstance(v, str) and v.strip()]
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        return " OR ".join(items)
    return ""


def composer_map(path: Path, table: dict[str, Any], key: str, what: str = "") -> dict[str, Any]:
    """Return the ``key`` map of a Composer document, empty when absent.

    PHP serialises an empty map as an empty array, so ``[]`` is an empty map
    here. Any other value that is not an object is recorded as a gap named
    ``what`` (the quoted key when omitted).
    """
    if table.get(key) == []:
        return {}
    return typed_field(path, table, key, dict, what or f'"{key}"') or {}


# Repository types that fetch a package from a version-control repository.
VCS_REPOSITORY_TYPES = frozenset(
    {
        "vcs",
        "git",
        "github",
        "gitlab",
        "bitbucket",
        "git-bitbucket",
        "forgejo",
        "hg",
        "svn",
        "fossil",
        "perforce",
    }
)
# The ``source.type`` values that are not git.
_OTHER_VCS = frozenset({"hg", "svn", "fossil"})

_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_URL_USER_RE = re.compile(r"^[^/@]+@")


def composer_repositories(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The repository tables of a composer.json, in its list or its map form."""
    repositories = data.get("repositories")
    if isinstance(repositories, dict):
        repositories = list(repositories.values())
    if not isinstance(repositories, list):
        return []
    return [cast("dict[str, Any]", repo) for repo in repositories if isinstance(repo, dict)]


def repository_key(url: str) -> str:
    """A repository URL in a form two spellings of one repository share.

    Host and path, lowercased, without scheme, user, ``.git``, or a trailing
    slash; ``git@host:path`` reads as ``host/path``.
    """
    key = url.strip().lower()
    if "://" in key:
        key = _URL_USER_RE.sub("", _URL_SCHEME_RE.sub("", key))
    else:
        key = _URL_USER_RE.sub("", key).replace(":", "/", 1)
    return key.rstrip("/").removesuffix(".git")


def package_origin(package: dict[str, Any], base_dir: Path, scan_root: Path) -> str | None:
    """Origin of a Composer package definition, from its ``source`` or ``dist``.

    ``package`` is a composer.lock entry or an inline ``package`` repository
    definition. ``source`` is the repository plus its ``reference`` (the
    locked commit in a lockfile). Without one, ``dist`` is a path
    (``None`` when it is inside ``scan_root``) or a download URL plus its
    ``shasum``.
    """
    source = package.get("source")
    dist = package.get("dist")
    for table, is_source in ((source, True), (dist, False)):
        if not isinstance(table, dict):
            continue
        url = table.get("url")
        if not isinstance(url, str) or not url:
            continue
        kind = table.get("type")
        if kind == "path":
            return path_origin(url, base_dir, scan_root)
        reference = table.get("reference")
        if is_source:
            vcs = kind if kind in _OTHER_VCS else "git"
            return git_origin(url, reference if isinstance(reference, str) else "", vcs=vcs)
        shasum = table.get("shasum")
        return url_origin(url, shasum if isinstance(shasum, str) else "")
    return UNRECORDED


def inline_package_origins(
    repositories: list[dict[str, Any]], base_dir: Path, scan_root: Path
) -> dict[str, str | None]:
    """Lowercased name → origin of each package a ``package`` repository defines."""
    origins: dict[str, str | None] = {}
    for repo in repositories:
        if repo.get("type") != "package":
            continue
        defined = repo.get("package")
        for package in defined if isinstance(defined, list) else [defined]:
            if isinstance(package, dict) and isinstance(package.get("name"), str):
                origins.setdefault(
                    package["name"].lower(),
                    package_origin(cast("dict[str, Any]", package), base_dir, scan_root),
                )
    return origins


def _own_path_packages(
    repositories: list[dict[str, Any]], base_dir: Path, names_by_dir: dict[Path, str]
) -> set[str]:
    """Lowercased names of the in-tree packages the ``path`` repositories hold.

    ``names_by_dir`` maps the directory of each composer.json in the scanned
    tree to the name it declares. A ``path`` repository URL is relative to
    ``base_dir`` and may hold ``*`` wildcards (``packages/*``).
    """
    patterns = [
        repo["url"].replace("\\", "/").removeprefix("./").rstrip("/")
        for repo in repositories
        if repo.get("type") == "path" and isinstance(repo.get("url"), str)
    ]
    own: set[str] = set()
    for directory, name in names_by_dir.items():
        relative = Path(os.path.relpath(directory, base_dir)).as_posix()
        if any(fnmatchcase(relative, pattern) for pattern in patterns):
            own.add(name.lower())
    return own


def _parse_composer_json(
    filepath: Path,
    data: dict[str, Any],
    source: str,
    scan_root: Path,
    names_by_dir: dict[Path, str],
) -> tuple[list[Dependency], int]:
    """Parse a single composer.json document into direct Dependencies.

    A section that is not a map, and a constraint that is not a string, are
    recorded as gaps and read as absent: the section declares nothing, the
    package is unconstrained. The other section is still read.

    Returns ``(deps, filtered)``. A requirement on a package that a
    ``package`` repository of this file defines carries that origin. One on
    a package of the scanned tree, held by a ``path`` repository of this
    file, is the project's own code: it is counted in ``filtered`` and not
    returned.
    """
    deps: list[Dependency] = []
    filtered = 0
    repositories = composer_repositories(data)
    inline = inline_package_origins(repositories, filepath.parent, scan_root)
    own = _own_path_packages(repositories, filepath.parent, names_by_dir)

    for field_name, group in (
        ("require", DependencyGroup.PROD),
        ("require-dev", DependencyGroup.DEV),
    ):
        for name, spec in composer_map(filepath, data, field_name).items():
            # No ``/`` means a platform pseudo-package (or a malformed name),
            # never an installable ``vendor/package``.
            if "/" not in name:
                continue
            if not isinstance(spec, str):
                record_unexpected_type(filepath, f'an entry of "{field_name}"')
                spec = ""
            origin = inline.get(name.lower(), "")
            if name.lower() in own or origin is None:
                filtered += 1
                continue
            deps.append(
                Dependency(
                    name=name,
                    version_constraint="" if origin else spec,
                    ecosystem=Ecosystem.PHP,
                    group=group,
                    source=source,
                    origin=origin,
                )
            )
    return deps, filtered


def discover_composer_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover all PHP dependencies from composer.json files in the tree.

    Returns ``(deps, filtered_count)``. The filter count is the number of
    requirements on a package of the scanned tree that a ``path`` repository
    of the requiring composer.json holds: the project's own code.
    """
    composer_files = walk_project_files(project_path, "composer.json", exclude_paths=exclude_paths)
    parsed = [
        (cj, data) for cj in composer_files if (data := root_table(cj, load_json(cj))) is not None
    ]
    names_by_dir = {
        cj.parent: data["name"] for cj, data in parsed if isinstance(data.get("name"), str)
    }
    deps: list[Dependency] = []
    filtered = 0
    for cj, data in parsed:
        source = cj.relative_to(project_path).as_posix()
        file_deps, file_filtered = _parse_composer_json(
            cj, data, source, project_path, names_by_dir
        )
        deps.extend(file_deps)
        filtered += file_filtered
    return deps, filtered


def detect_project_license_composer_json(composer_json: Path) -> str:
    """Return the license one ``composer.json`` declares for its package, or ``""``.

    Array values are joined with ``OR`` per Composer's disjunctive-array
    convention; a downstream normalizer maps that through SPDX
    canonicalization.
    """
    data = root_table(composer_json, load_json(composer_json))
    if data is None:
        return ""
    return _license_field_to_raw(data.get("license", ""))
