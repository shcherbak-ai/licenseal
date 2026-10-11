"""Shared constants and helpers for Python dependency discovery.

A requirement on a registry release carries a version specifier. One that
points at a URL, a VCS repository, or a path does not come from PyPI: the
helpers here turn it into a dependency with an origin (see
:mod:`licenseal.discovery._origin`), or into nothing when the path is inside
the scanned directory, which makes it the project's own code.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

from packaging.requirements import Requirement

from licenseal.discovery._origin import UNRECORDED, git_origin, path_origin, url_origin
from licenseal.discovery._read import record_unexpected_type, typed_field
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Everything ``Requirement(text)`` raises on text it cannot parse.
# ``InvalidRequirement`` is a ``ValueError``. The marker parser adds the rest:
# a quoted value is evaluated as a Python string literal, so one that is not a
# valid literal (a stray backslash, a line break) is a ``SyntaxError``, an
# embedded NUL a ``SyntaxError`` or ``ValueError`` depending on the
# interpreter, and parentheses nested too deeply a ``RecursionError``.
REQUIREMENT_PARSE_ERRORS = (ValueError, SyntaxError, RecursionError)

# Regex to extract package name from PEP 508 / setup.cfg dependency strings
DEP_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
VERSION_RE = re.compile(r"([><=!~]+\s*[\d.*]+(?:\s*,\s*[><=!~]+\s*[\d.*]+)*)")
# A leading token that contains a path separator is a local wheel, archive, or
# directory path rather than a requirement. A ``scheme://`` URL is not a path
# and is left as it was. A backslash only counts when more of the token
# follows it: a lone trailing one is a line continuation.
_PATH_TOKEN_RE = re.compile(r"(?!\S*://)\S*(?:/|\\\S)")

# ``name @ <location>`` in a form PEP 508 does not parse (a path with a space
# in it): the location runs to the end of the string or to a ``;`` marker.
_NAME_AT_LOCATION_RE = re.compile(
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?"
    r"\s*@\s*(?P<location>[^;]+?)\s*(?:;.*)?"
)
# A requirement given as a bare URL: ``https://…/pkg.whl``, ``git+https://…``.
_URL_TOKEN_RE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://|(?:git|hg|svn|bzr)\+)")
_VCS_URL_RE = re.compile(r"(?:git|hg|svn|bzr)\+")
# Extras requested of a path or URL requirement: ``./dir[test]``.
_TRAILING_EXTRAS_RE = re.compile(r"\[[^\]]*\]$")
# File names of the archives a requirement can point at.
_ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")
# ``<name>-<version>…``, the layout of a wheel or sdist file name.
_ARCHIVE_NAME_RE = re.compile(r"(?P<name>.+?)-\d")
_EGG_RE = re.compile(r"(?:^|&)egg=(?P<name>[^&\[]+)")
# A hash a URL carries in its fragment: ``#sha256=…``.
_HASH_FRAGMENT_RE = re.compile(r"(?:^|&)(?P<hash>(?:sha\d+|md5|blake2b?)=[0-9A-Fa-f]+)")
# The keys of a Poetry, uv, or Pipfile source table that name a repository,
# and the ones that name the revision to take from it.
_VCS_KEYS = ("git", "hg", "svn", "bzr")
_REVISION_KEYS = ("rev", "ref", "tag", "branch")

# Group names that indicate development (not production) dependencies.
# Used across pyproject.toml optional-dependencies/dependency-groups,
# setup.cfg extras_require, and requirements filename patterns.
DEV_GROUP_NAMES = frozenset({"dev", "test", "tests", "testing", "lint", "ci", "docs"})


def table_spec(path: Path, spec: object, what: str) -> tuple[str, frozenset[str]]:
    """Read a Poetry or Pipfile dependency spec into ``(version, extras)``.

    A spec is a version string, or a table whose ``version`` is a string and
    whose ``extras`` is a list of strings; both keys are optional. Anything
    of another type is recorded as a gap on ``path``, named ``what``, and
    read as absent: the dependency is kept, without the constraint or the
    extras that could not be read.
    """
    if isinstance(spec, str):
        return spec, frozenset()
    if not isinstance(spec, dict):
        record_unexpected_type(path, what)
        return "", frozenset()
    table = cast("dict[str, Any]", spec)
    version = typed_field(path, table, "version", str, what) or ""
    extras = typed_field(path, table, "extras", list, what) or []
    if not all(isinstance(extra, str) for extra in extras):
        record_unexpected_type(path, what)
    return version, frozenset(extra for extra in extras if isinstance(extra, str))


def parse_pep508_dep(dep_str: str) -> tuple[str, str, frozenset[str]]:
    """Parse a PEP 508 string into ``(name, version_constraint, extras)``.

    Uses :class:`packaging.requirements.Requirement` so we capture extras
    requested at the call site — ``requests[socks]>=2`` →
    ``("requests", ">=2", {"socks"})``. The transitive walker needs the
    extras to evaluate child deps' ``extra ==`` markers correctly (without
    them we'd over-report every extras-gated transitive).

    Returns ``("", "", frozenset())`` for syntactically-invalid strings
    rather than raising; callers historically skip empty-name entries.
    """
    text = dep_str.strip()
    if not text:
        return "", "", frozenset()
    try:
        req = Requirement(text)
    except REQUIREMENT_PARSE_ERRORS:
        # Fall back to the regex parser for malformed strings — they were
        # silently dropped before this helper existed, and changing that
        # would alter discovery behavior on quirky manifests. A path is the
        # exception: its first segment is a directory, not a package name.
        name_match = DEP_NAME_RE.match(text)
        if not name_match or _PATH_TOKEN_RE.match(text):
            return "", "", frozenset()
        version_match = VERSION_RE.search(text)
        return (
            name_match.group(1),
            version_match.group(1) if version_match else "",
            frozenset(),
        )
    spec = str(req.specifier) if req.specifier else ""
    return req.name, spec, frozenset(req.extras)


def _location_name(location: str) -> str:
    """Name for a requirement that is given only as a URL or a path.

    The ``#egg=`` fragment names it when there is one. Otherwise the name is
    read off the last path segment: the distribution name of a wheel or
    sdist file name, the repository name of a VCS URL, the directory name of
    a path. A segment that leaves no letter or digit (``..``, ``*.whl``, a
    bare ``.whl``, the root) names nothing: the location as written is the
    name then, so the requirement is neither dropped nor called ``*``.
    """
    main, _, fragment = location.partition("#")
    egg = _EGG_RE.search(fragment)
    if egg:
        return egg.group("name")
    name = main.partition("?")[0].replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if _VCS_URL_RE.match(location):
        name = name.partition("@")[0].removesuffix(".git")
    for suffix in _ARCHIVE_SUFFIXES:
        if name.lower().endswith(suffix):
            stem = name[: -len(suffix)]
            archive = _ARCHIVE_NAME_RE.match(stem)
            name = archive.group("name") if archive else stem
            break
    return name if any(char.isalnum() for char in name) else main.strip()


def direct_reference_origin(
    location: str, base_dir: Path, scan_root: Path, digest: str = ""
) -> str | None:
    """Origin of a requirement's direct reference; ``None`` for the project's own code.

    ``location`` is what follows ``@`` in a PEP 508 direct reference, or a
    requirement given as a bare URL or path. A VCS URL (``git+https://…@rev``)
    is a repository at that revision. Any other URL is a direct download,
    with ``digest`` (or the hash in its fragment) when one is recorded. A
    ``file:`` URL and a bare path are a path, relative to ``base_dir``.
    """
    main, _, fragment = location.strip().partition("#")
    if _VCS_URL_RE.match(main):
        # The revision follows the last ``@`` of the path; an ``@`` before
        # the path belongs to the host part.
        path_start = main.find("/", main.find("://") + 3)
        repository, at, revision = main[path_start:].rpartition("@")
        if path_start != -1 and at:
            return git_origin(main[:path_start] + repository, revision)
        return git_origin(main)
    if "://" in main and not main.startswith("file:"):
        recorded = _HASH_FRAGMENT_RE.search(fragment)
        return url_origin(main, digest or (recorded.group("hash") if recorded else ""))
    return path_origin(main, base_dir, scan_root)


def _unparsed_reference(text: str) -> tuple[str, str] | None:
    """``(name, location)`` of a URL or path requirement PEP 508 does not parse."""
    named = _NAME_AT_LOCATION_RE.fullmatch(text)
    if named:
        return named.group("name"), named.group("location")
    token = _TRAILING_EXTRAS_RE.sub("", text.split(maxsplit=1)[0])
    if _URL_TOKEN_RE.match(token) or _PATH_TOKEN_RE.match(token) or token in (".", ".."):
        return _location_name(token), token
    return None


def requirement_dependency(
    text: str,
    group: DependencyGroup,
    source: str,
    base_dir: Path,
    scan_root: Path,
    *,
    digest: str = "",
) -> Dependency | None:
    """Turn one requirement string into a Dependency, or ``None`` when it declares none.

    A requirement on a registry release is returned with its version
    specifier and extras. A direct reference (``name @ <url>``), a bare URL
    or VCS URL, and a path are not registry releases: the dependency carries
    an origin instead of a specifier and is never looked up. A path inside
    ``scan_root`` is the project's own code and yields ``None``, as does a
    string with no readable name.

    ``base_dir`` is the directory a relative path is taken from, and
    ``digest`` a hash recorded beside the requirement.
    """
    text = text.strip()
    if not text:
        return None
    try:
        req = Requirement(text)
    except REQUIREMENT_PARSE_ERRORS:
        reference = _unparsed_reference(text)
        extras: frozenset[str] = frozenset()
    else:
        extras = frozenset(req.extras)
        if req.url:
            reference = (req.name, req.url)
        elif req.name.lower().endswith(_ARCHIVE_SUFFIXES):
            # A bare archive file name is a file in the working directory.
            reference = (_location_name(req.name), req.name)
        else:
            reference = None
    if reference is None:
        name, spec, extras = parse_pep508_dep(text)
        origin: str | None = ""
    else:
        name, location = reference
        spec = ""
        origin = direct_reference_origin(location, base_dir, scan_root, digest)
    if not name or origin is None:
        return None
    return Dependency(
        name=name,
        version_constraint=spec,
        ecosystem=Ecosystem.PYTHON,
        group=group,
        source=source,
        origin=origin,
        extras=extras,
    )


def source_table_origin(
    path: Path, table: dict[str, Any], what: str, base_dir: Path, scan_root: Path
) -> str | None:
    """Origin a Poetry, uv, Pipfile, or Pipfile.lock dependency table declares.

    Empty when the table names no source outside the registry (a version, an
    alternate index). ``None`` when it names the project's own code: a uv
    ``workspace = true`` member, or a path that the scan reads. A source key
    whose value is not a string is recorded as a gap on ``path``, named
    ``what``; the dependency is then off the registry with no recorded source.
    """
    if table.get("workspace") is True:
        return None
    for key in (*_VCS_KEYS, "url", "path", "file"):
        if key not in table:
            continue
        value = typed_field(path, table, key, str, what)
        if not value:
            return UNRECORDED
        if key in _VCS_KEYS:
            revision = next(
                (table[k] for k in _REVISION_KEYS if isinstance(table.get(k), str) and table[k]),
                "",
            )
            return git_origin(value, revision, vcs=key)
        if key == "url" or (key == "file" and "://" in value and not value.startswith("file:")):
            return url_origin(value)
        return path_origin(value, base_dir, scan_root)
    return ""
