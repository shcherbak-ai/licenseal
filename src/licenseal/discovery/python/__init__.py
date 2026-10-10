"""Shared constants and helpers for Python dependency discovery."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

from packaging.requirements import Requirement

from licenseal.discovery._read import record_unexpected_type, typed_field

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
