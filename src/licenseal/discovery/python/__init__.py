"""Shared constants and helpers for Python dependency discovery."""

from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement

# Regex to extract package name from PEP 508 / setup.cfg dependency strings
DEP_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
VERSION_RE = re.compile(r"([><=!~]+\s*[\d.*]+(?:\s*,\s*[><=!~]+\s*[\d.*]+)*)")

# Group names that indicate development (not production) dependencies.
# Used across pyproject.toml optional-dependencies/dependency-groups,
# setup.cfg extras_require, and requirements filename patterns.
DEV_GROUP_NAMES = frozenset({"dev", "test", "tests", "testing", "lint", "ci", "docs"})


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
    except InvalidRequirement:
        # Fall back to the regex parser for malformed strings — they were
        # silently dropped before this helper existed, and changing that
        # would alter discovery behavior on quirky manifests.
        name_match = DEP_NAME_RE.match(text)
        if not name_match:
            return "", "", frozenset()
        version_match = VERSION_RE.search(text)
        return (
            name_match.group(1),
            version_match.group(1) if version_match else "",
            frozenset(),
        )
    spec = str(req.specifier) if req.specifier else ""
    return req.name, spec, frozenset(req.extras)
