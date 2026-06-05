"""Static *.gemspec parser.

A ``Gem::Specification.new do |spec| ... end`` block is Ruby source — same
no-execution rule applies. We regex over the source text for the load-bearing
fields:

* ``<receiver>.license = "X"`` (singular) and
  ``<receiver>.licenses = ["X", "Y"]`` (plural) — project license signal.
* ``<receiver>.add_dependency "name", "constraint"`` and
  ``<receiver>.add_runtime_dependency "name", "constraint"`` — PROD deps.
* ``<receiver>.add_development_dependency "name", "constraint"`` — DEV deps.
* ``<receiver>.name = "X"`` — for the workspace-internal filter (monorepo
  gemspecs reference each other; we shouldn't try to resolve a sibling gem
  against rubygems.org).

Anything that isn't a string literal (constants, ENV reads, method calls,
interpolated strings) is rejected silently — the field becomes "" and the
registry resolver backfills.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files_matching
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Match ``spec.license = "MIT"`` / ``s.license = 'MIT'`` (singular).
# Receiver is any identifier; we only need the RHS string.
_LICENSE_SINGULAR_RE = re.compile(
    r"""\b\w+\.license\s*=\s*(['"])([^'"]+)\1""",
)

# Match ``spec.licenses = ["MIT", "Apache-2.0"]`` (plural).
_LICENSES_PLURAL_RE = re.compile(
    r"""\b\w+\.licenses\s*=\s*\[(?P<body>[^\]]*)\]""",
)

# Extract each quoted token from the plural array body.
_LITERAL_STRING_RE = re.compile(r"""(['"])([^'"]+)\1""")

# Match ``spec.name = "foo"`` (workspace-internal name).
_SPEC_NAME_RE = re.compile(
    r"""\b\w+\.name\s*=\s*(['"])([^'"]+)\1""",
)

# Match dependency-add calls. The ``add_dependency`` form is an alias for
# ``add_runtime_dependency``; both → PROD. ``add_development_dependency`` →
# DEV. The constraint args are optional.
_DEP_CALL_RE = re.compile(
    r"""
    \b\w+\.
    (?P<kind>add_dependency|add_runtime_dependency|add_development_dependency)
    \s*\(?\s*
    (?P<quote>['"])
    (?P<name>[^'"]+)
    (?P=quote)
    (?P<rest>[^\n]*)
    """,
    re.VERBOSE,
)

_CONSTRAINT_TOKEN_RE = re.compile(r"""\s*,\s*(['"])([^'"]+)\1""")


def _license_array_body_to_raw(body: str) -> str:
    """``"MIT", "Apache-2.0"`` → ``MIT OR Apache-2.0``.

    Mirrors the PHP convention: array form is disjunctive (consumer picks
    one), joined with ``OR`` so the SPDX normalizer can parse it as an
    expression. Empty body → "".
    """
    items = [m.group(2).strip() for m in _LITERAL_STRING_RE.finditer(body)]
    items = [item for item in items if item]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return " OR ".join(items)


def _extract_license_from_text(text: str) -> str:
    """Return the first license value found in gemspec source.

    Plural form is preferred when both are present (newer gemspec convention).
    """
    plural = _LICENSES_PLURAL_RE.search(text)
    if plural is not None:
        raw = _license_array_body_to_raw(plural.group("body"))
        if raw:
            return raw
    singular = _LICENSE_SINGULAR_RE.search(text)
    if singular is not None:
        return singular.group(2).strip()
    return ""


def _extract_name_from_text(text: str) -> str:
    """Return the gem's declared name (``spec.name = "..."``) if a literal."""
    m = _SPEC_NAME_RE.search(text)
    if m is None:
        return ""
    return m.group(2).strip()


def _parse_gemspec_text(text: str, source: str) -> list[Dependency]:
    """Extract Dependency entries from a gemspec source body."""
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for m in _DEP_CALL_RE.finditer(text):
        name = m.group("name").strip()
        if not name:
            continue
        kind = m.group("kind")
        rest = m.group("rest") or ""
        constraints: list[str] = []
        remaining = rest
        while True:
            v = _CONSTRAINT_TOKEN_RE.match(remaining)
            if v is None:
                break
            constraints.append(v.group(2).strip())
            remaining = remaining[v.end() :]
        group = (
            DependencyGroup.DEV if kind == "add_development_dependency" else DependencyGroup.PROD
        )
        key = (name.lower(), group.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Dependency(
                name=name,
                version_constraint=", ".join(constraints),
                ecosystem=Ecosystem.RUBY,
                group=group,
                source=source,
            )
        )
    return out


def workspace_gemspec_names(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> frozenset[str]:
    """Return the lowercased set of in-tree gemspec ``spec.name`` values.

    Used as the workspace-internal filter by the Gemfile and Gemfile.lock
    discovery paths so monorepo siblings (rails: ``actionpack`` referencing
    ``activesupport``) are dropped before any registry lookup.
    """
    names: set[str] = set()
    for gemspec in _walk_gemspecs(project_path, exclude_paths=exclude_paths):
        text = decode_text(gemspec)
        if text is None:
            continue
        spec_name = _extract_name_from_text(text)
        if spec_name:
            names.add(spec_name.lower())
        else:
            # Fall back to the file stem: ``activerecord.gemspec`` → ``activerecord``.
            stem = gemspec.stem
            if stem:  # pragma: no branch - *.gemspec always has a non-empty stem
                names.add(stem.lower())
    return frozenset(names)


def _walk_gemspecs(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``*.gemspec`` file in the tree."""
    return walk_project_files_matching(
        project_path,
        lambda fname: fname.endswith(".gemspec"),
        exclude_paths=exclude_paths,
    )


def discover_gemspec_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    workspace_names: frozenset[str] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover deps from every ``*.gemspec`` in the tree.

    ``workspace_names`` filters out monorepo sibling references (e.g. rails
    gemspecs reference each other). The filter count is returned alongside.
    """
    out: list[Dependency] = []
    filtered = 0
    for gemspec in _walk_gemspecs(project_path, exclude_paths=exclude_paths):
        text = decode_text(gemspec)
        if text is None:
            continue
        source = gemspec.relative_to(project_path).as_posix()
        for dep in _parse_gemspec_text(text, source):
            if dep.name.lower() in workspace_names:
                filtered += 1
                continue
            out.append(dep)
    return out, filtered


def detect_project_license_gemspec(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Return the first non-empty ``license`` / ``licenses`` value from a gemspec.

    Walks the tree so monorepos without a root-level gemspec still surface
    a declared license. Plural form preferred (modern convention); array
    values OR-joined.
    """
    for gemspec in _walk_gemspecs(project_path, exclude_paths=exclude_paths):
        text = decode_text(gemspec)
        if text is None:
            continue
        raw = _extract_license_from_text(text)
        if raw:
            return raw
    return ""
