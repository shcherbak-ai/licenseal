"""Version-selection helpers for range-aware registry resolution."""

from __future__ import annotations

import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion
from packaging.version import Version as PackagingVersion
from semantic_version import NpmSpec
from semantic_version import Version as SemVer

_UNSUPPORTED_NPM_PREFIXES = (
    "workspace:",
    "file:",
    "link:",
    "npm:",
    "git+",
    "git://",
    "http://",
    "https://",
)
_UNSUPPORTED_PYTHON_MARKERS = (" @ ", "://", "git+")

# Real npm semver accepts whitespace between comparison operators and version
# numbers (`">= 1.0.0 < 2.0.0"`), and multiple spaces between AND-combined
# range terms; the `semantic_version` library's NpmSpec accepts neither.
# Tighten operators against their version and collapse runs of whitespace to
# a single space so we accept what registries publish.
_NPM_OPERATOR_SPACE_RE = re.compile(r"(<=|>=|<|>|=|~|\^)\s+(?=\d|[xX*])")
_NPM_RUN_OF_WHITESPACE_RE = re.compile(r"\s+")


def select_python_version(version_constraint: str, published_versions: list[str]) -> str | None:
    """Select the highest published Python version that matches the constraint."""
    spec = version_constraint.strip()
    if not spec or any(marker in spec for marker in _UNSUPPORTED_PYTHON_MARKERS):
        return None

    try:
        specifier = SpecifierSet(spec)
    except InvalidSpecifier:
        return None

    candidates: dict[PackagingVersion, str] = {}
    for raw_version in published_versions:
        try:
            parsed = PackagingVersion(raw_version)
        except InvalidVersion:
            continue
        candidates[parsed] = raw_version

    if not candidates:
        return None
    allowed = list(specifier.filter(candidates, prereleases=None))
    if not allowed:
        return None
    return candidates[max(allowed)]


def select_npm_version(version_constraint: str, published_versions: list[str]) -> str | None:
    """Select the highest published npm version that matches the constraint."""
    spec = version_constraint.strip()
    if not spec or spec.startswith(_UNSUPPORTED_NPM_PREFIXES):
        return None

    spec = _NPM_OPERATOR_SPACE_RE.sub(r"\1", spec)
    spec = _NPM_RUN_OF_WHITESPACE_RE.sub(" ", spec)

    try:
        npm_spec = NpmSpec(spec)
    except ValueError:
        return None

    candidates: list[tuple[SemVer, str]] = []
    for raw_version in published_versions:
        try:
            parsed = SemVer(raw_version.lstrip("v"))
        except ValueError:
            continue
        if npm_spec.match(parsed):
            candidates.append((parsed, raw_version))

    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


# Composer-native constraint prefixes that aren't a published-version range:
# ``dev-<branch>`` and ``<branch>-dev`` aliases resolve to a branch ref, not
# a Packagist-published version. Their license belongs to whatever the
# lockfile pinned, not to a stable tag — return None so the resolver picks
# the latest stable instead. ``*`` is the "any version" wildcard; we also
# treat it as "pick latest stable".
_PHP_NON_RANGE_PREFIXES = ("dev-",)
_PHP_NON_RANGE_SUFFIXES = ("-dev",)


def select_php_version(version_constraint: str, published_versions: list[str]) -> str | None:
    """Select the highest published Composer version that matches the constraint.

    Composer's range grammar is close enough to npm's for the common shapes
    (``^1.2``, ``~1.2``, ``1.2.*``, ``>=1.0 <2.0``, exact pins) that npm's
    spec resolver covers nearly all real-world cases. Differences worth
    documenting:

    * Composer's ``~1.2.3`` means ``>=1.2.3 <1.3.0`` (locked to patch);
      npm's ``~1.2.3`` means ``>=1.2.3 <1.3.0`` — same.
    * Composer's ``~1.2`` means ``>=1.2 <2.0`` (locked to minor); npm's
      ``~1.2`` means ``>=1.2.0 <1.3.0`` — diverges.
    * Composer's ``^`` matches npm's ``^`` for ``X.Y.Z`` with ``X>=1``.
    * Branch aliases (``dev-main``, ``1.x-dev``) return None — the caller
      falls back to the latest stable published version.

    Accepted v1 risk: the lockfile-first path bypasses this selector
    entirely, so the divergences only affect manifest-only scans. Stress-
    testing will surface the frequency of mismatch in practice.
    """
    spec = version_constraint.strip()
    if not spec or spec == "*":
        return None
    if spec.startswith(_PHP_NON_RANGE_PREFIXES):
        return None
    if any(spec.endswith(suffix) for suffix in _PHP_NON_RANGE_SUFFIXES):
        return None
    # Composer's ``v`` prefix on version strings is decorative; strip it
    # both from the spec and the published list before npm-semver matching.
    if spec.startswith(("^v", "~v")):
        spec = spec[0] + spec[2:]
    cleaned_versions = [v.lstrip("v") for v in published_versions]
    return select_npm_version(spec, cleaned_versions)


def resolve_npm_spec(package_data: dict, version_constraint: str) -> str:
    """Resolve an npm version spec against the registry's ``/{name}`` response.

    Handles npm dist-tags (``"latest"``, ``"next"``, ``"beta"``, or any custom
    tag the publisher set) by consulting the response's ``dist-tags`` field
    first. Falls back to semver-range resolution via :func:`select_npm_version`
    against the ``versions`` map. Returns the resolved version string, or ""
    if no match.
    """
    spec = version_constraint.strip()
    dist_tags = package_data.get("dist-tags", {})
    if isinstance(dist_tags, dict):
        tag_version = dist_tags.get(spec)
        if isinstance(tag_version, str) and tag_version:
            return tag_version
    versions = package_data.get("versions", {})
    version_map = versions if isinstance(versions, dict) else {}
    return select_npm_version(spec, list(version_map)) or ""
