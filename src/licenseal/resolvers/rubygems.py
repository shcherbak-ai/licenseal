"""Resolve license information for Ruby gems from rubygems.org.

Two endpoints carry the load:

* ``GET /api/v2/rubygems/{name}/versions/{version}.json`` — primary, used
  whenever the lockfile pinned a specific version (the typical scan path).
  Returns ``{"licenses": ["MIT"], "source_code_uri": "...", "dependencies":
  {"runtime": [...], "development": [...]}}``.
* ``GET /api/v1/gems/{name}.json`` — fallback for manifest-only scans with
  no resolved version. Returns the latest version's metadata in the same
  shape (top-level ``licenses`` array etc.).

Unlike PHP / Composer, ``Gemfile.lock`` carries no embedded SPDX license
field, so there is **no lockfile-license pre-pass** for Ruby — every dep
either hits the deps.dev batch cache (handled in the CLI dispatch) or
falls through to one of the rubygems.org endpoints here.

Off-registry deps (``GIT`` / ``PATH`` sections in Gemfile.lock) short-
circuit to UNKNOWN without any fetch — they don't have a rubygems.org
record and a 404 would be wasted bandwidth.
"""

from __future__ import annotations

from dataclasses import replace

import httpx

from licenseal.analysis.spdx import normalize_license
from licenseal.discovery.ruby.lockfiles import is_off_registry_marker
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.http import Fetcher, fetch_registry_json

_RUBYGEMS_REGISTRY_URL = "https://rubygems.org"


def _rubygems_version_url(name: str, version: str) -> str:
    """Per-version v2 endpoint URL."""
    return f"{_RUBYGEMS_REGISTRY_URL}/api/v2/rubygems/{name}/versions/{version}.json"


def _rubygems_gem_url(name: str) -> str:
    """Latest-version v1 endpoint URL (unpinned fallback)."""
    return f"{_RUBYGEMS_REGISTRY_URL}/api/v1/gems/{name}.json"


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact RubyGems version when the spec is pinned.

    Accepts two pin shapes:

    * ``==X.Y.Z`` — licenseal-internal form emitted by the lockfile parser.
    * ``= X.Y.Z`` — Gem::Requirement's native exact-pin operator, which
      appears in ``dependencies.runtime.requirements`` on the registry
      response. The walker propagates that constraint to children.

    Range / wildcard / multi-constraint shapes (``~> 1.2``, ``>= 1.0``,
    ``"~> 1.2", ">= 1.2.3"``) return None. RubyGems versions do not use a
    ``v`` prefix (unlike Packagist's optional decorative ``v``), so no
    prefix-stripping is needed.
    """
    spec = version_constraint.strip()
    if not spec or "," in spec:
        return None
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        if not candidate or " " in candidate:
            return None
        return candidate
    if spec.startswith("="):
        candidate = spec[1:].strip()
        # pragma: no branch — ``=`` form is always one of two outcomes
        if not candidate or " " in candidate:  # pragma: no branch
            return None
        return candidate
    return None


def _license_field_to_raw(value: object) -> str:
    """Normalize the registry ``licenses`` field into a single raw string.

    rubygems.org always returns ``licenses`` as an array of strings; we
    follow the same disjunctive convention as PHP — multi-element arrays
    are OR-joined (the publisher offered the consumer a choice). Bare-
    string is accepted defensively even though the v2/v1 endpoints never
    emit it.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        items = [v.strip() for v in value if isinstance(v, str) and v.strip()]
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        return " OR ".join(items)
    return ""


def _extract_repository_url(entry: dict) -> str:
    """Return the publisher-declared ``source_code_uri``, or "" when absent.

    The homepage is surfaced separately via :func:`_extract_homepage_url`
    into ``LicenseInfo.homepage_url``; the two registry fields stay in
    their own slots rather than one falling back to the other.
    """
    src = entry.get("source_code_uri")
    if isinstance(src, str) and src.strip():
        return src.strip()
    return ""


def _extract_homepage_url(entry: dict) -> str:
    homepage = entry.get("homepage_uri")
    if isinstance(homepage, str) and homepage.strip():
        return homepage.strip()
    return ""


def _resolved_version_from_entry(entry: dict) -> str:
    """v2 endpoint uses ``number``; v1 uses ``version``. Read whichever exists."""
    number = entry.get("number")
    if isinstance(number, str) and number:
        return number
    version = entry.get("version")
    if isinstance(version, str) and version:
        return version
    return ""


def _unknown(dep: Dependency, *, from_registry: bool) -> LicenseInfo:
    return LicenseInfo(
        dependency=dep,
        license_id="UNKNOWN",
        license_raw="",
        from_registry=from_registry,
    )


def resolve_ruby_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    lockfile_license_map: None = None,  # noqa: ARG001 — kept for cross-eco dispatch parity
    fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Resolve license for a Ruby gem via rubygems.org.

    Pinned (``==X.Y.Z``) deps hit the v2 per-version endpoint; unpinned
    deps fall back to the v1 latest-version endpoint. GIT / PATH-sourced
    gems (off-registry marker set by the lockfile parser) short-circuit
    to UNKNOWN without a fetch.
    """
    if is_off_registry_marker(dep.source):
        # Drop the internal marker so it doesn't surface as the report's
        # Source — off-registry gems carry no manifest-path source.
        return _unknown(replace(dep, source=""), from_registry=False)

    name = dep.name
    pinned = _extract_pinned_version(dep.version_constraint)

    if pinned is not None:
        data = fetcher(_rubygems_version_url(name, pinned), client)
        if not isinstance(data, dict):
            return _unknown(dep, from_registry=False)
        raw = _license_field_to_raw(data.get("licenses"))
        return LicenseInfo(
            dependency=dep,
            license_id=normalize_license(raw) if raw else "UNKNOWN",
            license_raw=raw,
            repository_url=_extract_repository_url(data),
            homepage_url=_extract_homepage_url(data),
            resolved_version=_resolved_version_from_entry(data) or pinned,
            from_registry=True,
        )

    # Unpinned: latest-version fallback.
    data = fetcher(_rubygems_gem_url(name), client)
    if not isinstance(data, dict):
        return _unknown(dep, from_registry=False)
    raw = _license_field_to_raw(data.get("licenses"))
    return LicenseInfo(
        dependency=dep,
        license_id=normalize_license(raw) if raw else "UNKNOWN",
        license_raw=raw,
        repository_url=_extract_repository_url(data),
        homepage_url=_extract_homepage_url(data),
        resolved_version=_resolved_version_from_entry(data),
        from_registry=True,
    )


def fetch_rubygems_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
) -> list[Dependency]:
    """Fetch runtime dependencies of ``name@version`` from rubygems.org.

    Used by the manifest-only transitive walker (no Gemfile.lock present).
    Reads only the ``dependencies.runtime`` list — development dependencies
    aren't followed transitively (same posture as PHP / npm / Python).
    """
    data = fetcher(_rubygems_version_url(name, version), client)
    if not isinstance(data, dict):
        return []
    deps_field = data.get("dependencies")
    if not isinstance(deps_field, dict):
        return []
    runtime = deps_field.get("runtime")
    if not isinstance(runtime, list):
        return []
    out: list[Dependency] = []
    seen: set[str] = set()
    for entry in runtime:
        if not isinstance(entry, dict):
            continue
        child_name = entry.get("name")
        if not isinstance(child_name, str) or not child_name.strip():
            continue
        lowered = child_name.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        child_constraint = entry.get("requirements")
        constraint_str = child_constraint.strip() if isinstance(child_constraint, str) else ""
        out.append(
            Dependency(
                name=child_name.strip(),
                version_constraint=constraint_str,
                ecosystem=Ecosystem.RUBY,
                group=parent_group,
                depth=parent_depth + 1,
            )
        )
    return out
