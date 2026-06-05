"""Resolve license information for Hex packages from hex.pm.

License is **package-level** on hex.pm (every version of a package shares
``meta.licenses``), so license resolution needs only one endpoint:

* ``GET /api/packages/{name}`` — ``meta.licenses`` (the SPDX-ish string array),
  ``meta.links`` (repo / homepage URLs), and ``latest_stable_version`` for the
  unpinned fallback.

The per-version release endpoint
(``GET /api/packages/{name}/releases/{version}``) carries no license — only the
transitive ``requirements`` edges — so it's read exclusively by the
manifest-only transitive walker (:func:`fetch_hex_dependencies`), never for
license resolution.

deps.dev does not index Hex, so there is no batch pre-pass: every dep is
resolved here against hex.pm (lockfile-first keeps this to one GET per unique
package, deduped by the per-scan cache). Off-registry deps (``:git`` / ``:path``
in ``mix.lock``, ``git:`` / ``path:`` in ``mix.exs``) short-circuit to UNKNOWN.
"""

from __future__ import annotations

from dataclasses import replace

import httpx

from licenseal.analysis.spdx import normalize_license
from licenseal.discovery.hex.mix_lock import is_off_registry_marker
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.http import Fetcher, fetch_registry_json

_HEX_REGISTRY_URL = "https://hex.pm"

# ``meta.links`` is a free-form label→URL map; these labels denote the source
# repository (used for the report's repository link).
_REPO_LINK_LABELS = ("github", "gitlab", "bitbucket")


def _hex_package_url(name: str) -> str:
    """Package metadata endpoint (license + links + latest version)."""
    return f"{_HEX_REGISTRY_URL}/api/packages/{name}"


def _hex_release_url(name: str, version: str) -> str:
    """Per-version release endpoint (transitive ``requirements`` edges)."""
    return f"{_HEX_REGISTRY_URL}/api/packages/{name}/releases/{version}"


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact version when the spec is a ``==X.Y.Z`` pin.

    The ``mix.lock`` parser emits ``==X.Y.Z``; manifest-mode constraints
    (``~> 1.7``, ``>= 1.0``, ``~> 1.0 or ~> 2.0``) are ranges → None.
    """
    spec = version_constraint.strip()
    if not spec or "," in spec:
        return None
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        if not candidate or " " in candidate:
            return None
        return candidate
    return None


def _license_field_to_raw(value: object) -> str:
    """Collapse ``meta.licenses`` into a single raw string.

    hex.pm emits an array; multi-element arrays are OR-joined (disjunctive —
    the publisher offers a choice, the same convention as RubyGems / Composer).
    A bare string is accepted defensively even though the API always emits an
    array.
    """
    if isinstance(value, list):
        items = [v.strip() for v in value if isinstance(v, str) and v.strip()]
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        return " OR ".join(items)
    if isinstance(value, str):
        return value.strip()
    return ""


def _extract_repository_url(links: object) -> str:
    """Return the source-repo URL from ``meta.links`` (a label→URL map)."""
    if not isinstance(links, dict):
        return ""
    for label, url in links.items():
        if (
            isinstance(label, str)
            and isinstance(url, str)
            and label.strip().lower() in _REPO_LINK_LABELS
            and url.strip()
        ):
            return url.strip()
    return ""


def _extract_homepage_url(links: object) -> str:
    """Return the first non-repository link from ``meta.links`` as homepage."""
    if not isinstance(links, dict):
        return ""
    for label, url in links.items():
        if not (isinstance(label, str) and isinstance(url, str) and url.strip()):
            continue
        if label.strip().lower() in _REPO_LINK_LABELS:
            continue
        return url.strip()
    return ""


def _latest_version(data: dict) -> str:
    """Prefer ``latest_stable_version``; fall back to ``latest_version``."""
    for key in ("latest_stable_version", "latest_version"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _unknown(dep: Dependency, *, from_registry: bool) -> LicenseInfo:
    return LicenseInfo(
        dependency=dep,
        license_id="UNKNOWN",
        license_raw="",
        from_registry=from_registry,
    )


def resolve_hex_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    lockfile_license_map: None = None,  # noqa: ARG001 — kept for cross-eco dispatch parity
    fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Resolve a Hex package's license via the hex.pm package endpoint.

    One ``GET /api/packages/{name}`` yields the package-level license + links;
    the resolved version is the lockfile pin when present, else the package's
    ``latest_stable_version``. Off-registry (git/path) deps short-circuit to
    UNKNOWN without a fetch.
    """
    if is_off_registry_marker(dep.source):
        # Drop the internal marker so it doesn't surface as the report's Source.
        return _unknown(replace(dep, source=""), from_registry=False)

    # `effective_registry_name` is the real hex.pm package for a `hex:`-renamed
    # dep (declared local app name ≠ published package); else just the name.
    data = fetcher(_hex_package_url(dep.effective_registry_name), client)
    if not isinstance(data, dict):
        return _unknown(dep, from_registry=False)

    meta = data.get("meta")
    if not isinstance(meta, dict):
        meta = {}
    raw = _license_field_to_raw(meta.get("licenses"))
    pinned = _extract_pinned_version(dep.version_constraint)
    return LicenseInfo(
        dependency=dep,
        license_id=normalize_license(raw) if raw else "UNKNOWN",
        license_raw=raw,
        repository_url=_extract_repository_url(meta.get("links")),
        homepage_url=_extract_homepage_url(meta.get("links")),
        resolved_version=pinned or _latest_version(data),
        from_registry=True,
    )


def fetch_hex_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
) -> list[Dependency]:
    """Fetch runtime dependency edges of ``name@version`` from hex.pm.

    Used by the manifest-only transitive walker (no ``mix.lock`` present).
    Reads the release endpoint's ``requirements`` map; optional requirements
    are skipped (not guaranteed to ship, matching the npm / Python posture of
    not following optional deps transitively).
    """
    data = fetcher(_hex_release_url(name, version), client)
    if not isinstance(data, dict):
        return []
    requirements = data.get("requirements")
    if not isinstance(requirements, dict):
        return []
    out: list[Dependency] = []
    # ``requirements`` is a JSON object keyed by dependency name, so the keys
    # are already unique — no dedup pass needed (unlike the array-shaped
    # RubyGems runtime list).
    for child_name, spec in requirements.items():
        if not isinstance(child_name, str) or not child_name.strip():
            continue
        if isinstance(spec, dict) and spec.get("optional") is True:
            continue
        requirement = spec.get("requirement") if isinstance(spec, dict) else None
        constraint = requirement.strip() if isinstance(requirement, str) else ""
        out.append(
            Dependency(
                name=child_name.strip(),
                version_constraint=constraint,
                ecosystem=Ecosystem.HEX,
                group=parent_group,
                depth=parent_depth + 1,
            )
        )
    return out
