"""Resolve license information for Hex packages from hex.pm.

License is **package-level** on hex.pm: a package has one ``meta.licenses``,
overwritten each time a release is published, so it holds the license of the
release published last. License resolution needs only one endpoint:

* ``GET /api/packages/{name}`` — ``meta.licenses`` (the SPDX-ish string array),
  ``meta.links`` (repo / homepage URLs), ``latest_stable_version``, and
  ``releases``, the versions a declared requirement is resolved against, each
  with the time it was published.

The license reported for any other release than the one published last is an
estimate (``LicenseInfo.license_estimated``).

The per-version release endpoint
(``GET /api/packages/{name}/releases/{version}``) carries no license — only the
transitive ``requirements`` edges — so it's read exclusively by the
manifest-only transitive walker (:func:`fetch_hex_dependencies`), never for
license resolution.

deps.dev does not index Hex, so there is no batch pre-pass: every dep is
resolved here against hex.pm (lockfile-first keeps this to one GET per unique
package, deduped by the per-scan cache). A dep with an ``origin`` (``:git`` in
``mix.lock``, ``git:`` / ``path:`` in ``mix.exs``) is not a hex.pm package; the
CLI never passes one to this module.

One request per package means a large project exceeds hex.pm's per-window
request quota. That is handled in the shared HTTP layer, not here: a 429 pauses
all hex.pm requests until the window resets (``_HostRateLimitWindow`` in
:mod:`licenseal.resolvers.http`).
"""

from __future__ import annotations

import re

import httpx

from licenseal.analysis.spdx import read_license_array
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.http import Fetcher, fetch_registry_json
from licenseal.resolvers.version_selection import select_version

_HEX_REGISTRY_URL = "https://hex.pm"

# A requirement that is a version and nothing else: ``{:x, "1.2.3"}``.
_BARE_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")

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
    """Return the exact version when the spec names one.

    The ``mix.lock`` parser emits ``==X.Y.Z``; a manifest pins with
    ``== X.Y.Z`` or with a bare ``X.Y.Z``, which a Hex requirement reads the
    same way. Other manifest-mode constraints (``~> 1.7``, ``>= 1.0``,
    ``~> 1.0 or ~> 2.0``) are ranges → None.
    """
    spec = version_constraint.strip()
    if not spec or "," in spec:
        return None
    if _BARE_VERSION_RE.fullmatch(spec):
        return spec
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        if not candidate or " " in candidate:
            return None
        return candidate
    return None


def _license_entries(value: object) -> list[str]:
    """Entries of ``meta.licenses``.

    hex.pm emits an array of strings. A bare string is accepted defensively
    even though the API always emits an array.
    """
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


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


def _published_versions(data: dict) -> list[str]:
    """The version numbers a package response lists under ``releases``."""
    releases = data.get("releases")
    if not isinstance(releases, list):
        return []
    return [
        release["version"]
        for release in releases
        if isinstance(release, dict) and isinstance(release.get("version"), str)
    ]


def _described_version(data: dict) -> str:
    """The release a package response's ``meta`` describes; "" when it cannot be told.

    That is the release published last, which is the highest version unless
    a release on an older line followed it. It is told from the
    ``inserted_at`` of each ``releases`` entry: UTC timestamps in one fixed
    ISO 8601 layout, so the strings order as the times do. A response whose
    entries do not all name a version and a time describes no release that
    can be told.
    """
    releases = data.get("releases")
    if not isinstance(releases, list):
        return ""
    newest = ("", "")
    for release in releases:
        published = release.get("inserted_at") if isinstance(release, dict) else None
        version = release.get("version") if isinstance(release, dict) else None
        if not isinstance(published, str) or not isinstance(version, str):
            return ""
        newest = max(newest, (published, version))
    return newest[1]


def _select_version(spec: str, data: dict) -> str:
    """The version ``spec`` resolves to on a package response; "" when there is none.

    A pin is returned as it is. No requirement at all is the latest stable
    release. Any other requirement resolves to the highest release satisfying
    it among those the response lists, the same response the license is read
    from.

    A requirement that cannot be read, or that no published version
    satisfies, resolves to nothing; it never falls back to the latest
    release. The walker and the license resolver both resolve through here.
    """
    pinned = _extract_pinned_version(spec)
    if pinned:
        return pinned
    latest = _latest_version(data)
    if not spec.strip():
        return latest
    # The latest release is a candidate even when the response lists none.
    published = _published_versions(data) + ([latest] if latest else [])
    return select_version(Ecosystem.HEX, spec, published) or ""


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

    One ``GET /api/packages/{name}`` yields the package-level license + links
    and the releases the declared requirement is resolved against
    (:func:`_select_version`). A requirement that selects no release is
    UNKNOWN with no version: the license is the package's, but no published
    version of it is the one declared.

    The license is the one of the release published last
    (:func:`_described_version`). For any other reported version it is an
    estimate.
    """
    # `effective_registry_name` is the real hex.pm package for a `hex:`-renamed
    # dep (declared local app name ≠ published package); else just the name.
    data = fetcher(_hex_package_url(dep.effective_registry_name), client)
    if not isinstance(data, dict):
        return _unknown(dep, from_registry=False)

    resolved_version = _select_version(dep.version_constraint, data)
    if not resolved_version and dep.version_constraint.strip():
        return _unknown(dep, from_registry=False)

    meta = data.get("meta")
    if not isinstance(meta, dict):
        meta = {}
    # ``meta.licenses`` does not say whether its entries are alternatives or
    # all apply, so both readings are kept.
    entries = _license_entries(meta.get("licenses"))
    license_id, all_apply_license_id = read_license_array(entries)
    return LicenseInfo(
        dependency=dep,
        license_id=license_id,
        license_raw=", ".join(entries),
        repository_url=_extract_repository_url(meta.get("links")),
        homepage_url=_extract_homepage_url(meta.get("links")),
        resolved_version=resolved_version,
        from_registry=True,
        all_apply_license_id=all_apply_license_id,
        license_estimated=resolved_version != _described_version(data),
    )


def fetch_hex_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
) -> tuple[list[Dependency], bool]:
    """Fetch runtime dependency edges of ``name@version`` from hex.pm.

    Returns ``(children, complete)``. Used by the manifest-only transitive
    walker (no ``mix.lock`` present). Reads the release endpoint's
    ``requirements`` map; optional requirements are skipped (not guaranteed
    to ship, matching the npm / Python posture of not following optional
    deps transitively).

    ``complete`` is False when the dependency list could not be determined:
    the fetch failed, ``requirements`` is not a map, or one of its keys is
    blank. The requirements that could be read are returned all the same. A
    ``requirements`` that is absent or ``null`` declares nothing.
    """
    data = fetcher(_hex_release_url(name, version), client)
    if not isinstance(data, dict):
        return [], False
    requirements = data.get("requirements")
    if requirements is None:
        return [], True
    if not isinstance(requirements, dict):
        return [], False
    complete = True
    out: list[Dependency] = []
    # ``requirements`` is a JSON object keyed by dependency name, so the keys
    # are already unique — no dedup pass needed (unlike the array-shaped
    # RubyGems runtime list).
    for child_name, spec in requirements.items():
        if not isinstance(child_name, str) or not child_name.strip():
            complete = False
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
    return out, complete
