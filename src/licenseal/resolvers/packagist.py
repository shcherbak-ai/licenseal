"""Resolve license information for Composer packages from Packagist.

Lockfile-first resolver: composer.lock embeds an SPDX-shaped ``license``
field per package, so the resolver answers from that map when available
and only falls back to Packagist's ``/p2/{vendor}/{package}.json`` endpoint
for deps the lockfile doesn't cover (manifest-only mode) or where the
lockfile's license field is empty.

Packagist exposes no batch endpoint, and deps.dev does not index
Packagist — so the per-package fallback is the only network path here.
Lockfile-first behaviour minimizes load on a donation-funded registry.
"""

from __future__ import annotations

from typing import Any

import httpx

from licenseal.analysis.spdx import normalize_license
from licenseal.discovery.php.lockfiles import LockfileLicenseMap
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.http import Fetcher, fetch_registry_json
from licenseal.resolvers.version_selection import select_php_version

_PACKAGIST_REGISTRY_URL = "https://repo.packagist.org/p2"


def _packagist_url(name: str) -> str:
    """Build the canonical Packagist v2 metadata URL for a package."""
    return f"{_PACKAGIST_REGISTRY_URL}/{name.lower()}.json"


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact Composer version when the spec is pinned.

    The PHP lockfile parser emits ``==X.Y.Z``; manifest-mode constraints
    use Composer-native shapes (``^1.2``, ``~1.2``, ``1.2.*``, ``dev-main``,
    ``>=1.0 <2.0``). Only the ``==`` form pins. Returns the version in the
    canonical (v-stripped) form so lockfile-license map lookups are shape-
    stable regardless of how the publisher tagged the release.
    """
    spec = version_constraint.strip()
    if not spec or " " in spec or "||" in spec:
        return None
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        if not candidate:
            return None
        return candidate.lstrip("v")
    return None


def _normalize_repository_url(url: str) -> str:
    """Normalize Composer repository URLs into browser-friendly HTTPS links.

    Composer's ``source.url`` carries the upstream VCS URL — typically
    ``git@github.com:...`` (SSH form) or ``https://github.com/...git``.
    Reports want HTTPS without the trailing ``.git`` so the link opens
    the human-readable page.
    """
    normalized = url.strip()
    if not normalized:
        return ""
    if normalized.startswith("git@github.com:"):
        normalized = "https://github.com/" + normalized[len("git@github.com:") :]
    elif normalized.startswith("git@gitlab.com:"):
        normalized = "https://gitlab.com/" + normalized[len("git@gitlab.com:") :]
    elif normalized.startswith("git@bitbucket.org:"):
        normalized = "https://bitbucket.org/" + normalized[len("git@bitbucket.org:") :]
    elif normalized.startswith("git+"):
        normalized = normalized[4:]
    elif normalized.startswith("git://"):
        normalized = "https://" + normalized[len("git://") :]
    # Strip the fragment before stripping the .git suffix — ``...git#ref``
    # would otherwise survive both passes (suffix check fails on the
    # fragmented form, then the fragment strip leaves ``.git`` behind).
    if "#" in normalized:
        normalized = normalized.split("#", 1)[0]
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def _extract_repository_url(entry: dict) -> str:
    source = entry.get("source", {})
    if isinstance(source, dict):
        url = source.get("url", "")
        if isinstance(url, str):
            return _normalize_repository_url(url)
    return ""


def _extract_homepage_url(entry: dict) -> str:
    homepage = entry.get("homepage", "")
    if isinstance(homepage, str) and homepage.strip():
        return _normalize_repository_url(homepage)
    return ""


def _license_field_to_raw(value: object) -> str:
    """Same shape rule as composer.json — bare string or OR-joined array."""
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


def _versions_from_response(data: dict, name: str) -> list[dict[str, Any]]:
    """Extract the ordered version-entries list from a Packagist response.

    The v2 endpoint returns ``{"packages": {"<name>": [<version-entries>]}}``
    where the list is in descending version order. Lookup uses lowercase
    name (Packagist is case-insensitive).
    """
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        return []
    entries = packages.get(name.lower())
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict)]


def _select_version_entry(
    entries: list[dict[str, Any]], spec: str, pinned: str | None
) -> dict[str, Any] | None:
    """Pick the entry matching the dep's version spec.

    For a pinned ``==X.Y.Z`` spec, match by exact version string (Packagist
    serves both with and without the ``v`` prefix). For range / wildcard
    specs, use the npm-shaped selector against the published version list
    (Composer's ``^`` / ``~`` semantics diverge slightly from npm's for
    ``~`` — accepted v1 risk because the lockfile path bypasses this code
    entirely). Falls back to the first entry (highest version) when no
    spec is provided or selection fails.
    """
    if not entries:
        return None
    if pinned is not None:
        target = pinned.lstrip("v")
        for entry in entries:
            # Match against the displayed ``version`` first (``"3.5.0"``);
            # ``version_normalized`` is Composer's internal 4-segment form
            # (``"3.5.0.0"``) which doesn't equality-match the lockfile-
            # stored value. Fall back to the normalized form for entries
            # that only carry it.
            display_version = entry.get("version")
            if isinstance(display_version, str) and display_version.lstrip("v") == target:
                return entry
            entry_version = entry.get("version_normalized") or ""
            if isinstance(entry_version, str) and entry_version.lstrip("v") == target:
                return entry
        # Pinned but no match — fall back to first entry (best-effort);
        # the resolver will report the entry's version, the caller will
        # see the mismatch in resolved_version.
        return entries[0]
    if not spec.strip():
        return entries[0]
    published_versions: list[str] = []
    for entry in entries:
        version = entry.get("version")
        if isinstance(version, str):
            published_versions.append(version.lstrip("v"))
    selected = select_php_version(spec, published_versions)
    if selected is None:
        return entries[0]
    for entry in entries:
        version = entry.get("version")
        if isinstance(version, str) and version.lstrip("v") == selected:
            return entry
    # Defensive: select returns a member of published_versions, so the
    # for-loop above always finds a match. Kept as a safety net.
    return entries[0]  # pragma: no cover


def resolve_php_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    lockfile_license_map: LockfileLicenseMap | None = None,
    fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Resolve license for a Composer package.

    Lockfile-first: if ``lockfile_license_map`` carries a non-empty entry
    for ``(name_lower, pinned_version)``, return it without any HTTP fetch.
    Falls through to a single Packagist v2 metadata fetch for everything
    else (deps the lockfile didn't cover, lockfile entries with an empty
    license field, or manifest-only mode without a lockfile).
    """
    name = dep.name
    spec = dep.version_constraint.strip()
    pinned = _extract_pinned_version(spec)

    if (
        lockfile_license_map is not None
        and pinned is not None
        and (name.lower(), pinned) in lockfile_license_map
    ):
        raw = lockfile_license_map[(name.lower(), pinned)]
        if raw:
            return LicenseInfo(
                dependency=dep,
                license_id=normalize_license(raw),
                license_raw=raw,
                resolved_version=pinned,
                from_registry=True,
            )

    data = fetcher(_packagist_url(name), client)
    if data is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )
    entries = _versions_from_response(data, name)
    entry = _select_version_entry(entries, spec, pinned)
    if entry is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )
    raw = _license_field_to_raw(entry.get("license"))
    resolved_version = ""
    raw_version = entry.get("version")
    if isinstance(raw_version, str) and raw_version:
        resolved_version = raw_version.lstrip("v")
    return LicenseInfo(
        dependency=dep,
        license_id=normalize_license(raw) if raw else "UNKNOWN",
        license_raw=raw,
        repository_url=_extract_repository_url(entry),
        homepage_url=_extract_homepage_url(entry),
        resolved_version=resolved_version,
        from_registry=True,
    )


def fetch_packagist_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
) -> list[Dependency]:
    """Fetch the package's declared runtime dependencies from Packagist.

    Used by the manifest-only transitive walker (no composer.lock present).
    Reads only ``require`` from the matched version entry — dev requirements
    aren't followed transitively (matches the npm / Python / Rust posture
    of dev being a top-level concern, not a transitive one).

    Platform pseudo-packages (``php``, ``ext-*``, ``lib-*``, ``hhvm``) are
    filtered out.
    """
    data = fetcher(_packagist_url(name), client)
    if data is None:
        return []
    entries = _versions_from_response(data, name)
    target = version.lstrip("v")
    entry: dict[str, Any] | None = None
    for candidate in entries:
        # Match the displayed ``version`` first; fall back to the 4-segment
        # ``version_normalized`` form for entries that only carry it.
        display_version = candidate.get("version")
        if isinstance(display_version, str) and display_version.lstrip("v") == target:
            entry = candidate
            break
        cand_version = candidate.get("version_normalized") or ""
        if isinstance(cand_version, str) and cand_version.lstrip("v") == target:
            entry = candidate
            break
    if entry is None:
        return []
    require = entry.get("require")
    if not isinstance(require, dict):
        return []
    out: list[Dependency] = []
    seen: set[str] = set()
    for child_name, child_spec in require.items():
        if not isinstance(child_name, str) or "/" not in child_name:
            continue
        lowered = child_name.lower()
        if (
            lowered in {"php", "hhvm", "composer-plugin-api", "composer-runtime-api"}
            or lowered.startswith(("ext-", "lib-", "php-"))
            or lowered in seen
        ):
            continue
        seen.add(lowered)
        spec_str = child_spec if isinstance(child_spec, str) else ""
        out.append(
            Dependency(
                name=child_name,
                version_constraint=spec_str,
                ecosystem=Ecosystem.PHP,
                group=parent_group,
                depth=parent_depth + 1,
            )
        )
    return out
