"""Resolve license information from crates.io."""

from __future__ import annotations

import re

import httpx

from licenseal.analysis.spdx import normalize_license
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.deps_dev import resolve_via_deps_dev_stable_get
from licenseal.resolvers.http import Fetcher, fetch_registry_json

_CRATES_IO_URL = "https://crates.io/api/v1/crates"

# Cargo exact-pinned form: `=X.Y.Z[-pre][+build]`. Anything else (bare,
# caret, tilde, range, wildcard) is treated as a range and resolves to the
# crate's `max_stable_version` from the registry.
_PINNED_VERSION_RE = re.compile(r"^=\s*(\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.+_-]+)?)$")


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact requested version when the constraint is `=X.Y.Z`."""
    spec = version_constraint.strip()
    if not spec:
        return None
    # licenseal-internal lockfile output uses `==X.Y.Z`; accept both.
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        if re.fullmatch(r"\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.+_-]+)?", candidate):
            return candidate
        return None
    match = _PINNED_VERSION_RE.fullmatch(spec)
    if not match:
        return None
    return match.group(1)


def _resolve_version(
    name: str,
    spec: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> str | None:
    """Resolve `spec` to a concrete version, or None on failure.

    For pinned specs (`=X.Y.Z` or `==X.Y.Z`), returns the version verbatim.
    For everything else, falls back to the crate's `max_stable_version`.
    """
    pinned = _extract_pinned_version(spec)
    if pinned:
        return pinned
    data = fetcher(f"{_CRATES_IO_URL}/{name}", client)
    if data is None:
        return None
    crate = data.get("crate", {}) or {}
    version = crate.get("max_stable_version") or crate.get("newest_version")
    return version if isinstance(version, str) else None


def resolve_rust_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Resolve license for a Rust crate from crates.io.

    ``fetcher`` defaults to a direct HTTP fetch but can be the ``fetch``
    method of a :class:`~licenseal.resolvers.http.RegistryCache` so that
    repeated calls for the same crate (across the walk and the
    license-resolution pass) share one network round-trip.
    """
    name = dep.name
    spec = dep.version_constraint.strip()

    resolved_version = _resolve_version(name, spec, client, fetcher)
    if not resolved_version:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )

    url = f"{_CRATES_IO_URL}/{name}/{resolved_version}"
    data = fetcher(url, client)
    if data is None:
        # Resilience fallback: crates.io's HTTP retries exhausted (5xx
        # storm, partial outage). deps.dev runs on independent
        # infrastructure so a correlated outage is unlikely.
        return resolve_via_deps_dev_stable_get(
            dep,
            resolved_version,
            system="CARGO",
            client=client,
            fetcher=fetcher,
        )
    version_obj = data.get("version", {}) or {}
    raw_license = version_obj.get("license", "") or ""
    if not isinstance(raw_license, str):
        raw_license = ""

    # Repository URL lives on the crate, not the version. Homepage is a
    # separate field so consumers can distinguish a structured VCS URL from
    # a package-author-supplied homepage (which may point anywhere).
    repository_url = ""
    homepage_url = ""
    crate_data = fetcher(f"{_CRATES_IO_URL}/{name}", client)
    if crate_data is not None:
        crate_obj = crate_data.get("crate", {}) or {}
        repo = crate_obj.get("repository") or ""
        repository_url = repo if isinstance(repo, str) else ""
        home = crate_obj.get("homepage") or ""
        homepage_url = home if isinstance(home, str) else ""

    return LicenseInfo(
        dependency=dep,
        license_id=normalize_license(raw_license),
        license_raw=raw_license,
        repository_url=repository_url,
        homepage_url=homepage_url,
        resolved_version=resolved_version,
        from_registry=True,
    )


def fetch_rust_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
) -> list[Dependency]:
    """Fetch the crate's declared dependencies from crates.io.

    Returns only `kind == "normal"` and `kind == "build"` entries — `dev`
    dependencies aren't shipped with downstream consumers and are dropped
    from the registry-walk transitive expansion.

    ``fetcher`` defaults to a direct HTTP fetch; the walker passes a
    cache-backed fetcher so the dependencies endpoint is shared with any
    same-(name,version) call.
    """
    url = f"{_CRATES_IO_URL}/{name}/{version}/dependencies"
    data = fetcher(url, client)
    if data is None:
        return []
    deps = data.get("dependencies", [])
    if not isinstance(deps, list):
        return []
    out: list[Dependency] = []
    for raw in deps:
        if not isinstance(raw, dict):
            continue
        kind = raw.get("kind", "normal")
        if kind not in ("normal", "build"):
            continue
        crate_id = raw.get("crate_id")
        if not isinstance(crate_id, str):
            continue
        req = raw.get("req", "")
        spec = req if isinstance(req, str) else ""
        out.append(
            Dependency(
                name=crate_id,
                version_constraint=spec,
                ecosystem=Ecosystem.RUST,
                group=parent_group,
                depth=parent_depth + 1,
            )
        )
    return out
