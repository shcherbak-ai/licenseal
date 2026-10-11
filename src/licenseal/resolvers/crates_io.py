"""Resolve license information from crates.io."""

from __future__ import annotations

import re

import httpx

from licenseal.analysis.spdx import all_apply_reading, normalize_license
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.deps_dev import resolve_via_deps_dev_stable_get
from licenseal.resolvers.http import (
    Fetcher,
    fetch_registry_json,
    object_field,
    quote_coordinate,
)
from licenseal.resolvers.version_selection import select_version

_CRATES_IO_URL = "https://crates.io/api/v1/crates"


def _crate_url(name: str) -> str:
    """Crate endpoint: the crate's own fields and the versions it lists."""
    return f"{_CRATES_IO_URL}/{quote_coordinate(name)}"


def _version_url(name: str, version: str) -> str:
    """Endpoint of one version; ``+`` before its build metadata is sent as written."""
    return f"{_crate_url(name)}/{quote_coordinate(version, safe='+')}"


# Cargo exact-pinned form: `=X.Y.Z[-pre][+build]`, with all three segments;
# licenseal's lockfile output writes it `==X.Y.Z`. Anything else is a range,
# resolved against the versions the registry lists for the crate: bare,
# caret, tilde, comparison, wildcard, and `=` before a version that stops
# early (`=1.2` is every `1.2.x`, `=1` every `1.x`).
_PINNED_VERSION_RE = re.compile(r"==?\s*(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+_-]+)?)")


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact requested version when the constraint is `=X.Y.Z`."""
    match = _PINNED_VERSION_RE.fullmatch(version_constraint.strip())
    return match.group(1) if match else None


def _published_versions(data: dict) -> list[str]:
    """The version numbers a crate response lists, without the yanked ones."""
    versions = data.get("versions")
    if not isinstance(versions, list):
        return []
    return [
        entry["num"]
        for entry in versions
        if isinstance(entry, dict)
        and isinstance(entry.get("num"), str)
        and entry.get("yanked") is not True
    ]


def _resolve_version(
    name: str,
    spec: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> str | None:
    """Resolve `spec` to a concrete version, or None when there is none to report.

    A pinned spec (`=X.Y.Z` or `==X.Y.Z`) is returned verbatim. No spec at
    all is the crate's latest stable release. Any other requirement, `=1.2`
    included, resolves to the highest version satisfying it among those the
    crate response lists. That response is the one the latest release is
    read from, so a range costs no request of its own.

    A requirement that is not Cargo syntax, or that no published version
    satisfies, resolves to nothing; it never falls back to the latest
    release. The walker and the license resolver both resolve through here.
    """
    pinned = _extract_pinned_version(spec)
    if pinned:
        return pinned
    data = fetcher(_crate_url(name), client)
    if data is None:
        return None
    crate = object_field(data, "crate")
    latest = crate.get("max_stable_version") or crate.get("newest_version")
    if not isinstance(latest, str):
        latest = None
    if not spec.strip():
        return latest
    # The latest release is a candidate even when the response lists none.
    published = _published_versions(data) + ([latest] if latest else [])
    return select_version(Ecosystem.RUST, spec, published)


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

    data = fetcher(_version_url(name, resolved_version), client)
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
    raw_license = object_field(data, "version").get("license", "") or ""
    if not isinstance(raw_license, str):
        raw_license = ""

    # Repository URL lives on the crate, not the version. Homepage is a
    # separate field so consumers can distinguish a structured VCS URL from
    # a package-author-supplied homepage (which may point anywhere).
    repository_url = ""
    homepage_url = ""
    crate_data = fetcher(_crate_url(name), client)
    if crate_data is not None:
        crate_obj = object_field(crate_data, "crate")
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
        # Cargo documents ``/`` in ``license`` as a choice; a comma has no
        # defined meaning there.
        all_apply_license_id=all_apply_reading(raw_license, slash_is_choice=True),
    )


def fetch_rust_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
) -> tuple[list[Dependency], bool]:
    """Fetch the crate's declared dependencies from crates.io.

    Returns ``(children, complete)``. The children are only the
    `kind == "normal"` and `kind == "build"` entries — `dev` dependencies
    aren't shipped with downstream consumers and are dropped from the
    registry-walk transitive expansion.

    ``complete`` is False when the dependency list could not be determined:
    the fetch failed, ``dependencies`` is not a list, or an entry is not an
    object naming a crate. The entries that could be read are returned all
    the same. A ``dependencies`` that is absent or ``null`` declares nothing.

    Entries flagged `optional` are skipped: they are built only when a
    feature enables them, and the registry walk has no feature resolution,
    so following them would report crates the project may never build. A
    `Cargo.lock` records the graph Cargo resolved and avoids this walk.

    ``fetcher`` defaults to a direct HTTP fetch; the walker passes a
    cache-backed fetcher so the dependencies endpoint is shared with any
    same-(name,version) call.
    """
    data = fetcher(f"{_version_url(name, version)}/dependencies", client)
    if data is None:
        return [], False
    deps = data.get("dependencies")
    if deps is None:
        return [], True
    if not isinstance(deps, list):
        return [], False
    complete = True
    out: list[Dependency] = []
    for raw in deps:
        if not isinstance(raw, dict):
            complete = False
            continue
        kind = raw.get("kind", "normal")
        if kind not in ("normal", "build"):
            continue
        if raw.get("optional") is True:
            continue
        crate_id = raw.get("crate_id")
        if not isinstance(crate_id, str):
            complete = False
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
    return out, complete
