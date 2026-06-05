"""Resolve license information from the npm registry."""

from __future__ import annotations

import re
from typing import Any, cast

import httpx

from licenseal.analysis.spdx import normalize_license
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.deps_dev import resolve_via_deps_dev_stable_get
from licenseal.resolvers.http import Fetcher, fetch_registry_json
from licenseal.resolvers.version_selection import resolve_npm_spec

_NPM_REGISTRY_URL = "https://registry.npmjs.org"
_PINNED_VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)$")

# npm package-alias syntax: a dep can be declared under any name with the
# value ``npm:<target-name>@<spec>``. Common in monorepos that vendor two
# majors of the same lib under different local names, or in legacy/CJS-
# compatibility shims that pin the CJS-build major of a now-ESM package.
# The alias name has no registry entry; only the target does. Walker code
# must look up the target, not the alias, or every aliased dep 404s.
# Scoped-target form (``npm:@scope/name@spec``) is supported via the
# ``@?`` in the group.
_NPM_ALIAS_RE = re.compile(r"^npm:(@?[^@\s]+(?:/[^@\s]+)?)@(.+)$")


def _unpack_npm_alias(name: str, spec: str) -> tuple[str, str]:
    """Resolve npm alias syntax to (target_name, target_spec).

    For non-alias specs, returns ``(name, spec)`` unchanged. The license a
    transitive carries belongs to the underlying package, so report under
    the target name; the alias is purely the parent's local naming choice.
    """
    match = _NPM_ALIAS_RE.match(spec.strip())
    if not match:
        return name, spec
    return match.group(1), match.group(2)


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact npm version when the spec is pinned.

    Accepts both npm-native bare versions (``1.2.3``) and licenseal's
    internal lockfile-output form (``==1.2.3``), which the npm lockfile
    parsers emit for resolved deps.
    """
    spec = version_constraint.strip()
    if not spec or " " in spec or "||" in spec:
        return None
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        match = _PINNED_VERSION_RE.fullmatch(candidate)
        return match.group(1) if match else None
    if spec[0] in "^~<>*=":
        return None
    match = _PINNED_VERSION_RE.fullmatch(spec)
    if not match:
        return None
    return match.group(1)


def _normalize_repository_url(url: str) -> str:
    """Normalize npm repository references into browser-friendly HTTPS links."""
    normalized = url.strip()
    if not normalized:
        return ""
    if normalized.startswith("git+"):
        normalized = normalized[4:]
    if normalized.startswith("git://"):
        normalized = "https://" + normalized[6:]
    if normalized.startswith("github:"):
        normalized = f"https://github.com/{normalized[7:]}"
    elif normalized.startswith("gitlab:"):
        normalized = f"https://gitlab.com/{normalized[7:]}"
    elif normalized.startswith("bitbucket:"):
        normalized = f"https://bitbucket.org/{normalized[10:]}"
    elif normalized.count("/") == 1 and "://" not in normalized and not normalized.startswith("@"):
        normalized = f"https://github.com/{normalized}"
    if "#" in normalized:
        normalized = normalized.split("#", 1)[0]
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def _extract_repository_url(data: dict) -> str:
    """Best-effort extraction of the package repository URL from npm metadata."""
    repository = data.get("repository", "")
    if isinstance(repository, str):
        return _normalize_repository_url(repository)
    if isinstance(repository, dict):
        url = repository.get("url", "")
        if isinstance(url, str):
            return _normalize_repository_url(url)
    return ""


def _extract_homepage_url(data: dict) -> str:
    """Best-effort extraction of the package homepage URL from npm metadata.

    Kept separate from ``_extract_repository_url`` so consumers can
    distinguish a package-author-supplied homepage (untrusted, may point
    anywhere) from a structured ``repository`` URL.
    """
    homepage = data.get("homepage", "")
    if isinstance(homepage, str) and homepage.strip():
        return _normalize_repository_url(homepage)
    return ""


def _extract_legacy_licenses(raw: object) -> str:
    """Pull a license string from the pre-modern `licenses` (plural) field.

    npm's pre-CommonJS-era convention published license metadata as
    ``"licenses": [{"type": "MIT", "url": "..."}]`` (or a bare single dict).
    Many old-but-still-used packages never switched to the modern singular
    ``"license"`` string. Multi-entry arrays express dual licensing as OR.
    """
    if isinstance(raw, dict):
        entries: list[object] = [raw]
    elif isinstance(raw, list):
        entries = raw
    else:
        return ""
    ids: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        value = cast("dict[str, Any]", entry).get("type", "")
        if isinstance(value, str) and value.strip():
            ids.append(value.strip())
    if not ids:
        return ""
    if len(ids) == 1:
        return ids[0]
    return "(" + " OR ".join(ids) + ")"


def resolve_npm_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Resolve license for an npm package from the registry.

    ``fetcher`` defaults to a direct HTTP fetch but can be the ``fetch``
    method of a :class:`~licenseal.resolvers.http.RegistryCache` to dedupe
    URLs already fetched by the transitive walker.
    """
    name = dep.name
    spec = dep.version_constraint.strip()

    pinned_version = _extract_pinned_version(spec)
    if pinned_version:
        url = f"{_NPM_REGISTRY_URL}/{name}/{pinned_version}"
        data = fetcher(url, client)
    elif not spec:
        url = f"{_NPM_REGISTRY_URL}/{name}/latest"
        data = fetcher(url, client)
    else:
        url = f"{_NPM_REGISTRY_URL}/{name}"
        package_data = fetcher(url, client)
        if package_data is None:
            data = None
        else:
            selected_version = resolve_npm_spec(package_data, spec)
            if not selected_version:
                data = None
            else:
                versions = package_data.get("versions", {})
                version_map = versions if isinstance(versions, dict) else {}
                selected_data = version_map.get(selected_version)
                data = selected_data if isinstance(selected_data, dict) else None
    if data is None:
        # Resilience fallback: npm registry's HTTP retries exhausted
        # (5xx storm, partial outage). deps.dev runs on independent
        # infrastructure so a correlated outage is unlikely. Only fires
        # when we have a concrete pinned version — range specs that
        # never resolved have no version to look up.
        if pinned_version:
            return resolve_via_deps_dev_stable_get(
                dep,
                pinned_version,
                system="NPM",
                client=client,
                fetcher=fetcher,
            )
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )

    # /latest returns version-level metadata directly
    raw_license = ""
    resolved_version = data.get("version", "")
    repository_url = _extract_repository_url(data)
    homepage_url = _extract_homepage_url(data)

    license_val = data.get("license", "")
    if isinstance(license_val, str):
        raw_license = license_val
    elif isinstance(license_val, dict):
        raw_license = license_val.get("type", "")

    # Legacy npm metadata used a `licenses` array (or single dict) instead of
    # the modern `license` string. Many packages published before the
    # convention change still ship the plural-form metadata; without this
    # fallback they classify as UNKNOWN despite declaring a license.
    # Multiple entries express dual-licensing as OR (consumer picks).
    if not raw_license:
        raw_license = _extract_legacy_licenses(data.get("licenses"))

    normalized = normalize_license(raw_license)

    return LicenseInfo(
        dependency=dep,
        license_id=normalized,
        license_raw=raw_license,
        repository_url=repository_url,
        homepage_url=homepage_url,
        resolved_version=resolved_version,
        from_registry=True,
    )


def fetch_npm_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    include_optional: bool = True,
    include_peer: bool = True,
    fetcher: Fetcher = fetch_registry_json,
) -> list[Dependency]:
    """Fetch the package's declared dependencies from the npm registry.

    Reads ``dependencies``, ``peerDependencies``, and
    ``optionalDependencies`` from the version-specific metadata.
    ``devDependencies`` are skipped (callers handle dev filtering at the
    orchestrator level via ``--dev``).

    Children inherit ``parent_group``: a transitive only reachable through
    a devDep stays in the dev group so the dev → warning downgrade applies
    correctly. Default PROD matches the most common case (transitives of a
    prod-group seed) and keeps single-call test sites unchanged.

    ``fetcher`` defaults to a direct HTTP fetch; the walker passes a
    cache-backed fetcher so the response is reused for license resolution.
    """
    url = f"{_NPM_REGISTRY_URL}/{name}/{version}"
    data = fetcher(url, client)
    if data is None:
        return []
    out: list[Dependency] = []
    seen: set[str] = set()
    fields: list[str] = ["dependencies"]
    if include_peer:
        fields.append("peerDependencies")
    if include_optional:
        fields.append("optionalDependencies")
    for field_name in fields:
        deps_dict = data.get(field_name, {})
        if not isinstance(deps_dict, dict):
            continue
        for dep_name, raw_spec in deps_dict.items():
            if not isinstance(dep_name, str) or dep_name in seen:
                continue
            seen.add(dep_name)
            spec = raw_spec if isinstance(raw_spec, str) else ""
            target_name, target_spec = _unpack_npm_alias(dep_name, spec)
            out.append(
                Dependency(
                    name=target_name,
                    version_constraint=target_spec,
                    ecosystem=Ecosystem.NPM,
                    group=parent_group,
                    depth=parent_depth + 1,
                )
            )
    return out
