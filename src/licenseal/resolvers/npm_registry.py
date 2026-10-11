"""Resolve license information from the npm registry."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, cast

import httpx

from licenseal.analysis.spdx import all_apply_reading, normalize_license
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.deps_dev import resolve_via_deps_dev_stable_get
from licenseal.resolvers.http import (
    NO_KNOWN_404,
    Fetcher,
    fetch_registry_json,
    quote_coordinate,
)
from licenseal.resolvers.version_selection import resolve_npm_spec

_NPM_REGISTRY_URL = "https://registry.npmjs.org"
_PINNED_VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)$")

# Characters the names of packages published before npm's current naming rules
# may hold; the registry is asked for them as written.
_LEGACY_NAME_CHARACTERS = "!'()*"

# npm package-alias syntax: a dep can be declared under any name with the
# value ``npm:<target-name>@<spec>``. Common in monorepos that vendor two
# majors of the same lib under different local names, or in legacy/CJS-
# compatibility shims that pin the CJS-build major of a now-ESM package.
# The alias name has no registry entry; only the target does. Walker code
# must look up the target, not the alias, or every aliased dep 404s.
# Scoped-target form (``npm:@scope/name@spec``) is supported via the
# ``@?`` in the group.
_NPM_ALIAS_RE = re.compile(r"^npm:(@?[^@\s]+(?:/[^@\s]+)?)@(.+)$")


def _package_url(name: str) -> str:
    """Package endpoint: every published version and the dist-tags.

    The ``/`` of a scoped name (``@scope/name``) separates two path segments,
    as the registry serves it. It is the only ``/`` a name has: any other one
    is encoded with the segment it is in.
    """
    scope, slash, rest = name.partition("/")
    if slash and scope.startswith("@"):
        scope = quote_coordinate(scope, safe="@" + _LEGACY_NAME_CHARACTERS)
        return f"{_NPM_REGISTRY_URL}/{scope}/{quote_coordinate(rest, safe=_LEGACY_NAME_CHARACTERS)}"
    return f"{_NPM_REGISTRY_URL}/{quote_coordinate(name, safe=_LEGACY_NAME_CHARACTERS)}"


def _version_url(name: str, version: str) -> str:
    """Endpoint of one version, or of the version a dist-tag (``latest``) names.

    ``+`` before a version's build metadata is sent as written.
    """
    return f"{_package_url(name)}/{quote_coordinate(version, safe='+')}"


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

    A spec pins when it is one complete version and nothing else: bare
    (``1.2.3``), behind npm's equality operator (``=1.2.3``, ``= 1.2.3``),
    or in licenseal's internal lockfile-output form (``==1.2.3``), which the
    npm lockfile parsers emit for resolved deps. A ``v`` prefix is allowed
    in each (``v1.2.3``, ``=v1.2.3``) and is not part of the version.

    Anything else is a range and returns None: another operator, a partial
    version (``=1.2`` covers every ``1.2.x``), several comparators, ``||``.
    """
    spec = version_constraint.strip()
    if spec.startswith("=="):
        spec = spec[2:].strip()
    elif spec.startswith("="):
        spec = spec[1:].strip()
    match = _PINNED_VERSION_RE.fullmatch(spec)
    return match.group(1) if match else None


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


def _resolve_version(
    name: str, spec: str, client: httpx.Client, fetcher: Fetcher
) -> tuple[str, dict | None]:
    """Resolve ``spec`` to a version of ``name``: ``(version, response read for it)``.

    A pinned spec is returned as written, with no request. No spec at all is
    the version the ``latest`` dist-tag names, read from that version's
    document. Anything else is a dist-tag or a range, resolved on the package
    document (:func:`resolve_npm_spec`). The response that was read is
    returned beside the version for the caller to go on reading.

    The version is ``""`` when there is none to report: the lookup failed,
    the spec cannot be read, or no listed version satisfies it. The walker
    and the license resolver both resolve through here.
    """
    pinned = _extract_pinned_version(spec)
    if pinned:
        return pinned, None
    if not spec.strip():
        latest = fetcher(_version_url(name, "latest"), client)
        version = latest.get("version") if latest is not None else None
        return (version if isinstance(version, str) else ""), latest
    package_data = fetcher(_package_url(name), client)
    if package_data is None:
        return "", None
    return resolve_npm_spec(package_data, spec), package_data


def _version_entry(package_data: dict | None, version: str) -> dict | None:
    """The entry a package document has for ``version``: that version's own metadata."""
    versions = package_data.get("versions") if package_data is not None else None
    entry = versions.get(version) if isinstance(versions, dict) else None
    return entry if isinstance(entry, dict) else None


def resolve_npm_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_json,
    not_found: Callable[[str], bool] = NO_KNOWN_404,
) -> LicenseInfo:
    """Resolve license for an npm package from the registry.

    ``fetcher`` defaults to a direct HTTP fetch but can be the ``fetch``
    method of a :class:`~licenseal.resolvers.http.RegistryCache` to dedupe
    URLs already fetched by the transitive walker.

    The version the declaration resolves to, pinned or selected by a range,
    is looked up at its own endpoint. ``not_found`` tells whether the
    registry answered a URL that ``fetcher`` returned nothing for with HTTP
    404 (``RegistryCache.not_found`` beside that cache's ``fetch``). A 404
    means the registry has no document at that endpoint: the package
    document's entry for the version, which is the same release's metadata,
    then answers. Any other miss is a lookup that failed, and is not answered
    from the package document. The default knows of no 404, so with it every
    miss is a failed lookup.
    """
    name = dep.name
    spec = dep.version_constraint.strip()

    version, fetched = _resolve_version(name, spec, client, fetcher)
    data: dict | None = None
    if not spec:
        # No spec is the version ``latest`` names, which that response
        # describes.
        data = fetched
    elif version:
        url = _version_url(name, version)
        data = fetcher(url, client)
        if data is None and not_found(url):
            package_data = fetched if fetched is not None else fetcher(_package_url(name), client)
            data = _version_entry(package_data, version)
    if data is None:
        # Resilience fallback: npm registry's HTTP retries exhausted
        # (5xx storm, partial outage). deps.dev runs on independent
        # infrastructure so a correlated outage is unlikely. Only fires
        # when we have a concrete version — a spec that resolved to none
        # has no version to look up.
        if version:
            return resolve_via_deps_dev_stable_get(
                dep,
                version,
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

    raw_license = ""
    described = data.get("version")
    resolved_version = described if isinstance(described, str) else ""
    repository_url = _extract_repository_url(data)
    homepage_url = _extract_homepage_url(data)

    # ``license`` is a string, or the legacy ``{"type": ...}`` object. Any
    # other shape, at either level, carries no license string.
    license_val = data.get("license", "")
    if isinstance(license_val, dict):
        license_val = license_val.get("type")
    if isinstance(license_val, str):
        raw_license = license_val

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
        # npm defines ``license`` as an SPDX expression: ``,`` and ``/``
        # between licenses have no meaning there.
        all_apply_license_id=all_apply_reading(raw_license),
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
) -> tuple[list[Dependency], bool]:
    """Fetch the package's declared dependencies from the npm registry.

    Returns ``(children, complete)``. Reads ``dependencies``,
    ``peerDependencies``, and ``optionalDependencies`` from the
    version-specific metadata. ``devDependencies`` are skipped (callers
    handle dev filtering at the orchestrator level via ``--dev``).

    ``complete`` is False when the dependency list could not be determined:
    the fetch failed, or one of those fields is present and is not an
    object. The fields that could be read are returned all the same. A field
    that is absent or ``null`` declares nothing.

    Children inherit ``parent_group``: a transitive only reachable through
    a devDep stays in the dev group so the dev → warning downgrade applies
    correctly. Default PROD matches the most common case (transitives of a
    prod-group seed) and keeps single-call test sites unchanged.

    ``fetcher`` defaults to a direct HTTP fetch; the walker passes a
    cache-backed fetcher so the response is reused for license resolution.
    """
    data = fetcher(_version_url(name, version), client)
    if data is None:
        return [], False
    complete = True
    out: list[Dependency] = []
    seen: set[str] = set()
    fields: list[str] = ["dependencies"]
    if include_peer:
        fields.append("peerDependencies")
    if include_optional:
        fields.append("optionalDependencies")
    for field_name in fields:
        deps_dict = data.get(field_name)
        if deps_dict is None:
            continue
        if not isinstance(deps_dict, dict):
            complete = False
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
    return out, complete
