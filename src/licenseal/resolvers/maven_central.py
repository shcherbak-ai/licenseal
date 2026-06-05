"""Resolve license information for Java/JVM artifacts via Maven Central.

Maven Central (``repo.maven.apache.org``) is the canonical artifact
registry for the JVM ecosystem. It serves a raw POM (Project Object
Model) XML for every published artifact at a predictable URL:

.. code-block:: text

    https://repo.maven.apache.org/maven2/{group/path}/{artifact}/{version}/{artifact}-{version}.pom

The POM's ``<licenses>`` block is the authoritative author-declared
license metadata — exactly on-pattern with reading ``license`` from
``Cargo.toml`` (Rust) or PyPI's ``info.license`` (Python). Same trust
shape, routed through Java's actual declaration form.

**Parent-POM inheritance.** Maven's resolution model lets a child POM
omit ``<licenses>`` and inherit from its ``<parent>`` (and the parent's
parent, recursively). Most enterprise POMs only declare licenses at the
top of the chain — a starter / submodule POM inherits its license from
a shared ``-dependencies`` BOM at the reactor root. This resolver walks
the parent chain (capped at :data:`_MAX_PARENT_DEPTH`) looking for the
first POM with a ``<licenses>`` block.

**deps.dev fallback.** If the parent chain runs out (private corporate
parent not on Maven Central, malformed POM, or the long tail of
pre-2015 deployments that skipped license metadata altogether), the
resolver falls back to deps.dev's stable v3 endpoint for the MAVEN
system. deps.dev runs Google's ``licensecheck`` over the artifact's
LICENSE file at the tagged commit — same fallback pattern Python uses
for the PEP 658 sidecar when PyPI's JSON has empty license fields.

XML parsing is shared with the discovery layer
(:mod:`licenseal.discovery.java.pom_xml`) — both sides read the same
POM schema, both use defusedxml to block XML-bomb and external-entity
attacks (the registry response, like the on-disk POM, is untrusted
input).
"""

from __future__ import annotations

import re
import urllib.parse
from typing import cast

import httpx

from licenseal.analysis.spdx import normalize_license, spdx_from_license_url
from licenseal.discovery.java.pom_xml import (
    _expand_properties,
    _parse_pom,
    _PomData,
    _project_properties,
)
from licenseal.models import Dependency, LicenseInfo
from licenseal.resolvers.deps_dev import (
    _license_info_from_version_object,
)
from licenseal.resolvers.http import (
    Fetcher,
    fetch_registry_json,
    fetch_registry_text,
)

# Sonatype publishes Maven Central at multiple equivalent hostnames
# (CNAMEs to the same Cloudflare-fronted backend):
#   * ``repo.maven.apache.org`` — Apache Foundation alias, recommended
#   * ``repo1.maven.apache.org`` — historical primary
#   * ``repo1.maven.org`` — Sonatype-direct
# We use ``repo.maven.apache.org`` because the ``repo1`` subdomain has
# had DNS-resolution incidents in the past (some downstream resolvers
# cache a stale NXDOMAIN). ``repo.maven.apache.org`` resolves cleanly
# everywhere and serves identical bytes.
_MAVEN_CENTRAL_POM_URL = (
    "https://repo.maven.apache.org/maven2/"
    "{group_path}/{artifact}/{version}/{artifact}-{version}.pom"
)
_DEPS_DEV_MAVEN_VERSION_URL = (
    "https://api.deps.dev/v3/systems/MAVEN/packages/{name}/versions/{version}"
)

# Public Maven registry fallbacks tried in order when Maven Central 404s
# on a POM. Each entry is a base URL that serves the standard layout
# ``{base}/{group/path}/{artifact}/{version}/{artifact}-{version}.pom``.
#
# Inclusion criterion (also documented in SECURITY.md):
#   1. Operated by a recognized OSS foundation or major widely-trusted
#      vendor (here: Google, Jenkins Project / Continuous Delivery
#      Foundation).
#   2. Public-read, HTTPS, no authentication required.
#   3. Serves POMs at the canonical ``/maven2/`` layout.
#   4. Covers a meaningfully large fraction of OSS JVM artifacts not
#      mirrored to Maven Central (≥5% of typical dev usage).
#
# This list is hard-coded by design: scan targets cannot expand it via
# their own POM ``<repositories>`` declarations (the SSRF + cross-artifact
# license-misinformation surface that opens is wider than the trust
# already granted to scanned manifests). Adding a new entry requires a
# licenseal release.
_FALLBACK_POM_REGISTRIES: tuple[str, ...] = (
    # Vendor-operated Maven repository serving a parent-POM chain not mirrored
    # to Central. Required when a scan target's parent inheritance resolves
    # to artifacts published only here. See SECURITY.md for the inclusion
    # criterion and per-host trust rationale.
    "https://dl.google.com/dl/android/maven2/"
    "{group_path}/{artifact}/{version}/{artifact}-{version}.pom",
    # Foundation-operated Maven repository serving a parent-POM chain not
    # mirrored to Central. Same inclusion criterion as above; see SECURITY.md.
    "https://repo.jenkins-ci.org/public/{group_path}/{artifact}/{version}/{artifact}-{version}.pom",
)

# Cap parent-chain traversal. Maven itself permits unbounded inheritance
# but real-world chains rarely exceed 2-3 levels
# (``app → org-parent → super-parent``). A small cap also bounds the
# blast-radius of a maliciously-constructed circular parent reference
# in a scan-target POM tree.
_MAX_PARENT_DEPTH = 5

# Maven version syntax used as a dependency ``<version>``. Accepts the
# standard ``MAJOR[.MINOR[.PATCH]]`` plus optional qualifier suffix
# (``-SNAPSHOT``, ``-rc1``, ``.RELEASE``, ``+sha256.abc``…). Rejects
# range syntax (``[1.0,2.0)``, ``[1.0]``), the legacy ``RELEASE`` /
# ``LATEST`` macros (removed in Maven 3 but still seen in old POMs),
# and unresolved ``${…}`` property tokens that survived the discovery
# layer's local property-expansion pass (post-expansion these should
# not reach the network — the registry would 404 on the literal token).
_MAVEN_PINNED_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+.][A-Za-z0-9.+_-]+)?$")


def _extract_pinned_version_maven(version_constraint: str) -> str | None:
    """Return the pinned version when ``version_constraint`` is concrete.

    Accepts ``X.Y.Z`` / ``X.Y`` / ``X`` with optional qualifier suffix,
    plus the licenseal-internal ``==X.Y.Z`` form used by the transitive
    walker's lockfile-shaped output. Rejects ranges, ``RELEASE`` /
    ``LATEST``, and unresolved ``${…}`` placeholders.
    """
    spec = version_constraint.strip()
    if not spec:
        return None
    if spec.startswith("=="):
        spec = spec[2:].strip()
    if _MAVEN_PINNED_VERSION_RE.fullmatch(spec):
        return spec
    return None


def _license_string_from_pom(licenses: list[tuple[str, str]]) -> str:
    """Join multi-``<license>`` entries with ``" AND "``.

    Uses the ``<name>`` when present, falling back to the ``<url>`` for
    license entries that omit the name (rare but valid in modern POMs
    that point directly at an SPDX URL). Same conservative semantic as
    the Go path: a multi-LICENSE artifact binds the consumer to all
    named licenses simultaneously (per SPDX ``AND``).
    """
    names = [name or url for name, url in licenses]
    if len(names) == 1:
        return names[0]
    return " AND ".join(names)


def _maven_central_pom_url(group_id: str, artifact_id: str, version: str) -> str:
    """Build the canonical Maven Central POM URL for ``(group, artifact, version)``.

    Maven coordinates are URL-safe by spec (alphanumerics plus ``.-_``)
    but the group → path mapping splits on ``.``. URL-encoding each
    component defends against pathological coordinates without changing
    well-formed ones.
    """
    group_path = group_id.replace(".", "/")
    return _MAVEN_CENTRAL_POM_URL.format(
        group_path=urllib.parse.quote(group_path, safe="/"),
        artifact=urllib.parse.quote(artifact_id, safe=""),
        version=urllib.parse.quote(version, safe=""),
    )


def _fetch_pom(
    group_id: str,
    artifact_id: str,
    version: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> _PomData | None:
    """Fetch a POM from Maven Central, falling back to other well-known
    public Maven registries on 404.

    Tries each URL in turn:

    1. Maven Central (``repo.maven.apache.org``) — the canonical primary.
    2. Each entry in :data:`_FALLBACK_POM_REGISTRIES`. Hard-coded list
       covering OSS JVM artifacts not mirrored to Central; see SECURITY.md
       for the per-host inclusion criterion.

    Returns ``None`` when every registry returns no body (404 or network
    error) or the body isn't parseable XML. The caller routes those
    cases through the deps.dev fallback for license metadata.

    Per-scan URL cache deduplication still applies: each registry URL is
    cached independently, so the same fallback POM is fetched at most
    once per scan.
    """
    group_path = group_id.replace(".", "/")
    encoded_group_path = urllib.parse.quote(group_path, safe="/")
    encoded_artifact = urllib.parse.quote(artifact_id, safe="")
    encoded_version = urllib.parse.quote(version, safe="")

    candidate_urls = [_maven_central_pom_url(group_id, artifact_id, version)]
    candidate_urls.extend(
        template.format(
            group_path=encoded_group_path,
            artifact=encoded_artifact,
            version=encoded_version,
        )
        for template in _FALLBACK_POM_REGISTRIES
    )

    for url in candidate_urls:
        data = fetcher(url, client)
        if data is None:
            continue
        text = data.get("text", "")
        if not isinstance(text, str) or not text:
            continue
        return _parse_pom(text)
    return None


def _licenses_from_deps_dev(
    group_id: str,
    artifact_id: str,
    version: str,
    client: httpx.Client,
    json_fetcher: Fetcher,
) -> list[tuple[str, str]]:
    """Query deps.dev for a single Maven artifact's licenses.

    Returns a ``[(name, url)]`` list matching the shape of POM
    ``<licenses>`` so callers can drop the result into the same
    normalization path. ``url`` is always ``""`` because deps.dev's
    response only exposes SPDX-shaped names, no canonical URLs.

    Used as the parent-chain-fallback inside :func:`_walk_for_licenses`
    when a parent POM 404s on Maven Central: the parent may still be
    indexed by deps.dev (which mirrors a broader version set than
    Central's primary cache, including some artifacts only published to
    secondary repos like ``repo.jenkins-ci.org``). Empty list when
    deps.dev also has nothing.
    """
    coord = f"{group_id}:{artifact_id}"
    encoded_name = urllib.parse.quote(coord, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    url = _DEPS_DEV_MAVEN_VERSION_URL.format(name=encoded_name, version=encoded_version)
    data = json_fetcher(url, client)
    if data is None:
        return []
    licenses_field = cast("dict", data).get("licenses", [])
    if not isinstance(licenses_field, list):
        return []
    out: list[tuple[str, str]] = []
    for entry in licenses_field:
        if isinstance(entry, str) and entry.strip():
            out.append((entry.strip(), ""))
    return out


def _walk_for_licenses(
    pom: _PomData,
    client: httpx.Client,
    fetcher: Fetcher,
    json_fetcher: Fetcher,
) -> list[tuple[str, str]]:
    """Walk the parent chain looking for the first POM with a ``<licenses>`` block.

    Maven's resolution model says: when ``<licenses>`` is absent the
    artifact inherits from its ``<parent>``. The walk:

    * Examines the input POM first; if it has licenses, returns them.
    * Otherwise resolves the parent coordinates (with property expansion
      against the current POM's own ``<properties>`` — parent versions
      are commonly interpolated, e.g. ``<version>${revision}</version>``).
    * Fetches the parent POM from Maven Central, recurses up to
      :data:`_MAX_PARENT_DEPTH` levels deep.
    * When Maven Central 404s on a parent (the parent is published only
      to a secondary repository like ``repo.jenkins-ci.org`` or a
      retired Sun glassfish mirror), falls back to deps.dev's ``MAVEN``
      index for the parent's own ``<licenses>``. deps.dev does not
      expose POM content, so we can't continue the parent walk past
      that point — but the licenses for that specific parent are often
      enough (most enterprise parent POMs only declare licenses, not
      additional inheritance).

    Returns ``[]`` when the chain is exhausted without finding a
    ``<licenses>`` block — the caller routes to the deps.dev fallback
    for the original artifact.
    """
    current = pom
    for _ in range(_MAX_PARENT_DEPTH + 1):
        if current.licenses:
            return current.licenses
        parent_group = current.parent_group_id
        parent_artifact = current.parent_artifact_id
        parent_version = current.parent_version
        if not (parent_group and parent_artifact and parent_version):
            return []
        # Real-world parent versions may interpolate against the child's
        # own properties (``${revision}`` is the canonical example from
        # Maven's CI-friendly versions pattern). Resolve them locally
        # before hitting Maven Central; an unresolved token would 404.
        props = _project_properties(current)
        parent_version = _expand_properties(parent_version, props)
        if "${" in parent_version:
            return []
        parent_pom = _fetch_pom(parent_group, parent_artifact, parent_version, client, fetcher)
        if parent_pom is None:
            # Maven Central can't serve this parent — try deps.dev for
            # the parent's own licenses. If deps.dev also has nothing,
            # the chain ends here (we have no POM body to read the
            # grandparent from).
            return _licenses_from_deps_dev(
                parent_group, parent_artifact, parent_version, client, json_fetcher
            )
        current = parent_pom
    return []


def _resolve_via_deps_dev(
    dep: Dependency,
    group_id: str,
    artifact_id: str,
    version: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> LicenseInfo:
    """deps.dev fallback for artifacts whose POM chain has no ``<licenses>``.

    Hits the stable v3 single-version endpoint with ``system=MAVEN``;
    the response shape mirrors the Go-side endpoint (``licenses`` SPDX
    array + ``links``), so :func:`_license_info_from_version_object`
    is reused for the parse + normalization.
    """
    coord = f"{group_id}:{artifact_id}"
    encoded_name = urllib.parse.quote(coord, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    url = _DEPS_DEV_MAVEN_VERSION_URL.format(name=encoded_name, version=encoded_version)
    data = fetcher(url, client)
    if data is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            resolved_version=version,
            from_registry=False,
        )
    return _license_info_from_version_object(dep, version, cast("dict", data))


def resolve_maven_central_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_text,
    json_fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Resolve license for a Java/JVM artifact from Maven Central.

    Two-stage resolution:

    1. Fetch the artifact's POM from ``repo.maven.apache.org``. Walk
       up to :data:`_MAX_PARENT_DEPTH` parents looking for a
       ``<licenses>`` block. Return the first hit.

    2. If the chain doesn't surface ``<licenses>`` (or the artifact's
       own POM is unreachable), fall back to deps.dev's MAVEN system.
       deps.dev's index covers a broader version set than Maven Central
       currently serves (it retains old versions Central has retired)
       and applies a license-text scanner where the POM is silent.

    ``fetcher`` is the text-mode fetcher for POM XML (defaults to the
    direct HTTP call; the CLI passes ``RegistryCache.fetch_text`` so
    per-scan re-fetches of the same parent POM collapse).
    ``json_fetcher`` is the JSON-mode fetcher used for the deps.dev
    fallback — kept distinct because the cache trims those two
    endpoints differently.
    """
    if ":" not in dep.name:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )
    group_id, artifact_id = dep.name.split(":", 1)
    if not group_id or not artifact_id:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )
    pinned = _extract_pinned_version_maven(dep.version_constraint)
    if pinned is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )

    pom = _fetch_pom(group_id, artifact_id, pinned, client, fetcher)
    if pom is None:
        # POM is unreachable / malformed. deps.dev's MAVEN index
        # sometimes serves versions Central no longer mirrors directly,
        # so the fallback can still surface a license.
        return _resolve_via_deps_dev(dep, group_id, artifact_id, pinned, client, json_fetcher)

    licenses = _walk_for_licenses(pom, client, fetcher, json_fetcher)
    if licenses:
        # Normalize each ``<license><name>`` individually before composing
        # the SPDX expression. POM entries are free-form publisher strings
        # ("Apache License, Version 2.0", "The MIT License (MIT)") that
        # require alias-map lookup; if we joined first and normalized the
        # compound string, normalize_license's compound-decomposition
        # branch wouldn't fire (it short-circuits when the literal
        # uppercase ``" AND "`` is already present).
        #
        # Per-entry URL fallback: when ``<name>`` normalizes to UNKNOWN
        # or Proprietary, we consult the same entry's ``<url>``. Real
        # publishers (Apache, Eclipse, GNU, Mozilla, OSI) point ``<url>``
        # at the canonical license-text page on their own website; the
        # URL is structurally a license identifier and a stronger signal
        # than the free-form name. This is genuinely additional data
        # licenseal's direct POM fetch makes available — ``deps.dev``'s
        # API surfaces only the name.
        normalized_parts: list[str] = []
        for name, url in licenses:
            primary = normalize_license(name) if name else "UNKNOWN"
            if primary in ("UNKNOWN", "Proprietary") and url:
                from_url = spdx_from_license_url(url)
                if from_url:
                    primary = normalize_license(from_url)
            normalized_parts.append(primary)
        raw = _license_string_from_pom(licenses)
        if all(part == "UNKNOWN" for part in normalized_parts):
            # Every license entry (name + url) was unparseable; deps.dev's
            # licensecheck-over-LICENSE-file path may still recover one.
            return _resolve_via_deps_dev(dep, group_id, artifact_id, pinned, client, json_fetcher)
        if all(part == "Proprietary" for part in normalized_parts):
            # Maven Central is OSS-by-convention; a "Proprietary"
            # classification there is highly suspicious — overwhelmingly
            # the cause is a placeholder string in the POM ("non-standard",
            # "see LICENSE", custom internal text) rather than a real
            # commercial license. Probe deps.dev's licensecheck path,
            # which reads the actual ``LICENSE`` file at the artifact's
            # tagged commit. Keep the deps.dev answer only when it
            # surfaces a real SPDX ID; otherwise the original POM-derived
            # ``Proprietary`` stands so we don't downgrade a legitimately
            # commercial dep to UNKNOWN.
            fallback = _resolve_via_deps_dev(
                dep, group_id, artifact_id, pinned, client, json_fetcher
            )
            if fallback.from_registry and fallback.license_id not in ("UNKNOWN", "Proprietary", ""):
                return fallback
        license_id = (
            normalized_parts[0] if len(normalized_parts) == 1 else " AND ".join(normalized_parts)
        )
        return LicenseInfo(
            dependency=dep,
            license_id=license_id,
            license_raw=raw,
            resolved_version=pinned,
            from_registry=True,
        )

    # POM chain exhausted without licenses → deps.dev fallback.
    return _resolve_via_deps_dev(dep, group_id, artifact_id, pinned, client, json_fetcher)
