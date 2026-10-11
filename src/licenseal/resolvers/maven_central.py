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

from dataclasses import replace
from typing import cast

import httpx

from licenseal.analysis.spdx import (
    all_apply_reading,
    and_join_licenses,
    declares_proprietary,
    normalize_license,
    spdx_from_license_url,
)
from licenseal.discovery.java.build_gradle import _BUILD_GRADLE_NAMES
from licenseal.discovery.java.pom_xml import (
    _expand_properties,
    _parse_pom,
    _PomData,
    _project_properties,
)
from licenseal.models import Dependency, Ecosystem, LicenseInfo
from licenseal.resolvers.deps_dev import (
    _license_entries,
    _license_info_from_version_object,
)
from licenseal.resolvers.http import (
    Fetcher,
    fetch_registry_json,
    fetch_registry_text,
    quote_coordinate,
)
from licenseal.resolvers.version_selection import concrete_maven_version, select_version

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

# Public Maven registry fallbacks, tried in order after Maven Central for
# any POM (a dependency's own, a parent, an imported BOM) that Central
# gives no usable body for: a 404, another error status, a request that
# still fails after its retries, an empty body. An artifact's
# ``maven-metadata.xml`` is read from the same registries under the same
# condition (:data:`_VERSION_LIST_URLS`). Each entry is a base URL that
# serves the standard layout
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
    # Vendor-operated Maven repository serving artifacts not mirrored to
    # Central. Required when a scan target's dependencies, or the parents
    # and BOMs they inherit from, are published only here. See SECURITY.md
    # for the inclusion criterion and per-host trust rationale.
    "https://dl.google.com/dl/android/maven2/"
    "{group_path}/{artifact}/{version}/{artifact}-{version}.pom",
    # Foundation-operated Maven repository serving artifacts not mirrored
    # to Central. Same inclusion criterion as above; see SECURITY.md.
    "https://repo.jenkins-ci.org/public/{group_path}/{artifact}/{version}/{artifact}-{version}.pom",
)

# A registry of the standard layout lists an artifact's published versions in
# ``maven-metadata.xml``, beside the per-version directories its POMs are in.
# The list is read from the registries the POMs are read from, in the same
# order, and from no other host.
_VERSION_LIST_URLS: tuple[str, ...] = tuple(
    template.partition("{version}/")[0] + "maven-metadata.xml"
    for template in (_MAVEN_CENTRAL_POM_URL, *_FALLBACK_POM_REGISTRIES)
)

# Cap parent-chain traversal. Maven itself permits unbounded inheritance
# but real-world chains rarely exceed 2-3 levels
# (``app → org-parent → super-parent``). A small cap also bounds the
# blast-radius of a maliciously-constructed circular parent reference
# in a scan-target POM tree.
_MAX_PARENT_DEPTH = 5


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
        group_path=quote_coordinate(group_path, safe="/"),
        artifact=quote_coordinate(artifact_id, safe=""),
        version=quote_coordinate(version, safe=""),
    )


def _fetch_pom(
    group_id: str,
    artifact_id: str,
    version: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> _PomData | None:
    """Fetch a POM from Maven Central, falling back to other well-known
    public Maven registries when Central gives no usable body.

    Any POM is fetched this way: a dependency's own, a parent, an imported
    BOM. Tries each URL in turn and takes the first non-empty body:

    1. Maven Central (``repo.maven.apache.org``) — the canonical primary.
    2. Each entry in :data:`_FALLBACK_POM_REGISTRIES`. Hard-coded list
       covering OSS JVM artifacts not mirrored to Central; see SECURITY.md
       for the per-host inclusion criterion.

    A registry gives no usable body when the fetch fails (a 404, another
    error status, a request that still fails after its retries) or the
    body is empty. Returns ``None`` when no registry gives one, and when
    the first body found isn't parseable XML: the next registry is not
    asked for a POM another one served. The caller routes those cases
    through the deps.dev fallback for license metadata.

    Per-scan URL cache deduplication still applies: each registry URL is
    cached independently, so the same fallback POM is fetched at most
    once per scan.
    """
    group_path = group_id.replace(".", "/")
    encoded_group_path = quote_coordinate(group_path, safe="/")
    encoded_artifact = quote_coordinate(artifact_id, safe="")
    encoded_version = quote_coordinate(version, safe="")

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


def _versions_from_metadata(text: str) -> list[str]:
    """The versions a ``maven-metadata.xml`` body lists; empty when it lists none.

    Reads ``<versioning><versions><version>`` only. The ``<release>`` and
    ``<latest>`` elements beside it are not used: both may name a prerelease.
    """
    try:
        from defusedxml import ElementTree as DefusedET

        root = DefusedET.fromstring(text)
    except Exception:  # noqa: BLE001 - defusedxml raises many entity classes
        return []
    return [
        version.text.strip()
        for versioning in root
        if versioning.tag.rsplit("}", 1)[-1] == "versioning"
        for versions in versioning
        if versions.tag.rsplit("}", 1)[-1] == "versions"
        for version in versions
        if version.tag.rsplit("}", 1)[-1] == "version" and version.text and version.text.strip()
    ]


def _latest_release(
    group_id: str, artifact_id: str, client: httpx.Client, fetcher: Fetcher
) -> str | None:
    """The latest release of an artifact, or None when it cannot be determined.

    Asks each registry in :data:`_VERSION_LIST_URLS` in turn for the
    artifact's version list and answers from the first one that lists a
    usable version. The latest release is the highest version that is not a
    prerelease (an alpha, a milestone, a release candidate); an artifact
    published only as prereleases answers with the highest of those. A
    ``-SNAPSHOT`` is a build in progress, not a published version, and is
    never the answer.
    """
    group_path = quote_coordinate(group_id.replace(".", "/"), safe="/")
    artifact = quote_coordinate(artifact_id, safe="")
    for template in _VERSION_LIST_URLS:
        data = fetcher(template.format(group_path=group_path, artifact=artifact), client)
        text = data.get("text") if data is not None else None
        if not isinstance(text, str) or not text:
            continue
        # Only versions a POM can be fetched for are candidates.
        published = [
            version
            for version in _versions_from_metadata(text)
            if concrete_maven_version(version) == version
            and not version.upper().endswith("-SNAPSHOT")
        ]
        if published:
            return select_version(Ecosystem.JAVA, "", published)
    return None


def estimate_gradle_version(dep: Dependency, client: httpx.Client, fetcher: Fetcher) -> str | None:
    """The version to report for a Gradle coordinate declared with no version.

    A build that leaves versions to a BOM or to a dependency-management
    plugin declares bare ``group:artifact`` coordinates, and only a
    ``gradle.lockfile`` records the version the build selects. Without one,
    the artifact's latest release stands in as an estimate.

    Returns None for anything else: a coordinate that states a version (even
    one that cannot be resolved, such as a range or a ``${…}`` token), a
    dependency not declared in a Gradle build file (a ``pom.xml`` gets its
    missing versions from its parent chain), a dependency with an origin
    (it is not a registry artifact, and nothing is requested for it), and an
    artifact whose latest release cannot be determined. ``fetcher`` is the
    text-mode fetcher the POMs are read with.
    """
    if (
        dep.origin
        or dep.version_constraint.strip()
        or dep.source.rsplit("/", 1)[-1] not in _BUILD_GRADLE_NAMES
    ):
        return None
    group_id, _, artifact_id = dep.name.partition(":")
    if not group_id or not artifact_id:
        return None
    return _latest_release(group_id, artifact_id, client, fetcher)


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
    when no registry :func:`_fetch_pom` asks serves a parent POM: the
    parent may still be indexed by deps.dev (which mirrors a broader
    version set than Central's primary cache, including artifacts
    published only to secondary repositories). Empty list when
    deps.dev also has nothing, or answers with its ``non-standard``
    marker, alone or beside other entries — the same array is no answer in
    the batch pre-pass either.
    """
    coord = f"{group_id}:{artifact_id}"
    encoded_name = quote_coordinate(coord, safe="")
    encoded_version = quote_coordinate(version, safe="")
    url = _DEPS_DEV_MAVEN_VERSION_URL.format(name=encoded_name, version=encoded_version)
    data = json_fetcher(url, client)
    if data is None:
        return []
    entries = _license_entries(cast("dict", data).get("licenses"))
    return [(entry.strip(), "") for entry in entries if entry.strip()]


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
    * Fetches the parent POM through :func:`_fetch_pom` (Maven Central,
      then the fallback registries), recurses up to
      :data:`_MAX_PARENT_DEPTH` levels deep.
    * When none of those registries serves the parent (it is published
      only to a repository licenseal does not ask, or to a retired vendor
      mirror), falls back to deps.dev's ``MAVEN``
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
            # No registry serves this parent — try deps.dev for
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
    encoded_name = quote_coordinate(coord, safe="")
    encoded_version = quote_coordinate(version, safe="")
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
    pinned = concrete_maven_version(dep.version_constraint)
    if pinned is None:
        # A Gradle coordinate with no version is read at its latest release,
        # the version the transitive walk gives it too.
        pinned = estimate_gradle_version(dep, client, fetcher)
        if pinned is not None:
            dep = replace(dep, version_estimated=True)
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
        #
        # A name that declares the license proprietary in so many words
        # (``Proprietary``, ``Commercial License``) is the declaration, and
        # the URL does not replace it. A placeholder (``non-standard``) or a
        # pointer to a bundled file reads as Proprietary too, declares
        # nothing, and is still answered by the URL.
        #
        # A ``<name>`` that is a comma- or slash-separated list does not
        # say whether its entries are alternatives. ``normalized_parts``
        # reads each such name as a choice and ``all_apply_parts`` reads it
        # as every entry applying; the two differ only when a name is a
        # list.
        normalized_parts: list[str] = []
        all_apply_parts: list[str] = []
        for name, url in licenses:
            primary = normalize_license(name) if name else "UNKNOWN"
            all_apply = all_apply_reading(name) or primary
            undeclared = primary == "UNKNOWN" or (
                primary == "Proprietary" and not declares_proprietary(name)
            )
            if undeclared and url:
                from_url = spdx_from_license_url(url)
                if from_url:
                    primary = all_apply = normalize_license(from_url)
            normalized_parts.append(primary)
            all_apply_parts.append(all_apply)
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
        # The composed ``license_id`` is not normalized again, so an entry
        # that expanded to an ``OR`` expression has to be grouped here.
        license_id = (
            normalized_parts[0]
            if len(normalized_parts) == 1
            else and_join_licenses(normalized_parts)
        )
        return LicenseInfo(
            dependency=dep,
            license_id=license_id,
            license_raw=raw,
            resolved_version=pinned,
            from_registry=True,
            all_apply_license_id=(
                normalize_license(and_join_licenses(all_apply_parts))
                if all_apply_parts != normalized_parts
                else ""
            ),
        )

    # POM chain exhausted without licenses → deps.dev fallback.
    return _resolve_via_deps_dev(dep, group_id, artifact_id, pinned, client, json_fetcher)
