"""Resolve license information for Go modules via deps.dev.

deps.dev is the Open Source Insights project — a Google-operated index over
public package ecosystems that, for Go specifically, runs Google's
``licensecheck`` library (a high-confidence SPDX template matcher) over each
module's LICENSE file at the version's tagged commit. The output is structured
SPDX identifiers in the response's ``licenses`` array.

This is **not** prose extraction. Go's conventional license declaration is
the LICENSE file at module root (there's no manifest field for it, by design);
deps.dev is the ecosystem's canonical reader. Same trust shape as reading
``Cargo.toml``'s ``license = "MIT"`` for crates.io, routed through Go's
actual declaration form.

Two endpoints are used:

* ``POST /v3alpha/versionbatch`` — primary, batches up to 5000 ``(name,
  version)`` lookups per request. Almost every scan ships in 1-2 batch
  calls instead of N single GETs, which both reduces wall-clock and gives
  us a separate rate-limit budget from per-version GETs.
* ``GET /v3/systems/GO/packages/{name}/versions/{version}`` — fallback for
  the rare case where the batch POST itself fails (network / 5xx). Stable
  v3, same response shape as the per-item ``version`` object inside the
  batch response.

The earlier prototype against ``pkg.go.dev/v1beta`` is preserved in the
project history. It was correct on coverage (≈98% on sequential probes)
but its single per-IP rate budget couldn't carry bulk scans of large Go
projects (~73% 429s at 16-way concurrency, with cumulative throttling
even at cap=4). deps.dev sits on Google's API gateway, supports the batch
shape natively, and ships independent rate budgets per endpoint.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any, cast

import httpx

from licenseal._concurrency import map_with_context
from licenseal.analysis.spdx import normalize_license
from licenseal.models import Dependency, LicenseInfo
from licenseal.resolvers.http import (
    Fetcher,
    fetch_registry_json,
    fetch_registry_json_post,
)

_DEPS_DEV_BATCH_URL = "https://api.deps.dev/v3alpha/versionbatch"
_DEPS_DEV_V3_VERSION_URL = "https://api.deps.dev/v3/systems/GO/packages/{name}/versions/{version}"

# Maven-side equivalent of the version endpoint, used by the Maven
# resolver's deps.dev fallback path (see ``resolvers.maven_central``).
_DEPS_DEV_MAVEN_VERSION_URL = (
    "https://api.deps.dev/v3/systems/MAVEN/packages/{name}/versions/{version}"
)

# NuGet-side equivalent, used by the NuGet resolver as Tier 3 fallback
# when the NuGet flatcontainer .nuspec has neither <license type="expression">
# nor a mappable <licenseUrl>. deps.dev's NUGET index supplies SPDX results
# from its own licensecheck pass over the package's actual LICENSE file.
_DEPS_DEV_NUGET_VERSION_URL = (
    "https://api.deps.dev/v3/systems/NUGET/packages/{name}/versions/{version}"
)

# Transitive resolution: deps.dev's ``GetDependencies`` endpoint returns
# the resolved subgraph rooted at the requested ``(name, version)``.
# Documented as available for npm, Cargo, Maven, and PyPI (not Go); we
# use the Maven flavor to offload Maven's resolution model (parent POMs,
# ``<dependencyManagement>``, BOMs, ``${…}`` substitution) — implementing
# that ourselves would be weeks of work for an algorithm that ``mvn``
# already runs.
_DEPS_DEV_MAVEN_DEPS_URL = (
    "https://api.deps.dev/v3/systems/MAVEN/packages/{name}/versions/{version}:dependencies"
)

# Cap items per batch POST. Documented request-side ceiling is 5000, but
# the response truncates at exactly 100 entries regardless of request size
# (verified empirically against PYPI/NPM/CARGO systems: request 101 → 100
# returned, request 1000 → 100 returned, with the excess deps silently
# absent from ``responses``). Any chunk > 100 silently drops the tail and
# pushes those deps through the per-version fallback for no benefit, so
# 100 is the load-bearing value here, not a tunable. Smaller chunks also
# bound 5xx blast radius and let multiple chunks overlap in the executor.
_BATCH_CHUNK_SIZE = 100

# Ceiling on concurrent batch POSTs, applied on top of ``--max-workers``.
# Each POST asks deps.dev to run its license matcher over up to
# ``_BATCH_CHUNK_SIZE`` packages, so a batch request is far heavier
# server-side — and more rate-limit-sensitive — than the per-package GETs
# that ``--max-workers`` otherwise governs. Without this cap, a large
# monorepo (thousands of single-ecosystem deps → dozens of 100-dep chunks)
# scanned at a high worker count would burst that many heavy POSTs at the
# endpoint at once. ``--max-workers`` still governs DOWNWARD — lowering it
# throttles the batch too (``min`` below) — this only bounds the ceiling.
# This is the explicit per-endpoint knob the concurrency note in
# ``resolvers.http`` anticipates: visible and documented, not an invisible
# per-host cap that silently overrides the user-facing flag.
_BATCH_MAX_WORKERS = 8


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Pass through Go-style pinned semver verbatim.

    Go versions are always pinned (no ranges in ``go.mod`` / ``go.sum``; even
    with ``go get`` users are resolving against pinned versions chosen by
    Minimum Version Selection). Accepts standard ``vMAJOR.MINOR.PATCH``,
    pseudo-versions (``v0.0.0-20240101000000-abcdef123456``), and
    pre-release/build-metadata variants. Returns the value unchanged if it
    looks plausibly version-like, else None.
    """
    spec = version_constraint.strip()
    if not spec:
        return None
    # Strip licenseal-internal ``==`` if present (the cross-ecosystem
    # transitive walker sometimes wraps versions that way).
    if spec.startswith("=="):
        spec = spec[2:].strip()
    if not spec.startswith("v"):
        return None
    if len(spec) < 2 or not spec[1].isdigit():
        return None
    return spec


# Systems whose publisher convention treats a multi-element ``licenses``
# array as disjunctive (consumer picks one). RubyGems' gemspec ``licenses
# = [...]`` follows the same convention as Composer's composer.json
# ``license`` array — the publisher offers a choice. Empirically validated
# against the Ruby bench corpus: license_finder's ``Simplified BSD OR
# ruby`` matches the canonical ``["BSD-2-Clause", "Ruby"]`` interpretation
# that bigdecimal / nio4r / drb / json (Ruby stdlib gems) all carry.
_DISJUNCTIVE_MULTI_LICENSE_SYSTEMS: frozenset[str] = frozenset({"RUBYGEMS"})


def _licenses_to_spdx(licenses_field: object, *, system: str = "") -> str:
    """Collapse the response's ``licenses`` array into a single SPDX expression.

    deps.dev's documented contract is to return ONE entry per version that
    holds the full SPDX expression — including operators::

        "licenses": ["MIT"]
        "licenses": ["Apache-2.0 OR MIT"]
        "licenses": ["Apache-2.0 WITH LLVM-exception"]

    Verified empirically across 600 sampled deps in PYPI / NPM / CARGO
    (probe ``licenseal-scans/_probe_deps_dev_batch_coverage.py``): 599/600
    were 0- or 1-entry; the multi-entry case effectively does not occur
    in practice. The multi-entry branch below is retained as defensive
    code, with per-system join semantics:

    * For systems whose publisher convention treats multi-element license
      arrays as **disjunctive** (RubyGems, per gemspec convention; the same
      shape as Composer's ``license`` array) — join with ``OR``.
    * For every other system, join with ``AND`` (the conservative /
      more-restrictive choice; the user can override via
      ``licenseal.review.toml``).

    deps.dev surfaces ``"non-standard"`` for packages whose ``<licenseUrl>``
    (NuGet) or ``<license>`` (Maven) tag couldn't be matched to an SPDX
    expression — the publisher declared a license but in a shape
    deps.dev's licensecheck couldn't categorize. The string is returned
    by deps.dev as a "no opinion" signal, NOT a "proprietary license"
    claim. Some legacy Microsoft .NET Framework / pre-2018 NuGet
    packages (Microsoft.CSharp 4.3.0, System.* 4.3.x, ~60 mainstream
    packages from that era) carry only an old ``<licenseUrl>`` to
    Microsoft's generic ``.NET Library`` EULA page, hitting this code
    path. We filter ``"non-standard"`` out of the joined expression so
    it doesn't get fed into ``normalize_license`` (where it would alias
    to ``Proprietary`` — semantically wrong for the deps.dev source,
    even though that alias is correct for the Cargo-publisher source
    where the string is publisher-authored). When the ``"non-standard"``
    filter leaves the list empty, the caller surfaces UNKNOWN, which
    is the accurate signal for "deps.dev couldn't classify".
    """
    if not isinstance(licenses_field, list):
        return ""
    collected: list[str] = []
    seen: set[str] = set()
    for entry in licenses_field:
        if not isinstance(entry, str) or not entry:
            continue
        if entry.strip().lower() == "non-standard":
            # deps.dev's "I can't classify this" signal; do NOT route to
            # the publisher-authored "non-standard" → Proprietary alias.
            continue
        if entry not in seen:
            seen.add(entry)
            collected.append(entry)
    if not collected:
        return ""
    if len(collected) == 1:
        return collected[0]
    operator = " OR " if system in _DISJUNCTIVE_MULTI_LICENSE_SYSTEMS else " AND "
    return operator.join(collected)


def _repo_url_from_links(links_field: object) -> str:
    """Find the SOURCE_REPO link from deps.dev's ``links`` array.

    deps.dev returns ``links: [{"label": "SOURCE_REPO", "url": "..."}, ...]``
    where SOURCE_REPO points to the canonical VCS URL (GitHub / GitLab / etc.).
    Used to populate ``LicenseInfo.repository_url`` so the table renderer
    can construct a LICENSE-file hint URL.
    """
    if not isinstance(links_field, list):
        return ""
    for entry in links_field:
        if not isinstance(entry, dict):
            continue
        entry_d = cast("dict[str, Any]", entry)
        if entry_d.get("label") != "SOURCE_REPO":
            continue
        url = entry_d.get("url")
        if isinstance(url, str) and url:
            return url
    return ""


def _license_info_from_version_object(
    dep: Dependency,
    pinned: str,
    version_object: dict[str, Any] | None,
    *,
    system: str = "",
) -> LicenseInfo:
    """Build a ``LicenseInfo`` from a deps.dev ``version`` object.

    Same shape returned by:
    * the stable v3 single-version GET (top-level response)
    * the batch v3alpha response, inside each ``responses[i].version``

    ``system`` is the deps.dev system token (``PYPI`` / ``NPM`` / ``CARGO`` /
    ``GO`` / ``MAVEN`` / ``NUGET`` / ``RUBYGEMS``). Passed through to
    :func:`_licenses_to_spdx` so multi-element ``licenses`` arrays use the
    correct join semantics per publisher convention (OR for RubyGems'
    disjunctive gemspec convention; AND elsewhere as the conservative
    default).

    When the version object is missing or has no ``licenses``, returns an
    UNKNOWN result. ``from_registry=True`` is preserved on a real response
    with no detectable license (distinguishes "registry confirmed empty"
    from "network failure / not found").
    """
    if version_object is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )

    raw_license = _licenses_to_spdx(version_object.get("licenses"), system=system)
    normalized = normalize_license(raw_license)
    repo_url = _repo_url_from_links(version_object.get("links"))

    # ``versionKey.version`` echoes the version we asked for; prefer it over
    # the pinned input so re-encoded round-trips (e.g. ``+incompatible``) are
    # reflected accurately in the report.
    response_version = pinned
    version_key = version_object.get("versionKey")
    if isinstance(version_key, dict):
        candidate = version_key.get("version")
        if isinstance(candidate, str) and candidate:
            response_version = candidate

    return LicenseInfo(
        dependency=dep,
        license_id=normalized,
        license_raw=raw_license,
        repository_url=repo_url,
        resolved_version=response_version,
        from_registry=True,
    )


def resolve_go_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Single-version fallback for Go license resolution.

    Used when the batch POST itself failed (network / 5xx) and the bulk
    cache is empty for this dep. Hits ``api.deps.dev``'s stable v3
    single-version endpoint, which returns the same ``version``-object
    shape as the per-item batch response.

    ``fetcher`` defaults to a direct HTTP fetch; the CLI passes a
    ``RegistryCache.fetch`` so a repeated single-version lookup serves
    from memory.
    """
    pinned = _extract_pinned_version(dep.version_constraint)
    if pinned is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )
    return resolve_via_deps_dev_stable_get(
        dep,
        pinned,
        system="GO",
        client=client,
        fetcher=fetcher,
    )


def resolve_via_deps_dev_stable_get(
    dep: Dependency,
    pinned_version: str,
    *,
    system: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> LicenseInfo:
    """Hit ``api.deps.dev``'s stable v3 single-version GET for any system.

    Generic resilience-fallback / single-version helper used by:

    * :func:`resolve_go_license` — Go's primary single-version fallback
      when the batch POST fails (Go has no manifest license field, so
      deps.dev is the canonical source).
    * :func:`resolvers.pypi._fallback_to_deps_dev`,
      :func:`resolvers.npm_registry._fallback_to_deps_dev`,
      :func:`resolvers.crates_io._fallback_to_deps_dev` — final-tier
      resilience fallback when PyPI / npm registry / crates.io fetches
      have already exhausted their HTTP-retry budget. Independent
      infrastructure (deps.dev on Google API gateway vs the official
      registries) means correlated outages are unlikely.
    * :func:`resolvers.nuget._resolve_via_deps_dev` — NuGet's final tier
      after the flatcontainer ``.nuspec`` fetch fails to yield a
      usable license.

    URL-encodes ``dep.name`` and ``pinned_version`` because
    package names can contain ``/`` (Go module paths) and versions can
    contain ``+`` (Go ``+incompatible``, Python local-version segments).
    Returns an UNKNOWN ``LicenseInfo`` with ``from_registry=False`` when
    deps.dev itself returns no data — caller surfaces that as
    "no canonical source had license info."
    """
    encoded_name = urllib.parse.quote(dep.name, safe="")
    encoded_version = urllib.parse.quote(pinned_version, safe="")
    url = (
        f"https://api.deps.dev/v3/systems/{system}/packages/"
        f"{encoded_name}/versions/{encoded_version}"
    )
    data = fetcher(url, client)
    if data is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            resolved_version=pinned_version,
            from_registry=False,
        )
    return _license_info_from_version_object(dep, pinned_version, data, system=system)


def _build_batch_chunks(
    deps: list[Dependency],
    *,
    version_extractor: Callable[[str], str | None],
    chunk_size: int,
) -> list[list[tuple[Dependency, str]]]:
    """Pin, dedup, and chunk one system's deps for the batch endpoint.

    Deps whose constraint can't be pinned by ``version_extractor`` are
    dropped (they flow through the per-package resolver instead). Dedup is
    by ``(name, version)`` — the same package can appear multiple times in
    the flattened dep list; one batch entry suffices, and the resolver-side
    cache lookup re-binds the result to each dep instance.
    """
    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[Dependency, str]] = []
    for dep in deps:
        pinned = version_extractor(dep.version_constraint)
        if pinned is None:
            continue
        key = (dep.name, pinned)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((dep, pinned))
    return [deduped[i : i + chunk_size] for i in range(0, len(deduped), chunk_size)]


def _fetch_batch_chunk(
    chunk: list[tuple[Dependency, str]],
    client: httpx.Client,
    *,
    system: str,
) -> dict[tuple[str, str], LicenseInfo | None]:
    """POST one chunk to the batch endpoint; index results by ``(name, version)``.

    Returns an empty dict on whole-chunk failure (keys stay absent so each
    dep falls back to the single-version GET path; the outer merge stays a
    simple ``dict.update``). Responses are indexed by each entry's
    ``request.versionKey`` echo so any server-side reordering is tolerated.
    If ``request`` is missing the entry is dropped; if ``version`` (the
    response data object) is missing, the ``(name, version)`` is recorded
    as ``None`` (confirmed-not-found).
    """
    body = {
        "requests": [
            {
                "versionKey": {
                    "system": system,
                    "name": dep.name,
                    "version": pinned,
                }
            }
            for dep, pinned in chunk
        ]
    }
    out: dict[tuple[str, str], LicenseInfo | None] = {}
    data = fetch_registry_json_post(_DEPS_DEV_BATCH_URL, body, client)
    if data is None:
        return out

    responses = data.get("responses", [])
    if not isinstance(responses, list):
        return out
    for resp in responses:
        if not isinstance(resp, dict):
            continue
        req = resp.get("request")
        if not isinstance(req, dict):
            continue
        version_key = req.get("versionKey")
        if not isinstance(version_key, dict):
            continue
        name = version_key.get("name")
        ver = version_key.get("version")
        if not isinstance(name, str) or not isinstance(ver, str):
            continue
        key = (name, ver)
        version_obj = resp.get("version")
        if isinstance(version_obj, dict):
            # Re-bind through the chunk's source Dependency — the
            # LicenseInfo is rebound again at the call site via
            # ``replace(info, dependency=dep)``.
            sentinel = next(
                (dep for dep, pinned in chunk if dep.name == name and pinned == ver),
                None,
            )
            if sentinel is None:
                continue
            out[key] = _license_info_from_version_object(sentinel, ver, version_obj, system=system)
        else:
            out[key] = None
    return out


def _version_extractor_for(system: str) -> Callable[[str], str | None]:
    """Return the per-system version normalizer for batch requests.

    Imports are deferred because several resolver modules import from this
    module (URL constants, ``_license_info_from_version_object``); importing
    them at module top would be circular. Per-system pinning notes:

    * ``GO`` — versions are always pinned; plausible semver passes through.
    * ``MAVEN`` — ``group:artifact`` is already the deps.dev ``name`` form,
      so only the ``version_constraint`` side needs normalizing. The per-dep
      ``resolve_maven_central_license`` path remains canonical for artifacts
      whose license lives in a parent POM that deps.dev's ``licensecheck``
      over the artifact's own LICENSE file doesn't see.
    * ``CARGO`` — only ``=X.Y.Z`` / ``==X.Y.Z`` exact pins batch; range
      specs need crates.io's max-stable-version lookup and flow through
      ``resolve_rust_license``'s per-crate path.
    * ``NPM`` — package-alias unwrapping (``"npm:<target>@<spec>"``) happens
      at discovery, so ``dep.name`` is already the target package.
    * ``RUBYGEMS`` — lockfiles emit ``==X.Y.Z`` pins for every spec;
      manifest-only range specs return ``None`` and flow through
      ``resolve_ruby_license`` against the v1 latest-version endpoint.
    """
    if system == "GO":
        return _extract_pinned_version
    if system == "MAVEN":
        return _extract_maven_pinned_version
    if system == "NUGET":
        from licenseal.resolvers.nuget import _extract_pinned_version_nuget

        return _extract_pinned_version_nuget
    if system == "PYPI":
        from licenseal.resolvers.pypi import _extract_pinned_version as _extract_pypi_pin

        return _extract_pypi_pin
    if system == "NPM":
        from licenseal.resolvers.npm_registry import _extract_pinned_version as _extract_npm_pin

        return _extract_npm_pin
    if system == "CARGO":
        from licenseal.resolvers.crates_io import _extract_pinned_version as _extract_cargo_pin

        return _extract_cargo_pin
    if system == "RUBYGEMS":
        from licenseal.resolvers.rubygems import _extract_pinned_version as _extract_ruby_pin

        return _extract_ruby_pin
    raise ValueError(f"unknown deps.dev system: {system}")


def bulk_resolve_licenses(
    deps_by_system: Mapping[str, list[Dependency]],
    client: httpx.Client,
    *,
    chunk_size: int = _BATCH_CHUNK_SIZE,
    max_workers: int,
) -> dict[str, dict[tuple[str, str], LicenseInfo | None]]:
    """Pre-resolve licenses for every batched ecosystem in one shared fan-out.

    ``deps_by_system`` maps deps.dev system identifiers (``"GO"``,
    ``"PYPI"``, ``"NPM"``, ``"CARGO"``, ``"MAVEN"``, ``"NUGET"``,
    ``"RUBYGEMS"``) to that ecosystem's dep list. Returns one
    ``(name, version) -> LicenseInfo | None`` cache per input system:

    * **present, ``LicenseInfo``** — batch returned a real result. Caller
      uses it directly.
    * **present, ``None``** — batch confirmed the version doesn't exist
      (response had ``request`` but no ``version`` field). Caller skips
      further fetches and emits UNKNOWN (Go) or falls back (the rest).
    * **absent** — the chunk's POST failed, or the dep's version couldn't
      be pinned by the system's extractor. Caller falls through to the
      per-package official-registry path.

    Every system's chunks fan out through ONE threadpool
    ``min(chunks, max_workers, _BATCH_MAX_WORKERS)`` wide, so a polyglot
    scan overlaps its per-ecosystem batch POSTs instead of paying one
    sequential pool round per ecosystem — while the combined in-flight
    POST count against this rate-limit-sensitive endpoint keeps the same
    ceiling a single-ecosystem scan has. ``--max-workers`` still throttles
    downward; the cap only bounds the ceiling.
    """
    tagged_chunks: list[tuple[str, list[tuple[Dependency, str]]]] = []
    for system, deps in deps_by_system.items():
        extractor = _version_extractor_for(system)
        for chunk in _build_batch_chunks(deps, version_extractor=extractor, chunk_size=chunk_size):
            tagged_chunks.append((system, chunk))

    caches: dict[str, dict[tuple[str, str], LicenseInfo | None]] = {
        system: {} for system in deps_by_system
    }
    if not tagged_chunks:
        return caches
    if len(tagged_chunks) == 1:
        # Single chunk — fetch inline rather than paying pool setup.
        system, chunk = tagged_chunks[0]
        caches[system].update(_fetch_batch_chunk(chunk, client, system=system))
        return caches

    def _fetch_one(
        tagged: tuple[str, list[tuple[Dependency, str]]],
    ) -> tuple[str, dict[tuple[str, str], LicenseInfo | None]]:
        system, chunk = tagged
        return system, _fetch_batch_chunk(chunk, client, system=system)

    # Propagate the active tethered scope into the batch-POST workers — a
    # bare pool fetches in an empty context and bypasses the egress policy.
    for system, chunk_result in map_with_context(
        _fetch_one, tagged_chunks, min(max_workers, _BATCH_MAX_WORKERS)
    ):
        caches[system].update(chunk_result)
    return caches


def _extract_maven_pinned_version(version_constraint: str) -> str | None:
    """Return a concrete Maven version when the constraint is a single pin.

    Maven coordinates that the discovery layer surfaces are typically the
    POM ``<version>`` text. Lockfile-style pin (``[1.2.3]`` Maven-strict
    notation, ``==1.2.3`` licenseal-internal) and bare ``1.2.3`` are
    accepted; everything else (open ranges ``[1.0,)``, version-set
    expressions, property substitutions like ``${spring.version}``) is
    rejected so the per-package POM walker handles it.
    """
    spec = version_constraint.strip()
    if not spec:
        return None
    if spec.startswith("=="):
        spec = spec[2:].strip()
    if spec.startswith("[") and spec.endswith("]") and "," not in spec:
        spec = spec[1:-1].strip()
    if not spec or "," in spec or "$" in spec or " " in spec:
        return None
    if spec[0] in "([":
        return None
    return spec


def _fetch_deps_dev_dependencies(
    url: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str, str]]]:
    """Generic ``GetDependencies`` response parser.

    Used by :func:`fetch_maven_dependencies`. NuGet GetDependencies is
    NOT supported by deps.dev (docs explicitly list only npm / Cargo /
    Maven / PyPI; the NUGET URL returns 404). NuGet transitive
    resolution uses the nuspec-based walker in ``resolvers.nuget``
    instead.
    """
    data = fetcher(url, client)
    if data is None:
        return ([], [])
    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, list):
        return ([], [])

    # First pass: build the node table. Index 0 is always the SELF root
    # by deps.dev convention; we keep it in the indexed lookup so edge
    # ``fromNode``/``toNode`` references resolve correctly, but we don't
    # emit it as a dep (the caller already has the direct dep object).
    node_table: list[tuple[str, str] | None] = []
    nodes_out: list[tuple[str, str]] = []
    for raw_node in raw_nodes:
        if not isinstance(raw_node, dict):
            node_table.append(None)
            continue
        relation = raw_node.get("relation")
        version_key = raw_node.get("versionKey")
        if not isinstance(version_key, dict):
            node_table.append(None)
            continue
        node_name = version_key.get("name")
        node_version = version_key.get("version")
        if not isinstance(node_name, str) or not isinstance(node_version, str):
            node_table.append(None)
            continue
        node_table.append((node_name, node_version))
        if relation == "SELF":
            continue
        nodes_out.append((node_name, node_version))

    raw_edges = data.get("edges")
    edges_out: list[tuple[str, str, str, str]] = []
    if isinstance(raw_edges, list):
        for raw_edge in raw_edges:
            if not isinstance(raw_edge, dict):
                continue
            from_idx = raw_edge.get("fromNode")
            to_idx = raw_edge.get("toNode")
            if not isinstance(from_idx, int) or not isinstance(to_idx, int):
                continue
            if from_idx < 0 or from_idx >= len(node_table):
                continue
            if to_idx < 0 or to_idx >= len(node_table):
                continue
            from_entry = node_table[from_idx]
            to_entry = node_table[to_idx]
            if from_entry is None or to_entry is None:
                continue
            edges_out.append((from_entry[0], from_entry[1], to_entry[0], to_entry[1]))
    return (nodes_out, edges_out)


def fetch_maven_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_json,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str, str]]]:
    """Fetch the resolved Maven dependency subgraph for ``(name, version)``.

    Hits ``api.deps.dev``'s ``GetDependencies`` endpoint with the MAVEN
    system. The response shape::

        {
            "nodes": [
                {"versionKey": {"system":"MAVEN", "name":"g:a", "version":"1.0"},
                 "relation": "SELF"},
                {"versionKey": {"system":"MAVEN", "name":"x:y", "version":"2.0"},
                 "relation": "DIRECT"},
                ...
            ],
            "edges": [
                {"fromNode": 0, "toNode": 1, "requirement": "2.0"},
                ...
            ],
            "error": ""  // populated when the resolver couldn't fully expand
        }

    ``relation`` distinguishes the requested root (``SELF``) from deps it
    pulls in (``DIRECT`` / ``INDIRECT``). We skip the SELF node and emit
    every other node as a ``(coord, version)`` tuple; the edge list is
    re-mapped from node-index to ``(from_coord, from_version, to_coord,
    to_version)`` so the caller can build a name-keyed edge graph for
    reachability attribution.

    Returns ``([], [])`` on any fetch / parse failure — same conservative
    posture as the Go path. The transitive walker treats the empty
    subgraph as "no resolved children", and the direct dep still flows
    through with whatever license info we already have.
    """
    encoded_name = urllib.parse.quote(name, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    url = _DEPS_DEV_MAVEN_DEPS_URL.format(name=encoded_name, version=encoded_version)
    return _fetch_deps_dev_dependencies(url, client, fetcher)
