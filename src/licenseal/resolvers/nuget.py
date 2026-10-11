"""Resolve license information for .NET artifacts via NuGet flatcontainer.

NuGet's v3 API exposes raw ``.nuspec`` XML at a predictable URL:

.. code-block:: text

    https://api.nuget.org/v3-flatcontainer/{id-lowercased}/{version}/{id-lowercased}.nuspec

The ``.nuspec`` ``<metadata>`` block carries the author-declared license
in one of two shapes:

* **Modern** — ``<license type="expression">MIT OR Apache-2.0</license>``
  (NuGet 4.10+, 2018). Direct SPDX expression; the canonical form for
  packages published in the last several years.
* **Legacy** — ``<licenseUrl>https://www.apache.org/licenses/LICENSE-2.0</licenseUrl>``
  (pre-2018 packages). The URL itself is treated as a structured field:
  we map known patterns via :func:`analysis.spdx.spdx_from_license_url`
  to recover SPDX where the URL is canonical (Apache, MIT, GPL family,
  Eclipse, Mozilla, BSD variants, etc.). Per the no-prose-extraction
  rule, we never fetch and parse the URL body — only the URL string is
  consulted.

**Two-tier per-dep resolution** (the deps.dev batch is a separate
pre-pass at scan startup; see ``cli.check`` and the Mode-C pattern in
``AGENTS.md``. By the time ``resolve_nuget_license`` is called the
caller has already missed the batch cache):

1. **NuGet flatcontainer ``.nuspec``** — fetch the XML, parse the
   ``<license>`` and ``<licenseUrl>`` elements, return on hit. Modern
   packages declare ``<license type="expression">SPDX</license>``
   directly; legacy packages declare ``<licenseUrl>URL</licenseUrl>``
   (mapped to SPDX when the URL is in the known-patterns table).
2. **deps.dev v3 single-version GET** — per-dep fetch to the stable v3
   endpoint with ``system=NUGET``. Final fallback when the flatcontainer
   nuspec carries neither a usable expression nor a mappable licenseUrl
   (and the batch already returned UNKNOWN, hence the per-package call).

NuGet package IDs are case-insensitive per spec. The flatcontainer URL
requires the lowercase form; the canonical-name code path lowercases
elsewhere too.

XML parsing uses ``defusedxml.ElementTree`` to block billion-laughs and
external-entity attacks — necessary because the registry response, like
the on-disk ``.csproj``, is untrusted input.
"""

from __future__ import annotations

import json
from typing import cast
from xml.etree.ElementTree import Element  # nosec B405

import httpx

from licenseal.analysis.spdx import (
    all_apply_reading,
    normalize_license,
    spdx_from_license_url,
)
from licenseal.models import Dependency, Ecosystem, LicenseInfo
from licenseal.resolvers.deps_dev import (
    _DEPS_DEV_NUGET_VERSION_URL,
    _license_info_from_version_object,
)
from licenseal.resolvers.http import (
    Fetcher,
    fetch_registry_json,
    fetch_registry_text,
    quote_coordinate,
)
from licenseal.resolvers.version_selection import parse_nuget_range, select_version

# Key of a package name in the name sets and graphs below (see
# ``Ecosystem.identity``).
_key = Ecosystem.DOTNET.identity

_NUGET_FLATCONTAINER_URL = "https://api.nuget.org/v3-flatcontainer/{name}/{version}/{name}.nuspec"
# The flatcontainer's list of a package's published versions.
_NUGET_INDEX_URL = "https://api.nuget.org/v3-flatcontainer/{name}/index.json"


def _extract_pinned_version_nuget(version_constraint: str) -> str | None:
    """Return the version a NuGet version string names without a registry lookup.

    NuGet restores the lowest version a requirement allows, so an inclusive
    lower bound is the version it restores when that version is published:

    * Bare ``MAJOR.MINOR.PATCH[-prerelease]`` (a minimum) — that version.
    * 4-part legacy ``MAJOR.MINOR.PATCH.REVISION`` — that version.
    * NuGet bracket syntax ``[1.2.3]`` (exact) — strip brackets.
    * A range with an inclusive lower bound, ``[1.0,2.0)`` or ``[1.0,)`` —
      the lower bound.
    * licenseal-internal ``==X.Y.Z`` form — strip the ``==``.

    The version is returned in NuGet's normalized spelling, the one nuget.org
    lists and serves it under: ``1.2`` and ``1.2.0.0`` are ``1.2.0``, leading
    zeros and build metadata are dropped. The flatcontainer answers 404 for
    any other spelling of a version it has.

    Returns ``None`` when no version can be named this way: a range whose
    lower bound is exclusive or absent (``(1.0,2.0]``, ``(,2.0]``) or lies
    outside the range, a floating version (``*``, ``1.*``), an unresolved
    ``$(…)`` MSBuild property token, or anything that is not a NuGet version
    range. :func:`_resolve_version` resolves the first two against the
    registry.
    """
    parsed = parse_nuget_range(version_constraint)
    return (parsed.minimum or None) if parsed is not None else None


def _declares_exact_version_nuget(version_constraint: str) -> bool:
    """Whether the constraint names one version rather than bounding a range.

    A bare version and the ``[1.2.3]`` form each name the version NuGet
    restores. A bracket range does not, even though
    :func:`_extract_pinned_version_nuget` picks a version for it.
    """
    parsed = parse_nuget_range(version_constraint)
    return parsed is not None and parsed.exact


def _published_versions(package_id: str, client: httpx.Client, fetcher: Fetcher) -> list[str]:
    """The versions the flatcontainer lists for a package; empty when it lists none.

    ``fetcher`` is the text fetcher the ``.nuspec`` reads use, so the JSON
    index is parsed here.
    """
    url = _NUGET_INDEX_URL.format(name=quote_coordinate(package_id.lower(), safe=""))
    data = fetcher(url, client)
    text = data.get("text") if data is not None else None
    if not isinstance(text, str):
        return []
    try:
        index = json.loads(text)
    except (ValueError, RecursionError):
        return []
    versions = index.get("versions") if isinstance(index, dict) else None
    if not isinstance(versions, list):
        return []
    return [version for version in versions if isinstance(version, str)]


def _resolve_version(
    package_id: str, version_constraint: str, client: httpx.Client, fetcher: Fetcher
) -> str | None:
    """Resolve a declared NuGet version to the version to report, or None.

    A requirement with an inclusive lower bound (a bare version, ``[1.2.3]``,
    ``[1.0,2.0)``) resolves to that bound without a request, in the spelling
    nuget.org serves it under (``1.0.0`` for ``1.0``). Any other range
    is resolved against the package's published versions, one request: the
    lowest release inside an interval (``(1.0,2.0]``), the highest release a
    floating version matches (``1.*``).

    A string that is not a NuGet version range, and a range no published
    version satisfies, resolve to nothing; never to a bound the range
    excludes. The transitive walk and the license resolver both resolve
    through here.
    """
    parsed = parse_nuget_range(version_constraint)
    if parsed is None:
        return None
    if parsed.minimum:
        return parsed.minimum
    published = _published_versions(package_id, client, fetcher)
    return select_version(
        Ecosystem.DOTNET, version_constraint, published, lowest=not parsed.floating
    )


def _nuspec_url(package_id: str, version: str) -> str:
    """Build the canonical NuGet flatcontainer ``.nuspec`` URL.

    Per the NuGet spec, both the package ID and version segments in the
    flatcontainer URL must be lowercased (the underlying storage is
    case-folded). URL-encode each component as a defense against
    pathological IDs without changing well-formed ones.
    """
    lowered_id = package_id.lower()
    encoded_id = quote_coordinate(lowered_id, safe="")
    encoded_version = quote_coordinate(version.lower(), safe="")
    return _NUGET_FLATCONTAINER_URL.format(name=encoded_id, version=encoded_version)


def _local(tag: str) -> str:
    """Strip any XML namespace prefix from ``tag``."""
    return tag.rsplit("}", 1)[-1]


def _find_metadata(root: Element) -> Element | None:
    """Return the ``<metadata>`` child of a ``<package>`` root, or ``None``."""
    for child in root:
        if _local(child.tag) == "metadata":
            return child
    return None


def _dependencies_from_nuspec(text: str) -> tuple[list[tuple[str, str]], bool]:
    """Parse the ``<dependencies>`` block of a ``.nuspec``.

    Modern nuspec wraps deps per target framework::

        <dependencies>
          <group targetFramework="net8.0">
            <dependency id="X" version="1.2.3" />
          </group>
          <group targetFramework="netstandard2.0">
            <dependency id="X" version="1.2.0" />
          </group>
        </dependencies>

    Older nuspec uses a flat list of ``<dependency>`` children directly
    under ``<dependencies>`` (no per-TFM grouping).

    Following the same convention as the NuGet lockfile parsers
    (``discovery/dotnet``: union across TFMs), we collect every
    ``(id, version)`` pair from every group and dedupe — the rationale is
    that a metadata-only scan can't tell which TFM the user actually
    targets, so the conservative posture is to surface every dep that
    might be reachable in any build configuration.

    Each dependency is returned with its ``version`` attribute as declared
    (a minimum, a bracket range, a floating version), or with an empty
    string when it has none; :func:`_resolve_version` turns that into the
    version to walk.

    Returns ``(dependencies, complete)``. ``complete`` is False when the
    list could not be read in full: malformed XML, no ``<metadata>``, or a
    ``<dependency>`` without an ``id``. A nuspec with no ``<dependencies>``
    block declares none.
    """
    try:
        from defusedxml import ElementTree as DefusedET

        root = DefusedET.fromstring(text)
    except Exception:  # noqa: BLE001 - defusedxml raises many entity classes
        return [], False
    metadata = _find_metadata(root)
    if metadata is None:
        return [], False

    complete = True
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []

    def _emit_dependency(elem: Element) -> bool:
        package_id = (elem.get("id") or "").strip()
        if not package_id:
            return False
        # NuGet IDs are case-insensitive — normalize for dedup but keep
        # the publisher's casing in the emitted name (consistent with
        # the rest of the .NET path; the flatcontainer URL lowercases
        # at fetch time).
        declared = (elem.get("version") or "").strip()
        key = (_key(package_id), declared)
        if key not in seen:
            seen.add(key)
            out.append((package_id, declared))
        return True

    for child in metadata:
        if _local(child.tag) != "dependencies":
            continue
        for entry in child:
            tag = _local(entry.tag)
            if tag == "dependency":
                complete = _emit_dependency(entry) and complete
            elif tag == "group":
                for inner in entry:
                    if _local(inner.tag) == "dependency":
                        complete = _emit_dependency(inner) and complete
    return out, complete


def _license_from_nuspec(text: str) -> tuple[str, str]:
    """Parse a ``.nuspec`` XML body, returning ``(expression, license_url)``.

    ``expression`` is the text of ``<license type="expression">…</license>``
    when present (modern packages); the empty string otherwise. The
    ``type`` attribute can also be ``"file"`` (the license lives in a
    file inside the package — we don't fetch artifact bodies per the
    no-artifact-downloads rule, so this returns empty), in which case
    we fall through to the URL path.

    ``license_url`` is the text of ``<licenseUrl>…</licenseUrl>`` when
    present (legacy packages); empty otherwise. Many modern packages
    still carry a redirect-to-nuget.org ``<licenseUrl>`` for backwards
    compatibility — those URLs deliberately route to a generic
    deprecation page and won't map.

    Returns ``("", "")`` for malformed XML / empty body / billion-laughs.
    """
    try:
        from defusedxml import ElementTree as DefusedET

        root = DefusedET.fromstring(text)
    except Exception:  # noqa: BLE001 - defusedxml raises many entity classes
        return ("", "")
    metadata = _find_metadata(root)
    if metadata is None:
        return ("", "")
    expression = ""
    license_url = ""
    for child in metadata:
        tag = _local(child.tag)
        if tag == "license":
            license_type = (child.get("type") or "").strip().lower()
            content = (child.text or "").strip()
            if license_type == "expression" and content:
                expression = content
        elif tag == "licenseUrl":
            url = (child.text or "").strip()
            if url:
                license_url = url
    return (expression, license_url)


def _fetch_nuspec(
    package_id: str,
    version: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> str:
    """Fetch the raw ``.nuspec`` XML for ``(package_id, version)``.

    Returns the empty string on any HTTP/network/parse failure — the
    caller routes to the deps.dev fallback. Per-scan URL-cache dedup
    handled by the ``fetcher`` parameter (typically
    ``RegistryCache.fetch_text``).
    """
    url = _nuspec_url(package_id, version)
    data = fetcher(url, client)
    if data is None:
        return ""
    text = data.get("text", "")
    if not isinstance(text, str):
        return ""
    return text


def _resolve_via_deps_dev(
    dep: Dependency,
    version: str,
    client: httpx.Client,
    fetcher: Fetcher,
) -> LicenseInfo:
    """Per-dep deps.dev v3 single-version GET (final fallback).

    Reached only when the deps.dev batch pre-pass returned no usable
    license AND the ``.nuspec`` flatcontainer fetch provides neither
    ``<license type="expression">`` nor a mappable ``<licenseUrl>``.
    Same parse path as the Go and Maven deps.dev fallbacks —
    :func:`_license_info_from_version_object` normalizes the response
    into an SPDX-shaped :class:`LicenseInfo`.
    """
    encoded_name = quote_coordinate(dep.name, safe="")
    encoded_version = quote_coordinate(version, safe="")
    url = _DEPS_DEV_NUGET_VERSION_URL.format(name=encoded_name, version=encoded_version)
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


def resolve_nuget_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_text,
    json_fetcher: Fetcher = fetch_registry_json,
) -> LicenseInfo:
    """Resolve license for a .NET artifact via the two-tier per-dep path.

    Called by ``cli.check`` only after the deps.dev batch pre-pass
    returned no usable license for this ``(name, version)`` (advisory
    cache-miss). The Mode-C pattern hoists the batch cache check into
    the CLI orchestrator; this resolver covers the per-package fallback.

    1. **Tier 1**: fetch ``.nuspec`` from ``api.nuget.org`` flatcontainer
       and parse ``<license type="expression">`` / ``<licenseUrl>``.
       Modern packages carry the SPDX expression directly; legacy
       packages carry a URL that maps via ``spdx_from_license_url``'s
       known-patterns table.
    2. **Tier 2**: per-dep deps.dev v3 single-version GET. Final
       fallback when the flatcontainer fetch yields no usable license
       (typical for ancient packages with only a deprecated nuget.org
       redirect ``licenseUrl``).

    ``fetcher`` is the text-mode fetcher for ``.nuspec`` XML and for the
    package's version list. ``json_fetcher`` is the JSON fetcher for the
    deps.dev v3 endpoint.

    The declared version is resolved first (:func:`_resolve_version`); a
    range no published version satisfies is UNKNOWN with no version.
    """
    pinned = _resolve_version(dep.name, dep.version_constraint, client, fetcher)
    if pinned is None:
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )

    # Tier 1: NuGet flatcontainer.
    nuspec_text = _fetch_nuspec(dep.name, pinned, client, fetcher)
    if nuspec_text:
        expression, license_url = _license_from_nuspec(nuspec_text)
        if expression:
            normalized = normalize_license(expression)
            if normalized and normalized != "UNKNOWN":
                return LicenseInfo(
                    dependency=dep,
                    license_id=normalized,
                    license_raw=expression,
                    resolved_version=pinned,
                    from_registry=True,
                    # A license expression has no ``,`` or ``/`` operator.
                    all_apply_license_id=all_apply_reading(expression),
                )
        if license_url:
            # A non-empty return is always a usable license ID. It goes
            # through ``normalize_license`` like every other resolved
            # license, so this path cannot hand the compatibility layer a
            # spelling the rest of the pipeline would have rewritten.
            mapped = spdx_from_license_url(license_url)
            if mapped:
                return LicenseInfo(
                    dependency=dep,
                    license_id=normalize_license(mapped),
                    license_raw=license_url,
                    resolved_version=pinned,
                    from_registry=True,
                )

    # Tier 2: per-dep deps.dev v3 single-version GET.
    return _resolve_via_deps_dev(dep, pinned, client, json_fetcher)


# Cap on recursion depth for the nuspec walker. .NET dep graphs rarely
# go this deep in practice; the cap is defensive against cycles that
# slipped past the visited-set (shouldn't happen, but cheap to enforce).
# A package at the cap is reported, and its own dependencies as unread.
_NUSPEC_WALK_MAX_DEPTH = 32


def fetch_nuget_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_text,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str, str]], list[tuple[str, str]]]:
    """Walk a NuGet dep subgraph by recursively reading ``.nuspec`` files.

    Replaces the previous deps.dev ``GetDependencies`` call: deps.dev's
    docs and probing both confirm the endpoint is only available for
    npm / Cargo / Maven / PyPI — the NuGet URL returns 404. This walker
    reads each ``.nuspec``'s ``<dependencies>`` block instead, unioning
    across TFM ``<group>``s (same conservative posture as the .NET
    lockfile parsers).

    Returns the same ``(nodes, edges, unread)`` shape as the Maven walker,
    where each node is ``(package_id, pinned_version)`` and each edge is
    ``(from_id, from_version, to_id, to_version)``. The SELF root is NOT
    emitted as a node (the caller already has the direct dep object) but
    is implicit as the source of the first-level edges. A dependency whose
    declared version resolves to nothing (:func:`_resolve_version`) is a
    node with an empty version.

    ``unread`` lists the packages of the subgraph, the root included, whose
    own dependencies could not be read: the ``.nuspec`` could not be
    fetched or parsed in full, the package has no version to fetch one for,
    or it sits at :data:`_NUSPEC_WALK_MAX_DEPTH`. The rest of the subgraph
    is still returned: an unread package trims its own branch only.

    No conflict resolution: when a transitive appears under multiple
    requested versions through different paths, ALL are emitted. The
    Mode-C license pipeline runs per ``(name, version)`` so this matches
    the licenseal posture (lockfile-equivalent enumeration, not
    runtime resolution).
    """
    visited: set[tuple[str, str]] = set()
    nodes: list[tuple[str, str]] = []
    edges: list[tuple[str, str, str, str]] = []
    unread: list[tuple[str, str]] = []

    def _walk(parent_name: str, parent_version: str, depth: int) -> None:
        if not parent_version or depth >= _NUSPEC_WALK_MAX_DEPTH:
            unread.append((parent_name, parent_version))
            return
        text = _fetch_nuspec(parent_name, parent_version, client, fetcher)
        children, complete = _dependencies_from_nuspec(text) if text else ([], False)
        if not complete:
            unread.append((parent_name, parent_version))
        for child_name, declared in children:
            # A version that cannot be resolved leaves the child a node
            # without one: reported, and unread in its turn.
            child_version = _resolve_version(child_name, declared, client, fetcher) or ""
            edges.append((parent_name, parent_version, child_name, child_version))
            key = (_key(child_name), child_version)
            if key in visited:
                continue
            visited.add(key)
            nodes.append((child_name, child_version))
            _walk(child_name, child_version, depth + 1)

    # The SELF root itself isn't emitted as a node (caller already has
    # the direct dep), but its key is marked visited so a self-cycle
    # (rare but legal) doesn't recurse forever.
    visited.add((_key(name), version))
    _walk(name, version, 0)
    return (nodes, edges, unread)
