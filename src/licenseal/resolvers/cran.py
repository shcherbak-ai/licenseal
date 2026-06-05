"""Resolve R package licenses from the official CRAN ``PACKAGES`` index.

CRAN publishes ``cran.r-project.org/src/contrib/PACKAGES`` — a DCF index of
every current source package carrying its ``License`` and dependency edges
(``Depends`` / ``Imports`` / ``LinkingTo`` / ``Suggests`` / ``Enhances``).
licenseal fetches it once per scan (the same index ``install.packages`` / ``pak``
consult), parses it, and resolves every R package's license and transitive
closure locally — no per-package requests and no community mirror.

The index carries only *current* versions. R licenses are version-stable, so a
``renv.lock`` / ``packrat.lock`` pin to an older version resolves to that
package's current license (the pinned version is still what's reported). A
package absent from the index (archived, or off-CRAN such as Bioconductor /
GitHub) resolves to UNKNOWN. R's ``License`` grammar is translated to SPDX by
:func:`~licenseal.analysis.spdx.normalize_r_license`.
"""

from __future__ import annotations

from dataclasses import replace

import httpx

from licenseal.analysis.spdx import normalize_r_license
from licenseal.discovery.r._dcf import parse_dcf, parse_package_list
from licenseal.discovery.r._lock import is_off_registry_marker
from licenseal.discovery.r.description import is_base_package
from licenseal.models import Dependency, LicenseInfo
from licenseal.resolvers.http import Fetcher, fetch_registry_text

_CRAN_INDEX_URL = "https://cran.r-project.org/src/contrib/PACKAGES"

# Runtime / build dependency fields followed transitively. Suggests / Enhances
# (optional / test / vignette) are not followed — matching the npm / Python
# posture of not walking optional deps.
_EDGE_FIELDS = ("Depends", "Imports", "LinkingTo")

# name_lower -> DCF record (field name -> value)
CranIndex = dict[str, "dict[str, str]"]


def fetch_cran_index(
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_text,
) -> CranIndex:
    """Fetch + parse the CRAN ``PACKAGES`` index into a ``name_lower -> record`` map.

    Fetched as text (DCF) through the shared registry cache so the index is
    pulled at most once per scan. Returns an empty map on fetch failure — the
    callers then resolve every R package to UNKNOWN, the safe verdict.
    """
    data = fetcher(_CRAN_INDEX_URL, client)
    if not isinstance(data, dict):
        return {}
    text = data.get("text", "")
    if not isinstance(text, str) or not text:
        return {}
    index: CranIndex = {}
    for record in parse_dcf(text):
        name = record.get("Package", "").strip()
        if name:
            index.setdefault(name.lower(), record)
    return index


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact version when the spec is a ``==X.Y.Z`` pin.

    The renv.lock / packrat.lock parsers emit ``==X.Y.Z`` (R versions may carry
    a hyphen, e.g. ``==1.6-1``); manifest-mode constraints (``>= 1.0``, ``*``)
    are ranges → None.
    """
    spec = version_constraint.strip()
    if not spec or "," in spec:
        return None
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        if not candidate or " " in candidate:
            return None
        return candidate
    return None


def index_edge_names(record: dict[str, str]) -> list[str]:
    """Return the runtime/build dependency names declared by a CRAN record.

    Reads ``Depends`` / ``Imports`` / ``LinkingTo`` (DCF comma-lists with
    optional version constraints); the ``R`` pseudo-package and base-priority
    packages are filtered (not standalone CRAN packages). Order-preserving and
    de-duplicated.
    """
    out: list[str] = []
    seen: set[str] = set()
    for field in _EDGE_FIELDS:
        value = record.get(field)
        if not value:
            continue
        for name, _constraint in parse_package_list(value):
            if is_base_package(name):
                continue
            lowered = name.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            out.append(name)
    return out


def _unknown(dep: Dependency, *, from_registry: bool) -> LicenseInfo:
    return LicenseInfo(
        dependency=dep,
        license_id="UNKNOWN",
        license_raw="",
        from_registry=from_registry,
    )


def resolve_r_license(dep: Dependency, index: CranIndex) -> LicenseInfo:
    """Resolve an R package's license from the parsed CRAN ``PACKAGES`` index.

    Off-registry (GitHub / Bioconductor / Local) deps and packages absent from
    the current index (archived / off-CRAN) resolve to UNKNOWN. The reported
    ``resolved_version`` is the lockfile pin when present, else the index's
    current version. The index carries no repository/homepage URLs, so those
    stay empty for R.
    """
    if is_off_registry_marker(dep.source):
        # Drop the internal marker so it doesn't surface as the report's Source.
        return _unknown(replace(dep, source=""), from_registry=False)
    record = index.get(dep.name.lower())
    if record is None:
        return _unknown(dep, from_registry=False)
    raw = record.get("License", "").strip()
    pinned = _extract_pinned_version(dep.version_constraint)
    return LicenseInfo(
        dependency=dep,
        license_id=normalize_r_license(raw) if raw else "UNKNOWN",
        license_raw=raw,
        resolved_version=pinned or record.get("Version", "").strip(),
        from_registry=True,
    )
