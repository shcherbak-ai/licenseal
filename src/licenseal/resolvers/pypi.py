"""Resolve license information from PyPI."""

from __future__ import annotations

import re
from collections.abc import Callable

import httpx
from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement

from licenseal.analysis.spdx import normalize_license
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.deps_dev import resolve_via_deps_dev_stable_get
from licenseal.resolvers.http import Fetcher, fetch_pep658_metadata, fetch_registry_json
from licenseal.resolvers.version_selection import select_python_version

_PYPI_URL = "https://pypi.org/pypi"
# Legacy ``License:`` field values: short single-line forms ("MIT", "MIT License",
# "Apache 2.0") are SPDX-normalizable; long values are usually a full license
# text body and route to UNKNOWN per the no-prose-extraction rule. 60 chars is
# the empirical break point between the two on the PyPI corpus.
_LEGACY_LICENSE_MAX_LEN = 60

# Trove classifier prefix for license
_LICENSE_CLASSIFIER_PREFIX = "License :: OSI Approved :: "

# Patterns that indicate the license field contains junk, not a license ID
_JUNK_INDICATORS = ("copyright", "\n", "all rights reserved", "permission is hereby")
_PINNED_VERSION_RE = re.compile(
    r"^(?:={2,3}\s*)?(v?(?:\d+[A-Za-z0-9.+!_-]*)(?:\.\d+[A-Za-z0-9.+!_-]*)*)$"
)
_PROJECT_URL_KEYS = (
    "source",
    "sources",
    "source code",
    "repository",
    "homepage",
    "code",
    "github",
    "gitlab",
    "bitbucket",
)


def _is_junk_license(value: str) -> bool:
    """Check if a license field contains copyright text or other non-license junk."""
    lower = value.strip().lower()
    return any(indicator in lower for indicator in _JUNK_INDICATORS)


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact requested version when the constraint is pinned."""
    spec = version_constraint.strip()
    if not spec or "," in spec or ";" in spec or " " in spec:
        return None
    if spec[0] in "^~<>!*":
        return None
    match = _PINNED_VERSION_RE.fullmatch(spec)
    if not match:
        return None
    return match.group(1).lstrip("v")


def _normalize_repository_url(url: str) -> str:
    """Normalize repository URLs into browser-friendly HTTPS links."""
    normalized = url.strip()
    if not normalized:
        return ""
    if normalized.startswith("git+"):
        normalized = normalized[4:]
    if normalized.startswith("git://"):
        normalized = "https://" + normalized[6:]
    if "#" in normalized:
        normalized = normalized.split("#", 1)[0]
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def _extract_repository_url(info: dict) -> str:
    """Best-effort extraction of the package repository URL from PyPI metadata."""
    project_urls = info.get("project_urls", {})
    if isinstance(project_urls, dict):
        lowered = {
            str(key).strip().lower(): str(value).strip()
            for key, value in project_urls.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        for key in _PROJECT_URL_KEYS:
            url = lowered.get(key, "")
            if url:
                return _normalize_repository_url(url)

    home_page = info.get("home_page", "")
    if isinstance(home_page, str) and any(
        host in home_page for host in ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
    ):
        return _normalize_repository_url(home_page)

    return ""


def _extract_homepage_url(info: dict) -> str:
    """Best-effort extraction of the package homepage URL from PyPI metadata.

    Separate from ``_extract_repository_url`` so consumers can distinguish a
    package-author-supplied homepage (untrusted, may point anywhere) from a
    structured VCS URL declared in ``project_urls``. The legacy ``home_page``
    field and a ``project_urls.homepage`` entry both feed this — first
    non-empty wins.
    """
    home_page = info.get("home_page", "")
    if isinstance(home_page, str) and home_page.strip():
        return _normalize_repository_url(home_page)

    project_urls = info.get("project_urls", {})
    if isinstance(project_urls, dict):
        for key, value in project_urls.items():
            if (
                isinstance(key, str)
                and isinstance(value, str)
                and key.strip().lower() == "homepage"
                and value.strip()
            ):
                return _normalize_repository_url(value)

    return ""


def _extract_raw_license(info: dict) -> str:
    """Pull a license string out of a PyPI info dict, preferring PEP 639.

    Falls back to classifiers whenever the chosen field doesn't normalize to
    a known SPDX identifier — covers vague markers like ``Dual License`` that
    publish meaningful info only in the trove classifiers.

    Does *not* attempt to extract a license name from free-form license-text
    bodies: that's a soft signal that can be spoofed ("Apache 2.0 license
    DOES NOT APPLY. Commercial license takes precedence."), and license
    extraction can only safely move classification toward more scrutiny,
    never less. Bodies that don't surface a structured license identifier
    fall through to UNKNOWN and route to manual review.
    """
    if not isinstance(info, dict):
        return ""

    raw = info.get("license_expression", "") or ""
    if raw and normalize_license(raw) != "UNKNOWN":
        return raw

    legacy = info.get("license", "") or ""
    # When ``legacy`` is itself just a file pointer (``"LICENSE"``,
    # ``"LICENSE.txt"``, ``"SEE LICENSE IN ..."``), it carries no SPDX info
    # — only a hint to manual review. Prefer a concrete classifier here so
    # ``info.license = "License"`` + classifier ``"License :: OSI Approved
    # :: MIT License"`` returns MIT, not Proprietary-by-file-pointer.
    if legacy and not _is_junk_license(legacy):
        normalized = normalize_license(legacy)
        if normalized not in ("UNKNOWN", "Proprietary"):
            return legacy

    for classifier in info.get("classifiers", []) or []:
        if isinstance(classifier, str) and classifier.startswith(_LICENSE_CLASSIFIER_PREFIX):
            return classifier

    # No classifier rescued us — return legacy even if it's a file pointer
    # (still surfaces as Proprietary on the next normalize_license call,
    # routing to manual review).
    return raw or (legacy if legacy and not _is_junk_license(legacy) else "")


def _extract_wheel_url(data: dict) -> str:
    """Return the bdist_wheel URL from a PyPI per-version JSON response.

    The cached path (``RegistryCache.fetch``) flattens this into a top-level
    ``wheel_url`` string via ``_trim_pypi``; the uncached path leaves the
    raw ``urls`` list. Handle both shapes.
    """
    flattened = data.get("wheel_url", "")
    if isinstance(flattened, str) and flattened:
        return flattened
    urls = data.get("urls", [])
    if not isinstance(urls, list):
        return ""
    for entry in urls:
        if not isinstance(entry, dict):
            continue
        if entry.get("packagetype") != "bdist_wheel":
            continue
        candidate = entry.get("url", "")
        if isinstance(candidate, str) and candidate:
            return candidate
    return ""


def _license_from_pep658(
    data: dict,
    client: httpx.Client,
    fetcher_text: Callable[[str, httpx.Client], dict[str, str] | None],
) -> str:
    """Best-effort license read from a wheel's PEP 658 ``.metadata`` sidecar.

    Used when the PyPI JSON API leaves ``license`` / ``license_expression``
    / classifiers all empty. The JSON does generally surface these fields,
    but for a minority of packages (~3% of Python deps in measured corpora)
    they come back null even when the wheel's own ``METADATA`` file (PEP 643)
    carries clean license data — likely an indexer-side gap, not a deliberate
    PyPA design choice. PEP 658 is the officially-standardized HTTPS
    mechanism for reading the canonical ``METADATA`` directly.

    Prefers ``License-Expression`` (PEP 639, structured SPDX) over the legacy
    ``License:`` field, and only accepts a short single-line value from the
    latter (anything longer is almost always a full license text body — those
    don't survive ``_parse_pep658_headers`` anyway since it skips continuation
    lines, but the length guard adds a second belt against single-line bodies).
    Returns ``""`` if no usable identifier is found.
    """
    wheel_url = _extract_wheel_url(data)
    if not wheel_url:
        return ""
    headers = fetcher_text(wheel_url + ".metadata", client)
    if not isinstance(headers, dict):
        return ""
    expression = headers.get("License-Expression", "")
    if isinstance(expression, str) and expression.strip():
        return expression.strip()
    legacy = headers.get("License", "")
    if isinstance(legacy, str):
        legacy = legacy.strip()
        # Three guards, parity with the JSON-side ``_extract_raw_license``:
        # (1) length cap — blocks long prose pastes that landed on a single
        # line; (2) explicit newline reject (header parser already skips
        # continuation lines, but be paranoid); (3) ``_is_junk_license``
        # rejects short values that still carry prose markers like
        # "copyright" or "permission is hereby" — the no-prose-extraction
        # rule covers short scalars that are actually narrative, not just
        # full license-text bodies.
        if (
            legacy
            and len(legacy) < _LEGACY_LICENSE_MAX_LEN
            and "\n" not in legacy
            and not _is_junk_license(legacy)
        ):
            return legacy
    return ""


def resolve_python_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    fetcher: Fetcher = fetch_registry_json,
    pep658_fetcher: Callable[[str, httpx.Client], dict[str, str] | None] = fetch_pep658_metadata,
) -> LicenseInfo:
    """Resolve license for a Python package from PyPI.

    ``fetcher`` defaults to a direct HTTP fetch but can be the ``fetch``
    method of a :class:`~licenseal.resolvers.http.RegistryCache` to dedupe
    URLs that the transitive walker has already pulled. Same URLs are
    hit either way; the cache just short-circuits the second visit.
    """
    name = dep.name
    spec = dep.version_constraint.strip()

    pinned_version = _extract_pinned_version(spec)
    project_data: dict | None = None
    if pinned_version:
        url = f"{_PYPI_URL}/{name}/{pinned_version}/json"
        data = fetcher(url, client)
        # Custom-index versions (CUDA/ROCm GPU builds, internal mirrors,
        # PEP 440 local-version segments like `+cu124`) are pinned in the
        # project's lockfile but published to a separate index — PyPI 404s
        # on the per-version URL. The project exists on PyPI under a
        # different version with the canonical license; fall back to that
        # so the dep doesn't surface as UNKNOWN just because the wheel
        # binary lives elsewhere.
        if data is None:
            project_url = f"{_PYPI_URL}/{name}/json"
            project_data = fetcher(project_url, client)
            data = project_data
    elif not spec:
        url = f"{_PYPI_URL}/{name}/json"
        data = fetcher(url, client)
        project_data = data
    else:
        project_url = f"{_PYPI_URL}/{name}/json"
        project_data = fetcher(project_url, client)
        if project_data is None:
            data = None
        else:
            # `releases` is list[str] from the RegistryCache and dict[str,...]
            # from a direct fetch — both iterate the same way.
            releases = project_data.get("releases", [])
            release_keys = (
                [k for k in releases if isinstance(k, str)]
                if isinstance(releases, (dict, list))
                else []
            )
            selected_version = select_python_version(spec, release_keys)
            if not selected_version:
                data = None
            else:
                version_url = f"{_PYPI_URL}/{name}/{selected_version}/json"
                data = fetcher(version_url, client)
    if data is None:
        # Resilience fallback: PyPI's HTTP retries exhausted (5xx storm,
        # partial outage). deps.dev runs on independent infrastructure
        # (Google API gateway vs PyPI's Fastly + PSF infra), so a
        # correlated outage is unlikely. Only fires when we know a
        # concrete version to query — unpinned specs whose range
        # resolution failed have no version to look up.
        if pinned_version:
            return resolve_via_deps_dev_stable_get(
                dep,
                pinned_version,
                system="PYPI",
                client=client,
                fetcher=fetcher,
            )
        return LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="",
            from_registry=False,
        )
    info = data.get("info", {})
    resolved_version = info.get("version", "")
    repository_url = _extract_repository_url(info)
    homepage_url = _extract_homepage_url(info)

    raw_license = _extract_raw_license(info)

    # Older releases publish sparse per-version metadata (no license_expression,
    # no classifiers); the project-level endpoint reflects current metadata for
    # the same package, so consult it as a last resort.
    if not raw_license:
        if project_data is None:
            project_data = fetcher(f"{_PYPI_URL}/{name}/json", client)
        if project_data is not None and project_data is not data:
            project_info = project_data.get("info", {}) or {}
            raw_license = _extract_raw_license(project_info)
            if not repository_url:
                repository_url = _extract_repository_url(project_info)
            if not homepage_url:
                homepage_url = _extract_homepage_url(project_info)

    # PEP 658 fallback. The PyPI JSON API does generally surface PEP 639's
    # ``License-Expression``, the legacy ``license`` field, and classifiers
    # (warehouse PEP 639 implementation landed late 2024) — most Python deps
    # (~97% in measured stress-test corpora) resolve cleanly through one of
    # them. But for a minority (~3%), all of those JSON fields come back null
    # even though the wheel's own ``METADATA`` file (PEP 643) carries clean
    # license data. The trigger isn't well-documented externally; likely
    # indexer-side gap for specific uploads, not a deliberate PyPA design
    # choice. PEP 658's ``.metadata`` sidecar is the officially standardized
    # HTTPS mechanism for reading the wheel's canonical ``METADATA`` directly
    # — fetch and parse it only when the JSON-side fields yielded nothing
    # usable. ``not raw_license`` covers the "no field at all" case;
    # ``normalize_license(...) == "UNKNOWN"`` catches "field present but
    # unparseable" so a maintainer publishing PEP 639 metadata isn't overruled
    # by a stale-classifier holdover.
    if not raw_license or normalize_license(raw_license) == "UNKNOWN":
        pep658_license = _license_from_pep658(data, client, pep658_fetcher)
        if pep658_license:
            raw_license = pep658_license

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


def _marker_passes_with_extras(
    marker: Marker | None,
    requested_extras: frozenset[str],
) -> bool:
    """Decide whether to follow a ``requires_dist`` entry given requested extras.

    Policy:

    * No marker → include.
    * Marker references no ``extra`` (pure env: ``python_version``,
      ``sys_platform`` …) → include. License obligations don't depend on
      where the package runs, so a copyleft dep behind a platform gate
      still needs reporting on every platform.
    * Marker references ``extra`` → walk the marker tree treating any env
      term as ``True`` (preserves the rule above) and evaluating ``extra``
      against each value in ``requested_extras | {""}``. The ``""`` case
      models a default install with no extras requested. Include iff at
      least one extra value (real or empty) makes the marker evaluate True.

    This is what fixes the historical bug where the walker massively
    over-reported on Python projects whose dep tree included extras-heavy
    transitives (packages that list hundreds or thousands of optional
    integrations under ``extra ==`` markers).
    """
    if marker is None:
        return True
    if "extra" not in str(marker):
        return True
    candidates = {""} | set(requested_extras)
    nodes = marker._markers  # type: ignore[attr-defined]  # noqa: SLF001  (stable across packaging releases)
    return any(_eval_markers(nodes, extra_value=e) for e in candidates)


def _eval_markers(nodes: list, *, extra_value: str) -> bool:
    """Replicate packaging's marker-evaluation grouping (or splits, and joins).

    Mirrors ``packaging.markers._evaluate_markers``: split the flat list at
    each ``"or"`` into AND-groups; the overall expression is True iff some
    group has all-True leaves. Env-only leaves return True (policy);
    extras leaves compare against ``extra_value``.
    """
    groups: list[list[bool]] = [[]]
    for item in nodes:
        if isinstance(item, list):
            groups[-1].append(_eval_markers(item, extra_value=extra_value))
        elif isinstance(item, tuple):
            groups[-1].append(_eval_leaf(item, extra_value=extra_value))
        elif item == "or":
            groups.append([])
        # "and" is implicit between adjacent items in a group.
    return any(all(group) for group in groups if group)


def _eval_leaf(leaf: tuple, *, extra_value: str) -> bool:
    """A single ``(lhs, op, rhs)`` marker comparison."""
    lhs, op, rhs = leaf
    # One side is a Variable, the other a Value. Both expose `.value`, so
    # distinguish by the type name (Variable / Value are not in packaging's
    # public re-exports). Anything not naming `extra` is treated as env →
    # always True per policy.
    lhs_is_extra = type(lhs).__name__ == "Variable" and getattr(lhs, "value", "") == "extra"
    rhs_is_extra = type(rhs).__name__ == "Variable" and getattr(rhs, "value", "") == "extra"
    if not (lhs_is_extra or rhs_is_extra):
        return True
    op_str = getattr(op, "value", "")
    if lhs_is_extra:
        return _compare_strings(extra_value, op_str, rhs.value)
    return _compare_strings(lhs.value, op_str, extra_value)


def _compare_strings(left: str, op: str, right: str) -> bool:
    """String comparison ops as PEP 508 defines them for extras."""
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == "in":
        return left in right
    if op == "not in":
        return left not in right
    # PEP 440 ordering ops (<, <=, >, >=) aren't meaningful for extra strings.
    # Be conservative: True so the dep isn't silently dropped on a marker
    # shape we don't model.
    return True


def fetch_python_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
    requested_extras: frozenset[str] = frozenset(),
) -> list[Dependency]:
    """Fetch the package's declared dependencies from PyPI.

    Returns the package's own ``requires_dist`` filtered by extras
    semantics (see :func:`_marker_passes_with_extras`). Each returned
    ``Dependency`` carries the extras the *parent's* requirement specified
    for it (e.g. ``"requests[socks]"`` → child has ``extras={"socks"}``)
    so the walker can evaluate the child's own ``extra ==`` markers
    correctly when it recurses.

    ``fetcher`` defaults to a direct HTTP fetch; the walker passes a
    cache-backed fetcher so the response is reused for license resolution.
    """
    url = f"{_PYPI_URL}/{name}/{version}/json"
    data = fetcher(url, client)
    if data is None:
        return []
    info = data.get("info", {}) or {}
    requires = info.get("requires_dist", []) or []
    if not isinstance(requires, list):
        return []
    out: list[Dependency] = []
    for raw in requires:
        if not isinstance(raw, str):
            continue
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            continue
        if not _marker_passes_with_extras(req.marker, requested_extras):
            continue
        spec = str(req.specifier) if req.specifier else ""
        out.append(
            Dependency(
                name=req.name,
                version_constraint=spec,
                ecosystem=Ecosystem.PYTHON,
                group=parent_group,
                depth=parent_depth + 1,
                extras=frozenset(req.extras),
            )
        )
    return out
