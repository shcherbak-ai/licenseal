"""License compatibility assessment."""

from __future__ import annotations

from licenseal.analysis.risk import classify_risk, unavoidable_unresolved_licenses
from licenseal.analysis.spdx import normalize_license
from licenseal.models import (
    AnalysisReport,
    CompatibilityResult,
    CompatibilityVerdict,
    DependencyGroup,
    LicenseInfo,
    RiskLevel,
)

# Source-available licenses classify as UNKNOWN on the *dep* side (custom
# commercial-use restrictions are user-context-dependent and need manual
# review). But on the *project* side, they're effectively permissive for
# the compatibility matrix: the project's restrictive license is the
# project's own choice; it doesn't constrain what deps it can consume.
# Without this override, a BUSL / SSPL / Elastic / FSL-* project sees
# ``<dep> uses <license> — could not determine compatibility with <project>``
# for every dep, turning a clean dep tree into 100% UNKNOWN.
#
# Prefix matching covers all version/variant suffixes — FSL alone has
# FSL-1.0-Apache-2.0, FSL-1.0-MIT, FSL-1.1-Apache-2.0, FSL-1.1-MIT,
# FSL-1.1-ALv2; PolyForm has six+ variants; etc. The dep-side risk
# patterns in risk.py use the same prefix set.
_SOURCE_AVAILABLE_PROJECT_PREFIXES: tuple[str, ...] = (
    "BUSL-",
    "SSPL-",
    "Elastic-",
    "FSL-",
    "Parity-",
    "PolyForm-",
)


def _project_compat_risk(project_spdx: str, project_risk: RiskLevel) -> RiskLevel:
    """Risk level to use for the project's compatibility-matrix lookup.

    A restrictive *project* license doesn't constrain what deps it can
    consume — the project's restrictive choice is its own. So two families of
    project license get treated as PERMISSIVE for the matrix lookup:

    * ``Proprietary`` — a closed-source project can consume permissive deps
      (and still can't absorb copyleft). This treatment is project-side only;
      ``classify_risk`` rates ``Proprietary`` as UNKNOWN so that a
      ``Proprietary`` *dep* arm doesn't leak into dep-side OR aggregation.
    * Source-available licenses (BUSL / SSPL / Elastic / FSL / …) — same
      rationale; without this every dep of such a project reads UNKNOWN.
    """
    if project_spdx == "Proprietary":
        return RiskLevel.PERMISSIVE
    if project_risk == RiskLevel.UNKNOWN and project_spdx.startswith(
        _SOURCE_AVAILABLE_PROJECT_PREFIXES
    ):
        return RiskLevel.PERMISSIVE
    return project_risk


# Compatibility matrix: (project_risk, dependency_risk) -> verdict
# Key principle: a permissive project cannot incorporate copyleft dependencies
# (they would force the project to adopt the copyleft license).
# A copyleft project CAN incorporate permissive dependencies.
#
# (STRONG, NETWORK) is a WARNING rather than INCOMPATIBLE because AGPL-3.0
# § 13 and the matching GPL-3.0 § 13 explicitly permit combining the two
# (the combined work is legal; the AGPL portion's source-on-network-access
# obligation simply binds anyone who deploys the result over the network).
# GPL-2.0-only + AGPL-3.0 is genuinely incompatible, but the coarse matrix
# can't distinguish v2 from v3; warn rather than over-block.
_COMPAT_MATRIX: dict[tuple[RiskLevel, RiskLevel], CompatibilityVerdict] = {
    # Permissive project
    (RiskLevel.PERMISSIVE, RiskLevel.PERMISSIVE): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.PERMISSIVE, RiskLevel.WEAK_COPYLEFT): CompatibilityVerdict.WARNING,
    (RiskLevel.PERMISSIVE, RiskLevel.STRONG_COPYLEFT): CompatibilityVerdict.INCOMPATIBLE,
    (RiskLevel.PERMISSIVE, RiskLevel.NETWORK_COPYLEFT): CompatibilityVerdict.INCOMPATIBLE,
    (RiskLevel.PERMISSIVE, RiskLevel.UNKNOWN): CompatibilityVerdict.UNKNOWN,
    # Weak copyleft project
    (RiskLevel.WEAK_COPYLEFT, RiskLevel.PERMISSIVE): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.WEAK_COPYLEFT, RiskLevel.WEAK_COPYLEFT): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.WEAK_COPYLEFT, RiskLevel.STRONG_COPYLEFT): CompatibilityVerdict.INCOMPATIBLE,
    (RiskLevel.WEAK_COPYLEFT, RiskLevel.NETWORK_COPYLEFT): CompatibilityVerdict.INCOMPATIBLE,
    (RiskLevel.WEAK_COPYLEFT, RiskLevel.UNKNOWN): CompatibilityVerdict.UNKNOWN,
    # Strong copyleft project
    (RiskLevel.STRONG_COPYLEFT, RiskLevel.PERMISSIVE): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.STRONG_COPYLEFT, RiskLevel.WEAK_COPYLEFT): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.STRONG_COPYLEFT, RiskLevel.STRONG_COPYLEFT): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.STRONG_COPYLEFT, RiskLevel.NETWORK_COPYLEFT): CompatibilityVerdict.WARNING,
    (RiskLevel.STRONG_COPYLEFT, RiskLevel.UNKNOWN): CompatibilityVerdict.UNKNOWN,
    # Network copyleft project
    (RiskLevel.NETWORK_COPYLEFT, RiskLevel.PERMISSIVE): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.NETWORK_COPYLEFT, RiskLevel.WEAK_COPYLEFT): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.NETWORK_COPYLEFT, RiskLevel.STRONG_COPYLEFT): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.NETWORK_COPYLEFT, RiskLevel.NETWORK_COPYLEFT): CompatibilityVerdict.COMPATIBLE,
    (RiskLevel.NETWORK_COPYLEFT, RiskLevel.UNKNOWN): CompatibilityVerdict.UNKNOWN,
    # Unknown project license
    (RiskLevel.UNKNOWN, RiskLevel.PERMISSIVE): CompatibilityVerdict.UNKNOWN,
    (RiskLevel.UNKNOWN, RiskLevel.WEAK_COPYLEFT): CompatibilityVerdict.UNKNOWN,
    (RiskLevel.UNKNOWN, RiskLevel.STRONG_COPYLEFT): CompatibilityVerdict.UNKNOWN,
    (RiskLevel.UNKNOWN, RiskLevel.NETWORK_COPYLEFT): CompatibilityVerdict.UNKNOWN,
    (RiskLevel.UNKNOWN, RiskLevel.UNKNOWN): CompatibilityVerdict.UNKNOWN,
}

_RISK_LABELS = {
    RiskLevel.PERMISSIVE: "permissive license",
    RiskLevel.WEAK_COPYLEFT: (
        "weak copyleft license — modifications to the licensed files must remain "
        "under the same license; linking from other files is allowed"
    ),
    RiskLevel.STRONG_COPYLEFT: (
        "strong copyleft license — derivative works must be released under the "
        "same (or a compatible) license"
    ),
    RiskLevel.NETWORK_COPYLEFT: (
        "network copyleft license — copyleft extends to network use (SaaS)"
    ),
    RiskLevel.UNKNOWN: "unknown license — manual review required",
}


def check_compatibility(
    project_license_raw: str,
    license_info: LicenseInfo,
) -> CompatibilityResult:
    """Check a single dependency's license against the project license."""
    project_spdx = normalize_license(project_license_raw)
    project_risk = _project_compat_risk(project_spdx, classify_risk(project_spdx))
    return _check_compat(project_spdx, project_risk, license_info)


def _check_compat(
    project_spdx: str,
    project_risk: RiskLevel,
    license_info: LicenseInfo,
) -> CompatibilityResult:
    """Internal compatibility check with pre-computed project risk."""
    dep_license = license_info.effective_license_id
    is_dev = license_info.dependency.group == DependencyGroup.DEV

    # Proprietary deps short-circuit the matrix: every proprietary license
    # carries custom commercial terms (paid use, no-redistribution, royalties,
    # field-of-use limits) that licenseal cannot reason about. A human must
    # read the actual license text. Dev-only deps still warn — they don't
    # ship with the project but the developer machine still uses the package.
    if dep_license == "Proprietary":
        verdict = CompatibilityVerdict.WARNING if is_dev else CompatibilityVerdict.UNKNOWN
        return CompatibilityResult(
            license_info=license_info,
            risk_level=RiskLevel.UNKNOWN,
            verdict=verdict,
            reason=_proprietary_reason(license_info, is_dev),
        )

    dep_risk = classify_risk(dep_license)
    verdict = _COMPAT_MATRIX.get((project_risk, dep_risk), CompatibilityVerdict.UNKNOWN)

    # Downgrade violations to warnings for dev dependencies
    if is_dev and verdict == CompatibilityVerdict.INCOMPATIBLE:
        verdict = CompatibilityVerdict.WARNING

    # A compound license can bind the consumer to an unresolved license that
    # ``classify_risk`` hid behind a recognized one — an ``AND`` arm always
    # binds, and an ``OR`` only lets you escape it when some arm is fully
    # resolved (a GPL project consuming ``GPL-3.0-only AND <custom>``, or
    # ``(GPL AND <custom>) OR Proprietary``: no selectable branch is fully
    # resolved, so ``<custom>`` still needs review). The project context lives
    # here, not in the context-free classifier, so re-surface an unavoidable
    # unresolved license — but never soften the stricter INCOMPATIBLE, which
    # already flags a definite conflict (e.g. the same dep in a permissive
    # project).
    unresolved = unavoidable_unresolved_licenses(dep_license)
    if unresolved and verdict in (
        CompatibilityVerdict.COMPATIBLE,
        CompatibilityVerdict.WARNING,
    ):
        return CompatibilityResult(
            license_info=license_info,
            risk_level=dep_risk,
            verdict=CompatibilityVerdict.UNKNOWN,
            reason=_unresolved_and_reason(license_info, unresolved),
        )

    reason = _build_reason(project_spdx, project_risk, license_info, dep_risk, verdict, is_dev)

    return CompatibilityResult(
        license_info=license_info,
        risk_level=dep_risk,
        verdict=verdict,
        reason=reason,
    )


def _unresolved_and_reason(license_info: LicenseInfo, unresolved: list[str]) -> str:
    """Reason for a compound dep whose recognized arm is project-compatible but
    which still binds the consumer to an unresolved license (no fully-resolved
    branch can be elected)."""
    name = license_info.dependency.name
    dep_license = license_info.effective_license_id
    arms = ", ".join(unresolved)
    return (
        f"{name} uses {dep_license}; the consumer cannot avoid {arms}, which did "
        f"not resolve to a recognized license — manual review required"
    )


def _proprietary_reason(license_info: LicenseInfo, is_dev: bool) -> str:
    name = license_info.dependency.name
    base = (
        f"{name} uses a proprietary license — custom commercial terms cannot "
        f"be auto-classified; read the actual license and confirm permitted use"
    )
    if is_dev:
        return base + " (dev-only dependency; will not ship with your project)"
    return base


def _build_reason(
    project_spdx: str,
    project_risk: RiskLevel,
    license_info: LicenseInfo,
    dep_risk: RiskLevel,
    verdict: CompatibilityVerdict,
    is_dev: bool,
) -> str:
    """Build a human-readable reason string."""
    dep_name = license_info.dependency.name
    dep_license = license_info.effective_license_id

    if verdict == CompatibilityVerdict.COMPATIBLE:
        return f"{dep_license} is {_RISK_LABELS[dep_risk]}"

    if verdict == CompatibilityVerdict.WARNING:
        if is_dev:
            return (
                f"{dep_name} uses {dep_license} ({_RISK_LABELS[dep_risk]}), "
                f"but it is a dev-only dependency and will not ship with your project"
            )
        return (
            f"{dep_name} uses {dep_license} — {_RISK_LABELS[dep_risk]}. "
            f"Review whether this is acceptable for your {project_spdx} project"
        )

    if verdict == CompatibilityVerdict.INCOMPATIBLE:
        return (
            f"{dep_name} uses {dep_license} ({_RISK_LABELS[dep_risk]}), "
            f"which is incompatible with your {project_spdx} project license"
        )

    # Unknown
    if license_info.is_unknown:
        # Metadata WAS present, it just didn't normalize to a recognized
        # license. Surface the raw string so a reviewer can resolve it at a
        # glance instead of being told (falsely) there's nothing there.
        # license_raw is unbounded — PyPI's free-text ``license`` field (and
        # some other registries) can hold a whole single-line license body —
        # and this reason is printed verbatim into the terminal table, the
        # markdown report, and the JSON. Collapse whitespace and cap length so
        # a giant value can't wreck the layout; the full string always remains
        # in the report's own ``license_raw`` field.
        raw = " ".join((license_info.license_raw or "").split())
        if raw:
            if len(raw) > 80:
                raw = raw[:79] + "…"
            return (
                f"{dep_name} declares '{raw}' which did not resolve to a recognized "
                f"license — manual review required"
            )
        return f"{dep_name} has no license information — manual review required"
    return f"{dep_name} uses {dep_license} — could not determine compatibility with {project_spdx}"


def analyze(project_license: str, license_infos: list[LicenseInfo]) -> AnalysisReport:
    """Run full compatibility analysis.

    The stored ``project_license`` is the normalized SPDX form — the same
    value the compatibility matrix is keyed on. Reporting the raw publisher
    string (e.g. ``"Apache Software License"``) instead would falsely
    suggest the project license is non-canonical when licenseal in fact
    correctly resolved it.
    """
    project_spdx = normalize_license(project_license)
    project_risk = _project_compat_risk(project_spdx, classify_risk(project_spdx))
    results = [_check_compat(project_spdx, project_risk, li) for li in license_infos]
    return AnalysisReport(project_license=project_spdx, results=results)
