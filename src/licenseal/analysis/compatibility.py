"""License compatibility assessment."""

from __future__ import annotations

from licenseal.analysis.risk import (
    _split_top_level,
    _strip_outer_parens,
    classify_risk,
    unavoidable_unresolved_licenses,
)
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

    A dual-licensed project (top-level ``OR``) distributes under *every* arm
    it offers, so its deps must clear every arm: the matrix row is the
    strictest-consumption row across arms — the one with the LOWEST severity,
    since a PERMISSIVE row flags the most. Dep-side OR aggregation
    (elect one arm, drop unknowns) is the wrong semantics here: it would drop
    a ``Proprietary`` / ``LicenseRef-*`` arm and let an ``AGPL-3.0-only OR
    Proprietary`` open-core project consume copyleft deps that poison its
    commercial arm.
    """
    if project_spdx == "Proprietary":
        return RiskLevel.PERMISSIVE
    if project_risk == RiskLevel.UNKNOWN and project_spdx.startswith(
        _SOURCE_AVAILABLE_PROJECT_PREFIXES
    ):
        return RiskLevel.PERMISSIVE
    or_parts = _split_top_level(project_spdx, " OR ")
    if len(or_parts) > 1:
        return min(
            (_project_arm_compat_risk(arm) for arm in or_parts),
            key=lambda r: r.severity,
        )
    return project_risk


def _project_arm_compat_risk(arm: str) -> RiskLevel:
    """Matrix-row risk for one arm of a dual-licensed project expression.

    Applies the same project-side-permissive mapping as
    :func:`_project_compat_risk`, per arm: a ``Proprietary`` /
    ``LicenseRef-*`` / source-available arm maps to PERMISSIVE (the
    project's own restrictive choice doesn't constrain consumption — but it
    does pin the strictest row), everything else classifies normally. An arm
    that stays UNKNOWN (unrecognized string) keeps UNKNOWN's last-place
    severity, so a recognized arm wins the strictest-row ``min`` — matching
    the dep-side convention that unresolvable arms don't drive the verdict.
    """
    arm = _strip_outer_parens(arm.strip())
    risk = classify_risk(arm)
    if risk != RiskLevel.UNKNOWN:
        return risk
    if (
        arm == "Proprietary"
        or arm.startswith("LicenseRef-")
        or arm.startswith(_SOURCE_AVAILABLE_PROJECT_PREFIXES)
    ):
        return RiskLevel.PERMISSIVE
    return RiskLevel.UNKNOWN


# Compatibility matrix: (project_risk, dependency_risk) -> verdict
# Key principle: a permissive project cannot incorporate copyleft dependencies
# (they would force the project to adopt the copyleft license).
# A copyleft project CAN incorporate permissive dependencies.
#
# (STRONG, NETWORK) is a WARNING rather than INCOMPATIBLE because AGPL-3.0
# § 13 and the matching GPL-3.0 § 13 explicitly permit combining the two
# (the combined work is legal; the AGPL portion's source-on-network-access
# obligation simply binds anyone who deploys the result over the network).
# GPL-2.0-only + AGPL-3.0 is genuinely incompatible; the coarse matrix can't
# distinguish v2 from v3, but the pair-override layer below can — it
# upgrades exactly that pairing to INCOMPATIBLE while this cell stays a
# WARNING for the legal v3 combination.
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

# --- Pair-level overrides ----------------------------------------------------
#
# The coarse (project_risk, dep_risk) matrix cannot express incompatibilities
# between specific license pairs that land in a too-soft cell. The entries
# below are the high-confidence, FSF-documented conflicts; an override only
# ever STRENGTHENS the matrix verdict, never relaxes it. For a multi-licensed
# project every simple-ID leaf of the project expression is checked — the
# project distributes under every arm it offers, so a conflict against any
# arm flags (the same deps-must-clear-every-arm semantics as the
# strictest-row selection in ``_project_compat_risk``).

# GPLv3-family dep licenses that cannot be combined into a GPL-2.0-only work:
# GPLv3's additional conditions (express patent grant, anti-tivoization) are
# "further restrictions" under GPLv2 § 6, and a GPL-2.0-only project has no
# upgrade clause to escape them. LGPL-3.0 and AGPL-3.0 code is combinable
# with the GPL only at v3.
_GPL3_FAMILY_DEP_IDS: frozenset[str] = frozenset(
    {
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
    }
)

# Weak-copyleft licenses the FSF documents as GPL-incompatible (patent /
# choice-of-law / additional-restriction clauses). The conflict holds for
# every GPL/AGPL version, so these flag under any GPL-family project.
# EPL-2.0 is handled separately: it is GPL-compatible only when the
# contributor designated the GPL as a secondary license, which metadata
# can't reveal — so it warns instead of hard-failing.
_GPL_INCOMPATIBLE_WEAK_DEP_IDS: frozenset[str] = frozenset(
    {
        "EPL-1.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "MPL-1.1",
    }
)

_GPL_FAMILY_PROJECT_IDS: frozenset[str] = frozenset(
    {
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
    }
)

# Project IDs whose combined work must carry GPLv3-family terms, which
# GPL-2.0-only code cannot adopt (no 'or later' upgrade clause).
_GPL3_FAMILY_PROJECT_IDS: frozenset[str] = frozenset(
    {
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
    }
)


def _pair_conflict(project_spdx: str, dep_leaf: str) -> tuple[CompatibilityVerdict, str] | None:
    """Pair-specific verdict + reason fragment for a conflict the matrix misses.

    ``dep_leaf`` is a single expression leaf (no top-level OR/AND). Returns
    ``None`` when the pair has no override — the matrix verdict stands.
    """
    leaf = dep_leaf.rstrip("+")
    if project_spdx == "GPL-2.0-only":
        if leaf in _GPL3_FAMILY_DEP_IDS:
            return (
                CompatibilityVerdict.INCOMPATIBLE,
                f"{leaf} carries GPLv3-family terms that GPLv2 § 6 treats as further "
                f"restrictions, and a GPL-2.0-only project has no upgrade clause",
            )
        if leaf == "Apache-2.0":
            return (
                CompatibilityVerdict.INCOMPATIBLE,
                "the FSF documents Apache-2.0 as GPLv2-incompatible (patent-termination "
                "and indemnification terms), and a GPL-2.0-only project cannot upgrade "
                "to GPLv3 to resolve it",
            )
    if leaf == "GPL-2.0-only" and project_spdx in _GPL3_FAMILY_PROJECT_IDS:
        return (
            CompatibilityVerdict.INCOMPATIBLE,
            f"GPL-2.0-only code cannot be combined into a {project_spdx} work "
            f"(no 'or later' upgrade clause)",
        )
    if project_spdx in _GPL_FAMILY_PROJECT_IDS:
        if leaf in _GPL_INCOMPATIBLE_WEAK_DEP_IDS:
            return (
                CompatibilityVerdict.INCOMPATIBLE,
                f"the FSF documents {leaf} as GPL-incompatible weak copyleft "
                f"(patent / choice-of-law clauses), so it cannot be combined into a "
                f"{project_spdx} work",
            )
        if leaf == "EPL-2.0":
            return (
                CompatibilityVerdict.WARNING,
                f"EPL-2.0 is GPL-incompatible unless the contributor designated the GPL "
                f"as a secondary license — verify that grant before combining it into "
                f"your {project_spdx} project",
            )
    return None


def _unavoidable_pair_conflict(
    project_spdx: str, dep_expr: str
) -> tuple[CompatibilityVerdict, str] | None:
    """Pair conflict the consumer cannot avoid however they elect ``OR`` choices.

    Mirrors :func:`risk.unavoidable_unresolved_licenses`' bind/elect walk:

    * **leaf** → the pair override for (project, leaf), if any.
    * **AND** → every arm binds, so the worst conflict across arms.
    * **OR** → no conflict when some arm is conflict-free and classifies to a
      known risk (the consumer elects that arm); an UNKNOWN arm cannot clear
      the expression, matching the dep-side convention that unresolvable arms
      never relax a verdict. Otherwise the worst conflict across arms.
    """
    expr = dep_expr.strip()
    unwrapped = _strip_outer_parens(expr)
    if unwrapped != expr:
        return _unavoidable_pair_conflict(project_spdx, unwrapped)

    or_parts = _split_top_level(expr, " OR ")
    if len(or_parts) > 1:
        conflicts: list[tuple[CompatibilityVerdict, str]] = []
        for part in or_parts:
            conflict = _unavoidable_pair_conflict(project_spdx, part)
            if conflict is None:
                if classify_risk(part) != RiskLevel.UNKNOWN:
                    return None  # a conflict-free resolved arm is electable
            else:
                conflicts.append(conflict)
        return _worst_pair_conflict(conflicts)

    and_parts = _split_top_level(expr, " AND ")
    if len(and_parts) > 1:
        conflicts = [
            conflict
            for part in and_parts
            if (conflict := _unavoidable_pair_conflict(project_spdx, part)) is not None
        ]
        return _worst_pair_conflict(conflicts)

    return _pair_conflict(project_spdx, expr)


def _worst_pair_conflict(
    conflicts: list[tuple[CompatibilityVerdict, str]],
) -> tuple[CompatibilityVerdict, str] | None:
    """Most actionable conflict: a definite INCOMPATIBLE beats a WARNING."""
    if not conflicts:
        return None
    for conflict in conflicts:
        if conflict[0] == CompatibilityVerdict.INCOMPATIBLE:
            return conflict
    return conflicts[0]


def _project_pair_leaves(project_spdx: str) -> list[str]:
    """Simple-ID leaves of the project expression, for pair-conflict checks.

    Both ``OR`` and ``AND`` flatten: a multi-licensed project distributes
    under every arm it offers, so the dep must clear each one. WITH-compound
    leaves are dropped — pair entries key on exact simple IDs, and a
    GPL-with-exception project doesn't match the bare-GPL conflict entries.
    """
    expr = _strip_outer_parens(project_spdx.strip())
    for sep in (" OR ", " AND "):
        parts = _split_top_level(expr, sep)
        if len(parts) > 1:
            return [leaf for part in parts for leaf in _project_pair_leaves(part)]
    return [expr] if " " not in expr else []


def _pair_strengthens(
    pair_verdict: CompatibilityVerdict, matrix_verdict: CompatibilityVerdict
) -> bool:
    """True when the pair override is stricter than the matrix verdict.

    INCOMPATIBLE (a definite, documented conflict) replaces anything below
    it, including UNKNOWN — the same precedence ``risk._aggregate`` gives a
    pinned copyleft violation over an unresolvable AND arm. WARNING only
    replaces COMPATIBLE: it must never soften INCOMPATIBLE, and UNKNOWN's
    manual-review routing is already at least as loud.
    """
    if pair_verdict == CompatibilityVerdict.INCOMPATIBLE:
        return matrix_verdict != CompatibilityVerdict.INCOMPATIBLE
    return matrix_verdict == CompatibilityVerdict.COMPATIBLE


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

    # Pair-level overrides: specific (project, dep) license pairs the coarse
    # matrix lands in a too-soft cell for (GPL-family version conflicts,
    # Apache-2.0 under GPL-2.0-only, GPL-incompatible weak copyleft). Only
    # ever strengthens the verdict. Every simple-ID arm of a multi-licensed
    # project is checked: the project distributes under all of them.
    pair_fragment = ""
    pair = _worst_pair_conflict(
        [
            conflict
            for leaf in _project_pair_leaves(project_spdx)
            if (conflict := _unavoidable_pair_conflict(leaf, dep_license)) is not None
        ]
    )
    if pair is not None and _pair_strengthens(pair[0], verdict):
        verdict, pair_fragment = pair

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

    if pair_fragment:
        reason = _pair_conflict_reason(license_info, pair_fragment, is_dev)
    else:
        reason = _build_reason(project_spdx, project_risk, license_info, dep_risk, verdict, is_dev)

    return CompatibilityResult(
        license_info=license_info,
        risk_level=dep_risk,
        verdict=verdict,
        reason=reason,
    )


def _pair_conflict_reason(license_info: LicenseInfo, fragment: str, is_dev: bool) -> str:
    """Reason for a verdict set by the pair-override layer."""
    name = license_info.dependency.name
    dep_license = license_info.effective_license_id
    base = f"{name} uses {dep_license} — {fragment}"
    if is_dev:
        return base + " (dev-only dependency; will not ship with your project)"
    return base


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
