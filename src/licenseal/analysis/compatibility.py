"""License compatibility assessment."""

from __future__ import annotations

from dataclasses import replace
from typing import NamedTuple

from licenseal.analysis.risk import (
    _aggregate,
    _split_top_level,
    _strip_outer_parens,
    classify_risk,
    split_exception,
    unrecognized_exception,
)
from licenseal.analysis.spdx import (
    canonical_license_id,
    malformed_expression_conjunction,
    normalize_license,
    unresolved_list_readings,
)
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
    a ``Proprietary`` / ``LicenseRef-*`` / unrecognized arm and let an
    ``AGPL-3.0-only OR Proprietary`` open-core project consume copyleft deps
    that poison its commercial arm.
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

    An arm that classifies takes its own row. Every other arm maps to
    PERMISSIVE, the row that flags the most: a ``Proprietary`` /
    ``LicenseRef-*`` / source-available arm (the project's own restrictive
    choice doesn't constrain consumption — but it does pin the strictest
    row), and equally an arm licenseal does not recognize at all
    (``Commercial``). The project distributes under that arm too, and
    nothing says it can absorb copyleft, so it is judged exactly as a
    ``Proprietary`` arm. Dropping it instead would let the recognized arm
    alone pick the row.
    """
    risk = classify_risk(_strip_outer_parens(arm.strip()))
    return RiskLevel.PERMISSIVE if risk == RiskLevel.UNKNOWN else risk


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

# Exceptions that lift the Apache-2.0 / GPL-2.0-only conflict: the LLVM
# exception lets a recipient waive the Apache-2.0 sections that conflict
# with GPLv2 when the code is combined with GPLv2 code.
_APACHE_GPL2_WAIVER_EXCEPTIONS: frozenset[str] = frozenset({"LLVM-exception"})

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

    The entries key on current SPDX IDs, so a deprecated GNU spelling is
    rewritten first: ``GPL-3.0`` is ``GPL-3.0-only`` and ``GPL-3.0+`` is
    ``GPL-3.0-or-later``. That has to happen before the ``+`` is stripped —
    stripped first, an 'or later' grant would read as the bare, 'only' ID.

    A ``WITH`` leaf is looked up by its bare license: an exception that only
    adds a permission, and one the rules do not recognize, both leave that
    license's conflicts standing (``Apache-2.0 WITH Swift-exception`` and
    ``Apache-2.0 WITH Commons-Clause`` conflict like ``Apache-2.0``). Two
    recognized exceptions lift a conflict. A linking exception on a
    strong-copyleft license permits the combination whatever the other
    license is — the case in which it relaxes the risk class to weak
    copyleft — so no entry applies to it. An exception in
    ``_APACHE_GPL2_WAIVER_EXCEPTIONS`` lifts the Apache-2.0 entry under a
    GPL-2.0-only project and no other.
    """
    base, exception = split_exception(dep_leaf)
    if (
        exception
        and classify_risk(base) == RiskLevel.STRONG_COPYLEFT
        and classify_risk(dep_leaf) == RiskLevel.WEAK_COPYLEFT
    ):
        return None
    leaf = canonical_license_id(base).rstrip("+")
    if project_spdx == "GPL-2.0-only":
        if leaf in _GPL3_FAMILY_DEP_IDS:
            return (
                CompatibilityVerdict.INCOMPATIBLE,
                f"{leaf} carries GPLv3-family terms that GPLv2 § 6 treats as further "
                f"restrictions, and a GPL-2.0-only project has no upgrade clause",
            )
        if leaf == "Apache-2.0" and exception not in _APACHE_GPL2_WAIVER_EXCEPTIONS:
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


class _Outcome(NamedTuple):
    """What a dependency expression binds the consumer to once its ``OR``
    choices are elected: the risk class, the pair-level conflict, and the
    licenses that did not resolve."""

    risk: RiskLevel
    pair: tuple[CompatibilityVerdict, str] | None
    unresolved: list[str]


def _elect(project_risk: RiskLevel, project_leaf: str, dep_expr: str) -> _Outcome:
    """Outcome of ``dep_expr`` under the ``OR`` choices that suit the project best.

    Risk class, pair conflict and unresolved licenses are settled together
    for each operand, so one ``OR`` arm cannot supply the risk class while
    another supplies the clean pair check. ``project_leaf`` is one simple-ID
    arm of the project license. The walk mirrors :func:`classify_risk`'s
    parser with bind/elect semantics:

    * **leaf** → its risk class, its pair override against ``project_leaf``,
      and the leaf itself when it classifies UNKNOWN or carries a ``WITH``
      exception the rules do not recognize. The second case matters for a
      copyleft license, whose class stays known: the unread exception still
      has to be reviewed wherever the license alone would pass.
    * **AND** → every operand binds: the risk classes aggregate as in
      :func:`classify_risk`, the worst pair conflict stands, and the
      unresolved licenses add up.
    * **OR** → the fully-resolved arm with the most lenient verdict, taken
      whole. An arm that binds an unresolved license is never elected over a
      fully-resolved one, matching the dep-side convention that unresolvable
      arms never relax a verdict (``AGPL-3.0-only OR Proprietary`` stays
      driven by its AGPL arm). When every fully-resolved arm has a pair
      conflict, the worst conflict across all arms stands.
    * **OR with no fully-resolved arm** → no choice can be elected cleanly,
      so the unresolved licenses of every arm are unavoidable (``(GPL AND
      <custom>) OR Proprietary``). The risk class is the least restrictive
      known one, and the worst pair conflict stands unless an arm of known
      risk is conflict-free.
    """
    expr = dep_expr.strip()
    unwrapped = _strip_outer_parens(expr)
    if unwrapped != expr:
        return _elect(project_risk, project_leaf, unwrapped)

    # Split at the lowest-precedence operator first: AND binds tighter than OR.
    or_parts = _split_top_level(expr, " OR ")
    is_or = len(or_parts) > 1
    parts = or_parts if is_or else _split_top_level(expr, " AND ")
    if len(parts) == 1:
        risk = classify_risk(expr)
        unread = risk == RiskLevel.UNKNOWN or unrecognized_exception(expr)
        return _Outcome(risk, _pair_conflict(project_leaf, expr), [expr] if unread else [])

    arms = [_elect(project_risk, project_leaf, part) for part in parts]
    worst = _worst_pair_conflict([arm.pair for arm in arms if arm.pair is not None])
    unresolved = list(dict.fromkeys(tok for arm in arms for tok in arm.unresolved))
    risk = _aggregate([arm.risk for arm in arms], prefer_lower=is_or)
    if not is_or:
        return _Outcome(risk, worst, unresolved)

    resolved = [arm for arm in arms if not arm.unresolved]
    if resolved:
        best = min(
            resolved,
            key=lambda arm: (
                _VERDICT_STRICTNESS[_outcome_verdict(project_risk, arm)[0]],
                arm.risk.severity,
            ),
        )
        if all(arm.pair is not None for arm in resolved):
            return best._replace(pair=worst)
        return best
    if any(arm.pair is None and arm.risk != RiskLevel.UNKNOWN for arm in arms):
        worst = None
    return _Outcome(risk, worst, unresolved)


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
    under every arm it offers, so the dep must clear each one. A leaf with a
    recognized ``WITH`` exception is dropped — pair entries key on exact
    simple IDs, and a GPL-with-exception project doesn't match the bare-GPL
    conflict entries. A leaf with an exception the rules do not recognize
    keeps the entries of its bare license: terms nobody read cannot lift a
    conflict. Each leaf is returned in its current SPDX spelling, the form
    the pair entries key on.
    """
    expr = _strip_outer_parens(project_spdx.strip())
    for sep in (" OR ", " AND "):
        parts = _split_top_level(expr, sep)
        if len(parts) > 1:
            return [leaf for part in parts for leaf in _project_pair_leaves(part)]
    if unrecognized_exception(expr):
        expr = split_exception(expr)[0]
    return [canonical_license_id(expr)] if " " not in expr else []


# Verdicts from most to least lenient. INCOMPATIBLE (a definite, documented
# conflict) outranks everything, including UNKNOWN — the same precedence
# ``risk._aggregate`` gives a pinned copyleft violation over an unresolvable
# AND arm. UNKNOWN outranks WARNING: its manual-review routing is already at
# least as loud.
_VERDICT_STRICTNESS: dict[CompatibilityVerdict, int] = {
    CompatibilityVerdict.COMPATIBLE: 0,
    CompatibilityVerdict.WARNING: 1,
    CompatibilityVerdict.UNKNOWN: 2,
    CompatibilityVerdict.INCOMPATIBLE: 3,
}


def _outcome_verdict(
    project_risk: RiskLevel, outcome: _Outcome
) -> tuple[CompatibilityVerdict, str]:
    """Verdict for an outcome, with the pair's reason fragment when the pair set it.

    The matrix verdict for the outcome's risk class stands unless the pair
    conflict is stricter: an override only ever strengthens the matrix, so a
    pair WARNING replaces COMPATIBLE alone and never softens INCOMPATIBLE or
    UNKNOWN. The fragment is empty when the matrix verdict stands.
    """
    verdict = _COMPAT_MATRIX.get((project_risk, outcome.risk), CompatibilityVerdict.UNKNOWN)
    if outcome.pair is not None and (
        _VERDICT_STRICTNESS[outcome.pair[0]] > _VERDICT_STRICTNESS[verdict]
    ):
        return outcome.pair
    return verdict, ""


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

# Longest origin shown in a reason. The full string is the report's ``origin``
# field and the ``source`` line of a scaffolded review stanza.
_ORIGIN_REASON_MAX = 200


def is_recognised_project_license(project_license: str) -> bool:
    """Whether ``project_license`` gives the compatibility check a row to judge against.

    False for a declared value that does not normalize to a license the
    matrix can place (``"-"``, a sentence, a name with no SPDX mapping). Every
    dependency of a project judged against such a value comes out UNKNOWN.
    """
    project_spdx = normalize_license(project_license)
    return _project_compat_risk(project_spdx, classify_risk(project_spdx)) != RiskLevel.UNKNOWN


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
    # A license list whose source does not say whether its entries are
    # alternatives is judged under both readings. A reviewed license is an
    # explicit expression and is judged as written.
    if license_info.all_apply_license_id and not license_info.reviewed:
        return _check_both_readings(project_spdx, project_risk, license_info)

    dep_license = license_info.effective_license_id
    is_dev = license_info.dependency.group == DependencyGroup.DEV

    # A declared string that is a malformed expression did not normalize, but
    # the licenses it names still bind: it is judged as all of them applying
    # together with one unreadable operand. That reading can only turn up a
    # violation — with the unreadable operand in it, it is never compatible —
    # so anything short of one keeps the plain unknown-license result below.
    if license_info.is_unknown:
        conjunction = malformed_expression_conjunction(license_info.license_raw or "")
        if conjunction:
            judged = _check_compat(
                project_spdx, project_risk, replace(license_info, license_id=conjunction)
            )
            if judged.verdict == CompatibilityVerdict.INCOMPATIBLE:
                return CompatibilityResult(
                    license_info=license_info,
                    risk_level=judged.risk_level,
                    verdict=judged.verdict,
                    reason=_malformed_expression_reason(license_info, judged.reason),
                )
        # A comma- or slash-separated list with an entry that is not a
        # recognized license did not normalize either. Its recognized entries
        # still bind, so it is judged like any list with no stated meaning,
        # with the unrecognized entry as an unresolved operand. That operand
        # keeps the list from ever being compatible, so as above only a
        # violation — one under both readings — replaces the plain
        # unknown-license result below.
        choice, all_apply = unresolved_list_readings(license_info.license_raw or "")
        if choice:
            judged = _check_both_readings(
                project_spdx,
                project_risk,
                replace(license_info, license_id=choice, all_apply_license_id=all_apply),
            )
            if judged.verdict == CompatibilityVerdict.INCOMPATIBLE:
                return CompatibilityResult(
                    license_info=license_info,
                    risk_level=judged.risk_level,
                    verdict=judged.verdict,
                    reason=_unresolved_list_reason(license_info, judged.reason),
                )

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

    # ``risk_level`` is a property of the dependency: its least restrictive
    # choice, whatever the project. The verdict comes from the choice the
    # project can actually take, which is settled per ``OR`` arm — matrix
    # cell, pair-level override (GPL-family version conflicts, Apache-2.0
    # under GPL-2.0-only, GPL-incompatible weak copyleft) and unresolved
    # licenses together. A multi-licensed project distributes under every arm
    # it offers, so the dependency is settled against each simple-ID arm and
    # the strictest outcome stands; a project license with no such arm has no
    # pair entries and is settled once, on risk class and unresolved licenses.
    dep_risk = classify_risk(dep_license)
    outcome = max(
        (
            _elect(project_risk, leaf, dep_license)
            for leaf in _project_pair_leaves(project_spdx) or [project_spdx]
        ),
        key=lambda candidate: _VERDICT_STRICTNESS[_outcome_verdict(project_risk, candidate)[0]],
    )
    verdict, pair_fragment = _outcome_verdict(project_risk, outcome)

    # Downgrade violations to warnings for dev dependencies. Under a project
    # license with no matrix row the violation can only come from a pair
    # entry, and the matrix alone already says UNKNOWN: the downgrade stops
    # there instead of dropping below it.
    if is_dev and verdict == CompatibilityVerdict.INCOMPATIBLE:
        verdict = (
            CompatibilityVerdict.UNKNOWN
            if project_risk == RiskLevel.UNKNOWN
            else CompatibilityVerdict.WARNING
        )

    # The elected choice can still bind the consumer to an unresolved license
    # — an ``AND`` operand always binds, and an ``OR`` only escapes it when
    # some arm is fully resolved (a GPL project consuming ``GPL-3.0-only AND
    # <custom>``, or ``(GPL AND <custom>) OR Proprietary``: no selectable
    # branch is fully resolved, so ``<custom>`` still needs review). Route it
    # to manual review — but never soften the stricter INCOMPATIBLE, which
    # already flags a definite conflict (e.g. the same dep in a permissive
    # project).
    exception = _unread_exception(dep_license)
    if outcome.unresolved and verdict in (
        CompatibilityVerdict.COMPATIBLE,
        CompatibilityVerdict.WARNING,
    ):
        return CompatibilityResult(
            license_info=license_info,
            risk_level=dep_risk,
            verdict=CompatibilityVerdict.UNKNOWN,
            reason=(
                _unread_exception_reason(license_info, [exception])
                if exception
                else _unresolved_and_reason(license_info, outcome.unresolved)
            ),
        )

    # What nobody read in a term that is otherwise a known license: the
    # exception of a lone term, or those of the operands a compound binds.
    unread = [exception] if exception else _unread_operand_exceptions(outcome.unresolved)
    if unread and verdict == CompatibilityVerdict.UNKNOWN and not pair_fragment:
        reason = _unread_exception_reason(license_info, unread)
    elif pair_fragment:
        reason = _pair_conflict_reason(license_info, pair_fragment, is_dev)
    else:
        # The reason names the dependency's own risk class when that class
        # lands in the same matrix cell as the choice taken, and the class of
        # the choice taken when the project cannot take the least restrictive
        # one.
        same_cell = _COMPAT_MATRIX.get((project_risk, dep_risk)) == _COMPAT_MATRIX.get(
            (project_risk, outcome.risk)
        )
        reason = _build_reason(
            project_spdx,
            project_risk,
            license_info,
            dep_risk if same_cell else outcome.risk,
            verdict,
            is_dev,
        )
    if exception and (verdict != CompatibilityVerdict.UNKNOWN or pair_fragment):
        # The verdict comes from the license itself; say that the exception
        # beside it was not part of it.
        reason += (
            f" — '{exception}' is not an exception licenseal recognizes, so the license "
            f"is judged without it"
        )

    return CompatibilityResult(
        license_info=license_info,
        risk_level=dep_risk,
        verdict=verdict,
        reason=reason,
    )


def _unread_exception(dep_license: str) -> str:
    """The unrecognized ``WITH`` exception of a single license whose own class is known.

    ``""`` for a compound expression, a recognized or absent exception, and a
    license that does not classify either: there the license itself is what
    did not resolve.
    """
    if " AND " in dep_license or " OR " in dep_license:
        return ""
    exception = unrecognized_exception(dep_license)
    if exception and classify_risk(split_exception(dep_license)[0]) != RiskLevel.UNKNOWN:
        return exception
    return ""


def _unread_operand_exceptions(unresolved: list[str]) -> list[str]:
    """The unrecognized ``WITH`` exceptions among the unresolved operands of a compound.

    Only an exception on a license whose own class is known counts, as in
    :func:`_unread_exception`. Each exception is listed once, in the order
    of the operands.
    """
    return list(dict.fromkeys(filter(None, map(_unread_exception, unresolved))))


def _unread_exception_reason(license_info: LicenseInfo, exceptions: list[str]) -> str:
    """Reason for a license that would pass but carries exceptions nobody read."""
    name = license_info.dependency.name
    dep_license = license_info.effective_license_id
    if len(exceptions) == 1:
        return (
            f"{name} uses {dep_license} — '{exceptions[0]}' is not an exception licenseal "
            f"recognizes, so the terms it adds were not evaluated; manual review required"
        )
    named = ", ".join(f"'{exception}'" for exception in exceptions)
    return (
        f"{name} uses {dep_license} — {named} are not exceptions licenseal recognizes, "
        f"so the terms they add were not evaluated; manual review required"
    )


def _check_both_readings(
    project_spdx: str,
    project_risk: RiskLevel,
    license_info: LicenseInfo,
) -> CompatibilityResult:
    """Judge a license list with an undefined meaning as a choice and as a conjunction.

    ``license_id`` holds the list as a choice and ``all_apply_license_id``
    as every entry applying. When both readings give the same verdict, the
    result is the choice reading's, which is what a source that did define
    the list as a choice would report. When they differ, electing either
    one would be a guess: the verdict is UNKNOWN and the reason names both.
    """
    choice = _check_compat(
        project_spdx, project_risk, replace(license_info, all_apply_license_id="")
    )
    all_apply = _check_compat(
        project_spdx,
        project_risk,
        replace(
            license_info,
            license_id=license_info.all_apply_license_id,
            all_apply_license_id="",
        ),
    )
    if choice.verdict == all_apply.verdict:
        return replace(choice, license_info=license_info)
    return CompatibilityResult(
        license_info=license_info,
        risk_level=choice.risk_level,
        verdict=CompatibilityVerdict.UNKNOWN,
        reason=(
            f"{license_info.dependency.name} lists several licenses without stating whether "
            f"they are alternatives: read as a choice ({license_info.license_id}) the verdict "
            f"is {choice.verdict.value}, read as all applying "
            f"({license_info.all_apply_license_id}) it is {all_apply.verdict.value} — confirm "
            f"which holds and record that expression in licenseal.review.toml"
        ),
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


def _malformed_expression_reason(license_info: LicenseInfo, judged_reason: str) -> str:
    """Reason for a violation found in a malformed license expression.

    ``judged_reason`` is the reason for the conjunction the string was judged
    as, which names that conjunction and the conflict.
    """
    name = license_info.dependency.name
    return (
        f"{name} declares '{_shown_raw(license_info)}', which is not a well-formed license "
        f"expression and is judged as every license it names applying together — "
        f"{judged_reason}"
    )


def _unresolved_list_reason(license_info: LicenseInfo, judged_reason: str) -> str:
    """Reason for a violation found in a license list with an unrecognized entry.

    ``judged_reason`` is the reason for the list read as a choice, which
    names that expression and the conflict.
    """
    name = license_info.dependency.name
    return (
        f"{name} declares '{_shown_raw(license_info)}', a license list with an entry that "
        f"did not resolve to a recognized license; it is a violation whether its entries "
        f"are alternatives or all apply — {judged_reason}"
    )


def _shown_raw(license_info: LicenseInfo) -> str:
    """The declared license string, fit for a one-line reason.

    ``license_raw`` is unbounded — PyPI's free-text ``license`` field (and
    some other registries) can hold a whole single-line license body — and a
    reason is printed verbatim into the terminal table, the markdown report,
    and the JSON. Whitespace is collapsed and the length capped so a giant
    value can't wreck the layout; the full string always remains in the
    report's own ``license_raw`` field.
    """
    raw = " ".join((license_info.license_raw or "").split())
    if len(raw) > 80:
        raw = raw[:79] + "…"
    return raw


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
        origin = " ".join(license_info.dependency.origin.split())
        if origin:
            # Not a registry package, so no license was looked up. The reason
            # names the source: it is what tells this row from a registry
            # package of the same name, and what a review of it is keyed on.
            if len(origin) > _ORIGIN_REASON_MAX:
                origin = origin[: _ORIGIN_REASON_MAX - 1] + "…"
            return (
                f"{dep_name} comes from an off-registry source ({origin}); its license "
                f"is not looked up — manual review required"
            )
        # Metadata WAS present, it just didn't normalize to a recognized
        # license. Surface the raw string so a reviewer can resolve it at a
        # glance instead of being told (falsely) there's nothing there.
        raw = _shown_raw(license_info)
        if raw:
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
