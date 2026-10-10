"""Tests for licenseal.analysis.compatibility."""

from __future__ import annotations

import itertools
import json
import textwrap

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.analysis.compatibility import (
    analyze,
    check_compatibility,
    is_recognised_project_license,
)
from licenseal.analysis.spdx import (
    and_join_licenses,
    collapse_bundled_license_pairs,
    normalize_license,
)
from licenseal.cli import main
from licenseal.models import (
    CompatibilityVerdict,
    Dependency,
    DependencyGroup,
    Ecosystem,
    LicenseInfo,
    RiskLevel,
)


def _make_license_info(
    license_id: str,
    name: str = "pkg",
    group: DependencyGroup = DependencyGroup.PROD,
) -> LicenseInfo:
    dep = Dependency(
        name=name,
        version_constraint="",
        ecosystem=Ecosystem.PYTHON,
        group=group,
    )
    return LicenseInfo(
        dependency=dep,
        license_id=license_id,
        license_raw=license_id,
    )


class TestCheckCompatibility:
    def test_permissive_on_permissive(self):
        li = _make_license_info("MIT")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE
        assert result.risk_level == RiskLevel.PERMISSIVE

    def test_copyleft_on_permissive_is_violation(self):
        li = _make_license_info("GPL-3.0-only", name="gpl-pkg")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert result.risk_level == RiskLevel.STRONG_COPYLEFT
        assert "incompatible" in result.reason

    def test_weak_copyleft_on_permissive_is_warning(self):
        li = _make_license_info("LGPL-3.0-only", name="lgpl-pkg")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.WARNING
        assert result.risk_level == RiskLevel.WEAK_COPYLEFT

    def test_permissive_on_copyleft_is_ok(self):
        li = _make_license_info("MIT")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_network_copyleft_on_permissive_is_violation(self):
        li = _make_license_info("AGPL-3.0-only", name="agpl-pkg")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert result.risk_level == RiskLevel.NETWORK_COPYLEFT

    def test_network_copyleft_on_strong_copyleft_is_warning(self):
        # AGPL-3.0 § 13 and GPL-3.0 § 13 explicitly permit combining the two;
        # the AGPL portion's network-source-disclosure obligation binds anyone
        # who later deploys the combined work over the network. So the matrix
        # downgrades from INCOMPATIBLE to WARNING — the licenses don't conflict,
        # but the project's effective obligations are upgraded.
        li = _make_license_info("AGPL-3.0-only")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.WARNING

    def test_network_copyleft_on_network_copyleft_is_ok(self):
        li = _make_license_info("AGPL-3.0-only")
        result = check_compatibility("AGPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_dev_dependency_violation_downgraded_to_warning(self):
        li = _make_license_info("GPL-3.0-only", name="test-lib", group=DependencyGroup.DEV)
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.WARNING
        assert "dev-only" in result.reason

    def test_unknown_dep_license(self):
        li = _make_license_info("UNKNOWN", name="mystery-pkg")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.risk_level == RiskLevel.UNKNOWN
        assert "no license" in result.reason.lower() or "manual review" in result.reason.lower()

    def test_proprietary_project_license(self):
        """Proprietary project can freely use permissive dependencies."""
        li = _make_license_info("MIT")
        result = check_compatibility("Proprietary", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_unknown_both(self):
        li = _make_license_info("UNKNOWN")
        result = check_compatibility("UNKNOWN", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN

    def test_weak_copyleft_project_with_weak_copyleft_dep(self):
        li = _make_license_info("LGPL-3.0-only")
        result = check_compatibility("MPL-2.0", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_weak_copyleft_project_with_strong_copyleft_dep(self):
        li = _make_license_info("GPL-3.0-only")
        result = check_compatibility("MPL-2.0", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_strong_copyleft_project_with_weak_copyleft_dep(self):
        li = _make_license_info("LGPL-3.0-only")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_strong_copyleft_project_with_strong_copyleft_dep(self):
        li = _make_license_info("GPL-3.0-only")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_proprietary_project_with_copyleft_dep(self):
        """Proprietary project cannot incorporate strong copyleft dependencies."""
        li = _make_license_info("GPL-3.0-only")
        result = check_compatibility("Proprietary", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_compatible_reason_mentions_risk_label(self):
        li = _make_license_info("MIT")
        result = check_compatibility("MIT", li)
        assert "permissive" in result.reason

    def test_unknown_dep_but_not_unknown_id_reason(self):
        li = _make_license_info("SomeCustomLicense", name="custom-pkg")
        result = check_compatibility("MIT", li)
        assert result.reason == (
            "custom-pkg uses SomeCustomLicense — could not determine compatibility with MIT"
        )

    def test_use_restricted_dep_requires_review_under_every_project_license(self):
        # SPDX IDs that share a permissive prefix but carry a use restriction
        # must not come back compatible — under any project license.
        for dep_id in (
            "BSD-3-Clause-No-Military-License",
            "BSD-3-Clause-No-Nuclear-License",
            "BSD-3-Clause-No-Nuclear-License-2014",
            "BSD-Protection",
            "Unicode-TOU",
        ):
            for project in ("MIT", "Apache-2.0", "GPL-3.0-only", "Proprietary"):
                result = check_compatibility(project, _make_license_info(dep_id, name="dep"))
                assert result.verdict == CompatibilityVerdict.UNKNOWN, (project, dep_id)
                assert result.risk_level == RiskLevel.UNKNOWN
                assert result.reason == (
                    f"dep uses {dep_id} — could not determine compatibility with {project}"
                )

    def test_warranty_disclaimer_bsd_variant_stays_compatible(self):
        result = check_compatibility("MIT", _make_license_info("BSD-3-Clause-No-Nuclear-Warranty"))
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_proprietary_dep_with_permissive_project_requires_review(self):
        """A proprietary DEP always requires manual review regardless of the
        project's license — its custom commercial terms cannot be auto-
        classified, even when the project itself is permissive."""
        li = _make_license_info("Proprietary", name="closed-source-sdk")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.risk_level == RiskLevel.UNKNOWN
        assert "proprietary" in result.reason.lower()
        assert "review" in result.reason.lower() or "license" in result.reason.lower()

    def test_proprietary_dep_with_proprietary_project_still_requires_review(self):
        """Even in a proprietary project, proprietary deps still need review —
        the dep's terms may conflict with the project's intended distribution."""
        li = _make_license_info("Proprietary", name="closed-source-sdk")
        result = check_compatibility("Proprietary", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN

    def test_proprietary_dev_dep_softens_to_warning(self):
        """Dev-only proprietary deps don't ship with the project, so the
        verdict softens from UNKNOWN to WARNING."""
        li = _make_license_info("Proprietary", group=DependencyGroup.DEV)
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.WARNING
        assert "dev-only" in result.reason.lower() or "will not ship" in result.reason.lower()

    def test_copyleft_or_proprietary_dual_license_is_flagged(self):
        """A `copyleft OR commercial` dual-license dep (an
        "AGPL OR commercial" offer) must be flagged against a permissive project —
        the Proprietary arm must not let it masquerade as permissive."""
        li = _make_license_info("AGPL-3.0-only OR Proprietary", name="pymupdf")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert result.risk_level == RiskLevel.NETWORK_COPYLEFT

    def test_permissive_or_proprietary_dual_license_keeps_escape(self):
        """A `permissive OR commercial` dep stays compatible — the consumer
        can elect the permissive arm."""
        li = _make_license_info("MIT OR Proprietary", name="dual-pkg")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_unknown_dep_with_raw_metadata_names_the_raw_string(self):
        """When a dep has license metadata that didn't normalize, the reason
        must surface the raw string — not claim there's no license info."""
        li = _make_license_info("UNKNOWN", name="pypdfium2")
        li.license_raw = "weird, unparseable, license soup"
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "weird, unparseable, license soup" in result.reason
        assert "no license information" not in result.reason

    def test_unknown_dep_with_no_metadata_says_so(self):
        """With genuinely empty metadata, the 'no license information' wording
        still applies."""
        li = _make_license_info("UNKNOWN", name="ghost-pkg")
        li.license_raw = ""
        result = check_compatibility("MIT", li)
        assert "no license information" in result.reason

    def test_unknown_dep_with_long_raw_is_collapsed_and_truncated(self):
        """A giant / multi-line raw license body must not spill into the reason
        and wreck the terminal/markdown/JSON layout. Whitespace is collapsed and
        the value is capped; the full string still lives in license_raw."""
        li = _make_license_info("UNKNOWN", name="verbose-pkg")
        li.license_raw = (
            "Line one of a rambling custom license.\n\nLine two with    extra   "
            "spaces.\n" + "blah " * 60
        )
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "\n" not in result.reason  # newlines collapsed
        assert "  " not in result.reason  # runs of spaces collapsed
        assert "…" in result.reason  # truncated
        assert len(result.reason) < 200  # bounded regardless of raw length
        assert result.reason.endswith("manual review required")

    def test_reviewed_unknown_dep_becomes_compatible(self):
        li = _make_license_info("UNKNOWN", name="mystery-pkg")
        li.license_raw = "Custom internal license"
        li.reviewed_license_id = "MIT"
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE
        assert li.detected_license_id == "UNKNOWN"
        assert li.effective_license_id == "MIT"


class TestAndExpressionWithUnresolvedArm:
    """A compound license can bind the consumer to an unresolved license that
    ``classify_risk`` (context-free) hid behind a recognized one — an ``AND``
    arm always binds, and an ``OR`` only escapes it when some arm is fully
    resolved. The verdict layer re-surfaces an unavoidable unresolved license
    (the project license is known here), but must never soften a definite
    incompatibility that a known arm pins, and must not escalate when a clean
    arm is electable."""

    def test_compatible_copyleft_arm_does_not_mask_unknown(self):
        # GPL project + ``GPL-3.0-only AND <custom>``: the GPL arm is compatible
        # with a GPL project, but the unresolved arm still binds → review, not
        # a false-clean COMPATIBLE.
        li = _make_license_info("GPL-3.0-only AND CustomLicense", name="dual")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "CustomLicense" in result.reason
        assert result.reason.endswith("manual review required")

    def test_network_copyleft_compatible_arm_does_not_mask_unknown(self):
        li = _make_license_info("AGPL-3.0-only AND CustomLicense", name="dual")
        result = check_compatibility("AGPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN

    def test_warning_arm_does_not_mask_unknown(self):
        # GPL project + ``AGPL-3.0-only AND <custom>``: AGPL is a WARNING for a
        # GPL project (combinable under §13); the unresolved arm escalates it.
        li = _make_license_info("AGPL-3.0-only AND CustomLicense", name="dual")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN

    def test_incompatible_copyleft_arm_is_not_softened(self):
        # Permissive project + ``GPL-3.0-only AND <custom>``: the GPL arm is a
        # definite incompatibility. The unresolved arm must NOT downgrade that
        # to UNKNOWN (which could pass under --no-strict) — INCOMPATIBLE stays.
        li = _make_license_info("GPL-3.0-only AND CustomLicense", name="dual")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_all_recognized_and_stays_compatible(self):
        # No unresolved arm → no escalation; a fully-recognized AND that the
        # project can absorb stays COMPATIBLE.
        li = _make_license_info("GPL-3.0-only AND MIT", name="dual")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_or_arm_is_not_treated_as_binding(self):
        # ``MIT OR <custom>`` is an escapable choice (elect MIT), not an
        # all-bind AND — it must not escalate to UNKNOWN.
        li = _make_license_info("CustomLicense OR MIT", name="dual")
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_or_of_and_with_unknown_has_no_clean_arm(self):
        # ``(GPL-3.0-only AND <custom>) OR Proprietary`` for a GPL project:
        # classify_risk collapses the first OR arm to strong copyleft (hiding
        # <custom>), and the second arm is proprietary. NEITHER electable branch
        # is fully resolved, so this must escalate to review rather than report
        # the GPL-compatible-but-incomplete first arm as COMPATIBLE.
        li = _make_license_info("(GPL-3.0-only AND CustomLicense) OR Proprietary", name="dual")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "CustomLicense" in result.reason

    def test_or_with_fully_resolved_arm_is_electable(self):
        # ``(LGPL AND <custom>) OR MIT``: MIT is a fully-resolved, electable
        # arm, so the unresolved <custom> in the other arm is avoidable — stays
        # COMPATIBLE, no escalation.
        li = _make_license_info("(LGPL-3.0-only AND CustomLicense) OR MIT", name="dual")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_copyleft_or_proprietary_dual_license_is_unchanged(self):
        # The deliberately-preserved ``copyleft OR commercial`` case: the AGPL
        # arm is fully resolved, so the proprietary arm is avoidable and the
        # escalation must NOT fire — the verdict stays driven by the copyleft
        # arm (INCOMPATIBLE for a permissive project).
        li = _make_license_info("AGPL-3.0-only OR Proprietary", name="dual")
        assert check_compatibility("MIT", li).verdict == CompatibilityVerdict.INCOMPATIBLE
        # And a network-copyleft project can elect the AGPL arm cleanly.
        li2 = _make_license_info("AGPL-3.0-only OR Proprietary", name="dual")
        assert check_compatibility("AGPL-3.0-only", li2).verdict == CompatibilityVerdict.COMPATIBLE


class TestComposedExpressionGrouping:
    """An ``AND`` of independent license entries keeps every entry binding,
    whichever order the entries arrive in."""

    _OR_ENTRY = "Apache-2.0 OR GPL-2.0-only"
    _COPYLEFT_ENTRY = "AGPL-3.0-only"

    def test_or_entry_cannot_escape_the_other_entry(self):
        for entries in (
            [self._OR_ENTRY, self._COPYLEFT_ENTRY],
            [self._COPYLEFT_ENTRY, self._OR_ENTRY],
        ):
            li = _make_license_info(normalize_license(and_join_licenses(entries)))
            result = check_compatibility("MIT", li)
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, entries
            assert result.risk_level == RiskLevel.NETWORK_COPYLEFT, entries

    def test_each_entry_alone_is_the_control(self):
        # The OR entry on its own is electable down to Apache-2.0; only the
        # composition with the copyleft entry makes it a violation.
        alone = check_compatibility("MIT", _make_license_info(self._OR_ENTRY))
        assert alone.verdict == CompatibilityVerdict.COMPATIBLE
        copyleft = check_compatibility("MIT", _make_license_info(self._COPYLEFT_ENTRY))
        assert copyleft.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_bare_join_is_the_escape_the_grouping_closes(self):
        # Without the group, SPDX precedence reads the bare join as
        # ``Apache-2.0 OR (GPL-2.0-only AND AGPL-3.0-only)``.
        bare = _make_license_info(f"{self._OR_ENTRY} AND {self._COPYLEFT_ENTRY}")
        assert check_compatibility("MIT", bare).verdict == CompatibilityVerdict.COMPATIBLE

    def test_mixed_lowercase_connectors_get_the_uppercase_verdict(self):
        pairs = (
            (
                "GPL-3.0-only or Apache-2.0 and AGPL-3.0-only",
                "GPL-3.0-only OR Apache-2.0 AND AGPL-3.0-only",
            ),
            (
                "Apache-2.0 and AGPL-3.0-only or GPL-3.0-only",
                "Apache-2.0 AND AGPL-3.0-only OR GPL-3.0-only",
            ),
            ("MIT or Apache-2.0 and GPL-3.0-only", "MIT OR Apache-2.0 AND GPL-3.0-only"),
            ("(MIT or Apache-2.0) and GPL-3.0-only", "(MIT OR Apache-2.0) AND GPL-3.0-only"),
        )
        for project in ("MIT", "MPL-2.0", "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"):
            for lowercase, uppercase in pairs:
                lower = check_compatibility(
                    project, _make_license_info(normalize_license(lowercase))
                )
                upper = check_compatibility(
                    project, _make_license_info(normalize_license(uppercase))
                )
                assert lower.verdict == upper.verdict, (project, lowercase)
                assert lower.risk_level == upper.risk_level, (project, lowercase)

    def test_mixed_lowercase_connectors_no_longer_clear_a_permissive_project(self):
        li = _make_license_info(normalize_license("GPL-3.0-only or Apache-2.0 and AGPL-3.0-only"))
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert result.risk_level == RiskLevel.STRONG_COPYLEFT


class TestLicenseRefOperandOrder:
    """A custom ``LicenseRef-*`` operand gives the same verdict wherever it
    sits in the expression."""

    @staticmethod
    def _check(project: str, raw: str):
        return check_compatibility(project, _make_license_info(normalize_license(raw), name="dep"))

    def test_reference_and_copyleft_is_a_violation_in_either_order(self):
        for raw in ("LicenseRef-custom AND GPL-3.0-only", "GPL-3.0-only AND LicenseRef-custom"):
            result = self._check("MIT", raw)
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, raw
            assert result.risk_level == RiskLevel.STRONG_COPYLEFT, raw

    def test_reference_and_copyleft_needs_review_under_a_copyleft_project(self):
        # The GPL arm suits the project; the custom arm still binds.
        for raw in ("LicenseRef-custom AND GPL-3.0-only", "GPL-3.0-only AND LicenseRef-custom"):
            result = self._check("GPL-3.0-only", raw)
            assert result.verdict == CompatibilityVerdict.UNKNOWN, raw
            assert result.reason == (
                "dep uses GPL-3.0-only AND Proprietary; the consumer cannot avoid "
                "Proprietary, which did not resolve to a recognized license — "
                "manual review required"
            )

    def test_reference_or_permissive_is_electable_in_either_order(self):
        for raw in ("LicenseRef-custom OR MIT", "MIT OR LicenseRef-custom"):
            result = self._check("MIT", raw)
            assert result.verdict == CompatibilityVerdict.COMPATIBLE, raw
            assert result.risk_level == RiskLevel.PERMISSIVE, raw

    def test_reference_or_copyleft_keeps_the_copyleft_arm_in_either_order(self):
        for raw in ("LicenseRef-custom OR GPL-3.0-only", "GPL-3.0-only OR LicenseRef-custom"):
            result = self._check("MIT", raw)
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, raw

    def test_reference_alone_is_the_control(self):
        result = self._check("MIT", "LicenseRef-custom")
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "proprietary license" in result.reason

    def test_references_only_keep_the_proprietary_routing(self):
        # Prod: manual review. Dev: the proprietary downgrade to a warning.
        result = self._check("MIT", "LicenseRef-a AND LicenseRef-b")
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "proprietary license" in result.reason
        dev = _make_license_info(
            normalize_license("LicenseRef-a AND LicenseRef-b"), group=DependencyGroup.DEV
        )
        assert check_compatibility("MIT", dev).verdict == CompatibilityVerdict.WARNING

    def test_project_reference_arm_does_not_hide_the_other_arm(self):
        # The project's GPL-2.0-only arm cannot take Apache-2.0, whichever
        # side of the ``OR`` the commercial arm is written on.
        for project in (
            "LicenseRef-Commercial OR GPL-2.0-only",
            "GPL-2.0-only OR LicenseRef-Commercial",
        ):
            result = check_compatibility(project, _make_license_info("Apache-2.0"))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, project
            assert "GPLv2-incompatible" in result.reason

    def test_project_reference_arm_still_pins_the_permissive_row(self):
        for project in (
            "LicenseRef-Commercial OR AGPL-3.0-only",
            "AGPL-3.0-only OR LicenseRef-Commercial",
        ):
            result = check_compatibility(project, _make_license_info("GPL-3.0-only"))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, project
        report = analyze("LicenseRef-Commercial OR AGPL-3.0-only", [])
        assert report.project_license == "AGPL-3.0-only OR Proprietary"


class TestMalformedExpressionVerdict:
    """A license string with a dangling operator or parens that do not pair
    up is judged as every license it names applying together, plus one
    operand that could not be read. It can be a violation; it is never
    compatible because its well-formed half happens to be electable."""

    @staticmethod
    def _check(project: str, raw: str, group: DependencyGroup = DependencyGroup.PROD):
        li = _make_license_info(normalize_license(raw), name="dep", group=group)
        li.license_raw = raw
        return check_compatibility(project, li)

    @pytest.mark.parametrize(
        "project, raw",
        [
            ("MIT", "MIT OR GPL-3.0-only WITH"),
            ("MIT", "MIT OR AND"),
            ("MIT", "MIT AND"),
            ("MIT", "(MIT OR Apache-2.0"),
            ("MIT", "MIT OR (Apache-2.0"),
            ("MIT", "LGPL-3.0-only AND MIT AND"),
            ("GPL-3.0-only", "MIT OR GPL-3.0-only AND"),
            ("GPL-2.0-only", "GPL-2.0-only OR (MIT"),
            # Nothing it names is recognized, or it names nothing.
            ("MIT", "CustomLicense AND"),
            ("MIT", "OR AND"),
        ],
    )
    def test_malformed_expression_without_a_violation_is_unknown(self, project, raw):
        result = self._check(project, raw)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.risk_level == RiskLevel.UNKNOWN
        assert result.reason == (
            f"dep declares '{raw}' which did not resolve to a recognized license — "
            "manual review required"
        )

    @pytest.mark.parametrize(
        "project, raw, judged_as, risk",
        [
            ("MIT", "MIT AND GPL-3.0-only AND", "GPL-3.0-only AND MIT AND UNKNOWN", "strong"),
            # The operators of a malformed string are not trusted: its ``OR``
            # is not read as a choice.
            ("MIT", "MIT OR GPL-3.0-only AND", "GPL-3.0-only AND MIT AND UNKNOWN", "strong"),
            ("MIT", "AND GPL-3.0-only OR MIT", "GPL-3.0-only AND MIT AND UNKNOWN", "strong"),
            ("MIT", "MIT OR AND GPL-3.0-only", "GPL-3.0-only AND MIT AND UNKNOWN", "strong"),
            ("MIT", "GPL-3.0-only AND OR MIT", "GPL-3.0-only AND MIT AND UNKNOWN", "strong"),
            ("MIT", "MIT OR (GPL-3.0-only AND", "GPL-3.0-only AND MIT AND UNKNOWN", "strong"),
            ("MIT", "MIT OR (GPL-3.0-only", "GPL-3.0-only AND MIT AND UNKNOWN", "strong"),
            ("MIT", "MIT) OR (AGPL-3.0-only", "AGPL-3.0-only AND MIT AND UNKNOWN", "network"),
            ("MPL-2.0", "(GPL-2.0-only", "GPL-2.0-only AND UNKNOWN", "strong"),
        ],
    )
    def test_malformed_expression_naming_a_violation_is_a_violation(
        self, project, raw, judged_as, risk
    ):
        result = self._check(project, raw)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        risk_level, label = {
            "strong": (
                RiskLevel.STRONG_COPYLEFT,
                "strong copyleft license — derivative works must be released under the "
                "same (or a compatible) license",
            ),
            "network": (
                RiskLevel.NETWORK_COPYLEFT,
                "network copyleft license — copyleft extends to network use (SaaS)",
            ),
        }[risk]
        assert result.risk_level == risk_level
        assert result.reason == (
            f"dep declares '{raw}', which is not a well-formed license expression and is "
            f"judged as every license it names applying together — dep uses {judged_as} "
            f"({label}), which is incompatible with your {project} project license"
        )
        # The dependency still reports the license as it was detected.
        assert result.license_info.license_id == "UNKNOWN"
        assert result.license_info.license_raw == raw

    def test_pair_level_violation_in_a_malformed_expression_is_a_violation(self):
        result = self._check("GPL-3.0-only", "GPL-2.0-only AND OR GPL-3.0-only")
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert "is not a well-formed license expression" in result.reason
        assert "GPL-2.0-only code cannot be combined into a GPL-3.0-only work" in result.reason
        apache = self._check("GPL-2.0-only", "(Apache-2.0 WITH LLVM-exception OR MIT")
        assert apache.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert "GPLv2-incompatible" in apache.reason

    def test_dev_dependency_with_a_malformed_expression_stays_unknown(self):
        # The violation is downgraded for a dev dependency, and the operand
        # that could not be read then routes it to review.
        result = self._check("MIT", "MIT AND GPL-3.0-only AND", group=DependencyGroup.DEV)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.risk_level == RiskLevel.UNKNOWN
        assert result.reason == (
            "dep declares 'MIT AND GPL-3.0-only AND' which did not resolve to a recognized "
            "license — manual review required"
        )

    def test_long_malformed_expression_is_truncated_in_the_reason(self):
        raw = " AND ".join(["GPL-3.0-only", "MIT", "ISC", "Zlib", "0BSD", "BSD-2-Clause"]) * 2
        raw += " AND"
        assert 80 < len(raw) <= 200
        result = self._check("MIT", raw)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert f"declares '{raw[:79]}…', which is not" in result.reason

    def test_review_of_a_malformed_expression_is_judged_as_written(self):
        li = _make_license_info("UNKNOWN", name="dep")
        li.license_raw = "MIT OR GPL-3.0-only AND"
        li.reviewed_license_id = "GPL-3.0-only OR MIT"
        assert check_compatibility("MIT", li).verdict == CompatibilityVerdict.COMPATIBLE

    def test_unknown_license_without_a_declared_string_is_unchanged(self):
        li = _make_license_info("UNKNOWN", name="dep")
        li.license_raw = None  # type: ignore[assignment]
        result = check_compatibility("MIT", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.reason == "dep has no license information — manual review required"

    def test_completed_expression_is_the_control(self):
        # The same strings with the missing operand supplied classify normally.
        completed = self._check("MIT", "MIT OR GPL-3.0-only AND Apache-2.0")
        assert completed.verdict == CompatibilityVerdict.COMPATIBLE
        unelectable = self._check("MIT", "GPL-3.0-only AND Apache-2.0")
        assert unelectable.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_unknown_leaf_in_a_well_formed_or_stays_electable(self):
        result = self._check("MIT", "MIT OR CustomLicense")
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    @pytest.mark.parametrize(
        "license_id", ["GPL-3.0-only AND UNKNOWN", "GPL-3.0-only AND CustomLicense"]
    )
    def test_violation_beside_an_unknown_operand_stays_a_violation(self, license_id):
        # The well-formed counterpart of the malformed strings above.
        for project in ("MIT", "Apache-2.0", "MPL-2.0", "Proprietary"):
            result = check_compatibility(project, _make_license_info(license_id, name="dep"))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, project
            assert result.risk_level == RiskLevel.STRONG_COPYLEFT
        # No operand is a violation under a GPL project, so the unknown one
        # decides.
        result = check_compatibility("GPL-3.0-only", _make_license_info(license_id, name="dep"))
        assert result.verdict == CompatibilityVerdict.UNKNOWN

    def test_project_license_with_a_dangling_operator_is_unknown(self):
        assert analyze("MIT OR AND", []).project_license == "UNKNOWN"
        result = check_compatibility("MIT OR AND", _make_license_info("MIT"))
        assert result.verdict == CompatibilityVerdict.UNKNOWN


class TestSourceAvailableProjectLicense:
    """When the *project's own* license is source-available (BUSL-1.1,
    SSPL-1.0, Elastic-2.0, ...) it should behave like a permissive license
    for compatibility-matrix purposes: the project's restrictive choice
    constrains downstream USE of the project, not what deps the project
    consumes. Without this rule, every dep ends up UNKNOWN with a reason like
    ``<dep> uses <license> — could not determine compatibility with BUSL-1.1`` — a project
    with thousands of correctly-licensed deps reports zero useful signal."""

    def _li(self, dep_license: str, name: str = "dep") -> LicenseInfo:
        return LicenseInfo(
            dependency=Dependency(
                name=name,
                version_constraint="",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.PROD,
            ),
            license_id=dep_license,
            license_raw=dep_license,
        )

    def test_busl_project_with_permissive_deps_compatible(self):
        # The common case: BUSL-1.1 project consuming permissive deps
        # (Apache-2.0 / MIT / BSD). All should be COMPATIBLE.
        for dep_license in ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC"):
            r = check_compatibility("BUSL-1.1", self._li(dep_license))
            assert r.verdict == CompatibilityVerdict.COMPATIBLE, (
                f"BUSL-1.1 project + {dep_license} dep should be COMPATIBLE, "
                f"got {r.verdict.value}: {r.reason}"
            )

    def test_busl_project_with_strong_copyleft_incompatible(self):
        # BUSL-1.1 project still can't safely incorporate GPL deps — same
        # rule as a permissive project. The project's distinct license
        # would be eclipsed by the GPL dep's viral terms.
        r = check_compatibility("BUSL-1.1", self._li("GPL-3.0-only"))
        assert r.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_other_source_available_project_licenses(self):
        # Same compatibility rule applies to the rest of the source-available
        # family — SSPL, Elastic, FSL, Parity, PolyForm. Includes FSL variants
        # that an earlier enumerated-set version of the project-side check
        # missed; prefix matching covers all version/license suffixes.
        for project_license in (
            "SSPL-1.0",
            "Elastic-2.0",
            "FSL-1.1-MIT",
            "FSL-1.1-ALv2",
            "FSL-1.0-Apache-2.0",
            "FSL-1.0-MIT",
            "FSL-1.1-Apache-2.0",
            "Parity-7.0.0",
            "PolyForm-Noncommercial-1.0.0",
            "PolyForm-Small-Business-1.0.0",
        ):
            r = check_compatibility(project_license, self._li("MIT"))
            assert r.verdict == CompatibilityVerdict.COMPATIBLE, (
                f"{project_license} project + MIT dep should be COMPATIBLE, got {r.verdict.value}"
            )

    def test_source_available_on_dep_side_still_unknown(self):
        # The override only applies project-side. A BUSL-1.1 DEPENDENCY in
        # an MIT project still warrants manual review — its commercial-use
        # restrictions apply to the consumer (us).
        r = check_compatibility("MIT", self._li("BUSL-1.1", name="some-busl-dep"))
        assert r.verdict == CompatibilityVerdict.UNKNOWN


class TestEcosystemAgnosticVerdicts:
    """Verdicts must depend only on (project_license, dep_license), never on
    the dep's ecosystem. An AGPL npm dep in an MIT Python project must be
    flagged identically to an AGPL Python dep; a GPL Rust dep in an MIT npm
    project must be flagged identically to a GPL npm dep. This invariant is
    load-bearing for polyglot projects (e.g. Python wheels with bundled JS,
    desktop apps mixing Rust+TS) where ecosystem-skipping would silently hide
    real copyleft contamination."""

    def _li(self, license_id: str, name: str, ecosystem: Ecosystem) -> LicenseInfo:
        return LicenseInfo(
            dependency=Dependency(
                name=name, version_constraint="", ecosystem=ecosystem, group=DependencyGroup.PROD
            ),
            license_id=license_id,
            license_raw=license_id,
        )

    def test_agpl_dep_is_violation_against_mit_regardless_of_ecosystem(self):
        py_dep = self._li("AGPL-3.0-only", "py-agpl", Ecosystem.PYTHON)
        npm_dep = self._li("AGPL-3.0-only", "npm-agpl", Ecosystem.NPM)
        rust_dep = self._li("AGPL-3.0-only", "rust-agpl", Ecosystem.RUST)
        for li in (py_dep, npm_dep, rust_dep):
            result = check_compatibility("MIT", li)
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, (
                f"AGPL dep from {li.dependency.ecosystem.value} must be incompatible with MIT"
            )

    def test_gpl_dep_is_violation_against_apache_regardless_of_ecosystem(self):
        for ecosystem in (Ecosystem.PYTHON, Ecosystem.NPM, Ecosystem.RUST):
            li = self._li("GPL-3.0-only", f"{ecosystem.value}-gpl", ecosystem)
            result = check_compatibility("Apache-2.0", li)
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_lgpl_dep_is_warning_regardless_of_ecosystem(self):
        for ecosystem in (Ecosystem.PYTHON, Ecosystem.NPM, Ecosystem.RUST):
            li = self._li("LGPL-3.0-only", f"{ecosystem.value}-lgpl", ecosystem)
            result = check_compatibility("MIT", li)
            assert result.verdict == CompatibilityVerdict.WARNING

    def test_permissive_dep_is_compatible_regardless_of_ecosystem(self):
        for ecosystem in (Ecosystem.PYTHON, Ecosystem.NPM, Ecosystem.RUST):
            li = self._li("MIT", f"{ecosystem.value}-mit", ecosystem)
            result = check_compatibility("Apache-2.0", li)
            assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_polyglot_mixed_tree_violations_aggregate_uniformly(self):
        # Project is MIT (Python); deps come from all three ecosystems; one
        # AGPL npm dep, one GPL Rust dep, one MIT Python dep. The aggregate
        # report must surface both violations, not just the Python-side ones.
        lis = [
            self._li("MIT", "py-ok", Ecosystem.PYTHON),
            self._li("AGPL-3.0-only", "npm-agpl", Ecosystem.NPM),
            self._li("GPL-3.0-only", "rust-gpl", Ecosystem.RUST),
        ]
        report = analyze("MIT", lis)
        violator_names = {r.license_info.dependency.name for r in report.violations}
        assert violator_names == {"npm-agpl", "rust-gpl"}


class TestAnalyze:
    def test_full_analysis(self):
        lis = [
            _make_license_info("MIT", name="requests"),
            _make_license_info("Apache-2.0", name="httpx"),
            _make_license_info("GPL-3.0-only", name="gpl-lib"),
            _make_license_info("UNKNOWN", name="mystery"),
        ]
        report = analyze("MIT", lis)
        assert report.project_license == "MIT"
        assert len(report.results) == 4
        assert len(report.ok) == 2
        assert len(report.violations) == 1
        assert len(report.unknown) == 1

    def test_reviewed_unknown_not_counted_as_unknown(self):
        reviewed = _make_license_info("UNKNOWN", name="mystery")
        reviewed.reviewed_license_id = "MIT"
        report = analyze("MIT", [reviewed])
        assert len(report.unknown) == 0
        assert len(report.reviewed) == 1

    def test_empty_analysis(self):
        report = analyze("MIT", [])
        assert len(report.results) == 0
        assert report.ok == []

    def test_project_license_is_normalized_at_storage(self):
        # Raw publisher strings ("Apache Software License", PSF classifier
        # forms) must round-trip into the canonical SPDX ID on the report.
        # Some real-world pyproject.toml files declare the classifier form
        # rather than the canonical SPDX ID, and we must normalize at ingest.
        report = analyze("Apache Software License", [])
        assert report.project_license == "Apache-2.0"

        report = analyze("MIT License", [])
        assert report.project_license == "MIT"

        report = analyze("Python Software Foundation License", [])
        assert report.project_license == "PSF-2.0"


class TestPairLevelOverrides:
    """Specific (project, dep) pairs the coarse matrix lands in a too-soft cell for."""

    def test_apache2_dep_in_gplv2_only_project_is_violation(self):
        li = _make_license_info("Apache-2.0")
        result = check_compatibility("GPL-2.0-only", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        # risk_level stays dep-intrinsic: the dep itself is permissive; the
        # conflict is pair-specific and lives in the verdict + reason.
        assert result.risk_level == RiskLevel.PERMISSIVE
        assert "GPLv2-incompatible" in result.reason

    def test_gplv3_family_dep_in_gplv2_only_project_is_violation(self):
        for dep_id in (
            "GPL-3.0-only",
            "GPL-3.0-or-later",
            "LGPL-3.0-only",
            "LGPL-3.0-or-later",
            "AGPL-3.0-only",
            "AGPL-3.0-or-later",
        ):
            result = check_compatibility("GPL-2.0-only", _make_license_info(dep_id))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, dep_id

    def test_gplv2_only_dep_in_gplv3_family_project_is_violation(self):
        for project in ("GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later"):
            result = check_compatibility(project, _make_license_info("GPL-2.0-only"))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, project
            assert "upgrade clause" in result.reason

    def test_gpl_incompatible_weak_copyleft_dep_is_violation(self):
        for dep_id in ("EPL-1.0", "CDDL-1.0", "CDDL-1.1", "MPL-1.1"):
            result = check_compatibility("GPL-3.0-only", _make_license_info(dep_id))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, dep_id
            assert result.risk_level == RiskLevel.WEAK_COPYLEFT
        result = check_compatibility("GPL-2.0-or-later", _make_license_info("EPL-1.0"))
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_epl2_dep_in_gpl_project_warns_for_secondary_license(self):
        # EPL-2.0 is GPL-compatible only when the contributor designated the
        # GPL as a secondary license, which metadata can't reveal — so warn
        # instead of hard-failing.
        result = check_compatibility("GPL-3.0-only", _make_license_info("EPL-2.0"))
        assert result.verdict == CompatibilityVerdict.WARNING
        assert "secondary license" in result.reason

    def test_or_later_forms_are_exempt(self):
        # An upgrade clause on either side resolves the version conflict.
        for project, dep_id in (
            ("GPL-2.0-or-later", "GPL-3.0-only"),
            ("GPL-2.0-or-later", "Apache-2.0"),
            ("GPL-3.0-only", "GPL-2.0-or-later"),
            ("GPL-2.0-only", "GPL-2.0-or-later"),
        ):
            result = check_compatibility(project, _make_license_info(dep_id))
            assert result.verdict == CompatibilityVerdict.COMPATIBLE, (project, dep_id)

    def test_or_arm_election_clears_conflict(self):
        # The MIT arm is electable, so the GPL-3.0 arm's conflict is avoidable.
        li = _make_license_info("MIT OR GPL-3.0-only")
        assert check_compatibility("GPL-2.0-only", li).verdict == CompatibilityVerdict.COMPATIBLE

    def test_or_with_only_unresolved_escape_keeps_conflict(self):
        # The Proprietary arm classifies UNKNOWN and cannot clear the
        # expression — matching the dep-side convention that unresolvable
        # arms never relax a verdict.
        li = _make_license_info("GPL-3.0-only OR Proprietary")
        result = check_compatibility("GPL-2.0-only", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_and_arm_conflict_is_unavoidable(self):
        # An AND arm always binds; the definite conflict overrides even the
        # matrix's UNKNOWN verdict (it is the more actionable signal).
        li = _make_license_info("Apache-2.0 AND LicenseRef-custom")
        result = check_compatibility("GPL-2.0-only", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_parenthesized_expression_is_walked(self):
        li = _make_license_info("(GPL-3.0-only AND MIT)")
        result = check_compatibility("GPL-2.0-only", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_dev_pair_violation_downgrades_to_warning(self):
        li = _make_license_info("Apache-2.0", group=DependencyGroup.DEV)
        result = check_compatibility("GPL-2.0-only", li)
        assert result.verdict == CompatibilityVerdict.WARNING
        assert "dev-only" in result.reason

    def test_pair_warning_does_not_preempt_unknown(self):
        # EPL-2.0 inside an AND with an unresolved arm: the matrix verdict is
        # UNKNOWN (manual review), already at least as loud as the pair
        # WARNING — the override must not soften it.
        li = _make_license_info("EPL-2.0 AND LicenseRef-custom")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN

    def test_classpath_exception_dep_does_not_pair_conflict(self):
        # A WITH-bearing leaf must not match the bare GPL-3.0-only conflict
        # entry: the Classpath exception permits linking independent modules
        # regardless of their license.
        li = _make_license_info("GPL-3.0-only WITH Classpath-exception-2.0")
        result = check_compatibility("GPL-2.0-only", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_pair_conflict_checked_per_project_arm(self):
        # A dual-licensed project distributes under every arm; the GPLv2 arm
        # cannot consume Apache-2.0 even though the Proprietary arm could.
        li = _make_license_info("Apache-2.0")
        result = check_compatibility("GPL-2.0-only OR Proprietary", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_redundant_project_parens_keep_pair_conflicts(self):
        # Pair entries key on the exact project ID, so a wrap left on the
        # project license would switch the whole pair layer off.
        for depth in range(4):
            project = "(" * depth + "GPL-2.0-only" + ")" * depth
            result = check_compatibility(project, _make_license_info("Apache-2.0"))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, project
            assert "GPLv2-incompatible" in result.reason

    def test_redundant_parens_on_a_project_arm_keep_pair_conflicts(self):
        for project in (
            "((GPL-2.0-only)) OR Proprietary",
            "((GPL-2.0-only OR Proprietary))",
            "(((GPL-2.0-only)) OR (Proprietary))",
        ):
            result = check_compatibility(project, _make_license_info("Apache-2.0"))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, project

    def test_unrelated_pairs_unaffected(self):
        assert (
            check_compatibility("MIT", _make_license_info("Apache-2.0")).verdict
            == CompatibilityVerdict.COMPATIBLE
        )
        assert (
            check_compatibility("GPL-3.0-only", _make_license_info("MPL-2.0")).verdict
            == CompatibilityVerdict.COMPATIBLE
        )
        assert (
            check_compatibility("GPL-3.0-only", _make_license_info("LGPL-2.1-only")).verdict
            == CompatibilityVerdict.COMPATIBLE
        )


class TestWithExceptionVerdicts:
    """A ``WITH`` term is judged by its exception: one the rules recognize
    keeps its effect, one that only adds a permission leaves the license's own
    verdict, and any other makes the term an unresolved operand."""

    @staticmethod
    def _check(project: str, license_id: str, group: DependencyGroup = DependencyGroup.PROD):
        return check_compatibility(project, _make_license_info(license_id, name="dep", group=group))

    @pytest.mark.parametrize(
        "license_id, exception",
        [
            ("Apache-2.0 WITH Commons-Clause", "Commons-Clause"),
            ("MIT WITH NonCommercialRestriction", "NonCommercialRestriction"),
            ("MIT WITH GPL-3.0-only", "GPL-3.0-only"),
            ("GPL-3.0-only WITH Classpath-exception-evil", "Classpath-exception-evil"),
        ],
    )
    def test_unrecognized_exception_is_unknown_under_every_project(self, license_id, exception):
        for project in ("MIT", "MPL-2.0", "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"):
            result = self._check(project, license_id)
            assert result.verdict == CompatibilityVerdict.UNKNOWN, project
            assert result.risk_level == RiskLevel.UNKNOWN
            assert result.reason == (
                f"dep uses {license_id} — '{exception}' is not an exception licenseal "
                "recognizes, so the terms it adds were not evaluated; manual review required"
            )

    def test_bare_licenses_are_the_control(self):
        assert self._check("MIT", "Apache-2.0").verdict == CompatibilityVerdict.COMPATIBLE
        assert self._check("MIT", "GPL-3.0-only").verdict == CompatibilityVerdict.INCOMPATIBLE
        recognized = self._check("MIT", "Apache-2.0 WITH LLVM-exception")
        assert recognized.verdict == CompatibilityVerdict.COMPATIBLE
        assert recognized.reason == "Apache-2.0 WITH LLVM-exception is permissive license"

    def test_unrecognized_exception_on_an_unrecognized_license_keeps_the_generic_reason(self):
        result = self._check("MIT", "SomeCustomLicense WITH Commons-Clause")
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.reason == (
            "dep uses SomeCustomLicense WITH Commons-Clause — could not determine "
            "compatibility with MIT"
        )

    def test_recognized_exception_under_an_unclassified_project_keeps_the_generic_reason(self):
        result = self._check("SomeUnrecognizedLicense", "Apache-2.0 WITH LLVM-exception")
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.reason == (
            "dep uses Apache-2.0 WITH LLVM-exception — could not determine compatibility "
            "with SomeUnrecognizedLicense"
        )

    def test_unrecognized_exception_is_an_unresolved_operand_in_a_compound(self):
        bound = self._check("MIT", "MIT AND Apache-2.0 WITH Commons-Clause")
        assert bound.verdict == CompatibilityVerdict.UNKNOWN
        # A definite violation beside it stands.
        violation = self._check("MIT", "GPL-3.0-only AND Apache-2.0 WITH Commons-Clause")
        assert violation.verdict == CompatibilityVerdict.INCOMPATIBLE
        # A fully resolved arm of a choice is still electable.
        electable = self._check("MIT", "MIT OR Apache-2.0 WITH Commons-Clause")
        assert electable.verdict == CompatibilityVerdict.COMPATIBLE
        # Under a project that can take the other operand, the term still binds.
        copyleft = self._check("GPL-3.0-only", "GPL-3.0-only AND Apache-2.0 WITH Commons-Clause")
        assert copyleft.verdict == CompatibilityVerdict.UNKNOWN
        assert "cannot avoid Apache-2.0 WITH Commons-Clause" in copyleft.reason

    @pytest.mark.parametrize(
        "project, with_term, bare",
        [
            ("GPL-2.0-only", "Apache-2.0 WITH LLVM-exception", "Apache-2.0"),
            ("GPL-2.0-only", "Apache-2.0 WITH Swift-exception", "Apache-2.0"),
            ("GPL-2.0-only", "GPL-3.0-only WITH Autoconf-exception-3.0", "GPL-3.0-only"),
            ("GPL-2.0-only", "GPL-3.0-or-later WITH GCC-exception-3.1", "GPL-3.0-or-later"),
            ("GPL-2.0-only", "LGPL-3.0-only WITH OCaml-LGPL-linking-exception", "LGPL-3.0-only"),
            ("GPL-3.0-only", "GPL-2.0-only WITH Linux-syscall-note", "GPL-2.0-only"),
            ("AGPL-3.0-only", "GPL-2.0-only WITH Universal-FOSS-exception-1.0", "GPL-2.0-only"),
            # Deprecated spellings of the license are read first.
            ("GPL-2.0-only", "GPL-3.0 WITH GCC-exception-3.1", "GPL-3.0-only"),
            ("GPL-2.0-only", "GPL-3.0+ WITH GCC-exception-3.1", "GPL-3.0-or-later"),
            ("GPL-3.0-only", "GPL-2.0 WITH Bison-exception-2.2", "GPL-2.0-only"),
        ],
    )
    def test_added_permission_exception_keeps_the_pair_rules_of_its_license(
        self, project, with_term, bare
    ):
        control = self._check(project, bare)
        assert control.verdict == CompatibilityVerdict.INCOMPATIBLE
        result = self._check(project, with_term)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        # Same pair entry: the reasons differ only in the license they name.
        assert result.reason.split(" — ", 1)[1] == control.reason.split(" — ", 1)[1]
        assert result.risk_level == control.risk_level

    def test_or_later_license_with_an_exception_keeps_its_upgrade_clause(self):
        for project, with_term in (
            ("GPL-3.0-only", "GPL-2.0+ WITH GCC-exception-2.0"),
            ("GPL-3.0-only", "GPL-2.0-or-later WITH Bison-exception-2.2"),
            ("GPL-2.0-or-later", "Apache-2.0 WITH LLVM-exception"),
        ):
            assert self._check(project, with_term).verdict == CompatibilityVerdict.COMPATIBLE

    @pytest.mark.parametrize(
        "exception", ["Classpath-exception-2.0", "Classpath-exception-2.0-short"]
    )
    def test_linking_exception_on_a_gpl_license_has_no_pair_conflict(self, exception):
        for project, license_id in (
            ("GPL-2.0-only", "GPL-3.0-only"),
            ("GPL-2.0-only", "GPL-3.0-or-later"),
            ("GPL-3.0-only", "GPL-2.0-only"),
            ("AGPL-3.0-only", "GPL-2.0-only"),
        ):
            assert self._check(project, license_id).verdict == CompatibilityVerdict.INCOMPATIBLE
            result = self._check(project, f"{license_id} WITH {exception}")
            assert result.verdict == CompatibilityVerdict.COMPATIBLE, (project, license_id)
            assert result.risk_level == RiskLevel.WEAK_COPYLEFT

    def test_linking_exception_lifts_nothing_where_it_does_not_change_the_class(self):
        # The exception is modelled for a strong-copyleft license only; on
        # any other license the pair rules of that license stay in force.
        for license_id in ("Apache-2.0", "LGPL-3.0-only", "AGPL-3.0-only"):
            result = self._check("GPL-2.0-only", f"{license_id} WITH Classpath-exception-2.0")
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, license_id
        result = self._check("GPL-3.0-only", "EPL-1.0 WITH Classpath-exception-2.0")
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_unrecognized_exception_never_makes_a_pair_conflict_compatible(self):
        # No pair entry applies, and none is needed: the term is unresolved.
        for project, license_id in (
            ("GPL-2.0-only", "Apache-2.0 WITH Commons-Clause"),
            ("GPL-2.0-only", "GPL-3.0-only WITH Classpath-exception-evil"),
            ("GPL-3.0-only", "GPL-2.0-only WITH Classpath-exception"),
        ):
            assert self._check(project, license_id).verdict == CompatibilityVerdict.UNKNOWN

    def test_dev_dependency_with_an_unrecognized_exception_stays_unknown(self):
        result = self._check("MIT", "Apache-2.0 WITH Commons-Clause", group=DependencyGroup.DEV)
        assert result.verdict == CompatibilityVerdict.UNKNOWN

    def test_project_license_with_an_unrecognized_exception_is_unclassified(self):
        # The project's own terms are not known, so nothing is judged against
        # them; a recognized exception leaves the project's row in place.
        unknown = check_compatibility("MIT WITH Commons-Clause", _make_license_info("MIT"))
        assert unknown.verdict == CompatibilityVerdict.UNKNOWN
        known = check_compatibility(
            "GPL-3.0-or-later WITH GCC-exception-3.1", _make_license_info("MIT")
        )
        assert known.verdict == CompatibilityVerdict.COMPATIBLE


class TestWithExceptionDrivesTheExitCode:
    """``licenseal check`` exits by the exception in a ``WITH`` term declared
    in a registry ``license`` field."""

    @pytest.mark.parametrize(
        "project, declared, extra_args, exit_code, verdict, risk",
        [
            ("MIT", "Apache-2.0 WITH Commons-Clause", [], 1, "unknown", "unknown"),
            ("MIT", "Apache-2.0 WITH Commons-Clause", ["--no-strict"], 0, "unknown", "unknown"),
            ("MIT", "MIT WITH GPL-3.0-only", [], 1, "unknown", "unknown"),
            ("MIT", "GPL-3.0-only WITH Classpath-exception-evil", [], 1, "unknown", "unknown"),
            # Recognized exceptions: clean, a warning, and a pair-level violation.
            ("MIT", "Apache-2.0 WITH LLVM-exception", [], 0, "compatible", "permissive"),
            (
                "MIT",
                "GPL-2.0-only WITH Classpath-exception-2.0",
                ["--no-strict"],
                0,
                "warning",
                "weak-copyleft",
            ),
            (
                "GPL-2.0-only",
                "Apache-2.0 WITH LLVM-exception",
                ["--no-strict"],
                1,
                "incompatible",
                "permissive",
            ),
            (
                "GPL-2.0-only",
                "GPL-3.0-only WITH Classpath-exception-2.0",
                [],
                0,
                "compatible",
                "weak-copyleft",
            ),
        ],
    )
    @respx.mock
    def test_check_exit_code(
        self, tmp_path, project, declared, extra_args, exit_code, verdict, risk
    ):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": project, "dependencies": {"some-lib": "1.0.0"}})
        )
        respx.get("https://registry.npmjs.org/some-lib/1.0.0").mock(
            return_value=httpx.Response(200, json={"version": "1.0.0", "license": declared})
        )

        result = CliRunner().invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", *extra_args]
        )
        assert result.exit_code == exit_code
        data = json.loads(result.output[result.output.index("{") :])
        assert data["project_license"] == project
        dependency = data["dependencies"][0]
        assert dependency["license"] == declared
        assert dependency["verdict"] == verdict
        assert dependency["risk"] == risk


class TestDeprecatedIdPairConflicts:
    """Deprecated GNU spellings reach the pair-level rules as their current
    IDs — the bare ID as ``-only``, ``+`` as ``-or-later`` — on the
    dependency side and the project side."""

    @pytest.mark.parametrize(
        "project, deprecated, current",
        [
            ("GPL-3.0-only", "GPL-2.0 AND MIT", "GPL-2.0-only AND MIT"),
            ("GPL-3.0-only", "GPL-2.0", "GPL-2.0-only"),
            ("AGPL-3.0-only", "MIT AND GPL-2.0", "GPL-2.0-only AND MIT"),
            ("GPL-2.0-only", "GPL-3.0 AND MIT", "GPL-3.0-only AND MIT"),
            ("GPL-2.0-only", "GPL-3.0+ AND MIT", "GPL-3.0-or-later AND MIT"),
            ("GPL-2.0-only", "LGPL-3.0+", "LGPL-3.0-or-later"),
            ("GPL-2.0-only", "LGPL-3.0", "LGPL-3.0-only"),
            ("GPL-2.0-only", "AGPL-3.0", "AGPL-3.0-only"),
            (
                "GPL-2.0-only",
                "(GPL-3.0+ OR LGPL-3.0) AND MIT",
                "(GPL-3.0-or-later OR LGPL-3.0-only) AND MIT",
            ),
        ],
    )
    def test_deprecated_dep_id_conflicts_like_its_current_id(self, project, deprecated, current):
        assert normalize_license(deprecated) == current
        # As resolved, as the current ID was already handled, and as a raw
        # ``license_id`` that skipped normalization.
        for license_id in (normalize_license(deprecated), current, deprecated):
            result = check_compatibility(project, _make_license_info(license_id))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, license_id

    def test_plus_is_or_later_never_only(self):
        # ``GPL-2.0+`` carries an upgrade clause, so a GPLv3 project can take
        # it. Read as ``GPL-2.0-only`` it would be a false violation.
        for license_id in (
            "GPL-2.0+",
            "GPL-2.0+ AND MIT",
            normalize_license("GPL-2.0+"),
            normalize_license("GPL-2.0+ AND MIT"),
        ):
            result = check_compatibility("GPL-3.0-only", _make_license_info(license_id))
            assert result.verdict == CompatibilityVerdict.COMPATIBLE, license_id
        # Control: without the ``+`` the same ID is 'only' and conflicts.
        bare = check_compatibility("GPL-3.0-only", _make_license_info("GPL-2.0 AND MIT"))
        assert bare.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_or_arm_still_clears_a_deprecated_conflicting_arm(self):
        li = _make_license_info(normalize_license("MIT OR GPL-3.0"))
        assert check_compatibility("GPL-2.0-only", li).verdict == CompatibilityVerdict.COMPATIBLE

    @pytest.mark.parametrize(
        "project, dep",
        [
            ("GPL-2.0", "Apache-2.0"),
            ("GPL-2.0 OR MIT", "Apache-2.0"),
            ("MIT OR GPL-2.0", "Apache-2.0"),
            ("GPL-2.0", "GPL-3.0-only"),
            ("GPL-3.0", "GPL-2.0-only"),
            ("GPL-3.0+", "GPL-2.0-only"),
            ("AGPL-3.0", "GPL-2.0-only"),
            ("GPL-3.0", "EPL-1.0"),
        ],
    )
    def test_deprecated_project_id_conflicts_like_its_current_id(self, project, dep):
        result = check_compatibility(project, _make_license_info(dep))
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, (project, dep)

    @pytest.mark.parametrize(
        "project, dep",
        [
            ("GPL-2.0+", "Apache-2.0"),
            ("GPL-2.0+ OR MIT", "Apache-2.0"),
            ("GPL-2.0+", "GPL-3.0-only"),
        ],
    )
    def test_project_plus_is_or_later_never_only(self, project, dep):
        result = check_compatibility(project, _make_license_info(dep))
        assert result.verdict == CompatibilityVerdict.COMPATIBLE, (project, dep)

    def test_report_names_the_project_license_by_its_current_id(self):
        assert analyze("GPL-2.0", []).project_license == "GPL-2.0-only"
        assert analyze("GPL-2.0+ OR MIT", []).project_license == "GPL-2.0-or-later OR MIT"

    def test_survivor_of_a_collapsed_pair_conflicts_like_its_current_id(self):
        # In a deps.dev array, ``LGPL-3.0`` beside ``GPL-3.0`` collapses to
        # its LGPL entry, which a GPL-2.0-only project cannot take.
        li = _make_license_info(
            collapse_bundled_license_pairs(normalize_license("LGPL-3.0 AND GPL-3.0"))
        )
        assert li.license_id == "LGPL-3.0-only"
        assert check_compatibility("GPL-2.0-only", li).verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_written_conjunction_of_lgpl_and_gpl_binds_both(self):
        # The same two licenses in an expression a publisher wrote, or in a
        # review entry, are both binding: a violation for a permissive
        # project, where the LGPL alone is a warning.
        li = _make_license_info(normalize_license("GPL-3.0-only AND LGPL-3.0-only"))
        assert li.license_id == "GPL-3.0-only AND LGPL-3.0-only"
        assert check_compatibility("MIT", li).verdict == CompatibilityVerdict.INCOMPATIBLE
        reviewed = _make_license_info("UNKNOWN")
        reviewed.reviewed_license_id = normalize_license("GPL-3.0-only AND LGPL-3.0-only")
        assert check_compatibility("MIT", reviewed).verdict == CompatibilityVerdict.INCOMPATIBLE
        alone = _make_license_info("LGPL-3.0-only")
        assert check_compatibility("MIT", alone).verdict == CompatibilityVerdict.WARNING

    def test_written_cddl_gpl_classpath_conjunction_binds_both(self):
        # CDDL-1.0 is a pair-level violation in a GPL project. The dual
        # license escapes it through the GPL arm; a written AND does not.
        both = _make_license_info(
            normalize_license("CDDL-1.0 AND GPL-2.0-with-classpath-exception")
        )
        assert check_compatibility("GPL-3.0-only", both).verdict == (
            CompatibilityVerdict.INCOMPATIBLE
        )
        either = _make_license_info(
            normalize_license("CDDL-1.0 OR GPL-2.0-with-classpath-exception")
        )
        assert check_compatibility("GPL-3.0-only", either).verdict == (
            CompatibilityVerdict.COMPATIBLE
        )

    def test_permissive_project_verdicts_are_the_control(self):
        # The risk class comes from the ID's family prefix, so a permissive
        # project already judged the deprecated spellings correctly.
        for dep, expected in (
            ("GPL-2.0 AND MIT", CompatibilityVerdict.INCOMPATIBLE),
            ("LGPL-3.0+", CompatibilityVerdict.WARNING),
            ("AGPL-3.0", CompatibilityVerdict.INCOMPATIBLE),
        ):
            for license_id in (dep, normalize_license(dep)):
                result = check_compatibility("MIT", _make_license_info(license_id))
                assert result.verdict == expected, license_id


class TestOrArmJudgedWhole:
    """An ``OR`` dependency takes the verdict of one arm judged as a whole —
    risk class, pair-level conflict and unresolved licenses together. Two arms
    cannot each supply the half of a clean verdict that the other lacks."""

    _STRICTNESS = {
        CompatibilityVerdict.COMPATIBLE: 0,
        CompatibilityVerdict.WARNING: 1,
        CompatibilityVerdict.UNKNOWN: 2,
        CompatibilityVerdict.INCOMPATIBLE: 3,
    }

    @staticmethod
    def _check(project: str, license_id: str, group: DependencyGroup = DependencyGroup.PROD):
        return check_compatibility(project, _make_license_info(license_id, name="dep", group=group))

    @pytest.mark.parametrize(
        "project, arms, expected",
        [
            (
                "GPL-2.0-only",
                {
                    "Apache-2.0": CompatibilityVerdict.INCOMPATIBLE,
                    "GPL-2.0-only AND CustomLicense": CompatibilityVerdict.UNKNOWN,
                },
                CompatibilityVerdict.INCOMPATIBLE,
            ),
            (
                "GPL-2.0-only",
                {
                    "Apache-2.0": CompatibilityVerdict.INCOMPATIBLE,
                    "AGPL-1.0-only": CompatibilityVerdict.WARNING,
                },
                CompatibilityVerdict.WARNING,
            ),
            (
                "GPL-3.0-only",
                {
                    "EPL-1.0": CompatibilityVerdict.INCOMPATIBLE,
                    "AGPL-3.0-only": CompatibilityVerdict.WARNING,
                },
                CompatibilityVerdict.WARNING,
            ),
            (
                "GPL-3.0-only",
                {
                    "GPL-2.0-only": CompatibilityVerdict.INCOMPATIBLE,
                    "AGPL-3.0-only": CompatibilityVerdict.WARNING,
                },
                CompatibilityVerdict.WARNING,
            ),
            (
                # No pair entry involved: the unresolved operand rules one arm
                # out, the matrix cell flags the other.
                "GPL-3.0-only",
                {
                    "AGPL-3.0-only": CompatibilityVerdict.WARNING,
                    "GPL-3.0-only AND CustomLicense": CompatibilityVerdict.UNKNOWN,
                },
                CompatibilityVerdict.WARNING,
            ),
            (
                "GPL-3.0-only",
                {
                    "EPL-2.0": CompatibilityVerdict.WARNING,
                    "GPL-3.0-only AND CustomLicense": CompatibilityVerdict.UNKNOWN,
                },
                CompatibilityVerdict.WARNING,
            ),
        ],
    )
    def test_no_arm_compatible_on_its_own_means_not_compatible(self, project, arms, expected):
        # Single-arm controls: neither arm is compatible when it is the whole
        # license.
        for arm, verdict in arms.items():
            assert self._check(project, arm).verdict == verdict, arm
        operands = [f"({arm})" if " " in arm else arm for arm in arms]
        for ordered in (operands, operands[::-1]):
            assert self._check(project, " OR ".join(ordered)).verdict == expected, ordered

    def test_arm_with_an_unresolved_operand_is_not_elected_over_a_resolved_one(self):
        # The resolved arm is a definite conflict and the other arm needs
        # review. The dependency stays a violation rather than dropping to a
        # verdict that --no-strict would pass.
        result = self._check("GPL-2.0-only", "Apache-2.0 OR (GPL-2.0-only AND CustomLicense)")
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert "GPLv2-incompatible" in result.reason

    def test_reason_names_the_risk_class_of_the_arm_taken(self):
        result = self._check("GPL-2.0-only", "Apache-2.0 OR AGPL-1.0-only")
        assert result.reason == (
            "dep uses Apache-2.0 OR AGPL-1.0-only — network copyleft license — "
            "copyleft extends to network use (SaaS). Review whether this is "
            "acceptable for your GPL-2.0-only project"
        )

    def test_reason_keeps_the_dependencys_own_class_where_it_gives_the_same_verdict(self):
        # The project takes the GPL arm, and a permissive dependency would be
        # compatible too, so the reason still names the dependency's own class.
        compatible = self._check("GPL-2.0-only", "Apache-2.0 OR GPL-2.0-only")
        assert compatible.verdict == CompatibilityVerdict.COMPATIBLE
        assert compatible.reason == "Apache-2.0 OR GPL-2.0-only is permissive license"
        # Under a permissive project either copyleft class is a violation.
        violation = self._check("MIT", "AGPL-1.0-only OR (GPL-2.0-only AND CustomLicense)")
        assert violation.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert violation.risk_level == RiskLevel.STRONG_COPYLEFT
        assert "(strong copyleft license" in violation.reason

    def test_risk_level_stays_the_dependencys_own(self):
        # The risk level is the dependency's least restrictive choice under
        # every project license, including one that cannot take that choice.
        for license_id, risk in (
            ("Apache-2.0 OR AGPL-1.0-only", RiskLevel.PERMISSIVE),
            ("Apache-2.0 OR (GPL-2.0-only AND CustomLicense)", RiskLevel.PERMISSIVE),
            ("EPL-1.0 OR AGPL-3.0-only", RiskLevel.WEAK_COPYLEFT),
            ("AGPL-3.0-only OR (GPL-3.0-only AND CustomLicense)", RiskLevel.STRONG_COPYLEFT),
        ):
            for project in ("MIT", "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"):
                assert self._check(project, license_id).risk_level == risk, (project, license_id)

    def test_or_nested_in_an_and_is_judged_the_same_way(self):
        nested = self._check("GPL-2.0-only", "(Apache-2.0 OR AGPL-1.0-only) AND MIT")
        assert nested.verdict == CompatibilityVerdict.WARNING
        assert "network copyleft license" in nested.reason
        electable = self._check("GPL-2.0-only", "(Apache-2.0 OR GPL-2.0-only) AND MIT")
        assert electable.verdict == CompatibilityVerdict.COMPATIBLE

    def test_dev_dependency_downgrade_applies_to_the_arm_taken(self):
        result = self._check(
            "GPL-2.0-only",
            "Apache-2.0 OR (GPL-2.0-only AND CustomLicense)",
            group=DependencyGroup.DEV,
        )
        assert result.verdict == CompatibilityVerdict.WARNING
        assert "dev-only" in result.reason

    def test_dev_downgrade_stops_at_unknown_under_an_unclassified_project_license(self):
        # The project license has no matrix row, so every verdict starts at
        # UNKNOWN. A pair violation raises a prod dependency to INCOMPATIBLE;
        # for a dev dependency the downgrade stops at UNKNOWN, level with a
        # dev dependency that has no conflict at all.
        project = "(GPL-2.0-only OR MIT) AND SomeUnrecognizedLicense"
        for license_id in ("Apache-2.0", "Apache-2.0 OR (GPL-2.0-only AND CustomLicense)"):
            prod = self._check(project, license_id)
            assert prod.verdict == CompatibilityVerdict.INCOMPATIBLE, license_id
            dev = self._check(project, license_id, group=DependencyGroup.DEV)
            assert dev.verdict == CompatibilityVerdict.UNKNOWN, license_id
            assert "GPLv2-incompatible" in dev.reason
        clean = self._check(project, "MIT", group=DependencyGroup.DEV)
        assert clean.verdict == CompatibilityVerdict.UNKNOWN

    def test_every_arm_with_a_pair_conflict_keeps_the_worst_one(self):
        # Each arm has a pair-level conflict, so the worst one stands even
        # though the EPL-2.0 arm alone only warns.
        assert self._check("GPL-2.0-only", "Apache-2.0").verdict == (
            CompatibilityVerdict.INCOMPATIBLE
        )
        assert self._check("GPL-2.0-only", "EPL-2.0").verdict == CompatibilityVerdict.WARNING
        for license_id in ("Apache-2.0 OR EPL-2.0", "EPL-2.0 OR Apache-2.0"):
            result = self._check("GPL-2.0-only", license_id)
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, license_id
            assert "GPLv2-incompatible" in result.reason

    def test_conflict_on_an_unresolved_arm_counts_when_every_resolved_arm_has_one(self):
        result = self._check("GPL-2.0-only", "EPL-2.0 OR (Apache-2.0 AND CustomLicense)")
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert "GPLv2-incompatible" in result.reason

    def test_no_fully_resolved_arm_routes_every_unresolved_license_to_review(self):
        # The GPL arm has a known risk class and no pair conflict, so the
        # other arm's conflict does not stand; both custom licenses do.
        result = self._check(
            "GPL-2.0-only",
            "(GPL-2.0-only AND CustomLicense) OR (Apache-2.0 AND OtherCustomLicense)",
        )
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "cannot avoid CustomLicense, OtherCustomLicense" in result.reason

    def test_no_fully_resolved_arm_keeps_a_conflict_no_known_arm_escapes(self):
        result = self._check("GPL-2.0-only", "(Apache-2.0 AND CustomLicense) OR OtherCustomLicense")
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE
        assert "GPLv2-incompatible" in result.reason

    def test_electable_arm_still_clears_the_dependency(self):
        for project, license_id in (
            ("GPL-2.0-only", "MIT OR GPL-3.0-only"),
            ("GPL-2.0-only", "Apache-2.0 OR GPL-2.0-only"),
            ("GPL-3.0-only", "GPL-2.0-only OR GPL-3.0-only"),
            ("GPL-3.0-only", "EPL-1.0 OR LGPL-2.1-only"),
            ("MIT", "MIT OR CustomLicense"),
        ):
            assert self._check(project, license_id).verdict == CompatibilityVerdict.COMPATIBLE

    def test_project_license_without_a_simple_id_arm_has_no_pair_entries(self):
        # A WITH-compound project license matches no pair entry; the
        # dependency is still judged on risk class and unresolved licenses.
        project = "GPL-2.0-only WITH Classpath-exception-2.0"
        assert self._check(project, "Apache-2.0").verdict == CompatibilityVerdict.COMPATIBLE
        mixed = self._check(project, "Apache-2.0 OR (MIT AND CustomLicense)")
        assert mixed.verdict == CompatibilityVerdict.COMPATIBLE
        assert self._check(project, "MIT AND CustomLicense").verdict == CompatibilityVerdict.UNKNOWN

    _LEAVES = (
        "MIT",
        "Apache-2.0",
        "LGPL-2.1-only",
        "MPL-2.0",
        "EPL-1.0",
        "EPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "AGPL-1.0-only",
        "AGPL-3.0-only",
        "CustomLicense",
        "Proprietary",
        "GPL-3.0-only WITH Classpath-exception-2.0",
    )
    # Operands for the compound arms: each matrix column, both pair-level
    # verdicts, and an unresolved license.
    _BINDING = (
        "MIT",
        "Apache-2.0",
        "EPL-2.0",
        "GPL-2.0-only",
        "GPL-3.0-only",
        "AGPL-3.0-only",
        "CustomLicense",
    )
    # Single-license projects from every matrix row, multi-licensed projects
    # with at most one GPL-family arm, and a license with a GPL-family arm
    # but no matrix row.
    _PROJECTS = (
        "MIT",
        "Apache-2.0",
        "MPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "AGPL-3.0-only",
        "Proprietary",
        "BUSL-1.1",
        "SomeUnrecognizedLicense",
        "MIT OR Apache-2.0",
        "GPL-2.0-only OR Proprietary",
        "AGPL-3.0-only OR Proprietary",
        "GPL-2.0-only WITH Classpath-exception-2.0",
        "(GPL-2.0-only OR MIT) AND SomeUnrecognizedLicense",
    )

    @pytest.mark.parametrize("project", _PROJECTS)
    @pytest.mark.parametrize("group", [DependencyGroup.PROD, DependencyGroup.DEV])
    def test_compound_is_never_more_lenient_than_its_best_arm(self, project, group):
        # Arms are single licenses and AND-compounds; each arm's own verdict
        # comes from the public function.
        conjunctions = [f"({a} AND {b})" for a, b in itertools.combinations(self._BINDING, 2)]
        own = {
            arm: self._STRICTNESS[self._check(project, arm, group).verdict]
            for arm in (*self._LEAVES, *conjunctions)
        }
        for a, b in itertools.combinations(own, 2):
            compound = self._check(project, f"{a} OR {b}", group)
            assert self._STRICTNESS[compound.verdict] >= min(own[a], own[b]), (a, b)
        for a, b, c in itertools.combinations(self._BINDING, 3):
            compound = self._check(project, f"{a} OR {b} OR {c}", group)
            assert self._STRICTNESS[compound.verdict] >= min(own[a], own[b], own[c]), (a, b, c)

    @pytest.mark.parametrize("project", _PROJECTS)
    def test_and_keeps_the_obligations_of_every_operand(self, project):
        # An OR operand of an AND is no more lenient inside the AND than on
        # its own, whatever it is combined with.
        choices = [f"({a} OR {b})" for a, b in itertools.combinations(self._LEAVES, 2)]
        own = {
            operand: self._STRICTNESS[self._check(project, operand).verdict]
            for operand in (*self._BINDING, *choices)
        }
        for choice in choices:
            for leaf in self._BINDING:
                compound = self._check(project, f"{choice} AND {leaf}")
                assert self._STRICTNESS[compound.verdict] >= max(own[choice], own[leaf]), (
                    choice,
                    leaf,
                )

    def test_project_with_two_gpl_family_arms_elects_per_project_arm(self):
        # A multi-licensed project distributes under each arm separately, and
        # the dependency is judged against each one: it can take its
        # GPL-2.0-only arm for the project's GPL-2.0-only arm and its
        # GPL-3.0-only arm for the other. Either dependency arm as the whole
        # license fails one project arm.
        project = "GPL-2.0-only OR GPL-3.0-only"
        for arm in ("GPL-2.0-only", "GPL-3.0-only"):
            assert self._check(project, arm).verdict == CompatibilityVerdict.INCOMPATIBLE, arm
        both = self._check(project, "GPL-2.0-only OR GPL-3.0-only")
        assert both.verdict == CompatibilityVerdict.COMPATIBLE
        # An arm that fails the same project arm either way is not rescued.
        neither = self._check(project, "GPL-3.0-only OR AGPL-3.0-only")
        assert neither.verdict == CompatibilityVerdict.INCOMPATIBLE


class TestOrArmVerdictDrivesTheExitCode:
    """``licenseal check`` on a GPL-2.0-only project exits by the verdict of
    the arm the project can take, not by a mix of two arms."""

    @pytest.mark.parametrize(
        "declared, extra_args, exit_code, verdict, risk",
        [
            # Strict mode fails on the warning from the only arm left.
            ("Apache-2.0 OR AGPL-1.0-only", [], 1, "warning", "permissive"),
            # Single-arm controls.
            ("Apache-2.0", [], 1, "incompatible", "permissive"),
            ("AGPL-1.0-only", [], 1, "warning", "network-copyleft"),
            # --no-strict passes a warning and never a violation.
            ("Apache-2.0 OR AGPL-1.0-only", ["--no-strict"], 0, "warning", "permissive"),
            (
                "Apache-2.0 OR (GPL-2.0-only AND CustomLicense)",
                ["--no-strict"],
                1,
                "incompatible",
                "permissive",
            ),
            # An arm the project can take whole still clears the dependency.
            ("Apache-2.0 OR GPL-2.0-only", [], 0, "compatible", "permissive"),
        ],
    )
    @respx.mock
    def test_check_exit_code(self, tmp_path, declared, extra_args, exit_code, verdict, risk):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "GPL-2.0-only"
            dependencies = ["some-lib"]
            """)
        )
        payload = {
            "info": {
                "license": declared,
                "version": "1.0.0",
                "classifiers": [],
                "requires_dist": [],
            }
        }
        for url in (
            "https://pypi.org/pypi/some-lib/json",
            "https://pypi.org/pypi/some-lib/1.0.0/json",
        ):
            respx.get(url).mock(return_value=httpx.Response(200, json=payload))

        result = CliRunner().invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", *extra_args]
        )
        assert result.exit_code == exit_code
        data = json.loads(result.output[result.output.index("{") :])
        assert data["project_license"] == "GPL-2.0-only"
        assert data["dependencies"][0]["verdict"] == verdict
        assert data["dependencies"][0]["risk"] == risk


class TestListSeparatorInsideAnExpression:
    """A slash-joined operand in an SPDX expression names no license: the
    permissive IDs inside it are never elected."""

    @pytest.mark.parametrize(
        "raw", ["MIT/Apache-2.0 AND GPL-3.0-only", "MIT/Apache-2.0 OR GPL-3.0-only"]
    )
    def test_operand_with_a_separator_does_not_clear_the_expression(self, raw):
        li = _make_license_info(normalize_license(raw), name="dep")
        assert li.all_apply_license_id == ""
        # The copyleft operand is the only one that resolves.
        assert check_compatibility("MIT", li).verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_operand_with_a_separator_binds_in_a_conjunction(self):
        li = _make_license_info(normalize_license("MIT/Apache-2.0 AND GPL-3.0-only"), name="dep")
        result = check_compatibility("GPL-3.0-only", li)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert "cannot avoid MIT/Apache-2.0" in result.reason


class TestMalformedExpressionDrivesTheExitCode:
    """``licenseal check`` on an MIT project: a malformed license expression
    in a registry field fails the check when a license it names is a
    violation, with or without ``--no-strict``."""

    @pytest.mark.parametrize(
        "declared, extra_args, exit_code, verdict, risk",
        [
            ("MIT AND GPL-3.0-only AND", [], 1, "incompatible", "strong-copyleft"),
            ("MIT AND GPL-3.0-only AND", ["--no-strict"], 1, "incompatible", "strong-copyleft"),
            ("MIT OR (GPL-3.0-only", ["--no-strict"], 1, "incompatible", "strong-copyleft"),
            # Well-formed controls.
            ("MIT AND GPL-3.0-only", ["--no-strict"], 1, "incompatible", "strong-copyleft"),
            ("MIT OR GPL-3.0-only", [], 0, "compatible", "permissive"),
            # Malformed without a violation: review, which --no-strict passes.
            ("MIT AND Apache-2.0 AND", [], 1, "unknown", "unknown"),
            ("MIT AND Apache-2.0 AND", ["--no-strict"], 0, "unknown", "unknown"),
            ("MIT OR (Apache-2.0", [], 1, "unknown", "unknown"),
        ],
    )
    @respx.mock
    def test_check_exit_code(self, tmp_path, declared, extra_args, exit_code, verdict, risk):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "MIT"
            dependencies = ["some-lib"]
            """)
        )
        payload = {
            "info": {
                "license": declared,
                "version": "1.0.0",
                "classifiers": [],
                "requires_dist": [],
            }
        }
        for url in (
            "https://pypi.org/pypi/some-lib/json",
            "https://pypi.org/pypi/some-lib/1.0.0/json",
        ):
            respx.get(url).mock(return_value=httpx.Response(200, json=payload))

        result = CliRunner().invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", *extra_args]
        )
        assert result.exit_code == exit_code
        dependency = json.loads(result.output[result.output.index("{") :])["dependencies"][0]
        assert dependency["license_raw"] == declared
        assert dependency["verdict"] == verdict
        assert dependency["risk"] == risk
        if verdict != "compatible" and normalize_license(declared) == "UNKNOWN":
            # A malformed string is reported as the unknown license it is.
            assert dependency["license"] == "UNKNOWN"


class TestDualLicensedProjectRow:
    """A dual-licensed project picks the strictest consumption row across arms."""

    def test_proprietary_arm_pins_permissive_row(self):
        # The open-core pattern: the commercial arm cannot absorb copyleft,
        # so copyleft deps flag even though the AGPL arm alone accepts them.
        li = _make_license_info("GPL-3.0-only")
        result = check_compatibility("AGPL-3.0-only OR Proprietary", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_licenseref_arm_pins_permissive_row(self):
        li = _make_license_info("GPL-3.0-only")
        result = check_compatibility("AGPL-3.0-only OR LicenseRef-Commercial", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_source_available_arm_pins_permissive_row(self):
        li = _make_license_info("GPL-3.0-only")
        result = check_compatibility("GPL-3.0-only OR BUSL-1.1", li)
        assert result.verdict == CompatibilityVerdict.INCOMPATIBLE

    def test_permissive_dep_clears_dual_licensed_project(self):
        li = _make_license_info("MIT")
        result = check_compatibility("AGPL-3.0-only OR Proprietary", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_all_open_arms_keep_least_severe_row(self):
        # Two permissive arms → PERMISSIVE row, same as the previous
        # dep-side aggregation; behavior unchanged for plain dual licensing.
        li = _make_license_info("LGPL-3.0-only")
        result = check_compatibility("MIT OR Apache-2.0", li)
        assert result.verdict == CompatibilityVerdict.WARNING

    def test_unrecognized_arm_does_not_drive_row(self):
        # An arm that stays UNKNOWN ranks last in the strictest-row min; the
        # recognized copyleft arm picks the row.
        li = _make_license_info("GPL-3.0-only")
        result = check_compatibility("GPL-3.0-only OR SomeWeirdLicense", li)
        assert result.verdict == CompatibilityVerdict.COMPATIBLE

    def test_redundant_project_parens_do_not_change_the_row(self):
        # The strictest-row selection splits the project license on its
        # top-level OR; a redundant wrap must not hide that operator and let
        # the copyleft arm alone pick the row.
        for depth in range(4):
            project = "(" * depth + "AGPL-3.0-only OR Proprietary" + ")" * depth
            copyleft = check_compatibility(project, _make_license_info("GPL-3.0-only"))
            assert copyleft.verdict == CompatibilityVerdict.INCOMPATIBLE, project
            permissive = check_compatibility(project, _make_license_info("MIT"))
            assert permissive.verdict == CompatibilityVerdict.COMPATIBLE, project

    def test_redundant_parens_on_mixed_project_arms_do_not_change_the_row(self):
        for project in (
            "((AGPL-3.0-only)) OR Proprietary",
            "(AGPL-3.0-only) OR ((Proprietary))",
            "((GPL-3.0-only) OR ((BUSL-1.1)))",
        ):
            result = check_compatibility(project, _make_license_info("GPL-3.0-only"))
            assert result.verdict == CompatibilityVerdict.INCOMPATIBLE, project

    def test_analyze_reports_the_unwrapped_project_license(self):
        report = analyze("((AGPL-3.0-only OR Proprietary))", [_make_license_info("GPL-3.0-only")])
        assert report.project_license == "AGPL-3.0-only OR Proprietary"
        assert len(report.violations) == 1


class TestRecognisedProjectLicense:
    """A project license is recognised when the check has a row to judge
    against, and not when every dependency would come out UNKNOWN under it."""

    @pytest.mark.parametrize(
        "project_license",
        [
            "MIT",
            "MIT License",
            "GPL-3.0",
            "Apache-2.0 WITH LLVM-exception",
            # The project's own restrictive choice still has a row.
            "Proprietary",
            "UNLICENSED",
            "LicenseRef-Internal",
            "BUSL-1.1",
            "AGPL-3.0-only OR Proprietary",
            # One arm the check can place is enough for an ``OR``.
            "MIT OR Custom",
        ],
    )
    def test_recognised(self, project_license):
        assert is_recognised_project_license(project_license) is True
        verdict = check_compatibility(project_license, _make_license_info("MIT")).verdict
        assert verdict == CompatibilityVerdict.COMPATIBLE

    @pytest.mark.parametrize(
        "project_license",
        ["-", "UNKNOWN", "NOASSERTION", "see the LICENSE file", "Unheard-Of", "MIT AND Custom", ""],
    )
    def test_not_recognised(self, project_license):
        assert is_recognised_project_license(project_license) is False
        # What judging against it would give: nothing can be decided.
        verdict = check_compatibility(project_license, _make_license_info("MIT")).verdict
        assert verdict == CompatibilityVerdict.UNKNOWN
