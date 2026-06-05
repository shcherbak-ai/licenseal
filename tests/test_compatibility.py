"""Tests for licenseal.analysis.compatibility."""

from __future__ import annotations

from licenseal.analysis.compatibility import analyze, check_compatibility
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
        li = _make_license_info("SomeCustomLicense")
        result = check_compatibility("MIT", li)
        assert "Could not determine" in result.reason

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
        """A `copyleft OR commercial` dual-license dep (Artifex/PyMuPDF's
        "AGPL OR commercial") must be flagged against a permissive project —
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


class TestSourceAvailableProjectLicense:
    """When the *project's own* license is source-available (BUSL-1.1,
    SSPL-1.0, Elastic-2.0, ...) it should behave like a permissive license
    for compatibility-matrix purposes: the project's restrictive choice
    constrains downstream USE of the project, not what deps the project
    consumes. Without this rule, every dep ends up UNKNOWN with reason
    ``Could not determine compatibility of <X> with BUSL-1.1`` — a project
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
    Tauri apps mixing Rust+TS) where ecosystem-skipping would silently hide
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
