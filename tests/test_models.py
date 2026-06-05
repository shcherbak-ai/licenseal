"""Tests for licenseal.models."""

from __future__ import annotations

from licenseal.models import (
    AnalysisReport,
    CompatibilityResult,
    CompatibilityVerdict,
    Dependency,
    DependencyGroup,
    Ecosystem,
    LicenseInfo,
    RiskLevel,
)


class TestRiskLevel:
    def test_severity_ordering(self):
        assert RiskLevel.PERMISSIVE.severity < RiskLevel.WEAK_COPYLEFT.severity
        assert RiskLevel.WEAK_COPYLEFT.severity < RiskLevel.STRONG_COPYLEFT.severity
        assert RiskLevel.STRONG_COPYLEFT.severity < RiskLevel.NETWORK_COPYLEFT.severity
        assert RiskLevel.NETWORK_COPYLEFT.severity < RiskLevel.UNKNOWN.severity

    def test_values(self):
        assert RiskLevel.PERMISSIVE.value == "permissive"
        assert RiskLevel.UNKNOWN.value == "unknown"


class TestDependency:
    def test_defaults(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.NPM)
        assert dep.group == DependencyGroup.PROD


class TestLicenseInfo:
    def test_is_unknown(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        li = LicenseInfo(dependency=dep, license_id="UNKNOWN", license_raw="")
        assert li.is_unknown is True

        li2 = LicenseInfo(dependency=dep, license_id="MIT", license_raw="MIT")
        assert li2.is_unknown is False

    def test_noassertion_is_unknown(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        li = LicenseInfo(dependency=dep, license_id="NOASSERTION", license_raw="")
        assert li.is_unknown is True

    def test_empty_is_unknown(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        li = LicenseInfo(dependency=dep, license_id="", license_raw="")
        assert li.is_unknown is True

    def test_detected_license_defaults_to_license_id(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        li = LicenseInfo(dependency=dep, license_id="MIT", license_raw="MIT")
        assert li.detected_license_id == "MIT"
        assert li.reviewed is False

    def test_reviewed_property(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        li = LicenseInfo(
            dependency=dep,
            license_id="UNKNOWN",
            license_raw="UNKNOWN",
            reviewed_license_id="MIT",
        )
        assert li.reviewed is True
        assert li.detected_license_id == "UNKNOWN"
        assert li.effective_license_id == "MIT"
        assert li.is_unknown is False


class TestAnalysisReport:
    def _make_result(self, verdict: CompatibilityVerdict) -> CompatibilityResult:
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        li = LicenseInfo(dependency=dep, license_id="MIT", license_raw="MIT")
        return CompatibilityResult(
            license_info=li,
            risk_level=RiskLevel.PERMISSIVE,
            verdict=verdict,
        )

    def test_categorization(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                self._make_result(CompatibilityVerdict.COMPATIBLE),
                self._make_result(CompatibilityVerdict.COMPATIBLE),
                self._make_result(CompatibilityVerdict.WARNING),
                self._make_result(CompatibilityVerdict.INCOMPATIBLE),
                self._make_result(CompatibilityVerdict.UNKNOWN),
            ],
        )
        assert len(report.ok) == 2
        assert len(report.warnings) == 1
        assert len(report.violations) == 1
        assert len(report.unknown) == 1

    def test_reviewed_results(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        reviewed = CompatibilityResult(
            license_info=LicenseInfo(
                dependency=dep,
                license_id="UNKNOWN",
                license_raw="UNKNOWN",
                reviewed_license_id="MIT",
            ),
            risk_level=RiskLevel.PERMISSIVE,
            verdict=CompatibilityVerdict.COMPATIBLE,
        )
        report = AnalysisReport(project_license="MIT", results=[reviewed])
        assert len(report.reviewed) == 1

    def test_empty_report(self):
        report = AnalysisReport(project_license="MIT")
        assert report.ok == []
        assert report.violations == []


class TestEnums:
    def test_ecosystem_values(self):
        assert Ecosystem.PYTHON.value == "python"
        assert Ecosystem.NPM.value == "npm"
        assert Ecosystem.RUST.value == "rust"
        assert Ecosystem.GO.value == "go"
        assert Ecosystem.JAVA.value == "java"
        assert Ecosystem.DOTNET.value == "dotnet"
        assert Ecosystem.R.value == "r"

    def test_every_ecosystem_has_a_label(self):
        # The CLI workspace-filter echo iterates Ecosystem and reads ``.label``;
        # a missing entry would raise KeyError there, so enforce completeness.
        for eco in Ecosystem:
            assert isinstance(eco.label, str) and eco.label

    def test_label_examples(self):
        assert Ecosystem.R.label == "R"
        assert Ecosystem.DOTNET.label == ".NET"
        assert Ecosystem.JAVA.label == "Java/JVM"

    def test_dependency_group_values(self):
        assert DependencyGroup.PROD.value == "prod"
        assert DependencyGroup.DEV.value == "dev"

    def test_verdict_values(self):
        assert CompatibilityVerdict.COMPATIBLE.value == "compatible"
        assert CompatibilityVerdict.INCOMPATIBLE.value == "incompatible"
        assert CompatibilityVerdict.WARNING.value == "warning"
        assert CompatibilityVerdict.UNKNOWN.value == "unknown"
