"""Tests for licenseal.report."""

from __future__ import annotations

import json
import re
from io import BytesIO, StringIO, TextIOWrapper
from pathlib import Path

import pytest
from rich.console import Console

from licenseal.models import (
    AnalysisReport,
    CompatibilityResult,
    CompatibilityVerdict,
    Dependency,
    DependencyGroup,
    Ecosystem,
    LicenseInfo,
    ReportDiagnostic,
    RiskLevel,
)
from licenseal.report import (
    _REPORT_NOTE,
    _actionability,
    _detected_license_label,
    _grouped_results,
    _license_url,
    _markdown_license_label,
    _other_ancestors_suffix,
    _pick_from_parts,
    _pick_url_leaf,
    _printable,
    _source_terminal_url,
    render_check_failure,
    render_json,
    render_markdown,
    render_table,
)


def _make_result(
    name: str,
    license_id: str,
    risk: RiskLevel,
    verdict: CompatibilityVerdict,
    ecosystem: Ecosystem = Ecosystem.PYTHON,
    group: DependencyGroup = DependencyGroup.PROD,
    reason: str = "",
    repository_url: str = "",
    homepage_url: str = "",
    resolved_version: str = "",
    license_raw: str | None = None,
    reviewed_license_id: str = "",
    review_note: str = "",
    depth: int = 0,
    direct_ancestors: tuple[str, ...] = (),
    source: str = "",
    registry_name: str = "",
) -> CompatibilityResult:
    dep = Dependency(
        name=name,
        version_constraint="",
        ecosystem=ecosystem,
        group=group,
        depth=depth,
        direct_ancestors=direct_ancestors,
        source=source,
        registry_name=registry_name,
    )
    li = LicenseInfo(
        dependency=dep,
        license_id=license_id,
        license_raw=license_id if license_raw is None else license_raw,
        reviewed_license_id=reviewed_license_id,
        review_note=review_note,
        repository_url=repository_url,
        homepage_url=homepage_url,
        resolved_version=resolved_version,
    )
    return CompatibilityResult(
        license_info=li,
        risk_level=risk,
        verdict=verdict,
        reason=reason,
    )


def _sample_report() -> AnalysisReport:
    return AnalysisReport(
        project_license="MIT",
        elapsed_seconds=0.42,
        results=[
            _make_result(
                "requests",
                "Apache-2.0",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                repository_url="https://github.com/psf/requests",
                resolved_version="2.31.0",
            ),
            _make_result(
                "flask",
                "BSD-3-Clause",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                repository_url="https://github.com/pallets/flask",
                resolved_version="3.0.3",
            ),
            _make_result(
                "react",
                "MIT",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                ecosystem=Ecosystem.NPM,
                repository_url="https://github.com/facebook/react",
                resolved_version="18.2.0",
            ),
            _make_result(
                "gpl-lib",
                "GPL-3.0-only",
                RiskLevel.STRONG_COPYLEFT,
                CompatibilityVerdict.INCOMPATIBLE,
                reason="GPL is incompatible with MIT",
                resolved_version="1.0.0",
            ),
            _make_result(
                "lgpl-lib",
                "LGPL-3.0-only",
                RiskLevel.WEAK_COPYLEFT,
                CompatibilityVerdict.WARNING,
                reason="Weak copyleft, review needed",
                resolved_version="2.0.0",
            ),
            _make_result(
                "mystery",
                "UNKNOWN",
                RiskLevel.UNKNOWN,
                CompatibilityVerdict.UNKNOWN,
                reason="No license info",
            ),
        ],
    )


def _make_console(width: int = 120) -> tuple[Console, StringIO]:
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, no_color=True, width=width)
    return console, buf


def _make_terminal_console(width: int = 200, *, styled: bool = True) -> tuple[Console, StringIO]:
    """A terminal console whose capabilities don't come from the host environment.

    The colour system and an empty environment are passed explicitly: left to
    detection, ``TERM=dumb`` or ``NO_COLOR`` in the host environment would turn
    the escape sequences off and ``TERM=dumb`` or ``COLUMNS`` would override
    the width. ``styled=False`` keeps the terminal's layout rules but emits no
    escape sequences, for tests that read the layout as text.
    """
    buf = StringIO()
    console = Console(
        file=buf,
        force_terminal=True,
        color_system="standard" if styled else None,
        width=width,
        legacy_windows=False,
        _environ={},
    )
    return console, buf


# Everything in C0 and C1 plus DEL, except the line feed that ends a line.
_RAW_CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")


def _hostile_report() -> AnalysisReport:
    """A report whose registry- and manifest-derived strings carry control characters."""
    return AnalysisReport(
        project_license="MIT\x1b]0;title\x07",
        results=[
            _make_result(
                "pkg\x1b[31m",
                "Evil\x1b[2J\x9b31m",
                RiskLevel.UNKNOWN,
                CompatibilityVerdict.UNKNOWN,
                reason="pkg declares 'Evil\x1b[2J' which did not resolve\rSummary: 0 violations",
                resolved_version="1.0\x00",
                source="dir\x1b[1m/requirements.txt",
            ),
            _make_result(
                "child",
                "MIT",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                depth=1,
                direct_ancestors=("pkg\x1b[31m", "other\x08"),
            ),
            _make_result(
                "reviewed",
                "UNKNOWN",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                resolved_version="2.0.0",
                license_raw="raw\x1b[5m",
                reviewed_license_id="MIT",
                review_note="line one\nline two\ttabbed\x1b[0m\x7f",
            ),
        ],
    )


class TestRenderTable:
    def test_renders_empty_report(self):
        report = AnalysisReport(project_license="MIT")
        console, _ = _make_console()
        render_table(report, console)

    def test_renders_proprietary_project_license(self):
        report = AnalysisReport(
            project_license="Proprietary",
            elapsed_seconds=0.42,
            results=[
                _make_result("pkg", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE),
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "Proprietary" in output

    def test_renders_all_ok(self):
        report = AnalysisReport(
            project_license="MIT",
            elapsed_seconds=0.42,
            results=[
                _make_result("pkg", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE),
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "1 ok" in output

    def test_renders_only_violations(self):
        report = AnalysisReport(
            project_license="MIT",
            elapsed_seconds=0.42,
            results=[
                _make_result(
                    "gpl",
                    "GPL-3.0-only",
                    RiskLevel.STRONG_COPYLEFT,
                    CompatibilityVerdict.INCOMPATIBLE,
                    reason="Violation",
                ),
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "1 violation" in output
        assert "Violation" in output

    def test_singular_violation_text(self):
        """Ensure '1 violation' not '1 violations'."""
        report = AnalysisReport(
            project_license="MIT",
            elapsed_seconds=0.42,
            results=[
                _make_result(
                    "gpl",
                    "GPL-3.0-only",
                    RiskLevel.STRONG_COPYLEFT,
                    CompatibilityVerdict.INCOMPATIBLE,
                    reason="Bad",
                ),
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "1 violation" in output
        assert "1 violations" not in output

    def test_plural_warnings_text(self):
        report = AnalysisReport(
            project_license="MIT",
            elapsed_seconds=0.42,
            results=[
                _make_result(
                    "a",
                    "LGPL-3.0-only",
                    RiskLevel.WEAK_COPYLEFT,
                    CompatibilityVerdict.WARNING,
                    reason="W1",
                ),
                _make_result(
                    "b",
                    "MPL-2.0",
                    RiskLevel.WEAK_COPYLEFT,
                    CompatibilityVerdict.WARNING,
                    reason="W2",
                ),
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "2 warnings" in output

    def test_renders_elapsed_time(self):
        report = _sample_report()
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "Completed in: 0.42s" in output
        assert _REPORT_NOTE in output
        assert "requests (2.31.0)" in output

    def test_renders_reviewed_section_and_summary(self):
        report = AnalysisReport(
            project_license="MIT",
            elapsed_seconds=0.42,
            results=[
                _make_result(
                    "mystery",
                    "UNKNOWN",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    resolved_version="1.0.0",
                    license_raw="Custom internal license",
                    reviewed_license_id="MIT",
                    review_note="confirmed from packaged LICENSE file",
                ),
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "of which 1 reviewed" in output
        assert "Reviewed:" in output
        assert "Detected" in output
        assert "Reviewed" in output
        assert "mystery (1.0.0)" in output
        assert "UNKNOWN (raw: Custom internal license)" in output
        assert "confirmed from" in output
        assert "packaged LICENSE file" in output


class TestRenderJson:
    def test_valid_json(self):
        report = _sample_report()
        output = render_json(report)
        data = json.loads(output)
        assert data["project_license"] == "MIT"
        assert data["elapsed_seconds"] == 0.42
        assert data["summary"]["total"] == 6
        assert data["summary"]["ok"] == 3
        assert data["summary"]["violations"] == 1
        assert data["summary"]["warnings"] == 1
        assert data["summary"]["unknown"] == 1
        assert len(data["dependencies"]) == 6

    def test_dependency_fields(self):
        report = _sample_report()
        output = render_json(report)
        data = json.loads(output)
        dep = next(item for item in data["dependencies"] if item["name"] == "requests")
        assert "name" in dep
        assert "ecosystem" in dep
        assert "group" in dep
        assert "license" in dep
        assert "license_raw" in dep
        assert "detected_license" in dep
        assert "reviewed_license" in dep
        assert "effective_license" in dep
        assert "reviewed" in dep
        assert "review_note" in dep
        assert "resolved_version" in dep
        assert "repository_url" in dep
        assert "package_url" in dep
        assert "license_url" in dep
        assert "risk" in dep
        assert "verdict" in dep
        assert "reason" in dep
        assert dep["resolved_version"] == "2.31.0"
        assert dep["repository_url"] == "https://github.com/psf/requests"
        assert dep["package_url"] == "https://pypi.org/project/requests/"
        assert dep["license_url"] == "https://spdx.org/licenses/Apache-2.0.html"
        assert dep["detected_license"] == "Apache-2.0"
        assert dep["reviewed_license"] == ""
        assert dep["effective_license"] == "Apache-2.0"
        assert dep["reviewed"] is False
        assert dep["review_note"] == ""

    def test_depth_normalized_to_binary_in_json(self):
        # The emitted ``depth`` is a binary direct/transitive signal, not a tree
        # level: a transitive resolved deep by the registry walk carries a true
        # stored depth (e.g. 3) but must serialize to 1, while ``is_transitive``
        # stays true. The stored field is left intact for the walker's max-depth
        # cap and the dedup tiebreak.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "top",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    depth=0,
                ),
                _make_result(
                    "deep",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    depth=3,
                    direct_ancestors=("top",),
                ),
            ],
        )
        data = json.loads(render_json(report))
        top = next(d for d in data["dependencies"] if d["name"] == "top")
        deep = next(d for d in data["dependencies"] if d["name"] == "deep")
        assert top["depth"] == 0
        assert top["is_transitive"] is False
        assert deep["depth"] == 1
        assert deep["is_transitive"] is True

    def test_reviewed_dependency_fields(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "mystery",
                    "UNKNOWN",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    resolved_version="1.0.0",
                    license_raw="Custom internal license",
                    reviewed_license_id="MIT",
                    review_note="confirmed manually",
                )
            ],
        )
        data = json.loads(render_json(report))
        dep = data["dependencies"][0]
        assert dep["license"] == "MIT"
        assert dep["detected_license"] == "UNKNOWN"
        assert dep["reviewed_license"] == "MIT"
        assert dep["effective_license"] == "MIT"
        assert dep["reviewed"] is True
        assert dep["review_note"] == "confirmed manually"
        assert data["summary"]["reviewed"] == 1

    def test_package_url_falls_back_to_registry_page(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "pytest-cov",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                ),
                _make_result(
                    "react-dom",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.NPM,
                ),
                _make_result(
                    "serde",
                    "MIT OR Apache-2.0",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.RUST,
                ),
            ],
        )
        data = json.loads(render_json(report))
        python_dep = next(item for item in data["dependencies"] if item["name"] == "pytest-cov")
        npm_dep = next(item for item in data["dependencies"] if item["name"] == "react-dom")
        rust_dep = next(item for item in data["dependencies"] if item["name"] == "serde")
        assert python_dep["package_url"] == "https://pypi.org/project/pytest-cov/"
        assert npm_dep["package_url"] == "https://www.npmjs.com/package/react-dom"
        assert rust_dep["package_url"] == "https://crates.io/crates/serde"

    def test_package_url_go_includes_module_path_and_optional_version(self):
        # Go's package_url is pkg.go.dev's URL convention: ``pkg.go.dev/{module_path}@{version}``
        # when version is available, plain ``pkg.go.dev/{module_path}`` otherwise.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "github.com/foo/bar",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.GO,
                    resolved_version="v1.0.0",
                ),
                _make_result(
                    "github.com/baz/qux",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.GO,
                ),
            ],
        )
        data = json.loads(render_json(report))
        go_with_ver = next(d for d in data["dependencies"] if d["name"] == "github.com/foo/bar")
        go_no_ver = next(d for d in data["dependencies"] if d["name"] == "github.com/baz/qux")
        assert go_with_ver["package_url"] == "https://pkg.go.dev/github.com/foo/bar@v1.0.0"
        assert go_no_ver["package_url"] == "https://pkg.go.dev/github.com/baz/qux"

    def test_package_url_java_routes_to_sonatype_central(self):
        # Java/JVM packages link to Sonatype Central — the canonical
        # human-facing UI for Maven Central. URL shape:
        # ``central.sonatype.com/artifact/{groupId}/{artifactId}[/{version}]``.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "org.springframework:spring-core",
                    "Apache-2.0",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.JAVA,
                    resolved_version="5.3.20",
                ),
                _make_result(
                    "junit:junit",
                    "EPL-1.0",
                    RiskLevel.WEAK_COPYLEFT,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.JAVA,
                ),
            ],
        )
        data = json.loads(render_json(report))
        spring = next(
            d for d in data["dependencies"] if d["name"] == "org.springframework:spring-core"
        )
        junit = next(d for d in data["dependencies"] if d["name"] == "junit:junit")
        assert spring["package_url"] == (
            "https://central.sonatype.com/artifact/org.springframework/spring-core/5.3.20"
        )
        # Without a resolved version, the URL still resolves to the
        # artifact's landing page (Sonatype Central redirects to latest).
        assert junit["package_url"] == ("https://central.sonatype.com/artifact/junit/junit")

    def test_package_url_java_malformed_coord_yields_empty(self):
        # A Java dep whose name doesn't contain ``:`` (malformed coord
        # — usually a discovery-side regression) yields empty rather
        # than emitting a broken URL.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "no-colon",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    ecosystem=Ecosystem.JAVA,
                ),
            ],
        )
        data = json.loads(render_json(report))
        bad = next(d for d in data["dependencies"] if d["name"] == "no-colon")
        assert bad["package_url"] == ""

    def test_package_url_dotnet_routes_to_nuget_org(self):
        # .NET packages link to NuGet.org — the canonical human-facing
        # UI. URL shape: ``www.nuget.org/packages/{id}[/{version}]``.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "Newtonsoft.Json",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.DOTNET,
                    resolved_version="13.0.1",
                ),
                _make_result(
                    "Serilog",
                    "Apache-2.0",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.DOTNET,
                ),
            ],
        )
        data = json.loads(render_json(report))
        newtonsoft = next(d for d in data["dependencies"] if d["name"] == "Newtonsoft.Json")
        serilog = next(d for d in data["dependencies"] if d["name"] == "Serilog")
        assert newtonsoft["package_url"] == "https://www.nuget.org/packages/Newtonsoft.Json/13.0.1"
        # Without a resolved version, the URL still resolves to the
        # landing page (nuget.org redirects to latest).
        assert serilog["package_url"] == "https://www.nuget.org/packages/Serilog"

    def test_package_url_php_routes_to_packagist(self):
        # PHP packages link to Packagist's canonical human-facing UI.
        # URL shape: ``packagist.org/packages/{vendor}/{package}``.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "monolog/monolog",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.PHP,
                    resolved_version="3.5.0",
                ),
            ],
        )
        data = json.loads(render_json(report))
        monolog = next(d for d in data["dependencies"] if d["name"] == "monolog/monolog")
        assert monolog["package_url"] == "https://packagist.org/packages/monolog/monolog"

    def test_package_url_ruby_routes_to_rubygems(self):
        # Ruby packages link to rubygems.org with /versions/{v} suffix when
        # a resolved version is available, otherwise just /gems/{name}.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "rails",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.RUBY,
                    resolved_version="7.1.3",
                ),
                _make_result(
                    "no-version-gem",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.RUBY,
                    resolved_version="",
                ),
            ],
        )
        data = json.loads(render_json(report))
        by_name = {d["name"]: d for d in data["dependencies"]}
        assert by_name["rails"]["package_url"] == "https://rubygems.org/gems/rails/versions/7.1.3"
        assert (
            by_name["no-version-gem"]["package_url"] == "https://rubygems.org/gems/no-version-gem"
        )

    def test_package_url_r_routes_to_cran(self):
        # R packages link to CRAN's canonical package page (no per-version URL).
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "jsonlite",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.R,
                    resolved_version="2.0.0",
                ),
            ],
        )
        data = json.loads(render_json(report))
        by_name = {d["name"]: d for d in data["dependencies"]}
        assert by_name["jsonlite"]["package_url"] == "https://cran.r-project.org/package=jsonlite"

    def test_package_url_hex_routes_to_hexpm(self):
        # Hex packages link to hex.pm with /{version} suffix when a resolved
        # version is available, otherwise just /packages/{name}.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "phoenix",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.HEX,
                    resolved_version="1.7.10",
                ),
                _make_result(
                    "no-version-pkg",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.HEX,
                    resolved_version="",
                ),
            ],
        )
        data = json.loads(render_json(report))
        by_name = {d["name"]: d for d in data["dependencies"]}
        assert by_name["phoenix"]["package_url"] == "https://hex.pm/packages/phoenix/1.7.10"
        assert by_name["no-version-pkg"]["package_url"] == "https://hex.pm/packages/no-version-pkg"

    def test_package_url_hex_renamed_links_to_real_package(self):
        # A `hex:`-renamed dep displays under its local app name but links to
        # the real hex.pm package (registry_name), not the alias.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "my_dep",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.HEX,
                    resolved_version="1.0.0",
                    registry_name="real_pkg",
                ),
            ],
        )
        data = json.loads(render_json(report))
        dep = data["dependencies"][0]
        assert dep["name"] == "my_dep"
        assert dep["package_url"] == "https://hex.pm/packages/real_pkg/1.0.0"

    def test_empty_report(self):
        report = AnalysisReport(project_license="MIT")
        output = render_json(report)
        data = json.loads(output)
        assert data["elapsed_seconds"] == 0.0
        assert data["summary"]["total"] == 0
        assert data["dependencies"] == []


class TestRenderMarkdown:
    def test_detected_license_label_without_raw_suffix(self):
        result = _make_result(
            "mystery",
            "UNKNOWN",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            resolved_version="1.0.0",
            license_raw="UNKNOWN",
            reviewed_license_id="MIT",
        )
        assert _detected_license_label(result) == "UNKNOWN"

    def test_markdown_license_label_empty(self):
        assert _markdown_license_label("") == ""

    def test_markdown_structure(self):
        report = _sample_report()
        md = render_markdown(report)
        assert "# License Analysis Report" in md
        assert "**Project license:** MIT" in md
        assert "|Package|Ecosystem|Group|Source|License|Risk|Status|" in md
        assert "[requests (2.31.0)](https://pypi.org/project/requests/)" in md
        assert "[Apache-2.0](https://spdx.org/licenses/Apache-2.0.html)" in md
        assert "**Summary:**" in md
        assert "\n**Summary:** 1 violation, 1 warning, 1 unknown, 3 ok\n\n" in md
        assert "Completed in" not in md
        assert "1 violation," in md
        assert f"_{_REPORT_NOTE.replace('licenseal check', '`licenseal check`')}_" in md
        assert not md.endswith("\n")

    def test_markdown_does_not_depend_on_run_time(self):
        # The Markdown report is meant to be checked in (LICENSES.md): two
        # scans with the same findings must render identically, however long
        # each took, or the file changes on every run.
        slow = _sample_report()
        slow.elapsed_seconds = 83.7
        assert render_markdown(slow) == render_markdown(_sample_report())

    def test_render_check_failure(self):
        report = _sample_report()
        failing = report.violations + report.warnings
        text = render_check_failure(
            report, failing, gap_count=2, output_file=Path("reports/LICENSES.md")
        )
        lines = text.splitlines()
        assert lines[0] == "License check failed: 1 violation, 1 warning, 1 unknown, 3 ok"
        assert lines[1] == f"  ✗ {report.violations[0].reason}"
        assert lines[2] == f"  ⚠ {report.warnings[0].reason}"
        assert lines[3] == "  2 manifest(s) could not be fully analyzed (see the warnings above)"
        assert lines[4] == f"Full report: {Path('reports/LICENSES.md')}"

    def test_render_check_failure_without_gaps(self):
        report = _sample_report()
        text = render_check_failure(
            report, report.violations, gap_count=0, output_file=Path("LICENSES.md")
        )
        assert "could not be fully analyzed" not in text
        assert len(text.splitlines()) == 3

    def test_markdown_compound_license_links_each_part(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "packaging",
                    "Apache-2.0 OR BSD-2-Clause",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                )
            ],
        )
        md = render_markdown(report)
        assert (
            "[Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) OR "
            "[BSD-2-Clause](https://spdx.org/licenses/BSD-2-Clause.html)"
        ) in md

    def test_markdown_with_exception_keeps_operator_plain(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "pkg",
                    "Apache-2.0 WITH LLVM-exception",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                )
            ],
        )
        md = render_markdown(report)
        assert "[Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) WITH " in md
        assert "](https://spdx.org/licenses/WITH.html)" not in md

    def test_markdown_package_link_falls_back_to_registry(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "pytest-cov",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                )
            ],
        )
        md = render_markdown(report)
        assert "[pytest-cov](https://pypi.org/project/pytest-cov/)" in md

    def test_markdown_details(self):
        report = _sample_report()
        md = render_markdown(report)
        assert "## Details" in md
        assert "GPL is incompatible with MIT" in md

    def test_markdown_reviewed_section_and_summary(self):
        report = AnalysisReport(
            project_license="MIT",
            elapsed_seconds=0.42,
            results=[
                _make_result(
                    "mystery",
                    "UNKNOWN",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    resolved_version="1.0.0",
                    license_raw="Custom internal license",
                    reviewed_license_id="MIT",
                    review_note="confirmed manually",
                )
            ],
        )
        md = render_markdown(report)
        assert "**Summary:** 0 violations, 0 warnings, 0 unknown, 1 ok (of which 1 reviewed)" in md
        assert "## Reviewed" in md
        assert "|Package|Detected|Reviewed|Note|" in md
        assert "[mystery (1.0.0)](https://pypi.org/project/mystery/)" in md
        assert "UNKNOWN (raw: Custom internal license)" in md
        assert "[MIT](https://spdx.org/licenses/MIT.html)" in md
        assert "confirmed manually" in md

    def test_markdown_review_note_strips_newlines(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "mystery",
                    "UNKNOWN",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    resolved_version="1.0.0",
                    license_raw="Custom",
                    reviewed_license_id="MIT",
                    review_note="line one\nline two\r\nline three",
                ),
            ],
        )
        md = render_markdown(report)
        review_row = next(line for line in md.splitlines() if "line one" in line)
        assert "\n" not in review_row
        assert "line one line two line three" in review_row
        # Each table row must remain a single line (one leading + one trailing pipe).
        assert review_row.count("|") == 5

    def test_markdown_empty(self):
        report = AnalysisReport(project_license="MIT")
        md = render_markdown(report)
        assert "# License Analysis Report" in md
        assert "0 violations" in md

    def test_markdown_proprietary_project_license(self):
        report = AnalysisReport(project_license="Proprietary")
        md = render_markdown(report)
        assert "Proprietary" in md

    def test_markdown_all_ok(self):
        report = AnalysisReport(
            project_license="MIT",
            elapsed_seconds=0.42,
            results=[
                _make_result("pkg", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE),
            ],
        )
        md = render_markdown(report)
        assert "## Details" not in md  # No details when all ok

    def test_json_or_expression_picks_lowest_risk_component(self):
        # OR expressions resolve to the least restrictive component (most
        # permissive). Both leaves are permissive here; either could win
        # depending on tie-breaking, but the URL must point at one of them
        # — not be empty as the old behavior was.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "packaging",
                    "Apache-2.0 OR BSD-2-Clause",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                )
            ],
        )
        data = json.loads(render_json(report))
        dep = data["dependencies"][0]
        assert dep["license_url"] in (
            "https://spdx.org/licenses/Apache-2.0.html",
            "https://spdx.org/licenses/BSD-2-Clause.html",
        )

    def test_license_url_for_canonical_spdx_id(self):
        # A real SPDX ID gets the canonical spdx.org URL.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p", "Apache-2.0", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE
                )
            ],
        )
        data = json.loads(render_json(report))
        assert data["dependencies"][0]["license_url"] == "https://spdx.org/licenses/Apache-2.0.html"

    def test_license_url_strips_or_later_suffix(self):
        # `MPL-2.0+` should link to the MPL-2.0 page (SPDX has one page per
        # base ID; `+` is an expression operator, not part of the URL).
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result("p", "MPL-2.0+", RiskLevel.WEAK_COPYLEFT, CompatibilityVerdict.WARNING)
            ],
        )
        data = json.loads(render_json(report))
        assert data["dependencies"][0]["license_url"] == "https://spdx.org/licenses/MPL-2.0.html"

    def test_license_url_empty_for_non_canonical_string(self):
        # A made-up or wrong-cased string must not produce a known-404 URL.
        # `BSD-5-Clause` doesn't exist in the SPDX list.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result("p", "BSD-5-Clause", RiskLevel.UNKNOWN, CompatibilityVerdict.UNKNOWN)
            ],
        )
        data = json.loads(render_json(report))
        assert data["dependencies"][0]["license_url"] == ""

    def test_license_url_covers_obscure_spdx_ids(self):
        # Licenses we never enumerated in _RISK_OVERRIDES still get URLs,
        # because the URL generator looks at the canonical SPDX list, not at
        # our risk map.
        for spdx_id in ("Beerware", "OFL-1.1", "X11", "OLDAP-2.8", "AFL-3.0"):
            report = AnalysisReport(
                project_license="MIT",
                results=[
                    _make_result(
                        "p", spdx_id, RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE
                    )
                ],
            )
            data = json.loads(render_json(report))
            assert data["dependencies"][0]["license_url"] == (
                f"https://spdx.org/licenses/{spdx_id}.html"
            ), f"missing URL for {spdx_id!r}"

    def test_license_url_or_picks_lowest_risk(self):
        # `MIT OR GPL-3.0-only` — OR returns the most permissive, so MIT wins
        # over the strong-copyleft GPL component.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "MIT OR GPL-3.0-only",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                )
            ],
        )
        data = json.loads(render_json(report))
        assert data["dependencies"][0]["license_url"] == "https://spdx.org/licenses/MIT.html"

    def test_license_url_and_picks_highest_risk(self):
        # `MIT AND GPL-3.0-only` — AND returns the most restrictive component
        # because both terms must apply.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "MIT AND GPL-3.0-only",
                    RiskLevel.STRONG_COPYLEFT,
                    CompatibilityVerdict.INCOMPATIBLE,
                )
            ],
        )
        data = json.loads(render_json(report))
        assert (
            data["dependencies"][0]["license_url"] == "https://spdx.org/licenses/GPL-3.0-only.html"
        )

    def test_license_url_with_picks_base_license(self):
        # `GPL-2.0-only WITH Classpath-exception-2.0` — WITH yields the base.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "GPL-2.0-only WITH Classpath-exception-2.0",
                    RiskLevel.STRONG_COPYLEFT,
                    CompatibilityVerdict.INCOMPATIBLE,
                )
            ],
        )
        data = json.loads(render_json(report))
        assert (
            data["dependencies"][0]["license_url"] == "https://spdx.org/licenses/GPL-2.0-only.html"
        )

    def test_license_url_strips_outer_parens(self):
        # `(MIT OR Apache-2.0)` — parens get stripped before splitting.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "(MIT OR Apache-2.0)",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                )
            ],
        )
        data = json.loads(render_json(report))
        assert data["dependencies"][0]["license_url"] in (
            "https://spdx.org/licenses/MIT.html",
            "https://spdx.org/licenses/Apache-2.0.html",
        )

    def test_license_url_expression_with_no_known_component(self):
        # Expression where no leaf resolves to a known SPDX ID — empty.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "Custom-Foo OR Custom-Bar",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                )
            ],
        )
        data = json.loads(render_json(report))
        assert data["dependencies"][0]["license_url"] == ""

    def test_license_url_licenseref_still_rejected(self):
        # LicenseRef-* IDs don't have an SPDX page.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "LicenseRef-Custom",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                )
            ],
        )
        data = json.loads(render_json(report))
        assert data["dependencies"][0]["license_url"] == ""

    def test_homepage_url_emitted_in_json(self):
        # New field passes through from LicenseInfo.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    repository_url="https://github.com/example/p",
                    homepage_url="https://example.com/p",
                )
            ],
        )
        data = json.loads(render_json(report))
        dep = data["dependencies"][0]
        assert dep["repository_url"] == "https://github.com/example/p"
        assert dep["homepage_url"] == "https://example.com/p"

    def test_actionability_absent_for_compatible(self):
        # Compatible deps don't carry an actionability block.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result("p", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE)
            ],
        )
        data = json.loads(render_json(report))
        assert "actionability" not in data["dependencies"][0]

    def test_actionability_present_for_warning(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "MPL-2.0",
                    RiskLevel.WEAK_COPYLEFT,
                    CompatibilityVerdict.WARNING,
                    repository_url="https://github.com/example/p",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert a["investigate_url"] == "https://spdx.org/licenses/MPL-2.0.html"
        assert any("https://spdx.org/licenses/MPL-2.0.html" in step for step in a["next_steps"])
        assert any("github.com/example/p" in step for step in a["next_steps"])

    def test_actionability_unknown_uses_repo_or_homepage(self):
        # Unknown verdict with no license_url falls through to repo URL, and
        # next_steps embeds the GitHub LICENSE-file hint path.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    repository_url="https://github.com/example/p",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert a["investigate_url"] == "https://github.com/example/p"
        assert (
            a["next_steps"][0]
            == "Inspect LICENSE file at https://github.com/example/p/blob/HEAD/LICENSE"
        )

    def test_actionability_unknown_uses_gitlab_hint(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    repository_url="https://gitlab.com/group/project",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert (
            a["next_steps"][0]
            == "Inspect LICENSE file at https://gitlab.com/group/project/-/blob/HEAD/LICENSE"
        )

    def test_actionability_unknown_uses_bitbucket_hint(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    repository_url="https://bitbucket.org/owner/repo",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert (
            a["next_steps"][0]
            == "Inspect LICENSE file at https://bitbucket.org/owner/repo/src/HEAD/LICENSE"
        )

    def test_actionability_unknown_uses_codeberg_hint(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    repository_url="https://codeberg.org/owner/repo",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert (
            a["next_steps"][0]
            == "Inspect LICENSE file at https://codeberg.org/owner/repo/src/branch/HEAD/LICENSE"
        )

    def test_actionability_unknown_ignores_embedded_forge_hostname(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    repository_url="https://evil.example/://codeberg.org/owner/repo",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert (
            a["next_steps"][0]
            == "Inspect LICENSE file at https://evil.example/://codeberg.org/owner/repo"
        )

    def test_actionability_unknown_non_http_repo_uses_bare_url(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    repository_url="git://github.com/owner/repo",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert a["next_steps"][0] == "Inspect LICENSE file at git://github.com/owner/repo"

    def test_actionability_unknown_unknown_host_uses_bare_repo_url(self):
        # Self-hosted Gitea / SourceHut / random forge: no hint path; fall
        # back to the bare URL so the agent can navigate the file tree.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    repository_url="https://git.sr.ht/~owner/repo",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert a["next_steps"][0] == "Inspect LICENSE file at https://git.sr.ht/~owner/repo"

    def test_actionability_warning_uses_file_hint(self):
        # WARNING verdicts also get the hint in their "Confirm license text"
        # step so a reviewer can quickly cross-check the file.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "MPL-2.0",
                    RiskLevel.WEAK_COPYLEFT,
                    CompatibilityVerdict.WARNING,
                    repository_url="https://github.com/example/p",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert any(
            "https://github.com/example/p/blob/HEAD/LICENSE" in step for step in a["next_steps"]
        )

    def test_actionability_falls_through_to_homepage(self):
        # Unknown verdict with no license_url, no repo_url → homepage_url.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    homepage_url="https://example.com/p",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert a["investigate_url"] == "https://example.com/p"

    def test_actionability_falls_through_to_package_url(self):
        # No URLs at all → package_url is the last resort and is always set.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "UNKNOWN",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert a["investigate_url"] == "https://pypi.org/project/p/"

    def test_actionability_incompatible_includes_registry_step(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "p",
                    "GPL-3.0-only",
                    RiskLevel.STRONG_COPYLEFT,
                    CompatibilityVerdict.INCOMPATIBLE,
                    repository_url="https://github.com/example/p",
                )
            ],
        )
        data = json.loads(render_json(report))
        a = data["dependencies"][0]["actionability"]
        assert any("GPL-3.0-only is incompatible" in s for s in a["next_steps"])
        assert any("pypi.org/project/p" in s for s in a["next_steps"])


class TestHierarchicalLayout:
    def test_other_ancestors_suffix_empty_for_direct(self):

        result = _make_result("a", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE)
        assert _other_ancestors_suffix(result) == ""

    def test_other_ancestors_suffix_empty_for_single_ancestor(self):

        result = _make_result(
            "child",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("root",),
        )
        assert _other_ancestors_suffix(result) == ""

    def test_other_ancestors_suffix_lists_extras(self):

        r2 = _make_result(
            "shared",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("a", "b"),
        )
        assert _other_ancestors_suffix(r2) == " (also: b)"

        r3 = _make_result(
            "shared",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("a", "b", "c"),
        )
        assert _other_ancestors_suffix(r3) == " (also: b, c)"

        r5 = _make_result(
            "shared",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("a", "b", "c", "d", "e"),
        )
        assert _other_ancestors_suffix(r5) == " (also: b, c +2 more)"

    def test_grouped_results_appends_orphan_transitives_at_end(self):

        a = _make_result("a", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE)
        # Transitive whose first ancestor is NOT in the report — appended at the
        # end as an orphan (defensive path; the orphan-filter normally drops these
        # before they reach the report).
        orphan = _make_result(
            "orphan-trans",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("missing-direct",),
        )
        ordered = _grouped_results([orphan, a])
        names = [r.license_info.dependency.name for r in ordered]
        assert names == ["a", "orphan-trans"]

    def test_grouped_results_nests_transitives_under_first_ancestor(self):

        a = _make_result("a", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE)
        b = _make_result("b", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE)
        shared = _make_result(
            "shared",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("a", "b"),
        )
        a_only = _make_result(
            "a-only",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("a",),
        )
        ordered = _grouped_results([b, shared, a_only, a])
        names = [r.license_info.dependency.name for r in ordered]
        # `a` direct then its transitives a-only, shared (sorted alphabetically),
        # then `b` direct (shared is NOT re-listed under b).
        assert names == ["a", "a-only", "shared", "b"]

    def test_grouped_results_lists_transitives_once_under_duplicate_direct_rows(self):
        # Two direct rows for one package (two resolved versions): the shared
        # transitive is listed once, under the row with the first version,
        # whatever order the results arrive in.
        def root(version: str) -> CompatibilityResult:
            return _make_result(
                "root",
                "MIT",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                resolved_version=version,
            )

        child = _make_result(
            "child",
            "MIT",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("root",),
        )
        for results in (
            [root("2.0.0"), root("1.0.0"), child],
            [child, root("1.0.0"), root("2.0.0")],
        ):
            ordered = _grouped_results(results)
            assert [
                (r.license_info.dependency.name, r.license_info.resolved_version) for r in ordered
            ] == [("root", "1.0.0"), ("child", ""), ("root", "2.0.0")]

    def test_grouped_results_matches_ancestors_within_their_ecosystem(self):
        def result(name: str, ecosystem: Ecosystem, ancestors: tuple[str, ...] = ()):
            return _make_result(
                name,
                "MIT",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                ecosystem=ecosystem,
                depth=1 if ancestors else 0,
                direct_ancestors=ancestors,
            )

        results = [
            result("shared", Ecosystem.PYTHON),
            result("shared", Ecosystem.NPM),
            result("python-child", Ecosystem.PYTHON, ("shared",)),
            # Its only ancestor name belongs to roots of other ecosystems.
            result("stray", Ecosystem.RUST, ("shared",)),
        ]
        ordered = _grouped_results(results)
        assert [
            (r.license_info.dependency.ecosystem.value, r.license_info.dependency.name)
            for r in ordered
        ] == [
            ("npm", "shared"),
            ("python", "shared"),
            ("python", "python-child"),
            ("rust", "stray"),
        ]

    def test_duplicate_direct_rows_do_not_repeat_rows_details_or_reviews(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "root",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    resolved_version=version,
                )
                for version in ("1.0.0", "2.0.0")
            ]
            + [
                _make_result(
                    "child",
                    "UNKNOWN",
                    RiskLevel.STRONG_COPYLEFT,
                    CompatibilityVerdict.INCOMPATIBLE,
                    reason="child is under a copyleft license",
                    resolved_version="0.3.0",
                    reviewed_license_id="GPL-3.0-only",
                    review_note="confirmed in the repository",
                    depth=1,
                    direct_ancestors=("root",),
                ),
            ],
        )
        total = json.loads(render_json(report))["summary"]["total"]

        md = render_markdown(report)
        main_table, _, reviewed_table = md.partition("## Reviewed")
        assert sum(line.startswith("|") for line in main_table.splitlines()) - 2 == total == 3
        assert "**Summary:** 1 violation, " in md
        assert md.count("- ✗ child is under a copyleft license") == 1
        assert reviewed_table.count("[child (0.3.0)]") == 1

        console, buf = _make_console()
        render_table(report, console)
        table = buf.getvalue()
        assert table.count("└─ child (0.3.0)") == 1
        assert "1 violation" in table
        assert table.count("child is under a copyleft license") == 1
        assert table.count("confirmed in the repository") == 1

    def test_table_renders_indented_transitive_with_also_suffix(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result("a", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE),
                _make_result("b", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE),
                _make_result(
                    "shared",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    depth=1,
                    direct_ancestors=("a", "b"),
                ),
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "└─ shared" in output
        assert "(also: b)" in output

    def test_markdown_links_source_path_for_direct_deps(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "click",
                    "BSD-3-Clause",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    source="pyproject.toml",
                ),
                _make_result(
                    "colorama",
                    "BSD-3-Clause",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    depth=1,
                    direct_ancestors=("click",),
                ),
            ],
        )
        md = render_markdown(report)
        # Direct dep: source rendered as a relative-path link.
        assert "[pyproject.toml](pyproject.toml)" in md
        # Transitive: empty Source cell — no link.
        # Verify by finding the colorama row and confirming it has consecutive pipes
        # surrounding an empty Source cell.
        colorama_row = next(line for line in md.splitlines() if "colorama" in line)
        # ...|npm-or-python|prod|<source>|<license>|... — empty source means ||
        assert "|prod||" in colorama_row

    def test_source_terminal_url_builds_file_uri_for_direct_deps(self, tmp_path):

        result = _make_result(
            "click",
            "BSD-3-Clause",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            source="pyproject.toml",
        )
        url = _source_terminal_url(result, tmp_path)
        assert url.startswith("file://")
        assert url.endswith("pyproject.toml")

    def test_source_terminal_url_empty_for_transitive(self, tmp_path):

        result = _make_result(
            "colorama",
            "BSD-3-Clause",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            depth=1,
            direct_ancestors=("click",),
        )
        assert _source_terminal_url(result, tmp_path) == ""

    def test_source_terminal_url_empty_when_no_project_path(self):

        result = _make_result(
            "click",
            "BSD-3-Clause",
            RiskLevel.PERMISSIVE,
            CompatibilityVerdict.COMPATIBLE,
            source="pyproject.toml",
        )
        assert _source_terminal_url(result, None) == ""

    def test_table_renders_clickable_source_link(self, tmp_path):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "click",
                    "BSD-3-Clause",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    source="pyproject.toml",
                ),
            ],
        )
        # A terminal with its capabilities pinned, so rich emits OSC-8
        # hyperlinks whatever TERM the tests run under.
        console, buf = _make_terminal_console()
        render_table(report, console, project_path=tmp_path)
        output = buf.getvalue()
        # OSC-8 hyperlink escape should reference a file:// URI.
        assert "file://" in output
        assert "pyproject.toml" in output

    def test_json_includes_source_url(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "click",
                    "BSD-3-Clause",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    source="requirements-dev.txt",
                ),
            ],
        )
        data = json.loads(render_json(report))
        dep = data["dependencies"][0]
        assert dep["source"] == "requirements-dev.txt"
        assert dep["source_url"] == "requirements-dev.txt"

    def test_markdown_renders_indented_transitive(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result("root", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE),
                _make_result(
                    "child",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    depth=1,
                    direct_ancestors=("root",),
                ),
            ],
        )
        md = render_markdown(report)
        assert "└─ " in md  # indent prefix for transitive


class TestPickUrlLeaf:
    def test_empty_input_returns_empty(self):
        assert _pick_url_leaf("") == ""
        assert _pick_url_leaf("   ") == ""


class TestPickFromParts:
    def test_returns_empty_when_no_part_resolves_to_canonical_url(self):
        # Junk inputs — neither produces a canonical SPDX URL, so candidates
        # stays empty and we return "".
        assert _pick_from_parts(["NotALicense", "AlsoNotALicense"], prefer_lower=True) == ""

    def test_skips_canonical_ids_with_unknown_risk(self):
        # BUSL-1.1 and SSPL-1.0 are canonical SPDX IDs (so _spdx_canonical_url
        # returns a URL), but both classify to RiskLevel.UNKNOWN — the
        # function must skip them rather than picking one. With no
        # surviving candidate, it returns "".
        assert _pick_from_parts(["BUSL-1.1", "SSPL-1.0"], prefer_lower=True) == ""

    def test_license_url_compound_with_no_resolvable_leaf_returns_empty(self):
        # Public surface for the empty-candidates path.
        assert _license_url("NotALicense OR AlsoNotALicense") == ""


class TestActionabilityWarning:
    def test_warning_without_license_url_still_emits_file_hint_and_decide(self):
        info = LicenseInfo(
            dependency=Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON),
            license_id="GPL-3.0-only",
            license_raw="GPL-3.0-only",
            resolved_version="1.0.0",
            repository_url="https://github.com/example/pkg",
        )
        result = CompatibilityResult(
            license_info=info,
            risk_level=RiskLevel.STRONG_COPYLEFT,
            verdict=CompatibilityVerdict.WARNING,
        )
        action = _actionability(
            result,
            license_url="",
            repository_url="https://github.com/example/pkg",
            homepage_url="",
            package_url="https://pypi.org/project/pkg/",
        )
        assert action is not None
        steps = action["next_steps"]
        assert all("Verify license terms" not in s for s in steps)
        assert any("Confirm license text" in s for s in steps)


class TestUntrustedStrings:
    """Registry- and manifest-derived strings are escaped for display only."""

    def test_printable_shows_control_characters(self):
        assert _printable("a\x1b[2Jb\x9bc\x7fd\x00") == "a\\x1b[2Jb\\x9bc\\x7fd\\x00"
        # Line breaks and tabs fold to a space, a CRLF pair to a single one.
        assert _printable("one\r\ntwo\nthree\rfour\tfive") == "one two three four five"
        assert _printable("plain (text) — ✓") == "plain (text) — ✓"

    def test_table_file_output_has_no_control_characters(self):
        console, buf = _make_console(width=300)
        render_table(_hostile_report(), console)
        output = buf.getvalue()
        assert not _RAW_CONTROL.search(output)
        assert "Project license: MIT\\x1b]0;title\\x07" in output
        assert "pkg\\x1b[31m (1.0\\x00)" in output
        assert "Evil\\x1b[2J\\x9b31m" in output
        assert "dir\\x1b[1m/requirements.txt" in output
        assert "(also: other\\x08)" in output
        # A carriage return can't move the cursor back to forge a line.
        assert "which did not resolve Summary: 0 violations" in output
        assert "UNKNOWN (raw: raw\\x1b[5m)" in output
        assert "line one line two tabbed\\x1b[0m\\x7f" in output

    def test_table_terminal_output_carries_only_its_own_escape_sequences(self):
        console, buf = _make_terminal_console()
        render_table(_hostile_report(), console)
        output = buf.getvalue()
        # The console's own styling is there; none of the hostile sequences is.
        assert "\x1b[" in output
        for raw in ("\x1b[2J", "\x1b[5m", "\x1b]0;", "\x9b", "\x07", "\x08", "\x00", "\x7f", "\r"):
            assert raw not in output
        assert "Evil\\x1b[2J\\x9b31m" in output
        # The hyperlink target is percent-encoded, so it can't end the sequence.
        assert "https://pypi.org/project/pkg%1B%5B31m/" in output

    def test_markdown_has_no_control_characters(self):
        md = render_markdown(_hostile_report())
        assert not _RAW_CONTROL.search(md)
        assert "**Project license:** MIT\\\\x1b\\]0;title\\\\x07" in md
        assert (
            "|[pkg\\\\x1b\\[31m (1.0\\\\x00)](https://pypi.org/project/pkg%1B%5B31m/)|python|prod|"
            "[dir\\\\x1b\\[1m/requirements.txt](dir%1B%5B1m/requirements.txt)|"
            "Evil\\\\x1b\\[2J\\\\x9b31m|unknown|?|"
        ) in md
        assert (
            "- ? pkg declares 'Evil\\\\x1b\\[2J' which did not resolve Summary: 0 violations"
        ) in md
        assert "|line one line two tabbed\\\\x1b\\[0m\\\\x7f|" in md

    def test_check_failure_message_has_no_control_characters(self):
        report = _hostile_report()
        text = render_check_failure(
            report, report.unknown, gap_count=0, output_file=Path("LICENSES.md")
        )
        assert not _RAW_CONTROL.search(text)
        assert "  ? pkg declares 'Evil\\x1b[2J' which did not resolve Summary: 0 violations" in text

    def test_json_keeps_strings_verbatim(self):
        data = json.loads(render_json(_hostile_report()))
        dep = next(d for d in data["dependencies"] if d["name"] == "pkg\x1b[31m")
        assert dep["license"] == dep["license_raw"] == "Evil\x1b[2J\x9b31m"
        assert dep["resolved_version"] == "1.0\x00"
        assert dep["source"] == dep["source_url"] == "dir\x1b[1m/requirements.txt"
        assert dep["reason"].endswith("which did not resolve\rSummary: 0 violations")
        assert dep["package_url"] == "https://pypi.org/project/pkg%1B%5B31m/"
        assert data["project_license"] == "MIT\x1b]0;title\x07"

    @pytest.mark.parametrize("name", ["brack[et", "tag[bold]x[/bold]", "close]d", "[/link]", "\\"])
    def test_table_renders_console_markup_in_names_literally(self, name):
        # A ``[`` in a name used to raise a markup error after the whole scan.
        report = AnalysisReport(
            project_license="[red]MIT[/red]",
            results=[
                _make_result(
                    name,
                    "[bold]Custom[/bold]",
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    ecosystem=Ecosystem.NPM,
                    reason=f"{name} declares '[bold]Custom[/bold]' [/dim]",
                    resolved_version="1.0.0[/cyan]",
                    source=f"{name}/package.json",
                ),
                _make_result(
                    "child",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.NPM,
                    depth=1,
                    direct_ancestors=(name, "[i]other[/i]"),
                    resolved_version="2.0.0",
                    reviewed_license_id="MIT",
                    review_note="see [link=https://example.invalid]the notes[/link]",
                ),
            ],
        )
        console, buf = _make_console(width=300)
        render_table(report, console)
        output = buf.getvalue()
        assert f"{name} (1.0.0[/cyan])" in output
        assert "Project license: [red]MIT[/red]" in output
        assert "[bold]Custom[/bold]" in output
        assert f"{name} declares '[bold]Custom[/bold]' [/dim]" in output
        assert "(also: [i]other[/i])" in output
        assert "see [link=https://example.invalid]the notes[/link]" in output

        # Styled output goes through the same code without a markup error.
        terminal, _ = _make_terminal_console()
        render_table(report, terminal)

    def test_table_link_targets_are_percent_encoded(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result(
                    "brack[et]",
                    "MIT",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.NPM,
                    resolved_version="1.0.0",
                ),
            ],
        )
        console, buf = _make_terminal_console()
        render_table(report, console)
        output = buf.getvalue()
        assert "https://www.npmjs.com/package/brack%5Bet%5D" in output
        assert "brack[et] (1.0.0)" in output

    def test_markdown_escapes_link_cell_and_bullet_syntax(self):
        name = "a](https://evil.example)[b"
        license_id = "![x](https://evil.example/p.png)<img/src=x>|`code`\\"
        report = AnalysisReport(
            project_license="<b>MIT</b>",
            results=[
                _make_result(
                    name,
                    license_id,
                    RiskLevel.UNKNOWN,
                    CompatibilityVerdict.UNKNOWN,
                    ecosystem=Ecosystem.NPM,
                    reason=f"{name} declares '{license_id}' which did not resolve",
                    resolved_version="1.0.0",
                    source="my dir/(group)/package.json",
                ),
                _make_result(
                    "child",
                    "UNKNOWN",
                    RiskLevel.PERMISSIVE,
                    CompatibilityVerdict.COMPATIBLE,
                    ecosystem=Ecosystem.NPM,
                    depth=1,
                    direct_ancestors=(name, "[other](https://evil.example)"),
                    resolved_version="2.0.0",
                    license_raw="<script>|raw",
                    reviewed_license_id="MIT",
                    review_note="see [the notes](https://evil.example) | `x` <b>",
                ),
            ],
        )
        md = render_markdown(report)
        lines = md.splitlines()

        assert "**Project license:** \\<b\\>MIT\\</b\\>" in lines
        row = next(line for line in lines if line.startswith("|[a"))
        assert row == (
            "|[a\\](https://evil.example)\\[b (1.0.0)]"
            "(https://www.npmjs.com/package/a%5D%28https%3A//evil.example%29%5Bb)"
            "|npm|prod|[my dir/(group)/package.json](my%20dir/%28group%29/package.json)"
            "|!\\[x\\](https://evil.example/p.png)\\<img/src=x\\>\\|\\`code\\`\\\\"
            "|unknown|?|"
        )
        child = next(line for line in lines if "└─ [child (2.0.0)]" in line)
        assert "(also: \\[other\\](https://evil.example))|npm|" in child
        assert (
            "- ? a\\](https://evil.example)\\[b declares "
            "'!\\[x\\](https://evil.example/p.png)\\<img/src=x\\>\\|\\`code\\`\\\\' "
            "which did not resolve"
        ) in lines
        assert (
            "|[child (2.0.0)](https://www.npmjs.com/package/child)"
            "|UNKNOWN (raw: \\<script\\>\\|raw)|[MIT](https://spdx.org/licenses/MIT.html)"
            "|see \\[the notes\\](https://evil.example) \\| \\`x\\` \\<b\\>|"
        ) in lines
        # No cell can add or remove a column: with escaped pipes set aside,
        # each dependency row still has its eight delimiters.
        for line in lines:
            if "|npm|" in line:
                assert len(re.sub(r"\\.", "", line).split("|")) == 9

    def test_markdown_of_well_formed_strings_is_not_escaped(self):
        # Parentheses, underscores, asterisks and ampersands are common in
        # names, versions and notes and need no escaping.
        report = AnalysisReport(
            project_license="Apache-2.0",
            results=[
                _make_result(
                    "@scope/typing_extensions",
                    "Apache-2.0 OR MIT",
                    RiskLevel.WEAK_COPYLEFT,
                    CompatibilityVerdict.WARNING,
                    ecosystem=Ecosystem.NPM,
                    reason="uses MPL-2.0 (weak copyleft) — review *this* & that; ok?",
                    resolved_version="1.0.0+build.5",
                    source="packages/@scope/web_app/package.json",
                    reviewed_license_id="MIT",
                    review_note="Unmodified dep (transitive via x); see #12 & docs/notes_v2.md!",
                ),
            ],
        )
        md = render_markdown(report)
        assert "\\" not in md
        assert "%" not in md
        assert (
            "|[@scope/typing_extensions (1.0.0+build.5)]"
            "(https://www.npmjs.com/package/@scope/typing_extensions)|npm|prod|"
            "[packages/@scope/web_app/package.json](packages/@scope/web_app/package.json)|"
        ) in md
        assert "- ⚠ uses MPL-2.0 (weak copyleft) — review *this* & that; ok?" in md

    def test_package_url_percent_encodes_names_and_versions(self):
        def url(name: str, ecosystem: Ecosystem, version: str = "", registry_name: str = "") -> str:
            report = AnalysisReport(
                project_license="MIT",
                results=[
                    _make_result(
                        name,
                        "MIT",
                        RiskLevel.PERMISSIVE,
                        CompatibilityVerdict.COMPATIBLE,
                        ecosystem=ecosystem,
                        resolved_version=version,
                        registry_name=registry_name,
                    )
                ],
            )
            dep = json.loads(render_json(report))["dependencies"][0]
            # Identity is never rewritten; only the derived link is encoded.
            assert dep["name"] == name
            assert dep["resolved_version"] == version
            return dep["package_url"]

        # Well-formed names and versions are written as before.
        assert url("@scope/pkg", Ecosystem.NPM) == "https://www.npmjs.com/package/@scope/pkg"
        assert url("github.com/Foo/bar.v2", Ecosystem.GO, "v2.0.0+incompatible") == (
            "https://pkg.go.dev/github.com/Foo/bar.v2@v2.0.0+incompatible"
        )
        assert url("vendor/pkg~x", Ecosystem.PHP) == "https://packagist.org/packages/vendor/pkg~x"
        # Anything else is encoded: no query, fragment, or stray delimiter.
        assert url("a b?c#d", Ecosystem.PYTHON) == "https://pypi.org/project/a%20b%3Fc%23d/"
        assert url("a%2Fb", Ecosystem.RUST) == "https://crates.io/crates/a%252Fb"
        assert url("g<r>:a(b)", Ecosystem.JAVA, "1 0") == (
            "https://central.sonatype.com/artifact/g%3Cr%3E/a%28b%29/1%200"
        )
        assert url("Pkg|x", Ecosystem.DOTNET, "1.0`") == (
            "https://www.nuget.org/packages/Pkg%7Cx/1.0%60"
        )
        assert url('gem"x', Ecosystem.RUBY, "1]") == (
            "https://rubygems.org/gems/gem%22x/versions/1%5D"
        )
        assert url("app", Ecosystem.HEX, "1[0", registry_name="real pkg") == (
            "https://hex.pm/packages/real%20pkg/1%5B0"
        )
        assert url("pkg x", Ecosystem.R) == "https://cran.r-project.org/package=pkg%20x"
        assert url("é", Ecosystem.NPM) == "https://www.npmjs.com/package/%C3%A9"


def _gap(path: str, reason: str = "is not valid TOML; skipped") -> ReportDiagnostic:
    return ReportDiagnostic(path=path, reason=reason, severity="gap")


_RECOVERED = ReportDiagnostic(
    path="requirements.txt",
    reason="decoded as latin-1 (not valid UTF-8); non-ASCII content may be wrong",
    severity="recovered",
)


class TestAnalysisGaps:
    """Manifests the scan could not analyze are listed in the saved reports."""

    @staticmethod
    def _table(report: AnalysisReport) -> str:
        console, buf = _make_console(width=200)
        render_table(report, console)
        return buf.getvalue()

    def test_report_without_gaps_is_unchanged(self):
        # A recovered read (latin-1 fallback) lost nothing and is not a gap.
        clean = _sample_report()
        recovered = _sample_report()
        recovered.read_diagnostics = [_RECOVERED]

        assert render_markdown(recovered) == render_markdown(clean)
        assert self._table(recovered) == self._table(clean)
        assert "nalysis gap" not in render_markdown(clean)
        assert "nalysis gap" not in self._table(clean)

    def test_markdown_lists_gaps(self):
        report = _sample_report()
        report.read_diagnostics = [
            _gap("services/api/pom.xml", "is not valid XML; skipped"),
            _RECOVERED,
            _gap("broken/pyproject.toml"),
        ]
        md = render_markdown(report)
        # After the summary, before Details; sorted by file.
        assert (
            "\n**Summary:** 1 violation, 1 warning, 1 unknown, 3 ok, 2 analysis gaps\n"
            "\n"
            "## Analysis gaps\n"
            "\n"
            "These manifests could not be fully analyzed; "
            "their dependencies may be missing from this report.\n"
            "\n"
            "|File|Reason|\n"
            "|------|--------|\n"
            "|[broken/pyproject.toml](broken/pyproject.toml)|is not valid TOML; skipped|\n"
            "|[services/api/pom.xml](services/api/pom.xml)|is not valid XML; skipped|\n"
            "\n"
            "## Details\n"
        ) in md
        assert "requirements.txt" not in md

    def test_table_lists_gaps(self):
        report = _sample_report()
        report.read_diagnostics = [
            _gap("services/api/pom.xml", "is not valid XML; skipped"),
            _RECOVERED,
            _gap("broken/pyproject.toml"),
        ]
        table = self._table(report)
        assert "  Summary: 1 violation, 1 warning, 1 unknown, 3 ok, 2 analysis gaps\n" in table
        assert (
            "  Analysis gaps (their dependencies may be missing from this report):\n"
            "    broken/pyproject.toml: is not valid TOML; skipped\n"
            "    services/api/pom.xml: is not valid XML; skipped\n"
            "\n"
            "  Details:\n"
        ) in table
        assert "requirements.txt" not in table

    def test_gap_count_is_distinct_files_as_in_json(self):
        # One file can carry more than one diagnostic; it is one gap.
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result("pkg", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE)
            ],
            read_diagnostics=[
                _gap("go.work", "references '/abs/module', which is not a relative path"),
                _gap("go.work", "references 'C:/module', which is not a relative path"),
            ],
        )
        assert json.loads(render_json(report))["summary"]["gaps"] == 1
        md = render_markdown(report)
        assert "**Summary:** 0 violations, 0 warnings, 0 unknown, 1 ok, 1 analysis gap\n" in md
        assert md.count("|[go.work](go.work)|references ") == 2
        table = self._table(report)
        assert "  Summary: 1 ok, 1 analysis gap\n" in table
        assert table.count("    go.work: references ") == 2

    def test_empty_report_with_a_gap_does_not_read_as_clean(self):
        clean = AnalysisReport(project_license="MIT")
        gapped = AnalysisReport(
            project_license="MIT",
            read_diagnostics=[_gap("package.json", "is not valid JSON; skipped")],
        )
        md = render_markdown(gapped)
        assert md != render_markdown(clean)
        assert "**Summary:** 0 violations, 0 warnings, 0 unknown, 0 ok, 1 analysis gap\n" in md
        assert "|[package.json](package.json)|is not valid JSON; skipped|" in md

        table = self._table(gapped)
        assert table != self._table(clean)
        assert "  Summary: 0 ok, 1 analysis gap\n" in table
        assert "    package.json: is not valid JSON; skipped\n" in table

    def test_file_outside_the_project_is_named_without_its_absolute_path(self, tmp_path):
        # The diagnostics view shows a file outside the scan root by its
        # absolute path. A saved report must not depend on the checkout
        # location, so only the file name is printed.
        outside = tmp_path / "shared" / "common.props"
        report = AnalysisReport(
            project_license="MIT",
            read_diagnostics=[
                _gap(str(outside), "is not valid XML; skipped"),
                _gap("z-last/pom.xml", "is not valid XML; skipped"),
                _gap("../sibling/go.mod", "could not be read (PermissionError); skipped"),
            ],
        )
        md = render_markdown(report)
        assert (
            "|[../sibling/go.mod](../sibling/go.mod)"
            "|could not be read (PermissionError); skipped|\n"
            "|common.props (outside the project directory)|is not valid XML; skipped|\n"
            "|[z-last/pom.xml](z-last/pom.xml)|is not valid XML; skipped|\n"
        ) in md
        table = self._table(report)
        assert (
            "    common.props (outside the project directory): is not valid XML; skipped" in table
        )
        for rendered in (md, table):
            assert str(tmp_path) not in rendered
            assert tmp_path.as_posix() not in rendered
            assert "shared" not in rendered
        # JSON keeps reporting the path it was given.
        paths = [d["path"] for d in json.loads(render_json(report))["diagnostics"]]
        assert paths == [str(outside), "z-last/pom.xml", "../sibling/go.mod"]

    def test_gap_paths_and_reasons_are_escaped(self):
        report = AnalysisReport(
            project_license="MIT",
            read_diagnostics=[
                _gap(
                    "we|ird [dir]/<b>/pyproject.toml",
                    "references '[x](https://evil.example)\x1b[2J', which is not `relative` | <i>",
                ),
            ],
        )
        md = render_markdown(report)
        assert (
            "|[we\\|ird \\[dir\\]/\\<b\\>/pyproject.toml]"
            "(we%7Cird%20%5Bdir%5D/%3Cb%3E/pyproject.toml)"
            "|references '\\[x\\](https://evil.example)\\\\x1b\\[2J', "
            "which is not \\`relative\\` \\| \\<i\\>|"
        ) in md.splitlines()
        assert not _RAW_CONTROL.search(md)

        table = self._table(report)
        assert (
            "    we|ird [dir]/<b>/pyproject.toml: references "
            "'[x](https://evil.example)\\x1b[2J', which is not `relative` | <i>\n"
        ) in table
        assert not _RAW_CONTROL.search(table)


_LONG_NAME = "@example-scope/client-identity-provider-bindings"
_HEADERS = ["Package", "Ecosystem", "Group", "Source", "License", "Risk", "Status"]


def _wide_report() -> AnalysisReport:
    """A report whose table needs more columns than a default console has."""
    return AnalysisReport(
        project_license="MIT",
        elapsed_seconds=0.42,
        results=[
            _make_result(
                _LONG_NAME,
                "Apache-2.0",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                ecosystem=Ecosystem.NPM,
                resolved_version="3.540.0",
                source="packages/web-frontend/package.json",
            ),
            _make_result(
                "network-thing",
                "AGPL-3.0-only",
                RiskLevel.NETWORK_COPYLEFT,
                CompatibilityVerdict.INCOMPATIBLE,
                ecosystem=Ecosystem.NPM,
                reason="network-thing uses AGPL-3.0-only",
                resolved_version="1.0.0",
                depth=1,
                direct_ancestors=(_LONG_NAME, "other"),
            ),
            _make_result(
                "dual",
                "LGPL-3.0-only OR (MIT AND BSD-3-Clause)",
                RiskLevel.WEAK_COPYLEFT,
                CompatibilityVerdict.WARNING,
                ecosystem=Ecosystem.NPM,
                reason="dual needs review",
                resolved_version="2.0.0",
                reviewed_license_id="LGPL-3.0-only",
                review_note="Unmodified dependency; only modified files carry the obligation.",
            ),
            _make_result(
                "mystery",
                "UNKNOWN",
                RiskLevel.UNKNOWN,
                CompatibilityVerdict.UNKNOWN,
                ecosystem=Ecosystem.NPM,
                reason="mystery has no license information",
            ),
        ],
    )


# The Package column of ``_wide_report``, top to bottom, without whitespace.
_WIDE_PACKAGES = f"{_LONG_NAME}(3.540.0)└─network-thing(1.0.0)(also:other)dual(2.0.0)mystery"


def _first_table(output: str) -> tuple[list[str], list[str]]:
    """Header lines and body lines of the first table in a rendered report.

    Reads the three box styles rich picks between: heavy-headed, square (a
    legacy Windows console) and ASCII (a stream that is not UTF-encoded).
    """
    lines = output.splitlines()
    top = next(i for i, line in enumerate(lines) if line.startswith(("┏", "┌", "+")))
    rule = next(i for i in range(top + 1, len(lines)) if lines[i].startswith(("┡", "├", "|-")))
    bottom = next(i for i in range(rule + 1, len(lines)) if lines[i].startswith(("└", "+")))
    return lines[top + 1 : rule], lines[rule + 1 : bottom]


def _cells(line: str) -> list[str]:
    """The cells of one table line, padding stripped."""
    return [cell.strip() for cell in re.split("[┃│|]", line)[1:-1]]


def _column(lines: list[str], index: int) -> str:
    """One column's text down ``lines``, with folds and all whitespace removed."""
    return "".join("".join(_cells(line)[index].split()) for line in lines)


class TestTableWidth:
    """No column is dropped or cut short, on a terminal or off it."""

    @pytest.mark.parametrize("width", [80, 120])
    def test_off_a_terminal_every_cell_is_whole(self, width):
        # 80 is what a stream that is not a terminal gets by default (a pipe,
        # a CI log); 120 is the width an ``-o`` table file starts from.
        console, buf = _make_console(width)
        render_table(_wide_report(), console)
        output = buf.getvalue()

        header, body = _first_table(output)
        assert [_cells(line) for line in header] == [_HEADERS]
        assert [_cells(line) for line in body] == [
            [
                f"{_LONG_NAME} (3.540.0)",
                "npm",
                "prod",
                "packages/web-frontend/package.json",
                "Apache-2.0",
                "permissive",
                "✓",
            ],
            [
                "└─ network-thing (1.0.0) (also: other)",
                "npm",
                "prod",
                "",
                "AGPL-3.0-only",
                "network-copyleft",
                "✗",
            ],
            ["dual (2.0.0)", "npm", "prod", "", "LGPL-3.0-only", "weak-copyleft", "⚠"],
            ["mystery", "npm", "prod", "", "UNKNOWN", "unknown", "?"],
        ]
        # The Reviewed table is laid out the same way: one line per row.
        reviewed = next(line for line in output.splitlines() if "Unmodified dependency" in line)
        assert _cells(reviewed) == [
            "dual (2.0.0)",
            "LGPL-3.0-only OR (MIT AND BSD-3-Clause)",
            "LGPL-3.0-only",
            "Unmodified dependency; only modified files carry the obligation.",
        ]
        assert "…" not in output

    def test_off_a_terminal_a_table_that_fits_leaves_the_width_alone(self):
        console, _ = _make_console()
        render_table(_sample_report(), console)
        assert console.width == 120

    def test_roomy_terminal_keeps_the_minimum_column_widths(self):
        report = AnalysisReport(
            project_license="MIT",
            results=[
                _make_result("pkg", "MIT", RiskLevel.PERMISSIVE, CompatibilityVerdict.COMPATIBLE)
            ],
        )
        console, buf = _make_terminal_console(120, styled=False)
        render_table(report, console)
        header, body = _first_table(buf.getvalue())
        assert header == [
            "┃ Package              ┃ Ecosystem ┃ Group ┃ Source       ┃ License      "
            "┃ Risk           ┃ Status ┃"
        ]
        assert body == [
            "│ pkg                  │ python    │ prod  │              │ MIT          "
            "│ permissive     │   ✓    │"
        ]

    @pytest.mark.parametrize("width", [100, 80])
    def test_narrow_terminal_folds_the_text_columns(self, width):
        console, buf = _make_terminal_console(width, styled=False)
        render_table(_wide_report(), console)
        output = buf.getvalue()

        assert max(len(line) for line in output.splitlines()) <= width
        header, body = _first_table(output)
        # All seven columns, with their headings on one line.
        assert [_cells(line) for line in header] == [_HEADERS]
        assert all(len(_cells(line)) == 7 for line in body)
        # The text columns fold: every character is still there.
        assert _column(body, 0) == _WIDE_PACKAGES
        assert _column(body, 3) == "packages/web-frontend/package.json"
        assert _column(body, 4) == "Apache-2.0AGPL-3.0-onlyLGPL-3.0-onlyUNKNOWN"
        assert "…" not in output
        # The fixed-vocabulary columns are not folded: one value per row.
        assert [cells[5] for line in body if (cells := _cells(line))[5]] == [
            "permissive",
            "network-copyleft",
            "weak-copyleft",
            "unknown",
        ]
        assert [cells[6] for line in body if (cells := _cells(line))[6]] == ["✓", "✗", "⚠", "?"]

    @pytest.mark.parametrize("width", [79, 60, 40])
    def test_terminal_under_80_columns_folds_every_column(self, width):
        console, buf = _make_terminal_console(width, styled=False)
        render_table(_wide_report(), console)
        output = buf.getvalue()

        assert max(len(line) for line in output.splitlines()) <= width
        header, body = _first_table(output)
        assert all(len(_cells(line)) == 7 for line in header + body)
        assert [_column(header, index) for index in range(7)] == _HEADERS
        assert _column(body, 0) == _WIDE_PACKAGES
        assert _column(body, 3) == "packages/web-frontend/package.json"
        assert _column(body, 5) == "permissivenetwork-copyleftweak-copyleftunknown"
        assert _column(body, 6) == "✓✗⚠?"
        assert "…" not in output


class TestGlyphFallback:
    """A stream that cannot encode the report's glyphs gets ASCII ones."""

    @staticmethod
    def _report() -> AnalysisReport:
        report = _sample_report()
        report.results.append(
            _make_result(
                "child",
                "MIT",
                RiskLevel.PERMISSIVE,
                CompatibilityVerdict.COMPATIBLE,
                depth=1,
                direct_ancestors=("flask",),
                resolved_version="1.0.0",
            )
        )
        return report

    def test_markdown_for_a_legacy_code_page(self):
        md = render_markdown(self._report(), encoding="cp1252")
        md.encode("cp1252")
        lines = md.splitlines()
        assert "|  +- [child (1.0.0)](https://pypi.org/project/child/)|python|prod||" in md
        assert sum(line.endswith("|permissive|OK|") for line in lines) == 4
        assert sum(line.endswith("|strong-copyleft|X|") for line in lines) == 1
        assert sum(line.endswith("|weak-copyleft|!|") for line in lines) == 1
        assert sum(line.endswith("|unknown|?|") for line in lines) == 1
        assert "- X GPL is incompatible with MIT" in lines
        assert "- ! Weak copyleft, review needed" in lines
        assert "- ? No license info" in lines

    def test_markdown_keeps_its_glyphs_where_they_can_be_encoded(self):
        report = self._report()
        md = render_markdown(report)
        assert md == render_markdown(report, encoding="utf-8")
        assert md == render_markdown(report, encoding="utf-16")
        assert "|  └─ [child (1.0.0)]" in md
        assert "|permissive|✓|" in md and "- ✗ GPL" in md and "- ⚠ Weak" in md

    def test_table_on_a_legacy_code_page_stream(self):
        raw = BytesIO()
        stream = TextIOWrapper(raw, encoding="cp1252", newline="")
        console = Console(
            file=stream, force_terminal=False, width=200, legacy_windows=False, _environ={}
        )
        render_table(self._report(), console)
        stream.flush()
        output = raw.getvalue().decode("cp1252")

        header, body = _first_table(output)
        assert [_cells(line) for line in header] == [_HEADERS]
        assert [(_cells(line)[0], _cells(line)[6]) for line in body] == [
            ("react (18.2.0)", "OK"),
            ("flask (3.0.3)", "OK"),
            ("+- child (1.0.0)", "OK"),
            ("gpl-lib (1.0.0)", "X"),
            ("lgpl-lib (2.0.0)", "!"),
            ("mystery", "?"),
            ("requests (2.31.0)", "OK"),
        ]
        assert "    X GPL is incompatible with MIT" in output
        assert "    ! Weak copyleft, review needed" in output
        # Nothing had to be replaced: the borders are ASCII too.
        assert output.isascii()
