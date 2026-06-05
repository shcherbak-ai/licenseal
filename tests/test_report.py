"""Tests for licenseal.report."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

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
    _source_terminal_url,
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


def _make_console() -> tuple[Console, StringIO]:
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, no_color=True, width=120)
    return console, buf


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
        assert "**Completed in:** 0.42s" in md
        assert "1 violation," in md
        assert f"_{_REPORT_NOTE.replace('licenseal check', '`licenseal check`')}_" in md
        assert not md.endswith("\n")

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
        # force_terminal + legacy_windows=False so rich emits OSC-8 hyperlinks.
        buf = StringIO()
        console = Console(
            file=buf,
            force_terminal=True,
            no_color=True,
            width=200,
            legacy_windows=False,
        )
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
