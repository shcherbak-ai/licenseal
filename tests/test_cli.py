"""Tests for licenseal.cli."""

from __future__ import annotations

import json
import textwrap
import time
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

import click
import httpx
import pytest
import respx
import tethered
from click.testing import CliRunner

from licenseal import __version__
from licenseal.cli import (
    _echo_read_diagnostics,
    _http_headers,
    _package_version,
    _parse_installed_skill,
    _project_skill_staleness_hint,
    _read_diagnostics_view,
    _registries_unreachable,
    _render_installed_skill,
    _should_fail,
    _warn_unscaffoldable,
    _worker_count,
    main,
)
from licenseal.discovery._read import ReadDiagnostic
from licenseal.models import (
    AnalysisReport,
    CompatibilityResult,
    CompatibilityVerdict,
    Dependency,
    Ecosystem,
    LicenseInfo,
    RiskLevel,
)
from licenseal.review import (
    FlaggedEntry,
    ReviewFileContents,
    apply_reviewed_licenses,
    canonical_name,
    load_review_file,
    render_review_template,
    review_key,
)


def _mock_pypi(name: str, license_str: str, version: str = "1.0.0"):
    """Helper to mock a PyPI response.

    Mocks both the project-level URL (used by the unpinned/range path) and the
    version-pinned URL (used when `version_constraint` is `==X.Y.Z`). Both
    return identical license metadata.
    """
    payload = {
        "info": {
            "license": license_str,
            "version": version,
            "classifiers": [],
            "requires_dist": [],
        }
    }
    respx.get(f"https://pypi.org/pypi/{name}/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    respx.get(f"https://pypi.org/pypi/{name}/{version}/json").mock(
        return_value=httpx.Response(200, json=payload)
    )


def _mock_npm(name: str, license_str: str, version: str = "1.0.0"):
    """Helper to mock an npm registry response."""
    respx.get(f"https://registry.npmjs.org/{name}").mock(
        return_value=httpx.Response(
            200,
            json={
                "versions": {
                    version: {
                        "license": license_str,
                        "version": version,
                    }
                },
            },
        )
    )
    respx.get(f"https://registry.npmjs.org/{name}/latest").mock(
        return_value=httpx.Response(
            200,
            json={
                "license": license_str,
                "version": version,
            },
        )
    )
    # Version-pinned URL is hit by `fetch_npm_dependencies` during the transitive
    # walk; return the same metadata with no children.
    respx.get(f"https://registry.npmjs.org/{name}/{version}").mock(
        return_value=httpx.Response(
            200,
            json={
                "license": license_str,
                "version": version,
            },
        )
    )


class TestEchoReadDiagnostics:
    def test_dedups_and_handles_path_outside_root(self, tmp_path, capsys):
        project = tmp_path / "proj"
        project.mkdir()
        inside = project / "requirements.txt"
        outside = tmp_path / "elsewhere.txt"
        reason = "decoded as latin-1 (not valid UTF-8); non-ASCII content may be wrong"
        diags = [
            ReadDiagnostic(path=inside, reason=reason, is_gap=False),
            ReadDiagnostic(path=inside, reason=reason, is_gap=False),  # exact duplicate
            ReadDiagnostic(
                path=outside, reason="could not be read (OSError); skipped", is_gap=True
            ),
        ]
        view = _read_diagnostics_view(diags, project)
        # De-duplicated to two distinct entries, with relativized paths + severity.
        assert len(view) == 2
        assert view[0].path == "requirements.txt" and view[0].severity == "recovered"
        # A path not under the scan root can't be made relative — shown absolute.
        assert view[1].path == str(outside) and view[1].severity == "gap"

        gap_count = _echo_read_diagnostics(view)
        err = capsys.readouterr().err
        assert err.count("requirements.txt") == 1
        assert "Warning: requirements.txt:" in err
        assert str(outside) in err
        # Only the unreadable file is a gap; the latin-1 recovery is not.
        assert gap_count == 1

    def test_empty_is_silent(self, tmp_path, capsys):
        assert _read_diagnostics_view([], tmp_path) == []
        assert _echo_read_diagnostics([]) == 0
        assert capsys.readouterr().err == ""


class TestRegistriesUnreachable:
    """Unit tests for the wholesale-unreachability gate decision."""

    @staticmethod
    def _info(*, from_registry: bool) -> LicenseInfo:
        return LicenseInfo(
            dependency=Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON),
            license_id="UNKNOWN",
            license_raw="",
            from_registry=from_registry,
        )

    def test_empty_scan_is_not_unreachable(self):
        # No dependencies to resolve is a clean (empty) scan, not an outage.
        assert _registries_unreachable([], attempted=0, succeeded=0) is False

    def test_no_requests_issued_is_not_unreachable(self):
        # Every dep short-circuited (git / path / workspace spec, or resolved
        # from a lockfile / batch / index): no request was issued, so there
        # was nothing to be unreachable.
        assert (
            _registries_unreachable([self._info(from_registry=False)], attempted=0, succeeded=0)
            is False
        )

    def test_reached_but_unresolved_is_not_unreachable(self):
        # A registry that answered (succeeded > 0) but yielded no license — e.g.
        # a git-sourced dep whose metadata fetch returned 200 yet matched no
        # version — is reachable. It must not read as a connectivity failure.
        assert (
            _registries_unreachable([self._info(from_registry=False)], attempted=2, succeeded=1)
            is False
        )

    def test_one_resolved_dep_disables_the_gate(self):
        # A partial outage where some deps resolved (via batch / lockfile) but
        # the tail's fetches failed stays on the per-dep UNKNOWN / strict path.
        infos = [self._info(from_registry=True), self._info(from_registry=False)]
        assert _registries_unreachable(infos, attempted=3, succeeded=0) is False

    def test_all_failed_and_nothing_resolved_is_unreachable(self):
        infos = [self._info(from_registry=False), self._info(from_registry=False)]
        assert _registries_unreachable(infos, attempted=2, succeeded=0) is True


class TestCheckCommand:
    @respx.mock
    def test_latin1_comment_requirements_surfaces_warning(self, tmp_path):
        # End-to-end: a requirements.txt with a stray non-UTF-8 byte in a
        # comment is parsed (its ASCII deps survive) AND the latin-1 fallback
        # is surfaced on stderr rather than silently swallowed.
        (tmp_path / "requirements.txt").write_bytes(b"# maintainer: Jos\xe9 Garcia\nflask\n")
        _mock_pypi("flask", "BSD-3-Clause")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "Warning: requirements.txt: decoded as latin-1" in result.output

    def test_should_fail_on_analysis_gaps_in_strict_mode(self):
        # An analysis gap (unreadable/unparseable manifest) is morally an
        # UNKNOWN: --strict fails on it, --no-strict does not.
        report = AnalysisReport(project_license="MIT", results=[])
        assert _should_fail(report, strict=True, had_analysis_gaps=True) is True
        assert _should_fail(report, strict=False, had_analysis_gaps=True) is False
        assert _should_fail(report, strict=True, had_analysis_gaps=False) is False

    @respx.mock
    def test_unparseable_manifest_surfaces_gap_and_fails_strict(self, tmp_path):
        # A malformed package.json is a coverage gap (its deps are lost). It
        # must be surfaced, and --strict must fail on it like an UNKNOWN.
        (tmp_path / "package.json").write_text("{ not valid json", encoding="utf-8")
        runner = CliRunner()

        warn = runner.invoke(main, ["check", "--path", str(tmp_path), "--no-strict"])
        assert warn.exit_code == 0
        assert "package.json: is not valid JSON" in warn.output
        assert "could not be fully analyzed" in warn.output

        strict = runner.invoke(main, ["check", "--path", str(tmp_path), "--strict"])
        assert strict.exit_code == 1
        assert "fails --strict" in strict.output

    @respx.mock
    def test_json_report_includes_diagnostics(self, tmp_path):
        # The JSON report must carry gaps too (stderr is not machine-readable):
        # summary.gaps + a diagnostics[] entry for the malformed manifest.
        (tmp_path / "package.json").write_text("{ not valid json", encoding="utf-8")
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "--no-strict", "-f", "json", "-o", str(out)],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["summary"]["gaps"] >= 1
        assert any(
            d["severity"] == "gap" and "package.json" in d["path"] and "JSON" in d["reason"]
            for d in data["diagnostics"]
        )

    @respx.mock
    def test_json_report_clean_has_empty_diagnostics(self, tmp_path):
        # A clean scan still emits the keys (stable contract), empty.
        (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", "-o", str(out)]
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["summary"]["gaps"] == 0
        assert data["diagnostics"] == []

    def test_http_headers_include_user_agent(self):
        headers = _http_headers("check")
        assert headers["Accept"] == "application/json"
        assert headers["User-Agent"].startswith("licenseal/")
        assert "; check)" in headers["User-Agent"]

    def test_package_version_falls_back_when_metadata_missing(self):
        with patch("licenseal.cli.version", side_effect=PackageNotFoundError):
            assert _package_version() == "0.0.0"

    def test_worker_count_caps_to_dependency_count(self):
        assert _worker_count(3, 8) == 3
        assert _worker_count(12, 4) == 4

    def test_should_fail_respects_strict_mode(self):
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        result = CompatibilityResult(
            license_info=LicenseInfo(dependency=dep, license_id="UNKNOWN", license_raw=""),
            risk_level=RiskLevel.UNKNOWN,
            verdict=CompatibilityVerdict.UNKNOWN,
        )
        report = AnalysisReport(project_license="MIT", results=[result])
        assert _should_fail(report, strict=True) is True
        assert _should_fail(report, strict=False) is False

    def test_should_fail_skips_reviewed_warning_in_strict_mode(self):
        # A reviewed warning is the user's explicit accept — strict mode
        # passes because the audit trail (note field) covers it.
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        result = CompatibilityResult(
            license_info=LicenseInfo(
                dependency=dep,
                license_id="MPL-2.0",
                license_raw="MPL-2.0",
                reviewed_license_id="MPL-2.0",
                review_note="used unmodified",
            ),
            risk_level=RiskLevel.WEAK_COPYLEFT,
            verdict=CompatibilityVerdict.WARNING,
        )
        report = AnalysisReport(project_license="MIT", results=[result])
        assert _should_fail(report, strict=True) is False
        assert _should_fail(report, strict=False) is False

    def test_should_fail_skips_reviewed_violation(self):
        # Even violations: when explicitly reviewed (e.g. accepted because
        # internal-use only), strict mode passes. The audit trail is in
        # the review note.
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        result = CompatibilityResult(
            license_info=LicenseInfo(
                dependency=dep,
                license_id="GPL-3.0-only",
                license_raw="GPL-3.0-only",
                reviewed_license_id="GPL-3.0-only",
                review_note="internal-use only, no distribution",
            ),
            risk_level=RiskLevel.STRONG_COPYLEFT,
            verdict=CompatibilityVerdict.INCOMPATIBLE,
        )
        report = AnalysisReport(project_license="MIT", results=[result])
        assert _should_fail(report, strict=True) is False
        assert _should_fail(report, strict=False) is False

    def test_should_fail_unreviewed_warning_still_fails_strict(self):
        # Mixed: one reviewed warning + one unreviewed warning. Strict
        # fails because the unreviewed one isn't covered by an audit
        # entry — the reviewed one alone wouldn't have triggered failure.
        dep_a = Dependency(name="a", version_constraint="", ecosystem=Ecosystem.PYTHON)
        dep_b = Dependency(name="b", version_constraint="", ecosystem=Ecosystem.PYTHON)
        reviewed = CompatibilityResult(
            license_info=LicenseInfo(
                dependency=dep_a,
                license_id="MPL-2.0",
                license_raw="MPL-2.0",
                reviewed_license_id="MPL-2.0",
                review_note="accepted",
            ),
            risk_level=RiskLevel.WEAK_COPYLEFT,
            verdict=CompatibilityVerdict.WARNING,
        )
        unreviewed = CompatibilityResult(
            license_info=LicenseInfo(dependency=dep_b, license_id="LGPL-3.0-only", license_raw=""),
            risk_level=RiskLevel.WEAK_COPYLEFT,
            verdict=CompatibilityVerdict.WARNING,
        )
        report = AnalysisReport(project_license="MIT", results=[reviewed, unreviewed])
        assert _should_fail(report, strict=True) is True
        # Non-strict only fails on violations, and there are none here.
        assert _should_fail(report, strict=False) is False

    def test_should_fail_unreviewed_violation_fails_even_no_strict(self):
        # The non-strict mode still fails on violations — but only when
        # there's an unreviewed one. A reviewed violation (above) passes.
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        result = CompatibilityResult(
            license_info=LicenseInfo(dependency=dep, license_id="GPL-3.0-only", license_raw=""),
            risk_level=RiskLevel.STRONG_COPYLEFT,
            verdict=CompatibilityVerdict.INCOMPATIBLE,
        )
        report = AnalysisReport(project_license="MIT", results=[result])
        assert _should_fail(report, strict=True) is True
        assert _should_fail(report, strict=False) is True

    def test_load_review_file_missing_returns_empty_maps(self, tmp_path):
        contents = load_review_file(tmp_path)
        assert contents.licenses == {}
        assert contents.notes == {}
        assert contents.incomplete == []

    def test_load_review_file_reads_multiple_entries(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = "MIT"
            note = "confirmed manually"

            [[review]]
            ecosystem = "python"
            package = "vendor-sdk"
            version = "2.4.1"
            license = "Proprietary"
            """)
        )
        contents = load_review_file(tmp_path)
        assert contents.licenses == {
            "python:mystery-lib@1.0.0": "MIT",
            "python:vendor-sdk@2.4.1": "Proprietary",
        }
        assert contents.notes == {"python:mystery-lib@1.0.0": "confirmed manually"}
        assert contents.incomplete == []

    def test_load_review_file_normalizes_python_name_per_pep503(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "My_Mystery.Lib"
            version = "1.0.0"
            license = "MIT"
            """)
        )
        contents = load_review_file(tmp_path)
        assert contents.licenses == {"python:my-mystery-lib@1.0.0": "MIT"}

    def test_canonical_name_normalizes_python_per_pep503(self):
        assert canonical_name(Ecosystem.PYTHON, "My_Pkg.Name") == "my-pkg-name"
        assert canonical_name(Ecosystem.PYTHON, "multiple___underscores") == "multiple-underscores"
        assert canonical_name("python", "MIXED-Case") == "mixed-case"

    def test_canonical_name_keeps_npm_lowercase(self):
        assert canonical_name(Ecosystem.NPM, "React-DOM") == "react-dom"
        assert canonical_name(Ecosystem.NPM, "@scope/Pkg") == "@scope/pkg"

    def test_load_review_file_detects_pep503_duplicate(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "my-pkg"
            version = "1.0.0"
            license = "MIT"

            [[review]]
            ecosystem = "python"
            package = "MY_PKG"
            version = "1.0.0"
            license = "Apache-2.0"
            """)
        )
        with pytest.raises(
            click.ClickException,
            match="duplicate review entry for python:MY_PKG@1.0.0",
        ):
            load_review_file(tmp_path)

    def test_load_review_file_rejects_invalid_toml(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text("[[review]\n")
        with pytest.raises(click.ClickException, match="Invalid licenseal.review.toml"):
            load_review_file(tmp_path)

    def test_load_review_file_rejects_non_list_review_section(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text('review = "bad"')
        with pytest.raises(click.ClickException, match=r"expected \[\[review\]\] entries"):
            load_review_file(tmp_path)

    def test_load_review_file_rejects_non_table_entry(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            review = [1]
            """)
        )
        with pytest.raises(click.ClickException, match="review entry 1 must be a table"):
            load_review_file(tmp_path)

    def test_load_review_file_rejects_missing_package(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            version = "1.0.0"
            license = "MIT"
            """)
        )
        with pytest.raises(click.ClickException, match="missing a string 'package'"):
            load_review_file(tmp_path)

    def test_load_review_file_rejects_missing_version(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            license = "MIT"
            """)
        )
        with pytest.raises(click.ClickException, match="missing a string 'version'"):
            load_review_file(tmp_path)

    def test_load_review_file_rejects_missing_required_fields(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "1.0.0"
            """)
        )
        contents = load_review_file(tmp_path)
        assert contents.licenses == {}
        assert contents.notes == {}
        assert contents.incomplete == ["python:requests@1.0.0"]

    def test_load_review_file_rejects_duplicate_entries(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "1.0.0"
            license = "MIT"

            [[review]]
            ecosystem = "python"
            package = "Requests"
            version = "1.0.0"
            license = "Apache-2.0"
            """)
        )
        with pytest.raises(
            click.ClickException,
            match="duplicate review entry for python:Requests@1.0.0",
        ):
            load_review_file(tmp_path)

    def test_load_review_file_allows_same_name_version_across_ecosystems(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "shared"
            version = "1.0.0"
            license = "MIT"

            [[review]]
            ecosystem = "npm"
            package = "shared"
            version = "1.0.0"
            license = "Apache-2.0"
            """)
        )
        contents = load_review_file(tmp_path)
        assert contents.licenses == {
            "python:shared@1.0.0": "MIT",
            "npm:shared@1.0.0": "Apache-2.0",
        }
        assert contents.notes == {}
        assert contents.incomplete == []

    def test_load_review_file_rejects_invalid_license_value(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "1.0.0"
            license = "totally made up license"
            """)
        )
        with pytest.raises(click.ClickException, match="Invalid reviewed license"):
            load_review_file(tmp_path)

    def test_load_review_file_rejects_non_string_license(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "1.0.0"
            license = 123
            """)
        )
        with pytest.raises(click.ClickException, match="missing a string 'license'"):
            load_review_file(tmp_path)

    def test_load_review_file_tracks_incomplete_review_entry(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "1.0.0"
            license = ""
            note = "pending"
            """)
        )
        contents = load_review_file(tmp_path)
        assert contents.licenses == {}
        assert contents.notes == {}
        assert contents.incomplete == ["python:requests@1.0.0"]
        assert contents.all_keys == {"python:requests@1.0.0"}

    def test_load_review_file_rejects_missing_ecosystem(self, tmp_path):
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            package = "requests"
            version = "1.0.0"
            license = "MIT"
            """)
        )
        with pytest.raises(click.ClickException, match="missing a valid 'ecosystem'"):
            load_review_file(tmp_path)

    def test_apply_reviewed_licenses_skips_unresolved_versions(self):
        license_info = LicenseInfo(
            dependency=Dependency(
                name="requests",
                version_constraint="",
                ecosystem=Ecosystem.PYTHON,
            ),
            license_id="UNKNOWN",
            license_raw="Unknown",
        )
        contents = ReviewFileContents(licenses={"python:requests@1.0.0": "MIT"})
        with pytest.raises(
            click.ClickException,
            match=(
                "Reviewed licenses did not match any resolved package versions: "
                "python:requests@1.0.0"
            ),
        ):
            apply_reviewed_licenses([license_info], contents, set())

    def test_apply_reviewed_licenses_rejects_note_without_matching_license(self):
        contents = ReviewFileContents(notes={"python:requests@1.0.0": "confirmed manually"})
        with pytest.raises(
            click.ClickException,
            match="Review notes require matching reviewed license entries: python:requests@1.0.0",
        ):
            apply_reviewed_licenses([], contents, set())

    def test_apply_reviewed_licenses_rejects_non_flagged_override(self):
        license_info = LicenseInfo(
            dependency=Dependency(
                name="requests",
                version_constraint="",
                ecosystem=Ecosystem.PYTHON,
            ),
            license_id="MIT",
            license_raw="MIT",
            resolved_version="1.0.0",
        )
        contents = ReviewFileContents(licenses={"python:requests@1.0.0": "Apache-2.0"})
        with pytest.raises(
            click.ClickException,
            match=(
                "Review entries can only override flagged dependencies; these match "
                "already-compatible dependencies and should be removed: "
                "python:requests@1.0.0"
            ),
        ):
            apply_reviewed_licenses([license_info], contents, set())

    def test_apply_reviewed_licenses_matches_ecosystem_specific_key(self):
        python_dep = LicenseInfo(
            dependency=Dependency(name="shared", version_constraint="", ecosystem=Ecosystem.PYTHON),
            license_id="UNKNOWN",
            license_raw="Unknown",
            resolved_version="1.0.0",
        )
        npm_dep = LicenseInfo(
            dependency=Dependency(name="shared", version_constraint="", ecosystem=Ecosystem.NPM),
            license_id="UNKNOWN",
            license_raw="Unknown",
            resolved_version="1.0.0",
        )

        contents = ReviewFileContents(
            licenses={"npm:shared@1.0.0": "MIT"},
            notes={"npm:shared@1.0.0": "confirmed manually"},
        )
        apply_reviewed_licenses([python_dep, npm_dep], contents, {"npm:shared@1.0.0"})

        assert python_dep.license_id == "UNKNOWN"
        assert python_dep.reviewed is False
        # detected stays as license_id; reviewed comes via the property.
        assert npm_dep.license_id == "UNKNOWN"
        assert npm_dep.detected_license_id == "UNKNOWN"
        assert npm_dep.effective_license_id == "MIT"
        assert npm_dep.reviewed is True
        assert npm_dep.review_note == "confirmed manually"

    def test_review_key_normalizes_python_name(self):
        assert review_key(Ecosystem.PYTHON, "My_Pkg", "1.0.0") == "python:my-pkg@1.0.0"

    def test_review_template_content_omits_raw_comment_when_not_needed(self):
        entry = FlaggedEntry(
            ecosystem="python",
            name="mystery-lib",
            version="1.0.0",
            detected_license="UNKNOWN",
            license_raw="UNKNOWN",
            verdict="unknown",
        )
        content = render_review_template([entry])
        assert "# detected: UNKNOWN" in content
        assert "# status: unknown" in content
        assert 'ecosystem = "python"' in content
        assert "# raw:" not in content

    @respx.mock
    def test_basic_check(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "Apache 2.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 0

    @respx.mock
    def test_requests_include_identifying_headers(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        route = respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "MIT",
                        "version": "1.0.0",
                        "classifiers": [],
                    }
                },
            )
        )
        respx.get("https://pypi.org/pypi/requests/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "MIT",
                        "version": "1.0.0",
                        "classifiers": [],
                        "requires_dist": [],
                    }
                },
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 0
        request = route.calls[0].request
        assert request.headers["Accept"] == "application/json"
        assert request.headers["User-Agent"].startswith("licenseal/")

    @respx.mock
    def test_violation_exits_nonzero(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["gpl-lib"]
            """)
        )
        _mock_pypi("gpl-lib", "GPL-3.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 1

    @respx.mock
    def test_warning_exits_nonzero_in_strict_mode(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["lgpl-lib"]
            """)
        )
        _mock_pypi("lgpl-lib", "LGPL-3.0-only")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 1

    @respx.mock
    def test_warning_can_be_allowed_with_no_strict(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["lgpl-lib"]
            """)
        )
        _mock_pypi("lgpl-lib", "LGPL-3.0-only")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--no-strict"])
        assert result.exit_code == 0

    @respx.mock
    def test_unknown_exits_nonzero_in_strict_mode(self, tmp_path):
        # Use a git+ spec — it's unsupported (no registry version) but unlike
        # ``workspace:`` / ``file:`` / ``link:`` it points at an external
        # source we genuinely can't license-check, so it surfaces as UNKNOWN
        # and triggers strict-mode failure. Workspace-local specs are filtered
        # at discovery (no point license-checking the user's own workspace).
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "myproject",
                    "license": "MIT",
                    "dependencies": {"react": "git+https://github.com/facebook/react.git"},
                }
            )
        )
        respx.get("https://registry.npmjs.org/react").mock(
            return_value=httpx.Response(
                200,
                json={"versions": {"18.2.0": {"license": "MIT", "version": "18.2.0"}}},
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 1

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_total_registry_unreachable_fails_even_no_strict(self, tmp_path, monkeypatch):
        # No connectivity: every registry request (the deps.dev batch and the
        # per-package PyPI fetch) fails at the connection layer. The scan
        # resolves nothing, so it must fail loudly rather than report a wall of
        # UNKNOWN — and must do so EVEN under --no-strict, where UNKNOWN alone
        # wouldn't gate (the false-clean hole this guard closes).
        monkeypatch.setattr("licenseal.resolvers.http._INITIAL_BACKOFF_SECONDS", 0.0)
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests==2.31.0"]
            """)
        )
        # Every registry call fails at the connection layer — the deps.dev
        # batch POST, the PyPI per-package fetch, and the deps.dev stable-GET
        # fallback all route through this catch-all.
        respx.route(url__regex=r"https://.*").mock(side_effect=httpx.ConnectError("no network"))

        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "--no-transitive", "--no-strict"]
        )
        assert result.exit_code == 1
        assert "Could not resolve any of the 1 dependencies" in result.output
        assert "registry request(s) failed" in result.output

    @respx.mock
    def test_reachable_but_unresolved_dep_does_not_trip_gate(self, tmp_path):
        # A reachable registry that can't yield a license must NOT be mistaken
        # for an outage: the npm metadata fetch returns 200, but the git+ spec
        # matches no published version, so the dep is UNKNOWN. That is the
        # normal strict-mode failure path — exit 1 with no unreachable message.
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "myproject",
                    "license": "MIT",
                    "dependencies": {"react": "git+https://github.com/facebook/react.git"},
                }
            )
        )
        respx.get("https://registry.npmjs.org/react").mock(
            return_value=httpx.Response(
                200,
                json={"versions": {"18.2.0": {"license": "MIT", "version": "18.2.0"}}},
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--no-transitive"])
        assert result.exit_code == 1
        assert "Could not reach any package registry" not in result.output

    @respx.mock
    def test_json_output(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        # Click mixes stderr into output by default; extract JSON part
        output = result.output
        json_start = output.index("{")
        data = json.loads(output[json_start:])
        assert data["project_license"] == "MIT"
        assert data["elapsed_seconds"] >= 0

    @respx.mock
    def test_output_flag_writes_json_to_file(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")
        out_file = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "-o", str(out_file)],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["project_license"] == "MIT"
        # Confirmation message goes to stderr (still in result.output via CliRunner).
        assert f"Wrote json report to {out_file}" in result.output

    @respx.mock
    def test_output_flag_writes_markdown_to_file(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")
        out_file = tmp_path / "LICENSES.md"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "markdown", "-o", str(out_file)],
        )
        assert result.exit_code == 0
        content = out_file.read_text(encoding="utf-8")
        assert content.startswith("# License Analysis Report")
        assert "**Project license:** MIT" in content

    @respx.mock
    def test_output_flag_writes_table_to_file_without_ansi(self, tmp_path):
        # Table format writes plain text (no ANSI escapes) when going to disk.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")
        out_file = tmp_path / "report.txt"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "table", "-o", str(out_file)],
        )
        assert result.exit_code == 0
        content = out_file.read_text(encoding="utf-8")
        # No ANSI escape sequences should be present.
        assert "\x1b[" not in content
        # Should still contain the project license summary.
        assert "MIT" in content

    @respx.mock
    def test_output_flag_creates_missing_parent_dirs(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")
        out_file = tmp_path / "reports" / "nested" / "out.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "-o", str(out_file)],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    @respx.mock
    def test_output_flag_writes_file_when_gate_fails(self, tmp_path):
        """CI contract: when --output is set, the file lands on disk even when
        strict-mode evaluation fails. The artifact is the evidence; the exit
        code is the gate signal — they're orthogonal."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["gpl-lib"]
            """)
        )
        _mock_pypi("gpl-lib", "GPL-3.0")
        out_file = tmp_path / "report.json"

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "-o", str(out_file)],
        )
        # MIT project + GPL-3.0 dep → violation → strict-mode failure.
        assert result.exit_code == 1
        # File must exist regardless — CI publishes it after the failing step.
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["summary"]["violations"] >= 1
        names = {dep["name"] for dep in data["dependencies"]}
        assert "gpl-lib" in names

    @respx.mock
    def test_output_flag_reports_disk_write_error_cleanly(self, tmp_path):
        """A failed write_text surfaces as a ClickException, not a Python
        traceback. Exit is non-zero and the error message names the target."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")
        out_file = tmp_path / "report.json"

        runner = CliRunner()
        with patch(
            "pathlib.Path.write_text",
            side_effect=PermissionError("disk full or permission denied"),
        ):
            result = runner.invoke(
                main,
                ["check", "--path", str(tmp_path), "-f", "json", "-o", str(out_file)],
            )
        assert result.exit_code == 1
        assert f"Failed to write report to {out_file}" in result.output
        # No raw Python traceback in user-facing output.
        assert "Traceback" not in result.output

    @respx.mock
    def test_reviewed_license_applies_to_exact_resolved_version(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = "MIT"
            note = "confirmed from packaged LICENSE file"
            """)
        )
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--path",
                str(tmp_path),
                "-f",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        dep = data["dependencies"][0]
        assert dep["detected_license"] == "UNKNOWN"
        assert dep["reviewed_license"] == "MIT"
        assert dep["effective_license"] == "MIT"
        assert dep["license"] == "MIT"
        assert dep["reviewed"] is True
        assert dep["review_note"] == "confirmed from packaged LICENSE file"
        assert data["summary"]["reviewed"] == 1
        assert data["summary"]["unknown"] == 0

    @respx.mock
    def test_reviewed_override_leaves_other_deps_unchanged(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib", "requests"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = "MIT"
            note = "verified"
            """)
        )
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")
        _mock_pypi("requests", "MIT", version="2.31.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        by_name = {dep["name"]: dep for dep in data["dependencies"]}
        assert by_name["mystery-lib"]["reviewed"] is True
        assert by_name["requests"]["reviewed"] is False
        assert by_name["requests"]["effective_license"] == "MIT"
        assert data["summary"]["reviewed"] == 1
        assert data["summary"]["ok"] == 2

    @respx.mock
    def test_reviewed_license_can_override_flagged_violation(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["gpl-lib"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "gpl-lib"
            version = "1.0.0"
            license = "MIT"
            note = "resolver metadata mismatch verified manually"
            """)
        )
        _mock_pypi("gpl-lib", "GPL-3.0", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        dep = data["dependencies"][0]
        assert dep["detected_license"] == "GPL-3.0-only"
        assert dep["reviewed_license"] == "MIT"
        assert dep["effective_license"] == "MIT"
        assert dep["reviewed"] is True
        assert data["summary"]["violations"] == 0
        assert data["summary"]["reviewed"] == 1

    @respx.mock
    def test_invalid_review_file_license_is_rejected(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "1.0.0"
            license = "totally made up license"
            """)
        )
        _mock_pypi("requests", "MIT")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code != 0
        assert "Invalid reviewed license" in result.output

    @respx.mock
    def test_unmatched_review_file_entry_is_rejected(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "2.0.0"
            license = "MIT"
            """)
        )
        _mock_pypi("requests", "MIT", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code != 0
        assert "did not match any resolved package versions" in result.output
        assert "python:requests@2.0.0" in result.output
        # The error must point the user at the actual manual fix — a stale
        # pin (very common after `uv sync --upgrade` / `npm update`) is
        # resolved by editing the version in licenseal.review.toml, NOT by
        # re-running init-review-file --merge (which only appends new
        # entries; existing stale stanzas stay put). The hint regresses
        # silently if no test pins the actionable text.
        assert "licenseal.review.toml" in result.output
        assert "`version`" in result.output
        # The hint must also warn that licenses can change between versions
        # — version-keyed relicensings are a real failure mode the strict
        # guard exists to prevent. Without this warning, a user blindly
        # bumping the pin would silently carry the old review forward onto
        # a potentially-relicensed package.
        assert "Licenses may change between versions" in result.output

    @respx.mock
    def test_stale_pin_hint_workflow_actually_resolves_the_error(self, tmp_path):
        """End-to-end: the workflow the stale-pin hint recommends must work.

        Text-presence assertions (above) verify the hint exists; this test
        verifies its *content* is correct guidance — following the hint
        verbatim must turn a failing check into a passing one. Otherwise the
        hint can drift into misleading advice without any test failing (see
        the earlier `init-review-file --merge` recommendation, which the text
        test happily green-lit despite not actually fixing stale pins).
        """
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib"]
            """)
        )
        review_path = tmp_path / "licenseal.review.toml"
        # User has a reviewed entry pinning an old version.
        review_path.write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = "MIT"
            note = "confirmed from packaged LICENSE file"
            """)
        )
        # Registry now resolves the dep at a newer version with the same
        # underlying license — the dependency-upgrade case the hint targets.
        _mock_pypi("mystery-lib", "Unknown", version="2.0.0")

        runner = CliRunner()

        # Step 1: check fails because the review pins 1.0.0 but 2.0.0 resolves.
        result1 = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result1.exit_code != 0
        assert "did not match any resolved package versions" in result1.output

        # Step 2: follow the hint verbatim — open the file, bump the version.
        # The hint's prerequisite ("ONLY if the new version still reports the
        # same `license` as the original review") is satisfied here: the
        # registry still returns the same Unknown license for 2.0.0, so the
        # original "MIT" review is still legitimate evidence.
        review_path.write_text(
            review_path.read_text().replace('version = "1.0.0"', 'version = "2.0.0"')
        )

        # Step 3: check now passes. If the hint ever drifts back to advice
        # that doesn't actually fix the situation (e.g. recommending a
        # command that only appends new stanzas), this assertion fails.
        result2 = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result2.exit_code == 0, (
            f"Following the stale-pin hint should resolve the error; got "
            f"exit {result2.exit_code} with output:\n{result2.output}"
        )

    @respx.mock
    def test_non_string_review_note_is_rejected(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "requests"
            version = "1.0.0"
            license = "MIT"
            note = 123
            """)
        )
        _mock_pypi("requests", "MIT", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code != 0
        assert "non-string 'note'" in result.output

    @respx.mock
    def test_incomplete_review_entries_warn_and_fail_in_strict_mode(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = ""
            note = ""
            """)
        )
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 1
        assert (
            "incomplete review entries were not applied: python:mystery-lib@1.0.0" in result.output
        )

    @respx.mock
    def test_incomplete_review_entries_warn_but_allow_no_strict(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = ""
            note = ""
            """)
        )
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--no-strict"])
        assert result.exit_code == 0
        assert (
            "incomplete review entries were not applied: python:mystery-lib@1.0.0" in result.output
        )

    @respx.mock
    def test_init_review_file_writes_unknown_template(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib"]
            """)
        )
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        content = (tmp_path / "licenseal.review.toml").read_text()
        assert "# status: unknown" in content
        assert 'ecosystem = "python"' in content
        assert 'package = "mystery-lib"' in content
        assert 'version = "1.0.0"' in content
        assert 'license = ""' in content
        assert 'note = ""' in content

    @respx.mock
    def test_init_review_file_skips_non_unknown_dependencies(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "No reviewable flagged dependencies found." in result.output
        assert not (tmp_path / "licenseal.review.toml").exists()

    @respx.mock
    def test_init_review_file_scaffolds_flagged_warning(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["lgpl-lib"]
            """)
        )
        _mock_pypi("lgpl-lib", "LGPL-3.0-only")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        content = (tmp_path / "licenseal.review.toml").read_text()
        assert 'package = "lgpl-lib"' in content
        assert "# status: warning" in content

    @respx.mock
    def test_init_review_file_requires_force_to_merge_existing(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib"]
            """)
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "other"
            version = "1.0.0"
            license = "MIT"
            """)
        )
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code != 0
        assert "Use --merge to add new flagged entries" in result.output

    @respx.mock
    def test_init_review_file_force_appends_without_clobbering(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib", "lgpl-lib"]
            """)
        )
        original = textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = "MIT"
            note = "verified manually"
            """)
        review_path = tmp_path / "licenseal.review.toml"
        review_path.write_text(original)
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")
        _mock_pypi("lgpl-lib", "LGPL-3.0-only", version="2.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path), "--merge"])
        assert result.exit_code == 0
        text = review_path.read_text()
        # Existing entry preserved verbatim, including note.
        assert "verified manually" in text
        assert text.count('package = "mystery-lib"') == 1
        # New flagged entry appended.
        assert 'package = "lgpl-lib"' in text
        assert "Appended 1 review entry" in result.output

    @respx.mock
    def test_init_review_file_force_no_new_entries(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["mystery-lib"]
            """)
        )
        review_path = tmp_path / "licenseal.review.toml"
        review_path.write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "python"
            package = "mystery-lib"
            version = "1.0.0"
            license = "MIT"
            """)
        )
        _mock_pypi("mystery-lib", "Unknown", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path), "--merge"])
        assert result.exit_code == 0
        assert "No new flagged dependencies to add." in result.output

    def test_init_review_file_from_report_skips_network(self, tmp_path):
        report_path = tmp_path / "report.json"
        report_path.write_text(
            json.dumps(
                {
                    "project_license": "MIT",
                    "elapsed_seconds": 0.0,
                    "summary": {},
                    "dependencies": [
                        {
                            "name": "mystery-lib",
                            "ecosystem": "python",
                            "verdict": "unknown",
                            "resolved_version": "1.0.0",
                            "detected_license": "UNKNOWN",
                            "license_raw": "Custom internal license",
                        },
                        {
                            "name": "ok-lib",
                            "ecosystem": "python",
                            "verdict": "compatible",
                            "resolved_version": "2.0.0",
                            "detected_license": "MIT",
                            "license_raw": "MIT",
                        },
                    ],
                }
            )
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
            ],
        )
        assert result.exit_code == 0
        content = (tmp_path / "licenseal.review.toml").read_text()
        assert 'package = "mystery-lib"' in content
        assert 'package = "ok-lib"' not in content
        assert "# raw: Custom internal license" in content

    def test_init_review_file_from_report_warns_unscaffoldable(self, tmp_path):
        # A flagged dep with an empty resolved_version can't be keyed in the
        # review file. The CLI should still write entries for scaffoldable
        # deps and emit a stderr note pointing at the gap.
        report_path = tmp_path / "report.json"
        report_path.write_text(
            json.dumps(
                {
                    "project_license": "MIT",
                    "elapsed_seconds": 0.0,
                    "summary": {},
                    "dependencies": [
                        {
                            "name": "mystery-lib",
                            "ecosystem": "python",
                            "verdict": "unknown",
                            "resolved_version": "1.0.0",
                            "detected_license": "UNKNOWN",
                        },
                        {
                            "name": "ghost-lib",
                            "ecosystem": "python",
                            "verdict": "unknown",
                            "resolved_version": "",
                            "detected_license": "UNKNOWN",
                        },
                    ],
                }
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
            ],
        )
        assert result.exit_code == 0
        content = (tmp_path / "licenseal.review.toml").read_text()
        assert 'package = "mystery-lib"' in content
        assert 'package = "ghost-lib"' not in content
        assert "1 flagged dependency could not be scaffolded" in result.output
        assert "python:ghost-lib" in result.output

    def test_init_review_file_warns_unscaffoldable_when_only_unscaffoldable(self, tmp_path):
        # All flagged deps unscaffoldable → no file written, but the note
        # still fires so the user understands why "no reviewable flagged
        # dependencies found" despite the scan having flagged things.
        report_path = tmp_path / "report.json"
        report_path.write_text(
            json.dumps(
                {
                    "project_license": "MIT",
                    "elapsed_seconds": 0.0,
                    "summary": {},
                    "dependencies": [
                        {
                            "name": "ghost-lib",
                            "ecosystem": "python",
                            "verdict": "unknown",
                            "resolved_version": "",
                            "detected_license": "UNKNOWN",
                        },
                    ],
                }
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
            ],
        )
        assert result.exit_code == 0
        assert not (tmp_path / "licenseal.review.toml").exists()
        assert "No reviewable flagged dependencies found." in result.output
        assert "1 flagged dependency could not be scaffolded" in result.output

    def test_init_review_file_from_report_rejects_invalid_json(self, tmp_path):
        bad = tmp_path / "report.json"
        bad.write_text("not json")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(bad),
            ],
        )
        assert result.exit_code != 0
        assert "Invalid JSON report" in result.output

    def test_init_review_file_handles_no_dependencies(self, tmp_path):
        # Zero deps → zero flagged entries. We let the flow run through
        # to the second early-return ("No reviewable flagged dependencies
        # found"); the FIRST early-return on `if not deps` was removed so
        # that the `check` command's --format flag emits a valid empty
        # document, and init-review-file rides the same fix.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = []
            """)
        )

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "No reviewable flagged dependencies found" in result.output

    @respx.mock
    def test_markdown_output(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "markdown"])
        assert result.exit_code == 0
        assert "# License Analysis Report" in result.output
        assert "**Completed in:** " in result.output
        assert "|Package|Ecosystem|Group|Source|License|Risk|Status|" in result.output
        assert not result.output.endswith("\n\n")

    @respx.mock
    def test_no_deps_renders_table_with_project_license(self, tmp_path):
        # Zero-dep scan must still render a valid report: project license
        # surfaces, summary line shows zeros, stderr explains nothing
        # needed resolving. Pins the fix for the bug where the old
        # early-return swallowed the project license and broke -f json.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "MIT"
            dependencies = []
            """)
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 0
        # Project license surfaces in the table (we removed the early-return
        # that previously swallowed it).
        assert "MIT" in result.output
        # The stderr note replaces the old "No dependencies found." message.
        assert "No dependencies to resolve" in result.output

    @respx.mock
    def test_no_deps_json_emits_valid_document(self, tmp_path):
        # The original bug: `licenseal check -f json` on a zero-dep project
        # emitted empty stdout, breaking downstream JSON parsers. The fix
        # must always emit a parseable document.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "MIT"
            dependencies = []
            """)
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        # Click mixes stderr into result.output; the JSON document is the
        # tail starting at the first `{` (existing convention in this file).
        data = json.loads(result.output[result.output.index("{") :])
        assert data["project_license"] == "MIT"
        assert data["dependencies"] == []
        assert "elapsed_seconds" in data

    @respx.mock
    def test_no_deps_markdown_renders_full_document(self, tmp_path):
        # Markdown renderer must also produce a complete document on a
        # zero-dep scan — header + project-license line + table header.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "MIT"
            dependencies = []
            """)
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "markdown"])
        assert result.exit_code == 0
        assert "# License Analysis Report" in result.output
        assert "MIT" in result.output

    @respx.mock
    def test_no_project_license_defaults_to_proprietary(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        output = result.output
        json_start = output.index("{")
        data = json.loads(output[json_start:])
        assert data["project_license"] == "Proprietary"
        assert data["elapsed_seconds"] >= 0

    @respx.mock
    def test_dev_dependencies_are_excluded_by_default(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]

            [project.optional-dependencies]
            dev = ["gpl-lib"]
            """)
        )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-lib", "GPL-3.0", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        assert [dep["name"] for dep in data["dependencies"]] == ["requests"]

    @respx.mock
    def test_include_dev_opt_in_can_fail_strict_mode(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]

            [project.optional-dependencies]
            dev = ["gpl-lib"]
            """)
        )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-lib", "GPL-3.0", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--dev"])
        assert result.exit_code == 1

    @respx.mock
    def test_init_review_file_excludes_dev_by_default(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]

            [project.optional-dependencies]
            dev = ["gpl-lib"]
            """)
        )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-lib", "GPL-3.0", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "No reviewable flagged dependencies found." in result.output
        assert not (tmp_path / "licenseal.review.toml").exists()

    @respx.mock
    def test_init_review_file_include_dev_scaffolds_dev_flags(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]

            [project.optional-dependencies]
            dev = ["gpl-lib"]
            """)
        )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-lib", "GPL-3.0", version="1.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["init-review-file", "--path", str(tmp_path), "--dev"])
        assert result.exit_code == 0
        content = (tmp_path / "licenseal.review.toml").read_text()
        assert 'package = "gpl-lib"' in content
        assert "# status: warning" in content

    @respx.mock
    def test_npm_dependencies(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = []
            """)
        )
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "^18.0"}}))
        _mock_npm("react", "MIT", version="18.2.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 0

    @respx.mock
    def test_max_workers_option_limits_executor(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")
        seen: list[int] = []

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                seen.append(max_workers)

            def __enter__(self) -> FakeExecutor:
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                return False

            def map(self, func, *iterables):
                return [func(*args) for args in zip(*iterables, strict=True)]

        with patch("licenseal.cli.ThreadPoolExecutor", FakeExecutor):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["check", "--path", str(tmp_path), "--max-workers", "1"],
            )
        assert result.exit_code == 0
        assert seen == [1]

    @respx.mock
    def test_detect_license_from_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "myproject",
                    "license": "MIT",
                    "dependencies": {"express": "^4.0"},
                }
            )
        )
        _mock_npm("express", "MIT", version="4.0.0")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 0

    @respx.mock
    def test_warns_on_unsupported_npm_spec(self, tmp_path):
        # ``git+`` URL: unsupported by registry resolution, so it surfaces as
        # an UNKNOWN with the "could not be resolved" warning. Distinct from
        # workspace-local specs (``workspace:`` / ``file:`` / ``link:``) which
        # are filtered at discovery as the user's own workspace, not a third-
        # party dep to license-check.
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "myproject",
                    "license": "MIT",
                    "dependencies": {"react": "git+https://github.com/facebook/react.git"},
                }
            )
        )
        respx.get("https://registry.npmjs.org/react").mock(
            return_value=httpx.Response(
                200,
                json={"versions": {"18.2.0": {"license": "MIT", "version": "18.2.0"}}},
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--no-strict"])
        assert result.exit_code == 0
        assert "could not be resolved" in result.output


class TestTetheredIntegration:
    def test_conftest_activate_blocks_unmocked_egress(self):
        """The test suite's no-real-network invariant is enforced by two
        layers: respx mocks per-test, and a process-wide
        ``tethered.activate(allow=[])`` installed by conftest.py. This test
        is the load-bearing assertion that the *second* layer actually
        works — if respx is ever bypassed (a forgotten decorator, a future
        non-httpx client), tethered must catch the call before it hits the
        network. conftest's autouse ``_restore_tethered_baseline`` fixture
        guarantees the baseline at function entry, so no manual re-arm
        is needed.
        """
        with httpx.Client() as client, pytest.raises(tethered.EgressBlocked):
            client.get("https://example.invalid/sentinel")

    @respx.mock
    def test_parallel_workers_inherit_scope(self, tmp_path):
        """Regression: ThreadPoolExecutor workers must each get an independent
        context snapshot. A single shared Context cannot be entered concurrently
        — the second worker would crash with 'context already entered'.

        Uses a slow mock side_effect so workers actually overlap inside the
        context. Instant (synchronous) mocks would let workers serialize and
        hide the race entirely.
        """
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["a", "b", "c", "d"]
            """)
        )

        def slow_response(request):
            # Hold the worker inside ctx.run for long enough that other
            # workers reach their own ctx.run() concurrently.
            time.sleep(0.05)
            return httpx.Response(
                200,
                json={"info": {"license": "MIT", "version": "1.0.0", "classifiers": []}},
            )

        for name in ("a", "b", "c", "d"):
            respx.get(f"https://pypi.org/pypi/{name}/json").mock(side_effect=slow_response)
            # Transitive walk fetches the version-pinned URL; return empty deps.
            respx.get(f"https://pypi.org/pypi/{name}/1.0.0/json").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "info": {
                            "license": "MIT",
                            "version": "1.0.0",
                            "classifiers": [],
                            "requires_dist": [],
                        }
                    },
                )
            )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--max-workers", "4"])
        assert result.exit_code == 0
        assert result.exception is None
        assert "context is already entered" not in result.output

    @respx.mock
    def test_scope_wraps_resolution(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")

        with patch.object(tethered, "scope", wraps=tethered.scope) as mock_scope:
            runner = CliRunner()
            result = runner.invoke(main, ["check", "--path", str(tmp_path)])
            assert result.exit_code == 0
            mock_scope.assert_called_once()
            kwargs = mock_scope.call_args.kwargs
            assert kwargs["allow"] == [
                "pypi.org:443",
                "files.pythonhosted.org:443",
                "registry.npmjs.org:443",
                "crates.io:443",
                "api.deps.dev:443",
                "proxy.golang.org:443",
                "repo.maven.apache.org:443",
                "dl.google.com:443",
                "repo.jenkins-ci.org:443",
                "api.nuget.org:443",
                "repo.packagist.org:443",
                "rubygems.org:443",
                "hex.pm:443",
                "cran.r-project.org:443",
            ]
            assert kwargs["label"] == "licenseal.resolve"
            assert "pypi.org:443" in kwargs["hint"]
            assert "files.pythonhosted.org:443" in kwargs["hint"]
            assert "registry.npmjs.org:443" in kwargs["hint"]
            assert "api.deps.dev:443" in kwargs["hint"]
            assert "proxy.golang.org:443" in kwargs["hint"]
            assert "repo.maven.apache.org:443" in kwargs["hint"]
            assert "dl.google.com:443" in kwargs["hint"]
            assert "repo.jenkins-ci.org:443" in kwargs["hint"]
            assert "api.nuget.org:443" in kwargs["hint"]

    @respx.mock
    def test_runs_under_host_activate_policy(self, tmp_path):
        """Local-dev / host process can call tethered.activate() and the CLI's
        scope() intersects with it instead of overriding it."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        _mock_pypi("requests", "MIT")

        tethered.activate(allow=["pypi.org:443", "registry.npmjs.org:443"])
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert result.exit_code == 0

    def test_host_activate_without_registries_yields_clean_error(self, tmp_path):
        """If a host's activate() omits the registry hosts, the user sees a
        clear ClickException, not a Python traceback."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )

        tethered.activate(allow=["only-allowed.example.com:443"])
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])

        assert result.exit_code != 0
        # Tethered's own message + our actionable disambiguation.
        # (Note: when activate() makes the scope's rules empty, tethered drops
        # the scope and blocks at the activate() layer, so the scope hint
        # doesn't surface in this path — licenseal's CLI text carries the user.)
        assert "Blocked by tethered" in result.output
        assert "pypi.org" in result.output
        assert "tethered.activate()" in result.output
        # Make sure we didn't dump a raw traceback at the user.
        assert "Traceback" not in result.output

    def test_host_outer_scope_without_registries_yields_clean_error(self, tmp_path):
        """If a host wraps licenseal in an outer tethered.scope() without the
        registries, the inner scope's hint surfaces and the CLI exits cleanly."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )

        # conftest.py installs a global activate(allow=[]); lift it for this
        # test so the outer scope is the actual blocker. The autouse
        # _restore_tethered_baseline fixture re-arms activate(allow=[]) at
        # teardown, so no manual restore is needed.
        tethered.deactivate()
        with tethered.scope(allow=["only-allowed.example.com:443"], label="host"):
            runner = CliRunner()
            result = runner.invoke(main, ["check", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "Blocked by tethered" in result.output
        # In the outer-scope path, tethered preserves the inner scope's hint.
        assert "Hint:" in result.output
        assert "pypi.org:443" in result.output
        assert "registry.npmjs.org:443" in result.output
        # licenseal's actionable disambig mentions enclosing scope as a possibility.
        assert "enclosing tethered.scope()" in result.output
        assert "Traceback" not in result.output

    @respx.mock
    def test_warns_on_failed_resolution(self, tmp_path):
        # Partial failure: one dep resolves, one returns 500. Because the scan
        # still resolved something, this is the soft per-dep warning path — not
        # the wholesale-unreachable hard error, which requires *every* lookup to
        # fail (see test_total_registry_unreachable_fails_even_no_strict).
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["badpkg", "goodpkg"]
            """)
        )
        respx.get("https://pypi.org/pypi/badpkg/json").mock(return_value=httpx.Response(500))
        _mock_pypi("goodpkg", "MIT")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path)])
        assert "could not be resolved" in result.output
        assert "Could not resolve any of the" not in result.output


class TestVersionCommand:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        # Assert against the source-of-truth constant, not a literal, so the
        # test tracks version bumps and also flags drift between
        # ``__init__.__version__`` and the packaged metadata Click reports.
        assert __version__ in result.output


def _installed_skill_path(project_dir):
    """Project-local skill layout: <project>/.claude/skills/<name>/SKILL.md."""
    return project_dir / ".claude" / "skills" / "licenseal-review" / "SKILL.md"


def _write_skill(project_dir, *, body, version):
    """Write a stamped project-local ``licenseal-review/SKILL.md``."""
    path = _installed_skill_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_installed_skill(body, version), encoding="utf-8")
    return path


class TestInstallSkill:
    def test_install_skill_writes_file(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill", "--path", str(tmp_path)])
        assert result.exit_code == 0
        # Project-local layout: <project>/.claude/skills/<name>/SKILL.md.
        out = _installed_skill_path(tmp_path)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        # YAML frontmatter is the agent-facing contract — agents need it to
        # discover and dispatch the skill.
        assert content.startswith("---\n")
        assert "name: licenseal-review" in content
        assert "description:" in content
        assert str(out) in result.output

    def test_install_skill_creates_missing_dirs(self, tmp_path):
        # A fresh project has no .claude/skills/ tree yet.
        proj = tmp_path / "proj"
        proj.mkdir()
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill", "--path", str(proj)])
        assert result.exit_code == 0
        assert _installed_skill_path(proj).exists()

    def test_install_skill_defaults_to_cwd(self, tmp_path, monkeypatch):
        # With no --path, installs into the current directory's .claude/skills.
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill"])
        assert result.exit_code == 0
        assert _installed_skill_path(tmp_path).exists()

    def test_install_skill_errors_on_existing_without_force(self, tmp_path):
        out = _installed_skill_path(tmp_path)
        out.parent.mkdir(parents=True)
        out.write_text("stale", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill", "--path", str(tmp_path)])
        assert result.exit_code != 0
        assert "already exists" in result.output
        # Existing content must be preserved on the failed install.
        assert out.read_text(encoding="utf-8") == "stale"

    def test_install_skill_overwrites_with_force(self, tmp_path):
        out = _installed_skill_path(tmp_path)
        out.parent.mkdir(parents=True)
        out.write_text("stale", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill", "--path", str(tmp_path), "--force"])
        assert result.exit_code == 0
        content = out.read_text(encoding="utf-8")
        assert content.startswith("---\n")
        assert content != "stale"

    def test_install_skill_stamps_version_and_hash(self, tmp_path):
        # The installed file carries provenance markers so a later install can
        # tell a pristine copy from a hand-edited one. Frontmatter stays first.
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill", "--path", str(tmp_path)])
        assert result.exit_code == 0
        content = _installed_skill_path(tmp_path).read_text(encoding="utf-8")
        assert content.startswith("---\n")
        stamped_version, _, pristine = _parse_installed_skill(content)
        assert stamped_version == _package_version()
        assert pristine is True

    def test_install_skill_idempotent_when_identical(self, tmp_path):
        # Re-running with no upgrade is a no-op and needs no --force.
        runner = CliRunner()
        assert runner.invoke(main, ["install-skill", "--path", str(tmp_path)]).exit_code == 0
        second = runner.invoke(main, ["install-skill", "--path", str(tmp_path)])
        assert second.exit_code == 0
        assert "up to date" in second.output

    def test_install_skill_refreshes_pristine_older_install_without_force(self, tmp_path):
        # Simulate an older pristine install (the post-upgrade state), then
        # confirm a bare re-install refreshes it in place — no --force.
        from licenseal.cli import _bundled_skill_body

        out = _installed_skill_path(tmp_path)
        out.parent.mkdir(parents=True)
        out.write_text(_render_installed_skill(_bundled_skill_body(), "0.0.1"), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "Refreshed licenseal skill 0.0.1" in result.output
        stamped_version, _, pristine = _parse_installed_skill(out.read_text(encoding="utf-8"))
        assert stamped_version == _package_version()
        assert pristine is True

    def test_install_skill_requires_force_for_hand_modified(self, tmp_path):
        # Markers present but the body was edited (hash no longer matches):
        # refuse to clobber the user's edits without --force.
        from licenseal.cli import _bundled_skill_body

        out = _installed_skill_path(tmp_path)
        out.parent.mkdir(parents=True)
        tampered = _render_installed_skill(_bundled_skill_body(), "0.0.1").replace(
            "\n<!-- licenseal-skill-version:",
            "\nMY LOCAL EDIT\n<!-- licenseal-skill-version:",
            1,
        )
        out.write_text(tampered, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["install-skill", "--path", str(tmp_path)])
        assert result.exit_code != 0
        assert "hand-modified" in result.output
        assert "MY LOCAL EDIT" in out.read_text(encoding="utf-8")


class TestSkillStaleness:
    """The post-upgrade nudge is read-only, project-local only, and a no-op
    for the common case: a project with no installed skill. It never reaches
    outside the scanned project (no home / global access)."""

    def _stale_body(self):
        from licenseal.cli import _bundled_skill_body

        return _bundled_skill_body() + "\n<!-- content from an older release -->\n"

    def test_silent_when_no_skill_installed(self, tmp_path):
        # No .claude/skills in the project — the common case. Silent, no raise.
        proj = tmp_path / "proj"
        proj.mkdir()
        assert _project_skill_staleness_hint(proj) is None

    def test_fires_when_bundled_skill_changed(self, tmp_path):
        # Content-based: a project skill whose body differs from the bundled
        # skill (a release changed it) triggers a nudge.
        proj = tmp_path / "proj"
        _write_skill(proj, body=self._stale_body(), version="0.0.1")
        hint = _project_skill_staleness_hint(proj)
        assert hint is not None
        assert "0.0.1" in hint
        assert "install-skill" in hint

    def test_silent_when_only_version_differs(self, tmp_path):
        # A release that bumps licenseal but leaves the skill body unchanged
        # must NOT nag: same content, older stamp -> silent.
        from licenseal.cli import _bundled_skill_body

        proj = tmp_path / "proj"
        _write_skill(proj, body=_bundled_skill_body(), version="0.0.1")
        assert _project_skill_staleness_hint(proj) is None

    def test_silent_when_current(self, tmp_path):
        from licenseal.cli import _bundled_skill_body

        proj = tmp_path / "proj"
        _write_skill(proj, body=_bundled_skill_body(), version=_package_version())
        assert _project_skill_staleness_hint(proj) is None

    def test_unstamped_skill_is_ignored(self, tmp_path):
        # A hand-written skill with no licenseal markers isn't ours to manage:
        # no nudge (install-side already requires --force for this case).
        proj = tmp_path / "proj"
        path = _installed_skill_path(proj)
        path.parent.mkdir(parents=True)
        path.write_text("hand-written, no markers\n", encoding="utf-8")
        assert _project_skill_staleness_hint(proj) is None

    def test_tampered_markers_treated_as_unstamped(self, tmp_path):
        # A corrupted marker block (hash line removed, or no closing `-->`) is
        # treated as unstamped: no nudge, the user's file is left alone.
        from licenseal.cli import _bundled_skill_body

        proj = tmp_path / "proj"
        path = _installed_skill_path(proj)
        path.parent.mkdir(parents=True)
        body = _bundled_skill_body() + "\n<!-- older -->\n"

        # (a) version marker present, hash marker removed
        path.write_text(body + "\n<!-- licenseal-skill-version: 0.0.1 -->\n", encoding="utf-8")
        assert _project_skill_staleness_hint(proj) is None

        # (b) version marker with no closing `-->`
        path.write_text(body + "\n<!-- licenseal-skill-version: 0.0.1", encoding="utf-8")
        assert _project_skill_staleness_hint(proj) is None

    def test_bundled_body_read_error_is_silent(self, tmp_path, monkeypatch):
        # If the packaged skill can't be read, the nudge degrades to silence
        # rather than raising into `check`.
        def boom():
            raise OSError("unreadable")

        proj = tmp_path / "proj"
        _write_skill(proj, body="anything", version="0.0.1")
        monkeypatch.setattr("licenseal.cli._bundled_skill_body", boom)
        assert _project_skill_staleness_hint(proj) is None

    def test_check_silent_without_skill(self, tmp_path):
        # End-to-end: `check` on a project with no installed skill runs
        # normally and emits no nudge — and never touches anything outside it.
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "x"\nlicense = "MIT"\n', encoding="utf-8"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(proj)])
        assert result.exit_code == 0
        assert "install-skill" not in result.output

    def test_check_emits_project_nudge(self, tmp_path):
        # End-to-end: a project carrying a stale project-local skill gets the
        # nudge on stderr; exit code unaffected.
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "x"\nlicense = "MIT"\n', encoding="utf-8"
        )
        _write_skill(proj, body=self._stale_body(), version="0.0.1")
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(proj)])
        assert result.exit_code == 0
        assert "install-skill" in result.output


class TestFlagValidation:
    def test_max_depth_with_no_transitive_errors(self, tmp_path):
        """`--max-depth` and `--no-transitive` are mutually exclusive: the
        cap only applies to transitive expansion. Pass both → UsageError."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "MIT"
            """)
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "--no-transitive", "--max-depth", "10"],
        )
        assert result.exit_code != 0
        assert "--max-depth has no effect with --no-transitive" in result.output

    def test_default_max_depth_with_no_transitive_is_fine(self, tmp_path):
        """Only an explicit non-default --max-depth errors; the default
        value is silently ignored under --no-transitive."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "MIT"
            """)
        )
        runner = CliRunner()
        # No --max-depth passed → uses the default (50) → should not error.
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--no-transitive"])
        assert result.exit_code == 0

    def test_from_report_with_dev_errors(self, tmp_path):
        """`--from-report` consumes a pre-resolved report; discovery flags
        like --dev/--no-dev are inert in that branch → UsageError."""
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"dependencies": []}))
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
                "--dev",
            ],
        )
        assert result.exit_code != 0
        assert "--dev/--no-dev" in result.output
        assert "--from-report" in result.output

    def test_from_report_with_max_workers_errors(self, tmp_path):
        """`--max-workers` only controls resolver concurrency; with
        --from-report there is no resolution step → UsageError."""
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"dependencies": []}))
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
                "--max-workers",
                "4",
            ],
        )
        assert result.exit_code != 0
        assert "--max-workers" in result.output

    def test_from_report_with_exclude_dirs_errors(self, tmp_path):
        """`--exclude-dirs` only affects on-disk discovery; with
        --from-report no walking happens → UsageError."""
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"dependencies": []}))
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
                "--exclude-dirs",
                "vendor",
            ],
        )
        assert result.exit_code != 0
        assert "--exclude-dirs" in result.output

    def test_from_report_lists_all_inert_flags_together(self, tmp_path):
        """When several discovery flags are passed alongside --from-report,
        the error lists all of them in one shot."""
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"dependencies": []}))
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
                "--dev",
                "--max-workers",
                "4",
                "--exclude-dirs",
                "vendor",
            ],
        )
        assert result.exit_code != 0
        assert "--dev/--no-dev" in result.output
        assert "--max-workers" in result.output
        assert "--exclude-dirs" in result.output
        assert "have no effect" in result.output

    def test_from_report_alone_is_fine(self, tmp_path):
        """No inert discovery flags → no error."""
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"dependencies": []}))
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(report_path),
            ],
        )
        assert result.exit_code == 0


class TestRustEcosystem:
    """End-to-end test that the Rust ecosystem is wired through the CLI."""

    @respx.mock
    def test_check_resolves_rust_license_from_crates_io(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "myapp"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            serde = "=1.0.193"
            """)
        )
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193").mock(
            return_value=httpx.Response(
                200,
                json={"version": {"num": "1.0.193", "license": "MIT OR Apache-2.0"}},
            )
        )
        respx.get("https://crates.io/api/v1/crates/serde").mock(
            return_value=httpx.Response(
                200,
                json={
                    "crate": {
                        "max_stable_version": "1.0.193",
                        "repository": "https://github.com/serde-rs/serde",
                    }
                },
            )
        )
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193/dependencies").mock(
            return_value=httpx.Response(200, json={"dependencies": []})
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        rust_dep = next(d for d in data["dependencies"] if d["name"] == "serde")
        assert rust_dep["ecosystem"] == "rust"
        assert rust_dep["license"] == "Apache-2.0 OR MIT"
        assert rust_dep["package_url"] == "https://crates.io/crates/serde"
        assert rust_dep["source"] == "Cargo.toml"

    @respx.mock
    def test_check_resolves_go_license_from_deps_dev(self, tmp_path):
        # End-to-end: go.mod + go.sum drive discovery, the deps.dev batch POST
        # resolves the license, proxy.golang.org returns the go.mod edge data
        # (no transitives here). Exercises the CLI Ecosystem.GO dispatch branch
        # including the bulk pre-pass cache lookup.
        (tmp_path / "go.mod").write_text(
            "module example.com/myproject\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n",
            encoding="utf-8",
        )
        (tmp_path / "go.sum").write_text(
            "github.com/foo/bar v1.2.3 h1:h\ngithub.com/foo/bar v1.2.3/go.mod h1:h\n",
            encoding="utf-8",
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.2.3",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/foo/bar",
                                    "version": "v1.2.3",
                                },
                                "licenses": ["MIT"],
                                "links": [
                                    {
                                        "label": "SOURCE_REPO",
                                        "url": "https://github.com/foo/bar",
                                    }
                                ],
                            },
                        }
                    ],
                    "nextPageToken": "",
                },
            )
        )
        # proxy.golang.org go.mod fetch — no transitives in this minimal example.
        respx.get("https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.mod").mock(
            return_value=httpx.Response(200, text="module github.com/foo/bar\ngo 1.22\n")
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        go_dep = next(d for d in data["dependencies"] if d["name"] == "github.com/foo/bar")
        assert go_dep["ecosystem"] == "go"
        assert go_dep["license"] == "MIT"
        # The package_url stays pointing at pkg.go.dev: that's the human-facing
        # Go module docs site (the place developers expect to click through to),
        # independent of which API we use server-side for license resolution.
        assert go_dep["package_url"] == "https://pkg.go.dev/github.com/foo/bar@v1.2.3"

    @respx.mock
    def test_check_go_falls_back_to_single_version_when_batch_fails(self, tmp_path):
        # When deps.dev's batch POST exhausts its retries (e.g. 5xx), the per-dep
        # resolver falls back to the stable v3 single-version GET path.
        (tmp_path / "go.mod").write_text(
            "module example.com/myproject\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n",
            encoding="utf-8",
        )
        (tmp_path / "go.sum").write_text(
            "github.com/foo/bar v1.2.3 h1:h\ngithub.com/foo/bar v1.2.3/go.mod h1:h\n",
            encoding="utf-8",
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(503)
        )
        respx.get(
            "https://api.deps.dev/v3/systems/GO/packages/github.com%2Ffoo%2Fbar/versions/v1.2.3"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "GO",
                        "name": "github.com/foo/bar",
                        "version": "v1.2.3",
                    },
                    "licenses": ["MIT"],
                    "links": [{"label": "SOURCE_REPO", "url": "https://github.com/foo/bar"}],
                },
            )
        )
        respx.get("https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.mod").mock(
            return_value=httpx.Response(200, text="module github.com/foo/bar\ngo 1.22\n")
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        go_dep = next(d for d in data["dependencies"] if d["name"] == "github.com/foo/bar")
        assert go_dep["license"] == "MIT"

    @respx.mock
    def test_check_go_batch_confirmed_missing_emits_unknown(self, tmp_path):
        # When the batch returns a response entry with ``request`` but no
        # ``version`` field, that (name, version) is confirmed not in deps.dev.
        # The per-dep resolver returns UNKNOWN without fetching the single
        # endpoint (which would also 404). Verified by NOT arming a respx mock
        # for the single-version GET — if the resolver tried to fetch it, the
        # request would error.
        (tmp_path / "go.mod").write_text(
            "module example.com/myproject\n\ngo 1.22\n\n"
            "require github.com/missing/x v0.0.0-20240101000000-abc123def456\n",
            encoding="utf-8",
        )
        (tmp_path / "go.sum").write_text(
            "github.com/missing/x v0.0.0-20240101000000-abc123def456 h1:h\n"
            "github.com/missing/x v0.0.0-20240101000000-abc123def456/go.mod h1:h\n",
            encoding="utf-8",
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "GO",
                                    "name": "github.com/missing/x",
                                    "version": "v0.0.0-20240101000000-abc123def456",
                                }
                            }
                            # No ``version`` key — confirmed not found
                        }
                    ],
                    "nextPageToken": "",
                },
            )
        )
        respx.get(
            "https://proxy.golang.org/github.com/missing/x/@v/"
            "v0.0.0-20240101000000-abc123def456.mod"
        ).mock(return_value=httpx.Response(404))
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", "--no-strict"]
        )
        # --no-strict so an UNKNOWN result doesn't fail the CLI; we just want
        # to confirm the dep is reported as UNKNOWN.
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        go_dep = next(d for d in data["dependencies"] if d["name"] == "github.com/missing/x")
        assert go_dep["license"] in ("UNKNOWN", "")

    @respx.mock
    def test_check_go_unparseable_version_falls_through_to_single_get(self, tmp_path):
        # A go.mod with an unparseable version (no v prefix or v + non-digit)
        # produces a Dependency that _extract_go_pinned_version rejects. In
        # that case the CLI's Go branch doesn't try the batch cache at all —
        # it falls through to resolve_go_license, which itself short-circuits
        # to UNKNOWN without making any HTTP call.
        (tmp_path / "go.mod").write_text(
            "module example.com/myproject\n\ngo 1.22\n\nrequire github.com/foo/bar vlatest\n",
            encoding="utf-8",
        )
        (tmp_path / "go.sum").write_text(
            "github.com/foo/bar vlatest h1:h\ngithub.com/foo/bar vlatest/go.mod h1:h\n",
            encoding="utf-8",
        )
        # The batch POST is still made for any deps with parseable versions —
        # here, none — so we mock it to return an empty response just to be
        # safe. Most realistic case: no POST happens because requests is
        # empty after the version-filter, so this mock is defensive.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": [], "nextPageToken": ""})
        )
        # Transitive walker still fetches proxy.golang.org for edge data.
        respx.get("https://proxy.golang.org/github.com/foo/bar/@v/vlatest.mod").mock(
            return_value=httpx.Response(404)
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", "--no-strict"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        go_dep = next(d for d in data["dependencies"] if d["name"] == "github.com/foo/bar")
        assert go_dep["license"] in ("UNKNOWN", "")


class TestJavaEcosystem:
    @respx.mock
    def test_check_with_transitive_walks_maven_deps(self, tmp_path):
        # End-to-end Maven scan with transitive resolution:
        #  1. discovery picks up pom.xml direct dep
        #  2. _resolve_java_transitive hits deps.dev :dependencies
        #  3. Maven Central serves POM XML for license resolution
        #  4. Sonatype Central URL in the package_url field
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <groupId>com.example</groupId>
                <artifactId>myapp</artifactId>
                <version>1.0.0</version>
                <licenses>
                    <license><name>MIT</name></license>
                </licenses>
                <dependencies>
                    <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>direct</artifactId>
                        <version>1.0</version>
                    </dependency>
                </dependencies>
            </project>
            """),
            encoding="utf-8",
        )
        # deps.dev :dependencies returns the transitive subgraph.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.example%3Adirect/versions/1.0:dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        {
                            "versionKey": {
                                "system": "MAVEN",
                                "name": "com.example:direct",
                                "version": "1.0",
                            },
                            "relation": "SELF",
                        },
                        {
                            "versionKey": {
                                "system": "MAVEN",
                                "name": "com.example:transitive",
                                "version": "2.0",
                            },
                            "relation": "DIRECT",
                        },
                    ],
                    "edges": [{"fromNode": 0, "toNode": 1}],
                },
            )
        )
        # Maven Central POM XML for both deps.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/direct/1.0/direct-1.0.pom"
        ).mock(
            return_value=httpx.Response(
                200,
                text="""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>direct</artifactId>
    <version>1.0</version>
    <licenses><license><name>Apache-2.0</name></license></licenses>
</project>
""",
            )
        )
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/transitive/2.0/transitive-2.0.pom"
        ).mock(
            return_value=httpx.Response(
                200,
                text="""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>transitive</artifactId>
    <version>2.0</version>
    <licenses><license><name>MIT</name></license></licenses>
</project>
""",
            )
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {d["name"] for d in data["dependencies"]}
        # Both direct and transitive surface.
        assert "com.example:direct" in names
        assert "com.example:transitive" in names
        direct = next(d for d in data["dependencies"] if d["name"] == "com.example:direct")
        transitive = next(d for d in data["dependencies"] if d["name"] == "com.example:transitive")
        assert direct["license"] == "Apache-2.0"
        assert transitive["license"] == "MIT"
        # Transitive is attributed to its direct ancestor.
        assert "direct_ancestors" in transitive
        assert "com.example:direct" in transitive["direct_ancestors"]
        # Sonatype Central URL.
        assert direct["package_url"] == (
            "https://central.sonatype.com/artifact/com.example/direct/1.0"
        )

    @respx.mock
    def test_check_with_gradle_lockfile_skips_deps_dev(self, tmp_path):
        # When gradle.lockfile is present, the transitive walker uses it
        # directly — no deps.dev :dependencies calls for lockfile-covered
        # entries. Maven Central is still hit for per-dep license resolution.
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n    implementation 'com.example:lib:1.0.0'\n}\n",
            encoding="utf-8",
        )
        (tmp_path / "gradle.lockfile").write_text(
            "com.example:lib:1.0.0=compileClasspath,runtimeClasspath\n"
            "com.example:transitive:2.0.0=compileClasspath,runtimeClasspath\n",
            encoding="utf-8",
        )
        # Maven Central serves the POMs.
        for coord, version, license_name in (
            ("com/example/lib", "1.0.0", "Apache-2.0"),
            ("com/example/transitive", "2.0.0", "MIT"),
        ):
            artifact = coord.rsplit("/", 1)[1]
            respx.get(
                f"https://repo.maven.apache.org/maven2/{coord}/{version}/{artifact}-{version}.pom"
            ).mock(
                return_value=httpx.Response(
                    200,
                    text=f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>{coord.replace("/", ".").rsplit(".", 1)[0]}</groupId>
    <artifactId>{artifact}</artifactId>
    <version>{version}</version>
    <licenses><license><name>{license_name}</name></license></licenses>
</project>
""",
                )
            )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {d["name"] for d in data["dependencies"]}
        assert "com.example:lib" in names
        assert "com.example:transitive" in names

    @respx.mock
    def test_check_resolves_java_license_from_maven_central(self, tmp_path):
        # End-to-end: pom.xml drives discovery; Maven Central serves the
        # raw POM XML and the resolver extracts the license. Exercises
        # the CLI's Ecosystem.JAVA dispatch branch through
        # ``resolve_maven_central_license`` with the cache-backed text
        # fetcher. ``--no-transitive`` keeps the test focused on
        # Phase 2 wiring; Phase 3 covers the transitive path.
        (tmp_path / "pom.xml").write_text(
            textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <groupId>com.example</groupId>
                <artifactId>myapp</artifactId>
                <version>1.0.0</version>
                <licenses>
                    <license><name>MIT</name></license>
                </licenses>
                <dependencies>
                    <dependency>
                        <groupId>org.example</groupId>
                        <artifactId>guava-style-lib</artifactId>
                        <version>33.0.0</version>
                    </dependency>
                </dependencies>
            </project>
            """),
            encoding="utf-8",
        )
        respx.get(
            "https://repo.maven.apache.org/maven2/org/example/"
            "guava-style-lib/33.0.0/guava-style-lib-33.0.0.pom"
        ).mock(
            return_value=httpx.Response(
                200,
                text="""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>org.example</groupId>
    <artifactId>guava-style-lib</artifactId>
    <version>33.0.0</version>
    <licenses>
        <license><name>Apache License, Version 2.0</name></license>
    </licenses>
</project>
""",
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "--no-transitive"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        java_dep = next(
            d for d in data["dependencies"] if d["name"] == "org.example:guava-style-lib"
        )
        assert java_dep["ecosystem"] == "java"
        assert java_dep["license"] == "Apache-2.0"


class TestDotnetEcosystem:
    @respx.mock
    def test_check_resolves_nuget_dep_via_flatcontainer(self, tmp_path):
        # End-to-end: .csproj discovery → NuGet flatcontainer license fetch
        # → NuGet.org URL in package_url. Skip transitive (--no-transitive)
        # to keep the mocks minimal — the transitive path is exercised in
        # the test_transitive Dotnet suite.
        (tmp_path / "App.csproj").write_text(
            textwrap.dedent("""\
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
              </ItemGroup>
            </Project>
            """),
            encoding="utf-8",
        )
        # NuGet flatcontainer serves .nuspec with the modern <license type="expression">.
        respx.get(
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.nuspec"
        ).mock(
            return_value=httpx.Response(
                200,
                text="""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.1</version>
    <license type="expression">MIT</license>
  </metadata>
</package>""",
            )
        )
        # Suppress deps.dev batch (Tier 2 pre-pass) and v3 (Tier 3 fallback)
        # — Tier 1 (NuGet flatcontainer) already supplied the license, so
        # the CLI should never hit either of these.
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []}),
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--path",
                str(tmp_path),
                "--no-transitive",
                "--no-strict",
                "-f",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        dotnet_dep = next(d for d in data["dependencies"] if d["name"] == "Newtonsoft.Json")
        assert dotnet_dep["ecosystem"] == "dotnet"
        assert dotnet_dep["license"] == "MIT"
        assert dotnet_dep["package_url"] == (
            "https://www.nuget.org/packages/Newtonsoft.Json/13.0.1"
        )


class TestPhpEcosystem:
    @respx.mock
    def test_check_resolves_php_dep_via_lockfile(self, tmp_path):
        # End-to-end: composer.json + composer.lock discovery → lockfile-
        # first resolver returns the embedded SPDX license without any
        # HTTP fetch → Packagist.org URL in package_url. The Packagist
        # endpoint is registered with assert_all_called=False to confirm
        # ZERO fetches were made (the lockfile path is hit instead).
        (tmp_path / "composer.json").write_text(
            json.dumps(
                {
                    "name": "acme/demo",
                    "license": "MIT",
                    "require": {"acme/lib": "^1.0"},
                }
            )
        )
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "acme/lib",
                            "version": "1.2.3",
                            "source": {
                                "type": "git",
                                "url": "https://github.com/acme/lib.git",
                            },
                            "license": ["MIT"],
                        }
                    ]
                }
            )
        )
        packagist_route = respx.get("https://repo.packagist.org/p2/acme/lib.json").mock(
            return_value=httpx.Response(500)
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []}),
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--path",
                str(tmp_path),
                "--no-strict",
                "-f",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        php_dep = next(d for d in data["dependencies"] if d["name"] == "acme/lib")
        assert php_dep["ecosystem"] == "php"
        assert php_dep["license"] == "MIT"
        assert php_dep["package_url"] == ("https://packagist.org/packages/acme/lib")
        # Critical: lockfile-first path returned without hitting Packagist.
        assert packagist_route.call_count == 0


class TestRubyEcosystem:
    @respx.mock
    def test_check_resolves_ruby_dep_via_rubygems(self, tmp_path):
        # End-to-end: Gemfile + Gemfile.lock → lockfile-driven resolution →
        # batch pre-pass empty → RubyGems v2 per-version → JSON output with
        # rubygems.org package URL.
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "acme-lib"\n')
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    acme-lib (1.2.3)\n"
            "\n"
            "DEPENDENCIES\n"
            "  acme-lib\n"
            "\n"
        )
        respx.get("https://rubygems.org/api/v2/rubygems/acme-lib/versions/1.2.3.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "acme-lib",
                    "number": "1.2.3",
                    "licenses": ["MIT"],
                    "homepage_uri": "https://example.com/acme-lib",
                    "source_code_uri": "https://github.com/acme/lib",
                    "dependencies": {"runtime": [], "development": []},
                },
            )
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []}),
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        ruby_dep = next(d for d in data["dependencies"] if d["name"] == "acme-lib")
        assert ruby_dep["ecosystem"] == "ruby"
        assert ruby_dep["license"] == "MIT"
        assert ruby_dep["package_url"] == ("https://rubygems.org/gems/acme-lib/versions/1.2.3")

    @respx.mock
    def test_deps_dev_batch_cache_hit_short_circuits(self, tmp_path):
        # When the deps.dev RUBYGEMS batch returns a license for the
        # (name, version) pair, the resolver returns the cached license
        # without hitting rubygems.org.
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "cached-gem"\n')
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    cached-gem (3.0.0)\n"
            "\n"
            "DEPENDENCIES\n"
            "  cached-gem\n"
            "\n"
        )
        rubygems_route = respx.get(
            "https://rubygems.org/api/v2/rubygems/cached-gem/versions/3.0.0.json"
        ).mock(return_value=httpx.Response(500))
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {
                                "versionKey": {
                                    "system": "RUBYGEMS",
                                    "name": "cached-gem",
                                    "version": "3.0.0",
                                }
                            },
                            "version": {
                                "versionKey": {
                                    "system": "RUBYGEMS",
                                    "name": "cached-gem",
                                    "version": "3.0.0",
                                },
                                "licenses": ["BSD-3-Clause"],
                                "links": [],
                            },
                        }
                    ],
                    "nextPageToken": "",
                },
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        dep = next(d for d in data["dependencies"] if d["name"] == "cached-gem")
        assert dep["license"] == "BSD-3-Clause"
        # Batch hit → no rubygems.org fetch.
        assert rubygems_route.call_count == 0

    @respx.mock
    def test_off_registry_gem_is_unknown_without_fetch(self, tmp_path):
        # GIT-sourced gem in Gemfile.lock → off-registry marker → resolver
        # short-circuits to UNKNOWN. The companion regular gem confirms the
        # rest of the pipeline still resolves normally.
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\n'
            'gem "regular"\n'
            'gem "edge", git: "https://github.com/example/edge.git"\n'
        )
        (tmp_path / "Gemfile.lock").write_text(
            "GIT\n"
            "  remote: https://github.com/example/edge.git\n"
            "  revision: deadbeef\n"
            "  specs:\n"
            "    edge (0.0.1)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    regular (1.0.0)\n"
            "\n"
            "DEPENDENCIES\n"
            "  edge!\n"
            "  regular\n"
            "\n"
        )
        edge_route = respx.get(
            "https://rubygems.org/api/v2/rubygems/edge/versions/0.0.1.json"
        ).mock(return_value=httpx.Response(500))
        respx.get("https://rubygems.org/api/v2/rubygems/regular/versions/1.0.0.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "regular",
                    "number": "1.0.0",
                    "licenses": ["MIT"],
                    "dependencies": {"runtime": [], "development": []},
                },
            )
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []}),
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        edge = next(d for d in data["dependencies"] if d["name"] == "edge")
        assert edge["ecosystem"] == "ruby"
        assert edge["license"] in ("UNKNOWN", "Unknown")
        # The internal off-registry marker must not leak into the JSON source.
        assert edge["source"] == ""
        # Off-registry short-circuits to unknown; no rubygems.org fetch on edge.
        assert edge_route.call_count == 0


class TestHexEcosystem:
    @respx.mock
    def test_check_resolves_hex_dep_via_hexpm(self, tmp_path):
        # End-to-end: mix.exs + mix.lock → lockfile-driven resolution →
        # hex.pm package endpoint → JSON with the hex.pm package URL.
        (tmp_path / "mix.exs").write_text(
            "defmodule M.MixProject do\n"
            "  def project, do: [app: :m, deps: deps()]\n"
            '  defp deps, do: [{:acme, "~> 1.0"}]\n'
            "end\n"
        )
        (tmp_path / "mix.lock").write_text(
            '%{\n  "acme": {:hex, :acme, "1.2.3", "h", [:mix], [], "hexpm", "h2"},\n}\n'
        )
        respx.get("https://hex.pm/api/packages/acme").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {
                        "licenses": ["MIT"],
                        "links": {"GitHub": "https://github.com/acme/acme"},
                    },
                    "latest_stable_version": "1.2.3",
                },
            )
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []})
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        dep = next(d for d in data["dependencies"] if d["name"] == "acme")
        assert dep["ecosystem"] == "hex"
        assert dep["license"] == "MIT"
        assert dep["package_url"] == "https://hex.pm/packages/acme/1.2.3"

    @respx.mock
    def test_check_resolves_r_dep_via_cran_index(self, tmp_path):
        # End-to-end: DESCRIPTION + renv.lock → lockfile-driven resolution →
        # official CRAN PACKAGES index (fetched once) → JSON with the CRAN URL.
        (tmp_path / "DESCRIPTION").write_text("Package: myproj\nLicense: MIT\nImports: jsonlite\n")
        (tmp_path / "renv.lock").write_text(
            json.dumps(
                {
                    "Packages": {
                        "jsonlite": {
                            "Package": "jsonlite",
                            "Version": "2.0.0",
                            "Source": "Repository",
                            "Repository": "CRAN",
                        }
                    }
                }
            )
        )
        respx.get("https://cran.r-project.org/src/contrib/PACKAGES").mock(
            return_value=httpx.Response(
                200, text="Package: jsonlite\nVersion: 2.0.0\nLicense: MIT + file LICENSE\n"
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        dep = next(d for d in data["dependencies"] if d["name"] == "jsonlite")
        assert dep["ecosystem"] == "r"
        assert dep["license"] == "MIT"
        assert dep["package_url"] == "https://cran.r-project.org/package=jsonlite"

    @respx.mock
    def test_check_resolves_renv_only_project(self, tmp_path):
        # renv.lock with NO DESCRIPTION (analysis-project layout): zero direct
        # deps from manifest discovery, but the lockfile must still be resolved.
        # Regression — the empty-deps gate previously skipped resolution
        # entirely, so these projects reported nothing.
        (tmp_path / "renv.lock").write_text(
            json.dumps(
                {
                    "Packages": {
                        "cli": {
                            "Package": "cli",
                            "Version": "3.6.6",
                            "Source": "Repository",
                            "Repository": "CRAN",
                        },
                        "rlang": {
                            "Package": "rlang",
                            "Version": "1.1.0",
                            "Source": "Repository",
                            "Repository": "CRAN",
                        },
                    }
                }
            )
        )
        respx.get("https://cran.r-project.org/src/contrib/PACKAGES").mock(
            return_value=httpx.Response(
                200,
                text=(
                    "Package: cli\nVersion: 3.6.6\nLicense: MIT + file LICENSE\n\n"
                    "Package: rlang\nVersion: 1.1.0\nLicense: MIT + file LICENSE\n"
                ),
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        r = {x["name"]: x for x in data["dependencies"] if x["ecosystem"] == "r"}
        assert set(r) == {"cli", "rlang"}
        assert r["cli"]["license"] == "MIT"

    @respx.mock
    def test_off_registry_dep_unknown_without_fetch(self, tmp_path):
        # A git-sourced dep in mix.lock → off-registry → UNKNOWN, no fetch,
        # internal marker dropped from the JSON source.
        (tmp_path / "mix.exs").write_text(
            "defmodule M.MixProject do\n"
            "  def project, do: [app: :m, deps: deps()]\n"
            "  defp deps do\n"
            '    [{:regular, "~> 1.0"}, {:edge, github: "me/edge"}]\n'
            "  end\n"
            "end\n"
        )
        (tmp_path / "mix.lock").write_text(
            "%{\n"
            '  "regular": {:hex, :regular, "1.0.0", "h", [:mix], [], "hexpm", "h2"},\n'
            '  "edge": {:git, "https://github.com/me/edge.git", "sha", []},\n'
            "}\n"
        )
        edge_route = respx.get("https://hex.pm/api/packages/edge").mock(
            return_value=httpx.Response(500)
        )
        respx.get("https://hex.pm/api/packages/regular").mock(
            return_value=httpx.Response(
                200,
                json={"meta": {"licenses": ["MIT"], "links": {}}, "latest_stable_version": "1.0.0"},
            )
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []})
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        edge = next(d for d in data["dependencies"] if d["name"] == "edge")
        assert edge["ecosystem"] == "hex"
        assert edge["license"] in ("UNKNOWN", "Unknown")
        assert edge["source"] == ""
        assert edge_route.call_count == 0

    @respx.mock
    def test_erlang_mk_project_resolves_via_hexpm(self, tmp_path):
        # erlang.mk Makefile (no lock) → manifest-only fallback walk → hex.pm.
        # A workspace sibling (in a sub-app Makefile) is filtered out.
        (tmp_path / "Makefile").write_text(
            "PROJECT = myapp\n"
            "DEPS = cowlib internal_app\n"
            "dep_cowlib = hex 2.12.1\n"
            "include erlang.mk\n"
        )
        (tmp_path / "apps" / "internal_app").mkdir(parents=True)
        (tmp_path / "apps" / "internal_app" / "Makefile").write_text(
            "PROJECT = internal_app\ninclude erlang.mk\n"
        )
        respx.get("https://hex.pm/api/packages/cowlib").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"licenses": ["ISC"], "links": {}},
                    "latest_stable_version": "2.12.1",
                },
            )
        )
        respx.get("https://hex.pm/api/packages/cowlib/releases/2.12.1").mock(
            return_value=httpx.Response(200, json={"requirements": {}})
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(200, json={"responses": []})
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "--no-strict", "-f", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {d["name"]: d for d in data["dependencies"]}
        assert names["cowlib"]["ecosystem"] == "hex"
        assert names["cowlib"]["license"] == "ISC"
        assert names["cowlib"]["package_url"] == "https://hex.pm/packages/cowlib/2.12.1"
        # internal_app is a workspace sibling → filtered, not resolved.
        assert "internal_app" not in names


class TestTransitiveFlag:
    @respx.mock
    def test_transitive_uses_uv_lockfile_when_present(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["click"]
            """)
        )
        (tmp_path / "uv.lock").write_text(
            textwrap.dedent("""\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            dependencies = [
                { name = "colorama" },
            ]

            [[package]]
            name = "colorama"
            version = "0.4.6"
            """)
        )
        _mock_pypi("click", "BSD-3-Clause", version="8.3.3")
        _mock_pypi("colorama", "BSD-3-Clause", version="0.4.6")

        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", "--transitive"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert names == {"click", "colorama"}
        # Verify direct/transitive marking
        click_dep = next(d for d in data["dependencies"] if d["name"] == "click")
        colorama_dep = next(d for d in data["dependencies"] if d["name"] == "colorama")
        assert click_dep["depth"] == 0
        assert click_dep["is_transitive"] is False
        assert colorama_dep["depth"] == 1
        assert colorama_dep["is_transitive"] is True
        assert colorama_dep["direct_ancestors"] == ["click"]

    @respx.mock
    def test_transitive_falls_back_to_registry_when_no_lockfile(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["foo"]
            """)
        )
        respx.get("https://pypi.org/pypi/foo/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "classifiers": [],
                        "requires_dist": ["bar"],
                    },
                    "releases": {"1.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "classifiers": [],
                        "requires_dist": ["bar"],
                    },
                },
            )
        )
        respx.get("https://pypi.org/pypi/bar/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "2.0.0",
                        "license": "MIT",
                        "classifiers": [],
                        "requires_dist": [],
                    },
                    "releases": {"2.0.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/bar/2.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "2.0.0",
                        "license": "MIT",
                        "classifiers": [],
                        "requires_dist": [],
                    },
                },
            )
        )

        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", "--transitive"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert names == {"foo", "bar"}

    @respx.mock
    def test_no_transitive_skips_lockfile(self, tmp_path):
        """`--no-transitive` opts out of the lockfile walk; only direct deps surface."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["click"]
            """)
        )
        # uv.lock present but should be ignored with --no-transitive
        (tmp_path / "uv.lock").write_text(
            textwrap.dedent("""\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"

            [[package]]
            name = "colorama"
            version = "0.4.6"
            """)
        )
        _mock_pypi("click", "BSD-3-Clause")

        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", "--no-transitive"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert names == {"click"}

    @respx.mock
    def test_transitive_progress_message(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["click"]
            """)
        )
        (tmp_path / "uv.lock").write_text(
            textwrap.dedent("""\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            """)
        )
        _mock_pypi("click", "BSD-3-Clause", version="8.3.3")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--transitive"])
        assert result.exit_code == 0
        assert "Resolving transitive graph" in result.output

    @respx.mock
    def test_table_nests_transitive_under_direct(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["click"]
            """)
        )
        (tmp_path / "uv.lock").write_text(
            textwrap.dedent("""\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            dependencies = [
                { name = "colorama" },
            ]

            [[package]]
            name = "colorama"
            version = "0.4.6"
            """)
        )
        _mock_pypi("click", "BSD-3-Clause", version="8.3.3")
        _mock_pypi("colorama", "BSD-3-Clause", version="0.4.6")

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "--transitive"])
        assert result.exit_code == 0
        # Source column header is present (even when rich truncates the cell value
        # at narrow terminal widths, the header label survives).
        assert "Source" in result.output
        # Transitive row is indented beneath the direct dep.
        assert "└─ colorama" in result.output

    @respx.mock
    def test_markdown_renders_source_column_with_manifest_file(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["click"]
            """)
        )
        (tmp_path / "uv.lock").write_text(
            textwrap.dedent("""\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            dependencies = [
                { name = "colorama" },
            ]

            [[package]]
            name = "colorama"
            version = "0.4.6"
            """)
        )
        _mock_pypi("click", "BSD-3-Clause", version="8.3.3")
        _mock_pypi("colorama", "BSD-3-Clause", version="0.4.6")

        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "markdown", "--transitive"]
        )
        assert result.exit_code == 0
        assert "|Package|Ecosystem|Group|Source|License|Risk|Status|" in result.output
        # Direct dep carries pyproject.toml in the Source column; transitive is empty.
        assert "|click (8.3.3)" in result.output.split("\n")[5] or "click" in result.output
        assert "pyproject.toml" in result.output
        assert "└─ " in result.output


class TestRegistryCacheDedupe:
    """The cli wires one `RegistryCache` through both the walker and the
    license-resolution fan-out. URLs the walker has already pulled are served
    from memory the second time around. These tests pin the dedupe contract
    at the cli level."""

    @respx.mock
    def test_python_transitive_walk_avoids_second_license_fetch(self, tmp_path):
        # The walker's per-version fetch and resolve_python_license's
        # per-version fetch target the same URL. With the cache, that URL is
        # hit exactly once across the whole scan.
        pypi_version_route = respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "requires_dist": [],
                        "classifiers": [],
                    }
                },
            )
        )
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["foo==1.0.0"]
            """)
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        # Walker fetches once; license resolution finds the cache and skips
        # the network. Without dedupe this would be 2.
        assert pypi_version_route.call_count == 1

    @respx.mock
    def test_no_transitive_still_makes_license_call(self, tmp_path):
        # `--no-transitive` skips the walker so there's nothing to pre-warm
        # the cache. The license-resolution path goes to the network — once.
        pypi_version_route = respx.get("https://pypi.org/pypi/foo/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "classifiers": [],
                    }
                },
            )
        )
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["foo==1.0.0"]
            """)
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["check", "--path", str(tmp_path), "-f", "json", "--no-transitive"]
        )
        assert result.exit_code == 0
        assert pypi_version_route.call_count == 1

    @respx.mock
    def test_walker_dedupes_same_name_across_different_specs(self, tmp_path):
        # numpy is requested from two different parents at two different
        # specs. The walker resolves both, but `/pypi/numpy/json` (the
        # version-selection endpoint) is hit exactly once thanks to the
        # cache. Without dedupe, every spec triggers its own fetch.
        numpy_project = respx.get("https://pypi.org/pypi/numpy/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "2.0.0", "classifiers": []},
                    "releases": {"2.0.0": [], "1.26.0": []},
                },
            )
        )
        respx.get("https://pypi.org/pypi/numpy/2.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "2.0.0",
                        "license_expression": "BSD-3-Clause",
                        "classifiers": [],
                    }
                },
            )
        )
        respx.get("https://pypi.org/pypi/parent_a/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent_a/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "requires_dist": ["numpy>=1.0"],
                        "classifiers": [],
                    }
                },
            )
        )
        respx.get("https://pypi.org/pypi/parent_b/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"version": "1.0.0", "classifiers": []}, "releases": {"1.0.0": []}},
            )
        )
        respx.get("https://pypi.org/pypi/parent_b/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license_expression": "MIT",
                        "requires_dist": ["numpy>=2.0"],
                        "classifiers": [],
                    }
                },
            )
        )

        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["parent_a==1.0.0", "parent_b==1.0.0"]
            """)
        )
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        # /pypi/numpy/json is the version-selection endpoint. Both parents
        # depend on numpy with different specs; without dedupe each would
        # fetch it. With the cache, exactly one fetch.
        assert numpy_project.call_count == 1


class TestExcludeDirsAndNestedGit:
    """`--exclude-dirs` flag + auto-skip nested git repos.

    Both commands accept ``--exclude-dirs PATH`` (repeatable). The walker
    also auto-skips any descended subdirectory that contains its own ``.git``
    so cloned/vendored repos under a parent project don't pollute the scan.
    """

    @respx.mock
    def test_check_exclude_dirs_skips_subtree(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        inner = tmp_path / "vendored"
        inner.mkdir()
        (inner / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "vendored-pkg"
            license = {text = "MIT"}
            dependencies = ["gpl-lib"]
            """)
        )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-lib", "GPL-3.0")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "--exclude-dirs", "vendored"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert "requests" in names
        assert "gpl-lib" not in names

    @respx.mock
    def test_check_exclude_dirs_accepts_absolute_path(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        inner = tmp_path / "vendored"
        inner.mkdir()
        (inner / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "vendored-pkg"
            license = {text = "MIT"}
            dependencies = ["gpl-lib"]
            """)
        )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-lib", "GPL-3.0")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "--exclude-dirs", str(inner)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert "gpl-lib" not in names

    @respx.mock
    def test_check_exclude_dirs_multiple_values(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        for sub, dep in (("a", "gpl-a"), ("b", "gpl-b")):
            d = tmp_path / sub
            d.mkdir()
            (d / "pyproject.toml").write_text(
                textwrap.dedent(f"""\
                [project]
                name = "{sub}-pkg"
                license = {{text = "MIT"}}
                dependencies = ["{dep}"]
                """)
            )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-a", "GPL-3.0")
        _mock_pypi("gpl-b", "GPL-3.0")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check",
                "--path",
                str(tmp_path),
                "-f",
                "json",
                "--exclude-dirs",
                "a",
                "--exclude-dirs",
                "b",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert "gpl-a" not in names
        assert "gpl-b" not in names

    @respx.mock
    def test_check_exclude_dirs_comma_separated(self, tmp_path):
        # Single invocation, comma-separated paths.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        for sub, dep in (("a", "gpl-a"), ("b", "gpl-b")):
            d = tmp_path / sub
            d.mkdir()
            (d / "pyproject.toml").write_text(
                textwrap.dedent(f"""\
                [project]
                name = "{sub}-pkg"
                license = {{text = "MIT"}}
                dependencies = ["{dep}"]
                """)
            )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-a", "GPL-3.0")
        _mock_pypi("gpl-b", "GPL-3.0")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "--exclude-dirs", "a,b"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert "gpl-a" not in names
        assert "gpl-b" not in names

    def test_check_exclude_dirs_ignores_empty_segments(self, tmp_path):
        # Empty/whitespace-only comma segments in a single value are skipped
        # (e.g. trailing comma or stray spaces from shell tab-completion).
        # Walker still scans the project — no deps, but the run succeeds.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = []
            """)
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "json", "--exclude-dirs", " a , ,"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        assert data["project_license"] == "MIT"

    @respx.mock
    def test_workspace_internal_dep_filter_emits_message(self, tmp_path):
        # Root pyproject lists `sub-pkg` as a dep; a nested pyproject declares
        # `name = "sub-pkg"`. That dep reference must be filtered out by the
        # workspace-local-package check, which surfaces a stderr message
        # reporting how many references were filtered (one, in this case).
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests", "sub-pkg"]
            """)
        )
        sub = tmp_path / "libs" / "sub"
        sub.mkdir(parents=True)
        (sub / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "sub-pkg"
            license = {text = "MIT"}
            dependencies = []
            """)
        )
        _mock_pypi("requests", "MIT")
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        assert "Excluded 1 local Python workspace package reference(s)" in result.stderr
        data = json.loads(result.stdout[result.stdout.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert "requests" in names
        assert "sub-pkg" not in names

    @respx.mock
    def test_check_auto_skips_nested_git_repo(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["requests"]
            """)
        )
        # A descended subdir with its own .git — must be skipped without
        # the user having to pass --exclude-dirs.
        cloned = tmp_path / "cloned-dep"
        (cloned / ".git").mkdir(parents=True)
        (cloned / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "cloned-pkg"
            license = {text = "MIT"}
            dependencies = ["gpl-lib"]
            """)
        )
        _mock_pypi("requests", "MIT")
        _mock_pypi("gpl-lib", "GPL-3.0")
        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        names = {dep["name"] for dep in data["dependencies"]}
        assert "requests" in names
        assert "gpl-lib" not in names

    @respx.mock
    def test_init_review_file_exclude_dirs(self, tmp_path):
        # Mirror flag on the second command — same exclusion semantics.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "MIT"}
            dependencies = ["gpl-lib"]
            """)
        )
        inner = tmp_path / "vendored"
        inner.mkdir()
        (inner / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "vendored-pkg"
            license = {text = "MIT"}
            dependencies = ["other-gpl-lib"]
            """)
        )
        _mock_pypi("gpl-lib", "GPL-3.0")
        _mock_pypi("other-gpl-lib", "GPL-3.0")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--exclude-dirs",
                "vendored",
            ],
        )
        assert result.exit_code == 0
        review_text = (tmp_path / "licenseal.review.toml").read_text(encoding="utf-8")
        assert "gpl-lib" in review_text
        assert "other-gpl-lib" not in review_text


class TestWarnUnscaffoldableOverflow:
    def test_more_than_five_entries_emits_overflow_suffix(self, capsys):
        # _warn_unscaffoldable lists up to five names inline; once there are
        # more than five, the remainder is rolled up into "(+N more)" so the
        # stderr note stays readable on real scans.
        _warn_unscaffoldable([f"python:pkg-{i}" for i in range(7)])
        captured = capsys.readouterr()
        assert "(+2 more)" in captured.err


class TestDepsDevBatchHitShortcut:
    """End-to-end coverage for the Mode-C batch-hit shortcut.

    For Python / npm / Rust, the CLI POSTs to deps.dev /v3alpha/versionbatch
    before any per-package resolver runs. When the batch returns a real SPDX
    answer for a pinned dep, the cached LicenseInfo is rebound to the dep
    and returned directly — the per-package PyPI / npm registry / crates.io
    fetch is skipped. These tests verify that shortcut by mocking ONLY the
    batch POST (no per-package mock — if the shortcut works, the per-package
    URL is never hit; if it doesn't, respx would fail the test with an
    AllMockedAssertionError).

    Each test opts out of the conftest's empty-batch default so the
    test-specific batch response wins.
    """

    @staticmethod
    def _batch_response(system: str, name: str, version: str, licenses: list[str]) -> dict:
        """deps.dev versionbatch response shape for one (system, name, version)."""
        return {
            "responses": [
                {
                    "request": {"versionKey": {"system": system, "name": name, "version": version}},
                    "version": {
                        "versionKey": {"system": system, "name": name, "version": version},
                        "licenses": licenses,
                        "links": [],
                    },
                }
            ]
        }

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_python_batch_hit_skips_pypi_license_fetch(self, tmp_path):
        # PyPI mock returns BSD-3-Clause; deps.dev batch returns Apache-2.0.
        # The reported license is whichever path the resolver took — if the
        # batch shortcut fired, it's Apache-2.0; if it fell through to PyPI,
        # it'd be BSD-3-Clause. (The transitive walker hits PyPI for the
        # children list regardless, so PyPI must still be mocked.)
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myapp"
            version = "0.1.0"
            license = "MIT"
            dependencies = ["requests==2.32.3"]
            """)
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200, json=self._batch_response("PYPI", "requests", "2.32.3", ["Apache-2.0"])
            )
        )
        respx.get("https://pypi.org/pypi/requests/2.32.3/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "name": "requests",
                        "version": "2.32.3",
                        "license": "BSD-3-Clause",
                        "requires_dist": [],
                    }
                },
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        py_dep = next(d for d in data["dependencies"] if d["name"] == "requests")
        assert py_dep["ecosystem"] == "python"
        assert py_dep["license"] == "Apache-2.0"  # batch source, not BSD-3-Clause

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_npm_batch_hit_skips_registry_license_fetch(self, tmp_path):
        # npm registry mock returns BSD-3-Clause; deps.dev batch returns MIT.
        # The result must be the batch's MIT if the shortcut fires.
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "myapp",
                    "version": "0.1.0",
                    "license": "MIT",
                    "dependencies": {"lodash": "4.17.21"},
                }
            )
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200, json=self._batch_response("NPM", "lodash", "4.17.21", ["MIT"])
            )
        )
        respx.get("https://registry.npmjs.org/lodash/4.17.21").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "lodash",
                    "version": "4.17.21",
                    "license": "BSD-3-Clause",
                    "dependencies": {},
                },
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        npm_dep = next(d for d in data["dependencies"] if d["name"] == "lodash")
        assert npm_dep["ecosystem"] == "npm"
        assert npm_dep["license"] == "MIT"  # batch source, not BSD-3-Clause

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_rust_batch_hit_skips_crates_io_license_fetch(self, tmp_path):
        # crates.io per-version mock returns BSD-3-Clause; deps.dev batch
        # returns Apache-2.0 OR MIT. The result must be the batch's value
        # if the shortcut fires.
        (tmp_path / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "myapp"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            serde = "=1.0.193"
            """)
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json=self._batch_response("CARGO", "serde", "1.0.193", ["Apache-2.0 OR MIT"]),
            )
        )
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193").mock(
            return_value=httpx.Response(
                200, json={"version": {"num": "1.0.193", "license": "BSD-3-Clause"}}
            )
        )
        respx.get("https://crates.io/api/v1/crates/serde").mock(
            return_value=httpx.Response(200, json={"crate": {"repository": ""}})
        )
        respx.get("https://crates.io/api/v1/crates/serde/1.0.193/dependencies").mock(
            return_value=httpx.Response(200, json={"dependencies": []})
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        rust_dep = next(d for d in data["dependencies"] if d["name"] == "serde")
        assert rust_dep["ecosystem"] == "rust"
        assert rust_dep["license"] == "Apache-2.0 OR MIT"  # batch source

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_java_batch_hit_skips_maven_central_fetch(self, tmp_path):
        # Maven Central per-POM mock returns BSD-3-Clause; deps.dev batch
        # returns Apache-2.0. The result must be the batch's value if the
        # shortcut fires. Transitive walker hits deps.dev's MAVEN
        # :dependencies endpoint, mocked here with an empty subgraph.
        (tmp_path / "pom.xml").write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<modelVersion>4.0.0</modelVersion>"
            "<groupId>com.example</groupId>"
            "<artifactId>myapp</artifactId>"
            "<version>0.1.0</version>"
            "<licenses><license><name>MIT</name></license></licenses>"
            "<dependencies>"
            "  <dependency>"
            "    <groupId>com.google.guava</groupId>"
            "    <artifactId>guava</artifactId>"
            "    <version>32.1.3-jre</version>"
            "  </dependency>"
            "</dependencies>"
            "</project>"
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json=self._batch_response(
                    "MAVEN", "com.google.guava:guava", "32.1.3-jre", ["Apache-2.0"]
                ),
            )
        )
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/"
            "com.google.guava%3Aguava/versions/32.1.3-jre:dependencies"
        ).mock(return_value=httpx.Response(200, json={"nodes": [], "edges": []}))
        # Maven Central POM mock — never reached if batch shortcut fires.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/google/guava/guava/"
            "32.1.3-jre/guava-32.1.3-jre.pom"
        ).mock(
            return_value=httpx.Response(
                200,
                text=(
                    '<project xmlns="http://maven.apache.org/POM/4.0.0">'
                    "<licenses><license><name>BSD-3-Clause</name></license></licenses>"
                    "</project>"
                ),
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        java_dep = next(d for d in data["dependencies"] if d["name"] == "com.google.guava:guava")
        assert java_dep["ecosystem"] == "java"
        assert java_dep["license"] == "Apache-2.0"  # batch source, not POM-walker

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_dotnet_batch_hit_skips_nuspec_fetch(self, tmp_path):
        # NuGet flatcontainer .nuspec carries BSD-3-Clause; deps.dev
        # batch returns MIT. The result must be the batch's MIT if the
        # shortcut fires. The same nuspec doubles as the transitive
        # walker's input (no <dependencies> → no transitives to walk).
        (tmp_path / "myapp.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk">'
            "<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>"
            "<ItemGroup>"
            '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />'
            "</ItemGroup>"
            "</Project>"
        )
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json=self._batch_response("NUGET", "Newtonsoft.Json", "13.0.3", ["MIT"]),
            )
        )
        respx.get(
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec"
        ).mock(
            return_value=httpx.Response(
                200,
                text=(
                    "<package><metadata><id>Newtonsoft.Json</id>"
                    '<license type="expression">BSD-3-Clause</license>'
                    "</metadata></package>"
                ),
            )
        )

        runner = CliRunner()
        result = runner.invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output[result.output.index("{") :])
        dotnet_dep = next(d for d in data["dependencies"] if d["name"] == "Newtonsoft.Json")
        assert dotnet_dep["ecosystem"] == "dotnet"
        assert dotnet_dep["license"] == "MIT"  # batch source


class TestCliMarkdownViolation:
    @respx.mock
    def test_markdown_with_violation_exits_nonzero(self, tmp_path):

        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
        [project]
        name = "myproject"
        license = {text = "MIT"}
        dependencies = ["gpl-lib"]
        """)
        )
        respx.get("https://pypi.org/pypi/gpl-lib/json").mock(
            return_value=httpx.Response(
                200,
                json={"info": {"license": "GPL-3.0", "version": "1.0", "classifiers": []}},
            )
        )
        respx.get("https://pypi.org/pypi/gpl-lib/1.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "GPL-3.0",
                        "version": "1.0",
                        "classifiers": [],
                        "requires_dist": [],
                    }
                },
            )
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "markdown"],
        )
        assert result.exit_code == 1
        assert "# License Analysis Report" in result.output
