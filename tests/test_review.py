"""Unit tests for licenseal.review — apply / scaffold / merge edge cases.

Direct unit coverage of the review module's helpers (the CLI-level review
flow is exercised in test_cli.py): the early-return when there's nothing to
apply, dropping unscaffoldable (unresolved-version) entries, empty-template
rendering, merge newline handling, and the JSON-report reader's row
validation.
"""

from __future__ import annotations

import json

import click
import pytest

from licenseal.models import (
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
    flagged_entries_from_json_report,
    flagged_entries_from_results,
    merge_review_template,
    render_review_template,
)


class TestReviewModuleEdgeCases:
    def test_apply_returns_early_when_nothing_to_do(self):

        info = LicenseInfo(
            dependency=Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON),
            license_id="MIT",
            license_raw="MIT",
            resolved_version="1.0.0",
        )
        # Empty contents — nothing to apply, must not touch the dep.
        apply_reviewed_licenses([info], ReviewFileContents(), set())
        assert info.reviewed is False

    def test_flagged_entries_skip_unresolved_versions(self):

        result = CompatibilityResult(
            license_info=LicenseInfo(
                dependency=Dependency(
                    name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON
                ),
                license_id="UNKNOWN",
                license_raw="",
                resolved_version="",  # unresolved → not scaffoldable
            ),
            risk_level=RiskLevel.UNKNOWN,
            verdict=CompatibilityVerdict.UNKNOWN,
        )
        entries, unscaffoldable = flagged_entries_from_results([result])
        assert entries == []
        assert unscaffoldable == ["python:pkg"]

    def test_render_review_template_empty(self):

        assert render_review_template([]) == ""

    def test_merge_review_template_into_empty_text(self):

        entry = FlaggedEntry(
            ecosystem="python",
            name="pkg",
            version="1.0.0",
            detected_license="UNKNOWN",
            license_raw="",
            verdict="unknown",
        )
        merged, count = merge_review_template("", [entry], set())
        assert count == 1
        assert 'package = "pkg"' in merged

    def test_merge_review_template_appends_newline_when_missing(self):

        entry = FlaggedEntry(
            ecosystem="python",
            name="new-pkg",
            version="1.0.0",
            detected_license="UNKNOWN",
            license_raw="",
            verdict="unknown",
        )
        existing = (
            '[[review]]\necosystem = "python"\npackage = "old"\nversion = "1.0.0"\nlicense = "MIT"'
        )
        merged, count = merge_review_template(existing, [entry], {"python:old@1.0.0"})
        assert count == 1
        assert merged.startswith(existing + "\n\n")
        assert 'package = "new-pkg"' in merged

    def test_flagged_entries_from_json_report_skips_invalid_rows(self, tmp_path):

        report_path = tmp_path / "r.json"
        report_path.write_text(
            json.dumps(
                {
                    "dependencies": [
                        # not a dict
                        "not-a-dict",
                        # compatible — skipped
                        {
                            "name": "ok",
                            "ecosystem": "python",
                            "verdict": "compatible",
                            "resolved_version": "1.0.0",
                        },
                        # missing version
                        {
                            "name": "noversion",
                            "ecosystem": "python",
                            "verdict": "unknown",
                            "resolved_version": "",
                        },
                        # invalid ecosystem
                        {
                            "name": "alien",
                            "ecosystem": "swift",
                            "verdict": "unknown",
                            "resolved_version": "1.0.0",
                        },
                        # missing name
                        {
                            "name": "",
                            "ecosystem": "python",
                            "verdict": "unknown",
                            "resolved_version": "1.0.0",
                        },
                        # valid row
                        {
                            "name": "mystery",
                            "ecosystem": "python",
                            "verdict": "unknown",
                            "resolved_version": "1.0.0",
                            "detected_license": "UNKNOWN",
                            "license_raw": "Custom",
                        },
                    ]
                }
            )
        )
        entries, unscaffoldable = flagged_entries_from_json_report(report_path)
        assert [e.name for e in entries] == ["mystery"]
        # ``noversion`` was flagged but had no resolved version → unscaffoldable.
        # ``alien`` (invalid ecosystem) and the empty-name row are dropped entirely.
        assert unscaffoldable == ["python:noversion"]

    def test_flagged_entries_from_json_rejects_non_object_root(self, tmp_path):

        bad = tmp_path / "bad.json"
        bad.write_text("[]")
        with pytest.raises(click.ClickException, match="expected a JSON object"):
            flagged_entries_from_json_report(bad)

    def test_flagged_entries_from_json_rejects_non_list_dependencies(self, tmp_path):

        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"dependencies": {}}))
        with pytest.raises(click.ClickException, match="'dependencies' must be a list"):
            flagged_entries_from_json_report(bad)
