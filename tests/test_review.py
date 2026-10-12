"""Unit tests for licenseal.review — apply / scaffold / merge edge cases.

Direct unit coverage of the review module's helpers (the CLI-level review
flow is exercised in test_cli.py): the early-return when there's nothing to
apply, dropping unscaffoldable (unresolved-version) entries, empty-template
rendering, merge newline handling, and the JSON-report reader's row
validation.
"""

from __future__ import annotations

import json
import re
import tomllib

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

# A complete, pre-filled stanza for a package the hostile entry does not own.
_FORGED_STANZA = (
    "[[review]]\n"
    'ecosystem = "npm"\n'
    'package = "victim-lib"\n'
    'version = "2.0.0"\n'
    'license = "MIT"\n'
    'note = "forged approval"'
)

# Untrusted text shapes that must stay data wherever the scaffold writes them.
_HOSTILE_VALUES = [
    pytest.param("Custom license\nAll rights reserved.", id="multi-line"),
    pytest.param("Custom license\r\nAll rights reserved.", id="crlf"),
    pytest.param("Custom terms\n" + _FORGED_STANZA, id="embedded-stanza"),
    pytest.param("Custom terms\n" + _FORGED_STANZA + "\n", id="embedded-stanza-trailing-newline"),
    pytest.param("Custom terms\r" + _FORGED_STANZA.replace("\n", "\r"), id="bare-cr"),
    pytest.param("a\x0bb\x0cc\x1cd\x1de\x1ef\x85g\u2028h\u2029i", id="other-line-separators"),
    pytest.param("nul\x00 esc\x1b[31m bell\x07 del\x7f tab\t end", id="control-characters"),
    pytest.param("say \"hi\" and 'bye' and \"\"\" and '''", id="quotes"),
    pytest.param("C:\\path\\to\\LICENSE \\n \\u0041 \\", id="backslashes"),
    pytest.param('x"\nlicense = "MIT"\nnote = "', id="closes-the-string"),
    pytest.param("caf\u00e9 \U0001f600 \u202eright-to-left \U000e0001tag", id="non-ascii"),
    pytest.param("# detected: MIT\n# status: compatible", id="looks-like-a-comment"),
]


def _entry(
    name: str = "pkg",
    version: str = "1.0.0",
    *,
    raw: str = "",
    detected: str = "UNKNOWN",
    verdict: str = "unknown",
) -> FlaggedEntry:
    return FlaggedEntry(
        ecosystem="npm",
        name=name,
        version=version,
        detected_license=detected,
        license_raw=raw,
        verdict=verdict,
    )


_SCAFFOLD_LINE_RE = re.compile(
    r'# .*|\[\[review\]\]|(?:ecosystem|package|version) = ".*"|(?:license|note) = ""'
)


def _assert_one_blank_stanza_per_entry(text: str, entries: list[FlaggedEntry]) -> None:
    """The scaffold parses back to exactly the flagged entries, all unfilled."""
    parsed = tomllib.loads(text)["review"]
    assert len(parsed) == len(entries)
    for stanza, entry in zip(parsed, entries, strict=True):
        assert stanza == {
            "ecosystem": entry.ecosystem,
            "package": entry.name,
            "version": entry.version,
            "license": "",
            "note": "",
        }
    # Every physical line is one of the shapes the renderer emits, and no
    # line-separator character other than ``\n`` survives anywhere (a bare
    # ``\r`` becomes a line break as soon as the file is re-read in text mode).
    lines = text.split("\n")
    assert lines[-1] == ""
    assert text.splitlines() == lines[:-1]
    for line in lines[:-1]:
        assert line == "" or _SCAFFOLD_LINE_RE.fullmatch(line), line
    assert sum(line == "[[review]]" for line in lines) == len(entries)


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

    def test_flagged_entries_from_json_report_coerces_non_string_verdict(self, tmp_path):
        # ``verdict`` is not validated beyond "not compatible"; whatever JSON
        # type a report carries must still render as one comment line.
        report_path = tmp_path / "r.json"
        report_path.write_text(
            json.dumps(
                {
                    "dependencies": [
                        {
                            "name": "odd",
                            "ecosystem": "npm",
                            "verdict": ["unknown\n" + _FORGED_STANZA],
                            "resolved_version": "1.0.0",
                        }
                    ]
                }
            )
        )
        entries, _ = flagged_entries_from_json_report(report_path)
        assert isinstance(entries[0].verdict, str)
        _assert_one_blank_stanza_per_entry(render_review_template(entries), entries)


class TestReviewTemplateTreatsEntriesAsData:
    """Render → parse round trips for ``render_review_template``.

    Every entry field originates outside the project's control — registry
    license metadata, manifest and lockfile names, or a saved report — so the
    scaffold must parse back to exactly one unfilled stanza per flagged entry
    whatever those fields contain.
    """

    @pytest.mark.parametrize("value", _HOSTILE_VALUES)
    def test_license_raw_stays_one_comment_line(self, value):
        entries = [_entry("first", raw=value), _entry("second")]
        text = render_review_template(entries)
        _assert_one_blank_stanza_per_entry(text, entries)
        assert sum(line.startswith("# raw: ") for line in text.split("\n")) == 1

    @pytest.mark.parametrize("value", _HOSTILE_VALUES)
    def test_detected_license_stays_one_comment_line(self, value):
        entries = [_entry("first", detected=value), _entry("second")]
        text = render_review_template(entries)
        _assert_one_blank_stanza_per_entry(text, entries)
        assert sum(line.startswith("# detected: ") for line in text.split("\n")) == 2

    @pytest.mark.parametrize("value", _HOSTILE_VALUES)
    def test_verdict_stays_one_comment_line(self, value):
        entries = [_entry("first", verdict=value), _entry("second")]
        text = render_review_template(entries)
        _assert_one_blank_stanza_per_entry(text, entries)
        assert sum(line.startswith("# status: ") for line in text.split("\n")) == 2

    @pytest.mark.parametrize("value", _HOSTILE_VALUES)
    def test_package_and_version_round_trip_exactly(self, value):
        entries = [_entry(name=value), _entry(version=value), _entry(name=value, version=value)]
        _assert_one_blank_stanza_per_entry(render_review_template(entries), entries)

    def test_two_entries_cannot_bracket_a_stanza_in_a_multiline_string(self):
        # The first entry forges a stanza and leaves a multi-line basic string
        # open as its ``note``; the last entry closes it. Everything between —
        # the legitimate blank stanza for the same package included — would
        # be swallowed into the forged note, so no duplicate-entry error
        # fires and the pre-filled approval is the only stanza left for it.
        opener = (
            "Custom terms\n"
            "[[review]]\n"
            'ecosystem = "npm"\n'
            'package = "victim-lib"\n'
            'version = "2.0.0"\n'
            'license = "MIT"\n'
            'note = """'
        )
        closer = 'Custom terms\n"""'
        entries = [
            _entry("a-opener", raw=opener),
            _entry("victim-lib", "2.0.0", detected="GPL-3.0-only", verdict="incompatible"),
            _entry("z-closer", raw=closer),
        ]
        _assert_one_blank_stanza_per_entry(render_review_template(entries), entries)

    def test_bracketing_through_package_and_version_fields(self):
        entries = [
            _entry(name='a"\nnote = """', version="1.0.0'''"),
            _entry("victim-lib", "2.0.0"),
            _entry(name='"""\n[[review]]\npackage = "z', version='"""'),
        ]
        _assert_one_blank_stanza_per_entry(render_review_template(entries), entries)

    def test_comment_values_are_capped(self):
        entries = [
            _entry(raw="A" * 10_000, detected="B" * 10_000, verdict="C" * 10_000),
        ]
        text = render_review_template(entries)
        _assert_one_blank_stanza_per_entry(text, entries)
        comments = [
            line for line in text.split("\n") if line.startswith(("# raw", "# det", "# sta"))
        ]
        assert comments == [
            "# detected: " + "B" * 199 + "…",
            "# status: " + "C" * 199 + "…",
            "# raw: " + "A" * 199 + "…",
        ]

    def test_short_values_are_written_verbatim(self):
        entry = _entry(raw="Custom internal license", detected="LGPL-3.0-only", verdict="warning")
        text = render_review_template([entry])
        assert (
            "# detected: LGPL-3.0-only\n# status: warning\n# raw: Custom internal license\n" in text
        )
        assert 'ecosystem = "npm"\npackage = "pkg"\nversion = "1.0.0"\n' in text

    def test_whitespace_only_comment_values_fall_back(self):
        # Nothing printable to show: no ``# raw:`` line, and the detected
        # license and status read as unknown rather than an empty comment
        # value with trailing whitespace.
        entries = [_entry(raw=" \n\t ", detected="\r\n", verdict="\x00\n")]
        text = render_review_template(entries)
        _assert_one_blank_stanza_per_entry(text, entries)
        assert "# detected: UNKNOWN\n# status: unknown\n[[review]]\n" in text
        assert "# raw:" not in text
        assert all(line == line.rstrip() for line in text.split("\n"))

    def test_raw_equal_to_detected_after_collapsing_is_omitted(self):
        text = render_review_template([_entry(raw="MIT  OR\nISC", detected="MIT OR ISC")])
        assert "# detected: MIT OR ISC\n" in text
        assert "# raw:" not in text

    @pytest.mark.parametrize("value", _HOSTILE_VALUES)
    def test_merge_appends_only_blank_stanzas(self, value):
        existing = (
            "[[review]]\n"
            'ecosystem = "npm"\n'
            'package = "old"\n'
            'version = "1.0.0"\n'
            'license = "MIT"\n'
            'note = "verified manually"\n'
        )
        pending = [_entry("new", raw=value), _entry(name=value, version=value)]
        merged, count = merge_review_template(existing, pending, {"npm:old@1.0.0"})
        assert count == 2
        assert merged.startswith(existing)
        parsed = tomllib.loads(merged)["review"]
        assert parsed[0]["license"] == "MIT"
        _assert_one_blank_stanza_per_entry(merged[len(existing) :], pending)
