"""``init-review-file`` and a dependency whose stanza a TOML file cannot hold.

A JSON manifest or report can carry a lone surrogate (an unpaired
``\\uD800``-``\\uDFFF`` escape) in a dependency's name, version, or source. A
TOML string cannot: not as a character, and not as a ``\\uXXXX`` escape. Such
a dependency gets no stanza and is named on stderr. Every other stanza is
written, and the file loads.

Manifests and reports are written as raw JSON text, so the escapes stay
unpaired on disk exactly as a scan would meet them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import respx
from click.testing import CliRunner, Result

from licenseal.cli import main
from licenseal.review import (
    FlaggedEntry,
    load_review_file,
    render_review_template,
    toml_can_hold,
    writable_entries,
)
from tests._helpers import _check_json, _mock_npm

_REASON = (
    "a lone surrogate in the name, version, or source, which a TOML file cannot hold, "
    "so no review can be recorded for it"
)
_PLAIN_KEY = "off-registry npm:plain from git+https://github.com/team/plain"


def _init(project: Path, *flags: str) -> Result:
    return CliRunner().invoke(main, ["init-review-file", "--path", str(project), *flags])


def _project(tmp_path: Path, *, plain: bool = True) -> Path:
    """Off-registry npm dependencies: two that TOML cannot name, and a plain one."""
    dependencies = [
        '"bad\\ud800name": "github:team/first"',
        '"odd-source": "git+https://git.example.org/re\\udc00po.git"',
    ]
    if plain:
        dependencies.append('"plain": "github:team/plain"')
    (tmp_path / "package.json").write_text(
        '{"name": "app", "license": "MIT", "dependencies": {' + ", ".join(dependencies) + "}}",
        encoding="utf-8",
    )
    return tmp_path


def _note(count: int, *names: str) -> str:
    noun = "dependency" if count == 1 else "dependencies"
    return f"Note: {count} flagged {noun} could not be scaffolded ({_REASON}): {', '.join(names)}."


class TestTomlCanHold:
    @pytest.mark.parametrize(
        "value", ["", "plain", "naïve", "\U0001f600", "tab\there", "\x00", "�"]
    )
    def test_scalar_values(self, value):
        assert toml_can_hold(value) is True

    @pytest.mark.parametrize("value", ["\ud800", "a\udfffb", "\udc00\ud800", "x\udbff"])
    def test_lone_surrogates(self, value):
        assert toml_can_hold(value) is False


class TestWritableEntries:
    @staticmethod
    def _entry(name: str = "pkg", version: str = "1.0.0", origin: str = "") -> FlaggedEntry:
        return FlaggedEntry(
            ecosystem="npm",
            name=name,
            version=version,
            detected_license="UNKNOWN",
            license_raw="",
            verdict="unknown",
            origin=origin,
        )

    def test_entry_is_left_out_for_any_of_its_three_keys(self):
        kept = [self._entry("a"), self._entry("b", origin="git+https://git.example.org/b")]
        dropped = [
            self._entry("na\ud800me"),
            self._entry("version", version="1.0.0\udc00"),
            self._entry("source", origin="git+https://git.example.org/\udfff"),
        ]
        writable, unwritable = writable_entries([kept[0], *dropped, kept[1]])
        assert writable == kept
        assert unwritable == ["npm:na\ud800me", "npm:version", "npm:source"]

    def test_surrogate_in_a_comment_field_does_not_cost_the_stanza(self):
        # The detected license, the raw license, and the verdict only reach
        # comment lines, where an unprintable character becomes a space.
        entry = FlaggedEntry(
            ecosystem="npm",
            name="pkg",
            version="1.0.0",
            detected_license="Cus\ud800tom",
            license_raw="raw\udc00text",
            verdict="unk\udfffnown",
        )
        assert writable_entries([entry]) == ([entry], [])
        text = render_review_template([entry])
        text.encode("utf-8")
        assert "# detected: Cus tom" in text

    def test_nothing_to_split(self):
        assert writable_entries([]) == ([], [])


class TestLiveScan:
    def test_unwritable_stanzas_are_left_out_and_the_file_loads(self, tmp_path):
        result = _init(_project(tmp_path))
        assert result.exit_code == 0
        assert "Wrote licenseal.review.toml with 1 review entry." in result.output
        assert _note(2, "npm:bad\\ud800name", "npm:odd-source") in result.output
        # The file is valid TOML and holds the one stanza that could be written.
        assert load_review_file(tmp_path).incomplete == [_PLAIN_KEY]
        text = (tmp_path / "licenseal.review.toml").read_text(encoding="utf-8")
        assert text.count("[[review]]") == 1
        assert "bad" not in text and "odd-source" not in text

    def test_filled_in_file_is_applied_by_check(self, tmp_path):
        project = _project(tmp_path)
        _init(project)
        review = project / "licenseal.review.toml"
        review.write_text(
            review.read_text(encoding="utf-8").replace('license = ""', 'license = "MIT"'),
            encoding="utf-8",
            newline="\n",
        )
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert {dep["name"]: dep["reviewed"] for dep in data["dependencies"]} == {
            "bad\ud800name": False,
            "odd-source": False,
            "plain": True,
        }

    def test_nothing_writable_writes_no_file(self, tmp_path):
        result = _init(_project(tmp_path, plain=False))
        assert result.exit_code == 0
        assert "No reviewable flagged dependencies found." in result.output
        assert _note(2, "npm:bad\\ud800name", "npm:odd-source") in result.output
        assert not (tmp_path / "licenseal.review.toml").exists()

    def test_merge_appends_only_what_can_be_written(self, tmp_path):
        project = _project(tmp_path)
        existing = (
            '[[review]]\necosystem = "npm"\npackage = "kept"\nversion = "1.0.0"\n'
            'license = "MIT"\nnote = "earlier review"\n'
        )
        (project / "licenseal.review.toml").write_text(existing, encoding="utf-8", newline="\n")
        result = _init(project, "--merge")
        assert result.exit_code == 0
        assert "Appended 1 review entry to licenseal.review.toml." in result.output
        assert _note(2, "npm:bad\\ud800name", "npm:odd-source") in result.output
        contents = load_review_file(project)
        assert contents.licenses == {"npm:kept@1.0.0": "MIT"}
        assert contents.incomplete == [_PLAIN_KEY]
        assert (project / "licenseal.review.toml").read_text(encoding="utf-8").startswith(existing)

    def test_merge_with_nothing_new_still_names_them(self, tmp_path):
        project = _project(tmp_path)
        _init(project)
        before = (project / "licenseal.review.toml").read_bytes()
        result = _init(project, "--merge")
        assert result.exit_code == 0
        assert "No new flagged dependencies to add." in result.output
        assert _note(2, "npm:bad\\ud800name", "npm:odd-source") in result.output
        assert (project / "licenseal.review.toml").read_bytes() == before

    @respx.mock
    def test_registry_dependency_with_an_unwritable_name(self, tmp_path):
        # A pinned one has a version to key a stanza on, a ranged one has
        # none: each is named under its own reason, escaped for the terminal.
        # Neither can be looked up; the third dependency is the one lookup
        # that succeeds.
        (tmp_path / "package.json").write_text(
            '{"name": "app", "license": "MIT", "dependencies": '
            '{"pin\\ud800ned": "1.0.0", "ran\\udc00ged": "^1.0.0", "fine": "1.0.0"}}',
            encoding="utf-8",
        )
        _mock_npm("fine", "MIT")
        result = _init(tmp_path)
        assert result.exit_code == 0
        assert "No reviewable flagged dependencies found." in result.output
        assert _note(1, "npm:pin\\ud800ned") in result.output
        assert (
            "Note: 1 flagged dependency could not be scaffolded (no resolved version, usually "
            "a manifest typo / yanked release / registry miss): npm:ran\\udc00ged."
        ) in result.output
        assert not (tmp_path / "licenseal.review.toml").exists()


def _report(tmp_path: Path, *rows: str) -> Path:
    """A saved JSON report holding ``rows``, each the raw JSON text of a dependency."""
    path = tmp_path / "report.json"
    path.write_text(
        '{"project_license": "MIT", "dependencies": [' + ", ".join(rows) + "]}", encoding="utf-8"
    )
    return path


def _report_row(name: str, *, version: str = "1.0.0", origin: str = "") -> str:
    return (
        f'{{"name": "{name}", "ecosystem": "python", "verdict": "unknown", '
        f'"resolved_version": "{version}", "origin": "{origin}", '
        '"detected_license": "UNKNOWN", "license_raw": ""}'
    )


class TestFromReport:
    def test_unwritable_rows_are_left_out_and_the_file_loads(self, tmp_path):
        report = _report(
            tmp_path,
            _report_row("na\\ud800me"),
            _report_row("fine"),
            _report_row("by-version", version="1.0\\udfff"),
            _report_row("by-source", version="", origin="git+https://git.example.org/x\\udc00"),
        )
        result = _init(tmp_path, "--from-report", str(report))
        assert result.exit_code == 0
        assert "Wrote licenseal.review.toml with 1 review entry." in result.output
        assert (
            _note(3, "python:by-source", "python:by-version", "python:na\\ud800me") in result.output
        )
        assert load_review_file(tmp_path).incomplete == ["python:fine@1.0.0"]

    def test_merge_from_report(self, tmp_path):
        report = _report(tmp_path, _report_row("na\\ud800me"), _report_row("fine"))
        (tmp_path / "licenseal.review.toml").write_text(
            '[[review]]\necosystem = "python"\npackage = "fine"\nversion = "1.0.0"\n'
            'license = "MIT"\n',
            encoding="utf-8",
            newline="\n",
        )
        result = _init(tmp_path, "--from-report", str(report), "--merge")
        assert result.exit_code == 0
        assert "No new flagged dependencies to add." in result.output
        assert _note(1, "python:na\\ud800me") in result.output
        assert load_review_file(tmp_path).licenses == {"python:fine@1.0.0": "MIT"}

    def test_more_than_five_are_summarised(self, tmp_path):
        report = _report(tmp_path, *(_report_row(f"pkg{i}\\ud800") for i in range(7)))
        result = _init(tmp_path, "--from-report", str(report))
        assert result.exit_code == 0
        assert (
            _note(7, *(f"python:pkg{i}\\ud800" for i in range(5)), "… (+2 more)") in result.output
        )
