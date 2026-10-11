"""The ``license`` of a review entry has to name licenses.

A reviewed dependency does not fail the check, so an entry whose license
names something that is no license (a typo) must be an error rather than a
review. Every scan here has one flagged dependency and a review entry for it.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner, Result

from licenseal.analysis.compatibility import _SOURCE_AVAILABLE_PROJECT_PREFIXES
from licenseal.analysis.risk import _RISK_PATTERNS
from licenseal.cli import main
from licenseal.models import RiskLevel

_ENTRY = "npm:custom-lib@2.0.0"
_NOT_A_LICENSE = (
    "Error: Invalid licenseal.review.toml: the license of the review entry for {} names '{}', "
    "which is not a license licenseal recognises. Use SPDX license IDs, `Proprietary`, or a "
    "`LicenseRef-` reference."
)


def _stanza(license_value: str, key: str = 'version = "2.0.0"') -> str:
    return (
        f'[[review]]\necosystem = "npm"\npackage = "custom-lib"\n{key}\n'
        f"license = {json.dumps(license_value)}\n"
    )


def _project(project: Path, review: str) -> None:
    """A project with one dependency whose license needs review, and a review file."""
    (project / "package.json").write_text(
        json.dumps({"name": "app", "license": "MIT", "dependencies": {"custom-lib": "2.0.0"}})
    )
    respx.get("https://registry.npmjs.org/custom-lib/2.0.0").mock(
        return_value=httpx.Response(
            200, json={"version": "2.0.0", "license": "SEE LICENSE IN terms.txt"}
        )
    )
    (project / "licenseal.review.toml").write_text(review, encoding="utf-8", newline="\n")


def _check(project: Path) -> Result:
    return CliRunner().invoke(
        main, ["check", "--path", str(project), "-f", "json", "--no-require-lockfile"]
    )


class TestOperandThatIsNotALicense:
    @pytest.mark.parametrize(
        "license_value, operand",
        [
            ("MTI", "MTI"),
            ("X", "X"),
            ("MIT AND MTI", "MTI"),
            ("MIT OR MTI", "MTI"),
            # Inside parentheses, and before ``WITH``.
            ("(MIT OR MTI) AND Apache-2.0", "MTI"),
            ("Apache-2.0 AND (MIT OR (ISC AND MTI))", "MTI"),
            ("MTI WITH Classpath-exception-2.0", "MTI"),
            ("MIT, MTI", "MTI"),
            # Placeholders are not licenses.
            ("MIT AND UNKNOWN", "UNKNOWN"),
            ("NOASSERTION", "NOASSERTION"),
            # An ID that only looks like a member of a license family.
            ("GPL-3", "GPL-3"),
            ("GPL-Custom", "GPL-Custom"),
            ("MIT-NonCommercial", "MIT-NonCommercial"),
            ("mit-license", "mit-license"),
        ],
    )
    @respx.mock
    def test_check_names_the_entry_and_the_operand(self, tmp_path, license_value, operand):
        _project(tmp_path, _stanza(license_value))
        result = _check(tmp_path)
        assert result.exit_code == 1
        assert _NOT_A_LICENSE.format(_ENTRY, operand) in result.stderr.splitlines()
        # No report is written for a scan whose review file is invalid.
        assert result.stdout == ""

    @respx.mock
    def test_entry_keyed_on_a_source_is_named_by_it(self, tmp_path):
        source = "git+https://git.example.org/team/custom-lib.git@0123abcd"
        _project(tmp_path, _stanza("MTI", key=f'source = "{source}"'))
        result = _check(tmp_path)
        assert result.exit_code == 1
        entry = f"off-registry npm:custom-lib from {source}"
        assert _NOT_A_LICENSE.format(entry, "MTI") in result.stderr.splitlines()

    @respx.mock
    def test_first_operand_that_is_not_a_license_is_named(self, tmp_path):
        _project(tmp_path, _stanza("MIT AND Foo AND Bar"))
        result = _check(tmp_path)
        assert _NOT_A_LICENSE.format(_ENTRY, "Bar") in result.stderr.splitlines()

    @respx.mock
    def test_operand_is_shown_escaped(self, tmp_path):
        _project(tmp_path, _stanza("MIT AND Evil\x1b[2J\u202eId"))
        result = _check(tmp_path)
        assert result.exit_code == 1
        assert (
            _NOT_A_LICENSE.format(_ENTRY, "Evil\\x1b[2J\\u202eId").encode()
            in result.stderr_bytes.splitlines()
        )
        assert b"\x1b" not in result.stderr_bytes

    @pytest.mark.parametrize("license_value", ["MIT OR", "(MIT", "UNKNOWN", "not a license at all"])
    @respx.mock
    def test_value_that_is_not_an_expression_keeps_its_own_error(self, tmp_path, license_value):
        _project(tmp_path, _stanza(license_value))
        result = _check(tmp_path)
        assert result.exit_code == 1
        assert f"Error: Invalid reviewed license {license_value!r}." in result.stderr

    @respx.mock
    def test_empty_license_is_a_warning_not_an_error(self, tmp_path):
        _project(tmp_path, _stanza(""))
        result = _check(tmp_path)
        # The dependency stays flagged, which is what fails the scan.
        assert result.exit_code == 1
        assert (
            f"Warning: incomplete review entries were not applied: {_ENTRY}"
            in result.stderr.splitlines()
        )
        assert "not a license" not in result.stderr
        dependency = json.loads(result.stdout)["dependencies"][0]
        assert (dependency["reviewed"], dependency["verdict"]) == (False, "unknown")

    @respx.mock
    def test_merge_reads_the_existing_file_under_the_same_rule(self, tmp_path):
        review = _stanza("MIT OR MTI")
        _project(tmp_path, review)
        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path), "--merge"])
        assert result.exit_code == 1
        assert _NOT_A_LICENSE.format(_ENTRY, "MTI") in result.stderr.splitlines()
        assert (tmp_path / "licenseal.review.toml").read_text(encoding="utf-8") == review


class TestOperandThatIsALicense:
    @pytest.mark.parametrize(
        "license_value, reviewed_as, verdict",
        [
            ("MIT", "MIT", "compatible"),
            (
                "(MIT OR Apache-2.0) AND BSD-3-Clause",
                "(Apache-2.0 OR MIT) AND BSD-3-Clause",
                "compatible",
            ),
            # A spelling the normalizer maps to an ID.
            ("Apache 2.0", "Apache-2.0", "compatible"),
            ("mit", "MIT", "compatible"),
            ("Commercial License", "Proprietary", "unknown"),
            # Deprecated SPDX IDs: the GNU spellings read as their current
            # IDs, the others are kept and classify as before.
            ("GPL-2.0", "GPL-2.0-only", "incompatible"),
            ("LGPL-2.1+", "LGPL-2.1-or-later", "warning"),
            ("GPL-2.0-with-classpath-exception", "GPL-2.0-with-classpath-exception", "warning"),
            ("GPL-3.0-with-GCC-exception", "GPL-3.0-with-GCC-exception", "incompatible"),
            ("BSD-2-Clause-FreeBSD", "BSD-2-Clause-FreeBSD", "unknown"),
            ("eCos-2.0", "eCos-2.0", "unknown"),
            ("MIT OR wxWindows", "MIT OR wxWindows", "compatible"),
            # Custom terms.
            ("Proprietary", "Proprietary", "unknown"),
            ("MIT AND Proprietary", "MIT AND Proprietary", "unknown"),
            ("LicenseRef-acme-terms", "Proprietary", "unknown"),
            ("LicenseRef-Public-Domain", "LicenseRef-Public-Domain", "compatible"),
            # A source-available family licenseal reports, listed by SPDX or not.
            ("BUSL-1.1", "BUSL-1.1", "unknown"),
            ("FSL-1.1-Apache-2.0", "FSL-1.1-Apache-2.0", "unknown"),
            ("PolyForm-Shield-1.0.0", "PolyForm-Shield-1.0.0", "unknown"),
            # The text after ``WITH`` is not checked against a list.
            ("MIT WITH Made-Up-exception", "MIT WITH Made-Up-exception", "unknown"),
            (
                "GPL-3.0-only WITH Qt-GPL-exception-1.0",
                "GPL-3.0-only WITH Qt-GPL-exception-1.0",
                "incompatible",
            ),
            ("Apache-2.0 WITH LLVM-exception", "Apache-2.0 WITH LLVM-exception", "compatible"),
            # The ``+`` suffix belongs to the ID before it.
            ("MPL-2.0+", "MPL-2.0+", "warning"),
        ],
    )
    @respx.mock
    def test_check_applies_the_review(self, tmp_path, license_value, reviewed_as, verdict):
        _project(tmp_path, _stanza(license_value))
        result = _check(tmp_path)
        # A reviewed dependency does not fail the check, whatever its verdict.
        assert result.exit_code == 0
        dependency = json.loads(result.stdout)["dependencies"][0]
        assert dependency["reviewed"] is True
        assert dependency["detected_license"] == "Proprietary"
        assert dependency["reviewed_license"] == dependency["license"] == reviewed_as
        assert dependency["verdict"] == verdict

    def test_source_available_families_are_the_ones_the_risk_rules_classify(self):
        # The prefixes an operand is accepted by are the compatibility
        # check's; the risk patterns name the same families.
        classified = {
            pattern.pattern.removeprefix("^")
            for pattern, level in _RISK_PATTERNS
            if level == RiskLevel.UNKNOWN
        }
        assert classified == set(_SOURCE_AVAILABLE_PROJECT_PREFIXES)

    @respx.mock
    def test_merge_keeps_a_valid_file(self, tmp_path):
        review = _stanza("LicenseRef-acme-terms")
        _project(tmp_path, review)
        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path), "--merge"])
        assert result.exit_code == 0
        assert "No new flagged dependencies to add." in result.stderr
        assert (tmp_path / "licenseal.review.toml").read_text(encoding="utf-8") == review
