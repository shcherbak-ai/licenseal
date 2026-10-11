"""A license read from metadata for another release is reported as an estimate.

Three registries cannot always answer for the reported release. The CRAN
``PACKAGES`` index lists each package's current version only, hex.pm keeps one
license per package (that of the release published last), and a PyPI release
that declares no license takes the one of the project's latest release. The
row keeps that license and says so: ``"license"`` in the JSON ``estimated``
array, ``~`` before the license in the table and Markdown reports.

Every test scans files on disk against mocked registry responses.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from tests._helpers import _check_json, _write

_LEGEND = (
    "marks an estimate: a version picked from the registry (not locked or pinned), "
    "or a license read from metadata for another release"
)
_CRAN_INDEX = "https://cran.r-project.org/src/contrib/PACKAGES"


def _row(data: dict, name: str) -> tuple[str, str, list[str]]:
    """``(resolved_version, license, estimated)`` of the report row for ``name``."""
    (row,) = [dep for dep in data["dependencies"] if dep["name"] == name]
    return row["resolved_version"], row["license"], row["estimated"]


def _r_project(tmp_path: Path, locked: str, *, current: str, license_field: str = "MIT") -> Path:
    """An R package whose ``renv.lock`` pins ``jsonlite`` at ``locked``.

    The CRAN index lists ``jsonlite`` at ``current`` under ``license_field``.
    """
    _write(tmp_path / "DESCRIPTION", "Package: myproj\nLicense: MIT\nImports: jsonlite\n")
    (tmp_path / "renv.lock").write_text(
        json.dumps(
            {
                "Packages": {
                    "jsonlite": {
                        "Package": "jsonlite",
                        "Version": locked,
                        "Source": "Repository",
                        "Repository": "CRAN",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    respx.get(_CRAN_INDEX).mock(
        return_value=httpx.Response(
            200, text=f"Package: jsonlite\nVersion: {current}\nLicense: {license_field}\n"
        )
    )
    return tmp_path


class TestCranPin:
    """The index holds the license of each package's current version only."""

    @respx.mock
    def test_pin_to_another_version_is_a_license_estimate_and_passes_strict(self, tmp_path):
        result, data = _check_json(_r_project(tmp_path, "1.8.0", current="2.0.0"))
        assert _row(data, "jsonlite") == ("1.8.0", "MIT", ["license"])
        # An estimate is neither a finding nor a gap.
        assert result.exit_code == 0
        assert data["diagnostics"] == []
        assert data["summary"] == {
            "total": 1,
            "ok": 1,
            "warnings": 0,
            "violations": 0,
            "unknown": 0,
            "reviewed": 0,
            "gaps": 0,
        }

    @respx.mock
    def test_pin_to_the_current_version_is_not_an_estimate(self, tmp_path):
        result, data = _check_json(_r_project(tmp_path, "2.0.0", current="2.0.0"))
        assert result.exit_code == 0
        assert _row(data, "jsonlite") == ("2.0.0", "MIT", [])

    @respx.mock
    def test_estimated_license_is_judged_like_any_other(self, tmp_path):
        project = _r_project(tmp_path, "1.8.0", current="2.0.0", license_field="GPL-3")
        result, data = _check_json(project)
        assert result.exit_code == 1
        assert _row(data, "jsonlite") == ("1.8.0", "GPL-3.0-only", ["license"])
        assert data["summary"]["violations"] == 1

    @respx.mock
    def test_reviewed_license_is_not_an_estimate(self, tmp_path):
        project = _r_project(tmp_path, "1.8.0", current="2.0.0", license_field="GPL-3")
        _write(
            project / "licenseal.review.toml",
            """\
            [[review]]
            ecosystem = "r"
            package = "jsonlite"
            version = "1.8.0"
            license = "MIT"
            note = "1.8.0 was published under MIT"
            """,
        )
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert _row(data, "jsonlite") == ("1.8.0", "MIT", [])
        (row,) = data["dependencies"]
        assert (row["detected_license"], row["reviewed"]) == ("GPL-3.0-only", True)

    @respx.mock
    def test_unknown_license_has_nothing_to_mark(self, tmp_path):
        project = _r_project(tmp_path, "1.8.0", current="2.0.0", license_field="file LICENSE")
        _, data = _check_json(project, "--no-strict")
        assert _row(data, "jsonlite") == ("1.8.0", "UNKNOWN", [])

    @respx.mock
    def test_package_without_a_lockfile_is_reported_at_the_indexed_version(self, tmp_path):
        # The version is the index's, picked by the scan, and the license is
        # the one the index records for that very version.
        _write(tmp_path / "DESCRIPTION", "Package: myproj\nLicense: MIT\nImports: jsonlite\n")
        respx.get(_CRAN_INDEX).mock(
            return_value=httpx.Response(
                200, text="Package: jsonlite\nVersion: 2.0.0\nLicense: MIT\n"
            )
        )
        result, data = _check_json(tmp_path, "--no-require-lockfile")
        assert result.exit_code == 0
        assert _row(data, "jsonlite") == ("2.0.0", "MIT", ["version"])


# Three releases of one Hex package. 1.9.1 went out on the older line after
# 2.0.0, so it is the release the package-level metadata describes.
_HEX_RELEASES = [
    {"version": "2.0.0", "inserted_at": "2024-03-01T10:00:00.000000Z"},
    {"version": "1.9.1", "inserted_at": "2024-05-01T10:00:00.000000Z"},
    {"version": "1.9.0", "inserted_at": "2024-01-01T10:00:00.000000Z"},
]


def _mix_project(tmp_path: Path, *, locked: str | None, requirement: str = "~> 1.0") -> Path:
    """A Mix project requiring ``acme``, locked at ``locked`` when given."""
    _write(
        tmp_path / "mix.exs",
        f"""\
        defmodule M.MixProject do
          def project, do: [app: :m, deps: deps(), package: [licenses: ["MIT"]]]
          defp deps, do: [{{:acme, "{requirement}"}}]
        end
        """,
    )
    if locked is not None:
        _write(
            tmp_path / "mix.lock",
            f'%{{\n  "acme": {{:hex, :acme, "{locked}", "h", [:mix], [], "hexpm", "h2"}},\n}}\n',
        )
    return tmp_path


def _mock_hex_package(releases: list[dict]) -> None:
    respx.get("https://hex.pm/api/packages/acme").mock(
        return_value=httpx.Response(
            200,
            json={
                "meta": {"licenses": ["MIT"], "links": {}},
                "latest_version": "2.0.0",
                "latest_stable_version": "2.0.0",
                "releases": releases,
            },
        )
    )


class TestHexPin:
    """hex.pm serves one license per package: that of the release published last."""

    @pytest.mark.parametrize(
        ("locked", "estimated"),
        [
            ("1.9.1", []),
            # The highest version, and still not the one the metadata describes.
            ("2.0.0", ["license"]),
            ("1.9.0", ["license"]),
        ],
        ids=["published-last", "highest-version", "older"],
    )
    @respx.mock
    def test_only_the_release_published_last_has_its_own_license(self, tmp_path, locked, estimated):
        _mock_hex_package(_HEX_RELEASES)
        result, data = _check_json(_mix_project(tmp_path, locked=locked))
        assert result.exit_code == 0
        assert data["diagnostics"] == []
        assert _row(data, "acme") == (locked, "MIT", estimated)

    @respx.mock
    def test_range_without_a_lockfile_estimates_version_and_license(self, tmp_path):
        # ``~> 1.0`` selects 1.9.1, the release published last: its version is
        # the scan's pick and its license is its own.
        _mock_hex_package(_HEX_RELEASES)
        project = _mix_project(tmp_path, locked=None)
        _, data = _check_json(project, "--no-transitive")
        assert _row(data, "acme") == ("1.9.1", "MIT", ["version"])

    @respx.mock
    def test_range_selecting_another_release_estimates_both(self, tmp_path):
        _mock_hex_package(_HEX_RELEASES)
        project = _mix_project(tmp_path, locked=None, requirement="~> 2.0")
        _, data = _check_json(project, "--no-transitive")
        assert _row(data, "acme") == ("2.0.0", "MIT", ["license", "version"])

    @pytest.mark.parametrize(
        "releases",
        [
            [{"version": "1.9.1"}],
            [{"version": "1.9.1", "inserted_at": 1714557600}],
            [{"inserted_at": "2024-05-01T10:00:00.000000Z"}],
            ["1.9.1"],
            {"1.9.1": "2024-05-01T10:00:00.000000Z"},
            [],
        ],
        ids=["no-time", "numeric-time", "no-version", "bare-string", "not-a-list", "empty"],
    )
    @respx.mock
    def test_response_that_does_not_date_its_releases_describes_none(self, tmp_path, releases):
        # Which release the metadata describes cannot be told, so the license
        # is not taken to be the pinned release's own.
        _mock_hex_package(releases)
        _, data = _check_json(_mix_project(tmp_path, locked="1.9.1"))
        assert _row(data, "acme") == ("1.9.1", "MIT", ["license"])


def _python_project(tmp_path: Path) -> Path:
    """A project pinning ``pkg-a==1.0.0``, a release whose own JSON declares no license."""
    _write(
        tmp_path / "pyproject.toml",
        """\
        [project]
        name = "app"
        version = "0.1.0"
        license = "MIT"
        dependencies = ["pkg-a==1.0.0"]
        """,
    )
    respx.get("https://pypi.org/pypi/pkg-a/1.0.0/json").mock(
        return_value=httpx.Response(200, json={"info": {"version": "1.0.0", "requires_dist": []}})
    )
    return tmp_path


def _mock_latest_release(version: str, license_expression: str = "MIT") -> None:
    respx.get("https://pypi.org/pypi/pkg-a/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {"version": version, "license_expression": license_expression},
                "releases": {"1.0.0": [], version: []},
            },
        )
    )


class TestPyPIReleaseWithoutALicense:
    """A release that declares nothing takes the license of the latest release."""

    @respx.mock
    def test_license_of_a_later_release_is_an_estimate(self, tmp_path):
        _mock_latest_release("2.0.0")
        result, data = _check_json(_python_project(tmp_path), "--no-require-lockfile")
        assert result.exit_code == 0
        assert _row(data, "pkg-a") == ("1.0.0", "MIT", ["license"])

    @pytest.mark.parametrize("latest", ["1.0.0", "1.0"])
    @respx.mock
    def test_license_of_the_same_release_is_not_an_estimate(self, tmp_path, latest):
        # The project endpoint describes the pinned release itself, under
        # either spelling of its version.
        _mock_latest_release(latest)
        result, data = _check_json(_python_project(tmp_path), "--no-require-lockfile")
        assert result.exit_code == 0
        assert _row(data, "pkg-a") == ("1.0.0", "MIT", [])

    @respx.mock
    def test_project_response_that_names_no_version_is_an_estimate(self, tmp_path):
        respx.get("https://pypi.org/pypi/pkg-a/json").mock(
            return_value=httpx.Response(200, json={"info": {"license_expression": "MIT"}})
        )
        _, data = _check_json(_python_project(tmp_path), "--no-require-lockfile")
        assert _row(data, "pkg-a") == ("1.0.0", "MIT", ["license"])

    @respx.mock
    def test_latest_release_under_a_version_that_is_not_pep_440(self, tmp_path):
        _mock_latest_release("2004d")
        _, data = _check_json(_python_project(tmp_path), "--no-require-lockfile")
        assert _row(data, "pkg-a") == ("1.0.0", "MIT", ["license"])

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_answer_for_the_exact_version_from_deps_dev_is_not_an_estimate(self, tmp_path):
        key = {"system": "PYPI", "name": "pkg-a", "version": "1.0.0"}
        respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {"versionKey": key},
                            "version": {"versionKey": key, "licenses": ["MIT"], "links": []},
                        }
                    ]
                },
            )
        )
        project_route = respx.get("https://pypi.org/pypi/pkg-a/json").mock(
            return_value=httpx.Response(404)
        )
        result, data = _check_json(_python_project(tmp_path), "--no-require-lockfile")
        assert result.exit_code == 0
        assert _row(data, "pkg-a") == ("1.0.0", "MIT", [])
        assert not project_route.called


class TestReportFormats:
    @respx.mock
    def test_markdown_marks_the_license_and_explains_the_mark(self, tmp_path):
        out = tmp_path / "report.md"
        project = _r_project(tmp_path, "1.8.0", current="2.0.0", license_field="GPL-2 | MIT")
        result = CliRunner().invoke(
            main, ["check", "--path", str(project), "-f", "markdown", "-o", str(out)]
        )
        assert result.exit_code == 0
        report = out.read_text(encoding="utf-8")
        assert (
            "|[jsonlite (1.8.0)](https://cran.r-project.org/package=jsonlite)|r|prod|"
            "[DESCRIPTION](DESCRIPTION)|"
            "~[GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html) OR "
            "[MIT](https://spdx.org/licenses/MIT.html)|permissive|✓|"
        ) in report
        assert report.count(f"`~` {_LEGEND}") == 1

    @respx.mock
    def test_table_marks_the_license_and_explains_the_mark(self, tmp_path):
        out = tmp_path / "report.txt"
        project = _r_project(tmp_path, "1.8.0", current="2.0.0")
        result = CliRunner().invoke(main, ["check", "--path", str(project), "-o", str(out)])
        assert result.exit_code == 0
        report = out.read_text(encoding="utf-8")
        assert "│ jsonlite (1.8.0) " in report
        assert "│ ~MIT " in report
        # Longer than the saved table is wide, and still one line.
        assert report.count(f"  ~ {_LEGEND}\n") == 1

    @respx.mock
    def test_report_without_an_estimate_has_no_mark(self, tmp_path):
        out = tmp_path / "report.md"
        project = _r_project(tmp_path, "2.0.0", current="2.0.0")
        CliRunner().invoke(
            main, ["check", "--path", str(project), "-f", "markdown", "-o", str(out)]
        )
        assert "~" not in out.read_text(encoding="utf-8")
