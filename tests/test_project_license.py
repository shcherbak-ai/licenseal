"""The project's own license comes from a manifest in the scanned directory.

Only files directly in the directory given to ``--path`` are consulted, in a
fixed order across ecosystems. A manifest further down belongs to a
sub-package: its license is that package's, and it never decides what every
dependency of the project is judged against. With no declaration in the
scanned directory the project is ``Proprietary``, and the scan says which of
the two it was.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.analysis.compatibility import analyze
from licenseal.cli import main
from licenseal.discovery import ProjectLicense, detect_project_license
from licenseal.discovery._read import collect_read_diagnostics
from licenseal.report import render_markdown
from tests._helpers import _check_json, _file_diagnostics, _mock_npm, _mock_pypi

_MIX_EXS = """\
defmodule App.MixProject do
  use Mix.Project

  def project do
    [app: :app, version: "0.1.0", package: [licenses: ["EPL-2.0"]]]
  end
end
"""

# Every manifest that can declare the project's license, in the order they are
# consulted: file name, content, the value as declared, and its SPDX form. No
# two declare the same license.
_MANIFESTS = [
    ("pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n', "MIT", "MIT"),
    ("setup.cfg", "[metadata]\nlicense = BSD-3-Clause\n", "BSD-3-Clause", "BSD-3-Clause"),
    (
        "setup.py",
        'from setuptools import setup\n\nsetup(name="app", license="BSD-2-Clause")\n',
        "BSD-2-Clause",
        "BSD-2-Clause",
    ),
    ("package.json", '{"name": "app", "license": "ISC"}', "ISC", "ISC"),
    ("Cargo.toml", '[package]\nname = "app"\nlicense = "MPL-2.0"\n', "MPL-2.0", "MPL-2.0"),
    (
        "pom.xml",
        "<project><licenses><license><name>Apache License 2.0</name></license>"
        "</licenses></project>",
        "Apache License 2.0",
        "Apache-2.0",
    ),
    (
        "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<PackageLicenseExpression>LGPL-3.0-only</PackageLicenseExpression>"
        "</PropertyGroup></Project>",
        "LGPL-3.0-only",
        "LGPL-3.0-only",
    ),
    (
        "Directory.Build.props",
        "<Project><PropertyGroup>"
        "<PackageLicenseExpression>Zlib</PackageLicenseExpression>"
        "</PropertyGroup></Project>",
        "Zlib",
        "Zlib",
    ),
    (
        "composer.json",
        '{"name": "vendor/app", "license": ["MIT", "GPL-2.0-only"]}',
        "MIT OR GPL-2.0-only",
        "GPL-2.0-only OR MIT",
    ),
    (
        "app.gemspec",
        'Gem::Specification.new do |s|\n  s.name = "app"\n  s.license = "0BSD"\nend\n',
        "0BSD",
        "0BSD",
    ),
    ("mix.exs", _MIX_EXS, "EPL-2.0", "EPL-2.0"),
    ("DESCRIPTION", "Package: app\nLicense: GPL (>= 2)\n", "GPL (>= 2)", "GPL-2.0-or-later"),
]
_MANIFEST_IDS = [name for name, *_ in _MANIFESTS]


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


class TestDetectProjectLicense:
    @pytest.mark.parametrize(("name", "content", "declared", "spdx"), _MANIFESTS, ids=_MANIFEST_IDS)
    def test_manifest_in_the_scanned_directory_supplies_the_license(
        self, tmp_path: Path, name, content, declared, spdx
    ):
        _write(tmp_path / name, content)
        assert detect_project_license(tmp_path) == ProjectLicense(
            license=spdx, source=name, declared=((name, declared),)
        )

    @pytest.mark.parametrize(("name", "content", "declared", "spdx"), _MANIFESTS, ids=_MANIFEST_IDS)
    def test_nested_manifest_never_supplies_the_license(
        self, tmp_path: Path, name, content, declared, spdx
    ):
        # One level down and several: neither is the scanned directory.
        _write(tmp_path / "pkg" / name, content)
        _write(tmp_path / "libs" / "deep" / "core" / name, content)
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="Proprietary", source="", declared=()
        )
        # Scanned on its own, the sub-package has its license.
        assert detect_project_license(tmp_path / "pkg").license == spdx

    def test_manifests_are_consulted_in_a_fixed_order(self, tmp_path: Path):
        # All of them declare a different license. Removing the one that
        # decides hands the decision to the next in the order.
        for name, content, _, _ in _MANIFESTS:
            _write(tmp_path / name, content)
        for index, (name, _, _, spdx) in enumerate(_MANIFESTS):
            detected = detect_project_license(tmp_path)
            assert (detected.license, detected.source) == (spdx, name)
            # The deciding manifest first, then each one that disagrees.
            assert detected.declared == tuple(
                (later, value) for later, _, value, _ in _MANIFESTS[index:]
            )
            (tmp_path / name).unlink()
        assert detect_project_license(tmp_path) == ProjectLicense()

    def test_no_manifest_at_all_is_proprietary(self, tmp_path: Path):
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="Proprietary", source="", declared=()
        )

    def test_manifest_that_declares_no_license_is_passed_over(self, tmp_path: Path):
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\n')
        _write(tmp_path / "package.json", '{"name": "app", "license": "ISC"}')
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="ISC", source="package.json", declared=(("package.json", "ISC"),)
        )

    def test_manifests_that_agree_are_not_reported_as_different(self, tmp_path: Path):
        # Three spellings of one license, and one manifest that disagrees.
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n')
        _write(tmp_path / "setup.cfg", "[metadata]\nlicense = MIT License\n")
        _write(tmp_path / "package.json", '{"name": "app", "license": "mit"}')
        _write(tmp_path / "composer.json", '{"name": "vendor/app", "license": "GPL-3.0-only"}')
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="MIT",
            source="pyproject.toml",
            declared=(("pyproject.toml", "MIT"), ("composer.json", "GPL-3.0-only")),
        )

    @pytest.mark.parametrize(
        ("name", "content", "declared"),
        [
            ("package.json", '{"name": "app", "license": "-"}', "-"),
            ("pyproject.toml", '[project]\nlicense = {text = "see the LICENSE file"}\n', None),
            ("Cargo.toml", '[package]\nname = "app"\nlicense = "MIT AND Custom"\n', None),
            ("DESCRIPTION", "Package: app\nLicense: file LICENSE\n", "file LICENSE"),
            (
                "App.csproj",
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><PackageLicenseUrl>'
                "https://example.org/spdx.org/licenses/MIT</PackageLicenseUrl>"
                "</PropertyGroup></Project>",
                "https://example.org/spdx.org/licenses/MIT",
            ),
        ],
        ids=["dash", "prose", "unknown-operand", "r-file-reference", "lookalike-license-url"],
    )
    def test_declared_value_that_is_not_recognised_leaves_proprietary(
        self, tmp_path: Path, name, content, declared
    ):
        _write(tmp_path / name, content)
        detected = detect_project_license(tmp_path)
        assert (detected.license, detected.source) == ("Proprietary", "")
        assert [manifest for manifest, _ in detected.declared] == [name]
        if declared is not None:
            assert detected.declared == ((name, declared),)

    def test_unrecognised_first_value_decides_over_a_recognised_later_one(self, tmp_path: Path):
        # The first declaration in the order decides even when it cannot be
        # used: falling through to another ecosystem's manifest would pick a
        # license the first one may contradict.
        _write(tmp_path / "package.json", '{"name": "app", "license": "-"}')
        _write(tmp_path / "composer.json", '{"name": "vendor/app", "license": "MIT"}')
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="Proprietary",
            source="",
            declared=(("package.json", "-"), ("composer.json", "MIT")),
        )

    @pytest.mark.parametrize(
        "declared",
        ["Proprietary", "UNLICENSED", "BUSL-1.1", "AGPL-3.0-only OR LicenseRef-Commercial"],
    )
    def test_restrictive_project_license_is_recognised(self, tmp_path: Path, declared):
        # A project's own restrictive choice is a license the check knows how
        # to judge against, not an unrecognised value.
        _write(tmp_path / "package.json", json.dumps({"name": "app", "license": declared}))
        detected = detect_project_license(tmp_path)
        assert detected.source == "package.json"
        assert detected.declared == (("package.json", declared),)

    def test_several_project_files_in_the_scanned_directory(self, tmp_path: Path):
        project = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>{}</PropertyGroup></Project>'
        expression = "<PackageLicenseExpression>{}</PackageLicenseExpression>"
        _write(tmp_path / "App.csproj", project.format(""))
        _write(tmp_path / "Lib.fsproj", project.format(expression.format("MIT")))
        _write(tmp_path / "Tool.vbproj", project.format(expression.format("Apache-2.0")))
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="MIT",
            source="Lib.fsproj",
            declared=(("Lib.fsproj", "MIT"), ("Tool.vbproj", "Apache-2.0")),
        )

    def test_several_gemspecs_in_the_scanned_directory(self, tmp_path: Path):
        gemspec = "Gem::Specification.new do |s|\n  s.licenses = [{}]\nend\n"
        _write(tmp_path / "a.gemspec", gemspec.format(""))
        _write(tmp_path / "b.gemspec", gemspec.format('"MIT"'))
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="MIT", source="b.gemspec", declared=(("b.gemspec", "MIT"),)
        )

    def test_unreadable_manifest_is_a_gap_and_the_next_one_decides(self, tmp_path: Path):
        broken = _write(tmp_path / "pyproject.toml", "this is = = not toml")
        _write(tmp_path / "package.json", '{"name": "app", "license": "ISC"}')
        with collect_read_diagnostics() as diags:
            detected = detect_project_license(tmp_path)
        assert (detected.license, detected.source) == ("ISC", "package.json")
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (broken, "is not valid TOML; skipped", True)
        ]

    def test_excluded_subdirectory_does_not_change_what_is_read(self, tmp_path: Path):
        _write(tmp_path / "package.json", '{"name": "app", "license": "ISC"}')
        _write(tmp_path / "vendored" / "package.json", '{"name": "v", "license": "MIT"}')
        detected = detect_project_license(
            tmp_path, exclude_paths=frozenset({(tmp_path / "vendored").resolve()})
        )
        assert (detected.license, detected.source) == ("ISC", "package.json")


def _package_json(path: Path, license_value: str | None, **dependencies: str) -> None:
    manifest: dict = {"name": path.parent.name, "dependencies": dependencies}
    if license_value is not None:
        manifest["license"] = license_value
    _write(path, json.dumps(manifest))


def _verdicts(data: dict) -> dict[str, str]:
    return {dep["name"]: dep["verdict"] for dep in data["dependencies"]}


# The projects scanned here have no lockfile. That is accepted, so that the
# licenses alone decide each exit code.
_NO_LOCKFILE = "--no-require-lockfile"

_ASSUMED = (
    "Project license: Proprietary (assumed: no manifest in the scanned directory declares a "
    "license). Scanning a subproject with --path uses that subproject's license."
)


class TestCheckProjectLicense:
    """What the scan judges against, and what it says about where that came from."""

    @respx.mock
    def test_nested_manifests_do_not_decide_the_verdicts(self, tmp_path: Path):
        # A monorepo with no license at its root. One sub-package declares a
        # value that is not a license, another declares GPL. Neither is the
        # project's: it is judged as Proprietary, so the MIT dependency passes
        # and the GPL one is a violation.
        _package_json(tmp_path / "web" / "package.json", "-", **{"left-pad": "1.0.0"})
        _package_json(tmp_path / "tools" / "package.json", "GPL-3.0-only", **{"gpl-lib": "1.0.0"})
        _mock_npm("left-pad", "MIT")
        _mock_npm("gpl-lib", "GPL-3.0-only")

        result, data = _check_json(tmp_path, _NO_LOCKFILE)
        assert result.exit_code == 1
        assert (data["project_license"], data["project_license_source"]) == ("Proprietary", "")
        assert _verdicts(data) == {"left-pad": "compatible", "gpl-lib": "incompatible"}
        assert _ASSUMED in result.stderr.splitlines()
        assert "declares the license" not in result.stderr
        assert "declare different licenses" not in result.stderr

        # Scanned on its own, each sub-package is judged by its own manifest.
        result, data = _check_json(tmp_path / "tools", _NO_LOCKFILE)
        assert result.exit_code == 0
        assert (data["project_license"], data["project_license_source"]) == (
            "GPL-3.0-only",
            "package.json",
        )
        assert _verdicts(data) == {"gpl-lib": "compatible"}
        assert "Project license: GPL-3.0-only (from package.json)." in result.stderr.splitlines()

    @respx.mock
    def test_root_value_that_is_not_a_license_warns_and_judges_as_proprietary(self, tmp_path: Path):
        # Judged against the declared value, every dependency would come out
        # UNKNOWN. The value is reported and the project is judged as
        # Proprietary: the MIT dependency passes, the GPL one is a violation.
        _package_json(tmp_path / "package.json", "-", **{"left-pad": "1.0.0", "gpl-lib": "1.0.0"})
        _mock_npm("left-pad", "MIT")
        _mock_npm("gpl-lib", "GPL-3.0-only")

        result, data = _check_json(tmp_path, _NO_LOCKFILE)
        assert result.exit_code == 1
        assert (data["project_license"], data["project_license_source"]) == ("Proprietary", "")
        assert _verdicts(data) == {"left-pad": "compatible", "gpl-lib": "incompatible"}
        lines = result.stderr.splitlines()
        assert (
            "Warning: package.json declares the license '-', which is not a recognised license; "
            "dependencies are checked against Proprietary."
        ) in lines
        assert (
            "Project license: Proprietary (assumed: package.json declares no recognised license)."
        ) in lines

    @respx.mock
    def test_root_manifests_that_disagree_keep_the_first_and_warn(self, tmp_path: Path):
        # pyproject.toml is consulted first and decides. Cargo.toml agrees
        # with it, so only package.json is named beside it.
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n')
        _package_json(tmp_path / "package.json", "GPL-3.0-only", **{"gpl-lib": "1.0.0"})
        _write(tmp_path / "Cargo.toml", '[package]\nname = "app"\nlicense = "MIT"\n')
        _mock_npm("gpl-lib", "GPL-3.0-only")

        result, data = _check_json(tmp_path, _NO_LOCKFILE)
        assert result.exit_code == 1
        assert (data["project_license"], data["project_license_source"]) == (
            "MIT",
            "pyproject.toml",
        )
        assert _verdicts(data) == {"gpl-lib": "incompatible"}
        lines = result.stderr.splitlines()
        assert (
            "Warning: manifests in the scanned directory declare different licenses: "
            "pyproject.toml declares 'MIT', package.json declares 'GPL-3.0-only'; "
            "the first, pyproject.toml, decides."
        ) in lines
        assert "Project license: MIT (from pyproject.toml)." in lines

    @respx.mock
    def test_source_is_shown_in_the_table_and_markdown_reports(self, tmp_path: Path):
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n')
        _package_json(tmp_path / "web" / "package.json", "GPL-3.0-only", **{"left-pad": "1.0.0"})
        _mock_npm("left-pad", "MIT")

        table = CliRunner().invoke(main, ["check", "--path", str(tmp_path), _NO_LOCKFILE])
        assert table.exit_code == 0
        assert "Project license: MIT (from pyproject.toml)" in table.stdout

        markdown = CliRunner().invoke(
            main, ["check", "--path", str(tmp_path), "-f", "markdown", _NO_LOCKFILE]
        )
        assert markdown.exit_code == 0
        assert (
            "**Project license:** MIT (from [pyproject.toml](pyproject.toml))"
            in markdown.stdout.splitlines()
        )

    @pytest.mark.parametrize(
        ("root_license", "assumption"),
        [
            (None, "no manifest in the scanned directory declares a license"),
            ("<our terms>", "package.json declares no recognised license"),
        ],
        ids=["nothing-declared", "value-not-a-license"],
    )
    @respx.mock
    def test_assumed_license_says_so_in_the_table_and_markdown_reports(
        self, tmp_path: Path, root_license: str | None, assumption: str
    ):
        # A saved report is read without the scan's stderr. It says that
        # Proprietary was assumed, and why, in the words of the stderr line.
        if root_license is not None:
            _package_json(tmp_path / "package.json", root_license)
        _package_json(tmp_path / "web" / "package.json", "MIT", **{"left-pad": "1.0.0"})
        _mock_npm("left-pad", "MIT")

        table = CliRunner().invoke(main, ["check", "--path", str(tmp_path), _NO_LOCKFILE])
        assert table.exit_code == 0
        assert f"Project license: Proprietary (assumed: {assumption})\n" in table.stdout
        assert f"Project license: Proprietary (assumed: {assumption})." in table.stderr

        markdown = CliRunner().invoke(
            main, ["check", "--path", str(tmp_path), "-f", "markdown", _NO_LOCKFILE]
        )
        assert markdown.exit_code == 0
        assert (
            f"**Project license:** Proprietary (assumed: {assumption})"
            in markdown.stdout.splitlines()
        )

        saved = tmp_path / "out" / "LICENSES.md"
        CliRunner().invoke(
            main,
            ["check", "--path", str(tmp_path), "-f", "markdown", "-o", str(saved), _NO_LOCKFILE],
        )
        assert (
            f"**Project license:** Proprietary (assumed: {assumption})"
            in saved.read_text(encoding="utf-8").splitlines()
        )

    @respx.mock
    def test_declared_proprietary_is_not_called_assumed(self, tmp_path: Path):
        _package_json(tmp_path / "package.json", "Proprietary", **{"left-pad": "1.0.0"})
        _mock_npm("left-pad", "MIT")

        table = CliRunner().invoke(main, ["check", "--path", str(tmp_path), _NO_LOCKFILE])
        assert "Project license: Proprietary (from package.json)\n" in table.stdout
        assert "assumed" not in table.stdout
        markdown = CliRunner().invoke(
            main, ["check", "--path", str(tmp_path), "-f", "markdown", _NO_LOCKFILE]
        )
        assert (
            "**Project license:** Proprietary (from [package.json](package.json))"
            in markdown.stdout.splitlines()
        )
        assert "assumed" not in markdown.stdout

    def test_report_built_without_the_cli_says_nothing_about_the_source(self):
        # Neither field is set unless the scan sets it: a report rendered from
        # a hand-built analysis names no file and claims no assumption.
        report = analyze("Proprietary", [])
        assert report.project_license_source == ""
        assert report.project_license_assumption == ""
        assert "**Project license:** Proprietary" in render_markdown(report).splitlines()

    @respx.mock
    def test_declared_value_is_shown_on_one_line_and_capped(self, tmp_path: Path):
        # A manifest can hold a whole license text, or control characters,
        # where an identifier belongs. The warning stays one printable line.
        text = "Permission is hereby granted,\nfree of charge\x1b[2J, " + "to any person " * 20
        _package_json(tmp_path / "package.json", text, **{"left-pad": "1.0.0"})
        _mock_npm("left-pad", "MIT")

        result, _ = _check_json(tmp_path, _NO_LOCKFILE)
        assert result.exit_code == 0
        assert "\x1b" not in result.stderr
        warning = next(
            line for line in result.stderr.splitlines() if "declares the license" in line
        )
        shown = warning.split("'")[1]
        assert shown.startswith("Permission is hereby granted, free of charge\\x1b[2J, to any")
        assert shown.endswith("...")
        assert len(shown) == 80


class TestInitReviewFileProjectLicense:
    @respx.mock
    def test_same_detection_as_check(self, tmp_path: Path):
        # The only license declared is a sub-package's GPL. Judged against
        # it, the GPL dependency would be compatible and nothing would be
        # scaffolded; judged as Proprietary it is flagged.
        _package_json(tmp_path / "tools" / "package.json", "GPL-3.0-only", **{"gpl-lib": "1.0.0"})
        _mock_npm("gpl-lib", "GPL-3.0-only")

        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert _ASSUMED in result.stderr.splitlines()
        review = (tmp_path / "licenseal.review.toml").read_text(encoding="utf-8")
        assert 'package = "gpl-lib"' in review

        # Control: with the license declared in the scanned directory itself,
        # the same dependency is compatible and there is nothing to review.
        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path / "tools")])
        assert result.exit_code == 0
        assert "Project license: GPL-3.0-only (from package.json)." in result.stderr.splitlines()
        assert "No reviewable flagged dependencies found." in result.stderr
        assert not (tmp_path / "tools" / "licenseal.review.toml").exists()


def _setup_cfg(tmp_path: Path, metadata: str, requirement: str = "gpl-lib==1.0.0") -> Path:
    """A root ``setup.cfg`` with the given ``[metadata]`` lines and one requirement."""
    return _write(
        tmp_path / "setup.cfg",
        f"[metadata]\nname = app\n{metadata}\n[options]\ninstall_requires =\n    {requirement}\n",
    )


class TestSetupCfgValueThatCannotBeInterpolated:
    """A ``[metadata]`` value configparser cannot read declares no usable license.

    ``setup.cfg`` values are interpolated when read, so a stray ``%`` in one
    is an error that surfaces only when that value is asked for.
    """

    @pytest.mark.parametrize(
        "metadata",
        [
            "license = 100% free\n",
            # The license value is the one asked for first: a classifier
            # that could be read does not stand in for it.
            "license = 100% free\nclassifiers =\n    License :: OSI Approved :: MIT License\n",
            "classifiers =\n    Topic :: 100% done\n    License :: OSI Approved :: MIT License\n",
            "license = %(spdx)s\n",
        ],
        ids=["license", "license-beside-a-classifier", "classifiers", "missing-option"],
    )
    @respx.mock
    def test_scan_runs_and_judges_the_project_as_proprietary(self, tmp_path: Path, metadata):
        _setup_cfg(tmp_path, metadata)
        _mock_pypi("gpl-lib", "GPL-3.0-only")

        result, data = _check_json(tmp_path, _NO_LOCKFILE)
        # Not a crash: the GPL dependency is a violation for a Proprietary project.
        assert result.exit_code == 1
        assert (data["project_license"], data["project_license_source"]) == ("Proprietary", "")
        assert _verdicts(data) == {"gpl-lib": "incompatible"}
        assert _ASSUMED in result.stderr.splitlines()
        # The requirement in the same file was read, and nothing about the
        # file is reported: the value that cannot be read is not one the
        # dependencies come from.
        assert _file_diagnostics(data) == []

    @respx.mock
    def test_file_whose_requirements_cannot_be_read_either_is_one_gap(self, tmp_path: Path):
        # Dependency discovery records the file. License detection adds no
        # second entry for it.
        _setup_cfg(tmp_path, "license = 100% free\n", requirement="gpl-lib==1.0.0 ; 100% sure")
        _write(tmp_path / "requirements.txt", "mit-lib==1.0.0\n")
        _mock_pypi("mit-lib", "MIT")

        result, data = _check_json(tmp_path, _NO_LOCKFILE, "--no-strict")
        assert result.exit_code == 0
        assert data["project_license"] == "Proprietary"
        assert _verdicts(data) == {"mit-lib": "compatible"}
        assert _file_diagnostics(data) == [
            {"path": "setup.cfg", "reason": "is not valid INI; skipped", "severity": "gap"}
        ]
        assert result.stderr.count("Warning: setup.cfg:") == 1

    def test_detection_records_nothing_and_the_next_manifest_decides(self, tmp_path: Path):
        _setup_cfg(tmp_path, "license = 100% free\n")
        _write(tmp_path / "package.json", '{"name": "app", "license": "ISC"}')
        with collect_read_diagnostics() as diags:
            detected = detect_project_license(tmp_path)
        assert detected == ProjectLicense(
            license="ISC", source="package.json", declared=(("package.json", "ISC"),)
        )
        assert diags == []

    @pytest.mark.parametrize(
        ("metadata", "declared", "spdx"),
        [
            # Interpolation still applies to a value that can be read.
            ("license = %(spdx)s\nspdx = MIT\n", "MIT", "MIT"),
            ("classifiers =\n    License :: OSI Approved :: BSD License\n", "BSD License", None),
        ],
        ids=["reference", "classifier"],
    )
    def test_value_that_can_be_read_is_still_used(self, tmp_path: Path, metadata, declared, spdx):
        _setup_cfg(tmp_path, metadata)
        detected = detect_project_license(tmp_path)
        assert detected.declared == (("setup.cfg", declared),)
        if spdx is not None:
            assert (detected.license, detected.source) == (spdx, "setup.cfg")

    @respx.mock
    def test_escaped_percent_is_a_declared_value_that_is_not_a_license(self, tmp_path: Path):
        # ``%%`` is how setup.cfg writes a percent sign. The value is read,
        # is not a license, and is reported like any other such value.
        _setup_cfg(tmp_path, "license = 100%% free\n", requirement="mit-lib==1.0.0")
        _mock_pypi("mit-lib", "MIT")

        result, data = _check_json(tmp_path, _NO_LOCKFILE)
        assert result.exit_code == 0
        assert data["project_license"] == "Proprietary"
        assert (
            "Warning: setup.cfg declares the license '100% free', which is not a recognised "
            "license; dependencies are checked against Proprietary."
        ) in result.stderr.splitlines()

    @respx.mock
    def test_init_review_file_runs_the_same_detection(self, tmp_path: Path):
        _setup_cfg(tmp_path, "license = 100% free\n")
        _mock_pypi("gpl-lib", "GPL-3.0-only")

        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert _ASSUMED in result.stderr.splitlines()
        review = (tmp_path / "licenseal.review.toml").read_text(encoding="utf-8")
        assert 'package = "gpl-lib"' in review


_APACHE_URL = "https://www.apache.org/licenses/LICENSE-2.0"


def _msbuild(*properties: str, group: str = "<PropertyGroup>") -> str:
    """An MSBuild file whose one property group holds ``properties``."""
    return f"<Project>{group}{''.join(properties)}</PropertyGroup></Project>"


def _expression(license_id: str) -> str:
    return f"<PackageLicenseExpression>{license_id}</PackageLicenseExpression>"


class TestDirectoryBuildProps:
    """A solution's shared package properties carry its license.

    The projects of a .NET solution live in subdirectories and take
    ``PackageLicenseExpression`` from the ``Directory.Build.props`` in the
    solution root, so the scanned directory holds no project file to read.
    """

    def test_license_url_is_read_when_there_is_no_expression(self, tmp_path: Path):
        _write(
            tmp_path / "Directory.Build.props",
            _msbuild(f"<PackageLicenseUrl>{_APACHE_URL}</PackageLicenseUrl>"),
        )
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="Apache-2.0",
            source="Directory.Build.props",
            declared=(("Directory.Build.props", _APACHE_URL),),
        )

    def test_expression_is_read_ahead_of_the_license_url(self, tmp_path: Path):
        _write(
            tmp_path / "Directory.Build.props",
            _msbuild(f"<PackageLicenseUrl>{_APACHE_URL}</PackageLicenseUrl>", _expression("MIT")),
        )
        detected = detect_project_license(tmp_path)
        assert (detected.license, detected.declared) == (
            "MIT",
            (("Directory.Build.props", "MIT"),),
        )

    def test_project_file_in_the_scanned_directory_decides_first(self, tmp_path: Path):
        # A project's own property overrides the one it imports.
        _write(tmp_path / "Directory.Build.props", _msbuild(_expression("Apache-2.0")))
        _write(tmp_path / "App.csproj", _msbuild(_expression("MIT")))
        assert detect_project_license(tmp_path) == ProjectLicense(
            license="MIT",
            source="App.csproj",
            declared=(("App.csproj", "MIT"), ("Directory.Build.props", "Apache-2.0")),
        )

    def test_project_file_without_a_license_leaves_the_props_file_to_decide(self, tmp_path: Path):
        _write(tmp_path / "Directory.Build.props", _msbuild(_expression("Apache-2.0")))
        _write(tmp_path / "App.csproj", _msbuild("<TargetFramework>net8.0</TargetFramework>"))
        detected = detect_project_license(tmp_path)
        assert (detected.license, detected.source) == ("Apache-2.0", "Directory.Build.props")

    @pytest.mark.parametrize(
        "content",
        [
            _msbuild(
                _expression("MIT"), group="<PropertyGroup Condition=\"'$(IsPackable)' == 'true'\">"
            ),
            _msbuild(
                "<PackageLicenseExpression Condition=\"'$(Configuration)' == 'Release'\">MIT"
                "</PackageLicenseExpression>"
            ),
        ],
        ids=["group-condition", "property-condition"],
    )
    def test_conditions_are_not_evaluated(self, tmp_path: Path, content):
        # The property is read whether or not its condition would hold.
        _write(tmp_path / "Directory.Build.props", content)
        detected = detect_project_license(tmp_path)
        assert (detected.license, detected.source) == ("MIT", "Directory.Build.props")

    def test_imports_are_not_followed(self, tmp_path: Path):
        _write(tmp_path / "build" / "Common.props", _msbuild(_expression("MIT")))
        _write(
            tmp_path / "Directory.Build.props",
            '<Project><Import Project="build/Common.props" /></Project>',
        )
        assert detect_project_license(tmp_path) == ProjectLicense()

    def test_property_inside_a_choose_branch_is_not_read(self, tmp_path: Path):
        _write(
            tmp_path / "Directory.Build.props",
            "<Project><Choose><When Condition=\"'$(OS)' == 'Windows_NT'\">"
            f"<PropertyGroup>{_expression('MIT')}</PropertyGroup></When></Choose></Project>",
        )
        assert detect_project_license(tmp_path) == ProjectLicense()

    @pytest.mark.parametrize(
        "name",
        ["Directory.Build.targets", "Directory.Packages.props", "directory.build.props"],
    )
    def test_no_other_shared_file_declares_the_license(self, tmp_path: Path, name):
        # The file name is matched as MSBuild looks it up, by its exact spelling.
        _write(tmp_path / name, _msbuild(_expression("MIT")))
        assert detect_project_license(tmp_path) == ProjectLicense()

    def test_value_that_is_not_a_license_is_reported_and_not_used(self, tmp_path: Path):
        _write(tmp_path / "Directory.Build.props", _msbuild(_expression("$(SharedLicense)")))
        assert detect_project_license(tmp_path) == ProjectLicense(
            declared=(("Directory.Build.props", "$(SharedLicense)"),)
        )

    def test_file_that_is_not_xml_is_a_gap_and_the_next_manifest_decides(self, tmp_path: Path):
        broken = _write(tmp_path / "Directory.Build.props", "<Project><PropertyGroup>")
        _write(tmp_path / "composer.json", '{"name": "vendor/app", "license": "MIT"}')
        with collect_read_diagnostics() as diags:
            detected = detect_project_license(tmp_path)
        assert (detected.license, detected.source) == ("MIT", "composer.json")
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (broken, "is not valid XML; skipped", True)
        ]

    @staticmethod
    def _solution(tmp_path: Path) -> Path:
        """A solution whose one project, in a subdirectory, references a GPL package."""
        _write(
            tmp_path / "src" / "App" / "App.csproj",
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<PackageReference Include="GplPkg" Version="1.0.0" />'
            "</ItemGroup></Project>",
        )
        respx.get("https://api.nuget.org/v3-flatcontainer/gplpkg/1.0.0/gplpkg.nuspec").mock(
            return_value=httpx.Response(
                200,
                text=(
                    '<?xml version="1.0" encoding="utf-8"?>\n'
                    '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
                    "<metadata><id>GplPkg</id><version>1.0.0</version>"
                    '<license type="expression">GPL-3.0-only</license></metadata></package>'
                ),
            )
        )
        return tmp_path

    @respx.mock
    def test_solution_is_judged_against_the_license_of_its_root_props_file(self, tmp_path: Path):
        project = self._solution(tmp_path)
        _write(project / "Directory.Build.props", _msbuild(_expression("GPL-3.0-only")))

        result, data = _check_json(project, _NO_LOCKFILE)
        assert result.exit_code == 0
        assert (data["project_license"], data["project_license_source"]) == (
            "GPL-3.0-only",
            "Directory.Build.props",
        )
        assert _verdicts(data) == {"GplPkg": "compatible"}
        assert (
            "Project license: GPL-3.0-only (from Directory.Build.props)."
            in result.stderr.splitlines()
        )

    @respx.mock
    def test_props_file_of_a_subdirectory_is_not_the_solution_license(self, tmp_path: Path):
        # Control for the test above: the same declaration one level down
        # belongs to the projects under it, and the solution is Proprietary.
        project = self._solution(tmp_path)
        _write(project / "src" / "Directory.Build.props", _msbuild(_expression("GPL-3.0-only")))

        result, data = _check_json(project, _NO_LOCKFILE)
        assert result.exit_code == 1
        assert (data["project_license"], data["project_license_source"]) == ("Proprietary", "")
        assert _verdicts(data) == {"GplPkg": "incompatible"}
        assert _ASSUMED in result.stderr.splitlines()

    @respx.mock
    def test_markdown_report_names_the_props_file(self, tmp_path: Path):
        project = self._solution(tmp_path)
        _write(project / "Directory.Build.props", _msbuild(_expression("GPL-3.0-only")))
        markdown = CliRunner().invoke(
            main, ["check", "--path", str(project), "-f", "markdown", _NO_LOCKFILE]
        )
        assert markdown.exit_code == 0
        assert (
            "**Project license:** GPL-3.0-only (from "
            "[Directory.Build.props](Directory.Build.props))" in markdown.stdout.splitlines()
        )
