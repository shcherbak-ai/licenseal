"""Tests for R / CRAN discovery (DESCRIPTION manifest + DCF parser)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from licenseal.discovery import detect_project_license, discover_all_dependencies
from licenseal.discovery.r._dcf import parse_dcf, parse_package_list
from licenseal.discovery.r.description import (
    collect_dev_direct_names,
    detect_project_license_description,
    discover_description_dependencies,
    is_base_package,
    workspace_r_names,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_DESCRIPTION = textwrap.dedent(
    """\
    Package: mypkg
    Type: Package
    Title: My Package
    Version: 1.0.0
    License: GPL (>= 2)
    Depends: R (>= 3.5.0), methods
    Imports: cli,
        rlang (>= 1.0.0),
        jsonlite
    Suggests: testthat (>= 3.0.0),
        knitr
    LinkingTo: cpp11
    """
)


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestParseDcf:
    def test_single_record_fields(self):
        records = parse_dcf("Package: x\nVersion: 1.0\n")
        assert records == [{"Package": "x", "Version": "1.0"}]

    def test_continuation_lines_joined(self):
        records = parse_dcf("Imports: cli,\n    rlang,\n    jsonlite\n")
        assert records[0]["Imports"] == "cli, rlang, jsonlite"

    def test_multiple_records_blank_line_separated(self):
        records = parse_dcf("Package: a\n\nPackage: b\nVersion: 2\n")
        assert records == [{"Package": "a"}, {"Package": "b", "Version": "2"}]

    def test_non_field_line_skipped(self):
        # A line without a colon that isn't a continuation is ignored.
        records = parse_dcf("Package: x\nnot a field line\nVersion: 1\n")
        assert records == [{"Package": "x", "Version": "1"}]

    def test_leading_continuation_with_no_field_skipped(self):
        # An indented line before any field has no field to attach to.
        records = parse_dcf("    orphan\nPackage: x\n")
        assert records == [{"Package": "x"}]

    def test_url_value_with_colon_kept_whole(self):
        records = parse_dcf("URL: https://example.org/path\n")
        assert records[0]["URL"] == "https://example.org/path"

    def test_blank_lines_with_empty_current(self):
        # Leading blanks (empty current → skipped) and a trailing blank (flush
        # the record, then end the loop with current empty).
        assert parse_dcf("\n\nPackage: x\n\n") == [{"Package": "x"}]


class TestParsePackageList:
    def test_name_and_constraint(self):
        assert parse_package_list("cli (>= 1.0.0)") == [("cli", ">= 1.0.0")]

    def test_name_only(self):
        assert parse_package_list("cli") == [("cli", "")]

    def test_multiple(self):
        assert parse_package_list("cli, rlang (>= 1.0), jsonlite") == [
            ("cli", ""),
            ("rlang", ">= 1.0"),
            ("jsonlite", ""),
        ]

    def test_empty_entries_skipped(self):
        assert parse_package_list("cli, , ") == [("cli", "")]

    def test_empty_name_skipped(self):
        assert parse_package_list("(>= 1.0)") == []


class TestIsBasePackage:
    def test_base_and_pseudo(self):
        assert is_base_package("R")
        assert is_base_package("stats")
        assert is_base_package("methods")

    def test_case_insensitive(self):
        assert is_base_package("STATS")

    def test_non_base(self):
        assert not is_base_package("ggplot2")
        assert not is_base_package("cli")
        # Recommended packages ARE on CRAN → not filtered.
        assert not is_base_package("MASS")


class TestDiscoverDescription:
    def test_prod_dev_split_and_filters(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", _DESCRIPTION)
        deps, filtered = discover_description_dependencies(tmp_path)
        prod = {d.name for d in deps if d.group == DependencyGroup.PROD}
        dev = {d.name for d in deps if d.group == DependencyGroup.DEV}
        # R + methods (base) filtered out of Depends.
        assert prod == {"cli", "rlang", "jsonlite", "cpp11"}
        assert dev == {"testthat", "knitr"}
        assert filtered == 0
        assert all(d.ecosystem == Ecosystem.R for d in deps)
        rlang = next(d for d in deps if d.name == "rlang")
        assert rlang.version_constraint == ">= 1.0.0"
        assert rlang.source == "DESCRIPTION"

    def test_workspace_filter(self, tmp_path):
        _write(
            tmp_path / "DESCRIPTION",
            "Package: mypkg\nImports: sibling, cli\n",
        )
        deps, filtered = discover_description_dependencies(
            tmp_path, workspace_names=frozenset({"sibling"})
        )
        assert {d.name for d in deps} == {"cli"}
        assert filtered == 1

    def test_duplicate_in_same_field_deduped(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", "Package: x\nImports: cli, cli\n")
        deps, _ = discover_description_dependencies(tmp_path)
        assert [d.name for d in deps] == ["cli"]

    def test_non_r_description_skipped(self, tmp_path):
        # A DESCRIPTION-named file with no R markers is not parsed.
        _write(tmp_path / "DESCRIPTION", "Title: Something\nDescription: not R\n")
        deps, filtered = discover_description_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    def test_read_error_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path / "DESCRIPTION", _DESCRIPTION)

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        deps, filtered = discover_description_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0


class TestCollectDevDirectNames:
    def test_dev_only_names(self):
        deps = [
            Dependency("cli", "", Ecosystem.R, group=DependencyGroup.PROD),
            Dependency("knitr", "", Ecosystem.R, group=DependencyGroup.DEV),
            # foo is both prod and dev → not dev-only.
            Dependency("foo", "", Ecosystem.R, group=DependencyGroup.PROD),
            Dependency("foo", "", Ecosystem.R, group=DependencyGroup.DEV),
            # Non-R deps ignored.
            Dependency("x", "", Ecosystem.PYTHON, group=DependencyGroup.DEV),
        ]
        assert collect_dev_direct_names(deps) == {"knitr"}


class TestDetectProjectLicense:
    def test_normalized_license(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", _DESCRIPTION)
        assert detect_project_license_description(tmp_path) == "GPL-2.0-or-later"

    def test_mit_plus_file(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", "Package: x\nLicense: MIT + file LICENSE\n")
        assert detect_project_license_description(tmp_path) == "MIT"

    def test_unknown_license_returns_empty(self, tmp_path):
        # A bare file-reference can't be resolved → empty (caller defaults).
        _write(tmp_path / "DESCRIPTION", "Package: x\nLicense: file LICENSE\n")
        assert detect_project_license_description(tmp_path) == ""

    def test_no_license_field(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", "Package: x\nVersion: 1.0\n")
        assert detect_project_license_description(tmp_path) == ""

    def test_non_r_description_skipped(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", "License: MIT\nFoo: bar\n")
        assert detect_project_license_description(tmp_path) == ""

    def test_read_error_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path / "DESCRIPTION", _DESCRIPTION)

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert detect_project_license_description(tmp_path) == ""


class TestWorkspaceRNames:
    def test_collects_package_names(self, tmp_path):
        _write(tmp_path / "a" / "DESCRIPTION", "Package: PkgA\nImports: cli\n")
        _write(tmp_path / "b" / "DESCRIPTION", "Package: PkgB\n")
        assert workspace_r_names(tmp_path) == frozenset({"pkga", "pkgb"})

    def test_no_package_field(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", "Type: Package\nImports: cli\n")
        assert workspace_r_names(tmp_path) == frozenset()

    def test_read_error_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path / "DESCRIPTION", "Package: x\n")

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert workspace_r_names(tmp_path) == frozenset()


class TestDiscoveryAggregator:
    def test_r_deps_in_discover_all(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", _DESCRIPTION)
        deps, counts = discover_all_dependencies(tmp_path)
        r_names = {d.name for d in deps if d.ecosystem == Ecosystem.R}
        assert {"cli", "rlang", "jsonlite", "cpp11", "testthat", "knitr"} <= r_names
        assert counts["r"] == 0

    def test_workspace_filter_count_in_aggregator(self, tmp_path):
        _write(tmp_path / "a" / "DESCRIPTION", "Package: PkgA\nImports: PkgB, cli\n")
        _write(tmp_path / "b" / "DESCRIPTION", "Package: PkgB\n")
        deps, counts = discover_all_dependencies(tmp_path)
        # PkgB filtered as a workspace sibling; cli survives.
        r_names = {d.name for d in deps if d.ecosystem == Ecosystem.R}
        assert "cli" in r_names
        assert "PkgB" not in r_names
        assert counts["r"] == 1

    def test_detect_project_license_falls_through_to_r(self, tmp_path):
        _write(tmp_path / "DESCRIPTION", "Package: x\nLicense: MIT + file LICENSE\n")
        assert detect_project_license(tmp_path) == "MIT"
