"""Gap-surfacing coverage: malformed / unreadable manifests must be recorded.

Each parser routes its read+parse through ``licenseal.discovery._read``; a file
that can't be read or parsed is recorded as an analysis *gap* rather than
silently dropped. These tests exercise the record-and-skip branch of the
representative formats (XML, JSON/nuget, yarn text, INI).
"""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import collect_read_diagnostics
from licenseal.discovery.dotnet.lockfiles import discover_nuget_lockfile_dependencies
from licenseal.discovery.java.pom_xml import (
    detect_project_license_pom_xml,
    discover_pom_xml_dependencies,
)
from licenseal.discovery.npm.lockfiles import parse_yarn_lock
from licenseal.discovery.python.setup_cfg import (
    detect_project_license_setup_cfg,
    discover_setup_cfg_dependencies,
)
from licenseal.discovery.rust.lockfiles import parse_cargo_lock
from licenseal.transitive import _read_local_pom


def _raise_oserror(self, *args, **kwargs):
    raise OSError("simulated")


class TestPomGaps:
    def test_malformed_pom_recorded_at_every_pass(self, tmp_path: Path):
        # A truncated pom.xml is read by all three pom passes (workspace-local
        # index, dependency discovery, license detection); each records a gap.
        (tmp_path / "pom.xml").write_text("<project><dependencies", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            deps, _ = discover_pom_xml_dependencies(tmp_path)
            lic = detect_project_license_pom_xml(tmp_path)
        assert deps == []
        assert lic == ""
        assert any(d.is_gap and "not valid XML" in d.reason for d in diags)


class TestNugetLockfileGaps:
    def test_unreadable_packages_lock_recorded(self, tmp_path: Path, monkeypatch):
        (tmp_path / "packages.lock.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
        with collect_read_diagnostics() as diags:
            deps, _ = discover_nuget_lockfile_dependencies(tmp_path)
        assert deps == []
        assert any(d.is_gap and "could not be read" in d.reason for d in diags)

    def test_malformed_packages_lock_recorded(self, tmp_path: Path):
        (tmp_path / "packages.lock.json").write_text("{ not json", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            deps, _ = discover_nuget_lockfile_dependencies(tmp_path)
        assert deps == []
        assert any(d.is_gap and "not valid JSON" in d.reason for d in diags)


class TestYarnLockGaps:
    def test_unreadable_yarn_lock_returns_empty(self, tmp_path: Path, monkeypatch):
        lock = tmp_path / "yarn.lock"
        lock.write_text("# yarn\n", encoding="utf-8")
        monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
        with collect_read_diagnostics() as diags:
            assert parse_yarn_lock(lock, set(), set(), include_dev=True) == []
        assert any(d.is_gap and "could not be read" in d.reason for d in diags)


class TestSetupCfgGaps:
    _MALFORMED = "[metadata]\nlicense = MIT\nlicense = BSD\n"  # duplicate option

    def test_malformed_setup_cfg_discover_recorded(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(self._MALFORMED, encoding="utf-8")
        with collect_read_diagnostics() as diags:
            assert discover_setup_cfg_dependencies(tmp_path) == []
        assert any(d.is_gap and "not valid INI" in d.reason for d in diags)

    def test_malformed_setup_cfg_detect_recorded(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(self._MALFORMED, encoding="utf-8")
        with collect_read_diagnostics() as diags:
            assert detect_project_license_setup_cfg(tmp_path) == ""
        assert any(d.is_gap and "not valid INI" in d.reason for d in diags)

    def test_unreadable_setup_cfg_skipped(self, tmp_path: Path, monkeypatch):
        (tmp_path / "setup.cfg").write_text("[metadata]\nlicense = MIT\n", encoding="utf-8")
        monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
        assert discover_setup_cfg_dependencies(tmp_path) == []
        assert detect_project_license_setup_cfg(tmp_path) == ""


class TestCargoLockGaps:
    def test_malformed_cargo_lock_returns_empty(self, tmp_path: Path):
        lock = tmp_path / "Cargo.lock"
        lock.write_text("this is = = not toml", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            deps, known = parse_cargo_lock(lock, set(), set(), include_dev=True)
        assert deps == [] and known == set()
        assert any(d.is_gap and "not valid TOML" in d.reason for d in diags)


class TestLocalPomGaps:
    def test_malformed_local_pom_recorded(self, tmp_path: Path):
        # The transitive walker reads in-tree parent POMs; a malformed one is a
        # gap, not a silently-empty parent.
        pom = tmp_path / "pom.xml"
        pom.write_text("<project><parent", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            assert _read_local_pom(pom) is None
        assert any(d.is_gap and "not valid XML" in d.reason for d in diags)
