"""Tests for Paket discovery (paket.dependencies + paket.lock)."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.dotnet.paket import (
    _group_to_dependency_group,
    _parse_paket_dependencies_text,
    _parse_paket_lock_text,
    discover_paket_dependencies,
    find_paket_lockfiles,
    parse_paket_lock,
)
from licenseal.models import DependencyGroup, Ecosystem


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# _group_to_dependency_group
# ---------------------------------------------------------------------------


class TestGroupToDependencyGroup:
    def test_main_group_is_prod(self):
        assert _group_to_dependency_group("Main") == DependencyGroup.PROD
        assert _group_to_dependency_group("main") == DependencyGroup.PROD

    def test_test_group_is_dev(self):
        assert _group_to_dependency_group("Test") == DependencyGroup.DEV
        assert _group_to_dependency_group("test") == DependencyGroup.DEV

    def test_build_group_is_dev(self):
        assert _group_to_dependency_group("Build") == DependencyGroup.DEV

    def test_tools_group_is_dev(self):
        assert _group_to_dependency_group("Tools") == DependencyGroup.DEV

    def test_test_suffix_is_dev(self):
        # Custom groups ending in ``Test``/``test`` (e.g. ``IntegrationTest``,
        # ``UnitTest``) are conservatively classified DEV.
        assert _group_to_dependency_group("IntegrationTest") == DependencyGroup.DEV
        assert _group_to_dependency_group("UnitTest") == DependencyGroup.DEV

    def test_unknown_group_stays_prod(self):
        # A truly novel group name flows through as PROD. The conservative
        # alternative (default-to-DEV) would hide real prod deps; we'd
        # rather flag PROD and let the user reclassify via review.toml.
        assert _group_to_dependency_group("CustomFeature") == DependencyGroup.PROD


# ---------------------------------------------------------------------------
# _parse_paket_dependencies_text
# ---------------------------------------------------------------------------


class TestParsePaketDependencies:
    def test_simple_nuget_lines(self):
        text = """source https://api.nuget.org/v3/index.json

nuget Newtonsoft.Json ~> 13.0
nuget Serilog >= 3.1
"""
        entries = _parse_paket_dependencies_text(text)
        assert len(entries) == 2
        names = [e[0] for e in entries]
        assert names == ["Newtonsoft.Json", "Serilog"]
        # All in implicit Main group → PROD.
        assert all(e[2] == DependencyGroup.PROD for e in entries)

    def test_nuget_without_constraint_emits_empty_version(self):
        text = "nuget OnlyName\n"
        entries = _parse_paket_dependencies_text(text)
        assert entries == [("OnlyName", "", DependencyGroup.PROD)]

    def test_group_directive_switches_group_to_dev(self):
        text = """nuget MainDep ~> 1.0

group Test
    source https://api.nuget.org/v3/index.json
    nuget TestDep
    nuget FsCheck
"""
        entries = _parse_paket_dependencies_text(text)
        by_name = {e[0]: e for e in entries}
        assert by_name["MainDep"][2] == DependencyGroup.PROD
        assert by_name["TestDep"][2] == DependencyGroup.DEV
        assert by_name["FsCheck"][2] == DependencyGroup.DEV

    def test_build_group_classified_dev(self):
        text = """group Build
    nuget Fake.Core.Target
"""
        entries = _parse_paket_dependencies_text(text)
        assert entries[0][2] == DependencyGroup.DEV

    def test_unknown_group_stays_prod(self):
        text = """group Mystery
    nuget MysteryDep
"""
        entries = _parse_paket_dependencies_text(text)
        assert entries[0][2] == DependencyGroup.PROD

    def test_blank_lines_and_comments_skipped(self):
        text = """
// this is a comment
# also a comment

nuget Real.Dep ~> 1.0
"""
        entries = _parse_paket_dependencies_text(text)
        assert entries == [("Real.Dep", "~> 1.0", DependencyGroup.PROD)]

    def test_non_nuget_source_lines_ignored(self):
        # ``git``, ``github``, ``http`` sources are not honored — only
        # ``nuget`` lines are parsed. The source directive itself doesn't
        # look like a ``nuget`` line so it falls through silently.
        text = """git https://example.com/repo.git Some.Lib
github user/repo Other.Lib
http https://example.com/blob/foo.zip
nuget RealOne ~> 1.0
"""
        entries = _parse_paket_dependencies_text(text)
        assert [e[0] for e in entries] == ["RealOne"]

    def test_inline_comment_stripped_from_constraint(self):
        text = "nuget Lib ~> 1.0 // pinned to 1.x for now\n"
        entries = _parse_paket_dependencies_text(text)
        assert entries[0][1] == "~> 1.0"


# ---------------------------------------------------------------------------
# _parse_paket_lock_text
# ---------------------------------------------------------------------------


class TestParsePaketLock:
    def test_simple_lockfile(self):
        text = """NUGET
  remote: https://api.nuget.org/v3/index.json
    Newtonsoft.Json (13.0.1)
    Serilog (3.1.1)
      FSharp.Core (>= 5.0)
"""
        entries = _parse_paket_lock_text(text)
        by_name = {e[0]: e for e in entries}
        assert by_name["Newtonsoft.Json"][1] == "13.0.1"
        assert by_name["Serilog"][1] == "3.1.1"
        # Transitive edge surfaces as its own entry (with constraint, not pin).
        assert by_name["FSharp.Core"][1] == ">= 5.0"

    def test_group_switches_attribution(self):
        text = """NUGET
  remote: https://api.nuget.org/v3/index.json
    MainDep (1.0.0)
GROUP Test
NUGET
  remote: https://api.nuget.org/v3/index.json
    TestDep (2.0.0)
"""
        entries = _parse_paket_lock_text(text)
        by_name = {e[0]: e for e in entries}
        assert by_name["MainDep"][2] == DependencyGroup.PROD
        assert by_name["TestDep"][2] == DependencyGroup.DEV

    def test_git_source_section_skipped(self):
        # GIT-sourced entries are not honored; only NUGET ones surface.
        text = """NUGET
  remote: https://api.nuget.org/v3/index.json
    KeepMe (1.0)
GIT
  remote: https://example.com/repo.git
    SkipMe (master)
NUGET
  remote: https://api.nuget.org/v3/index.json
    AlsoKeep (2.0)
"""
        entries = _parse_paket_lock_text(text)
        names = {e[0] for e in entries}
        assert names == {"KeepMe", "AlsoKeep"}

    def test_github_and_http_sources_skipped(self):
        text = """NUGET
  remote: https://api.nuget.org/v3/index.json
    KeepMe (1.0)
GITHUB
  remote: user/repo
    SkipMe (master)
HTTP
  remote: https://example.com
    AlsoSkip (1.0)
"""
        entries = _parse_paket_lock_text(text)
        names = {e[0] for e in entries}
        assert names == {"KeepMe"}

    def test_specs_marker_skipped(self):
        # Some Paket lockfile dialects include a ``specs:`` line; it's
        # informational and must not be parsed as an entry.
        text = """NUGET
  remote: https://api.nuget.org/v3/index.json
  specs:
    RealDep (1.0)
"""
        entries = _parse_paket_lock_text(text)
        assert [e[0] for e in entries] == ["RealDep"]

    def test_unrelated_lines_ignored(self):
        # Lines that don't fit any pattern (random text, sub-line metadata)
        # must be silently skipped.
        text = """NUGET
  remote: https://api.nuget.org/v3/index.json
random garbage line
    Real (1.0)
"""
        entries = _parse_paket_lock_text(text)
        assert [e[0] for e in entries] == ["Real"]

    def test_blank_lines_skipped(self):
        text = "\n\nNUGET\n\n  remote: https://api.nuget.org/\n\n    X (1.0)\n\n"
        entries = _parse_paket_lock_text(text)
        assert entries == [("X", "1.0", DependencyGroup.PROD)]

    def test_no_nuget_source_no_entries(self):
        text = """GIT
  remote: https://example.com/repo.git
    SkipMe (master)
"""
        entries = _parse_paket_lock_text(text)
        assert entries == []


# ---------------------------------------------------------------------------
# discover_paket_dependencies — end-to-end
# ---------------------------------------------------------------------------


class TestDiscoverPaketDependencies:
    def test_single_file(self, tmp_path):
        _write(
            tmp_path / "paket.dependencies",
            """source https://api.nuget.org/v3/index.json
nuget Newtonsoft.Json ~> 13.0
""",
        )
        deps, filtered = discover_paket_dependencies(tmp_path)
        assert filtered == 0
        assert len(deps) == 1
        assert deps[0].name == "Newtonsoft.Json"
        assert deps[0].version_constraint == "~> 13.0"
        assert deps[0].ecosystem == Ecosystem.DOTNET
        assert deps[0].group == DependencyGroup.PROD

    def test_no_paket_files_returns_empty(self, tmp_path):
        deps, filtered = discover_paket_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    def test_unreadable_file_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path / "paket.dependencies", "nuget X\n")
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "paket.dependencies":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        deps, _ = discover_paket_dependencies(tmp_path)
        assert deps == []

    def test_source_path_is_posix(self, tmp_path):
        _write(tmp_path / "deeply" / "nested" / "paket.dependencies", "nuget X ~> 1\n")
        deps, _ = discover_paket_dependencies(tmp_path)
        assert deps[0].source == "deeply/nested/paket.dependencies"

    def test_utf8_bom_tolerated(self, tmp_path):
        path = tmp_path / "paket.dependencies"
        path.write_bytes(b"\xef\xbb\xbfnuget BomDep ~> 1.0\n")
        deps, _ = discover_paket_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "BomDep"


# ---------------------------------------------------------------------------
# find_paket_lockfiles + parse_paket_lock
# ---------------------------------------------------------------------------


class TestFindPaketLockfiles:
    def test_returns_lockfiles(self, tmp_path):
        _write(tmp_path / "paket.lock", "")
        _write(tmp_path / "nested" / "paket.lock", "")
        result = find_paket_lockfiles(tmp_path)
        assert len(result) == 2

    def test_empty_workspace_returns_empty(self, tmp_path):
        assert find_paket_lockfiles(tmp_path) == []


class TestParsePaketLockHelper:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "paket.lock"
        _write(
            path,
            """NUGET
  remote: https://api.nuget.org/v3/index.json
    Newtonsoft.Json (13.0.1)
""",
        )
        deps = parse_paket_lock(path, project_path=tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "Newtonsoft.Json"
        assert deps[0].version_constraint == "13.0.1"
        assert deps[0].ecosystem == Ecosystem.DOTNET
        assert deps[0].source == "paket.lock"

    def test_unreadable_returns_empty(self, tmp_path, monkeypatch):
        path = tmp_path / "paket.lock"
        _write(path, "NUGET\n  remote: x\n    X (1.0)\n")
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "paket.lock":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        assert parse_paket_lock(path, project_path=tmp_path) == []
