"""Tests for Go ``go.sum`` enumeration."""

from __future__ import annotations

from licenseal.discovery.go.lockfile import find_go_lockfiles, parse_go_sum_entries


class TestParseGoSumEntries:
    def test_dedupe_zip_and_go_mod_rows(self, tmp_path):
        # Each Go module appears twice in go.sum — for ``.zip`` and ``/go.mod``.
        # Dedupe to a single (module_path, version) tuple per package.
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(
            "github.com/foo/bar v1.2.3 h1:hash1\ngithub.com/foo/bar v1.2.3/go.mod h1:hash2\n",
            encoding="utf-8",
        )
        entries = parse_go_sum_entries(go_sum)
        assert entries == [("github.com/foo/bar", "v1.2.3")]

    def test_returns_entries_in_first_seen_order(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(
            "github.com/alpha v1.0.0 h1:h\n"
            "github.com/alpha v1.0.0/go.mod h1:h\n"
            "github.com/beta v2.0.0 h1:h\n"
            "github.com/beta v2.0.0/go.mod h1:h\n",
            encoding="utf-8",
        )
        entries = parse_go_sum_entries(go_sum)
        assert entries == [
            ("github.com/alpha", "v1.0.0"),
            ("github.com/beta", "v2.0.0"),
        ]

    def test_malformed_lines_skipped(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(
            "incomplete\ntwo fields\ngithub.com/good v1.0.0 h1:hash\n",
            encoding="utf-8",
        )
        entries = parse_go_sum_entries(go_sum)
        assert entries == [("github.com/good", "v1.0.0")]

    def test_missing_file_returns_empty(self, tmp_path):
        nonexistent = tmp_path / "nonexistent.sum"
        assert parse_go_sum_entries(nonexistent) == []

    def test_duplicate_zip_rows_deduped(self, tmp_path):
        # Defensive: same (module, version) listed twice (e.g. concatenated
        # lockfiles or a corrupted regenerate) — dedupe.
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(
            "github.com/dup v1.0.0 h1:h1\ngithub.com/dup v1.0.0 h1:h2\n",
            encoding="utf-8",
        )
        entries = parse_go_sum_entries(go_sum)
        assert entries == [("github.com/dup", "v1.0.0")]


class TestFindGoLockfiles:
    def test_finds_nested(self, tmp_path):
        (tmp_path / "go.sum").write_text("", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "go.sum").write_text("", encoding="utf-8")
        found = find_go_lockfiles(tmp_path)
        assert len(found) == 2
