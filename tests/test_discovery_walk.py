"""Tests for licenseal.discovery._walk — the shared project-file walker.

Covers deep-nesting discovery, permission-error handling, symlink skipping,
nested-``.git`` auto-skip (cloned repos / submodules), and explicit
``exclude_paths`` pruning. The walker is ecosystem-neutral; ``package.json``
is used here only as a convenient target filename.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from licenseal.discovery._walk import walk_project_files


class TestPackageJsonEdgeCases:
    def test_deeply_nested_package_json_is_found(self, tmp_path):
        """Nested project-owned package.json files should still be discovered."""
        deep = tmp_path
        for i in range(12):
            deep = deep / f"d{i}"
        deep.mkdir(parents=True)
        (deep / "package.json").write_text(json.dumps({"dependencies": {"deep-pkg": "1.0"}}))
        results = walk_project_files(tmp_path, "package.json")
        assert deep / "package.json" in results

    def test_permission_error(self, tmp_path):
        """PermissionError during directory iteration should be handled."""
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0"}}))
        with patch("licenseal.discovery._walk.os.walk", side_effect=PermissionError):
            results = walk_project_files(tmp_path, "package.json")
            assert results == []

    def test_permission_error_during_walk_iteration(self, tmp_path):
        """PermissionError from the walk iterator should be handled."""

        class BrokenWalk:
            def __iter__(self):
                return self

            def __next__(self):
                raise PermissionError("denied")

        with patch("licenseal.discovery._walk.os.walk", return_value=BrokenWalk()):
            results = walk_project_files(tmp_path, "package.json")
            assert results == []


class TestSymlinkSkip:
    def test_symlink_skipped_in_discovery(self, tmp_path):
        """Symlinks should be skipped during package.json discovery."""
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"real-pkg": "1.0"}}))
        target = tmp_path / "target"
        target.mkdir()
        (target / "package.json").write_text(json.dumps({"dependencies": {"symlinked-pkg": "1.0"}}))
        link = tmp_path / "linked"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("symlinks not supported")
        results = walk_project_files(tmp_path, "package.json")
        names = [str(r) for r in results]
        assert not any("linked" in n for n in names)

    def test_symlink_skipped_via_mock_when_os_does_not_support_symlinks(self, tmp_path):
        """Cover the symlink-skip branch deterministically on platforms (Windows
        without Developer Mode, restricted CI runners) where ``Path.symlink_to``
        raises and the real-OS test above is skipped. Patch ``Path.is_symlink``
        to return True for a specific subdirectory so the walker takes the
        ``continue`` branch without depending on filesystem capabilities.
        """
        from pathlib import Path

        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"real-pkg": "1.0"}}))
        fake_link = tmp_path / "fake-link"
        fake_link.mkdir()
        (fake_link / "package.json").write_text(
            json.dumps({"dependencies": {"behind-link": "1.0"}})
        )

        real_is_symlink = Path.is_symlink

        def fake_is_symlink(self):
            if self.name == "fake-link":
                return True
            return real_is_symlink(self)

        with patch.object(Path, "is_symlink", fake_is_symlink):
            results = walk_project_files(tmp_path, "package.json")
        names = [str(r) for r in results]
        # Root manifest is found; the symlink subtree is pruned.
        assert any("package.json" in n for n in names)
        assert not any("fake-link" in n for n in names)


class TestNestedGitAndExclude:
    """Auto-skip nested git repos + explicit ``exclude_paths`` in the walker.

    The auto-skip handles the common case of cloned/vendored projects under
    a parent project (e.g. licenseal-scans/<repo>/). The explicit
    ``exclude_paths`` covers vendored snapshots that don't have a ``.git``.
    """

    def test_walker_skips_subdir_with_git_directory(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "root"}))
        inner = tmp_path / "cloned"
        (inner / ".git").mkdir(parents=True)
        (inner / "package.json").write_text(json.dumps({"name": "inner"}))
        results = walk_project_files(tmp_path, "package.json")
        assert tmp_path / "package.json" in results
        assert inner / "package.json" not in results

    def test_walker_skips_subdir_with_git_file(self, tmp_path):
        # Git submodules use a ``.git`` *file* (not directory) that points at
        # the parent's `.git/modules/<name>/`. The skip heuristic checks for
        # existence regardless of whether ``.git`` is a file or a directory.
        (tmp_path / "package.json").write_text(json.dumps({"name": "root"}))
        submodule = tmp_path / "vendored-submodule"
        submodule.mkdir()
        (submodule / ".git").write_text("gitdir: ../.git/modules/vendored-submodule\n")
        (submodule / "package.json").write_text(json.dumps({"name": "sub"}))
        results = walk_project_files(tmp_path, "package.json")
        assert tmp_path / "package.json" in results
        assert submodule / "package.json" not in results

    def test_walker_does_not_skip_root_with_own_git(self, tmp_path):
        # The project root may itself be a git repo; the heuristic only fires
        # on descended children, so the root's manifest is still picked up.
        (tmp_path / ".git").mkdir()
        (tmp_path / "package.json").write_text(json.dumps({"name": "root"}))
        results = walk_project_files(tmp_path, "package.json")
        assert results == [tmp_path / "package.json"]

    def test_walker_excludes_explicit_resolved_path(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "root"}))
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "package.json").write_text(json.dumps({"name": "vendored"}))
        results = walk_project_files(
            tmp_path,
            "package.json",
            exclude_paths=frozenset({vendor.resolve()}),
        )
        assert tmp_path / "package.json" in results
        assert vendor / "package.json" not in results

    def test_walker_exclude_nonexistent_path_is_noop(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "root"}))
        results = walk_project_files(
            tmp_path,
            "package.json",
            exclude_paths=frozenset({(tmp_path / "missing").resolve()}),
        )
        assert results == [tmp_path / "package.json"]

    def test_walker_exclude_project_root_returns_empty(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "root"}))
        results = walk_project_files(
            tmp_path,
            "package.json",
            exclude_paths=frozenset({tmp_path.resolve()}),
        )
        assert results == []
