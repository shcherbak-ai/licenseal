"""Tests for Rust manifest discovery (Cargo.toml)."""

from __future__ import annotations

import textwrap
from unittest.mock import patch

from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.rust.cargo_toml import (
    detect_project_license_cargo_toml,
    discover_cargo_toml_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem


def _write(tmp_path, content):
    path = tmp_path / "Cargo.toml"
    path.write_text(textwrap.dedent(content))
    return path


class TestDiscoverCargoToml:
    def test_returns_empty_when_no_cargo_toml(self, tmp_path):
        assert discover_cargo_toml_dependencies(tmp_path) == ([], 0)

    def test_parses_top_level_dependencies(self, tmp_path):
        _write(
            tmp_path,
            """\
            [package]
            name = "myapp"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            tokio = { version = "1.20", features = ["full"] }

            [dev-dependencies]
            criterion = "0.4"

            [build-dependencies]
            cc = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["serde"].group == DependencyGroup.PROD
        assert by_name["serde"].version_constraint == "1.0"
        assert by_name["serde"].ecosystem == Ecosystem.RUST
        assert by_name["serde"].source == "Cargo.toml"
        assert by_name["tokio"].version_constraint == "1.20"
        assert by_name["tokio"].group == DependencyGroup.PROD
        assert by_name["criterion"].group == DependencyGroup.DEV
        assert by_name["cc"].group == DependencyGroup.PROD

    def test_source_is_project_relative_path(self, tmp_path):
        # Workspace layout: root Cargo.toml + nested crate Cargo.toml. Each
        # dep's source carries the project-relative path of its declaring
        # file so callers can tell which crate declared it.
        _write(
            tmp_path,
            """\
            [package]
            name = "root"

            [dependencies]
            root-dep = "1.0"
            """,
        )
        (tmp_path / "crates" / "core").mkdir(parents=True)
        (tmp_path / "crates" / "core" / "Cargo.toml").write_text(
            textwrap.dedent("""\
                [package]
                name = "core"

                [dependencies]
                nested-dep = "1.0"
            """)
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["root-dep"].source == "Cargo.toml"
        assert by_name["nested-dep"].source == "crates/core/Cargo.toml"

    def test_skips_path_and_git_deps(self, tmp_path):
        _write(
            tmp_path,
            """\
            [dependencies]
            local-crate = { path = "../local-crate" }
            git-crate = { git = "https://github.com/x/y" }
            registry-crate = { version = "1.0" }
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"registry-crate"}

    def test_target_specific_deps_flatten(self, tmp_path):
        _write(
            tmp_path,
            """\
            [target.'cfg(unix)'.dependencies]
            libc = "0.2"

            [target.'cfg(windows)'.build-dependencies]
            winapi = "0.3"

            [target.'cfg(target_os = "macos")'.dev-dependencies]
            mac-helper = "0.1"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        groups = {d.name: d.group for d in deps}
        assert groups["libc"] == DependencyGroup.PROD
        assert groups["winapi"] == DependencyGroup.PROD
        assert groups["mac-helper"] == DependencyGroup.DEV

    def test_workspace_dependencies(self, tmp_path):
        _write(
            tmp_path,
            """\
            [workspace]
            members = ["crate-a", "crate-b"]

            [workspace.dependencies]
            shared-lib = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"shared-lib"}
        assert deps[0].group == DependencyGroup.PROD

    def test_skips_non_string_keys_and_invalid_specs(self, tmp_path):
        _write(
            tmp_path,
            """\
            [dependencies]
            valid = "1.0"
            also-table = { version = "2.0" }
            no-version-table = { features = ["x"] }
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "valid" in names
        assert "also-table" in names
        # `no-version-table` has no version + no path/git → skipped.
        assert "no-version-table" not in names

    def test_handles_malformed_target_section(self, tmp_path):
        _write(
            tmp_path,
            """\
            [target]
            "cfg(unix)" = "oops"

            [dependencies]
            valid = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"valid"}

    def test_skips_non_string_non_table_specs(self, tmp_path):
        # Defensive: a Cargo.toml with a non-string, non-table dep value
        # (e.g. an integer) should not crash.
        _write(
            tmp_path,
            """\
            [dependencies]
            valid = "1.0"
            weird = 42
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"valid"}

    def test_handles_missing_dependencies_table(self, tmp_path):
        _write(
            tmp_path,
            """\
            [package]
            name = "empty"
            version = "0.0.1"
            """,
        )
        assert discover_cargo_toml_dependencies(tmp_path) == ([], 0)

    def test_rename_package_uses_canonical_crate_name(self, tmp_path):
        # Cargo lets a Cargo.toml declare a dep under a local alias by
        # setting `package = "<real-name>"`. The crates.io entry lives under
        # the real name; the alias has no registry record. Without this fix,
        # registry-walk-only paths (no Cargo.lock or workspace member
        # uncovered by the root lockfile) 404 on the alias and the dep
        # surfaces as an empty-version UNKNOWN.
        _write(
            tmp_path,
            """\
            [package]
            name = "wrapper"
            version = "0.0.1"

            [dependencies]
            getrandom_4 = { package = "getrandom", version = "0.4" }
            getrandom_3_3 = { package = "getrandom", version = "0.3.3" }
            normal_dep = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        by_name = {d.name: d.version_constraint for d in deps}
        # Both renamed entries collapse to the canonical crate name (two
        # entries, same name, different versions — that's correct: it's the
        # actual package coexisting in two majors).
        assert by_name.keys() == {"getrandom", "normal_dep"} or (
            # Order isn't guaranteed; the multi-entry case stores both.
            [d.name for d in deps].count("getrandom") == 2 and "normal_dep" in by_name
        )
        # Local-alias names never leak into the emitted deps.
        names = {d.name for d in deps}
        assert "getrandom_4" not in names
        assert "getrandom_3_3" not in names
        # Versions of both renamed entries surface.
        renamed_versions = {d.version_constraint for d in deps if d.name == "getrandom"}
        assert renamed_versions == {"0.4", "0.3.3"}


class TestDetectProjectLicenseCargoToml:
    def test_returns_empty_when_no_cargo_toml(self, tmp_path):
        assert detect_project_license_cargo_toml(tmp_path) == ""

    def test_reads_package_license(self, tmp_path):
        _write(
            tmp_path,
            """\
            [package]
            name = "myapp"
            version = "0.1.0"
            license = "MIT OR Apache-2.0"
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == "MIT OR Apache-2.0"

    def test_returns_empty_when_no_license_field(self, tmp_path):
        _write(
            tmp_path,
            """\
            [package]
            name = "myapp"
            version = "0.1.0"
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == ""

    def test_returns_empty_when_no_package_table(self, tmp_path):
        _write(
            tmp_path,
            """\
            [workspace]
            members = ["a", "b"]
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == ""

    def test_returns_empty_for_non_string_license(self, tmp_path):
        _write(
            tmp_path,
            """\
            [package]
            name = "myapp"
            version = "0.1.0"
            license = { text = "Custom" }
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == ""


class TestRustWorkspaceDiscovery:
    """Cargo workspaces declare `[workspace] members = [...]` at root with
    no `[dependencies]` of their own — actual deps live in member crates'
    Cargo.toml files."""

    def _write(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))

    def test_walks_member_cargo_tomls(self, tmp_path):
        # Workspace root: no [package], no [dependencies], just members list.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [workspace]
            members = ["crate-a", "crate-b"]
            """,
        )
        self._write(
            tmp_path / "crate-a" / "Cargo.toml",
            """\
            [package]
            name = "crate-a"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            """,
        )
        self._write(
            tmp_path / "crate-b" / "Cargo.toml",
            """\
            [package]
            name = "crate-b"
            version = "0.1.0"

            [dependencies]
            tokio = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"serde", "tokio"}

    def test_workspace_internal_refs_filtered(self, tmp_path):
        # `crate-b` declares `crate-a` as a version-bare dep (rather than a
        # path dep). Local-name filter must drop it so we don't try to
        # resolve a non-published crate from crates.io.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [workspace]
            members = ["crate-a", "crate-b"]
            """,
        )
        self._write(
            tmp_path / "crate-a" / "Cargo.toml",
            """\
            [package]
            name = "crate-a"
            version = "0.1.0"
            """,
        )
        self._write(
            tmp_path / "crate-b" / "Cargo.toml",
            """\
            [package]
            name = "crate-b"
            version = "0.1.0"

            [dependencies]
            crate-a = "0.1.0"
            tokio = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"tokio"}
        assert "crate-a" not in names

    def test_walk_skips_examples_dir(self, tmp_path):
        # `examples/<sample>/Cargo.toml` are demo sub-projects, not part of
        # the audited project's dep tree. Common pattern in large Rust
        # projects — they must not pollute the main scan.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [package]
            name = "real"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            """,
        )
        self._write(
            tmp_path / "examples" / "demo" / "Cargo.toml",
            """\
            [package]
            name = "demo"
            version = "0.0.0"

            [dependencies]
            should-not-appear = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"serde"}

    def test_walk_skips_target_and_vendor(self, tmp_path):
        # `target/` is Cargo's build output; `vendor/` is `cargo vendor`'s
        # checkout of all deps. Both contain real Cargo.toml files we must
        # not treat as project source.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [package]
            name = "real-crate"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            """,
        )
        self._write(
            tmp_path / "target" / "debug" / "build" / "foo-abc" / "Cargo.toml",
            """\
            [package]
            name = "build-artifact"
            version = "0.0.0"

            [dependencies]
            should-not-appear = "1.0"
            """,
        )
        self._write(
            tmp_path / "vendor" / "vendored-dep" / "Cargo.toml",
            """\
            [package]
            name = "vendored-dep"
            version = "1.0.0"

            [dependencies]
            also-should-not-appear = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"serde"}

    def test_malformed_cargo_toml_does_not_abort_walk(self, tmp_path):
        # Bad TOML in one crate must not prevent discovery of the others.
        self._write(tmp_path / "broken" / "Cargo.toml", "this [is = not toml")
        self._write(
            tmp_path / "good" / "Cargo.toml",
            """\
            [package]
            name = "good"
            version = "0.1.0"

            [dependencies]
            anyhow = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"anyhow"}

    def test_license_detection_walks_members(self, tmp_path):
        # Root has no [package], so no license — must fall through to the
        # first member with a license declared.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [workspace]
            members = ["crate-a"]
            """,
        )
        self._write(
            tmp_path / "crate-a" / "Cargo.toml",
            """\
            [package]
            name = "crate-a"
            version = "0.1.0"
            license = "Apache-2.0"
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == "Apache-2.0"

    def test_oserror_on_walk_returns_empty(self, tmp_path):
        with patch("licenseal.discovery._walk.os.walk", side_effect=OSError("denied")):
            assert walk_project_files(tmp_path, "Cargo.toml") == []

    def test_permission_error_during_walk_returns_empty(self, tmp_path):
        class BrokenWalk:
            def __iter__(self):
                return self

            def __next__(self):
                raise PermissionError("denied")

        with patch("licenseal.discovery._walk.os.walk", return_value=BrokenWalk()):
            assert walk_project_files(tmp_path, "Cargo.toml") == []

    def test_license_detection_skips_malformed_toml(self, tmp_path):
        # First-found file is broken TOML; license-detection walk must skip
        # past it and try the next one rather than crash.
        self._write(tmp_path / "Cargo.toml", "[package] this = not [ valid")
        self._write(
            tmp_path / "sub" / "Cargo.toml",
            """\
            [package]
            name = "sub"
            version = "0.1.0"
            license = "Apache-2.0"
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == "Apache-2.0"

    def test_workspace_package_license_inheritance(self, tmp_path):
        # Cargo workspaces frequently declare the license once under
        # [workspace.package].license at the root, with member crates using
        # `license.workspace = true` to inherit. licenseal must read the
        # workspace declaration as the project license. Common pattern in
        # large multi-crate Rust projects.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [workspace]
            members = ["crate-a"]

            [workspace.package]
            license = "MIT"
            """,
        )
        self._write(
            tmp_path / "crate-a" / "Cargo.toml",
            """\
            [package]
            name = "crate-a"
            license.workspace = true
            version = "0.1.0"
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == "MIT"

    def test_workspace_package_without_license_falls_through(self, tmp_path):
        # `[workspace.package]` exists but has no `license` field — must
        # fall through to subsequent member crates rather than return early.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [workspace]
            members = ["crate-a"]

            [workspace.package]
            version = "0.1.0"
            """,
        )
        self._write(
            tmp_path / "crate-a" / "Cargo.toml",
            """\
            [package]
            name = "crate-a"
            version = "0.1.0"
            license = "Apache-2.0"
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path) == "Apache-2.0"

    def test_local_names_ignores_package_without_name(self, tmp_path):
        # A `[package]` table with no `name` field (rare but valid TOML) must
        # be tolerated by the workspace-local name collection rather than
        # erroring — discovery still resolves the real deps.
        self._write(
            tmp_path / "Cargo.toml",
            """\
            [package]
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            """,
        )
        self._write(
            tmp_path / "real" / "Cargo.toml",
            """\
            [package]
            name = "real-crate"
            version = "0.1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"serde"}
