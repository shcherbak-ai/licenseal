"""Tests for Rust manifest discovery (Cargo.toml)."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from licenseal.discovery import ProjectLicense, detect_project_license
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.rust.cargo_toml import (
    cargo_sources,
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

    def test_path_and_git_deps_carry_an_origin(self, tmp_path):
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
        assert {d.name: d.origin for d in deps} == {
            "local-crate": "../local-crate",
            "git-crate": "git+https://github.com/x/y",
            "registry-crate": "",
        }

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

    def test_workspace_dependencies_referenced_by_member(self, tmp_path):
        # [workspace.dependencies] is a version catalog: an entry becomes a
        # dependency when a member opts in with `dep = { workspace = true }`,
        # carrying the catalog's version.
        _write(
            tmp_path,
            """\
            [workspace]
            members = ["crate-a"]

            [workspace.dependencies]
            shared-lib = "1.0"
            """,
        )
        member = tmp_path / "crate-a" / "Cargo.toml"
        member.parent.mkdir()
        member.write_text(
            textwrap.dedent(
                """\
                [package]
                name = "crate-a"
                version = "0.1.0"

                [dependencies]
                shared-lib = { workspace = true }
                """
            )
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"shared-lib"}
        assert deps[0].group == DependencyGroup.PROD
        assert deps[0].version_constraint == "1.0"
        assert deps[0].source == "Cargo.toml"  # the catalog declares the version

    def test_unreferenced_workspace_dependencies_dropped(self, tmp_path):
        # Catalog entries no member references are inert declarations — they
        # are typically absent from Cargo.lock, and emitting them sends the
        # transitive resolver on a registry walk of a tree the project never
        # builds (observed on a large Rust workspace: hundreds of phantom
        # crates, including spurious GPL violations).
        _write(
            tmp_path,
            """\
            [workspace]
            members = ["crate-a"]

            [workspace.dependencies]
            used-lib = "1.0"
            unused-lib = "2.0"
            """,
        )
        member = tmp_path / "crate-a" / "Cargo.toml"
        member.parent.mkdir()
        member.write_text(
            textwrap.dedent(
                """\
                [package]
                name = "crate-a"
                version = "0.1.0"

                [dependencies]
                used-lib = { workspace = true }
                """
            )
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"used-lib"}

    def test_workspace_dep_referenced_only_from_dev_table_is_dev(self, tmp_path):
        _write(
            tmp_path,
            """\
            [workspace]
            members = ["crate-a", "crate-b"]

            [workspace.dependencies]
            test-helper = "0.5"
            both-lib = "1.0"
            """,
        )
        for crate, body in (
            ("crate-a", "[dev-dependencies]\ntest-helper = { workspace = true }\n"),
            (
                "crate-b",
                "[dependencies]\nboth-lib = { workspace = true }\n"
                "[dev-dependencies]\nboth-lib = { workspace = true }\n",
            ),
        ):
            member = tmp_path / crate / "Cargo.toml"
            member.parent.mkdir()
            member.write_text(f'[package]\nname = "{crate}"\nversion = "0.1.0"\n{body}')
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        groups = {d.name: d.group for d in deps}
        assert groups["test-helper"] == DependencyGroup.DEV
        # Referenced from a prod table anywhere → PROD wins.
        assert groups["both-lib"] == DependencyGroup.PROD

    def test_workspace_catalog_rename_uses_canonical_name(self, tmp_path):
        _write(
            tmp_path,
            """\
            [workspace]
            members = ["crate-a"]

            [workspace.dependencies]
            local-alias = { package = "real-crate", version = "0.4" }
            path-entry = { path = "../local" }
            """,
        )
        member = tmp_path / "crate-a" / "Cargo.toml"
        member.parent.mkdir()
        member.write_text(
            textwrap.dedent(
                """\
                [package]
                name = "crate-a"
                version = "0.1.0"

                [dependencies]
                local-alias = { workspace = true }
                path-entry = { workspace = true }
                """
            )
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        # The alias resolves to the published crate name; the path catalog
        # entry points outside the scanned directory and carries its origin.
        assert {d.name: d.origin for d in deps} == {"real-crate": "", "path-entry": "../local"}

    def test_workspace_ref_without_catalog_entry_dropped(self, tmp_path):
        # A `workspace = true` ref with no matching catalog entry (broken
        # manifest — cargo itself would error) has no version to resolve.
        _write(
            tmp_path,
            """\
            [package]
            name = "standalone"
            version = "0.1.0"

            [dependencies]
            ghost = { workspace = true }
            serde = "1.0"
            """,
        )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"serde"}

    def test_workspace_ref_resolves_against_nearest_ancestor_catalog(self, tmp_path):
        # Two independent workspaces in one tree: each member's ref resolves
        # against its own workspace root, not a sibling's.
        for ws, version in (("ws-one", "1.0"), ("ws-two", "2.0")):
            root = tmp_path / ws / "Cargo.toml"
            root.parent.mkdir()
            root.write_text(
                f'[workspace]\nmembers = ["m"]\n[workspace.dependencies]\nshared = "{version}"\n'
            )
            member = tmp_path / ws / "m" / "Cargo.toml"
            member.parent.mkdir()
            member.write_text(
                f'[package]\nname = "m-{ws}"\nversion = "0.1.0"\n'
                "[dependencies]\nshared = { workspace = true }\n"
            )
        deps, _ = discover_cargo_toml_dependencies(tmp_path)
        constraints = {d.source: d.version_constraint for d in deps if d.name == "shared"}
        assert constraints == {
            "ws-one/Cargo.toml": "1.0",
            "ws-two/Cargo.toml": "2.0",
        }

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


class TestCargoSources:
    """Dependencies declared with ``git`` or ``path``.

    One declared with ``git``, or with a ``path`` outside the scanned
    directory, is emitted with its origin. A ``path`` inside it is the
    project's own code: no dependency, and a root of the Cargo.lock graph
    when its own Cargo.toml is not scanned."""

    @staticmethod
    def _rows(project: Path) -> dict[str, tuple[str, str, DependencyGroup]]:
        deps, _ = discover_cargo_toml_dependencies(project)
        return {d.name: (d.version_constraint, d.origin, d.group) for d in deps}

    def test_no_cargo_toml(self, tmp_path):
        assert cargo_sources(tmp_path) == (set(), set(), {}, {})

    def test_git_and_path_dependencies_carry_an_origin(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        _write(
            project,
            """\
            [package]
            name = "myapp"

            [dependencies]
            Forked = { git = "https://tok3n@example.org/forked.git", rev = "abc123", tag = "v9" }
            by-tag = { git = "https://example.org/by-tag.git", tag = "v1.0" }
            by-branch = { git = "https://example.org/by-branch.git", branch = "main" }
            sibling = { path = "../sibling" }
            pinned-fork = { git = "https://example.org/pinned.git", version = "1.2" }
            registry-crate = { version = "1.0" }
            mirrored = { version = "2.0", registry = "internal" }
            no-version = { features = ["x"] }
            bad-git = { git = 7 }
            bad-path = { path = [] }

            [build-dependencies]
            build-fork = { git = "https://example.org/build.git" }

            [dev-dependencies]
            test-fork = { git = "https://example.org/test.git" }
            registry-dev = "2.0"

            [target.'cfg(unix)'.dependencies]
            unix-fork = { git = "https://example.org/unix.git" }

            [target.'cfg(windows)'.dev-dependencies]
            windows-test-fork = { path = "../windows-test" }
            """,
        )
        prod, dev = DependencyGroup.PROD, DependencyGroup.DEV
        assert self._rows(project) == {
            "Forked": ("", "git+https://example.org/forked.git@abc123", prod),
            "by-tag": ("", "git+https://example.org/by-tag.git@v1.0", prod),
            "by-branch": ("", "git+https://example.org/by-branch.git@main", prod),
            "sibling": ("", "../sibling", prod),
            # A version beside ``git`` does not make it a registry crate.
            "pinned-fork": ("", "git+https://example.org/pinned.git", prod),
            "registry-crate": ("1.0", "", prod),
            # Another registry is not an off-registry source.
            "mirrored": ("2.0", "", prod),
            "bad-git": ("", "unrecorded source", prod),
            "bad-path": ("", "unrecorded source", prod),
            "build-fork": ("", "git+https://example.org/build.git", prod),
            "test-fork": ("", "git+https://example.org/test.git", dev),
            "registry-dev": ("2.0", "", dev),
            "unix-fork": ("", "git+https://example.org/unix.git", prod),
            "windows-test-fork": ("", "../windows-test", dev),
        }
        sources = cargo_sources(project)
        # None of them is inside the scanned directory, so none is a root
        # without a row. Names are lowercased, as the lockfile pass compares
        # them.
        assert (sources.prod_roots, sources.dev_roots, sources.patches) == (set(), set(), {})
        assert sources.origins["forked"] == "git+https://example.org/forked.git@abc123"
        assert sources.origins["sibling"] == "../sibling"
        assert "registry-crate" not in sources.origins

    def test_renamed_dependency_uses_the_package_name(self, tmp_path):
        # Cargo.lock records the package name, not the local alias.
        _write(
            tmp_path,
            """\
            [dependencies]
            alias = { git = "https://example.org/real.git", package = "real-crate" }
            """,
        )
        assert self._rows(tmp_path) == {
            "real-crate": ("", "git+https://example.org/real.git", DependencyGroup.PROD)
        }

    def test_path_dependency_inside_the_scanned_directory_is_not_a_dependency(self, tmp_path):
        # ``core`` is scanned through its own Cargo.toml. ``vendored`` is in
        # the tree but under a directory the scan skips, so nothing declares
        # its dependencies: it is a root of the lockfile graph, with no row.
        project = tmp_path / "project"
        project.mkdir()
        _write(
            project,
            """\
            [package]
            name = "app"

            [dependencies]
            core = { path = "core" }
            vendored = { path = "vendor/vendored" }
            elsewhere = { path = "../elsewhere" }

            [dev-dependencies]
            dev-vendored = { path = "vendor/dev-vendored" }
            """,
        )
        (project / "core").mkdir()
        (project / "core" / "Cargo.toml").write_text(
            '[package]\nname = "core"\n\n[dependencies]\ncore-dep = "1.0"\n'
        )
        assert self._rows(project) == {
            "elsewhere": ("", "../elsewhere", DependencyGroup.PROD),
            "core-dep": ("1.0", "", DependencyGroup.PROD),
        }
        sources = cargo_sources(project)
        assert (sources.prod_roots, sources.dev_roots) == ({"vendored"}, {"dev-vendored"})
        assert sources.origins == {"elsewhere": "../elsewhere"}

    def test_workspace_catalog_entries_referenced_by_a_member(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        _write(
            project,
            """\
            [workspace]
            members = ["crates/member"]

            [workspace.dependencies]
            forked = { git = "https://example.org/forked.git" }
            test-fork = { git = "https://example.org/test.git" }
            renamed = { git = "https://example.org/real.git", package = "real-crate" }
            unused-fork = { git = "https://example.org/unused.git" }
            shared = { path = "../shared" }
            inner = { path = "vendor/inner" }
            no-source = { features = ["x"] }
            serde = "1.0"
            """,
        )
        (project / "crates" / "member").mkdir(parents=True)
        (project / "crates" / "member" / "Cargo.toml").write_text(
            textwrap.dedent("""\
                [package]
                name = "member"

                [dependencies]
                forked = { workspace = true }
                renamed = { workspace = true }
                shared = { workspace = true }
                inner = { workspace = true }
                no-source = { workspace = true }
                serde = { workspace = true }

                [dev-dependencies]
                test-fork = { workspace = true }
            """)
        )
        prod, dev = DependencyGroup.PROD, DependencyGroup.DEV
        # A catalog entry no member references is inert, as for registry
        # entries; one that is neither git nor path, and has no version, is
        # not a dependency. A catalog path is relative to the catalog.
        assert self._rows(project) == {
            "forked": ("", "git+https://example.org/forked.git", prod),
            "real-crate": ("", "git+https://example.org/real.git", prod),
            "shared": ("", "../shared", prod),
            "serde": ("1.0", "", prod),
            "test-fork": ("", "git+https://example.org/test.git", dev),
        }
        assert cargo_sources(project).prod_roots == {"inner"}

    def test_patch_and_replace_redirect_a_registry_dependency(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        _write(
            project,
            """\
            [package]
            name = "app"

            [dependencies]
            serde = "1.0"
            local-fix = "0.2"
            own-fix = "0.1"
            replaced = "0.3"
            also-replaced = "0.4"
            untouched = "2.0"
            already-git = { git = "https://example.org/already.git" }

            [patch.crates-io]
            serde = { git = "https://example.org/serde.git", branch = "fix" }
            local-fix = { path = "../local-fix" }
            own-fix = { path = "patches/own-fix" }
            already-git = { path = "../already" }
            alias = { git = "https://example.org/transitive.git", package = "transitive-only" }
            just-a-pin = { version = "=1.0.0" }

            [patch."https://example.org/other.git"]
            other = { path = "../other" }

            [replace]
            "replaced:0.3.0" = { git = "https://example.org/replaced.git", rev = "abc" }
            "https://example.org/index#also-replaced@0.4.0" = { path = "../also-replaced" }
            """,
        )
        prod = DependencyGroup.PROD
        assert self._rows(project) == {
            "serde": ("", "git+https://example.org/serde.git@fix", prod),
            "local-fix": ("", "../local-fix", prod),
            "replaced": ("", "git+https://example.org/replaced.git@abc", prod),
            "also-replaced": ("", "../also-replaced", prod),
            "untouched": ("2.0", "", prod),
            # A dependency's own source is not overridden by a patch.
            "already-git": ("", "git+https://example.org/already.git", prod),
        }
        sources = cargo_sources(project)
        # A crate patched to a path inside the tree is the project's own
        # code: no row, and a root of the lockfile graph.
        assert sources.prod_roots == {"own-fix"}
        assert sources.patches == {
            "serde": "git+https://example.org/serde.git@fix",
            "local-fix": "../local-fix",
            "own-fix": None,
            "already-git": "../already",
            "transitive-only": "git+https://example.org/transitive.git",
            "other": "../other",
            "replaced": "git+https://example.org/replaced.git@abc",
            "also-replaced": "../also-replaced",
        }
        # The declared git source is what the lockfile pass is told.
        assert sources.origins["already-git"] == "git+https://example.org/already.git"

    def test_exclude_paths_respected(self, tmp_path):
        (tmp_path / "skipped").mkdir()
        (tmp_path / "skipped" / "Cargo.toml").write_text(
            '[dependencies]\nforked = { git = "https://example.org/forked.git" }\n'
        )
        assert cargo_sources(tmp_path).origins == {"forked": "git+https://example.org/forked.git"}
        assert (
            cargo_sources(tmp_path, exclude_paths=frozenset({tmp_path / "skipped"})).origins == {}
        )


class TestDetectProjectLicenseCargoToml:
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
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == "MIT OR Apache-2.0"

    def test_returns_empty_when_no_license_field(self, tmp_path):
        _write(
            tmp_path,
            """\
            [package]
            name = "myapp"
            version = "0.1.0"
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == ""

    def test_returns_empty_when_no_package_table(self, tmp_path):
        _write(
            tmp_path,
            """\
            [workspace]
            members = ["a", "b"]
            """,
        )
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == ""

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
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == ""


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

    def test_license_detection_does_not_walk_members(self, tmp_path):
        # The workspace root declares no license. A member crate's license is
        # that crate's, not the workspace's.
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
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == ""
        assert detect_project_license(tmp_path) == ProjectLicense()
        # Scanned on its own, the member crate has its license.
        assert detect_project_license(tmp_path / "crate-a").license == "Apache-2.0"

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

    def test_license_detection_survives_malformed_toml(self, tmp_path):
        # The root file is broken TOML: it declares nothing, and detection
        # returns rather than crash.
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
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == ""
        assert detect_project_license(tmp_path) == ProjectLicense()

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
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == "MIT"

    def test_workspace_package_without_license_declares_nothing(self, tmp_path):
        # `[workspace.package]` exists but has no `license` field. The
        # workspace declares no license, whatever a member crate declares.
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
        assert detect_project_license_cargo_toml(tmp_path / "Cargo.toml") == ""
        assert detect_project_license(tmp_path) == ProjectLicense()

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
