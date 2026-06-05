"""Tests for the Rust lockfile parser (Cargo.lock)."""

from __future__ import annotations

import textwrap

from licenseal.discovery.rust.lockfiles import (
    find_rust_lockfiles,
    parse_cargo_lock,
)
from licenseal.models import DependencyGroup

_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def _write(tmp_path, content):
    path = tmp_path / "Cargo.lock"
    path.write_text(textwrap.dedent(content))
    return path


class TestFindRustLockfiles:
    """Tree-wide Cargo.lock discovery — polyglot setups often nest the Rust
    workspace under a subdir (e.g. ``tauri/src-tauri/Cargo.lock`` next to a
    JS root)."""

    def test_returns_empty_when_no_cargo_lock(self, tmp_path):
        assert find_rust_lockfiles(tmp_path) == []

    def test_returns_root_plus_nested(self, tmp_path):
        (tmp_path / "Cargo.lock").write_text("version = 3\n")
        (tmp_path / "tauri" / "src-tauri").mkdir(parents=True)
        (tmp_path / "tauri" / "src-tauri" / "Cargo.lock").write_text("version = 3\n")
        found = {p.relative_to(tmp_path).as_posix() for p in find_rust_lockfiles(tmp_path)}
        assert found == {"Cargo.lock", "tauri/src-tauri/Cargo.lock"}


class TestParseCargoLock:
    def test_parses_simple_lock(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"
            dependencies = [
                "serde_derive",
            ]

            [[package]]
            name = "serde_derive"
            version = "1.0.193"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"serde"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["serde"].depth == 0
        assert by_name["serde"].version_constraint == "==1.0.193"
        assert by_name["serde_derive"].depth == 1
        assert by_name["serde_derive"].direct_ancestors == ("serde",)

    def test_skips_local_crate_without_source(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "myapp"
            version = "0.1.0"
            dependencies = [
                "serde",
            ]

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"
            """,
        )
        # `myapp` has no `source` field → skipped (it's the local crate).
        # Only `serde` survives, and only if it's listed as a root.
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"serde"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["serde"]

    def test_skips_path_and_git_sources(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "git-dep"
            version = "0.1.0"
            source = "git+https://github.com/x/y#abc123"

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"serde"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["serde"]

    def test_dependencies_with_version_and_source_suffix(self, tmp_path):
        # Real Cargo.lock entries can be "name", "name 1.2.3", or
        # "name 1.2.3 (registry+...)". Only the leading name token matters
        # for edge attribution.
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "tokio"
            version = "1.35.1"
            source = "{_REGISTRY}"
            dependencies = [
                "bytes 1.5.0",
                "pin-project-lite 0.2.13 (registry+https://github.com/rust-lang/crates.io-index)",
            ]

            [[package]]
            name = "bytes"
            version = "1.5.0"
            source = "{_REGISTRY}"

            [[package]]
            name = "pin-project-lite"
            version = "0.2.13"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"tokio"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["bytes"].direct_ancestors == ("tokio",)
        assert by_name["pin-project-lite"].direct_ancestors == ("tokio",)

    def test_drops_orphans_not_reachable_from_any_root(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"

            [[package]]
            name = "lonely"
            version = "0.1.0"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"serde"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["serde"]

    def test_dev_attribution_via_dev_root(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "criterion"
            version = "0.5.0"
            source = "{_REGISTRY}"
            dependencies = [
                "plotters",
            ]

            [[package]]
            name = "plotters"
            version = "0.3.5"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path,
            prod_root_names=set(),
            dev_root_names={"criterion"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["criterion"].group == DependencyGroup.DEV
        assert by_name["plotters"].group == DependencyGroup.DEV
        assert by_name["plotters"].direct_ancestors == ("criterion",)

    def test_dev_dropped_without_include_dev(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "criterion"
            version = "0.5.0"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path,
            prod_root_names=set(),
            dev_root_names={"criterion"},
            include_dev=False,
        )
        assert deps == []

    def test_prod_wins_when_reachable_from_both_groups(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"
            dependencies = [
                "shared",
            ]

            [[package]]
            name = "criterion"
            version = "0.5.0"
            source = "{_REGISTRY}"
            dependencies = [
                "shared",
            ]

            [[package]]
            name = "shared"
            version = "1.0.0"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path,
            prod_root_names={"serde"},
            dev_root_names={"criterion"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["shared"].group == DependencyGroup.PROD

    def test_dedupes_same_name_version(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"serde"}, dev_root_names=set(), include_dev=False
        )
        assert len(deps) == 1

    def test_handles_non_list_packages_field(self, tmp_path):
        path = tmp_path / "Cargo.lock"
        path.write_text("version = 3\npackage = 'oops'\n")
        deps, known = parse_cargo_lock(
            path, prod_root_names=set(), dev_root_names=set(), include_dev=False
        )
        assert deps == []
        assert known == set()

    def test_skips_non_dict_package_entries(self, tmp_path):
        # Hand-craft TOML where `package` is a flat array containing non-table
        # entries. tomllib parses this; the parser must skip non-dicts.
        path = tmp_path / "Cargo.lock"
        path.write_text("version = 3\npackage = [42, 'oops']\n")
        deps, _ = parse_cargo_lock(
            path, prod_root_names=set(), dev_root_names=set(), include_dev=False
        )
        assert deps == []

    def test_skips_entries_missing_required_fields(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "no-version"
            source = "{_REGISTRY}"

            [[package]]
            source = "{_REGISTRY}"
            version = "1.0.0"

            [[package]]
            name = "valid"
            version = "1.0.0"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_skips_non_string_dependency_entries(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "x"
            version = "1.0.0"
            source = "{_REGISTRY}"
            dependencies = [
                42,
                "valid-child",
            ]

            [[package]]
            name = "valid-child"
            version = "2.0.0"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"x"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["valid-child"].direct_ancestors == ("x",)

    def test_handles_non_list_dependencies_field(self, tmp_path):
        # `dependencies = "oops"` (string, not array) — must not crash.
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "x"
            version = "1.0.0"
            source = "{_REGISTRY}"
            dependencies = "oops"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"x"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["x"]

    def test_root_not_present_in_lockfile_is_ignored(self, tmp_path):
        # Roots passed in but not present in lockfile name_case must be skipped
        # cleanly (covers the `if n in name_case` False branch in _attribute).
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "serde"
            version = "1.0.193"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path,
            prod_root_names={"serde", "absent-prod"},
            dev_root_names={"absent-dev"},
            include_dev=True,
        )
        assert {d.name for d in deps} == {"serde"}

    def test_skips_empty_child_name_token(self, tmp_path):
        path = _write(
            tmp_path,
            f"""\
            version = 3

            [[package]]
            name = "x"
            version = "1.0.0"
            source = "{_REGISTRY}"
            dependencies = [
                " ",
                "real",
            ]

            [[package]]
            name = "real"
            version = "1.0.0"
            source = "{_REGISTRY}"
            """,
        )
        deps, _ = parse_cargo_lock(
            path, prod_root_names={"x"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["real"].direct_ancestors == ("x",)

    def test_patch_crates_io_dep_passthrough(self, tmp_path):
        """[patch.crates-io] overrides land in Cargo.lock with a git/path
        source rather than the registry. The parser must:

        1. Exclude the patched dep itself from the output (no crates.io entry).
        2. Track its edges so the BFS reaches its lockfile-resolved
           children — those children ARE registry-sourced and need
           emitting with the patched dep as their direct ancestor.
        3. Surface the patched dep's name via the returned known-names set
           so the upstream walker doesn't treat it as uncovered and
           registry-walk the unpatched crates.io version (which would pull
           a different transitive set — the phantom-version bug seen on
           polars and brush before this fix).
        """
        path = _write(
            tmp_path,
            f"""
            version = 3

            [[package]]
            name = "patched-root"
            version = "1.0.0"
            source = "git+https://github.com/fork/patched-root?rev=abc#abc"
            dependencies = [
                "real-child 0.5.0 ({_REGISTRY})",
            ]

            [[package]]
            name = "real-child"
            version = "0.5.0"
            source = "{_REGISTRY}"
            """,
        )
        deps, known = parse_cargo_lock(
            path,
            prod_root_names={"patched-root"},
            dev_root_names=set(),
            include_dev=False,
        )
        names = {d.name for d in deps}
        assert "patched-root" not in names, (
            "git-sourced patched dep must not appear in output (no crates.io license)"
        )
        assert "real-child" in names, (
            "real-child should be reached via BFS through the patched dep's edges"
        )
        real_child = next(d for d in deps if d.name == "real-child")
        assert real_child.direct_ancestors == ("patched-root",)
        assert real_child.depth == 1
        assert real_child.group == DependencyGroup.PROD
        assert "patched-root" in known
        assert "real-child" in known
