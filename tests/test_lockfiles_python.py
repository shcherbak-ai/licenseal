"""Tests for Python lockfile parsers (uv.lock, poetry.lock)."""

from __future__ import annotations

import textwrap

import pytest

from licenseal.discovery.python.lockfiles import (
    find_python_lockfiles,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_python_lockfile,
    parse_uv_lock,
)
from licenseal.models import DependencyGroup, Ecosystem


class TestFindPythonLockfiles:
    """Tree-wide Python lockfile discovery — polyglot setups often nest a
    Python lockfile under a service subdir (e.g. ``ml/uv.lock``) next to
    JS/Rust code."""

    def test_returns_empty_when_no_lockfile(self, tmp_path):
        assert find_python_lockfiles(tmp_path) == []

    def test_returns_root_plus_nested(self, tmp_path):
        (tmp_path / "uv.lock").write_text("version = 1\n")
        (tmp_path / "ml").mkdir()
        (tmp_path / "ml" / "uv.lock").write_text("version = 1\n")
        found = {p.relative_to(tmp_path).as_posix() for p in find_python_lockfiles(tmp_path)}
        assert found == {"uv.lock", "ml/uv.lock"}

    def test_priority_within_single_dir(self, tmp_path):
        # uv.lock wins over poetry.lock in the same directory.
        (tmp_path / "uv.lock").write_text("version = 1\n")
        (tmp_path / "poetry.lock").write_text("")
        found = find_python_lockfiles(tmp_path)
        assert [p.name for p in found] == ["uv.lock"]


class TestParseUvLock:
    def _write(self, tmp_path, content):
        path = tmp_path / "uv.lock"
        path.write_text(textwrap.dedent(content))
        return path

    def test_parses_simple_lock(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            dependencies = [
                { name = "requests" },
            ]

            [[package]]
            name = "requests"
            version = "2.31.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name: d for d in deps}
        assert names["click"].version_constraint == "==8.3.3"
        assert names["click"].depth == 0
        assert names["click"].is_transitive is False
        assert names["requests"].depth == 1
        assert names["requests"].is_transitive is True

    def test_pep503_separator_divergent_edge_connects(self, tmp_path):
        # PEP 503 folds runs of -_. and lowercases, so "my.pkg" / "my_pkg" /
        # "my-pkg" are one distribution. A parent that spells a child's name
        # with a different separator than the package node must still connect
        # the edge. Plain .lower() left the child unreachable → orphan-dropped;
        # canonicalize_name reconnects it.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "app"
            version = "1.0.0"
            dependencies = [
                { name = "my.pkg" },
            ]

            [[package]]
            name = "my_pkg"
            version = "2.0.0"
            """,
        )
        deps = parse_uv_lock(path, prod_root_names={"app"}, dev_root_names=set(), include_dev=False)
        names = {d.name: d for d in deps}
        assert "my_pkg" in names  # was orphan-dropped before the PEP 503 fix
        assert names["my_pkg"].depth == 1
        assert names["my_pkg"].group == DependencyGroup.PROD
        assert names["my_pkg"].direct_ancestors == ("app",)

    def test_pep503_root_name_separator_divergence_matches(self, tmp_path):
        # Direct-dep root names come from the manifest (e.g. "zope-interface");
        # the lock may spell the same distribution "zope.interface". PEP 503
        # canonicalization makes the root match so it's depth-0, not dropped.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "zope.interface"
            version = "6.1.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"zope-interface"}, dev_root_names=set(), include_dev=False
        )
        names = {d.name: d for d in deps}
        assert "zope.interface" in names
        assert names["zope.interface"].depth == 0

    def test_dedupes_same_name_version(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"

            [[package]]
            name = "click"
            version = "8.3.3"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert len(deps) == 1

    def test_skips_non_table_entries(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            """,
        )
        # This should parse cleanly even though we don't have malformed entries.
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert len(deps) == 1

    def test_handles_empty_or_missing_packages(self, tmp_path):
        path = self._write(tmp_path, "version = 1\n")
        assert (
            parse_uv_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_non_list_packages_field(self, tmp_path):
        # Manually craft TOML where 'package' isn't an array.
        path = tmp_path / "uv.lock"
        path.write_text("version = 1\npackage = 'oops'\n")
        assert (
            parse_uv_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_skips_non_table_entries_in_array(self, tmp_path):
        path = tmp_path / "uv.lock"
        path.write_text("version = 1\npackage = [42, 'oops']\n")
        assert (
            parse_uv_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_skips_entries_missing_name_or_version(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            version = "1.0.0"

            [[package]]
            name = "click"

            [[package]]
            name = "valid"
            version = "2.0.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_skips_editable_workspace_root(self, tmp_path):
        # uv.lock includes the project itself with `source = { editable = "." }`.
        # That entry is the project being scanned, not an external dep.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "myproject"
            version = "1.0.0"
            source = { editable = "." }

            [[package]]
            name = "click"
            version = "8.3.3"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["click"]

    def test_skips_virtual_workspace_member(self, tmp_path):
        # uv workspaces use `source = { virtual = true }` for sub-packages.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "submodule"
            version = "1.0.0"
            source = { virtual = true }

            [[package]]
            name = "click"
            version = "8.3.3"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["click"]

    def test_populates_direct_ancestors_from_uv_dependencies(self, tmp_path):
        # httpx -> httpcore -> certifi. Expect certifi to attribute to httpx.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "httpx"
            version = "0.28.1"
            dependencies = [
                { name = "httpcore" },
            ]

            [[package]]
            name = "httpcore"
            version = "1.0.9"
            dependencies = [
                { name = "certifi" },
            ]

            [[package]]
            name = "certifi"
            version = "2026.4.22"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"httpx"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["httpx"].direct_ancestors == ()
        assert by_name["httpcore"].direct_ancestors == ("httpx",)
        assert by_name["certifi"].direct_ancestors == ("httpx",)

    def test_handles_malformed_dependencies_field(self, tmp_path):
        # `dependencies = "oops"` (string instead of array) — must not crash.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            dependencies = "oops"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["click"]

    def test_skips_malformed_dependency_entries(self, tmp_path):
        # Non-dict entries in the dependencies array are skipped; entries
        # whose `name` isn't a string are also ignored.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            dependencies = [
                "oops",
                { name = 42 },
                { name = "real-dep" },
            ]

            [[package]]
            name = "real-dep"
            version = "1.0.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["real-dep"].direct_ancestors == ("click",)

    def test_drops_orphan_packages_not_reachable_from_any_root(self, tmp_path):
        # `lonely` is in the lockfile but no root reaches it — must be dropped.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"

            [[package]]
            name = "lonely"
            version = "1.0.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert {d.name for d in deps} == {"click"}

    def test_dev_dep_dropped_without_include_dev(self, tmp_path):
        # `pytest` is a dev root; without include_dev, it's dropped.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"

            [[package]]
            name = "pytest"
            version = "8.0.0"
            """,
        )
        deps = parse_uv_lock(
            path,
            prod_root_names={"click"},
            dev_root_names={"pytest"},
            include_dev=False,
        )
        assert {d.name for d in deps} == {"click"}

    def test_dev_only_transitive_attributed_via_reachability(self, tmp_path):
        # `dev-only-shared` is reachable only from a dev root → DEV.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"

            [[package]]
            name = "pytest"
            version = "8.0.0"
            dependencies = [
                { name = "dev-only-shared" },
            ]

            [[package]]
            name = "dev-only-shared"
            version = "1.0.0"
            """,
        )
        deps = parse_uv_lock(
            path,
            prod_root_names={"click"},
            dev_root_names={"pytest"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["dev-only-shared"].group == DependencyGroup.DEV
        assert by_name["dev-only-shared"].direct_ancestors == ("pytest",)

    def test_prod_wins_when_reachable_from_both_groups(self, tmp_path):
        # `shared` is reachable from a prod root AND a dev root → PROD takes precedence.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            dependencies = [
                { name = "shared" },
            ]

            [[package]]
            name = "pytest"
            version = "8.0.0"
            dependencies = [
                { name = "shared" },
            ]

            [[package]]
            name = "shared"
            version = "1.0.0"
            """,
        )
        deps = parse_uv_lock(
            path,
            prod_root_names={"click"},
            dev_root_names={"pytest"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["shared"].group == DependencyGroup.PROD

    def test_root_not_present_in_lockfile_is_ignored(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "click"
            version = "8.3.3"
            """,
        )
        deps = parse_uv_lock(
            path,
            prod_root_names={"click", "absent-prod"},
            dev_root_names={"absent-dev"},
            include_dev=True,
        )
        assert {d.name for d in deps} == {"click"}

    def test_populates_direct_ancestors_with_multiple_roots(self, tmp_path):
        # Two roots converging on one transitive.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "a"
            version = "1.0.0"
            dependencies = [
                { name = "shared" },
            ]

            [[package]]
            name = "b"
            version = "1.0.0"
            dependencies = [
                { name = "shared" },
            ]

            [[package]]
            name = "shared"
            version = "2.0.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"a", "b"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["shared"].direct_ancestors == ("a", "b")

    def test_malformed_toml_returns_empty_without_crashing(self, tmp_path):
        # Real-world case: another tool's UV-parser test fixture ships a
        # ``testdata/broken-lock/uv.lock`` that's literally one byte (``!``).
        # licenseal's walker picks it up by name; the parser must skip it
        # without crashing the whole scan with TOMLDecodeError.
        path = tmp_path / "uv.lock"
        path.write_text("!", encoding="utf-8")
        deps = parse_uv_lock(
            path,
            prod_root_names=set(),
            dev_root_names=set(),
            include_dev=True,
        )
        assert deps == []

    def test_follows_extras_requested_by_the_project(self, tmp_path):
        # The project asks for `django[argon2]`; argon2-cffi lives only in
        # django's [package.optional-dependencies] table. Its whole subtree
        # must be attributed to django instead of dropped as orphans.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "myproject"
            version = "0.1.0"
            source = { virtual = "." }
            dependencies = [
                { name = "django", extra = ["argon2"] },
            ]

            [[package]]
            name = "django"
            version = "6.1.1"
            dependencies = [
                { name = "asgiref" },
            ]

            [package.optional-dependencies]
            argon2 = [
                { name = "argon2-cffi" },
            ]
            bcrypt = [
                { name = "bcrypt" },
            ]

            [[package]]
            name = "asgiref"
            version = "3.12.1"

            [[package]]
            name = "argon2-cffi"
            version = "25.1.0"
            dependencies = [
                { name = "cffi" },
            ]

            [[package]]
            name = "cffi"
            version = "2.1.1"

            [[package]]
            name = "bcrypt"
            version = "5.0.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"django"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert set(by_name) == {"django", "asgiref", "argon2-cffi", "cffi"}
        for name in ("argon2-cffi", "cffi"):
            assert by_name[name].group == DependencyGroup.PROD
            assert by_name[name].direct_ancestors == ("django",)
        # bcrypt is behind an extra nobody requested: not installed.
        assert "bcrypt" not in by_name

    def test_follows_extras_requested_by_transitive_packages(self, tmp_path):
        # Extras requested deeper in the graph count too, and an extra's
        # optional dependencies can request further extras of their own.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "app"
            version = "1.0.0"
            dependencies = [
                { name = "client", extra = ["http2"] },
                { name = "helper" },
            ]

            [[package]]
            name = "helper"
            version = "1.0.0"
            dependencies = [
                { name = "client", extra = ["http2"] },
            ]

            [[package]]
            name = "client"
            version = "1.0.0"

            [package.optional-dependencies]
            http2 = [
                { name = "codec", extra = ["fast"] },
            ]

            [[package]]
            name = "codec"
            version = "1.0.0"

            [package.optional-dependencies]
            fast = [
                { name = "accelerator" },
            ]

            [[package]]
            name = "accelerator"
            version = "1.0.0"
            """,
        )
        deps = parse_uv_lock(path, prod_root_names={"app"}, dev_root_names=set(), include_dev=False)
        by_name = {d.name: d for d in deps}
        assert set(by_name) == {"app", "helper", "client", "codec", "accelerator"}
        assert by_name["accelerator"].direct_ancestors == ("app",)

    @pytest.mark.parametrize(
        "source",
        [
            '{ editable = "." }',
            # A non-package project (`tool.uv.package = false`): uv records
            # `virtual` as a path, and the entry must still count as the
            # project, or the extras its dependency groups request are missed.
            '{ virtual = "." }',
        ],
    )
    def test_extras_requested_by_a_dependency_group_stay_dev(self, tmp_path, source):
        # A project's dependency groups are recorded under
        # [package.dev-dependencies]; extras requested there only install
        # dev-side packages.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "myproject"
            version = "0.1.0"
            source = SOURCE

            [package.dev-dependencies]
            dev = [
                { name = "server", extra = ["standard"] },
            ]

            [[package]]
            name = "server"
            version = "1.0.0"

            [package.optional-dependencies]
            standard = [
                { name = "reloader" },
            ]

            [[package]]
            name = "reloader"
            version = "1.0.0"
            """.replace("SOURCE", source),
        )
        with_dev = parse_uv_lock(
            path, prod_root_names=set(), dev_root_names={"server"}, include_dev=True
        )
        by_name = {d.name: d for d in with_dev}
        assert by_name["reloader"].group == DependencyGroup.DEV
        assert by_name["reloader"].direct_ancestors == ("server",)
        without_dev = parse_uv_lock(
            path, prod_root_names=set(), dev_root_names={"server"}, include_dev=False
        )
        assert without_dev == []

    @pytest.mark.parametrize("source", ['{ editable = "." }', '{ virtual = "." }'])
    def test_follows_extras_requested_in_the_projects_own_extras(self, tmp_path, source):
        # `[project.optional-dependencies] server = ["server[standard]"]` is
        # recorded in the project entry's [package.optional-dependencies];
        # the extra it requests must be followed like any other.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "myproject"
            version = "0.1.0"
            source = SOURCE

            [package.optional-dependencies]
            server = [
                { name = "server", extra = ["standard"] },
            ]

            [[package]]
            name = "server"
            version = "1.0.0"

            [package.optional-dependencies]
            standard = [
                { name = "reloader" },
            ]

            [[package]]
            name = "reloader"
            version = "1.0.0"
            """.replace("SOURCE", source),
        )
        deps = parse_uv_lock(
            path, prod_root_names={"server"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert set(by_name) == {"server", "reloader"}
        assert by_name["reloader"].direct_ancestors == ("server",)

    def test_ignores_malformed_extras(self, tmp_path):
        # Non-list `extra` values, non-string extra names and non-table
        # optional-dependencies are skipped rather than crashing the scan.
        path = self._write(
            tmp_path,
            """\
            version = 1

            [[package]]
            name = "myproject"
            version = "0.1.0"
            source = { editable = "." }
            optional-dependencies = "not-a-table"
            dependencies = [
                { name = "a", extra = "not-a-list" },
                { name = "b", extra = [1, "real"] },
            ]

            [[package]]
            name = "a"
            version = "1.0.0"

            [[package]]
            name = "b"
            version = "1.0.0"

            [package.optional-dependencies]
            real = [
                { name = "c" },
            ]

            [[package]]
            name = "c"
            version = "1.0.0"
            """,
        )
        deps = parse_uv_lock(
            path, prod_root_names={"a", "b"}, dev_root_names=set(), include_dev=False
        )
        assert {d.name for d in deps} == {"a", "b", "c"}


class TestParsePoetryLock:
    def _write(self, tmp_path, content):
        path = tmp_path / "poetry.lock"
        path.write_text(textwrap.dedent(content))
        return path

    def test_parses_main_and_dev(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            [[package]]
            name = "click"
            version = "8.3.3"
            category = "main"

            [[package]]
            name = "pytest"
            version = "8.0.0"
            category = "dev"
            """,
        )
        prod = parse_poetry_lock(
            path, prod_root_names={"click"}, dev_root_names={"pytest"}, include_dev=False
        )
        assert {d.name for d in prod} == {"click"}

        all_deps = parse_poetry_lock(
            path, prod_root_names={"click"}, dev_root_names={"pytest"}, include_dev=True
        )
        groups = {d.name: d.group for d in all_deps}
        assert groups["click"] == DependencyGroup.PROD
        assert groups["pytest"] == DependencyGroup.DEV

    def test_dedupes_same_name_version(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            [[package]]
            name = "click"
            version = "8.3.3"
            category = "main"

            [[package]]
            name = "click"
            version = "8.3.3"
            category = "main"
            """,
        )
        deps = parse_poetry_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert len(deps) == 1

    def test_handles_missing_packages_field(self, tmp_path):
        path = self._write(tmp_path, "metadata = {python-versions = '>=3.10'}\n")
        assert (
            parse_poetry_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_non_list_packages_field(self, tmp_path):
        path = tmp_path / "poetry.lock"
        path.write_text("package = 'bad'\n")
        assert (
            parse_poetry_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_skips_non_table_entries_in_array(self, tmp_path):
        path = tmp_path / "poetry.lock"
        path.write_text("package = [42, 'oops']\n")
        assert (
            parse_poetry_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_skips_entries_missing_name_or_version(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            [[package]]
            version = "1.0.0"
            category = "main"

            [[package]]
            name = "click"
            category = "main"

            [[package]]
            name = "valid"
            version = "2.0.0"
            category = "main"
            """,
        )
        deps = parse_poetry_lock(
            path, prod_root_names={"valid"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_handles_malformed_dependencies_field(self, tmp_path):
        # `dependencies = "oops"` (string instead of table) — must not crash.
        path = self._write(
            tmp_path,
            """\
            [[package]]
            name = "click"
            version = "8.3.3"
            category = "main"
            dependencies = "oops"
            """,
        )
        deps = parse_poetry_lock(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["click"]

    def test_drops_orphans_and_dev_when_not_included(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            [[package]]
            name = "click"
            version = "8.3.3"
            category = "main"

            [[package]]
            name = "pytest"
            version = "8.0.0"
            category = "dev"

            [[package]]
            name = "lonely"
            version = "9.0.0"
            category = "main"
            """,
        )
        deps = parse_poetry_lock(
            path,
            prod_root_names={"click"},
            dev_root_names={"pytest"},
            include_dev=False,
        )
        assert {d.name for d in deps} == {"click"}

    def test_populates_direct_ancestors_from_dependencies_table(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            [[package]]
            name = "httpx"
            version = "0.28.1"
            category = "main"
            [package.dependencies]
            httpcore = ">=1.0"

            [[package]]
            name = "httpcore"
            version = "1.0.9"
            category = "main"
            [package.dependencies]
            certifi = "*"

            [[package]]
            name = "certifi"
            version = "2026.4.22"
            category = "main"
            """,
        )
        deps = parse_poetry_lock(
            path, prod_root_names={"httpx"}, dev_root_names=set(), include_dev=False
        )
        by_name = {d.name: d for d in deps}
        assert by_name["httpx"].direct_ancestors == ()
        assert by_name["httpcore"].direct_ancestors == ("httpx",)
        assert by_name["certifi"].direct_ancestors == ("httpx",)


class TestParsePythonLockfileDispatch:
    def test_dispatches_to_uv(self, tmp_path):
        path = tmp_path / "uv.lock"
        path.write_text(
            textwrap.dedent(
                """\
                version = 1
                [[package]]
                name = "click"
                version = "8.3.3"
                """
            )
        )
        deps = parse_python_lockfile(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].ecosystem == Ecosystem.PYTHON

    def test_dispatches_to_poetry(self, tmp_path):
        path = tmp_path / "poetry.lock"
        path.write_text(
            textwrap.dedent(
                """\
                [[package]]
                name = "click"
                version = "8.3.3"
                category = "main"
                """
            )
        )
        deps = parse_python_lockfile(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "click"

    def test_dispatches_to_pipfile(self, tmp_path):
        path = tmp_path / "Pipfile.lock"
        path.write_text('{"default": {"click": {"version": "==8.3.3"}}, "develop": {}}')
        deps = parse_python_lockfile(
            path, prod_root_names={"click"}, dev_root_names=set(), include_dev=False
        )
        assert deps[0].name == "click"
        assert deps[0].version_constraint == "==8.3.3"

    def test_unsupported_filename_raises(self, tmp_path):
        path = tmp_path / "requirements.lock"
        path.write_text("{}")
        with pytest.raises(ValueError, match="Unsupported"):
            parse_python_lockfile(
                path, prod_root_names=set(), dev_root_names=set(), include_dev=False
            )


class TestParsePipfileLock:
    def _write(self, tmp_path, content):
        path = tmp_path / "Pipfile.lock"
        path.write_text(textwrap.dedent(content))
        return path

    def test_parses_default_and_develop(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            {
                "_meta": {"hash": {"sha256": "abc"}},
                "default": {
                    "click": {"version": "==8.3.3", "hashes": ["sha256:..."]},
                    "requests": {"version": "==2.31.0"}
                },
                "develop": {
                    "pytest": {"version": "==8.0.0"}
                }
            }
            """,
        )
        deps = parse_pipfile_lock(
            path,
            prod_root_names={"click"},
            dev_root_names={"pytest"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["click"].group == DependencyGroup.PROD
        assert by_name["click"].depth == 0  # named in prod_root_names → direct
        assert by_name["click"].version_constraint == "==8.3.3"
        # requests is in `default` but not a declared root → transitive.
        assert by_name["requests"].group == DependencyGroup.PROD
        assert by_name["requests"].depth == 1
        assert by_name["requests"].direct_ancestors == ()
        assert by_name["pytest"].group == DependencyGroup.DEV
        assert by_name["pytest"].depth == 0

    def test_no_include_dev_drops_develop_section(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            {
                "default": {"click": {"version": "==8.3.3"}},
                "develop": {"pytest": {"version": "==8.0.0"}}
            }
            """,
        )
        deps = parse_pipfile_lock(
            path,
            prod_root_names={"click"},
            dev_root_names={"pytest"},
            include_dev=False,
        )
        assert {d.name for d in deps} == {"click"}

    def test_skips_git_path_file_sources(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            {
                "default": {
                    "git-dep": {"git": "https://example.com/repo.git", "ref": "abc"},
                    "path-dep": {"path": "./local"},
                    "file-dep": {"file": "./dist/pkg.tar.gz"},
                    "real": {"version": "==1.0.0"}
                }
            }
            """,
        )
        deps = parse_pipfile_lock(
            path, prod_root_names={"real"}, dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["real"]

    def test_skips_entries_missing_version(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            {
                "default": {
                    "no-version": {"hashes": ["sha256:..."]},
                    "empty-version": {"version": ""},
                    "non-string-version": {"version": 42},
                    "valid": {"version": "==1.0.0"}
                }
            }
            """,
        )
        deps = parse_pipfile_lock(
            path, prod_root_names=set(), dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["valid"]

    def test_skips_non_dict_entry_values(self, tmp_path):
        path = self._write(
            tmp_path,
            """\
            {
                "default": {
                    "bad": "oops",
                    "good": {"version": "==1.0.0"}
                }
            }
            """,
        )
        deps = parse_pipfile_lock(
            path, prod_root_names=set(), dev_root_names=set(), include_dev=False
        )
        assert [d.name for d in deps] == ["good"]

    def test_handles_non_dict_section_value(self, tmp_path):
        # If `default` somehow isn't a dict (malformed lockfile), skip cleanly.
        path = self._write(tmp_path, '{"default": "oops", "develop": {}}')
        assert (
            parse_pipfile_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_empty_lockfile(self, tmp_path):
        path = self._write(tmp_path, "{}")
        assert (
            parse_pipfile_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_malformed_json(self, tmp_path):
        path = self._write(tmp_path, "{not valid json")
        assert (
            parse_pipfile_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_handles_non_object_root(self, tmp_path):
        path = self._write(tmp_path, "[1, 2, 3]")
        assert (
            parse_pipfile_lock(path, prod_root_names=set(), dev_root_names=set(), include_dev=False)
            == []
        )

    def test_dev_root_marks_depth_zero(self, tmp_path):
        # A name in dev_root_names but living in `develop` is depth=0 DEV.
        path = self._write(
            tmp_path,
            """\
            {
                "default": {},
                "develop": {
                    "pytest": {"version": "==8.0.0"},
                    "iniconfig": {"version": "==2.0.0"}
                }
            }
            """,
        )
        deps = parse_pipfile_lock(
            path,
            prod_root_names=set(),
            dev_root_names={"pytest"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["pytest"].depth == 0
        assert by_name["iniconfig"].depth == 1
        assert by_name["iniconfig"].group == DependencyGroup.DEV
