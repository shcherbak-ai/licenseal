"""Tests for Go ``go.mod`` discovery."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.go.go_mod import (
    _is_test_fixture_go_mod,
    _module_for_tool_path,
    _parse_go_mod,
    discover_go_mod_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem


class TestParseGoMod:
    def test_basic_require_block(self):
        text = """
module example.com/myproject

go 1.22

require (
    github.com/foo/bar v1.2.3
    github.com/baz/qux v0.4.5
)
"""
        requires, replaces, tools = _parse_go_mod(text)
        assert ("github.com/foo/bar", "v1.2.3") in requires
        assert ("github.com/baz/qux", "v0.4.5") in requires
        assert replaces == {}
        assert tools == []

    def test_indirect_marker_does_not_drop_entry(self):
        # ``// indirect`` is a tooling annotation, NOT a dev marker. Discover.
        text = """
require (
    github.com/foo/bar v1.2.3
    github.com/baz/qux v0.4.5 // indirect
)
"""
        requires, _, _ = _parse_go_mod(text)
        names = {r[0] for r in requires}
        assert "github.com/foo/bar" in names
        assert "github.com/baz/qux" in names

    def test_single_line_require_without_block(self):
        text = "require github.com/single/dep v1.0.0\n"
        requires, _, _ = _parse_go_mod(text)
        assert requires == [("github.com/single/dep", "v1.0.0")]

    def test_replace_to_other_module(self):
        text = "replace github.com/old/path v1.0.0 => github.com/new/path v2.0.0\n"
        _, replaces, _ = _parse_go_mod(text)
        assert replaces == {"github.com/old/path": ("github.com/new/path", "v2.0.0")}

    def test_replace_to_local_path_yields_none(self):
        text = "replace github.com/local/dep => ../local-dir\n"
        _, replaces, _ = _parse_go_mod(text)
        assert replaces == {"github.com/local/dep": None}

    def test_exclude_directive_skipped(self):
        text = """
require github.com/foo v1.0.0
exclude github.com/bad/dep v9.9.9
"""
        requires, _, _ = _parse_go_mod(text)
        assert requires == [("github.com/foo", "v1.0.0")]

    def test_inline_comments_stripped(self):
        text = """
require (
    github.com/foo v1.0.0 // some non-indirect comment
)
"""
        requires, _, _ = _parse_go_mod(text)
        assert requires == [("github.com/foo", "v1.0.0")]

    def test_multiple_require_blocks(self):
        text = """
require (
    github.com/a v1.0.0
)

require (
    github.com/b v2.0.0
)
"""
        requires, _, _ = _parse_go_mod(text)
        assert ("github.com/a", "v1.0.0") in requires
        assert ("github.com/b", "v2.0.0") in requires

    def test_empty_input_yields_empty(self):
        requires, replaces, tools = _parse_go_mod("")
        assert requires == []
        assert replaces == {}
        assert tools == []

    def test_malformed_require_line_skipped(self):
        text = """
require (
    incomplete-line-no-version
    github.com/valid v1.0.0
)
"""
        requires, _, _ = _parse_go_mod(text)
        assert requires == [("github.com/valid", "v1.0.0")]

    def test_replace_block_malformed_skipped(self):
        text = """
replace garbage
require github.com/foo v1.0.0
"""
        requires, replaces, _ = _parse_go_mod(text)
        assert requires == [("github.com/foo", "v1.0.0")]
        assert replaces == {}

    def test_single_line_require_with_missing_version_skipped(self):
        text = "require github.com/incomplete\n"
        requires, _, _ = _parse_go_mod(text)
        assert requires == []


class TestParseGoModToolDirective:
    """Go 1.24+ ``tool`` directive — the only mechanism that distinguishes
    dev-time tooling deps from production deps in ``go.mod``.
    """

    def test_block_form_tool_directive(self):
        text = """
require (
    golang.org/x/tools v0.20.0
)

tool (
    golang.org/x/tools/cmd/stringer
    example.com/build/cmd/generator
)
"""
        _, _, tools = _parse_go_mod(text)
        assert "golang.org/x/tools/cmd/stringer" in tools
        assert "example.com/build/cmd/generator" in tools

    def test_single_line_tool_directive(self):
        text = "tool golang.org/x/tools/cmd/stringer\n"
        _, _, tools = _parse_go_mod(text)
        assert tools == ["golang.org/x/tools/cmd/stringer"]

    def test_empty_tool_block(self):
        text = "tool (\n)\n"
        _, _, tools = _parse_go_mod(text)
        assert tools == []

    def test_malformed_tool_block_line_skipped(self):
        # A blank or malformed line inside a ``tool ( ... )`` block shouldn't
        # crash or add a garbage entry. ``_TOOL_LINE_RE`` requires a single
        # non-whitespace token; multi-token lines don't match.
        text = """
tool (
    valid.tool/path/cmd/x
    two tokens
)
"""
        _, _, tools = _parse_go_mod(text)
        assert tools == ["valid.tool/path/cmd/x"]


class TestModuleForToolPath:
    """Match a tool import path to its require'd module via longest prefix."""

    def test_exact_match(self):
        assert (
            _module_for_tool_path("golang.org/x/tools", ["golang.org/x/tools"])
            == "golang.org/x/tools"
        )

    def test_subpath_matches_parent_module(self):
        assert (
            _module_for_tool_path(
                "golang.org/x/tools/cmd/stringer",
                ["golang.org/x/tools"],
            )
            == "golang.org/x/tools"
        )

    def test_longest_prefix_wins(self):
        # Two require'd modules; one is a sub-module of the other.
        assert (
            _module_for_tool_path(
                "example.com/a/b/cmd/tool",
                ["example.com/a", "example.com/a/b"],
            )
            == "example.com/a/b"
        )

    def test_no_match_returns_none(self):
        assert _module_for_tool_path("golang.org/x/tools", ["example.com/other"]) is None

    def test_prefix_only_matches_on_path_boundary(self):
        # ``example.com/foo`` is NOT a prefix of ``example.com/foobar`` —
        # the boundary is the ``/`` separator.
        assert _module_for_tool_path("example.com/foobar", ["example.com/foo"]) is None


class TestDiscoverGoModDependencies:
    def test_basic_discovery(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            """module example.com/p

go 1.22

require (
    github.com/foo v1.0.0
    github.com/bar v2.0.0 // indirect
)
""",
            encoding="utf-8",
        )
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        assert len(deps) == 2
        for d in deps:
            assert d.ecosystem == Ecosystem.GO
            assert d.group == DependencyGroup.PROD
            assert d.depth == 0
        names = {d.name: d.version_constraint for d in deps}
        assert names == {"github.com/foo": "v1.0.0", "github.com/bar": "v2.0.0"}

    def test_replace_rewrites_dep(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            """require github.com/old/x v1.0.0
replace github.com/old/x v1.0.0 => github.com/new/x v2.0.0
""",
            encoding="utf-8",
        )
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "github.com/new/x"
        assert deps[0].version_constraint == "v2.0.0"

    def test_replace_to_local_drops_dep(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            """require github.com/local v1.0.0
replace github.com/local => ../local
""",
            encoding="utf-8",
        )
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        assert deps == []

    def test_nested_go_mod_discovered(self, tmp_path):
        # Polyglot / monorepo style: a nested ``cli/go.mod`` alongside the root.
        (tmp_path / "go.mod").write_text("require github.com/a v1.0.0\n", encoding="utf-8")
        (tmp_path / "cli").mkdir()
        (tmp_path / "cli" / "go.mod").write_text("require github.com/b v2.0.0\n", encoding="utf-8")
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"github.com/a", "github.com/b"}

    def test_unreadable_go_mod_skipped(self, tmp_path, monkeypatch):
        (tmp_path / "go.mod").write_text("require github.com/x v1.0.0\n", encoding="utf-8")
        # Simulate IO error
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "go.mod":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        assert deps == []

    def test_source_path_is_relative(self, tmp_path):
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "go.mod").write_text(
            "require github.com/x v1.0.0\n", encoding="utf-8"
        )
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].source == "subdir/go.mod"

    def test_tool_directive_marks_dep_as_dev(self, tmp_path):
        # End-to-end: a require'd module that's also listed in the tool block
        # comes back as DependencyGroup.DEV.
        (tmp_path / "go.mod").write_text(
            """module example.com/p

go 1.24

require (
    golang.org/x/tools v0.20.0
    github.com/runtime/dep v1.0.0
)

tool golang.org/x/tools/cmd/stringer
""",
            encoding="utf-8",
        )
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["golang.org/x/tools"].group == DependencyGroup.DEV
        assert by_name["github.com/runtime/dep"].group == DependencyGroup.PROD

    def test_tool_directive_with_no_matching_require_inert(self, tmp_path):
        # A tool entry without a matching require module shouldn't mark
        # anything as DEV (the tool block by itself doesn't add a dep).
        (tmp_path / "go.mod").write_text(
            """require github.com/runtime/dep v1.0.0

tool unrelated.tool/cmd/x
""",
            encoding="utf-8",
        )
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD


class TestWorkspaceLocalFilter:
    """A direct require whose name matches a workspace-local module path
    (declared by any in-tree go.mod or a go.work-used directory) should
    be filtered out — that module isn't on the public proxy/deps.dev,
    so license resolution would 404.
    """

    def test_implicit_monorepo_sibling_filtered(self, tmp_path):
        # ``server/go.mod`` declares module ``example.com/repo/server``;
        # ``cli/go.mod`` requires it. The cli's require should be filtered
        # because ``example.com/repo/server`` is workspace-local.
        (tmp_path / "server").mkdir()
        (tmp_path / "server" / "go.mod").write_text(
            "module example.com/repo/server\ngo 1.22\n", encoding="utf-8"
        )
        (tmp_path / "cli").mkdir()
        (tmp_path / "cli" / "go.mod").write_text(
            "module example.com/repo/cli\n\n"
            "require (\n"
            "    example.com/repo/server v0.0.0-20240101000000-abcdef\n"
            "    github.com/external v1.0.0\n"
            ")\n",
            encoding="utf-8",
        )
        deps, filtered = discover_go_mod_dependencies(tmp_path)
        names = {d.name for d in deps}
        # Workspace-local module dropped; external one kept.
        assert "example.com/repo/server" not in names
        assert "github.com/external" in names
        assert filtered == 1

    def test_go_work_use_block_marks_sibling_as_local(self, tmp_path):
        # go.work explicitly uses ./moduleA and ./moduleB. Either's
        # require of the other should be filtered.
        (tmp_path / "go.work").write_text(
            "go 1.22\n\nuse (\n    ./moduleA\n    ./moduleB\n)\n",
            encoding="utf-8",
        )
        (tmp_path / "moduleA").mkdir()
        (tmp_path / "moduleA" / "go.mod").write_text(
            "module example.com/a\ngo 1.22\n", encoding="utf-8"
        )
        (tmp_path / "moduleB").mkdir()
        (tmp_path / "moduleB" / "go.mod").write_text(
            "module example.com/b\n\nrequire example.com/a v0.0.0-20240101-abc\n",
            encoding="utf-8",
        )
        deps, filtered = discover_go_mod_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "example.com/a" not in names
        assert filtered == 1

    def test_go_work_single_line_use_directive(self, tmp_path):
        # ``use ./dir`` (single-line form) — verify it's parsed too.
        (tmp_path / "go.work").write_text("go 1.22\n\nuse ./sub\n", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "go.mod").write_text(
            "module example.com/sub\n\nrequire github.com/x v1.0.0\n",
            encoding="utf-8",
        )
        (tmp_path / "go.mod").write_text(
            "module example.com/root\n\nrequire example.com/sub v0.0.0-abc\n",
            encoding="utf-8",
        )
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "example.com/sub" not in names

    def test_go_work_use_directive_quoted_path(self, tmp_path):
        # Defensive: ``use "./path"`` (quoted) should also work.
        (tmp_path / "go.work").write_text('go 1.22\n\nuse "./sub"\n', encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "go.mod").write_text("module example.com/sub\n", encoding="utf-8")
        (tmp_path / "go.mod").write_text(
            "module example.com/root\nrequire example.com/sub v0.0.0-abc\n",
            encoding="utf-8",
        )
        deps, _ = discover_go_mod_dependencies(tmp_path)
        assert "example.com/sub" not in {d.name for d in deps}

    def test_go_work_use_pointing_outside_project_tree(self, tmp_path):
        # ``use ../sibling`` — target is a directory outside the project
        # tree (a peer repo). Its go.mod is read explicitly via the
        # go.work ``use`` machinery, and its module name is filtered.
        sibling = tmp_path / "sibling"
        sibling.mkdir()
        (sibling / "go.mod").write_text("module example.com/sibling\n", encoding="utf-8")
        project = tmp_path / "project"
        project.mkdir()
        (project / "go.work").write_text(
            "go 1.22\n\nuse (\n    .\n    ../sibling\n)\n", encoding="utf-8"
        )
        (project / "go.mod").write_text(
            "module example.com/project\nrequire example.com/sibling v0.0.0-abc\n",
            encoding="utf-8",
        )
        deps, filtered = discover_go_mod_dependencies(project)
        assert "example.com/sibling" not in {d.name for d in deps}
        assert filtered == 1

    def test_go_work_use_pointing_to_missing_dir_skipped(self, tmp_path):
        # ``use ./nonexistent`` — the directory doesn't exist or has no
        # go.mod; gracefully skipped, no crash, no false-positive filter.
        (tmp_path / "go.work").write_text("go 1.22\n\nuse ./nonexistent\n", encoding="utf-8")
        (tmp_path / "go.mod").write_text(
            "module example.com/root\nrequire github.com/external v1.0.0\n",
            encoding="utf-8",
        )
        deps, filtered = discover_go_mod_dependencies(tmp_path)
        assert {d.name for d in deps} == {"github.com/external"}
        assert filtered == 0

    def test_go_work_unreadable_skipped(self, tmp_path, monkeypatch):
        # go.work exists but reading it raises — fall back to the in-tree
        # workspace-local set without crashing.
        (tmp_path / "go.work").write_text("garbage", encoding="utf-8")
        (tmp_path / "go.mod").write_text(
            "module example.com/root\nrequire github.com/external v1.0.0\n",
            encoding="utf-8",
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "go.work":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        deps, filtered = discover_go_mod_dependencies(tmp_path)
        # External dep present; nothing filtered (root's own module is the
        # only local one and external doesn't match it).
        assert {d.name for d in deps} == {"github.com/external"}
        assert filtered == 0

    def test_go_work_use_target_go_mod_unreadable_skipped(self, tmp_path, monkeypatch):
        # The use-target directory exists, its go.mod exists, but reading
        # it raises. Defensive skip.
        (tmp_path / "go.work").write_text("go 1.22\nuse ./sub\n", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        bad_mod = tmp_path / "sub" / "go.mod"
        bad_mod.write_text("module example.com/sub\n", encoding="utf-8")
        (tmp_path / "go.mod").write_text(
            "module example.com/root\nrequire github.com/external v1.0.0\n",
            encoding="utf-8",
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            # Only the use-target's go.mod fails — the root one still reads OK.
            if self == bad_mod:
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        deps, _filtered = discover_go_mod_dependencies(tmp_path)
        # external still present; the use-target's module name wasn't
        # added to the local set so nothing extra filtered.
        assert "github.com/external" in {d.name for d in deps}

    def test_quoted_module_declaration_extracted(self, tmp_path):
        # ``module "github.com/foo/bar"`` (quoted form) is rare but valid.
        (tmp_path / "go.work").write_text("go 1.22\nuse ./sub\n", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "go.mod").write_text('module "example.com/quoted"\n', encoding="utf-8")
        (tmp_path / "go.mod").write_text(
            "module example.com/root\nrequire example.com/quoted v0.0.0-abc\n",
            encoding="utf-8",
        )
        deps, _ = discover_go_mod_dependencies(tmp_path)
        assert "example.com/quoted" not in {d.name for d in deps}

    def test_go_work_use_target_without_module_declaration_skipped(self, tmp_path):
        # The use-target's go.mod exists but has no ``module`` line (e.g.,
        # a malformed go.mod). Nothing's added to the workspace-local set.
        (tmp_path / "go.work").write_text("go 1.22\nuse ./sub\n", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "go.mod").write_text(
            "go 1.22\n", encoding="utf-8"
        )  # no `module` declaration
        (tmp_path / "go.mod").write_text(
            "module example.com/root\nrequire github.com/external v1.0.0\n",
            encoding="utf-8",
        )
        deps, _ = discover_go_mod_dependencies(tmp_path)
        assert "github.com/external" in {d.name for d in deps}

    def test_unreadable_in_tree_go_mod_doesnt_break_filter(self, tmp_path, monkeypatch):
        # An IOError reading one in-tree go.mod (during the workspace-local
        # collection pass) shouldn't crash; that module just isn't added
        # to the local set.
        (tmp_path / "go.mod").write_text(
            "module example.com/root\nrequire github.com/external v1.0.0\n",
            encoding="utf-8",
        )
        (tmp_path / "sub").mkdir()
        bad = tmp_path / "sub" / "go.mod"
        bad.write_text("module example.com/sub\n", encoding="utf-8")
        original = Path.read_bytes
        first_call_for_bad = {"done": False}

        def explode(self, *args, **kwargs):
            # Only fail the FIRST read (during workspace-local collection);
            # the discover-loop's second read of the same file succeeds.
            if self == bad and not first_call_for_bad["done"]:
                first_call_for_bad["done"] = True
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        deps, _ = discover_go_mod_dependencies(tmp_path)
        # external from root is present; sub's go.mod produced no requires
        # so nothing else.
        assert "github.com/external" in {d.name for d in deps}


class TestIsTestFixtureGoMod:
    def test_top_level_go_mod_is_not_fixture(self, tmp_path):
        assert _is_test_fixture_go_mod(tmp_path / "go.mod") is False

    def test_testdata_at_any_depth_is_fixture(self, tmp_path):
        assert _is_test_fixture_go_mod(
            tmp_path / "pkg" / "parser" / "testdata" / "normal" / "go.mod"
        )
        assert _is_test_fixture_go_mod(tmp_path / "testdata" / "go.mod")
        assert _is_test_fixture_go_mod(
            tmp_path / "a" / "b" / "c" / "testdata" / "x" / "y" / "z" / "go.mod"
        )

    def test_similar_but_not_testdata_is_not_fixture(self, tmp_path):
        # Don't accidentally exclude legitimate paths whose components
        # merely contain the substring ``testdata`` — only the exact
        # directory name counts.
        assert _is_test_fixture_go_mod(tmp_path / "mytestdata" / "go.mod") is False
        assert _is_test_fixture_go_mod(tmp_path / "testdataset" / "go.mod") is False


class TestWorkspaceLocalTestdataFilter:
    def test_testdata_go_mod_does_not_shadow_real_require(self, tmp_path):
        # A test fixture declares ``module golang.org/x/xerrors`` to exercise
        # the parser. Without the testdata filter, that declaration would
        # be added to the workspace-local set and the project's real
        # ``require golang.org/x/xerrors`` would silently disappear.
        # Mirrors the trivy regression discovered via polyglot regression
        # sweep on 2026-05-26.
        (tmp_path / "go.mod").write_text(
            "module example.com/project\n"
            "require golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da\n",
            encoding="utf-8",
        )
        fixture = tmp_path / "pkg" / "parser" / "testdata" / "fake-xerrors"
        fixture.mkdir(parents=True)
        (fixture / "go.mod").write_text("module golang.org/x/xerrors\n", encoding="utf-8")
        deps, filtered = discover_go_mod_dependencies(tmp_path)
        assert "golang.org/x/xerrors" in {d.name for d in deps}
        assert filtered == 0

    def test_real_sibling_module_still_filtered(self, tmp_path):
        # The fix excludes ``testdata/`` paths only — a real sibling
        # in-tree module (no ``testdata`` segment in the path) is still
        # treated as workspace-local and filtered.
        (tmp_path / "go.mod").write_text(
            "module example.com/project\n"
            "require example.com/sibling v1.0.0\n"
            "require github.com/external v2.0.0\n",
            encoding="utf-8",
        )
        sibling = tmp_path / "submodule"
        sibling.mkdir()
        (sibling / "go.mod").write_text("module example.com/sibling\n", encoding="utf-8")
        deps, filtered = discover_go_mod_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "example.com/sibling" not in names
        assert "github.com/external" in names
        assert filtered == 1
