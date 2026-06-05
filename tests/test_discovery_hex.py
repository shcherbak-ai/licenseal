"""Tests for Hex / Elixir (mix.exs) discovery."""

from __future__ import annotations

from pathlib import Path  # noqa: F401 - used by monkeypatch in tests

from licenseal.discovery.hex.erlang_mk import (
    _logical_lines,
    _parse_dep_def,
    discover_erlang_mk_dependencies,
    workspace_erlang_mk_project_names,
    workspace_hex_names,
)
from licenseal.discovery.hex.mix_exs import (
    _is_dev_only,
    _license_array_body_to_raw,
    collect_dev_direct_names,
    detect_project_license_mix_exs,
    discover_mix_exs_dependencies,
    workspace_mix_names,
)
from licenseal.discovery.hex.mix_lock import is_off_registry_marker
from licenseal.discovery.hex.rebar_config import (
    _parse_dep,
    discover_rebar_config_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem

_FIXTURES = Path(__file__).parent / "fixtures" / "mix"
_REBAR_FIXTURES = Path(__file__).parent / "fixtures" / "rebar"
_ERLANG_MK_FIXTURES = Path(__file__).parent / "fixtures" / "erlang_mk"


class TestDiscoverMixExsDependencies:
    def test_simple_extracts_prod_and_dev(self):
        deps, filtered = discover_mix_exs_dependencies(_FIXTURES / "simple")
        assert filtered == 0
        prod = {d.name for d in deps if d.group == DependencyGroup.PROD}
        dev = {d.name for d in deps if d.group == DependencyGroup.DEV}
        assert {"phoenix", "ecto_sql", "jason"} <= prod
        assert "credo" in dev
        assert "ex_doc" in dev

    def test_version_constraints_preserved(self):
        deps, _ = discover_mix_exs_dependencies(_FIXTURES / "simple")
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["phoenix"] == "~> 1.7.10"
        assert by_name["jason"] == ">= 1.0.0"

    def test_off_registry_emitted_with_marker(self):
        deps, _ = discover_mix_exs_dependencies(_FIXTURES / "simple")
        by_name = {d.name: d for d in deps}
        for nm in ("my_fork", "vendored"):
            assert nm in by_name, nm
            assert is_off_registry_marker(by_name[nm].source)
            assert by_name[nm].version_constraint == ""  # url/path, not a version

    def test_ecosystem_and_source_stamped(self):
        deps, _ = discover_mix_exs_dependencies(_FIXTURES / "simple")
        for dep in deps:
            assert dep.ecosystem == Ecosystem.HEX
            if is_off_registry_marker(dep.source):
                continue
            assert dep.source == "mix.exs"

    def test_umbrella_workspace_filter(self):
        workspace = workspace_mix_names(_FIXTURES / "umbrella")
        deps, filtered = discover_mix_exs_dependencies(
            _FIXTURES / "umbrella", workspace_names=workspace
        )
        names = {d.name for d in deps}
        # `core` is an in-umbrella sibling → filtered; external deps kept.
        assert "core" not in names
        assert {"phoenix", "jason", "credo"} <= names
        assert filtered == 1

    def test_no_deps_function_returns_empty(self, tmp_path):
        (tmp_path / "mix.exs").write_text(
            "defmodule X.MixProject do\n  use Mix.Project\n  def project, do: [app: :x]\nend\n"
        )
        deps, _ = discover_mix_exs_dependencies(tmp_path)
        assert deps == []

    def test_deps_without_literal_list_returns_empty(self, tmp_path):
        # deps delegates to a helper — no literal [...] after the header.
        (tmp_path / "mix.exs").write_text(
            "defmodule X.MixProject do\n"
            "  def project do\n"
            "    [app: :x]\n"
            "  end\n"
            "  defp deps, do: external_deps()\n"
            "end\n"
        )
        deps, _ = discover_mix_exs_dependencies(tmp_path)
        assert deps == []

    def test_non_tuple_and_atomless_entries_skipped(self, tmp_path):
        (tmp_path / "mix.exs").write_text(
            "defmodule X.MixProject do\n"
            "  defp deps do\n"
            "    [\n"
            "      :not_a_tuple,\n"
            "      {},\n"
            '      {:real, "~> 1.0"}\n'
            "    ]\n"
            "  end\n"
            "end\n"
        )
        deps, _ = discover_mix_exs_dependencies(tmp_path)
        assert {d.name for d in deps} == {"real"}

    def test_duplicate_deps_deduped(self, tmp_path):
        (tmp_path / "mix.exs").write_text(
            "defmodule X.MixProject do\n"
            "  defp deps do\n"
            '    [{:dep, "~> 1.0"}, {:dep, "~> 2.0"}]\n'
            "  end\n"
            "end\n"
        )
        deps, _ = discover_mix_exs_dependencies(tmp_path)
        assert sum(1 for d in deps if d.name == "dep") == 1

    def test_hex_rename_sets_registry_name(self, tmp_path):
        # `hex: :real_pkg` publishes under a different hex.pm package: the dep
        # keeps the local app name "my_dep" (graph/display) and carries the hex
        # name as registry_name so the manifest-only walk resolves the right
        # package instead of 404ing on the alias.
        (tmp_path / "mix.exs").write_text(
            "defmodule X.MixProject do\n"
            "  defp deps do\n"
            '    [{:my_dep, "~> 1.0", hex: :real_pkg}, {:plain, "~> 2.0"}]\n'
            "  end\n"
            "end\n"
        )
        deps, _ = discover_mix_exs_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["my_dep"].registry_name == "real_pkg"
        assert by_name["my_dep"].effective_registry_name == "real_pkg"
        assert by_name["my_dep"].version_constraint == "~> 1.0"
        # A non-renamed dep has no registry_name override.
        assert by_name["plain"].registry_name == ""

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "mix.exs").write_text(
            'defmodule X do\n  defp deps, do: [{:dep, "~> 1.0"}]\nend\n'
        )

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        deps, filtered = discover_mix_exs_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0


class TestIsDevOnly:
    def test_no_only_is_prod(self):
        assert _is_dev_only('{:dep, "~> 1.0"}') is False

    def test_single_dev_atom(self):
        assert _is_dev_only('{:dep, "~> 1.0", only: :dev}') is True

    def test_list_dev_test(self):
        assert _is_dev_only('{:dep, "~> 1.0", only: [:dev, :test]}') is True

    def test_only_prod_is_prod(self):
        assert _is_dev_only('{:dep, "~> 1.0", only: :prod}') is False

    def test_list_including_prod_is_prod(self):
        assert _is_dev_only('{:dep, "~> 1.0", only: [:dev, :prod]}') is False

    def test_only_test(self):
        assert _is_dev_only('{:dep, "~> 1.0", only: :test}') is True


class TestCollectDevDirectNames:
    def test_prod_outranks_dev(self):
        from licenseal.models import Dependency

        deps = [
            Dependency(
                name="x", version_constraint="", ecosystem=Ecosystem.HEX, group=DependencyGroup.PROD
            ),
            Dependency(
                name="x", version_constraint="", ecosystem=Ecosystem.HEX, group=DependencyGroup.DEV
            ),
            Dependency(
                name="credo",
                version_constraint="",
                ecosystem=Ecosystem.HEX,
                group=DependencyGroup.DEV,
            ),
        ]
        assert collect_dev_direct_names(deps) == {"credo"}

    def test_non_hex_deps_ignored(self):
        from licenseal.models import Dependency

        deps = [
            Dependency(
                name="rubocop",
                version_constraint="",
                ecosystem=Ecosystem.RUBY,
                group=DependencyGroup.DEV,
            ),
        ]
        assert collect_dev_direct_names(deps) == set()


class TestLicenseArrayBodyToRaw:
    def test_single(self):
        assert _license_array_body_to_raw('"MIT"') == "MIT"

    def test_multi_or_joined(self):
        assert _license_array_body_to_raw('"MIT", "Apache-2.0"') == "MIT OR Apache-2.0"

    def test_empty(self):
        assert _license_array_body_to_raw("") == ""
        assert _license_array_body_to_raw("   ") == ""


class TestDetectProjectLicenseMixExs:
    def test_simple_array_or_joined(self):
        assert detect_project_license_mix_exs(_FIXTURES / "simple") == "MIT OR Apache-2.0"

    def test_single_license(self, tmp_path):
        (tmp_path / "mix.exs").write_text(
            'defmodule X do\n  defp package, do: [licenses: ["MIT"]]\nend\n'
        )
        assert detect_project_license_mix_exs(tmp_path) == "MIT"

    def test_no_license_returns_empty(self, tmp_path):
        (tmp_path / "mix.exs").write_text("defmodule X do\n  def project, do: []\nend\n")
        assert detect_project_license_mix_exs(tmp_path) == ""

    def test_empty_license_array_skipped(self, tmp_path):
        (tmp_path / "mix.exs").write_text(
            "defmodule X do\n  defp package, do: [licenses: []]\nend\n"
        )
        assert detect_project_license_mix_exs(tmp_path) == ""

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "mix.exs").write_text(
            'defmodule X do\n  defp package, do: [licenses: ["MIT"]]\nend\n'
        )

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert detect_project_license_mix_exs(tmp_path) == ""


class TestWorkspaceMixNames:
    def test_umbrella_collects_app_names(self):
        names = workspace_mix_names(_FIXTURES / "umbrella")
        assert "core" in names
        assert "web" in names

    def test_single_project_collects_own_app(self):
        assert "simple" in workspace_mix_names(_FIXTURES / "simple")

    def test_no_mix_exs_returns_empty(self, tmp_path):
        assert workspace_mix_names(tmp_path) == frozenset()

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "mix.exs").write_text("defmodule X do\n  def project, do: [app: :x]\nend\n")

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert workspace_mix_names(tmp_path) == frozenset()


class TestDiscoverRebarConfigDependencies:
    def test_prod_and_dev_split(self):
        deps, filtered = discover_rebar_config_dependencies(_REBAR_FIXTURES / "simple")
        assert filtered == 0
        prod = {d.name for d in deps if d.group == DependencyGroup.PROD}
        dev = {d.name for d in deps if d.group == DependencyGroup.DEV}
        # `renamed` resolves to its {pkg, real_hex_name, ...} target.
        assert prod == {"cowlib", "ranch", "jsx", "real_hex_name"}
        assert dev == {"meck", "proper", "redbug"}

    def test_versions_and_off_registry(self):
        deps, _ = discover_rebar_config_dependencies(_REBAR_FIXTURES / "simple")
        by_name = {d.name: d for d in deps}
        assert by_name["ranch"].version_constraint == "1.8.0"
        assert by_name["cowlib"].version_constraint == ""  # bare atom, latest
        assert by_name["real_hex_name"].version_constraint == "2.0.0"
        assert is_off_registry_marker(by_name["jsx"].source)
        for dep in deps:
            assert dep.ecosystem == Ecosystem.HEX

    def test_workspace_filter(self):
        deps, filtered = discover_rebar_config_dependencies(
            _REBAR_FIXTURES / "simple", workspace_names=frozenset({"cowlib"})
        )
        assert "cowlib" not in {d.name for d in deps}
        assert filtered == 1

    def test_no_deps_returns_empty(self, tmp_path):
        (tmp_path / "rebar.config").write_text("{erl_opts, [debug_info]}.\n")
        deps, _ = discover_rebar_config_dependencies(tmp_path)
        assert deps == []

    def test_no_profiles_only_prod(self, tmp_path):
        (tmp_path / "rebar.config").write_text('{deps, [{cowlib, "2.0"}]}.\n')
        deps, _ = discover_rebar_config_dependencies(tmp_path)
        assert {d.name for d in deps} == {"cowlib"}
        assert deps[0].group == DependencyGroup.PROD

    def test_profile_without_deps_skipped(self, tmp_path):
        # A test profile with no {deps,...} key, and no dev profile at all.
        (tmp_path / "rebar.config").write_text(
            '{deps, [{cowlib, "2.0"}]}.\n{profiles, [{test, [{erl_opts, [debug_info]}]}]}.\n'
        )
        deps, _ = discover_rebar_config_dependencies(tmp_path)
        assert {d.name for d in deps} == {"cowlib"}

    def test_dep_in_prod_and_test_emits_both_groups(self, tmp_path):
        # Like the Gemfile parser, a dep in both top-level deps and a dev
        # profile is emitted in both groups; the aggregator +
        # collect_dev_direct_names resolve prod-precedence downstream.
        (tmp_path / "rebar.config").write_text(
            '{deps, [{shared, "1.0"}]}.\n{profiles, [{test, [{deps, [{shared, "1.0"}]}]}]}.\n'
        )
        deps, _ = discover_rebar_config_dependencies(tmp_path)
        groups = {d.group for d in deps if d.name == "shared"}
        assert groups == {DependencyGroup.PROD, DependencyGroup.DEV}
        assert "shared" not in collect_dev_direct_names(deps)

    def test_duplicate_across_dev_profiles_deduped(self, tmp_path):
        # Same (name, group) declared in both test and dev profiles → emitted
        # once.
        (tmp_path / "rebar.config").write_text(
            '{profiles, [{test, [{deps, [{meck, "1.0"}]}]}, {dev, [{deps, [{meck, "1.0"}]}]}]}.\n'
        )
        deps, _ = discover_rebar_config_dependencies(tmp_path)
        meck = [d for d in deps if d.name == "meck"]
        assert len(meck) == 1
        assert meck[0].group == DependencyGroup.DEV

    def test_atomless_entry_in_deps_skipped(self, tmp_path):
        (tmp_path / "rebar.config").write_text('{deps, [{42, "x"}, {real, "1.0"}]}.\n')
        deps, _ = discover_rebar_config_dependencies(tmp_path)
        assert {d.name for d in deps} == {"real"}

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "rebar.config").write_text('{deps, [{cowlib, "2.0"}]}.\n')

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        deps, filtered = discover_rebar_config_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0


class TestParseRebarDep:
    def test_bare_atom(self):
        assert _parse_dep("cowlib") == ("cowlib", "", False)

    def test_name_version(self):
        assert _parse_dep('{ranch, "1.8.0"}') == ("ranch", "1.8.0", False)

    def test_git_off_registry(self):
        name, version, off = _parse_dep('{jsx, {git, "https://x/y.git", {tag, "v3"}}}')
        assert (name, version, off) == ("jsx", "", True)

    def test_pkg_rename(self):
        assert _parse_dep('{renamed, {pkg, real_name, "2.0.0"}}') == (
            "real_name",
            "2.0.0",
            False,
        )

    def test_empty_entry(self):
        assert _parse_dep("") == ("", "", False)

    def test_atomless_braced_entry(self):
        assert _parse_dep('{42, "x"}') == ("", "", False)

    def test_atomless_bare_entry(self):
        assert _parse_dep("123") == ("", "", False)


class TestDiscoverErlangMk:
    def test_prod_and_dev_split(self):
        ws = workspace_hex_names(_ERLANG_MK_FIXTURES / "simple")
        deps, filtered = discover_erlang_mk_dependencies(
            _ERLANG_MK_FIXTURES / "simple", workspace_names=ws
        )
        prod = {d.name for d in deps if d.group == DependencyGroup.PROD}
        dev = {d.name for d in deps if d.group == DependencyGroup.DEV}
        # ranch is git (off-registry) but still a prod dep; recon is REL_DEPS;
        # jsx is renamed to its hex package jsx_renamed.
        assert prod == {"cowlib", "ranch", "jsx_renamed", "recon"}
        assert dev == {"meck", "proper", "rebar3"}
        assert filtered == 1  # internal_sibling (a workspace app)

    def test_versions_sources_and_ecosystem(self):
        ws = workspace_hex_names(_ERLANG_MK_FIXTURES / "simple")
        deps, _ = discover_erlang_mk_dependencies(
            _ERLANG_MK_FIXTURES / "simple", workspace_names=ws
        )
        by_name = {d.name: d for d in deps}
        assert by_name["cowlib"].version_constraint == "==2.12.1"
        assert by_name["cowlib"].source == "Makefile"  # registry, manifest path
        assert is_off_registry_marker(by_name["ranch"].source)
        assert by_name["ranch"].version_constraint == ""
        assert by_name["jsx_renamed"].version_constraint == "==3.1.0"
        assert by_name["recon"].version_constraint == ""  # hex-by-name (no dep_ line)
        assert by_name["meck"].version_constraint == ""
        for dep in deps:
            assert dep.ecosystem == Ecosystem.HEX

    def test_local_deps_and_make_tokens_skipped(self):
        deps, _ = discover_erlang_mk_dependencies(
            _ERLANG_MK_FIXTURES / "simple",
            workspace_names=workspace_hex_names(_ERLANG_MK_FIXTURES / "simple"),
        )
        names = {d.name for d in deps}
        assert "crypto" not in names and "ssl" not in names  # LOCAL_DEPS (OTP)
        # $(if ...) / ci.erlang.mk Make-function tokens never become deps.
        assert not any("." in n or "$" in n for n in names)

    def test_non_erlang_mk_makefile_ignored(self, tmp_path):
        (tmp_path / "Makefile").write_text("all:\n\tgcc -o x x.c\nDEPS = fake\n")
        deps, _ = discover_erlang_mk_dependencies(tmp_path)
        assert deps == []

    def test_duplicate_dep_deduped(self, tmp_path):
        (tmp_path / "Makefile").write_text("DEPS = cowlib\nDEPS += cowlib\ninclude erlang.mk\n")
        deps, _ = discover_erlang_mk_dependencies(tmp_path)
        assert sum(1 for d in deps if d.name == "cowlib") == 1

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "Makefile").write_text("DEPS = cowlib\ninclude erlang.mk\n")

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        deps, filtered = discover_erlang_mk_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0


class TestParseDepDef:
    def test_hex_with_version(self):
        assert _parse_dep_def("hex 2.12.1") == (None, "2.12.1", False)

    def test_hex_with_rename(self):
        assert _parse_dep_def("hex 3.1.0 realpkg") == ("realpkg", "3.1.0", False)

    def test_hex_no_version(self):
        assert _parse_dep_def("hex") == (None, "", False)

    def test_git_off_registry(self):
        assert _parse_dep_def("git https://x/y 1.0") == (None, "", True)

    def test_empty_off_registry(self):
        assert _parse_dep_def("") == (None, "", True)


class TestWorkspaceErlangMkProjectNames:
    def test_collects_project_names(self):
        names = workspace_erlang_mk_project_names(_ERLANG_MK_FIXTURES / "simple")
        assert names == frozenset({"myapp", "internal_sibling"})

    def test_workspace_hex_names_union(self):
        # No mix.exs in this tree, so the union equals the erlang.mk PROJECTs.
        assert workspace_hex_names(_ERLANG_MK_FIXTURES / "simple") == frozenset(
            {"myapp", "internal_sibling"}
        )

    def test_non_erlang_mk_makefile_skipped(self, tmp_path):
        (tmp_path / "Makefile").write_text("PROJECT = generic\nall:\n\tgcc\n")
        assert workspace_erlang_mk_project_names(tmp_path) == frozenset()

    def test_project_after_other_lines(self, tmp_path):
        # PROJECT not on the first line — earlier non-matching lines are skipped.
        (tmp_path / "Makefile").write_text("DEPS = cowlib\nPROJECT = late_app\ninclude erlang.mk\n")
        assert workspace_erlang_mk_project_names(tmp_path) == frozenset({"late_app"})

    def test_erlang_mk_without_project(self, tmp_path):
        # An erlang.mk Makefile with no PROJECT line contributes nothing.
        (tmp_path / "Makefile").write_text("DEPS = cowlib\ninclude erlang.mk\n")
        assert workspace_erlang_mk_project_names(tmp_path) == frozenset()

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "Makefile").write_text("PROJECT = x\ninclude erlang.mk\n")

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert workspace_erlang_mk_project_names(tmp_path) == frozenset()


class TestErlangMkLogicalLines:
    def test_continuation_joined(self):
        # Spacing is collapsed downstream by split(); assert tokens, not exact spaces.
        lines = _logical_lines("DEPS = a \\\n b\nFOO = x\n")
        assert lines[0].split() == ["DEPS", "=", "a", "b"]
        assert lines[1] == "FOO = x"

    def test_comment_stripped(self):
        assert _logical_lines("DEPS = a # comment\n") == ["DEPS = a "]

    def test_trailing_backslash_flushed_at_eof(self):
        # A continuation with no following line flushes the pending buffer.
        assert "a" in _logical_lines("X = a \\")[0]
