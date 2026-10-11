"""Tests for Hex / Elixir (mix.exs) discovery."""

from __future__ import annotations

from pathlib import Path  # noqa: F401 - used by monkeypatch in tests

from licenseal.discovery import discover_all_dependencies
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

    def test_off_registry_deps_carry_their_origin(self):
        deps, _ = discover_mix_exs_dependencies(_FIXTURES / "simple")
        by_name = {d.name: d for d in deps}
        assert by_name["my_fork"].origin == "git+https://github.com/me/my_fork.git@main"
        # ``../vendored`` is outside the scanned directory.
        assert by_name["vendored"].origin == "../vendored"
        for nm in ("my_fork", "vendored"):
            assert by_name[nm].version_constraint == ""  # url/path, not a version
        assert {d.name for d in deps if d.origin} == {"my_fork", "vendored"}

    def test_ecosystem_and_source_stamped(self):
        deps, _ = discover_mix_exs_dependencies(_FIXTURES / "simple")
        for dep in deps:
            assert dep.ecosystem == Ecosystem.HEX
            assert dep.source == "mix.exs"

    def test_source_options_in_every_form(self, tmp_path):
        (tmp_path / "apps" / "inside").mkdir(parents=True)
        (tmp_path / "mix.exs").write_text(
            "defmodule M.MixProject do\n"
            "  defp deps do\n"
            "    [\n"
            '      {:by_ref, git: "https://u:p@example.org/by_ref.git", ref: "abc123", tag: "v9"'
            "},\n"
            '      {:by_tag, git: "https://example.org/by_tag.git", tag: "v1.0"},\n'
            '      {:bare, git: "https://example.org/bare.git"},\n'
            "      {:computed_git, git: repo_url()},\n"
            '      {:hub, github: "me/hub"},\n'
            "      {:computed_hub, github: hub_name()},\n"
            '      {:inside, path: "apps/inside"},\n'
            "      {:computed_path, path: local_dir()},\n"
            "      {:sibling, in_umbrella: true},\n"
            '      {:not_sibling, "~> 1.0", in_umbrella: false},\n'
            '      {:versioned_sibling, "~> 1.0"},\n'
            '      {:plain, "~> 2.0"}\n'
            "    ]\n"
            "  end\n"
            "end\n"
        )
        deps, filtered = discover_mix_exs_dependencies(
            tmp_path, workspace_names=frozenset({"sibling", "versioned_sibling"})
        )
        assert {d.name: d.origin for d in deps} == {
            "by_ref": "git+https://example.org/by_ref.git@abc123",
            "by_tag": "git+https://example.org/by_tag.git@v1.0",
            "bare": "git+https://example.org/bare.git",
            "computed_git": "unrecorded source",
            "hub": "git+https://github.com/me/hub.git",
            "computed_hub": "unrecorded source",
            "computed_path": "unrecorded source",
            "not_sibling": "",
            "plain": "",
        }
        # ``inside`` and ``sibling`` are the project's own apps: neither is a
        # dependency, and only the one that is a workspace app is counted,
        # beside the workspace app that is declared by version.
        assert filtered == 2

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
        assert (
            detect_project_license_mix_exs(_FIXTURES / "simple" / "mix.exs") == "MIT OR Apache-2.0"
        )

    def test_single_license(self, tmp_path):
        (tmp_path / "mix.exs").write_text(
            'defmodule X do\n  defp package, do: [licenses: ["MIT"]]\nend\n'
        )
        assert detect_project_license_mix_exs(tmp_path / "mix.exs") == "MIT"

    def test_no_license_returns_empty(self, tmp_path):
        (tmp_path / "mix.exs").write_text("defmodule X do\n  def project, do: []\nend\n")
        assert detect_project_license_mix_exs(tmp_path / "mix.exs") == ""

    def test_empty_license_array_skipped(self, tmp_path):
        (tmp_path / "mix.exs").write_text(
            "defmodule X do\n  defp package, do: [licenses: []]\nend\n"
        )
        assert detect_project_license_mix_exs(tmp_path / "mix.exs") == ""

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "mix.exs").write_text(
            'defmodule X do\n  defp package, do: [licenses: ["MIT"]]\nend\n'
        )

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert detect_project_license_mix_exs(tmp_path / "mix.exs") == ""


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
        assert by_name["jsx"].origin == "git+https://github.com/talentdeficit/jsx.git@v3.1.0"
        assert by_name["jsx"].source == "rebar.config"
        assert {d.name for d in deps if d.origin} == {"jsx"}
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

    def test_deps_outside_the_test_and_dev_profiles_are_production(self, tmp_path):
        # Only the test and dev profiles are development profiles. A prod
        # profile, and a profile under any other name, ships.
        (tmp_path / "rebar.config").write_text(
            "{erl_opts, [debug_info]}.\n"
            '{deps, [{base_lib, "1.0.0"}]}.\n'
            "{profiles, [\n"
            '    {prod, [{deps, [{release_lib, "2.0.0"}]}, {relx, [{dev_mode, false}]}]},\n'
            '    {bench, [{deps, [{bench_lib, "3.0.0"}]}]},\n'
            '    {test, [{deps, [{test_lib, "4.0.0"}]}]},\n'
            '    {dev, [{deps, [{dev_lib, "5.0.0"}]}]}\n'
            "]}.\n",
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {(d.name, d.version_constraint, d.group) for d in deps} == {
            ("base_lib", "1.0.0", DependencyGroup.PROD),
            ("release_lib", "2.0.0", DependencyGroup.PROD),
            ("bench_lib", "3.0.0", DependencyGroup.PROD),
            ("test_lib", "4.0.0", DependencyGroup.DEV),
            ("dev_lib", "5.0.0", DependencyGroup.DEV),
        }
        assert {d.source for d in deps} == {"rebar.config"}

    def test_dep_in_a_production_profile_and_the_test_profile_is_production(self, tmp_path):
        (tmp_path / "rebar.config").write_text(
            "{profiles, [\n"
            '    {test, [{deps, [{shared, "1.0.0"}, {test_only, "1.0.0"}]}]},\n'
            '    {prod, [{deps, [{shared, "1.0.0"}]}]}\n'
            "]}.\n",
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name: d.group for d in deps} == {
            "shared": DependencyGroup.PROD,
            "test_only": DependencyGroup.DEV,
        }
        assert collect_dev_direct_names(deps) == {"test_only"}

    def test_deps_nested_in_another_term_are_not_the_project_deps(self, tmp_path):
        # An overrides entry rewrites one dependency's own configuration. Its
        # deps list is not the project's, wherever the term sits in the file.
        overrides = '{overrides, [{override, patched_app, [{deps, [{forced_lib, "9.0.0"}]}]}]}.\n'
        deps_term = '{deps, [{real_lib, "1.0.0"}, {patched_app, "2.0.0"}]}.\n'
        expected = {("real_lib", "1.0.0"), ("patched_app", "2.0.0")}
        for content in (overrides + deps_term, deps_term + overrides, deps_term):
            (tmp_path / "rebar.config").write_text(content, encoding="utf-8")
            deps, _ = discover_all_dependencies(tmp_path)
            assert {(d.name, d.version_constraint) for d in deps} == expected
            assert all(d.group == DependencyGroup.PROD for d in deps)

    def test_overrides_term_alone_declares_no_dependencies(self, tmp_path):
        (tmp_path / "rebar.config").write_text(
            '{overrides, [{override, patched_app, [{deps, [{forced_lib, "9.0.0"}]}]}]}.\n',
            encoding="utf-8",
        )
        assert discover_all_dependencies(tmp_path)[0] == []

    def test_every_top_level_deps_term_is_read(self, tmp_path):
        (tmp_path / "rebar.config").write_text(
            '{deps, [{first, "1.0.0"}]}.\n{plugins, [a_plugin]}.\n{deps, [{second, "2.0.0"}]}.\n',
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name for d in deps} == {"first", "second"}

    def test_terms_of_another_shape_are_skipped(self, tmp_path):
        # A deps or profiles value that is not a list, a profile entry that is
        # not a {Name, Options} pair, and a term that is not a pair at all.
        (tmp_path / "rebar.config").write_text(
            "{deps, undefined}.\n"
            "{minimum_otp_vsn}.\n"
            "{profiles, undefined}.\n"
            '{profiles, [docs, {lint}, {test, undefined}, {prod, [{deps, [{kept, "1.0.0"}]}]}]}.\n',
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [(d.name, d.group) for d in deps] == [("kept", DependencyGroup.PROD)]

    def test_truncated_final_term_keeps_the_complete_terms(self, tmp_path):
        (tmp_path / "rebar.config").write_text(
            '{deps, [{complete, "1.0.0"}]}.\n{profiles, [{prod, [{deps, [{cut_off, "2.0.0"}',
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.name for d in deps] == ["complete"]


class TestParseRebarDep:
    def test_bare_atom(self):
        assert _parse_dep("cowlib") == ("cowlib", "", "")

    def test_name_version(self):
        assert _parse_dep('{ranch, "1.8.0"}') == ("ranch", "1.8.0", "")

    def test_git_off_registry(self):
        name, version, origin = _parse_dep('{jsx, {git, "https://x/y.git", {tag, "v3"}}}')
        assert (name, version, origin) == ("jsx", "", "git+https://x/y.git@v3")

    def test_git_branch_and_bare_forms(self):
        assert _parse_dep('{a, {git, "https://x/a.git", {branch, "main"}}}')[2] == (
            "git+https://x/a.git@main"
        )
        assert _parse_dep('{b, { git , "https://x/b.git"}}')[2] == "git+https://x/b.git"

    def test_legacy_form_with_a_version_pattern_before_the_source(self):
        entry = '{c, ".*", {git, "https://x/c.git", {ref, "abc"}}}'
        assert _parse_dep(entry) == ("c", "", "git+https://x/c.git@abc")

    def test_git_subdir_and_hg(self):
        assert _parse_dep('{d, {git_subdir, "https://x/mono.git", {tag, "v1"}, "apps/d"}}')[2] == (
            "git+https://x/mono.git@v1"
        )
        assert _parse_dep('{e, {hg, "https://x/e", {tag, "tip"}}}')[2] == "hg+https://x/e@tip"

    def test_git_source_with_no_literal_url_records_no_source(self):
        assert _parse_dep("{f, {git, Url, {tag, Tag}}}") == ("f", "", "unrecorded source")

    def test_pkg_rename(self):
        assert _parse_dep('{renamed, {pkg, real_name, "2.0.0"}}') == (
            "real_name",
            "2.0.0",
            "",
        )

    def test_empty_entry(self):
        assert _parse_dep("") == ("", "", "")

    def test_atomless_braced_entry(self):
        assert _parse_dep('{42, "x"}') == ("", "", "")

    def test_atomless_bare_entry(self):
        assert _parse_dep("123") == ("", "", "")


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
        assert by_name["ranch"].origin == "git+https://github.com/ninenines/ranch@1.8.1"
        assert by_name["ranch"].source == "Makefile"
        assert by_name["ranch"].version_constraint == ""
        assert {d.name for d in deps if d.origin} == {"ranch"}
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
    @staticmethod
    def _parse(value: str, tmp_path: Path):
        return _parse_dep_def(value, tmp_path, tmp_path)

    def test_hex_with_version(self, tmp_path):
        assert self._parse("hex 2.12.1", tmp_path) == (None, "2.12.1", "")

    def test_hex_with_rename(self, tmp_path):
        assert self._parse("hex 3.1.0 realpkg", tmp_path) == ("realpkg", "3.1.0", "")

    def test_hex_no_version(self, tmp_path):
        assert self._parse("hex", tmp_path) == (None, "", "")

    def test_git_off_registry(self, tmp_path):
        assert self._parse("git https://x/y 1.0", tmp_path) == (None, "", "git+https://x/y@1.0")

    def test_git_without_a_commit(self, tmp_path):
        assert self._parse("git https://x/y", tmp_path)[2] == "git+https://x/y"

    def test_git_subfolder_is_a_git_repository(self, tmp_path):
        assert self._parse("git-subfolder https://x/mono v2 apps/y", tmp_path)[2] == (
            "git+https://x/mono@v2"
        )

    def test_other_vcs_keeps_its_name(self, tmp_path):
        assert self._parse("hg https://x/y tip", tmp_path)[2] == "hg+https://x/y@tip"
        assert self._parse("svn https://x/y", tmp_path)[2] == "svn+https://x/y"

    def test_legacy_form_without_a_fetch_method(self, tmp_path):
        assert self._parse("https://x/y 1.0", tmp_path)[2] == "git+https://x/y@1.0"
        assert self._parse("git@example.org:x/y.git 1.0", tmp_path)[2] == (
            "git+example.org:x/y.git@1.0"
        )

    def test_copied_path_outside_the_scanned_directory(self, tmp_path):
        assert self._parse("cp ../elsewhere", tmp_path)[2] == "../elsewhere"
        assert self._parse("ln /opt/elsewhere", tmp_path)[2] == "/opt/elsewhere"

    def test_copied_directory_the_scan_walks_is_own_code(self, tmp_path):
        (tmp_path / "local" / "thing").mkdir(parents=True)
        assert self._parse("cp local/thing", tmp_path) == (None, "", None)
        # One the scan does not walk is a dependency.
        assert self._parse("cp vendor/thing", tmp_path) == (None, "", "vendor/thing")

    def test_method_without_a_source_records_none(self, tmp_path):
        for value in ("", "git", "cp", "git-submodule", "fail unsupported"):
            assert self._parse(value, tmp_path) == (None, "", "unrecorded source"), value


class TestErlangMkOwnCode:
    def test_dep_copied_from_inside_the_tree_is_not_a_dependency(self, tmp_path):
        for app in ("local_a", "local_b"):
            (tmp_path / "apps" / app).mkdir(parents=True)
        (tmp_path / "Makefile").write_text(
            "DEPS = cowlib local_a local_b\n"
            "dep_local_a = cp apps/local_a\n"
            "dep_local_b = ln apps/local_b\n"
            "include erlang.mk\n"
        )
        deps, filtered = discover_erlang_mk_dependencies(
            tmp_path, workspace_names=frozenset({"local_a"})
        )
        assert [d.name for d in deps] == ["cowlib"]
        # Only the one that is a workspace app counts as a filtered reference.
        assert filtered == 1


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
