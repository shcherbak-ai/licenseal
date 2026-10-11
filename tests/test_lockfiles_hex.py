"""Tests for the mix.lock parser."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.hex.mix_lock import (
    _extract_edges,
    _first_atom,
    _parse_lock_tuple,
    _reachable,
    _split_top_level,
    _unquote,
    find_mix_lockfiles,
    parse_mix_lock,
)
from licenseal.discovery.hex.rebar_lock import (
    _balanced_braces,
    _parse_lock_entry,
    find_rebar_lockfiles,
    parse_rebar_lock,
)
from licenseal.models import DependencyGroup, Ecosystem

_FIXTURES = Path(__file__).parent / "fixtures" / "mix"
_REBAR_FIXTURES = Path(__file__).parent / "fixtures" / "rebar"


def _direct_names() -> set[str]:
    """Direct dep names declared in the simple fixture's mix.exs."""
    return {"phoenix", "ecto_sql", "jason", "credo", "ex_doc", "my_fork", "vendored"}


def _dev_direct_names() -> set[str]:
    return {"credo", "ex_doc"}


class TestFindMixLockfiles:
    def test_finds_lock_in_simple_fixture(self):
        locks = find_mix_lockfiles(_FIXTURES / "simple")
        assert len(locks) == 1
        assert locks[0].name == "mix.lock"

    def test_empty_when_absent(self, tmp_path):
        assert find_mix_lockfiles(tmp_path) == []


class TestParseMixLock:
    def test_prod_specs_no_dev_excluded(self):
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=False,
        )
        names = {d.name for d in deps}
        assert {
            "phoenix",
            "phoenix_pubsub",
            "plug",
            "plug_crypto",
            "ecto_sql",
            "ecto",
            "decimal",
            "jason",
        } <= names
        # DEV-only chains dropped.
        assert "credo" not in names
        assert "ex_doc" not in names
        assert "bunt" not in names  # transitive of dev-only credo

    def test_dev_included_when_flag_set(self):
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        dev_names = {d.name for d in deps if d.group == DependencyGroup.DEV}
        assert "credo" in dev_names
        assert "ex_doc" in dev_names
        assert "bunt" in dev_names  # transitive of dev root credo

    def test_prod_outranks_dev_for_shared_transitive(self):
        # jason is both a prod direct dep AND a dep of dev-only credo;
        # prod wins.
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        jason = next(d for d in deps if d.name == "jason")
        assert jason.group == DependencyGroup.PROD

    def test_pinned_versions(self):
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["phoenix"] == "==1.7.10"
        assert by_name["decimal"] == "==2.1.1"

    def test_direct_vs_transitive_depth(self):
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["phoenix"].depth == 0
        assert by_name["plug"].depth == 1  # transitive of phoenix

    def test_direct_ancestors_attributed(self):
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        # plug_crypto is reached only via plug ← phoenix.
        assert "phoenix" in by_name["plug_crypto"].direct_ancestors
        # decimal via ecto ← ecto_sql.
        assert "ecto_sql" in by_name["decimal"].direct_ancestors
        # direct deps carry no ancestors.
        assert by_name["phoenix"].direct_ancestors == ()

    def test_git_spec_carries_repository_and_locked_commit(self):
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        my_fork = next(d for d in deps if d.name == "my_fork")
        assert my_fork.origin == "git+https://github.com/me/my_fork.git@abcdef1234567890"
        assert my_fork.source == ""
        assert my_fork.version_constraint == ""
        assert my_fork.depth == 0  # declared direct
        assert all(d.origin == "" for d in deps if d.name != "my_fork")

    def test_path_entry_outside_the_scanned_directory_is_a_row(self, tmp_path):
        project = tmp_path / "project"
        (project / "apps" / "own").mkdir(parents=True)
        (project / "mix.lock").write_text(
            '%{\n  "elsewhere": {:path, "../elsewhere"},\n  "own": {:path, "apps/own"},\n}\n'
        )
        deps = parse_mix_lock(
            project / "mix.lock", direct_names=set(), dev_direct_names=set(), include_dev=True
        )
        # ``apps/own`` is a directory the scan walks: the project's own code.
        assert [(d.name, d.origin) for d in deps] == [("elsewhere", "../elsewhere")]

    def test_ecosystem_stamped_as_hex(self):
        deps = parse_mix_lock(
            _FIXTURES / "simple" / "mix.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        assert all(d.ecosystem == Ecosystem.HEX for d in deps)

    def test_renamed_dep_carries_hex_registry_name(self, tmp_path):
        # `{:my_dep, "~> 1.0", hex: :real_pkg}` in mix.exs → lock key "my_dep"
        # (the local app name), but the tuple's 2nd element is the real hex.pm
        # package name. The dep keeps the app name (graph/display) and carries
        # the hex name as registry_name so resolution targets it instead of
        # 404ing on the alias and surfacing UNKNOWN.
        (tmp_path / "mix.lock").write_text(
            '%{\n  "my_dep": {:hex, :real_pkg, "1.0.0", "h", [:mix], [], "hexpm", "h2"},\n}\n'
        )
        deps = parse_mix_lock(
            tmp_path / "mix.lock",
            direct_names={"my_dep"},
            dev_direct_names=set(),
            include_dev=True,
        )
        assert len(deps) == 1
        assert deps[0].name == "my_dep"  # graph key + display = the app name
        assert deps[0].registry_name == "real_pkg"  # resolution target
        assert deps[0].effective_registry_name == "real_pkg"
        assert deps[0].depth == 0
        assert deps[0].version_constraint == "==1.0.0"

    def test_non_renamed_dep_has_empty_registry_name(self, tmp_path):
        # When the hex package name equals the lock key (the common case),
        # registry_name stays empty — byte-identical to pre-fix output.
        (tmp_path / "mix.lock").write_text(
            '%{\n  "jason": {:hex, :jason, "1.4.1", "h", [:mix], [], "hexpm", "h2"},\n}\n'
        )
        deps = parse_mix_lock(
            tmp_path / "mix.lock",
            direct_names={"jason"},
            dev_direct_names=set(),
            include_dev=True,
        )
        assert [d.name for d in deps] == ["jason"]
        assert deps[0].registry_name == ""
        assert deps[0].effective_registry_name == "jason"

    def test_unreadable_lockfile_returns_empty(self, tmp_path):
        path = tmp_path / "mix.lock"
        path.mkdir()  # OSError on read_text
        assert (
            parse_mix_lock(path, direct_names=set(), dev_direct_names=set(), include_dev=False)
            == []
        )

    def test_empty_lockfile_returns_empty(self, tmp_path):
        path = tmp_path / "mix.lock"
        path.write_text("%{}\n")
        assert (
            parse_mix_lock(path, direct_names=set(), dev_direct_names=set(), include_dev=False)
            == []
        )

    def test_orphan_transitive_defaults_to_prod(self, tmp_path):
        # An entry reachable from no root (empty direct_names) → PROD.
        (tmp_path / "mix.lock").write_text(
            '%{\n  "orphan" => {:hex, :orphan, "1.0.0", "h", [:mix], [], "hexpm", "h2"},\n}\n'
        )
        deps = parse_mix_lock(
            tmp_path / "mix.lock",
            direct_names=set(),
            dev_direct_names=set(),
            include_dev=False,
        )
        assert deps[0].name == "orphan"
        assert deps[0].group == DependencyGroup.PROD
        assert deps[0].depth == 1  # not in direct_names

    def test_dev_root_with_no_edges(self, tmp_path):
        (tmp_path / "mix.lock").write_text(
            '%{\n  "credo" => {:hex, :credo, "1.7.5", "h", [:mix], [], "hexpm", "h2"},\n}\n'
        )
        deps = parse_mix_lock(
            tmp_path / "mix.lock",
            direct_names={"credo"},
            dev_direct_names={"credo"},
            include_dev=True,
        )
        assert deps[0].group == DependencyGroup.DEV

    def test_non_matching_lines_skipped(self, tmp_path):
        # The %{ and } framing lines and a comment don't match the entry regex.
        (tmp_path / "mix.lock").write_text(
            "%{\n"
            "  # a comment line\n"
            '  "jason" => {:hex, :jason, "1.4.4", "h", [:mix], [], "hexpm", "h2"},\n'
            "}\n"
        )
        deps = parse_mix_lock(
            tmp_path / "mix.lock",
            direct_names={"jason"},
            dev_direct_names=set(),
            include_dev=False,
        )
        assert {d.name for d in deps} == {"jason"}

    def test_both_key_syntaxes_parse(self, tmp_path):
        # `mix deps.get` emits the keyword form ``"name":``; the map-literal
        # ``"name" =>`` form is accepted too. Both must yield the pinned dep.
        tuple_body = '{:hex, :jason, "1.4.4", "h", [:mix], [], "hexpm", "h2"}'
        for sep in (":", "=>"):
            (tmp_path / "mix.lock").write_text(f'%{{\n  "jason" {sep} {tuple_body},\n}}\n')
            deps = parse_mix_lock(
                tmp_path / "mix.lock",
                direct_names={"jason"},
                dev_direct_names=set(),
                include_dev=False,
            )
            assert [(d.name, d.version_constraint) for d in deps] == [("jason", "==1.4.4")]


class TestMixLockHelpers:
    """Direct unit tests for the scanner helpers (branch coverage)."""

    def test_split_top_level_respects_nesting(self):
        edges = '[{:a, "~> 1.0", [opt: true]}, {:b, "2.0"}]'
        body = f':hex, :n, "1.0", "h", [:mix], {edges}, "hexpm", "h2"'
        parts = _split_top_level(body)
        assert parts[0] == ":hex"
        assert parts[2] == '"1.0"'
        # the edge list stays one element despite its inner commas
        assert parts[5] == edges

    def test_split_top_level_empty(self):
        assert _split_top_level("") == []

    def test_split_top_level_string_with_comma(self):
        # A comma inside a string literal must not split.
        assert _split_top_level('"a, b", :c') == ['"a, b"', ":c"]

    def test_first_atom(self):
        assert _first_atom("{:phoenix, ...}") == "phoenix"
        assert _first_atom('"no atom here"') == ""

    def test_unquote(self):
        assert _unquote('"1.4.4"') == "1.4.4"
        assert _unquote("bare") == "bare"
        assert _unquote('"') == '"'  # too short to be a quoted pair

    def test_extract_edges_content_based(self):
        elements = _split_top_level(
            ':hex, :n, "1.0", "h", [:mix], [{:a, "~> 1.0", []}, {:b, "2.0", []}], "hexpm", "h2"'
        )
        assert _extract_edges(elements) == ["a", "b"]

    def test_extract_edges_positional_fallback_both_empty(self):
        # Both list elements empty → can't disambiguate by content; the
        # second list (deps) is taken positionally → no children.
        elements = _split_top_level(':hex, :n, "1.0", "h", [], [], "hexpm", "h2"')
        assert _extract_edges(elements) == []

    def test_extract_edges_single_list_no_deps(self):
        # Only the build-tools list present (no deps list, <2 lists) → empty.
        elements = _split_top_level(':hex, :n, "1.0", "h", [:mix]')
        assert _extract_edges(elements) == []

    def test_extract_edges_skips_atomless_child(self):
        # A malformed child tuple with no atom is skipped defensively.
        elements = _split_top_level(
            ':hex, :n, "1.0", "h", [:mix], [{}, {:b, "2.0", []}], "hexpm", "h2"'
        )
        assert _extract_edges(elements) == ["b"]

    def test_reachable_revisits_diamond(self):
        # A diamond (a→b, a→c, b→d, c→d) exercises the already-seen guard.
        edges = {"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": set()}
        assert _reachable(edges, {"a"}) == {"a", "b", "c", "d"}

    def test_parse_lock_tuple_hex(self, tmp_path):
        hex_name, version, children, origin = _parse_lock_tuple(
            ':hex, :n, "1.0", "h", [:mix], [{:a, "~> 1.0", []}], "hexpm", "h2"', tmp_path, tmp_path
        )
        assert hex_name == "n"
        assert version == "1.0"
        assert children == ["a"]
        assert origin == ""

    def test_parse_lock_tuple_hex_renamed(self, tmp_path):
        # Lock key may differ from the hex package name (`hex: :real` rename);
        # the 2nd tuple element carries the real hex.pm package name.
        hex_name, version, children, origin = _parse_lock_tuple(
            ':hex, :real_pkg, "2.0", "h", [:mix], [], "hexpm", "h2"', tmp_path, tmp_path
        )
        assert hex_name == "real_pkg"
        assert version == "2.0"
        assert origin == ""

    def test_parse_lock_tuple_git(self, tmp_path):
        hex_name, version, children, origin = _parse_lock_tuple(
            ':git, "https://github.com/x/y.git", "sha", [branch: "main"]', tmp_path, tmp_path
        )
        assert hex_name == ""
        assert version == ""
        assert children == []
        assert origin == "git+https://github.com/x/y.git@sha"

    def test_parse_lock_tuple_git_without_a_commit(self, tmp_path):
        body = ':git, "https://token@github.com/x/y.git"'
        assert _parse_lock_tuple(body, tmp_path, tmp_path)[3] == "git+https://github.com/x/y.git"

    def test_parse_lock_tuple_other_scm_keeps_its_name(self, tmp_path):
        body = ':hg, "https://example.org/repo", "tip"'
        assert _parse_lock_tuple(body, tmp_path, tmp_path)[3] == "hg+https://example.org/repo@tip"

    def test_parse_lock_tuple_without_a_location_records_no_source(self, tmp_path):
        assert _parse_lock_tuple(":git", tmp_path, tmp_path)[3] == "unrecorded source"

    def test_parse_lock_tuple_empty(self, tmp_path):
        assert _parse_lock_tuple("", tmp_path, tmp_path) == ("", "", [], "")

    def test_parse_lock_tuple_hex_no_version(self, tmp_path):
        # Defensive: a :hex tuple truncated before the version element.
        hex_name, version, children, origin = _parse_lock_tuple(":hex, :n", tmp_path, tmp_path)
        assert hex_name == "n"
        assert version == ""
        assert origin == ""

    def test_parse_lock_tuple_hex_without_a_name(self, tmp_path):
        assert _parse_lock_tuple(":hex", tmp_path, tmp_path) == ("", "", [], "")


class TestFindRebarLockfiles:
    def test_finds_lock_in_simple_fixture(self):
        locks = find_rebar_lockfiles(_REBAR_FIXTURES / "simple")
        assert len(locks) == 1
        assert locks[0].name == "rebar.lock"

    def test_empty_when_absent(self, tmp_path):
        assert find_rebar_lockfiles(tmp_path) == []


class TestParseRebarLock:
    def test_level_and_group_attribution(self):
        deps = parse_rebar_lock(
            _REBAR_FIXTURES / "simple" / "rebar.lock",
            dev_direct_names={"meck"},
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert set(by_name) == {"cowlib", "meck", "telemetry", "myfork"}
        # level 0, not a dev-profile dep → PROD direct.
        assert by_name["cowlib"].group == DependencyGroup.PROD
        assert by_name["cowlib"].depth == 0
        # level 0 AND in the rebar.config dev set → DEV.
        assert by_name["meck"].group == DependencyGroup.DEV
        assert by_name["meck"].depth == 0
        # level 1 → transitive, conservative PROD, no ancestors.
        assert by_name["telemetry"].depth == 1
        assert by_name["telemetry"].group == DependencyGroup.PROD
        assert by_name["telemetry"].direct_ancestors == ()

    def test_versions_pinned(self):
        deps = parse_rebar_lock(
            _REBAR_FIXTURES / "simple" / "rebar.lock",
            dev_direct_names={"meck"},
            include_dev=True,
        )
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["cowlib"] == "==2.12.1"
        assert by_name["telemetry"] == "==1.2.1"  # 4-tuple pkg with hash

    def test_git_entry_off_registry(self):
        deps = parse_rebar_lock(
            _REBAR_FIXTURES / "simple" / "rebar.lock",
            dev_direct_names=set(),
            include_dev=True,
        )
        myfork = next(d for d in deps if d.name == "myfork")
        assert myfork.origin == "git+https://github.com/me/myfork.git@abc123"
        assert myfork.source == ""
        assert myfork.version_constraint == ""

    def test_dev_excluded_under_no_dev(self):
        deps = parse_rebar_lock(
            _REBAR_FIXTURES / "simple" / "rebar.lock",
            dev_direct_names={"meck"},
            include_dev=False,
        )
        assert "meck" not in {d.name for d in deps}
        assert {"cowlib", "telemetry", "myfork"} == {d.name for d in deps}

    def test_ecosystem_hex(self):
        deps = parse_rebar_lock(
            _REBAR_FIXTURES / "simple" / "rebar.lock",
            dev_direct_names=set(),
            include_dev=True,
        )
        assert all(d.ecosystem == Ecosystem.HEX for d in deps)

    def test_unreadable_returns_empty(self, tmp_path):
        path = tmp_path / "rebar.lock"
        path.mkdir()
        assert parse_rebar_lock(path, dev_direct_names=set(), include_dev=False) == []

    def test_truncated_entry_skipped(self, tmp_path):
        # A `{<<"` start with no closing brace → _balanced_braces returns None.
        (tmp_path / "rebar.lock").write_text('[{<<"truncated">>')
        deps = parse_rebar_lock(tmp_path / "rebar.lock", dev_direct_names=set(), include_dev=False)
        assert deps == []


class TestRebarLockHelpers:
    def test_balanced_braces(self):
        assert _balanced_braces("{a, b}", 0) == "a, b"

    def test_balanced_braces_unbalanced(self):
        assert _balanced_braces("{a, b", 0) is None

    @staticmethod
    def _parse(elements: list[str], tmp_path: Path):
        return _parse_lock_entry(elements, tmp_path, tmp_path)

    def test_parse_lock_entry_pkg_three_tuple(self, tmp_path):
        elements = ['<<"cowlib">>', '{pkg,<<"cowlib">>,<<"2.12.1">>}', "0"]
        assert self._parse(elements, tmp_path) == ("cowlib", "2.12.1", 0, "")

    def test_parse_lock_entry_pkg_four_tuple(self, tmp_path):
        elements = ['<<"t">>', '{pkg,<<"t">>,<<"1.0">>,<<"hash">>}', "1"]
        assert self._parse(elements, tmp_path) == ("t", "1.0", 1, "")

    def test_parse_lock_entry_git(self, tmp_path):
        elements = ['<<"jsx">>', '{git,"https://x/y.git",{ref,"abc"}}', "0"]
        assert self._parse(elements, tmp_path) == ("jsx", "", 0, "git+https://x/y.git@abc")

    def test_parse_lock_entry_git_subdir_is_a_git_repository(self, tmp_path):
        elements = ['<<"sub">>', '{git_subdir,"https://x/mono.git",{ref,"abc"},"apps/sub"}', "1"]
        assert self._parse(elements, tmp_path) == ("sub", "", 1, "git+https://x/mono.git@abc")

    def test_parse_lock_entry_other_scm_keeps_its_name(self, tmp_path):
        elements = ['<<"old">>', '{hg,"https://x/old",{ref,"tip"}}', "0"]
        assert self._parse(elements, tmp_path) == ("old", "", 0, "hg+https://x/old@tip")

    def test_parse_lock_entry_without_a_url_records_no_source(self, tmp_path):
        elements = ['<<"odd">>', "{raw,something}", "0"]
        assert self._parse(elements, tmp_path) == ("odd", "", 0, "unrecorded source")

    def test_parse_lock_entry_pkg_no_binaries_falls_back_to_entry_name(self, tmp_path):
        # Malformed {pkg} with no name binary → fall back to the entry name.
        assert self._parse(['<<"x">>', "{pkg}", "0"], tmp_path) == ("x", "", 0, "")

    def test_parse_lock_entry_pkg_only_name_no_version(self, tmp_path):
        assert self._parse(['<<"x">>', '{pkg,<<"x">>}', "0"], tmp_path) == ("x", "", 0, "")

    def test_parse_lock_entry_path_outside_the_scanned_directory(self, tmp_path):
        elements = ['<<"near">>', '{path,"../near",{mtime,<<"2024-01-01T00:00:00Z">>}}', "0"]
        assert self._parse(elements, tmp_path) == ("near", "", 0, "../near")

    def test_parse_lock_entry_path_the_scan_reads_is_own_code(self, tmp_path):
        (tmp_path / "apps" / "own").mkdir(parents=True)
        elements = ['<<"own">>', '{path,"apps/own"}', "0"]
        assert self._parse(elements, tmp_path) == ("own", "", 0, None)

    def test_parse_lock_entry_path_without_a_directory_records_no_source(self, tmp_path):
        elements = ['<<"odd">>', "{path,Dir}", "0"]
        assert self._parse(elements, tmp_path) == ("odd", "", 0, "unrecorded source")


class TestRebarLockPathEntries:
    _LOCK = (
        '{"1.2.0",\n'
        '[{<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>},0},\n'
        ' {<<"own">>,{path,"apps/own",{mtime,<<"2024-01-01T00:00:00Z">>}},0},\n'
        ' {<<"near">>,{path,"../near",{mtime,<<"2024-01-01T00:00:00Z">>}},0}]}.\n'
    )

    def test_path_entry_the_scan_reads_has_no_row(self, tmp_path):
        project = tmp_path / "project"
        (project / "apps" / "own").mkdir(parents=True)
        (project / "rebar.lock").write_text(self._LOCK, encoding="utf-8")
        deps = parse_rebar_lock(project / "rebar.lock", dev_direct_names=set(), include_dev=True)
        assert [(d.name, d.version_constraint, d.origin) for d in deps] == [
            ("cowlib", "==2.12.1", ""),
            ("near", "", "../near"),
        ]

    def test_path_is_judged_against_the_scanned_directory(self, tmp_path):
        # The lockfile is in a subdirectory: ``../near`` leaves that directory
        # but not the scan, where it is a directory the walk enters.
        project = tmp_path / "project"
        (project / "sub" / "apps" / "own").mkdir(parents=True)
        (project / "near").mkdir()
        lock = project / "sub" / "rebar.lock"
        lock.write_text(self._LOCK, encoding="utf-8")
        alone = parse_rebar_lock(lock, dev_direct_names=set(), include_dev=True)
        assert [d.name for d in alone] == ["cowlib", "near"]
        whole = parse_rebar_lock(lock, dev_direct_names=set(), include_dev=True, scan_root=project)
        assert [d.name for d in whole] == ["cowlib"]
