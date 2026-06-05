"""Tests for the Gemfile.lock parser."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.ruby.lockfiles import (
    attach_direct_sources,
    find_gemfile_lockfiles,
    is_off_registry_marker,
    parse_gemfile_lock,
)
from licenseal.models import DependencyGroup, Ecosystem

_FIXTURES = Path(__file__).parent / "fixtures" / "gemfile"


def _direct_names() -> set[str]:
    """Direct gem names declared in the simple fixture's Gemfile."""
    return {
        "rails",
        "pg",
        "puma",
        "rspec-rails",
        "factory_bot_rails",
        "rubocop",
        "byebug",
        "edge",
        "vendored",
        "shorthand",
        "nokogiri",
    }


def _dev_direct_names() -> set[str]:
    return {"rspec-rails", "factory_bot_rails", "rubocop", "byebug"}


class TestFindGemfileLockfiles:
    def test_finds_lock_in_simple_fixture(self):
        locks = find_gemfile_lockfiles(_FIXTURES / "simple")
        assert len(locks) == 1
        assert locks[0].name == "Gemfile.lock"

    def test_empty_when_absent(self, tmp_path):
        assert find_gemfile_lockfiles(tmp_path) == []


class TestParseGemfileLock:
    def test_prod_specs_no_dev_excluded(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=False,
        )
        names = {d.name for d in deps}
        assert {"rails", "actionpack", "activesupport", "rack", "tzinfo", "nokogiri"} <= names
        # DEV-only branches dropped.
        assert "rspec-rails" not in names
        assert "rubocop" not in names
        assert "byebug" not in names

    def test_dev_included_when_flag_set(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        dev_names = {d.name for d in deps if d.group == DependencyGroup.DEV}
        assert "rspec-rails" in dev_names
        assert "rspec-core" in dev_names  # transitive of dev root
        assert "rubocop" in dev_names

    def test_platform_suffix_stripped(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        nokogiri = next(d for d in deps if d.name == "nokogiri")
        assert nokogiri.version_constraint == "==1.16.0"

    def test_direct_vs_transitive_depth(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["rails"].depth == 0
        assert by_name["actionpack"].depth == 1  # transitive of rails

    def test_pinned_version_double_equals(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["rails"] == "==7.1.3.2"
        assert by_name["pg"] == "==1.5.4"

    def test_direct_ancestors_attributed(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        # activesupport is reachable from both rails and actionpack-via-rails
        # so its only direct ancestor is rails.
        assert "rails" in by_name["activesupport"].direct_ancestors
        # rack is reached only via actionpack which is reached via rails
        assert "rails" in by_name["rack"].direct_ancestors

    def test_off_registry_marker_on_git_path_specs(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        edge = next(d for d in deps if d.name == "edge")
        assert is_off_registry_marker(edge.source)
        vendored = next(d for d in deps if d.name == "vendored")
        assert is_off_registry_marker(vendored.source)

    def test_ecosystem_stamped_as_ruby(self):
        deps = parse_gemfile_lock(
            _FIXTURES / "simple" / "Gemfile.lock",
            direct_names=_direct_names(),
            dev_direct_names=_dev_direct_names(),
            include_dev=True,
        )
        assert all(d.ecosystem == Ecosystem.RUBY for d in deps)

    def test_unreadable_lockfile_returns_empty(self, tmp_path):
        path = tmp_path / "Gemfile.lock"
        path.mkdir()  # OSError on read_text
        assert (
            parse_gemfile_lock(
                path,
                direct_names=set(),
                dev_direct_names=set(),
                include_dev=False,
            )
            == []
        )

    def test_empty_lockfile_returns_empty(self, tmp_path):
        path = tmp_path / "Gemfile.lock"
        path.write_text("")
        assert (
            parse_gemfile_lock(
                path,
                direct_names=set(),
                dev_direct_names=set(),
                include_dev=False,
            )
            == []
        )

    def test_fallback_to_dependencies_section_when_no_direct_set(self, tmp_path):
        # No Gemfile → direct_names empty. Parser falls back to lockfile's
        # DEPENDENCIES section to mark direct deps.
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    rails (7.0.0)\n"
            "      activesupport (= 7.0.0)\n"
            "    activesupport (7.0.0)\n"
            "\n"
            "DEPENDENCIES\n"
            "  rails (~> 7.0)\n"
            "\n"
        )
        deps = parse_gemfile_lock(
            tmp_path / "Gemfile.lock",
            direct_names=set(),
            dev_direct_names=set(),
            include_dev=False,
        )
        by_name = {d.name: d for d in deps}
        assert by_name["rails"].depth == 0
        assert by_name["activesupport"].depth == 1

    def test_orphan_transitive_defaults_to_prod(self, tmp_path):
        # An entry not reachable from any root (no DEPENDENCIES section,
        # empty direct_names) defaults to PROD.
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    orphan (1.0.0)\n\n"
        )
        deps = parse_gemfile_lock(
            tmp_path / "Gemfile.lock",
            direct_names=set(),
            dev_direct_names=set(),
            include_dev=False,
        )
        assert deps[0].name == "orphan"
        assert deps[0].group == DependencyGroup.PROD

    def test_dev_root_with_no_edges(self, tmp_path):
        # A direct dev gem with no transitives — should still be DEV.
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    rubocop (1.59.0)\n"
            "\n"
            "DEPENDENCIES\n"
            "  rubocop\n"
            "\n"
        )
        deps = parse_gemfile_lock(
            tmp_path / "Gemfile.lock",
            direct_names={"rubocop"},
            dev_direct_names={"rubocop"},
            include_dev=True,
        )
        assert deps[0].group == DependencyGroup.DEV

    def test_malformed_spec_line_skipped(self, tmp_path):
        # 4-space spec line with no parsable name (empty after rstrip("!"))
        # is skipped silently.
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    !\n    real (1.0.0)\n\n"
        )
        deps = parse_gemfile_lock(
            tmp_path / "Gemfile.lock",
            direct_names=set(),
            dev_direct_names=set(),
            include_dev=False,
        )
        assert {d.name for d in deps} == {"real"}


class TestParseSpecLineHelpers:
    """Direct unit tests for the spec/dep line helpers (defensive branches)."""

    def test_parse_spec_line_empty(self):
        from licenseal.discovery.ruby.lockfiles import _parse_spec_line

        assert _parse_spec_line("!") == ("", "")
        assert _parse_spec_line("") == ("", "")

    def test_parse_spec_line_no_parens(self):
        from licenseal.discovery.ruby.lockfiles import _parse_spec_line

        # Lenient: name with no version segment.
        assert _parse_spec_line("orphan") == ("orphan", "")

    def test_parse_spec_line_normal(self):
        from licenseal.discovery.ruby.lockfiles import _parse_spec_line

        assert _parse_spec_line("rails (7.1.3)") == ("rails", "7.1.3")

    def test_parse_spec_line_platform_stripped(self):
        from licenseal.discovery.ruby.lockfiles import _parse_spec_line

        assert _parse_spec_line("nokogiri (1.16.0-x86_64-linux)") == (
            "nokogiri",
            "1.16.0",
        )

    def test_parse_dep_line_empty(self):
        from licenseal.discovery.ruby.lockfiles import _parse_dep_line

        assert _parse_dep_line("!") == ""
        assert _parse_dep_line("") == ""

    def test_parse_dep_line_no_parens(self):
        from licenseal.discovery.ruby.lockfiles import _parse_dep_line

        # Lenient: name with no constraint.
        assert _parse_dep_line("rails") == "rails"

    def test_parse_dep_line_with_constraint(self):
        from licenseal.discovery.ruby.lockfiles import _parse_dep_line

        assert _parse_dep_line("rails (~> 7.0)") == "rails"

    def test_indent_level_zero_for_unindented_line(self):
        from licenseal.discovery.ruby.lockfiles import _indent_level

        assert _indent_level("GEM") == 0

    def test_indent_level_counts_spaces(self):
        from licenseal.discovery.ruby.lockfiles import _indent_level

        assert _indent_level("    spec") == 4
        assert _indent_level("      child") == 6

    def test_indent_level_all_spaces_returns_length(self):
        from licenseal.discovery.ruby.lockfiles import _indent_level

        # Defensive: a whitespace-only line should still return the count
        # rather than hanging or erroring.
        assert _indent_level("    ") == 4
        assert _indent_level("") == 0

    def test_six_space_before_any_spec_ignored(self, tmp_path):
        # Defensive: a 6-space line appearing before any 4-space spec.
        # Real Bundler output never produces this, but the parser must
        # not crash if it does.
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "      orphan-child (1.0.0)\n"  # 6-space without preceding 4-space
            "    rails (7.1.3)\n"
            "\n"
        )
        deps = parse_gemfile_lock(
            tmp_path / "Gemfile.lock",
            direct_names={"rails"},
            dev_direct_names=set(),
            include_dev=False,
        )
        # rails parses normally; the orphan-child 6-space line is dropped.
        assert {d.name for d in deps} == {"rails"}


class TestAttachDirectSources:
    def test_stamps_depth0_source(self):
        from licenseal.models import Dependency

        deps = [
            Dependency(
                name="rails",
                version_constraint="==7.0",
                ecosystem=Ecosystem.RUBY,
                group=DependencyGroup.PROD,
                depth=0,
            ),
            Dependency(
                name="activesupport",
                version_constraint="==7.0",
                ecosystem=Ecosystem.RUBY,
                depth=1,
            ),
        ]
        out = attach_direct_sources(deps, {"rails": "Gemfile"})
        by_name = {d.name: d for d in out}
        assert by_name["rails"].source == "Gemfile"
        assert by_name["activesupport"].source == ""

    def test_preserves_off_registry_marker(self):
        from licenseal.discovery.ruby.lockfiles import _OFF_REGISTRY_MARKER
        from licenseal.models import Dependency

        deps = [
            Dependency(
                name="edge",
                version_constraint="==0.0.1",
                ecosystem=Ecosystem.RUBY,
                group=DependencyGroup.PROD,
                depth=0,
                source=_OFF_REGISTRY_MARKER,
            ),
        ]
        out = attach_direct_sources(deps, {"edge": "Gemfile"})
        assert is_off_registry_marker(out[0].source)

    def test_no_match_keeps_empty_source(self):
        from licenseal.models import Dependency

        deps = [
            Dependency(
                name="solo",
                version_constraint="==1.0",
                ecosystem=Ecosystem.RUBY,
                depth=0,
            )
        ]
        out = attach_direct_sources(deps, {})
        assert out[0].source == ""
