"""Tests for Ruby (Gemfile + *.gemspec) discovery."""

from __future__ import annotations

from pathlib import Path  # noqa: F401 - used by monkeypatch in tests

from licenseal.discovery.ruby.gemfile import (
    collect_dev_direct_names,
    discover_gemfile_dependencies,
)
from licenseal.discovery.ruby.gemspec import (
    _license_array_body_to_raw,
    detect_project_license_gemspec,
    discover_gemspec_dependencies,
    workspace_gemspec_names,
)
from licenseal.discovery.ruby.lockfiles import is_off_registry_marker
from licenseal.models import DependencyGroup, Ecosystem

_FIXTURES = Path(__file__).parent / "fixtures" / "gemfile"


class TestDiscoverGemfileDependencies:
    def test_simple_fixture_extracts_prod_and_dev(self):
        deps, filtered = discover_gemfile_dependencies(_FIXTURES / "simple")
        assert filtered == 0
        names_by_group = {
            DependencyGroup.PROD: {d.name for d in deps if d.group == DependencyGroup.PROD},
            DependencyGroup.DEV: {d.name for d in deps if d.group == DependencyGroup.DEV},
        }
        assert "rails" in names_by_group[DependencyGroup.PROD]
        assert "pg" in names_by_group[DependencyGroup.PROD]
        assert "puma" in names_by_group[DependencyGroup.PROD]
        assert "rspec-rails" in names_by_group[DependencyGroup.DEV]
        assert "factory_bot_rails" in names_by_group[DependencyGroup.DEV]
        assert "rubocop" in names_by_group[DependencyGroup.DEV]
        assert "byebug" in names_by_group[DependencyGroup.DEV]

    def test_version_constraints_preserved(self):
        deps, _ = discover_gemfile_dependencies(_FIXTURES / "simple")
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["rails"] == "~> 7.1.0"
        assert by_name["pg"] == ">= 1.5"
        assert by_name["puma"] == ""

    def test_off_registry_sources_emitted_with_marker(self):
        # git: / path: / github: gems are emitted (not skipped) so their
        # group + direct-ness survive; they carry the off-registry marker
        # so the resolver short-circuits them to UNKNOWN.
        deps, _ = discover_gemfile_dependencies(_FIXTURES / "simple")
        by_name = {d.name: d for d in deps}
        for nm in ("edge", "vendored", "shorthand"):
            assert nm in by_name, nm
            assert is_off_registry_marker(by_name[nm].source)

    def test_ecosystem_and_source_stamped(self):
        deps, _ = discover_gemfile_dependencies(_FIXTURES / "simple")
        for dep in deps:
            assert dep.ecosystem == Ecosystem.RUBY
            # Registry gems carry the manifest path; off-registry gems carry
            # the marker instead.
            if is_off_registry_marker(dep.source):
                continue
            assert dep.source == "Gemfile"

    def test_monorepo_walks_nested_gemfiles(self):
        deps, _ = discover_gemfile_dependencies(_FIXTURES / "monorepo")
        names = {d.name for d in deps}
        assert "rails" in names
        assert "sinatra" in names
        assert "puma" in names
        sources = {d.source for d in deps}
        assert "Gemfile" in sources
        assert any("apps/api/Gemfile" in s for s in sources)

    def test_workspace_internal_filter(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\ngem "internal"\ngem "external"\n'
        )
        deps, filtered = discover_gemfile_dependencies(
            tmp_path, workspace_names=frozenset({"internal"})
        )
        names = {d.name for d in deps}
        assert names == {"external"}
        assert filtered == 1

    def test_comment_stripping(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\n# gem "rejected", "1.0"\ngem "kept" # trailing\n'
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"kept"}

    def test_multiline_continuation(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\ngem "rails",\n  "~> 7.1.0",\n  ">= 7.1.2"\n'
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["rails"] == "~> 7.1.0, >= 7.1.2"

    def test_inline_group_kwarg_array_form(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\ngem "rspec", groups: [:development, :test]\n'
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        assert deps[0].group == DependencyGroup.DEV

    def test_production_group_classified_as_prod(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\ngroup :production do\n  gem "newrelic_rpm"\nend\n'
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        assert deps[0].group == DependencyGroup.PROD

    def test_nested_do_block_inside_group_keeps_group(self, tmp_path):
        # A non-group ``do`` block (platforms) nested inside a group must not
        # pop the group context: gems after the inner block stay DEV.
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\n'
            "group :test do\n"
            '  gem "a"\n'
            "  platforms :mri do\n"
            '    gem "b"\n'
            "  end\n"
            '  gem "c"\n'
            "end\n"
            'gem "d"\n'
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        by_name = {d.name: d.group for d in deps}
        assert by_name["a"] == DependencyGroup.DEV
        assert by_name["b"] == DependencyGroup.DEV
        assert by_name["c"] == DependencyGroup.DEV  # was PROD before the fix
        assert by_name["d"] == DependencyGroup.PROD  # top-level

    def test_nested_keyword_block_inside_group_keeps_group(self, tmp_path):
        # An ``if`` guard (keyword block, no trailing ``do``) nested in a
        # group — same balance via the leading-keyword opener detection.
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\n'
            "group :development do\n"
            '  gem "a"\n'
            '  if RUBY_VERSION >= "3.0"\n'
            '    gem "b"\n'
            "  end\n"
            '  gem "c"\n'
            "end\n"
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        by_name = {d.name: d.group for d in deps}
        assert by_name["a"] == DependencyGroup.DEV
        assert by_name["b"] == DependencyGroup.DEV
        assert by_name["c"] == DependencyGroup.DEV

    def test_stray_end_at_depth_zero_ignored(self, tmp_path):
        # A spurious ``end`` with no open block must not underflow; the gem
        # after it still parses.
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "a"\nend\ngem "b"\n')
        deps, _ = discover_gemfile_dependencies(tmp_path)
        assert {d.name for d in deps} == {"a", "b"}

    def test_top_level_do_block_gems_are_prod(self, tmp_path):
        # A ``do`` block at top level (no enclosing group) → gems PROD; the
        # block's ``end`` pops nothing (no group frames).
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\nplatforms :mri do\n  gem "a"\nend\ngem "b"\n'
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        by_name = {d.name: d.group for d in deps}
        assert by_name["a"] == DependencyGroup.PROD
        assert by_name["b"] == DependencyGroup.PROD

    def test_unreadable_gemfile_skipped(self, tmp_path):
        # Gemfile is a directory — read_text raises OSError. The walker
        # finds it, but the parser drops it silently.
        (tmp_path / "Gemfile").mkdir()
        deps, filtered = discover_gemfile_dependencies(tmp_path)
        # Walker only finds plain files; the directory is invisible to it,
        # so the call returns empty without exercising the OSError branch.
        assert deps == []
        assert filtered == 0

    def test_empty_gem_call_skipped(self, tmp_path):
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem ""\ngem "real"\n')
        deps, _ = discover_gemfile_dependencies(tmp_path)
        assert {d.name for d in deps} == {"real"}

    def test_whitespace_only_gem_name_skipped(self, tmp_path):
        # Regex matches whitespace-only content between quotes; the strip
        # step empties it and the `if not name` branch fires.
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "   "\ngem "real"\n')
        deps, _ = discover_gemfile_dependencies(tmp_path)
        assert {d.name for d in deps} == {"real"}

    def test_duplicate_gem_lines_deduped(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            'source "https://rubygems.org"\ngem "rails"\ngem "rails", "7.0"\n'
        )
        deps, _ = discover_gemfile_dependencies(tmp_path)
        rails = [d for d in deps if d.name == "rails"]
        assert len(rails) == 1

    def test_pending_continuation_at_eof(self, tmp_path):
        # File ends mid-continuation (trailing comma, no closing line) —
        # the pending buffer is flushed at end-of-input.
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "rails",\n')
        deps, _ = discover_gemfile_dependencies(tmp_path)
        assert {d.name for d in deps} == {"rails"}

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        # The walker finds the Gemfile but read_text raises an OSError;
        # the loop's except branch swallows it and continues.
        (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "x"\n')

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        deps, filtered = discover_gemfile_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0


class TestCollectDevDirectNames:
    def test_prod_outranks_dev(self):
        # Gem declared in both prod and dev → final classification is prod;
        # not in dev_direct_names.
        from licenseal.models import Dependency

        deps = [
            Dependency(
                name="rails",
                version_constraint="",
                ecosystem=Ecosystem.RUBY,
                group=DependencyGroup.PROD,
            ),
            Dependency(
                name="rails",
                version_constraint="",
                ecosystem=Ecosystem.RUBY,
                group=DependencyGroup.DEV,
            ),
            Dependency(
                name="rspec",
                version_constraint="",
                ecosystem=Ecosystem.RUBY,
                group=DependencyGroup.DEV,
            ),
        ]
        assert collect_dev_direct_names(deps) == {"rspec"}

    def test_non_ruby_deps_ignored(self):
        from licenseal.models import Dependency

        deps = [
            Dependency(
                name="some-npm-dev",
                version_constraint="",
                ecosystem=Ecosystem.NPM,
                group=DependencyGroup.DEV,
            ),
        ]
        assert collect_dev_direct_names(deps) == set()


class TestDiscoverGemspecDependencies:
    def test_gemspec_only_runtime_and_dev(self):
        deps, _ = discover_gemspec_dependencies(_FIXTURES / "gemspec_only")
        names_by_group = {
            DependencyGroup.PROD: {d.name for d in deps if d.group == DependencyGroup.PROD},
            DependencyGroup.DEV: {d.name for d in deps if d.group == DependencyGroup.DEV},
        }
        assert "rack" in names_by_group[DependencyGroup.PROD]
        assert "puma" in names_by_group[DependencyGroup.PROD]
        assert "rspec" in names_by_group[DependencyGroup.DEV]

    def test_workspace_filter_applied(self, tmp_path):
        (tmp_path / "foo.gemspec").write_text(
            "Gem::Specification.new do |s|\n"
            '  s.name = "foo"\n'
            '  s.add_dependency "internal-sibling"\n'
            '  s.add_dependency "external"\n'
            "end\n"
        )
        deps, filtered = discover_gemspec_dependencies(
            tmp_path, workspace_names=frozenset({"internal-sibling"})
        )
        assert {d.name for d in deps} == {"external"}
        assert filtered == 1

    def test_unreadable_gemspec_skipped(self, tmp_path):
        (tmp_path / "a.gemspec").mkdir()
        deps, _ = discover_gemspec_dependencies(tmp_path)
        assert deps == []

    def test_dep_line_with_no_constraints(self, tmp_path):
        (tmp_path / "x.gemspec").write_text(
            'Gem::Specification.new do |s|\n  s.add_dependency "rack"\nend\n'
        )
        deps, _ = discover_gemspec_dependencies(tmp_path)
        assert deps[0].version_constraint == ""

    def test_duplicate_dep_calls_deduped(self, tmp_path):
        (tmp_path / "x.gemspec").write_text(
            "Gem::Specification.new do |s|\n"
            '  s.add_dependency "rack"\n'
            '  s.add_dependency "rack", "1.0"\n'
            "end\n"
        )
        deps, _ = discover_gemspec_dependencies(tmp_path)
        assert sum(1 for d in deps if d.name == "rack") == 1

    def test_whitespace_only_dep_name_skipped(self, tmp_path):
        # The dep-call regex requires non-empty match but the captured
        # name can be whitespace-only after stripping. Skipped silently.
        (tmp_path / "x.gemspec").write_text(
            "Gem::Specification.new do |s|\n"
            '  s.add_dependency "   "\n'
            '  s.add_dependency "real"\n'
            "end\n"
        )
        deps, _ = discover_gemspec_dependencies(tmp_path)
        assert {d.name for d in deps} == {"real"}

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "x.gemspec").write_text(
            'Gem::Specification.new do |s|\n  s.add_dependency "rack"\nend\n'
        )

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        deps, _ = discover_gemspec_dependencies(tmp_path)
        assert deps == []


class TestWorkspaceGemspecNames:
    def test_extracts_spec_name(self, tmp_path):
        (tmp_path / "alpha.gemspec").write_text(
            'Gem::Specification.new do |s|\n  s.name = "alpha-canonical"\nend\n'
        )
        names = workspace_gemspec_names(tmp_path)
        assert "alpha-canonical" in names

    def test_fallback_to_filename_stem(self, tmp_path):
        (tmp_path / "beta.gemspec").write_text(
            "Gem::Specification.new do |s|\n  s.name = SOMECONST\nend\n"
        )
        names = workspace_gemspec_names(tmp_path)
        assert "beta" in names

    def test_unreadable_gemspec_skipped(self, tmp_path):
        (tmp_path / "broken.gemspec").mkdir()
        assert workspace_gemspec_names(tmp_path) == frozenset()

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "a.gemspec").write_text(
            'Gem::Specification.new do |s|\n  s.name = "real"\nend\n'
        )

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert workspace_gemspec_names(tmp_path) == frozenset()


class TestDetectProjectLicenseGemspec:
    def test_plural_array_joined(self):
        assert detect_project_license_gemspec(_FIXTURES / "gemspec_only") == "MIT OR Apache-2.0"

    def test_singular_string(self, tmp_path):
        (tmp_path / "a.gemspec").write_text(
            'Gem::Specification.new do |s|\n  s.license = "MIT"\nend\n'
        )
        assert detect_project_license_gemspec(tmp_path) == "MIT"

    def test_plural_overrides_singular(self, tmp_path):
        # Plural form preferred when both present.
        (tmp_path / "a.gemspec").write_text(
            "Gem::Specification.new do |s|\n"
            '  s.license = "MIT"\n'
            '  s.licenses = ["Apache-2.0"]\n'
            "end\n"
        )
        assert detect_project_license_gemspec(tmp_path) == "Apache-2.0"

    def test_no_gemspec_returns_empty(self, tmp_path):
        assert detect_project_license_gemspec(tmp_path) == ""

    def test_non_literal_license_returns_empty(self, tmp_path):
        (tmp_path / "a.gemspec").write_text(
            "Gem::Specification.new do |s|\n  s.license = MY_CONST\nend\n"
        )
        assert detect_project_license_gemspec(tmp_path) == ""

    def test_unreadable_gemspec_skipped(self, tmp_path):
        (tmp_path / "x.gemspec").mkdir()
        assert detect_project_license_gemspec(tmp_path) == ""

    def test_multiple_gemspecs_pick_first(self, tmp_path):
        (tmp_path / "a.gemspec").write_text(
            "Gem::Specification.new do |s|\n  s.licenses = []\nend\n"
        )
        (tmp_path / "b.gemspec").write_text(
            'Gem::Specification.new do |s|\n  s.license = "BSD-3-Clause"\nend\n'
        )
        # Plural empty in a.gemspec → skipped; b.gemspec singular wins.
        assert detect_project_license_gemspec(tmp_path) == "BSD-3-Clause"

    def test_read_error_swallowed(self, tmp_path, monkeypatch):
        (tmp_path / "a.gemspec").write_text(
            'Gem::Specification.new do |s|\n  s.license = "MIT"\nend\n'
        )

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert detect_project_license_gemspec(tmp_path) == ""


class TestLicenseArrayBodyToRaw:
    def test_single_string(self):
        assert _license_array_body_to_raw('"MIT"') == "MIT"

    def test_multi_string(self):
        assert _license_array_body_to_raw('"MIT", "Apache-2.0"') == "MIT OR Apache-2.0"

    def test_mixed_quotes(self):
        assert _license_array_body_to_raw("'MIT', \"Apache-2.0\"") == "MIT OR Apache-2.0"

    def test_empty_body(self):
        assert _license_array_body_to_raw("") == ""
        assert _license_array_body_to_raw("   ") == ""
