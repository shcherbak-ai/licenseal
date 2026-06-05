"""Tests for the top-level discovery module."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from licenseal.discovery import discover_all_dependencies
from licenseal.models import Ecosystem


class TestDiscoverAll:
    def test_deduplication(self, tmp_path):
        """Same package in pyproject.toml and requirements.txt — keep first."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = ["requests>=2.28"]
            """)
        )
        (tmp_path / "requirements.txt").write_text("requests>=2.0\n")

        deps, _ = discover_all_dependencies(tmp_path)
        req_deps = [d for d in deps if d.name.lower() == "requests"]
        assert len(req_deps) == 1
        assert req_deps[0].version_constraint == ">=2.28"  # from pyproject

    def test_mixed_ecosystems(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = ["flask>=3.0"]
            """)
        )
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "^18.0"}}))
        deps, _ = discover_all_dependencies(tmp_path)
        ecosystems = {d.ecosystem for d in deps}
        assert Ecosystem.PYTHON in ecosystems
        assert Ecosystem.NPM in ecosystems

    def test_empty_project(self, tmp_path):
        deps, _ = discover_all_dependencies(tmp_path)
        assert deps == []

    def test_case_insensitive_dedup(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = ["Flask>=3.0"]
            """)
        )
        (tmp_path / "requirements.txt").write_text("flask>=2.0\n")

        deps, _ = discover_all_dependencies(tmp_path)
        flask_deps = [d for d in deps if d.name.lower() == "flask"]
        assert len(flask_deps) == 1

    def test_dedup_prefers_prod_over_dev(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = []

            [project.optional-dependencies]
            dev = ["requests>=2.28"]
            """)
        )
        (tmp_path / "requirements.txt").write_text("requests>=2.0\n")

        deps, _ = discover_all_dependencies(tmp_path)
        requests_dep = next(d for d in deps if d.name.lower() == "requests")
        assert requests_dep.group.value == "prod"
        assert requests_dep.version_constraint == ">=2.0"


class TestPolyglotDiscovery:
    """Real-world polyglot layouts (Tauri = Rust+TS, ML projects = Python+JS,
    Python+npm+Rust hybrids). All three ecosystems must be discovered from
    one scan, with no cross-ecosystem dedup collisions."""

    def test_all_three_ecosystems_coexist(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "polyglot"
            dependencies = ["flask>=3.0", "httpx>=0.27"]
            """)
        )
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "polyglot-web",
                    "dependencies": {"react": "^18.0.0", "react-dom": "^18.0.0"},
                }
            )
        )
        (tmp_path / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "polyglot-rs"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            tokio = "1.0"
            """)
        )

        deps, _ = discover_all_dependencies(tmp_path)
        by_eco = {e: sorted(d.name for d in deps if d.ecosystem == e) for e in Ecosystem}
        assert by_eco[Ecosystem.PYTHON] == ["flask", "httpx"]
        assert by_eco[Ecosystem.NPM] == ["react", "react-dom"]
        assert by_eco[Ecosystem.RUST] == ["serde", "tokio"]

    def test_same_name_across_ecosystems_does_not_collapse(self, tmp_path):
        # `serde` exists on crates.io; an npm `serde` package also exists.
        # They are different packages under different licenses — dedup must
        # key on (name, ecosystem), not name alone, or a polyglot project
        # would silently lose one of them.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "p", "dependencies": {"serde": "^0.1.0"}})
        )
        (tmp_path / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "p-rs"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            """)
        )

        deps, _ = discover_all_dependencies(tmp_path)
        serdes = [d for d in deps if d.name == "serde"]
        assert len(serdes) == 2
        assert {d.ecosystem for d in serdes} == {Ecosystem.NPM, Ecosystem.RUST}

    def test_python_npm_polyglot_with_dev_groups(self, tmp_path):
        # Python prod + npm prod + npm dev — three distinct entries, no
        # cross-ecosystem dedup. Mirrors a common polyglot layout (Python
        # backend with JS-side tooling).
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "backend"
            dependencies = ["fastapi>=0.110"]
            """)
        )
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "frontend",
                    "dependencies": {"react": "^18.0.0"},
                    "devDependencies": {"eslint": "^9.0.0"},
                }
            )
        )

        deps, _ = discover_all_dependencies(tmp_path)
        names = {(d.ecosystem, d.name, d.group.value) for d in deps}
        assert (Ecosystem.PYTHON, "fastapi", "prod") in names
        assert (Ecosystem.NPM, "react", "prod") in names
        assert (Ecosystem.NPM, "eslint", "dev") in names


class TestDotnetIntegration:
    """Integration tests for the .NET section of ``discover_all_dependencies``.

    The .NET path stitches .csproj-emitted deps against
    ``Directory.Packages.props`` (CPM) and ``Directory.Build.props`` (MSBuild
    property scope). These tests exercise that cross-file resolution.
    """

    def _write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_csproj_discovery_wires_in(self, tmp_path):
        self._write(
            tmp_path / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>""",
        )
        deps, counts = discover_all_dependencies(tmp_path)
        assert "dotnet" in counts
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert len(dotnet) == 1
        assert dotnet[0].name == "Newtonsoft.Json"
        assert dotnet[0].version_constraint == "13.0.1"

    def test_packages_config_alongside_csproj(self, tmp_path):
        # Migration-state project with both formats — both surface, dedup
        # by (name, ecosystem) happens at the aggregator level.
        self._write(
            tmp_path / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="ModernDep" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        self._write(
            tmp_path / "packages.config",
            """<?xml version="1.0"?>
<packages>
  <package id="LegacyDep" version="2.0" />
</packages>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        names = {d.name for d in deps if d.ecosystem == Ecosystem.DOTNET}
        assert names == {"ModernDep", "LegacyDep"}

    def test_cpm_stitching_fills_missing_version(self, tmp_path):
        # A .csproj with ``<PackageReference Include="X" />`` (no Version)
        # picks up its version from the closest Directory.Packages.props.
        self._write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>""",
        )
        self._write(
            tmp_path / "src" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert len(dotnet) == 1
        assert dotnet[0].name == "Newtonsoft.Json"
        assert dotnet[0].version_constraint == "13.0.1"

    def test_global_package_reference_materialized_as_dev(self, tmp_path):
        # GlobalPackageReference packages apply implicitly to every project under
        # the props subtree (analyzers, source-link tooling); the csproj parser
        # never sees them. The aggregator must materialize each as a direct DEV
        # dependency so its license still gets checked instead of being silently
        # dropped.
        from licenseal.models import DependencyGroup

        self._write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
    <GlobalPackageReference Include="StyleCop.Analyzers" Version="1.2.0-beta.556" />
  </ItemGroup>
</Project>""",
        )
        self._write(
            tmp_path / "src" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = {d.name: d for d in deps if d.ecosystem == Ecosystem.DOTNET}
        assert "StyleCop.Analyzers" in dotnet  # was silently dropped before
        gpr = dotnet["StyleCop.Analyzers"]
        assert gpr.group == DependencyGroup.DEV
        assert gpr.version_constraint == "1.2.0-beta.556"
        assert gpr.depth == 0
        assert gpr.source == "Directory.Packages.props"

    def test_cpm_stitching_closest_ancestor_wins(self, tmp_path):
        # The closer Directory.Packages.props overrides the root.
        self._write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        self._write(
            tmp_path / "src" / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="2.0" />
  </ItemGroup>
</Project>""",
        )
        self._write(
            tmp_path / "src" / "Proj" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert dotnet[0].version_constraint == "2.0"

    def test_build_props_expansion_resolves_property_token(self, tmp_path):
        self._write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <PropertyGroup>
    <LibVersion>3.1.1</LibVersion>
  </PropertyGroup>
</Project>""",
        )
        self._write(
            tmp_path / "src" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="$(LibVersion)" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert dotnet[0].version_constraint == "3.1.1"

    def test_build_props_unresolved_token_stays_literal(self, tmp_path):
        # A property the build-props chain can't resolve stays as a
        # literal $(...) token; the resolver routes to UNKNOWN at scan
        # time but the discovery layer doesn't fabricate values.
        self._write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <PropertyGroup>
    <SomeOtherProp>x</SomeOtherProp>
  </PropertyGroup>
</Project>""",
        )
        self._write(
            tmp_path / "src" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Lib" Version="$(MissingProp)" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert dotnet[0].version_constraint == "$(MissingProp)"

    def test_paket_discovery_wires_in(self, tmp_path):
        self._write(tmp_path / "paket.dependencies", "nuget Newtonsoft.Json ~> 13.0\n")
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert any(d.name == "Newtonsoft.Json" for d in dotnet)

    def test_detect_project_license_checks_csproj_when_no_other_source(self, tmp_path):
        from licenseal.discovery import detect_project_license

        self._write(
            tmp_path / "Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
  </PropertyGroup>
</Project>""",
        )
        assert detect_project_license(tmp_path) == "MIT"

    def test_dotnet_filter_count_in_local_filter_counts(self, tmp_path):
        # Even a project with no .NET files has the ``dotnet`` key in
        # local_filter_counts (always present, value 0).
        deps, counts = discover_all_dependencies(tmp_path)
        assert deps == []
        assert "dotnet" in counts
        assert counts["dotnet"] == 0

    def test_no_cpm_or_build_props_means_no_stitch_pass(self, tmp_path):
        # When neither file exists, ``_stitch_dotnet_versions`` short-
        # circuits (no work to do). Just confirm the regular discovery
        # output flows through unchanged.
        self._write(
            tmp_path / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Concrete" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert dotnet[0].version_constraint == "1.0"

    def test_non_dotnet_deps_passthrough_in_stitcher(self, tmp_path):
        # Python deps flow through the stitcher unchanged — the function
        # only touches Ecosystem.DOTNET deps.
        self._write(
            tmp_path / "pyproject.toml",
            """[project]
name = "x"
version = "0.1"
dependencies = ["fastapi>=0.110"]
""",
        )
        self._write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>""",
        )
        self._write(
            tmp_path / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        python = [d for d in deps if d.ecosystem == Ecosystem.PYTHON]
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert any(d.name == "fastapi" for d in python)
        assert dotnet[0].version_constraint == "13.0.1"

    def test_csproj_dep_without_source_passthrough(self, tmp_path):
        # Edge case: if a .NET Dependency somehow has empty source (shouldn't
        # happen with the current parser but the stitcher guards against
        # it), the stitcher must leave it alone.
        # Achieved via a Paket dep — its source field is the paket.dependencies
        # relative path so it's non-empty, but the stitcher skips it because
        # paket deps don't use CPM/build-props.
        self._write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>""",
        )
        self._write(tmp_path / "paket.dependencies", "nuget Newtonsoft.Json\n")
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        # Paket dep was emitted with empty version (no constraint after
        # the package name); CPM only applies to .csproj-source
        # deps, so this stays empty.
        paket = next(d for d in dotnet if d.source == "paket.dependencies")
        assert paket.version_constraint == ""

    def test_dotnet_dep_with_empty_source_passthrough_in_stitcher(self):
        # Direct unit test for ``_stitch_dotnet_versions``: a Dependency
        # carrying ecosystem=DOTNET but empty source skips the stitching
        # logic (defensive guard against malformed callers).
        from licenseal.discovery import _stitch_dotnet_versions
        from licenseal.discovery.dotnet import CpmData
        from licenseal.models import Dependency, DependencyGroup

        dep_no_source = Dependency(
            name="X",
            version_constraint="",
            ecosystem=Ecosystem.DOTNET,
            group=DependencyGroup.PROD,
            source="",
        )
        # Provide non-empty cpm_files so the early-exit short-circuit
        # doesn't fire; the loop must reach the per-dep guard and
        # passthrough.
        cpm_files = {
            Path("/somewhere"): CpmData(versions={"x": "1.0"}),
        }
        out = _stitch_dotnet_versions(
            [dep_no_source],
            project_path=Path("/project"),
            cpm_files=cpm_files,
            build_props_files={},
        )
        assert out == [dep_no_source]

    def test_cpm_present_but_package_not_declared_keeps_empty(self, tmp_path):
        # The CPM file exists but doesn't declare this specific package's
        # version → ``lookup_version`` returns empty and the dep retains
        # its empty version_constraint.
        self._write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="OtherPackage" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        self._write(
            tmp_path / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="UndeclaredInCpm" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        # Version remains empty (CPM doesn't supply it); the resolver
        # later routes to UNKNOWN.
        target = next(d for d in dotnet if d.name == "UndeclaredInCpm")
        assert target.version_constraint == ""

    def test_property_token_with_no_applicable_build_props_stays_literal(self, tmp_path):
        # A Directory.Build.props exists in a sibling tree (NOT an ancestor),
        # so ``closest_build_props`` returns empty for our project. The
        # property token stays literal.
        self._write(
            tmp_path / "unrelated" / "Directory.Build.props",
            """<Project>
  <PropertyGroup>
    <SomeVar>nope</SomeVar>
  </PropertyGroup>
</Project>""",
        )
        self._write(
            tmp_path / "src" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="$(MissingProp)" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert dotnet[0].version_constraint == "$(MissingProp)"
