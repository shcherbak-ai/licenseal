"""Tests for ``Directory.Build.props`` / ``.targets`` discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import collect_read_diagnostics
from licenseal.discovery.dotnet.directory_build_props import (
    _parse_directory_build_props,
    closest_build_props,
    find_directory_build_props,
)
from licenseal.models import DependencyGroup, Ecosystem
from tests._helpers import _NON_RELATIVE_PATH_VALUES, _record_path_io


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# _parse_directory_build_props
# ---------------------------------------------------------------------------


class TestParseDirectoryBuildProps:
    def test_property_group_captured(self):
        text = """<Project>
  <PropertyGroup>
    <NewtonsoftVersion>13.0.1</NewtonsoftVersion>
    <SerilogVersion>3.1.1</SerilogVersion>
  </PropertyGroup>
</Project>"""
        props = _parse_directory_build_props(text)
        assert props == {
            "NewtonsoftVersion": "13.0.1",
            "SerilogVersion": "3.1.1",
        }

    def test_multiple_property_groups_merged(self):
        # Last-write-wins for collisions (MSBuild behavior).
        text = """<Project>
  <PropertyGroup>
    <X>first</X>
    <Y>only-in-first</Y>
  </PropertyGroup>
  <PropertyGroup>
    <X>second</X>
    <Z>only-in-second</Z>
  </PropertyGroup>
</Project>"""
        props = _parse_directory_build_props(text)
        assert props == {"X": "second", "Y": "only-in-first", "Z": "only-in-second"}

    def test_empty_values_skipped(self):
        # An empty <Version></Version> in props mustn't shadow a meaningful
        # value supplied elsewhere; drop it during parse.
        text = """<Project>
  <PropertyGroup>
    <Empty></Empty>
    <Real>1.0</Real>
  </PropertyGroup>
</Project>"""
        props = _parse_directory_build_props(text)
        assert props == {"Real": "1.0"}

    def test_unrelated_root_child_ignored(self):
        # <Target>, <ItemGroup>, <Import> don't carry properties.
        text = """<Project>
  <Target Name="X" />
  <ItemGroup>
    <Compile Include="foo.cs" />
  </ItemGroup>
  <PropertyGroup>
    <Lib>1.0</Lib>
  </PropertyGroup>
</Project>"""
        props = _parse_directory_build_props(text)
        assert props == {"Lib": "1.0"}

    def test_namespaced_legacy_props(self):
        # Pre-SDK-style props files carry MSBuild 2003 namespace.
        text = """<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <Lib>1.0</Lib>
  </PropertyGroup>
</Project>"""
        props = _parse_directory_build_props(text)
        assert props == {"Lib": "1.0"}

    def test_malformed_returns_none(self):
        assert _parse_directory_build_props("<not closed") is None

    def test_billion_laughs_returns_none(self):
        billion = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<Project>
  <PropertyGroup>
    <X>&lol2;</X>
  </PropertyGroup>
</Project>"""
        assert _parse_directory_build_props(billion) is None

    def test_xxe_returns_none(self):
        xxe = """<?xml version="1.0"?>
<!DOCTYPE Project [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Project>
  <PropertyGroup>
    <X>&xxe;</X>
  </PropertyGroup>
</Project>"""
        assert _parse_directory_build_props(xxe) is None


# ---------------------------------------------------------------------------
# find_directory_build_props
# ---------------------------------------------------------------------------


class TestFindDirectoryBuildProps:
    def test_props_file_found(self, tmp_path):
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <PropertyGroup>
    <Lib>1.0</Lib>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result == {tmp_path: {"Lib": "1.0"}}

    def test_targets_file_also_supported(self, tmp_path):
        _write(
            tmp_path / "Directory.Build.targets",
            """<Project>
  <PropertyGroup>
    <Targets>yes</Targets>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result == {tmp_path: {"Targets": "yes"}}

    def test_props_wins_over_targets_in_same_dir(self, tmp_path):
        # When both files exist in the same directory and declare the
        # same property, .props overrides .targets (closer to MSBuild's
        # actual ordering — .props is loaded before .targets).
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <PropertyGroup>
    <Shared>from-props</Shared>
    <OnlyInProps>props-value</OnlyInProps>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.targets",
            """<Project>
  <PropertyGroup>
    <Shared>from-targets</Shared>
    <OnlyInTargets>targets-value</OnlyInTargets>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        merged = result[tmp_path]
        assert merged["Shared"] == "from-props"
        assert merged["OnlyInProps"] == "props-value"
        assert merged["OnlyInTargets"] == "targets-value"

    def test_nested_files_independently_indexed(self, tmp_path):
        _write(
            tmp_path / "Directory.Build.props",
            """<Project><PropertyGroup><Root>r</Root></PropertyGroup></Project>""",
        )
        _write(
            tmp_path / "src" / "Directory.Build.props",
            """<Project><PropertyGroup><Src>s</Src></PropertyGroup></Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result[tmp_path] == {"Root": "r"}
        assert result[tmp_path / "src"] == {"Src": "s"}

    def test_unreadable_file_skipped(self, tmp_path, monkeypatch):
        _write(
            tmp_path / "Directory.Build.props",
            """<Project><PropertyGroup><X>1</X></PropertyGroup></Project>""",
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "Directory.Build.props":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        result = find_directory_build_props(tmp_path)
        assert result == {}

    def test_malformed_file_skipped(self, tmp_path):
        _write(tmp_path / "Directory.Build.props", "<not closed")
        _write(
            tmp_path / "good" / "Directory.Build.props",
            """<Project><PropertyGroup><X>1</X></PropertyGroup></Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert tmp_path not in result
        assert (tmp_path / "good") in result

    def test_empty_props_file_dropped(self, tmp_path):
        # A valid XML props file with no PropertyGroup content produces an
        # empty dict; the directory is dropped from the result map (only
        # non-empty files survive).
        _write(tmp_path / "Directory.Build.props", """<Project></Project>""")
        result = find_directory_build_props(tmp_path)
        assert result == {}


# ---------------------------------------------------------------------------
# closest_build_props
# ---------------------------------------------------------------------------


class TestClosestBuildProps:
    def test_immediate_directory_match(self, tmp_path):
        build_props = {
            tmp_path / "src" / "Proj": {"X": "1"},
        }
        result = closest_build_props(tmp_path / "src" / "Proj" / "App.csproj", build_props)
        assert result == {"X": "1"}

    def test_ancestor_match(self, tmp_path):
        build_props = {
            tmp_path: {"X": "1"},
        }
        result = closest_build_props(tmp_path / "src" / "App.csproj", build_props)
        assert result == {"X": "1"}

    def test_merge_across_ancestor_chain_closer_wins(self, tmp_path):
        # Root declares X=root, Y=root. ``src/`` overrides X=src.
        # Final scope at src/App.csproj: X=src (closer wins), Y=root.
        build_props = {
            tmp_path: {"X": "root", "Y": "root"},
            tmp_path / "src": {"X": "src"},
        }
        result = closest_build_props(tmp_path / "src" / "App.csproj", build_props)
        assert result == {"X": "src", "Y": "root"}

    def test_unique_property_at_root_visible_at_leaf(self, tmp_path):
        # The closest ancestor doesn't redeclare; the leaf still inherits.
        build_props = {
            tmp_path: {"OnlyAtRoot": "value"},
            tmp_path / "src": {"OnlyAtSrc": "src-value"},
        }
        result = closest_build_props(tmp_path / "src" / "Proj" / "App.csproj", build_props)
        assert result == {"OnlyAtRoot": "value", "OnlyAtSrc": "src-value"}

    def test_no_props_returns_empty(self, tmp_path):
        result = closest_build_props(tmp_path / "App.csproj", {})
        assert result == {}

    def test_no_ancestor_match_returns_empty(self, tmp_path):
        # Props exist but in a sibling tree, not an ancestor.
        build_props = {
            tmp_path / "unrelated": {"X": "1"},
        }
        result = closest_build_props(tmp_path / "src" / "App.csproj", build_props)
        assert result == {}


def _dotnet_rows(project: Path) -> list[tuple[str, str, DependencyGroup, str]]:
    """``(name, version, group, source)`` of every .NET dep discovery finds on disk."""
    deps, _ = discover_all_dependencies(project)
    return [
        (d.name, d.version_constraint, d.group, d.source)
        for d in deps
        if d.ecosystem == Ecosystem.DOTNET
    ]


def _project(*references: str) -> str:
    return (
        '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n'
        + "".join(f"    {reference}\n" for reference in references)
        + "  </ItemGroup>\n</Project>\n"
    )


class TestDirectoryBuildPackageReferences:
    """``<PackageReference>`` items declared in ``Directory.Build.props`` /
    ``.targets`` are direct dependencies, read from files on disk through the
    aggregator, with versions stitched like a project file's references.
    """

    def test_references_in_props_and_targets_are_direct_dependencies(self, tmp_path):
        _write(
            tmp_path / "Directory.Build.props",
            _project(
                '<PackageReference Include="Shared.Lib" Version="1.0.0" />',
                '<PackageReference Include="Shared.Tool" Version="2.0.0" PrivateAssets="all" />',
            ),
        )
        _write(
            tmp_path / "Directory.Build.targets",
            _project(
                '<PackageReference Include="Late.Lib" Version="3.0.0" />',
                '<PackageReference Include="Late.Tool"><Version>4.0.0</Version>'
                "<PrivateAssets>all</PrivateAssets></PackageReference>",
            ),
        )
        _write(
            tmp_path / "src" / "App" / "App.csproj",
            _project('<PackageReference Include="Own.Lib" Version="5.0.0" />'),
        )
        assert _dotnet_rows(tmp_path) == [
            ("Own.Lib", "5.0.0", DependencyGroup.PROD, "src/App/App.csproj"),
            ("Shared.Lib", "1.0.0", DependencyGroup.PROD, "Directory.Build.props"),
            ("Shared.Tool", "2.0.0", DependencyGroup.DEV, "Directory.Build.props"),
            ("Late.Lib", "3.0.0", DependencyGroup.PROD, "Directory.Build.targets"),
            ("Late.Tool", "4.0.0", DependencyGroup.DEV, "Directory.Build.targets"),
        ]

    def test_reference_is_emitted_without_a_project_file_beneath(self, tmp_path):
        # The projects the file applies to can be of a kind discovery does
        # not read; the reference is reported either way.
        _write(
            tmp_path / "native" / "Directory.Build.props",
            _project('<PackageReference Include="Shared.Lib" Version="1.0.0" />'),
        )
        assert _dotnet_rows(tmp_path) == [
            ("Shared.Lib", "1.0.0", DependencyGroup.PROD, "native/Directory.Build.props")
        ]

    def test_cpm_versions_and_property_tokens_are_stitched(self, tmp_path):
        # Versionless references take the Central Package Management version;
        # $(Property) tokens expand from the file itself, from the other
        # Directory.Build file beside it, from a file it imports, and from an
        # ancestor's Directory.Build.props.
        _write(
            tmp_path / "Directory.Packages.props",
            _project(
                '<PackageVersion Include="Cpm.Lib" Version="1.0.0" />',
                '<PackageVersion Include="Cpm.Nested" Version="1.5.0" />',
            ),
        )
        _write(
            tmp_path / "eng" / "Versions.props",
            "<Project><PropertyGroup><ImportedVersion>2.0.0</ImportedVersion>"
            "</PropertyGroup></Project>",
        )
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="eng\\Versions.props" />
  <PropertyGroup>
    <OwnVersion>3.0.0</OwnVersion>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Cpm.Lib" />
    <PackageReference Include="Own.Lib" Version="$(OwnVersion)" />
    <PackageReference Include="Imported.Lib" Version="$(ImportedVersion)" />
    <PackageReference Include="Sibling.Lib" Version="$(TargetsVersion)" />
    <PackageReference Include="Missing.Lib" Version="$(NotDeclared)" />
    <PackageReference Include="Unmanaged.Lib" />
  </ItemGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.targets",
            "<Project><PropertyGroup><TargetsVersion>4.0.0</TargetsVersion>"
            "</PropertyGroup></Project>",
        )
        _write(
            tmp_path / "src" / "Directory.Build.targets",
            _project(
                '<PackageReference Include="Cpm.Nested" />',
                '<PackageReference Include="Ancestor.Lib" Version="$(OwnVersion)" />',
            ),
        )
        assert _dotnet_rows(tmp_path) == [
            ("Cpm.Lib", "1.0.0", DependencyGroup.PROD, "Directory.Build.props"),
            ("Own.Lib", "3.0.0", DependencyGroup.PROD, "Directory.Build.props"),
            ("Imported.Lib", "2.0.0", DependencyGroup.PROD, "Directory.Build.props"),
            ("Sibling.Lib", "4.0.0", DependencyGroup.PROD, "Directory.Build.props"),
            ("Missing.Lib", "$(NotDeclared)", DependencyGroup.PROD, "Directory.Build.props"),
            ("Unmanaged.Lib", "", DependencyGroup.PROD, "Directory.Build.props"),
            ("Cpm.Nested", "1.5.0", DependencyGroup.PROD, "src/Directory.Build.targets"),
            ("Ancestor.Lib", "3.0.0", DependencyGroup.PROD, "src/Directory.Build.targets"),
        ]

    def test_references_in_imported_files_are_emitted(self, tmp_path):
        # A Directory.Build file's <Import> chain is part of it: references
        # in the imported files are reported under the importing
        # Directory.Build file, with that file's property scope.
        _write(
            tmp_path / "eng" / "Analyzers.props",
            _project(
                '<PackageReference Include="Nested.Analyzer" Version="1.0.0" PrivateAssets="all" />'
            ),
        )
        _write(
            tmp_path / "eng" / "Packages.props",
            """<Project>
  <Import Project="Analyzers.props" />
  <ItemGroup>
    <PackageReference Include="Imported.Lib" Version="$(ImportedVersion)" />
  </ItemGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="eng/Packages.props" />
  <PropertyGroup>
    <ImportedVersion>2.0.0</ImportedVersion>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Own.Lib" Version="3.0.0" />
  </ItemGroup>
</Project>""",
        )
        assert _dotnet_rows(tmp_path) == [
            ("Nested.Analyzer", "1.0.0", DependencyGroup.DEV, "Directory.Build.props"),
            ("Imported.Lib", "2.0.0", DependencyGroup.PROD, "Directory.Build.props"),
            ("Own.Lib", "3.0.0", DependencyGroup.PROD, "Directory.Build.props"),
        ]

    def test_choose_branches_in_a_build_file_are_unioned(self, tmp_path):
        _write(
            tmp_path / "Directory.Build.targets",
            """<Project>
  <Choose>
    <When Condition="'$(TargetFrameworkIdentifier)' == '.NETFramework'">
      <ItemGroup>
        <PackageReference Include="Framework.Lib" Version="1.0.0" />
      </ItemGroup>
    </When>
    <Otherwise>
      <ItemGroup>
        <PackageReference Include="Core.Lib" Version="2.0.0" />
      </ItemGroup>
    </Otherwise>
  </Choose>
</Project>""",
        )
        assert _dotnet_rows(tmp_path) == [
            ("Framework.Lib", "1.0.0", DependencyGroup.PROD, "Directory.Build.targets"),
            ("Core.Lib", "2.0.0", DependencyGroup.PROD, "Directory.Build.targets"),
        ]

    def test_production_reference_wins_over_a_dev_one_for_the_same_package(self, tmp_path):
        # Dev in the Directory.Build file and production in a project, and
        # the other way round: either way the package ships.
        _write(
            tmp_path / "Directory.Build.props",
            _project(
                '<PackageReference Include="Dev.Above" Version="1.0.0" PrivateAssets="all" />',
                '<PackageReference Include="Prod.Above" Version="2.0.0" />',
            ),
        )
        _write(
            tmp_path / "App.csproj",
            _project(
                '<PackageReference Include="Dev.Above" Version="1.0.0" />',
                '<PackageReference Include="Prod.Above" Version="2.0.0" PrivateAssets="all" />',
            ),
        )
        assert _dotnet_rows(tmp_path) == [
            ("Dev.Above", "1.0.0", DependencyGroup.PROD, "App.csproj"),
            ("Prod.Above", "2.0.0", DependencyGroup.PROD, "Directory.Build.props"),
        ]

    def test_reference_named_like_an_in_tree_project_is_filtered(self, tmp_path):
        _write(tmp_path / "Local.Lib" / "Local.Lib.csproj", '<Project Sdk="Microsoft.NET.Sdk" />')
        _write(
            tmp_path / "Directory.Build.props",
            _project(
                '<PackageReference Include="Local.Lib" Version="1.0.0" />',
                '<PackageReference Include="Published.Lib" Version="2.0.0" />',
            ),
        )
        deps, counts = discover_all_dependencies(tmp_path)
        assert [d.name for d in deps] == ["Published.Lib"]
        assert counts["dotnet"] == 1

    def test_unreadable_build_file_is_a_gap_and_the_rest_is_read(self, tmp_path, monkeypatch):
        _write(
            tmp_path / "Directory.Build.props",
            _project('<PackageReference Include="Hidden.Lib" Version="1.0.0" />'),
        )
        _write(
            tmp_path / "Directory.Build.targets",
            _project('<PackageReference Include="Read.Lib" Version="2.0.0" />'),
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "Directory.Build.props":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        with collect_read_diagnostics() as diags:
            rows = _dotnet_rows(tmp_path)
        assert rows == [("Read.Lib", "2.0.0", DependencyGroup.PROD, "Directory.Build.targets")]
        assert {(d.path, d.is_gap) for d in diags} == {(tmp_path / "Directory.Build.props", True)}

    def test_malformed_build_file_and_malformed_import_are_gaps(self, tmp_path):
        _write(tmp_path / "Directory.Build.targets", "<Project><ItemGroup>")
        _write(tmp_path / "eng" / "Broken.props", "<Project><broken")
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="eng/Broken.props" />
  <ItemGroup>
    <PackageReference Include="Own.Lib" Version="1.0.0" />
  </ItemGroup>
</Project>""",
        )
        with collect_read_diagnostics() as diags:
            rows = _dotnet_rows(tmp_path)
        assert rows == [("Own.Lib", "1.0.0", DependencyGroup.PROD, "Directory.Build.props")]
        assert {(d.path, d.reason) for d in diags if d.is_gap} == {
            (tmp_path / "Directory.Build.targets", "is not valid XML; skipped"),
            ((tmp_path / "eng" / "Broken.props").resolve(), "is not valid XML; skipped"),
        }


class TestImportFollowing:
    """``Directory.Build.props`` <Import> chain following.

    Real-world repos keep version variables in a separate
    ``Versions.props`` / ``Common.props`` imported by
    ``Directory.Build.props``. licenseal must follow these imports so the
    property scope is complete.
    """

    def test_import_resolves_sibling_props_file(self, tmp_path):
        _write(
            tmp_path / "Versions.props",
            """<Project>
  <PropertyGroup>
    <NewtonsoftVersion>13.0.1</NewtonsoftVersion>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="Versions.props" />
  <PropertyGroup>
    <LocalProp>local-value</LocalProp>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        merged = result[tmp_path]
        # Property from the imported file is visible alongside the
        # importing file's own properties.
        assert merged["NewtonsoftVersion"] == "13.0.1"
        assert merged["LocalProp"] == "local-value"

    def test_importing_file_wins_on_collision(self, tmp_path):
        # MSBuild's evaluation: <Import> happens first, then the
        # current file's <PropertyGroup>s overwrite collisions.
        _write(
            tmp_path / "Versions.props",
            """<Project>
  <PropertyGroup>
    <X>from-imported</X>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="Versions.props" />
  <PropertyGroup>
    <X>from-directory-build</X>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result[tmp_path]["X"] == "from-directory-build"

    def test_windows_backslash_import_path_resolved(self, tmp_path):
        # Many real-world files use ``Project="build\Common.props"``
        # with Windows backslashes. The resolver normalizes them.
        (tmp_path / "build").mkdir()
        _write(
            tmp_path / "build" / "Common.props",
            """<Project>
  <PropertyGroup>
    <CommonVar>common</CommonVar>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            r"""<Project>
  <Import Project="build\Common.props" />
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result[tmp_path] == {"CommonVar": "common"}

    def test_nested_imports_followed(self, tmp_path):
        # A.props imports B.props imports C.props — all three levels
        # contribute properties.
        _write(
            tmp_path / "C.props",
            """<Project>
  <PropertyGroup>
    <FromC>c</FromC>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "B.props",
            """<Project>
  <Import Project="C.props" />
  <PropertyGroup>
    <FromB>b</FromB>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="B.props" />
  <PropertyGroup>
    <FromA>a</FromA>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        merged = result[tmp_path]
        assert merged["FromA"] == "a"
        assert merged["FromB"] == "b"
        assert merged["FromC"] == "c"

    def test_circular_import_terminates(self, tmp_path):
        # A.props imports B.props imports A.props — must not loop.
        _write(
            tmp_path / "A.props",
            """<Project>
  <Import Project="B.props" />
  <PropertyGroup>
    <FromA>a</FromA>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "B.props",
            """<Project>
  <Import Project="A.props" />
  <PropertyGroup>
    <FromB>b</FromB>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="A.props" />
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        merged = result[tmp_path]
        # Both A and B contribute; circular re-entry is suppressed.
        assert merged.get("FromA") == "a"
        assert merged.get("FromB") == "b"

    def test_unresolved_msbuild_token_in_import_path_skipped(self, tmp_path):
        # ``<Import Project="$(MSBuildThisFileDirectory)foo.props">`` —
        # we don't expand MSBuild tokens in import paths (would require
        # the full engine), so the import is silently skipped.
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="$(MSBuildThisFileDirectory)Versions.props" />
  <PropertyGroup>
    <Local>local</Local>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        # Only the file's own properties survive — the unresolved
        # import-path is skipped.
        assert result[tmp_path] == {"Local": "local"}

    def test_missing_import_target_skipped(self, tmp_path):
        # Import points at a file that doesn't exist — silently skipped.
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="DoesNotExist.props" />
  <PropertyGroup>
    <Local>local</Local>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result[tmp_path] == {"Local": "local"}

    def test_malformed_imported_file_skipped(self, tmp_path):
        _write(tmp_path / "Bad.props", "<not closed")
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="Bad.props" />
  <PropertyGroup>
    <Local>local</Local>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result[tmp_path] == {"Local": "local"}

    def test_xunit_versions_props_pattern_end_to_end(self, tmp_path):
        # Real-world xunit pattern: src/Directory.Build.props imports
        # src/Versions.props which declares package-version variables.
        # licenseal must see those variables when resolving a .csproj
        # under src/xunit.v3.core/.
        _write(
            tmp_path / "src" / "Versions.props",
            """<Project>
  <PropertyGroup>
    <Nerdbank_GitVersioning_Version>3.9.50</Nerdbank_GitVersioning_Version>
    <System_Collections_Immutable_Version>6.0.0</System_Collections_Immutable_Version>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "src" / "Directory.Build.props",
            """<Project>
  <Import Project="Versions.props" />
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        src_props = result[tmp_path / "src"]
        assert src_props["Nerdbank_GitVersioning_Version"] == "3.9.50"
        assert src_props["System_Collections_Immutable_Version"] == "6.0.0"

    def test_import_with_empty_project_attribute_skipped(self, tmp_path):
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="" />
  <Import />
  <PropertyGroup>
    <Local>local</Local>
  </PropertyGroup>
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        assert result[tmp_path] == {"Local": "local"}

    def test_parse_imports_returns_empty_on_malformed_xml(self):
        from licenseal.discovery.dotnet.directory_build_props import _parse_imports

        assert _parse_imports("<not closed") == []

    def test_unreadable_imported_file_skipped(self, tmp_path, monkeypatch):
        _write(
            tmp_path / "Sibling.props",
            """<Project>
  <PropertyGroup>
    <FromSibling>v</FromSibling>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="Sibling.props" />
  <PropertyGroup>
    <Local>local</Local>
  </PropertyGroup>
</Project>""",
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "Sibling.props":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        result = find_directory_build_props(tmp_path)
        # Sibling.props can't be read; the directory still surfaces with
        # only the local property.
        assert result[tmp_path] == {"Local": "local"}

    def test_depth_cap_terminates_long_chains(self, tmp_path):
        # 10-link chain — depth cap should stop before reaching the end.
        # Build A.props -> B.props -> C.props ... J.props, each with a
        # unique property; chain longer than _MAX_IMPORT_DEPTH must be
        # truncated.
        names = list("ABCDEFGHIJ")
        for i, name in enumerate(names):
            nxt = names[i + 1] if i + 1 < len(names) else None
            content = "<Project>\n"
            if nxt is not None:
                content += f'  <Import Project="{nxt}.props" />\n'
            content += (
                f"  <PropertyGroup>\n    <From{name}>{name}</From{name}>\n  </PropertyGroup>\n"
            )
            content += "</Project>"
            _write(tmp_path / f"{name}.props", content)
        _write(
            tmp_path / "Directory.Build.props",
            """<Project>
  <Import Project="A.props" />
</Project>""",
        )
        result = find_directory_build_props(tmp_path)
        merged = result[tmp_path]
        # First several links should resolve; the chain is cut by the
        # depth cap. Don't assert exact cap — just confirm early links
        # are present and late links are not.
        assert merged.get("FromA") == "A"
        assert merged.get("FromB") == "B"
        # The last link past the cap doesn't appear.
        assert merged.get("FromJ") is None


class TestImportPathConfinement:
    """An ``<Import Project>`` value is followed only when it is a relative
    path. A rooted, drive-qualified, UNC or device value is rejected before
    any filesystem call and recorded as a gap on the importing file.
    """

    _VERSIONS = """<Project>
  <PropertyGroup>
    <LibVersion>3.1.1</LibVersion>
  </PropertyGroup>
</Project>"""

    @pytest.mark.parametrize("value", _NON_RELATIVE_PATH_VALUES)
    def test_non_relative_import_never_reaches_filesystem(self, tmp_path, monkeypatch, value):
        _write(tmp_path / "Versions.props", self._VERSIONS)
        manifest = tmp_path / "Directory.Build.props"
        _write(
            manifest,
            f"""<Project>
  <Import Project="{value}" />
  <Import Project="Versions.props" />
  <PropertyGroup>
    <Local>local</Local>
  </PropertyGroup>
</Project>""",
        )
        calls = _record_path_io(monkeypatch, "example.invalid")
        with collect_read_diagnostics() as diags:
            result = find_directory_build_props(tmp_path)

        assert [call for call in calls if "example.invalid" in call[1]] == []
        # The recorder is live: the relative import beside it was resolved,
        # probed and read.
        followed = {method for method, path in calls if Path(path).name == "Versions.props"}
        assert {"resolve", "is_file", "read_bytes"} <= followed
        assert result[tmp_path] == {"LibVersion": "3.1.1", "Local": "local"}

        gaps = [d for d in diags if d.is_gap]
        assert len(gaps) == 1
        assert gaps[0].path == manifest
        assert repr(value) in gaps[0].reason

    def test_rejected_import_in_imported_file_names_that_file(self, tmp_path, monkeypatch):
        # The gap points at the file that carried the value, which is the
        # imported file here, not the top-level one.
        imported = tmp_path / "build" / "Common.props"
        _write(
            imported,
            r"""<Project>
  <Import Project="\\example.invalid\share\external.props" />
  <PropertyGroup>
    <FromCommon>common</FromCommon>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Directory.Build.props",
            r"""<Project>
  <Import Project="build\Common.props" />
</Project>""",
        )
        calls = _record_path_io(monkeypatch, "example.invalid")
        with collect_read_diagnostics() as diags:
            result = find_directory_build_props(tmp_path)

        assert [call for call in calls if "example.invalid" in call[1]] == []
        assert result[tmp_path] == {"FromCommon": "common"}
        assert [d.path for d in diags if d.is_gap] == [imported.resolve()]

    def test_parent_relative_import_still_followed(self, tmp_path):
        # ``..`` stays a relative reference: a props file shared from above
        # the importing directory keeps resolving, with no gap.
        _write(tmp_path / "shared" / "Versions.props", self._VERSIONS)
        _write(
            tmp_path / "src" / "Directory.Build.props",
            r"""<Project>
  <Import Project="..\shared\Versions.props" />
</Project>""",
        )
        with collect_read_diagnostics() as diags:
            result = find_directory_build_props(tmp_path / "src")
        assert result[tmp_path / "src"] == {"LibVersion": "3.1.1"}
        assert diags == []

    def test_rejected_import_leaves_version_token_unexpanded(self, tmp_path, monkeypatch):
        # Through the aggregator: the property the rejected import would have
        # supplied is not invented, and the gap is recorded.
        _write(
            tmp_path / "Directory.Build.props",
            r"""<Project>
  <Import Project="\\example.invalid\share\external.props" />
</Project>""",
        )
        _write(
            tmp_path / "src" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Example.Lib" Version="$(LibVersion)" />
  </ItemGroup>
</Project>""",
        )
        calls = _record_path_io(monkeypatch, "example.invalid")
        with collect_read_diagnostics() as diags:
            deps, _ = discover_all_dependencies(tmp_path)

        assert [call for call in calls if "example.invalid" in call[1]] == []
        dotnet = [d for d in deps if d.ecosystem == Ecosystem.DOTNET]
        assert [(d.name, d.version_constraint) for d in dotnet] == [
            ("Example.Lib", "$(LibVersion)")
        ]
        # The file is read once for its properties and once for its
        # references, so both passes record the same gap.
        assert {d.path for d in diags if d.is_gap} == {tmp_path / "Directory.Build.props"}
