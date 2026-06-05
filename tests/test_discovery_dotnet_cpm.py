"""Tests for ``Directory.Packages.props`` (CPM) discovery."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.dotnet.directory_packages_props import (
    CpmData,
    _parse_directory_packages_props,
    closest_cpm_data,
    find_directory_packages_props,
    lookup_version,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# _parse_directory_packages_props
# ---------------------------------------------------------------------------


class TestParseDirectoryPackagesProps:
    def test_package_version_captured(self):
        text = """<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageVersion Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {
            "newtonsoft.json": "13.0.1",
            "serilog": "3.1.1",
        }

    def test_global_package_reference_captured_separately(self):
        text = """<Project>
  <ItemGroup>
    <PackageVersion Include="Lib" Version="1.0" />
    <GlobalPackageReference Include="StyleCop.Analyzers" Version="1.2.0-beta.556" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {"lib": "1.0"}
        # GlobalPackageReference is keyed by the as-authored Include (not
        # lowercased like PackageVersion) so the materialized dep keeps its
        # real display casing.
        assert data.global_package_refs == {"StyleCop.Analyzers": "1.2.0-beta.556"}

    def test_keys_lowercased_for_case_insensitive_lookup(self):
        # NuGet IDs are case-insensitive; the parser stores lowercase keys.
        text = """<Project>
  <ItemGroup>
    <PackageVersion Include="Microsoft.Extensions.Logging" Version="8.0.0" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert "microsoft.extensions.logging" in data.versions

    def test_missing_include_attribute_skipped(self):
        text = """<Project>
  <ItemGroup>
    <PackageVersion Version="1.0" />
    <PackageVersion Include="Valid" Version="2.0" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {"valid": "2.0"}

    def test_missing_version_attribute_skipped(self):
        # A PackageVersion without a Version attribute is non-functional;
        # don't pollute the version map with empty values.
        text = """<Project>
  <ItemGroup>
    <PackageVersion Include="NoVersion" />
    <PackageVersion Include="HasVersion" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {"hasversion": "1.0"}

    def test_unrelated_root_child_ignored(self):
        # <PropertyGroup>, <Target>, <Import> coexist with ItemGroups but
        # don't carry PackageVersion info.
        text = """<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <Target Name="X" />
  <ItemGroup>
    <PackageVersion Include="Lib" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {"lib": "1.0"}

    def test_unrelated_itemgroup_child_ignored(self):
        # An ItemGroup may carry Content, Compile, Reference items — those
        # aren't CPM entries and must be silently skipped.
        text = """<Project>
  <ItemGroup>
    <Content Include="appsettings.json" />
    <Compile Include="Program.cs" />
    <PackageVersion Include="OnlyOne" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {"onlyone": "1.0"}

    def test_itemgroup_child_with_both_attrs_but_unknown_tag_ignored(self):
        # Even when an unrelated item happens to carry both Include AND
        # Version attributes (rare but valid), the parser must skip it
        # — only PackageVersion / GlobalPackageReference are CPM entries.
        text = """<Project>
  <ItemGroup>
    <Reference Include="System.Web" Version="4.0" />
    <PackageVersion Include="Real" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {"real": "1.0"}
        assert data.global_package_refs == {}

    def test_msbuild_namespace_stripped(self):
        # Legacy props files carry the MSBuild 2003 namespace.
        text = """<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <PackageVersion Include="LegacyNS" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_directory_packages_props(text)
        assert data is not None
        assert data.versions == {"legacyns": "1.0"}

    def test_malformed_xml_returns_none(self):
        assert _parse_directory_packages_props("<not closed") is None

    def test_billion_laughs_returns_none(self):
        billion = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<Project>
  <ItemGroup>
    <PackageVersion Include="&lol2;" Version="1.0" />
  </ItemGroup>
</Project>"""
        assert _parse_directory_packages_props(billion) is None

    def test_xxe_entity_reference_returns_none(self):
        xxe = """<?xml version="1.0"?>
<!DOCTYPE Project [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Project>
  <ItemGroup>
    <PackageVersion Include="&xxe;" Version="1.0" />
  </ItemGroup>
</Project>"""
        assert _parse_directory_packages_props(xxe) is None


# ---------------------------------------------------------------------------
# find_directory_packages_props
# ---------------------------------------------------------------------------


class TestFindDirectoryPackagesProps:
    def test_single_root_file(self, tmp_path):
        _write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="Lib" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        result = find_directory_packages_props(tmp_path)
        assert len(result) == 1
        assert tmp_path in result
        assert result[tmp_path].versions == {"lib": "1.0"}

    def test_nested_files_keyed_by_directory(self, tmp_path):
        _write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="RootLib" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        _write(
            tmp_path / "src" / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="SrcLib" Version="2.0" />
  </ItemGroup>
</Project>""",
        )
        result = find_directory_packages_props(tmp_path)
        assert len(result) == 2
        assert "rootlib" in result[tmp_path].versions
        assert "srclib" in result[tmp_path / "src"].versions

    def test_unreadable_file_skipped(self, tmp_path, monkeypatch):
        _write(
            tmp_path / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "Directory.Packages.props":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        result = find_directory_packages_props(tmp_path)
        assert result == {}

    def test_malformed_file_skipped(self, tmp_path):
        _write(tmp_path / "Directory.Packages.props", "<not closed")
        _write(
            tmp_path / "good" / "Directory.Packages.props",
            """<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        result = find_directory_packages_props(tmp_path)
        # Only the good one survives.
        assert tmp_path not in result
        assert (tmp_path / "good") in result

    def test_utf8_bom_tolerated(self, tmp_path):
        path = tmp_path / "Directory.Packages.props"
        path.write_bytes(
            b"\xef\xbb\xbf<Project>"
            b"<ItemGroup>"
            b'<PackageVersion Include="BomLib" Version="1.0" />'
            b"</ItemGroup>"
            b"</Project>"
        )
        result = find_directory_packages_props(tmp_path)
        assert result[tmp_path].versions == {"bomlib": "1.0"}


# ---------------------------------------------------------------------------
# closest_cpm_data + lookup_version
# ---------------------------------------------------------------------------


class TestClosestCpmData:
    def test_returns_immediate_directory_match(self, tmp_path):
        cpm_files = {
            tmp_path / "src" / "Proj": CpmData(versions={"x": "1.0"}),
        }
        result = closest_cpm_data(tmp_path / "src" / "Proj" / "App.csproj", cpm_files)
        assert result is not None
        assert result.versions == {"x": "1.0"}

    def test_returns_ancestor_when_immediate_missing(self, tmp_path):
        # CPM file is at repo root; csproj is nested two levels deeper.
        # Closest-ancestor rule walks up to find the props file.
        cpm_files = {
            tmp_path: CpmData(versions={"x": "1.0"}),
        }
        result = closest_cpm_data(tmp_path / "src" / "Proj" / "App.csproj", cpm_files)
        assert result is not None
        assert result.versions == {"x": "1.0"}

    def test_closer_ancestor_wins_over_farther(self, tmp_path):
        # MSBuild's actual semantics: the closest ancestor overrides
        # farther ones. The src/ props supplies a different version than
        # the root.
        cpm_files = {
            tmp_path: CpmData(versions={"x": "1.0"}),
            tmp_path / "src": CpmData(versions={"x": "2.0"}),
        }
        result = closest_cpm_data(tmp_path / "src" / "Proj" / "App.csproj", cpm_files)
        assert result is not None
        # ``src/`` wins because it's closer.
        assert result.versions == {"x": "2.0"}

    def test_no_match_returns_none(self, tmp_path):
        # CPM file in a sibling tree — not an ancestor of csproj.
        cpm_files = {
            tmp_path / "unrelated": CpmData(versions={"x": "1.0"}),
        }
        result = closest_cpm_data(tmp_path / "src" / "App.csproj", cpm_files)
        assert result is None

    def test_empty_cpm_files_returns_none(self, tmp_path):
        # Short-circuit when no CPM files exist.
        result = closest_cpm_data(tmp_path / "App.csproj", {})
        assert result is None


class TestLookupVersion:
    def test_resolves_via_closest_ancestor(self, tmp_path):
        cpm_files = {
            tmp_path: CpmData(versions={"newtonsoft.json": "13.0.1"}),
        }
        result = lookup_version("Newtonsoft.Json", tmp_path / "src" / "App.csproj", cpm_files)
        assert result == "13.0.1"

    def test_case_insensitive_match(self, tmp_path):
        # Both the CPM map (already lowercased) and the lookup key are
        # case-folded; mixed-case input must still resolve.
        cpm_files = {
            tmp_path: CpmData(versions={"newtonsoft.json": "13.0.1"}),
        }
        for input_name in (
            "newtonsoft.json",
            "NEWTONSOFT.JSON",
            "Newtonsoft.Json",
            "NewTonSoft.JSON",
        ):
            result = lookup_version(input_name, tmp_path / "App.csproj", cpm_files)
            assert result == "13.0.1", f"failed for input {input_name!r}"

    def test_no_cpm_returns_empty(self, tmp_path):
        # No CPM files in workspace → lookup gracefully returns empty.
        result = lookup_version("X", tmp_path / "App.csproj", {})
        assert result == ""

    def test_package_not_in_cpm_returns_empty(self, tmp_path):
        # CPM file exists but doesn't declare this package.
        cpm_files = {
            tmp_path: CpmData(versions={"other": "1.0"}),
        }
        result = lookup_version("Missing", tmp_path / "App.csproj", cpm_files)
        assert result == ""
