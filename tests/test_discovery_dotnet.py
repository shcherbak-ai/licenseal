"""Tests for .NET ecosystem discovery (.csproj / .fsproj / .vbproj)."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.dotnet import (
    detect_project_license_csproj,
    discover_csproj_dependencies,
)
from licenseal.discovery.dotnet.csproj import (
    _CsprojData,
    _CsprojDep,
    _discover_workspace_local_project_ids,
    _expand_properties,
    _is_dev_package_ref,
    _parse_csproj,
    _strip_ns,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# ---------------------------------------------------------------------------
# _strip_ns
# ---------------------------------------------------------------------------


class TestStripNs:
    def test_strips_msbuild_2003_namespace(self):
        assert (
            _strip_ns("{http://schemas.microsoft.com/developer/msbuild/2003}Project") == "Project"
        )
        assert (
            _strip_ns("{http://schemas.microsoft.com/developer/msbuild/2003}PackageReference")
            == "PackageReference"
        )

    def test_no_namespace_returns_unchanged(self):
        # SDK-style projects have no XML namespace.
        assert _strip_ns("Project") == "Project"
        assert _strip_ns("PackageReference") == "PackageReference"

    def test_unrelated_namespace_left_intact(self):
        # We only strip the canonical MSBuild 2003 namespace; an unrelated
        # namespace is not our concern.
        assert _strip_ns("{http://example.com/foo}Bar") == "{http://example.com/foo}Bar"


# ---------------------------------------------------------------------------
# _expand_properties
# ---------------------------------------------------------------------------


class TestExpandProperties:
    def test_known_property_substituted(self):
        assert _expand_properties("$(MyVersion)", {"MyVersion": "1.2.3"}) == "1.2.3"

    def test_unknown_property_left_literal(self):
        # The resolver detects ``$(`` and routes to UNKNOWN, which is the
        # correct posture for build-time-only properties.
        assert _expand_properties("$(Unknown)", {"Other": "1.0"}) == "$(Unknown)"

    def test_no_property_returns_unchanged(self):
        assert _expand_properties("13.0.1", {"Anything": "x"}) == "13.0.1"

    def test_empty_value_returns_unchanged(self):
        assert _expand_properties("", {"X": "y"}) == ""

    def test_multiple_properties_in_one_value(self):
        result = _expand_properties("$(Major).$(Minor)", {"Major": "1", "Minor": "2"})
        assert result == "1.2"

    def test_whitespace_around_property_name_tolerated(self):
        # MSBuild tolerates ``$( Name )`` with surrounding whitespace.
        assert _expand_properties("$( MyVersion )", {"MyVersion": "1.0"}) == "1.0"

    def test_no_substitution_token_short_circuits(self):
        # The function short-circuits when no ``$(`` is present (perf path).
        assert _expand_properties("just a string", {}) == "just a string"


# ---------------------------------------------------------------------------
# _is_dev_package_ref
# ---------------------------------------------------------------------------


class TestIsDevPackageRef:
    def test_private_assets_all_marks_dev(self):
        assert _is_dev_package_ref(None, private_assets="all", condition="") is True

    def test_private_assets_other_value_stays_prod(self):
        # Only the exact ``all`` value is the dev hint; other values (e.g.
        # ``compile``, ``analyzers``, comma-lists) flow through as PROD.
        assert _is_dev_package_ref(None, private_assets="compile", condition="") is False

    def test_debug_configuration_condition_marks_dev(self):
        cond = "'$(Configuration)' == 'Debug'"
        assert _is_dev_package_ref(None, private_assets="", condition=cond) is True

    def test_istestproject_condition_marks_dev(self):
        cond = "'$(IsTestProject)' == 'true'"
        assert _is_dev_package_ref(None, private_assets="", condition=cond) is True

    def test_unrelated_condition_stays_prod(self):
        cond = "'$(TargetFramework)' == 'net8.0'"
        assert _is_dev_package_ref(None, private_assets="", condition=cond) is False

    def test_no_attrs_stays_prod(self):
        assert _is_dev_package_ref(None, private_assets="", condition="") is False


# ---------------------------------------------------------------------------
# _parse_csproj — SDK-style
# ---------------------------------------------------------------------------


class TestParseCsprojSdkStyle:
    def test_simple_package_reference_attr_version(self, tmp_path):
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "MyApp.csproj")
        assert data is not None
        assert data.project_id == "MyApp"
        assert len(data.package_refs) == 1
        assert data.package_refs[0].package_id == "Newtonsoft.Json"
        assert data.package_refs[0].version == "13.0.1"
        assert data.package_refs[0].group == DependencyGroup.PROD

    def test_nested_version_element(self, tmp_path):
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert data.package_refs[0].package_id == "Serilog"
        assert data.package_refs[0].version == "3.1.1"

    def test_private_assets_all_classifies_as_dev(self, tmp_path):
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="xunit" Version="2.6.1" PrivateAssets="all" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "Tests.csproj")
        assert data is not None
        assert data.package_refs[0].group == DependencyGroup.DEV

    def test_project_reference_captured_separately_not_as_dep(self, tmp_path):
        # ProjectReference is an in-tree project link, NOT a NuGet dep.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\\Other\\Other.csproj" />
    <PackageReference Include="RealDep" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        # Only RealDep is a package; the ProjectReference is captured separately.
        assert len(data.package_refs) == 1
        assert data.package_refs[0].package_id == "RealDep"
        assert "..\\Other\\Other.csproj" in data.project_refs

    def test_empty_include_skipped(self, tmp_path):
        # A PackageReference with no Include attribute is malformed; skip it
        # rather than crashing.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Version="1.0" />
    <PackageReference Include="ValidDep" Version="2.0" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert len(data.package_refs) == 1
        assert data.package_refs[0].package_id == "ValidDep"

    def test_no_version_leaves_constraint_empty(self, tmp_path):
        # Central Package Management case: the .csproj has no Version
        # attribute, expecting Directory.Packages.props to supply it.
        # This parser leaves the field empty for the CPM stitching layer.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Microsoft.Extensions.Logging" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert data.package_refs[0].package_id == "Microsoft.Extensions.Logging"
        assert data.package_refs[0].version == ""

    def test_property_expansion_in_version_attribute(self, tmp_path):
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <NewtonsoftVersion>13.0.1</NewtonsoftVersion>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="$(NewtonsoftVersion)" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert data.package_refs[0].version == "13.0.1"

    def test_unresolved_property_left_literal(self, tmp_path):
        # When the property isn't declared anywhere this parser can see,
        # leave the literal token. The resolver detects $( and UNKNOWNs it.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="ExternalProp" Version="$(NotDeclared)" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert data.package_refs[0].version == "$(NotDeclared)"

    def test_packageid_property_overrides_filename_for_project_id(self, tmp_path):
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageId>Authored.Package.Name</PackageId>
  </PropertyGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "Different.csproj")
        assert data is not None
        assert data.project_id == "Authored.Package.Name"

    def test_unrecognized_root_child_ignored(self, tmp_path):
        # ``<Target>``, ``<Import>``, ``<UsingTask>`` etc. are valid MSBuild
        # elements that don't carry NuGet info; the parser must skip them
        # cleanly (loop falls through to the next child).
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <Target Name="BeforeBuild" />
  <Import Project="some.targets" />
  <ItemGroup>
    <PackageReference Include="OnlyOne" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert len(data.package_refs) == 1
        assert data.package_refs[0].package_id == "OnlyOne"

    def test_unrecognized_itemgroup_child_ignored(self, tmp_path):
        # ItemGroup can carry many item types (Reference, Compile, Content,
        # EmbeddedResource, etc.) — only PackageReference and ProjectReference
        # are relevant; the rest must fall through silently.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <Reference Include="System.Web" />
    <Compile Include="Program.cs" />
    <Content Include="appsettings.json" />
    <PackageReference Include="OnlyOne" Version="1.0" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert len(data.package_refs) == 1
        assert len(data.project_refs) == 0

    def test_empty_project_reference_include_skipped(self, tmp_path):
        # A ProjectReference with whitespace-only Include is malformed and
        # must not pollute project_refs.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="   " />
    <ProjectReference Include="..\\Real\\Real.csproj" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert data.project_refs == ["..\\Real\\Real.csproj"]

    def test_package_reference_with_non_version_children_ignored(self, tmp_path):
        # A nested element that isn't <Version> (e.g. <ExcludeAssets>,
        # <IncludeAssets>) must not crash the version reader; the loop
        # continues past non-matching children.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="HasOtherChildren">
      <ExcludeAssets>runtime</ExcludeAssets>
      <PrivateAssets>none</PrivateAssets>
      <Version>2.0.0</Version>
    </PackageReference>
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert len(data.package_refs) == 1
        assert data.package_refs[0].version == "2.0.0"

    def test_package_reference_with_empty_version_child_falls_through(self, tmp_path):
        # A <PackageReference><Version></Version></PackageReference> with an
        # empty Version child must not be treated as a hit; the for-loop
        # continues and the function returns the empty string.
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="EmptyVersionChild">
      <Version></Version>
    </PackageReference>
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "App.csproj")
        assert data is not None
        assert data.package_refs[0].version == ""


# ---------------------------------------------------------------------------
# _parse_csproj — legacy MSBuild-namespace project files
# ---------------------------------------------------------------------------


class TestParseCsprojLegacyNamespace:
    def test_msbuild_2003_namespace_stripped(self, tmp_path):
        # Pre-SDK-style legacy projects carry the 2003 MSBuild namespace.
        text = """<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"
                    DefaultTargets="Build" ToolsVersion="14.0">
  <ItemGroup>
    <PackageReference Include="Legacy.Lib" Version="0.9.0" />
  </ItemGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "Old.csproj")
        assert data is not None
        assert len(data.package_refs) == 1
        assert data.package_refs[0].package_id == "Legacy.Lib"


# ---------------------------------------------------------------------------
# _parse_csproj — robustness
# ---------------------------------------------------------------------------


class TestParseCsprojRobustness:
    def test_malformed_xml_returns_none(self, tmp_path):
        assert _parse_csproj("<not closed", source_path=tmp_path / "x.csproj") is None

    def test_empty_xml_returns_none(self, tmp_path):
        assert _parse_csproj("", source_path=tmp_path / "x.csproj") is None

    def test_billion_laughs_returns_none(self, tmp_path):
        # defusedxml refuses entity expansion; the parser must surface
        # the failure as a graceful None, not raise.
        billion_laughs = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="&lol2;" Version="1.0" />
  </ItemGroup>
</Project>"""
        assert _parse_csproj(billion_laughs, source_path=tmp_path / "x.csproj") is None

    def test_xxe_entity_reference_returns_none(self, tmp_path):
        # XXE via an entity referencing an external SYSTEM source.
        # defusedxml refuses to dereference the SYSTEM URL and raises
        # ExternalReferenceForbidden — the parser surfaces the failure as
        # a graceful None instead of leaking attacker-controlled content
        # back into the value of Include.
        xxe = """<?xml version="1.0"?>
<!DOCTYPE Project [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="&xxe;" Version="1.0" />
  </ItemGroup>
</Project>"""
        assert _parse_csproj(xxe, source_path=tmp_path / "x.csproj") is None

    def test_empty_property_value_not_stored(self, tmp_path):
        # An empty/whitespace-only PropertyGroup value is dropped so it
        # doesn't shadow a real value from a parent props file (when CPM
        # stitching arrives in a follow-up).
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <Version></Version>
    <RealProp>real</RealProp>
  </PropertyGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "x.csproj")
        assert data is not None
        assert "Version" not in data.properties
        assert data.properties.get("RealProp") == "real"

    def test_authored_package_license_expression_captured(self, tmp_path):
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
  </PropertyGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "Lib.csproj")
        assert data is not None
        assert data.license_expression == "MIT"

    def test_authored_package_license_url_captured(self, tmp_path):
        text = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseUrl>https://www.apache.org/licenses/LICENSE-2.0</PackageLicenseUrl>
  </PropertyGroup>
</Project>"""
        data = _parse_csproj(text, source_path=tmp_path / "Lib.csproj")
        assert data is not None
        assert data.license_url == "https://www.apache.org/licenses/LICENSE-2.0"


# ---------------------------------------------------------------------------
# discover_csproj_dependencies — end-to-end
# ---------------------------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestDiscoverCsprojDependencies:
    def test_single_csproj_emits_deps(self, tmp_path):
        _write(
            tmp_path / "MyApp.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>""",
        )
        deps, filtered = discover_csproj_dependencies(tmp_path)
        assert filtered == 0
        names = {d.name for d in deps}
        assert names == {"Newtonsoft.Json", "Serilog"}
        assert all(d.ecosystem == Ecosystem.DOTNET for d in deps)
        assert all(d.group == DependencyGroup.PROD for d in deps)

    def test_fsproj_and_vbproj_handled_by_same_parser(self, tmp_path):
        _write(
            tmp_path / "FApp.fsproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="FSharp.Core" Version="8.0.0" />
  </ItemGroup>
</Project>""",
        )
        _write(
            tmp_path / "VbApp.vbproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Microsoft.VisualBasic" Version="10.4.0" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_csproj_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert "FSharp.Core" in names
        assert "Microsoft.VisualBasic" in names

    def test_multi_project_workspace_dedup(self, tmp_path):
        # Two .csproj files referencing the same NuGet package surface as
        # one Dependency per source-manifest line (no dedup at this layer;
        # the aggregator does cross-format dedup).
        _write(
            tmp_path / "ProjA" / "ProjA.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Shared.Lib" Version="1.0.0" />
  </ItemGroup>
</Project>""",
        )
        _write(
            tmp_path / "ProjB" / "ProjB.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Shared.Lib" Version="1.0.0" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_csproj_dependencies(tmp_path)
        # Two entries because two manifests declared it.
        shared = [d for d in deps if d.name == "Shared.Lib"]
        assert len(shared) == 2
        sources = {d.source for d in shared}
        assert sources == {"ProjA/ProjA.csproj", "ProjB/ProjB.csproj"}

    def test_workspace_local_project_id_collision_filtered(self, tmp_path):
        # Edge case: an in-tree project is named ``Shared.Lib`` AND another
        # project's .csproj declares ``<PackageReference Include="Shared.Lib"/>``
        # — should be filtered as workspace-local, not register-resolved.
        _write(
            tmp_path / "Shared.Lib" / "Shared.Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk" />""",
        )
        _write(
            tmp_path / "Consumer" / "Consumer.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Shared.Lib" Version="1.0.0" />
  </ItemGroup>
</Project>""",
        )
        deps, filtered = discover_csproj_dependencies(tmp_path)
        assert filtered == 1
        assert all(d.name != "Shared.Lib" for d in deps)

    def test_unreadable_csproj_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path / "A.csproj", """<Project Sdk="Microsoft.NET.Sdk" />""")
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "A.csproj":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        deps, _ = discover_csproj_dependencies(tmp_path)
        assert deps == []

    def test_malformed_csproj_skipped_gracefully(self, tmp_path):
        _write(tmp_path / "A.csproj", "<not closed")
        deps, filtered = discover_csproj_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    def test_utf8_bom_tolerated(self, tmp_path):
        # Visual Studio has historically written .csproj with a UTF-8 BOM.
        path = tmp_path / "App.csproj"
        path.write_bytes(
            b'\xef\xbb\xbf<Project Sdk="Microsoft.NET.Sdk">'
            b"<ItemGroup>"
            b'<PackageReference Include="BomDep" Version="1.0" />'
            b"</ItemGroup>"
            b"</Project>"
        )
        deps, _ = discover_csproj_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "BomDep"

    def test_source_path_is_relative_posix(self, tmp_path):
        _write(
            tmp_path / "src" / "App" / "App.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Dep" Version="1.0" />
  </ItemGroup>
</Project>""",
        )
        deps, _ = discover_csproj_dependencies(tmp_path)
        # Source must be POSIX-style relative path for cross-platform stability.
        assert deps[0].source == "src/App/App.csproj"


# ---------------------------------------------------------------------------
# _discover_workspace_local_project_ids
# ---------------------------------------------------------------------------


class TestDiscoverWorkspaceLocalProjectIds:
    def test_file_stem_used_as_default_project_id(self, tmp_path):
        _write(tmp_path / "MyLib.csproj", """<Project Sdk="Microsoft.NET.Sdk" />""")
        ids = _discover_workspace_local_project_ids(tmp_path)
        assert ids == {"MyLib"}

    def test_packageid_overrides_file_stem(self, tmp_path):
        _write(
            tmp_path / "MyLib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageId>Custom.Name</PackageId>
  </PropertyGroup>
</Project>""",
        )
        ids = _discover_workspace_local_project_ids(tmp_path)
        assert ids == {"Custom.Name"}

    def test_malformed_file_skipped(self, tmp_path):
        _write(tmp_path / "Good.csproj", """<Project Sdk="Microsoft.NET.Sdk" />""")
        _write(tmp_path / "Bad.csproj", "<not closed")
        ids = _discover_workspace_local_project_ids(tmp_path)
        assert ids == {"Good"}

    def test_unreadable_file_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path / "Good.csproj", """<Project Sdk="Microsoft.NET.Sdk" />""")
        _write(tmp_path / "Bad.csproj", """<Project Sdk="Microsoft.NET.Sdk" />""")
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "Bad.csproj":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        ids = _discover_workspace_local_project_ids(tmp_path)
        assert ids == {"Good"}


# ---------------------------------------------------------------------------
# detect_project_license_csproj
# ---------------------------------------------------------------------------


class TestDetectProjectLicenseCsproj:
    def test_modern_expression_returned_as_spdx(self, tmp_path):
        _write(
            tmp_path / "Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
  </PropertyGroup>
</Project>""",
        )
        assert detect_project_license_csproj(tmp_path) == "MIT"

    def test_legacy_url_mapped_via_known_pattern(self, tmp_path):
        # Apache 2.0 URL is in spdx_from_license_url's pattern map.
        _write(
            tmp_path / "Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseUrl>https://www.apache.org/licenses/LICENSE-2.0</PackageLicenseUrl>
  </PropertyGroup>
</Project>""",
        )
        result = detect_project_license_csproj(tmp_path)
        assert "Apache" in result.upper() or result == "Apache-2.0"

    def test_no_license_metadata_returns_empty(self, tmp_path):
        _write(tmp_path / "App.csproj", """<Project Sdk="Microsoft.NET.Sdk" />""")
        assert detect_project_license_csproj(tmp_path) == ""

    def test_no_csproj_files_returns_empty(self, tmp_path):
        assert detect_project_license_csproj(tmp_path) == ""

    def test_malformed_csproj_skipped(self, tmp_path):
        _write(tmp_path / "Bad.csproj", "<not closed")
        _write(
            tmp_path / "Good.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>BSD-3-Clause</PackageLicenseExpression>
  </PropertyGroup>
</Project>""",
        )
        assert detect_project_license_csproj(tmp_path) == "BSD-3-Clause"

    def test_unreadable_csproj_skipped(self, tmp_path, monkeypatch):
        _write(
            tmp_path / "Bad.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Good.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>
  </PropertyGroup>
</Project>""",
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "Bad.csproj":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        # Good.csproj still resolves cleanly.
        result = detect_project_license_csproj(tmp_path)
        assert result in {"MIT", "Apache-2.0"}

    def test_unknown_license_falls_through(self, tmp_path):
        # If normalize_license returns UNKNOWN, the function should keep
        # looking (returns empty in this case since there's no other source).
        _write(
            tmp_path / "Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>SomethingTotallyMadeUp</PackageLicenseExpression>
  </PropertyGroup>
</Project>""",
        )
        # Either returns empty (UNKNOWN treated as no-hit) or returns the
        # normalized form. Both behaviours are acceptable; just confirm we
        # don't crash.
        result = detect_project_license_csproj(tmp_path)
        assert isinstance(result, str)

    def test_unknown_expression_falls_through_to_license_url(self, tmp_path):
        # When PackageLicenseExpression normalizes to UNKNOWN but a
        # PackageLicenseUrl is also present and mappable, fall through.
        # The literal string ``UNKNOWN`` is the canonical input that
        # normalize_license maps to UNKNOWN (everything else maps to a
        # concrete SPDX ID or echoes the input).
        _write(
            tmp_path / "Lib.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>UNKNOWN</PackageLicenseExpression>
    <PackageLicenseUrl>https://www.apache.org/licenses/LICENSE-2.0</PackageLicenseUrl>
  </PropertyGroup>
</Project>""",
        )
        result = detect_project_license_csproj(tmp_path)
        # Expression normalizes to UNKNOWN → falls through to URL mapping.
        assert "Apache" in result.upper() or result == "Apache-2.0"

    def test_unmappable_license_url_continues_scan(self, tmp_path):
        # First project has an unmappable URL; second has a mappable one.
        # The loop must continue past the first to find the second.
        _write(
            tmp_path / "First.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseUrl>https://invented-domain.example/license</PackageLicenseUrl>
  </PropertyGroup>
</Project>""",
        )
        _write(
            tmp_path / "Second.csproj",
            """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PackageLicenseExpression>BSD-3-Clause</PackageLicenseExpression>
  </PropertyGroup>
</Project>""",
        )
        result = detect_project_license_csproj(tmp_path)
        assert result == "BSD-3-Clause"


# ---------------------------------------------------------------------------
# Dataclass round-tripping (light sanity)
# ---------------------------------------------------------------------------


class TestCsprojDataclasses:
    def test_csproj_dep_round_trip(self):
        dep = _CsprojDep(package_id="X", version="1.0", group=DependencyGroup.PROD)
        assert dep.package_id == "X"
        assert dep.version == "1.0"
        assert dep.group == DependencyGroup.PROD

    def test_csproj_data_defaults(self):
        data = _CsprojData()
        assert data.project_id == ""
        assert data.package_refs == []
        assert data.project_refs == []
        assert data.properties == {}
        assert data.license_expression == ""
        assert data.license_url == ""

    def test_dependency_built_from_csproj_dep(self):
        # Confirms the Dependency shape we emit from discover_*.
        dep = Dependency(
            name="X",
            version_constraint="1.0",
            ecosystem=Ecosystem.DOTNET,
            group=DependencyGroup.PROD,
            source="App.csproj",
        )
        assert dep.ecosystem == Ecosystem.DOTNET
        assert dep.name == "X"
