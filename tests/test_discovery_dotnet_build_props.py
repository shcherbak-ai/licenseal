"""Tests for ``Directory.Build.props`` / ``.targets`` discovery."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.dotnet.directory_build_props import (
    _parse_directory_build_props,
    closest_build_props,
    find_directory_build_props,
)


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
