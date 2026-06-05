"""Tests for legacy ``packages.config`` discovery."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery.dotnet.packages_config import (
    _dependency_from_package_element,
    _parse_packages_config,
    discover_packages_config_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# _parse_packages_config
# ---------------------------------------------------------------------------


class TestParsePackagesConfig:
    def test_simple_entry_parsed(self):
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert len(deps) == 1
        assert deps[0].name == "Newtonsoft.Json"
        assert deps[0].version_constraint == "13.0.1"
        assert deps[0].group == DependencyGroup.PROD
        assert deps[0].ecosystem == Ecosystem.DOTNET

    def test_development_dependency_marks_dev(self):
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="NUnit" version="3.13.3" developmentDependency="true" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert deps[0].group == DependencyGroup.DEV

    def test_development_dependency_false_stays_prod(self):
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Lib" version="1.0" developmentDependency="false" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert deps[0].group == DependencyGroup.PROD

    def test_development_dependency_case_insensitive(self):
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Lib" version="1.0" developmentDependency="TRUE" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert deps[0].group == DependencyGroup.DEV

    def test_multiple_packages_in_order(self):
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="A" version="1.0" />
  <package id="B" version="2.0" />
  <package id="C" version="3.0" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert [d.name for d in deps] == ["A", "B", "C"]

    def test_empty_id_skipped(self):
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="" version="1.0" />
  <package id="   " version="2.0" />
  <package id="ValidOne" version="3.0" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert len(deps) == 1
        assert deps[0].name == "ValidOne"

    def test_missing_id_attribute_skipped(self):
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package version="1.0" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps == []

    def test_missing_version_attribute_emits_empty_constraint(self):
        # A package without a version is malformed but not invalid XML;
        # emit it with empty version_constraint so the resolver can
        # surface it as UNKNOWN rather than silently dropping the entry.
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="NoVersion" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert deps[0].name == "NoVersion"
        assert deps[0].version_constraint == ""

    def test_non_package_children_ignored(self):
        # Comments, whitespace nodes, foreign elements — all must be
        # silently skipped without crashing.
        text = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <metadata>some authoring info</metadata>
  <package id="RealOne" version="1.0" />
</packages>"""
        deps = _parse_packages_config(text)
        assert deps is not None
        assert len(deps) == 1
        assert deps[0].name == "RealOne"

    def test_wrong_root_element_returns_empty(self):
        text = """<?xml version="1.0"?><config><foo /></config>"""
        assert _parse_packages_config(text) == []

    def test_malformed_xml_returns_none(self):
        assert _parse_packages_config("<not closed") is None

    def test_empty_text_returns_none(self):
        # An empty file isn't valid XML.
        assert _parse_packages_config("") is None

    def test_billion_laughs_returns_none(self):
        billion = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<packages>
  <package id="&lol2;" version="1.0" />
</packages>"""
        assert _parse_packages_config(billion) is None

    def test_xxe_entity_reference_returns_none(self):
        xxe = """<?xml version="1.0"?>
<!DOCTYPE packages [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<packages>
  <package id="&xxe;" version="1.0" />
</packages>"""
        assert _parse_packages_config(xxe) is None


# ---------------------------------------------------------------------------
# _dependency_from_package_element direct tests
# ---------------------------------------------------------------------------


class TestDependencyFromPackageElement:
    def test_full_attributes(self):
        from xml.etree.ElementTree import Element

        el = Element(
            "package",
            attrib={
                "id": "X",
                "version": "1.2.3",
                "targetFramework": "net48",
            },
        )
        dep = _dependency_from_package_element(el)
        assert dep is not None
        assert dep.name == "X"
        assert dep.version_constraint == "1.2.3"
        assert dep.ecosystem == Ecosystem.DOTNET
        assert dep.group == DependencyGroup.PROD

    def test_blank_id_returns_none(self):
        from xml.etree.ElementTree import Element

        el = Element("package", attrib={"id": "", "version": "1.0"})
        assert _dependency_from_package_element(el) is None


# ---------------------------------------------------------------------------
# discover_packages_config_dependencies — end-to-end
# ---------------------------------------------------------------------------


class TestDiscoverPackagesConfigDependencies:
    def test_single_file(self, tmp_path):
        _write(
            tmp_path / "MyProject" / "packages.config",
            """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="A" version="1.0" />
  <package id="B" version="2.0" developmentDependency="true" />
</packages>""",
        )
        deps, filtered = discover_packages_config_dependencies(tmp_path)
        assert filtered == 0
        assert len(deps) == 2
        a = next(d for d in deps if d.name == "A")
        b = next(d for d in deps if d.name == "B")
        assert a.group == DependencyGroup.PROD
        assert b.group == DependencyGroup.DEV

    def test_multiple_files_each_with_own_source_path(self, tmp_path):
        _write(
            tmp_path / "Proj1" / "packages.config",
            """<?xml version="1.0"?><packages><package id="X" version="1.0" /></packages>""",
        )
        _write(
            tmp_path / "Proj2" / "packages.config",
            """<?xml version="1.0"?><packages><package id="Y" version="2.0" /></packages>""",
        )
        deps, _ = discover_packages_config_dependencies(tmp_path)
        sources = {d.source for d in deps}
        assert "Proj1/packages.config" in sources
        assert "Proj2/packages.config" in sources

    def test_no_packages_config_files_returns_empty(self, tmp_path):
        # Tree with nothing relevant.
        (tmp_path / "src" / "foo.cs").parent.mkdir(parents=True)
        (tmp_path / "src" / "foo.cs").write_text("// nothing", encoding="utf-8")
        deps, filtered = discover_packages_config_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    def test_unreadable_file_skipped(self, tmp_path, monkeypatch):
        _write(
            tmp_path / "packages.config",
            """<?xml version="1.0"?><packages><package id="X" version="1.0" /></packages>""",
        )
        original = Path.read_bytes

        def explode(self, *args, **kwargs):
            if self.name == "packages.config":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", explode)
        deps, _ = discover_packages_config_dependencies(tmp_path)
        assert deps == []

    def test_malformed_file_skipped(self, tmp_path):
        _write(tmp_path / "packages.config", "<not closed")
        _write(
            tmp_path / "Good" / "packages.config",
            """<?xml version="1.0"?><packages><package id="Good" version="1.0" /></packages>""",
        )
        deps, _ = discover_packages_config_dependencies(tmp_path)
        assert {d.name for d in deps} == {"Good"}

    def test_empty_packages_block_skipped(self, tmp_path):
        # Valid XML but no packages — must not emit anything.
        _write(
            tmp_path / "packages.config",
            """<?xml version="1.0"?><packages></packages>""",
        )
        deps, _ = discover_packages_config_dependencies(tmp_path)
        assert deps == []

    def test_utf8_bom_tolerated(self, tmp_path):
        path = tmp_path / "packages.config"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            b'\xef\xbb\xbf<?xml version="1.0"?>'
            b"<packages>"
            b'<package id="BomDep" version="1.0" />'
            b"</packages>"
        )
        deps, _ = discover_packages_config_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "BomDep"

    def test_source_path_is_posix(self, tmp_path):
        _write(
            tmp_path / "src" / "Proj" / "packages.config",
            """<?xml version="1.0"?><packages><package id="X" version="1.0" /></packages>""",
        )
        deps, _ = discover_packages_config_dependencies(tmp_path)
        assert deps[0].source == "src/Proj/packages.config"
