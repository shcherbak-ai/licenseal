"""Tests for Java/JVM (Maven + Gradle) discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import collect_read_diagnostics
from licenseal.discovery.java.build_gradle import (
    _extract_coord_from_rest,
    _parse_build_gradle,
    discover_build_gradle_dependencies,
)
from licenseal.discovery.java.gradle_lockfile import (
    find_gradle_lockfiles,
    parse_gradle_lockfile,
)
from licenseal.discovery.java.pom_xml import (
    _discover_workspace_local_artifacts,
    _expand_properties,
    _findall,
    _findtext,
    _parse_pom,
    _project_properties,
    _scope_to_group,
    _strip_ns,
    detect_project_license_pom_xml,
    discover_pom_xml_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem

# ============================================================================
# pom.xml — internal helpers
# ============================================================================


class TestStripNs:
    def test_strips_maven_namespace(self):
        assert _strip_ns("{http://maven.apache.org/POM/4.0.0}project") == "project"

    def test_unprefixed_tag_passthrough(self):
        assert _strip_ns("project") == "project"

    def test_other_namespace_stripped(self):
        # Any ``{…}`` prefix is stripped, not just Maven's 4.0.0.
        # This covers Maven 4.1.0 POMs (``…/POM/4.1.0`` namespace) and
        # hand-authored test fixtures that pick non-standard URIs.
        assert _strip_ns("{http://example.com}foo") == "foo"

    def test_maven_4_1_namespace_stripped(self):
        # Maven 4 POMs (Apache Maven 4.x development) declare the
        # ``http://maven.apache.org/POM/4.1.0`` namespace. The Apache
        # Maven repo itself ships test fixtures using this form.
        assert _strip_ns("{http://maven.apache.org/POM/4.1.0}artifactId") == "artifactId"

    def test_unclosed_namespace_marker_passthrough(self):
        # Defensive: ElementTree never produces a tag like ``{unclosed``
        # without a closing ``}``, but if one ever slipped through (e.g.
        # a hand-constructed Element with junk in `.tag`) the stripper
        # should leave it alone rather than slice into the rest of the
        # string.
        assert _strip_ns("{unclosed") == "{unclosed"


class TestFindHelpers:
    def _root(self, xml: str):
        from defusedxml import ElementTree as DefusedET

        return DefusedET.fromstring(xml)

    def test_findtext_returns_text(self):
        el = self._root("<project><groupId>com.x</groupId></project>")
        assert _findtext(el, "groupId") == "com.x"

    def test_findtext_strips_whitespace(self):
        el = self._root("<project><groupId>\n  com.x  \n</groupId></project>")
        assert _findtext(el, "groupId") == "com.x"

    def test_findtext_missing_returns_empty(self):
        el = self._root("<project></project>")
        assert _findtext(el, "groupId") == ""

    def test_findtext_empty_text_returns_empty(self):
        el = self._root("<project><groupId></groupId></project>")
        assert _findtext(el, "groupId") == ""

    def test_findtext_first_match_wins(self):
        el = self._root("<project><groupId>first</groupId><groupId>second</groupId></project>")
        assert _findtext(el, "groupId") == "first"

    def test_findall_returns_all_matching(self):
        el = self._root("<project><dep>a</dep><dep>b</dep><other>x</other></project>")
        assert len(_findall(el, "dep")) == 2

    def test_findall_no_matches_returns_empty(self):
        el = self._root("<project></project>")
        assert _findall(el, "dep") == []


class TestParsePom:
    def test_minimal_pom(self):
        pom = _parse_pom(
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<groupId>com.x</groupId>"
            "<artifactId>art</artifactId>"
            "<version>1.0</version>"
            "</project>"
        )
        assert pom.group_id == "com.x"
        assert pom.artifact_id == "art"
        assert pom.version == "1.0"

    def test_no_namespace_still_parses(self):
        # Some POMs in the wild omit the xmlns; defusedxml still parses.
        pom = _parse_pom(
            "<project>"
            "<groupId>com.x</groupId>"
            "<artifactId>art</artifactId>"
            "<version>1.0</version>"
            "</project>"
        )
        assert pom.group_id == "com.x"

    def test_parent_inheritance_for_groupid(self):
        # Child omits <groupId>; should inherit from <parent><groupId>.
        pom = _parse_pom(
            "<project>"
            "<artifactId>child</artifactId>"
            "<parent>"
            "<groupId>com.parent</groupId>"
            "<artifactId>parent-pom</artifactId>"
            "<version>2.0</version>"
            "</parent>"
            "</project>"
        )
        assert pom.group_id == "com.parent"
        assert pom.version == "2.0"
        assert pom.parent_group_id == "com.parent"
        assert pom.parent_artifact_id == "parent-pom"
        assert pom.parent_version == "2.0"

    def test_explicit_groupid_overrides_parent(self):
        pom = _parse_pom(
            "<project>"
            "<groupId>com.child</groupId>"
            "<artifactId>child</artifactId>"
            "<version>1.0</version>"
            "<parent>"
            "<groupId>com.parent</groupId>"
            "<artifactId>parent</artifactId>"
            "<version>2.0</version>"
            "</parent>"
            "</project>"
        )
        assert pom.group_id == "com.child"
        assert pom.version == "1.0"

    def test_properties_collected(self):
        pom = _parse_pom(
            "<project>"
            "<properties>"
            "<jackson.version>2.15.0</jackson.version>"
            "<spring.version>5.3.20</spring.version>"
            "</properties>"
            "</project>"
        )
        assert pom.properties == {
            "jackson.version": "2.15.0",
            "spring.version": "5.3.20",
        }

    def test_licenses_collected(self):
        # Each entry surfaces both ``<name>`` and ``<url>`` as a tuple —
        # the URL is the canonical fallback when the name is non-SPDX.
        pom = _parse_pom(
            "<project>"
            "<licenses>"
            "<license>"
            "<name>Apache License 2.0</name>"
            "<url>http://www.apache.org/licenses/LICENSE-2.0</url>"
            "</license>"
            "<license><name>MIT</name></license>"
            "</licenses>"
            "</project>"
        )
        assert pom.licenses == [
            ("Apache License 2.0", "http://www.apache.org/licenses/LICENSE-2.0"),
            ("MIT", ""),
        ]

    def test_license_url_only_no_name_kept(self):
        # An entry with only ``<url>`` is now retained — modern POMs
        # sometimes point directly at an SPDX URL with no human-readable
        # name, and the resolver can identify the license from the URL.
        pom = _parse_pom(
            "<project>"
            "<licenses>"
            "<license><url>https://spdx.org/licenses/MIT.html</url></license>"
            "<license><name>MIT</name></license>"
            "</licenses>"
            "</project>"
        )
        assert pom.licenses == [
            ("", "https://spdx.org/licenses/MIT.html"),
            ("MIT", ""),
        ]

    def test_license_entry_with_nothing_skipped(self):
        # An entry with neither name nor url is meaningless — drop.
        pom = _parse_pom(
            "<project>"
            "<licenses>"
            "<license></license>"
            "<license><name>MIT</name></license>"
            "</licenses>"
            "</project>"
        )
        assert pom.licenses == [("MIT", "")]

    def test_dependencies_collected(self):
        pom = _parse_pom(
            "<project>"
            "<dependencies>"
            "<dependency>"
            "<groupId>g1</groupId><artifactId>a1</artifactId><version>1.0</version>"
            "</dependency>"
            "<dependency>"
            "<groupId>g2</groupId><artifactId>a2</artifactId><version>2.0</version>"
            "<scope>test</scope>"
            "</dependency>"
            "</dependencies>"
            "</project>"
        )
        assert len(pom.dependencies) == 2
        assert pom.dependencies[0].group_id == "g1"
        assert pom.dependencies[1].scope == "test"

    def test_dependency_missing_groupid_skipped(self):
        pom = _parse_pom(
            "<project>"
            "<dependencies>"
            "<dependency>"
            "<artifactId>orphan</artifactId><version>1.0</version>"
            "</dependency>"
            "</dependencies>"
            "</project>"
        )
        assert pom.dependencies == []

    def test_import_scope_flagged(self):
        pom = _parse_pom(
            "<project>"
            "<dependencies>"
            "<dependency>"
            "<groupId>g</groupId><artifactId>a</artifactId><version>1</version>"
            "<type>pom</type><scope>import</scope>"
            "</dependency>"
            "</dependencies>"
            "</project>"
        )
        assert pom.dependencies[0].is_import is True

    def test_import_scope_without_pom_type_not_flagged(self):
        # ``<scope>import</scope>`` is a BOM marker only when combined with
        # ``<type>pom</type>``. Without the type, treat as a regular import-
        # scoped dep (rare; defensive).
        pom = _parse_pom(
            "<project>"
            "<dependencies>"
            "<dependency>"
            "<groupId>g</groupId><artifactId>a</artifactId><version>1</version>"
            "<scope>import</scope>"
            "</dependency>"
            "</dependencies>"
            "</project>"
        )
        assert pom.dependencies[0].is_import is False

    def test_malformed_xml_returns_none(self):
        # Truncated / unparseable XML → ``None`` (parse failure → analysis gap),
        # the same contract as the empty-string case below.
        assert _parse_pom("<project><not closed") is None

    def test_non_project_root_returns_empty(self):
        # If the root element isn't <project>, refuse to parse — POM XML
        # spec requires <project> as root.
        pom = _parse_pom("<settings><groupId>x</groupId></settings>")
        assert pom.group_id == ""
        assert pom.dependencies == []

    def test_billion_laughs_neutralized(self):
        # defusedxml refuses to expand the entity bomb.
        bomb = (
            '<?xml version="1.0"?>'
            "<!DOCTYPE lolz ["
            '<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            "]>"
            "<project><artifactId>&lol2;</artifactId></project>"
        )
        pom = _parse_pom(bomb)
        # Either EntitiesForbidden or ParseError — both now return ``None`` so
        # the caller records an analysis gap. Code MUST NOT crash, and the
        # entity MUST NOT have been expanded.
        assert pom is None

    def test_empty_string_returns_none(self):
        # Empty / unparseable XML → ``None`` (parse failure → gap), as opposed
        # to a valid-but-non-project document which returns an empty _PomData.
        assert _parse_pom("") is None

    def test_external_entity_blocked(self):
        # External entity expansion would fetch URLs — defusedxml blocks.
        evil = (
            '<?xml version="1.0"?>'
            "<!DOCTYPE foo ["
            '<!ENTITY x SYSTEM "http://example.com/evil.xml">'
            "]>"
            "<project><artifactId>&x;</artifactId></project>"
        )
        pom = _parse_pom(evil)
        # Blocked (EntitiesForbidden) → None; nothing fetched.
        assert pom is None


class TestProjectProperties:
    def test_includes_project_defaults(self):
        pom = _parse_pom(
            "<project>"
            "<groupId>com.x</groupId>"
            "<artifactId>art</artifactId>"
            "<version>1.0</version>"
            "<parent>"
            "<groupId>com.parent</groupId>"
            "<artifactId>parent</artifactId>"
            "<version>2.0</version>"
            "</parent>"
            "</project>"
        )
        props = _project_properties(pom)
        assert props["project.groupId"] == "com.x"
        assert props["project.artifactId"] == "art"
        assert props["project.version"] == "1.0"
        assert props["project.parent.version"] == "2.0"

    def test_user_properties_override_defaults(self):
        # If user defines a property named "project.version", their value
        # overrides the default (matches Maven behavior).
        pom = _parse_pom(
            "<project>"
            "<version>1.0</version>"
            "<properties>"
            "<project.version>custom</project.version>"
            "</properties>"
            "</project>"
        )
        props = _project_properties(pom)
        assert props["project.version"] == "custom"


class TestExpandProperties:
    def test_basic_substitution(self):
        assert _expand_properties("${foo}", {"foo": "bar"}) == "bar"

    def test_no_substitution_when_no_braces(self):
        assert _expand_properties("plain", {"foo": "bar"}) == "plain"

    def test_multiple_substitutions(self):
        result = _expand_properties("${a}-${b}", {"a": "1", "b": "2"})
        assert result == "1-2"

    def test_unresolved_token_left_literal(self):
        # The downstream version extractor will reject literal ${...}
        # tokens and emit UNKNOWN — correct posture for deps that need
        # parent-POM resolution.
        assert _expand_properties("${missing}", {}) == "${missing}"

    def test_partial_resolution(self):
        # Mix of resolved + unresolved tokens.
        assert _expand_properties("${a}-${b}", {"a": "X"}) == "X-${b}"

    def test_empty_value(self):
        assert _expand_properties("", {}) == ""

    def test_no_braces_passthrough(self):
        # The early-exit branch when no ``${`` is present.
        assert _expand_properties("5.3.20", {"foo": "bar"}) == "5.3.20"

    def test_nested_property_reference_expands(self):
        # Real Maven BOMs (jackson-bom is the canonical example) define
        # a property whose value is itself another ``${…}`` reference.
        # Single-pass expansion would leave the intermediate literal in
        # place; the multi-pass loop chases through until stable.
        props = {
            "jackson.version.dataformat": "${jackson.version}",
            "jackson.version": "2.20.2",
        }
        assert _expand_properties("${jackson.version.dataformat}", props) == "2.20.2"

    def test_three_level_nested_expansion(self):
        # ${a} → ${b} → ${c} → "1.0" — typical of CI-friendly versioning
        # plus a per-module override layer plus the actual value.
        props = {"a": "${b}", "b": "${c}", "c": "1.0"}
        assert _expand_properties("${a}", props) == "1.0"

    def test_circular_property_references_terminate(self):
        # Pathological POM with a self-referencing property cycle. The
        # multi-pass loop's expansion cap prevents an infinite loop;
        # the result is bounded but not necessarily empty (a literal
        # ``${...}`` survives, which the version-extractor rejects).
        props = {"foo": "${bar}", "bar": "${foo}"}
        result = _expand_properties("${foo}", props)
        # Result is one of the cycle members, not exploded into infinity.
        assert result in {"${foo}", "${bar}"}


class TestScopeToGroup:
    @pytest.mark.parametrize(
        ("scope", "expected"),
        [
            ("compile", DependencyGroup.PROD),
            ("runtime", DependencyGroup.PROD),
            ("", DependencyGroup.PROD),
            ("test", DependencyGroup.DEV),
            ("provided", DependencyGroup.DEV),
            ("system", DependencyGroup.DEV),
            ("unknown-scope", DependencyGroup.PROD),  # unknown defaults to PROD
        ],
    )
    def test_mapping(self, scope, expected):
        assert _scope_to_group(scope) == expected


# ============================================================================
# pom.xml — discovery
# ============================================================================


def _write_pom(p: Path, content: str) -> None:
    p.write_text(content, encoding="utf-8")


_BASIC_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>myproject</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.12.0</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""


class TestDiscoverPomXmlDependencies:
    def test_basic_discovery(self, tmp_path):
        _write_pom(tmp_path / "pom.xml", _BASIC_POM)
        deps, filtered = discover_pom_xml_dependencies(tmp_path)
        assert filtered == 0
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"org.apache.commons:commons-lang3", "junit:junit"}
        groups = {d.name: d.group for d in deps}
        assert groups["org.apache.commons:commons-lang3"] == DependencyGroup.PROD
        assert groups["junit:junit"] == DependencyGroup.DEV
        for d in deps:
            assert d.ecosystem == Ecosystem.JAVA
            assert d.source == "pom.xml"

    def test_local_dependency_management_fills_in_version(self, tmp_path):
        # A POM that declares both <dependencyManagement> and <dependencies>
        # with versions only in the DM block — the BOM-consumer pattern
        # within a single file. The discovery layer must surface the
        # version from the DM block rather than emitting an empty
        # version_constraint (which would route to UNKNOWN at resolve time).
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.apache.commons</groupId>
                        <artifactId>commons-lang3</artifactId>
                        <version>3.12.0</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
            <dependencies>
                <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "org.apache.commons:commons-lang3"
        assert deps[0].version_constraint == "3.12.0"

    def test_local_dm_with_property_expansion(self, tmp_path):
        # The DM block's version can itself be a ``${name}`` reference;
        # discovery must expand against the same <properties> set.
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <properties>
                <spring.version>5.3.20</spring.version>
            </properties>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>${spring.version}</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
            <dependencies>
                <dependency>
                    <groupId>org.springframework</groupId>
                    <artifactId>spring-core</artifactId>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        assert deps[0].version_constraint == "5.3.20"

    def test_local_dm_skips_bom_imports(self, tmp_path):
        # BOM-import entries in <dependencyManagement> (scope=import,
        # type=pom) declare *other POMs whose DM should be merged*,
        # not managed versions for the local dep set. The local-DM
        # fill-in path must not pick up the BOM-import's version
        # (which is the BOM POM's version, not any specific dep's).
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-dependencies</artifactId>
                        <version>3.2.0</version>
                        <type>pom</type>
                        <scope>import</scope>
                    </dependency>
                </dependencies>
            </dependencyManagement>
            <dependencies>
                <dependency>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-dependencies</artifactId>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        # The local lookup must NOT use the BOM-import entry; the
        # <dependency> remains version-empty, and the transitive walker's
        # parent-chain walk is responsible for filling it in.
        assert deps[0].version_constraint == ""

    def test_empty_dm_block_no_dependencies_child(self, tmp_path):
        # Edge case: a <dependencyManagement> block declared without a
        # <dependencies> child. Maven permits this (DM with only BOM
        # plugin config inheriting from a parent); the parser must
        # handle it without trying to enumerate non-existent children.
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <dependencyManagement>
            </dependencyManagement>
            <dependencies>
                <dependency>
                    <groupId>org.x</groupId>
                    <artifactId>y</artifactId>
                    <version>1.0</version>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        # No crash; the dep with an explicit version is still extracted.
        assert len(deps) == 1
        assert deps[0].name == "org.x:y"
        assert deps[0].version_constraint == "1.0"

    def test_local_dm_skips_unresolved_property(self, tmp_path):
        # If a DM entry's version is itself an unresolved ${…} token
        # (a parent-POM property), don't poison the local lookup with
        # the literal token; leave the consumer version empty so the
        # transitive walker's parent walk can resolve it.
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.x</groupId>
                        <artifactId>y</artifactId>
                        <version>${parent.defined.version}</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
            <dependencies>
                <dependency>
                    <groupId>org.x</groupId>
                    <artifactId>y</artifactId>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        assert deps[0].version_constraint == ""

    def test_profile_dm_fills_in_version(self, tmp_path):
        # Profile-conditional <dependencyManagement>: a child POM
        # declares a dep without version; the version lives in
        # <profiles><profile><dependencyManagement>. For license
        # discovery we treat all profile DMs as available — we don't
        # need to know which profile is "active" at build time.
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <profiles>
                <profile>
                    <id>java-21</id>
                    <dependencyManagement>
                        <dependencies>
                            <dependency>
                                <groupId>org.apache.commons</groupId>
                                <artifactId>commons-lang3</artifactId>
                                <version>3.14.0</version>
                            </dependency>
                        </dependencies>
                    </dependencyManagement>
                </profile>
            </profiles>
            <dependencies>
                <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "org.apache.commons:commons-lang3"
        # Profile-DM resolved the version.
        assert deps[0].version_constraint == "3.14.0"

    def test_top_level_dm_wins_over_profile_dm(self, tmp_path):
        # When the same coord is managed by both the top-level DM and
        # a profile DM, the top-level should win (it's the
        # always-active baseline). Order of insertion into
        # managed_dependencies is: top-level first, then profiles —
        # so the dict-based local_dm lookup naturally takes the
        # first hit, which is top-level.
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.apache.commons</groupId>
                        <artifactId>commons-lang3</artifactId>
                        <version>3.12.0</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
            <profiles>
                <profile>
                    <id>p1</id>
                    <dependencyManagement>
                        <dependencies>
                            <dependency>
                                <groupId>org.apache.commons</groupId>
                                <artifactId>commons-lang3</artifactId>
                                <version>3.99.0</version>
                            </dependency>
                        </dependencies>
                    </dependencyManagement>
                </profile>
            </profiles>
            <dependencies>
                <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        # Top-level DM wins.
        assert deps[0].version_constraint == "3.12.0"

    def test_property_expansion(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId>
            <artifactId>p</artifactId>
            <version>1.0</version>
            <properties>
                <jackson.version>2.15.0</jackson.version>
            </properties>
            <dependencies>
                <dependency>
                    <groupId>com.fasterxml.jackson.core</groupId>
                    <artifactId>jackson-databind</artifactId>
                    <version>${jackson.version}</version>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        assert deps[0].version_constraint == "2.15.0"

    def test_unresolved_property_left_literal(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId><artifactId>p</artifactId><version>1.0</version>
            <dependencies>
                <dependency>
                    <groupId>g</groupId>
                    <artifactId>a</artifactId>
                    <version>${external.parent.property}</version>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        # Unresolved ${...} stays literal — resolver will UNKNOWN it.
        assert deps[0].version_constraint == "${external.parent.property}"

    def test_bom_import_skipped(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.x</groupId><artifactId>p</artifactId><version>1.0</version>
            <dependencies>
                <dependency>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-dependencies</artifactId>
                    <version>3.2.0</version>
                    <type>pom</type>
                    <scope>import</scope>
                </dependency>
                <dependency>
                    <groupId>g</groupId>
                    <artifactId>a</artifactId>
                    <version>1.0</version>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"g:a"}

    def test_multi_module_workspace_local_filter(self, tmp_path):
        # Root POM declares two modules, plus a sibling reference to one.
        # The sibling reference must be filtered.
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <groupId>com.example</groupId>
            <artifactId>root</artifactId>
            <version>1.0</version>
            <modules>
                <module>core</module>
                <module>web</module>
            </modules>
            </project>""",
        )
        (tmp_path / "core").mkdir()
        _write_pom(
            tmp_path / "core" / "pom.xml",
            """<project>
            <parent>
                <groupId>com.example</groupId>
                <artifactId>root</artifactId>
                <version>1.0</version>
            </parent>
            <artifactId>core</artifactId>
            </project>""",
        )
        (tmp_path / "web").mkdir()
        _write_pom(
            tmp_path / "web" / "pom.xml",
            """<project>
            <parent>
                <groupId>com.example</groupId>
                <artifactId>root</artifactId>
                <version>1.0</version>
            </parent>
            <artifactId>web</artifactId>
            <dependencies>
                <dependency>
                    <groupId>com.example</groupId>
                    <artifactId>core</artifactId>
                    <version>1.0</version>
                </dependency>
                <dependency>
                    <groupId>org.external</groupId>
                    <artifactId>lib</artifactId>
                    <version>2.0</version>
                </dependency>
            </dependencies>
            </project>""",
        )
        deps, filtered = discover_pom_xml_dependencies(tmp_path)
        assert filtered == 1  # com.example:core filtered as workspace-local
        names = {d.name for d in deps}
        assert names == {"org.external:lib"}

    def test_unreadable_pom_skipped(self, tmp_path, monkeypatch):
        _write_pom(tmp_path / "pom.xml", _BASIC_POM)

        original_read_bytes = Path.read_bytes

        def failing_read_bytes(self, *args, **kwargs):
            if self.name == "pom.xml":
                raise OSError("simulated")
            return original_read_bytes(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_bytes", failing_read_bytes)
        deps, filtered = discover_pom_xml_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    def test_non_utf8_pom_decoded_via_prolog(self, tmp_path):
        # A pom.xml validly encoded as ISO-8859-1 (declared in its prolog),
        # with a non-ASCII byte in a comment, must be parsed rather than
        # dropped — ElementTree honors the prolog when handed raw bytes, so a
        # forced-UTF-8 read no longer silently skips the whole file.
        pom = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            "<project><!-- José Garcia -->"
            "<dependencies><dependency>"
            "<groupId>com.x</groupId><artifactId>y</artifactId><version>2.0</version>"
            "</dependency></dependencies></project>"
        )
        (tmp_path / "pom.xml").write_bytes(pom.encode("latin-1"))
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        assert {d.name for d in deps} == {"com.x:y"}


def _dep(coord: str, version: str = "", scope: str = "", dep_type: str = "") -> str:
    group_id, artifact_id = coord.split(":")
    return (
        f"<dependency><groupId>{group_id}</groupId><artifactId>{artifact_id}</artifactId>"
        + (f"<version>{version}</version>" if version else "")
        + (f"<scope>{scope}</scope>" if scope else "")
        + (f"<type>{dep_type}</type>" if dep_type else "")
        + "</dependency>"
    )


def _deps(*entries: str) -> str:
    return "<dependencies>" + "".join(entries) + "</dependencies>"


def _properties(**values: str) -> str:
    # Keyword names use ``_`` where the property name has ``.``.
    body = "".join(f"<{k.replace('_', '.')}>{v}</{k.replace('_', '.')}>" for k, v in values.items())
    return f"<properties>{body}</properties>"


def _profile(*body: str, activation: str = "") -> str:
    return f"<profile><id>p</id>{activation}{''.join(body)}</profile>"


def _profile_pom(*profiles: str, top_level: str = "") -> str:
    return f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    {top_level}
    <profiles>{"".join(profiles)}</profiles>
</project>"""


class TestDiscoverPomXmlProfileDependencies:
    """A ``<dependency>`` declared inside ``<profiles><profile>`` is a
    dependency of the project. Activation is not evaluated: every profile's
    dependencies are unioned with the top-level ones.
    """

    def test_default_active_profile_dependency_discovered(self, tmp_path):
        # The only dependency lives in a profile that is active by default.
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(
                    _deps(_dep("org.example:runtime-lib", "2.1.0", "runtime")),
                    activation="<activation><activeByDefault>true</activeByDefault></activation>",
                )
            ),
        )
        with collect_read_diagnostics() as diags:
            deps, _ = discover_all_dependencies(tmp_path)
        assert [(d.name, d.version_constraint, d.group, d.source) for d in deps] == [
            ("org.example:runtime-lib", "2.1.0", DependencyGroup.PROD, "pom.xml")
        ]
        # A profile is not an analysis gap.
        assert diags == []

    def test_every_profile_unioned_whatever_its_activation(self, tmp_path):
        activations = [
            "",
            "<activation><jdk>[17,)</jdk></activation>",
            "<activation><os><family>windows</family></os></activation>",
            "<activation><property><name>release</name></property></activation>",
            "<activation><activeByDefault>false</activeByDefault></activation>",
        ]
        profiles = [
            _profile(_deps(_dep(f"org.example:lib-{i}", "1.0")), activation=activation)
            for i, activation in enumerate(activations)
        ]
        _write_pom(tmp_path / "pom.xml", _profile_pom(*profiles))
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.name for d in deps] == [f"org.example:lib-{i}" for i in range(5)]

    def test_profile_dependencies_use_the_normal_scope_mapping(self, tmp_path):
        entries = [
            _dep(f"org.example:{scope or 'default'}", "1.0", scope)
            for scope in ("", "compile", "runtime", "test", "provided", "system")
        ]
        _write_pom(tmp_path / "pom.xml", _profile_pom(_profile(_deps(*entries))))
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name.split(":")[1]: d.group for d in deps} == {
            "default": DependencyGroup.PROD,
            "compile": DependencyGroup.PROD,
            "runtime": DependencyGroup.PROD,
            "test": DependencyGroup.DEV,
            "provided": DependencyGroup.DEV,
            "system": DependencyGroup.DEV,
        }

    def test_profile_property_resolves_profile_dependency_version(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(
                    _properties(lib_version="4.5.6"),
                    _deps(_dep("org.example:lib", "${lib.version}")),
                )
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [(d.name, d.version_constraint) for d in deps] == [("org.example:lib", "4.5.6")]

    def test_project_property_wins_over_profile_property(self, tmp_path):
        # Profile properties are a fallback: a name the POM's own
        # <properties> defines is never overridden by a profile.
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(
                    _properties(lib_version="9.9.9"),
                    _deps(_dep("org.example:lib", "${lib.version}")),
                ),
                top_level=_properties(lib_version="1.2.3"),
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.version_constraint for d in deps] == ["1.2.3"]

    def test_first_profile_definition_of_a_property_wins(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(_properties(lib_version="1.0.0")),
                _profile(
                    _properties(lib_version="2.0.0"),
                    _deps(_dep("org.example:lib", "${lib.version}")),
                ),
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.version_constraint for d in deps] == ["1.0.0"]

    def test_profile_property_does_not_reach_top_level_dependency(self, tmp_path):
        # A top-level dependency keeps resolving exactly as before: a name
        # defined only in a profile stays a literal token for it.
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(_properties(lib_version="4.5.6")),
                top_level=_deps(_dep("org.example:lib", "${lib.version}")),
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.version_constraint for d in deps] == ["${lib.version}"]

    def test_unresolved_profile_property_left_literal(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(
                    "<properties/>",
                    _deps(_dep("org.example:lib", "${elsewhere.version}")),
                )
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.version_constraint for d in deps] == ["${elsewhere.version}"]

    def test_versionless_profile_dependency_filled_from_dependency_management(self, tmp_path):
        managed = _deps(_dep("org.example:managed", "3.0.0"))
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(_deps(_dep("org.example:managed"))),
                top_level=f"<dependencyManagement>{managed}</dependencyManagement>",
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [(d.name, d.version_constraint) for d in deps] == [("org.example:managed", "3.0.0")]

    def test_bom_import_marker_in_profile_dependencies_skipped(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(
                    _deps(
                        _dep("org.example:bom", "1.0", "import", "pom"),
                        _dep("org.example:lib", "1.0"),
                    )
                )
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.name for d in deps] == ["org.example:lib"]

    def test_workspace_local_sibling_in_profile_filtered(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(_deps(_dep("com.example:core", "1.0.0"), _dep("org.example:lib", "1.0")))
            ),
        )
        (tmp_path / "core").mkdir()
        _write_pom(
            tmp_path / "core" / "pom.xml",
            "<project><groupId>com.example</groupId><artifactId>core</artifactId>"
            "<version>1.0.0</version></project>",
        )
        deps, counts = discover_all_dependencies(tmp_path)
        assert [d.name for d in deps] == ["org.example:lib"]
        assert counts["java"] == 1

    def test_top_level_declaration_precedes_profile_declaration(self, tmp_path):
        # The same coordinate declared at both levels: the always-active
        # top-level entry is listed first, so it is the one the aggregator
        # keeps.
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(_deps(_dep("org.example:lib", "2.0.0"))),
                top_level=_deps(_dep("org.example:lib", "1.0.0")),
            ),
        )
        deps, _ = discover_pom_xml_dependencies(tmp_path)
        assert [d.version_constraint for d in deps] == ["1.0.0", "2.0.0"]
        unique, _ = discover_all_dependencies(tmp_path)
        assert [d.version_constraint for d in unique] == ["1.0.0"]

    def test_profile_production_scope_upgrades_top_level_test_scope(self, tmp_path):
        # Test-scoped at the top level, compile-scoped in a profile: the
        # aggregator prefers the production declaration.
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(
                _profile(_deps(_dep("org.example:lib", "1.0.0"))),
                top_level=_deps(_dep("org.example:lib", "1.0.0", "test")),
            ),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [(d.name, d.group) for d in deps] == [("org.example:lib", DependencyGroup.PROD)]

    def test_profile_without_dependencies_emits_nothing(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            _profile_pom(_profile("<build/>"), _profile("<dependencies/>")),
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert deps == []

    def test_parse_pom_marks_profile_dependencies(self):
        pom = _parse_pom(
            _profile_pom(
                _profile(_properties(a="1"), _deps(_dep("org.example:in-profile", "1.0"))),
                top_level=_properties(b="2") + _deps(_dep("org.example:top-level", "1.0")),
            )
        )
        assert [(d.artifact_id, d.from_profile) for d in pom.dependencies] == [
            ("top-level", False),
            ("in-profile", True),
        ]
        # Profile properties stay out of the project's own property map.
        assert pom.properties == {"b": "2"}
        assert pom.profile_properties == {"a": "1"}


class TestDiscoverWorkspaceLocalArtifacts:
    def test_collects_all_in_tree_modules(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            "<project>"
            "<groupId>g</groupId><artifactId>root</artifactId><version>1</version>"
            "</project>",
        )
        (tmp_path / "sub").mkdir()
        _write_pom(
            tmp_path / "sub" / "pom.xml",
            "<project>"
            "<groupId>g</groupId><artifactId>sub</artifactId><version>1</version>"
            "</project>",
        )
        local = _discover_workspace_local_artifacts(tmp_path)
        assert local == {"g:root", "g:sub"}

    def test_skips_pom_without_groupid_or_artifactid(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            "<project></project>",  # incomplete
        )
        local = _discover_workspace_local_artifacts(tmp_path)
        assert local == set()

    def test_unreadable_pom_skipped(self, tmp_path, monkeypatch):
        _write_pom(
            tmp_path / "pom.xml",
            "<project><groupId>g</groupId><artifactId>a</artifactId></project>",
        )

        def failing_read_bytes(self, *args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", failing_read_bytes)
        local = _discover_workspace_local_artifacts(tmp_path)
        assert local == set()


class TestDiscoverWorkspaceLocalPomPathsTestFixtureFilter:
    """Test-fixture POMs (under ``src/test/`` or ``src/it/``) must NOT
    be indexed as workspace-local reactor siblings — they frequently
    declare fake/colliding coordinates that, when matched, send the
    DM-walk to the wrong pom (the apache/maven self-hosting case
    surfaced this: a fixture POM with ``<artifactId>maven</artifactId>``
    collided with the real reactor root and the walk lost ~21 deps).
    """

    from licenseal.discovery.java.pom_xml import (  # noqa: PLC0415
        _discover_workspace_local_pom_paths,
        _is_test_fixture_pom,
    )

    def test_test_resources_fixture_excluded(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            "<project><groupId>g</groupId><artifactId>real</artifactId>"
            "<version>1</version></project>",
        )
        # Build src/test/resources hierarchy with a colliding fixture
        # pom that would normally clobber the real one if not filtered.
        fixture_dir = tmp_path / "module" / "src" / "test" / "resources" / "fx"
        fixture_dir.mkdir(parents=True)
        _write_pom(
            fixture_dir / "pom.xml",
            "<project><groupId>g</groupId><artifactId>real</artifactId>"
            "<version>1</version></project>",
        )
        from licenseal.discovery.java.pom_xml import (  # noqa: PLC0415
            _discover_workspace_local_pom_paths,
        )

        result = _discover_workspace_local_pom_paths(tmp_path)
        assert "g:real" in result
        assert "src" not in result["g:real"].parts  # the real one, not the fixture

    def test_src_it_fixture_excluded(self, tmp_path):
        # Maven Invoker plugin convention: ``src/it/<test-name>/pom.xml``.
        _write_pom(
            tmp_path / "pom.xml",
            "<project><groupId>g</groupId><artifactId>real</artifactId>"
            "<version>1</version></project>",
        )
        it_dir = tmp_path / "module" / "src" / "it" / "scenario1"
        it_dir.mkdir(parents=True)
        _write_pom(
            it_dir / "pom.xml",
            "<project><groupId>g</groupId><artifactId>fictional</artifactId>"
            "<version>1</version></project>",
        )
        from licenseal.discovery.java.pom_xml import (  # noqa: PLC0415
            _discover_workspace_local_pom_paths,
        )

        result = _discover_workspace_local_pom_paths(tmp_path)
        assert "g:real" in result
        assert "g:fictional" not in result

    def test_helper_recognizes_test_fixture_paths(self):
        from licenseal.discovery.java.pom_xml import (  # noqa: PLC0415
            _is_test_fixture_pom,
        )

        assert _is_test_fixture_pom(Path("foo/src/test/resources/p/pom.xml"))
        assert _is_test_fixture_pom(Path("foo/src/it/scenario/pom.xml"))
        assert _is_test_fixture_pom(Path("a/b/c/src/test/anything/pom.xml"))

    def test_helper_does_not_match_non_test_paths(self):
        from licenseal.discovery.java.pom_xml import (  # noqa: PLC0415
            _is_test_fixture_pom,
        )

        assert not _is_test_fixture_pom(Path("foo/pom.xml"))
        assert not _is_test_fixture_pom(Path("foo/src/main/pom.xml"))
        # "test" as a non-src-immediate-child must not match — some
        # projects legitimately name a top-level submodule "test".
        assert not _is_test_fixture_pom(Path("foo/test/pom.xml"))


class TestDetectProjectLicensePomXml:
    def test_single_license(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <licenses>
                <license><name>Apache License 2.0</name></license>
            </licenses>
            </project>""",
        )
        assert detect_project_license_pom_xml(tmp_path) == "Apache License 2.0"

    def test_multi_license_joined_with_and(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            """<project>
            <licenses>
                <license><name>Apache-2.0</name></license>
                <license><name>MIT</name></license>
            </licenses>
            </project>""",
        )
        assert detect_project_license_pom_xml(tmp_path) == "Apache-2.0 AND MIT"

    def test_no_pom_returns_empty(self, tmp_path):
        assert detect_project_license_pom_xml(tmp_path) == ""

    def test_pom_without_licenses_returns_empty(self, tmp_path):
        _write_pom(
            tmp_path / "pom.xml",
            "<project><groupId>g</groupId><artifactId>a</artifactId></project>",
        )
        assert detect_project_license_pom_xml(tmp_path) == ""

    def test_nested_pom_used_when_root_missing(self, tmp_path):
        # If the repo root has no pom.xml but a nested module does, the
        # shallowest one is the project pom.
        (tmp_path / "submodule").mkdir()
        _write_pom(
            tmp_path / "submodule" / "pom.xml",
            """<project>
            <licenses>
                <license><name>BSD-3-Clause</name></license>
            </licenses>
            </project>""",
        )
        assert detect_project_license_pom_xml(tmp_path) == "BSD-3-Clause"

    def test_unreadable_root_pom_returns_empty(self, tmp_path, monkeypatch):
        _write_pom(
            tmp_path / "pom.xml",
            "<project><licenses><license><name>X</name></license></licenses></project>",
        )

        def failing_read_bytes(self, *args, **kwargs):
            raise OSError("nope")

        monkeypatch.setattr(Path, "read_bytes", failing_read_bytes)
        assert detect_project_license_pom_xml(tmp_path) == ""


# ============================================================================
# gradle.lockfile
# ============================================================================


class TestGradleLockfile:
    def test_find_returns_lockfiles(self, tmp_path):
        (tmp_path / "gradle.lockfile").write_text("", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "gradle.lockfile").write_text("", encoding="utf-8")
        result = find_gradle_lockfiles(tmp_path)
        assert len(result) == 2

    def test_parse_basic(self, tmp_path):
        lock = tmp_path / "gradle.lockfile"
        lock.write_text(
            "# header\n"
            "org.springframework:spring-core:5.3.20=compileClasspath,runtimeClasspath\n"
            "junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n"
            "empty=annotationProcessor\n",
            encoding="utf-8",
        )
        deps = parse_gradle_lockfile(lock)
        assert len(deps) == 2
        groups = {d.name: d.group for d in deps}
        assert groups["org.springframework:spring-core"] == DependencyGroup.PROD
        assert groups["junit:junit"] == DependencyGroup.DEV
        versions = {d.name: d.version_constraint for d in deps}
        assert versions["org.springframework:spring-core"] == "==5.3.20"

    def test_comments_and_empty_lines_skipped(self, tmp_path):
        lock = tmp_path / "gradle.lockfile"
        lock.write_text(
            "# comment\n\n    \ng:a:1.0=compileClasspath\n",
            encoding="utf-8",
        )
        deps = parse_gradle_lockfile(lock)
        assert len(deps) == 1

    def test_malformed_lines_skipped(self, tmp_path):
        lock = tmp_path / "gradle.lockfile"
        lock.write_text(
            "no-equals-sign\n"
            "too:few=classpath\n"  # missing version segment
            "valid:dep:1.0=compileClasspath\n",
            encoding="utf-8",
        )
        deps = parse_gradle_lockfile(lock)
        assert len(deps) == 1
        assert deps[0].name == "valid:dep"

    def test_empty_classpath_list_skipped(self, tmp_path):
        # Line with `=` but empty RHS — defensive, real Gradle output
        # always has at least one classpath.
        lock = tmp_path / "gradle.lockfile"
        lock.write_text("g:a:1.0=\n", encoding="utf-8")
        deps = parse_gradle_lockfile(lock)
        assert deps == []

    def test_prod_wins_on_duplicate(self, tmp_path):
        lock = tmp_path / "gradle.lockfile"
        # Same coord appears twice — once as test, once as prod. PROD wins.
        lock.write_text(
            "g:a:1.0=testCompileClasspath\ng:a:1.0=compileClasspath\n",
            encoding="utf-8",
        )
        deps = parse_gradle_lockfile(lock)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD

    def test_prod_wins_reverse_order(self, tmp_path):
        # Same coord twice — prod FIRST, then dev. Prod must remain (the
        # ``if key in seen and seen[key] == PROD: continue`` guard).
        lock = tmp_path / "gradle.lockfile"
        lock.write_text(
            "g:a:1.0=compileClasspath\ng:a:1.0=testCompileClasspath\n",
            encoding="utf-8",
        )
        deps = parse_gradle_lockfile(lock)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD

    def test_include_dev_false_drops_dev(self, tmp_path):
        lock = tmp_path / "gradle.lockfile"
        lock.write_text(
            "p:p:1=compileClasspath\nt:t:1=testCompileClasspath\n",
            encoding="utf-8",
        )
        deps = parse_gradle_lockfile(lock, include_dev=False)
        names = {d.name for d in deps}
        assert names == {"p:p"}

    def test_unreadable_lockfile_returns_empty(self, tmp_path, monkeypatch):
        lock = tmp_path / "gradle.lockfile"
        lock.write_text("g:a:1=compileClasspath\n", encoding="utf-8")
        monkeypatch.setattr(
            Path, "read_bytes", lambda self, *a, **kw: (_ for _ in ()).throw(OSError())
        )
        assert parse_gradle_lockfile(lock) == []


# ============================================================================
# build.gradle / build.gradle.kts
# ============================================================================


class TestConfigToGroup:
    def test_prod_configurations(self):
        from licenseal.discovery.java.build_gradle import _config_to_group as cg

        assert cg("implementation") == DependencyGroup.PROD
        assert cg("api") == DependencyGroup.PROD
        assert cg("runtimeOnly") == DependencyGroup.PROD
        assert cg("annotationProcessor") == DependencyGroup.PROD

    def test_dev_configurations(self):
        from licenseal.discovery.java.build_gradle import _config_to_group as cg

        assert cg("testImplementation") == DependencyGroup.DEV
        assert cg("androidTestImplementation") == DependencyGroup.DEV
        assert cg("checkstyle") == DependencyGroup.DEV

    def test_unknown_configuration_returns_none(self):
        from licenseal.discovery.java.build_gradle import _config_to_group as cg

        assert cg("customConfig") is None

    @pytest.mark.parametrize(
        "config",
        ["compileOnlyApi", "releaseImplementation", "releaseApi", "releaseRuntimeOnly", "shadow"],
    )
    def test_shipped_variant_configurations_are_prod(self, config):
        from licenseal.discovery.java.build_gradle import _config_to_group as cg

        assert cg(config) == DependencyGroup.PROD

    @pytest.mark.parametrize(
        "config",
        [
            "debugImplementation",
            "debugApi",
            "debugRuntimeOnly",
            "developmentOnly",
            "testFixturesApi",
            "testFixturesImplementation",
        ],
    )
    def test_debug_development_and_fixture_configurations_are_dev(self, config):
        from licenseal.discovery.java.build_gradle import _config_to_group as cg

        assert cg(config) == DependencyGroup.DEV

    def test_compile_only_api_matches_compile_only(self):
        from licenseal.discovery.java.build_gradle import _config_to_group as cg

        assert cg("compileOnlyApi") == cg("compileOnly")


class TestExtractCoordFromRest:
    def test_groovy_single_quoted(self):
        assert _extract_coord_from_rest("'g:a:1.0'") == ("g", "a", "1.0")

    def test_kotlin_double_quoted(self):
        assert _extract_coord_from_rest('"g:a:1.0"') == ("g", "a", "1.0")

    def test_with_classifier_takes_first_three(self):
        # `g:a:1.0:sources` — extra colon for classifier, we keep the version
        # truncated to the first non-colon stretch.
        result = _extract_coord_from_rest("'g:a:1.0:sources'")
        assert result == ("g", "a", "1.0")

    def test_groovy_map_form(self):
        assert _extract_coord_from_rest("group: 'g', name: 'a', version: 'v'") == ("g", "a", "v")

    def test_kotlin_map_form(self):
        assert _extract_coord_from_rest('group = "g", name = "a", version = "v"') == ("g", "a", "v")

    def test_map_form_missing_version(self):
        # Allowed — bare group+name with no version produces a coord with
        # empty version (the downstream resolver will UNKNOWN it).
        assert _extract_coord_from_rest("group: 'g', name: 'a'") == ("g", "a", "")

    def test_map_form_missing_name_returns_none(self):
        # Without name, can't form an artifact coordinate.
        assert _extract_coord_from_rest("group: 'g', version: '1'") is None

    def test_variable_interpolation_returns_none(self):
        # ``"...:$ver"`` is variable interpolation — heuristic skips.
        # Our regex requires ASCII-only chars in version, so $ breaks it.
        result = _extract_coord_from_rest('"g:a:$ver"')
        assert result is None

    def test_project_dep_returns_none(self):
        assert _extract_coord_from_rest("project(':core')") is None

    def test_platform_dep_returns_none(self):
        assert _extract_coord_from_rest("platform('g:a:1.0')") is None

    def test_enforced_platform_returns_none(self):
        assert _extract_coord_from_rest("enforcedPlatform('g:a:1.0')") is None

    def test_files_returns_none(self):
        assert _extract_coord_from_rest("files('libs/x.jar')") is None

    def test_filetree_returns_none(self):
        assert _extract_coord_from_rest("fileTree(dir: 'libs')") is None

    def test_no_match_returns_none(self):
        assert _extract_coord_from_rest("some random text") is None

    @pytest.mark.parametrize(
        "rest",
        [
            "'g:a'",  # Groovy
            '"g:a"',  # Kotlin, or a Groovy double-quoted string
            "'g:a') {",  # opens a configuration closure
            '"g:a") { exclude(group = "x", module = "y") }',
        ],
    )
    def test_versionless_string_form_has_empty_version(self, rest):
        # Same result as the map form without a version.
        assert _extract_coord_from_rest(rest) == ("g", "a", "")
        assert _extract_coord_from_rest(rest) == _extract_coord_from_rest("group: 'g', name: 'a'")

    @pytest.mark.parametrize(
        "rest",
        [
            "platform('g:a')",
            'platform("g:a")',
            "enforcedPlatform('g:a')",
            "project(':core')",
            'project(":libs:core")',
            "project(path: ':core', configuration: 'shadow')",
            "files('libs:x.jar')",
        ],
    )
    def test_versionless_shape_inside_a_call_is_not_a_coordinate(self, rest):
        assert _extract_coord_from_rest(rest) is None

    @pytest.mark.parametrize(
        "rest",
        [
            '"g:$artifact"',
            '"$group:a"',
            '"g:a$suffix"',
            '"g:${artifact}"',
            "'g:a:'",
            "':a'",
            "'g:'",
            "'https://example.invalid/x'",
        ],
    )
    def test_interpolated_or_malformed_two_segment_string_returns_none(self, rest):
        assert _extract_coord_from_rest(rest) is None

    @pytest.mark.parametrize(
        "rest",
        [
            # A two-segment string that is not the first argument is not a
            # coordinate: a closure argument, a version-catalog reference
            # followed by a string, a bare word.
            "libs.some.lib) { because('see:tracker') }",
            "someVariable, 'g:a'",
            "name 'g:a'",
        ],
    )
    def test_two_segment_string_past_the_first_argument_is_ignored(self, rest):
        assert _extract_coord_from_rest(rest) is None

    def test_map_form_not_shadowed_by_a_two_segment_map_value(self):
        rest = "group: 'g', name: 'a', version: '1.0', classifier: 'x:y'"
        assert _extract_coord_from_rest(rest) == ("g", "a", "1.0")

    def test_three_segment_string_still_wins(self):
        assert _extract_coord_from_rest("'g:a:1.0') { because('see:tracker') }") == (
            "g",
            "a",
            "1.0",
        )


class TestParseBuildGradle:
    def test_basic_groovy_implementation(self):
        text = "dependencies {\n  implementation 'g:a:1.0'\n}\n"
        result = _parse_build_gradle(text)
        assert ("g", "a", "1.0", DependencyGroup.PROD) in result

    def test_kotlin_implementation(self):
        text = 'dependencies {\n  implementation("g:a:1.0")\n}\n'
        result = _parse_build_gradle(text)
        assert ("g", "a", "1.0", DependencyGroup.PROD) in result

    def test_test_implementation_to_dev(self):
        text = "dependencies {\n  testImplementation 'g:a:1.0'\n}\n"
        result = _parse_build_gradle(text)
        assert ("g", "a", "1.0", DependencyGroup.DEV) in result

    def test_block_comment_stripped(self):
        text = (
            "dependencies {\n"
            "  /* commented out\n"
            "  implementation 'commented:out:1.0'\n"
            "  */\n"
            "  implementation 'real:dep:1.0'\n"
            "}\n"
        )
        result = _parse_build_gradle(text)
        names = {(g, a) for g, a, v, _ in result}
        assert ("real", "dep") in names
        assert ("commented", "out") not in names

    def test_inline_block_comment(self):
        text = "implementation /* note */ 'g:a:1.0'\n"
        result = _parse_build_gradle(text)
        # The inline `/* */` becomes whitespace; the regex should still
        # match the coordinate.
        assert ("g", "a", "1.0", DependencyGroup.PROD) in result

    def test_line_comment_stripped(self):
        text = "implementation 'g:a:1.0' // a comment\n"
        result = _parse_build_gradle(text)
        assert ("g", "a", "1.0", DependencyGroup.PROD) in result

    def test_unknown_configuration_skipped(self):
        text = "shadowImplementation 'g:a:1.0'\n"  # not in known set
        result = _parse_build_gradle(text)
        assert result == []

    def test_version_catalog_reference_skipped(self):
        # `libs.x.y` is a Gradle version catalog reference — we don't
        # resolve those.
        text = "implementation libs.spring.core\n"
        result = _parse_build_gradle(text)
        assert result == []

    def test_no_match_lines_skipped(self):
        text = "plugins { id 'java' }\n"
        result = _parse_build_gradle(text)
        assert result == []

    def test_empty_text(self):
        assert _parse_build_gradle("") == []

    def test_block_comment_across_lines_with_end(self):
        # A block comment that opens AND closes mid-line in the same line:
        # already covered by inline test. Now: opens on one line, closes
        # on a later line.
        text = (
            "dependencies {\n"
            "  /* multi\n"
            "  line implementation 'fake:fake:1.0' end */\n"
            "  implementation 'real:real:1.0'\n"
            "}\n"
        )
        result = _parse_build_gradle(text)
        names = {(g, a) for g, a, _, _ in result}
        assert ("real", "real") in names
        assert ("fake", "fake") not in names


class TestDiscoverBuildGradleDependencies:
    def test_discovers_from_build_gradle(self, tmp_path):
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n  implementation 'g:a:1.0'\n  testImplementation 'jt:jt:2.0'\n}\n",
            encoding="utf-8",
        )
        deps, filtered = discover_build_gradle_dependencies(tmp_path)
        assert filtered == 0
        names = {d.name for d in deps}
        assert names == {"g:a", "jt:jt"}

    def test_discovers_from_build_gradle_kts(self, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(
            'dependencies {\n  implementation("g:a:1.0")\n}\n',
            encoding="utf-8",
        )
        deps, _ = discover_build_gradle_dependencies(tmp_path)
        assert {d.name for d in deps} == {"g:a"}

    def test_prod_wins_on_duplicate_across_configurations(self, tmp_path):
        # Same coord appears in both test and prod configs across nested
        # build.gradle files — PROD wins.
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n  testImplementation 'g:a:1.0'\n}\n",
            encoding="utf-8",
        )
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "build.gradle").write_text(
            "dependencies {\n  implementation 'g:a:1.0'\n}\n",
            encoding="utf-8",
        )
        deps, _ = discover_build_gradle_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD

    def test_prod_stays_when_dev_seen_later(self, tmp_path):
        # PROD declared first, DEV second — PROD must remain (exercises the
        # False branch of the "promote DEV→PROD" guard in the dedup loop).
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n  implementation 'g:a:1.0'\n}\n",
            encoding="utf-8",
        )
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "build.gradle").write_text(
            "dependencies {\n  testImplementation 'g:a:1.0'\n}\n",
            encoding="utf-8",
        )
        deps, _ = discover_build_gradle_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD

    def test_unreadable_file_skipped(self, tmp_path, monkeypatch):
        (tmp_path / "build.gradle").write_text(
            "dependencies { implementation 'g:a:1.0' }\n", encoding="utf-8"
        )
        monkeypatch.setattr(
            Path, "read_bytes", lambda self, *a, **kw: (_ for _ in ()).throw(OSError())
        )
        deps, filtered = discover_build_gradle_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    def test_empty_directory(self, tmp_path):
        deps, filtered = discover_build_gradle_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    # A build whose versions come from a BOM or a dependency-management
    # plugin declares bare ``group:artifact`` coordinates. Each is reported
    # with an empty version in both DSLs; the BOM reference itself, project
    # references and interpolated strings stay unread.
    _VERSIONLESS_EXPECTED = {
        "org.example:web": DependencyGroup.PROD,
        "org.example:parens": DependencyGroup.PROD,
        "org.example:driver": DependencyGroup.PROD,
        "org.example:mapped": DependencyGroup.PROD,
        "org.example:excluding": DependencyGroup.PROD,
        "org.example:testing": DependencyGroup.DEV,
    }

    def test_versionless_coordinates_groovy(self, tmp_path):
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'java' }\n"
            "dependencies {\n"
            "    implementation platform('org.example:bom:1.0.0')\n"
            "    implementation enforcedPlatform('org.example:strict-bom')\n"
            "    implementation 'org.example:web'\n"
            "    implementation('org.example:parens')\n"
            "    runtimeOnly 'org.example:driver'\n"
            "    implementation group: 'org.example', name: 'mapped'\n"
            "    implementation('org.example:excluding') {\n"
            "        exclude group: 'org.unwanted', module: 'thing'\n"
            "    }\n"
            "    testImplementation 'org.example:testing'\n"
            "    implementation project(':core')\n"
            '    implementation "org.example:interpolated:$libVersion"\n'
            '    implementation "org.example:$artifactName"\n'
            "}\n",
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name: d.group for d in deps} == self._VERSIONLESS_EXPECTED
        assert {d.version_constraint for d in deps} == {""}
        assert {d.source for d in deps} == {"build.gradle"}

    def test_versionless_coordinates_kotlin(self, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(
            "plugins { java }\n"
            "dependencies {\n"
            '    implementation(platform("org.example:bom:1.0.0"))\n'
            '    implementation(enforcedPlatform("org.example:strict-bom"))\n'
            '    implementation("org.example:web")\n'
            '    implementation( "org.example:parens" )\n'
            '    runtimeOnly("org.example:driver")\n'
            '    implementation(group = "org.example", name = "mapped")\n'
            '    implementation("org.example:excluding") {\n'
            '        exclude(group = "org.unwanted", module = "thing")\n'
            "    }\n"
            '    testImplementation("org.example:testing")\n'
            '    implementation(project(":core"))\n'
            '    implementation("org.example:interpolated:$libVersion")\n'
            '    implementation("org.example:${artifactName}")\n'
            "}\n",
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name: d.group for d in deps} == self._VERSIONLESS_EXPECTED
        assert {d.version_constraint for d in deps} == {""}
        assert {d.source for d in deps} == {"build.gradle.kts"}

    def test_versioned_and_versionless_declarations_coexist(self, tmp_path):
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n"
            "    implementation 'org.example:pinned:1.2.3'\n"
            "    implementation 'org.example:managed'\n"
            "}\n",
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {(d.name, d.version_constraint) for d in deps} == {
            ("org.example:pinned", "1.2.3"),
            ("org.example:managed", ""),
        }

    def test_variant_configurations_discovered(self, tmp_path):
        (tmp_path / "build.gradle").write_text(
            "dependencies {\n"
            "    compileOnlyApi 'org.example:compile-only-api:1.0'\n"
            "    releaseImplementation 'org.example:release-impl:1.0'\n"
            "    releaseApi 'org.example:release-api:1.0'\n"
            "    releaseRuntimeOnly 'org.example:release-runtime:1.0'\n"
            "    shadow 'org.example:shadow:1.0'\n"
            "    debugImplementation 'org.example:debug-impl:1.0'\n"
            "    debugApi 'org.example:debug-api:1.0'\n"
            "    debugRuntimeOnly 'org.example:debug-runtime:1.0'\n"
            "    developmentOnly 'org.example:development-only:1.0'\n"
            "    testFixturesApi 'org.example:fixtures-api:1.0'\n"
            "    testFixturesImplementation 'org.example:fixtures-impl:1.0'\n"
            "    stagingImplementation 'org.example:unknown-variant:1.0'\n"
            "    customConfiguration 'org.example:unknown-custom:1.0'\n"
            "}\n",
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name.split(":")[1]: d.group for d in deps} == {
            "compile-only-api": DependencyGroup.PROD,
            "release-impl": DependencyGroup.PROD,
            "release-api": DependencyGroup.PROD,
            "release-runtime": DependencyGroup.PROD,
            "shadow": DependencyGroup.PROD,
            "debug-impl": DependencyGroup.DEV,
            "debug-api": DependencyGroup.DEV,
            "debug-runtime": DependencyGroup.DEV,
            "development-only": DependencyGroup.DEV,
            "fixtures-api": DependencyGroup.DEV,
            "fixtures-impl": DependencyGroup.DEV,
        }

    def test_variant_configurations_kotlin(self, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(
            "dependencies {\n"
            '    compileOnlyApi("org.example:compile-only-api")\n'
            '    releaseImplementation("org.example:release-impl:1.0")\n'
            '    debugImplementation("org.example:debug-impl:1.0")\n'
            '    developmentOnly("org.example:development-only")\n'
            '    testFixturesImplementation("org.example:fixtures-impl:1.0")\n'
            "}\n",
            encoding="utf-8",
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name.split(":")[1]: (d.version_constraint, d.group) for d in deps} == {
            "compile-only-api": ("", DependencyGroup.PROD),
            "release-impl": ("1.0", DependencyGroup.PROD),
            "debug-impl": ("1.0", DependencyGroup.DEV),
            "development-only": ("", DependencyGroup.DEV),
            "fixtures-impl": ("1.0", DependencyGroup.DEV),
        }
