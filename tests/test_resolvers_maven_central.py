"""Tests for the Maven Central license resolver."""

from __future__ import annotations

import httpx
import respx

from licenseal.analysis.spdx import spdx_from_license_url
from licenseal.resolvers.http import (
    RegistryCache,
    _trim_for_cache,
    _trim_maven_central_pom,
    fetch_registry_text,
)
from licenseal.resolvers.maven_central import (
    _extract_pinned_version_maven,
    _license_string_from_pom,
    _maven_central_pom_url,
    resolve_maven_central_license,
)
from tests._helpers import _java_dep

_SIMPLE_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>simple</artifactId>
    <version>1.0.0</version>
    <licenses>
        <license>
            <name>Apache License, Version 2.0</name>
            <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
        </license>
    </licenses>
</project>
"""

_DUAL_LICENSE_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>dual</artifactId>
    <version>1.0.0</version>
    <licenses>
        <license><name>MIT License</name></license>
        <license><name>Apache License, Version 2.0</name></license>
    </licenses>
</project>
"""

_CHILD_NO_LICENSES_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>2.0.0</version>
    </parent>
    <groupId>com.example</groupId>
    <artifactId>child</artifactId>
    <version>1.0.0</version>
</project>
"""

_PARENT_WITH_LICENSES_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>2.0.0</version>
    <licenses>
        <license><name>Apache-2.0</name></license>
    </licenses>
</project>
"""

# Heavy POM with all the blocks the trim drops. Used to verify the
# cache trim strips dependencies, build, etc. but keeps the resolver-
# read fields (groupId, artifactId, version, parent, licenses, properties,
# dependencyManagement, profiles — the last because a profile can carry its
# own <dependencyManagement> the resolver reads).
_HEAVY_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>heavy</artifactId>
    <version>1.0.0</version>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>2.0.0</version>
    </parent>
    <properties>
        <java.version>17</java.version>
    </properties>
    <licenses>
        <license><name>Apache License, Version 2.0</name></license>
    </licenses>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.example</groupId>
                <artifactId>managed-lib</artifactId>
                <version>3.4.5</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.junit</groupId>
            <artifactId>junit</artifactId>
            <version>5.0</version>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.8.0</version>
            </plugin>
        </plugins>
    </build>
    <reporting>
        <plugins>
            <plugin><groupId>x</groupId><artifactId>y</artifactId></plugin>
        </plugins>
    </reporting>
    <distributionManagement>
        <repository><id>ex</id><url>https://example.com</url></repository>
    </distributionManagement>
    <profiles>
        <profile>
            <id>dev</id>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.example</groupId>
                        <artifactId>profile-managed-lib</artifactId>
                        <version>9.9.9</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
        </profile>
    </profiles>
</project>
"""

_BILLION_LAUGHS_POM = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;">
]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>evil</artifactId>
    <version>1.0.0</version>
    <licenses>
        <license><name>&lol2;</name></license>
    </licenses>
</project>
"""


def _mock_fallback_404(group_path: str, artifact: str, version: str) -> None:
    """Mock the two fallback Maven registries (Google + Jenkins) to 404 for
    a given coord. Used in tests that want to exercise the post-fallback
    code path (deps.dev fallback for licenses, etc.) without actually
    hitting Google / Jenkins for the artifact.
    """
    respx.get(
        f"https://dl.google.com/dl/android/maven2/"
        f"{group_path}/{artifact}/{version}/{artifact}-{version}.pom"
    ).mock(return_value=httpx.Response(404))
    respx.get(
        f"https://repo.jenkins-ci.org/public/"
        f"{group_path}/{artifact}/{version}/{artifact}-{version}.pom"
    ).mock(return_value=httpx.Response(404))


class TestExtractPinnedVersionMaven:
    def test_simple_semver(self):
        assert _extract_pinned_version_maven("1.0.0") == "1.0.0"

    def test_two_component_version(self):
        # ``X.Y`` is legal Maven syntax (e.g. ``3.0``).
        assert _extract_pinned_version_maven("3.0") == "3.0"

    def test_single_component_version(self):
        assert _extract_pinned_version_maven("7") == "7"

    def test_qualifier_suffix(self):
        assert _extract_pinned_version_maven("1.0.0-SNAPSHOT") == "1.0.0-SNAPSHOT"

    def test_release_qualifier_dot_separator(self):
        # Legacy JVM versioning style with a ``.RELEASE`` qualifier suffix.
        assert _extract_pinned_version_maven("5.3.20.RELEASE") == "5.3.20.RELEASE"

    def test_build_metadata_suffix(self):
        assert _extract_pinned_version_maven("1.0.0+sha.abc") == "1.0.0+sha.abc"

    def test_double_equal_prefix_stripped(self):
        # Internal lockfile-shaped convention; the transitive walker
        # produces ``==X.Y.Z`` for ecosystems that don't carry a native
        # exact-pin syntax.
        assert _extract_pinned_version_maven("==1.2.3") == "1.2.3"

    def test_double_equal_with_whitespace(self):
        assert _extract_pinned_version_maven("==  1.2.3  ") == "1.2.3"

    def test_empty_constraint(self):
        # Versionless dep — depends on parent's ``<dependencyManagement>``.
        # The resolver can't satisfy that without the parent walk; UNKNOWN
        # is the right outcome at this layer.
        assert _extract_pinned_version_maven("") is None

    def test_whitespace_only(self):
        assert _extract_pinned_version_maven("   ") is None

    def test_range_syntax_rejected(self):
        # ``[1.0,2.0)`` and friends are not concrete pins.
        assert _extract_pinned_version_maven("[1.0,2.0)") is None

    def test_release_macro_rejected(self):
        # ``RELEASE`` / ``LATEST`` were deprecated in Maven 3 and removed
        # from version resolution; treat as unparseable.
        assert _extract_pinned_version_maven("RELEASE") is None

    def test_latest_macro_rejected(self):
        assert _extract_pinned_version_maven("LATEST") is None

    def test_unresolved_property_token_rejected(self):
        # If a literal ``${name}`` token slips through the discovery
        # layer's expansion (parent-POM property), we must NOT try to
        # fetch ``…/${name}.pom`` from the registry.
        assert _extract_pinned_version_maven("${spring.version}") is None

    def test_double_equal_with_unresolved_token_rejected(self):
        assert _extract_pinned_version_maven("==${spring.version}") is None

    def test_garbage_rejected(self):
        assert _extract_pinned_version_maven("not-a-version") is None


class TestSpdxFromLicenseUrl:
    """``<license><url>`` to SPDX-ID mapping.

    The URL is a structured reference — publishers point at the
    canonical license-text page on their own website (Apache, Eclipse,
    GNU, Mozilla, OSI, SPDX). This is genuinely additional data
    licenseal's direct POM fetch captures that ``deps.dev`` does not
    surface (deps.dev only exposes the name string).
    """

    def test_apache_2_0_canonical_url(self):
        assert spdx_from_license_url("http://www.apache.org/licenses/LICENSE-2.0") == "Apache-2.0"

    def test_apache_2_0_with_txt_extension(self):
        # Real POMs ship every URL variant — extension, https, trailing slash.
        assert (
            spdx_from_license_url("https://www.apache.org/licenses/LICENSE-2.0.txt") == "Apache-2.0"
        )

    def test_eclipse_epl_v10(self):
        assert spdx_from_license_url("http://www.eclipse.org/legal/epl-v10.html") == "EPL-1.0"

    def test_eclipse_epl_2_0(self):
        assert spdx_from_license_url("https://www.eclipse.org/legal/epl-2.0/") == "EPL-2.0"

    def test_gnu_gpl_3_0(self):
        assert spdx_from_license_url("https://www.gnu.org/licenses/gpl-3.0.html") == "GPL-3.0"

    def test_gnu_lgpl_2_1_specific_before_bare_lgpl(self):
        # Order matters: ``lgpl-2.1`` must be checked before bare ``lgpl``
        # so 2.1 doesn't get caught by the generic LGPL prefix.
        assert spdx_from_license_url("https://www.gnu.org/licenses/lgpl-2.1.html") == "LGPL-2.1"

    def test_mit_via_opensource_org(self):
        assert spdx_from_license_url("https://opensource.org/licenses/MIT") == "MIT"

    def test_mpl_2_0_via_mozilla(self):
        assert spdx_from_license_url("https://www.mozilla.org/MPL/2.0/") == "MPL-2.0"

    def test_spdx_direct_url(self):
        # SPDX direct URLs pull the ID straight from the path.
        assert spdx_from_license_url("https://spdx.org/licenses/MIT.html") == "MIT"

    def test_spdx_direct_url_with_complex_id(self):
        # Compound SPDX IDs like ``GPL-2.0-with-classpath-exception``
        # round-trip correctly.
        assert (
            spdx_from_license_url("https://spdx.org/licenses/GPL-2.0-with-classpath-exception.html")
            == "GPL-2.0-with-classpath-exception"
        )

    def test_creative_commons_cc0(self):
        assert (
            spdx_from_license_url("http://creativecommons.org/publicdomain/zero/1.0/") == "CC0-1.0"
        )

    def test_aopalliance_url_maps_to_public_domain_sentinel(self):
        # Must emit the internal permissive sentinel: a bare "Public-Domain"
        # matches neither the risk overrides nor any family pattern, which
        # would route a known public-domain artifact to manual review.
        assert (
            spdx_from_license_url("http://aopalliance.sourceforge.net/license.html")
            == "LicenseRef-Public-Domain"
        )

    def test_url_with_query_and_fragment_stripped(self):
        # The matcher strips ``?query`` and ``#fragment`` before matching.
        assert (
            spdx_from_license_url("https://www.apache.org/licenses/LICENSE-2.0.html?foo=1#section3")
            == "Apache-2.0"
        )

    def test_url_with_www_prefix_stripped(self):
        # ``www.`` is normalized off so ``apache.org`` matches both forms.
        assert spdx_from_license_url("https://apache.org/licenses/LICENSE-2.0") == "Apache-2.0"

    def test_unknown_url_returns_empty(self):
        # Project-homepage URLs and other non-canonical refs don't
        # produce a false match.
        assert spdx_from_license_url("https://example.com/custom-license") == ""

    def test_empty_url_returns_empty(self):
        assert spdx_from_license_url("") == ""

    def test_url_that_is_only_a_fragment_returns_empty(self):
        # Defensive: a URL collapsing to "" after normalization
        # (just ``#anchor`` or ``?query``) doesn't crash.
        assert spdx_from_license_url("#") == ""

    def test_spdx_url_with_no_id_returns_empty(self):
        # ``spdx.org/licenses/`` with no ID after the prefix → no match.
        assert spdx_from_license_url("https://spdx.org/licenses/") == ""


class TestLicenseStringFromPom:
    def test_single_license_returned_verbatim(self):
        # Single ``<license>`` entry passes through unchanged so the
        # normalize_license step has a clean alias-map input.
        assert (
            _license_string_from_pom(
                [("Apache License, Version 2.0", "http://www.apache.org/licenses/LICENSE-2.0")]
            )
            == "Apache License, Version 2.0"
        )

    def test_multi_license_joined_with_and(self):
        # SPDX ``AND`` semantics — consumer is bound by all named
        # licenses simultaneously. Conservative: if intent was ``OR``
        # the user overrides via review file.
        assert _license_string_from_pom([("MIT", ""), ("Apache-2.0", "")]) == "MIT AND Apache-2.0"

    def test_url_used_when_name_missing(self):
        # When a license entry has no name, the URL is the displayable
        # identifier. Modern POMs sometimes point directly at an SPDX
        # URL with no human-readable name.
        assert (
            _license_string_from_pom([("", "https://spdx.org/licenses/MIT.html")])
            == "https://spdx.org/licenses/MIT.html"
        )


class TestMavenCentralPomUrl:
    def test_group_dots_become_slashes(self):
        # ``com.example.org`` → ``com/example/org`` in the URL path.
        url = _maven_central_pom_url("com.example.org", "lib-core", "5.3.20")
        assert url == (
            "https://repo.maven.apache.org/maven2/"
            "com/example/org/lib-core/5.3.20/lib-core-5.3.20.pom"
        )

    def test_single_segment_group(self):
        url = _maven_central_pom_url("junit", "junit", "4.13.2")
        assert url == ("https://repo.maven.apache.org/maven2/junit/junit/4.13.2/junit-4.13.2.pom")

    def test_url_encoding_of_components(self):
        # URL-encoding is defensive — well-formed Maven coords never
        # contain reserved characters, but pathological inputs shouldn't
        # produce path-traversal attempts.
        url = _maven_central_pom_url("group with space", "art", "1.0")
        assert "%20" in url


class TestResolveMavenCentralLicense:
    @respx.mock
    def test_simple_license_extracted_from_pom(self):
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(), client)
        assert info.license_id == "Apache-2.0"
        assert info.license_raw == "Apache License, Version 2.0"
        assert info.resolved_version == "1.0.0"
        assert info.from_registry is True

    @respx.mock
    def test_dual_license_joined_and_normalized(self):
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/dual/1.0.0/dual-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_DUAL_LICENSE_POM))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:dual"), client)
        # Multi-license → ``AND`` join → normalize_license routes the
        # compound expression through the SPDX-expression path.
        assert "MIT" in info.license_id
        assert "Apache-2.0" in info.license_id
        assert info.license_raw == "MIT License AND Apache License, Version 2.0"

    @respx.mock
    def test_parent_pom_walked_for_license_inheritance(self):
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_CHILD_NO_LICENSES_POM))
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/parent/2.0.0/parent-2.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_PARENT_WITH_LICENSES_POM))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True
        assert info.resolved_version == "1.0.0"

    @respx.mock
    def test_parent_chain_exhausted_falls_back_to_deps_dev(self):
        # Child has parent metadata but parent fetch 404s on every Maven
        # registry → walk tries deps.dev for that parent (empty), then
        # resolver falls back to deps.dev for the CHILD which returns the
        # license.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_CHILD_NO_LICENSES_POM))
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/parent/2.0.0/parent-2.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        _mock_fallback_404("com/example", "parent", "2.0.0")
        # New: deps.dev parent fallback fires when Maven Central 404s
        # mid-chain. Empty response here exercises the "deps.dev also has
        # nothing" branch — chain ends, resolver continues to child fallback.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Aparent/versions/2.0.0"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Achild/versions/1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "MAVEN",
                        "name": "com.example:child",
                        "version": "1.0.0",
                    },
                    "licenses": ["Apache-2.0"],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_parent_404_recovers_via_deps_dev_parent_licenses(self):
        # The Proposal-2 path: a child POM has no <licenses> and its
        # parent 404s on Maven Central AND on the public-fallback
        # registries, but deps.dev has the parent indexed with licenses.
        # Walk recovers the parent's licenses from deps.dev — no need to
        # fall through to the child's own deps.dev entry (which may not
        # exist for retired artifacts).
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_CHILD_NO_LICENSES_POM))
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/parent/2.0.0/parent-2.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        _mock_fallback_404("com/example", "parent", "2.0.0")
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Aparent/versions/2.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "MAVEN",
                        "name": "com.example:parent",
                        "version": "2.0.0",
                    },
                    "licenses": ["Apache-2.0"],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_parent_404_deps_dev_returns_mixed_invalid_entries(self):
        # deps.dev returns a ``licenses`` list with some entries that
        # aren't strings (None, empty string, integer). The helper skips
        # invalid entries and keeps the valid ones.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_CHILD_NO_LICENSES_POM))
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/parent/2.0.0/parent-2.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        _mock_fallback_404("com/example", "parent", "2.0.0")
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Aparent/versions/2.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "MAVEN",
                        "name": "com.example:parent",
                        "version": "2.0.0",
                    },
                    "licenses": [None, "", "Apache-2.0", 42],  # mixed
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "Apache-2.0"

    @respx.mock
    def test_parent_404_deps_dev_returns_invalid_licenses_field(self):
        # deps.dev returns a malformed ``licenses`` field (e.g. dict
        # instead of list, or list of non-strings) — defensive against
        # API drift. Helper returns ``[]``, walk ends, resolver falls
        # through to child's deps.dev entry.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_CHILD_NO_LICENSES_POM))
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/parent/2.0.0/parent-2.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        _mock_fallback_404("com/example", "parent", "2.0.0")
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Aparent/versions/2.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "MAVEN",
                        "name": "com.example:parent",
                        "version": "2.0.0",
                    },
                    "licenses": {"not-a": "list"},  # malformed
                },
            )
        )
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Achild/versions/1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "MAVEN",
                        "name": "com.example:child",
                        "version": "1.0.0",
                    },
                    "licenses": ["MIT"],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "MIT"

    @respx.mock
    def test_pom_404_falls_back_to_deps_dev(self):
        # Direct POM 404 on every Maven registry (artifact retired from
        # Central, not on Google / Jenkins fallbacks). deps.dev returns
        # a result, so we surface it.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        _mock_fallback_404("com/example", "simple", "1.0.0")
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Asimple/versions/1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {
                        "system": "MAVEN",
                        "name": "com.example:simple",
                        "version": "1.0.0",
                    },
                    "licenses": ["MIT"],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(), client)
        assert info.license_id == "MIT"
        assert info.from_registry is True

    @respx.mock
    def test_pom_and_deps_dev_both_unavailable_yields_unknown(self):
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        _mock_fallback_404("com/example", "simple", "1.0.0")
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Asimple/versions/1.0.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False
        # Resolved version preserved so a review file can scaffold the entry.
        assert info.resolved_version == "1.0.0"

    @respx.mock
    def test_fallback_registry_google_serves_pom_when_central_404s(self):
        # Maven Central 404s on the artifact's own POM, but Google Android
        # Maven (first fallback) serves it. The fallback chain succeeds
        # without needing deps.dev.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://dl.google.com/dl/android/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(), client)
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_fallback_registry_jenkins_serves_pom_when_central_and_google_404(self):
        # Maven Central AND Google both 404, but Jenkins serves the POM.
        # Exercises the second fallback in the chain.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://dl.google.com/dl/android/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://repo.jenkins-ci.org/public/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(), client)
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_malformed_xml_falls_back_to_deps_dev(self):
        # Garbage body → defusedxml ParseError → _parse_pom returns
        # empty _PomData → walk_for_licenses sees no licenses and no
        # parent → returns [] → deps.dev fallback fires.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text="not xml at all"))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Asimple/versions/1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {"name": "com.example:simple", "version": "1.0.0"},
                    "licenses": ["MIT"],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(), client)
        assert info.license_id == "MIT"

    @respx.mock
    def test_billion_laughs_xml_refused_no_crash(self):
        # defusedxml's EntitiesForbidden short-circuits to empty
        # _PomData; the resolver then routes to deps.dev fallback.
        # Critical: no recursive entity expansion, no crash.
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/evil/1.0.0/evil-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_BILLION_LAUGHS_POM))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Aevil/versions/1.0.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:evil"), client)
        # No license recovered (deps.dev 404), but the scan didn't blow up.
        assert info.license_id == "UNKNOWN"

    def test_missing_colon_in_name_yields_unknown(self):
        # The coord parser expects ``groupId:artifactId``; a bare name
        # is a discovery-side bug we shouldn't network-fetch on.
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="not-a-coord"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    def test_empty_group_id_yields_unknown(self):
        # ``:artifact`` — coord split succeeds but group is empty.
        # The URL we'd build would 404 anyway; short-circuit before
        # going to the network.
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name=":artifact"), client)
        assert info.license_id == "UNKNOWN"

    def test_empty_artifact_id_yields_unknown(self):
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="group:"), client)
        assert info.license_id == "UNKNOWN"

    def test_unparseable_version_yields_unknown(self):
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="com.example:simple", version="${spring.version}"),
                client,
            )
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_parent_with_unresolvable_property_breaks_chain(self):
        # The child names a parent at ``${revision}`` which the child's
        # ``<properties>`` doesn't define. We must not fetch
        # ``.../${revision}.pom`` from Central. Chain stops, deps.dev fallback.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>${revision}</version>
    </parent>
    <groupId>com.example</groupId>
    <artifactId>child</artifactId>
    <version>1.0.0</version>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=pom))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Achild/versions/1.0.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_parent_version_resolved_via_child_properties(self):
        # Child defines ``${parent.ver}`` and uses it in parent block.
        # We resolve locally before fetching the parent.
        child_pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>${parent.ver}</version>
    </parent>
    <groupId>com.example</groupId>
    <artifactId>child</artifactId>
    <version>1.0.0</version>
    <properties>
        <parent.ver>2.0.0</parent.ver>
    </properties>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=child_pom))
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/parent/2.0.0/parent-2.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_PARENT_WITH_LICENSES_POM))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "Apache-2.0"

    @respx.mock
    def test_parent_missing_coordinate_breaks_chain(self):
        # Parent block names only groupId+artifactId (no version) — we
        # can't resolve the URL. Stop the walk, route to deps.dev.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
    </parent>
    <groupId>com.example</groupId>
    <artifactId>child</artifactId>
    <version>1.0.0</version>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=pom))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Achild/versions/1.0.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:child"), client)
        assert info.license_id == "UNKNOWN"

    @respx.mock
    def test_pom_name_is_non_standard_but_url_is_canonical(self):
        # The aopalliance-shaped case: POM declares ``<name>non-standard</name>``
        # (which normalizes to Proprietary) BUT also declares a canonical
        # ``<url>`` pointing at the Apache license page. The URL-fallback
        # picks up the real SPDX without going to deps.dev.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>aopalliance</groupId>
    <artifactId>aopalliance</artifactId>
    <version>1.0</version>
    <licenses>
        <license>
            <name>non-standard</name>
            <url>http://www.apache.org/licenses/LICENSE-2.0</url>
        </license>
    </licenses>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/aopalliance/aopalliance/1.0/aopalliance-1.0.pom"
        ).mock(return_value=httpx.Response(200, text=pom))
        # Note: NO deps.dev mock — the URL fallback resolves it before
        # the Proprietary-fallback path fires.
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="aopalliance:aopalliance", version="1.0"), client
            )
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_url_fallback_no_match_keeps_original_classification(self):
        # Name normalizes to Proprietary, URL is non-canonical (project
        # homepage, not a license page). spdx_from_license_url returns
        # empty; the original Proprietary classification stands. This
        # exercises the URL-fallback "no match" branch in the resolver.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>vendor</artifactId>
    <version>1.0</version>
    <licenses>
        <license>
            <name>see LICENSE.txt</name>
            <url>https://example.com/about/our-license</url>
        </license>
    </licenses>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/vendor/1.0/vendor-1.0.pom"
        ).mock(return_value=httpx.Response(200, text=pom))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Avendor/versions/1.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="com.example:vendor", version="1.0"), client
            )
        # URL didn't match a canonical license — Proprietary survives.
        assert info.license_id == "Proprietary"

    @respx.mock
    def test_pom_url_recovers_when_name_is_unknown(self):
        # Similar but with ``<name>blah blah blah</name>`` that normalizes
        # to UNKNOWN, plus a canonical URL. URL fallback fires for the
        # all-UNKNOWN-name case too.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>weird</artifactId>
    <version>1.0</version>
    <licenses>
        <license>
            <name>blah blah blah</name>
            <url>https://opensource.org/licenses/MIT</url>
        </license>
    </licenses>
</project>
"""
        respx.get("https://repo.maven.apache.org/maven2/com/example/weird/1.0/weird-1.0.pom").mock(
            return_value=httpx.Response(200, text=pom)
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="com.example:weird", version="1.0"), client
            )
        assert info.license_id == "MIT"
        assert info.from_registry is True

    @respx.mock
    def test_pom_with_proprietary_license_falls_back_to_deps_dev(self):
        # Pre-2010 Maven artifacts often declare placeholder license
        # names ("non-standard", "see LICENSE", "Custom Vendor Terms")
        # that normalize_license routes to Proprietary. Maven Central
        # is OSS-by-convention, so Proprietary there is highly suspicious
        # — overwhelmingly a POM-data issue, not a real commercial dep.
        # The resolver probes deps.dev's licensecheck (which reads the
        # actual LICENSE file at the tagged commit) and prefers its
        # answer when it surfaces a real SPDX ID.
        pom_with_placeholder = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>4.5</version>
    <licenses>
        <license><name>non-standard</name></license>
    </licenses>
</project>
"""
        respx.get("https://repo.maven.apache.org/maven2/junit/junit/4.5/junit-4.5.pom").mock(
            return_value=httpx.Response(200, text=pom_with_placeholder)
        )
        respx.get("https://api.deps.dev/v3/systems/MAVEN/packages/junit%3Ajunit/versions/4.5").mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {"name": "junit:junit", "version": "4.5"},
                    "licenses": ["CPL-1.0"],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="junit:junit", version="4.5"), client
            )
        # deps.dev recovered the real license. The POM's "non-standard"
        # placeholder is overridden.
        assert info.license_id == "CPL-1.0"
        assert info.from_registry is True

    @respx.mock
    def test_proprietary_kept_when_deps_dev_also_says_proprietary(self):
        # Defensive: if the POM says Proprietary AND deps.dev also can't
        # surface a real SPDX, keep the POM's Proprietary classification
        # — better than silently downgrading a legitimately commercial
        # dep to UNKNOWN.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>vendor-lib</artifactId>
    <version>1.0</version>
    <licenses>
        <license><name>Acme Inc. Proprietary License</name></license>
    </licenses>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/vendor-lib/1.0/vendor-lib-1.0.pom"
        ).mock(return_value=httpx.Response(200, text=pom))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Avendor-lib/versions/1.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="com.example:vendor-lib", version="1.0"), client
            )
        # Proprietary preserved; deps.dev couldn't help.
        assert info.license_id == "Proprietary"
        # license_raw preserved from POM.
        assert info.license_raw == "Acme Inc. Proprietary License"

    @respx.mock
    def test_proprietary_kept_when_deps_dev_returns_unknown(self):
        # If deps.dev returns a result but the license normalizes to
        # UNKNOWN, the POM's Proprietary still wins.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>vendor-lib</artifactId>
    <version>1.0</version>
    <licenses>
        <license><name>see LICENSE.txt</name></license>
    </licenses>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/vendor-lib/1.0/vendor-lib-1.0.pom"
        ).mock(return_value=httpx.Response(200, text=pom))
        # deps.dev returns a result but no licenses populated.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Avendor-lib/versions/1.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {"name": "com.example:vendor-lib", "version": "1.0"},
                    "licenses": [],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="com.example:vendor-lib", version="1.0"), client
            )
        # POM-derived Proprietary preserved.
        assert info.license_id == "Proprietary"

    @respx.mock
    def test_pom_with_only_unknown_licenses_falls_back_to_deps_dev(self):
        # POM declares <licenses> but every name is garbage that
        # normalize_license routes to UNKNOWN. Without the all-UNKNOWN
        # guard we'd emit ``UNKNOWN`` and skip deps.dev — losing a real
        # fallback path. With the guard, deps.dev gets a chance.
        # All-lowercase no-hyphen no-digit license name fails every
        # alias-map and SPDX-shape check → normalizes to UNKNOWN.
        pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>simple</artifactId>
    <version>1.0.0</version>
    <licenses>
        <license><name>blah blah blah</name></license>
    </licenses>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=pom))
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Asimple/versions/1.0.0"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "versionKey": {"name": "com.example:simple", "version": "1.0.0"},
                    "licenses": ["Apache-2.0"],
                },
            )
        )
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(), client)
        # deps.dev's scanner recovered the real license that the POM
        # author mis-declared. The all-UNKNOWN guard let the fallback fire.
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_parent_chain_capped_at_max_depth(self):
        # Build a chain longer than the depth cap. Each parent points to
        # the next; none declare licenses. After hitting the cap the
        # walk gives up and routes to deps.dev — even if a deeper
        # parent WOULD have the license.
        def _link_pom(child_artifact: str, parent_artifact: str) -> str:
            return f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <parent>
        <groupId>com.example</groupId>
        <artifactId>{parent_artifact}</artifactId>
        <version>1.0.0</version>
    </parent>
    <groupId>com.example</groupId>
    <artifactId>{child_artifact}</artifactId>
    <version>1.0.0</version>
</project>
"""

        # Create a long chain: a → b → c → d → e → f → g (7 levels;
        # cap is 5 parents past the root, so 6 fetches max). Only ``g``
        # declares the license but we never reach it.
        chain = ["a", "b", "c", "d", "e", "f", "g"]
        for i in range(len(chain) - 1):
            respx.get(
                f"https://repo.maven.apache.org/maven2/com/example/"
                f"{chain[i]}/1.0.0/{chain[i]}-1.0.0.pom"
            ).mock(return_value=httpx.Response(200, text=_link_pom(chain[i], chain[i + 1])))
        # ``g`` has licenses — the deep parent.
        terminal = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>g</artifactId>
    <version>1.0.0</version>
    <licenses><license><name>Apache-2.0</name></license></licenses>
</project>
"""
        respx.get("https://repo.maven.apache.org/maven2/com/example/g/1.0.0/g-1.0.0.pom").mock(
            return_value=httpx.Response(200, text=terminal)
        )
        # deps.dev fallback fires after cap.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/com.example%3Aa/versions/1.0.0"
        ).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            info = resolve_maven_central_license(_java_dep(name="com.example:a"), client)
        assert info.license_id == "UNKNOWN"


class TestFetchPomEdgeCases:
    """Defensive guards in ``_fetch_pom`` for response shapes that the
    happy-path respx mocks don't cover."""

    def test_text_key_missing_routes_to_deps_dev(self, monkeypatch):
        # Simulate a cache hit whose stored body is shapeless — e.g. a
        # future cache-write bug, or a manual seed for testing. The
        # resolver must not blow up; it falls through to deps.dev.
        text_fetcher_calls: list[str] = []
        json_fetcher_calls: list[str] = []

        def fake_text_fetcher(url: str, _client: httpx.Client) -> dict:
            text_fetcher_calls.append(url)
            # No ``text`` key — the resolver's `data.get("text", "")`
            # returns "" and the empty-text guard fires.
            return {"unexpected": "shape"}

        def fake_json_fetcher(url: str, _client: httpx.Client) -> dict:
            json_fetcher_calls.append(url)
            return {
                "versionKey": {"name": "com.example:simple", "version": "1.0.0"},
                "licenses": ["MIT"],
            }

        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(),
                client,
                fetcher=fake_text_fetcher,
                json_fetcher=fake_json_fetcher,
            )
        # POM fetch had a bad shape → fallback to deps.dev → MIT recovered.
        assert info.license_id == "MIT"
        assert text_fetcher_calls  # text fetcher was called
        assert json_fetcher_calls  # then json fetcher fired the fallback


class TestTrimMavenCentralPom:
    def test_keeps_resolver_read_fields(self):
        trimmed = _trim_maven_central_pom({"text": _HEAVY_POM})
        text = trimmed["text"]
        # Fields the resolver / DM walker read survive.
        assert "groupId" in text
        assert "artifactId" in text
        assert "parent" in text
        assert "Apache License, Version 2.0" in text
        assert "java.version" in text
        # dependencyManagement is what BOMs carry their entire payload in;
        # dropping it would break BOM-of-BOM transitive resolution end-to-end.
        assert "dependencyManagement" in text
        assert "managed-lib" in text
        assert "3.4.5" in text
        # profile-conditional <dependencyManagement> must survive too — a
        # managed version supplied only inside a <profile> block was lost on
        # the cached path before ``profiles`` was added to the keep set.
        assert "profile-managed-lib" in text
        assert "9.9.9" in text

    def test_drops_heavy_blocks(self):
        trimmed = _trim_maven_central_pom({"text": _HEAVY_POM})
        text = trimmed["text"]
        # Heavy blocks are gone.
        assert "maven-compiler-plugin" not in text
        assert "<reporting" not in text
        assert "distributionManagement" not in text
        assert "<dependencies>\n" not in text  # top-level <dependencies> dropped
        # junit was inside the top-level <dependencies>, not DM, so it must
        # be gone — the top-level dependencies block is what the trim drops.
        assert "junit" not in text

    def test_malformed_text_returned_unchanged(self):
        # If we can't parse the XML, leave the broken text alone so the
        # resolver's own parse path (which sees the same data) also
        # fails and routes to UNKNOWN deterministically.
        data = {"text": "<not xml"}
        trimmed = _trim_maven_central_pom(data)
        assert trimmed == data

    def test_billion_laughs_replaced_with_empty_sentinel(self):
        # EntitiesForbidden trims to an empty sentinel — the cache MUST
        # NOT hold the raw bomb body. The resolver's own defusedxml parse
        # rejects the empty/bomb input independently and emits UNKNOWN.
        data = {"text": _BILLION_LAUGHS_POM}
        trimmed = _trim_maven_central_pom(data)
        assert trimmed == {"text": ""}

    def test_empty_text_returned_unchanged(self):
        data = {"text": ""}
        assert _trim_maven_central_pom(data) == data

    def test_non_string_text_returned_unchanged(self):
        data = {"text": None}
        assert _trim_maven_central_pom(data) == data

    def test_dispatch_via_trim_for_cache_routes_maven_url(self):
        trimmed = _trim_for_cache(
            "https://repo.maven.apache.org/maven2/x/y/1/y-1.pom",
            {"text": _HEAVY_POM},
        )
        assert "maven-compiler-plugin" not in trimmed["text"]

    def test_dispatch_via_trim_for_cache_routes_fallback_google_url(self):
        # Hard-coded fallback registry — the cache dispatcher must
        # route its POMs through the same Maven trim. A regression that
        # changes the URL match list would otherwise silently stop
        # trimming heavy bodies fetched from the fallback hosts.
        trimmed = _trim_for_cache(
            "https://dl.google.com/dl/android/maven2/x/y/1/y-1.pom",
            {"text": _HEAVY_POM},
        )
        assert "maven-compiler-plugin" not in trimmed["text"]

    def test_dispatch_via_trim_for_cache_routes_fallback_jenkins_url(self):
        trimmed = _trim_for_cache(
            "https://repo.jenkins-ci.org/public/x/y/1/y-1.pom",
            {"text": _HEAVY_POM},
        )
        assert "maven-compiler-plugin" not in trimmed["text"]

    def test_dispatch_ignores_embedded_jenkins_hostname(self):
        data = {"text": _HEAVY_POM}
        result = _trim_for_cache(
            "https://example.com/repo.jenkins-ci.org/public/x/y/1/y-1.pom",
            data,
        )
        assert result is data
        assert "maven-compiler-plugin" in result["text"]

    def test_dispatch_for_unrelated_url_passes_through(self):
        # The Maven trim only fires for known Maven-registry URL roots.
        data = {"text": _HEAVY_POM}
        result = _trim_for_cache("https://example.com/whatever", data)
        # No trim ran, full POM text survives.
        assert "maven-compiler-plugin" in result["text"]


class TestMavenResolverThroughRegistryCache:
    """Per the resolver_cache_keep_set memory rule: any resolver field
    read must be tested through ``RegistryCache.fetch_text`` (or
    ``fetch``) to verify the trim keeps it.
    """

    @respx.mock
    def test_pom_license_survives_cache_trim(self):
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/heavy/1.0.0/heavy-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_HEAVY_POM))
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="com.example:heavy"),
                client,
                fetcher=cache.fetch_text,
                json_fetcher=cache.fetch,
            )
        # Through the cache, heavy blocks are trimmed but the licenses
        # the resolver reads survive.
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_parent_chain_survives_cache_trim(self):
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/child/1.0.0/child-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_CHILD_NO_LICENSES_POM))
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/parent/2.0.0/parent-2.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_PARENT_WITH_LICENSES_POM))
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_maven_central_license(
                _java_dep(name="com.example:child"),
                client,
                fetcher=cache.fetch_text,
                json_fetcher=cache.fetch,
            )
        assert info.license_id == "Apache-2.0"

    @respx.mock
    def test_bom_dependency_management_survives_cache_trim(self):
        # Regression: the cache trim originally dropped <dependencyManagement>
        # because the license-resolution path didn't need it. When the DM
        # walker was added to resolve BOM-consumer / parent-managed versions,
        # the keep-set update was missed — BOMs fetched through the cache
        # came back with managed_dependencies=0 and the BOM-of-BOM walk
        # silently returned empty. This test fetches a BOM POM through
        # RegistryCache and asserts the DM entries survive end-to-end.
        bom_pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>my-bom</artifactId>
    <version>1.0.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>managed-coord</artifactId>
                <version>7.7.7</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/my-bom/1.0.0/my-bom-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=bom_pom))
        cache = RegistryCache()
        from licenseal.resolvers.maven_central import _fetch_pom  # noqa: PLC0415

        with httpx.Client() as client:
            fetched = _fetch_pom("com.example", "my-bom", "1.0.0", client, cache.fetch_text)
        assert fetched is not None
        assert len(fetched.managed_dependencies) == 1
        managed = fetched.managed_dependencies[0]
        assert managed.group_id == "com.example"
        assert managed.artifact_id == "managed-coord"
        assert managed.version == "7.7.7"

    @respx.mock
    def test_profile_dependency_management_survives_cache_trim(self):
        # Regression: the cache trim dropped <profiles>, so a managed version
        # supplied only inside a <profile>'s <dependencyManagement> was lost on
        # the cached path — a BOM/parent consumer of that version degraded to
        # UNKNOWN even though parser unit tests (raw POM text) passed. This
        # fetches a profile-DM POM through RegistryCache and asserts the
        # profile-scoped managed entry survives end-to-end.
        profile_pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>profile-bom</artifactId>
    <version>1.0.0</version>
    <profiles>
        <profile>
            <id>release</id>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>profile-coord</artifactId>
                        <version>8.8.8</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
        </profile>
    </profiles>
</project>
"""
        respx.get(
            "https://repo.maven.apache.org/maven2/com/example/profile-bom/1.0.0/profile-bom-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=profile_pom))
        cache = RegistryCache()
        from licenseal.resolvers.maven_central import _fetch_pom  # noqa: PLC0415

        with httpx.Client() as client:
            fetched = _fetch_pom("com.example", "profile-bom", "1.0.0", client, cache.fetch_text)
        assert fetched is not None
        managed = {m.artifact_id: m.version for m in fetched.managed_dependencies}
        assert managed.get("profile-coord") == "8.8.8"

    @respx.mock
    def test_repeated_fetch_serves_from_cache(self):
        # The second call for the same URL must not re-hit the network.
        # Use respx's call counter — if the network is hit twice, the
        # cache is broken.
        route = respx.get(
            "https://repo.maven.apache.org/maven2/com/example/simple/1.0.0/simple-1.0.0.pom"
        ).mock(return_value=httpx.Response(200, text=_SIMPLE_POM))
        cache = RegistryCache()
        with httpx.Client() as client:
            info1 = resolve_maven_central_license(
                _java_dep(), client, fetcher=cache.fetch_text, json_fetcher=cache.fetch
            )
            info2 = resolve_maven_central_license(
                _java_dep(), client, fetcher=cache.fetch_text, json_fetcher=cache.fetch
            )
        assert info1.license_id == "Apache-2.0"
        assert info2.license_id == "Apache-2.0"
        # Two resolves, one HTTP fetch.
        assert route.call_count == 1


class TestFetchRegistryText:
    """The text-mode fetcher is now used for both Go module proxy and
    Maven Central. Existing Go tests cover most of its behavior; these
    add direct coverage of the public function and its delegation."""

    @respx.mock
    def test_returns_text_wrapped_in_dict(self):
        respx.get("https://repo.maven.apache.org/x.pom").mock(
            return_value=httpx.Response(200, text="<project/>")
        )
        with httpx.Client() as client:
            result = fetch_registry_text("https://repo.maven.apache.org/x.pom", client)
        assert result == {"text": "<project/>"}

    @respx.mock
    def test_404_returns_none(self):
        respx.get("https://repo.maven.apache.org/x.pom").mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            result = fetch_registry_text("https://repo.maven.apache.org/x.pom", client)
        assert result is None
