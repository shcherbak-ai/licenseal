"""Tests for the NuGet license resolver."""

from __future__ import annotations

import httpx
import respx

from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.http import (
    RegistryCache,
    _trim_for_cache,
    _trim_nuspec,
    fetch_registry_text,
)
from licenseal.resolvers.nuget import (
    _extract_pinned_version_nuget,
    _fetch_nuspec,
    _find_metadata,
    _license_from_nuspec,
    _local,
    _nuspec_url,
    _resolve_via_deps_dev,
    resolve_nuget_license,
)


def _dotnet_dep(name: str = "Newtonsoft.Json", version: str = "13.0.1") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.DOTNET,
        group=DependencyGroup.PROD,
        source="App.csproj",
    )


# ---------------------------------------------------------------------------
# _extract_pinned_version_nuget
# ---------------------------------------------------------------------------


class TestExtractPinnedVersionNuget:
    def test_semver_passthrough(self):
        assert _extract_pinned_version_nuget("13.0.1") == "13.0.1"
        assert _extract_pinned_version_nuget("1.0") == "1.0"
        assert _extract_pinned_version_nuget("1") == "1"

    def test_prerelease_passthrough(self):
        assert _extract_pinned_version_nuget("8.0.0-rc.2.24474.1") == "8.0.0-rc.2.24474.1"
        assert _extract_pinned_version_nuget("1.2.3-beta.4") == "1.2.3-beta.4"

    def test_build_metadata_passthrough(self):
        assert _extract_pinned_version_nuget("1.0.0+sha.abc123") == "1.0.0+sha.abc123"

    def test_four_part_legacy_version(self):
        assert _extract_pinned_version_nuget("1.2.3.4") == "1.2.3.4"

    def test_bracket_exact_pin(self):
        # NuGet's ``[1.2.3]`` syntax means "exactly this version".
        assert _extract_pinned_version_nuget("[1.2.3]") == "1.2.3"

    def test_bracket_range_picks_lower_bound(self):
        # Conservative posture: pick the lower bound rather than guessing
        # the resolver's actual pick.
        assert _extract_pinned_version_nuget("[1.0,2.0)") == "1.0"
        assert _extract_pinned_version_nuget("(1.0,2.0]") == "1.0"
        assert _extract_pinned_version_nuget("[1.0,)") == "1.0"

    def test_double_equals_prefix_stripped(self):
        # licenseal-internal pinned form used by the transitive walker.
        assert _extract_pinned_version_nuget("==13.0.1") == "13.0.1"

    def test_msbuild_property_token_rejected(self):
        # An unresolved $(...) survived discovery; can't pin.
        assert _extract_pinned_version_nuget("$(LibVersion)") is None

    def test_floating_version_rejected(self):
        assert _extract_pinned_version_nuget("*") is None
        assert _extract_pinned_version_nuget("1.*") is None
        assert _extract_pinned_version_nuget("1.0.*") is None

    def test_empty_or_whitespace_rejected(self):
        assert _extract_pinned_version_nuget("") is None
        assert _extract_pinned_version_nuget("   ") is None
        # ``==`` with nothing after also rejected.
        assert _extract_pinned_version_nuget("==") is None

    def test_garbage_rejected(self):
        assert _extract_pinned_version_nuget("not-a-version") is None
        assert _extract_pinned_version_nuget("abc.def.ghi") is None

    def test_malformed_bracket_rejected(self):
        # Brackets with garbage inside.
        assert _extract_pinned_version_nuget("[not-a-version]") is None


# ---------------------------------------------------------------------------
# _nuspec_url + _local
# ---------------------------------------------------------------------------


class TestNuspecUrl:
    def test_lowercase_id_and_version(self):
        url = _nuspec_url("Newtonsoft.Json", "13.0.1")
        assert url == (
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.nuspec"
        )

    def test_uppercase_input_lowercased(self):
        # Per NuGet spec, IDs are case-insensitive; the storage layer is
        # case-folded so the URL must use lowercase.
        url = _nuspec_url("NEWTONSOFT.JSON", "13.0.1")
        assert "newtonsoft.json" in url
        assert "NEWTONSOFT" not in url

    def test_special_chars_url_encoded(self):
        # Pathological IDs aren't real but the parser shouldn't crash.
        url = _nuspec_url("X/Y", "1.0")
        assert "%2F" in url

    def test_local_strips_namespace(self):
        assert _local("{http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd}id") == "id"
        assert _local("id") == "id"


# ---------------------------------------------------------------------------
# _license_from_nuspec
# ---------------------------------------------------------------------------


_SIMPLE_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.1</version>
    <license type="expression">MIT</license>
    <projectUrl>https://www.newtonsoft.com/json</projectUrl>
  </metadata>
</package>"""

_LEGACY_URL_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>LegacyPackage</id>
    <version>1.0.0</version>
    <licenseUrl>https://www.apache.org/licenses/LICENSE-2.0</licenseUrl>
  </metadata>
</package>"""

_FILE_LICENSE_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>FileLicensed</id>
    <version>1.0.0</version>
    <license type="file">LICENSE.txt</license>
    <licenseUrl>https://example.com/license</licenseUrl>
  </metadata>
</package>"""

_NO_LICENSE_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>NoLicense</id>
    <version>1.0.0</version>
  </metadata>
</package>"""


class TestLicenseFromNuspec:
    def test_modern_expression_extracted(self):
        expression, url = _license_from_nuspec(_SIMPLE_NUSPEC)
        assert expression == "MIT"
        assert url == ""

    def test_legacy_url_extracted(self):
        expression, url = _license_from_nuspec(_LEGACY_URL_NUSPEC)
        assert expression == ""
        assert url == "https://www.apache.org/licenses/LICENSE-2.0"

    def test_file_type_falls_through_to_url(self):
        # ``<license type="file">`` is unfetchable without artifact-body
        # access; only the licenseUrl is returned.
        expression, url = _license_from_nuspec(_FILE_LICENSE_NUSPEC)
        assert expression == ""
        assert url == "https://example.com/license"

    def test_no_license_returns_empty_tuple(self):
        assert _license_from_nuspec(_NO_LICENSE_NUSPEC) == ("", "")

    def test_malformed_xml_returns_empty_tuple(self):
        assert _license_from_nuspec("<not closed") == ("", "")

    def test_billion_laughs_returns_empty_tuple(self):
        billion = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<package><metadata><id>&lol2;</id></metadata></package>"""
        assert _license_from_nuspec(billion) == ("", "")

    def test_xxe_entity_reference_returns_empty_tuple(self):
        xxe = """<?xml version="1.0"?>
<!DOCTYPE package [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<package><metadata><id>&xxe;</id></metadata></package>"""
        assert _license_from_nuspec(xxe) == ("", "")

    def test_no_metadata_element_returns_empty(self):
        # Malformed package without <metadata> child.
        text = """<package><other>x</other></package>"""
        assert _license_from_nuspec(text) == ("", "")

    def test_empty_license_text_treated_as_missing(self):
        text = """<package><metadata>
  <id>X</id>
  <license type="expression"></license>
  <licenseUrl>   </licenseUrl>
</metadata></package>"""
        assert _license_from_nuspec(text) == ("", "")

    def test_no_type_attribute_falls_through(self):
        # A <license> element with no type="expression" attribute isn't
        # an expression; we treat it as unparseable and let licenseUrl
        # take over.
        text = """<package><metadata>
  <id>X</id>
  <license>LICENSE.txt</license>
  <licenseUrl>https://example.com/x</licenseUrl>
</metadata></package>"""
        expr, url = _license_from_nuspec(text)
        assert expr == ""
        assert url == "https://example.com/x"

    def test_find_metadata_returns_none_when_missing(self):
        from xml.etree.ElementTree import Element

        root = Element("package")
        assert _find_metadata(root) is None


# ---------------------------------------------------------------------------
# resolve_nuget_license — end-to-end with respx
# ---------------------------------------------------------------------------


class TestResolveNugetLicense:
    @respx.mock
    def test_tier1_expression_hit(self):
        respx.get(_nuspec_url("Newtonsoft.Json", "13.0.1")).respond(
            text=_SIMPLE_NUSPEC,
        )
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep(), client)
        assert info.license_id == "MIT"
        assert info.from_registry is True
        assert info.resolved_version == "13.0.1"

    @respx.mock
    def test_tier1_legacy_url_mapped(self):
        respx.get(_nuspec_url("LegacyPackage", "1.0.0")).respond(
            text=_LEGACY_URL_NUSPEC,
        )
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("LegacyPackage", "1.0.0"), client)
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_tier1_miss_falls_through_to_tier3(self):
        # Nuspec has no license metadata; deps.dev v3 supplies it.
        respx.get(_nuspec_url("NoLicense", "1.0.0")).respond(text=_NO_LICENSE_NUSPEC)
        respx.get(
            "https://api.deps.dev/v3/systems/NUGET/packages/NoLicense/versions/1.0.0"
        ).respond(
            json={
                "versionKey": {
                    "system": "NUGET",
                    "name": "NoLicense",
                    "version": "1.0.0",
                },
                "licenses": ["BSD-3-Clause"],
                "links": [],
            }
        )
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("NoLicense", "1.0.0"), client)
        assert info.license_id == "BSD-3-Clause"
        assert info.from_registry is True

    @respx.mock
    def test_tier1_404_falls_through_to_tier3(self):
        respx.get(_nuspec_url("Unknown.Pkg", "1.0.0")).respond(status_code=404)
        respx.get(
            "https://api.deps.dev/v3/systems/NUGET/packages/Unknown.Pkg/versions/1.0.0"
        ).respond(
            json={
                "versionKey": {
                    "system": "NUGET",
                    "name": "Unknown.Pkg",
                    "version": "1.0.0",
                },
                "licenses": ["MIT"],
                "links": [],
            }
        )
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("Unknown.Pkg", "1.0.0"), client)
        assert info.license_id == "MIT"

    @respx.mock
    def test_all_tiers_miss_returns_unknown(self):
        respx.get(_nuspec_url("MissingEverywhere", "1.0.0")).respond(status_code=404)
        respx.get(
            "https://api.deps.dev/v3/systems/NUGET/packages/MissingEverywhere/versions/1.0.0"
        ).respond(status_code=404)
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("MissingEverywhere", "1.0.0"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_unmappable_url_falls_through_to_tier3(self):
        # licenseUrl is set but the URL isn't in the known-patterns map
        # → fall through to deps.dev.
        text = """<package><metadata>
  <id>UnmappableUrl</id>
  <licenseUrl>https://invented-site.example/license</licenseUrl>
</metadata></package>"""
        respx.get(_nuspec_url("UnmappableUrl", "1.0.0")).respond(text=text)
        respx.get(
            "https://api.deps.dev/v3/systems/NUGET/packages/UnmappableUrl/versions/1.0.0"
        ).respond(
            json={
                "versionKey": {
                    "system": "NUGET",
                    "name": "UnmappableUrl",
                    "version": "1.0.0",
                },
                "licenses": ["GPL-3.0-only"],
                "links": [],
            }
        )
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("UnmappableUrl", "1.0.0"), client)
        assert info.license_id == "GPL-3.0-only"

    @respx.mock
    def test_expression_normalizes_to_unknown_falls_through(self):
        text = """<package><metadata>
  <id>UnknownExpr</id>
  <license type="expression">UNKNOWN</license>
  <licenseUrl>https://www.apache.org/licenses/LICENSE-2.0</licenseUrl>
</metadata></package>"""
        respx.get(_nuspec_url("UnknownExpr", "1.0.0")).respond(text=text)
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("UnknownExpr", "1.0.0"), client)
        # Expression was UNKNOWN, but licenseUrl mapped to Apache-2.0.
        assert info.license_id == "Apache-2.0"

    def test_unparseable_version_skips_all_tiers(self):
        # No HTTP mocks needed — extraction fails before any call.
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("X", "$(NotResolved)"), client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_nuspec_url_is_case_insensitive_lookup(self):
        # Dep name is mixed-case but the flatcontainer URL uses lowercase.
        respx.get(
            "https://api.nuget.org/v3-flatcontainer/mypackage/1.0.0/mypackage.nuspec"
        ).respond(
            text="""<package><metadata>
  <id>MyPackage</id>
  <license type="expression">MIT</license>
</metadata></package>""",
        )
        with httpx.Client() as client:
            info = resolve_nuget_license(_dotnet_dep("MyPackage", "1.0.0"), client)
        assert info.license_id == "MIT"


# ---------------------------------------------------------------------------
# _fetch_nuspec — direct testing of the fetch helper
# ---------------------------------------------------------------------------


class TestFetchNuspec:
    @respx.mock
    def test_returns_text_on_success(self):
        respx.get(_nuspec_url("X", "1.0")).respond(text=_SIMPLE_NUSPEC)
        with httpx.Client() as client:
            text = _fetch_nuspec("X", "1.0", client, fetch_registry_text)
        assert "<id>Newtonsoft.Json</id>" in text

    @respx.mock
    def test_returns_empty_on_404(self):
        respx.get(_nuspec_url("Missing", "1.0")).respond(status_code=404)
        with httpx.Client() as client:
            text = _fetch_nuspec("Missing", "1.0", client, fetch_registry_text)
        assert text == ""

    def test_returns_empty_when_fetcher_returns_none(self):
        def null_fetcher(url, client):
            return None

        with httpx.Client() as client:
            text = _fetch_nuspec("X", "1.0", client, null_fetcher)
        assert text == ""

    def test_returns_empty_when_text_field_missing(self):
        def empty_fetcher(url, client):
            return {"text": ""}

        with httpx.Client() as client:
            text = _fetch_nuspec("X", "1.0", client, empty_fetcher)
        assert text == ""

    def test_returns_empty_when_text_field_not_string(self):
        # Defensive against a fetcher returning a non-string value.
        def bad_fetcher(url, client):
            return {"text": 123}

        with httpx.Client() as client:
            text = _fetch_nuspec("X", "1.0", client, bad_fetcher)
        assert text == ""


# ---------------------------------------------------------------------------
# _resolve_via_deps_dev (direct Tier 3 invocation)
# ---------------------------------------------------------------------------


class TestResolveViaDepsDev:
    @respx.mock
    def test_success_returns_license_info(self):
        from licenseal.resolvers.http import fetch_registry_json

        respx.get("https://api.deps.dev/v3/systems/NUGET/packages/X/versions/1.0.0").respond(
            json={
                "versionKey": {"system": "NUGET", "name": "X", "version": "1.0.0"},
                "licenses": ["Apache-2.0"],
                "links": [],
            }
        )
        with httpx.Client() as client:
            info = _resolve_via_deps_dev(
                _dotnet_dep("X", "1.0.0"),
                "1.0.0",
                client,
                fetcher=fetch_registry_json,
            )
        assert info.license_id == "Apache-2.0"
        assert info.from_registry is True

    @respx.mock
    def test_404_returns_unknown_not_from_registry(self):
        from licenseal.resolvers.http import fetch_registry_json

        respx.get("https://api.deps.dev/v3/systems/NUGET/packages/X/versions/1.0.0").respond(
            status_code=404
        )
        with httpx.Client() as client:
            info = _resolve_via_deps_dev(
                _dotnet_dep("X", "1.0.0"),
                "1.0.0",
                client,
                fetcher=fetch_registry_json,
            )
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False
        assert info.resolved_version == "1.0.0"


# ---------------------------------------------------------------------------
# _trim_nuspec + RegistryCache integration (keep-set verification)
# ---------------------------------------------------------------------------


_HEAVY_NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Heavy</id>
    <version>1.0.0</version>
    <license type="expression">MIT</license>
    <licenseUrl>https://opensource.org/licenses/MIT</licenseUrl>
    <projectUrl>https://example.com/heavy</projectUrl>
    <repository url="https://github.com/example/heavy" type="git" />
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="SomeDep" version="1.0" />
      </group>
    </dependencies>
    <icon>icon.png</icon>
    <description>Long description text...</description>
    <releaseNotes>Many release notes...</releaseNotes>
    <owners>some-owner</owners>
    <tags>parse;serialize;json</tags>
    <readme>README.md</readme>
    <authors>Some Author</authors>
    <copyright>2026</copyright>
  </metadata>
  <files>
    <file src="bin\\Release\\net8.0\\Heavy.dll" target="lib\\net8.0" />
  </files>
</package>"""


class TestTrimNuspec:
    def test_keeps_resolver_read_fields(self):
        # Re-serialization preserves the namespace prefix (``ns0:id`` etc.)
        # — functionally identical for the resolver which strips prefixes.
        trimmed = _trim_nuspec({"text": _HEAVY_NUSPEC})
        text = trimmed["text"]
        assert "Heavy</" in text and ":id>Heavy" in text or "<id>Heavy</id>" in text
        assert "1.0.0" in text
        assert "MIT" in text
        assert "opensource.org/licenses/MIT" in text
        assert "example.com/heavy" in text
        assert "SomeDep" in text

    def test_drops_heavy_blocks(self):
        trimmed = _trim_nuspec({"text": _HEAVY_NUSPEC})
        text = trimmed["text"]
        assert "icon.png" not in text
        assert "release notes" not in text.lower()
        assert "some-owner" not in text
        assert "parse;serialize;json" not in text
        assert "README.md" not in text
        assert "Some Author" not in text
        # Outside-<metadata> <files> block is dropped entirely.
        assert "Heavy.dll" not in text

    def test_billion_laughs_returns_empty_sentinel(self):
        billion = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<package><metadata><id>&lol2;</id></metadata></package>"""
        result = _trim_nuspec({"text": billion})
        assert result == {"text": ""}

    def test_malformed_xml_returns_data_unchanged(self):
        broken = {"text": "<not closed"}
        assert _trim_nuspec(broken) == broken

    def test_empty_text_returns_data_unchanged(self):
        empty = {"text": ""}
        assert _trim_nuspec(empty) == empty

    def test_non_string_text_returns_data_unchanged(self):
        bad = {"text": 123}
        assert _trim_nuspec(bad) == bad

    def test_dispatch_via_trim_for_cache_routes_nuspec_url(self):
        url = "https://api.nuget.org/v3-flatcontainer/x/1.0/x.nuspec"
        trimmed = _trim_for_cache(url, {"text": _HEAVY_NUSPEC})
        # Verify the dispatcher routed through _trim_nuspec (heavy block dropped).
        assert "icon.png" not in trimmed["text"]

    def test_dispatch_skips_non_nuspec_flatcontainer_urls(self):
        # An index.json endpoint isn't a nuspec; the trim dispatcher
        # leaves it alone (returns data unchanged).
        url = "https://api.nuget.org/v3-flatcontainer/x/index.json"
        data = {"versions": ["1.0", "2.0"]}
        assert _trim_for_cache(url, data) is data

    @respx.mock
    def test_resolver_works_through_registry_cache(self):
        # End-to-end: the resolver fetches through RegistryCache.fetch_text,
        # the cache calls _trim_for_cache (which routes to _trim_nuspec for
        # the nuspec URL), and the trimmed body still has all resolver-read
        # fields intact.
        respx.get(_nuspec_url("Heavy", "1.0.0")).respond(text=_HEAVY_NUSPEC)
        cache = RegistryCache()
        with httpx.Client() as client:
            info = resolve_nuget_license(
                _dotnet_dep("Heavy", "1.0.0"), client, fetcher=cache.fetch_text
            )
        assert info.license_id == "MIT"
        assert info.from_registry is True
