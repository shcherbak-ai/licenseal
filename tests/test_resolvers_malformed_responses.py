"""Registry responses and coordinates no resolver should have to trust.

A registry can answer HTTP 200 with a body whose fields have the wrong type,
and a manifest or a registry can name a dependency with characters no URL may
carry. Each case here must end in a result for that one dependency (UNKNOWN,
or whatever the well-formed fields still say), never in an exception. The
resolvers are driven through ``RegistryCache.fetch``, the production wiring.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.crates_io import fetch_rust_dependencies, resolve_rust_license
from licenseal.resolvers.deps_dev import (
    bulk_resolve_licenses,
    fetch_maven_dependencies,
    resolve_go_license,
)
from licenseal.resolvers.hex import fetch_hex_dependencies, resolve_hex_license
from licenseal.resolvers.http import RegistryCache
from licenseal.resolvers.maven_central import resolve_maven_central_license
from licenseal.resolvers.npm_registry import fetch_npm_dependencies, resolve_npm_license
from licenseal.resolvers.nuget import fetch_nuget_dependencies, resolve_nuget_license
from licenseal.resolvers.packagist import fetch_packagist_dependencies, resolve_php_license
from licenseal.resolvers.pypi import (
    _extract_pinned_version as extract_python_pinned_version,
)
from licenseal.resolvers.pypi import fetch_python_dependencies, resolve_python_license
from licenseal.resolvers.rubygems import fetch_rubygems_dependencies, resolve_ruby_license
from licenseal.resolvers.version_selection import select_python_version

_MIT_CLASSIFIER = "License :: OSI Approved :: MIT License"
# More digits than the interpreter converts between ``str`` and ``int``.
_OVERSIZED_NUMBER = "1" * 5000
# A marker nested deeper than the requirement parser can recurse.
_DEEP_MARKER = "(" * 5000 + 'os_name == "posix"' + ")" * 5000
_BACKSLASH = chr(92)
# A JSON value of every type but the one the field is documented to have.
_NOT_AN_OBJECT = [[], ["MIT"], "MIT", 5, True, None]
_NOT_A_STRING = [7, 1.5, ["1.0.0"], {"v": "1.0.0"}, True, None]


@pytest.fixture(scope="module")
def client():
    """One client for the module: building one per test dominates the runtime."""
    with httpx.Client() as shared:
        yield shared


def _dep(ecosystem: Ecosystem, name: str = "pkg-a", version: str = "") -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=ecosystem,
        group=DependencyGroup.PROD,
    )


def _json(url: str, payload: object) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(200, json=payload))


def _resolve(resolve, ecosystem: Ecosystem, client: httpx.Client, version: str = "") -> LicenseInfo:
    """Resolve ``pkg-a`` through a fresh per-scan cache."""
    return resolve(_dep(ecosystem, version=version), client, fetcher=RegistryCache().fetch)


def _resolve_python(client: httpx.Client, version: str = "") -> LicenseInfo:
    return _resolve(resolve_python_license, Ecosystem.PYTHON, client, version)


def _resolve_npm(client: httpx.Client, version: str = "") -> LicenseInfo:
    return _resolve(resolve_npm_license, Ecosystem.NPM, client, version)


def _resolve_rust(client: httpx.Client, version: str = "") -> LicenseInfo:
    return _resolve(resolve_rust_license, Ecosystem.RUST, client, version)


class TestPyPIFieldOfTheWrongType:
    @respx.mock
    @pytest.mark.parametrize(
        "info",
        [
            pytest.param({"license": {"text": "MIT"}}, id="license-object"),
            pytest.param({"license": 5}, id="license-number"),
            pytest.param({"license": ["MIT"]}, id="license-list"),
            pytest.param({"license": True}, id="license-boolean"),
            pytest.param({"license_expression": {"id": "MIT"}}, id="expression-object"),
            pytest.param({"license_expression": 5}, id="expression-number"),
            pytest.param({"license_expression": ["MIT"]}, id="expression-list"),
            pytest.param({"classifiers": 5}, id="classifiers-number"),
            pytest.param({"classifiers": True}, id="classifiers-boolean"),
            pytest.param({"classifiers": {_MIT_CLASSIFIER: 1}}, id="classifiers-object"),
            pytest.param({"classifiers": _MIT_CLASSIFIER}, id="classifiers-string"),
            pytest.param(
                {"license": {"a": 1}, "license_expression": 2, "classifiers": 3},
                id="every-license-field",
            ),
        ],
    )
    def test_malformed_license_field_reads_as_absent(self, client, info):
        _json("https://pypi.org/pypi/pkg-a/json", {"info": {"version": "1.0.0", **info}})
        result = _resolve_python(client)
        assert (result.license_id, result.license_raw) == ("UNKNOWN", "")
        # The registry answered; it just declared nothing usable.
        assert result.from_registry is True
        assert result.resolved_version == "1.0.0"

    @respx.mock
    @pytest.mark.parametrize(
        ("info", "license_id"),
        [
            pytest.param(
                {"license": {"text": "x"}, "classifiers": [_MIT_CLASSIFIER]},
                "MIT",
                id="classifier-beside-a-malformed-license",
            ),
            pytest.param(
                {"license_expression": 5, "license": "Apache-2.0"},
                "Apache-2.0",
                id="license-beside-a-malformed-expression",
            ),
            pytest.param(
                {"classifiers": 5, "license_expression": "BSD-3-Clause"},
                "BSD-3-Clause",
                id="expression-beside-malformed-classifiers",
            ),
        ],
    )
    def test_well_formed_field_beside_a_malformed_one_is_still_read(self, client, info, license_id):
        _json("https://pypi.org/pypi/pkg-a/json", {"info": {"version": "1.0.0", **info}})
        result = _resolve_python(client)
        assert result.license_id == license_id
        assert result.from_registry is True

    @respx.mock
    @pytest.mark.parametrize("version", _NOT_A_STRING)
    def test_version_that_is_not_a_string_is_dropped(self, client, version):
        _json("https://pypi.org/pypi/pkg-a/json", {"info": {"version": version, "license": "MIT"}})
        result = _resolve_python(client)
        assert result.license_id == "MIT"
        assert result.resolved_version == ""

    @respx.mock
    @pytest.mark.parametrize("info", _NOT_AN_OBJECT)
    def test_info_that_is_not_an_object(self, client, info):
        # Fetched without the cache, whose trim would already have replaced
        # ``info``: the resolver has to hold on its own as well.
        _json("https://pypi.org/pypi/pkg-a/json", {"info": info})
        _json("https://pypi.org/pypi/pkg-a/1.0.0/json", {"info": info})
        unpinned = resolve_python_license(_dep(Ecosystem.PYTHON), client)
        pinned = resolve_python_license(_dep(Ecosystem.PYTHON, version="==1.0.0"), client)
        children = fetch_python_dependencies("pkg-a", "1.0.0", client, parent_depth=0)
        for result in (unpinned, pinned):
            assert (result.license_id, result.resolved_version) == ("UNKNOWN", "")
            assert result.from_registry is True
        # No dependency list was read, with or without the cache in between.
        assert children == ([], False)
        cached = fetch_python_dependencies(
            "pkg-a", "1.0.0", client, parent_depth=0, fetcher=RegistryCache().fetch
        )
        assert cached == ([], False)

    @respx.mock
    @pytest.mark.parametrize(
        "wheel_url",
        [
            pytest.param("https://files.pythonhosted.org/pkg\x01a.whl", id="control-character"),
            pytest.param("https://files\uff0fpythonhosted.org/pkg_a.whl", id="unparseable-host"),
        ],
    )
    def test_wheel_link_that_is_not_a_url_skips_the_sidecar(self, client, wheel_url):
        _json(
            "https://pypi.org/pypi/pkg-a/json",
            {
                "info": {"version": "1.0.0"},
                "urls": [{"packagetype": "bdist_wheel", "url": wheel_url}],
            },
        )
        result = _resolve_python(client)
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is True
        # Only the JSON lookup went out.
        assert respx.calls.call_count == 1


class TestPyPIRequirementsAndVersionsNoParserAccepts:
    @respx.mock
    @pytest.mark.parametrize(
        "marker",
        [
            pytest.param(_DEEP_MARKER, id="nested-too-deeply"),
            # A quoted marker value is read as a Python string literal.
            pytest.param(f'platform_release == "C:{_BACKSLASH}Users"', id="invalid-escape"),
            pytest.param(f'os_name == "{_BACKSLASH}"', id="lone-backslash"),
            pytest.param('os_name == "po\x00six"', id="embedded-nul"),
        ],
    )
    def test_requirement_whose_marker_the_parser_cannot_read_is_an_unread_entry(
        self, client, marker
    ):
        _json(
            "https://pypi.org/pypi/pkg-a/1.0.0/json",
            {
                "info": {
                    "version": "1.0.0",
                    "requires_dist": ["first>=1", f"skipped; {marker}", "last"],
                }
            },
        )
        children, complete = fetch_python_dependencies(
            "pkg-a", "1.0.0", client, parent_depth=0, fetcher=RegistryCache().fetch
        )
        # The entries beside it are still read; the list is not complete.
        assert complete is False
        assert [child.name for child in children] == ["first", "last"]

    def test_oversized_version_is_not_a_pin(self):
        assert extract_python_pinned_version(f"=={_OVERSIZED_NUMBER}") is None
        assert extract_python_pinned_version(f"==1.{_OVERSIZED_NUMBER}") is None

    def test_oversized_published_version_is_passed_over(self):
        published = [_OVERSIZED_NUMBER, "1.0", f"2.{_OVERSIZED_NUMBER}", "2.0"]
        assert select_python_version(">=1", published) == "2.0"

    @pytest.mark.parametrize("operator", [">=", "==", "~=", "<", "!="])
    def test_oversized_version_in_the_constraint_selects_nothing(self, operator):
        assert select_python_version(f"{operator}{_OVERSIZED_NUMBER}.0", ["1.0", "2.0"]) is None

    def test_invalid_constraint_still_selects_nothing(self):
        assert select_python_version("not a specifier", ["1.0", "2.0"]) is None

    @respx.mock
    def test_oversized_pin_resolves_to_unknown(self, client):
        _json(
            "https://pypi.org/pypi/pkg-a/json",
            {"info": {"version": "2.0", "license": "MIT"}, "releases": {"1.0": [], "2.0": []}},
        )
        result = _resolve_python(client, version=f"=={_OVERSIZED_NUMBER}")
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is False

    @respx.mock
    def test_oversized_release_does_not_break_range_resolution(self, client):
        _json(
            "https://pypi.org/pypi/pkg-a/json",
            {"info": {"version": "1.0"}, "releases": {_OVERSIZED_NUMBER: [], "1.0": []}},
        )
        _json(
            "https://pypi.org/pypi/pkg-a/1.0/json", {"info": {"version": "1.0", "license": "MIT"}}
        )
        result = _resolve_python(client, version=">=1")
        assert (result.license_id, result.resolved_version) == ("MIT", "1.0")

    @respx.mock
    def test_oversized_pin_is_left_out_of_the_batch(self, client):
        batch = respx.post("https://api.deps.dev/v3alpha/versionbatch")
        caches = bulk_resolve_licenses(
            {"PYPI": [_dep(Ecosystem.PYTHON, version=f"=={_OVERSIZED_NUMBER}")]},
            client,
            max_workers=4,
        )
        assert caches == {"PYPI": {}}
        assert batch.call_count == 0


class TestNpmFieldOfTheWrongType:
    @respx.mock
    @pytest.mark.parametrize(
        "license_value",
        [
            pytest.param({"type": 5}, id="type-number"),
            pytest.param({"type": None}, id="type-null"),
            pytest.param({"type": ["MIT"]}, id="type-list"),
            pytest.param({"type": {"id": "MIT"}}, id="type-object"),
            pytest.param({"type": True}, id="type-boolean"),
            pytest.param({}, id="object-without-type"),
            pytest.param(5, id="number"),
            pytest.param(["MIT"], id="list"),
            pytest.param(True, id="boolean"),
            pytest.param(None, id="null"),
        ],
    )
    def test_malformed_license_reads_as_absent(self, client, license_value):
        payload = {"version": "1.0.0", "license": license_value}
        _json("https://registry.npmjs.org/pkg-a/latest", payload)
        _json("https://registry.npmjs.org/pkg-a/1.0.0", payload)
        _json("https://registry.npmjs.org/pkg-a", {"versions": {"1.0.0": payload}})
        # Unpinned, pinned, and range specs read the license from three
        # different endpoints.
        for spec in ("", "1.0.0", "^1.0.0"):
            result = _resolve_npm(client, version=spec)
            assert (result.license_id, result.license_raw) == ("UNKNOWN", ""), spec
            assert result.from_registry is True, spec
            assert result.resolved_version == "1.0.0", spec

    @respx.mock
    def test_legacy_licenses_field_is_still_read_beside_a_malformed_license(self, client):
        _json(
            "https://registry.npmjs.org/pkg-a/latest",
            {"version": "1.0.0", "license": {"type": 5}, "licenses": [{"type": "MIT"}]},
        )
        assert _resolve_npm(client).license_id == "MIT"

    @respx.mock
    def test_license_object_with_a_string_type_is_read(self, client):
        _json(
            "https://registry.npmjs.org/pkg-a/latest",
            {"version": "1.0.0", "license": {"type": "ISC", "url": "https://example.com"}},
        )
        assert _resolve_npm(client).license_id == "ISC"

    @respx.mock
    @pytest.mark.parametrize("version", _NOT_A_STRING)
    def test_version_that_is_not_a_string_is_dropped(self, client, version):
        _json("https://registry.npmjs.org/pkg-a/latest", {"version": version, "license": "MIT"})
        result = _resolve_npm(client)
        assert result.license_id == "MIT"
        assert result.resolved_version == ""


class TestCratesIoFieldOfTheWrongType:
    @respx.mock
    @pytest.mark.parametrize("crate", _NOT_AN_OBJECT)
    def test_crate_that_is_not_an_object_leaves_the_version_unresolved(self, client, crate):
        _json("https://crates.io/api/v1/crates/pkg-a", {"crate": crate})
        result = _resolve_rust(client)
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is False

    @respx.mock
    @pytest.mark.parametrize("field", _NOT_AN_OBJECT)
    def test_version_and_crate_that_are_not_objects_read_as_empty(self, client, field):
        _json("https://crates.io/api/v1/crates/pkg-a/1.0.0", {"version": field})
        _json("https://crates.io/api/v1/crates/pkg-a", {"crate": field})
        result = _resolve_rust(client, version="=1.0.0")
        assert (result.license_id, result.license_raw) == ("UNKNOWN", "")
        assert (result.repository_url, result.homepage_url) == ("", "")
        assert result.from_registry is True
        assert result.resolved_version == "1.0.0"

    @respx.mock
    def test_well_formed_response_is_unaffected(self, client):
        _json("https://crates.io/api/v1/crates/pkg-a/1.0.0", {"version": {"license": "MIT"}})
        _json(
            "https://crates.io/api/v1/crates/pkg-a",
            {"crate": {"repository": "https://example.com/pkg-a"}},
        )
        result = _resolve_rust(client, version="=1.0.0")
        assert result.license_id == "MIT"
        assert result.repository_url == "https://example.com/pkg-a"


_UNBUILDABLE = "pkg\x01a"


class TestCoordinateNoUrlCanCarry:
    """A name or version with an ASCII control character. The identity stays
    exactly as declared; the lookup fails for that dependency alone.
    """

    @respx.mock
    @pytest.mark.parametrize(
        ("ecosystem", "resolve", "name", "version"),
        [
            pytest.param(Ecosystem.PYTHON, resolve_python_license, _UNBUILDABLE, "", id="python"),
            pytest.param(Ecosystem.NPM, resolve_npm_license, _UNBUILDABLE, "", id="npm"),
            pytest.param(Ecosystem.NPM, resolve_npm_license, _UNBUILDABLE, "^1.0", id="npm-range"),
            pytest.param(Ecosystem.RUST, resolve_rust_license, _UNBUILDABLE, "", id="rust"),
            pytest.param(
                Ecosystem.PHP, resolve_php_license, f"vendor/{_UNBUILDABLE}", "", id="php"
            ),
            pytest.param(Ecosystem.RUBY, resolve_ruby_license, _UNBUILDABLE, "", id="ruby"),
            pytest.param(
                Ecosystem.RUBY, resolve_ruby_license, _UNBUILDABLE, "==1.0", id="ruby-pin"
            ),
            pytest.param(Ecosystem.RUBY, resolve_ruby_license, "pkg-a", "==1.0\x01", id="ruby-ver"),
            pytest.param(Ecosystem.HEX, resolve_hex_license, _UNBUILDABLE, "==1.0", id="hex"),
        ],
    )
    def test_lookup_fails_without_a_request(self, client, ecosystem, resolve, name, version):
        dep = _dep(ecosystem, name=name, version=version)
        result = resolve(dep, client, fetcher=RegistryCache().fetch)
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is False
        assert result.dependency is dep
        assert respx.calls.call_count == 0

    @respx.mock
    @pytest.mark.parametrize(
        ("ecosystem", "resolve", "version"),
        [
            pytest.param(Ecosystem.PYTHON, resolve_python_license, "==1.0.0", id="python"),
            pytest.param(Ecosystem.NPM, resolve_npm_license, "1.0.0", id="npm"),
            pytest.param(Ecosystem.RUST, resolve_rust_license, "=1.0.0", id="rust"),
            pytest.param(Ecosystem.GO, resolve_go_license, "v1.0.0", id="go"),
        ],
    )
    def test_pinned_lookup_ends_at_the_fallback_that_percent_encodes(
        self, client, ecosystem, resolve, version
    ):
        # The pinned path ends at an endpoint whose URL percent-encodes the
        # name, so that one request is well-formed and simply finds nothing.
        fallback = respx.get(host="api.deps.dev").mock(return_value=httpx.Response(404))
        dep = _dep(ecosystem, name=_UNBUILDABLE, version=version)
        result = resolve(dep, client, fetcher=RegistryCache().fetch)
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is False
        assert result.dependency is dep
        assert respx.calls.call_count == fallback.call_count == 1
        assert b"/packages/pkg%01a/versions/" in fallback.calls.last.request.url.raw_path

    @respx.mock
    @pytest.mark.parametrize(
        ("ecosystem", "resolve", "name"),
        [
            pytest.param(
                Ecosystem.JAVA, resolve_maven_central_license, "com.example:pkg\x01a", id="java"
            ),
            pytest.param(Ecosystem.DOTNET, resolve_nuget_license, _UNBUILDABLE, id="dotnet"),
        ],
    )
    def test_resolver_that_percent_encodes_gets_a_plain_miss(
        self, client, ecosystem, resolve, name
    ):
        misses = respx.get(url__regex=r"^https://.*$").mock(return_value=httpx.Response(404))
        dep = _dep(ecosystem, name=name, version="1.0.0")
        cache = RegistryCache()
        result = resolve(dep, client, fetcher=cache.fetch_text, json_fetcher=cache.fetch)
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is False
        assert result.dependency is dep
        assert misses.call_count >= 1
        assert all(b"%01" in call.request.url.raw_path for call in misses.calls)

    @respx.mock
    @pytest.mark.parametrize(
        ("fetch", "name", "version_is_in_the_url"),
        [
            pytest.param(fetch_python_dependencies, _UNBUILDABLE, True, id="python"),
            pytest.param(fetch_npm_dependencies, _UNBUILDABLE, True, id="npm"),
            pytest.param(fetch_rust_dependencies, _UNBUILDABLE, True, id="rust"),
            pytest.param(fetch_packagist_dependencies, f"vendor/{_UNBUILDABLE}", False, id="php"),
            pytest.param(fetch_rubygems_dependencies, _UNBUILDABLE, True, id="ruby"),
            pytest.param(fetch_hex_dependencies, _UNBUILDABLE, True, id="hex"),
        ],
    )
    def test_dependency_walk_finds_no_children_without_a_request(
        self, client, fetch, name, version_is_in_the_url
    ):
        cache = RegistryCache()
        assert fetch(name, "1.0.0", client, parent_depth=0, fetcher=cache.fetch) == ([], False)
        if version_is_in_the_url:
            assert fetch("pkg-a", "1.0\x01", client, parent_depth=0, fetcher=cache.fetch) == (
                [],
                False,
            )
        assert respx.calls.call_count == 0


# Half of a UTF-16 pair on its own: what an unpaired ``\uD800``-style escape in
# a JSON manifest or registry response decodes to. It has no UTF-8 encoding.
_NO_ENCODING = "pkg\ud800a"


class TestCoordinateWithNoEncoding:
    """A name or version holding a lone surrogate. No request can carry it, so
    none is sent: the lookup fails for that dependency alone, and its identity
    stays exactly as declared.
    """

    @respx.mock
    @pytest.mark.parametrize(
        ("ecosystem", "resolve", "name", "version"),
        [
            pytest.param(Ecosystem.PYTHON, resolve_python_license, _NO_ENCODING, "", id="python"),
            pytest.param(Ecosystem.NPM, resolve_npm_license, _NO_ENCODING, "", id="npm"),
            pytest.param(Ecosystem.NPM, resolve_npm_license, _NO_ENCODING, "^1.0", id="npm-range"),
            pytest.param(Ecosystem.RUST, resolve_rust_license, _NO_ENCODING, "", id="rust"),
            pytest.param(
                Ecosystem.PHP, resolve_php_license, f"vendor/{_NO_ENCODING}", "", id="php"
            ),
            pytest.param(Ecosystem.RUBY, resolve_ruby_license, _NO_ENCODING, "", id="ruby"),
            pytest.param(
                Ecosystem.RUBY, resolve_ruby_license, _NO_ENCODING, "==1.0", id="ruby-pin"
            ),
            pytest.param(
                Ecosystem.RUBY, resolve_ruby_license, "pkg-a", "==1.0\ud800", id="ruby-ver"
            ),
            pytest.param(Ecosystem.HEX, resolve_hex_license, _NO_ENCODING, "==1.0", id="hex"),
            # Pinned: these end at the fallback endpoint whose URL is
            # percent-encoded, and there is nothing to percent-encode this to.
            pytest.param(
                Ecosystem.PYTHON, resolve_python_license, _NO_ENCODING, "==1.0.0", id="python-pin"
            ),
            pytest.param(Ecosystem.NPM, resolve_npm_license, _NO_ENCODING, "1.0.0", id="npm-pin"),
            pytest.param(
                Ecosystem.RUST, resolve_rust_license, _NO_ENCODING, "=1.0.0", id="rust-pin"
            ),
            pytest.param(Ecosystem.GO, resolve_go_license, _NO_ENCODING, "v1.0.0", id="go"),
            pytest.param(
                Ecosystem.GO, resolve_go_license, "example.com/mod", "v1.0\ud800", id="go-ver"
            ),
        ],
    )
    def test_lookup_fails_without_a_request(self, client, ecosystem, resolve, name, version):
        dep = _dep(ecosystem, name=name, version=version)
        result = resolve(dep, client, fetcher=RegistryCache().fetch)
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is False
        assert result.dependency is dep
        assert respx.calls.call_count == 0

    @respx.mock
    @pytest.mark.parametrize(
        ("ecosystem", "resolve", "name"),
        [
            pytest.param(
                Ecosystem.JAVA,
                resolve_maven_central_license,
                "com.example:pkg\ud800a",
                id="java-artifact",
            ),
            pytest.param(
                Ecosystem.JAVA,
                resolve_maven_central_license,
                "com.exa\ud800mple:pkg-a",
                id="java-group",
            ),
            pytest.param(Ecosystem.DOTNET, resolve_nuget_license, _NO_ENCODING, id="dotnet"),
        ],
    )
    def test_resolver_that_percent_encodes_fails_without_a_request(
        self, client, ecosystem, resolve, name
    ):
        dep = _dep(ecosystem, name=name, version="1.0.0")
        cache = RegistryCache()
        result = resolve(dep, client, fetcher=cache.fetch_text, json_fetcher=cache.fetch)
        assert result.license_id == "UNKNOWN"
        assert result.from_registry is False
        assert result.dependency is dep
        assert respx.calls.call_count == 0
        # Every registry tried counts as a failed lookup, none as answered.
        assert cache.fetches_attempted >= 1
        assert cache.fetches_succeeded == 0

    @respx.mock
    @pytest.mark.parametrize(
        ("fetch", "name", "version_is_in_the_url"),
        [
            pytest.param(fetch_python_dependencies, _NO_ENCODING, True, id="python"),
            pytest.param(fetch_npm_dependencies, _NO_ENCODING, True, id="npm"),
            pytest.param(fetch_rust_dependencies, _NO_ENCODING, True, id="rust"),
            pytest.param(fetch_packagist_dependencies, f"vendor/{_NO_ENCODING}", False, id="php"),
            pytest.param(fetch_rubygems_dependencies, _NO_ENCODING, True, id="ruby"),
            pytest.param(fetch_hex_dependencies, _NO_ENCODING, True, id="hex"),
        ],
    )
    def test_dependency_walk_finds_no_children_without_a_request(
        self, client, fetch, name, version_is_in_the_url
    ):
        cache = RegistryCache()
        assert fetch(name, "1.0.0", client, parent_depth=0, fetcher=cache.fetch) == ([], False)
        if version_is_in_the_url:
            assert fetch("pkg-a", "1.0\ud800", client, parent_depth=0, fetcher=cache.fetch) == (
                [],
                False,
            )
        assert respx.calls.call_count == 0

    @respx.mock
    def test_graph_walk_finds_nothing_without_a_request(self, client):
        cache = RegistryCache()
        for name, version in (("com.example:pkg\ud800a", "1.0.0"), ("com.example:a", "1\ud800")):
            assert fetch_maven_dependencies(name, version, client, fetcher=cache.fetch) == (
                [],
                [],
                [(name, version)],
            )
        for name, version in ((_NO_ENCODING, "1.0.0"), ("pkg-a", "1.0\ud800")):
            walked = fetch_nuget_dependencies(name, version, client, fetcher=cache.fetch_text)
            assert walked == ([], [], [(name, version)])
        assert respx.calls.call_count == 0

    @respx.mock
    def test_it_is_left_out_of_the_batch_and_its_chunk_is_still_answered(self, client):
        # One request body holds a whole chunk. A coordinate that cannot be
        # written into it is not sent, so the dependencies beside it resolve.
        key = {"system": "NPM", "name": "pkg-a", "version": "1.0.0"}
        batch = respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
            return_value=httpx.Response(
                200,
                json={
                    "responses": [
                        {
                            "request": {"versionKey": key},
                            "version": {"versionKey": key, "licenses": ["MIT"]},
                        }
                    ]
                },
            )
        )
        caches = bulk_resolve_licenses(
            {
                "NPM": [
                    _dep(Ecosystem.NPM, name=_NO_ENCODING, version="1.0.0"),
                    _dep(Ecosystem.NPM, name="pkg-a", version="1.0.0"),
                ],
                "GO": [_dep(Ecosystem.GO, name="example.com/mod", version="v1.0\ud800")],
            },
            client,
            max_workers=4,
        )
        assert batch.call_count == 1
        assert json.loads(batch.calls.last.request.content) == {"requests": [{"versionKey": key}]}
        assert set(caches["NPM"]) == {("pkg-a", "1.0.0")}
        npm_hit = caches["NPM"]["pkg-a", "1.0.0"]
        assert npm_hit is not None
        assert npm_hit.license_id == "MIT"
        # Absent, not ``None``: the caller goes on to the per-package lookup.
        assert caches["GO"] == {}
