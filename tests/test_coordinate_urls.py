"""What a dependency name or version becomes in a registry request URL.

A manifest, a lockfile, or a registry response can name a dependency with
characters that mean something in a URL: ``/`` and ``..`` address another
resource, ``?`` starts a query, ``#`` a fragment, and ``%`` an escape the
server decodes. Each coordinate is written into the URL percent-encoded, as
one path segment, so the request is for the package as it is named or for
nothing. The dependency keeps its declared name either way.

The resolver tests read through ``RegistryCache.fetch``; the scans start from
files on disk.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
import respx

from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers.crates_io import fetch_rust_dependencies, resolve_rust_license
from licenseal.resolvers.hex import fetch_hex_dependencies, resolve_hex_license
from licenseal.resolvers.http import RegistryCache
from licenseal.resolvers.npm_registry import fetch_npm_dependencies, resolve_npm_license
from licenseal.resolvers.packagist import fetch_packagist_dependencies, resolve_php_license
from licenseal.resolvers.pypi import fetch_python_dependencies, resolve_python_license
from licenseal.resolvers.rubygems import fetch_rubygems_dependencies, resolve_ruby_license
from tests._helpers import _check_json, _write

# A hostile coordinate and the one path segment it is sent as. ``None`` where
# the segment would still be read as ``.`` or ``..``: nothing is sent.
_COORDINATES = {
    "victim/../other": None,
    "victim?x=1": "victim%3Fx%3D1",
    "victim#frag": "victim%23frag",
    "%2e%2e": "%252e%252e",
    "..": None,
}


@pytest.fixture(scope="module")
def client():
    """One client for the module: building one per test dominates the runtime."""
    with httpx.Client() as shared:
        yield shared


def _misses() -> respx.Route:
    """Answer every GET no earlier route matches with a 404, and keep the requests."""
    return respx.get(url__regex=r"^https://.*$").mock(return_value=httpx.Response(404))


def _serve(url: str, body: dict) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(200, json=body))


def _requested(route: respx.Route) -> list[str]:
    """``host/path`` of each request, with the path as it went on the wire."""
    return [
        f"{call.request.url.host}{call.request.url.raw_path.decode('ascii')}"
        for call in route.calls
    ]


def _deps_dev(system: str) -> str:
    """The single-version lookup a pinned miss ends at, for a package named ``{name}``."""
    return f"api.deps.dev/v3/systems/{system}/packages/{{name}}/versions/1.0.0"


# Per ecosystem: the license resolver, the pin its lookup is made for, and the
# URLs that lookup asks for a package named ``{name}``.
_LICENSE_LOOKUPS = [
    pytest.param(
        Ecosystem.PYTHON,
        resolve_python_license,
        "==1.0.0",
        ["pypi.org/pypi/{name}/1.0.0/json", _deps_dev("PYPI")],
        id="python",
    ),
    pytest.param(
        Ecosystem.NPM,
        resolve_npm_license,
        "1.0.0",
        ["registry.npmjs.org/{name}/1.0.0", _deps_dev("NPM")],
        id="npm",
    ),
    pytest.param(
        Ecosystem.RUST,
        resolve_rust_license,
        "=1.0.0",
        ["crates.io/api/v1/crates/{name}/1.0.0", _deps_dev("CARGO")],
        id="rust",
    ),
    pytest.param(
        Ecosystem.RUBY,
        resolve_ruby_license,
        "==1.0.0",
        ["rubygems.org/api/v2/rubygems/{name}/versions/1.0.0.json"],
        id="ruby",
    ),
    pytest.param(
        Ecosystem.HEX,
        resolve_hex_license,
        "==1.0.0",
        ["hex.pm/api/packages/{name}"],
        id="hex",
    ),
]

# Per ecosystem: the dependency fetcher, and the URL it asks for version 1.0.0
# of a package named ``{name}``.
_WALKS = [
    pytest.param(fetch_python_dependencies, "pypi.org/pypi/{name}/1.0.0/json", id="python"),
    pytest.param(fetch_npm_dependencies, "registry.npmjs.org/{name}/1.0.0", id="npm"),
    pytest.param(
        fetch_rust_dependencies, "crates.io/api/v1/crates/{name}/1.0.0/dependencies", id="rust"
    ),
    pytest.param(
        fetch_rubygems_dependencies,
        "rubygems.org/api/v2/rubygems/{name}/versions/1.0.0.json",
        id="ruby",
    ),
    pytest.param(fetch_hex_dependencies, "hex.pm/api/packages/{name}/releases/1.0.0", id="hex"),
]


class TestNameInTheUrl:
    """A name is one path segment of the request, whatever it holds."""

    @respx.mock
    @pytest.mark.parametrize(("ecosystem", "resolve", "pin", "urls"), _LICENSE_LOOKUPS)
    @pytest.mark.parametrize("name", _COORDINATES)
    def test_license_lookup_asks_for_the_name_as_declared_or_for_nothing(
        self, client, ecosystem, resolve, pin, urls, name
    ):
        misses = _misses()
        dep = Dependency(name=name, version_constraint=pin, ecosystem=ecosystem)
        result = resolve(dep, client, fetcher=RegistryCache().fetch)
        segment = _COORDINATES[name]
        assert _requested(misses) == (
            [] if segment is None else [url.format(name=segment) for url in urls]
        )
        assert (result.license_id, result.from_registry) == ("UNKNOWN", False)
        assert result.dependency is dep

    @respx.mock
    @pytest.mark.parametrize(("fetch", "url"), _WALKS)
    @pytest.mark.parametrize("name", _COORDINATES)
    def test_dependency_walk_asks_for_the_name_as_declared_or_for_nothing(
        self, client, fetch, url, name
    ):
        misses = _misses()
        walked = fetch(name, "1.0.0", client, parent_depth=0, fetcher=RegistryCache().fetch)
        segment = _COORDINATES[name]
        assert _requested(misses) == ([] if segment is None else [url.format(name=segment)])
        # No children, and the list is not known to be complete.
        assert walked == ([], False)

    @respx.mock
    @pytest.mark.parametrize(
        ("name", "requested"),
        [
            # Vendor and package are a segment each; the first ``/`` is the
            # only one that separates anything.
            ("victim/../other/pkg", []),
            ("vendor/victim/../other", []),
            ("victim?x=1/pkg", ["repo.packagist.org/p2/victim%3Fx%3D1/pkg.json"]),
            ("vendor/pkg#frag", ["repo.packagist.org/p2/vendor/pkg%23frag.json"]),
            ("vendor/a/b", ["repo.packagist.org/p2/vendor/a%2Fb.json"]),
            ("%2e%2e/pkg", ["repo.packagist.org/p2/%252e%252e/pkg.json"]),
            ("../pkg", []),
            # ``...json`` is a file name, not a ``..`` segment.
            ("vendor/..", ["repo.packagist.org/p2/vendor/...json"]),
        ],
    )
    def test_packagist_name_is_a_vendor_segment_and_a_package_segment(
        self, client, name, requested
    ):
        misses = _misses()
        cache = RegistryCache()
        dep = Dependency(name=name, version_constraint="", ecosystem=Ecosystem.PHP)
        result = resolve_php_license(dep, client, fetcher=cache.fetch)
        assert (result.license_id, result.from_registry) == ("UNKNOWN", False)
        assert result.dependency is dep
        walked = fetch_packagist_dependencies(
            name, "1.0.0", client, parent_depth=0, fetcher=cache.fetch
        )
        assert walked == ([], False)
        # One request serves both: the walk reads the response the license
        # lookup cached.
        assert _requested(misses) == requested

    @respx.mock
    @pytest.mark.parametrize(
        ("name", "requested"),
        [
            # A slash outside a scope is part of the name.
            ("victim/other", "registry.npmjs.org/victim%2Fother/1.0.0"),
            ("@scope/victim/other", "registry.npmjs.org/@scope/victim%2Fother/1.0.0"),
            ("@scope/victim?x=1", "registry.npmjs.org/@scope/victim%3Fx%3D1/1.0.0"),
            ("@scope?x=1/victim", "registry.npmjs.org/@scope%3Fx%3D1/victim/1.0.0"),
            ("%72ealpkg", "registry.npmjs.org/%2572ealpkg/1.0.0"),
        ],
    )
    def test_npm_scope_is_the_only_slash_kept(self, client, name, requested):
        misses = _misses()
        fetch_npm_dependencies(name, "1.0.0", client, parent_depth=0, fetcher=RegistryCache().fetch)
        assert _requested(misses) == [requested]

    @respx.mock
    @pytest.mark.parametrize("name", ["@scope/..", "@scope/victim/../other", "../victim"])
    def test_npm_name_with_a_dot_segment_is_not_sent(self, client, name):
        misses = _misses()
        dep = Dependency(name=name, version_constraint="", ecosystem=Ecosystem.NPM)
        result = resolve_npm_license(dep, client, fetcher=RegistryCache().fetch)
        assert (result.license_id, result.from_registry) == ("UNKNOWN", False)
        assert _requested(misses) == []


# The dependency fetchers that put the version in the URL, with the URL each
# asks for version ``{version}`` of ``pkg-a``.
_VERSIONED_WALKS = [
    pytest.param(fetch_python_dependencies, "pypi.org/pypi/pkg-a/{version}/json", id="python"),
    pytest.param(fetch_npm_dependencies, "registry.npmjs.org/pkg-a/{version}", id="npm"),
    pytest.param(
        fetch_rust_dependencies,
        "crates.io/api/v1/crates/pkg-a/{version}/dependencies",
        id="rust",
    ),
    pytest.param(fetch_hex_dependencies, "hex.pm/api/packages/pkg-a/releases/{version}", id="hex"),
]


class TestVersionInTheUrl:
    """A version is one path segment too."""

    @respx.mock
    @pytest.mark.parametrize(("fetch", "walk_url"), _VERSIONED_WALKS)
    @pytest.mark.parametrize("version", _COORDINATES)
    def test_dependency_walk_asks_for_the_version_as_given_or_for_nothing(
        self, client, fetch, walk_url, version
    ):
        misses = _misses()
        walked = fetch("pkg-a", version, client, parent_depth=0, fetcher=RegistryCache().fetch)
        segment = _COORDINATES[version]
        assert _requested(misses) == ([] if segment is None else [walk_url.format(version=segment)])
        assert walked == ([], False)

    @respx.mock
    @pytest.mark.parametrize(
        ("version", "requested"),
        [
            ("1.0/../../../../../v1/gems/other", []),
            ("1.0?x=1", ["rubygems.org/api/v2/rubygems/pkg-a/versions/1.0%3Fx%3D1.json"]),
            ("1.0#frag", ["rubygems.org/api/v2/rubygems/pkg-a/versions/1.0%23frag.json"]),
            ("%2e%2e", ["rubygems.org/api/v2/rubygems/pkg-a/versions/%252e%252e.json"]),
            # The version is followed by ``.json``: a file name, not ``..``.
            ("..", ["rubygems.org/api/v2/rubygems/pkg-a/versions/...json"]),
        ],
    )
    def test_rubygems_lockfile_version(self, client, version, requested):
        misses = _misses()
        cache = RegistryCache()
        dep = Dependency(name="pkg-a", version_constraint=f"=={version}", ecosystem=Ecosystem.RUBY)
        result = resolve_ruby_license(dep, client, fetcher=cache.fetch)
        assert (result.license_id, result.from_registry) == ("UNKNOWN", False)
        assert result.dependency is dep
        walked = fetch_rubygems_dependencies(
            "pkg-a", version, client, parent_depth=0, fetcher=cache.fetch
        )
        assert walked == ([], False)
        assert _requested(misses) == requested


def _go_proxy_requests(tmp_path, module: str, version: str) -> list[str]:
    """The module-proxy requests a scan makes for ``module``, listed in ``go.sum``.

    ``go.mod`` requires ``example.com/steady``, which resolves, so the scan
    reads the edges of every ``go.sum`` module.
    """
    _write(
        tmp_path / "go.mod",
        "module example.com/app\n\ngo 1.21\n\nrequire example.com/steady v1.0.0\n",
    )
    _write(
        tmp_path / "go.sum",
        "".join(
            f"{path} {tag} h1:x\n{path} {tag}/go.mod h1:x\n"
            for path, tag in (("example.com/steady", "v1.0.0"), (module, version))
        ),
    )
    _serve(
        "https://api.deps.dev/v3/systems/GO/packages/example.com%2Fsteady/versions/v1.0.0",
        {"licenses": ["MIT"]},
    )
    respx.get("https://proxy.golang.org/example.com/steady/@v/v1.0.0.mod").mock(
        return_value=httpx.Response(200, text="module example.com/steady\n")
    )
    misses = _misses()
    _check_json(tmp_path)
    return [url for url in _requested(misses) if url.startswith("proxy.golang.org/")]


class TestGoModulePathInTheUrl:
    """A module path keeps the ``/`` between its elements; each element is encoded."""

    @respx.mock
    @pytest.mark.parametrize(
        ("module", "requested"),
        [
            (
                "example.com/victim?x=1",
                ["proxy.golang.org/example.com/victim%3Fx%3D1/@v/v1.0.0.mod"],
            ),
            (
                "example.com/victim#frag",
                ["proxy.golang.org/example.com/victim%23frag/@v/v1.0.0.mod"],
            ),
            (
                "example.com/%2e%2e/other",
                ["proxy.golang.org/example.com/%252e%252e/other/@v/v1.0.0.mod"],
            ),
            ("example.com/victim/../other", []),
        ],
    )
    def test_module_path(self, tmp_path, module, requested):
        assert _go_proxy_requests(tmp_path, module, "v1.0.0") == requested


# A well-formed coordinate, the call that looks it up, and the request made.
_WELL_FORMED: list[tuple[str, Callable[..., object], tuple[str, str], str]] = [
    ("python", fetch_python_dependencies, ("Pkg_A.b", "1.0"), "pypi.org/pypi/Pkg_A.b/1.0/json"),
    (
        "python-local-version",
        fetch_python_dependencies,
        ("pkg-a", "2.1.0+cu124"),
        "pypi.org/pypi/pkg-a/2.1.0+cu124/json",
    ),
    (
        "python-epoch",
        fetch_python_dependencies,
        ("pkg-a", "1!2.0"),
        "pypi.org/pypi/pkg-a/1!2.0/json",
    ),
    ("npm", fetch_npm_dependencies, ("pkg-a", "1.0.0"), "registry.npmjs.org/pkg-a/1.0.0"),
    (
        "npm-scoped",
        fetch_npm_dependencies,
        ("@scope/pkg-a", "1.0.0-rc.1"),
        "registry.npmjs.org/@scope/pkg-a/1.0.0-rc.1",
    ),
    (
        "npm-build-metadata",
        fetch_npm_dependencies,
        ("pkg-a", "1.0.0+build.5"),
        "registry.npmjs.org/pkg-a/1.0.0+build.5",
    ),
    (
        "npm-legacy-name",
        fetch_npm_dependencies,
        ("Pkg~a!(b)*'c", "1.0.0"),
        "registry.npmjs.org/Pkg~a!(b)*'c/1.0.0",
    ),
    (
        "rust-build-metadata",
        fetch_rust_dependencies,
        ("pkg_a", "1.0.0+build.5"),
        "crates.io/api/v1/crates/pkg_a/1.0.0+build.5/dependencies",
    ),
    (
        "ruby",
        fetch_rubygems_dependencies,
        ("pkg-a_b", "1.0.0.pre1"),
        "rubygems.org/api/v2/rubygems/pkg-a_b/versions/1.0.0.pre1.json",
    ),
    (
        "hex-build-metadata",
        fetch_hex_dependencies,
        ("pkg_a", "1.0.0-rc.1+build"),
        "hex.pm/api/packages/pkg_a/releases/1.0.0-rc.1+build",
    ),
    (
        "php",
        fetch_packagist_dependencies,
        ("Vendor-A/pkg_a.b", "1.0.0"),
        "repo.packagist.org/p2/vendor-a/pkg_a.b.json",
    ),
]


class TestWellFormedCoordinate:
    """The request for a coordinate its registry could publish is unchanged."""

    @respx.mock
    @pytest.mark.parametrize(
        ("fetch", "coordinate", "requested"),
        [pytest.param(*case[1:], id=case[0]) for case in _WELL_FORMED],
    )
    def test_is_requested_as_written(self, client, fetch, coordinate, requested):
        misses = _misses()
        fetch(*coordinate, client, parent_depth=0, fetcher=RegistryCache().fetch)
        assert _requested(misses) == [requested]

    @respx.mock
    def test_go_module_and_version_keep_their_case_encoding(self, tmp_path):
        assert _go_proxy_requests(tmp_path, "github.com/Team/Mod", "v2.0.0+incompatible") == [
            "proxy.golang.org/github.com/!team/!mod/@v/v2.0.0+incompatible.mod"
        ]


def _rows(data: dict) -> dict[str, tuple[str, str]]:
    return {dep["name"]: (dep["license"], dep["verdict"]) for dep in data["dependencies"]}


class TestScan:
    """A coordinate that names another package's endpoint, in a file a scan reads.

    Each project also declares ``steady``, which resolves: the scan goes on,
    and only the hostile row is UNKNOWN.
    """

    @respx.mock
    def test_gemfile_lock_version_that_walks_to_another_gem(self, tmp_path):
        _write(tmp_path / "Gemfile", 'source "https://rubygems.org"\ngem "steady"\ngem "victim"\n')
        _write(
            tmp_path / "Gemfile.lock",
            """\
            GEM
              remote: https://rubygems.org/
              specs:
                steady (1.0.0)
                victim (1.0/../../../../../v1/gems/other)

            PLATFORMS
              ruby

            DEPENDENCIES
              steady
              victim
            """,
        )
        _serve(
            "https://rubygems.org/api/v2/rubygems/steady/versions/1.0.0.json",
            {"name": "steady", "number": "1.0.0", "licenses": ["MIT"]},
        )
        other = _serve(
            "https://rubygems.org/api/v1/gems/other.json",
            {"name": "other", "version": "9.9.9", "licenses": ["MIT"]},
        )
        misses = _misses()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        assert _rows(data) == {"steady": ("MIT", "compatible"), "victim": ("UNKNOWN", "unknown")}
        assert not other.called
        assert _requested(misses) == []

    @respx.mock
    def test_rebar_lock_package_name_that_walks_to_another_package(self, tmp_path):
        _write(
            tmp_path / "rebar.lock",
            """\
            {"1.2.0",
            [{<<"steady">>,{pkg,<<"steady">>,<<"1.0.0">>},0},
             {<<"victim">>,{pkg,<<"victim/../other">>,<<"1.0.0">>},0}]}.
            """,
        )
        package = {
            "meta": {"licenses": ["MIT"]},
            "latest_stable_version": "1.0.0",
            "releases": [{"version": "1.0.0", "inserted_at": "2024-01-01T00:00:00.000000Z"}],
        }
        _serve("https://hex.pm/api/packages/steady", package)
        other = _serve("https://hex.pm/api/packages/other", package)
        misses = _misses()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        # The lockfile's package name is the name of the row.
        assert _rows(data) == {
            "steady": ("MIT", "compatible"),
            "victim/../other": ("UNKNOWN", "unknown"),
        }
        assert not other.called
        assert _requested(misses) == []

    @respx.mock
    def test_package_json_names_with_a_query_a_fragment_and_a_parent_segment(self, tmp_path):
        _write(
            tmp_path / "package.json",
            """\
            {
              "name": "app",
              "version": "1.0.0",
              "license": "MIT",
              "dependencies": {
                "steady": "1.0.0",
                "realpkg?y": "2.0.0",
                "realpkg#x": "3.0.0",
                "realpkg/../other": "1.0.0",
                "%72ealpkg": "4.0.0"
              }
            }
            """,
        )
        answer = {"name": "realpkg", "version": "9.0.0", "license": "MIT"}
        _serve("https://registry.npmjs.org/steady/1.0.0", {"version": "1.0.0", "license": "MIT"})
        # What each name asked for when it was written into the URL as it is:
        # the package document, a version of ``realpkg``, a version of ``other``.
        hijacked = [
            respx.get(host="registry.npmjs.org", path="/realpkg").mock(
                return_value=httpx.Response(200, json=answer)
            ),
            _serve("https://registry.npmjs.org/realpkg/4.0.0", answer),
            _serve("https://registry.npmjs.org/other/1.0.0", answer),
        ]
        misses = _misses()
        result, data = _check_json(tmp_path, "--no-transitive", "--no-require-lockfile")
        assert result.exit_code == 1
        assert _rows(data) == {
            "steady": ("MIT", "compatible"),
            "realpkg?y": ("UNKNOWN", "unknown"),
            "realpkg#x": ("UNKNOWN", "unknown"),
            "realpkg/../other": ("UNKNOWN", "unknown"),
            "%72ealpkg": ("UNKNOWN", "unknown"),
        }
        assert not any(route.called for route in hijacked)
        # Each is asked for under its own name: the version, the package
        # document that might list it, then the fallback.
        assert sorted(_requested(misses)) == sorted(
            [
                "registry.npmjs.org/realpkg%3Fy/2.0.0",
                "registry.npmjs.org/realpkg%3Fy",
                "api.deps.dev/v3/systems/NPM/packages/realpkg%3Fy/versions/2.0.0",
                "registry.npmjs.org/realpkg%23x/3.0.0",
                "registry.npmjs.org/realpkg%23x",
                "api.deps.dev/v3/systems/NPM/packages/realpkg%23x/versions/3.0.0",
                "registry.npmjs.org/%2572ealpkg/4.0.0",
                "registry.npmjs.org/%2572ealpkg",
                "api.deps.dev/v3/systems/NPM/packages/%2572ealpkg/versions/4.0.0",
            ]
        )

    @respx.mock
    def test_cargo_toml_name_with_a_fragment(self, tmp_path):
        _write(
            tmp_path / "Cargo.toml",
            """\
            [package]
            name = "app"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            steady = "=1.0.0"
            "realpkg#x" = "=1.0.0"
            """,
        )
        _serve(
            "https://crates.io/api/v1/crates/steady/1.0.0",
            {"version": {"num": "1.0.0", "license": "MIT"}},
        )
        _serve("https://crates.io/api/v1/crates/steady", {"crate": {}})
        realpkg = _serve(
            "https://crates.io/api/v1/crates/realpkg",
            {"crate": {"max_stable_version": "1.0.0"}, "version": {"license": "MIT"}},
        )
        misses = _misses()
        result, data = _check_json(tmp_path, "--no-transitive", "--no-require-lockfile")
        assert result.exit_code == 1
        assert _rows(data) == {
            "steady": ("MIT", "compatible"),
            "realpkg#x": ("UNKNOWN", "unknown"),
        }
        assert not realpkg.called
        assert _requested(misses) == [
            "crates.io/api/v1/crates/realpkg%23x/1.0.0",
            "api.deps.dev/v3/systems/CARGO/packages/realpkg%23x/versions/1.0.0",
        ]

    @respx.mock
    def test_pipfile_lock_name_that_walks_to_another_project(self, tmp_path):
        _write(
            tmp_path / "Pipfile.lock",
            """\
            {
              "_meta": {"pipfile-spec": 6, "hash": {"sha256": "x"}},
              "default": {
                "steady": {"version": "==1.0"},
                "victim/../other": {"version": "==1.0"}
              },
              "develop": {}
            }
            """,
        )
        release = {"info": {"version": "1.0", "license": "MIT", "requires_dist": []}}
        _serve("https://pypi.org/pypi/steady/1.0/json", release)
        other = _serve("https://pypi.org/pypi/other/1.0/json", release)
        misses = _misses()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        assert _rows(data) == {
            "steady": ("MIT", "compatible"),
            "victim/../other": ("UNKNOWN", "unknown"),
        }
        assert not other.called
        assert _requested(misses) == []
