"""A lockfile row covers a declaration only when both come from one source.

One package name can be a registry release in one manifest and a git
repository in another, or two repositories in two manifests. A lockfile's row
for the name covers a manifest's declaration only when the two come from the
same place:

* a registry row covers a registry declaration it satisfies, never one from a
  repository;
* a row from a repository covers a declaration from that repository, whatever
  commit, tag, or branch either names, and never a registry declaration of
  the name when a manifest declares that repository;
* a declaration no row covers is reported as its own row: resolved through
  the registry, with its manifest recorded as lacking a lockfile, or as it is
  declared when it has an origin.

Every lockfile format that records where a package came from is run both
ways: the lockfile holds the registry row, or the repository row.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.discovery._origin import UNRECORDED, same_source
from tests._helpers import _check_json, _file_diagnostics, _mock_npm, _mock_pypi, _write

_SHA = "0123456789abcdef0123456789abcdef01234567"
_GPL = "GPL-3.0-only"
_MISSING = (
    "declares dependencies that no lockfile covers; their versions and "
    "transitive dependencies are estimated from the registry"
)


def _refuse_everything_else() -> None:
    """Answer 404 to any request no earlier route matched, so that it is on record."""
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


def _registry_requests() -> list[str]:
    """URL of every request made for ``shared``, the batch pre-pass aside."""
    return [str(call.request.url) for call in respx.calls if "shared" in str(call.request.url)]


# ---------------------------------------------------------------- registries
#
# Every registry publishes ``shared`` 1.0.0 under a license the scanned
# project cannot use, so a row resolved from the registry is a violation.


def _mock_registries() -> None:
    _mock_npm("shared", _GPL)
    _mock_pypi("shared", _GPL)
    respx.get("https://rubygems.org/api/v2/rubygems/shared/versions/1.0.0.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "shared",
                "number": "1.0.0",
                "licenses": [_GPL],
                "dependencies": {"runtime": [], "development": []},
            },
        )
    )
    crate = "https://crates.io/api/v1/crates/shared"
    respx.get(crate).mock(
        return_value=httpx.Response(
            200,
            json={
                "crate": {"max_stable_version": "1.0.0", "max_version": "1.0.0"},
                "versions": [{"num": "1.0.0", "license": _GPL, "yanked": False}],
            },
        )
    )
    respx.get(f"{crate}/1.0.0").mock(
        return_value=httpx.Response(200, json={"version": {"num": "1.0.0", "license": _GPL}})
    )
    respx.get(f"{crate}/1.0.0/dependencies").mock(
        return_value=httpx.Response(200, json={"dependencies": []})
    )
    respx.get("https://hex.pm/api/packages/shared").mock(
        return_value=httpx.Response(
            200,
            json={
                "meta": {"licenses": [_GPL], "links": {}},
                "latest_stable_version": "1.0.0",
                "releases": [{"version": "1.0.0"}],
            },
        )
    )
    respx.get("https://hex.pm/api/packages/shared/releases/1.0.0").mock(
        return_value=httpx.Response(200, json={"requirements": {}})
    )
    respx.get("https://cran.r-project.org/src/contrib/PACKAGES").mock(
        return_value=httpx.Response(200, text="Package: shared\nVersion: 1.0.0\nLicense: GPL-3\n")
    )
    respx.get("https://repo.packagist.org/p2/acme/shared.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "packages": {
                    "acme/shared": [{"version": "1.0.0", "license": [_GPL], "require": {}}]
                }
            },
        )
    )
    _refuse_everything_else()


# ------------------------------------------------------------------- formats


@dataclass(frozen=True)
class _Format:
    """One manifest format with one lockfile format, for a package named ``shared``.

    ``registry`` is a manifest that requires the registry release 1.0.0.
    ``sourced(owner, ref)`` is a manifest that takes the package from the
    repository ``<owner>/shared`` at ``ref``; ``declared(owner, ref)`` is the
    origin that declaration has. ``respelled`` is a manifest that names the
    repository ``team/shared`` in another spelling, with another ref.

    ``registry_lock`` holds the registry release, ``sourced_lock`` the
    repository ``team/shared`` at a commit: a row with the origin ``locked``
    at the version ``locked_version`` (empty where the format records none).
    """

    ecosystem: str
    manifest: str
    registry: str
    sourced: Callable[[str, str], str]
    declared: Callable[[str, str], str]
    respelled: str
    lockfile: str
    registry_lock: str
    sourced_lock: str
    locked: str
    locked_version: str = "0.9.0"
    name: str = "shared"


_GIT = "https://git.example.org"


def _package_json(spec: str) -> str:
    return json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"shared": spec}})


_NPM = {
    "ecosystem": "npm",
    "manifest": "package.json",
    "registry": _package_json("1.0.0"),
    "sourced": lambda owner, ref: _package_json(f"github:{owner}/shared#{ref}"),
    "declared": lambda owner, ref: f"git+https://github.com/{owner}/shared@{ref}",
    "respelled": _package_json("git+ssh://git@github.com/team/shared.git#main"),
}
_NPM_TARBALL = "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz"
_CODELOAD = f"https://codeload.github.com/team/shared/tar.gz/{_SHA}"

_PEP621 = '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["{0}"]\n'
_POETRY = (
    '[tool.poetry]\nname = "app"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\nshared = {0}\n'
)
_PIPFILE_LOCK = (
    '{{"_meta": {{"pipfile-spec": 6}}, "default": {{"shared": {0}}}, "develop": {{}}}}\n'
)
_GEMFILE = 'source "https://rubygems.org"\ngem "shared", {0}\n'
_CARGO_TOML = '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nshared = {0}\n'
_CARGO_LOCK = (
    'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["shared"]\n\n'
    '[[package]]\nname = "shared"\nversion = "{0}"\nsource = "{1}"\n'
)
_MIX_EXS = (
    "defmodule App.MixProject do\n  use Mix.Project\n\n"
    '  def project do\n    [app: :app, version: "0.1.0", deps: deps()]\n  end\n\n'
    "  defp deps do\n    [{{:shared, {0}}}]\n  end\nend\n"
)
_DESCRIPTION = "Package: app\nVersion: 0.1.0\nImports: shared\n"


def _composer_json(owner: str = "", ref: str = "") -> str:
    """A composer.json that requires ``acme/shared``, from Packagist or from a repository."""
    if not owner:
        return json.dumps({"name": "x/app", "require": {"acme/shared": "1.0.0"}})
    package = {
        "name": "acme/shared",
        "version": "0.9.0",
        "source": {"type": "git", "url": f"{_GIT}/{owner}/shared.git", "reference": ref},
    }
    return json.dumps(
        {
            "name": "x/app",
            "require": {"acme/shared": "0.9.0"},
            "repositories": [{"type": "package", "package": package}],
        }
    )


def _renv_lock(**fields: str) -> str:
    return json.dumps({"Packages": {"shared": {"Package": "shared", **fields}}})


_FORMATS: dict[str, _Format] = {
    "package-lock": _Format(
        **_NPM,
        lockfile="package-lock.json",
        registry_lock=json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/shared": {"version": "1.0.0", "resolved": _NPM_TARBALL},
                },
            }
        ),
        sourced_lock=json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/shared": {
                        "version": "0.9.0",
                        "resolved": f"git+ssh://git@github.com/team/shared.git#{_SHA}",
                    },
                },
            }
        ),
        locked=f"git+ssh://github.com/team/shared.git@{_SHA}",
    ),
    "package-lock-v1": _Format(
        **_NPM,
        lockfile="package-lock.json",
        registry_lock=json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {"shared": {"version": "1.0.0", "resolved": _NPM_TARBALL}},
            }
        ),
        sourced_lock=json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "shared": {
                        "version": f"github:team/shared#{_SHA}",
                        "from": "github:team/shared",
                    }
                },
            }
        ),
        locked=f"git+https://github.com/team/shared@{_SHA}",
        locked_version="",
    ),
    "yarn-classic": _Format(
        **_NPM,
        lockfile="yarn.lock",
        registry_lock=(
            "# yarn lockfile v1\n\n\nshared@1.0.0:\n"
            f'  version "1.0.0"\n  resolved "{_NPM_TARBALL}#aa"\n'
        ),
        # The tarball of the commit the shorthand resolved to.
        sourced_lock=(
            '# yarn lockfile v1\n\n\n"shared@github:team/shared#v9":\n'
            f'  version "0.9.0"\n  resolved "{_CODELOAD}"\n'
        ),
        locked=_CODELOAD,
    ),
    "yarn-berry": _Format(
        **_NPM,
        lockfile="yarn.lock",
        registry_lock=(
            '__metadata:\n  version: 8\n\n"shared@npm:1.0.0":\n'
            '  version: 1.0.0\n  resolution: "shared@npm:1.0.0"\n'
        ),
        sourced_lock=(
            '__metadata:\n  version: 8\n\n"shared@github:team/shared#v9":\n  version: 0.9.0\n'
            f'  resolution: "shared@https://github.com/team/shared.git#commit={_SHA}"\n'
        ),
        locked=f"git+https://github.com/team/shared.git@{_SHA}",
    ),
    "pnpm": _Format(
        **_NPM,
        lockfile="pnpm-lock.yaml",
        registry_lock=(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      shared:\n"
            "        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  shared@1.0.0:\n"
            "    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  shared@1.0.0: {}\n"
        ),
        sourced_lock=(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      shared:\n"
            f"        specifier: github:team/shared#v9\n        version: {_CODELOAD}\n\n"
            f"packages:\n\n  shared@{_CODELOAD}:\n    resolution: {{tarball: {_CODELOAD}}}\n"
            f"    version: 0.9.0\n\nsnapshots:\n\n  shared@{_CODELOAD}: {{}}\n"
        ),
        locked=_CODELOAD,
    ),
    "bun": _Format(
        **_NPM,
        lockfile="bun.lock",
        registry_lock=json.dumps(
            {"lockfileVersion": 1, "packages": {"shared": ["shared@1.0.0", "", {}, "sha512-x"]}}
        ),
        sourced_lock=json.dumps(
            {
                "lockfileVersion": 1,
                "packages": {
                    "shared": [f"shared@github:team/shared#{_SHA[:7]}", {}, "team-shared"]
                },
            }
        ),
        locked=f"git+https://github.com/team/shared@{_SHA[:7]}",
        locked_version="",
    ),
    "uv": _Format(
        ecosystem="python",
        manifest="pyproject.toml",
        registry=_PEP621.format("shared==1.0.0"),
        sourced=lambda owner, ref: _PEP621.format(f"shared @ git+{_GIT}/{owner}/shared.git@{ref}"),
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=_PEP621.format("shared @ git+ssh://git@git.example.org/team/shared@main"),
        lockfile="uv.lock",
        registry_lock=(
            'version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n'
            'source = { virtual = "." }\ndependencies = [{ name = "shared" }]\n\n'
            '[[package]]\nname = "shared"\nversion = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        ),
        sourced_lock=(
            'version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n'
            'source = { virtual = "." }\ndependencies = [{ name = "shared" }]\n\n'
            '[[package]]\nname = "shared"\nversion = "0.9.0"\n'
            f'source = {{ git = "{_GIT}/team/shared.git?tag=v9#{_SHA}" }}\n'
        ),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
    ),
    "poetry": _Format(
        ecosystem="python",
        manifest="pyproject.toml",
        registry=_POETRY.format('"==1.0.0"'),
        sourced=lambda owner, ref: _POETRY.format(
            f'{{git = "{_GIT}/{owner}/shared.git", tag = "{ref}"}}'
        ),
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=_POETRY.format('{git = "git@git.example.org:team/shared.git", branch = "main"}'),
        lockfile="poetry.lock",
        registry_lock=(
            '[[package]]\nname = "shared"\nversion = "1.0.0"\n\n[metadata]\nlock-version = "2.0"\n'
        ),
        sourced_lock=(
            '[[package]]\nname = "shared"\nversion = "0.9.0"\n\n[package.source]\ntype = "git"\n'
            f'url = "{_GIT}/team/shared.git"\nreference = "v9"\nresolved_reference = "{_SHA}"\n\n'
            '[metadata]\nlock-version = "2.0"\n'
        ),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
    ),
    "pipfile": _Format(
        ecosystem="python",
        manifest="Pipfile",
        registry='[packages]\nshared = "==1.0.0"\n',
        sourced=lambda owner, ref: (
            f'[packages]\nshared = {{git = "{_GIT}/{owner}/shared.git", ref = "{ref}"}}\n'
        ),
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=(
            '[packages]\nshared = {git = "ssh://git@git.example.org/team/shared", ref = "main"}\n'
        ),
        lockfile="Pipfile.lock",
        registry_lock=_PIPFILE_LOCK.format('{"version": "==1.0.0", "hashes": []}'),
        sourced_lock=_PIPFILE_LOCK.format(
            json.dumps({"git": f"{_GIT}/team/shared.git", "ref": _SHA})
        ),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
        locked_version="",
    ),
    "gemfile": _Format(
        ecosystem="ruby",
        manifest="Gemfile",
        registry=_GEMFILE.format('"1.0.0"'),
        sourced=lambda owner, ref: _GEMFILE.format(
            f'git: "{_GIT}/{owner}/shared.git", tag: "{ref}"'
        ),
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=_GEMFILE.format('git: "git@git.example.org:team/shared.git", branch: "main"'),
        lockfile="Gemfile.lock",
        registry_lock=(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    shared (1.0.0)\n\n"
            "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  shared (= 1.0.0)\n"
        ),
        sourced_lock=(
            f"GIT\n  remote: {_GIT}/team/shared.git\n  revision: {_SHA}\n  tag: v9\n"
            "  specs:\n    shared (0.9.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\n"
            "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  shared!\n"
        ),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
    ),
    "cargo": _Format(
        ecosystem="rust",
        manifest="Cargo.toml",
        registry=_CARGO_TOML.format('"=1.0.0"'),
        sourced=lambda owner, ref: _CARGO_TOML.format(
            f'{{ git = "{_GIT}/{owner}/shared.git", tag = "{ref}" }}'
        ),
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=_CARGO_TOML.format(
            '{ git = "ssh://git@git.example.org/team/shared", branch = "main" }'
        ),
        lockfile="Cargo.lock",
        registry_lock=_CARGO_LOCK.format(
            "1.0.0", "registry+https://github.com/rust-lang/crates.io-index"
        ),
        sourced_lock=_CARGO_LOCK.format("0.9.0", f"git+{_GIT}/team/shared.git?tag=v9#{_SHA}"),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
    ),
    "mix": _Format(
        ecosystem="hex",
        manifest="mix.exs",
        registry=_MIX_EXS.format('"1.0.0"'),
        sourced=lambda owner, ref: _MIX_EXS.format(
            f'git: "{_GIT}/{owner}/shared.git", tag: "{ref}"'
        ),
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=_MIX_EXS.format('git: "git@git.example.org:team/shared.git", branch: "main"'),
        lockfile="mix.lock",
        registry_lock=(
            '%{\n  "shared": {:hex, :shared, "1.0.0", "h", [:mix], [], "hexpm", "h2"},\n}\n'
        ),
        sourced_lock=(
            f'%{{\n  "shared": {{:git, "{_GIT}/team/shared.git", "{_SHA}", [tag: "v9"]}},\n}}\n'
        ),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
        locked_version="",
    ),
    "rebar": _Format(
        ecosystem="hex",
        manifest="rebar.config",
        registry='{deps, [{shared, "1.0.0"}]}.\n',
        sourced=lambda owner, ref: (
            f'{{deps, [{{shared, {{git, "{_GIT}/{owner}/shared.git", {{tag, "{ref}"}}}}}}]}}.\n'
        ),
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=(
            '{deps, [{shared, {git, "git@git.example.org:team/shared.git", {branch, "main"}}}]}.\n'
        ),
        lockfile="rebar.lock",
        registry_lock='{"1.2.0",\n[{<<"shared">>,{pkg,<<"shared">>,<<"1.0.0">>},0}]}.\n',
        sourced_lock=(
            f'{{"1.2.0",\n[{{<<"shared">>,{{git,"{_GIT}/team/shared.git",{{ref,"{_SHA}"}}}},0}}]}}.\n'
        ),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
        locked_version="",
    ),
    "renv": _Format(
        ecosystem="r",
        manifest="DESCRIPTION",
        registry=_DESCRIPTION,
        sourced=lambda owner, ref: f"{_DESCRIPTION}Remotes: {owner}/shared@{ref}\n",
        declared=lambda owner, ref: f"git+https://github.com/{owner}/shared@{ref}",
        respelled=f"{_DESCRIPTION}Remotes: git::git@github.com:team/shared.git@main\n",
        lockfile="renv.lock",
        registry_lock=_renv_lock(Version="1.0.0", Source="Repository", Repository="CRAN"),
        sourced_lock=_renv_lock(
            Version="0.9.0",
            Source="GitHub",
            RemoteUsername="team",
            RemoteRepo="shared",
            RemoteRef="v9",
            RemoteSha=_SHA,
        ),
        locked=f"git+https://github.com/team/shared@{_SHA}",
    ),
    "packrat": _Format(
        ecosystem="r",
        manifest="DESCRIPTION",
        registry=_DESCRIPTION,
        sourced=lambda owner, ref: f"{_DESCRIPTION}Remotes: {owner}/shared@{ref}\n",
        declared=lambda owner, ref: f"git+https://github.com/{owner}/shared@{ref}",
        respelled=f"{_DESCRIPTION}Remotes: github::team/shared@main\n",
        lockfile="packrat/packrat.lock",
        registry_lock=(
            "PackratFormat: 1.4\nRVersion: 4.3.0\n\nPackage: shared\nSource: CRAN\nVersion: 1.0.0\n"
        ),
        sourced_lock=(
            "PackratFormat: 1.4\nRVersion: 4.3.0\n\nPackage: shared\nSource: github\n"
            f"Version: 0.9.0\nGithubUsername: team\nGithubRepo: shared\nGithubSha1: {_SHA}\n"
        ),
        locked=f"git+https://github.com/team/shared@{_SHA}",
    ),
    "composer": _Format(
        ecosystem="php",
        manifest="composer.json",
        registry=_composer_json(),
        sourced=_composer_json,
        declared=lambda owner, ref: f"git+{_GIT}/{owner}/shared.git@{ref}",
        respelled=_composer_json("team", "main").replace(
            f"{_GIT}/team/shared.git", "git@git.example.org:team/shared.git"
        ),
        lockfile="composer.lock",
        registry_lock=json.dumps(
            {
                "packages": [{"name": "acme/shared", "version": "1.0.0", "license": [_GPL]}],
                "packages-dev": [],
            }
        ),
        sourced_lock=json.dumps(
            {
                "packages": [
                    {
                        "name": "acme/shared",
                        "version": "0.9.0",
                        "source": {
                            "type": "git",
                            "url": f"{_GIT}/team/shared.git",
                            "reference": _SHA,
                        },
                    }
                ],
                "packages-dev": [],
            }
        ),
        locked=f"git+{_GIT}/team/shared.git@{_SHA}",
        name="acme/shared",
    ),
}


def _project(root: Path, fmt: _Format, locked: str, lock: str, unlocked: str) -> None:
    """``a`` holds the manifest ``locked`` and the lockfile ``lock``; ``b`` holds ``unlocked``."""
    for relative, content in (
        (f"a/{fmt.manifest}", locked),
        (f"a/{fmt.lockfile}", lock),
        (f"b/{fmt.manifest}", unlocked),
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")


def _rows(data: dict) -> list[tuple[str, str, str, str, str]]:
    """Each row as ``(name, origin, version, detected license, source)``."""
    return sorted(
        (d["name"], d["origin"], d["resolved_version"], d["detected_license"], d["source"])
        for d in data["dependencies"]
    )


def _review(root: Path, fmt: _Format, origin: str) -> None:
    (root / "licenseal.review.toml").write_text(
        f'[[review]]\necosystem = "{fmt.ecosystem}"\npackage = "{fmt.name}"\n'
        f'source = "{origin}"\nlicense = "MIT"\nnote = "read at that commit"\n',
        encoding="utf-8",
    )


@pytest.mark.parametrize("layout", sorted(_FORMATS))
class TestEveryLockfileFormat:
    @respx.mock
    def test_registry_row_does_not_cover_a_declaration_from_a_repository(self, tmp_path, layout):
        fmt = _FORMATS[layout]
        _project(tmp_path, fmt, fmt.registry, fmt.registry_lock, fmt.sourced("team", "v9"))
        _mock_registries()

        result, data = _check_json(tmp_path)

        assert result.exit_code == 1
        assert _rows(data) == [
            (fmt.name, "", "1.0.0", _GPL, f"a/{fmt.manifest}"),
            (fmt.name, fmt.declared("team", "v9"), "", "UNKNOWN", f"b/{fmt.manifest}"),
        ]
        # The lockfile covers the one registry requirement there is.
        assert data["diagnostics"] == []

    @respx.mock
    def test_repository_row_does_not_cover_a_registry_declaration(self, tmp_path, layout):
        fmt = _FORMATS[layout]
        _project(tmp_path, fmt, fmt.sourced("team", "v9"), fmt.sourced_lock, fmt.registry)
        _mock_registries()
        # The repository row is reviewed: what is left is the registry release.
        _review(tmp_path, fmt, fmt.locked)

        result, data = _check_json(tmp_path)

        assert result.exit_code == 1
        assert _rows(data) == [
            (fmt.name, "", "1.0.0", _GPL, f"b/{fmt.manifest}"),
            (fmt.name, fmt.locked, fmt.locked_version, "UNKNOWN", f"a/{fmt.manifest}"),
        ]
        registry_row = next(d for d in data["dependencies"] if not d["origin"])
        assert registry_row["verdict"] == "incompatible"
        assert data["diagnostics"] == [
            {"path": f"b/{fmt.manifest}", "reason": _MISSING, "severity": "gap"}
        ]

        # With the estimate accepted the violation still fails the scan.
        accepted, data = _check_json(tmp_path, "--no-require-lockfile")
        assert accepted.exit_code == 1
        assert _file_diagnostics(data) == []
        assert data["summary"]["violations"] == 1

    @respx.mock
    def test_same_repository_in_another_spelling_is_covered(self, tmp_path, layout):
        fmt = _FORMATS[layout]
        _project(tmp_path, fmt, fmt.sourced("team", "v9"), fmt.sourced_lock, fmt.respelled)
        _mock_registries()

        result, data = _check_json(tmp_path)

        assert result.exit_code == 1
        # One row, with the commit the lockfile records.
        assert _rows(data) == [
            (fmt.name, fmt.locked, fmt.locked_version, "UNKNOWN", f"a/{fmt.manifest}")
        ]
        assert data["diagnostics"] == []
        assert _registry_requests() == []

        _review(tmp_path, fmt, fmt.locked)
        reviewed, _ = _check_json(tmp_path)
        assert reviewed.exit_code == 0

    @respx.mock
    def test_another_repository_is_a_row_of_its_own(self, tmp_path, layout):
        fmt = _FORMATS[layout]
        _project(
            tmp_path, fmt, fmt.sourced("team", "v9"), fmt.sourced_lock, fmt.sourced("other", "main")
        )
        _mock_registries()
        _review(tmp_path, fmt, fmt.locked)

        result, data = _check_json(tmp_path)

        # The review of one repository does not clear the other.
        assert result.exit_code == 1
        assert _rows(data) == [
            (fmt.name, fmt.declared("other", "main"), "", "UNKNOWN", f"b/{fmt.manifest}"),
            (fmt.name, fmt.locked, fmt.locked_version, "UNKNOWN", f"a/{fmt.manifest}"),
        ]
        assert data["diagnostics"] == []
        assert _registry_requests() == []


# One layout for each manifest format.
_MANIFESTS = (
    "package-lock",
    "uv",
    "poetry",
    "pipfile",
    "gemfile",
    "cargo",
    "mix",
    "rebar",
    "renv",
    "composer",
)


class TestWithoutALockfile:
    @respx.mock
    @pytest.mark.parametrize("layout", _MANIFESTS)
    def test_two_repositories_are_two_rows(self, tmp_path, layout):
        fmt = _FORMATS[layout]
        _write(tmp_path / "a" / fmt.manifest, fmt.sourced("team", "v9"))
        _write(tmp_path / "b" / fmt.manifest, fmt.sourced("other", "main"))
        _mock_registries()

        result, data = _check_json(tmp_path)

        assert result.exit_code == 1
        assert _rows(data) == [
            (fmt.name, fmt.declared("other", "main"), "", "UNKNOWN", f"b/{fmt.manifest}"),
            (fmt.name, fmt.declared("team", "v9"), "", "UNKNOWN", f"a/{fmt.manifest}"),
        ]
        assert _registry_requests() == []


class TestLockfileAndManifestDisagree:
    @respx.mock
    def test_registry_row_stands_for_one_declared_repository(self, tmp_path):
        # Both manifests take the package from a repository; the lockfile,
        # which is stale, still holds the registry release.
        fmt = _FORMATS["uv"]
        _project(
            tmp_path,
            fmt,
            fmt.sourced("team", "v9"),
            fmt.registry_lock,
            fmt.sourced("other", "main"),
        )
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _rows(data) == [
            ("shared", fmt.declared("other", "main"), "", "UNKNOWN", "b/pyproject.toml"),
            ("shared", fmt.declared("team", "v9"), "1.0.0", "UNKNOWN", "a/pyproject.toml"),
        ]
        assert _registry_requests() == []

        # The same repository in both manifests is the one row.
        _write(tmp_path / "b" / fmt.manifest, fmt.respelled)
        _, data = _check_json(tmp_path)
        assert _rows(data) == [
            ("shared", fmt.declared("team", "v9"), "1.0.0", "UNKNOWN", "a/pyproject.toml")
        ]

    @respx.mock
    def test_manifest_that_moved_to_another_repository(self, tmp_path):
        fmt = _FORMATS["package-lock"]
        _write(tmp_path / fmt.manifest, fmt.sourced("other", "main"))
        _write(tmp_path / fmt.lockfile, fmt.sourced_lock)
        _mock_registries()

        _, data = _check_json(tmp_path)

        # The declared repository is the direct dependency. The lockfile's
        # row is what was installed, under no manifest.
        assert sorted(
            (d["origin"], d["resolved_version"], d["depth"], d["source"])
            for d in data["dependencies"]
        ) == [
            (fmt.declared("other", "main"), "", 0, "package.json"),
            (fmt.locked, "0.9.0", 1, ""),
        ]

    @respx.mock
    def test_known_limit_lockfile_names_a_repository_that_no_manifest_declares(self, tmp_path):
        """Known limit: one row, where the two requirements may be two packages.

        ``a`` requires the package without saying where from, and its
        lockfile takes it from a repository. ``b`` requires the registry
        package and has no lockfile. No manifest names the repository, so
        the lockfile's row answers both requirements. Telling them apart
        needs to know which manifest a lockfile belongs to.
        """
        fmt = _FORMATS["renv"]
        _project(tmp_path, fmt, fmt.registry, fmt.sourced_lock, fmt.registry)
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _rows(data) == [("shared", fmt.locked, "0.9.0", "UNKNOWN", "a/DESCRIPTION")]
        assert data["diagnostics"] == []
        assert _registry_requests() == []


class TestSourcesThatAreNotRepositories:
    @respx.mock
    def test_path_is_compared_from_the_directory_of_each_file(self, tmp_path):
        # A workspace: the lockfile at the root writes a member's path from
        # the root, the member writes it from its own directory. ``n`` names
        # another archive, which the lockfile does not hold.
        member = {"version": "1.0.0", "dependencies": {"shared": "file:./lib/shared-0.9.0.tgz"}}
        other = {"version": "1.0.0", "dependencies": {"shared": "file:../n/shared-0.9.0.tgz"}}
        root = {"name": "root", "private": True, "workspaces": ["packages/*"]}
        _write(tmp_path / "package.json", json.dumps(root))
        _write(tmp_path / "packages" / "m" / "package.json", json.dumps({"name": "m", **member}))
        _write(tmp_path / "packages" / "n" / "package.json", json.dumps({"name": "n", **other}))
        _write(
            tmp_path / "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": root,
                        "node_modules/m": {"resolved": "packages/m", "link": True},
                        "packages/m": {"name": "m", **member},
                        "node_modules/shared": {
                            "version": "0.9.0",
                            "resolved": "file:packages/m/lib/shared-0.9.0.tgz",
                        },
                    },
                }
            ),
        )
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _rows(data) == [
            ("shared", "../n/shared-0.9.0.tgz", "", "UNKNOWN", "packages/n/package.json"),
            (
                "shared",
                "packages/m/lib/shared-0.9.0.tgz",
                "0.9.0",
                "UNKNOWN",
                "packages/m/package.json",
            ),
        ]
        assert _registry_requests() == []

    @respx.mock
    def test_path_a_lockfile_does_not_record_is_read_from_the_manifest_that_words_it(
        self, tmp_path
    ):
        # A Cargo.lock gives no location for a crate built from a path: the
        # row has the path one member declares, here the deeper one. The
        # other member names the same directory from another depth.
        crate = (
            '[package]\nname = "{0}"\nversion = "0.1.0"\n\n'
            '[dependencies]\nshared = {{ path = "{1}" }}\n'
        )
        _write(tmp_path / "Cargo.toml", '[workspace]\nmembers = ["app", "crates/*"]\n')
        _write(tmp_path / "app" / "Cargo.toml", crate.format("app", "../../outside/shared"))
        _write(
            tmp_path / "crates" / "deep" / "Cargo.toml",
            crate.format("deep", "../../../outside/shared"),
        )
        _write(
            tmp_path / "Cargo.lock",
            "version = 3\n\n"
            + "".join(
                f'[[package]]\nname = "{name}"\nversion = "0.1.0"\ndependencies = ["shared"]\n\n'
                for name in ("app", "deep")
            )
            + '[[package]]\nname = "shared"\nversion = "0.9.0"\n',
        )
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _rows(data) == [
            ("shared", "../../../outside/shared", "0.9.0", "UNKNOWN", "app/Cargo.toml")
        ]
        assert data["diagnostics"] == []
        assert _registry_requests() == []

    @respx.mock
    def test_source_label_covers_a_declaration_from_any_source(self, tmp_path):
        # The lockfile says only "Bioconductor": nothing shows that the
        # repository the other manifest names is another source.
        _write(tmp_path / "a" / "DESCRIPTION", f"{_DESCRIPTION}Remotes: bioc::shared\n")
        _write(tmp_path / "a" / "renv.lock", _renv_lock(Version="0.9.0", Source="Bioconductor"))
        _write(tmp_path / "b" / "DESCRIPTION", f"{_DESCRIPTION}Remotes: team/shared@v9\n")
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _rows(data) == [("shared", "Bioconductor", "0.9.0", "UNKNOWN", "a/DESCRIPTION")]
        assert _registry_requests() == []


_REPOSITORY = "git+https://github.com/team/shared"


class TestSameSource:
    @pytest.mark.parametrize(
        ("locked", "declared", "expected"),
        [
            # One repository, whatever the spelling and the revision.
            (f"git+ssh://github.com/team/shared.git@{_SHA}", f"{_REPOSITORY}@v9", True),
            (f"{_REPOSITORY}.git@{_SHA}", "git+github.com:team/shared.git", True),
            (f"git+https://GitHub.com/Team/Shared/@{_SHA}", f"{_REPOSITORY}@main", True),
            # A tag can hold an ``@``.
            (f"{_REPOSITORY}@{_SHA}", f"{_REPOSITORY}@@scope/shared@1.0.0", True),
            (f"git+https://github.com/other/shared@{_SHA}", f"{_REPOSITORY}@v9", False),
            (f"git+https://gitlab.com/team/shared@{_SHA}", f"{_REPOSITORY}@v9", False),
            # One URL, whatever the hash.
            (
                "https://dl.example.org/shared-1.0.tgz#sha512-x",
                "https://dl.example.org/shared-1.0.tgz",
                True,
            ),
            (
                "https://dl.example.org/shared-1.1.tgz",
                "https://dl.example.org/shared-1.0.tgz",
                False,
            ),
            # The archive a host serves for a commit of a repository.
            (f"https://codeload.github.com/team/shared/tar.gz/{_SHA}", f"{_REPOSITORY}@v9", True),
            (f"{_REPOSITORY}@{_SHA}", "https://github.com/team/shared/archive/v9.tar.gz", True),
            (f"https://codeload.github.com/other/shared/tar.gz/{_SHA}", f"{_REPOSITORY}@v9", False),
            ("https://dl.example.org/team/shared/v9.tgz", f"{_REPOSITORY}@v9", False),
            # A path is no repository and no URL.
            ("../shared", _REPOSITORY, False),
            ("https://dl.example.org/shared-1.0.tgz", "../shared-1.0.tgz", False),
            # Nothing to compare: the origin names no place.
            ("Bioconductor", _REPOSITORY, None),
            (_REPOSITORY, "Bioconductor", None),
            (UNRECORDED, "../shared", None),
        ],
    )
    def test_repositories_and_urls(self, locked, declared, expected):
        assert same_source(locked, declared) is expected

    @pytest.mark.parametrize(
        ("locked", "declared", "declared_dir", "expected"),
        [
            ("../outside/shared", "../outside/shared", "a", True),
            ("vendor\\shared.tgz", "./vendor/shared.tgz", "", True),
            # A lockfile above the manifest writes the path from where it is.
            ("packages/m/lib/shared.tgz", "./lib/shared.tgz", "packages/m", True),
            ("../outside/shared", "../../../outside/shared", "packages/m", True),
            ("packages/n/lib/shared.tgz", "./lib/shared.tgz", "packages/m", False),
            ("../other/shared", "../outside/shared", "a", False),
            # A rooted path is taken from no directory.
            ("/opt/shared", "/opt/shared/", "a", True),
            ("C:\\libs\\shared", "C:/libs/shared", "a", True),
            ("/opt/shared", "../opt/shared", "a", False),
            ("~/lib/shared", "lib/shared", "", False),
        ],
    )
    def test_paths(self, locked, declared, declared_dir, expected):
        assert same_source(locked, declared, declared_dir) is expected

    @pytest.mark.parametrize(
        ("locked_dir", "declared", "declared_dir", "expected"),
        [
            ("crates/deep", "../../outside/shared", "app", True),
            ("crates/deep", "../../../outside/shared", "x/y/z", False),
            # Not taken from a directory above the manifest when it is known.
            ("elsewhere/a/b", "../../../outside/shared", "crates/deep", False),
        ],
    )
    def test_path_written_from_a_known_directory(
        self, locked_dir, declared, declared_dir, expected
    ):
        locked = "../../../outside/shared"
        assert same_source(locked, declared, declared_dir, locked_dir) is expected
