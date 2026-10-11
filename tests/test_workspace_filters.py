"""A workspace member is the project's own code, however another manifest spells its name.

A package of the scanned tree that another manifest of the tree depends on
is not published: it is left out before any registry is asked about it. The
name is compared by the ecosystem's identity rule. Where the registry folds
case (.NET, Rust, PHP, Hex, R, and Python under PEP 503), a member named in
another case is still the member. Where case is part of the name (npm, Ruby,
Go, Java), a name in another case is another package and stays a dependency.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.discovery import discover_all_dependencies
from licenseal.discovery.rust.cargo_toml import cargo_sources
from tests._helpers import _check_json, _write

_MODES = pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
_FLAGS = ("--no-require-lockfile",)


def _refuse_everything_else() -> None:
    """Answer 404 to any request no earlier route matched, so that it is on record."""
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


def _requests_mentioning(name: str) -> list[str]:
    """URL of every request made whose URL or body mentions ``name``, in any case."""
    hits: list[str] = []
    for call in respx.calls:
        request = call.request
        text = f"{request.url} {request.content.decode('utf-8', 'replace')}".lower()
        if name.lower() in text:
            hits.append(str(request.url))
    return hits


def _excluded(label: str, count: int = 1) -> str:
    return (
        f"Excluded {count} local {label} workspace package reference(s) from resolution "
        "(not published to the registry)."
    )


# -------------------------------------------------------------------- .NET


def _csproj(*references: tuple[str, str]) -> str:
    items = "".join(
        f'<PackageReference Include="{name}" Version="{version}" />' for name, version in references
    )
    return f'<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>{items}</ItemGroup></Project>'


def _mock_nuspec(package_id: str, version: str) -> None:
    lowered = package_id.lower()
    respx.get(f"https://api.nuget.org/v3-flatcontainer/{lowered}/{version}/{lowered}.nuspec").mock(
        return_value=httpx.Response(
            200,
            text=(
                f"<package><metadata><id>{package_id}</id><version>{version}</version>"
                '<license type="expression">MIT</license></metadata></package>'
            ),
        )
    )


class TestDotnetProjectNamedInAnotherCase:
    def _project(self, root: Path) -> None:
        _write(root / "MyLib" / "MyLib.csproj", _csproj())
        _write(root / "App" / "App.csproj", _csproj(("mylib", "1.0.0"), ("Real.Pkg", "1.0.0")))
        _mock_nuspec("Real.Pkg", "1.0.0")
        _refuse_everything_else()

    @respx.mock
    @_MODES
    def test_project_file_reference_is_not_looked_up(self, tmp_path, mode):
        self._project(tmp_path)

        result, data = _check_json(tmp_path, mode, *_FLAGS)

        assert result.exit_code == 0
        assert [dep["name"] for dep in data["dependencies"]] == ["Real.Pkg"]
        assert _excluded(".NET") in result.output
        assert _requests_mentioning("mylib") == []

    @respx.mock
    def test_directory_build_props_reference_is_not_looked_up(self, tmp_path):
        _write(tmp_path / "MyLib" / "MyLib.csproj", _csproj())
        _write(tmp_path / "Directory.Build.props", _csproj(("MYLIB", "1.0.0")))
        _refuse_everything_else()

        result, data = _check_json(tmp_path, "--no-transitive")

        assert result.exit_code == 0
        assert data["dependencies"] == []
        assert _excluded(".NET") in result.output
        assert respx.calls.call_count == 0


# -------------------------------------------------------------------- Rust


def _cargo(name: str, dependencies: str = "", extra: str = "") -> str:
    return f'[package]\nname = "{name}"\nversion = "0.1.0"\n\n[dependencies]\n{dependencies}{extra}'


def _mock_crate(name: str, version: str) -> None:
    base = f"https://crates.io/api/v1/crates/{name}"
    respx.get(base).mock(
        return_value=httpx.Response(200, json={"crate": {"max_stable_version": version}})
    )
    respx.get(f"{base}/{version}").mock(
        return_value=httpx.Response(200, json={"version": {"num": version, "license": "MIT"}})
    )
    respx.get(f"{base}/{version}/dependencies").mock(
        return_value=httpx.Response(200, json={"dependencies": []})
    )


class TestCargoMemberNamedInAnotherCase:
    def _project(self, root: Path) -> None:
        _write(root / "Cargo.toml", '[workspace]\nmembers = ["core-lib", "app"]\n')
        _write(root / "core-lib" / "Cargo.toml", _cargo("core-lib"))
        # A version-only reference to the member, in another case.
        _write(
            root / "app" / "Cargo.toml",
            _cargo("app", 'Core-Lib = "0.1"\nreal = "=1.0.0"\n'),
        )
        _mock_crate("real", "1.0.0")
        _refuse_everything_else()

    @respx.mock
    @_MODES
    def test_member_is_not_looked_up(self, tmp_path, mode):
        self._project(tmp_path)

        result, data = _check_json(tmp_path, mode, *_FLAGS)

        assert result.exit_code == 0
        assert [dep["name"] for dep in data["dependencies"]] == ["real"]
        assert _excluded("Rust") in result.output
        assert _requests_mentioning("core-lib") == []

    def test_path_dependency_on_a_member_in_another_case_is_not_a_lockfile_root(self, tmp_path):
        # A path dependency on a directory that holds a crate of that name is
        # no root of the Cargo.lock graph: the member's own manifest supplies
        # its dependencies. The crate is the same in any case.
        _write(tmp_path / "Cargo.toml", '[workspace]\nmembers = ["core-lib", "app"]\n')
        _write(tmp_path / "core-lib" / "Cargo.toml", _cargo("core-lib"))
        _write(
            tmp_path / "app" / "Cargo.toml",
            _cargo("app", 'Core-Lib = { path = "../core-lib" }\n'),
        )

        sources = cargo_sources(tmp_path)

        assert (sources.prod_roots, sources.dev_roots) == (set(), set())


class TestCargoPatchNamedInAnotherCase:
    @respx.mock
    @_MODES
    def test_patched_crate_is_not_looked_up(self, tmp_path, mode):
        patch = 'Forked-Dep = { git = "https://git.example.org/forked.git" }'
        _write(
            tmp_path / "Cargo.toml",
            _cargo(
                "app",
                'forked-dep = "1.0"\nreal = "=1.0.0"\n',
                f"\n[patch.crates-io]\n{patch}\n",
            ),
        )
        _mock_crate("real", "1.0.0")
        _refuse_everything_else()

        result, data = _check_json(tmp_path, mode, "--no-strict", *_FLAGS)

        assert result.exit_code == 0
        rows = {dep["name"]: dep for dep in data["dependencies"]}
        assert set(rows) == {"forked-dep", "real"}
        assert rows["forked-dep"]["origin"] == "git+https://git.example.org/forked.git"
        assert _requests_mentioning("forked-dep") == []


# ------------------------------------------------- every workspace filter


def _mix(app: str, deps: str) -> str:
    return (
        f"defmodule {app.title()}.MixProject do\n  use Mix.Project\n\n"
        f'  def project do\n    [app: :{app}, version: "0.1.0", deps: deps()]\n  end\n\n'
        f"  defp deps do\n    [{deps}]\n  end\nend\n"
    )


def _pom(artifact: str, body: str = "") -> str:
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        f"<groupId>com.example</groupId><artifactId>{artifact}</artifactId>"
        f"<version>1.0</version>{body}</project>"
    )


# ecosystem -> files of a tree in which one package names another in another case
_MEMBER_IN_ANOTHER_CASE: dict[str, dict[str, str]] = {
    "dotnet": {
        "MyLib/MyLib.csproj": _csproj(),
        "App/App.csproj": _csproj(("mylib", "1.0.0")),
    },
    "rust": {
        "core-lib/Cargo.toml": _cargo("core-lib"),
        "app/Cargo.toml": _cargo("app", 'Core-Lib = "0.1"\n'),
    },
    "php": {
        "composer.json": json.dumps(
            {
                "repositories": [{"type": "path", "url": "packages/*"}],
                "require": {"Acme/Core": "*"},
            }
        ),
        "packages/core/composer.json": json.dumps({"name": "acme/core"}),
    },
    "hex": {
        "apps/core_lib/mix.exs": _mix("core_lib", ""),
        "apps/web/mix.exs": _mix("web", '{:Core_Lib, "~> 1.0"}'),
    },
    "r": {
        "corelib/DESCRIPTION": "Package: corelib\nVersion: 0.1\n",
        "app/DESCRIPTION": "Package: app\nVersion: 0.1\nImports: CoreLib\n",
    },
    "python": {
        "libs/core/pyproject.toml": '[project]\nname = "core-lib"\nversion = "0.1.0"\n',
        "app/pyproject.toml": (
            '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["Core_Lib"]\n'
        ),
    },
    "npm": {
        "packages/core/package.json": json.dumps({"name": "core-lib"}),
        "packages/app/package.json": json.dumps(
            {"name": "app", "dependencies": {"Core-Lib": "1.0.0"}}
        ),
    },
    "ruby": {
        "core_lib.gemspec": 'Gem::Specification.new do |spec|\n  spec.name = "core_lib"\nend\n',
        "Gemfile": 'source "https://rubygems.org"\ngem "Core_Lib"\n',
    },
    "go": {
        "core/go.mod": "module example.com/Core\n\ngo 1.22\n",
        "app/go.mod": "module example.com/app\n\ngo 1.22\n\nrequire example.com/core v1.0.0\n",
    },
    "java": {
        "pom.xml": _pom(
            "parent",
            "<packaging>pom</packaging><modules><module>core</module>"
            "<module>app</module></modules>",
        ),
        "core/pom.xml": _pom("core"),
        "app/pom.xml": _pom(
            "app",
            "<dependencies><dependency><groupId>com.example</groupId>"
            "<artifactId>Core</artifactId><version>1.0</version></dependency></dependencies>",
        ),
    },
}

_FOLDING = ("dotnet", "rust", "php", "hex", "r", "python")
_EXACT = ("npm", "ruby", "go", "java")


def _discover(root: Path, ecosystem: str) -> tuple[list[str], int]:
    for relative, content in _MEMBER_IN_ANOTHER_CASE[ecosystem].items():
        _write(root / relative, content)
    deps, filtered = discover_all_dependencies(root)
    return [dep.name for dep in deps], filtered[ecosystem]


class TestMemberNamedInAnotherCase:
    def test_every_ecosystem_is_covered(self):
        assert {*_FOLDING, *_EXACT} == set(_MEMBER_IN_ANOTHER_CASE)

    @pytest.mark.parametrize("ecosystem", _FOLDING)
    def test_it_is_the_member_where_the_registry_folds_case(self, tmp_path, ecosystem):
        assert _discover(tmp_path, ecosystem) == ([], 1)

    @pytest.mark.parametrize("ecosystem", _EXACT)
    def test_it_is_another_package_where_case_is_part_of_the_name(self, tmp_path, ecosystem):
        names, filtered = _discover(tmp_path, ecosystem)

        assert len(names) == 1
        assert filtered == 0

    @pytest.mark.parametrize("ecosystem", _EXACT)
    def test_member_named_exactly_is_filtered_in_those_too(self, tmp_path, ecosystem):
        files = _MEMBER_IN_ANOTHER_CASE[ecosystem]
        # The same tree with the reference spelled as the member is.
        exact = {
            "npm": ("Core-Lib", "core-lib"),
            "ruby": ("Core_Lib", "core_lib"),
            "go": ("example.com/core v1.0.0", "example.com/Core v1.0.0"),
            "java": ("<artifactId>Core</artifactId>", "<artifactId>core</artifactId>"),
        }[ecosystem]
        for relative, content in files.items():
            _write(tmp_path / relative, content.replace(*exact))

        deps, filtered = discover_all_dependencies(tmp_path)

        assert deps == []
        assert filtered[ecosystem] == 1


class TestInitReviewFileSkipsTheMember:
    @respx.mock
    def test_live_scan_makes_no_request_for_a_member(self, tmp_path):
        _write(tmp_path / "MyLib" / "MyLib.csproj", _csproj())
        _write(tmp_path / "App" / "App.csproj", _csproj(("mylib", "1.0.0")))
        _refuse_everything_else()

        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert _excluded(".NET") in result.output
        assert respx.calls.call_count == 0
