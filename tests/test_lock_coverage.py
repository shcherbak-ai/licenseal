"""A lockfile covers a requirement only when it holds a version that satisfies it.

A lockfile that merely names a package does not cover every manifest that
declares it. A sub-project that pins another version, and a manifest its own
lockfile has fallen behind, are resolved through the registry like a manifest
with no lockfile: the declared version is reported under its manifest, as an
estimate where the manifest does not pin it exactly, and the manifest is
recorded as lacking a lockfile. A lockfile row is a direct dependency, with a
manifest as its source, only at a version that manifest's declaration admits.

An unresolved requirement is likewise not the same thing as a resolved row of
the same name. It is dropped as a duplicate only when it is a transitive
requirement that the resolved version satisfies.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import collect_read_diagnostics
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.http import RegistryCache
from licenseal.resolvers.version_selection import is_prerelease
from licenseal.transitive import (
    _declaration_for,
    _declarations,
    _dedupe,
    _meets,
    _uncovered_by,
    _with_declared_source,
    resolve_transitive,
)
from tests._helpers import _check_json, _file_diagnostics, _write

_MISSING = (
    "declares dependencies that no lockfile covers; their versions and "
    "transitive dependencies are estimated from the registry"
)


def _refuse_everything_else() -> None:
    """Answer 404 to any request no earlier route matched, so that it is on record."""
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


def _scan(
    project: Path, *, include_dev: bool = True
) -> tuple[dict[tuple[str, str], Dependency], list[str]]:
    """Discover and expand ``project`` against the mocked registries.

    Returns the rows by ``(name, version constraint)`` and the manifests
    recorded as lacking a lockfile, project-relative.
    """
    cache = RegistryCache()
    with collect_read_diagnostics() as diags, httpx.Client() as client:
        direct, _ = discover_all_dependencies(project)
        deps = resolve_transitive(
            direct,
            project,
            include_dev=include_dev,
            max_depth=50,
            client=client,
            fetcher=cache.fetch,
            pom_fetcher=cache.fetch_text,
        )
    rows = {(d.name, d.version_constraint): d for d in deps}
    assert len(rows) == len(deps)
    missing = sorted({d.path.relative_to(project).as_posix() for d in diags if d.missing_lockfile})
    return rows, missing


def _shape(rows: dict[tuple[str, str], Dependency]) -> dict[tuple[str, str], tuple]:
    """Each row as ``(depth, source, estimated, ancestors)``."""
    return {
        key: (d.depth, d.source, d.version_estimated, d.direct_ancestors) for key, d in rows.items()
    }


# ---------------------------------------------------------------- registries


def _mock_pypi(name: str, versions: dict[str, list[str]], license_id: str = "MIT") -> None:
    """Publish ``name`` on PyPI: ``{version: requires_dist}``."""
    respx.get(f"https://pypi.org/pypi/{name}/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {"name": name, "version": list(versions)[-1], "classifiers": []},
                "releases": {version: [] for version in versions},
            },
        )
    )
    for version, requires in versions.items():
        respx.get(f"https://pypi.org/pypi/{name}/{version}/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "name": name,
                        "version": version,
                        "license": license_id,
                        "classifiers": [],
                        "requires_dist": requires,
                    }
                },
            )
        )


def _mock_npm(name: str, versions: dict[str, dict[str, str]], license_id: str = "MIT") -> None:
    """Publish ``name`` on the npm registry: ``{version: dependencies}``."""
    payloads = {
        version: {
            "name": name,
            "version": version,
            "license": license_id,
            "dependencies": dependencies,
        }
        for version, dependencies in versions.items()
    }
    respx.get(f"https://registry.npmjs.org/{name}").mock(
        return_value=httpx.Response(
            200, json={"dist-tags": {"latest": list(versions)[-1]}, "versions": payloads}
        )
    )
    for version, payload in payloads.items():
        respx.get(f"https://registry.npmjs.org/{name}/{version}").mock(
            return_value=httpx.Response(200, json=payload)
        )


def _uv_lock(root: str, packages: dict[str, tuple[str, list[str]]]) -> str:
    """uv.lock text: the project ``root`` and ``{name: (version, dependency names)}``."""
    blocks = [
        f'[[package]]\nname = "{root}"\nversion = "0.1.0"\nsource = {{ virtual = "." }}\n'
        "dependencies = ["
        + ", ".join(f'{{ name = "{name}" }}' for name in packages[root][1])
        + "]\n"
    ]
    for name, (version, dependencies) in packages.items():
        if name == root:
            continue
        block = (
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )
        if dependencies:
            block += (
                "dependencies = ["
                + ", ".join(f'{{ name = "{dep}" }}' for dep in dependencies)
                + "]\n"
            )
        blocks.append(block)
    return "version = 1\n\n" + "\n".join(blocks)


def _pyproject(name: str, *dependencies: str) -> str:
    listed = ", ".join(f'"{dep}"' for dep in dependencies)
    return f'[project]\nname = "{name}"\nversion = "0.1.0"\ndependencies = [{listed}]\n'


def _package_lock(root: dict, packages: dict[str, tuple[str, dict[str, str]]]) -> str:
    """package-lock.json text: ``{node_modules path: (version, dependencies)}``."""
    entries: dict[str, dict] = {"": root}
    for path, (version, dependencies) in packages.items():
        name = path.rsplit("node_modules/", 1)[-1]
        entry: dict = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "integrity": "sha512-h",
        }
        if dependencies:
            entry["dependencies"] = dependencies
        entries[path] = entry
    return json.dumps({"name": "root", "lockfileVersion": 3, "packages": entries})


# ------------------------------------------------------------ a stale lockfile


class TestStaleLockfile:
    def _project(self, root: Path, requirement: str) -> None:
        _write(root / "pyproject.toml", _pyproject("app", requirement))
        _write(
            root / "uv.lock",
            _uv_lock(
                "app",
                {
                    "app": ("0.1.0", ["shared"]),
                    "shared": ("1.0.0", ["old-child"]),
                    "old-child": ("1.0.0", []),
                },
            ),
        )

    @respx.mock
    def test_manifest_ahead_of_its_lockfile_is_resolved_from_the_registry(self, tmp_path):
        self._project(tmp_path, "shared>=2.0")
        _mock_pypi("shared", {"1.0.0": ["old-child"], "2.0.0": [], "2.1.0": ["new-child"]})
        _mock_pypi("new-child", {"1.0.0": []})
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        assert _shape(rows) == {
            # What the manifest asks for, picked from the registry.
            ("shared", "==2.1.0"): (0, "pyproject.toml", True, ()),
            ("new-child", "==1.0.0"): (1, "", True, ("shared",)),
            # What the lockfile still holds: not the declared dependency.
            ("shared", "==1.0.0"): (1, "", False, ()),
            ("old-child", "==1.0.0"): (1, "", False, ("shared",)),
        }
        assert missing == ["pyproject.toml"]

    @respx.mock
    def test_stale_lockfile_is_a_gap_unless_accepted(self, tmp_path):
        self._project(tmp_path, "shared>=2.0")
        _mock_pypi("shared", {"1.0.0": [], "2.0.0": [], "2.1.0": ["new-child"]})
        _mock_pypi("new-child", {"1.0.0": []})
        _mock_pypi("old-child", {"1.0.0": []})
        _refuse_everything_else()

        strict, data = _check_json(tmp_path)
        assert strict.exit_code == 1
        assert data["summary"]["gaps"] == 1
        assert _file_diagnostics(data) == [
            {"path": "pyproject.toml", "reason": _MISSING, "severity": "gap"}
        ]
        versions = {(d["name"], d["resolved_version"]): d for d in data["dependencies"]}
        assert versions["shared", "2.1.0"]["estimated"] == ["version"]
        assert versions["shared", "2.1.0"]["source"] == "pyproject.toml"
        assert versions["shared", "1.0.0"]["depth"] == 1

        accepted, data = _check_json(tmp_path, "--no-require-lockfile")
        assert accepted.exit_code == 0
        assert data["summary"]["gaps"] == 0

    @respx.mock
    def test_lockfile_that_satisfies_its_manifest_is_the_whole_answer(self, tmp_path):
        self._project(tmp_path, "shared>=1.0,<2")
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        assert _shape(rows) == {
            ("shared", "==1.0.0"): (0, "pyproject.toml", False, ()),
            ("old-child", "==1.0.0"): (1, "", False, ("shared",)),
        }
        assert missing == []
        assert respx.calls.call_count == 0

    @respx.mock
    @pytest.mark.parametrize(
        "requirement",
        [
            # Not a version constraint the grammar reads: nothing can be told.
            "shared @ https://files.example.org/shared.whl",
            # No constraint at all.
            "shared",
        ],
    )
    def test_constraint_that_cannot_be_compared_is_covered(self, tmp_path, requirement):
        self._project(tmp_path, requirement)
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        assert ("old-child", "==1.0.0") in rows
        assert missing == []
        assert respx.calls.call_count == 0

    @respx.mock
    def test_locked_prerelease_is_the_resolver_s_call(self, tmp_path):
        # ``>=1.0`` admits no prerelease by itself; a resolver told to allow
        # them does, and the lockfile shows that it did.
        _write(tmp_path / "pyproject.toml", _pyproject("app", "shared>=1.0"))
        _write(
            tmp_path / "uv.lock",
            _uv_lock("app", {"app": ("0.1.0", ["shared"]), "shared": ("2.0.0rc1", [])}),
        )
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        assert _shape(rows) == {("shared", "==2.0.0rc1"): (0, "pyproject.toml", False, ())}
        assert missing == []
        assert respx.calls.call_count == 0


# ------------------------------- a sub-project lockfile beside an unlocked root


class TestSubProjectLockfile:
    def _project(self, root: Path) -> None:
        library = {"name": "lib", "dependencies": {"ui": "^18.0.0"}}
        _write(root / "package.json", json.dumps(library))
        website = {"name": "website", "dependencies": {"ui": "^17.0.0"}}
        _write(root / "website" / "package.json", json.dumps(website))
        _write(
            root / "website" / "package-lock.json",
            _package_lock(website, {"node_modules/ui": ("17.0.2", {})}),
        )
        _mock_npm("ui", {"17.0.2": {}, "18.3.1": {"scheduler": "^0.23.0"}})
        _mock_npm("scheduler", {"0.23.2": {}}, "GPL-3.0-only")
        _refuse_everything_else()

    @respx.mock
    def test_root_requirement_is_not_covered_by_the_sub_project_lock(self, tmp_path):
        self._project(tmp_path)

        rows, missing = _scan(tmp_path)

        assert _shape(rows) == {
            ("ui", "==17.0.2"): (0, "website/package.json", False, ()),
            ("ui", "==18.3.1"): (0, "package.json", True, ()),
            ("scheduler", "==0.23.2"): (1, "", True, ("ui",)),
        }
        assert missing == ["package.json"]

    @respx.mock
    def test_what_the_root_pulls_in_is_judged(self, tmp_path):
        self._project(tmp_path)

        result, data = _check_json(tmp_path, "--no-require-lockfile")

        licenses = {(d["name"], d["resolved_version"]): d["license"] for d in data["dependencies"]}
        assert licenses == {
            ("ui", "17.0.2"): "MIT",
            ("ui", "18.3.1"): "MIT",
            ("scheduler", "0.23.2"): "GPL-3.0-only",
        }
        assert result.exit_code == 1


# ----------------------------------- disjoint constraints across sub-projects


class TestDisjointConstraints:
    @respx.mock
    def test_locked_and_unlocked_sub_projects(self, tmp_path):
        _write(tmp_path / "svc-a" / "pyproject.toml", _pyproject("svc-a", "shared>=1,<2"))
        _write(
            tmp_path / "svc-a" / "uv.lock",
            _uv_lock("svc-a", {"svc-a": ("0.1.0", ["shared"]), "shared": ("1.5.0", [])}),
        )
        _write(tmp_path / "svc-b" / "requirements.txt", "shared>=2,<3\n")
        _mock_pypi("shared", {"1.5.0": [], "2.4.0": [], "3.0.0": []})
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        assert _shape(rows) == {
            ("shared", "==1.5.0"): (0, "svc-a/pyproject.toml", False, ()),
            ("shared", "==2.4.0"): (0, "svc-b/requirements.txt", True, ()),
        }
        assert missing == ["svc-b/requirements.txt"]

    @respx.mock
    def test_root_lock_holds_the_package_only_as_a_transitive(self, tmp_path):
        _write(tmp_path / "pyproject.toml", _pyproject("app", "host"))
        _write(
            tmp_path / "uv.lock",
            _uv_lock(
                "app",
                {
                    "app": ("0.1.0", ["host"]),
                    "host": ("1.0.0", ["shared"]),
                    "shared": ("1.0.0", []),
                },
            ),
        )
        _write(tmp_path / "service" / "pyproject.toml", _pyproject("service", "shared==2.0.0"))
        _mock_pypi("shared", {"1.0.0": [], "2.0.0": ["extra-child"]})
        _mock_pypi("extra-child", {"1.0.0": []})
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        shape = _shape(rows)
        assert shape["host", "==1.0.0"] == (0, "pyproject.toml", False, ())
        # The lockfile's 1.0.0 is not what the service declares.
        assert shape["shared", "==1.0.0"] == (1, "", False, ())
        # The pin is exact, so the version is not an estimate; its graph is.
        assert shape["shared", "==2.0.0"] == (0, "service/pyproject.toml", False, ())
        assert shape["extra-child", "==1.0.0"] == (1, "", True, ("shared",))
        assert len(shape) == 4
        assert missing == ["service/pyproject.toml"]

    @respx.mock
    def test_two_versions_in_one_lock_one_of_them_declared(self, tmp_path):
        root = {"name": "root", "dependencies": {"shared": "^2.0.0", "host": "1.0.0"}}
        _write(tmp_path / "package.json", json.dumps(root))
        _write(
            tmp_path / "package-lock.json",
            _package_lock(
                root,
                {
                    "node_modules/shared": ("2.1.0", {}),
                    "node_modules/host": ("1.0.0", {"shared": "^1.0.0"}),
                    "node_modules/host/node_modules/shared": ("1.4.0", {}),
                },
            ),
        )
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        assert _shape(rows) == {
            ("shared", "==2.1.0"): (0, "package.json", False, ()),
            ("host", "==1.0.0"): (0, "package.json", False, ()),
            # The copy nested under ``host`` is not the declared dependency.
            ("shared", "==1.4.0"): (1, "", False, ()),
        }
        assert missing == []
        assert respx.calls.call_count == 0


# ------------------------------------------------------- every lockfile format


_GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    shared (1.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  shared

BUNDLED WITH
   2.5.0
"""

# ecosystem -> (files for a declaration of ``shared`` with a constraint, the
# manifest that declares it, and whether an unmet declaration is recorded as
# lacking a lockfile). Every lockfile holds ``shared`` 1.0.0.
_LOCKED_AT_1_0_0: dict[str, tuple] = {
    "python-poetry": (
        lambda c: {
            "pyproject.toml": _pyproject("app", f"shared{c}"),
            "poetry.lock": (
                '[[package]]\nname = "shared"\nversion = "1.0.0"\n\n'
                '[metadata]\nlock-version = "2.0"\n'
            ),
        },
        "pyproject.toml",
        ("==1.0.0", ">=2.0"),
    ),
    "rust": (
        lambda c: {
            "Cargo.toml": (
                f'[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nshared = "{c}"\n'
            ),
            "Cargo.lock": (
                'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n'
                'dependencies = ["shared"]\n\n'
                '[[package]]\nname = "shared"\nversion = "1.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            ),
        },
        "Cargo.toml",
        ("1.0", "2.0"),
    ),
    "php": (
        lambda c: {
            "composer.json": json.dumps({"require": {"acme/shared": c}}),
            "composer.lock": json.dumps(
                {
                    "packages": [
                        {
                            "name": "acme/shared",
                            "version": "1.0.0",
                            "license": ["MIT"],
                            "source": {"type": "git", "url": "https://git.example.org/s.git"},
                        }
                    ],
                    "packages-dev": [],
                }
            ),
        },
        "composer.json",
        ("^1.0", "^2.0"),
    ),
    "ruby": (
        lambda c: {
            "Gemfile": f'source "https://rubygems.org"\ngem "shared", "{c}"\n',
            "Gemfile.lock": _GEMFILE_LOCK,
        },
        "Gemfile",
        ("~> 1.0", "~> 2.0"),
    ),
    "hex": (
        lambda c: {
            "mix.exs": (
                "defmodule App.MixProject do\n  use Mix.Project\n\n"
                '  def project do\n    [app: :app, version: "0.1.0", deps: deps()]\n  end\n\n'
                f'  defp deps do\n    [{{:shared, "{c}"}}]\n  end\nend\n'
            ),
            "mix.lock": (
                '%{\n  "shared": {:hex, :shared, "1.0.0", "h", [:mix], [], "hexpm", "h"},\n}\n'
            ),
        },
        "mix.exs",
        ("~> 1.0", "~> 2.0"),
    ),
    "r": (
        lambda c: {
            "DESCRIPTION": f"Package: app\nVersion: 0.1\nImports: shared ({c})\n",
            "renv.lock": json.dumps(
                {
                    "R": {"Version": "4.3.0"},
                    "Packages": {
                        "shared": {
                            "Package": "shared",
                            "Version": "1.0.0",
                            "Source": "Repository",
                            "Repository": "CRAN",
                        }
                    },
                }
            ),
        },
        "DESCRIPTION",
        (">= 1.0.0", ">= 2.0.0"),
    ),
    "dotnet-nuget": (
        lambda c: {
            "App.csproj": (
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
                f'<PackageReference Include="shared" Version="{c}" />'
                "</ItemGroup></Project>"
            ),
            "packages.lock.json": json.dumps(
                {
                    "version": 1,
                    "dependencies": {"net8.0": {"shared": {"type": "Direct", "resolved": "1.0.0"}}},
                }
            ),
        },
        "App.csproj",
        ("1.0.0", "2.0.0"),
    ),
    "dotnet-paket": (
        lambda c: {
            "paket.dependencies": f"source https://api.nuget.org/v3/index.json\nnuget shared {c}\n",
            "paket.lock": (
                "NUGET\n  remote: https://api.nuget.org/v3/index.json\n    shared (1.0.0)\n"
            ),
        },
        "paket.dependencies",
        ("1.0.0", "2.0.0"),
    ),
    "java-gradle": (
        lambda c: {
            "build.gradle": f"dependencies {{\n    implementation 'org.example:shared:{c}'\n}}\n",
            "gradle.lockfile": "org.example:shared:1.0.0=runtimeClasspath\nempty=\n",
        },
        "build.gradle",
        ("1.0.0", "2.0.0"),
    ),
}

_NAME = {"php": "acme/shared", "java-gradle": "org.example:shared"}

# Lockfiles that list packages with no direct / transitive distinction: a
# row whose declaration it does not satisfy stays as the lockfile lists it.
_FLAT = {"dotnet-paket": "paket.lock", "java-gradle": ""}


def _write_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        (root / relative).write_text(content, encoding="utf-8", newline="\n")


class TestEveryLockfileFormat:
    @respx.mock
    @pytest.mark.parametrize("layout", _LOCKED_AT_1_0_0)
    def test_declaration_the_lock_satisfies_is_covered(self, tmp_path, layout):
        files, manifest, (met, _unmet) = _LOCKED_AT_1_0_0[layout]
        _write_files(tmp_path, files(met))
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        (row,) = rows.values()
        assert (row.name, row.depth, row.source) == (_NAME.get(layout, "shared"), 0, manifest)
        assert row.version_constraint.removeprefix("==") == "1.0.0"
        assert not row.version_estimated
        assert missing == []
        assert respx.calls.call_count == 0

    @respx.mock
    @pytest.mark.parametrize("layout", _LOCKED_AT_1_0_0)
    def test_declaration_the_lock_does_not_satisfy_is_resolved_on_its_own(self, tmp_path, layout):
        files, manifest, (_met, unmet) = _LOCKED_AT_1_0_0[layout]
        _write_files(tmp_path, files(unmet))
        # No registry answers: the declaration comes back as it was written.
        _refuse_everything_else()

        rows, missing = _scan(tmp_path)

        name = _NAME.get(layout, "shared")
        locked = next(d for d in rows.values() if d.version_constraint.endswith("1.0.0"))
        declared = next(d for d in rows.values() if d is not locked)
        assert len(rows) == 2
        assert (locked.name, declared.name) == (name, name)
        # The lockfile's row is no longer reported under the manifest.
        if layout in _FLAT:
            assert (locked.depth, locked.source) == (0, _FLAT[layout])
        else:
            assert (locked.depth, locked.source, locked.direct_ancestors) == (1, "", ())
        assert (declared.depth, declared.source) == (0, manifest)
        assert missing == [manifest]
        assert respx.calls.call_count > 0


class TestDotnetLockedAndWalkedRows:
    """A NuGet lockfile row and a ``.nuspec`` walk row of one package, in one scan.

    One project has a lockfile; another references a package no lockfile
    holds, whose ``.nuspec`` depends on a package the lockfile does hold.
    """

    def _project(self, root: Path, walked_requires: str) -> None:
        def csproj(package: str) -> str:
            return (
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
                f'<PackageReference Include="{package}" Version="1.0.0" />'
                "</ItemGroup></Project>"
            )

        _write(root / "App" / "App.csproj", csproj("Host.Lib"))
        _write(
            root / "App" / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "Host.Lib": {
                                "type": "Direct",
                                "resolved": "1.0.0",
                                "dependencies": {"Shared.Lib": "1.0.0"},
                            },
                            "Shared.Lib": {"type": "Transitive", "resolved": "1.0.0"},
                        }
                    },
                }
            ),
        )
        _write(root / "Tool" / "Tool.csproj", csproj("Walked.Lib"))
        for package, version, dependency in (
            ("Walked.Lib", "1.0.0", f'<dependency id="Shared.Lib" version="{walked_requires}" />'),
            ("Shared.Lib", "1.0.0", ""),
            ("Shared.Lib", "2.0.0", ""),
        ):
            lowered = package.lower()
            respx.get(
                f"https://api.nuget.org/v3-flatcontainer/{lowered}/{version}/{lowered}.nuspec"
            ).mock(
                return_value=httpx.Response(
                    200,
                    text=(
                        f"<package><metadata><id>{package}</id><version>{version}</version>"
                        f"<dependencies>{dependency}</dependencies></metadata></package>"
                    ),
                )
            )
        _refuse_everything_else()

    @respx.mock
    def test_same_version_is_one_row_that_the_lockfile_fixes(self, tmp_path):
        self._project(tmp_path, "1.0.0")

        rows, missing = _scan(tmp_path)

        assert _shape(rows) == {
            ("Host.Lib", "==1.0.0"): (0, "App/App.csproj", False, ()),
            ("Walked.Lib", "==1.0.0"): (0, "Tool/Tool.csproj", False, ()),
            # Reached through both: the lockfile's entry and the walk's node.
            ("Shared.Lib", "==1.0.0"): (1, "", False, ("Host.Lib", "Walked.Lib")),
        }
        assert missing == ["Tool/Tool.csproj"]

    @respx.mock
    def test_locked_version_is_kept_beside_the_version_the_walk_reaches(self, tmp_path):
        self._project(tmp_path, "2.0.0")

        rows, _ = _scan(tmp_path)

        shape = _shape(rows)
        assert shape["Shared.Lib", "==1.0.0"] == (1, "", False, ("Host.Lib",))
        assert shape["Shared.Lib", "==2.0.0"] == (1, "", True, ("Walked.Lib",))
        assert len(shape) == 4


# ---------------------------------------------------- unresolved requirements


def _dep(
    constraint: str,
    *,
    depth: int = 1,
    ancestors: tuple[str, ...] = (),
    ecosystem: Ecosystem = Ecosystem.PYTHON,
    origin: str = "",
    name: str = "shared",
) -> Dependency:
    return Dependency(
        name=name,
        version_constraint=constraint,
        ecosystem=ecosystem,
        depth=depth,
        direct_ancestors=ancestors,
        origin=origin,
    )


class TestPhantomRows:
    def test_transitive_the_resolved_version_satisfies_is_dropped(self):
        resolved = _dep("==1.5.0", ancestors=("a",))
        unresolved = _dep(">=1,<2", ancestors=("b",))

        (kept,) = _dedupe([resolved, unresolved])

        assert kept.version_constraint == "==1.5.0"
        assert kept.direct_ancestors == ("a", "b")

    def test_transitive_the_resolved_version_does_not_satisfy_is_kept(self):
        resolved = _dep("==1.0.0", ancestors=("a",))
        unresolved = _dep(">=2,<3", ancestors=("b",))

        rows = _dedupe([resolved, unresolved])

        assert [(d.version_constraint, d.direct_ancestors) for d in rows] == [
            ("==1.0.0", ("a",)),
            (">=2,<3", ("b",)),
        ]

    def test_ancestry_goes_to_the_versions_that_satisfy(self):
        first = _dep("==1.0.0", ancestors=("a",))
        second = _dep("==2.5.0", ancestors=("b",))
        unresolved = _dep(">=2,<3", ancestors=("c",))

        rows = _dedupe([first, second, unresolved])

        assert [(d.version_constraint, d.direct_ancestors) for d in rows] == [
            ("==1.0.0", ("a",)),
            ("==2.5.0", ("b", "c")),
        ]

    def test_spec_that_cannot_be_compared_is_dropped(self):
        resolved = _dep("==5.2.1", ancestors=("a",), ecosystem=Ecosystem.NPM)
        unresolved = _dep("next", ancestors=("b",), ecosystem=Ecosystem.NPM)

        (kept,) = _dedupe([resolved, unresolved])

        assert kept.direct_ancestors == ("a", "b")

    def test_direct_dependency_is_never_dropped(self):
        resolved = _dep("==1.5.0", ancestors=("a",))
        direct = _dep(">=1,<2", depth=0)

        rows = _dedupe([resolved, direct])

        assert [(d.version_constraint, d.depth) for d in rows] == [("==1.5.0", 1), (">=1,<2", 0)]

    def test_off_registry_row_is_never_dropped_and_drops_nothing(self):
        git = _dep("", depth=0, origin="git+https://git.example.org/shared.git@v9")
        resolved = _dep("==1.2.3", ancestors=("a",))
        pinned_git = _dep("==9.0.0", origin="git+https://git.example.org/shared.git@abc")
        unresolved = _dep(">=9", ancestors=("b",))

        rows = _dedupe([git, resolved, pinned_git, unresolved])

        # The unresolved requirement is not satisfied by the registry row, and
        # the git row at 9.0.0 is not the registry package.
        assert len(rows) == 4


class TestUnresolvedRowsInAScan:
    @respx.mock
    def test_git_dependency_beside_a_registry_transitive_of_the_same_name(self, tmp_path):
        _write(
            tmp_path / "package.json",
            json.dumps(
                {
                    "name": "app",
                    "dependencies": {"shared": "github:someone/fork#v9", "host": "1.0.0"},
                }
            ),
        )
        _mock_npm("host", {"1.0.0": {"shared": "^1.2.0"}})
        _mock_npm("shared", {"1.2.3": {}})
        _refuse_everything_else()

        result, data = _check_json(tmp_path, "--no-require-lockfile", "--no-strict")

        rows = {(d["name"], d["resolved_version"]): d for d in data["dependencies"]}
        assert set(rows) == {("shared", ""), ("shared", "1.2.3"), ("host", "1.0.0")}
        fork = rows["shared", ""]
        assert fork["origin"] == "git+https://github.com/someone/fork@v9"
        assert (fork["depth"], fork["source"], fork["license"]) == (0, "package.json", "UNKNOWN")
        assert rows["shared", "1.2.3"]["depth"] == 1
        assert rows["shared", "1.2.3"]["direct_ancestors"] == ["host"]
        assert result.exit_code == 0

    @respx.mock
    def test_direct_dependency_with_an_undefined_version_beside_a_resolved_transitive(
        self, tmp_path
    ):
        def dependency(artifact: str, version: str) -> str:
            return (
                f"<dependency><groupId>org.example</groupId><artifactId>{artifact}</artifactId>"
                f"<version>{version}</version></dependency>"
            )

        _write(
            tmp_path / "pom.xml",
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<groupId>com.example</groupId><artifactId>app</artifactId><version>1</version>"
            f"<dependencies>{dependency('lib', '${undefined.version}')}"
            f"{dependency('host', '1.0')}</dependencies></project>",
        )

        def node(name: str, version: str, relation: str) -> dict:
            return {
                "versionKey": {"system": "MAVEN", "name": name, "version": version},
                "relation": relation,
            }

        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/org.example%3Ahost/versions/1.0"
            ":dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        node("org.example:host", "1.0", "SELF"),
                        node("org.example:lib", "2.0", "DIRECT"),
                    ],
                    "edges": [{"fromNode": 0, "toNode": 1}],
                },
            )
        )
        _refuse_everything_else()

        rows, _ = _scan(tmp_path)

        # The declaration that did not resolve is still a row: the version
        # another dependency pulls in is not the one this pom.xml asks for.
        assert _shape(rows) == {
            ("org.example:lib", "${undefined.version}"): (0, "pom.xml", True, ()),
            ("org.example:host", "==1.0"): (0, "pom.xml", False, ()),
            ("org.example:lib", "==2.0"): (1, "", True, ("org.example:host",)),
        }

    @respx.mock
    def test_requirement_no_resolved_version_satisfies_stays_unknown(self, tmp_path):
        _write(tmp_path / "requirements.txt", "first==1.0.0\nsecond==1.0.0\n")
        _mock_pypi("first", {"1.0.0": ["shared==1.0.0"]})
        _mock_pypi("second", {"1.0.0": ["shared>=2,<3"]})
        # The pin needs no version list; the range does, and gets none.
        respx.get("https://pypi.org/pypi/shared/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "name": "shared",
                        "version": "1.0.0",
                        "license": "MIT",
                        "classifiers": [],
                        "requires_dist": [],
                    }
                },
            )
        )
        _refuse_everything_else()

        rows, _ = _scan(tmp_path)

        assert _shape(rows) == {
            ("first", "==1.0.0"): (0, "requirements.txt", False, ()),
            ("second", "==1.0.0"): (0, "requirements.txt", False, ()),
            ("shared", "==1.0.0"): (1, "", True, ("first",)),
            ("shared", "<3,>=2"): (1, "", True, ("second",)),
        }

        strict, data = _check_json(tmp_path, "--no-require-lockfile")
        assert strict.exit_code == 1
        unknown = [d for d in data["dependencies"] if d["verdict"] == "unknown"]
        assert [(d["name"], d["resolved_version"]) for d in unknown] == [("shared", "")]

    @respx.mock
    def test_requirement_the_resolved_version_satisfies_is_one_row(self, tmp_path):
        _write(tmp_path / "requirements.txt", "first==1.0.0\nsecond==1.0.0\n")
        _mock_pypi("first", {"1.0.0": ["shared==1.0.0"]})
        _mock_pypi("second", {"1.0.0": ["shared>=1"]})
        respx.get("https://pypi.org/pypi/shared/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "name": "shared",
                        "version": "1.0.0",
                        "license": "MIT",
                        "classifiers": [],
                        "requires_dist": [],
                    }
                },
            )
        )
        _refuse_everything_else()

        rows, _ = _scan(tmp_path)

        assert _shape(rows)["shared", "==1.0.0"] == (1, "", True, ("first", "second"))
        assert len(rows) == 3


# ------------------------------------------------------------------ the rule


class TestCoverageRule:
    @staticmethod
    def _locked(version: str, ecosystem: Ecosystem = Ecosystem.PYTHON, **kwargs) -> Dependency:
        return Dependency(name="shared", version_constraint=version, ecosystem=ecosystem, **kwargs)

    @staticmethod
    def _declared(constraint: str, ecosystem: Ecosystem = Ecosystem.PYTHON, **kwargs) -> Dependency:
        return Dependency(
            name="shared", version_constraint=constraint, ecosystem=ecosystem, source="m", **kwargs
        )

    @pytest.mark.parametrize(
        ("ecosystem", "locked", "constraint", "expected"),
        [
            (Ecosystem.PYTHON, "==2.31.0", ">=2", True),
            (Ecosystem.PYTHON, "==1.4.0", ">=2", False),
            (Ecosystem.NPM, "==17.0.2", "^18.0.0", False),
            (Ecosystem.NPM, "==18.3.1", "^18.0.0", True),
            # Bare versions, as NuGet lockfiles and go.sum hold them.
            (Ecosystem.DOTNET, "13.0.3", "13.0.1", True),
            (Ecosystem.DOTNET, "12.0.1", "13.0.1", False),
            # Nothing to compare: no constraint, an unread constraint, no version.
            (Ecosystem.PYTHON, "==1.0", "", True),
            (Ecosystem.NPM, "==1.0.0", "latest", None),
            (Ecosystem.NPM, "==1.0.0", "workspace:*", None),
            (Ecosystem.JAVA, "==1.0", "${undefined.version}", None),
            (Ecosystem.PYTHON, "", ">=2", None),
            # A prerelease the constraint does not name: the resolver's call.
            (Ecosystem.PYTHON, "==2.0.0rc1", ">=1.0", None),
            (Ecosystem.PHP, "==1.0.0-beta3", "^1.0", None),
            (Ecosystem.PYTHON, "==2.0.0rc1", ">=2.0.0rc1", True),
        ],
    )
    def test_meets(self, ecosystem, locked, constraint, expected):
        row = self._locked(locked, ecosystem)
        assert _meets(row, self._declared(constraint, ecosystem)) is expected

    def test_off_registry_declaration_is_not_compared(self):
        declared = self._declared(">=9", origin="git+https://git.example.org/shared.git")
        assert _meets(self._locked("==1.0.0"), declared) is None

    def test_is_prerelease(self):
        assert is_prerelease(Ecosystem.PYTHON, "2.0.0rc1") is True
        assert is_prerelease(Ecosystem.PYTHON, "2.0.0") is False
        assert is_prerelease(Ecosystem.NPM, "1.0.0-beta.1") is True
        assert is_prerelease(Ecosystem.NPM, "not a version") is False

    def test_uncovered_by(self):
        rows = [self._locked("==1.0.0"), self._locked("==1.5.0", depth=1)]
        met = self._declared(">=1.2,<2")
        unmet = self._declared(">=2")
        unnamed = Dependency(name="other", version_constraint="", ecosystem=Ecosystem.PYTHON)
        own = Dependency(name="own-code", version_constraint="1.0", ecosystem=Ecosystem.PYTHON)

        assert _uncovered_by(rows, [met, unmet, unnamed, own], {"own-code"}) == [unmet, unnamed]
        # Another ecosystem's row of the same name covers nothing.
        assert _uncovered_by([self._locked("==1.5.0", Ecosystem.NPM)], [met]) == [met]

    def test_declaration_for_prefers_a_met_declaration_then_an_uncomparable_one(self):
        unread = self._declared("@ branch")
        unmet = self._declared("==3.0")
        met = self._declared(">=2")
        row = self._locked("==2.5")

        assert _declaration_for(row, _declarations([unmet, unread, met])) is met
        assert _declaration_for(row, _declarations([unmet, unread])) is unread
        assert _declaration_for(row, _declarations([unmet])) is None
        assert _declaration_for(row, {}) is None

    def test_row_no_declaration_admits_is_a_transitive(self):
        unmet = self._declared("==3.0")
        row = self._locked("==2.5", direct_ancestors=("x",), group=DependencyGroup.PROD)

        demoted = _with_declared_source(row, _declarations([unmet]))
        assert (demoted.depth, demoted.source, demoted.direct_ancestors) == (1, "", ())

        # Nobody declares it: the row is the lockfile parser's own call.
        assert _with_declared_source(row, {}) is row
        # A transitive is left alone, whatever is declared.
        transitive = self._locked("==2.5", depth=1)
        assert _with_declared_source(transitive, _declarations([unmet])) is transitive
