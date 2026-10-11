"""Every version a manifest asks for is scanned.

Two manifests of one tree can require the same package at different
versions. Each requirement is a direct dependency of its own: the release it
names is resolved, its dependencies are walked, and its row carries the
manifest that declared it. Only two declarations of the same package with
the same constraint are one dependency; they keep every extra either asks
for, and ship when either does.

The rows a scan reports as production do not depend on ``--dev``.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.discovery import discover_all_dependencies
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.review import REVIEW_FILE_NAME
from licenseal.transitive import _declaration_for, _with_declared_source, resolve_transitive
from tests._helpers import _check_json, _write

_MODES = pytest.mark.parametrize("dev", ["--dev", "--no-dev"])

# The projects below have no lockfile unless a test writes one.
_ACCEPT = "--no-require-lockfile"


def _refuse_everything_else() -> None:
    """Answer 404 to any request no earlier route matched, so that it is on record."""
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


def _requested(fragment: str) -> list[str]:
    return [str(call.request.url) for call in respx.calls if fragment in str(call.request.url)]


def _rows(data: dict) -> dict[tuple[str, str], dict]:
    """The report's rows by ``(name, resolved version)``, each of them once."""
    rows = {(dep["name"], dep["resolved_version"]): dep for dep in data["dependencies"]}
    assert len(rows) == len(data["dependencies"])
    return rows


def _prod(data: dict) -> set[tuple[str, str]]:
    return {key for key, row in _rows(data).items() if row["group"] == "prod"}


def _mock_batch(licenses: dict[tuple[str, str, str], str]) -> None:
    """Answer the deps.dev batch lookup from ``{(system, name, version): SPDX id}``."""

    def batch(request: httpx.Request) -> httpx.Response:
        responses = []
        for item in json.loads(request.content)["requests"]:
            key = item["versionKey"]
            entry: dict = {"request": {"versionKey": key}}
            license_id = licenses.get((key["system"], key["name"], key["version"]))
            if license_id:
                entry["version"] = {"versionKey": key, "licenses": [license_id], "links": []}
            responses.append(entry)
        return httpx.Response(200, json={"responses": responses, "nextPageToken": ""})

    respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(side_effect=batch)


# ------------------------------------------------------------------ Python


def _mock_pypi(name: str, version: str, license_id: str, requires: list[str] | None = None) -> None:
    payload = {
        "info": {
            "name": name,
            "version": version,
            "license": license_id,
            "classifiers": [],
            "requires_dist": requires or [],
        },
        "releases": {version: []},
    }
    respx.get(f"https://pypi.org/pypi/{name}/{version}/json").mock(
        return_value=httpx.Response(200, json=payload)
    )


def _mock_pypi_project(name: str, versions: list[str]) -> None:
    """The project endpoint: the versions a range is resolved against."""
    respx.get(f"https://pypi.org/pypi/{name}/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {"name": name, "version": versions[-1], "classifiers": []},
                "releases": {version: [] for version in versions},
            },
        )
    )


def _mock_shared_on_pypi() -> None:
    """``shared`` 1.0.0 (MIT) and 2.0.0 (GPL), each with one child per extra."""
    _mock_pypi(
        "shared",
        "1.0.0",
        "MIT",
        ['first-one; extra == "first"', 'second-one; extra == "second"'],
    )
    _mock_pypi(
        "shared",
        "2.0.0",
        "GPL-3.0-only",
        ['first-two; extra == "first"', 'second-two; extra == "second"'],
    )
    for child in ("first-one", "second-one", "first-two", "second-two"):
        _mock_pypi(child, "1.0.0", "MIT")
        _mock_pypi_project(child, ["1.0.0"])


class TestRequirementsFiles:
    @respx.mock
    @_MODES
    def test_two_files_pinning_different_versions(self, tmp_path, dev):
        _write(tmp_path / "svc-a" / "requirements.txt", "shared[first]==1.0.0\n")
        _write(tmp_path / "svc-b" / "requirements.txt", "shared[second]==2.0.0\n")
        _mock_shared_on_pypi()
        _refuse_everything_else()

        result, data = _check_json(tmp_path, dev, _ACCEPT)

        rows = _rows(data)
        # Each release with the extra its own manifest asks for, and no other.
        assert set(rows) == {
            ("shared", "1.0.0"),
            ("shared", "2.0.0"),
            ("first-one", "1.0.0"),
            ("second-two", "1.0.0"),
        }
        assert rows["shared", "1.0.0"]["source"] == "svc-a/requirements.txt"
        assert rows["shared", "1.0.0"]["license"] == "MIT"
        assert rows["shared", "2.0.0"]["source"] == "svc-b/requirements.txt"
        assert rows["shared", "2.0.0"]["license"] == "GPL-3.0-only"
        assert {row["depth"] for key, row in rows.items() if key[0] == "shared"} == {0}
        assert {row["estimated"] == [] for key, row in rows.items() if key[0] == "shared"} == {True}
        # The second release is a violation the scan used to miss.
        assert result.exit_code == 1
        assert rows["shared", "2.0.0"]["verdict"] == "incompatible"

    @respx.mock
    @_MODES
    def test_same_pin_in_two_files_keeps_the_extras_of_both(self, tmp_path, dev):
        _write(tmp_path / "svc-a" / "requirements.txt", "shared[first]==1.0.0\n")
        _write(tmp_path / "svc-b" / "requirements.txt", "shared[second]==1.0.0\n")
        _mock_shared_on_pypi()
        _refuse_everything_else()

        result, data = _check_json(tmp_path, dev, _ACCEPT)

        rows = _rows(data)
        assert set(rows) == {("shared", "1.0.0"), ("first-one", "1.0.0"), ("second-one", "1.0.0")}
        assert rows["shared", "1.0.0"]["source"] == "svc-a/requirements.txt"
        assert result.exit_code == 0

    @respx.mock
    def test_production_declaration_wins_and_dev_scan_keeps_production_rows(self, tmp_path):
        # The dev file is read first; the production file declares the same pin.
        _write(tmp_path / "a" / "requirements-dev.txt", "shared[first]==1.0.0\nshared==2.0.0\n")
        _write(tmp_path / "b" / "requirements.txt", "shared[second]==1.0.0\n")
        _mock_shared_on_pypi()
        _refuse_everything_else()

        _, without_dev = _check_json(tmp_path, "--no-dev", _ACCEPT)
        _, with_dev = _check_json(tmp_path, "--dev", _ACCEPT)

        rows = _rows(with_dev)
        assert rows["shared", "1.0.0"]["group"] == "prod"
        assert rows["shared", "1.0.0"]["source"] == "b/requirements.txt"
        assert rows["shared", "2.0.0"]["group"] == "dev"
        assert rows["shared", "2.0.0"]["source"] == "a/requirements-dev.txt"
        assert _prod(with_dev) == set(_rows(without_dev))
        assert ("shared", "2.0.0") not in _rows(without_dev)

    @respx.mock
    def test_two_ranges_that_resolve_to_one_version_are_one_row(self, tmp_path):
        _write(tmp_path / "a" / "requirements.txt", "shared>=1.0\n")
        _write(tmp_path / "b" / "requirements.txt", "shared>=1.5\n")
        _mock_shared_on_pypi()
        _mock_pypi_project("shared", ["1.0.0", "2.0.0"])
        _refuse_everything_else()

        for flags in ((), ("--no-transitive",)):
            result, data = _check_json(tmp_path, _ACCEPT, *flags)
            assert set(_rows(data)) == {("shared", "2.0.0")}
            assert _rows(data)["shared", "2.0.0"]["source"] == "a/requirements.txt"

        # One row, so one review stanza.
        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.output
        scaffold = (tmp_path / REVIEW_FILE_NAME).read_text(encoding="utf-8")
        assert scaffold.count("[[review]]") == 1

    @respx.mock
    def test_direct_only_scan_reports_each_declared_version(self, tmp_path):
        _write(tmp_path / "a" / "requirements.txt", "shared==1.0.0\n")
        _write(tmp_path / "b" / "requirements-dev.txt", "shared==1.0.0\nshared==2.0.0\n")
        _mock_shared_on_pypi()
        _refuse_everything_else()

        _, data = _check_json(tmp_path, "--no-transitive", "--dev")

        rows = _rows(data)
        assert set(rows) == {("shared", "1.0.0"), ("shared", "2.0.0")}
        assert rows["shared", "1.0.0"]["group"] == "prod"
        assert rows["shared", "2.0.0"]["group"] == "dev"


class TestLockedVersionsKeepTheirOwnManifest:
    """A lockfile row for a direct dep is reported under the manifest that asks for it."""

    @staticmethod
    def _uv_lock(version: str) -> str:
        return (
            "version = 1\n\n"
            '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
            'dependencies = [{ name = "shared" }]\n\n'
            f'[[package]]\nname = "shared"\nversion = "{version}"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )

    def test_one_lockfile_per_sub_project(self, tmp_path):
        for directory, version in (("svc-a", "1.0.0"), ("svc-b", "2.0.0")):
            _write(
                tmp_path / directory / "pyproject.toml",
                f'[project]\nname = "{directory}"\nversion = "0.1.0"\n'
                f'dependencies = ["shared=={version}"]\n',
            )
            _write(tmp_path / directory / "uv.lock", self._uv_lock(version))

        direct, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct, tmp_path, include_dev=True, max_depth=50, client=client
            )

        assert {(d.name, d.version_constraint, d.depth, d.source) for d in deps} == {
            ("shared", "==1.0.0", 0, "svc-a/pyproject.toml"),
            ("shared", "==2.0.0", 0, "svc-b/pyproject.toml"),
        }

    def test_one_lockfile_holding_both_versions(self, tmp_path):
        manifest = {"name": "root", "workspaces": ["packages/*"]}
        _write(tmp_path / "package.json", json.dumps(manifest))
        packages: dict[str, dict] = {"": manifest}
        for member, spec, version, where in (
            ("a", "^1.0.0", "1.4.0", "node_modules/shared"),
            ("b", "^2.0.0", "2.1.0", "packages/b/node_modules/shared"),
        ):
            member_manifest = {"name": f"member-{member}", "dependencies": {"shared": spec}}
            _write(tmp_path / "packages" / member / "package.json", json.dumps(member_manifest))
            packages[f"packages/{member}"] = member_manifest
            packages[where] = {
                "version": version,
                "resolved": f"https://registry.npmjs.org/shared/-/shared-{version}.tgz",
                "integrity": "sha512-h",
            }
        _write(
            tmp_path / "package-lock.json",
            json.dumps({"name": "root", "lockfileVersion": 3, "packages": packages}),
        )

        direct, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct, tmp_path, include_dev=True, max_depth=50, client=client
            )

        assert {(d.name, d.version_constraint, d.depth, d.source) for d in deps} == {
            ("shared", "==1.4.0", 0, "packages/a/package.json"),
            ("shared", "==2.1.0", 0, "packages/b/package.json"),
        }

    @respx.mock
    @pytest.mark.parametrize("go_sum", [True, False], ids=["go.sum", "no-go.sum"])
    def test_two_go_modules_requiring_different_versions(self, tmp_path, go_sum):
        module = "example.org/shared"
        for directory, version in (("svc-a", "v1.0.0"), ("svc-b", "v1.1.0")):
            _write(
                tmp_path / directory / "go.mod",
                f"module example.com/{directory}\n\ngo 1.22\n\nrequire {module} {version}\n",
            )
            if go_sum:
                _write(
                    tmp_path / directory / "go.sum",
                    f"{module} {version} h1:h\n{module} {version}/go.mod h1:h\n",
                )
            respx.get(f"https://proxy.golang.org/{module}/@v/{version}.mod").mock(
                return_value=httpx.Response(200, text=f"module {module}\n")
            )

        direct, _ = discover_all_dependencies(tmp_path)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct, tmp_path, include_dev=True, max_depth=50, client=client
            )

        # Each requirement is a direct dependency of the module that states it.
        assert {(d.name, d.version_constraint, d.depth, d.source) for d in deps} == {
            (module, "v1.0.0", 0, "svc-a/go.mod"),
            (module, "v1.1.0", 0, "svc-b/go.mod"),
        }


class TestDeclarationOfALockedRow:
    """``_declaration_for``: which manifest a lockfile's depth-0 row belongs to."""

    @staticmethod
    def _declared(*specs: tuple[str, str], origin: str = "") -> dict:
        deps = [
            Dependency(
                name="shared",
                version_constraint=constraint,
                ecosystem=Ecosystem.PYTHON,
                source=source,
                origin=origin if source == "off-registry" else "",
            )
            for constraint, source in specs
        ]
        return {(Ecosystem.PYTHON, "shared"): deps}

    @staticmethod
    def _row(version: str, origin: str = "") -> Dependency:
        return Dependency(
            name="Shared", version_constraint=version, ecosystem=Ecosystem.PYTHON, origin=origin
        )

    def test_first_declaration_the_version_satisfies(self):
        declared = self._declared(("==1.0", "a"), (">=2", "b"), (">=2.1", "c"))
        assert _declaration_for(self._row("==2.5"), declared).source == "b"
        assert _declaration_for(self._row("==1.0"), declared).source == "a"

    def test_a_constraint_that_cannot_be_read_comes_after_one_that_is_met(self):
        declared = self._declared(("@ branch", "a"), (">=2", "b"))
        assert _declaration_for(self._row("==2.5"), declared).source == "b"
        # Nothing is met: the unreadable constraint may still be the one.
        assert _declaration_for(self._row("==1.0"), declared).source == "a"

    def test_no_declaration_met_is_no_declaration(self):
        declared = self._declared(("==1.0", "a"), ("==2.0", "b"))
        assert _declaration_for(self._row("==3.0"), declared) is None

    def test_row_without_a_version_takes_the_first(self):
        declared = self._declared(("==1.0", "a"), ("==2.0", "b"))
        assert _declaration_for(self._row(""), declared).source == "a"

    def test_off_registry_row_goes_with_the_off_registry_declaration(self):
        declared = self._declared(("", "registry"), ("", "off-registry"), origin="git+https://x")
        assert _declaration_for(self._row("==1.0"), declared).source == "registry"
        assert _declaration_for(self._row("==1.0", "git+https://x@abc"), declared).source == (
            "off-registry"
        )

    def test_package_nobody_declares(self):
        assert _declaration_for(self._row("==1.0"), {}) is None

    def test_direct_row_takes_the_manifest_and_a_transitive_is_left_alone(self):
        declared = self._declared(("==1.0", "manifest"))
        direct = self._row("==1.0")
        transitive = replace(direct, depth=1)

        assert _with_declared_source(direct, declared).source == "manifest"
        assert _with_declared_source(transitive, declared) is transitive

    def test_row_keeps_its_own_source_when_no_manifest_supplies_one(self):
        # A lockfile that names itself as the source of its rows.
        row = replace(self._row("==1.0"), source="paket.lock")

        assert _with_declared_source(row, {}) is row
        # A declaration built without a manifest path has none to give.
        assert _with_declared_source(row, self._declared(("==1.0", ""))) is row

    def test_off_registry_row_gets_its_manifest_and_keeps_its_origin(self):
        declared = self._declared(("", "off-registry"), origin="git+https://x")
        row = self._row("==0.1.0", "git+https://x@abc")

        stamped = _with_declared_source(row, declared)

        assert (stamped.source, stamped.origin) == ("off-registry", "git+https://x@abc")


# --------------------------------------------------------------------- npm


def _mock_npm(name: str, version: str, license_id: str, dependencies: dict | None = None) -> None:
    meta = {
        "name": name,
        "version": version,
        "license": license_id,
        "dependencies": dependencies or {},
    }
    respx.get(f"https://registry.npmjs.org/{name}/{version}").mock(
        return_value=httpx.Response(200, json=meta)
    )


class TestPackageJsonFiles:
    def _project(self, root: Path, *, first_is_dev: bool = False) -> None:
        section = "devDependencies" if first_is_dev else "dependencies"
        _write(
            root / "app-a" / "package.json", json.dumps({"name": "a", section: {"shared": "1.0.0"}})
        )
        _write(
            root / "app-b" / "package.json",
            json.dumps({"name": "b", "dependencies": {"shared": "2.0.0"}}),
        )
        _mock_npm("shared", "1.0.0", "MIT", {"child-one": "1.0.0"})
        _mock_npm("shared", "2.0.0", "GPL-3.0-only", {"child-two": "1.0.0"})
        _mock_npm("child-one", "1.0.0", "MIT")
        _mock_npm("child-two", "1.0.0", "MIT")
        _refuse_everything_else()

    @respx.mock
    @_MODES
    def test_two_files_pinning_different_versions(self, tmp_path, dev):
        self._project(tmp_path)

        result, data = _check_json(tmp_path, dev, _ACCEPT)

        rows = _rows(data)
        assert set(rows) == {
            ("shared", "1.0.0"),
            ("shared", "2.0.0"),
            ("child-one", "1.0.0"),
            ("child-two", "1.0.0"),
        }
        assert rows["shared", "1.0.0"]["source"] == "app-a/package.json"
        assert rows["shared", "2.0.0"]["source"] == "app-b/package.json"
        assert rows["shared", "2.0.0"]["license"] == "GPL-3.0-only"
        assert result.exit_code == 1

    @respx.mock
    def test_dev_scan_keeps_production_rows(self, tmp_path):
        self._project(tmp_path, first_is_dev=True)

        _, without_dev = _check_json(tmp_path, "--no-dev", _ACCEPT)
        _, with_dev = _check_json(tmp_path, "--dev", _ACCEPT)

        assert set(_rows(without_dev)) == {("shared", "2.0.0"), ("child-two", "1.0.0")}
        assert _prod(with_dev) == set(_rows(without_dev))
        assert _rows(with_dev)["shared", "1.0.0"]["group"] == "dev"
        assert _rows(with_dev)["child-one", "1.0.0"]["group"] == "dev"


# -------------------------------------------------------------------- .NET


def _mock_nuspec(
    package_id: str, version: str, license_id: str = "MIT", requires: dict | None = None
) -> None:
    lowered = package_id.lower()
    dependencies = "".join(
        f'<dependency id="{name}" version="{spec}" />' for name, spec in (requires or {}).items()
    )
    respx.get(f"https://api.nuget.org/v3-flatcontainer/{lowered}/{version}/{lowered}.nuspec").mock(
        return_value=httpx.Response(
            200,
            text=(
                f"<package><metadata><id>{package_id}</id><version>{version}</version>"
                f'<license type="expression">{license_id}</license>'
                f"<dependencies>{dependencies}</dependencies></metadata></package>"
            ),
        )
    )


def _csproj(*references: tuple[str, str, bool]) -> str:
    items = "".join(
        f'<PackageReference Include="{name}" Version="{version}"'
        + (' PrivateAssets="all"' if dev else "")
        + " />"
        for name, version, dev in references
    )
    return f'<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>{items}</ItemGroup></Project>'


class TestDotnetProjectFiles:
    @respx.mock
    @_MODES
    def test_two_project_files_pinning_different_versions(self, tmp_path, dev):
        _write(tmp_path / "App1" / "App1.csproj", _csproj(("Shared.Lib", "1.0.0", False)))
        _write(tmp_path / "App2" / "App2.csproj", _csproj(("Shared.Lib", "2.0.0", False)))
        _mock_nuspec("Shared.Lib", "1.0.0", "MIT", {"Child.One": "1.0.0"})
        _mock_nuspec("Shared.Lib", "2.0.0", "GPL-3.0-only", {"Child.Two": "1.0.0"})
        _mock_nuspec("Child.One", "1.0.0")
        _mock_nuspec("Child.Two", "1.0.0")
        _refuse_everything_else()

        result, data = _check_json(tmp_path, dev, _ACCEPT)

        rows = _rows(data)
        assert set(rows) == {
            ("Shared.Lib", "1.0.0"),
            ("Shared.Lib", "2.0.0"),
            ("Child.One", "1.0.0"),
            ("Child.Two", "1.0.0"),
        }
        assert rows["Shared.Lib", "1.0.0"]["source"] == "App1/App1.csproj"
        assert rows["Shared.Lib", "2.0.0"]["source"] == "App2/App2.csproj"
        assert rows["Shared.Lib", "2.0.0"]["license"] == "GPL-3.0-only"
        assert result.exit_code == 1

    @respx.mock
    def test_direct_reference_and_another_version_pulled_in_are_both_rows(self, tmp_path):
        _write(
            tmp_path / "App.csproj",
            _csproj(("Shared.Lib", "1.0.0", False), ("Host.Lib", "1.0.0", False)),
        )
        _mock_nuspec("Host.Lib", "1.0.0", "MIT", {"Shared.Lib": "2.0.0"})
        _mock_nuspec("Shared.Lib", "1.0.0", "MIT")
        _mock_nuspec("Shared.Lib", "2.0.0", "GPL-3.0-only")
        _refuse_everything_else()

        result, data = _check_json(tmp_path, _ACCEPT)

        rows = _rows(data)
        assert set(rows) == {
            ("Shared.Lib", "1.0.0"),
            ("Shared.Lib", "2.0.0"),
            ("Host.Lib", "1.0.0"),
        }
        assert rows["Shared.Lib", "1.0.0"]["depth"] == 0
        assert rows["Shared.Lib", "2.0.0"]["depth"] == 1
        assert rows["Shared.Lib", "2.0.0"]["direct_ancestors"] == ["Host.Lib"]
        assert rows["Shared.Lib", "2.0.0"]["estimated"] == ["version"]
        assert result.exit_code == 1

    @respx.mock
    def test_dev_reference_does_not_replace_the_version_production_pulls_in(self, tmp_path):
        # Shared.Lib 1.0.0 is a dev-only reference; production reaches 2.0.0
        # through Host.Lib, and Tool.Lib at the version a dev reference pins.
        _write(
            tmp_path / "App.csproj",
            _csproj(
                ("Shared.Lib", "1.0.0", True),
                ("Tool.Lib", "3.0.0", True),
                ("Host.Lib", "1.0.0", False),
            ),
        )
        _mock_nuspec("Host.Lib", "1.0.0", "MIT", {"Shared.Lib": "2.0.0", "Tool.Lib": "3.0.0"})
        _mock_nuspec("Shared.Lib", "1.0.0", "MIT", {"Dev.Child": "1.0.0"})
        _mock_nuspec("Shared.Lib", "2.0.0", "MIT")
        _mock_nuspec("Tool.Lib", "3.0.0", "MIT")
        _mock_nuspec("Dev.Child", "1.0.0", "MIT")
        _refuse_everything_else()

        _, without_dev = _check_json(tmp_path, "--no-dev", _ACCEPT)
        _, with_dev = _check_json(tmp_path, "--dev", _ACCEPT)

        assert set(_rows(without_dev)) == {
            ("Host.Lib", "1.0.0"),
            ("Shared.Lib", "2.0.0"),
            ("Tool.Lib", "3.0.0"),
        }
        assert _prod(with_dev) == set(_rows(without_dev))
        rows = _rows(with_dev)
        assert rows["Shared.Lib", "1.0.0"]["group"] == "dev"
        assert rows["Dev.Child", "1.0.0"]["group"] == "dev"
        assert rows["Dev.Child", "1.0.0"]["direct_ancestors"] == ["Shared.Lib"]
        # The dev reference at the version production ships is the production row.
        assert rows["Tool.Lib", "3.0.0"]["group"] == "prod"
        assert rows["Tool.Lib", "3.0.0"]["depth"] == 0


class TestPaketGroups:
    _NUGET = "NUGET\n  remote: https://api.nuget.org/v3/index.json\n"

    def test_groups_pinning_one_package_at_two_versions(self, tmp_path):
        # A dev-class group lists Shared.Lib first, at another version than
        # the production group after it.
        _write(
            tmp_path / "paket.lock",
            f"GROUP Test\n{self._NUGET}    Shared.Lib (1.0.0)\n    Test.Only (5.0.0)\n\n"
            f"GROUP Server\n{self._NUGET}    Shared.Lib (2.0.0)\n    Same.Pin (4.0.0)\n\n"
            f"GROUP Build\n{self._NUGET}    Same.Pin (4.0.0)\n",
        )

        def scan(include_dev: bool) -> dict[tuple[str, str], DependencyGroup]:
            direct, _ = discover_all_dependencies(tmp_path)
            with httpx.Client() as client:
                deps = resolve_transitive(
                    direct, tmp_path, include_dev=include_dev, max_depth=50, client=client
                )
            rows = {(d.name, d.version_constraint): d.group for d in deps}
            assert len(rows) == len(deps)
            return rows

        without_dev = scan(False)
        with_dev = scan(True)

        prod, dev = DependencyGroup.PROD, DependencyGroup.DEV
        assert without_dev == {("Shared.Lib", "==2.0.0"): prod, ("Same.Pin", "==4.0.0"): prod}
        assert with_dev == {
            ("Shared.Lib", "==1.0.0"): dev,
            ("Shared.Lib", "==2.0.0"): prod,
            ("Test.Only", "==5.0.0"): dev,
            # Pinned alike in a dev-class and a production group: it ships.
            ("Same.Pin", "==4.0.0"): prod,
        }
        assert {key for key, group in with_dev.items() if group == prod} == set(without_dev)


# ------------------------------------------------------------------- Maven


def _pom(artifact: str, body: str) -> str:
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        f"<groupId>com.example</groupId><artifactId>{artifact}</artifactId>"
        f"<version>1.0</version>{body}</project>"
    )


def _mock_maven_graph(name: str, version: str, children: dict[str, str] | None = None) -> None:
    nodes = [
        {"versionKey": {"system": "MAVEN", "name": name, "version": version}, "relation": "SELF"}
    ]
    nodes += [
        {
            "versionKey": {"system": "MAVEN", "name": child, "version": child_version},
            "relation": "DIRECT",
        }
        for child, child_version in (children or {}).items()
    ]
    respx.get(
        "https://api.deps.dev/v3/systems/MAVEN/packages/"
        f"{name.replace(':', '%3A')}/versions/{version}:dependencies"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "nodes": nodes,
                "edges": [{"fromNode": 0, "toNode": index} for index in range(1, len(nodes))],
            },
        )
    )


class TestMavenMultiModuleBuild:
    @respx.mock
    @_MODES
    def test_modules_pinning_different_versions(self, tmp_path, dev):
        _write(
            tmp_path / "pom.xml",
            _pom(
                "parent",
                "<packaging>pom</packaging><modules><module>mod-a</module>"
                "<module>mod-b</module></modules>",
            ),
        )
        for module, version in (("mod-a", "1.0"), ("mod-b", "2.0")):
            _write(
                tmp_path / module / "pom.xml",
                _pom(
                    module,
                    "<dependencies><dependency><groupId>org.example</groupId>"
                    f"<artifactId>shared</artifactId><version>{version}</version>"
                    "</dependency></dependencies>",
                ),
            )
        _mock_maven_graph("org.example:shared", "1.0", {"org.example:child-one": "1.0"})
        _mock_maven_graph("org.example:shared", "2.0", {"org.example:child-two": "1.0"})
        _mock_batch(
            {
                ("MAVEN", "org.example:shared", "1.0"): "MIT",
                ("MAVEN", "org.example:shared", "2.0"): "GPL-3.0-only",
                ("MAVEN", "org.example:child-one", "1.0"): "MIT",
                ("MAVEN", "org.example:child-two", "1.0"): "MIT",
            }
        )
        _refuse_everything_else()

        result, data = _check_json(tmp_path, dev)

        rows = _rows(data)
        assert set(rows) == {
            ("org.example:shared", "1.0"),
            ("org.example:shared", "2.0"),
            ("org.example:child-one", "1.0"),
            ("org.example:child-two", "1.0"),
        }
        assert rows["org.example:shared", "1.0"]["source"] == "mod-a/pom.xml"
        assert rows["org.example:shared", "2.0"]["source"] == "mod-b/pom.xml"
        assert rows["org.example:shared", "2.0"]["license"] == "GPL-3.0-only"
        assert result.exit_code == 1


# --------------------------------------------------------------- discovery


class TestDiscoveryKey:
    def test_different_constraints_are_two_dependencies(self, tmp_path):
        _write(tmp_path / "a" / "requirements.txt", "shared==1.0\n")
        _write(tmp_path / "b" / "requirements.txt", "Shared==2.0\n")

        deps, _ = discover_all_dependencies(tmp_path)

        assert [(d.name, d.version_constraint, d.source) for d in deps] == [
            ("shared", "==1.0", "a/requirements.txt"),
            ("Shared", "==2.0", "b/requirements.txt"),
        ]

    def test_same_constraint_unions_extras_and_prefers_production(self, tmp_path):
        _write(tmp_path / "a" / "requirements-dev.txt", "shared[first]==1.0\n")
        _write(tmp_path / "b" / "requirements.txt", "shared[second] == 1.0\n")
        _write(tmp_path / "c" / "requirements-test.txt", "shared[third]==1.0\n")

        deps, _ = discover_all_dependencies(tmp_path)

        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD
        assert deps[0].source == "b/requirements.txt"
        assert deps[0].extras == frozenset({"first", "second", "third"})

    def test_off_registry_dependency_is_keyed_on_its_origin(self, tmp_path):
        # The same repository, declared with and without a version: one
        # dependency, whatever a manifest says beside the source.
        _write(
            tmp_path / "a" / "Cargo.toml",
            '[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\n'
            'forked = { git = "https://git.example.org/forked.git", version = "1.0" }\n',
        )
        _write(
            tmp_path / "b" / "Cargo.toml",
            '[package]\nname = "b"\nversion = "0.1.0"\n\n[dependencies]\n'
            'forked = { git = "https://git.example.org/forked.git" }\n',
        )

        deps, _ = discover_all_dependencies(tmp_path)

        assert [(d.name, d.source) for d in deps] == [("forked", "a/Cargo.toml")]
        assert deps[0].origin


# ------------------------------------------------ one stanza per review key


def _mix_project(root: Path, app: str, dep: str) -> None:
    _write(
        root / "mix.exs",
        f"""\
        defmodule {app.title()}.MixProject do
          use Mix.Project

          def project do
            [app: :{app}, version: "0.1.0", deps: deps()]
          end

          defp deps do
            [{dep}]
          end
        end
        """,
    )


class TestOneStanzaPerReviewKey:
    """Rows that share a review key are scaffolded once, and one stanza covers them."""

    @respx.mock
    def test_two_local_names_for_one_published_package(self, tmp_path):
        # Two apps of one tree use the same hex.pm release, one of them under
        # a local name of its own: two rows, one package to review.
        _mix_project(tmp_path / "apps" / "one", "one", '{:my_alias, "== 1.0.0", hex: :real_pkg}')
        _mix_project(tmp_path / "apps" / "two", "two", '{:real_pkg, "== 1.0.0"}')
        respx.get("https://hex.pm/api/packages/real_pkg").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"licenses": ["GPL-3.0-only"], "links": {}},
                    "latest_stable_version": "1.0.0",
                    "releases": [{"version": "1.0.0"}],
                },
            )
        )
        respx.get("https://hex.pm/api/packages/real_pkg/releases/1.0.0").mock(
            return_value=httpx.Response(200, json={"requirements": {}})
        )
        _refuse_everything_else()

        result, data = _check_json(tmp_path, _ACCEPT)
        assert result.exit_code == 1
        assert sorted(dep["name"] for dep in data["dependencies"]) == ["my_alias", "real_pkg"]
        report = tmp_path / "report.json"

        review_file = tmp_path / REVIEW_FILE_NAME
        for source in ((), ("--from-report", str(report))):
            review_file.unlink(missing_ok=True)
            result = CliRunner().invoke(
                main, ["init-review-file", "--path", str(tmp_path), *source]
            )
            assert result.exit_code == 0, result.output
            scaffold = review_file.read_text(encoding="utf-8")
            assert scaffold.count("[[review]]") == 1
            assert 'package = "real_pkg"\n' in scaffold

        review_file.write_text(
            scaffold.replace('license = ""', 'license = "MIT"'), encoding="utf-8", newline="\n"
        )
        result, data = _check_json(tmp_path, _ACCEPT)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == 2
