"""Two names are one package only where the registry says so.

``Ecosystem.identity`` is the one rule every key is built with. A Go module
path, a Maven coordinate, an npm package name, and a gem name that differ
only in case are different packages: each is a row with its own license, with
or without a lockfile, and a review written for one never applies to the
other. NuGet, Packagist, crates.io, Hex, and CRAN names that differ only in
case are one package, and PyPI names are one package under PEP 503.

A Hex dependency is reviewed under the name it is published as on hex.pm,
not under the local name ``mix.exs`` gives it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.discovery import discover_all_dependencies
from licenseal.models import (
    CompatibilityResult,
    CompatibilityVerdict,
    Dependency,
    Ecosystem,
    LicenseInfo,
    RiskLevel,
)
from licenseal.report import _grouped_results
from licenseal.review import (
    REVIEW_FILE_NAME,
    canonical_name,
    flagged_entries_from_json_report,
    info_review_key,
    review_key,
)
from tests._helpers import _check_json, _write

_EXACT = (Ecosystem.GO, Ecosystem.JAVA, Ecosystem.NPM, Ecosystem.RUBY)
_FOLDED = (Ecosystem.DOTNET, Ecosystem.PHP, Ecosystem.RUST, Ecosystem.HEX, Ecosystem.R)

_UNMATCHED = "Reviewed licenses did not match any resolved package versions: "
_EXACT_HINT = (
    "for go, java, npm, and ruby it must be spelled exactly as the report shows the "
    "dependency, upper and lower case included"
)


def _refuse_everything_else() -> None:
    """Answer 404 to any request no earlier route matched."""
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


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


def _check_fails(project: Path) -> str:
    """Run a scan that ends in an error before any report is written; return its output."""
    result = CliRunner().invoke(main, ["check", "--path", str(project), *_FLAGS])
    assert result.exit_code == 1
    return result.output


def _rows(data: dict) -> dict[str, dict]:
    rows = {dep["name"]: dep for dep in data["dependencies"]}
    assert len(rows) == len(data["dependencies"])
    return rows


def _review(project: Path, ecosystem: str, package: str, version: str) -> None:
    _write(
        project / REVIEW_FILE_NAME,
        f"""\
        [[review]]
        ecosystem = "{ecosystem}"
        package = "{package}"
        version = "{version}"
        license = "MIT"
        note = "read the license of {package}"
        """,
    )


# ---------------------------------------------------------------- the rule


class TestIdentityRule:
    @pytest.mark.parametrize("ecosystem", _EXACT)
    def test_case_is_part_of_the_name(self, ecosystem):
        assert ecosystem.identity("Group/Name-X_y.z") == "Group/Name-X_y.z"
        assert ecosystem.identity("Widget") != ecosystem.identity("widget")

    @pytest.mark.parametrize("ecosystem", _FOLDED)
    def test_case_is_folded(self, ecosystem):
        assert ecosystem.identity("Group/Name-X_y.z") == "group/name-x_y.z"
        assert ecosystem.identity("Widget") == ecosystem.identity("widget")

    def test_python_is_pep_503(self):
        assert Ecosystem.PYTHON.identity("My_Pkg.Name") == "my-pkg-name"
        assert Ecosystem.PYTHON.identity("a-_-b") == "a-b"

    def test_every_ecosystem_has_a_rule(self):
        assert set(Ecosystem) == {*_EXACT, *_FOLDED, Ecosystem.PYTHON}

    @pytest.mark.parametrize("ecosystem", list(Ecosystem))
    def test_dependency_and_review_key_use_it(self, ecosystem):
        dep = Dependency(name="Some_Name", version_constraint="1.0", ecosystem=ecosystem)
        assert dep.identity == ecosystem.identity("Some_Name")
        assert canonical_name(ecosystem, " Some_Name ") == dep.identity
        assert canonical_name(ecosystem.value, "Some_Name") == dep.identity
        assert review_key(ecosystem, "Some_Name", "1.0") == f"{ecosystem.value}:{dep.identity}@1.0"


# ------------------------------------- exact case: Go, Java, npm, Ruby


def _go_project(project: Path, licenses: dict[str, str], *, lockfile: bool) -> str:
    version = "v1.0.0"
    requires = "".join(f"    {name} {version}\n" for name in licenses)
    (project / "go.mod").write_text(
        f"module example.com/app\n\ngo 1.22\n\nrequire (\n{requires})\n",
        encoding="utf-8",
        newline="\n",
    )
    if lockfile:
        (project / "go.sum").write_text(
            "".join(f"{name} {version} h1:h\n{name} {version}/go.mod h1:h\n" for name in licenses),
            encoding="utf-8",
            newline="\n",
        )
    for name in licenses:
        # The proxy writes an uppercase letter as ``!`` and its lowercase.
        encoded = "".join(f"!{ch.lower()}" if ch.isupper() else ch for ch in name)
        respx.get(f"https://proxy.golang.org/{encoded}/@v/{version}.mod").mock(
            return_value=httpx.Response(200, text=f"module {name}\n")
        )
    _mock_batch({("GO", name, version): spdx for name, spdx in licenses.items()})
    return version


def _java_project(project: Path, licenses: dict[str, str], *, lockfile: bool) -> str:
    version = "1.0"
    if lockfile:
        (project / "build.gradle").write_text(
            "dependencies {\n"
            + "".join(f"    implementation '{name}:{version}'\n" for name in licenses)
            + "}\n",
            encoding="utf-8",
            newline="\n",
        )
        (project / "gradle.lockfile").write_text(
            "".join(f"{name}:{version}=runtimeClasspath\n" for name in licenses) + "empty=\n",
            encoding="utf-8",
            newline="\n",
        )
    else:
        dependencies = "".join(
            "<dependency><groupId>{}</groupId><artifactId>{}</artifactId>"
            "<version>{}</version></dependency>".format(*name.split(":"), version)
            for name in licenses
        )
        (project / "pom.xml").write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<groupId>com.example</groupId><artifactId>app</artifactId><version>1</version>"
            f"<dependencies>{dependencies}</dependencies></project>",
            encoding="utf-8",
        )
        for name in licenses:
            respx.get(
                "https://api.deps.dev/v3/systems/MAVEN/packages/"
                f"{name.replace(':', '%3A')}/versions/{version}:dependencies"
            ).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "nodes": [
                            {
                                "versionKey": {"system": "MAVEN", "name": name, "version": version},
                                "relation": "SELF",
                            }
                        ]
                    },
                )
            )
    _mock_batch({("MAVEN", name, version): spdx for name, spdx in licenses.items()})
    return version


def _npm_project(project: Path, licenses: dict[str, str], *, lockfile: bool) -> str:
    version = "1.0.0"
    dependencies = dict.fromkeys(licenses, version)
    (project / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": dependencies}), encoding="utf-8"
    )
    if lockfile:
        packages: dict[str, dict] = {"": {"name": "app", "dependencies": dependencies}}
        for name in licenses:
            packages[f"node_modules/{name}"] = {
                "version": version,
                "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
                "integrity": "sha512-h",
            }
        (project / "package-lock.json").write_text(
            json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}),
            encoding="utf-8",
        )
    for name, spdx in licenses.items():
        meta = {"name": name, "version": version, "license": spdx}
        respx.get(f"https://registry.npmjs.org/{name}").mock(
            return_value=httpx.Response(200, json={"versions": {version: meta}})
        )
        respx.get(f"https://registry.npmjs.org/{name}/{version}").mock(
            return_value=httpx.Response(200, json=meta)
        )
    return version


def _ruby_project(project: Path, licenses: dict[str, str], *, lockfile: bool) -> str:
    version = "1.0.0"
    (project / "Gemfile").write_text(
        'source "https://rubygems.org"\n'
        + "".join(f'gem "{name}", "{version}"\n' for name in licenses),
        encoding="utf-8",
        newline="\n",
    )
    if lockfile:
        (project / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n"
            + "".join(f"    {name} ({version})\n" for name in licenses)
            + "\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n"
            + "".join(f"  {name} (= {version})\n" for name in licenses)
            + "\nBUNDLED WITH\n   2.5.0\n",
            encoding="utf-8",
            newline="\n",
        )
    for name, spdx in licenses.items():
        respx.get(f"https://rubygems.org/api/v2/rubygems/{name}/versions/{version}.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": name,
                    "number": version,
                    "licenses": [spdx],
                    "dependencies": {"runtime": [], "development": []},
                },
            )
        )
    return version


# ecosystem -> (project builder, the two spellings)
_CASE_SENSITIVE: dict[str, tuple[Callable[..., str], str, str]] = {
    "go": (_go_project, "example.org/Foo", "example.org/foo"),
    "java": (_java_project, "org.example:Widget", "org.example:widget"),
    "npm": (_npm_project, "Widget", "widget"),
    "ruby": (_ruby_project, "Widget", "widget"),
}

_each_case_sensitive_layout = pytest.mark.parametrize(
    ("ecosystem", "lockfile"),
    [(ecosystem, lockfile) for ecosystem in _CASE_SENSITIVE for lockfile in (True, False)],
    ids=lambda value: {True: "lockfile", False: "no-lockfile"}.get(value, value),
)

# The scans below judge rows and reviews; a missing lockfile is accepted.
_FLAGS = ("--no-require-lockfile",)


class TestNamesThatDifferOnlyInCase:
    """Go, Java, npm, Ruby: each spelling is a package of its own."""

    @respx.mock
    @_each_case_sensitive_layout
    def test_two_rows_each_with_its_own_license(self, tmp_path, ecosystem, lockfile):
        build, upper, lower = _CASE_SENSITIVE[ecosystem]
        version = build(tmp_path, {upper: "MIT", lower: "GPL-3.0-only"}, lockfile=lockfile)
        _refuse_everything_else()

        result, data = _check_json(tmp_path, *_FLAGS)

        rows = _rows(data)
        assert set(rows) == {upper, lower}
        assert rows[upper]["license"] == "MIT"
        assert rows[upper]["verdict"] == "compatible"
        assert rows[lower]["license"] == "GPL-3.0-only"
        assert rows[lower]["verdict"] == "incompatible"
        assert {row["resolved_version"] for row in rows.values()} == {version}
        assert {row["depth"] for row in rows.values()} == {0}
        assert result.exit_code == 1

    @respx.mock
    @_each_case_sensitive_layout
    def test_review_of_one_spelling_does_not_apply_to_the_other(
        self, tmp_path, ecosystem, lockfile
    ):
        build, upper, lower = _CASE_SENSITIVE[ecosystem]
        version = build(tmp_path, {lower: "GPL-3.0-only"}, lockfile=lockfile)
        _refuse_everything_else()

        # The review was written for the other spelling: it matches nothing.
        _review(tmp_path, ecosystem, upper, version)
        output = _check_fails(tmp_path)
        assert f"{_UNMATCHED}{ecosystem}:{upper}@{version}\n" in output
        assert _EXACT_HINT in output

        # Written for the package the project uses, it applies.
        _review(tmp_path, ecosystem, lower, version)
        result, data = _check_json(tmp_path, *_FLAGS)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == 1
        assert _rows(data)[lower]["review_note"] == f"read the license of {lower}"

    @respx.mock
    @_each_case_sensitive_layout
    def test_review_covers_one_of_two_flagged_spellings(self, tmp_path, ecosystem, lockfile):
        build, upper, lower = _CASE_SENSITIVE[ecosystem]
        version = build(tmp_path, {upper: "GPL-2.0-only", lower: "GPL-3.0-only"}, lockfile=lockfile)
        _refuse_everything_else()
        _review(tmp_path, ecosystem, upper, version)

        result, data = _check_json(tmp_path, *_FLAGS)

        rows = _rows(data)
        assert rows[upper]["reviewed"] is True
        assert rows[upper]["license"] == "MIT"
        assert rows[lower]["reviewed"] is False
        assert rows[lower]["license"] == "GPL-3.0-only"
        assert data["summary"]["reviewed"] == 1
        # The unreviewed spelling is still a violation and fails the scan.
        assert data["summary"]["violations"] == 1
        assert rows[lower]["verdict"] == "incompatible"
        assert result.exit_code == 1


# --------------------- folded case: .NET, PHP, Rust, Hex, R; PEP 503: Python


# ecosystem -> (manifest file name, manifest text for one dependency name)
_ONE_DEPENDENCY: dict[Ecosystem, tuple[str, Callable[[str, str], str]]] = {
    Ecosystem.DOTNET: (
        "{dir}.csproj",
        lambda _dir, name: (
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            f'<PackageReference Include="{name}" Version="1.0.0" />'
            "</ItemGroup></Project>"
        ),
    ),
    Ecosystem.PHP: (
        "composer.json",
        lambda _dir, name: json.dumps({"require": {name: "1.0.0"}}),
    ),
    Ecosystem.RUST: (
        "Cargo.toml",
        lambda dir_, name: (
            f'[package]\nname = "crate-{dir_}"\nversion = "0.1.0"\n\n'
            f'[dependencies]\n"{name}" = "=1.0.0"\n'
        ),
    ),
    Ecosystem.HEX: (
        "mix.exs",
        lambda dir_, name: (
            f"defmodule App{dir_.title()}.MixProject do\n  use Mix.Project\n\n"
            f'  def project do\n    [app: :app_{dir_}, version: "0.1.0", deps: deps()]\n  end\n\n'
            f'  defp deps do\n    [{{:{name}, "== 1.0.0"}}]\n  end\nend\n'
        ),
    ),
    Ecosystem.R: (
        "DESCRIPTION",
        lambda dir_, name: f"Package: app{dir_}\nVersion: 0.1\nImports: {name} (>= 1.0)\n",
    ),
    Ecosystem.PYTHON: (
        "requirements.txt",
        lambda _dir, name: f"{name}==1.0.0\n",
    ),
}

_ONE_PACKAGE = [
    (Ecosystem.DOTNET, "Acme.Widget", "acme.widget"),
    (Ecosystem.PHP, "Acme/Widget", "acme/widget"),
    (Ecosystem.RUST, "Widget", "widget"),
    (Ecosystem.HEX, "Widget", "widget"),
    (Ecosystem.R, "Widget", "widget"),
    (Ecosystem.PYTHON, "Acme_Widget", "acme-widget"),
]


def _two_manifests(project: Path, ecosystem: Ecosystem, first: str, second: str) -> None:
    """Declare ``first`` in the project's own manifest and ``second`` in a sub-project's."""
    file_name, render = _ONE_DEPENDENCY[ecosystem]
    for directory, name in (("main", first), ("sub", second)):
        target = project if directory == "main" else project / directory
        _write(target / file_name.format(dir=directory), render(directory, name))


class TestNamesTheRegistryFolds:
    """.NET, PHP, Rust, Hex, R, and Python: both spellings are one package."""

    @pytest.mark.parametrize(("ecosystem", "first", "second"), _ONE_PACKAGE)
    def test_two_spellings_are_one_dependency(self, tmp_path, ecosystem, first, second):
        _two_manifests(tmp_path, ecosystem, first, second)

        deps, _ = discover_all_dependencies(tmp_path)

        assert [(d.ecosystem, d.name) for d in deps] == [(ecosystem, first)]
        assert review_key(ecosystem, first, "1.0.0") == review_key(ecosystem, second, "1.0.0")

    @pytest.mark.parametrize("ecosystem", _EXACT)
    def test_review_keys_of_two_spellings_differ_where_case_counts(self, ecosystem):
        assert review_key(ecosystem, "Widget", "1.0.0") != review_key(ecosystem, "widget", "1.0.0")

    @respx.mock
    def test_review_written_in_another_case_applies(self, tmp_path):
        # composer.lock carries the license, so no registry is asked.
        _two_manifests(tmp_path, Ecosystem.PHP, "Acme/Widget", "acme/widget")
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "acme/widget",
                            "version": "1.0.0",
                            "license": ["GPL-3.0-only"],
                            "source": {"type": "git", "url": "https://git.example.org/w.git"},
                        }
                    ],
                    "packages-dev": [],
                }
            ),
            encoding="utf-8",
        )
        _refuse_everything_else()

        result, data = _check_json(tmp_path, *_FLAGS)
        assert result.exit_code == 1
        assert [(d["name"], d["license"]) for d in data["dependencies"]] == [
            ("acme/widget", "GPL-3.0-only")
        ]

        _review(tmp_path, "php", "ACME/Widget", "1.0.0")
        result, data = _check_json(tmp_path, *_FLAGS)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == 1


# ------------------------------------------------- Hex: the published package


def _mock_hex(name: str, license_id: str) -> None:
    respx.get(f"https://hex.pm/api/packages/{name}").mock(
        return_value=httpx.Response(
            200,
            json={
                "meta": {"licenses": [license_id], "links": {}},
                "latest_stable_version": "1.0.0",
                "releases": [{"version": "1.0.0"}],
            },
        )
    )
    respx.get(f"https://hex.pm/api/packages/{name}/releases/1.0.0").mock(
        return_value=httpx.Response(200, json={"requirements": {}})
    )


def _mix_project(project: Path, published_as: str, *, lockfile: bool) -> None:
    """A project whose ``my_alias`` dependency is the hex.pm package ``published_as``."""
    _write(
        project / "mix.exs",
        f"""\
        defmodule App.MixProject do
          use Mix.Project

          def project do
            [app: :app, version: "0.1.0", deps: deps()]
          end

          defp deps do
            [{{:my_alias, "== 1.0.0", hex: :{published_as}}}]
          end
        end
        """,
    )
    lock = project / "mix.lock"
    if lockfile:
        lock.write_text(
            "%{\n"
            f'  "my_alias": {{:hex, :{published_as}, "1.0.0", "h", [:mix], [], "hexpm", "h"}},\n'
            "}\n",
            encoding="utf-8",
            newline="\n",
        )
    else:
        lock.unlink(missing_ok=True)


@pytest.mark.parametrize("lockfile", [True, False], ids=["mix.lock", "no-lockfile"])
class TestHexReviewKey:
    @respx.mock
    def test_review_names_the_published_package(self, tmp_path, lockfile):
        _mix_project(tmp_path, "real_pkg", lockfile=lockfile)
        _mock_hex("real_pkg", "GPL-3.0-only")
        _refuse_everything_else()

        _review(tmp_path, "hex", "real_pkg", "1.0.0")
        result, data = _check_json(tmp_path, *_FLAGS)

        assert result.exit_code == 0
        row = _rows(data)["my_alias"]
        assert row["registry_name"] == "real_pkg"
        assert row["reviewed"] is True
        assert row["package_url"] == "https://hex.pm/packages/real_pkg/1.0.0"

    @respx.mock
    def test_review_of_the_local_name_matches_nothing(self, tmp_path, lockfile):
        _mix_project(tmp_path, "real_pkg", lockfile=lockfile)
        _mock_hex("real_pkg", "GPL-3.0-only")
        _refuse_everything_else()

        _review(tmp_path, "hex", "my_alias", "1.0.0")
        output = _check_fails(tmp_path)

        assert f"{_UNMATCHED}hex:my_alias@1.0.0\n" in output
        assert "for hex it is the package's name on hex.pm" in output

    @respx.mock
    def test_review_stops_applying_when_the_name_points_at_another_package(
        self, tmp_path, lockfile
    ):
        _mock_hex("real_pkg", "GPL-3.0-only")
        _mock_hex("other_pkg", "GPL-3.0-only")
        _refuse_everything_else()
        _review(tmp_path, "hex", "real_pkg", "1.0.0")

        _mix_project(tmp_path, "real_pkg", lockfile=lockfile)
        result, _ = _check_json(tmp_path, *_FLAGS)
        assert result.exit_code == 0

        # Same local name, same version, another package: the review is void.
        _mix_project(tmp_path, "other_pkg", lockfile=lockfile)
        assert f"{_UNMATCHED}hex:real_pkg@1.0.0\n" in _check_fails(tmp_path)

    @respx.mock
    def test_scaffold_names_the_published_package(self, tmp_path, lockfile):
        _mix_project(tmp_path, "real_pkg", lockfile=lockfile)
        _mock_hex("real_pkg", "GPL-3.0-only")
        _refuse_everything_else()
        _, data = _check_json(tmp_path, *_FLAGS)
        report = tmp_path / "report.json"

        for source in ((), ("--from-report", str(report))):
            (tmp_path / REVIEW_FILE_NAME).unlink(missing_ok=True)
            result = CliRunner().invoke(
                main, ["init-review-file", "--path", str(tmp_path), *source]
            )
            assert result.exit_code == 0, result.output
            scaffold = (tmp_path / REVIEW_FILE_NAME).read_text(encoding="utf-8")
            assert 'package = "real_pkg"\nversion = "1.0.0"\n' in scaffold
            assert "my_alias" not in scaffold

        # The scaffold, once filled in, is the entry the scan applies.
        (tmp_path / REVIEW_FILE_NAME).write_text(
            scaffold.replace('license = ""', 'license = "MIT"'), encoding="utf-8", newline="\n"
        )
        result, data = _check_json(tmp_path, *_FLAGS)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == 1


class TestRegistryNameInReports:
    def _info(self, **kwargs: str) -> LicenseInfo:
        dep = Dependency(
            name="my_alias", version_constraint="==1.0.0", ecosystem=Ecosystem.HEX, **kwargs
        )
        return LicenseInfo(
            dependency=dep, license_id="UNKNOWN", license_raw="", resolved_version="1.0.0"
        )

    def test_key_is_the_published_name(self):
        assert info_review_key(self._info(registry_name="Real_Pkg")) == "hex:real_pkg@1.0.0"
        assert info_review_key(self._info()) == "hex:my_alias@1.0.0"

    def test_off_registry_row_is_keyed_on_its_own_name(self):
        info = self._info(origin="git+https://git.example.org/a.git@abc")
        assert info_review_key(info) == (
            "off-registry hex:my_alias from git+https://git.example.org/a.git@abc"
        )

    @pytest.mark.parametrize(
        ("registry_name", "expected"),
        [
            ("real_pkg", "real_pkg"),
            # Absent, empty, or not a string: the row's own name is the package.
            (None, "my_alias"),
            ("", "my_alias"),
            (["real_pkg"], "my_alias"),
        ],
    )
    def test_saved_report_supplies_the_published_name(self, tmp_path, registry_name, expected):
        row: dict = {
            "name": "my_alias",
            "ecosystem": "hex",
            "resolved_version": "1.0.0",
            "verdict": "unknown",
        }
        if registry_name is not None:
            row["registry_name"] = registry_name
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"dependencies": [row]}), encoding="utf-8")

        entries, unscaffoldable = flagged_entries_from_json_report(report)

        assert [entry.name for entry in entries] == [expected]
        assert unscaffoldable == []


# ---------------------------------------------------------- report nesting


def _result(dep: Dependency) -> CompatibilityResult:
    info = LicenseInfo(dependency=dep, license_id="MIT", license_raw="MIT", resolved_version="1.0")
    return CompatibilityResult(
        license_info=info, risk_level=RiskLevel.PERMISSIVE, verdict=CompatibilityVerdict.COMPATIBLE
    )


class TestReportNesting:
    def _nested_order(self, ecosystem: Ecosystem) -> list[str]:
        direct = Dependency(name="Parent", version_constraint="==1.0", ecosystem=ecosystem)
        other = Dependency(name="zz-last", version_constraint="==1.0", ecosystem=ecosystem)
        child = Dependency(
            name="child",
            version_constraint="==1.0",
            ecosystem=ecosystem,
            depth=1,
            direct_ancestors=("parent",),
        )
        grouped = _grouped_results([_result(other), _result(child), _result(direct)])
        return [r.license_info.dependency.name for r in grouped]

    @pytest.mark.parametrize("ecosystem", _FOLDED)
    def test_ancestor_in_another_case_is_the_same_package(self, ecosystem):
        assert self._nested_order(ecosystem) == ["Parent", "child", "zz-last"]

    @pytest.mark.parametrize("ecosystem", _EXACT)
    def test_ancestor_in_another_case_is_another_package(self, ecosystem):
        # No row is named ``parent``: the transitive is listed after the directs.
        assert self._nested_order(ecosystem) == ["Parent", "zz-last", "child"]
