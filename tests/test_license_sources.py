"""How the answer of each license source is read, from a manifest on disk and
mocked registry responses through ``licenseal check`` to the JSON report."""

from __future__ import annotations

import json
import textwrap

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main


def _batch_response(system: str, name: str, version: str, licenses: list[str]) -> dict:
    """deps.dev versionbatch response for one ``(system, name, version)``."""
    key = {"system": system, "name": name, "version": version}
    return {
        "responses": [
            {
                "request": {"versionKey": key},
                "version": {"versionKey": key, "licenses": licenses, "links": []},
            }
        ]
    }


def _mock_batch(system: str, name: str, version: str, licenses: list[str]) -> None:
    respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(
        return_value=httpx.Response(200, json=_batch_response(system, name, version, licenses))
    )


def _check(tmp_path, *args: str, transitive: bool = False) -> tuple[int, dict]:
    """Run ``check`` on ``tmp_path``; return the exit code and the one dependency.

    ``transitive`` leaves the default full-tree scan on, which is what reads
    a lockfile's pins.
    """
    walk = [] if transitive else ["--no-transitive"]
    result = CliRunner().invoke(
        main, ["check", "--path", str(tmp_path), *walk, "-f", "json", *args]
    )
    data = json.loads(result.output[result.output.index("{") :])
    assert len(data["dependencies"]) == 1
    return result.exit_code, data["dependencies"][0]


def _declare_project_license(tmp_path, project_license: str) -> None:
    """Give a project whose own manifest carries no license field a license."""
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "app"\nversion = "0.1.0"\nlicense = "{project_license}"\n'
    )


def _ruby_project(tmp_path, project_license: str = "MIT") -> None:
    _declare_project_license(tmp_path, project_license)
    (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "dep"\n')
    (tmp_path / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    dep (1.0.0)\n\nDEPENDENCIES\n  dep\n\n"
    )


def _mock_rubygems(licenses: list[str]) -> None:
    respx.get("https://rubygems.org/api/v2/rubygems/dep/versions/1.0.0.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "dep",
                "number": "1.0.0",
                "licenses": licenses,
                "dependencies": {"runtime": [], "development": []},
            },
        )
    )


def _hex_project(tmp_path, project_license: str = "MIT") -> None:
    _declare_project_license(tmp_path, project_license)
    (tmp_path / "mix.exs").write_text(
        "defmodule M.MixProject do\n"
        "  def project, do: [app: :m, deps: deps()]\n"
        '  defp deps, do: [{:dep, "~> 1.0"}]\n'
        "end\n"
    )
    (tmp_path / "mix.lock").write_text(
        '%{\n  "dep": {:hex, :dep, "1.0.0", "h", [:mix], [], "hexpm", "h2"},\n}\n'
    )


def _pypi_project(tmp_path, project_license: str = "MIT") -> None:
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent(f"""\
        [project]
        name = "app"
        version = "0.1.0"
        license = "{project_license}"
        dependencies = ["dep"]
        """)
    )


def _mock_pypi(info: dict) -> None:
    payload = {"info": {"version": "1.0.0", "requires_dist": [], **info}}
    for url in ("https://pypi.org/pypi/dep/json", "https://pypi.org/pypi/dep/1.0.0/json"):
        respx.get(url).mock(return_value=httpx.Response(200, json=payload))


def _mock_npm(license_value: str) -> None:
    respx.get("https://registry.npmjs.org/dep/1.0.0").mock(
        return_value=httpx.Response(200, json={"version": "1.0.0", "license": license_value})
    )


def _npm_project(tmp_path, project_license: str = "MIT") -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "license": project_license, "dependencies": {"dep": "1.0.0"}})
    )


def _maven_project(tmp_path, project_license: str) -> None:
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<modelVersion>4.0.0</modelVersion>"
        "<groupId>com.example</groupId><artifactId>app</artifactId><version>0.1.0</version>"
        f"<licenses><license><name>{project_license}</name></license></licenses>"
        "<dependencies><dependency>"
        "<groupId>com.example</groupId><artifactId>dep</artifactId><version>1.0.0</version>"
        "</dependency></dependencies>"
        "</project>"
    )


def _mock_maven_pom(*license_names: str) -> None:
    entries = "".join(f"<license><name>{name}</name></license>" for name in license_names)
    respx.get("https://repo.maven.apache.org/maven2/com/example/dep/1.0.0/dep-1.0.0.pom").mock(
        return_value=httpx.Response(
            200,
            text=(
                '<project xmlns="http://maven.apache.org/POM/4.0.0">'
                "<groupId>com.example</groupId><artifactId>dep</artifactId>"
                f"<version>1.0.0</version><licenses>{entries}</licenses></project>"
            ),
        )
    )


class TestPairRewritesBelongToTheDepsDevJoin:
    """The LGPL + GPL and CDDL + GPL-with-Classpath rewrites apply to a
    multi-entry deps.dev array and to nothing else."""

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_deps_dev_array_listing_gpl_beside_lgpl_is_the_lgpl(self, tmp_path):
        _npm_project(tmp_path)
        _mock_batch("NPM", "dep", "1.0.0", ["LGPL-3.0", "GPL-3.0"])
        exit_code, dep = _check(tmp_path, "--no-strict")
        assert exit_code == 0
        assert dep["license"] == "LGPL-3.0-only"
        # What deps.dev answered stays visible.
        assert dep["license_raw"] == "LGPL-3.0 AND GPL-3.0"
        assert dep["verdict"] == "warning"

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_deps_dev_single_entry_expression_keeps_its_operator(self, tmp_path):
        # One entry is an expression, not two license texts found side by side.
        _npm_project(tmp_path)
        _mock_batch("NPM", "dep", "1.0.0", ["GPL-3.0-only AND LGPL-3.0-only"])
        exit_code, dep = _check(tmp_path, "--no-strict")
        assert exit_code == 1
        assert dep["license"] == "GPL-3.0-only AND LGPL-3.0-only"
        assert dep["verdict"] == "incompatible"

    @respx.mock
    def test_publisher_expression_keeps_its_operator(self, tmp_path):
        _npm_project(tmp_path)
        respx.get("https://registry.npmjs.org/dep/1.0.0").mock(
            return_value=httpx.Response(
                200, json={"version": "1.0.0", "license": "GPL-3.0-only AND LGPL-3.0-only"}
            )
        )
        exit_code, dep = _check(tmp_path, "--no-strict")
        assert exit_code == 1
        assert dep["license"] == "GPL-3.0-only AND LGPL-3.0-only"
        assert dep["license_raw"] == "GPL-3.0-only AND LGPL-3.0-only"
        assert dep["verdict"] == "incompatible"

    @respx.mock
    def test_review_entry_keeps_its_operator(self, tmp_path):
        _npm_project(tmp_path)
        respx.get("https://registry.npmjs.org/dep/1.0.0").mock(
            return_value=httpx.Response(200, json={"version": "1.0.0", "license": "Custom terms"})
        )
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent("""\
            [[review]]
            ecosystem = "npm"
            package = "dep"
            version = "1.0.0"
            license = "GPL-3.0-only AND LGPL-3.0-only"
            note = "both license files apply"
            """)
        )
        exit_code, dep = _check(tmp_path)
        # A reviewed entry does not fail the check; its verdict is still judged.
        assert exit_code == 0
        assert dep["reviewed_license"] == "GPL-3.0-only AND LGPL-3.0-only"
        assert dep["license"] == "GPL-3.0-only AND LGPL-3.0-only"
        assert dep["verdict"] == "incompatible"

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_deps_dev_array_listing_the_cddl_gpl_dual_license_is_a_choice(self, tmp_path):
        _maven_project(tmp_path, "GPL-3.0-only")
        _mock_batch(
            "MAVEN", "com.example:dep", "1.0.0", ["CDDL-1.0", "GPL-2.0-with-classpath-exception"]
        )
        exit_code, dep = _check(tmp_path)
        assert exit_code == 0
        assert dep["license"] == "CDDL-1.0 OR GPL-2.0-with-classpath-exception"
        assert dep["license_raw"] == "CDDL-1.0 AND GPL-2.0-with-classpath-exception"
        assert dep["verdict"] == "compatible"

    @respx.mock
    def test_pom_listing_the_same_two_licenses_binds_both(self, tmp_path):
        # A POM's ``<licenses>`` entries are joined with AND and stay that
        # way; CDDL-1.0 is a pair-level violation in a GPL project.
        _maven_project(tmp_path, "GPL-3.0-only")
        _mock_maven_pom("CDDL-1.0", "GPL-2.0-with-classpath-exception")
        exit_code, dep = _check(tmp_path, "--no-strict")
        assert exit_code == 1
        assert dep["license"] == "CDDL-1.0 AND GPL-2.0-with-classpath-exception"
        assert dep["verdict"] == "incompatible"

    @respx.mock
    def test_pom_naming_the_dual_license_in_one_entry_is_a_choice(self, tmp_path):
        _maven_project(tmp_path, "GPL-3.0-only")
        _mock_maven_pom("CDDL + GPLv2 with classpath exception")
        exit_code, dep = _check(tmp_path)
        assert exit_code == 0
        assert dep["license"] == "CDDL-1.0 OR GPL-2.0-with-classpath-exception"
        assert dep["verdict"] == "compatible"


_UNDEFINED_LIST = "lists several licenses without stating whether they are alternatives"


class TestLicenseListWithNoDefinedMeaning:
    """A list whose source does not say whether its entries are alternatives
    is judged under both readings; when they differ the verdict is unknown."""

    @respx.mock
    def test_rubygems_array_with_a_copyleft_entry_is_unknown(self, tmp_path):
        _ruby_project(tmp_path)
        _mock_rubygems(["MIT", "GPL-3.0-only"])
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        # The reported license is the list read as a choice.
        assert dep["license"] == "GPL-3.0-only OR MIT"
        assert dep["detected_license"] == "GPL-3.0-only OR MIT"
        assert dep["license_raw"] == "MIT, GPL-3.0-only"
        assert dep["risk"] == "permissive"
        assert dep["reason"] == (
            f"dep {_UNDEFINED_LIST}: read as a choice (GPL-3.0-only OR MIT) the verdict is "
            "compatible, read as all applying (GPL-3.0-only AND MIT) it is incompatible — "
            "confirm which holds and record that expression in licenseal.review.toml"
        )

    @respx.mock
    def test_unknown_from_a_list_passes_no_strict(self, tmp_path):
        _ruby_project(tmp_path)
        _mock_rubygems(["MIT", "GPL-3.0-only"])
        exit_code, dep = _check(tmp_path, "--no-strict", transitive=True)
        assert exit_code == 0
        assert dep["verdict"] == "unknown"

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_same_gem_answered_by_deps_dev_gets_the_same_verdict(self, tmp_path):
        # deps.dev repeats the gemspec's array; rubygems.org is not asked.
        _ruby_project(tmp_path)
        _mock_batch("RUBYGEMS", "dep", "1.0.0", ["MIT", "GPL-3.0-only"])
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert dep["license"] == "GPL-3.0-only OR MIT"
        assert dep["license_raw"] == "MIT, GPL-3.0-only"
        assert _UNDEFINED_LIST in dep["reason"]

    @respx.mock
    def test_rubygems_array_whose_readings_agree_is_reported_as_before(self, tmp_path):
        _ruby_project(tmp_path)
        _mock_rubygems(["MIT", "Apache-2.0"])
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 0
        assert dep["verdict"] == "compatible"
        assert dep["license"] == "Apache-2.0 OR MIT"
        assert dep["reason"] == "Apache-2.0 OR MIT is permissive license"

    @respx.mock
    def test_ruby_license_with_its_bsd_alternative_is_a_choice(self, tmp_path):
        _ruby_project(tmp_path)
        _mock_rubygems(["Ruby", "BSD-2-Clause"])
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 0
        assert dep["verdict"] == "compatible"
        assert dep["license"] == "BSD-2-Clause OR Ruby"

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_ruby_license_with_its_bsd_alternative_from_deps_dev_is_a_choice(self, tmp_path):
        _ruby_project(tmp_path)
        _mock_batch("RUBYGEMS", "dep", "1.0.0", ["BSD-2-Clause", "Ruby"])
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 0
        assert dep["verdict"] == "compatible"
        assert dep["license"] == "BSD-2-Clause OR Ruby"

    @respx.mock
    def test_ruby_license_beside_any_other_license_is_unknown(self, tmp_path):
        _ruby_project(tmp_path)
        _mock_rubygems(["MIT", "Ruby"])
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert _UNDEFINED_LIST in dep["reason"]

    @pytest.mark.parametrize(
        "reviewed, verdict",
        [("MIT OR GPL-3.0-only", "compatible"), ("MIT AND GPL-3.0-only", "incompatible")],
    )
    @respx.mock
    def test_review_entry_records_the_confirmed_reading(self, tmp_path, reviewed, verdict):
        _ruby_project(tmp_path)
        _mock_rubygems(["MIT", "GPL-3.0-only"])
        (tmp_path / "licenseal.review.toml").write_text(
            textwrap.dedent(f"""\
            [[review]]
            ecosystem = "ruby"
            package = "dep"
            version = "1.0.0"
            license = "{reviewed}"
            note = "confirmed with the gem's LICENSE file"
            """)
        )
        exit_code, dep = _check(tmp_path, transitive=True)
        # The reviewed expression is judged as written, and a reviewed
        # dependency does not fail the check.
        assert exit_code == 0
        assert dep["reviewed"] is True
        assert dep["verdict"] == verdict
        assert _UNDEFINED_LIST not in dep["reason"]

    @respx.mock
    def test_hex_array_with_a_copyleft_entry_is_unknown(self, tmp_path):
        _hex_project(tmp_path)
        respx.get("https://hex.pm/api/packages/dep").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"licenses": ["Apache-2.0", "GPL-3.0-only"], "links": {}},
                    "latest_stable_version": "1.0.0",
                },
            )
        )
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert dep["license"] == "Apache-2.0 OR GPL-3.0-only"
        assert dep["license_raw"] == "Apache-2.0, GPL-3.0-only"
        assert _UNDEFINED_LIST in dep["reason"]

    @pytest.mark.parametrize("declared", ["MIT, GPL-3.0-only", "MIT/GPL-3.0-only"])
    @respx.mock
    def test_list_in_one_license_string_is_unknown(self, tmp_path, declared):
        _pypi_project(tmp_path)
        _mock_pypi({"license": declared})
        exit_code, dep = _check(tmp_path)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert dep["license"] == "GPL-3.0-only OR MIT"
        assert dep["license_raw"] == declared
        assert _UNDEFINED_LIST in dep["reason"]

    @respx.mock
    def test_list_in_a_nuget_license_expression_is_unknown(self, tmp_path):
        _declare_project_license(tmp_path, "MIT")
        (tmp_path / "app.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<PackageReference Include="Dep" Version="1.0.0" />'
            "</ItemGroup></Project>"
        )
        respx.get("https://api.nuget.org/v3-flatcontainer/dep/1.0.0/dep.nuspec").mock(
            return_value=httpx.Response(
                200,
                text=(
                    "<package><metadata><id>Dep</id>"
                    '<license type="expression">MIT/GPL-3.0-only</license>'
                    "</metadata></package>"
                ),
            )
        )
        exit_code, dep = _check(tmp_path)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert dep["license"] == "GPL-3.0-only OR MIT"
        assert _UNDEFINED_LIST in dep["reason"]

    @respx.mock
    def test_list_in_one_composer_license_string_is_unknown(self, tmp_path):
        # Composer defines an array of licenses as a choice, not a comma
        # inside one string.
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "acme/app", "license": "MIT", "require": {"acme/dep": "^1.0"}})
        )
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {"name": "acme/dep", "version": "1.0.0", "license": "MIT, GPL-3.0-only"}
                    ]
                }
            )
        )
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert _UNDEFINED_LIST in dep["reason"]

    @respx.mock
    def test_list_in_one_packagist_license_string_is_unknown(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "acme/app", "license": "MIT", "require": {"acme/dep": "1.0.0"}})
        )
        respx.get("https://repo.packagist.org/p2/acme/dep.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "packages": {"acme/dep": [{"version": "1.0.0", "license": "MIT, GPL-3.0-only"}]}
                },
            )
        )
        exit_code, dep = _check(tmp_path)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert _UNDEFINED_LIST in dep["reason"]

    @respx.mock
    def test_comma_list_in_a_cargo_license_is_unknown(self, tmp_path):
        # Cargo documents ``/`` as a choice; it says nothing about a comma.
        (tmp_path / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "app"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            dep = "=1.0.0"
            """)
        )
        respx.get("https://crates.io/api/v1/crates/dep/1.0.0").mock(
            return_value=httpx.Response(
                200, json={"version": {"num": "1.0.0", "license": "MIT, GPL-3.0-only"}}
            )
        )
        respx.get("https://crates.io/api/v1/crates/dep").mock(
            return_value=httpx.Response(200, json={"crate": {"repository": ""}})
        )
        exit_code, dep = _check(tmp_path)
        assert exit_code == 1
        assert dep["verdict"] == "unknown"
        assert _UNDEFINED_LIST in dep["reason"]

    @pytest.mark.parametrize(
        "project_license, exit_code, verdict",
        [
            # Both entries suit an MIT project under either reading.
            ("MIT", 0, "compatible"),
            # Apache-2.0 conflicts with GPL-2.0-only, so the readings differ.
            ("GPL-2.0-only", 1, "unknown"),
        ],
    )
    @respx.mock
    def test_slash_list_from_a_source_that_does_not_define_the_slash(
        self, tmp_path, project_license, exit_code, verdict
    ):
        _npm_project(tmp_path, project_license)
        _mock_npm("MIT/Apache-2.0")
        code, dep = _check(tmp_path)
        assert code == exit_code
        assert dep["verdict"] == verdict
        assert dep["license"] == "Apache-2.0 OR MIT"

    @respx.mock
    def test_explicit_expression_is_the_control(self, tmp_path):
        _npm_project(tmp_path, "GPL-2.0-only")
        _mock_npm("MIT OR Apache-2.0")
        exit_code, dep = _check(tmp_path)
        assert exit_code == 0
        assert dep["verdict"] == "compatible"

    @pytest.mark.parametrize(
        "declared",
        [
            "MIT/Apache-2.0 and GPL-3.0-only",
            "MIT, Apache-2.0 or GPL-3.0-only",
            "HTTPS://Example.com/licenses/MIT",
            "https://Example.com/MIT/Apache-2.0",
        ],
    )
    @respx.mock
    def test_list_mixed_with_a_connector_and_url_are_not_read_as_a_list(self, tmp_path, declared):
        _npm_project(tmp_path)
        _mock_npm(declared)
        exit_code, dep = _check(tmp_path)
        assert exit_code == 1
        assert dep["license"] == "UNKNOWN"
        assert dep["license_raw"] == declared
        assert dep["verdict"] == "unknown"


class TestLicenseListWithADefinedMeaning:
    """Sources that define what their list means keep that meaning."""

    @respx.mock
    def test_cargo_slash_is_a_choice(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "app"
            version = "0.1.0"
            license = "GPL-2.0-only"

            [dependencies]
            dep = "=1.0.0"
            """)
        )
        respx.get("https://crates.io/api/v1/crates/dep/1.0.0").mock(
            return_value=httpx.Response(
                200, json={"version": {"num": "1.0.0", "license": "MIT/Apache-2.0"}}
            )
        )
        respx.get("https://crates.io/api/v1/crates/dep").mock(
            return_value=httpx.Response(200, json={"crate": {"repository": ""}})
        )
        exit_code, dep = _check(tmp_path)
        assert exit_code == 0
        assert dep["license"] == "Apache-2.0 OR MIT"
        assert dep["verdict"] == "compatible"

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_cargo_slash_answered_by_deps_dev_is_a_choice(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "app"
            version = "0.1.0"
            license = "GPL-2.0-only"

            [dependencies]
            dep = "=1.0.0"
            """)
        )
        _mock_batch("CARGO", "dep", "1.0.0", ["MIT/Apache-2.0"])
        exit_code, dep = _check(tmp_path)
        assert exit_code == 0
        assert dep["license"] == "Apache-2.0 OR MIT"
        assert dep["verdict"] == "compatible"

    @respx.mock
    def test_composer_license_array_is_a_choice(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "acme/app", "license": "MIT", "require": {"acme/dep": "^1.0"}})
        )
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "acme/dep",
                            "version": "1.0.0",
                            "license": ["MIT", "GPL-3.0-only"],
                        }
                    ]
                }
            )
        )
        exit_code, dep = _check(tmp_path, transitive=True)
        assert exit_code == 0
        assert dep["license"] == "GPL-3.0-only OR MIT"
        assert dep["license_raw"] == "MIT OR GPL-3.0-only"
        assert dep["verdict"] == "compatible"

    @pytest.mark.no_default_deps_dev_mock
    @respx.mock
    def test_deps_dev_array_is_a_conjunction(self, tmp_path):
        _npm_project(tmp_path)
        _mock_batch("NPM", "dep", "1.0.0", ["MIT", "GPL-3.0-only"])
        exit_code, dep = _check(tmp_path, "--no-strict")
        assert exit_code == 1
        assert dep["license"] == "GPL-3.0-only AND MIT"
        assert dep["verdict"] == "incompatible"

    @respx.mock
    def test_pom_license_entries_are_a_conjunction(self, tmp_path):
        _maven_project(tmp_path, "MIT")
        _mock_maven_pom("MIT", "GPL-3.0-only")
        exit_code, dep = _check(tmp_path, "--no-strict")
        assert exit_code == 1
        assert dep["license"] == "MIT AND GPL-3.0-only"
        assert dep["verdict"] == "incompatible"

    @respx.mock
    def test_list_inside_one_pom_entry_is_not_defined_by_the_pom(self, tmp_path):
        _maven_project(tmp_path, "GPL-2.0-only")
        _mock_maven_pom("MIT/Apache-2.0")
        exit_code, dep = _check(tmp_path)
        assert exit_code == 1
        assert dep["license"] == "Apache-2.0 OR MIT"
        assert dep["verdict"] == "unknown"
        assert _UNDEFINED_LIST in dep["reason"]
