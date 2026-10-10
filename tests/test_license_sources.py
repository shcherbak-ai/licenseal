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


def _check(tmp_path, *args: str) -> tuple[int, dict]:
    """Run ``check`` on ``tmp_path``; return the exit code and the one dependency."""
    result = CliRunner().invoke(
        main, ["check", "--path", str(tmp_path), "--no-transitive", "-f", "json", *args]
    )
    data = json.loads(result.output[result.output.index("{") :])
    assert len(data["dependencies"]) == 1
    return result.exit_code, data["dependencies"][0]


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
