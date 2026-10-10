"""CLI tests for the human-readable report formats (table and Markdown)."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import httpx
import respx
from click.testing import CliRunner

from licenseal.cli import main
from tests.test_cli import _mock_npm, _mock_pypi

_CRATES_IO_INDEX = "registry+https://github.com/rust-lang/crates.io-index"


def _mock_crate(name: str, version: str, license_str: str) -> None:
    """Mock the crates.io version and crate endpoints for one crate."""
    respx.get(f"https://crates.io/api/v1/crates/{name}/{version}").mock(
        return_value=httpx.Response(200, json={"version": {"num": version, "license": license_str}})
    )
    respx.get(f"https://crates.io/api/v1/crates/{name}").mock(
        return_value=httpx.Response(200, json={"crate": {"max_stable_version": version}})
    )


def _check(project: Path, *args: str) -> tuple[int, str]:
    """Run ``check`` and return ``(exit_code, stdout)``."""
    result = CliRunner().invoke(main, ["check", "--path", str(project), *args])
    return result.exit_code, result.stdout


def _check_to_file(project: Path, output_format: str, *args: str) -> tuple[int, str]:
    """Run ``check -o`` and return ``(exit_code, file contents)``."""
    out_file = project / f"report.{output_format}"
    result = CliRunner().invoke(
        main, ["check", "--path", str(project), "-f", output_format, "-o", str(out_file), *args]
    )
    return result.exit_code, out_file.read_text(encoding="utf-8")


def _markdown_rows(markdown: str) -> list[str]:
    """Dependency rows of the main table in a Markdown report."""
    lines = markdown.splitlines()
    start = lines.index("|Package|Ecosystem|Group|Source|License|Risk|Status|") + 2
    rows = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        rows.append(line)
    return rows


def _table_rows(table: str) -> list[str]:
    """Dependency rows of the main table in a table-format report."""
    lines = table.splitlines()
    start = next(i for i, line in enumerate(lines) if "Package" in line and "Status" in line) + 2
    rows = []
    for line in lines[start:]:
        if not line.startswith(("│", "|")):
            break
        rows.append(line)
    return rows


class TestRowCardinality:
    """Every dependency is one row, however many direct rows share its root's name."""

    @staticmethod
    def _two_locked_versions_of_one_crate(project: Path) -> None:
        # The manifest requires one major version of a crate; the lockfile also
        # holds an older one. Both versions depend on the same two crates, one
        # of them under a copyleft license.
        (project / "Cargo.toml").write_text(
            textwrap.dedent("""\
            [package]
            name = "myapp"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            parser = "2"
            """)
        )
        (project / "Cargo.lock").write_text(
            textwrap.dedent(f"""\
            version = 3

            [[package]]
            name = "copyleft-child"
            version = "0.3.0"
            source = "{_CRATES_IO_INDEX}"

            [[package]]
            name = "myapp"
            version = "0.1.0"
            dependencies = ["parser 2.0.0"]

            [[package]]
            name = "parser"
            version = "1.0.0"
            source = "{_CRATES_IO_INDEX}"
            dependencies = ["copyleft-child", "plain-child"]

            [[package]]
            name = "parser"
            version = "2.0.0"
            source = "{_CRATES_IO_INDEX}"
            dependencies = ["copyleft-child", "plain-child"]

            [[package]]
            name = "plain-child"
            version = "0.5.0"
            source = "{_CRATES_IO_INDEX}"
            """)
        )
        _mock_crate("parser", "1.0.0", "MIT")
        _mock_crate("parser", "2.0.0", "MIT")
        _mock_crate("plain-child", "0.5.0", "MIT")
        _mock_crate("copyleft-child", "0.3.0", "GPL-3.0-only")

    @respx.mock
    def test_two_locked_versions_of_a_crate_markdown(self, tmp_path):
        self._two_locked_versions_of_one_crate(tmp_path)
        _, raw_json = _check_to_file(tmp_path, "json")
        summary = json.loads(raw_json)["summary"]
        exit_code, markdown = _check_to_file(tmp_path, "markdown")

        assert exit_code == 1
        rows = _markdown_rows(markdown)
        assert len(rows) == summary["total"] == 4
        assert sum("copyleft-child" in row for row in rows) == 1
        assert sum("plain-child" in row for row in rows) == 1
        # One violation in the summary is one bullet in Details.
        assert summary["violations"] == 1
        assert "**Summary:** 1 violation, " in markdown
        assert markdown.count("- ✗ copyleft-child uses GPL-3.0-only") == 1

    @respx.mock
    def test_two_locked_versions_of_a_crate_table(self, tmp_path, monkeypatch):
        # Wide enough for one line per row on stdout, whatever the host's width.
        monkeypatch.setenv("COLUMNS", "200")
        self._two_locked_versions_of_one_crate(tmp_path)
        _, raw_json = _check_to_file(tmp_path, "json")
        summary = json.loads(raw_json)["summary"]

        for exit_code, table in (
            _check_to_file(tmp_path, "table"),
            _check(tmp_path, "-f", "table"),
        ):
            assert exit_code == 1
            rows = _table_rows(table)
            assert len(rows) == summary["total"] == 4
            assert sum("copyleft-child" in row for row in rows) == 1
            assert sum("plain-child" in row for row in rows) == 1
            assert "1 violation" in table
            assert table.count("copyleft-child uses GPL-3.0-only") == 1

    @respx.mock
    def test_nested_second_version_in_npm_lock(self, tmp_path):
        # package.json requires one major version; a nested node_modules entry
        # in the lockfile pins an older one for another package.
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "app",
                    "license": "MIT",
                    "dependencies": {"painter": "^5.0.0", "wrapper": "^1.0.0"},
                }
            )
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "app",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "app",
                            "dependencies": {"painter": "^5.0.0", "wrapper": "^1.0.0"},
                        },
                        "node_modules/painter": {
                            "version": "5.0.0",
                            "dependencies": {"palette": "^1.0.0"},
                        },
                        "node_modules/wrapper": {
                            "version": "1.0.0",
                            "dependencies": {"painter": "^4.0.0"},
                        },
                        "node_modules/wrapper/node_modules/painter": {
                            "version": "4.0.0",
                            "dependencies": {"palette": "^1.0.0"},
                        },
                        "node_modules/palette": {"version": "1.0.0"},
                    },
                }
            )
        )
        _mock_npm("painter", "MIT", version="5.0.0")
        respx.get("https://registry.npmjs.org/painter/4.0.0").mock(
            return_value=httpx.Response(200, json={"license": "MIT", "version": "4.0.0"})
        )
        _mock_npm("wrapper", "MIT")
        _mock_npm("palette", "MIT")

        _, raw_json = _check_to_file(tmp_path, "json")
        total = json.loads(raw_json)["summary"]["total"]
        exit_code, markdown = _check_to_file(tmp_path, "markdown")
        _, table = _check_to_file(tmp_path, "table")

        assert exit_code == 0
        assert len(_markdown_rows(markdown)) == total
        assert len(_table_rows(table)) == total
        assert sum("palette" in row for row in _markdown_rows(markdown)) == 1
        assert sum("palette" in row for row in _table_rows(table)) == 1

    @respx.mock
    def test_same_root_name_in_two_ecosystems(self, tmp_path):
        # A Python package and an npm package share a name; only the Python
        # one has a child. No lockfiles: the graph comes from the registries.
        (tmp_path / "requirements.txt").write_text("shared==1.0.0\n")
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": {"shared": "1.0.0"}})
        )
        for url in ("https://pypi.org/pypi/shared/json", "https://pypi.org/pypi/shared/1.0.0/json"):
            respx.get(url).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "info": {
                            "license": "MIT",
                            "version": "1.0.0",
                            "classifiers": [],
                            "requires_dist": ["python-child"],
                        },
                        "releases": {"1.0.0": []},
                    },
                )
            )
        _mock_pypi("python-child", "MIT")
        _mock_npm("shared", "MIT")

        _, raw_json = _check_to_file(tmp_path, "json")
        data = json.loads(raw_json)
        assert data["summary"]["total"] == 3
        exit_code, markdown = _check_to_file(tmp_path, "markdown")
        _, table = _check_to_file(tmp_path, "table")

        assert exit_code == 0
        rows = _markdown_rows(markdown)
        assert len(rows) == len(_table_rows(table)) == 3
        # The child follows its own ecosystem's root, not the same-named npm one.
        assert [row.split("|")[2] for row in rows] == ["npm", "python", "python"]
        assert "python-child" in rows[2]
