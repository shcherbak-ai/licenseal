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


def _mock_npm_registry(packages: dict[str, dict[str, object]]) -> None:
    """Serve npm metadata for ``packages`` (name -> fields of version 1.0.0).

    One route for the whole host, answered from the decoded request path, so a
    name that is not a clean URL path segment can be served like any other.
    """

    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        name = max((n for n in packages if path.startswith(f"/{n}")), key=len)
        document = {"name": name, "version": "1.0.0", **packages[name]}
        # ``/{name}`` is the packument; ``/{name}/{version}`` one version's document.
        body = {"versions": {"1.0.0": document}} if path == f"/{name}" else document
        return httpx.Response(200, json=body)

    respx.route(method="GET", host="registry.npmjs.org").mock(side_effect=respond)


class TestUntrustedStrings:
    """Markup, link syntax and control characters from manifests and registries."""

    LINK_NAME = "a](https://evil.example)[b"

    def _project(self, project: Path) -> None:
        # One direct dependency is a manifest key with a ``[`` in it; another
        # pulls in a registry-declared child whose name is Markdown link syntax
        # and whose license string carries terminal escape sequences.
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "app",
                    "license": "MIT",
                    "dependencies": {"brack[et": "1.0.0", "parent": "1.0.0"},
                }
            )
        )
        _mock_npm_registry(
            {
                "brack[et": {"license": "MIT"},
                "parent": {"license": "MIT", "dependencies": {self.LINK_NAME: "1.0.0"}},
                self.LINK_NAME: {"license": "\x1b[2JEvil\x9b31m<b>|`x`"},
            }
        )

    @respx.mock
    def test_table_renders_and_writes_file(self, tmp_path, monkeypatch):
        # Wide enough for one line per row on stdout, whatever the host's width.
        monkeypatch.setenv("COLUMNS", "300")
        self._project(tmp_path)

        exit_code, stdout = _check(tmp_path, "--no-strict")
        file_exit_code, saved = _check_to_file(tmp_path, "table", "--no-strict")

        # The unresolved license is advisory under --no-strict; nothing crashes.
        assert exit_code == file_exit_code == 0
        for table in (stdout, saved):
            assert "\x1b" not in table
            assert "\x9b" not in table
            assert "brack[et (1.0.0)" in table
            assert "Summary: 1 unknown, 2 ok" in table
        assert f"└─ {self.LINK_NAME} (1.0.0)" in stdout
        assert "\\x1b[2JEvil\\x9b31m<b>|`x`" in stdout

    @respx.mock
    def test_strict_fails_on_the_finding_not_on_rendering(self, tmp_path):
        self._project(tmp_path)
        exit_code, saved = _check_to_file(tmp_path, "table")
        assert exit_code == 1
        assert "brack[et (1.0.0)" in saved

    @respx.mock
    def test_markdown_escapes_names_and_license_strings(self, tmp_path):
        self._project(tmp_path)
        exit_code, stdout = _check(tmp_path, "-f", "markdown", "--no-strict")
        file_exit_code, saved = _check_to_file(tmp_path, "markdown", "--no-strict")

        assert exit_code == file_exit_code == 0
        assert saved == stdout
        rows = _markdown_rows(saved)
        assert rows == [
            "|[brack\\[et (1.0.0)](https://www.npmjs.com/package/brack%5Bet)|npm|prod|"
            "[package.json](package.json)|[MIT](https://spdx.org/licenses/MIT.html)|permissive|✓|",
            "|[parent (1.0.0)](https://www.npmjs.com/package/parent)|npm|prod|"
            "[package.json](package.json)|[MIT](https://spdx.org/licenses/MIT.html)|permissive|✓|",
            "|  └─ [a\\](https://evil.example)\\[b (1.0.0)]"
            "(https://www.npmjs.com/package/a%5D%28https%3A//evil.example%29%5Bb)|npm|prod||"
            "\\\\x1b\\[2JEvil\\\\x9b31m\\<b\\>\\|\\`x\\`|unknown|?|",
        ]
        assert (
            "- ? a\\](https://evil.example)\\[b uses \\\\x1b\\[2JEvil\\\\x9b31m\\<b\\>\\|\\`x\\` "
            "— could not determine compatibility with MIT"
        ) in saved.splitlines()
        assert "\x1b" not in saved

    @respx.mock
    def test_json_keeps_identity_and_raw_strings(self, tmp_path):
        self._project(tmp_path)
        _, raw_json = _check_to_file(tmp_path, "json", "--no-strict")
        deps = {d["name"]: d for d in json.loads(raw_json)["dependencies"]}

        assert set(deps) == {"brack[et", "parent", self.LINK_NAME}
        child = deps[self.LINK_NAME]
        assert child["direct_ancestors"] == ["parent"]
        assert child["license"] == child["license_raw"] == "\x1b[2JEvil\x9b31m<b>|`x`"
        assert child["package_url"] == (
            "https://www.npmjs.com/package/a%5D%28https%3A//evil.example%29%5Bb"
        )
        assert deps["brack[et"]["package_url"] == "https://www.npmjs.com/package/brack%5Bet"
        # The file itself is ASCII: JSON escapes the control characters.
        assert "\\u001b[2JEvil" in raw_json


class TestAnalysisGaps:
    """A manifest the scan could not analyze is named in the table and Markdown reports."""

    GAP_ROW = "|[broken/pyproject.toml](broken/pyproject.toml)|is not valid TOML; skipped|"
    GAP_LINE = "    broken/pyproject.toml: is not valid TOML; skipped"

    @staticmethod
    def _healthy_manifest_beside_a_broken_one(project: Path) -> None:
        (project / "requirements.txt").write_text("flask\n")
        (project / "broken").mkdir()
        (project / "broken" / "pyproject.toml").write_text("[project\nname = ")
        _mock_pypi("flask", "BSD-3-Clause")

    @respx.mock
    def test_markdown_names_the_gap(self, tmp_path):
        self._healthy_manifest_beside_a_broken_one(tmp_path)
        _, raw_json = _check_to_file(tmp_path, "json", "--no-strict")
        assert json.loads(raw_json)["summary"]["gaps"] == 1

        exit_code, stdout = _check(tmp_path, "-f", "markdown", "--no-strict")
        file_exit_code, saved = _check_to_file(tmp_path, "markdown", "--no-strict")

        # Advisory mode passes, and this is the mode a saved audit is made in:
        # the report itself has to say that a manifest is missing from it.
        assert exit_code == file_exit_code == 0
        assert saved == stdout
        lines = saved.splitlines()
        assert "**Summary:** 0 violations, 0 warnings, 0 unknown, 1 ok, 1 analysis gap" in lines
        assert "## Analysis gaps" in lines
        assert self.GAP_ROW in lines

    @respx.mock
    def test_table_names_the_gap(self, tmp_path, monkeypatch):
        monkeypatch.setenv("COLUMNS", "200")
        self._healthy_manifest_beside_a_broken_one(tmp_path)

        exit_code, stdout = _check(tmp_path, "--no-strict")
        file_exit_code, saved = _check_to_file(tmp_path, "table", "--no-strict")

        assert exit_code == file_exit_code == 0
        for table in (stdout, saved):
            lines = table.splitlines()
            assert "  Summary: 1 ok, 1 analysis gap" in lines
            assert "  Analysis gaps (their dependencies may be missing from this report):" in lines
            assert self.GAP_LINE in lines

    @respx.mock
    def test_strict_fails_and_the_saved_report_still_names_the_gap(self, tmp_path):
        self._healthy_manifest_beside_a_broken_one(tmp_path)
        exit_code, markdown = _check_to_file(tmp_path, "markdown")
        table_exit_code, table = _check_to_file(tmp_path, "table")

        assert exit_code == table_exit_code == 1
        assert self.GAP_ROW in markdown.splitlines()
        assert self.GAP_LINE in table.splitlines()

    @respx.mock
    def test_scan_with_only_an_unparseable_manifest_does_not_read_as_clean(self, tmp_path):
        (tmp_path / "package.json").write_text("{ not valid json")

        exit_code, markdown = _check_to_file(tmp_path, "markdown", "--no-strict")
        table_exit_code, table = _check_to_file(tmp_path, "table", "--no-strict")

        assert exit_code == table_exit_code == 0
        assert _markdown_rows(markdown) == []
        assert (
            "**Summary:** 0 violations, 0 warnings, 0 unknown, 0 ok, 1 analysis gap"
        ) in markdown.splitlines()
        assert "|[package.json](package.json)|is not valid JSON; skipped|" in markdown.splitlines()
        assert "  Summary: 0 ok, 1 analysis gap" in table.splitlines()
        assert "    package.json: is not valid JSON; skipped" in table.splitlines()

    @respx.mock
    def test_scan_without_gaps_has_no_gap_section(self, tmp_path, monkeypatch):
        monkeypatch.setenv("COLUMNS", "200")
        # A stray non-UTF-8 byte in a comment is recovered, not a gap.
        (tmp_path / "requirements.txt").write_bytes(b"# maintainer: Jos\xe9\nflask\n")
        _mock_pypi("flask", "BSD-3-Clause")

        _, raw_json = _check_to_file(tmp_path, "json")
        data = json.loads(raw_json)
        assert data["summary"]["gaps"] == 0
        assert [d["severity"] for d in data["diagnostics"]] == ["recovered"]
        for exit_code, report in (
            _check(tmp_path, "-f", "markdown"),
            _check_to_file(tmp_path, "markdown"),
            _check(tmp_path),
            _check_to_file(tmp_path, "table"),
        ):
            assert exit_code == 0
            assert "nalysis gap" not in report
            assert "1 ok" in report

    @respx.mock
    def test_file_outside_the_scan_root_is_named_without_its_absolute_path(self, tmp_path):
        # A manifest imports a malformed file that sits beside the project.
        project = tmp_path / "project"
        project.mkdir()
        (tmp_path / "shared").mkdir()
        (tmp_path / "shared" / "common.props").write_text("<Project><broken")
        (project / "Directory.Build.props").write_text(
            '<Project>\n  <Import Project="../shared/common.props" />\n</Project>\n'
        )
        (project / "requirements.txt").write_text("flask\n")
        _mock_pypi("flask", "BSD-3-Clause")

        _, markdown = _check_to_file(project, "markdown", "--no-strict")
        _, table = _check_to_file(project, "table", "--no-strict")

        assert (
            "|common.props (outside the project directory)|is not valid XML; skipped|"
        ) in markdown.splitlines()
        assert (
            "    common.props (outside the project directory): is not valid XML; skipped"
        ) in table.splitlines()
        # Nothing in a saved report depends on where the project was checked out.
        for report in (markdown, table):
            assert str(tmp_path) not in report
            assert tmp_path.as_posix() not in report
            assert tmp_path.name not in report
