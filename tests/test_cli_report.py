"""CLI tests for the human-readable report formats (table and Markdown)."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import textwrap
from pathlib import Path

import httpx
import pytest
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


@pytest.fixture(autouse=True)
def _stdout_is_an_80_column_pipe(monkeypatch):
    """Give ``check`` the console a CI log gets, whatever the host terminal is.

    ``check`` builds its stdout console from the environment. Left alone, a
    host that forces terminal mode would put escape sequences into the
    captured output, and the console width would follow the terminal the
    tests happen to run in.
    """
    for name in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE", "NO_COLOR", "LINES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "80")


def _check(project: Path, *args: str, charset: str = "utf-8") -> tuple[int, str]:
    """Run ``check`` and return ``(exit_code, stdout)``.

    ``charset`` is the encoding of the emulated stdout; its error handler is
    strict, as a redirected stdout's is.
    """
    result = CliRunner(charset=charset).invoke(main, ["check", "--path", str(project), *args])
    return result.exit_code, result.stdout


def _check_to_file(
    project: Path, output_format: str, *args: str, charset: str = "utf-8"
) -> tuple[int, str]:
    """Run ``check -o`` and return ``(exit_code, file contents)``."""
    out_file = project / f"report.{output_format}"
    result = CliRunner(charset=charset).invoke(
        main, ["check", "--path", str(project), "-f", output_format, "-o", str(out_file), *args]
    )
    return result.exit_code, out_file.read_text(encoding="utf-8")


def _mock_pypi_package(name: str, license_str: str, requires: tuple[str, ...] = ()) -> None:
    """Mock PyPI for version 1.0.0 of ``name``, declaring ``requires`` as its dependencies."""
    payload = {
        "info": {
            "license": license_str,
            "version": "1.0.0",
            "classifiers": [],
            "requires_dist": list(requires),
        },
        "releases": {"1.0.0": []},
    }
    for url in (f"https://pypi.org/pypi/{name}/json", f"https://pypi.org/pypi/{name}/1.0.0/json"):
        respx.get(url).mock(return_value=httpx.Response(200, json=payload))


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
    def test_two_locked_versions_of_a_crate_table(self, tmp_path):
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
        _mock_pypi_package("shared", "MIT", requires=("python-child",))
        _mock_pypi_package("python-child", "MIT")
        _mock_npm("shared", "MIT")

        _, raw_json = _check_to_file(tmp_path, "json")
        data = json.loads(raw_json)
        assert data["summary"]["total"] == 3
        exit_code, markdown = _check_to_file(tmp_path, "markdown", "--no-require-lockfile")
        _, table = _check_to_file(tmp_path, "table", "--no-require-lockfile")

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
    def test_table_renders_and_writes_file(self, tmp_path):
        self._project(tmp_path)

        exit_code, stdout = _check(tmp_path, "--no-strict")
        file_exit_code, saved = _check_to_file(tmp_path, "table", "--no-strict")

        # The unresolved license is advisory under --no-strict; nothing crashes.
        assert exit_code == file_exit_code == 0
        for table in (stdout, saved):
            assert "\x1b" not in table
            assert "\x9b" not in table
            assert "brack[et (1.0.0)" in table
            # The child's version was picked by the registry walk: marked.
            assert f"└─ {self.LINK_NAME} (~1.0.0)" in table
            assert "\\x1b[2JEvil\\x9b31m<b>|`x`" in table
            assert "Summary: 1 unknown, 2 ok" in table

    @respx.mock
    def test_strict_fails_on_the_finding_not_on_rendering(self, tmp_path):
        self._project(tmp_path)
        exit_code, saved = _check_to_file(tmp_path, "table", "--no-require-lockfile")
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
            "|  └─ [a\\](https://evil.example)\\[b (~1.0.0)]"
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

    @staticmethod
    def _project_with_lone_surrogates(project: Path) -> None:
        # An unpaired ``\uD800``-style JSON escape decodes to a lone surrogate,
        # which no encoding can write. One is in a manifest key; a registry
        # answer puts one in a child's name and one in a license string.
        manifest = {
            "name": "app",
            "license": "MIT",
            "dependencies": {"bad\ud800name": "1.0.0", "parent": "1.0.0"},
        }
        (project / "package.json").write_text(json.dumps(manifest), encoding="ascii")
        documents = {
            "parent": {
                "license": "MIT",
                "dependencies": {"odd-license": "1.0.0", "evil\udfffchild": "1.0.0"},
            },
            "odd-license": {"license": "Odd\ud800License"},
        }
        for name, fields in documents.items():
            body = json.dumps({"name": name, "version": "1.0.0", **fields})
            assert body.isascii()
            respx.get(f"https://registry.npmjs.org/{name}/1.0.0").mock(
                return_value=httpx.Response(200, content=body.encode("ascii"))
            )

    @respx.mock
    def test_lone_surrogates_are_written_in_every_format(self, tmp_path):
        self._project_with_lone_surrogates(tmp_path)
        shown = {
            "table": ("bad\\ud800name", "evil\\udfffchild", "Odd\\ud800License"),
            "markdown": ("bad\\\\ud800name", "evil\\\\udfffchild", "Odd\\\\ud800License"),
            "json": ('"bad\\ud800name"', '"evil\\udfffchild"', '"Odd\\ud800License"'),
        }
        for output_format, expected in shown.items():
            exit_code, stdout = _check(tmp_path, "-f", output_format, "--no-strict")
            file_exit_code, saved = _check_to_file(tmp_path, output_format, "--no-strict")
            assert exit_code == file_exit_code == 0, output_format
            for report in (stdout, saved):
                for text in expected:
                    assert text in report, output_format
                # Nothing the stream or the UTF-8 file could not encode.
                assert not re.search("[\ud800-\udfff\ufffd]", report), output_format

    @respx.mock
    def test_lone_surrogates_keep_identity_in_json_and_fail_strict_cleanly(self, tmp_path):
        self._project_with_lone_surrogates(tmp_path)
        _, raw_json = _check_to_file(tmp_path, "json", "--no-strict")
        deps = {d["name"]: d for d in json.loads(raw_json)["dependencies"]}
        assert set(deps) == {"bad\ud800name", "parent", "odd-license", "evil\udfffchild"}
        assert deps["bad\ud800name"]["verdict"] == "unknown"
        assert deps["bad\ud800name"]["package_url"] == (
            "https://www.npmjs.com/package/bad%ED%A0%80name"
        )
        assert deps["evil\udfffchild"]["direct_ancestors"] == ["parent"]
        odd = deps["odd-license"]
        assert odd["license"] == odd["license_raw"] == "Odd\ud800License"
        assert odd["verdict"] == "unknown"

        # Strict mode fails on the findings, and says so on stderr, for a
        # report saved in any format.
        for output_format in ("table", "markdown", "json"):
            out_file = tmp_path / f"strict.{output_format}"
            result = CliRunner().invoke(
                main,
                [
                    "check",
                    "--path",
                    str(tmp_path),
                    "--no-require-lockfile",
                    "-f",
                    output_format,
                    "-o",
                    str(out_file),
                ],
            )
            assert result.exit_code == 1
            assert isinstance(result.exception, SystemExit)
            assert (
                "License check failed: 0 violations, 0 warnings, 3 unknown, 1 ok" in result.stderr
            )
            assert "bad\\ud800name" in result.stderr
            assert out_file.read_text(encoding="utf-8")


def _mock_npm_registry_with_misses(packages: dict[str, dict[str, object]]) -> None:
    """Like :func:`_mock_npm_registry`, with a 404 for every package not in ``packages``.

    The deps.dev lookup the npm resolver falls back to answers 404 as well,
    so a missing package stays unresolved.
    """

    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        known = [name for name in packages if path.startswith(f"/{name}")]
        if not known:
            return httpx.Response(404)
        name = max(known, key=len)
        document = {"name": name, "version": "1.0.0", **packages[name]}
        body = {"versions": {"1.0.0": document}} if path == f"/{name}" else document
        return httpx.Response(200, json=body)

    respx.route(method="GET", host="registry.npmjs.org").mock(side_effect=respond)
    respx.route(method="GET", host="api.deps.dev").mock(return_value=httpx.Response(404))


class TestUntrustedStringsOnStderr:
    """The lines ``check`` and ``init-review-file`` write to stderr show a
    control character, a bidirectional control or a lone surrogate from a
    manifest, a registry or the review file escaped, as the report body does.
    Every assertion is on the bytes the stream received."""

    # Each name with the form it is shown in.
    HOSTILE = {
        "osc\x1b]0;title\x07x": b"osc\\x1b]0;title\\x07x",
        "bell\x07name": b"bell\\x07name",
        "c1\x9b31mname": b"c1\\x9b31mname",
        "rtl\u202ename": b"rtl\\u202ename",
        "iso\u2066late": b"iso\\u2066late",
    }
    # What must not reach the terminal: ESC, BEL, the C1 control sequence
    # introducer, and the two bidirectional controls, as UTF-8.
    RAW = (b"\x1b", b"\x07", b"\xc2\x9b", b"\xe2\x80\xae", b"\xe2\x81\xa6")

    @staticmethod
    def _run(*args: str) -> tuple[int, bytes, bytes]:
        result = CliRunner().invoke(main, list(args))
        return result.exit_code, result.stdout_bytes, result.stderr_bytes

    def _assert_no_raw_bytes(self, stream: bytes) -> None:
        for raw in self.RAW:
            assert raw not in stream, raw

    def _project(self, project: Path, declared_in: str, spec: str = "1.0.0") -> None:
        # The names are dependency keys of the manifest, or the dependencies
        # a registry answer declares for a package. No registry has them.
        hostile = dict.fromkeys(self.HOSTILE, spec)
        direct = {"parent": "1.0.0", **(hostile if declared_in == "manifest" else {})}
        (project / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": direct}),
            encoding="ascii",
        )
        _mock_npm_registry_with_misses(
            {
                "parent": {
                    "license": "MIT",
                    "dependencies": hostile if declared_in == "registry" else {},
                }
            }
        )

    @pytest.mark.parametrize("declared_in", ["manifest", "registry"])
    @respx.mock
    def test_diagnostics_show_names_escaped(self, tmp_path, declared_in):
        self._project(tmp_path, declared_in)
        exit_code, _, stderr = self._run(
            "check", "--path", str(tmp_path), "--no-require-lockfile", "--no-strict", "-f", "json"
        )
        assert exit_code == 0
        for shown in self.HOSTILE.values():
            assert (
                b"Warning: package.json: the dependencies of " + shown + b" 1.0.0 could not be "
                b"read from the registry; its transitive dependencies may be missing"
            ) in stderr.splitlines()
        self._assert_no_raw_bytes(stderr)

    @pytest.mark.parametrize("declared_in", ["manifest", "registry"])
    @pytest.mark.parametrize("output_format", ["table", "markdown", "json"])
    @respx.mock
    def test_failure_message_shows_names_escaped(self, tmp_path, declared_in, output_format):
        self._project(tmp_path, declared_in)
        out_file = tmp_path / f"report.{output_format}"
        exit_code, _, stderr = self._run(
            "check",
            "--path",
            str(tmp_path),
            "--no-require-lockfile",
            "-f",
            output_format,
            "-o",
            str(out_file),
        )
        assert exit_code == 1
        lines = stderr.splitlines()
        assert b"License check failed: 0 violations, 0 warnings, 5 unknown, 1 ok" in lines
        for shown in self.HOSTILE.values():
            reason = "has no license information — manual review required".encode()
            assert b"  ? " + shown + b" " + reason in lines
        self._assert_no_raw_bytes(stderr)
        saved = out_file.read_bytes()
        if output_format == "json":
            # The report keeps the names as they are; JSON writes them as
            # ASCII escapes of its own.
            names = {dep["name"] for dep in json.loads(saved)["dependencies"]}
            assert names == {"parent", *self.HOSTILE}
        self._assert_no_raw_bytes(saved)

    @pytest.mark.parametrize("declared_in", ["manifest", "registry"])
    @respx.mock
    def test_init_review_file_note_shows_names_escaped(self, tmp_path, declared_in):
        # A range no registry answers for leaves a dependency with no
        # version to key a review on, and the note names it.
        self._project(tmp_path, declared_in, spec="^1.0.0")
        exit_code, _, stderr = self._run("init-review-file", "--path", str(tmp_path))
        assert exit_code == 0
        assert (
            b"Note: 5 flagged dependencies could not be scaffolded (no resolved version, "
            b"usually a manifest typo / yanked release / registry miss): "
            + b", ".join(b"npm:" + shown for shown in sorted(self.HOSTILE.values()))
            + b"."
        ) in stderr.splitlines()
        self._assert_no_raw_bytes(stderr)

    @pytest.mark.parametrize("declared_in", ["manifest", "registry"])
    @respx.mock
    def test_init_review_file_diagnostics_show_names_escaped(self, tmp_path, declared_in):
        self._project(tmp_path, declared_in)
        exit_code, stdout, stderr = self._run("init-review-file", "--path", str(tmp_path))
        assert exit_code == 0
        assert stdout.splitlines() == [b"Wrote licenseal.review.toml with 5 review entries."]
        for shown in self.HOSTILE.values():
            assert (
                b"Warning: package.json: the dependencies of " + shown + b" 1.0.0 could not be "
                b"read from the registry; its transitive dependencies may be missing"
            ) in stderr.splitlines()
        self._assert_no_raw_bytes(stderr)

    @staticmethod
    def _reviewed_project(project: Path, review: str) -> None:
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "app",
                    "license": "MIT",
                    "dependencies": {"parent": "1.0.0", "rtl\u202ename": "1.0.0"},
                }
            ),
            encoding="ascii",
        )
        _mock_npm_registry_with_misses(
            {"parent": {"license": "MIT"}, "rtl\u202ename": {"license": "MIT"}}
        )
        (project / "licenseal.review.toml").write_text(review, encoding="utf-8")

    # A review entry whose package holds an escape sequence and a
    # bidirectional override, written as TOML escapes.
    _STANZA = (
        '[[review]]\necosystem = "npm"\npackage = "evil\\u001B[2J\\u202Epkg"\n'
        'version = "1.0.0"\nlicense = "{}"\n'
    )
    _SHOWN_KEY = b"npm:evil\\x1b[2J\\u202epkg@1.0.0"

    @pytest.mark.parametrize(
        "review, exit_code, message",
        [
            (
                _STANZA.format(""),
                0,
                b"Warning: incomplete review entries were not applied: " + _SHOWN_KEY,
            ),
            (
                _STANZA.format("MIT") * 2,
                1,
                b"Error: Invalid licenseal.review.toml: duplicate review entry for "
                + _SHOWN_KEY
                + b".",
            ),
            (
                _STANZA.format("MIT"),
                1,
                b"Error: Reviewed licenses did not match any resolved package versions: "
                + _SHOWN_KEY,
            ),
            (
                '[[review]]\necosystem = "npm"\npackage = "rtl\\u202Ename"\n'
                'version = "1.0.0"\nlicense = "MIT"\n',
                1,
                b"Error: Review entries can only override flagged dependencies; these match "
                b"already-compatible dependencies and should be removed: "
                b"npm:rtl\\u202ename@1.0.0",
            ),
            (
                _STANZA.format("evil\\u001B[2J\\u202E terms"),
                1,
                b"Error: Invalid reviewed license 'evil\\x1b[2J\\u202e terms'. Use a valid SPDX "
                b"ID or SPDX expression.",
            ),
        ],
        ids=["incomplete", "duplicate", "unmatched", "not-flagged", "invalid-license"],
    )
    @respx.mock
    def test_review_file_messages_show_entries_escaped(self, tmp_path, review, exit_code, message):
        self._reviewed_project(tmp_path, review)
        code, _, stderr = self._run(
            "check", "--path", str(tmp_path), "--no-require-lockfile", "-f", "json"
        )
        assert code == exit_code
        assert message in stderr.splitlines()
        self._assert_no_raw_bytes(stderr)

    @respx.mock
    def test_review_file_that_does_not_parse_is_reported_escaped(self, tmp_path):
        self._reviewed_project(tmp_path, '[[review]]\npackage = "evil\x1b[2J\u202epkg"\n')
        code, _, stderr = self._run(
            "check", "--path", str(tmp_path), "--no-require-lockfile", "-f", "json"
        )
        assert code == 1
        assert b"Error: Invalid licenseal.review.toml: " in stderr
        self._assert_no_raw_bytes(stderr)

    @respx.mock
    def test_project_license_lines_show_the_declared_value_escaped(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT\u202e\x1b[2J"}), encoding="ascii"
        )
        exit_code, _, stderr = self._run("check", "--path", str(tmp_path), "-f", "json")
        assert exit_code == 0
        assert (
            b"Warning: package.json declares the license 'MIT\\u202e\\x1b[2J', which is not a "
            b"recognised license; dependencies are checked against Proprietary."
        ) in stderr.splitlines()
        self._assert_no_raw_bytes(stderr)

    @staticmethod
    def _installed_skill(project: Path, body: str, stamped_version: str) -> Path:
        skill = project / ".claude" / "skills" / "licenseal-review" / "SKILL.md"
        skill.parent.mkdir(parents=True)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        skill.write_text(
            f"{body}\n<!-- licenseal-skill-version: {stamped_version} -->\n"
            f"<!-- licenseal-skill-body-sha256: {digest} -->\n",
            encoding="utf-8",
            newline="\n",
        )
        return skill

    def test_skill_version_of_an_installed_skill_is_shown_escaped(self, tmp_path):
        # The version is read back from a file of the scanned project.
        self._installed_skill(tmp_path, "an older skill", "0.0.1\x1b[2J\u202e")
        exit_code, _, stderr = self._run("check", "--path", str(tmp_path), "-f", "json")
        assert exit_code == 0
        assert b"Installed Claude skill (from licenseal 0.0.1\\x1b[2J\\u202e) is out of date" in (
            stderr
        )
        self._assert_no_raw_bytes(stderr)

        exit_code, stdout, stderr = self._run("install-skill", "--path", str(tmp_path))
        assert exit_code == 0
        assert b"Refreshed licenseal skill 0.0.1\\x1b[2J\\u202e " in stdout
        self._assert_no_raw_bytes(stdout + stderr)


class TestBidirectionalControlsAndEmphasis:
    """The table and Markdown reports show a bidirectional control escaped,
    and Markdown shows ``*`` as a character."""

    @staticmethod
    def _project(project: Path) -> None:
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "app",
                    "license": "MIT",
                    "dependencies": {
                        "rtl\u202ename": "1.0.0",
                        "snake_case_name": "1.0.0",
                        "star*name": "1.0.0",
                    },
                }
            ),
            encoding="ascii",
        )
        _mock_npm_registry(
            {
                "rtl\u202ename": {"license": "MIT"},
                "snake_case_name": {"license": "MIT"},
                "star*name": {"license": "**Custom** terms\u2067"},
            }
        )

    @respx.mock
    def test_table_shows_bidirectional_controls_escaped(self, tmp_path):
        self._project(tmp_path)
        exit_code, stdout = _check(tmp_path, "--no-strict")
        file_exit_code, saved = _check_to_file(tmp_path, "table", "--no-strict")
        assert exit_code == file_exit_code == 0
        for table in (stdout, saved):
            assert "rtl\\u202ename (1.0.0)" in table
            assert "star*name declares '**Custom** terms\\u2067' which did not resolve" in (
                " ".join(table.split())
            )
            assert not re.search("[\u202a-\u202e\u2066-\u2069]", table)

    @respx.mock
    def test_markdown_escapes_bidirectional_controls_and_asterisks(self, tmp_path):
        self._project(tmp_path)
        exit_code, stdout = _check(tmp_path, "-f", "markdown", "--no-strict")
        file_exit_code, saved = _check_to_file(tmp_path, "markdown", "--no-strict")
        assert exit_code == file_exit_code == 0
        assert saved == stdout
        assert _markdown_rows(saved) == [
            "|[rtl\\\\u202ename (1.0.0)](https://www.npmjs.com/package/rtl%E2%80%AEname)|npm|prod|"
            "[package.json](package.json)|[MIT](https://spdx.org/licenses/MIT.html)|permissive|✓|",
            # An underscore inside a word starts no emphasis: left as it is.
            "|[snake_case_name (1.0.0)](https://www.npmjs.com/package/snake_case_name)|npm|prod|"
            "[package.json](package.json)|[MIT](https://spdx.org/licenses/MIT.html)|permissive|✓|",
            "|[star\\*name (1.0.0)](https://www.npmjs.com/package/star%2Aname)|npm|prod|"
            "[package.json](package.json)|UNKNOWN|unknown|?|",
        ]
        assert (
            "- ? star\\*name declares '\\*\\*Custom\\*\\* terms\\\\u2067' which did not resolve "
            "to a recognized license — manual review required"
        ) in saved.splitlines()
        assert not re.search("[\u202a-\u202e\u2066-\u2069]", saved)

    @respx.mock
    def test_json_reports_the_original_strings(self, tmp_path):
        self._project(tmp_path)
        _, raw_json = _check_to_file(tmp_path, "json", "--no-strict")
        deps = {dep["name"]: dep for dep in json.loads(raw_json)["dependencies"]}
        assert set(deps) == {"rtl\u202ename", "snake_case_name", "star*name"}
        assert deps["star*name"]["license_raw"] == "**Custom** terms\u2067"
        assert "declares '**Custom** terms\u2067' which" in deps["star*name"]["reason"]


class TestDirectionMarksAndLineSeparators:
    """A direction mark and a line or paragraph separator in a name are shown
    escaped in the table, in Markdown and on stderr. A zero-width character
    is left as it is: a joiner is part of the spelling in some scripts."""

    NAME = "m\u200ea\u200fr\u061ck\u2028s\u2029x"
    SHOWN = "m\\u200ea\\u200fr\\u061ck\\u2028s\\u2029x"
    JOINED = "zero\u200dwidth"
    ESCAPED = re.compile("[\u061c\u200e\u200f\u2028\u2029]")

    def _project(self, project: Path) -> None:
        # No registry has the two packages, so both rows are unresolved and
        # both names reach the diagnostics.
        dependencies = {"parent": "1.0.0", self.NAME: "1.0.0", self.JOINED: "1.0.0"}
        (project / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": dependencies}),
            encoding="ascii",
        )
        _mock_npm_registry_with_misses({"parent": {"license": "MIT"}})

    @respx.mock
    def test_stderr_shows_the_name_escaped(self, tmp_path):
        self._project(tmp_path)
        out_file = tmp_path / "report.json"
        result = CliRunner().invoke(
            main,
            [
                "check",
                "--path",
                str(tmp_path),
                "--no-require-lockfile",
                "-f",
                "json",
                "-o",
                str(out_file),
            ],
        )
        assert result.exit_code == 1
        lines = result.stderr_bytes.splitlines()
        for name in (self.SHOWN.encode(), self.JOINED.encode()):
            assert (
                b"Warning: package.json: the dependencies of " + name + b" 1.0.0 could not be "
                b"read from the registry; its transitive dependencies may be missing"
            ) in lines
            reason = "has no license information — manual review required".encode()
            assert b"  ? " + name + b" " + reason in lines
        assert not self.ESCAPED.search(result.stderr_bytes.decode("utf-8"))
        # The JSON report keeps both names as they are.
        saved = json.loads(out_file.read_text(encoding="utf-8"))
        names = {dep["name"] for dep in saved["dependencies"]}
        assert names == {"parent", self.NAME, self.JOINED}

    @respx.mock
    def test_table_and_markdown_show_the_name_escaped(self, tmp_path):
        self._project(tmp_path)
        exit_code, table = _check_to_file(tmp_path, "table", "--no-strict")
        md_exit_code, markdown = _check_to_file(tmp_path, "markdown", "--no-strict")
        assert exit_code == md_exit_code == 0
        assert f"{self.SHOWN} (1.0.0)" in table
        assert f"{self.JOINED} (1.0.0)" in table
        doubled = self.SHOWN.replace("\\", "\\\\")
        assert f"|[{doubled} (1.0.0)](https://www.npmjs.com/package/" in markdown
        assert f"|[{self.JOINED} (1.0.0)](https://www.npmjs.com/package/" in markdown
        for report in (table, markdown):
            assert not self.ESCAPED.search(report)


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

    # The healthy manifest has no lockfile. These scans accept that, so the
    # broken manifest is the one gap; the estimate is listed apart from it.
    ADVISORY = ("--no-strict", "--no-require-lockfile")
    ESTIMATE_ROW = (
        "|[requirements.txt](requirements.txt)|declares dependencies that no lockfile covers; "
        "their versions and transitive dependencies are estimated from the registry|"
    )

    @respx.mock
    def test_markdown_names_the_gap(self, tmp_path):
        self._healthy_manifest_beside_a_broken_one(tmp_path)
        _, raw_json = _check_to_file(tmp_path, "json", *self.ADVISORY)
        assert json.loads(raw_json)["summary"]["gaps"] == 1

        exit_code, stdout = _check(tmp_path, "-f", "markdown", *self.ADVISORY)
        file_exit_code, saved = _check_to_file(tmp_path, "markdown", *self.ADVISORY)

        # Advisory mode passes, and this is the mode a saved audit is made in:
        # the report itself has to say that a manifest is missing from it.
        assert exit_code == file_exit_code == 0
        assert saved == stdout
        lines = saved.splitlines()
        assert (
            "**Summary:** 0 violations, 0 warnings, 0 unknown, 1 ok, 1 analysis gap, "
            "1 estimated manifest"
        ) in lines
        gaps, estimates = lines.index("## Analysis gaps"), lines.index("## Estimates")
        assert lines.index(self.GAP_ROW) in range(gaps, estimates)
        assert lines.index(self.ESTIMATE_ROW) > estimates

    @respx.mock
    def test_table_names_the_gap(self, tmp_path):
        self._healthy_manifest_beside_a_broken_one(tmp_path)

        exit_code, stdout = _check(tmp_path, *self.ADVISORY)
        file_exit_code, saved = _check_to_file(tmp_path, "table", *self.ADVISORY)

        assert exit_code == file_exit_code == 0
        for table in (stdout, saved):
            lines = table.splitlines()
            assert "  Summary: 1 ok, 1 analysis gap, 1 estimated manifest" in lines
            assert "  Analysis gaps (their dependencies may be missing from this report):" in lines
            assert self.GAP_LINE in lines

    @respx.mock
    def test_strict_fails_and_the_saved_report_still_names_the_gap(self, tmp_path):
        self._healthy_manifest_beside_a_broken_one(tmp_path)
        exit_code, markdown = _check_to_file(tmp_path, "markdown", "--no-require-lockfile")
        table_exit_code, table = _check_to_file(tmp_path, "table", "--no-require-lockfile")

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
    def test_scan_without_gaps_has_no_gap_section(self, tmp_path):
        # A stray non-UTF-8 byte in a comment is recovered, not a gap.
        (tmp_path / "requirements.txt").write_bytes(b"# maintainer: Jos\xe9\nflask\n")
        _mock_pypi("flask", "BSD-3-Clause")

        # Neither is the missing lockfile, once the scan is told to accept it.
        accept = "--no-require-lockfile"
        _, raw_json = _check_to_file(tmp_path, "json", accept)
        data = json.loads(raw_json)
        assert data["summary"]["gaps"] == 0
        assert [d["severity"] for d in data["diagnostics"]] == ["recovered", "estimate"]
        for exit_code, report in (
            _check(tmp_path, "-f", "markdown", accept),
            _check_to_file(tmp_path, "markdown", accept),
            _check(tmp_path, accept),
            _check_to_file(tmp_path, "table", accept),
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


class TestTableWidth:
    """Off a terminal, the table keeps every column and no cell is cut short."""

    LONG_NAME = "extremely-long-distribution-name-for-a-python-package"
    CHILD = "child-with-a-long-name-of-its-own"

    @respx.mock
    def test_piped_stdout_and_saved_file_have_every_column(self, tmp_path):
        # The table is wider than both the 80 columns a pipe is assumed to
        # have and the 120 a saved table file starts from.
        (tmp_path / "requirements.txt").write_text(f"{self.LONG_NAME}==1.0.0\n")
        _mock_pypi_package(self.LONG_NAME, "MIT", requires=(self.CHILD,))
        _mock_pypi_package(self.CHILD, "LGPL-3.0-only")
        _, raw_json = _check_to_file(tmp_path, "json", "--no-strict")
        total = json.loads(raw_json)["summary"]["total"]

        for exit_code, table in (
            _check(tmp_path, "--no-strict"),
            _check_to_file(tmp_path, "table", "--no-strict"),
        ):
            assert exit_code == 0
            lines = table.splitlines()
            header = next(line for line in lines if "Package" in line)
            for heading in ("Ecosystem", "Group", "Source", "License", "Risk", "Status"):
                assert heading in header
            assert max(len(line) for line in lines) > 120
            # One line per dependency, each cell whole.
            rows = _table_rows(table)
            assert len(rows) == total == 2
            cells = [[cell.strip() for cell in row[1:-1].split(row[0])] for row in rows]
            assert cells == [
                [
                    f"{self.LONG_NAME} (1.0.0)",
                    "python",
                    "prod",
                    "requirements.txt",
                    "MIT",
                    "permissive",
                    "✓",
                ],
                [
                    f"└─ {self.CHILD} (~1.0.0)",
                    "python",
                    "prod",
                    "",
                    "LGPL-3.0-only",
                    "weak-copyleft",
                    "⚠",
                ],
            ]
            assert "…" not in table


class TestLegacyCodePageStdout:
    """A stdout that cannot encode the report's glyphs still gets the report."""

    UNENCODABLE = "Свободная"

    def _project(self, project: Path) -> None:
        # A tree branch, three different verdicts, and a license string with
        # characters outside the code page.
        (project / "requirements.txt").write_text("parent==1.0.0\nodd==1.0.0\n")
        _mock_pypi_package("parent", "MIT", requires=("child",))
        _mock_pypi_package("child", "LGPL-3.0-only")
        _mock_pypi_package("odd", self.UNENCODABLE)

    @respx.mock
    def test_table_falls_back_to_ascii(self, tmp_path):
        self._project(tmp_path)
        exit_code, table = _check(tmp_path, "--no-strict", charset="cp1252")

        assert exit_code == 0
        rows = [[cell.strip() for cell in row[1:-1].split("|")] for row in _table_rows(table)]
        assert [(row[0], row[4], row[6]) for row in rows] == [
            ("odd (1.0.0)", "?" * len(self.UNENCODABLE), "?"),
            ("parent (1.0.0)", "MIT", "OK"),
            # The mark on an estimated version is ASCII: written as it is.
            ("+- child (~1.0.0)", "LGPL-3.0-only", "!"),
        ]
        assert "    ! child uses LGPL-3.0-only" in table
        assert "✓" not in table and "└" not in table

    @respx.mock
    def test_markdown_falls_back_to_ascii(self, tmp_path):
        self._project(tmp_path)
        exit_code, markdown = _check(tmp_path, "-f", "markdown", "--no-strict", charset="cp1252")

        assert exit_code == 0
        rows = _markdown_rows(markdown)
        assert [row.split("|")[-2] for row in rows] == ["?", "OK", "!"]
        assert rows[0].split("|")[5] == "?" * len(self.UNENCODABLE)
        assert rows[2].startswith("|  +- [child (~1.0.0)](https://pypi.org/project/child/)|")
        assert "- ! child uses LGPL-3.0-only" in markdown

    @respx.mock
    def test_saved_reports_and_json_are_not_affected(self, tmp_path):
        self._project(tmp_path)
        _, markdown = _check_to_file(tmp_path, "markdown", "--no-strict", charset="cp1252")
        _, table = _check_to_file(tmp_path, "table", "--no-strict", charset="cp1252")
        _, raw_json = _check(tmp_path, "-f", "json", "--no-strict", charset="cp1252")

        # A saved file is UTF-8 whatever the terminal's code page is.
        for report in (markdown, table):
            assert "✓" in report and "⚠" in report
            assert "└─ " in report
            assert self.UNENCODABLE in report
        assert "+--" not in table
        licenses = {d["name"]: d["license"] for d in json.loads(raw_json)["dependencies"]}
        assert licenses["odd"] == self.UNENCODABLE

    @respx.mock
    @pytest.mark.parametrize("output_format", ["table", "markdown"])
    def test_stdout_swapped_for_an_in_memory_buffer(self, tmp_path, output_format):
        # An in-process caller that replaces sys.stdout with a text buffer:
        # there is no encoding to consult and no error handler to relax.
        self._project(tmp_path)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            main.main(
                ["check", "--path", str(tmp_path), "-f", output_format, "--no-strict"],
                standalone_mode=False,
            )
        report = buffer.getvalue()
        assert "✓" in report and "⚠" in report
        assert "└─ " in report
        assert self.UNENCODABLE in report
