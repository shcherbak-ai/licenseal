"""Gap-surfacing coverage: malformed / unreadable manifests must be recorded.

Each parser routes its read+parse through ``licenseal.discovery._read``; a file
that can't be read or parsed is recorded as an analysis *gap* rather than
silently dropped. These tests exercise the record-and-skip branch of the
representative formats (XML, JSON/nuget, yarn text, INI).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import respx

from licenseal.discovery import ProjectLicense, detect_project_license, discover_all_dependencies
from licenseal.discovery._read import ReadDiagnostic, collect_read_diagnostics
from licenseal.discovery.dotnet.lockfiles import parse_nuget_lockfile
from licenseal.discovery.hex.rebar_lock import parse_rebar_lock
from licenseal.discovery.java.pom_xml import (
    detect_project_license_pom_xml,
    discover_pom_xml_dependencies,
)
from licenseal.discovery.npm.lockfiles import (
    parse_bun_lock,
    parse_package_lock_json,
    parse_yarn_lock,
)
from licenseal.discovery.python.setup_cfg import (
    detect_project_license_setup_cfg,
    discover_setup_cfg_dependencies,
)
from licenseal.discovery.rust.lockfiles import parse_cargo_lock
from licenseal.transitive import _read_local_pom
from tests._helpers import (
    _DEEP,
    _assert_gap_fails_only_strict,
    _check_json,
    _gaps,
    _mock_npm,
    _mock_pypi,
    _resolve,
)


def _raise_oserror(self, *args, **kwargs):
    raise OSError("simulated")


_BACKSLASH = chr(92)
_TRUNCATED_UTF16 = b"\xff\xfe\x52"
_UTF16_LONE_SURROGATE = b"\xff\xfe" + b"\x00\xd8" + '{"dependencies": {}}'.encode("utf-16-le")
_TRUNCATED_UTF32 = b"\xff\xfe\x00\x00" + b"\x41\x00"
_PYPROJECT = '[project]\nname = "app"\ndependencies = ["flask==3.0.0"]\n'
_CARGO = '[package]\nname = "app"\n\n[dependencies]\nserde = "1"\n'
_PIPFILE = '[packages]\nflask = "*"\n'


def _deep(prefix: str, opener: str, core: str, closer: str, suffix: str = "") -> bytes:
    """A syntactically valid document nested ``_DEEP`` levels."""
    return (prefix + opener * _DEEP + core + closer * _DEEP + suffix).encode("ascii")


def _discover(project: Path) -> tuple[set[str], list[ReadDiagnostic]]:
    """Run whole-project discovery; return the names found and what was recorded."""
    with collect_read_diagnostics() as diags:
        deps, _ = discover_all_dependencies(project)
    return {dep.name for dep in deps}, diags


class TestBadManifestBesideAHealthyOne:
    """A manifest that can't be decoded or parsed costs the scan that manifest,
    never the run: discovery returns, the healthy manifest beside it is still
    read, and the bad one is on record.
    """

    @pytest.fixture
    def project(self, tmp_path: Path) -> Path:
        (tmp_path / "requirements.txt").write_bytes(b"requests==2.31.0\n")
        (tmp_path / "sub").mkdir()
        return tmp_path

    @pytest.mark.parametrize(
        ("manifest", "content", "reason"),
        [
            pytest.param(
                "requirements.txt",
                _TRUNCATED_UTF16,
                "has a UTF-16 byte-order mark but is not valid UTF-16; skipped",
                id="text-truncated-utf16",
            ),
            pytest.param(
                "setup.cfg",
                _TRUNCATED_UTF16,
                "has a UTF-16 byte-order mark but is not valid UTF-16; skipped",
                id="ini-truncated-utf16",
            ),
            pytest.param(
                "package.json",
                _UTF16_LONE_SURROGATE,
                "has a UTF-16 byte-order mark but is not valid UTF-16; skipped",
                id="json-utf16-lone-surrogate",
            ),
            pytest.param(
                "go.mod",
                _TRUNCATED_UTF32,
                "has a UTF-32 byte-order mark but is not valid UTF-32; skipped",
                id="text-truncated-utf32",
            ),
            pytest.param(
                "pyproject.toml",
                _TRUNCATED_UTF16,
                "has a UTF-16 byte-order mark but is not valid UTF-16; skipped",
                id="toml-truncated-utf16",
            ),
            pytest.param(
                "Cargo.toml",
                _TRUNCATED_UTF32,
                "has a UTF-32 byte-order mark but is not valid UTF-32; skipped",
                id="toml-truncated-utf32",
            ),
            pytest.param(
                "pom.xml",
                b'<?xml version="1.0" encoding="Shift_JIS"?>\n<project/>\n',
                "is not valid XML; skipped",
                id="xml-multi-byte-encoding",
            ),
            pytest.param(
                "pom.xml",
                b'<?xml version="1.0" encoding="no-such-encoding"?>\n<project/>\n',
                "is not valid XML; skipped",
                id="xml-unknown-encoding",
            ),
            pytest.param(
                "pom.xml",
                b'<?xml version="1.0" encoding="hex"?>\n<project/>\n',
                "is not valid XML; skipped",
                id="xml-non-text-codec",
            ),
            pytest.param(
                "package.json",
                _deep('{"dependencies": ', "[", "", "]", "}"),
                "is not valid JSON; skipped",
                id="json-nested-too-deeply",
            ),
            pytest.param(
                "composer.json",
                _deep('{"require": ', '{"a": ', "1", "}", "}"),
                "is not valid JSON; skipped",
                id="json-objects-nested-too-deeply",
            ),
            pytest.param(
                "pyproject.toml",
                _deep("a = ", "[", "", "]", "\n"),
                "is not valid TOML; skipped",
                id="toml-nested-too-deeply",
            ),
            pytest.param(
                "Pipfile",
                _deep("a = ", "{b = ", "1", "}", "\n"),
                "is not valid TOML; skipped",
                id="toml-inline-tables-nested-too-deeply",
            ),
            pytest.param(
                "pyproject.toml",
                b"# maintainer: Jos\xe9\n" + _PYPROJECT.encode("ascii"),
                "is not valid UTF-8, which TOML requires; skipped",
                id="toml-stray-non-utf8-byte",
            ),
            pytest.param(
                "Cargo.toml",
                b"\xef\xbb\xbf# maintainer: Jos\xe9\n" + _CARGO.encode("ascii"),
                "is not valid UTF-8, which TOML requires; skipped",
                id="toml-stray-non-utf8-byte-after-utf8-bom",
            ),
            pytest.param(
                "Pipfile",
                _PIPFILE.encode("latin-1") + "# café\n".encode("latin-1"),
                "is not valid UTF-8, which TOML requires; skipped",
                id="toml-latin1-encoded",
            ),
        ],
    )
    def test_bad_manifest_is_a_gap_and_the_healthy_one_is_read(
        self, project: Path, manifest, content, reason
    ):
        bad = project / "sub" / manifest
        bad.write_bytes(content)
        names, diags = _discover(project)
        assert names == {"requests"}
        assert diags, "the bad manifest was dropped without a diagnostic"
        assert {(d.path, d.reason, d.is_gap) for d in diags} == {(bad, reason, True)}

    @pytest.mark.parametrize(
        ("manifest", "content", "found"),
        [
            pytest.param(
                "pyproject.toml",
                b"\xff\xfe" + _PYPROJECT.replace("\n", "\r\n").encode("utf-16-le"),
                "flask",
                id="pyproject-utf16-le",
            ),
            pytest.param(
                "pyproject.toml",
                b"\xfe\xff" + _PYPROJECT.encode("utf-16-be"),
                "flask",
                id="pyproject-utf16-be",
            ),
            pytest.param(
                "pyproject.toml",
                b"\xef\xbb\xbf" + _PYPROJECT.encode("utf-8"),
                "flask",
                id="pyproject-utf8-bom",
            ),
            pytest.param(
                "pyproject.toml", _PYPROJECT.encode("utf-32"), "flask", id="pyproject-utf32"
            ),
            pytest.param(
                "Cargo.toml",
                b"\xff\xfe" + _CARGO.encode("utf-16-le"),
                "serde",
                id="cargo-utf16-le",
            ),
            pytest.param(
                "Pipfile",
                b"\xef\xbb\xbf" + _PIPFILE.encode("utf-8"),
                "flask",
                id="pipfile-utf8-bom",
            ),
        ],
    )
    def test_toml_manifest_with_a_bom_parses(self, project: Path, manifest, content, found):
        (project / "sub" / manifest).write_bytes(content)
        names, diags = _discover(project)
        assert names == {"requests", found}
        assert diags == []

    @pytest.mark.parametrize("bom", [b"", b"\xef\xbb\xbf"], ids=["no-bom", "utf8-bom"])
    @pytest.mark.parametrize(
        ("manifest", "content", "found"),
        [
            pytest.param(
                "requirements.txt", b"# maintainer: Jos\xe9\nflask==3.0.0\n", "flask", id="text"
            ),
            pytest.param(
                "package.json",
                b'{"description": "Jos\xe9", "dependencies": {"left-pad": "1.3.0"}}',
                "left-pad",
                id="json",
            ),
        ],
    )
    def test_stray_non_utf8_byte_recovers_with_or_without_a_utf8_bom(
        self, project: Path, bom, manifest, content, found
    ):
        # The documented latin-1 recovery: the ASCII dependency lines survive,
        # the file is flagged but is not a gap, and a UTF-8 BOM changes nothing.
        # TOML has no such recovery; its cases are with the gaps above.
        recovered = project / "sub" / manifest
        recovered.write_bytes(bom + content)
        names, diags = _discover(project)
        assert names == {"requests", found}
        assert diags
        assert {(d.path, d.is_gap) for d in diags} == {(recovered, False)}
        assert all("decoded as latin-1" in d.reason for d in diags)

    @pytest.mark.parametrize(
        "marker",
        [
            # The parser recurses once per parenthesis.
            pytest.param("(" * 5000 + 'os_name == "posix"' + ")" * 5000, id="nested-too-deeply"),
            # A quoted marker value is read as a Python string literal.
            pytest.param(f'platform_release == "C:{_BACKSLASH}Users"', id="invalid-escape"),
            pytest.param(f'os_name == "{_BACKSLASH}"', id="lone-backslash"),
        ],
    )
    def test_requirement_whose_marker_the_parser_cannot_read_keeps_its_name(
        self, project: Path, marker
    ):
        # A requirement the PEP 508 parser fails on in any way, not only with
        # its own error type, is handled like every other malformed line.
        line = f"flask>=2; {marker}\n"
        (project / "sub" / "requirements.txt").write_text(line, encoding="utf-8", newline="\n")
        with collect_read_diagnostics() as diags:
            deps, _ = discover_all_dependencies(project)
        assert {(d.name, d.version_constraint) for d in deps} == {
            ("requests", "==2.31.0"),
            ("flask", ">=2"),
        }
        assert diags == []

    def test_requirement_whose_marker_holds_an_escaped_nul_keeps_its_name(self, project: Path):
        # The file is text: the NUL is written as an escape and reaches the
        # requirement only once the TOML is parsed.
        (project / "sub" / "pyproject.toml").write_text(
            '[project]\nname = "app"\ndependencies = ["flask>=2; os_name == \\"po\\u0000six\\""]\n',
            encoding="utf-8",
        )
        with collect_read_diagnostics() as diags:
            deps, _ = discover_all_dependencies(project)
        assert {(d.name, d.version_constraint) for d in deps} == {
            ("requests", "==2.31.0"),
            ("flask", ">=2"),
        }
        assert diags == []

    def test_license_detection_survives_an_undecodable_root_pom(self, tmp_path: Path):
        pom = tmp_path / "pom.xml"
        pom.write_bytes(b'<?xml version="1.0" encoding="EUC-JP"?>\n<project/>\n')
        with collect_read_diagnostics() as diags:
            assert detect_project_license(tmp_path) == ProjectLicense()
        assert {(d.path, d.reason, d.is_gap) for d in diags} == {
            (pom, "is not valid XML; skipped", True)
        }


class TestPomGaps:
    def test_malformed_pom_recorded_at_every_pass(self, tmp_path: Path):
        # A truncated pom.xml is read by all three pom passes (workspace-local
        # index, dependency discovery, license detection); each records a gap.
        (tmp_path / "pom.xml").write_text("<project><dependencies", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            deps, _ = discover_pom_xml_dependencies(tmp_path)
            lic = detect_project_license_pom_xml(tmp_path / "pom.xml")
        assert deps == []
        assert lic == ""
        assert any(d.is_gap and "not valid XML" in d.reason for d in diags)


class TestNugetLockfileGaps:
    @staticmethod
    def _parse(lock: Path):
        return parse_nuget_lockfile(
            lock, prod_root_names=set(), dev_root_names=set(), include_dev=True
        )

    def test_unreadable_packages_lock_recorded(self, tmp_path: Path, monkeypatch):
        lock = tmp_path / "packages.lock.json"
        lock.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
        with collect_read_diagnostics() as diags:
            deps = self._parse(lock)
        assert deps == []
        assert any(d.is_gap and "could not be read" in d.reason for d in diags)

    def test_malformed_packages_lock_recorded(self, tmp_path: Path):
        lock = tmp_path / "packages.lock.json"
        lock.write_text("{ not json", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            deps = self._parse(lock)
        assert deps == []
        assert any(d.is_gap and "not valid JSON" in d.reason for d in diags)

    def test_malformed_project_assets_recorded(self, tmp_path: Path):
        lock = tmp_path / "project.assets.json"
        lock.write_text("{ not json", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            deps = self._parse(lock)
        assert deps == []
        assert any(d.is_gap and "not valid JSON" in d.reason for d in diags)

    @pytest.mark.parametrize(
        ("lockfile", "prefix"),
        [("packages.lock.json", '{"dependencies": '), ("project.assets.json", '{"targets": ')],
    )
    def test_lockfile_nested_too_deeply_recorded(self, tmp_path: Path, lockfile, prefix):
        lock = tmp_path / lockfile
        lock.write_bytes(_deep(prefix, "[", "", "]", "}"))
        with collect_read_diagnostics() as diags:
            deps = self._parse(lock)
        assert deps == []
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (lock, "is not valid JSON; skipped", True)
        ]


class TestYarnLockGaps:
    def test_unreadable_yarn_lock_returns_empty(self, tmp_path: Path, monkeypatch):
        lock = tmp_path / "yarn.lock"
        lock.write_text("# yarn\n", encoding="utf-8")
        monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
        with collect_read_diagnostics() as diags:
            assert parse_yarn_lock(lock, set(), set(), include_dev=True) == []
        assert any(d.is_gap and "could not be read" in d.reason for d in diags)

    def test_berry_lock_nested_too_deeply_recorded(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_bytes(_deep('__metadata:\n  version: 8\n"a@npm:1.0.0": ', "[", "", "]", "\n"))
        with collect_read_diagnostics() as diags:
            assert parse_yarn_lock(lock, {"a"}, set(), include_dev=True) == []
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (lock, "is not valid YAML; skipped", True)
        ]


class TestBunLockGaps:
    def test_bun_lock_nested_too_deeply_recorded(self, tmp_path: Path):
        lock = tmp_path / "bun.lock"
        lock.write_bytes(_deep('{"lockfileVersion": 1, "packages": ', "[", "", "]", "}"))
        with collect_read_diagnostics() as diags:
            assert parse_bun_lock(lock, {"a"}, set(), include_dev=True) == []
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (lock, "is not valid JSON; skipped", True)
        ]


class TestPackageLockGaps:
    """A lockfileVersion-1 ``dependencies`` tree is walked recursively, one
    call per nesting level, so depth can defeat the walk as well as the parse.
    """

    @staticmethod
    def _nested(levels: int) -> dict:
        tree: dict = {"version": "1.0.0"}
        for _ in range(levels):
            tree = {"version": "1.0.0", "dependencies": {"a": tree}}
        return {"lockfileVersion": 1, "dependencies": {"a": tree}}

    def test_tree_too_deep_to_walk_recorded(self, tmp_path: Path, monkeypatch):
        # The parsed tree is supplied directly so the walk is what fails:
        # whether the JSON parser gets through a file this deep depends on the
        # interpreter, and the next test covers the file either way.
        lock = tmp_path / "package-lock.json"
        tree = self._nested(sys.getrecursionlimit() + 100)
        monkeypatch.setattr("licenseal.discovery.npm.lockfiles.load_json", lambda _path: tree)
        with collect_read_diagnostics() as diags:
            assert parse_package_lock_json(lock, {"a"}, set(), include_dev=True) == []
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (lock, "is not valid JSON; skipped", True)
        ]

    def test_lockfile_nested_too_deeply_recorded(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_bytes(
            _deep(
                '{"lockfileVersion": 1, "dependencies": {"a": ',
                '{"version": "1.0.0", "dependencies": {"a": ',
                '{"version": "1.0.0"}',
                "}}",
                "}}",
            )
        )
        with collect_read_diagnostics() as diags:
            assert parse_package_lock_json(lock, {"a"}, set(), include_dev=True) == []
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (lock, "is not valid JSON; skipped", True)
        ]


class TestRebarLockGaps:
    @pytest.mark.parametrize(
        "level",
        [
            "\u00b2",  # a digit to ``str.isdigit`` that ``int()`` rejects
            "\u0663",  # a non-ASCII decimal digit
            "1" * 5000,  # past the interpreter's int-conversion digit limit
        ],
        ids=["superscript-digit", "non-ascii-decimal", "oversized"],
    )
    def test_entry_whose_level_is_not_a_plain_integer_is_skipped(self, tmp_path: Path, level):
        lock = tmp_path / "rebar.lock"
        lock.write_text(
            '{"1.2.0",\n'
            '[{<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>},0},\n'
            ' {<<"meck">>,{pkg,<<"meck">>,<<"0.9.2">>},' + level + "}]}.\n",
            encoding="utf-8",
        )
        deps = parse_rebar_lock(lock, dev_direct_names=set(), include_dev=True)
        assert [(d.name, d.version_constraint) for d in deps] == [("cowlib", "==2.12.1")]

    @pytest.mark.parametrize(
        "entry",
        [
            # The name binary is never closed.
            '{<<"meck">,{pkg,<<"meck">>,<<"0.9.2">>},1}',
            '{<<"meck"> >,{git,"https://example.invalid/meck",{ref,"abc"}},1}',
        ],
        ids=["unterminated-pkg-name", "unterminated-git-name"],
    )
    def test_entry_whose_name_binary_is_not_closed_is_skipped(self, tmp_path: Path, entry):
        lock = tmp_path / "rebar.lock"
        lock.write_text(
            '{"1.2.0",\n[{<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>},0},\n ' + entry + "]}.\n",
            encoding="utf-8",
        )
        deps = parse_rebar_lock(lock, dev_direct_names=set(), include_dev=True)
        assert [(d.name, d.version_constraint) for d in deps] == [("cowlib", "==2.12.1")]


class TestSetupCfgGaps:
    _MALFORMED = "[metadata]\nlicense = MIT\nlicense = BSD\n"  # duplicate option

    def test_malformed_setup_cfg_discover_recorded(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(self._MALFORMED, encoding="utf-8")
        with collect_read_diagnostics() as diags:
            assert discover_setup_cfg_dependencies(tmp_path) == []
        assert any(d.is_gap and "not valid INI" in d.reason for d in diags)

    def test_malformed_setup_cfg_detect_recorded(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(self._MALFORMED, encoding="utf-8")
        with collect_read_diagnostics() as diags:
            assert detect_project_license_setup_cfg(tmp_path / "setup.cfg") == ""
        assert any(d.is_gap and "not valid INI" in d.reason for d in diags)

    def test_unreadable_setup_cfg_skipped(self, tmp_path: Path, monkeypatch):
        (tmp_path / "setup.cfg").write_text("[metadata]\nlicense = MIT\n", encoding="utf-8")
        monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
        assert discover_setup_cfg_dependencies(tmp_path) == []
        assert detect_project_license_setup_cfg(tmp_path / "setup.cfg") == ""


class TestCargoLockGaps:
    def test_malformed_cargo_lock_returns_empty(self, tmp_path: Path):
        lock = tmp_path / "Cargo.lock"
        lock.write_text("this is = = not toml", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            deps, known = parse_cargo_lock(lock, set(), set(), include_dev=True)
        assert deps == [] and known == set()
        assert any(d.is_gap and "not valid TOML" in d.reason for d in diags)


_NOT_UTF8_TOML = "is not valid UTF-8, which TOML requires; skipped"


class TestNonUtf8Toml:
    """TOML must be UTF-8. A TOML manifest or lockfile that is not is a gap,
    with no latin-1 recovery, wherever the stray byte sits."""

    @respx.mock
    @pytest.mark.parametrize("bom", [b"", b"\xef\xbb\xbf"], ids=["no-bom", "utf8-bom"])
    def test_manifest_fails_only_strict_and_reads_once_it_is_utf8(self, tmp_path: Path, bom):
        # The stray byte is in a comment, and the dependency lines are ASCII.
        # The file is skipped all the same; saved as UTF-8 it is read.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": {"left-pad": "1.0.0"}})
        )
        text = "# maintainer: José\n" + _PYPROJECT
        bad = tmp_path / "sub" / "pyproject.toml"
        bad.parent.mkdir()
        bad.write_bytes(bom + text.encode("latin-1"))
        _mock_npm("left-pad", "MIT")
        _mock_pypi("flask", "MIT", "3.0.0")

        _assert_gap_fails_only_strict(
            tmp_path,
            bad,
            _NOT_UTF8_TOML,
            [("left-pad", "MIT")],
            repair=lambda: bad.write_bytes(bom + text.encode("utf-8")),
        )
        _, data = _check_json(tmp_path)
        assert sorted(d["name"] for d in data["dependencies"]) == ["flask", "left-pad"]

    @pytest.mark.parametrize(
        ("manifest", "manifest_text", "lockfile", "lock_text", "unpinned", "pinned"),
        [
            pytest.param(
                "pyproject.toml",
                '[project]\nname = "app"\ndependencies = ["flask"]\n',
                "uv.lock",
                'version = 1\n\n[[package]]\nname = "flask"\nversion = "3.0.0"\n',
                ("flask", ""),
                ("flask", "==3.0.0"),
                id="uv.lock",
            ),
            pytest.param(
                "pyproject.toml",
                '[project]\nname = "app"\ndependencies = ["flask"]\n',
                "poetry.lock",
                '[[package]]\nname = "flask"\nversion = "3.0.0"\n',
                ("flask", ""),
                ("flask", "==3.0.0"),
                id="poetry.lock",
            ),
            pytest.param(
                "Cargo.toml",
                _CARGO,
                "Cargo.lock",
                'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
                ("serde", "1"),
                ("serde", "==1.0.200"),
                id="Cargo.lock",
            ),
        ],
    )
    def test_lockfile_is_a_gap_and_pins_nothing(
        self, tmp_path: Path, manifest, manifest_text, lockfile, lock_text, unpinned, pinned
    ):
        (tmp_path / manifest).write_text(manifest_text, encoding="utf-8", newline="\n")
        lock = tmp_path / lockfile
        lock.write_bytes(b"# locked by Jos\xe9\n" + lock_text.encode("ascii"))
        rows, diags = _resolve(tmp_path)
        assert _gaps(diags) == {(lock, _NOT_UTF8_TOML)}
        # The lockfile's pin is not used: the dependency keeps the manifest's
        # constraint, as in a scan with no lockfile.
        assert {(name, version) for name, version, _ in rows} == {unpinned}

        # Control: the same lockfile as UTF-8 is read.
        lock.write_bytes("# locked by José\n".encode() + lock_text.encode("ascii"))
        rows, diags = _resolve(tmp_path)
        assert diags == []
        assert {(name, version) for name, version, _ in rows} == {pinned}


_NOT_TEXT = (
    "contains NUL characters and is not read as text (UTF-16 needs a byte-order mark); skipped"
)

# The manifests and lockfiles that are read line by line, each declaring or
# pinning one package. No parser rejects such a file for what it holds: one
# that is not text matches no line and would read as an empty file.
_LINE_ORIENTED = {
    "requirements.txt": "markerpkg==1.0\n",
    "setup.cfg": "[options]\ninstall_requires =\n    markerpkg==1.0\n",
    "setup.py": 'from setuptools import setup\nsetup(install_requires=["markerpkg==1.0"])\n',
    "Gemfile": 'source "https://rubygems.org"\ngem "markerpkg", "1.0.0"\n',
    "Gemfile.lock": (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    markerpkg (1.0.0)\n\n"
        "DEPENDENCIES\n  markerpkg\n"
    ),
    "app.gemspec": (
        'Gem::Specification.new do |s|\n  s.name = "app"\n'
        '  s.add_dependency "markerpkg", "1.0.0"\nend\n'
    ),
    "go.mod": "module example.org/app\n\ngo 1.22\n\nrequire example.org/markerpkg v1.0.0\n",
    "go.sum": "example.org/markerpkg v1.0.0 h1:h\nexample.org/markerpkg v1.0.0/go.mod h1:h\n",
    "build.gradle": "dependencies {\n    implementation 'org.example:markerpkg:1.0'\n}\n",
    "gradle.lockfile": "org.example:markerpkg:1.0=runtimeClasspath\nempty=\n",
    "paket.dependencies": "source https://api.nuget.org/v3/index.json\nnuget markerpkg 1.0.0\n",
    "paket.lock": "NUGET\n  remote: https://api.nuget.org/v3/index.json\n    markerpkg (1.0.0)\n",
    "mix.exs": (
        'defmodule App.MixProject do\n  defp deps do\n    [{:markerpkg, "== 1.0.0"}]\n  end\nend\n'
    ),
    "mix.lock": (
        '%{\n  "markerpkg": {:hex, :markerpkg, "1.0.0", "aa", [:mix], [], "hexpm", "bb"},\n}\n'
    ),
    "rebar.config": '{deps, [{markerpkg, "1.0.0"}]}.\n',
    "rebar.lock": '{"1.2.0",\n[{<<"markerpkg">>,{pkg,<<"markerpkg">>,<<"1.0.0">>},0}]}.\n',
    "DESCRIPTION": "Package: app\nVersion: 1.0\nImports: markerpkg\n",
    "packrat/packrat.lock": (
        "PackratFormat: 1.4\n\nPackage: markerpkg\nSource: CRAN\nVersion: 1.0\n"
    ),
    "yarn.lock": '# yarn lockfile v1\n\n\nmarkerpkg@1.0.0:\n  version "1.0.0"\n',
    "Makefile": "PROJECT = app\nDEPS = markerpkg\ndep_markerpkg = hex 1.0.0\ninclude erlang.mk\n",
}

_NOT_TEXT_VARIANTS = {
    "nul-bytes": lambda text: b"\x00\x00\x00\x00",
    "utf16-le-without-bom": lambda text: text.encode("utf-16-le"),
    "utf16-be-without-bom": lambda text: text.encode("utf-16-be"),
    "one-nul-at-the-end": lambda text: text.encode("utf-8") + b"\x00",
}


class TestFileThatIsNotText:
    """A text manifest or lockfile that holds a NUL character is a gap.

    UTF-16 without a byte-order mark is the common case: every ASCII
    character decodes with a NUL beside it.
    """

    @respx.mock
    @pytest.mark.parametrize("variant", _NOT_TEXT_VARIANTS)
    @pytest.mark.parametrize("name", _LINE_ORIENTED)
    def test_gap_fails_only_strict_beside_a_healthy_manifest(self, tmp_path: Path, name, variant):
        good = tmp_path / "good" / "requirements.txt"
        good.parent.mkdir()
        good.write_text("flask==1.0.0\n", encoding="utf-8")
        bad = tmp_path / name
        bad.parent.mkdir(exist_ok=True)
        bad.write_bytes(_NOT_TEXT_VARIANTS[variant](_LINE_ORIENTED[name]))
        _mock_pypi("flask", "BSD-3-Clause")

        _assert_gap_fails_only_strict(
            tmp_path, bad, _NOT_TEXT, [("flask", "BSD-3-Clause")], repair=bad.unlink
        )

    @pytest.mark.parametrize(
        "name",
        [name for name in _LINE_ORIENTED if not name.endswith((".lock", ".sum", "lockfile"))],
    )
    def test_manifest_with_a_byte_order_mark_is_read_in_its_encoding(self, tmp_path: Path, name):
        # The codec writes the mark: the same text, UTF-16, and not a gap.
        (tmp_path / name).write_bytes(_LINE_ORIENTED[name].encode("utf-16"))
        names, diags = _discover(tmp_path)
        assert [found.rsplit(":", 1)[-1].rsplit("/", 1)[-1] for found in names] == ["markerpkg"]
        assert diags == []


class TestLocalPomGaps:
    def test_malformed_local_pom_recorded(self, tmp_path: Path):
        # The transitive walker reads in-tree parent POMs; a malformed one is a
        # gap, not a silently-empty parent.
        pom = tmp_path / "pom.xml"
        pom.write_text("<project><parent", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            assert _read_local_pom(pom) is None
        assert any(d.is_gap and "not valid XML" in d.reason for d in diags)

    def test_local_pom_in_an_unsupported_encoding_recorded(self, tmp_path: Path):
        pom = tmp_path / "pom.xml"
        pom.write_bytes(b'<?xml version="1.0" encoding="GB2312"?>\n<project/>\n')
        with collect_read_diagnostics() as diags:
            assert _read_local_pom(pom) is None
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (pom, "is not valid XML; skipped", True)
        ]
