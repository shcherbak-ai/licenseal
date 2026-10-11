"""An npm spec that names a file or a directory is a path, with or without a protocol.

npm reads a dependency spec as a path when it starts like one (``./``, ``/``,
``~/``, a drive letter, a backslash) and, once it is known to be no URL, git
remote, or hosting shorthand, when it holds a slash or ends in an archive
suffix. Such a dependency does not come from the registry: it is one UNKNOWN
row with the path as written as its origin, and nothing is requested for it.
A version range or a dist-tag is never a path.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.discovery.npm._specs import path_spec
from tests._helpers import _check_json, _dirs, _mock_npm, _record_path_io

# Specs npm reads as a file or a directory, and the origin each one has.
_PATH_SPECS = {
    "drive": "C:\\pkgs\\drive",
    "drive-slash": "C:/pkgs/drive-slash",
    "drive-relative": "c:drive-relative",
    "unc": "\\\\fileserver.invalid\\share\\unc",
    "unc-slash": "//fileserver.invalid/share/unc-slash",
    "rooted-backslash": "\\pkgs\\rooted-backslash",
    "tgz": "tgz-1.0.0.tgz",
    "tar-gz": "tar-gz-1.0.0.tar.gz",
    "tar": "TAR-1.0.0.TAR",
    "nested": "libs/nested/pkg",
    "dotted": ".hidden-pkg",
}


def _refuse_everything_else() -> None:
    """Answer 404 to any request no earlier route matched, so that it is on record."""
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


def _manifest(root: Path, dependencies: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "app", "license": "MIT", "dependencies": dependencies}),
        encoding="utf-8",
    )


def _rows(data: dict) -> dict[str, tuple[str, str, str]]:
    return {
        d["name"]: (d["origin"], d["resolved_version"], d["license"]) for d in data["dependencies"]
    }


class TestPathSpec:
    @pytest.mark.parametrize(
        "spec",
        [
            "^1.2.3",
            "~1.2.3",
            "1.0.0",
            "=1.0.0",
            "v1.2.3",
            "1.x || >=2.5.0",
            ">=1.0.0 <2.0.0",
            "1.2.3 - 2.3.4",
            "1.0.0-beta.1",
            "*",
            "x",
            "",
            "latest",
            "next",
            # A protocol, an alias, a URL, a git remote, a hosting shorthand.
            "npm:real-name@^1.0.0",
            "workspace:*",
            "catalog:",
            "exec:./gen.js",
            "https://dl.example.org/pkg-1.0.0.tgz",
            "git+ssh://git@git.example.org/team/pkg.git#v1",
            "git@git.example.org:team/pkg.git",
            "github:team/pkg",
            "team/pkg",
            "team/pkg#feature/x",
        ],
    )
    def test_range_tag_url_and_repository_are_no_path(self, spec):
        assert path_spec(spec) is None

    @pytest.mark.parametrize(
        ("spec", "path"),
        [
            ("file:../dir", "../dir"),
            ("link:../dir", "../dir"),
            ("portal:../dir", "../dir"),
            ("./dir", "./dir"),
            ("../dir", "../dir"),
            (".", "."),
            ("..", ".."),
            ("/opt/pkgs/dir", "/opt/pkgs/dir"),
            ("~/dir", "~/dir"),
            ("..\\dir", "..\\dir"),
            *((spec, spec) for spec in _PATH_SPECS.values()),
        ],
    )
    def test_file_and_directory_specs_are_paths(self, spec, path):
        assert path_spec(spec) == path


class TestManifest:
    @respx.mock
    def test_bare_path_is_an_unknown_row_and_is_never_requested(self, tmp_path, monkeypatch):
        project = tmp_path / "project"
        _manifest(project, {"regular": "^1.0.0", **_PATH_SPECS})
        _mock_npm("regular", "MIT")
        # The registry has a package under each of those names.
        for name in _PATH_SPECS:
            _mock_npm(name, "GPL-3.0-only")
        _refuse_everything_else()
        calls = _record_path_io(monkeypatch, "fileserver.invalid")

        result, data = _check_json(project, "--no-strict", "--no-require-lockfile")

        assert result.exit_code == 0
        assert _rows(data) == {
            "regular": ("", "1.0.0", "MIT"),
            **{name: (spec, "", "UNKNOWN") for name, spec in _PATH_SPECS.items()},
        }
        requested = [str(call.request.url) for call in respx.calls]
        assert not [url for url in requested if any(f"/{name}" in url for name in _PATH_SPECS)]
        # A rooted, drive-qualified, or UNC path is reported as written and
        # never handed to the filesystem.
        assert [call for call in calls if "fileserver.invalid" in call[1]] == []

    @respx.mock
    def test_review_keyed_on_the_path_clears_the_row(self, tmp_path):
        _manifest(tmp_path, {"drive": _PATH_SPECS["drive"]})
        _refuse_everything_else()
        (tmp_path / "licenseal.review.toml").write_text(
            '[[review]]\necosystem = "npm"\npackage = "drive"\n'
            'source = \'C:\\pkgs\\drive\'\nlicense = "MIT"\nnote = "vendored copy"\n',
            encoding="utf-8",
        )

        result, data = _check_json(tmp_path, "--no-require-lockfile")

        assert result.exit_code == 0
        assert data["dependencies"][0]["reviewed"] is True

    @respx.mock
    def test_directory_the_scan_reads_is_the_projects_own_code(self, tmp_path):
        _dirs(tmp_path, "libs/nested/pkg")
        _manifest(tmp_path, {"nested": "libs/nested/pkg"})
        _refuse_everything_else()

        result, data = _check_json(tmp_path)

        assert result.exit_code == 0
        assert data["dependencies"] == []
        assert respx.calls.call_count == 0


def _lockfile(name: str, spec: str) -> tuple[str, str]:
    """A lockfile, by file name, whose entry for ``archived`` is the spec itself."""
    if name == "package-lock.json":
        return name, json.dumps(
            {"lockfileVersion": 1, "dependencies": {"archived": {"version": spec}}}
        )
    if name == "bun.lock":
        return name, json.dumps(
            {"lockfileVersion": 1, "packages": {"archived": [f"archived@{spec}", {}]}}
        )
    return name, f'# yarn lockfile v1\n\n\n"archived@{spec}":\n  version "1.0.0"\n'


class TestLockfiles:
    @respx.mock
    @pytest.mark.parametrize("lockfile", ["package-lock.json", "bun.lock", "yarn.lock"])
    @pytest.mark.parametrize(
        "spec", ["archived-1.0.0.tgz", "C:/pkgs/archived", "libs/archived/pkg"]
    )
    def test_bare_path_in_a_lockfile_entry_is_the_same_row(self, tmp_path, lockfile, spec):
        _manifest(tmp_path, {"archived": spec})
        name, content = _lockfile(lockfile, spec)
        (tmp_path / name).write_text(content, encoding="utf-8")
        _mock_npm("archived", "GPL-3.0-only")
        _refuse_everything_else()

        result, data = _check_json(tmp_path, "--no-strict")

        assert result.exit_code == 0
        version = "1.0.0" if lockfile == "yarn.lock" else ""
        assert _rows(data) == {"archived": (spec, version, "UNKNOWN")}
        assert data["diagnostics"] == []
        assert respx.calls.call_count == 0
