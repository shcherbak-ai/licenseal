"""A setuptools ``file:`` directive names the files that hold the requirements.

``install_requires = file: reqs.in`` in ``setup.cfg``, each value of its
``[options.extras_require]``, and the ``file`` key of a
``[tool.setuptools.dynamic]`` entry in ``pyproject.toml`` name one or more
requirements files, relative to the manifest. Each is read like a ``-r``
include: its requirements take the group of the option that names it and are
reported with the file as their source. A file that is not followed is a gap
on the manifest that names it, and ``file`` is never a dependency.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import respx

from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import ReadDiagnostic, collect_read_diagnostics
from licenseal.models import Dependency, DependencyGroup
from tests._helpers import (
    _NON_RELATIVE_PATH_VALUES,
    _assert_gap_fails_only_strict,
    _check_json,
    _gaps,
    _mock_pypi,
    _record_path_io,
    _write,
)

PROD = DependencyGroup.PROD
DEV = DependencyGroup.DEV


def _discover(project: Path) -> tuple[list[Dependency], list[ReadDiagnostic]]:
    with collect_read_diagnostics() as diags:
        deps, _ = discover_all_dependencies(project)
    return deps, diags


def _rows(deps: list[Dependency]) -> set[tuple[str, str, DependencyGroup, str]]:
    return {(d.name, d.version_constraint, d.group, d.source) for d in deps}


def _unfollowed(value: str, why: str) -> str:
    return f"references {value!r}, which {why}; not followed"


def _setup_cfg(install_requires: str = "", **extras: str) -> str:
    text = "[metadata]\nname = app\n\n[options]\n"
    if install_requires:
        text += f"install_requires = {install_requires}\n"
    if extras:
        text += "\n[options.extras_require]\n"
        text += "".join(f"{extra} = {value}\n" for extra, value in extras.items())
    return text


def _pyproject(dynamic: str) -> str:
    return (
        '[project]\nname = "app"\nversion = "0.1.0"\n'
        'dynamic = ["dependencies", "optional-dependencies"]\n\n'
        f"[tool.setuptools.dynamic]\n{dynamic}\n"
    )


class TestSetupCfg:
    @pytest.mark.parametrize(
        "value",
        ["file: reqs.in", "file:reqs.in", "file:   reqs.in  ", "\n    file: reqs.in"],
        ids=["spaced", "unspaced", "padded", "on-the-next-line"],
    )
    def test_named_file_is_read_and_is_the_source_of_its_requirements(self, tmp_path: Path, value):
        _write(tmp_path / "setup.cfg", _setup_cfg(value))
        _write(tmp_path / "reqs.in", "# the runtime set\nflask==3.0.0\nrich>=13\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("flask", "==3.0.0", PROD, "reqs.in"),
            ("rich", ">=13", PROD, "reqs.in"),
        }
        assert diags == []

    def test_several_files_relative_to_the_directory_of_the_setup_cfg(self, tmp_path: Path):
        _write(tmp_path / "pkg" / "setup.cfg", _setup_cfg("file: deps/a.in, deps/b.in,"))
        _write(tmp_path / "pkg" / "deps" / "a.in", "flask\n")
        _write(tmp_path / "pkg" / "deps" / "b.in", "rich\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("flask", "", PROD, "pkg/deps/a.in"),
            ("rich", "", PROD, "pkg/deps/b.in"),
        }
        assert diags == []

    def test_extra_takes_the_group_its_name_gives_it(self, tmp_path: Path):
        _write(
            tmp_path / "setup.cfg",
            _setup_cfg("click", dev="file: tools.in", speed="file: speed.in"),
        )
        _write(tmp_path / "tools.in", "pytest\n")
        _write(tmp_path / "speed.in", "orjson\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("click", "", PROD, "setup.cfg"),
            ("pytest", "", DEV, "tools.in"),
            ("orjson", "", PROD, "speed.in"),
        }
        assert diags == []

    def test_directive_among_requirement_lines(self, tmp_path: Path):
        _write(tmp_path / "setup.cfg", _setup_cfg("\n    click>=8\n    file: reqs.in\n    rich"))
        _write(tmp_path / "reqs.in", "flask\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("click", ">=8", PROD, "setup.cfg"),
            ("flask", "", PROD, "reqs.in"),
            ("rich", "", PROD, "setup.cfg"),
        }
        assert diags == []

    def test_include_inside_the_named_file_is_followed(self, tmp_path: Path):
        _write(tmp_path / "setup.cfg", _setup_cfg("file: reqs.in"))
        _write(tmp_path / "reqs.in", "-r pinned/base.txt\nflask\n")
        _write(tmp_path / "pinned" / "base.txt", "rich==13.0\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("flask", "", PROD, "reqs.in"),
            ("rich", "==13.0", PROD, "pinned/base.txt"),
        }
        assert diags == []

    def test_file_url_requirement_is_not_a_directive(self, tmp_path: Path):
        # ``file://`` starts a URL: the requirement is a path dependency.
        _write(
            tmp_path / "setup.cfg", _setup_cfg("file:///opt/wheels/flask-3.0.0-py3-none-any.whl")
        )
        deps, diags = _discover(tmp_path)
        assert [(d.name, d.origin) for d in deps] == [
            ("flask", "/opt/wheels/flask-3.0.0-py3-none-any.whl")
        ]
        assert diags == []


class TestPyproject:
    @pytest.mark.parametrize(
        "files",
        ['"reqs.in"', '["reqs.in"]', '["reqs.in", "deps/more.in"]'],
        ids=["string", "list", "several"],
    )
    def test_dynamic_dependencies_are_read_from_the_named_files(self, tmp_path: Path, files):
        _write(tmp_path / "pyproject.toml", _pyproject(f"dependencies = {{file = {files}}}"))
        _write(tmp_path / "reqs.in", "flask==3.0.0\n")
        _write(tmp_path / "deps" / "more.in", "rich\n")

        deps, diags = _discover(tmp_path)

        expected = {("flask", "==3.0.0", PROD, "reqs.in")}
        if "more.in" in files:
            expected.add(("rich", "", PROD, "deps/more.in"))
        assert _rows(deps) == expected
        assert diags == []

    def test_dynamic_optional_dependencies_take_the_group_of_their_extra(self, tmp_path: Path):
        _write(
            tmp_path / "pkg" / "pyproject.toml",
            _pyproject(
                'optional-dependencies = {dev = {file = ["tools.in"]}, speed = {file = "speed.in"}}'
            ),
        )
        _write(tmp_path / "pkg" / "tools.in", "pytest\n")
        _write(tmp_path / "pkg" / "speed.in", "orjson\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("pytest", "", DEV, "pkg/tools.in"),
            ("orjson", "", PROD, "pkg/speed.in"),
        }
        assert diags == []

    @pytest.mark.parametrize(
        ("dynamic", "what"),
        [
            ('dependencies = "reqs.in"', "tool.setuptools.dynamic.dependencies"),
            ("dependencies = {file = 7}", "tool.setuptools.dynamic.dependencies"),
            ('dependencies = {file = ["reqs.in", 7]}', "tool.setuptools.dynamic.dependencies"),
            (
                'optional-dependencies = ["reqs.in"]',
                "tool.setuptools.dynamic.optional-dependencies",
            ),
            (
                'optional-dependencies = {dev = "reqs.in"}',
                "tool.setuptools.dynamic.optional-dependencies",
            ),
        ],
    )
    def test_value_of_another_type_is_a_gap(self, tmp_path: Path, dynamic, what):
        manifest = _write(tmp_path / "pyproject.toml", _pyproject(dynamic))
        _write(tmp_path / "reqs.in", "flask\n")

        deps, diags = _discover(tmp_path)

        # The list with one bad item still names one file.
        assert {d.name for d in deps} == ({"flask"} if '"reqs.in", 7' in dynamic else set())
        assert len(_gaps(diags)) == 1
        ((path, reason),) = _gaps(diags)
        assert path == manifest
        assert reason.endswith("has an unexpected type; ignored")
        assert what in reason

    def test_entry_that_names_no_file_declares_nothing(self, tmp_path: Path):
        _write(
            tmp_path / "pyproject.toml",
            _pyproject('version = {attr = "app.__version__"}\ndependencies = {}'),
        )
        deps, diags = _discover(tmp_path)
        assert deps == []
        assert diags == []


_MANIFESTS = {
    "setup.cfg": lambda value: _setup_cfg(f"file: {value}"),
    "pyproject.toml": lambda value: _pyproject(f"dependencies = {{file = ['{value}']}}"),
}


@pytest.mark.parametrize("manifest_name", sorted(_MANIFESTS))
class TestNotFollowed:
    @pytest.mark.parametrize("value", _NON_RELATIVE_PATH_VALUES)
    def test_path_that_is_not_relative_is_a_gap_and_is_never_touched(
        self, tmp_path: Path, monkeypatch, manifest_name, value
    ):
        manifest = _write(tmp_path / manifest_name, _MANIFESTS[manifest_name](value))
        calls = _record_path_io(monkeypatch, "example.invalid")

        deps, diags = _discover(tmp_path)

        assert deps == []
        assert _gaps(diags) == {(manifest, _unfollowed(value, "is not a relative path"))}
        assert [call for call in calls if "example.invalid" in call[1]] == []

    @pytest.mark.parametrize("value", ["missing.in", "deps"])
    def test_name_that_is_not_a_file_is_a_gap(self, tmp_path: Path, manifest_name, value):
        (tmp_path / "deps").mkdir()
        manifest = _write(tmp_path / manifest_name, _MANIFESTS[manifest_name](value))

        deps, diags = _discover(tmp_path)

        assert deps == []
        assert _gaps(diags) == {(manifest, _unfollowed(value, "is not a file"))}

    def test_file_outside_the_scanned_directory_is_a_gap(self, tmp_path: Path, manifest_name):
        project = tmp_path / "project"
        manifest = _write(project / manifest_name, _MANIFESTS[manifest_name]("../outside.in"))
        _write(tmp_path / "outside.in", "not-in-this-project==1.0\n")

        deps, diags = _discover(project)

        assert deps == []
        assert _gaps(diags) == {
            (manifest, _unfollowed("../outside.in", "is outside the scanned directory"))
        }

    def test_one_file_that_is_not_followed_leaves_the_others_read(
        self, tmp_path: Path, manifest_name
    ):
        value = "missing.in, reqs.in" if manifest_name == "setup.cfg" else "missing.in', 'reqs.in"
        manifest = _write(tmp_path / manifest_name, _MANIFESTS[manifest_name](value))
        _write(tmp_path / "reqs.in", "flask\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {("flask", "", PROD, "reqs.in")}
        assert _gaps(diags) == {(manifest, _unfollowed("missing.in", "is not a file"))}


@pytest.mark.parametrize("manifest_name", sorted(_MANIFESTS))
class TestFileTheScanReadsByItsName:
    def test_requirements_file_named_by_a_manifest_is_reported_once(
        self, tmp_path: Path, manifest_name
    ):
        _write(tmp_path / manifest_name, _MANIFESTS[manifest_name]("requirements.txt"))
        _write(tmp_path / "requirements.txt", "flask==3.0.0\n")

        with collect_read_diagnostics() as diags:
            deps, _ = discover_all_dependencies(tmp_path)

        # A list, not a set: a second row for the same line would show.
        assert [(d.name, d.version_constraint, d.group, d.source) for d in deps] == [
            ("flask", "==3.0.0", PROD, "requirements.txt")
        ]
        assert diags == []

    def test_production_wins_over_the_dev_name_of_the_file(self, tmp_path: Path, manifest_name):
        # The file's own name makes its requirements dev; the option that
        # names it installs them with the package.
        _write(tmp_path / manifest_name, _MANIFESTS[manifest_name]("requirements-dev.txt"))
        _write(tmp_path / "requirements-dev.txt", "flask==3.0.0\n")

        deps, diags = _discover(tmp_path)

        assert [(d.name, d.group, d.source) for d in deps] == [
            ("flask", PROD, "requirements-dev.txt")
        ]
        assert diags == []


class TestCheckCommand:
    @respx.mock
    @pytest.mark.parametrize("manifest_name", sorted(_MANIFESTS))
    def test_named_requirements_are_resolved_and_nothing_is_called_file(
        self, tmp_path: Path, manifest_name
    ):
        _write(tmp_path / manifest_name, _MANIFESTS[manifest_name]("reqs.in"))
        _write(tmp_path / "reqs.in", "flask==1.0.0\n")
        _mock_pypi("flask", "BSD-3-Clause")
        # A package that is published under the directive's own name.
        _mock_pypi("file", "GPL-3.0-only")

        result, data = _check_json(tmp_path, "--no-require-lockfile")

        assert result.exit_code == 0
        assert [(d["name"], d["license"], d["source"]) for d in data["dependencies"]] == [
            ("flask", "BSD-3-Clause", "reqs.in")
        ]
        assert not [call for call in respx.calls if "/pypi/file/" in str(call.request.url)]

    @respx.mock
    def test_file_that_cannot_be_followed_beside_a_healthy_manifest(self, tmp_path: Path):
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n')
        manifest = _write(tmp_path / "svc" / "setup.cfg", _setup_cfg("file: missing.in"))
        _write(tmp_path / "svc" / "requirements.txt", "flask\n")
        _write(tmp_path / "svc" / "reqs.in", "left-pad\n")
        _mock_pypi("flask", "BSD-3-Clause")
        _mock_pypi("left-pad", "MIT")

        _assert_gap_fails_only_strict(
            tmp_path,
            manifest,
            _unfollowed("missing.in", "is not a file"),
            [("flask", "BSD-3-Clause")],
            repair=lambda: manifest.write_text(_setup_cfg("file: reqs.in"), encoding="utf-8"),
        )
