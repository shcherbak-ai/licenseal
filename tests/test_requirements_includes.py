"""``-r`` / ``--requirement`` lines in a requirements file are followed.

The included file's requirements belong to the file that includes it: they
take that file's dev/prod classification and are reported with the included
file as their source. An include that cannot be followed is a gap on the file
that names it. ``-c`` / ``--constraint`` files only pin versions and are never
read.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import respx

from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import ReadDiagnostic, collect_read_diagnostics
from licenseal.discovery.python.requirements import discover_requirements_dependencies
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


class TestFollowed:
    def test_included_file_is_read_and_is_the_source_of_its_requirements(self, tmp_path: Path):
        _write(tmp_path / "requirements.txt", "-r deps/pinned.txt\nflask==3.0.0\n")
        _write(tmp_path / "deps" / "pinned.txt", "django==4.2.11\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("flask", "==3.0.0", PROD, "requirements.txt"),
            ("django", "==4.2.11", PROD, "deps/pinned.txt"),
        }
        assert diags == []

    @pytest.mark.parametrize(
        "line",
        [
            "-r deps/pinned.txt",
            "-rdeps/pinned.txt",
            "--requirement deps/pinned.txt",
            "--requirement=deps/pinned.txt",
            '-r "deps/pinned.txt"',
            "-r 'deps/pinned.txt'",
            "-r deps/pinned.txt  # the pinned set",
            "   -r    deps/pinned.txt   ",
            "-r ./deps/../deps/pinned.txt",
        ],
    )
    def test_every_spelling_of_the_option_is_followed(self, tmp_path: Path, line):
        # The file holds nothing but the include: all it declares is elsewhere.
        _write(tmp_path / "requirements.txt", line + "\n")
        _write(tmp_path / "deps" / "pinned.txt", "django==4.2.11\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {("django", "==4.2.11", PROD, "deps/pinned.txt")}
        assert diags == []

    def test_quoted_path_with_a_space_is_followed(self, tmp_path: Path):
        _write(tmp_path / "requirements.txt", '-r "my deps/pinned.txt"\n')
        _write(tmp_path / "my deps" / "pinned.txt", "django==4.2.11\n")
        deps, diags = _discover(tmp_path)
        assert _rows(deps) == {("django", "==4.2.11", PROD, "my deps/pinned.txt")}
        assert diags == []

    def test_path_is_relative_to_the_including_file(self, tmp_path: Path):
        # Each include is resolved from the directory of the file it is in,
        # not from the scan root or from the first file.
        _write(tmp_path / "svc" / "requirements.txt", "-r ../shared/base.txt\n")
        _write(tmp_path / "shared" / "base.txt", "-r extra/more.txt\nflask==3.0.0\n")
        _write(tmp_path / "shared" / "extra" / "more.txt", "-r ../../top.txt\nrich==13.0\n")
        _write(tmp_path / "top.txt", "click==8.1\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("flask", "==3.0.0", PROD, "shared/base.txt"),
            ("rich", "==13.0", PROD, "shared/extra/more.txt"),
            ("click", "==8.1", PROD, "top.txt"),
        }
        assert diags == []

    @pytest.mark.parametrize(
        ("files", "declared"),
        [
            (
                {"requirements.txt": "-r requirements.txt\nflask\n"},
                [("flask", "requirements.txt")],
            ),
            (
                {
                    "requirements.txt": "-r inc/a.txt\nflask\n",
                    "inc/a.txt": "-r ../requirements.txt\nrich\n",
                },
                [("flask", "requirements.txt"), ("rich", "inc/a.txt")],
            ),
            (
                {
                    "requirements.txt": "-r inc/a.txt\nflask\n",
                    "inc/a.txt": "-r b.txt\nrich\n",
                    "inc/b.txt": "-r a.txt\n-r ../requirements.txt\nclick\n",
                },
                [("flask", "requirements.txt"), ("rich", "inc/a.txt"), ("click", "inc/b.txt")],
            ),
        ],
        ids=["includes-itself", "two-file-cycle", "three-file-cycle"],
    )
    def test_cycle_ends_and_each_file_is_read_once(self, tmp_path: Path, files, declared):
        for name, content in files.items():
            _write(tmp_path / name, content)
        with collect_read_diagnostics() as diags:
            deps = discover_requirements_dependencies(tmp_path)

        # A list, not a set: a file read twice would repeat its requirement.
        assert [(d.name, d.source) for d in deps] == declared
        assert diags == []

    def test_file_included_twice_is_read_once(self, tmp_path: Path):
        _write(tmp_path / "requirements.txt", "-r deps/a.txt\n-r deps/b.txt\n-r deps/a.txt\n")
        _write(tmp_path / "deps" / "a.txt", "flask\n")
        _write(tmp_path / "deps" / "b.txt", "-r a.txt\nrich\n")
        deps = discover_requirements_dependencies(tmp_path)

        assert [(d.name, d.source) for d in deps] == [
            ("flask", "deps/a.txt"),
            ("rich", "deps/b.txt"),
        ]

    def test_chain_longer_than_the_recursion_limit_is_followed(self, tmp_path: Path):
        # One file per link, each including the next: reading them must not
        # depend on the interpreter's stack.
        length = sys.getrecursionlimit() + 50
        (tmp_path / "chain").mkdir()
        _write(tmp_path / "requirements.txt", "-r chain/0.txt\n")
        for index in range(length):
            (tmp_path / "chain" / f"{index}.txt").write_text(
                f"-r {index + 1}.txt\n", encoding="utf-8"
            )
        (tmp_path / "chain" / f"{length}.txt").write_text("flask==3.0.0\n", encoding="utf-8")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {("flask", "==3.0.0", PROD, f"chain/{length}.txt")}
        assert diags == []


class TestClassification:
    def test_requirement_takes_the_classification_of_the_including_file(self, tmp_path: Path):
        # Neither included file's own name decides anything: ``tools.txt``
        # is dev because a dev file includes it, ``test.txt`` is prod because
        # a prod file does.
        _write(tmp_path / "requirements-dev.txt", "-r deps/tools.txt\n")
        _write(tmp_path / "deps" / "tools.txt", "pytest\n")
        _write(tmp_path / "requirements.txt", "-r deps/test.txt\n")
        _write(tmp_path / "deps" / "test.txt", "flask\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("pytest", "", DEV, "deps/tools.txt"),
            ("flask", "", PROD, "deps/test.txt"),
        }
        assert diags == []

    def test_classification_carries_through_a_chain_of_includes(self, tmp_path: Path):
        _write(tmp_path / "requirements-dev.txt", "-r deps/a.txt\n")
        _write(tmp_path / "deps" / "a.txt", "-r b.txt\n")
        _write(tmp_path / "deps" / "b.txt", "pytest\n")
        deps, _ = _discover(tmp_path)
        assert _rows(deps) == {("pytest", "", DEV, "deps/b.txt")}

    @pytest.mark.parametrize(
        ("prod_file", "dev_file"),
        [
            # The walk reads files in name order, so each order is covered.
            ("requirements.txt", "requirements-dev.txt"),
            ("a-requirements.txt", "requirements-dev.txt"),
        ],
        ids=["dev-file-read-first", "prod-file-read-first"],
    )
    def test_production_wins_when_reached_from_both(self, tmp_path: Path, prod_file, dev_file):
        _write(tmp_path / prod_file, "-r deps/common.txt\n")
        _write(tmp_path / dev_file, "-r deps/common.txt\npytest\n")
        _write(tmp_path / "deps" / "common.txt", "flask==3.0.0\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("flask", "==3.0.0", PROD, "deps/common.txt"),
            ("pytest", "", DEV, dev_file),
        }
        assert diags == []

    def test_dev_file_that_includes_the_prod_file_leaves_it_prod(self, tmp_path: Path):
        # The common layout: the dev file starts from the production set.
        _write(tmp_path / "requirements.txt", "flask==3.0.0\n")
        _write(tmp_path / "requirements-dev.txt", "-r requirements.txt\npytest\n")

        deps, diags = _discover(tmp_path)

        assert _rows(deps) == {
            ("flask", "==3.0.0", PROD, "requirements.txt"),
            ("pytest", "", DEV, "requirements-dev.txt"),
        }
        assert diags == []

    def test_prod_file_that_includes_a_dev_file_makes_it_prod(self, tmp_path: Path):
        # Installing the production file installs these too.
        _write(tmp_path / "requirements.txt", "-r requirements-dev.txt\nflask\n")
        _write(tmp_path / "requirements-dev.txt", "pytest\n")

        deps, _ = _discover(tmp_path)

        assert {(d.name, d.group) for d in deps} == {("flask", PROD), ("pytest", PROD)}


class TestConstraints:
    @pytest.mark.parametrize(
        "line",
        [
            "-c pins-only.txt",
            "-cpins-only.txt",
            "--constraint pins-only.txt",
            "--constraint=pins-only.txt",
        ],
    )
    def test_constraints_file_is_never_read(self, tmp_path: Path, monkeypatch, line):
        _write(tmp_path / "requirements.txt", line + "\nflask\n")
        _write(tmp_path / "pins-only.txt", "flask==3.0.0\nnot-a-dependency==1.0\n")
        # The marker is the file's own name: nothing else under the scanned
        # directory matches it, so any call recorded is on that file.
        calls = _record_path_io(monkeypatch, "pins-only")

        deps, diags = _discover(tmp_path)

        # The constraint is not applied and its other pin is not a dependency.
        assert _rows(deps) == {("flask", "", PROD, "requirements.txt")}
        assert diags == []
        assert [call for call in calls if "pins-only" in call[1]] == []

    def test_missing_constraints_file_is_not_a_gap(self, tmp_path: Path):
        _write(tmp_path / "requirements.txt", "-c missing.txt\nflask\n")
        deps, diags = _discover(tmp_path)
        assert _rows(deps) == {("flask", "", PROD, "requirements.txt")}
        assert diags == []


class TestNotFollowed:
    @pytest.mark.parametrize("value", _NON_RELATIVE_PATH_VALUES)
    def test_path_that_is_not_relative_is_a_gap_and_is_never_touched(
        self, tmp_path: Path, monkeypatch, value
    ):
        manifest = _write(tmp_path / "requirements.txt", f"flask\n-r {value}\nrich\n")
        calls = _record_path_io(monkeypatch, "example.invalid")

        deps, diags = _discover(tmp_path)

        assert {d.name for d in deps} == {"flask", "rich"}
        assert _gaps(diags) == {(manifest, _unfollowed(value, "is not a relative path"))}
        assert [call for call in calls if "example.invalid" in call[1]] == []

    @pytest.mark.parametrize(
        "value",
        [
            "https://example.invalid/requirements.txt",
            "http://example.invalid/requirements.txt",
            "file:///example.invalid/requirements.txt",
        ],
    )
    @respx.mock
    def test_url_is_a_gap_and_is_never_fetched_or_opened(self, tmp_path: Path, monkeypatch, value):
        # No route is mocked: a request would fail the test.
        manifest = _write(tmp_path / "requirements.txt", f"flask\n--requirement={value}\n")
        calls = _record_path_io(monkeypatch, "example.invalid")

        deps, diags = _discover(tmp_path)

        assert {d.name for d in deps} == {"flask"}
        assert _gaps(diags) == {(manifest, _unfollowed(value, "is a URL"))}
        assert [call for call in calls if "example.invalid" in call[1]] == []
        assert respx.calls.call_count == 0

    @pytest.mark.parametrize("value", ["missing.txt", "deps/missing.txt", "deps", "${HOME}/r.txt"])
    def test_include_that_is_not_a_file_is_a_gap(self, tmp_path: Path, value):
        (tmp_path / "deps").mkdir()
        manifest = _write(tmp_path / "requirements.txt", f"-r {value}\nflask\n")

        deps, diags = _discover(tmp_path)

        assert {d.name for d in deps} == {"flask"}
        assert _gaps(diags) == {(manifest, _unfollowed(value, "is not a file"))}

    def test_gap_is_on_the_file_that_names_the_include(self, tmp_path: Path):
        _write(tmp_path / "requirements.txt", "-r deps/a.txt\nflask\n")
        nested = _write(tmp_path / "deps" / "a.txt", "-r missing.txt\nrich\n")

        deps, diags = _discover(tmp_path)

        assert {d.name for d in deps} == {"flask", "rich"}
        assert _gaps(diags) == {(nested, _unfollowed("missing.txt", "is not a file"))}

    def test_include_outside_the_scanned_directory_is_a_gap(self, tmp_path: Path):
        project = tmp_path / "project"
        manifest = _write(project / "requirements.txt", "-r ../outside.txt\nflask\n")
        _write(tmp_path / "outside.txt", "not-in-this-project==1.0\n")

        deps, diags = _discover(project)

        assert {d.name for d in deps} == {"flask"}
        assert _gaps(diags) == {
            (manifest, _unfollowed("../outside.txt", "is outside the scanned directory"))
        }

    def test_include_that_returns_into_the_scanned_directory_is_followed(self, tmp_path: Path):
        # ``..`` is not refused as such: what matters is where the path ends.
        project = tmp_path / "project"
        _write(project / "requirements.txt", "-r ../project/deps/pinned.txt\n")
        _write(project / "deps" / "pinned.txt", "flask==3.0.0\n")

        deps, diags = _discover(project)

        assert _rows(deps) == {("flask", "==3.0.0", PROD, "deps/pinned.txt")}
        assert diags == []

    def test_include_through_a_link_out_of_the_scanned_directory_is_a_gap(self, tmp_path: Path):
        project = tmp_path / "project"
        manifest = _write(project / "requirements.txt", "-r linked/reqs.txt\nflask\n")
        _write(tmp_path / "elsewhere" / "reqs.txt", "not-in-this-project==1.0\n")
        link = project / "linked"
        try:
            if sys.platform == "win32":
                import _winapi

                _winapi.CreateJunction(str(tmp_path / "elsewhere"), str(link))
            else:
                os.symlink(tmp_path / "elsewhere", link, target_is_directory=True)
        except OSError:  # pragma: no cover - a filesystem that cannot link
            pytest.skip("this filesystem cannot create a directory link")

        deps, diags = _discover(project)

        assert {d.name for d in deps} == {"flask"}
        assert _gaps(diags) == {
            (manifest, _unfollowed("linked/reqs.txt", "is outside the scanned directory"))
        }

    @pytest.mark.parametrize("error", [OSError, ValueError, RuntimeError])
    def test_include_the_filesystem_cannot_resolve_is_a_gap(
        self, tmp_path: Path, monkeypatch, error
    ):
        # What a link that loops back on itself does on some interpreters.
        manifest = _write(tmp_path / "requirements.txt", "-r loop/reqs.txt\nflask\n")
        original = Path.resolve

        def resolve(self, *args, **kwargs):
            if "loop" in self.parts:
                raise error("cannot resolve")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "resolve", resolve)

        deps, diags = _discover(tmp_path)

        assert {d.name for d in deps} == {"flask"}
        assert _gaps(diags) == {(manifest, _unfollowed("loop/reqs.txt", "is not a file"))}

    def test_included_file_that_cannot_be_decoded_is_a_gap_on_that_file(self, tmp_path: Path):
        _write(tmp_path / "requirements.txt", "-r deps/broken.txt\nflask\n")
        broken = tmp_path / "deps" / "broken.txt"
        broken.parent.mkdir()
        broken.write_bytes(b"\xff\xfe\x52")

        deps, diags = _discover(tmp_path)

        assert {d.name for d in deps} == {"flask"}
        assert _gaps(diags) == {
            (broken, "has a UTF-16 byte-order mark but is not valid UTF-16; skipped")
        }

    @pytest.mark.parametrize("line", ["-r", "--requirement", "--requirement=", "-r   "])
    def test_option_with_no_path_names_nothing(self, tmp_path: Path, line):
        _write(tmp_path / "requirements.txt", line + "\nflask\n")
        deps, diags = _discover(tmp_path)
        assert {d.name for d in deps} == {"flask"}
        assert diags == []

    @pytest.mark.parametrize(
        "line", ["--requirements.txt", "--require-hashes", "-requirements.txt"]
    )
    def test_other_options_are_not_includes(self, tmp_path: Path, line):
        # Only ``-r`` and ``--requirement`` name a file. ``-requirements.txt``
        # is ``-r`` with the value ``equirements.txt``, which is how pip
        # reads it too.
        manifest = _write(tmp_path / "requirements.txt", line + "\nflask\n")
        deps, diags = _discover(tmp_path)
        assert {d.name for d in deps} == {"flask"}
        expected = (
            {(manifest, _unfollowed("equirements.txt", "is not a file"))}
            if line == "-requirements.txt"
            else set()
        )
        assert _gaps(diags) == expected


class TestCheckCommand:
    @respx.mock
    def test_include_that_cannot_be_followed_beside_a_healthy_manifest(self, tmp_path: Path):
        # The healthy lines of the same file, and the manifest beside it, are
        # still resolved; only ``--strict`` fails; fixing the line is the control.
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n')
        manifest = _write(tmp_path / "svc" / "requirements.txt", "-r base/missing.txt\nflask\n")
        _write(tmp_path / "svc" / "base" / "pinned.txt", "left-pad\n")
        _mock_pypi("flask", "BSD-3-Clause")
        _mock_pypi("left-pad", "MIT")

        _assert_gap_fails_only_strict(
            tmp_path,
            manifest,
            _unfollowed("base/missing.txt", "is not a file"),
            [("flask", "BSD-3-Clause")],
            repair=lambda: manifest.write_text("-r base/pinned.txt\nflask\n", encoding="utf-8"),
        )

    @respx.mock
    def test_included_requirements_are_reported_with_their_group_and_source(self, tmp_path: Path):
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n')
        _write(tmp_path / "requirements.txt", "-r deps/base.txt\n")
        _write(tmp_path / "requirements-dev.txt", "-r deps/base.txt\n-r deps/tools.txt\n")
        _write(tmp_path / "deps" / "base.txt", "flask\n")
        _write(tmp_path / "deps" / "tools.txt", "left-pad\n")
        _mock_pypi("flask", "BSD-3-Clause")
        _mock_pypi("left-pad", "MIT")

        def reported(*flags: str) -> list[tuple[str, str, str]]:
            result, data = _check_json(tmp_path, "--strict", *flags)
            assert result.exit_code == 0
            assert data["summary"]["gaps"] == 0
            return sorted((d["name"], d["group"], d["source"]) for d in data["dependencies"])

        assert reported("--no-dev") == [("flask", "prod", "deps/base.txt")]
        assert reported("--dev") == [
            ("flask", "prod", "deps/base.txt"),
            ("left-pad", "dev", "deps/tools.txt"),
        ]
