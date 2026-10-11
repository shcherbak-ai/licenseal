"""A live ``init-review-file`` scaffolds the dependencies ``check`` flags.

Without ``--from-report`` the command scans the project itself. That scan is
the one ``check`` runs with its default options: lockfiles first, the
transitive graph, the same ``--dev`` filter and exclusions. Every stanza it
writes is therefore keyed as ``check`` reports the row, and filling it in is
enough for the next ``check`` to apply it.

Each test starts from files on disk and ends with that ``check``.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import respx
from click.testing import CliRunner, Result

from licenseal.cli import main
from licenseal.review import load_review_file, review_key, source_review_key
from tests._helpers import _check_json, _write

_PYPI = "https://pypi.org/pypi"
_FORK = "git+https://git.example.org/team/fork.git"
_FORK_LOCKED = '{ git = "https://git.example.org/team/fork.git?rev=main#0123abcd" }'
_FORK_KEY = f"off-registry python:fork from {_FORK}@0123abcd"


def _release(name: str, version: str, license_text: str) -> respx.Route:
    """Answer PyPI's endpoint for one release, which declares no dependencies."""
    return respx.get(f"{_PYPI}/{name}/{version}/json").mock(
        return_value=httpx.Response(
            200,
            json={"info": {"version": version, "license": license_text, "requires_dist": []}},
        )
    )


def _init(project: Path, *flags: str) -> Result:
    return CliRunner().invoke(main, ["init-review-file", "--path", str(project), *flags])


def _scaffolded(project: Path) -> list[str]:
    """The keys of the stanzas ``init-review-file`` left to fill in, sorted."""
    return sorted(load_review_file(project).incomplete)


def _fill_in(project: Path, license_id: str = "MIT") -> None:
    """Give every scaffolded stanza a reviewed license."""
    review = project / "licenseal.review.toml"
    text = review.read_text(encoding="utf-8")
    review.write_text(
        text.replace('license = ""', f'license = "{license_id}"'), encoding="utf-8", newline="\n"
    )


def _flagged_keys(data: dict) -> list[str]:
    """The review key of every flagged row of a ``check`` JSON report, sorted."""
    keys = []
    for dep in data["dependencies"]:
        if dep["verdict"] == "compatible":
            continue
        if dep["origin"]:
            keys.append(source_review_key(dep["ecosystem"], dep["name"], dep["origin"]))
        else:
            keys.append(review_key(dep["ecosystem"], dep["name"], dep["resolved_version"]))
    return sorted(keys)


def _reviewed(data: dict) -> dict[str, bool]:
    return {dep["name"]: dep["reviewed"] for dep in data["dependencies"]}


def _names(*names: str) -> str:
    """A TOML array of ``{ name = "..." }`` tables, as ``uv.lock`` lists dependencies."""
    return "[" + ", ".join('{ name = "' + name + '" }' for name in names) + "]"


def _app(*roots: str, dev: tuple[str, ...] = ()) -> str:
    """The lockfile table of the project itself, which depends on ``roots``."""
    table = (
        '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        f"dependencies = {_names(*roots)}\n"
    )
    if dev:
        table += f"\n[package.optional-dependencies]\ndev = {_names(*dev)}\n"
    return table


def _locked(name: str, version: str, *requires: str, source: str = "") -> str:
    """The lockfile table of one package, from PyPI unless ``source`` says otherwise."""
    source = source or '{ registry = "https://pypi.org/simple" }'
    table = f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = {source}\n'
    if requires:
        table += f"dependencies = {_names(*requires)}\n"
    return table


def _uv_project(tmp_path: Path, dependencies: str, lock: str, extra: str = "") -> Path:
    """A project declaring ``dependencies`` (a TOML list), locked by ``lock``."""
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\nversion = "0.1.0"\nlicense = "MIT"\n'
        f"dependencies = {dependencies}\n{extra}",
    )
    _write(tmp_path / "uv.lock", f"version = 1\n\n{lock}")
    return tmp_path


class TestFlaggedTransitive:
    """A flagged package that only a lockfile lists gets a stanza."""

    @staticmethod
    def _project(tmp_path: Path) -> Path:
        project = _uv_project(
            tmp_path,
            '["direct-lib"]',
            _app("direct-lib")
            + _locked("direct-lib", "1.0.0", "gpl-child")
            + _locked("gpl-child", "2.0.0"),
        )
        _release("direct-lib", "1.0.0", "MIT")
        _release("gpl-child", "2.0.0", "GPL-3.0-only")
        return project

    @respx.mock
    def test_transitive_is_scaffolded_and_its_review_applies(self, tmp_path):
        project = self._project(tmp_path)
        result = _init(project)
        assert result.exit_code == 0
        assert "Wrote licenseal.review.toml with 1 review entry." in result.output
        assert _scaffolded(project) == ["python:gpl-child@2.0.0"]

        _fill_in(project, "LGPL-3.0-only")
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _reviewed(data) == {"direct-lib": False, "gpl-child": True}
        assert data["summary"]["reviewed"] == 1

    @respx.mock
    def test_scaffold_is_what_check_flags(self, tmp_path):
        project = self._project(tmp_path)
        _, data = _check_json(project)
        _init(project)
        assert _scaffolded(project) == _flagged_keys(data) == ["python:gpl-child@2.0.0"]


class TestLockedVersion:
    """A direct dependency is keyed at its locked version, not the highest in range."""

    @respx.mock
    def test_locked_version_is_scaffolded_and_its_review_applies(self, tmp_path):
        project = _uv_project(
            tmp_path, '["mystery>=1.0"]', _app("mystery") + _locked("mystery", "1.2.0")
        )
        _release("mystery", "1.2.0", "Unknown")
        # The registry has a newer release inside the range. It is not the
        # one the project installs, and nothing is asked about it.
        newer = _release("mystery", "1.5.0", "Unknown")
        listing = respx.get(f"{_PYPI}/mystery/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "1.5.0", "license": "Unknown", "requires_dist": []},
                    "releases": {"1.2.0": [], "1.5.0": []},
                },
            )
        )
        result = _init(project)
        assert result.exit_code == 0
        assert _scaffolded(project) == ["python:mystery@1.2.0"]
        assert not newer.called
        assert not listing.called

        _fill_in(project)
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert _reviewed(data) == {"mystery": True}


class TestLockedOrigin:
    """An off-registry dependency is keyed on the commit its lockfile records."""

    @respx.mock
    def test_locked_commit_is_scaffolded_and_its_review_applies(self, tmp_path):
        project = _uv_project(
            tmp_path,
            f'["fork @ {_FORK}@main"]',
            _app("fork") + _locked("fork", "1.2.0", source=_FORK_LOCKED),
        )
        result = _init(project)
        assert result.exit_code == 0
        assert _scaffolded(project) == [_FORK_KEY]
        text = (project / "licenseal.review.toml").read_text(encoding="utf-8")
        # The branch the manifest names is not what the stanza is keyed on.
        assert f'source = "{_FORK}@0123abcd"' in text
        assert 'version = "1.2.0"' in text
        assert "@main" not in text

        _fill_in(project)
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert _reviewed(data) == {"fork": True}
        (row,) = data["dependencies"]
        assert (row["origin"], row["resolved_version"]) == (f"{_FORK}@0123abcd", "1.2.0")


class TestSameScanAsCheck:
    """One project with all three, and the options the two commands share."""

    _PROD = sorted([_FORK_KEY, "python:gpl-child@2.0.0", "python:mystery@1.2.0"])
    _DEV = "python:dev-child@4.0.0"

    @staticmethod
    def _project(tmp_path: Path) -> Path:
        project = _uv_project(
            tmp_path,
            f'["direct-lib", "mystery>=1.0", "fork @ {_FORK}@main"]',
            _app("direct-lib", "mystery", "fork", dev=("dev-tool",))
            + _locked("direct-lib", "1.0.0", "gpl-child")
            + _locked("gpl-child", "2.0.0")
            + _locked("mystery", "1.2.0")
            + _locked("fork", "1.2.0", source=_FORK_LOCKED)
            + _locked("dev-tool", "3.0.0", "dev-child")
            + _locked("dev-child", "4.0.0"),
            extra='\n[project.optional-dependencies]\ndev = ["dev-tool"]\n',
        )
        _release("direct-lib", "1.0.0", "MIT")
        _release("gpl-child", "2.0.0", "GPL-3.0-only")
        _release("mystery", "1.2.0", "Unknown")
        _release("dev-tool", "3.0.0", "MIT")
        _release("dev-child", "4.0.0", "GPL-3.0-only")
        return project

    @respx.mock
    def test_scaffold_matches_the_flagged_rows_of_check(self, tmp_path):
        project = self._project(tmp_path)
        _, data = _check_json(project)
        result = _init(project)
        assert result.exit_code == 0
        assert _scaffolded(project) == _flagged_keys(data) == self._PROD

        _fill_in(project)
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == 3

    @respx.mock
    def test_dev_only_transitive_needs_the_dev_flag(self, tmp_path):
        project = self._project(tmp_path)
        _, data = _check_json(project, "--dev")
        result = _init(project, "--dev")
        assert result.exit_code == 0
        assert _scaffolded(project) == _flagged_keys(data) == sorted([*self._PROD, self._DEV])

        _fill_in(project)
        result, data = _check_json(project, "--dev")
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == 4

    @respx.mock
    def test_merge_adds_what_a_later_scan_flags(self, tmp_path):
        # Reviewed without dev dependencies first, then extended for --dev:
        # the filled-in stanzas stay, and only the new row is appended.
        project = self._project(tmp_path)
        _init(project)
        _fill_in(project)
        result = _init(project, "--dev", "--merge")
        assert result.exit_code == 0
        assert "Appended 1 review entry to licenseal.review.toml." in result.output
        contents = load_review_file(project)
        assert sorted(contents.licenses) == self._PROD
        assert contents.incomplete == [self._DEV]

    @respx.mock
    def test_excluded_directory_is_left_out(self, tmp_path):
        project = self._project(tmp_path)
        _write(project / "tools" / "requirements.txt", "gpl-tool==9.0.0\n")
        _release("gpl-tool", "9.0.0", "GPL-3.0-only")
        result = _init(project, "--exclude-dirs", "tools")
        assert result.exit_code == 0
        assert _scaffolded(project) == self._PROD
        # Control: without the exclusion its flagged requirement is scaffolded.
        result = _init(project, "--merge")
        assert result.exit_code == 0
        assert _scaffolded(project) == sorted([*self._PROD, "python:gpl-tool@9.0.0"])

    @respx.mock
    def test_says_what_it_scans_the_way_check_does(self, tmp_path):
        result = _init(self._project(tmp_path))
        assert "Found 3 direct dependencies. Resolving transitive graph..." in result.output


class TestWithoutALockfile:
    """No lockfile: the scaffold follows the registry walk ``check`` falls back to."""

    @respx.mock
    def test_transitive_from_the_registry_walk_is_scaffolded(self, tmp_path):
        _write(
            tmp_path / "pyproject.toml",
            '[project]\nname = "app"\nlicense = "MIT"\ndependencies = ["direct-lib==1.0.0"]\n',
        )
        respx.get(f"{_PYPI}/direct-lib/1.0.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "requires_dist": ["gpl-child==2.0.0"],
                    }
                },
            )
        )
        _release("gpl-child", "2.0.0", "GPL-3.0-only")

        _, data = _check_json(tmp_path, "--no-require-lockfile")
        result = _init(tmp_path)
        assert result.exit_code == 0
        assert _scaffolded(tmp_path) == _flagged_keys(data) == ["python:gpl-child@2.0.0"]
        # The manifest has no lockfile, and the scaffold says so as check does.
        assert (
            "Warning: pyproject.toml: declares dependencies that no lockfile covers"
            in result.output
        )

        _fill_in(tmp_path)
        result, data = _check_json(tmp_path, "--no-require-lockfile")
        assert result.exit_code == 0
        assert _reviewed(data) == {"direct-lib": False, "gpl-child": True}

    @respx.mock
    def test_project_with_nothing_to_resolve(self, tmp_path):
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\nlicense = "MIT"\n')
        result = _init(tmp_path)
        assert result.exit_code == 0
        assert "No dependencies to resolve." in result.output
        assert "No reviewable flagged dependencies found." in result.output
        assert not (tmp_path / "licenseal.review.toml").exists()
