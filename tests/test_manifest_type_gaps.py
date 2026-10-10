"""A manifest or lockfile value of the wrong type is a gap, never a crash.

A file that parses can still hold a string where its format wants a table, or
a number where it wants a version string. Each case here writes such a file
beside a healthy one and scans the directory: the scan returns, the healthy
file and the well-formed parts of the bad one are still read, and the value
that could not be read is on record.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx

from licenseal.discovery import detect_project_license, discover_all_dependencies
from licenseal.discovery._read import ReadDiagnostic, collect_read_diagnostics
from licenseal.models import Dependency, DependencyGroup
from tests._helpers import (
    _assert_gap_fails_only_strict,
    _gaps,
    _mock_npm,
    _mock_pypi,
    _resolve,
    _write,
)


def _reason(what: str) -> str:
    return f"{what} has an unexpected type; ignored"


def _discover(project: Path) -> tuple[list[Dependency], list[ReadDiagnostic]]:
    with collect_read_diagnostics() as diags:
        deps, _ = discover_all_dependencies(project)
    return deps, diags


def _found(deps: list[Dependency]) -> set[tuple[str, str]]:
    return {(dep.name, dep.version_constraint) for dep in deps}


PROD = DependencyGroup.PROD
DEV = DependencyGroup.DEV
_HEALTHY = ("requests", "==2.31.0")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return tmp_path


class TestPackageJson:
    @pytest.mark.parametrize(
        "section", ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
    )
    @pytest.mark.parametrize("value", [[], ["left-pad"], "left-pad", 1, 1.5, True])
    def test_section_of_the_wrong_type_is_a_gap_and_the_others_are_read(
        self, project: Path, section, value
    ):
        sections = {
            "dependencies": {"a": "1.0.0"},
            "devDependencies": {"b": "2.0.0"},
            "peerDependencies": {"c": "3.0.0"},
            "optionalDependencies": {"d": "4.0.0"},
        }
        declared = {name: spec for entries in sections.values() for name, spec in entries.items()}
        lost = next(iter(sections[section]))
        manifest = project / "svc" / "package.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({"name": "svc", **sections, section: value}))

        deps, diags = _discover(project)

        expected = {(name, spec) for name, spec in declared.items() if name != lost}
        assert _found(deps) == expected | {_HEALTHY}
        assert _gaps(diags) == {(manifest, _reason(f'"{section}"'))}

    @pytest.mark.parametrize("spec", [None, 1, 1.5, True, [], ["1.0.0"], {}, {"version": "1.0.0"}])
    def test_spec_that_is_not_a_string_keeps_the_name_and_is_a_gap(self, project: Path, spec):
        manifest = project / "svc" / "package.json"
        manifest.parent.mkdir()
        manifest.write_text(
            json.dumps({"dependencies": {"left-pad": spec, "right-pad": "1.0.0"}}),
        )

        deps, diags = _discover(project)

        # The name is declared, so it stays in the scan without a constraint.
        assert _found(deps) == {("left-pad", ""), ("right-pad", "1.0.0"), _HEALTHY}
        assert _gaps(diags) == {(manifest, _reason('an entry of "dependencies"'))}

    @pytest.mark.parametrize("root", [[], [{"dependencies": {"a": "1"}}], "x", 1, 1.5, True])
    def test_top_level_that_is_not_an_object_is_a_gap(self, project: Path, root):
        manifest = project / "svc" / "package.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps(root))

        with collect_read_diagnostics() as diags:
            assert detect_project_license(project) == ""
            deps, _ = discover_all_dependencies(project)

        assert _found(deps) == {_HEALTHY}
        assert _gaps(diags) == {(manifest, _reason("the top level"))}

    @pytest.mark.parametrize("value", [None, {}])
    @pytest.mark.parametrize("section", ["dependencies", "devDependencies"])
    def test_null_or_empty_section_declares_nothing_and_is_clean(
        self, project: Path, section, value
    ):
        manifest = project / "svc" / "package.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({"peerDependencies": {"c": "3.0.0"}, section: value}))

        deps, diags = _discover(project)

        assert _found(deps) == {("c", "3.0.0"), _HEALTHY}
        assert diags == []

    def test_null_document_declares_nothing_and_is_clean(self, project: Path):
        (project / "svc").mkdir()
        (project / "svc" / "package.json").write_text("null")
        deps, diags = _discover(project)
        assert _found(deps) == {_HEALTHY}
        assert diags == []

    @pytest.mark.parametrize("name", [1, ["svc"], {"x": "y"}, True, None])
    def test_name_of_the_wrong_type_filters_nothing_and_is_clean(self, project: Path, name):
        # The package's own name only decides which sibling references are
        # workspace-local. One that cannot be read filters nothing out.
        manifest = project / "svc" / "package.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({"name": name, "dependencies": {"a": "1.0.0"}}))

        deps, diags = _discover(project)

        assert _found(deps) == {("a", "1.0.0"), _HEALTHY}
        assert diags == []


_PYPROJECT_CASES = [
    pytest.param(
        """\
        project = "x"

        [tool.poetry.dependencies]
        rich = "^13"
        """,
        {("rich", "^13")},
        {"project"},
        id="project-is-a-string",
    ),
    pytest.param(
        """\
        [project]
        dependencies = "flask"
        optional-dependencies = { extra = ["rich"] }
        """,
        # A string is not iterated into one requirement per character.
        {("rich", "")},
        {"project.dependencies"},
        id="dependencies-is-a-string",
    ),
    pytest.param(
        """\
        [project]
        dependencies = 3
        optional-dependencies = { extra = ["rich"] }
        """,
        {("rich", "")},
        {"project.dependencies"},
        id="dependencies-is-a-number",
    ),
    pytest.param(
        """\
        [project]
        dependencies = ["flask==3.0.0", 3, ["rich"], { name = "click" }]
        """,
        {("flask", "==3.0.0")},
        {"an entry of project.dependencies"},
        id="dependencies-item-is-not-a-string",
    ),
    pytest.param(
        """\
        [project]
        dependencies = ["flask==3.0.0"]
        optional-dependencies = "pytest"
        """,
        {("flask", "==3.0.0")},
        {"project.optional-dependencies"},
        id="optional-dependencies-is-a-string",
    ),
    pytest.param(
        """\
        [project]
        dependencies = ["flask==3.0.0"]

        [project.optional-dependencies]
        dev = "pytest"
        extra = ["rich"]
        """,
        # ``dev = "pytest"`` is one string, not the six requirements p, y, t, e, s, t.
        {("flask", "==3.0.0"), ("rich", "")},
        {"an entry of project.optional-dependencies"},
        id="extra-is-a-string",
    ),
    pytest.param(
        """\
        [project.optional-dependencies]
        extra = ["rich", 3]
        """,
        {("rich", "")},
        {"an entry of project.optional-dependencies"},
        id="extra-item-is-not-a-string",
    ),
    pytest.param(
        """\
        dependency-groups = "pytest"

        [project]
        dependencies = ["flask==3.0.0"]
        """,
        {("flask", "==3.0.0")},
        {"dependency-groups"},
        id="dependency-groups-is-a-string",
    ),
    pytest.param(
        """\
        [dependency-groups]
        dev = "pytest"
        lint = ["ruff"]
        """,
        {("ruff", "")},
        {"an entry of dependency-groups"},
        id="dependency-group-is-a-string",
    ),
    pytest.param(
        """\
        [dependency-groups]
        dev = ["pytest", 3, { other = "x" }, { include-group = 3 }, { include-group = "lint" }]
        lint = ["ruff"]
        """,
        {("pytest", ""), ("ruff", "")},
        {"an entry of dependency-groups"},
        id="dependency-group-item-is-neither-form",
    ),
    pytest.param(
        """\
        tool = "x"

        [project]
        dependencies = ["flask==3.0.0"]
        """,
        {("flask", "==3.0.0")},
        {"tool"},
        id="tool-is-a-string",
    ),
    pytest.param(
        """\
        [project]
        dependencies = ["flask==3.0.0"]

        [tool]
        poetry = ["x"]
        """,
        {("flask", "==3.0.0")},
        {"tool.poetry"},
        id="tool-poetry-is-a-list",
    ),
    pytest.param(
        """\
        [tool.poetry]
        dependencies = "django"

        [tool.poetry.group.extra.dependencies]
        rich = "^13"
        """,
        {("rich", "^13")},
        {"tool.poetry.dependencies"},
        id="poetry-dependencies-is-a-string",
    ),
    pytest.param(
        """\
        [tool.poetry.dependencies]
        python = "^3.10"
        django = 4
        httpx = { version = 5, extras = ["http2"] }
        click = { version = "^8", extras = "colour" }
        rich = { version = "^13", extras = ["jupyter", 3] }
        """,
        # Each dependency is still declared: it keeps what could be read.
        {("django", ""), ("httpx", ""), ("click", "^8"), ("rich", "^13")},
        {"an entry of tool.poetry.dependencies"},
        id="poetry-spec-is-not-a-readable-form",
    ),
    pytest.param(
        """\
        [tool.poetry]
        group = "dev"

        [tool.poetry.dependencies]
        django = "^4"
        """,
        {("django", "^4")},
        {"tool.poetry.group"},
        id="poetry-group-is-a-string",
    ),
    pytest.param(
        """\
        [tool.poetry.group]
        dev = "pytest"

        [tool.poetry.group.extra.dependencies]
        rich = "^13"
        """,
        {("rich", "^13")},
        {"an entry of tool.poetry.group"},
        id="poetry-group-entry-is-a-string",
    ),
    pytest.param(
        """\
        [tool.poetry.group.dev]
        dependencies = ["pytest"]

        [tool.poetry.group.extra.dependencies]
        rich = "^13"
        black = true
        """,
        {("rich", "^13"), ("black", "")},
        {"an entry of tool.poetry.group"},
        id="poetry-group-dependencies-is-a-list",
    ),
]


class TestPyproject:
    @pytest.mark.parametrize(("content", "found", "what"), _PYPROJECT_CASES)
    def test_value_of_the_wrong_type_is_a_gap_and_the_rest_is_read(
        self, project: Path, content, found, what
    ):
        manifest = _write(project / "svc" / "pyproject.toml", content)

        with collect_read_diagnostics() as diags:
            detect_project_license(project)
            deps, _ = discover_all_dependencies(project)

        assert _found(deps) == found | {_HEALTHY}
        assert _gaps(diags) == {(manifest, _reason(item)) for item in what}

    def test_extras_that_could_be_read_are_kept(self, project: Path):
        _write(
            project / "svc" / "pyproject.toml",
            """\
            [tool.poetry.dependencies]
            rich = { version = "^13", extras = ["jupyter", 3] }
            """,
        )
        deps, _ = _discover(project)
        assert {d.name: d.extras for d in deps}["rich"] == frozenset({"jupyter"})

    def test_poetry_multiple_constraints_form_is_clean(self, project: Path):
        # One constraint table per environment is a valid spec with no single
        # version, not a value of the wrong type.
        _write(
            project / "svc" / "pyproject.toml",
            """\
            [tool.poetry.dependencies]
            numpy = [
                { version = "<=1.24", python = "<3.9" },
                { version = "^1.26", python = ">=3.9" },
            ]
            """,
        )
        deps, diags = _discover(project)
        assert _found(deps) == {("numpy", ""), _HEALTHY}
        assert diags == []

    @pytest.mark.parametrize(
        "content",
        [
            '[project]\nname = 3\nlicense = 3\ndependencies = ["flask"]\n',
            '[project]\nname = ["x"]\nlicense = { text = 3 }\ndependencies = ["flask"]\n',
            '[project]\nlicense = ["MIT"]\nclassifiers = "x"\ndependencies = ["flask"]\n',
            '[project]\nclassifiers = [3, ["x"]]\ndependencies = ["flask"]\n',
            '[project]\ndependencies = ["flask"]\n[tool.poetry]\nname = 3\nlicense = 3\n',
        ],
        ids=[
            "name-and-license-numbers",
            "license-text-number",
            "classifiers-string",
            "classifier-items-not-strings",
            "poetry-name-and-license-numbers",
        ],
    )
    def test_project_metadata_of_the_wrong_type_reads_as_absent_and_is_clean(
        self, project: Path, content
    ):
        # The project's own name and license describe the project, not a
        # dependency. One that cannot be read leaves the strictest default
        # (no license, nothing filtered as workspace-local) and loses nothing.
        _write(project / "svc" / "pyproject.toml", content)

        with collect_read_diagnostics() as diags:
            assert detect_project_license(project) == ""
            deps, _ = discover_all_dependencies(project)

        assert _found(deps) == {("flask", ""), _HEALTHY}
        assert diags == []

    def test_license_is_still_read_past_a_classifier_of_the_wrong_type(self, project: Path):
        _write(
            project / "svc" / "pyproject.toml",
            """\
            [project]
            classifiers = [3, "License :: OSI Approved :: MIT License"]
            """,
        )
        assert detect_project_license(project) == "MIT License"

    def test_name_is_read_from_poetry_when_the_project_table_is_not_a_table(self, project: Path):
        # ``other`` depends on ``svc`` by name. ``svc`` is still recognised as
        # a workspace package through its Poetry name, so the reference is
        # filtered, and the unreadable ``project`` value is on record.
        manifest = _write(
            project / "svc" / "pyproject.toml",
            """\
            project = 3

            [tool.poetry]
            name = "svc"
            """,
        )
        _write(
            project / "other" / "pyproject.toml",
            """\
            [project]
            name = "other"
            dependencies = ["svc", "flask"]
            """,
        )
        with collect_read_diagnostics() as diags:
            deps, filtered = discover_all_dependencies(project)
        assert _found(deps) == {("flask", ""), _HEALTHY}
        assert filtered["python"] == 1
        assert _gaps(diags) == {(manifest, _reason("project"))}


class TestPipfile:
    @pytest.mark.parametrize(
        ("content", "found", "what"),
        [
            pytest.param(
                'packages = "flask"\n\n[dev-packages]\npytest = "*"\n',
                {("pytest", "")},
                "packages",
                id="packages-is-a-string",
            ),
            pytest.param(
                '[packages]\nflask = "*"\n\n[dev-packages]\nx = ["pytest"]\n',
                {("flask", ""), ("x", "")},
                "an entry of dev-packages",
                id="spec-is-a-list",
            ),
            pytest.param(
                '[packages]\nflask = 3\ndjango = { version = 4 }\nrich = { extras = "x" }\n',
                {("flask", ""), ("django", ""), ("rich", "")},
                "an entry of packages",
                id="spec-is-not-a-readable-form",
            ),
        ],
    )
    def test_value_of_the_wrong_type_is_a_gap_and_the_rest_is_read(
        self, project: Path, content, found, what
    ):
        manifest = _write(project / "svc" / "Pipfile", content)
        deps, diags = _discover(project)
        assert _found(deps) == found | {_HEALTHY}
        assert _gaps(diags) == {(manifest, _reason(what))}


class TestComposerJson:
    @pytest.mark.parametrize(
        ("document", "found", "what"),
        [
            pytest.param(
                {"require": "a/b", "require-dev": {"c/d": "^1"}},
                {("c/d", "^1")},
                '"require"',
                id="require-is-a-string",
            ),
            pytest.param(
                {"require": ["a/b"], "require-dev": {"c/d": "^1"}},
                {("c/d", "^1")},
                '"require"',
                id="require-is-a-non-empty-list",
            ),
            pytest.param(
                {"require": {"a/b": "^2"}, "require-dev": 3},
                {("a/b", "^2")},
                '"require-dev"',
                id="require-dev-is-a-number",
            ),
            pytest.param(
                {"require": {"a/b": None, "c/d": ["^1"], "e/f": "^3"}},
                {("a/b", ""), ("c/d", ""), ("e/f", "^3")},
                'an entry of "require"',
                id="constraint-is-not-a-string",
            ),
            pytest.param(["a/b"], set(), "the top level", id="top-level-is-a-list"),
        ],
    )
    def test_value_of_the_wrong_type_is_a_gap_and_the_rest_is_read(
        self, project: Path, document, found, what
    ):
        manifest = project / "svc" / "composer.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps(document))

        with collect_read_diagnostics() as diags:
            assert detect_project_license(project) == ""
            deps, _ = discover_all_dependencies(project)

        assert _found(deps) == found | {_HEALTHY}
        assert _gaps(diags) == {(manifest, _reason(what))}

    def test_empty_list_is_an_empty_map_and_is_clean(self, project: Path):
        # PHP serialises an empty map as an empty array.
        manifest = project / "svc" / "composer.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({"require": [], "require-dev": {"c/d": "^1"}}))
        deps, diags = _discover(project)
        assert _found(deps) == {("c/d", "^1"), _HEALTHY}
        assert diags == []

    def test_platform_requirement_is_not_read_whatever_its_type(self, project: Path):
        manifest = project / "svc" / "composer.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({"require": {"php": 8, "a/b": "^2"}}))
        deps, diags = _discover(project)
        assert _found(deps) == {("a/b", "^2"), _HEALTHY}
        assert diags == []


_NPM_MANIFEST = {"name": "app", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}}
_ROWS_A_B_D = {("a", "==1.0.0", PROD), ("b", "==1.0.0", PROD), ("d", "==1.0.0", DEV)}


def _npm_project(tmp_path: Path, lockfile: str, content: str) -> Path:
    (tmp_path / "package.json").write_text(json.dumps(_NPM_MANIFEST))
    return _write(tmp_path / lockfile, content)


class TestPackageLock:
    @staticmethod
    def _v3(packages: object) -> str:
        return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages})

    @pytest.mark.parametrize("packages", [[], ["node_modules/a"], "x", 3, True])
    def test_packages_of_the_wrong_type_is_a_gap(self, tmp_path: Path, packages):
        lock = _npm_project(tmp_path, "package-lock.json", self._v3(packages))
        rows, diags = _resolve(tmp_path)
        # Nothing is pinned, so the direct dependencies are all that is known.
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason('"packages"'))}

    @pytest.mark.parametrize(
        "bad",
        [
            {"node_modules/x": "1.0.0"},
            {"node_modules/x": ["1.0.0"]},
            {"node_modules/x": {"version": 1}},
            {"node_modules/x": {"version": "1.0.0", "name": 3}},
            {"node_modules/x": {"version": "1.0.0", "dependencies": ["b"]}},
            {"node_modules/x": {"version": "1.0.0", "peerDependencies": "b"}},
            {"node_modules/x": {"version": "1.0.0", "optionalDependencies": 3}},
            {"node_modules/x": {"version": "1.0.0", "transitivePeerDependencies": "b"}},
        ],
        ids=[
            "entry-string",
            "entry-list",
            "version-number",
            "name-number",
            "dependencies-list",
            "peer-dependencies-string",
            "optional-dependencies-number",
            "transitive-peers-string",
        ],
    )
    def test_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(self, tmp_path: Path, bad):
        packages = {
            "": {"name": "app"},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}},
            "node_modules/b": {"version": "1.0.0"},
            "node_modules/d": {"version": "1.0.0", "dev": True},
            **bad,
        }
        lock = _npm_project(tmp_path, "package-lock.json", self._v3(packages))
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert _gaps(diags) == {(lock, _reason('an entry of "packages"'))}

    def test_entries_without_a_version_are_not_a_gap(self, tmp_path: Path):
        # A workspace link carries no version; an absent field is not one of
        # the wrong type.
        packages = {
            "": {"name": "app"},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}},
            "node_modules/b": {"version": "1.0.0"},
            "node_modules/d": {"version": "1.0.0"},
            "node_modules/link": {"resolved": "packages/link", "link": True},
            "packages/link": {"name": "link", "version": "0.0.0"},
        }
        _npm_project(tmp_path, "package-lock.json", self._v3(packages))
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert diags == []

    @pytest.mark.parametrize("tree", [[], "x", 3])
    def test_v1_tree_of_the_wrong_type_is_a_gap(self, tmp_path: Path, tree):
        lock = _npm_project(
            tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": tree})
        )
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason('"dependencies"'))}

    @pytest.mark.parametrize(
        "bad",
        [
            {"x": "1.0.0"},
            {"x": {"version": 1}},
            {"x": {"version": "1.0.0", "requires": ["b"]}},
            {"x": {"version": "1.0.0", "dependencies": ["b"]}},
        ],
        ids=["entry-string", "version-number", "requires-list", "nested-list"],
    )
    def test_v1_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(self, tmp_path: Path, bad):
        tree = {
            "a": {
                "version": "1.0.0",
                "requires": {"b": "^1.0.0"},
                "dependencies": {"b": {"version": "1.0.0"}},
            },
            "d": {"version": "1.0.0", "dev": True},
            **bad,
        }
        lock = _npm_project(
            tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": tree})
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert _gaps(diags) == {(lock, _reason('an entry of "dependencies"'))}

    def test_top_level_that_is_not_an_object_is_a_gap(self, tmp_path: Path):
        lock = _npm_project(tmp_path, "package-lock.json", json.dumps(["x"]))
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason("the top level"))}


_PNPM_HEALTHY = """\
lockfileVersion: '9.0'
packages:
  a@1.0.0: {resolution: {integrity: sha512-x}}
  b@1.0.0: {resolution: {integrity: sha512-x}}
  d@1.0.0: {resolution: {integrity: sha512-x}}
snapshots:
  a@1.0.0:
    dependencies:
      b: 1.0.0
  b@1.0.0: {}
  d@1.0.0: {}
"""


class TestPnpmLock:
    @pytest.mark.parametrize(
        ("extra", "what"),
        [
            pytest.param("packages:\n  - a@1.0.0\n", '"packages"', id="packages-list"),
            pytest.param("snapshots: x\n", '"snapshots"', id="snapshots-string"),
        ],
    )
    def test_section_of_the_wrong_type_is_a_gap(self, tmp_path: Path, extra, what):
        lock = _npm_project(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n" + extra)
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason(what))}

    @pytest.mark.parametrize(
        ("bad", "what"),
        [
            pytest.param("  x@1.0.0: text\n", 'an entry of "packages"', id="package-string"),
            pytest.param("  7: {}\n", 'an entry of "packages"', id="package-key-number"),
            pytest.param("  true: {}\n", 'an entry of "packages"', id="package-key-boolean"),
        ],
    )
    def test_package_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(
        self, tmp_path: Path, bad, what
    ):
        content = _PNPM_HEALTHY.replace("snapshots:\n", bad + "snapshots:\n")
        lock = _npm_project(tmp_path, "pnpm-lock.yaml", content)
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert _gaps(diags) == {(lock, _reason(what))}

    @pytest.mark.parametrize(
        "bad",
        [
            "  x@1.0.0: text\n",
            "  7: {}\n",
            "  x@1.0.0:\n    dependencies: [b]\n",
            "  x@1.0.0:\n    optionalDependencies: b\n",
            "  x@1.0.0:\n    transitivePeerDependencies: b\n",
            "  x@1.0.0:\n    dependencies:\n      b: [1.0.0]\n",
            "  x@1.0.0:\n    dependencies:\n      b: 1.0\n",
        ],
        ids=[
            "snapshot-string",
            "snapshot-key-number",
            "dependencies-list",
            "optional-dependencies-string",
            "transitive-peers-string",
            "dependency-value-list",
            "dependency-value-number",
        ],
    )
    def test_snapshot_of_the_wrong_type_is_a_gap_and_the_others_are_rows(self, tmp_path: Path, bad):
        lock = _npm_project(tmp_path, "pnpm-lock.yaml", _PNPM_HEALTHY + bad)
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert _gaps(diags) == {(lock, _reason('an entry of "snapshots"'))}

    def test_empty_dependency_value_points_at_its_key_and_is_clean(self, tmp_path: Path):
        content = _PNPM_HEALTHY.replace("      b: 1.0.0\n", "      b:\n")
        _npm_project(tmp_path, "pnpm-lock.yaml", content)
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert diags == []

    def test_top_level_that_is_not_a_mapping_is_a_gap(self, tmp_path: Path):
        lock = _npm_project(tmp_path, "pnpm-lock.yaml", "- a@1.0.0\n")
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason("the top level"))}


_BERRY_HEALTHY = """\
__metadata:
  version: 8

"a@npm:^1.0.0":
  version: 1.0.0
  dependencies:
    b: "npm:^1.0.0"

"b@npm:^1.0.0":
  version: 1.0.0

"d@npm:^1.0.0":
  version: 1.0.0
"""


class TestYarnBerryLock:
    @pytest.mark.parametrize(
        "bad",
        [
            '"x@npm:^1.0.0": text\n',
            '"x@npm:^1.0.0":\n  version: 1.5\n',
            '"x@npm:^1.0.0":\n  version: 1.0.0\n  dependencies: [b]\n',
            "7:\n  version: 1.0.0\n",
            "true:\n  version: 1.0.0\n",
        ],
        ids=[
            "entry-string",
            "version-number",
            "dependencies-list",
            "key-number",
            "key-boolean",
        ],
    )
    def test_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(self, tmp_path: Path, bad):
        lock = _npm_project(tmp_path, "yarn.lock", _BERRY_HEALTHY + "\n" + bad)
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert _gaps(diags) == {(lock, _reason("a package entry"))}

    def test_top_level_that_is_not_a_mapping_is_a_gap(self, tmp_path: Path):
        # The first line still marks the file as a Berry lockfile.
        lock = _npm_project(tmp_path, "yarn.lock", "__metadata\n")
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason("the top level"))}


class TestBunLock:
    @staticmethod
    def _lock(packages: object) -> str:
        return json.dumps({"lockfileVersion": 1, "packages": packages})

    @pytest.mark.parametrize("packages", [[], "x", 3])
    def test_packages_of_the_wrong_type_is_a_gap(self, tmp_path: Path, packages):
        lock = _npm_project(tmp_path, "bun.lock", self._lock(packages))
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason('"packages"'))}

    @pytest.mark.parametrize(
        "bad",
        [
            {"x": "x@1.0.0"},
            {"x": {"0": "x@1.0.0"}},
            {"x": []},
            {"x": [3, "", {}]},
            {"x": ["x@1.0.0", "", {"dependencies": ["b"]}]},
        ],
        ids=["entry-string", "entry-object", "entry-empty", "id-number", "dependencies-list"],
    )
    def test_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(self, tmp_path: Path, bad):
        packages = {
            "a": ["a@1.0.0", "", {"dependencies": {"b": "^1.0.0"}}, "sha512-x"],
            "b": ["b@1.0.0", "", {}, "sha512-x"],
            "d": ["d@1.0.0", "", {}, "sha512-x"],
            **bad,
        }
        lock = _npm_project(tmp_path, "bun.lock", self._lock(packages))
        rows, diags = _resolve(tmp_path)
        assert rows == _ROWS_A_B_D
        assert _gaps(diags) == {(lock, _reason('an entry of "packages"'))}

    def test_top_level_that_is_not_an_object_is_a_gap(self, tmp_path: Path):
        lock = _npm_project(tmp_path, "bun.lock", "[1, 2]")
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason("the top level"))}


_PY_MANIFEST = """\
[project]
name = "app"
dependencies = ["flask"]

[dependency-groups]
dev = ["pytest"]
"""
_PY_ROWS = {("flask", "==3.0.0", PROD), ("werkzeug", "==3.0.1", PROD), ("pytest", "==8.0.0", DEV)}
_PY_UNPINNED = {("flask", "", PROD), ("pytest", "", DEV)}

_UV_HEALTHY = """\
version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "flask" }]

[[package]]
name = "flask"
version = "3.0.0"
dependencies = [{ name = "werkzeug" }]

[[package]]
name = "werkzeug"
version = "3.0.1"

[[package]]
name = "pytest"
version = "8.0.0"
"""


def _py_project(tmp_path: Path, lockfile: str, content: str) -> Path:
    _write(tmp_path / "pyproject.toml", _PY_MANIFEST)
    return _write(tmp_path / lockfile, content)


class TestUvLock:
    @pytest.mark.parametrize("package", ['"flask"', "3", '{ name = "flask" }'])
    def test_package_of_the_wrong_type_is_a_gap(self, tmp_path: Path, package):
        lock = _py_project(tmp_path, "uv.lock", f"version = 1\npackage = {package}\n")
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert _gaps(diags) == {(lock, _reason("package"))}

    @pytest.mark.parametrize(
        "bad",
        [
            'name = 3\nversion = "1.0.0"\n',
            'name = "x"\nversion = 1\n',
            'name = "x"\nversion = "1.0.0"\nsource = "registry"\n',
            'name = "x"\nversion = "1.0.0"\ndependencies = "werkzeug"\n',
            'name = "x"\nversion = "1.0.0"\ndependencies = ["werkzeug"]\n',
            'name = "x"\nversion = "1.0.0"\ndependencies = [{ name = 3 }]\n',
            'name = "x"\nversion = "1.0.0"\ndependencies = [{ name = "werkzeug", extra = "a" }]\n',
            'name = "x"\nversion = "1.0.0"\ndependencies = [{ name = "werkzeug", extra = [3] }]\n',
            'name = "x"\nversion = "1.0.0"\noptional-dependencies = ["werkzeug"]\n',
        ],
        ids=[
            "name-number",
            "version-number",
            "source-string",
            "dependencies-string",
            "dependency-string",
            "dependency-name-number",
            "extra-string",
            "extra-item-number",
            "optional-dependencies-list",
        ],
    )
    def test_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(self, tmp_path: Path, bad):
        lock = _py_project(tmp_path, "uv.lock", _UV_HEALTHY + "\n[[package]]\n" + bad)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_ROWS
        assert _gaps(diags) == {(lock, _reason("an entry of package"))}

    def test_package_list_item_that_is_not_a_table_is_a_gap(self, tmp_path: Path):
        lock = _py_project(
            tmp_path,
            "uv.lock",
            'version = 1\npackage = [{ name = "flask", version = "3.0.0" }, "pytest"]\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == {("flask", "==3.0.0", PROD), ("pytest", "", DEV)}
        assert _gaps(diags) == {(lock, _reason("an entry of package"))}

    def test_own_project_tables_of_the_wrong_type_are_a_gap(self, tmp_path: Path):
        content = _UV_HEALTHY.replace(
            'dependencies = [{ name = "flask" }]\n',
            'dependencies = [{ name = "flask" }]\ndev-dependencies = "pytest"\n',
        )
        lock = _py_project(tmp_path, "uv.lock", content)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_ROWS
        assert _gaps(diags) == {(lock, _reason("an entry of package"))}


_POETRY_HEALTHY = """\
[[package]]
name = "flask"
version = "3.0.0"

[package.dependencies]
werkzeug = ">=3"

[[package]]
name = "werkzeug"
version = "3.0.1"

[[package]]
name = "pytest"
version = "8.0.0"
"""


class TestPoetryLock:
    def test_package_of_the_wrong_type_is_a_gap(self, tmp_path: Path):
        lock = _py_project(tmp_path, "poetry.lock", 'package = "flask"\n')
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert _gaps(diags) == {(lock, _reason("package"))}

    @pytest.mark.parametrize(
        "bad",
        [
            'name = 3\nversion = "1.0.0"\n',
            'name = "x"\nversion = 1\n',
            'name = "x"\nversion = "1.0.0"\ndependencies = ["werkzeug"]\n',
        ],
        ids=["name-number", "version-number", "dependencies-list"],
    )
    def test_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(self, tmp_path: Path, bad):
        lock = _py_project(tmp_path, "poetry.lock", _POETRY_HEALTHY + "\n[[package]]\n" + bad)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_ROWS
        assert _gaps(diags) == {(lock, _reason("an entry of package"))}

    def test_package_list_item_that_is_not_a_table_is_a_gap(self, tmp_path: Path):
        lock = _py_project(
            tmp_path,
            "poetry.lock",
            'package = [{ name = "flask", version = "3.0.0" }, "pytest"]\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == {("flask", "==3.0.0", PROD), ("pytest", "", DEV)}
        assert _gaps(diags) == {(lock, _reason("an entry of package"))}


class TestPipfileLock:
    @staticmethod
    def _project(tmp_path: Path, document: object) -> Path:
        _write(tmp_path / "Pipfile", '[packages]\nflask = "*"\n\n[dev-packages]\npytest = "*"\n')
        lock = tmp_path / "Pipfile.lock"
        lock.write_text(json.dumps(document))
        return lock

    @pytest.mark.parametrize("include_dev", [True, False])
    @pytest.mark.parametrize(
        ("document", "what"),
        [
            pytest.param(
                {"default": {"flask": {"version": "==3.0.0"}}, "develop": ["pytest"]},
                '"develop"',
                id="develop-list",
            ),
            pytest.param(
                {"default": {"flask": {"version": "==3.0.0"}}, "develop": {"pytest": "==8"}},
                'an entry of "develop"',
                id="develop-entry-string",
            ),
            pytest.param(
                {
                    "default": {"flask": {"version": "==3.0.0"}},
                    "develop": {"pytest": {"version": 8}},
                },
                'an entry of "develop"',
                id="develop-version-number",
            ),
        ],
    )
    def test_develop_of_the_wrong_type_is_a_gap_with_or_without_dev(
        self, tmp_path: Path, document, what, include_dev
    ):
        # The section is read in both modes, so the two modes agree on
        # whether the lockfile could be read.
        lock = self._project(tmp_path, document)
        rows, diags = _resolve(tmp_path, include_dev=include_dev)
        dev_rows = {("pytest", "", DEV)} if include_dev else set()
        assert rows == {("flask", "==3.0.0", PROD)} | dev_rows
        assert _gaps(diags) == {(lock, _reason(what))}

    def test_default_of_the_wrong_type_is_a_gap_and_develop_is_read(self, tmp_path: Path):
        lock = self._project(
            tmp_path, {"default": "flask", "develop": {"pytest": {"version": "==8.0.0"}}}
        )
        rows, diags = _resolve(tmp_path)
        assert rows == {("flask", "", PROD), ("pytest", "==8.0.0", DEV)}
        assert _gaps(diags) == {(lock, _reason('"default"'))}

    def test_top_level_that_is_not_an_object_is_a_gap(self, tmp_path: Path):
        lock = self._project(tmp_path, ["flask"])
        rows, diags = _resolve(tmp_path)
        assert rows == {("flask", "", PROD), ("pytest", "", DEV)}
        assert _gaps(diags) == {(lock, _reason("the top level"))}


class TestComposerLock:
    @staticmethod
    def _project(tmp_path: Path, document: object) -> Path:
        (tmp_path / "composer.json").write_text(
            json.dumps({"require": {"a/a": "^1"}, "require-dev": {"d/d": "^1"}})
        )
        lock = tmp_path / "composer.lock"
        lock.write_text(json.dumps(document))
        return lock

    _A = {"name": "a/a", "version": "1.0.0", "require": {"b/b": "^1"}}
    _B = {"name": "b/b", "version": "1.0.0"}
    _D = {"name": "d/d", "version": "1.0.0"}
    _ROWS = {("a/a", "==1.0.0", PROD), ("b/b", "==1.0.0", PROD), ("d/d", "==1.0.0", DEV)}

    @pytest.mark.parametrize(
        ("document", "rows", "what"),
        [
            pytest.param(
                {"packages": "a/a", "packages-dev": [_D]},
                {("a/a", "^1", PROD), ("d/d", "==1.0.0", DEV)},
                '"packages"',
                id="packages-string",
            ),
            pytest.param(
                {"packages": [_A, _B], "packages-dev": {"d/d": _D}},
                {("a/a", "==1.0.0", PROD), ("b/b", "==1.0.0", PROD), ("d/d", "^1", DEV)},
                '"packages-dev"',
                id="packages-dev-object",
            ),
            pytest.param(
                {"packages": [_A, _B, "x/x"], "packages-dev": [_D]},
                _ROWS,
                'an entry of "packages"',
                id="entry-string",
            ),
            pytest.param(
                {"packages": [_A, _B, {"name": 3, "version": "1.0.0"}], "packages-dev": [_D]},
                _ROWS,
                'an entry of "packages"',
                id="name-number",
            ),
            pytest.param(
                {"packages": [_A, _B, {"name": "x/x", "version": 1}], "packages-dev": [_D]},
                _ROWS,
                'an entry of "packages"',
                id="version-number",
            ),
            pytest.param(
                {"packages": [{**_A, "require": ["b/b"]}, _B], "packages-dev": [_D]},
                _ROWS,
                'an entry of "packages"',
                id="require-non-empty-list",
            ),
            pytest.param(
                ["a/a"], {("a/a", "^1", PROD), ("d/d", "^1", DEV)}, "the top level", id="top-level"
            ),
        ],
    )
    def test_value_of_the_wrong_type_is_a_gap_and_the_rest_is_read(
        self, tmp_path: Path, document, rows, what
    ):
        lock = self._project(tmp_path, document)
        found, diags = _resolve(tmp_path)
        assert found == rows
        assert _gaps(diags) == {(lock, _reason(what))}

    @pytest.mark.parametrize("flag", ["false", "true", 1, 0, ["x"]])
    def test_dev_flag_that_is_not_a_boolean_leaves_the_package_in_production(
        self, tmp_path: Path, flag
    ):
        # A value that merely looks true must not move a production package
        # out of the default scan.
        lock = self._project(
            tmp_path, {"packages": [{**self._A, "dev": flag}, self._B], "packages-dev": [self._D]}
        )
        found, diags = _resolve(tmp_path, include_dev=False)
        assert found == {("a/a", "==1.0.0", PROD), ("b/b", "==1.0.0", PROD)}
        assert _gaps(diags) == {(lock, _reason('an entry of "packages"'))}

    def test_empty_lists_and_null_sections_are_clean(self, tmp_path: Path):
        # PHP serialises an empty map as an empty array, and a lockfile
        # written without dev packages can carry a null section.
        self._project(
            tmp_path,
            {"packages": [self._A, {**self._B, "require": []}], "packages-dev": None},
        )
        found, diags = _resolve(tmp_path, include_dev=False)
        assert found == {("a/a", "==1.0.0", PROD), ("b/b", "==1.0.0", PROD)}
        assert diags == []


class TestRenvLock:
    @staticmethod
    def _project(tmp_path: Path, packages: object) -> Path:
        _write(tmp_path / "DESCRIPTION", "Package: app\nVersion: 1.0\nImports: ggplot2\n")
        lock = tmp_path / "renv.lock"
        lock.write_text(json.dumps({"R": {"Version": "4.3.1"}, "Packages": packages}))
        return lock

    _GGPLOT = {
        "Package": "ggplot2",
        "Version": "3.4.0",
        "Source": "Repository",
        "Repository": "CRAN",
        "Requirements": ["rlang"],
    }
    _RLANG = {"Package": "rlang", "Version": "1.1.0", "Source": "Repository"}
    _ROWS = {("ggplot2", "==3.4.0", PROD), ("rlang", "==1.1.0", PROD)}

    @pytest.mark.parametrize("packages", [[], ["ggplot2"], "ggplot2", 3])
    def test_packages_of_the_wrong_type_is_a_gap(self, tmp_path: Path, packages):
        lock = self._project(tmp_path, packages)
        rows, diags = _resolve(tmp_path)
        assert rows == {("ggplot2", "", PROD)}
        assert _gaps(diags) == {(lock, _reason('"Packages"'))}

    @pytest.mark.parametrize(
        ("bad", "extra_rows"),
        [
            pytest.param({"x": "1.0.0"}, set(), id="entry-string"),
            # The name falls back to the key, as it does when the field is absent.
            pytest.param(
                {"x": {"Package": 3, "Version": "1.0.0"}},
                {("x", "==1.0.0", PROD)},
                id="package-number",
            ),
            pytest.param(
                {"x": {"Package": "x", "Version": ["1.0.0"]}}, {("x", "", PROD)}, id="version-list"
            ),
            pytest.param(
                {"x": {"Package": "x", "Version": "1.0.0", "Source": 3}},
                {("x", "==1.0.0", PROD)},
                id="source-number",
            ),
            pytest.param(
                {"x": {"Package": "x", "Version": "1.0.0", "Requirements": "rlang"}},
                {("x", "==1.0.0", PROD)},
                id="requirements-string",
            ),
            pytest.param(
                {"x": {"Package": "x", "Version": "1.0.0", "Requirements": ["rlang", 3]}},
                {("x", "==1.0.0", PROD)},
                id="requirement-number",
            ),
        ],
    )
    def test_entry_of_the_wrong_type_is_a_gap_and_the_others_are_rows(
        self, tmp_path: Path, bad, extra_rows
    ):
        lock = self._project(tmp_path, {"ggplot2": self._GGPLOT, "rlang": self._RLANG, **bad})
        rows, diags = _resolve(tmp_path)
        assert rows == self._ROWS | extra_rows
        assert _gaps(diags) == {(lock, _reason('an entry of "Packages"'))}

    def test_top_level_that_is_not_an_object_is_a_gap(self, tmp_path: Path):
        _write(tmp_path / "DESCRIPTION", "Package: app\nVersion: 1.0\nImports: ggplot2\n")
        lock = tmp_path / "renv.lock"
        lock.write_text(json.dumps(["ggplot2"]))
        rows, diags = _resolve(tmp_path)
        assert rows == {("ggplot2", "", PROD)}
        assert _gaps(diags) == {(lock, _reason("the top level"))}


class TestCheckCommand:
    """One file with a value of the wrong type beside a healthy manifest.

    The healthy manifest is resolved and reported, the bad value is a gap on
    stderr and in the JSON report, and only ``--strict`` fails on it. Removing
    the bad file is the control: the same scan then passes ``--strict``, so
    the gap is what failed it.
    """

    @respx.mock
    @pytest.mark.parametrize(
        ("manifest", "content", "what"),
        [
            pytest.param(
                "package.json",
                json.dumps({"dependencies": [], "peerDependencies": {"left-pad": "1.0.0"}}),
                '"dependencies"',
                id="package-json-section-is-a-list",
            ),
            pytest.param(
                "package.json",
                json.dumps({"dependencies": {"left-pad": None}}),
                'an entry of "dependencies"',
                id="package-json-spec-is-null",
            ),
            pytest.param(
                "pyproject.toml",
                '[project]\ndependencies = "pytest"\n\n'
                '[tool.poetry.dependencies]\nleft-pad = "1.0.0"\n',
                "project.dependencies",
                id="pyproject-dependencies-is-a-string",
            ),
            pytest.param(
                "pyproject.toml",
                '[project.optional-dependencies]\nextra = "pytest"\nmore = ["left-pad"]\n',
                "an entry of project.optional-dependencies",
                id="pyproject-extra-is-a-string",
            ),
        ],
    )
    def test_bad_manifest_beside_a_healthy_one(self, tmp_path: Path, manifest, content, what):
        (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
        bad = tmp_path / "svc" / manifest
        bad.parent.mkdir()
        bad.write_text(content, encoding="utf-8")
        _mock_pypi("flask", "BSD-3-Clause")
        # ``left-pad`` is the dependency the bad file still declares in a
        # form that can be read. No other name is mocked, so a string read
        # as one requirement per character would be an unmatched request.
        _mock_pypi("left-pad", "MIT")
        _mock_npm("left-pad", "MIT")

        _assert_gap_fails_only_strict(
            tmp_path,
            bad,
            _reason(what),
            [("flask", "BSD-3-Clause"), ("left-pad", "MIT")],
            repair=bad.unlink,
        )

    @respx.mock
    def test_bad_lockfile_beside_a_healthy_manifest(self, tmp_path: Path):
        # The lockfile pins nothing that can be read, so the direct
        # dependency is resolved through the registry instead.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": {"left-pad": "1.0.0"}})
        )
        bad = tmp_path / "package-lock.json"
        bad.write_text(json.dumps({"lockfileVersion": 3, "packages": ["node_modules/left-pad"]}))
        _mock_npm("left-pad", "MIT")

        _assert_gap_fails_only_strict(
            tmp_path, bad, _reason('"packages"'), [("left-pad", "MIT")], repair=bad.unlink
        )
