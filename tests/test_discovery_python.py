"""Tests for Python dependency discovery."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from licenseal.discovery import detect_project_license
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python import parse_pep508_dep
from licenseal.discovery.python.pipfile import discover_pipfile_dependencies
from licenseal.discovery.python.pyproject import (
    _extract_deps,
    _poetry_version,
    detect_project_license_pyproject,
    discover_pyproject_dependencies,
)
from licenseal.discovery.python.requirements import (
    _is_dev_file,
    discover_requirements_dependencies,
)
from licenseal.discovery.python.setup_cfg import (
    _parse_dep_line,
    detect_project_license_setup_cfg,
    discover_setup_cfg_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem


class TestPyprojectDiscovery:
    def test_pep621_dependencies(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = [
                "requests>=2.28",
                "click~=8.1",
                "flask",
            ]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert len(deps) == 3
        assert deps[0].name == "requests"
        assert deps[0].version_constraint == ">=2.28"
        assert deps[0].ecosystem == Ecosystem.PYTHON
        assert deps[0].group == DependencyGroup.PROD
        assert deps[1].name == "click"
        assert deps[2].name == "flask"
        assert deps[2].version_constraint == ""

    def test_pep621_optional_dependencies(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = []

            [project.optional-dependencies]
            dev = ["pytest>=7.0", "black"]
            docs = ["sphinx"]
            export = ["pandas"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert len(deps) == 4
        dev_deps = [d for d in deps if d.group == DependencyGroup.DEV]
        prod_deps = [d for d in deps if d.group == DependencyGroup.PROD]
        assert len(dev_deps) == 3  # pytest, black, sphinx
        assert len(prod_deps) == 1  # pandas

    def test_dependency_groups_pep735(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = []

            [dependency-groups]
            dev = ["pytest>=7.0", "mypy"]
            test = ["coverage"]
            prod = ["gunicorn"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert len(deps) == 4
        dev_deps = [d for d in deps if d.group == DependencyGroup.DEV]
        prod_deps = [d for d in deps if d.group == DependencyGroup.PROD]
        assert len(dev_deps) == 3  # pytest, mypy, coverage
        assert len(prod_deps) == 1  # gunicorn

    def test_dependency_groups_pep735_include_chain(self, tmp_path):
        # PEP 735 ``{ include-group = "<name>" }`` directives propagate the
        # parent group's intent (DEV when reachable from a DEV-named group)
        # to all transitively-included groups. Without include-chain
        # resolution, ``build-test`` here would be misclassified as PROD
        # because its name isn't in DEV_GROUP_NAMES — and the ``dev`` group
        # itself contributes zero deps because its entries are only include
        # references. Surfaced by a real-world stress-test repo using
        # uv's recommended layout.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = ["requests"]

            [dependency-groups]
            build-test = ["pytest>=7.0", "mypy"]
            type-stubs = ["types-psutil"]
            format = ["ruff"]
            ci = [
                {include-group = "build-test"},
                {include-group = "type-stubs"},
            ]
            dev = [{include-group = "ci"}, {include-group = "format"}]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        # Plain prod dep stays PROD.
        assert by_name["requests"].group == DependencyGroup.PROD
        # All deps reachable via include chain from ``dev`` are DEV, even
        # though their declaring groups (build-test, type-stubs, format)
        # aren't in DEV_GROUP_NAMES.
        for name in ("pytest", "mypy", "types-psutil", "ruff"):
            assert by_name[name].group == DependencyGroup.DEV, (
                f"{name} should be DEV via include chain"
            )

    def test_dependency_groups_pep735_malformed_entries_do_not_crash(self, tmp_path):
        # Defensive guards: parsing must survive malformed manifests where
        #   * a group's value isn't a list (TOML allows ``group = "string"``)
        #   * a list entry is neither string nor dict (e.g. an int)
        #   * an include directive's value isn't a string
        #   * a dict entry has no recognized key
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = [42, "real-dep"]

            [dependency-groups]
            bad-group = "not a list"
            dev = [
                "pytest>=7.0",
                42,
                {include-group = 42},
                {unrecognized-key = "ci"},
            ]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        names = {d.name: d for d in deps}
        # Plain PROD dep parses; the non-string entry next to it is dropped.
        assert "real-dep" in names and names["real-dep"].group == DependencyGroup.PROD
        # Valid dev dep parses; surrounding garbage is dropped silently.
        assert "pytest" in names and names["pytest"].group == DependencyGroup.DEV

    def test_dependency_groups_pep735_no_match_to_dev_stays_prod(self, tmp_path):
        # A group whose name isn't in DEV_GROUP_NAMES and isn't reached by
        # any dev-named group's include chain stays PROD.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = []

            [dependency-groups]
            build-only = ["maturin"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD

    def test_poetry_dependencies(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [tool.poetry.dependencies]
            python = "^3.10"
            requests = "^2.28"
            flask = {version = "^3.0", extras = ["async"]}

            [tool.poetry.group.dev.dependencies]
            pytest = "^7.0"

            [tool.poetry.group.test.dependencies]
            coverage = "^7.0"
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        names = [d.name for d in deps]
        assert "python" not in names
        assert "requests" in names
        assert "flask" in names
        assert "pytest" in names
        assert "coverage" in names

        req_dep = next(d for d in deps if d.name == "requests")
        assert req_dep.version_constraint == "^2.28"
        assert req_dep.group == DependencyGroup.PROD

        flask_dep = next(d for d in deps if d.name == "flask")
        assert flask_dep.version_constraint == "^3.0"  # extracted from dict spec

        pytest_dep = next(d for d in deps if d.name == "pytest")
        assert pytest_dep.group == DependencyGroup.DEV

        cov_dep = next(d for d in deps if d.name == "coverage")
        assert cov_dep.group == DependencyGroup.DEV

    def test_no_pyproject(self, tmp_path):
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert deps == []

    def test_non_string_dep_skipped(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = [
                "requests>=2.0",
            ]

            [dependency-groups]
            dev = [
                "pytest",
                {include-group = "typing"},
            ]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "pytest" in names
        assert len(deps) == 2


class TestProjectLicenseDetection:
    def test_pep639_string_license(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = "MIT"
            """)
        )
        assert detect_project_license_pyproject(tmp_path) == "MIT"

    def test_pep639_dict_license(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = "Apache-2.0"}
            """)
        )
        assert detect_project_license_pyproject(tmp_path) == "Apache-2.0"

    def test_classifier_fallback(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            classifiers = [
                "License :: OSI Approved :: MIT License",
            ]
            """)
        )
        result = detect_project_license_pyproject(tmp_path)
        assert result == "MIT License"

    def test_no_license(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            """)
        )
        assert detect_project_license_pyproject(tmp_path) == ""

    def test_no_pyproject(self, tmp_path):
        assert detect_project_license_pyproject(tmp_path) == ""

    def test_legacy_poetry_license(self, tmp_path):
        # Pre-PEP-621 Poetry projects keep license under [tool.poetry].
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [tool.poetry]
            name = "legacy-poetry"
            license = "GPL-3.0"
            """)
        )
        assert detect_project_license_pyproject(tmp_path) == "GPL-3.0"

    def test_monorepo_picks_root_license_first(self, tmp_path):
        # Root pyproject declares the canonical license; nested ones inherit
        # conceptually. Walk order returns root first.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "monorepo-root"
            license = "Apache-2.0"
            """)
        )
        (tmp_path / "libs" / "sub").mkdir(parents=True)
        (tmp_path / "libs" / "sub" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "sub"
            license = "MIT"
            """)
        )
        assert detect_project_license_pyproject(tmp_path) == "Apache-2.0"

    def test_monorepo_falls_through_to_first_subpackage_when_root_lacks_license(self, tmp_path):
        # LangChain-style: no root pyproject.toml, but every sub-package has
        # a `license = {text = "MIT"}` entry. First sub-package wins.
        (tmp_path / "libs" / "core").mkdir(parents=True)
        (tmp_path / "libs" / "core" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "core-pkg"
            license = {text = "MIT"}
            """)
        )
        (tmp_path / "libs" / "extra").mkdir(parents=True)
        (tmp_path / "libs" / "extra" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "extra-pkg"
            license = "BSD-3-Clause"
            """)
        )
        assert detect_project_license_pyproject(tmp_path) == "MIT"

    def test_monorepo_malformed_toml_is_skipped(self, tmp_path):
        # Defensive: an unreadable pyproject (bad TOML) must not abort the
        # walk; we just skip it and continue.
        (tmp_path / "pyproject.toml").write_text("this is = not [ valid toml")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "sub"
            license = "MIT"
            """)
        )
        assert detect_project_license_pyproject(tmp_path) == "MIT"


class TestPythonMonorepoDiscovery:
    """LangChain, Ray, JAX, and many other large Python projects ship a
    repo with no root pyproject.toml — instead, multiple sub-packages live
    under `libs/`, `packages/`, or similar. Walk for them and filter
    workspace-internal references so they don't show as unresolved deps."""

    def test_walks_nested_pyprojects(self, tmp_path):
        # No root pyproject.toml; two nested sub-packages each declare deps.
        (tmp_path / "libs" / "core").mkdir(parents=True)
        (tmp_path / "libs" / "core" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "monorepo-core"
            dependencies = ["pydantic>=2.0"]
            """)
        )
        (tmp_path / "libs" / "extras").mkdir()
        (tmp_path / "libs" / "extras" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "monorepo-extras"
            dependencies = ["httpx>=0.27"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"pydantic", "httpx"}

    def test_workspace_internal_refs_are_filtered(self, tmp_path):
        # `langchain` depends on `langchain-core` AND they're both defined
        # locally — the local sibling reference must be dropped so we don't
        # try to resolve it from the registry.
        (tmp_path / "libs" / "core").mkdir(parents=True)
        (tmp_path / "libs" / "core" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "langchain-core"
            dependencies = ["pydantic>=2.0"]
            """)
        )
        (tmp_path / "libs" / "main").mkdir()
        (tmp_path / "libs" / "main" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "langchain"
            dependencies = ["langchain-core", "httpx>=0.27"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        names = {d.name for d in deps}
        # External deps stay; local sibling is filtered.
        assert names == {"pydantic", "httpx"}
        assert "langchain-core" not in names

    def test_self_named_dep_is_preserved(self, tmp_path):
        # A pyproject that lists its own ``name`` as a dep targets the
        # published-registry version of itself — e.g. a docs build pulling
        # the installed wheel — not a workspace alias. The workspace-local
        # filter must exempt this self-reference.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "mypkg"
            dependencies = ["mypkg>=1.0", "httpx>=0.27"]
            """)
        )
        deps, filtered = discover_pyproject_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"mypkg", "httpx"}
        assert filtered == 0

    def test_source_is_project_relative_path(self, tmp_path):
        # Workspace layout: each pyproject's deps carry the project-relative
        # path of its declaring file in ``source``, so callers can tell
        # which package declared a given dep.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "root"
            dependencies = ["root-dep>=1.0"]
            """)
        )
        (tmp_path / "libs" / "core").mkdir(parents=True)
        (tmp_path / "libs" / "core" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "core"
            dependencies = ["nested-dep>=1.0"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["root-dep"].source == "pyproject.toml"
        assert by_name["nested-dep"].source == "libs/core/pyproject.toml"

    def test_workspace_filter_is_pep503_normalized(self, tmp_path):
        # `langchain_core` (underscore) in one pyproject and `langchain-core`
        # (dash) referenced in another must both match the same package.
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "Some_Pkg.Name"
            """)
        )
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "consumer"
            dependencies = ["some-pkg-name>=1.0", "external>=2.0"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        names = {d.name for d in deps}
        # Local sibling filtered (different separators / case); external kept.
        assert "external" in names
        assert "some-pkg-name" not in names

    def test_walk_skips_examples_dir(self, tmp_path):
        # Demo apps shipped under `examples/` are not part of the audited
        # project — skip them.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "real"
            dependencies = ["requests>=2.0"]
            """)
        )
        (tmp_path / "examples" / "demo").mkdir(parents=True)
        (tmp_path / "examples" / "demo" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "demo-project"
            dependencies = ["should-not-appear>=1.0"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert {d.name for d in deps} == {"requests"}

    def test_walk_skips_fixture_and_venv_dirs(self, tmp_path):
        # A real pyproject in the root, plus a fake one in tests/fixtures/
        # (test scaffolding) and one in .venv/ (installed deps). Only the
        # real one must be discovered.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "real"
            dependencies = ["requests>=2.0"]
            """)
        )
        (tmp_path / "tests" / "fixtures" / "fake").mkdir(parents=True)
        (tmp_path / "tests" / "fixtures" / "fake" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "fixture-fake"
            dependencies = ["should-not-appear>=1.0"]
            """)
        )
        (tmp_path / ".venv" / "lib" / "site-packages" / "installed").mkdir(parents=True)
        (tmp_path / ".venv" / "lib" / "site-packages" / "installed" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "installed-dep"
            dependencies = ["also-should-not-appear>=1.0"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"requests"}

    def test_malformed_toml_in_one_file_does_not_abort_walk(self, tmp_path):
        # Bad TOML in one file must not prevent discovery of the others.
        (tmp_path / "broken").mkdir()
        (tmp_path / "broken" / "pyproject.toml").write_text("[project] this is = not [ valid")
        (tmp_path / "good").mkdir()
        (tmp_path / "good" / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "good"
            dependencies = ["fastapi>=0.110"]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert {d.name for d in deps} == {"fastapi"}

    def test_oserror_on_walk_returns_empty(self, tmp_path):
        # Defensive: os.walk raises OSError (e.g. EACCES at the root). Walker
        # must return empty rather than crash the scan.
        with patch("licenseal.discovery._walk.os.walk", side_effect=OSError("denied")):
            assert walk_project_files(tmp_path, "pyproject.toml") == []

    def test_permission_error_during_walk_returns_partial(self, tmp_path):
        # Defensive: PermissionError mid-iteration short-circuits the walk.
        class BrokenWalk:
            def __iter__(self):
                return self

            def __next__(self):
                raise PermissionError("denied")

        with patch("licenseal.discovery._walk.os.walk", return_value=BrokenWalk()):
            assert walk_project_files(tmp_path, "pyproject.toml") == []


class TestSetupCfgLicenseDetection:
    def test_bare_license_field(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [metadata]
            name = legacy-pkg
            license = BSD-3-Clause
            """)
        )
        assert detect_project_license_setup_cfg(tmp_path) == "BSD-3-Clause"
        # And the top-level walker chains setup.cfg after pyproject.toml.
        assert detect_project_license(tmp_path) == "BSD-3-Clause"

    def test_classifier_fallback(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [metadata]
            name = legacy-pkg
            classifiers =
                License :: OSI Approved :: MIT License
                Programming Language :: Python :: 3
            """)
        )
        assert detect_project_license_setup_cfg(tmp_path) == "MIT License"

    def test_pyproject_wins_over_setup_cfg(self, tmp_path):
        """When both files exist, pyproject's PEP 621 license takes
        precedence — that's the modern source of truth."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "modern"
            license = "MIT"
            """)
        )
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [metadata]
            license = Apache-2.0
            """)
        )
        assert detect_project_license(tmp_path) == "MIT"

    def test_missing_setup_cfg(self, tmp_path):
        assert detect_project_license_setup_cfg(tmp_path) == ""

    def test_malformed_setup_cfg_returns_empty(self, tmp_path):
        # Duplicate option triggers configparser.DuplicateOptionError; the
        # detector must swallow it and return "" rather than crash the scan.
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [metadata]
            license = MIT
            license = Apache-2.0
            """)
        )
        assert detect_project_license_setup_cfg(tmp_path) == ""

    def test_neither_license_nor_recognized_classifier(self, tmp_path):
        # [metadata] exists but has no license field and no
        # `License :: OSI Approved ::` classifier — must fall through to "".
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [metadata]
            name = legacy-pkg
            classifiers =
                Programming Language :: Python :: 3
            """)
        )
        assert detect_project_license_setup_cfg(tmp_path) == ""


class TestRequirementsDiscovery:
    def test_basic_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            textwrap.dedent("""\
            requests>=2.28
            flask==3.0.0
            click
            """)
        )
        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 3
        assert deps[0].name == "requests"
        assert deps[0].version_constraint == ">=2.28"
        assert deps[0].group == DependencyGroup.PROD

    def test_dev_requirements(self, tmp_path):
        (tmp_path / "requirements-dev.txt").write_text("pytest>=7.0\nblack\n")
        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 2
        assert all(d.group == DependencyGroup.DEV for d in deps)

    def test_requirements_subdir(self, tmp_path):
        req_dir = tmp_path / "requirements"
        req_dir.mkdir()
        (req_dir / "requirements.txt").write_text("django>=4.0\n")
        (req_dir / "requirements-test.txt").write_text("pytest\n")
        deps = discover_requirements_dependencies(tmp_path)
        names = [d.name for d in deps]
        assert "django" in names
        assert "pytest" in names

    def test_source_is_project_relative_path(self, tmp_path):
        # Root and nested requirements.txt files share the basename — without
        # the relative path in `source`, callers can't tell which file
        # declared a given dep.
        (tmp_path / "requirements.txt").write_text("root-dep\n")
        nested = tmp_path / "MCP"
        nested.mkdir()
        (nested / "requirements.txt").write_text("mcp-only-dep\n")
        deps = discover_requirements_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["root-dep"].source == "requirements.txt"
        assert by_name["mcp-only-dep"].source == "MCP/requirements.txt"

    def test_comments_and_blanks_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            textwrap.dedent("""\
            # This is a comment
            requests>=2.0

            # Another comment
            flask
            """)
        )
        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 2

    def test_options_and_urls_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            textwrap.dedent("""\
            --index-url https://pypi.org/simple
            -r other.txt
            requests>=2.0
            git+https://github.com/user/repo.git
            https://example.com/package.tar.gz
            """)
        )
        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_env_markers(self, tmp_path):
        (tmp_path / "requirements.txt").write_text('requests>=2.0; python_version>="3.8"\n')
        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].version_constraint == ">=2.0"

    def test_no_requirements_files(self, tmp_path):
        deps = discover_requirements_dependencies(tmp_path)
        assert deps == []

    def test_utf16_requirements_file_decoded(self, tmp_path):
        # Real-world case: Windows PowerShell 5.1 writes UTF-16 LE with a BOM
        # for ``pip freeze > requirements.txt``. pip reads it back via BOM
        # detection; licenseal must too (it used to drop the whole file).
        (tmp_path / "requirements_utf16.txt").write_bytes(
            b"\xff\xfe" + "requests==2.28\n".encode("utf-16-le")
        )
        # Mix in a valid UTF-8 requirements file too — both must be found.
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        names = {d.name for d in discover_requirements_dependencies(tmp_path)}
        assert names == {"flask", "requests"}

    def test_utf8_bom_requirements_first_dep_not_corrupted(self, tmp_path):
        # PowerShell 5.1 ``Out-File -Encoding utf8`` / ``Set-Content`` write a
        # UTF-8 BOM. A plain utf-8 read leaves it as ``﻿`` on line 1, which
        # corrupts the *first* dependency's name. utf-8-sig strips it.
        (tmp_path / "requirements.txt").write_bytes(
            "flask==3.0.0\nrequests==2.28\n".encode("utf-8-sig")
        )
        names = {d.name for d in discover_requirements_dependencies(tmp_path)}
        assert names == {"flask", "requests"}

    def test_latin1_comment_does_not_drop_ascii_deps(self, tmp_path):
        # A single non-UTF-8 byte in a *comment* (a legacy-encoded author name)
        # must not take the file's ASCII dependency lines down with it.
        (tmp_path / "requirements.txt").write_bytes(
            b"# author: Jos\xe9 Garcia\nflask==3.0.0\nrequests==2.28\n"
        )
        names = {d.name for d in discover_requirements_dependencies(tmp_path)}
        assert names == {"flask", "requests"}

    def test_unreadable_requirements_file_skipped(self, tmp_path, monkeypatch):
        # A genuine I/O error (permission denied, etc.) skips the file without
        # crashing the scan.
        (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")

        def boom(self, *args, **kwargs):
            raise OSError("denied")

        monkeypatch.setattr(Path, "read_bytes", boom)
        assert discover_requirements_dependencies(tmp_path) == []

    def test_dev_requirements_underscore(self, tmp_path):
        (tmp_path / "requirements_test.txt").write_text("pytest\n")
        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.DEV

    def test_reversed_pattern_dev_requirements(self, tmp_path):
        (tmp_path / "dev-requirements.txt").write_text("black\n")
        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.DEV

    def test_nested_requirements_files_are_discovered(self, tmp_path):
        # Monorepo pattern: requirements files live under subdirs (e.g.
        # ``packages/foo/requirements-dev.txt``). The walker must find them
        # — discovery used to only check ``<root>`` and ``<root>/requirements``,
        # silently missing every nested file. Mirrors pyproject / cargo / npm
        # tree-walk behavior.
        (tmp_path / "packages" / "foo").mkdir(parents=True)
        (tmp_path / "packages" / "foo" / "requirements.txt").write_text("requests\n")
        (tmp_path / "packages" / "foo" / "requirements-dev.txt").write_text("pytest\n")
        (tmp_path / "packages" / "foo" / "requirements-ci.txt").write_text("coverage\n")
        deps = discover_requirements_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["requests"].group == DependencyGroup.PROD
        assert by_name["pytest"].group == DependencyGroup.DEV
        assert by_name["coverage"].group == DependencyGroup.DEV  # `ci` is in DEV_GROUP_NAMES

    def test_exclude_paths_honored(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("real-dep\n")
        (tmp_path / "vendored").mkdir()
        (tmp_path / "vendored" / "requirements.txt").write_text("vendored-dep\n")
        excluded = frozenset({(tmp_path / "vendored").resolve()})
        deps = discover_requirements_dependencies(tmp_path, exclude_paths=excluded)
        names = {d.name for d in deps}
        assert names == {"real-dep"}


class TestSetupCfgDiscovery:
    def test_install_requires(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [options]
            install_requires =
                requests>=2.28
                flask
            """)
        )
        deps = discover_setup_cfg_dependencies(tmp_path)
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[0].version_constraint == ">=2.28"
        assert deps[1].name == "flask"

    def test_extras_require(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [options]
            install_requires =
                requests

            [options.extras_require]
            dev =
                pytest
                black
            export =
                pandas
            """)
        )
        deps = discover_setup_cfg_dependencies(tmp_path)
        assert len(deps) == 4
        dev_deps = [d for d in deps if d.group == DependencyGroup.DEV]
        assert len(dev_deps) == 2  # pytest, black

    def test_no_setup_cfg(self, tmp_path):
        deps = discover_setup_cfg_dependencies(tmp_path)
        assert deps == []

    def test_malformed_setup_cfg_returns_empty(self, tmp_path):
        # A duplicate option raises configparser.DuplicateOptionError mid-read;
        # the deps parser must swallow it and return [] (matching the sibling
        # license detector and every other Python parser) rather than abort the
        # whole scan on one unparseable manifest.
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [options]
            install_requires = requests
            install_requires = flask
            """)
        )
        assert discover_setup_cfg_dependencies(tmp_path) == []

    def test_comments_skipped(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [options]
            install_requires =
                # comment
                requests
            """)
        )
        deps = discover_setup_cfg_dependencies(tmp_path)
        assert len(deps) == 1

    def test_empty_lines_skipped(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [options]
            install_requires =

                requests

            """)
        )
        deps = discover_setup_cfg_dependencies(tmp_path)
        assert len(deps) == 1


class TestExtrasCapture:
    """Discovery must preserve PEP 508 extras on direct deps so the
    transitive walker can evaluate the target's `extra ==` markers against
    the right context. Without this, every Python project with extras-heavy
    transitives over-reports massively (see the walker's marker eval)."""

    def test_pyproject_pep621_captures_extras(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            dependencies = [
                "requests[socks]>=2",
                "uvicorn[standard]==0.30.0",
                "plain-dep>=1.0",
            ]
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["requests"].extras == frozenset({"socks"})
        assert by_name["uvicorn"].extras == frozenset({"standard"})
        assert by_name["plain-dep"].extras == frozenset()

    def test_pyproject_poetry_structured_extras(self, tmp_path):
        # Poetry's dict form lets the user request extras via a list field.
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [tool.poetry]
            name = "myproject"

            [tool.poetry.dependencies]
            python = "^3.10"
            requests = { version = "^2", extras = ["socks", "use_chardet_on_py3"] }
            uvicorn = "^0.30"
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["requests"].extras == frozenset({"socks", "use_chardet_on_py3"})
        assert by_name["uvicorn"].extras == frozenset()

    def test_requirements_txt_captures_extras(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests[socks]>=2\nplain-pkg==1.0\n")
        deps = discover_requirements_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["requests"].extras == frozenset({"socks"})
        assert by_name["plain-pkg"].extras == frozenset()

    def test_setup_cfg_captures_extras(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
            [options]
            install_requires =
                requests[socks]>=2
                plain-pkg==1.0
            """)
        )
        deps = discover_setup_cfg_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["requests"].extras == frozenset({"socks"})
        assert by_name["plain-pkg"].extras == frozenset()


class TestPep508FallbackParser:
    def test_unparseable_with_no_name_match_returns_empty(self):
        # Both packaging.Requirement and the regex fallback fail — the
        # caller gets the empty-tuple sentinel.
        name, spec, extras = parse_pep508_dep("###")
        assert (name, spec, extras) == ("", "", frozenset())

    def test_unparseable_but_name_match_returns_partial(self):
        # Requirement rejects it (space inside the spec), but the regex
        # still pulls out the leading name token — preserves the historical
        # pre-helper behavior on quirky manifests.
        name, _, extras = parse_pep508_dep("foo invalid<1.0")
        assert name == "foo"
        assert extras == frozenset()


class TestPipfileDiscovery:
    def test_packages_and_dev_packages_split(self, tmp_path):
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            requests = ">=2.28"
            click = "*"

            [dev-packages]
            pytest = "*"
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["requests"].group == DependencyGroup.PROD
        assert by_name["requests"].version_constraint == ">=2.28"
        # `*` collapses to empty constraint (mirrors the rest of discovery).
        assert by_name["click"].version_constraint == ""
        assert by_name["pytest"].group == DependencyGroup.DEV
        assert by_name["requests"].source == "Pipfile"

    def test_dict_spec_with_extras(self, tmp_path):
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            django = {version = ">=4.0", extras = ["bcrypt", "argon2"]}
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        assert deps[0].name == "django"
        assert deps[0].version_constraint == ">=4.0"
        assert deps[0].extras == frozenset({"bcrypt", "argon2"})

    def test_dict_spec_star_version(self, tmp_path):
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            django = {version = "*"}
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        assert deps[0].version_constraint == ""

    def test_skips_git_path_file_sources(self, tmp_path):
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            from-git = {git = "https://example.com/repo.git"}
            from-path = {path = "./local"}
            from-file = {file = "./dist/pkg.tar.gz"}
            real = ">=1"
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        assert [d.name for d in deps] == ["real"]

    def test_skips_malformed_extras(self, tmp_path):
        # `extras` containing non-string entries: only the string ones survive.
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            django = {version = ">=4", extras = ["bcrypt", 42]}
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        assert deps[0].extras == frozenset({"bcrypt"})

    def test_handles_missing_sections(self, tmp_path):
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [[source]]
            url = "https://pypi.org/simple"
            name = "pypi"

            [requires]
            python_version = "3.11"
            """)
        )
        assert discover_pipfile_dependencies(tmp_path) == []

    def test_handles_non_dict_section(self, tmp_path):
        # `packages` declared as a string (malformed Pipfile) — skipped, no crash.
        (tmp_path / "Pipfile").write_text("packages = 'oops'\n")
        assert discover_pipfile_dependencies(tmp_path) == []

    def test_handles_malformed_toml(self, tmp_path):
        (tmp_path / "Pipfile").write_text("not [ valid toml")
        assert discover_pipfile_dependencies(tmp_path) == []

    def test_handles_missing_version_in_dict(self, tmp_path):
        # Dict spec with no `version` key resolves to an empty constraint.
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            mystery = {extras = ["x"]}
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        assert deps[0].version_constraint == ""
        assert deps[0].extras == frozenset({"x"})

    def test_dict_spec_with_non_string_version(self, tmp_path):
        # Robustness against weird specs — non-string `version` → empty.
        # tomllib accepts booleans / numbers; we tolerate them.
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            mystery = {version = 42}
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        assert deps[0].version_constraint == ""

    def test_handles_non_str_non_dict_spec(self, tmp_path):
        # Malformed Pipfile: a bare number where a spec should be.
        # Tolerated as an empty constraint rather than crashing.
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            weird = 42
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        assert deps[0].name == "weird"
        assert deps[0].version_constraint == ""

    def test_nested_pipfile_in_monorepo(self, tmp_path):
        (tmp_path / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            root-only = ">=1"
            """)
        )
        sub = tmp_path / "services" / "api"
        sub.mkdir(parents=True)
        (sub / "Pipfile").write_text(
            textwrap.dedent("""\
            [packages]
            api-only = ">=2"
            """)
        )
        deps = discover_pipfile_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert set(by_name) == {"root-only", "api-only"}
        assert by_name["api-only"].source == "services/api/Pipfile"


class TestPyprojectEdgeCases:
    def test_invalid_dep_string(self):
        """Malformed dep string falls back to regex; if regex also can't
        match a name, returns empty so callers can drop the entry."""
        name, version, extras = parse_pep508_dep("!!invalid!!")
        assert name == ""
        assert version == ""
        assert extras == frozenset()

    def test_empty_dep_string(self):
        name, version, extras = parse_pep508_dep("")
        assert name == ""
        assert version == ""
        assert extras == frozenset()

    def test_dict_license_empty_text(self, tmp_path):
        """Dict license with empty text should fall through to classifiers."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            license = {text = ""}
            classifiers = [
                "License :: OSI Approved :: MIT License",
            ]
            """)
        )
        result = detect_project_license_pyproject(tmp_path)
        assert result == "MIT License"

    def test_no_matching_classifier(self, tmp_path):
        """No license classifier at all."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [project]
            name = "myproject"
            classifiers = [
                "Programming Language :: Python :: 3",
            ]
            """)
        )
        result = detect_project_license_pyproject(tmp_path)
        assert result == ""


class TestSetupCfgEdgeCases:
    def test_parse_dep_line_empty(self):
        result = _parse_dep_line("", DependencyGroup.PROD)
        assert result is None

    def test_parse_dep_line_comment(self):
        result = _parse_dep_line("# comment", DependencyGroup.PROD)
        assert result is None

    def test_parse_dep_line_no_match(self):
        result = _parse_dep_line("!!!", DependencyGroup.PROD)
        assert result is None

    def test_no_options_section(self, tmp_path):
        (tmp_path / "setup.cfg").write_text("[metadata]\nname = pkg\n")
        deps = discover_setup_cfg_dependencies(tmp_path)
        assert deps == []


class TestRequirementsEdgeCases:
    def test_is_dev_file_variants(self):
        assert _is_dev_file("requirements-dev.txt") is True
        assert _is_dev_file("requirements-test.txt") is True
        assert _is_dev_file("requirements.txt") is False
        assert _is_dev_file("requirements-prod.txt") is False
        assert _is_dev_file("dev-requirements.txt") is True
        assert _is_dev_file("requirements_lint.txt") is True
        assert _is_dev_file("requirements_docs.txt") is True
        assert _is_dev_file("requirements_ci.txt") is True


class TestRequirementsPartialBranches:
    def test_no_dev_requirements_glob(self, tmp_path):
        """Only main requirements.txt, no *-requirements.txt patterns."""
        (tmp_path / "requirements.txt").write_text("requests\n")

        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 1

    def test_requirements_subdir_with_dev_pattern(self, tmp_path):
        """requirements/ subdir with dev-requirements.txt pattern."""
        req_dir = tmp_path / "requirements"
        req_dir.mkdir()
        (req_dir / "dev-requirements.txt").write_text("pytest\n")

        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.DEV


class TestSetupCfgPartialBranches:
    def test_extras_require_non_dev(self, tmp_path):
        """extras_require with only non-dev group names."""
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
        [options]
        install_requires =
            requests

        [options.extras_require]
        export =
            pandas
        """)
        )

        deps = discover_setup_cfg_dependencies(tmp_path)
        prod_deps = [d for d in deps if d.group == DependencyGroup.PROD]
        assert len(prod_deps) == 2  # requests + pandas


class TestPyprojectEmptyDeps:
    def test_empty_dependency_list(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
        [project]
        name = "myproject"
        dependencies = []
        """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        assert deps == []

    def test_dep_with_empty_name(self):
        """A dep string that parses to empty name should be skipped."""

        # An empty string parses to empty name
        result = _extract_deps([""], DependencyGroup.PROD, "pyproject.toml")
        assert result == []


class TestRequirementsEmptyFile:
    def test_empty_requirements_file(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("")

        deps = discover_requirements_dependencies(tmp_path)
        assert deps == []

    def test_non_matching_line(self, tmp_path):
        """A line that doesn't match the dep regex should be skipped."""
        (tmp_path / "requirements.txt").write_text("!!not-a-dep!!\nrequests\n")

        deps = discover_requirements_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_directory_named_like_requirements(self, tmp_path):
        """A directory named requirements*.txt should be skipped."""
        (tmp_path / "requirements.txt").mkdir()  # directory, not file
        (tmp_path / "dev-requirements.txt").mkdir()  # directory, not file

        deps = discover_requirements_dependencies(tmp_path)
        assert deps == []


class TestSetupCfgEmptyInstallRequires:
    def test_empty_install_requires(self, tmp_path):
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
        [options]
        install_requires =
        """)
        )

        deps = discover_setup_cfg_dependencies(tmp_path)
        assert deps == []

    def test_install_requires_with_unparseable_line(self, tmp_path):
        """Lines that _parse_dep_line returns None for within install_requires."""
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
        [options]
        install_requires =
            !!!invalid
            requests
        """)
        )

        deps = discover_setup_cfg_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_extras_require_with_unparseable_line(self, tmp_path):
        """Lines that _parse_dep_line returns None for within extras_require."""
        (tmp_path / "setup.cfg").write_text(
            textwrap.dedent("""\
        [options.extras_require]
        dev =
            !!!invalid
            pytest
        """)
        )

        deps = discover_setup_cfg_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "pytest"


class TestPoetryDictVersion:
    def test_poetry_dict_extracts_version(self, tmp_path):
        """Poetry dict spec should extract version constraint."""
        (tmp_path / "pyproject.toml").write_text(
            textwrap.dedent("""\
            [tool.poetry.dependencies]
            python = "^3.10"
            click = {version = "^8.0", optional = true}
            """)
        )
        deps, _ = discover_pyproject_dependencies(tmp_path)
        click_dep = next(d for d in deps if d.name == "click")
        assert click_dep.version_constraint == "^8.0"

    def test_poetry_version_unexpected_type(self):
        """Unexpected type for spec should return empty string."""

        assert _poetry_version(42) == ""  # type: ignore[arg-type]
