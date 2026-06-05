"""Tests for setup.py AST-based discovery.

Covers the literal-extraction paths plus the cross-file ``deps`` dict
resolution that lets us recover setups where pinned versions live in a
generated ``dependency_versions_table.py``-style file alongside setup.py.
"""

from __future__ import annotations

import textwrap
from unittest.mock import patch

from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python.setup_py import (
    detect_project_license_setup_py,
    discover_setup_py_dependencies,
)
from licenseal.models import DependencyGroup


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))


class TestSetupPyLicense:
    def test_literal_license_extracted(self, tmp_path):
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="mypkg", license="Apache 2.0 License", install_requires=[])
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == "Apache 2.0 License"

    def test_license_via_name_reference(self, tmp_path):
        # Common pattern: `__license__ = "MIT"` then `setup(license=__license__)`.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            __license__ = "MIT"
            setup(name="mypkg", license=__license__, install_requires=[])
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == "MIT"

    def test_returns_empty_when_no_setup_py(self, tmp_path):
        assert detect_project_license_setup_py(tmp_path) == ""

    def test_setuptools_attribute_form(self, tmp_path):
        # `import setuptools; setuptools.setup(...)` rather than the
        # `from setuptools import setup` form.
        _write(
            tmp_path / "setup.py",
            """\
            import setuptools
            setuptools.setup(name="mypkg", license="BSD-3-Clause")
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == "BSD-3-Clause"

    def test_dynamic_license_skipped(self, tmp_path):
        # Computed license (function call) is unresolvable — skip.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            def _get_license():
                return "MIT"
            setup(name="mypkg", license=_get_license())
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == ""

    def test_classifier_fallback_when_no_license_kwarg(self, tmp_path):
        # Legacy setuptools pattern: license declared only via the trove
        # classifier (PEP 301), not the `license=` kwarg. Mirror pyproject's
        # classifier fallback so these projects aren't misclassified as
        # Proprietary.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(
                name="mypkg",
                classifiers=[
                    "Development Status :: 3 - Alpha",
                    "License :: OSI Approved :: Apache Software License",
                    "Programming Language :: Python :: 3",
                ],
            )
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == "Apache Software License"

    def test_license_kwarg_takes_precedence_over_classifier(self, tmp_path):
        # When both are present, the explicit `license=` kwarg wins —
        # classifier is a fallback, not an override.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(
                name="mypkg",
                license="BSD-3-Clause",
                classifiers=["License :: OSI Approved :: MIT License"],
            )
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == "BSD-3-Clause"

    def test_classifier_fallback_via_name_reference(self, tmp_path):
        # Classifiers can also live in a module-level constant referenced by
        # name — mirror the install_requires resolution path.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            CLASSIFIERS = [
                "License :: OSI Approved :: MIT License",
            ]
            setup(name="mypkg", classifiers=CLASSIFIERS)
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == "MIT License"

    def test_classifier_without_license_entry_yields_empty(self, tmp_path):
        # No `License ::` entry → empty (caller falls through to other
        # detection sources).
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(
                name="mypkg",
                classifiers=[
                    "Development Status :: 3 - Alpha",
                    "Programming Language :: Python :: 3",
                ],
            )
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == ""


class TestSetupPyInstallRequires:
    def test_literal_list(self, tmp_path):
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(
                name="mypkg",
                install_requires=["requests>=2.28", "flask>=3.0", "tqdm"],
            )
            """,
        )
        deps = discover_setup_py_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"requests", "flask", "tqdm"}
        assert all(d.group == DependencyGroup.PROD for d in deps)
        requests = next(d for d in deps if d.name == "requests")
        assert requests.version_constraint == ">=2.28"

    def test_name_reference_to_module_list(self, tmp_path):
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            INSTALL_REQUIRES = ["requests>=2.28", "flask"]
            setup(name="mypkg", install_requires=INSTALL_REQUIRES)
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests", "flask"}

    def test_list_wrap_idiom(self, tmp_path):
        # The `install_requires=list(install_requires)` idiom seen in some
        # large Python packages — `list(...)` wrapping a Name reference to
        # a literal list.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            install_requires = ["requests>=2.28", "flask"]
            setup(name="mypkg", install_requires=list(install_requires))
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests", "flask"}

    def test_subscript_resolution_same_file(self, tmp_path):
        # Member-name dict lookup pattern: `install_requires=[deps["x"], deps["y"]]`.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            deps = {
                "requests": "requests>=2.28",
                "flask": "flask>=3.0",
            }
            setup(
                name="mypkg",
                install_requires=[deps["requests"], deps["flask"]],
            )
            """,
        )
        deps = discover_setup_py_dependencies(tmp_path)
        names = {d.name for d in deps}
        assert names == {"requests", "flask"}

    def test_subscript_resolution_across_files(self, tmp_path):
        # Common pattern: setup.py references `deps["key"]` but the literal
        # `deps` dict lives in a sibling `dependency_versions_table.py`
        # (auto-generated).
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            # `deps` here is a DictComp / non-literal — unresolvable in this file.
            deps = {b: a for a, b in []}
            install_requires = [
                deps["requests"],
                deps["flask"],
            ]
            setup(name="mypkg", install_requires=list(install_requires))
            """,
        )
        _write(
            tmp_path / "src" / "mypkg" / "dependency_versions_table.py",
            """\
            deps = {
                "requests": "requests>=2.28",
                "flask": "flask>=3.0",
            }
            """,
        )
        deps_out = discover_setup_py_dependencies(tmp_path)
        names = {d.name for d in deps_out}
        assert names == {"requests", "flask"}

    def test_unresolvable_subscript_silently_skipped(self, tmp_path):
        # Mixed list: some resolvable, some not. We keep the resolvable
        # entries and silently skip the rest rather than fail the whole list.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            deps = {"flask": "flask>=3.0"}
            install_requires = [deps["flask"], deps["missing"]]
            setup(name="mypkg", install_requires=install_requires)
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"flask"}

    def test_dynamic_install_requires_skipped_entirely(self, tmp_path):
        # `install_requires=read_deps("requirements.txt")` — Call we don't
        # recognize. We emit nothing rather than guess.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            def read_deps(path):
                return []
            setup(name="mypkg", install_requires=read_deps("requirements.txt"))
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []


class TestSetupPyExtras:
    def test_literal_extras_require(self, tmp_path):
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(
                name="mypkg",
                install_requires=["requests"],
                extras_require={
                    "dev": ["pytest", "black"],
                    "ml": ["numpy", "scipy"],
                },
            )
            """,
        )
        deps = discover_setup_py_dependencies(tmp_path)
        groups = {d.name: d.group for d in deps}
        # dev extra → DEV; ml extra (not a dev-name) → PROD.
        assert groups["pytest"] == DependencyGroup.DEV
        assert groups["black"] == DependencyGroup.DEV
        assert groups["numpy"] == DependencyGroup.PROD
        assert groups["scipy"] == DependencyGroup.PROD

    def test_extras_via_name_reference(self, tmp_path):
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            extras = {"dev": ["pytest"]}
            setup(name="mypkg", extras_require=extras)
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"pytest"}

    def test_extras_partial_resolution(self, tmp_path):
        # Some extras are literal lists, others are dynamic call results.
        # We extract the literal ones and silently skip the dynamic ones.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            def deps_list(*names):
                return list(names)
            extras = {
                "literal": ["pytest"],
                "dynamic": deps_list("torch"),
            }
            setup(name="mypkg", extras_require=extras)
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"pytest"}

    def test_source_is_project_relative_path(self, tmp_path):
        # Setup.py at a subdir carries its project-relative path in source.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="root", install_requires=["root-dep"])
            """,
        )
        _write(
            tmp_path / "subpkg" / "setup.py",
            """\
            from setuptools import setup
            setup(name="sub", install_requires=["nested-dep"])
            """,
        )
        deps = discover_setup_py_dependencies(tmp_path)
        by_name = {d.name: d for d in deps}
        assert by_name["root-dep"].source == "setup.py"
        assert by_name["nested-dep"].source == "subpkg/setup.py"


class TestSetupPyEdgeCases:
    def test_malformed_setup_py_is_skipped(self, tmp_path):
        # SyntaxError must not crash the walk.
        _write(tmp_path / "broken" / "setup.py", "this is = not [ valid python")
        _write(
            tmp_path / "good" / "setup.py",
            """\
            from setuptools import setup
            setup(name="good", install_requires=["requests"])
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests"}

    def test_setup_py_without_setup_call_is_skipped(self, tmp_path):
        # A setup.py that doesn't actually call setup() — e.g. just a
        # configuration shim that calls something else. We skip it cleanly.
        _write(
            tmp_path / "setup.py",
            """\
            # No setup() call here.
            print("nothing to do")
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []
        assert detect_project_license_setup_py(tmp_path) == ""

    def test_walks_nested_setup_pys(self, tmp_path):
        # Monorepo with two sub-packages, each with its own setup.py.
        _write(
            tmp_path / "pkg-a" / "setup.py",
            """\
            from setuptools import setup
            setup(name="pkg-a", install_requires=["requests"])
            """,
        )
        _write(
            tmp_path / "pkg-b" / "setup.py",
            """\
            from setuptools import setup
            setup(name="pkg-b", install_requires=["flask"])
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests", "flask"}

    def test_walk_skips_fixture_and_venv_dirs(self, tmp_path):
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="real", install_requires=["requests"])
            """,
        )
        _write(
            tmp_path / "tests" / "fixtures" / "fake" / "setup.py",
            """\
            from setuptools import setup
            setup(name="fake", install_requires=["should-not-appear"])
            """,
        )
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
        _write(
            tmp_path / ".venv" / "lib" / "pkg" / "setup.py",
            """\
            from setuptools import setup
            setup(name="vendored", install_requires=["also-skip"])
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests"}

    def test_unreadable_file_is_skipped(self, tmp_path):
        # OS-level read failure during _parse_ast must not abort the walk.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", license="MIT")
            """,
        )
        with patch("licenseal.discovery.python.setup_py.read_bytes", return_value=None):
            # `read_bytes` records the OS read failure and returns None;
            # `_parse_ast` returns None, so discover / detect both gracefully
            # return their empty result.
            assert discover_setup_py_dependencies(tmp_path) == []
            assert detect_project_license_setup_py(tmp_path) == ""

    def test_oserror_on_walk_returns_empty(self, tmp_path):
        with patch("licenseal.discovery._walk.os.walk", side_effect=OSError("denied")):
            assert walk_project_files(tmp_path, "setup.py") == []

    def test_permission_error_during_walk_returns_empty(self, tmp_path):
        class BrokenWalk:
            def __iter__(self):
                return self

            def __next__(self):
                raise PermissionError("denied")

        with patch("licenseal.discovery._walk.os.walk", return_value=BrokenWalk()):
            assert walk_project_files(tmp_path, "setup.py") == []

    def test_malformed_sibling_deps_file_is_skipped(self, tmp_path):
        # Bad sibling deps-table file must not abort setup.py extraction.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            deps = {b: a for a, b in []}
            setup(name="x", install_requires=[deps["flask"]])
            """,
        )
        _write(tmp_path / "src" / "x" / "dependency_versions_table.py", "this is = not [")
        # No resolution possible → silently empty.
        assert discover_setup_py_dependencies(tmp_path) == []

    def test_install_requires_undefined_name_returns_empty(self, tmp_path):
        # `install_requires=some_undefined_var` — Name has no module-level
        # binding. Resolver returns None and we emit nothing.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", install_requires=undefined_var)
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []

    def test_extras_require_undefined_name_returns_empty(self, tmp_path):
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", install_requires=[], extras_require=undefined_extras)
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []

    def test_extras_require_non_dict_value_silently_skipped(self, tmp_path):
        # `extras_require=some_function_call()` — not a Dict, not a Name.
        # Resolver gives up cleanly.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            def build_extras():
                return {}
            setup(name="x", install_requires=[], extras_require=build_extras())
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []

    def test_extras_require_non_string_key_skipped(self, tmp_path):
        # Dict literal with a non-string key (rare but possible). Skip that
        # entry, extract the rest.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(
                name="x",
                install_requires=[],
                extras_require={
                    "dev": ["pytest"],
                    42: ["weird"],
                },
            )
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"pytest"}

    def test_unparseable_dep_string_dropped(self, tmp_path):
        # A literal element that doesn't start with an identifier char.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(
                name="x",
                install_requires=["requests>=2.0", "!!invalid", "flask"],
            )
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests", "flask"}

    def test_install_requires_non_list_call_returns_none(self, tmp_path):
        # `install_requires=tuple(...)` — Call but not `list(...)`. Resolver
        # gives up rather than misinterpret.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", install_requires=tuple(["requests"]))
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []

    def test_license_via_unresolvable_name_returns_empty(self, tmp_path):
        # `license=undefined_name` — Name reference with no binding.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", license=undefined_license)
            """,
        )
        assert detect_project_license_setup_py(tmp_path) == ""

    def test_subscript_non_string_key_skipped(self, tmp_path):
        # `deps[some_var]` — slice is a Name, not a Constant string.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            deps = {"flask": "flask>=3.0"}
            key = "flask"
            setup(name="x", install_requires=[deps[key]])
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []

    def test_sibling_dir_with_matching_name_is_skipped(self, tmp_path):
        # A *directory* that happens to match the deps-file glob pattern
        # (e.g. someone made a folder named `deps.py`) — must not crash the
        # registry build. Glob hits the dir; `_gather_dict_registry` ignores
        # non-files and moves on.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", install_requires=["requests"])
            """,
        )
        (tmp_path / "deps.py").mkdir()
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests"}

    def test_tuple_assignment_target_skipped(self, tmp_path):
        # `a, b = "x", "y"` — tuple unpacking at module level.
        # `_module_assignments` only tracks plain `Name = value` so the
        # tuple-target branch must skip cleanly.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            a, b = "x", "y"
            setup(name="pkg", install_requires=["requests"])
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests"}

    def test_bare_annotation_without_value_skipped(self, tmp_path):
        # `x: list` — annotated declaration with no value (PEP 526). The
        # module-assignment tracker must skip these (no binding to record).
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            x: list
            setup(name="pkg", install_requires=["requests"])
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests"}

    def test_list_call_with_zero_args_returns_none(self, tmp_path):
        # `list()` with no arg — Call branch where `len(node.args) == 1` is
        # False. Resolver must fall through to return None.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", install_requires=list())
            """,
        )
        assert discover_setup_py_dependencies(tmp_path) == []

    def test_pep526_annotated_assignment_is_visible(self, tmp_path):
        # `install_requires: list[str] = ["..."]` — annotated assignment.
        # Module assignment tracker must include AnnAssign so resolution
        # succeeds.
        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            install_requires: list = ["requests"]
            setup(name="x", install_requires=install_requires)
            """,
        )
        names = {d.name for d in discover_setup_py_dependencies(tmp_path)}
        assert names == {"requests"}


class TestSetupPyTopLevelIntegration:
    """Confirm setup.py discovery is wired into the top-level walker."""

    def test_discover_all_picks_up_setup_py(self, tmp_path):
        from licenseal.discovery import discover_all_dependencies

        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", install_requires=["requests"])
            """,
        )
        all_deps, _ = discover_all_dependencies(tmp_path)
        names = {d.name for d in all_deps}
        assert "requests" in names

    def test_detect_project_license_picks_up_setup_py(self, tmp_path):
        from licenseal.discovery import detect_project_license

        _write(
            tmp_path / "setup.py",
            """\
            from setuptools import setup
            setup(name="x", license="Apache 2.0 License")
            """,
        )
        assert detect_project_license(tmp_path) == "Apache 2.0 License"
