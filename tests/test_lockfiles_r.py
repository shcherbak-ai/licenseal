"""Tests for R lockfile parsers (renv.lock + packrat.lock) and edge attribution."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from licenseal.discovery.r._lock import (
    _OFF_REGISTRY_MARKER,
    attach_direct_sources,
    build_lock_dependencies,
    is_off_registry_marker,
)
from licenseal.discovery.r.packrat import find_packrat_lockfiles, parse_packrat_lock
from licenseal.discovery.r.renv_lock import _is_on_cran, find_renv_lockfiles, parse_renv_lock
from licenseal.models import Dependency, DependencyGroup, Ecosystem

_RENV_LOCK = {
    "R": {"Version": "4.3.1"},
    "Packages": {
        "ggplot2": {
            "Package": "ggplot2",
            "Version": "3.4.0",
            "Source": "Repository",
            "Repository": "CRAN",
            "Requirements": ["cli", "rlang"],
        },
        "cli": {
            "Package": "cli",
            "Version": "3.6.0",
            "Source": "Repository",
            "Repository": "CRAN",
            "Requirements": [],
        },
        "rlang": {
            "Package": "rlang",
            "Version": "1.1.0",
            "Source": "Repository",
            "Repository": "CRAN",
        },
        "testthat": {
            "Package": "testthat",
            "Version": "3.1.0",
            "Source": "Repository",
            "Repository": "CRAN",
            "Requirements": ["cli"],
        },
        "myfork": {"Package": "myfork", "Version": "0.1.0", "Source": "GitHub"},
        "orphan": {
            "Package": "orphan",
            "Version": "9.9.9",
            "Source": "Repository",
            "Repository": "CRAN",
        },
    },
}

_PACKRAT_LOCK = textwrap.dedent(
    """\
    PackratFormat: 1.4
    PackratVersion: 0.4.9.3
    RVersion: 4.3.1
    Repos: CRAN=https://cran.rstudio.com

    Package: ggplot2
    Source: CRAN
    Version: 3.4.0
    Requires: cli, rlang

    Package: cli
    Source: CRAN
    Version: 3.6.0

    Package: rlang
    Source: CRAN
    Version: 1.1.0

    Package: myfork
    Source: github
    Version: 0.1.0
    """
)


def _by_name(deps: list[Dependency]) -> dict[str, Dependency]:
    return {d.name: d for d in deps}


class TestIsOffRegistryMarker:
    def test_marker(self):
        assert is_off_registry_marker(_OFF_REGISTRY_MARKER)

    def test_non_marker(self):
        assert not is_off_registry_marker("")
        assert not is_off_registry_marker("DESCRIPTION")


class TestIsOnCran:
    def test_cran_repository(self):
        assert _is_on_cran({"Source": "Repository", "Repository": "CRAN"})

    def test_empty_repository_is_cran(self):
        assert _is_on_cran({"Source": "Repository"})

    def test_rspm_mirror_is_cran(self):
        assert _is_on_cran({"Source": "Repository", "Repository": "RSPM"})

    def test_github_source(self):
        assert not _is_on_cran({"Source": "GitHub"})

    def test_bioconductor(self):
        assert not _is_on_cran({"Source": "Repository", "Repository": "Bioconductor"})

    def test_bioc_prefixed_repo(self):
        assert not _is_on_cran({"Source": "Repository", "Repository": "BioCsoft"})


class TestParseRenvLock:
    def _parse(self, tmp_path, *, include_dev: bool) -> dict[str, Dependency]:
        (tmp_path / "renv.lock").write_text(json.dumps(_RENV_LOCK), encoding="utf-8")
        deps = parse_renv_lock(
            tmp_path / "renv.lock",
            direct_names={"ggplot2", "testthat"},
            dev_direct_names={"testthat"},
            include_dev=include_dev,
        )
        return _by_name(deps)

    def test_direct_prod_root(self, tmp_path):
        deps = self._parse(tmp_path, include_dev=True)
        assert deps["ggplot2"].group == DependencyGroup.PROD
        assert deps["ggplot2"].depth == 0
        assert deps["ggplot2"].version_constraint == "==3.4.0"
        assert deps["ggplot2"].direct_ancestors == ()

    def test_dev_root(self, tmp_path):
        deps = self._parse(tmp_path, include_dev=True)
        assert deps["testthat"].group == DependencyGroup.DEV
        assert deps["testthat"].depth == 0

    def test_prod_reachable_wins_over_dev(self, tmp_path):
        # cli is reached from ggplot2 (prod) AND testthat (dev) → PROD wins.
        deps = self._parse(tmp_path, include_dev=True)
        assert deps["cli"].group == DependencyGroup.PROD
        assert deps["cli"].depth == 1
        assert deps["cli"].direct_ancestors == ("ggplot2", "testthat")

    def test_transitive_ancestor(self, tmp_path):
        deps = self._parse(tmp_path, include_dev=True)
        assert deps["rlang"].group == DependencyGroup.PROD
        assert deps["rlang"].direct_ancestors == ("ggplot2",)

    def test_off_registry_marker(self, tmp_path):
        deps = self._parse(tmp_path, include_dev=True)
        assert deps["myfork"].source == _OFF_REGISTRY_MARKER
        assert deps["myfork"].version_constraint == "==0.1.0"

    def test_orphan_is_prod(self, tmp_path):
        deps = self._parse(tmp_path, include_dev=True)
        assert deps["orphan"].group == DependencyGroup.PROD
        assert deps["orphan"].direct_ancestors == ()

    def test_no_dev_drops_dev_only(self, tmp_path):
        deps = self._parse(tmp_path, include_dev=False)
        assert "testthat" not in deps
        assert "cli" in deps  # prod-reachable survives

    def test_name_from_key_fallback(self, tmp_path):
        (tmp_path / "renv.lock").write_text(
            json.dumps({"Packages": {"cli": {"Version": "1.0", "Source": "Repository"}}}),
            encoding="utf-8",
        )
        deps = parse_renv_lock(
            tmp_path / "renv.lock",
            direct_names={"cli"},
            dev_direct_names=set(),
            include_dev=True,
        )
        assert deps[0].name == "cli"

    def test_empty_name_skipped(self, tmp_path):
        (tmp_path / "renv.lock").write_text(
            json.dumps({"Packages": {"  ": {"Version": "1.0"}}}), encoding="utf-8"
        )
        assert (
            parse_renv_lock(
                tmp_path / "renv.lock", direct_names=set(), dev_direct_names=set(), include_dev=True
            )
            == []
        )

    def test_non_dict_entry_skipped(self, tmp_path):
        (tmp_path / "renv.lock").write_text(
            json.dumps({"Packages": {"cli": "not-a-dict"}}), encoding="utf-8"
        )
        assert (
            parse_renv_lock(
                tmp_path / "renv.lock", direct_names=set(), dev_direct_names=set(), include_dev=True
            )
            == []
        )

    def test_requirements_non_list_ignored(self, tmp_path):
        (tmp_path / "renv.lock").write_text(
            json.dumps(
                {
                    "Packages": {
                        "cli": {"Version": "1.0", "Source": "Repository", "Requirements": "x"}
                    }
                }
            ),
            encoding="utf-8",
        )
        deps = parse_renv_lock(
            tmp_path / "renv.lock",
            direct_names={"cli"},
            dev_direct_names=set(),
            include_dev=True,
        )
        assert deps[0].name == "cli"

    def test_non_dict_data(self, tmp_path):
        (tmp_path / "renv.lock").write_text("[]", encoding="utf-8")
        assert (
            parse_renv_lock(
                tmp_path / "renv.lock", direct_names=set(), dev_direct_names=set(), include_dev=True
            )
            == []
        )

    def test_non_dict_packages(self, tmp_path):
        (tmp_path / "renv.lock").write_text('{"Packages": "x"}', encoding="utf-8")
        assert (
            parse_renv_lock(
                tmp_path / "renv.lock", direct_names=set(), dev_direct_names=set(), include_dev=True
            )
            == []
        )

    def test_invalid_json(self, tmp_path):
        (tmp_path / "renv.lock").write_text("not json {", encoding="utf-8")
        assert (
            parse_renv_lock(
                tmp_path / "renv.lock", direct_names=set(), dev_direct_names=set(), include_dev=True
            )
            == []
        )

    def test_read_error(self, tmp_path, monkeypatch):
        (tmp_path / "renv.lock").write_text(json.dumps(_RENV_LOCK), encoding="utf-8")

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert (
            parse_renv_lock(
                tmp_path / "renv.lock", direct_names=set(), dev_direct_names=set(), include_dev=True
            )
            == []
        )

    def test_find_renv_lockfiles(self, tmp_path):
        (tmp_path / "renv.lock").write_text("{}", encoding="utf-8")
        assert find_renv_lockfiles(tmp_path) == [tmp_path / "renv.lock"]


class TestParsePackratLock:
    def test_edge_attribution(self, tmp_path):
        (tmp_path / "packrat.lock").write_text(_PACKRAT_LOCK, encoding="utf-8")
        deps = _by_name(
            parse_packrat_lock(
                tmp_path / "packrat.lock",
                direct_names={"ggplot2"},
                dev_direct_names=set(),
                include_dev=True,
            )
        )
        # Header record (no Package) is skipped.
        assert set(deps) == {"ggplot2", "cli", "rlang", "myfork"}
        assert deps["ggplot2"].depth == 0
        assert deps["ggplot2"].version_constraint == "==3.4.0"
        assert deps["cli"].group == DependencyGroup.PROD
        assert deps["cli"].direct_ancestors == ("ggplot2",)
        assert deps["myfork"].source == _OFF_REGISTRY_MARKER  # Source: github

    def test_read_error(self, tmp_path, monkeypatch):
        (tmp_path / "packrat.lock").write_text(_PACKRAT_LOCK, encoding="utf-8")

        def _raise(*args, **kwargs):
            raise OSError("simulated")

        monkeypatch.setattr(Path, "read_bytes", _raise)
        assert (
            parse_packrat_lock(
                tmp_path / "packrat.lock",
                direct_names=set(),
                dev_direct_names=set(),
                include_dev=True,
            )
            == []
        )

    def test_find_packrat_lockfiles(self, tmp_path):
        (tmp_path / "packrat").mkdir()
        (tmp_path / "packrat" / "packrat.lock").write_text("", encoding="utf-8")
        assert find_packrat_lockfiles(tmp_path) == [tmp_path / "packrat" / "packrat.lock"]


class TestBuildLockDependencies:
    def test_empty_spec_info(self):
        assert (
            build_lock_dependencies(
                {}, {}, direct_names=set(), dev_direct_names=set(), include_dev=True
            )
            == []
        )

    def test_diamond_dependency_revisit(self):
        # a → b, c; b → d; c → d. ``d`` is reached via two paths, exercising
        # the "already reachable" short-circuit in the BFS.
        spec_info = {
            "a": ("a", "1.0", False),
            "b": ("b", "1.0", False),
            "c": ("c", "1.0", False),
            "d": ("d", "1.0", False),
        }
        edges = {"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": set()}
        deps = _by_name(
            build_lock_dependencies(
                spec_info, edges, direct_names={"a"}, dev_direct_names=set(), include_dev=True
            )
        )
        assert set(deps) == {"a", "b", "c", "d"}
        assert deps["d"].group == DependencyGroup.PROD
        assert deps["d"].direct_ancestors == ("a",)

    def test_no_direct_names_derives_roots_from_graph(self):
        # renv.lock-only layout (no DESCRIPTION → empty direct_names): packages
        # not required by any other become the direct (depth-0) roots, so the
        # closure still gets sensible depth / ancestor attribution.
        spec_info = {
            "app": ("app", "1.0", False),  # graph root (required by nobody)
            "helper": ("helper", "2.0", False),  # required by app
            "leaf": ("leaf", "3.0", False),  # required by helper
        }
        edges = {"app": {"helper"}, "helper": {"leaf"}, "leaf": set()}
        deps = _by_name(
            build_lock_dependencies(
                spec_info, edges, direct_names=set(), dev_direct_names=set(), include_dev=True
            )
        )
        assert set(deps) == {"app", "helper", "leaf"}
        assert deps["app"].depth == 0  # root → direct
        assert deps["app"].group == DependencyGroup.PROD
        assert deps["helper"].depth == 1
        assert deps["helper"].direct_ancestors == ("app",)
        assert deps["leaf"].direct_ancestors == ("app",)


class TestAttachDirectSources:
    def test_stamps_direct_registry_source(self):
        deps = [
            Dependency("cli", "==3.6.0", Ecosystem.R, depth=0),
            Dependency("rlang", "==1.1.0", Ecosystem.R, depth=1),
            Dependency("myfork", "==0.1.0", Ecosystem.R, depth=0, source=_OFF_REGISTRY_MARKER),
            Dependency("nomatch", "==1.0", Ecosystem.R, depth=0),
        ]
        result = _by_name(attach_direct_sources(deps, {"cli": "DESCRIPTION"}))
        assert result["cli"].source == "DESCRIPTION"
        assert result["rlang"].source == ""  # transitive untouched
        assert result["myfork"].source == _OFF_REGISTRY_MARKER  # off-registry untouched
        assert result["nomatch"].source == ""  # direct but no source match
