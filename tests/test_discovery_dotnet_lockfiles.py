"""Tests for NuGet lockfile discovery."""

from __future__ import annotations

import json
from pathlib import Path

from licenseal.discovery.dotnet.lockfiles import (
    _collect_assets_direct_names,
    _extract_edges,
    find_nuget_lockfiles,
    parse_nuget_lockfile,
    parse_packages_lock_json,
    parse_project_assets_json,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# parse_packages_lock_json
# ---------------------------------------------------------------------------


class TestParsePackagesLockJson:
    def test_simple_direct_and_transitive(self):
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Newtonsoft.Json": {
                            "type": "Direct",
                            "resolved": "13.0.1",
                            "dependencies": {},
                        },
                        "System.Text.Json": {
                            "type": "Transitive",
                            "resolved": "8.0.0",
                            "dependencies": {"System.Memory": "4.5.5"},
                        },
                    }
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        names = {(e.name, e.version): e for e in entries}
        assert names[("Newtonsoft.Json", "13.0.1")].is_direct
        assert not names[("System.Text.Json", "8.0.0")].is_direct
        assert names[("System.Text.Json", "8.0.0")].edges == ("system.memory",)

    def test_tfm_union_dedups_by_name_version(self):
        # Same package appearing in multiple TFMs at the same version
        # should produce ONE entry (TFM-union dedup).
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {"Shared": {"type": "Direct", "resolved": "1.0", "dependencies": {}}},
                    "net8.0-windows": {
                        "Shared": {"type": "Direct", "resolved": "1.0", "dependencies": {}}
                    },
                    "netstandard2.0": {
                        "Shared": {"type": "Direct", "resolved": "1.0", "dependencies": {}}
                    },
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        assert len(entries) == 1
        assert entries[0].name == "Shared"

    def test_tfm_union_keeps_every_frameworks_edges(self):
        # The same package@version depends on different packages under each
        # TFM, and is a direct reference under only one. The single entry
        # carries the union.
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Shared": {
                            "type": "Transitive",
                            "resolved": "1.0",
                            "dependencies": {"Common": "1.0"},
                        }
                    },
                    "net472": {
                        "Shared": {
                            "type": "Direct",
                            "resolved": "1.0",
                            "dependencies": {"Common": "1.0", "Polyfill": "2.0"},
                        }
                    },
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        (shared,) = entries
        assert shared.edges == ("common", "polyfill")
        assert shared.is_direct

    def test_same_name_different_version_kept(self):
        # If the same package resolves to DIFFERENT versions across TFMs
        # (rare but possible with conditional refs), both must surface.
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {"Lib": {"type": "Direct", "resolved": "1.0", "dependencies": {}}},
                    "net6.0": {"Lib": {"type": "Direct", "resolved": "0.9", "dependencies": {}}},
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        versions = {e.version for e in entries}
        assert versions == {"1.0", "0.9"}

    def test_direct_reference_type_also_recognized(self):
        # ``DirectReference`` is a less common ``type`` value also treated
        # as direct (covers some lockfile dialects).
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "X": {
                            "type": "DirectReference",
                            "resolved": "1.0",
                            "dependencies": {},
                        }
                    }
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        assert entries[0].is_direct

    def test_missing_resolved_skipped(self):
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "MissingVer": {"type": "Direct"},
                        "Valid": {"type": "Direct", "resolved": "1.0"},
                    }
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"Valid"}

    def test_non_string_package_name_skipped(self):
        # JSON only allows string keys at the object level — but defensive
        # against the inner ``dependencies`` map being a different shape
        # than expected.
        # We can't really put a non-string key in JSON, but we CAN put
        # a non-dict value where a dict is expected.
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Valid": {"type": "Direct", "resolved": "1.0"},
                        "Malformed": "not-a-dict",
                    }
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"Valid"}

    def test_non_dict_tfm_value_skipped(self):
        # The inner per-TFM value must be a dict; defensive against
        # malformed lockfiles.
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": "garbage",
                    "net6.0": {"Valid": {"type": "Direct", "resolved": "1.0"}},
                },
            }
        )
        entries = parse_packages_lock_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"Valid"}

    def test_malformed_json_returns_none(self):
        assert parse_packages_lock_json("not json {") is None

    def test_non_object_top_level_returns_empty(self):
        # JSON array at the top level is valid JSON but not a lockfile.
        assert parse_packages_lock_json("[]") == []

    def test_missing_dependencies_key_returns_empty(self):
        text = json.dumps({"version": 1})
        assert parse_packages_lock_json(text) == []

    def test_non_dict_dependencies_returns_empty(self):
        text = json.dumps({"version": 1, "dependencies": "garbage"})
        assert parse_packages_lock_json(text) == []


# ---------------------------------------------------------------------------
# parse_project_assets_json
# ---------------------------------------------------------------------------


class TestParseProjectAssetsJson:
    def test_simple_targets(self):
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": {
                        "Newtonsoft.Json/13.0.1": {
                            "type": "package",
                            "dependencies": {},
                        },
                        "System.Text.Json/8.0.0": {
                            "type": "package",
                            "dependencies": {"System.Memory": "4.5.5"},
                        },
                    }
                },
                "project": {
                    "frameworks": {
                        "net8.0": {"dependencies": {"Newtonsoft.Json": {"version": "[13.0.1, )"}}}
                    }
                },
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        by_name = {e.name: e for e in entries}
        assert by_name["Newtonsoft.Json"].is_direct
        assert not by_name["System.Text.Json"].is_direct
        assert by_name["System.Text.Json"].edges == ("system.memory",)

    def test_project_type_entries_skipped(self):
        # An in-repo project reference appears in targets but with
        # ``type: "project"`` — those are NOT NuGet packages.
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": {
                        "MyProject/1.0.0": {"type": "project"},
                        "RealPackage/1.0.0": {"type": "package"},
                    }
                },
                "project": {"frameworks": {}},
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"RealPackage"}

    def test_tfm_union_dedups(self):
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": {"Shared/1.0.0": {"type": "package", "dependencies": {}}},
                    "net6.0": {"Shared/1.0.0": {"type": "package", "dependencies": {}}},
                },
                "project": {"frameworks": {}},
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        assert len(entries) == 1

    def test_tfm_union_keeps_every_frameworks_edges(self):
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": {
                        "Shared/1.0.0": {"type": "package", "dependencies": {"Common": "1.0"}}
                    },
                    "net472": {
                        "Shared/1.0.0": {"type": "package", "dependencies": {"Polyfill": "2.0"}}
                    },
                },
                "project": {"frameworks": {}},
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        (shared,) = entries
        assert shared.edges == ("common", "polyfill")
        assert not shared.is_direct

    def test_malformed_coordinate_skipped(self):
        # A target key without ``/`` is malformed.
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": {
                        "NoSlashCoord": {"type": "package"},
                        "Valid/1.0": {"type": "package"},
                    }
                },
                "project": {"frameworks": {}},
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"Valid"}

    def test_empty_name_or_version_skipped(self):
        # A coordinate with empty name (``/1.0``) or empty version
        # (``X/``) is malformed.
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": {
                        "/1.0": {"type": "package"},
                        "X/": {"type": "package"},
                        "Real/1.0": {"type": "package"},
                    }
                },
                "project": {"frameworks": {}},
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"Real"}

    def test_missing_targets_returns_empty(self):
        text = json.dumps({"version": 3})
        assert parse_project_assets_json(text) == []

    def test_non_dict_targets_returns_empty(self):
        assert parse_project_assets_json(json.dumps({"targets": "x"})) == []

    def test_non_dict_tfm_value_skipped(self):
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": "garbage",
                    "net6.0": {"Valid/1.0": {"type": "package"}},
                },
                "project": {"frameworks": {}},
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"Valid"}

    def test_non_dict_entry_skipped(self):
        text = json.dumps(
            {
                "version": 3,
                "targets": {
                    "net8.0": {
                        "X/1.0": "not-a-dict",
                        "Y/1.0": {"type": "package"},
                    }
                },
                "project": {"frameworks": {}},
            }
        )
        entries = parse_project_assets_json(text)
        assert entries is not None
        assert {e.name for e in entries} == {"Y"}

    def test_malformed_json_returns_none(self):
        assert parse_project_assets_json("not json {") is None

    def test_non_object_top_level_returns_empty(self):
        assert parse_project_assets_json("[]") == []


# ---------------------------------------------------------------------------
# _collect_assets_direct_names
# ---------------------------------------------------------------------------


class TestCollectAssetsDirectNames:
    def test_union_across_frameworks(self):
        data = {
            "project": {
                "frameworks": {
                    "net8.0": {"dependencies": {"OnlyOnNet8": {}}},
                    "net6.0": {"dependencies": {"OnlyOnNet6": {}}},
                }
            }
        }
        assert _collect_assets_direct_names(data) == {"onlyonnet8", "onlyonnet6"}

    def test_lowercased(self):
        data = {"project": {"frameworks": {"net8.0": {"dependencies": {"NewTonSoft.JSON": {}}}}}}
        assert _collect_assets_direct_names(data) == {"newtonsoft.json"}

    def test_no_project_returns_empty(self):
        assert _collect_assets_direct_names({}) == set()

    def test_non_dict_project_returns_empty(self):
        assert _collect_assets_direct_names({"project": "garbage"}) == set()

    def test_non_dict_frameworks_returns_empty(self):
        assert _collect_assets_direct_names({"project": {"frameworks": "x"}}) == set()

    def test_non_dict_framework_value_skipped(self):
        data = {
            "project": {
                "frameworks": {
                    "net8.0": "garbage",
                    "net6.0": {"dependencies": {"Valid": {}}},
                }
            }
        }
        assert _collect_assets_direct_names(data) == {"valid"}

    def test_non_dict_dependencies_skipped(self):
        data = {
            "project": {
                "frameworks": {
                    "net8.0": {"dependencies": "garbage"},
                    "net6.0": {"dependencies": {"Valid": {}}},
                }
            }
        }
        assert _collect_assets_direct_names(data) == {"valid"}


# ---------------------------------------------------------------------------
# _extract_edges
# ---------------------------------------------------------------------------


class TestExtractEdges:
    def test_dict_keys_lowercased(self):
        assert _extract_edges({"FooDep": "1.0", "BarDep": "2.0"}) == ("foodep", "bardep")

    def test_non_dict_returns_empty(self):
        assert _extract_edges(None) == ()
        assert _extract_edges("garbage") == ()
        assert _extract_edges([]) == ()

    def test_empty_dict(self):
        assert _extract_edges({}) == ()


# ---------------------------------------------------------------------------
# find_nuget_lockfiles
# ---------------------------------------------------------------------------


class TestFindNugetLockfiles:
    def test_both_filenames_returned(self, tmp_path):
        _write(tmp_path / "packages.lock.json", "{}")
        _write(tmp_path / "obj" / "project.assets.json", "{}")
        # ``obj`` isn't in the auto-skip dir set, so it's walked.
        paths = find_nuget_lockfiles(tmp_path)
        names = {p.name for p in paths}
        assert names == {"packages.lock.json", "project.assets.json"}

    def test_empty_workspace_returns_empty(self, tmp_path):
        assert find_nuget_lockfiles(tmp_path) == []


# ---------------------------------------------------------------------------
# parse_nuget_lockfile
# ---------------------------------------------------------------------------


def _packages_lock(*tfms: dict) -> str:
    """A ``packages.lock.json`` with one ``{name: (type, version, [children])}`` map per TFM."""
    return json.dumps(
        {
            "version": 1,
            "dependencies": {
                f"tfm{index}": {
                    name: {
                        "type": entry_type,
                        "resolved": version,
                        "dependencies": dict.fromkeys(children, "1.0.0"),
                    }
                    for name, (entry_type, version, children) in packages.items()
                }
                for index, packages in enumerate(tfms)
            },
        }
    )


def _parse(
    path: Path,
    *,
    prod: frozenset[str] | set[str] = frozenset(),
    dev: frozenset[str] | set[str] = frozenset(),
    include_dev: bool = True,
) -> dict[str, Dependency]:
    deps = parse_nuget_lockfile(
        path, prod_root_names=set(prod), dev_root_names=set(dev), include_dev=include_dev
    )
    assert len({d.name for d in deps}) == len(deps)
    return {d.name: d for d in deps}


class TestParseNugetLockfile:
    def test_packages_lock_json_end_to_end(self, tmp_path):
        path = tmp_path / "packages.lock.json"
        _write(path, _packages_lock({"Lib": ("Direct", "1.0", [])}))
        (dep,) = _parse(path, prod={"lib"}).values()
        assert dep.name == "Lib"
        assert dep.version_constraint == "1.0"
        assert dep.group == DependencyGroup.PROD
        assert dep.ecosystem == Ecosystem.DOTNET
        assert dep.depth == 0

    def test_project_assets_json_end_to_end(self, tmp_path):
        path = tmp_path / "obj" / "project.assets.json"
        _write(
            path,
            json.dumps(
                {
                    "version": 3,
                    "targets": {
                        "net8.0": {
                            "Lib/1.0.0": {"type": "package", "dependencies": {"Child": "2.0.0"}},
                            "Child/2.0.0": {"type": "package"},
                        }
                    },
                    "project": {"frameworks": {}},
                }
            ),
        )
        deps = _parse(path, prod={"lib"})
        assert {(d.name, d.version_constraint, d.depth) for d in deps.values()} == {
            ("Lib", "1.0.0", 0),
            ("Child", "2.0.0", 1),
        }
        assert deps["Child"].direct_ancestors == ("Lib",)

    def test_unreadable_file_yields_nothing(self, tmp_path, monkeypatch):
        path = tmp_path / "packages.lock.json"
        _write(path, _packages_lock({"Lib": ("Direct", "1.0", [])}))

        def explode(self, *args, **kwargs):
            raise OSError("denied")

        monkeypatch.setattr(Path, "read_bytes", explode)
        assert _parse(path, prod={"lib"}) == {}

    def test_malformed_lockfile_yields_nothing(self, tmp_path):
        path = tmp_path / "packages.lock.json"
        _write(path, "not json {")
        assert _parse(path, prod={"lib"}) == {}

    def test_utf8_bom_tolerated(self, tmp_path):
        path = tmp_path / "packages.lock.json"
        path.write_bytes(
            b"\xef\xbb\xbf" + _packages_lock({"BomDep": ("Direct", "1.0", [])}).encode("utf-8")
        )
        assert set(_parse(path)) == {"BomDep"}


class TestNugetLockfileAttribution:
    """Group and ancestors come from the lockfile's edges, rooted at the
    direct dependencies discovery found."""

    # One PROD root and one DEV root, each with a chain of its own, plus a
    # package both chains reach.
    _GRAPH = {
        "ProdLib": ("Direct", "1.0.0", ["ProdChild", "Shared"]),
        "ProdChild": ("Transitive", "1.1.0", ["ProdGrandchild"]),
        "ProdGrandchild": ("Transitive", "1.2.0", []),
        "DevTool": ("Direct", "2.0.0", ["DevChild", "Shared"]),
        "DevChild": ("Transitive", "2.1.0", []),
        "Shared": ("Transitive", "3.0.0", []),
    }

    def _lock(self, tmp_path, *tfms: dict) -> Path:
        path = tmp_path / "packages.lock.json"
        _write(path, _packages_lock(*tfms))
        return path

    def test_prod_dev_and_shared_chains(self, tmp_path):
        deps = _parse(self._lock(tmp_path, self._GRAPH), prod={"prodlib"}, dev={"devtool"})
        assert {name: (d.group, d.depth, d.direct_ancestors) for name, d in deps.items()} == {
            "ProdLib": (DependencyGroup.PROD, 0, ()),
            "ProdChild": (DependencyGroup.PROD, 1, ("ProdLib",)),
            "ProdGrandchild": (DependencyGroup.PROD, 1, ("ProdLib",)),
            "DevTool": (DependencyGroup.DEV, 0, ()),
            "DevChild": (DependencyGroup.DEV, 1, ("DevTool",)),
            # Reached from both roots: production wins, and only the
            # production root is listed.
            "Shared": (DependencyGroup.PROD, 1, ("ProdLib",)),
        }

    def test_dev_only_chain_dropped_without_dev(self, tmp_path):
        deps = _parse(
            self._lock(tmp_path, self._GRAPH),
            prod={"prodlib"},
            dev={"devtool"},
            include_dev=False,
        )
        assert set(deps) == {"ProdLib", "ProdChild", "ProdGrandchild", "Shared"}
        assert {d.group for d in deps.values()} == {DependencyGroup.PROD}

    def test_dev_root_reached_from_prod_root_is_prod(self, tmp_path):
        # DevTool is declared dev, but the production ProdLib depends on it.
        graph = {**self._GRAPH, "ProdLib": ("Direct", "1.0.0", ["DevTool"])}
        deps = _parse(
            self._lock(tmp_path, graph), prod={"prodlib"}, dev={"devtool"}, include_dev=False
        )
        assert {name: (d.group, d.depth, d.direct_ancestors) for name, d in deps.items()} == {
            "ProdLib": (DependencyGroup.PROD, 0, ()),
            # Still a direct dependency: depth 0, no ancestors.
            "DevTool": (DependencyGroup.PROD, 0, ()),
            "DevChild": (DependencyGroup.PROD, 1, ("ProdLib",)),
            "Shared": (DependencyGroup.PROD, 1, ("ProdLib",)),
            # No root reaches these any more: kept as PROD, no ancestors.
            "ProdChild": (DependencyGroup.PROD, 1, ()),
            "ProdGrandchild": (DependencyGroup.PROD, 1, ()),
        }

    def test_package_reached_from_no_root_is_prod_without_ancestors(self, tmp_path):
        # Nothing discovery found is in this lockfile.
        deps = _parse(self._lock(tmp_path, self._GRAPH), include_dev=False)
        assert set(deps) == set(self._GRAPH)
        assert {(d.group, d.depth, d.direct_ancestors) for d in deps.values()} == {
            (DependencyGroup.PROD, 1, ())
        }

    def test_lockfile_direct_marker_adds_no_root(self, tmp_path):
        # DevTool is ``type: Direct`` in the lockfile but discovery did not
        # report it, so it is not a root: it and its chain are unattributed.
        deps = _parse(self._lock(tmp_path, self._GRAPH), prod={"prodlib"}, include_dev=False)
        assert deps["DevTool"].depth == 1
        assert deps["DevTool"].direct_ancestors == ()
        assert deps["DevChild"].direct_ancestors == ()
        assert deps["Shared"].direct_ancestors == ("ProdLib",)

    def test_root_names_match_case_insensitively(self, tmp_path):
        # The roots arrive lowercased; edges are lowercased by the parser.
        graph = {
            "PRODLIB": ("Direct", "1.0.0", ["prodCHILD"]),
            "ProdChild": ("Transitive", "1.1.0", []),
        }
        deps = _parse(self._lock(tmp_path, graph), prod={"prodlib"})
        assert deps["PRODLIB"].depth == 0
        assert deps["ProdChild"].direct_ancestors == ("PRODLIB",)

    def test_edges_unioned_across_target_frameworks(self, tmp_path):
        # DevTool pulls DevChild under one TFM and Polyfill under the other,
        # at the same version. Both stay on the dev chain.
        deps = _parse(
            self._lock(
                tmp_path,
                {
                    "DevTool": ("Direct", "2.0.0", ["DevChild"]),
                    "DevChild": ("Transitive", "2.1.0", []),
                },
                {
                    "DevTool": ("Direct", "2.0.0", ["Polyfill"]),
                    "Polyfill": ("Transitive", "4.0.0", []),
                },
            ),
            dev={"devtool"},
        )
        assert {name: (d.group, d.direct_ancestors) for name, d in deps.items()} == {
            "DevTool": (DependencyGroup.DEV, ()),
            "DevChild": (DependencyGroup.DEV, ("DevTool",)),
            "Polyfill": (DependencyGroup.DEV, ("DevTool",)),
        }

    def test_production_reach_under_one_target_framework_is_enough(self, tmp_path):
        # Shared is dev-only under the first TFM and reached from ProdLib
        # under the second.
        deps = _parse(
            self._lock(
                tmp_path,
                {
                    "DevTool": ("Direct", "2.0.0", ["Shared"]),
                    "Shared": ("Transitive", "3.0.0", []),
                },
                {
                    "ProdLib": ("Direct", "1.0.0", ["Shared"]),
                    "Shared": ("Transitive", "3.0.0", []),
                },
            ),
            prod={"prodlib"},
            dev={"devtool"},
            include_dev=False,
        )
        assert set(deps) == {"ProdLib", "Shared"}
        assert deps["Shared"].group == DependencyGroup.PROD

    def test_versions_of_one_package_share_attribution(self, tmp_path):
        # Two versions of Shared across TFMs. Edges are keyed by name, so
        # both are on the production chain.
        path = self._lock(
            tmp_path,
            {"ProdLib": ("Direct", "1.0.0", ["Shared"]), "Shared": ("Transitive", "3.0.0", [])},
            {"DevTool": ("Direct", "2.0.0", ["Shared"]), "Shared": ("Transitive", "3.1.0", [])},
        )
        deps = parse_nuget_lockfile(
            path, prod_root_names={"prodlib"}, dev_root_names={"devtool"}, include_dev=False
        )
        assert {(d.name, d.version_constraint, d.group) for d in deps} == {
            ("ProdLib", "1.0.0", DependencyGroup.PROD),
            ("Shared", "3.0.0", DependencyGroup.PROD),
            ("Shared", "3.1.0", DependencyGroup.PROD),
        }
