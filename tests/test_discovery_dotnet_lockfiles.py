"""Tests for NuGet lockfile discovery."""

from __future__ import annotations

import json
from pathlib import Path

from licenseal.discovery.dotnet.lockfiles import (
    _collect_assets_direct_names,
    _entries_to_dependencies,
    _extract_edges,
    _LockEntry,
    discover_nuget_lockfile_dependencies,
    find_nuget_lockfiles,
    parse_packages_lock_json,
    parse_project_assets_json,
)
from licenseal.models import DependencyGroup, Ecosystem


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
# find_nuget_lockfiles + discover_nuget_lockfile_dependencies
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


class TestDiscoverNugetLockfileDependencies:
    def test_packages_lock_json_end_to_end(self, tmp_path):
        _write(
            tmp_path / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {"net8.0": {"Lib": {"type": "Direct", "resolved": "1.0"}}},
                }
            ),
        )
        deps, filtered = discover_nuget_lockfile_dependencies(tmp_path)
        assert filtered == 0
        assert len(deps) == 1
        assert deps[0].name == "Lib"
        assert deps[0].version_constraint == "1.0"
        assert deps[0].group == DependencyGroup.PROD
        assert deps[0].ecosystem == Ecosystem.DOTNET

    def test_project_assets_json_end_to_end(self, tmp_path):
        _write(
            tmp_path / "obj" / "project.assets.json",
            json.dumps(
                {
                    "version": 3,
                    "targets": {"net8.0": {"Lib/1.0.0": {"type": "package"}}},
                    "project": {"frameworks": {}},
                }
            ),
        )
        deps, _ = discover_nuget_lockfile_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "Lib"
        assert deps[0].version_constraint == "1.0.0"

    def test_source_path_is_posix(self, tmp_path):
        _write(
            tmp_path / "src" / "Proj" / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {"net8.0": {"X": {"type": "Direct", "resolved": "1.0"}}},
                }
            ),
        )
        deps, _ = discover_nuget_lockfile_dependencies(tmp_path)
        assert deps[0].source == "src/Proj/packages.lock.json"

    def test_unreadable_file_skipped(self, tmp_path, monkeypatch):
        _write(tmp_path / "packages.lock.json", "{}")
        original = Path.read_text

        def explode(self, *args, **kwargs):
            if self.name == "packages.lock.json":
                raise OSError("denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", explode)
        deps, _ = discover_nuget_lockfile_dependencies(tmp_path)
        assert deps == []

    def test_malformed_lockfile_skipped(self, tmp_path):
        _write(tmp_path / "packages.lock.json", "not json {")
        _write(
            tmp_path / "good" / "packages.lock.json",
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {"net8.0": {"Good": {"type": "Direct", "resolved": "1.0"}}},
                }
            ),
        )
        deps, _ = discover_nuget_lockfile_dependencies(tmp_path)
        assert {d.name for d in deps} == {"Good"}

    def test_utf8_bom_tolerated(self, tmp_path):
        path = tmp_path / "packages.lock.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            b"\xef\xbb\xbf"
            + json.dumps(
                {
                    "version": 1,
                    "dependencies": {"net8.0": {"BomDep": {"type": "Direct", "resolved": "1.0"}}},
                }
            ).encode("utf-8")
        )
        deps, _ = discover_nuget_lockfile_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "BomDep"


# ---------------------------------------------------------------------------
# _entries_to_dependencies + _LockEntry dataclass sanity
# ---------------------------------------------------------------------------


class TestEntriesToDependencies:
    def test_round_trip(self):
        entries = [
            _LockEntry(name="A", version="1.0", is_direct=True, edges=()),
            _LockEntry(name="B", version="2.0", is_direct=False, edges=("a",)),
        ]
        deps = _entries_to_dependencies(entries, source="X")
        assert all(d.ecosystem == Ecosystem.DOTNET for d in deps)
        assert all(d.group == DependencyGroup.PROD for d in deps)
        assert all(d.source == "X" for d in deps)
        assert [d.name for d in deps] == ["A", "B"]
