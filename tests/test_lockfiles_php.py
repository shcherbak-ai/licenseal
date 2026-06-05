"""Tests for the PHP ``composer.lock`` parser."""

from __future__ import annotations

import json
from pathlib import Path

from licenseal.discovery.php.lockfiles import (
    extract_composer_lock_licenses,
    find_composer_lockfiles,
    parse_composer_lockfile,
)
from licenseal.models import DependencyGroup, Ecosystem

_FIXTURES = Path(__file__).parent / "fixtures" / "composer"


def _direct_names() -> set[str]:
    """Lowercased direct names declared in the simple fixture's composer.json."""
    return {
        "vendor-a/lib-one",
        "vendor-b/lib-two",
        "vendor-c/proprietary-lib",
        "vendor-d/dev-tool",
    }


class TestFindComposerLockfiles:
    def test_finds_composer_lock_in_simple_fixture(self):
        locks = find_composer_lockfiles(_FIXTURES / "simple")
        assert len(locks) == 1
        assert locks[0].name == "composer.lock"

    def test_empty_when_absent(self, tmp_path):
        assert find_composer_lockfiles(tmp_path) == []


class TestParseComposerLockfile:
    def test_prod_packages_with_dev_excluded(self):
        deps, _ = parse_composer_lockfile(
            _FIXTURES / "simple" / "composer.lock",
            direct_names=_direct_names(),
            include_dev=False,
        )
        names_by_group: dict[DependencyGroup, set[str]] = {
            DependencyGroup.PROD: set(),
            DependencyGroup.DEV: set(),
        }
        for dep in deps:
            names_by_group[dep.group].add(dep.name)

        # Prod packages from the simple fixture.
        assert {
            "vendor-a/lib-one",
            "vendor-b/lib-two",
            "vendor-c/proprietary-lib",
            "vendor-x/transitive-shared",
        } <= names_by_group[DependencyGroup.PROD]
        # Dev packages should be excluded entirely.
        assert names_by_group[DependencyGroup.DEV] == set()

    def test_dev_included_when_flag_set(self):
        deps, _ = parse_composer_lockfile(
            _FIXTURES / "simple" / "composer.lock",
            direct_names=_direct_names(),
            include_dev=True,
        )
        dev_names = {d.name for d in deps if d.group == DependencyGroup.DEV}
        assert "vendor-d/dev-tool" in dev_names
        assert "vendor-y/dev-only-transitive" in dev_names

    def test_direct_vs_transitive_depth(self):
        deps, _ = parse_composer_lockfile(
            _FIXTURES / "simple" / "composer.lock",
            direct_names=_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d for d in deps}
        # Direct (depth=0) — declared in composer.json.
        assert by_name["vendor-a/lib-one"].depth == 0
        # Transitive (depth=1) — reached through require edges.
        assert by_name["vendor-x/transitive-shared"].depth == 1

    def test_pinned_version_uses_double_equals(self):
        deps, _ = parse_composer_lockfile(
            _FIXTURES / "simple" / "composer.lock",
            direct_names=_direct_names(),
            include_dev=True,
        )
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["vendor-a/lib-one"] == "==1.2.3"
        assert by_name["vendor-b/lib-two"] == "==2.0.1"

    def test_direct_ancestors_populated_for_transitives(self):
        deps, _ = parse_composer_lockfile(
            _FIXTURES / "simple" / "composer.lock",
            direct_names=_direct_names(),
            include_dev=True,
        )
        shared = next(d for d in deps if d.name == "vendor-x/transitive-shared")
        # Reached from both vendor-a/lib-one AND vendor-b/lib-two.
        assert set(shared.direct_ancestors) == {"vendor-a/lib-one", "vendor-b/lib-two"}

    def test_license_map_contains_pinned_pairs(self):
        _, license_map = parse_composer_lockfile(
            _FIXTURES / "simple" / "composer.lock",
            direct_names=_direct_names(),
            include_dev=True,
        )
        assert license_map[("vendor-a/lib-one", "1.2.3")] == "MIT"
        # Multi-license array joined with OR.
        assert license_map[("vendor-b/lib-two", "2.0.1")] == "MIT OR Apache-2.0"
        # Legacy bare-string license form preserved.
        assert license_map[("vendor-d/dev-tool", "3.0.0")] == "BSD-3-Clause"
        # Proprietary placeholder passes through.
        assert license_map[("vendor-c/proprietary-lib", "1.0.0")] == "proprietary"
        # Empty license array → empty raw (resolver falls back to Packagist).
        assert license_map[("vendor-x/transitive-shared", "4.5.6")] == ""

    def test_ecosystem_stamped_as_php(self):
        deps, _ = parse_composer_lockfile(
            _FIXTURES / "simple" / "composer.lock",
            direct_names=_direct_names(),
            include_dev=True,
        )
        assert all(d.ecosystem == Ecosystem.PHP for d in deps)

    def test_path_source_filtered(self, tmp_path):
        # ``dist.type == "path"`` entries are workspace-local — filter out.
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "vendor/workspace-sibling",
                            "version": "dev-main",
                            "dist": {"type": "path", "url": "../sibling"},
                            "license": ["MIT"],
                        },
                        {
                            "name": "vendor/regular",
                            "version": "1.0.0",
                            "dist": {"type": "zip", "url": "https://example.com/x.zip"},
                            "license": ["MIT"],
                        },
                    ]
                }
            )
        )
        deps, _ = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names={"vendor/regular"},
            include_dev=False,
        )
        names = {d.name for d in deps}
        assert "vendor/regular" in names
        assert "vendor/workspace-sibling" not in names

    def test_malformed_lockfile_returns_empty(self, tmp_path):
        (tmp_path / "composer.lock").write_text("not json")
        deps, license_map = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names=set(),
            include_dev=False,
        )
        assert deps == []
        assert license_map == {}

    def test_non_dict_root_returns_empty(self, tmp_path):
        (tmp_path / "composer.lock").write_text(json.dumps([1, 2, 3]))
        deps, license_map = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names=set(),
            include_dev=False,
        )
        assert deps == []
        assert license_map == {}

    def test_dev_names_set_skips_non_dict_and_non_string_names(self, tmp_path):
        # Defensive: ``packages-dev`` contains malformed entries (non-dict
        # or dict with non-string name). The pre-compute step must skip
        # them without raising; the dev_names_set ends up empty so the
        # entries are attributed as PROD via the explicit dev flag.
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [{"name": "vendor/x", "version": "1.0", "license": ["MIT"]}],
                    "packages-dev": [
                        "not-a-dict",
                        {"name": None, "version": "1.0", "license": ["MIT"]},
                    ],
                }
            )
        )
        deps, _ = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names={"vendor/x"},
            include_dev=False,
        )
        # vendor/x is the only valid package and gets attributed as PROD.
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.PROD

    def test_packages_dev_inference_when_dev_flag_absent(self, tmp_path):
        # Older composer.lock files omit the per-entry ``dev`` boolean and
        # rely on the packages-dev array partition alone. Parser must still
        # attribute DEV correctly.
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [],
                    "packages-dev": [
                        {
                            "name": "vendor/dev-only",
                            "version": "1.0.0",
                            "license": ["MIT"],
                        }
                    ],
                }
            )
        )
        deps, _ = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names={"vendor/dev-only"},
            include_dev=True,
        )
        assert len(deps) == 1
        assert deps[0].group == DependencyGroup.DEV


class TestExtractComposerLockLicenses:
    def test_returns_license_map(self):
        license_map = extract_composer_lock_licenses(_FIXTURES / "simple" / "composer.lock")
        assert license_map[("vendor-a/lib-one", "1.2.3")] == "MIT"
        assert license_map[("vendor-b/lib-two", "2.0.1")] == "MIT OR Apache-2.0"
        assert license_map[("vendor-d/dev-tool", "3.0.0")] == "BSD-3-Clause"

    def test_missing_file_returns_empty(self, tmp_path):
        assert extract_composer_lock_licenses(tmp_path / "composer.lock") == {}

    def test_malformed_returns_empty(self, tmp_path):
        (tmp_path / "composer.lock").write_text("{not json")
        assert extract_composer_lock_licenses(tmp_path / "composer.lock") == {}

    def test_non_dict_root_returns_empty(self, tmp_path):
        (tmp_path / "composer.lock").write_text(json.dumps([]))
        assert extract_composer_lock_licenses(tmp_path / "composer.lock") == {}

    def test_non_list_packages_field_skipped(self, tmp_path):
        # Defensive: ``packages`` carried as a dict instead of a list.
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": {"name": "wrong shape"},
                    "packages-dev": [{"name": "vendor/x", "version": "1.0", "license": ["MIT"]}],
                }
            )
        )
        license_map = extract_composer_lock_licenses(tmp_path / "composer.lock")
        assert license_map == {("vendor/x", "1.0"): "MIT"}

    def test_non_dict_entry_in_list_skipped(self, tmp_path):
        # Defensive: list contains a non-dict (string).
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        "not-a-dict",
                        {"name": "vendor/x", "version": "1.0", "license": ["MIT"]},
                    ]
                }
            )
        )
        license_map = extract_composer_lock_licenses(tmp_path / "composer.lock")
        assert license_map == {("vendor/x", "1.0"): "MIT"}

    def test_non_string_name_or_version_skipped(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {"name": None, "version": "1.0"},
                        {"name": "vendor/x", "version": 1.0},
                    ]
                }
            )
        )
        assert extract_composer_lock_licenses(tmp_path / "composer.lock") == {}

    def test_non_string_non_list_license_returns_empty(self, tmp_path):
        # Defensive fallthrough: license field is neither a string nor an
        # array (publisher error / older Composer dialect with a dict).
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "vendor/x",
                            "version": "1.0",
                            "license": {"type": "MIT"},
                        }
                    ]
                }
            )
        )
        license_map = extract_composer_lock_licenses(tmp_path / "composer.lock")
        assert license_map == {("vendor/x", "1.0"): ""}

    def test_v_prefix_stripped_in_keys(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {"packages": [{"name": "vendor/x", "version": "v3.5.0", "license": ["MIT"]}]}
            )
        )
        license_map = extract_composer_lock_licenses(tmp_path / "composer.lock")
        # Key stored without the decorative ``v`` prefix.
        assert license_map == {("vendor/x", "3.5.0"): "MIT"}


class TestParseEdgeCases:
    def test_non_list_packages_field_skipped(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": "wrong shape",
                    "packages-dev": [],
                }
            )
        )
        deps, license_map = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names=set(),
            include_dev=False,
        )
        assert deps == []
        assert license_map == {}

    def test_non_dict_entry_in_list_skipped(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        "not-a-dict",
                        {"name": "vendor/x", "version": "1.0", "license": ["MIT"]},
                    ]
                }
            )
        )
        deps, _ = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names={"vendor/x"},
            include_dev=False,
        )
        assert [d.name for d in deps] == ["vendor/x"]

    def test_non_string_name_or_version_skipped(self, tmp_path):
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {"name": None, "version": "1.0", "license": ["MIT"]},
                        {"name": "vendor/y", "version": 42, "license": ["MIT"]},
                    ]
                }
            )
        )
        deps, license_map = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names=set(),
            include_dev=False,
        )
        assert deps == []
        assert license_map == {}

    def test_source_path_type_also_filtered(self, tmp_path):
        # ``source.type == "path"`` (rather than dist.type) — both shapes
        # signal a workspace-local dep.
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "vendor/workspace-by-source",
                            "version": "1.0.0",
                            "source": {"type": "path", "url": "../sib"},
                            "license": ["MIT"],
                        }
                    ]
                }
            )
        )
        deps, _ = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names={"vendor/workspace-by-source"},
            include_dev=False,
        )
        assert deps == []

    def test_duplicate_entry_is_seen_only_once(self, tmp_path):
        # Defensive: same (name, version) appearing twice — second
        # occurrence is dropped via the ``seen`` set.
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {"name": "vendor/x", "version": "1.0", "license": ["MIT"]},
                        {"name": "vendor/x", "version": "1.0", "license": ["MIT"]},
                    ]
                }
            )
        )
        deps, _ = parse_composer_lockfile(
            tmp_path / "composer.lock",
            direct_names={"vendor/x"},
            include_dev=False,
        )
        assert len(deps) == 1
