"""Tests for PHP / Composer ``composer.json`` discovery."""

from __future__ import annotations

import json
from pathlib import Path

from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import collect_read_diagnostics
from licenseal.discovery.php.composer_json import (
    _license_field_to_raw,
    detect_project_license_composer_json,
    discover_composer_dependencies,
)
from licenseal.models import DependencyGroup, Ecosystem

_FIXTURES = Path(__file__).parent / "fixtures" / "composer"


class TestPlatformPackages:
    """Platform pseudo-packages never contain a ``/``. A vendor that merely
    starts with a platform prefix is an ordinary, installable package."""

    def test_platform_names_are_not_dependencies(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps(
                {
                    "require": {
                        "php": "^8.1",
                        "PHP": "^8.1",
                        "php-64bit": "*",
                        "php-ipv6": "*",
                        "ext-mbstring": "*",
                        "ext-json": "*",
                        "lib-openssl": "*",
                        "hhvm": "*",
                        "composer-plugin-api": "^2.0",
                        "composer-runtime-api": "^2.0",
                        "real-vendor/real-lib": "^1.0",
                    }
                }
            )
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert [d.name for d in deps] == ["real-vendor/real-lib"]

    def test_vendor_starting_with_a_platform_prefix_is_a_dependency(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps(
                {
                    "require": {
                        "php": "^8.1",
                        "php-vendor/client": "^1.0",
                        "ext-vendor/bridge": "^2.0",
                        "lib-vendor/toolkit": "^3.0",
                        "PHP-Vendor/Mixed-Case": "^4.0",
                    },
                    "require-dev": {"php-vendor/dev-tool": "^5.0"},
                }
            )
        )
        deps, _ = discover_all_dependencies(tmp_path)
        assert {d.name: (d.version_constraint, d.group) for d in deps} == {
            "php-vendor/client": ("^1.0", DependencyGroup.PROD),
            "ext-vendor/bridge": ("^2.0", DependencyGroup.PROD),
            "lib-vendor/toolkit": ("^3.0", DependencyGroup.PROD),
            "PHP-Vendor/Mixed-Case": ("^4.0", DependencyGroup.PROD),
            "php-vendor/dev-tool": ("^5.0", DependencyGroup.DEV),
        }


class TestLicenseFieldToRaw:
    def test_bare_string(self):
        assert _license_field_to_raw("MIT") == "MIT"

    def test_single_entry_array(self):
        assert _license_field_to_raw(["MIT"]) == "MIT"

    def test_multi_entry_array_is_disjunctive(self):
        # Composer schema: array semantics = "consumer picks one" = OR.
        assert _license_field_to_raw(["MIT", "Apache-2.0"]) == "MIT OR Apache-2.0"

    def test_empty_array(self):
        assert _license_field_to_raw([]) == ""

    def test_empty_string(self):
        assert _license_field_to_raw("") == ""

    def test_non_string_entries_dropped(self):
        assert _license_field_to_raw(["MIT", None, 42, ""]) == "MIT"

    def test_unsupported_type_returns_empty(self):
        assert _license_field_to_raw({"name": "MIT"}) == ""
        assert _license_field_to_raw(None) == ""


class TestDiscoverComposerDependencies:
    def test_simple_fixture_emits_require_and_dev(self):
        deps, filtered = discover_composer_dependencies(_FIXTURES / "simple")
        assert filtered == 0

        prod_names = {d.name for d in deps if d.group == DependencyGroup.PROD}
        dev_names = {d.name for d in deps if d.group == DependencyGroup.DEV}

        assert "vendor-a/lib-one" in prod_names
        assert "vendor-b/lib-two" in prod_names
        assert "vendor-c/proprietary-lib" in prod_names
        assert "vendor-d/dev-tool" in dev_names

    def test_platform_packages_filtered(self):
        deps, _ = discover_composer_dependencies(_FIXTURES / "simple")
        names = {d.name for d in deps}
        assert "php" not in names
        assert "ext-mbstring" not in names

    def test_ecosystem_and_source_stamped(self):
        deps, _ = discover_composer_dependencies(_FIXTURES / "simple")
        for dep in deps:
            assert dep.ecosystem == Ecosystem.PHP
            assert dep.source == "composer.json"

    def test_version_constraints_preserved(self):
        deps, _ = discover_composer_dependencies(_FIXTURES / "simple")
        by_name = {d.name: d.version_constraint for d in deps}
        assert by_name["vendor-a/lib-one"] == "^1.2"
        assert by_name["vendor-b/lib-two"] == "^2.0"

    def test_monorepo_finds_nested_manifests(self):
        deps, _ = discover_composer_dependencies(_FIXTURES / "monorepo")
        # Root composer.json declares vendor-a/lib-one; nested apps/api
        # composer.json declares vendor-b/lib-two + vendor-d/dev-tool.
        names = {d.name for d in deps}
        assert "vendor-a/lib-one" in names
        assert "vendor-b/lib-two" in names
        assert "vendor-d/dev-tool" in names
        sources = {d.source for d in deps}
        # Nested manifest's source path uses forward-slash POSIX form.
        assert "composer.json" in sources
        assert any("apps/api/composer.json" in s for s in sources)

    def test_packages_without_vendor_slash_skipped(self, tmp_path):
        # Non-vendor/package names aren't real Composer packages — skip them.
        # (Composer would reject the manifest; tolerate gracefully here.)
        (tmp_path / "composer.json").write_text(
            json.dumps({"require": {"badname-no-slash": "^1.0"}})
        )
        deps, _ = discover_composer_dependencies(tmp_path)
        assert deps == []

    def test_malformed_json_skipped(self, tmp_path):
        (tmp_path / "composer.json").write_text("{this is not json")
        deps, filtered = discover_composer_dependencies(tmp_path)
        assert deps == []
        assert filtered == 0

    def test_missing_require_blocks_yields_no_deps(self, tmp_path):
        (tmp_path / "composer.json").write_text(json.dumps({"name": "x/y"}))
        deps, _ = discover_composer_dependencies(tmp_path)
        assert deps == []

    def test_non_dict_root_skipped(self, tmp_path):
        (tmp_path / "composer.json").write_text(json.dumps(["not", "a dict"]))
        deps, _ = discover_composer_dependencies(tmp_path)
        assert deps == []

    def test_non_string_require_value_is_unconstrained_and_a_gap(self, tmp_path):
        # The package is still declared, so it stays in the scan; only the
        # constraint is unreadable, and that is on record.
        manifest = tmp_path / "composer.json"
        manifest.write_text(json.dumps({"require": {"vendor/pkg": 42}}))
        with collect_read_diagnostics() as diags:
            deps, _ = discover_composer_dependencies(tmp_path)
        assert [(d.name, d.version_constraint) for d in deps] == [("vendor/pkg", "")]
        assert [(d.path, d.reason, d.is_gap) for d in diags] == [
            (manifest, 'an entry of "require" has an unexpected type; ignored', True)
        ]


class TestDetectProjectLicenseComposerJson:
    def test_simple_fixture(self):
        assert detect_project_license_composer_json(_FIXTURES / "simple") == "MIT"

    def test_array_license_joined_with_or(self):
        assert (
            detect_project_license_composer_json(_FIXTURES / "manifest_only") == "MIT OR Apache-2.0"
        )

    def test_missing_license_returns_empty(self, tmp_path):
        (tmp_path / "composer.json").write_text(json.dumps({"require": {}}))
        assert detect_project_license_composer_json(tmp_path) == ""

    def test_malformed_json_returns_empty(self, tmp_path):
        (tmp_path / "composer.json").write_text("not json")
        assert detect_project_license_composer_json(tmp_path) == ""

    def test_non_dict_root_returns_empty(self, tmp_path):
        (tmp_path / "composer.json").write_text(json.dumps([1, 2, 3]))
        assert detect_project_license_composer_json(tmp_path) == ""

    def test_no_composer_json_returns_empty(self, tmp_path):
        assert detect_project_license_composer_json(tmp_path) == ""
