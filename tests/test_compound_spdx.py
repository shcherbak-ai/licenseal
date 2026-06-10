"""Tests for compound SPDX expression handling and PEP 639 support."""

from __future__ import annotations

import httpx
import respx

from licenseal.analysis.risk import classify_risk
from licenseal.analysis.spdx import normalize_license
from licenseal.models import Dependency, Ecosystem, RiskLevel
from licenseal.resolvers.pypi import _is_junk_license, resolve_python_license


class TestCompoundSpdxRisk:
    def test_or_takes_least_restrictive(self):
        assert classify_risk("Apache-2.0 OR BSD-2-Clause") == RiskLevel.PERMISSIVE

    def test_or_with_copyleft_and_permissive(self):
        # User can choose MIT, so the effective risk is permissive
        assert classify_risk("GPL-3.0-only OR MIT") == RiskLevel.PERMISSIVE

    def test_and_takes_most_restrictive(self):
        assert classify_risk("MIT AND GPL-3.0-only") == RiskLevel.STRONG_COPYLEFT

    def test_and_all_permissive(self):
        expr = "BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0"
        assert classify_risk(expr) == RiskLevel.PERMISSIVE

    def test_or_all_unknown(self):
        assert classify_risk("CustomA OR CustomB") == RiskLevel.UNKNOWN

    def test_and_all_unknown(self):
        assert classify_risk("CustomA AND CustomB") == RiskLevel.UNKNOWN

    def test_or_with_one_unknown(self):
        # MIT is known permissive, custom is unknown — take best known
        assert classify_risk("MIT OR CustomLicense") == RiskLevel.PERMISSIVE

    def test_and_with_one_unknown_routes_to_review(self):
        # AND binds every arm simultaneously, so an unresolvable arm cannot be
        # dropped — the permissive arm alone does not vouch for the whole
        # expression. A `permissive AND <unknown>` dep must route to manual
        # review, not clear as permissive (which would silently drop a possibly
        # restrictive arm — e.g. `Apache-2.0 AND LicenseRef-Vendor-Proprietary`).
        assert classify_risk("MIT AND CustomLicense") == RiskLevel.UNKNOWN

    def test_and_with_unknown_keeps_definite_copyleft_incompatibility(self):
        # An unknown arm must NOT mask a copyleft arm that already pins a
        # definite incompatibility — that is the more actionable signal (an
        # UNKNOWN verdict can pass under --no-strict; a copyleft violation
        # never does). So at the (context-free) risk layer the known copyleft
        # arm wins, which is what lets a *permissive* project report the
        # GPL/AGPL arm as INCOMPATIBLE. The complementary case — a project that
        # is itself compatible with that copyleft arm — is handled at the
        # verdict layer (compatibility.check_compatibility, where the project
        # license is known) so the unresolved arm isn't silently dropped; see
        # tests/test_compatibility.py::TestAndExpressionWithUnresolvedArm.
        assert classify_risk("GPL-3.0-only AND CustomLicense") == RiskLevel.STRONG_COPYLEFT
        assert classify_risk("AGPL-3.0-only AND CustomLicense") == RiskLevel.NETWORK_COPYLEFT
        # Weak copyleft does not pin a project-independent incompatibility, so a
        # weak arm + unknown arm still routes to review (the unknown could be
        # worse than weak).
        assert classify_risk("LGPL-3.0-only AND CustomLicense") == RiskLevel.UNKNOWN

    def test_or_with_proprietary_arm_does_not_clear_copyleft(self):
        # A `copyleft OR commercial` dual license (e.g. Artifex/PyMuPDF's
        # "AGPL OR commercial") must NOT read as permissive: there's no free
        # permissive arm to choose. Proprietary's UNKNOWN risk drops out of
        # the OR aggregation, leaving the copyleft arm as the effective risk.
        assert classify_risk("AGPL-3.0-only OR Proprietary") == RiskLevel.NETWORK_COPYLEFT
        assert classify_risk("GPL-3.0-only OR Proprietary") == RiskLevel.STRONG_COPYLEFT

    def test_or_with_proprietary_arm_keeps_permissive_escape(self):
        # But a genuine `permissive OR commercial` dual license stays
        # permissive — the consumer can elect the permissive arm.
        assert classify_risk("MIT OR Proprietary") == RiskLevel.PERMISSIVE

    def test_direct_lookup_still_works(self):
        assert classify_risk("MIT") == RiskLevel.PERMISSIVE
        assert classify_risk("GPL-3.0-only") == RiskLevel.STRONG_COPYLEFT

    def test_mit_cmu(self):
        assert classify_risk("MIT-CMU") == RiskLevel.PERMISSIVE

    def test_with_exception_classifies_on_base_permissive(self):
        # Real example: Apache-2.0 WITH LLVM-exception (used by wasi, wit-bindgen)
        # The exception adds patent-grant clarifications; base stays permissive.
        assert classify_risk("Apache-2.0 WITH LLVM-exception") == RiskLevel.PERMISSIVE

    def test_with_classpath_exception_relaxes_to_weak(self):
        # The Classpath exception permits linking independent modules
        # "regardless of the license terms of these independent modules" —
        # LGPL-style linking permission, so a strong-copyleft GPL base
        # relaxes to weak copyleft (matching the deprecated
        # GPL-2.0-with-classpath-exception compound ID).
        assert classify_risk("GPL-3.0-only WITH Classpath-exception-2.0") == RiskLevel.WEAK_COPYLEFT
        assert classify_risk("GPL-2.0-only WITH Classpath-exception-2.0") == RiskLevel.WEAK_COPYLEFT

    def test_with_unknown_exception_keeps_base_copyleft(self):
        # Exceptions other than Classpath keep the base classification —
        # ignoring an exception can only add scrutiny, never remove it.
        assert classify_risk("GPL-3.0-only WITH Bison-exception-2.2") == RiskLevel.STRONG_COPYLEFT

    def test_with_classpath_exception_keeps_network_copyleft(self):
        # The relaxation is deliberately scoped to STRONG bases: an AGPL base
        # keeps its network-copyleft classification.
        expr = "AGPL-3.0-only WITH Classpath-exception-2.0"
        assert classify_risk(expr) == RiskLevel.NETWORK_COPYLEFT

    def test_with_exception_inside_or_keeps_or_semantics(self):
        # OR still aggregates least-restrictive across both branches; the WITH-
        # bearing branch is classified on its base.
        expr = "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"
        assert classify_risk(expr) == RiskLevel.PERMISSIVE

    def test_with_exception_inside_and_keeps_and_semantics(self):
        # AND still aggregates most-restrictive; the Classpath-relaxed
        # GPL leaf contributes weak copyleft, which outranks MIT.
        expr = "GPL-3.0-only WITH Classpath-exception-2.0 AND MIT"
        assert classify_risk(expr) == RiskLevel.WEAK_COPYLEFT

    def test_or_later_plus_suffix_weak_copyleft(self):
        # SPDX `+` suffix means "this version or later". MPL has no `-or-later`
        # SPDX ID, and several Rust crates (bitmaps, imbl, imbl-sized-chunks)
        # publish as `MPL-2.0+`. Must classify the same as `MPL-2.0`.
        assert classify_risk("MPL-2.0+") == RiskLevel.WEAK_COPYLEFT

    def test_or_later_plus_suffix_permissive(self):
        # Same `+` handling applied to a permissive base.
        assert classify_risk("Apache-2.0+") == RiskLevel.PERMISSIVE

    def test_or_later_plus_suffix_inside_or(self):
        # OR aggregation must see through the `+` on the copyleft side.
        assert classify_risk("MPL-2.0+ OR Apache-2.0") == RiskLevel.PERMISSIVE

    def test_or_later_plus_suffix_inside_and(self):
        # AND aggregation must see through the `+` on the copyleft side.
        assert classify_risk("MPL-2.0+ AND BSD-3-Clause") == RiskLevel.WEAK_COPYLEFT

    def test_plus_suffix_unknown_base_stays_unknown(self):
        # `+` is not a "make it known" trick.
        assert classify_risk("CustomCopyleft+") == RiskLevel.UNKNOWN

    def test_gpl_plus_still_normalizes_to_or_later(self):
        # GPL/LGPL/AGPL `+` forms go through normalize_license to their explicit
        # `-or-later` SPDX IDs; this regression-guards that the new branch in
        # classify_risk doesn't conflict with that upstream path.
        assert normalize_license("GPL-2.0+") == "GPL-2.0-or-later"
        assert classify_risk("GPL-2.0-or-later") == RiskLevel.STRONG_COPYLEFT


class TestSpdxNormalizerCompound:
    def test_compound_or_passes_through(self):
        assert normalize_license("Apache-2.0 OR BSD-3-Clause") == "Apache-2.0 OR BSD-3-Clause"

    def test_compound_and_passes_through(self):
        # Operand canonicalization sorts AND children alphabetically.
        result = normalize_license("BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0")
        assert result == "0BSD AND BSD-3-Clause AND CC0-1.0 AND MIT AND Zlib"

    def test_mit_cmu_normalizes(self):
        assert normalize_license("MIT-CMU") == "MIT-CMU"

    def test_long_compound_expression(self):
        # Should not be rejected for length; operand-sorted result.
        expr = "MIT AND BSD-3-Clause AND Apache-2.0 AND ISC AND 0BSD AND CC0-1.0 AND Zlib"
        expected = "0BSD AND Apache-2.0 AND BSD-3-Clause AND CC0-1.0 AND ISC AND MIT AND Zlib"
        assert normalize_license(expr) == expected

    def test_dual_license_is_unknown(self):
        assert normalize_license("Dual License") == "UNKNOWN"

    def test_looks_like_spdx_with_digits(self):
        # 0BSD starts with digit, should still be recognized
        assert normalize_license("0BSD") == "0BSD"

    def test_all_lowercase_still_unknown(self):
        assert normalize_license("some random words here") == "UNKNOWN"


class TestJunkLicenseDetection:
    def test_copyright_notice(self):
        assert _is_junk_license("Copyright (c) 2001 Enthought") is True

    def test_multiline_text(self):
        assert _is_junk_license("MIT License\nSome text") is True

    def test_all_rights_reserved(self):
        assert _is_junk_license("All Rights Reserved") is True

    def test_permission_text(self):
        assert _is_junk_license("Permission is hereby granted, free of charge") is True

    def test_normal_license_not_junk(self):
        assert _is_junk_license("MIT") is False
        assert _is_junk_license("Apache-2.0") is False
        assert _is_junk_license("GPL-3.0-only") is False


class TestPEP639Resolution:
    @respx.mock
    def test_license_expression_preferred(self):
        """PEP 639 license_expression should be preferred over legacy license field."""
        respx.get("https://pypi.org/pypi/urllib3/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": None,
                        "license_expression": "MIT",
                        "version": "2.0.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = Dependency(name="urllib3", version_constraint="", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "MIT"

    @respx.mock
    def test_license_expression_compound(self):
        """Compound license_expression should be normalized correctly."""
        respx.get("https://pypi.org/pypi/cryptography/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": None,
                        "license_expression": "Apache-2.0 OR BSD-3-Clause",
                        "version": "42.0.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = Dependency(name="cryptography", version_constraint="", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "Apache-2.0 OR BSD-3-Clause"

    @respx.mock
    def test_junk_license_falls_through_to_classifier(self):
        """Copyright text in license field should fall through to classifiers."""
        respx.get("https://pypi.org/pypi/scipy/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "Copyright (c) 2001 Enthought\nAll rights reserved",
                        "license_expression": None,
                        "version": "1.12.0",
                        "classifiers": [
                            "License :: OSI Approved :: BSD License",
                        ],
                    }
                },
            )
        )
        dep = Dependency(name="scipy", version_constraint="", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "BSD-3-Clause"

    @respx.mock
    def test_fallback_to_legacy_license(self):
        """When no license_expression, fall back to legacy license field."""
        respx.get("https://pypi.org/pypi/oldpkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "MIT License",
                        "version": "1.0.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = Dependency(name="oldpkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "MIT"

    @respx.mock
    def test_no_license_expression_no_legacy(self):
        """When both license_expression and license are None, try classifiers."""
        respx.get("https://pypi.org/pypi/pkg/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": None,
                        "license_expression": None,
                        "version": "1.0.0",
                        "classifiers": [
                            "License :: OSI Approved :: MIT License",
                        ],
                    }
                },
            )
        )
        dep = Dependency(name="pkg", version_constraint="", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "MIT"

    @respx.mock
    def test_pinned_falls_back_to_project_level(self):
        """When per-version metadata is sparse, fall back to project-level info."""
        respx.get("https://pypi.org/pypi/attrs/24.3.0/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "",
                        "license_expression": None,
                        "version": "24.3.0",
                        "classifiers": [],
                    }
                },
            )
        )
        respx.get("https://pypi.org/pypi/attrs/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {
                        "license": "",
                        "license_expression": "MIT",
                        "version": "25.0.0",
                        "classifiers": [],
                    }
                },
            )
        )
        dep = Dependency(name="attrs", version_constraint="==24.3.0", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            li = resolve_python_license(dep, client)
        assert li.license_id == "MIT"


class TestSlashFormNormalization:
    def test_cargo_slash_form_or(self):
        assert normalize_license("MIT/Apache-2.0") == "Apache-2.0 OR MIT"

    def test_cargo_slash_form_with_spaces(self):
        assert normalize_license("MIT / Apache-2.0") == "Apache-2.0 OR MIT"

    def test_slash_form_classifies_correctly(self):
        # The whole point: slash-form should be recognized as permissive
        assert classify_risk(normalize_license("MIT/Apache-2.0")) == RiskLevel.PERMISSIVE

    def test_slash_not_touched_when_or_already_present(self):
        # Don't double-translate something already SPDX-shaped; operand
        # canonicalization still sorts the OR children alphabetically.
        assert normalize_license("MIT OR Apache-2.0") == "Apache-2.0 OR MIT"


class TestUnicodeLicenses:
    def test_unicode_3_0_is_permissive(self):
        assert classify_risk("Unicode-3.0") == RiskLevel.PERMISSIVE

    def test_unicode_dfs_2016_is_permissive(self):
        assert classify_risk("Unicode-DFS-2016") == RiskLevel.PERMISSIVE


class TestAdditionalPermissiveLicenses:
    """SPDX IDs surfaced by real-world scans."""

    def test_blueoak_1_0_0_is_permissive(self):
        # BlueOak Model License — modern permissive license used by many
        # nodejs packages (npm's preferred SPDX for permissive-with-attribution)
        assert classify_risk("BlueOak-1.0.0") == RiskLevel.PERMISSIVE

    def test_python_2_0_is_permissive(self):
        # Canonical SPDX for the Python Software Foundation License.
        # Our normalization map already produces PSF-2.0; some registry
        # responses report Python-2.0 directly.
        assert classify_risk("Python-2.0") == RiskLevel.PERMISSIVE

    def test_cc_by_4_0_is_permissive(self):
        # Creative Commons Attribution: requires attribution but otherwise
        # places no restrictions on use. Treated as permissive for code
        # compatibility purposes (review obligations separately).
        assert classify_risk("CC-BY-4.0") == RiskLevel.PERMISSIVE

    def test_npm_unlicensed_normalizes_to_proprietary(self):
        # npm's `UNLICENSED` marker means "private package, do not
        # redistribute" — semantically Proprietary, not unknown.
        assert normalize_license("UNLICENSED") == "Proprietary"
        # Proprietary's risk is UNKNOWN (custom terms can't be auto-classified);
        # the dep-side compat short-circuit routes a bare Proprietary to manual
        # review, and the project-side permissive treatment lives in
        # compatibility._project_compat_risk — not the risk lattice.
        assert classify_risk(normalize_license("UNLICENSED")) == RiskLevel.UNKNOWN

    def test_real_world_apache_variants_normalize(self):
        # Variants seen in PyPI data published by older packages.
        assert normalize_license("Apache License v2.0") == "Apache-2.0"
        assert normalize_license("Apache License v2") == "Apache-2.0"
        assert normalize_license("ApacheV2") == "Apache-2.0"
        assert normalize_license("Apache 2.0 Software License") == "Apache-2.0"
        assert normalize_license("Apache Software License, Version 2.0") == "Apache-2.0"

    def test_real_world_bsd_variants_normalize(self):
        # Space/dash mix; lowercased lookup needs to find each form.
        assert normalize_license("BSD 3-Clause License") == "BSD-3-Clause"
        assert normalize_license("3-clause BSD") == "BSD-3-Clause"
        assert normalize_license("3 clause BSD") == "BSD-3-Clause"

    def test_real_world_expat_variants_normalize(self):
        assert normalize_license("Expat License") == "MIT"
        assert normalize_license("the Expat License") == "MIT"

    def test_psf_version_variants_normalize(self):
        # Some PSF deps publish the long-form name with a trailing
        # "Version 2" — must collapse to PSF-2.0.
        assert normalize_license("Python Software Foundation License Version 2") == "PSF-2.0"
        assert normalize_license("Python Software Foundation License, Version 2") == "PSF-2.0"
        assert normalize_license("PSF 2.0") == "PSF-2.0"

    def test_zpl_variants_normalize_and_classify_permissive(self):
        # Zope Public License: OSI-approved permissive, used by many Plone
        # ecosystem packages. Was previously normalize-passthrough → UNKNOWN
        # because no entry existed in the risk map. Space-separated form
        # (`"ZPL 2.1"`) shows up in PyPI metadata alongside the SPDX dash form.
        assert normalize_license("ZPL-2.1") == "ZPL-2.1"
        assert normalize_license("ZPL-2.0") == "ZPL-2.0"
        assert normalize_license("ZPL 2.1") == "ZPL-2.1"
        assert normalize_license("ZPL 2.0") == "ZPL-2.0"
        assert normalize_license("Zope Public License") == "ZPL-2.1"
        assert classify_risk("ZPL-2.1") == RiskLevel.PERMISSIVE
        assert classify_risk("ZPL-2.0") == RiskLevel.PERMISSIVE
        assert classify_risk("ZPL-1.1") == RiskLevel.PERMISSIVE

    def test_apache_asl_abbreviation_normalizes(self):
        # "ASL 2.0" is a common abbreviation for "Apache Software License 2.0"
        # used by Red Hat / Fedora and surfaced by some PyPI packages.
        assert normalize_license("ASL 2.0") == "Apache-2.0"
        assert normalize_license("ASL-2.0") == "Apache-2.0"
        assert normalize_license("asl 2.0") == "Apache-2.0"

    def test_more_real_world_variants_normalize(self):
        # Further variants surfaced by large-tree scans.
        assert normalize_license("Apache-2") == "Apache-2.0"
        assert normalize_license("BSD 2-Clause License") == "BSD-2-Clause"
        assert normalize_license("BSD (3-clause)") == "BSD-3-Clause"
        assert normalize_license("BSD (2-clause)") == "BSD-2-Clause"
        assert normalize_license("LGPL v3") == "LGPL-3.0-only"
        assert normalize_license("LGPL v3+") == "LGPL-3.0-or-later"
        assert normalize_license("GNU LGPL v3+") == "LGPL-3.0-or-later"

    def test_bare_license_filename_normalizes_to_proprietary(self):
        # Some publishers put a filename ("LICENSE.txt") in the license field;
        # opaque to a metadata-only scanner → Proprietary → manual review.
        assert normalize_license("LICENSE.txt") == "Proprietary"
        assert normalize_license("LICENSE.md") == "Proprietary"
        assert normalize_license("LICENCE.txt") == "Proprietary"

    def test_intel_and_nvidia_software_license_markers_normalize(self):
        # Regex-driven proprietary detection covers these without per-vendor
        # alias entries:
        #   - `\bsoftware\s+license\b` (Intel Simplified Software License)
        #   - `^LicenseRef-` minus the Public-Domain sentinel
        #   - `\bproprietary\b`
        assert normalize_license("Intel Simplified Software License") == "Proprietary"
        assert normalize_license("LicenseRef-NVIDIA-SOFTWARE-LICENSE") == "Proprietary"
        assert normalize_license("LicenseRef-Proprietary") == "Proprietary"

    def test_non_standard_and_custom_markers_normalize_to_proprietary(self):
        # Crates.io publishers occasionally use "non-standard" or "custom"
        # when their license isn't a clean SPDX expression but they don't
        # want to use the LicenseRef-* convention.
        assert normalize_license("non-standard") == "Proprietary"
        assert normalize_license("custom") == "Proprietary"

    def test_hpnd_is_permissive(self):
        # HPND (Historical Permission Notice and Disclaimer) is OSI-approved
        # permissive; used by Pillow and other long-lived deps.
        assert normalize_license("HPND") == "HPND"
        assert classify_risk("HPND") == RiskLevel.PERMISSIVE

    def test_fourth_wave_real_world_variants_normalize(self):
        # Variants surfaced by a deeper-coverage scan after URL caching made
        # previously-unnormalized prose visible. Apache/BSD/GPL/LGPL/MPL/ISC/PSF
        # bare and abbreviated forms.
        assert normalize_license("Apache2.0") == "Apache-2.0"
        assert normalize_license("Apache 2 License") == "Apache-2.0"
        assert normalize_license("ASL") == "Apache-2.0"
        assert normalize_license("ASL 2") == "Apache-2.0"
        assert normalize_license("ASLv2") == "Apache-2.0"
        assert normalize_license("AL2") == "Apache-2.0"

        assert normalize_license("Simplified BSD License") == "BSD-2-Clause"
        assert normalize_license("Revised BSD License") == "BSD-3-Clause"
        assert normalize_license("The BSD License") == "BSD-3-Clause"
        assert normalize_license("BSD License (3-Clause)") == "BSD-3-Clause"
        assert normalize_license("newBSD") == "BSD-3-Clause"

        # GPL bare forms — conservative default to current (3.0-only).
        assert normalize_license("GNU GPL") == "GPL-3.0-only"
        assert normalize_license("GNU General Public License") == "GPL-3.0-only"
        assert normalize_license("GNU General Public License Version 3") == "GPL-3.0-only"
        assert normalize_license("GNU General Public License v3.0") == "GPL-3.0-only"
        assert normalize_license("GPL V3.0") == "GPL-3.0-only"
        assert normalize_license("GPL2") == "GPL-2.0-only"
        assert normalize_license("GPL3") == "GPL-3.0-only"
        # GPL or-later variants.
        assert normalize_license("GPL-2+") == "GPL-2.0-or-later"
        assert normalize_license("GPL-3+") == "GPL-3.0-or-later"
        assert normalize_license("GPL-3.0+") == "GPL-3.0-or-later"
        assert normalize_license("GNU GPLv3+") == "GPL-3.0-or-later"

        # LGPL bare and or-later forms.
        assert normalize_license("LGPL 2.1") == "LGPL-2.1-only"
        assert normalize_license("LGPL v2.1") == "LGPL-2.1-only"
        assert normalize_license("LGPL-2.1+") == "LGPL-2.1-or-later"
        assert normalize_license("LGPLv2+") == "LGPL-2.0-or-later"
        assert normalize_license("LGPLv2.1+") == "LGPL-2.1-or-later"
        assert normalize_license("LGPL-3.0-or-newer") == "LGPL-3.0-or-later"

        # Mozilla — bare and v2.0 forms.
        assert normalize_license("Mozilla Public License") == "MPL-2.0"
        assert normalize_license("Mozilla Public License v2.0") == "MPL-2.0"

        # ISC abbreviation.
        assert normalize_license("ISCL") == "ISC"

        # PSF abbreviation.
        assert normalize_license("PSF2") == "PSF-2.0"

    def test_vendor_eulas_and_filename_strings_route_to_proprietary(self):
        # Regex-driven proprietary detection: vendor commercial license
        # strings (caught by `\bproprietary\b` / `\blicense agreement\b`),
        # `See <file>` pointers, and bare `LICENSE.<ext>` filenames all
        # route to Proprietary without needing per-publisher alias entries.
        assert normalize_license("Databricks Proprietary License") == "Proprietary"
        assert normalize_license("SAP DEVELOPER LICENSE AGREEMENT") == "Proprietary"
        assert normalize_license("See COPYING") == "Proprietary"
        assert normalize_license("LICENSE.BSD3") == "Proprietary"
        assert normalize_license("LICENSE.rst") == "Proprietary"

    def test_third_wave_real_world_variants_normalize(self):
        # Variants surfaced by a large ML-stack scan.
        assert normalize_license("Apache2") == "Apache-2.0"
        assert normalize_license("Apache License (2.0)") == "Apache-2.0"
        assert normalize_license("Apache Software License (Apache 2.0)") == "Apache-2.0"
        assert normalize_license("BSD3") == "BSD-3-Clause"
        assert normalize_license("Modified BSD License") == "BSD-3-Clause"
        assert normalize_license("FreeBSD") == "BSD-2-Clause"
        assert normalize_license("BSD2") == "BSD-2-Clause"
        assert normalize_license("GNU Lesser General Public License v3") == "LGPL-3.0-only"
        assert normalize_license("GNU LGPL") == "LGPL-3.0-only"
        assert normalize_license("MPLv2.0") == "MPL-2.0"
        assert normalize_license("MPL v2") == "MPL-2.0"
        assert normalize_license("Artistic License") == "Artistic-2.0"

    def test_ncsa_normalizes_and_is_permissive(self):
        assert normalize_license("NCSA") == "NCSA"
        assert normalize_license("University of Illinois/NCSA Open Source License") == "NCSA"
        # And via the trove classifier path.
        classifier = "License :: OSI Approved :: University of Illinois/NCSA Open Source License"
        assert normalize_license(classifier) == "NCSA"
        assert classify_risk("NCSA") == RiskLevel.PERMISSIVE

    def test_gust_font_license_normalizes_to_lppl(self):
        # GUST Font License = LPPL-1.3c plus font-specific addenda. Treat as
        # LPPL-1.3c for risk purposes (both OSI permissive).
        assert normalize_license("GUST Font License (GFL)") == "LPPL-1.3c"
        assert normalize_license("GUST Font License") == "LPPL-1.3c"
        assert classify_risk("LPPL-1.3c") == RiskLevel.PERMISSIVE
        assert classify_risk("LPPL-1.2") == RiskLevel.PERMISSIVE

    def test_source_available_licenses_preserve_spdx_id(self):
        # Elastic-2.0 and BUSL-1.1 are valid SPDX IDs (source-available but
        # not OSI-permissive). Normalization preserves the canonical SPDX
        # form — including translating English / abbreviated variants —
        # and `risk.py` classifies them as UNKNOWN, which routes them
        # through the compatibility matrix to manual review. We don't
        # collapse them to Proprietary so the report keeps the specific
        # license identity visible to the maintainer.
        assert normalize_license("Elastic-2.0") == "Elastic-2.0"
        assert normalize_license("Elastic License 2.0") == "Elastic-2.0"
        assert normalize_license("ELv2") == "Elastic-2.0"
        assert normalize_license("BUSL-1.1") == "BUSL-1.1"
        assert normalize_license("Business Source License 1.1") == "BUSL-1.1"

    def test_commercial_eulas_route_to_proprietary(self):
        # Bilateral commercial license agreements always require human review.
        assert (
            normalize_license("Intel End User License Agreement for Developer Tools")
            == "Proprietary"
        )
        assert normalize_license("Teradata License Agreement") == "Proprietary"
        assert (
            normalize_license("LICENSE AGREEMENT FOR NVIDIA SOFTWARE DEVELOPMENT KITS")
            == "Proprietary"
        )
        assert normalize_license("Google Cloud Platform Terms of Service") == "Proprietary"

    def test_dash_or_separator_treated_as_compound(self):
        # `MIT -or- Apache License 2.0` — informal OR separator seen in PyPI
        # publisher prose. Same conservative split as comma-as-OR. Operand
        # canonicalization sorts the OR children alphabetically.
        result = normalize_license("MIT -or- Apache License 2.0")
        assert result == "Apache-2.0 OR MIT"
        assert classify_risk(result) == RiskLevel.PERMISSIVE

    def test_dash_or_skipped_when_any_part_unrecognized(self):
        # If one part doesn't normalize cleanly, leave the string alone.
        # The right-hand part must not look like SPDX (no uppercase, digit,
        # or hyphen) so it normalizes to UNKNOWN and the OR-compound stays
        # unbuilt — the input is then returned unchanged and classifies as
        # UNKNOWN.
        result = normalize_license("MIT -or- some bare prose")
        # The OR-compound wasn't built (right side is UNKNOWN); the original
        # string falls through to _looks_like_spdx → returns as-is → UNKNOWN
        # at the risk layer.
        assert classify_risk(result) == RiskLevel.UNKNOWN

    def test_comma_separated_dual_license_treated_as_or(self):
        # PyPI convention surfaced by pycryptodome (`"BSD, Public Domain"`)
        # and several other packages. Comma is informal "OR" when both
        # parts are recognizable licenses.
        result = normalize_license("BSD, Public Domain")
        assert result == "BSD-3-Clause OR LicenseRef-Public-Domain"
        # OR-lower across two permissive branches stays permissive.
        assert classify_risk(result) == RiskLevel.PERMISSIVE

        # Two-clean-licenses variant.
        result = normalize_license("MIT, Apache-2.0")
        assert result == "Apache-2.0 OR MIT"
        assert classify_risk(result) == RiskLevel.PERMISSIVE

        # Three-part case to confirm the split is generic.
        result = normalize_license("MIT, Apache-2.0, BSD-3-Clause")
        assert result == "Apache-2.0 OR BSD-3-Clause OR MIT"

    def test_comma_split_skipped_when_any_part_unrecognized(self):
        # Conservative behavior: if even one comma-separated part doesn't
        # normalize cleanly, leave the string alone rather than guess. This
        # protects against splitting names that legitimately contain a comma
        # but aren't a multi-license declaration.
        # `"Apache License, Version 2.0"` is in the alias map so it's caught
        # by the direct lookup before the comma-split branch runs.
        assert normalize_license("Apache License, Version 2.0") == "Apache-2.0"
        # `"MIT, see LICENSE for details"` — second part is meaningless,
        # so the comma-split is suppressed and the whole thing stays as-is
        # (and ultimately classifies as UNKNOWN).
        assert classify_risk(normalize_license("MIT, see LICENSE for details")) == RiskLevel.UNKNOWN

    def test_bzip2_postgresql_openssl_are_permissive(self):
        # SPDX IDs for the bzip2 license (used by `libbz2-rs-sys`),
        # PostgreSQL License (used by `pq-src`), and OpenSSL License are all
        # OSI-approved permissive. Surfaced by Rust scans of packages
        # wrapping C dependencies.
        assert classify_risk("bzip2-1.0.6") == RiskLevel.PERMISSIVE
        assert classify_risk("PostgreSQL") == RiskLevel.PERMISSIVE
        assert classify_risk("OpenSSL") == RiskLevel.PERMISSIVE

    def test_lowercase_spdx_id_with_hyphen_passes_heuristic(self):
        # SPDX-canonical IDs like `zlib-acknowledgement` are all-lowercase
        # with hyphens — no uppercase, no digits. Surfaced by a Rust scan
        # where a crate declared `"zlib-acknowledgement OR MIT"`, which was
        # normalizing to UNKNOWN because `_looks_like_spdx` rejected the
        # left branch and short-circuited the compound classifier.
        assert normalize_license("zlib-acknowledgement") == "zlib-acknowledgement"
        assert classify_risk("zlib-acknowledgement") == RiskLevel.PERMISSIVE

    def test_compound_with_lowercase_spdx_branch_normalizes(self):
        # The whole compound must round-trip through normalize_license, then
        # classify_risk's OR rule picks the lower-risk branch (MIT here).
        # Operand-canonicalization sorts case-insensitively, so MIT comes
        # before zlib-acknowledgement.
        expr = "zlib-acknowledgement OR MIT"
        assert normalize_license(expr) == "MIT OR zlib-acknowledgement"
        assert classify_risk(expr) == RiskLevel.PERMISSIVE

    def test_generic_lgpl_classifier_normalizes_conservatively(self):
        # Some older PyPI packages use the version-less LGPL classifier.
        # Map to LGPL-3.0-only (still weak copyleft, no risk change).
        result = normalize_license(
            "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)"
        )
        assert result == "LGPL-3.0-only"
        assert classify_risk(result) == RiskLevel.WEAK_COPYLEFT

    def test_generic_gpl_classifier_normalizes_conservatively(self):
        # Version-less GPL classifier maps to GPL-3.0-only (most restrictive).
        result = normalize_license("License :: OSI Approved :: GNU General Public License (GPL)")
        assert result == "GPL-3.0-only"
        assert classify_risk(result) == RiskLevel.STRONG_COPYLEFT

    def test_psfl_abbreviation_normalizes(self):
        assert normalize_license("PSFL") == "PSF-2.0"
        assert normalize_license("psfl") == "PSF-2.0"

    def test_see_license_in_file_normalizes_to_proprietary(self):
        # Generic `SEE LICENSE IN <filename>` regex handles any filename and
        # any common spelling variant. Examples seen in real registry data:
        # claude-agent-sdk → README.md; many private packages → LICENSE.txt.
        assert normalize_license("SEE LICENSE IN LICENSE") == "Proprietary"
        assert normalize_license("SEE LICENSE IN LICENSE.md") == "Proprietary"
        assert normalize_license("SEE LICENSE IN LICENSE.txt") == "Proprietary"
        assert normalize_license("SEE LICENSE IN README.md") == "Proprietary"
        assert normalize_license("SEE LICENSE IN NOTICE") == "Proprietary"
        assert normalize_license("SEE LICENSE IN COPYING") == "Proprietary"
        assert normalize_license("see license in license") == "Proprietary"
        assert normalize_license("See Licence In LICENCE") == "Proprietary"  # British, mixed-case

    def test_vendor_proprietary_strings_normalize_to_proprietary(self):
        # PyPI/crates.io sometimes publish free-form vendor proprietary
        # markers; normalize them so they route to "manual review" via the
        # dep-side Proprietary override.
        assert normalize_license("NVIDIA Proprietary Software") == "Proprietary"
        assert normalize_license("LicenseRef-NVIDIA-Proprietary") == "Proprietary"

    def test_apache_2_0_license_variant(self):
        assert normalize_license("Apache 2.0 License") == "Apache-2.0"

    def test_cdla_permissive_is_permissive(self):
        assert classify_risk("CDLA-Permissive-2.0") == RiskLevel.PERMISSIVE


class TestParenthesizedExpressions:
    def test_paren_or_inside_and(self):
        # Real example from unicode-ident crate
        expr = "(MIT OR Apache-2.0) AND Unicode-DFS-2016"
        assert classify_risk(expr) == RiskLevel.PERMISSIVE

    def test_paren_or_with_strong_copyleft_inside_and(self):
        # AND across an OR group: OR resolves to permissive (best of), AND
        # then takes most restrictive of (permissive, strong) → strong
        expr = "(MIT OR GPL-3.0-only) AND GPL-3.0-only"
        assert classify_risk(expr) == RiskLevel.STRONG_COPYLEFT

    def test_paren_groups_on_both_sides_of_and(self):
        # Both branches independently parenthesized: the outer characters are
        # `(` and `)` but they don't form a single matched outer pair (the
        # first `)` is not the final char), so `_strip_outer_parens` returns
        # the expression unchanged and the AND-split unwraps each branch.
        assert classify_risk("(MIT) AND (Apache-2.0)") == RiskLevel.PERMISSIVE

    def test_malformed_unbalanced_parens_classifies_as_unknown(self):
        # Defensive: a string that starts with `(` and ends with `)` but never
        # rebalances (extra `(` mid-expression) must fall through to UNKNOWN
        # rather than asserting or mis-classifying.
        assert classify_risk("(MIT (BSD-3-Clause)") == RiskLevel.UNKNOWN

    def test_redundant_outer_parens(self):
        assert classify_risk("(MIT)") == RiskLevel.PERMISSIVE
        assert classify_risk("((Apache-2.0))") == RiskLevel.PERMISSIVE

    def test_precedence_and_binds_tighter_than_or(self):
        # SPDX 3.0: AND > OR. So `MIT OR GPL-3.0 AND BSD-3` parses as
        # `MIT OR (GPL-3.0 AND BSD-3)`. The OR can pick MIT → permissive.
        assert classify_risk("MIT OR GPL-3.0-only AND BSD-3-Clause") == RiskLevel.PERMISSIVE
