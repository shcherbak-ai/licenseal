"""Tests for licenseal.analysis.risk."""

from __future__ import annotations

import pytest

from licenseal.analysis.risk import classify_risk
from licenseal.models import RiskLevel


class TestClassifyRisk:
    @pytest.mark.parametrize(
        "spdx_id, expected",
        [
            # Permissive
            ("MIT", RiskLevel.PERMISSIVE),
            ("BSD-2-Clause", RiskLevel.PERMISSIVE),
            ("BSD-3-Clause", RiskLevel.PERMISSIVE),
            ("Apache-2.0", RiskLevel.PERMISSIVE),
            ("ISC", RiskLevel.PERMISSIVE),
            ("Unlicense", RiskLevel.PERMISSIVE),
            ("CC0-1.0", RiskLevel.PERMISSIVE),
            ("0BSD", RiskLevel.PERMISSIVE),
            ("PSF-2.0", RiskLevel.PERMISSIVE),
            ("Artistic-2.0", RiskLevel.PERMISSIVE),
            ("Zlib", RiskLevel.PERMISSIVE),
            ("WTFPL", RiskLevel.PERMISSIVE),
            ("BSL-1.0", RiskLevel.PERMISSIVE),
            # Proprietary's risk is genuinely UNKNOWN — custom commercial terms
            # can't be auto-classified. The dep-side compat short-circuit sends
            # a bare Proprietary to manual review; the project-side "may consume
            # permissive deps" convenience lives in _project_compat_risk. Rating
            # it PERMISSIVE here let a Proprietary OR-arm clear copyleft.
            ("Proprietary", RiskLevel.UNKNOWN),
            # Weak copyleft
            ("LGPL-2.1-only", RiskLevel.WEAK_COPYLEFT),
            ("LGPL-2.1-or-later", RiskLevel.WEAK_COPYLEFT),
            ("LGPL-3.0-only", RiskLevel.WEAK_COPYLEFT),
            ("LGPL-3.0-or-later", RiskLevel.WEAK_COPYLEFT),
            ("MPL-2.0", RiskLevel.WEAK_COPYLEFT),
            ("EPL-1.0", RiskLevel.WEAK_COPYLEFT),
            ("EPL-2.0", RiskLevel.WEAK_COPYLEFT),
            # Strong copyleft
            ("GPL-2.0-only", RiskLevel.STRONG_COPYLEFT),
            ("GPL-2.0-or-later", RiskLevel.STRONG_COPYLEFT),
            ("GPL-3.0-only", RiskLevel.STRONG_COPYLEFT),
            ("GPL-3.0-or-later", RiskLevel.STRONG_COPYLEFT),
            # Network copyleft
            ("AGPL-3.0-only", RiskLevel.NETWORK_COPYLEFT),
            ("AGPL-3.0-or-later", RiskLevel.NETWORK_COPYLEFT),
            # Unknown
            ("", RiskLevel.UNKNOWN),
            ("UNKNOWN", RiskLevel.UNKNOWN),
            ("NOASSERTION", RiskLevel.UNKNOWN),
            ("SomeCustomLicense", RiskLevel.UNKNOWN),
        ],
    )
    def test_classify(self, spdx_id: str, expected: RiskLevel):
        assert classify_risk(spdx_id) == expected


class TestPatternBasedClassification:
    """The pattern + override classifier covers SPDX IDs we never enumerated
    in ``_RISK_OVERRIDES`` — driven by name conventions (``^GPL-`` etc.).
    These tests pin the family rules so an SPDX ID we've never seen still
    gets the right risk level by virtue of its name.
    """

    @pytest.mark.parametrize(
        "spdx_id, expected",
        [
            # GPL family — all variants resolve to STRONG_COPYLEFT regardless
            # of version, including ones we never enumerated.
            ("GPL-1.0-only", RiskLevel.STRONG_COPYLEFT),
            ("GPL-1.0-or-later", RiskLevel.STRONG_COPYLEFT),
            # AGPL takes precedence over GPL (pattern order matters).
            ("AGPL-1.0", RiskLevel.NETWORK_COPYLEFT),
            ("AGPL-1.0-only", RiskLevel.NETWORK_COPYLEFT),
            ("AGPL-1.0-or-later", RiskLevel.NETWORK_COPYLEFT),
            # LGPL — full family.
            ("LGPL-2.0", RiskLevel.WEAK_COPYLEFT),
            ("LGPL-3.0", RiskLevel.WEAK_COPYLEFT),
            # MPL — every version.
            ("MPL-1.0", RiskLevel.WEAK_COPYLEFT),
            ("MPL-1.1", RiskLevel.WEAK_COPYLEFT),
            ("MPL-2.0", RiskLevel.WEAK_COPYLEFT),
            # CDDL — Common Development and Distribution License (Oracle).
            ("CDDL-1.0", RiskLevel.WEAK_COPYLEFT),
            ("CDDL-1.1", RiskLevel.WEAK_COPYLEFT),
            # OSL — Open Software License. FSF: strong copyleft, GPL-incompatible.
            ("OSL-1.0", RiskLevel.STRONG_COPYLEFT),
            ("OSL-2.0", RiskLevel.STRONG_COPYLEFT),
            ("OSL-3.0", RiskLevel.STRONG_COPYLEFT),
            # EUPL — European Union Public License. FSF: copyleft "comparable
            # to the GPL's". Has a compatibility appendix but is strong by itself.
            ("EUPL-1.0", RiskLevel.STRONG_COPYLEFT),
            ("EUPL-1.1", RiskLevel.STRONG_COPYLEFT),
            ("EUPL-1.2", RiskLevel.STRONG_COPYLEFT),
            # ODbL — Open Database License. Share-alike on derivative databases
            # *including the source data*; OSM-style strong copyleft.
            ("ODbL-1.0", RiskLevel.STRONG_COPYLEFT),
            # GFDL — GNU Free Documentation License (strong copyleft for docs).
            ("GFDL-1.1-only", RiskLevel.STRONG_COPYLEFT),
            ("GFDL-1.3-or-later", RiskLevel.STRONG_COPYLEFT),
            # Permissive family patterns.
            ("AFL-1.1", RiskLevel.PERMISSIVE),  # Academic Free License
            ("AFL-2.0", RiskLevel.PERMISSIVE),
            ("AFL-3.0", RiskLevel.PERMISSIVE),
            ("Artistic-1.0", RiskLevel.PERMISSIVE),
            ("Artistic-1.0-cl8", RiskLevel.PERMISSIVE),
            ("BSL-1.0", RiskLevel.PERMISSIVE),
            ("BlueOak-1.0.0", RiskLevel.PERMISSIVE),
            ("ECL-1.0", RiskLevel.PERMISSIVE),  # Educational Community License
            ("ECL-2.0", RiskLevel.PERMISSIVE),
            ("HPND-sell-variant", RiskLevel.PERMISSIVE),
            ("LPPL-1.3a", RiskLevel.PERMISSIVE),
            ("OFL-1.0", RiskLevel.PERMISSIVE),  # Open Font License
            ("OFL-1.1", RiskLevel.PERMISSIVE),
            ("OLDAP-2.8", RiskLevel.PERMISSIVE),  # OpenLDAP family
            ("Unicode-3.0", RiskLevel.PERMISSIVE),
            ("X11", RiskLevel.PERMISSIVE),
            ("Zend-2.0", RiskLevel.PERMISSIVE),
            ("ZPL-1.1", RiskLevel.PERMISSIVE),
            # CC family — pattern correctly distinguishes share-alike from
            # plain CC-BY (the regex `^CC-BY-\d` requires a digit immediately
            # after CC-BY, which CC-BY-SA / CC-BY-NC don't satisfy).
            # CC-BY-SA's share-alike applies to derivative works; classified
            # as strong copyleft (one-way compatible with GPL-3.0 per the 2015
            # Creative Commons / FSF ruling).
            ("CC-BY-3.0", RiskLevel.PERMISSIVE),
            ("CC-BY-4.0", RiskLevel.PERMISSIVE),
            ("CC-BY-SA-3.0", RiskLevel.STRONG_COPYLEFT),
            ("CC-BY-SA-4.0", RiskLevel.STRONG_COPYLEFT),
            # CDLA family. CDLA-Sharing has the same share-alike-on-derivatives
            # semantics as CC-BY-SA / ODbL.
            ("CDLA-Permissive-1.0", RiskLevel.PERMISSIVE),
            ("CDLA-Permissive-2.0", RiskLevel.PERMISSIVE),
            ("CDLA-Sharing-1.0", RiskLevel.STRONG_COPYLEFT),
            # Single-name permissive licenses via override.
            ("Beerware", RiskLevel.PERMISSIVE),
            ("FTL", RiskLevel.PERMISSIVE),  # FreeType
            ("ICU", RiskLevel.PERMISSIVE),
            ("Libpng", RiskLevel.PERMISSIVE),
            ("MS-PL", RiskLevel.PERMISSIVE),
            ("NTP", RiskLevel.PERMISSIVE),
            ("PHP-3.01", RiskLevel.PERMISSIVE),
            ("Sendmail", RiskLevel.PERMISSIVE),
            ("Vim", RiskLevel.PERMISSIVE),
            ("W3C", RiskLevel.PERMISSIVE),
            # Weak copyleft via override (no family prefix).
            ("MS-RL", RiskLevel.WEAK_COPYLEFT),
            ("IPL-1.0", RiskLevel.WEAK_COPYLEFT),
            # Strong copyleft via override.
            ("RPL-1.5", RiskLevel.STRONG_COPYLEFT),
            # Sleepycat / Berkeley DB: source disclosure extends to any
            # accompanying software that uses the DB — strong-copyleft effect.
            ("Sleepycat", RiskLevel.STRONG_COPYLEFT),
        ],
    )
    def test_pattern_classifies(self, spdx_id: str, expected: RiskLevel):
        assert classify_risk(spdx_id) == expected


class TestNonOSISourceAvailable:
    """Source-available / commercial-restrictive SPDX IDs route to UNKNOWN
    so the dep-side compatibility logic flags them for human review."""

    @pytest.mark.parametrize(
        "spdx_id",
        [
            "SSPL-1.0",  # MongoDB's Server Side Public License
            "BUSL-1.1",  # Business Source License
            "Elastic-2.0",  # Elastic License 2.0
            "FSL-1.1-MIT",  # Sentry's Functional Source License (future MIT)
            "FSL-1.1-ALv2",  # Sentry's Functional Source License (future Apache-2.0)
            "Parity-6.0.0",
            "Parity-7.0.0",
            "PolyForm-Noncommercial-1.0.0",
            "PolyForm-Small-Business-1.0.0",
        ],
    )
    def test_source_available_routes_to_unknown(self, spdx_id: str):
        assert classify_risk(spdx_id) == RiskLevel.UNKNOWN


class TestCCRestrictiveVariants:
    """CC-BY-NC-* and CC-BY-ND-* aren't free-software licenses. The
    `^CC-BY-\\d` pattern would mistakenly grab them as permissive without
    the explicit overrides."""

    @pytest.mark.parametrize(
        "spdx_id",
        [
            "CC-BY-NC-4.0",
            "CC-BY-NC-SA-4.0",
            "CC-BY-NC-ND-4.0",
            "CC-BY-ND-4.0",
        ],
    )
    def test_restrictive_cc_variants_route_to_unknown(self, spdx_id: str):
        assert classify_risk(spdx_id) == RiskLevel.UNKNOWN


class TestUnrecognizedSpdxIdReturnsUnknown:
    """A simple ID not covered by any pattern or override returns UNKNOWN."""

    def test_unknown_simple_id(self):
        # Not a real SPDX ID; pattern miss + override miss.
        assert classify_risk("Fictional-3.14") == RiskLevel.UNKNOWN

    def test_unknown_real_spdx_id_we_dont_cover(self):
        # `Bahyph` is a real SPDX ID but has no family pattern or override.
        # The conservative default is UNKNOWN — better to flag for manual
        # review than guess.
        assert classify_risk("Bahyph") == RiskLevel.UNKNOWN


class TestPrefixOvermatchDoesNotFalseClean:
    """A family prefix pattern (``^MIT``, ``^BSD``, ``^Apache-``) can match an
    ID that merely *looks* like a permissive license but is not a real SPDX ID
    (a registry typo or a custom restrictive license). PERMISSIVE is the only
    "clean" verdict, so a permissive prefix match is honoured only when the ID
    is a recognized SPDX ID; otherwise it routes to UNKNOWN (manual review).
    """

    @pytest.mark.parametrize(
        "spdx_id",
        [
            "MIT-NonCommercial",  # restrictive custom ID sharing the MIT prefix
            "MIT-Royalty-Required",
            "BSD-5-Clause",  # not a real SPDX ID
            "BSD-Protective",
            "Apache-Custom",
        ],
    )
    def test_unrecognized_permissive_prefix_routes_to_unknown(self, spdx_id: str):
        assert classify_risk(spdx_id) == RiskLevel.UNKNOWN

    @pytest.mark.parametrize(
        "spdx_id",
        [
            "MIT",
            "MIT-0",
            "BSD-3-Clause",
            "Apache-2.0",
            "CC-BY-4.0",
            "X11",
            "HPND",
        ],
    )
    def test_recognized_permissive_ids_still_classify(self, spdx_id: str):
        assert classify_risk(spdx_id) == RiskLevel.PERMISSIVE

    def test_copyleft_prefix_overmatch_is_not_gated(self):
        # Over-matching a copyleft prefix only adds scrutiny, so it is not
        # gated on the recognized-ID list — a fake ``GPL-Custom`` stays strong
        # copyleft rather than relaxing to UNKNOWN.
        assert classify_risk("GPL-Custom") == RiskLevel.STRONG_COPYLEFT


class TestWithExpressionRisk:
    def test_with_exception_strips_to_base(self):
        """WITH exception should classify based on the base license."""

        assert classify_risk("Apache-2.0 WITH LLVM-exception") == RiskLevel.PERMISSIVE
        assert classify_risk("GPL-3.0-only WITH Autoconf-exception-3.0") == (
            RiskLevel.STRONG_COPYLEFT
        )

    def test_classpath_exception_relaxes_strong_to_weak(self):
        """The Classpath exception grants LGPL-style linking permission, so a
        strong-copyleft GPL base relaxes to weak copyleft — both the modern
        WITH spelling and the deprecated compound ID."""

        assert classify_risk("GPL-2.0-only WITH Classpath-exception-2.0") == (
            RiskLevel.WEAK_COPYLEFT
        )
        assert classify_risk("GPL-2.0-with-classpath-exception") == RiskLevel.WEAK_COPYLEFT
