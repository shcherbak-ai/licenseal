"""Tests for licenseal.analysis.risk."""

from __future__ import annotations

import pytest

from licenseal.analysis.risk import (
    _ADDED_PERMISSION_EXCEPTIONS,
    _DEPRECATED_WITH_IDS,
    _LINKING_EXCEPTIONS,
    DEPRECATED_SPDX_IDS,
    KNOWN_SPDX_IDS,
    classify_risk,
    split_exception,
    unrecognized_exception,
)
from licenseal.analysis.spdx import _DEPRECATED_SPDX_URL_IDS, canonical_license_id
from licenseal.models import RiskLevel


class TestDeprecatedSpdxIds:
    """The deprecated SPDX license IDs are one list, kept apart from the
    vendored list of current ones."""

    def test_no_deprecated_id_is_on_the_current_list(self):
        assert len(DEPRECATED_SPDX_IDS) == 32
        assert not DEPRECATED_SPDX_IDS & KNOWN_SPDX_IDS

    def test_ids_with_an_exception_in_them_are_the_ones_judged_as_an_expression(self):
        assert set(_DEPRECATED_WITH_IDS) == {
            license_id for license_id in DEPRECATED_SPDX_IDS if "-with-" in license_id
        }

    def test_ids_recognized_in_a_license_url_are_deprecated_ids(self):
        assert _DEPRECATED_SPDX_URL_IDS <= DEPRECATED_SPDX_IDS

    def test_gnu_spellings_read_as_a_current_id_and_the_rest_are_kept(self):
        rewritten = {
            license_id
            for license_id in DEPRECATED_SPDX_IDS
            if canonical_license_id(license_id) != license_id
        }
        assert all(canonical_license_id(i) in KNOWN_SPDX_IDS for i in rewritten)
        assert DEPRECATED_SPDX_IDS - rewritten == {
            *_DEPRECATED_WITH_IDS,
            "BSD-2-Clause-FreeBSD",
            "BSD-2-Clause-NetBSD",
            "Net-SNMP",
            "Nunit",
            "StandardML-NJ",
            "bzip2-1.0.5",
            "eCos-2.0",
            "wxWindows",
        }

    def test_list_is_the_one_the_spdx_table_in_packaging_marks_deprecated(self):
        # A second copy of the SPDX license list, when the installed
        # ``packaging`` ships the same version of it.
        spdx = pytest.importorskip("packaging.licenses._spdx")
        if getattr(spdx, "VERSION", None) != "3.27.0":
            pytest.skip("packaging ships another version of the SPDX license list")
        deprecated = {entry["id"] for entry in spdx.LICENSES.values() if entry["deprecated"]}
        assert deprecated == DEPRECATED_SPDX_IDS


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
            # *including the source data*; strong copyleft for databases.
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


class TestUseRestrictedPermissivePrefixIds:
    """Real SPDX IDs that share a permissive family prefix (``^BSD``,
    ``^Unicode-``) but carry a use restriction route to UNKNOWN, the same way
    the restrictive CC variants do. They are in the recognized-ID list, so the
    prefix-overmatch gate alone would leave them permissive."""

    @pytest.mark.parametrize(
        "spdx_id",
        [
            "BSD-3-Clause-No-Military-License",
            "BSD-3-Clause-No-Nuclear-License",
            "BSD-3-Clause-No-Nuclear-License-2014",
            "BSD-Protection",
            "Unicode-TOU",
        ],
    )
    def test_use_restricted_ids_route_to_unknown(self, spdx_id: str):
        assert spdx_id in KNOWN_SPDX_IDS
        assert classify_risk(spdx_id) == RiskLevel.UNKNOWN
        # An AND binds every arm, so the restriction is not droppable; an OR
        # still lets the consumer elect the plain permissive arm.
        assert classify_risk(f"MIT AND {spdx_id}") == RiskLevel.UNKNOWN
        assert classify_risk(f"MIT OR {spdx_id}") == RiskLevel.PERMISSIVE

    @pytest.mark.parametrize(
        "spdx_id",
        [
            # A warranty disclaimer, not a use restriction.
            "BSD-3-Clause-No-Nuclear-Warranty",
            # Unrestricted members of the same families.
            "BSD-3-Clause",
            "BSD-3-Clause-Clear",
            "Unicode-3.0",
            "Unicode-DFS-2016",
        ],
    )
    def test_unrestricted_family_members_stay_permissive(self, spdx_id: str):
        assert classify_risk(spdx_id) == RiskLevel.PERMISSIVE


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
    def test_added_permission_exception_classifies_on_the_license(self):
        """An exception that only adds a permission leaves the class of the
        license it follows."""

        assert classify_risk("Apache-2.0 WITH LLVM-exception") == RiskLevel.PERMISSIVE
        assert classify_risk("GPL-3.0-only WITH Autoconf-exception-3.0") == (
            RiskLevel.STRONG_COPYLEFT
        )

    @pytest.mark.parametrize("exception", sorted(_ADDED_PERMISSION_EXCEPTIONS))
    def test_every_added_permission_exception_keeps_the_class_of_its_license(self, exception):
        for license_id, risk in (
            ("Apache-2.0", RiskLevel.PERMISSIVE),
            ("LGPL-2.1-or-later", RiskLevel.WEAK_COPYLEFT),
            ("GPL-3.0-or-later", RiskLevel.STRONG_COPYLEFT),
            ("GPL-2.0+", RiskLevel.STRONG_COPYLEFT),
            ("AGPL-3.0-only", RiskLevel.NETWORK_COPYLEFT),
            ("SomeCustomLicense", RiskLevel.UNKNOWN),
        ):
            assert classify_risk(f"{license_id} WITH {exception}") == risk, license_id

    def test_classpath_exception_relaxes_strong_to_weak(self):
        """The Classpath exception grants LGPL-style linking permission, so a
        strong-copyleft GPL base relaxes to weak copyleft — both the modern
        WITH spelling and the deprecated compound ID."""

        assert classify_risk("GPL-2.0-only WITH Classpath-exception-2.0") == (
            RiskLevel.WEAK_COPYLEFT
        )
        assert classify_risk("GPL-2.0-with-classpath-exception") == RiskLevel.WEAK_COPYLEFT

    @pytest.mark.parametrize("exception", sorted(_LINKING_EXCEPTIONS))
    def test_linking_exception_relaxes_only_a_strong_copyleft_license(self, exception):
        for license_id, risk in (
            ("GPL-2.0-only", RiskLevel.WEAK_COPYLEFT),
            ("GPL-3.0-or-later", RiskLevel.WEAK_COPYLEFT),
            ("LGPL-3.0-only", RiskLevel.WEAK_COPYLEFT),
            ("AGPL-3.0-only", RiskLevel.NETWORK_COPYLEFT),
            ("Apache-2.0", RiskLevel.PERMISSIVE),
            ("SomeCustomLicense", RiskLevel.UNKNOWN),
        ):
            assert classify_risk(f"{license_id} WITH {exception}") == risk, license_id

    @pytest.mark.parametrize(
        "expression",
        [
            # A use restriction written where an exception belongs.
            "Apache-2.0 WITH Commons-Clause",
            "MIT WITH NonCommercialRestriction",
            # A license where an exception belongs.
            "MIT WITH GPL-3.0-only",
            # Names that only start like a recognized exception, or differ
            # from one in case.
            "Apache-2.0 WITH LLVM-exception-2",
            "Apache-2.0 WITH llvm-exception",
            "LGPL-2.1-only WITH Classpath-exception-evil",
            # A real SPDX exception the rules do not reason about.
            "LGPL-2.1-only WITH Qwt-exception-1.0",
            # Not a single exception.
            "Apache-2.0 WITH LLVM-exception WITH Commons-Clause",
            "Apache-2.0 WITH (LLVM-exception)",
            # Nothing about the term is known.
            "SomeCustomLicense WITH Commons-Clause",
        ],
    )
    def test_unrecognized_exception_makes_the_term_unknown(self, expression):
        assert classify_risk(expression) == RiskLevel.UNKNOWN
        # In a conjunction the term is an unresolved operand; in a choice the
        # other arm is still electable.
        assert classify_risk(f"MIT AND {expression}") == RiskLevel.UNKNOWN
        assert classify_risk(f"MIT OR {expression}") == RiskLevel.PERMISSIVE
        assert classify_risk(f"AGPL-3.0-only AND {expression}") == RiskLevel.NETWORK_COPYLEFT

    @pytest.mark.parametrize(
        "expression, risk",
        [
            # Names that only start like the Classpath exception, or differ
            # from it in case: no relaxation to weak copyleft.
            ("GPL-3.0-only WITH Classpath-exception-evil", RiskLevel.STRONG_COPYLEFT),
            ("GPL-3.0-only WITH Classpath-exception", RiskLevel.STRONG_COPYLEFT),
            ("GPL-3.0-only WITH Classpath-exception-2.0-shorter", RiskLevel.STRONG_COPYLEFT),
            ("GPL-2.0-only WITH classpath-exception-2.0", RiskLevel.STRONG_COPYLEFT),
            # A real SPDX exception the rules do not reason about.
            ("GPL-2.0-only WITH Qwt-exception-1.0", RiskLevel.STRONG_COPYLEFT),
            ("GPL-3.0-or-later WITH Qt-GPL-exception-1.0", RiskLevel.STRONG_COPYLEFT),
            ("AGPL-3.0-only WITH Commons-Clause", RiskLevel.NETWORK_COPYLEFT),
        ],
    )
    def test_unrecognized_exception_does_not_lower_a_copyleft_license(self, expression, risk):
        # The term is its license together with an operand nobody read, like
        # ``<license> AND UNKNOWN``: a copyleft class stays known.
        license_id = split_exception(expression)[0]
        assert classify_risk(expression) == risk
        assert classify_risk(expression) == classify_risk(f"{license_id} AND UNKNOWN")
        assert classify_risk(f"MIT AND {expression}") == risk
        assert classify_risk(f"MIT OR {expression}") == RiskLevel.PERMISSIVE

    def test_unrecognized_exception_helper(self):
        assert unrecognized_exception("MIT") == ""
        assert unrecognized_exception("Apache-2.0 WITH LLVM-exception") == ""
        assert unrecognized_exception("GPL-2.0-only WITH Classpath-exception-2.0") == ""
        assert unrecognized_exception("Apache-2.0 WITH Commons-Clause") == "Commons-Clause"
        assert unrecognized_exception("MIT WITH A WITH B") == "A WITH B"

    def test_recognized_exceptions_are_real_spdx_exception_ids(self):
        # The vendored list holds license IDs only; an exception ID that also
        # named a license would make ``X WITH <id>`` ambiguous.
        assert not (_LINKING_EXCEPTIONS | _ADDED_PERMISSION_EXCEPTIONS) & KNOWN_SPDX_IDS
        assert not _LINKING_EXCEPTIONS & _ADDED_PERMISSION_EXCEPTIONS

    def test_split_exception(self):
        assert split_exception("MIT") == ("MIT", "")
        assert split_exception("Apache-2.0 WITH LLVM-exception") == (
            "Apache-2.0",
            "LLVM-exception",
        )
        assert split_exception("A WITH B WITH C") == ("A", "B WITH C")

    @pytest.mark.parametrize("deprecated, current", sorted(_DEPRECATED_WITH_IDS.items()))
    def test_deprecated_with_id_is_the_expression_it_stands_for(self, deprecated, current):
        license_id, _, exception = current.partition(" WITH ")
        assert split_exception(deprecated) == (license_id, exception)
        assert unrecognized_exception(deprecated) == ""
        assert classify_risk(deprecated) == classify_risk(current)
        # ``+`` is the upgrade clause of the license: the class is unchanged.
        later = license_id.replace("-only", "-or-later")
        assert later in KNOWN_SPDX_IDS
        assert split_exception(f"{deprecated}+") == (later, exception)
        assert classify_risk(f"{deprecated}+") == classify_risk(current)
        # An exception written after the ID is a second one, which matches
        # no recognized exception.
        assert split_exception(f"{deprecated} WITH LLVM-exception") == (
            license_id,
            f"{exception} WITH LLVM-exception",
        )
        assert unrecognized_exception(f"{deprecated} WITH LLVM-exception")

    def test_deprecated_with_ids_classify_by_their_exception(self):
        assert classify_risk("GPL-2.0-with-classpath-exception") == RiskLevel.WEAK_COPYLEFT
        for deprecated in sorted(set(_DEPRECATED_WITH_IDS) - {"GPL-2.0-with-classpath-exception"}):
            assert classify_risk(deprecated) == RiskLevel.STRONG_COPYLEFT, deprecated
        # An ID that only looks like one of them stays on the family pattern.
        assert classify_risk("GPL-2.0-with-made-up-exception") == RiskLevel.STRONG_COPYLEFT
        assert split_exception("GPL-2.0-with-made-up-exception") == (
            "GPL-2.0-with-made-up-exception",
            "",
        )
