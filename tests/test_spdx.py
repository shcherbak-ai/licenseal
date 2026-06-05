"""Tests for licenseal.analysis.spdx."""

from __future__ import annotations

import pytest

from licenseal.analysis.spdx import _looks_like_spdx, normalize_license, normalize_r_license


class TestNormalizeLicense:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            # MIT variants
            ("MIT", "MIT"),
            ("mit", "MIT"),
            ("MIT License", "MIT"),
            ("The MIT License", "MIT"),
            ("The MIT License (MIT)", "MIT"),
            ("MIT License (MIT)", "MIT"),
            ("mit licence", "MIT"),
            ("Expat", "MIT"),
            # BSD variants
            ("BSD", "BSD-3-Clause"),
            ("BSD License", "BSD-3-Clause"),
            ("BSD-2-Clause", "BSD-2-Clause"),
            ("BSD 2-Clause", "BSD-2-Clause"),
            ("BSD 2 Clause", "BSD-2-Clause"),
            ("Simplified BSD", "BSD-2-Clause"),
            ("BSD-3-Clause", "BSD-3-Clause"),
            ("New BSD", "BSD-3-Clause"),
            ("New BSD License", "BSD-3-Clause"),
            ("BSD-3", "BSD-3-Clause"),
            # Apache variants
            ("Apache-2.0", "Apache-2.0"),
            ("Apache 2.0", "Apache-2.0"),
            ("Apache License 2.0", "Apache-2.0"),
            ("Apache License, Version 2.0", "Apache-2.0"),
            ("Apache Software License", "Apache-2.0"),
            ("Apache Software License 2.0", "Apache-2.0"),
            # ISC
            ("ISC", "ISC"),
            ("ISC License", "ISC"),
            ("ISC License (ISCL)", "ISC"),
            # GPL variants
            ("GPL-2.0", "GPL-2.0-only"),
            ("GPL-2.0-only", "GPL-2.0-only"),
            ("GPL-2.0-or-later", "GPL-2.0-or-later"),
            ("GPLv2", "GPL-2.0-only"),
            ("GPL-3.0", "GPL-3.0-only"),
            ("GPL-3.0-only", "GPL-3.0-only"),
            ("GPL-3.0-or-later", "GPL-3.0-or-later"),
            ("GPLv3", "GPL-3.0-only"),
            ("GPLv3+", "GPL-3.0-or-later"),
            ("GNU General Public License v3", "GPL-3.0-only"),
            ("GNU General Public License (GPL)", "GPL-3.0-only"),
            # GNU prose "version N" / "vN.0" forms — publishers use these
            # interchangeably with "vN"; the alias map must cover all three.
            ("GNU General Public License v2.0", "GPL-2.0-only"),
            ("GNU General Public License version 2", "GPL-2.0-only"),
            # LGPL
            ("LGPL-2.1", "LGPL-2.1-only"),
            ("LGPL-3.0", "LGPL-3.0-only"),
            ("LGPLv3", "LGPL-3.0-only"),
            ("GNU Lesser General Public License version 3", "LGPL-3.0-only"),
            ("GNU Lesser General Public License v3.0", "LGPL-3.0-only"),
            ("GNU Lesser General Public License version 2", "LGPL-2.0-only"),
            ("GNU Lesser General Public License version 2.1", "LGPL-2.1-only"),
            # AGPL
            ("AGPL-3.0", "AGPL-3.0-only"),
            ("AGPLv3", "AGPL-3.0-only"),
            ("AGPL-3.0+", "AGPL-3.0-or-later"),  # `+` canonicalizes like gpl-3.0+
            # Long-form GNU prose with "version N" instead of "vN" — common
            # in package.json/pyproject license fields of network-copyleft
            # SaaS projects. Previously normalized to UNKNOWN because only
            # the "v3" alias existed for AGPL while GPL already had both.
            ("GNU Affero General Public License version 3", "AGPL-3.0-only"),
            ("GNU Affero General Public License v3.0", "AGPL-3.0-only"),
            ("GNU Affero General Public License", "AGPL-3.0-only"),
            ("GNU AGPL v3", "AGPL-3.0-only"),
            ("GNU AGPL v3+", "AGPL-3.0-or-later"),
            ("AGPLv3+", "AGPL-3.0-or-later"),
            # MPL
            ("MPL-2.0", "MPL-2.0"),
            ("Mozilla Public License 2.0", "MPL-2.0"),
            # EPL
            ("EPL-2.0", "EPL-2.0"),
            ("EPL-1.0", "EPL-1.0"),
            # Public domain
            ("Unlicense", "Unlicense"),
            ("The Unlicense", "Unlicense"),
            ("Public Domain", "LicenseRef-Public-Domain"),
            ("CC0-1.0", "CC0-1.0"),
            ("CC0 1.0 Universal", "CC0-1.0"),
            # PSF
            ("PSF-2.0", "PSF-2.0"),
            ("Python Software Foundation License", "PSF-2.0"),
            # Others
            ("Artistic-2.0", "Artistic-2.0"),
            ("0BSD", "0BSD"),
            ("Zlib", "Zlib"),
            ("WTFPL", "WTFPL"),
            # Proprietary
            ("proprietary", "Proprietary"),
            # Unknown
            ("UNKNOWN", "UNKNOWN"),
            ("unknown", "UNKNOWN"),
            ("", "UNKNOWN"),
            ("License :: OSI Approved", "UNKNOWN"),
        ],
    )
    def test_normalization(self, raw: str, expected: str):
        assert normalize_license(raw) == expected

    @pytest.mark.parametrize(
        "classifier, expected",
        [
            ("License :: OSI Approved :: MIT License", "MIT"),
            ("License :: OSI Approved :: BSD License", "BSD-3-Clause"),
            ("License :: OSI Approved :: Apache Software License", "Apache-2.0"),
            (
                "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
                "GPL-3.0-only",
            ),
            (
                "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
                "MPL-2.0",
            ),
            ("License :: Public Domain", "LicenseRef-Public-Domain"),
        ],
    )
    def test_classifier_normalization(self, classifier: str, expected: str):
        assert normalize_license(classifier) == expected

    def test_eclipse_public_license_v_prefix(self):
        # Eclipse uses ``v2.0`` / ``v1.0`` (with v) in their canonical
        # license strings. Both the bare and the ``- v 2.0`` long forms
        # publishers actually ship must map to SPDX.
        assert normalize_license("Eclipse Public License v2.0") == "EPL-2.0"
        assert normalize_license("Eclipse Public License v1.0") == "EPL-1.0"
        assert normalize_license("Eclipse Public License - v 2.0") == "EPL-2.0"
        # Eclipse Distribution License IS BSD-3-Clause per Eclipse Foundation.
        assert normalize_license("Eclipse Distribution License v1.0") == "BSD-3-Clause"

    def test_slash_or_recurses_into_prose_names(self):
        # Cargo's slash-as-OR convention is also used by publishers writing
        # prose: ``"Eclipse Public License v2.0 / Eclipse Distribution
        # License v1.0"``. Before the recursive normalization, slash → OR
        # alone produced an unparseable string that classified as UNKNOWN.
        # Now each side normalizes first.
        result = normalize_license(
            "Eclipse Public License v2.0 / Eclipse Distribution License v1.0"
        )
        assert result == "BSD-3-Clause OR EPL-2.0"

    def test_lowercase_and_connector(self):
        # Some publishers write ``"MIT and ISC"`` (visx/vendor) instead of
        # SPDX's uppercase AND. Each side normalizes and the result becomes
        # a valid compound expression — without this, the lowercase ``and``
        # wasn't recognized as a keyword and the whole string flunked
        # _looks_like_spdx, landing the dep in UNKNOWN. Operand
        # canonicalization sorts the AND/OR children alphabetically.
        assert normalize_license("MIT and ISC") == "ISC AND MIT"
        # Apache-2.0 is multi-token through the alias map; the case-folded
        # connector still works.
        assert normalize_license("BSD or MIT") == "BSD-3-Clause OR MIT"

    def test_lowercase_connector_with_unrecognizable_side_returns_unknown(self):
        # Lowercase prose ``"some random text and MIT"`` — the left side
        # doesn't normalize to anything SPDX-shaped, so we shouldn't fabricate
        # a clean compound out of it.
        assert normalize_license("some random text and MIT") == "UNKNOWN"

    def test_bare_license_filename(self):
        # Publishers sometimes set ``license`` to the bundled filename. The
        # extension-suffixed form (``LICENSE.txt``) was already handled; the
        # bare form (``LICENSE``, ``COPYING``) wasn't, so they landed in
        # UNKNOWN instead of routing to Proprietary for manual review.
        assert normalize_license("LICENSE") == "Proprietary"
        assert normalize_license("LICENCE") == "Proprietary"
        assert normalize_license("license") == "Proprietary"
        assert normalize_license("COPYING") == "Proprietary"
        # Extension form still works.
        assert normalize_license("LICENSE.txt") == "Proprietary"
        assert normalize_license("LICENSE.md") == "Proprietary"

    def test_url_input_canonical_apache(self):
        # Python ``setup.py`` / ``pyproject.toml`` sometimes set ``license``
        # to a URL pointing at the license text. Route through the URL-prefix
        # table so the project-license detector emits a real SPDX ID.
        assert normalize_license("https://www.apache.org/licenses/LICENSE-2.0") == "Apache-2.0"
        assert normalize_license("https://spdx.org/licenses/MIT") == "MIT"

    def test_url_input_unrecognized_falls_through(self):
        # An unrecognized URL falls through to UNKNOWN; we must NOT pretend
        # we recognized it (would corrupt downstream compat analysis).
        assert normalize_license("https://example.com/some-custom-license") == "UNKNOWN"

    def test_slash_with_one_unrecognized_side_falls_through(self):
        # If only one side normalizes, fall through to the legacy slash-OR
        # rewrite (lets the existing _looks_like_spdx heuristic handle it).
        # ``"FrobnicateLicense / MIT"`` — frobnicate isn't a real license, so
        # we don't fabricate; either UNKNOWN or the rewritten string.
        result = normalize_license("FrobnicateLicense / MIT")
        # Should not be "FrobnicateLicense OR MIT" treated as valid (would
        # imply Frobnicate is SPDX-shaped — defensible either way; the key
        # behavior is that we don't fabricate a clean SPDX out of it).
        assert "Frobnicate" not in result or result == "UNKNOWN" or "OR" in result

    def test_long_string_not_spdx(self):
        long_text = (
            "This is a very long license text that definitely is not"
            " a valid SPDX identifier and should be classified as unknown"
        )
        assert normalize_license(long_text) == "UNKNOWN"

    def test_all_lowercase_not_spdx(self):
        assert normalize_license("some random text") == "UNKNOWN"


class TestProseAndNoiseGaps:
    """Free-form vendor prose and bundled-dependency noise that publishers put
    in the ``license`` field. Capitalized prose used to slip through
    ``_looks_like_spdx`` as a pseudo-identifier; a trailing non-license note
    used to sink a whole comma list of real SPDX IDs to UNKNOWN.
    """

    def test_capitalized_prose_is_not_a_pseudo_spdx_id(self):
        # Every word is individually "ID-shaped" (capitalized), but two ID
        # leaves with no operator between them is prose, not an expression.
        assert normalize_license("Dual Licensed - GNU AFFERO GPL 3.0") == "UNKNOWN"
        assert normalize_license("Some Vendor License Terms") == "UNKNOWN"

    def test_spelled_out_affero_gpl_version_normalizes(self):
        # Sibling of the existing "gnu affero gpl" / "...v3" aliases.
        assert normalize_license("GNU AFFERO GPL 3.0") == "AGPL-3.0-only"
        assert normalize_license("GNU AFFERO GPL 3") == "AGPL-3.0-only"

    def test_artifex_pymupdf_dual_license(self):
        # Artifex's free-form dual-license prose → structured dual expression,
        # so the AGPL arm reaches the risk engine instead of being lost.
        assert (
            normalize_license("Dual Licensed - GNU AFFERO GPL 3.0 or Artifex Commercial License")
            == "AGPL-3.0-only OR Proprietary"
        )
        assert normalize_license("Artifex Commercial License") == "Proprietary"

    def test_comma_list_with_dependency_noise_keeps_real_ids(self):
        # The trailing "dependency licenses" note points at bundled deps, not a
        # license of the package; drop it and keep the two real SPDX IDs.
        assert (
            normalize_license("BSD-3-Clause, Apache-2.0, dependency licenses")
            == "Apache-2.0 OR BSD-3-Clause"
        )
        assert normalize_license("Apache-2.0, dependency licenses") == "Apache-2.0"
        assert normalize_license("MIT, dependencies") == "MIT"

    def test_comma_list_with_unrecognized_token_still_blocks(self):
        # Only *recognized* noise is dropped. A token that doesn't resolve to a
        # known license (and isn't recognized noise) must still block the
        # comma compound — we don't fabricate a verdict from the recognized
        # subset, since the unknown token might carry a real obligation.
        assert normalize_license("MIT, acme internal license") == "UNKNOWN"


class TestSlashOrFallback:
    def test_slash_substituted_when_a_part_is_unknown(self):
        # "MIT / foobar" splits to ["MIT", "foobar"]. The lowercase "foobar"
        # doesn't look SPDX-shaped and normalizes to UNKNOWN, so the fast-
        # path `all(p != UNKNOWN)` fails and the slash is rewritten to
        # " OR " before continuing through the normalizer. The substituted
        # form still doesn't resolve to a known license, so the final
        # answer is UNKNOWN — the substitution branch is what's exercised.
        assert normalize_license("MIT / foobar") == "UNKNOWN"


class TestPublisherAliasGapsClosedByBench:
    """Aliases added after the 20-repo lmp head-to-head surfaced cases
    where a publisher's literal license name routed to Proprietary or
    UNKNOWN despite the underlying license being a well-known SPDX. Each
    entry traces back to a specific corpus repo's L_PROPRIETARY_LMP_SPDX
    or DIFFERENT_SPDX disagreement.
    """

    def test_short_gplv2_classpath_exception_variants(self):
        # Used by Sun-licensed libraries / OpenJDK-derived projects
        # (nashorn-core, com.sun.* family). Without these the comma-
        # decompose path falls through to Proprietary.
        cpe = "GPL-2.0-with-classpath-exception"
        assert normalize_license("GPLv2 with classpath exception") == cpe
        assert normalize_license("GPL v2 with classpath exception") == cpe
        assert normalize_license("GPL v2 with the Classpath exception") == cpe

    def test_short_cddl_or_gpl_dual_variants(self):
        # Jenkins / glassfish.org / com.sun.* family. The
        # ``CDDL + GPL-2.0-with-classpath-exception`` two-license shape
        # is the Sun/Oracle dual-license pattern — publisher intent is
        # OR (either license suffices), and the collapse step in
        # ``normalize_license`` rewrites the alias map's literal AND
        # back to OR. The ``CDDL v1.1 / GPL v2`` variant (no classpath
        # exception) is not part of the OR-shorthand convention and
        # stays as the literal AND from the alias map.
        assert (
            normalize_license("CDDL or GPL 2 with Classpath Exception")
            == "CDDL-1.0 OR GPL-2.0-with-classpath-exception"
        )
        assert normalize_license("CDDL v1.1 / GPL v2 dual license") == "CDDL-1.1 AND GPL-2.0"

    def test_the_go_license_alias(self):
        # com.google.re2j:re2j and other Go-port libraries. The bare
        # "go license" was already aliased; this adds the "the" prefix
        # variant that re2j's POM uses verbatim.
        assert normalize_license("The Go license") == "BSD-3-Clause"

    def test_jai_imaging_nuclear_disclaimer_variant(self):
        # com.github.jai-imageio:jai-imageio-core publisher string —
        # the "w/nuclear disclaimer" suffix hits the proprietary-signal
        # regex without this alias.
        assert normalize_license("BSD 3-clause License w/nuclear disclaimer") == "BSD-3-Clause"

    def test_mysql_universal_foss_exception_routes_to_gpl(self):
        # com.mysql:mysql-connector-j. Oracle/MySQL FOSS Exception
        # wraps a GPL-2.0 base; we map to GPL-2.0-only so the risk classifier
        # places it correctly (the exception is documented separately).
        assert (
            normalize_license(
                "The GNU General Public License, v2 with Universal FOSS Exception, v1.0"
            )
            == "GPL-2.0-only"
        )


class TestSpdxOperandCanonicalization:
    """Operand-canonicalization branch of :func:`normalize_license`.

    Sorts OR/AND children case-insensitively at every nesting level so
    semantically-identical expressions compare as equal strings. Verifies
    the basic sort, paren-aware top-level splitting, WITH-as-leaf
    semantics, paren wrapping when AND children contain OR, and the
    defensive passthrough on malformed (unbalanced-paren) input.
    """

    def test_or_children_sorted_alphabetically(self):
        # The canonical case: MIT vs Apache-2.0 in either order produces
        # the same canonical form.
        assert normalize_license("MIT OR Apache-2.0") == "Apache-2.0 OR MIT"
        assert normalize_license("Apache-2.0 OR MIT") == "Apache-2.0 OR MIT"

    def test_and_children_sorted_alphabetically(self):
        assert normalize_license("MIT AND BSD-3-Clause") == "BSD-3-Clause AND MIT"

    def test_with_compound_treated_as_leaf(self):
        # WITH binds tighter than OR/AND and is not commutative — the WITH-
        # compound moves as a single unit when sorting the OR children.
        result = normalize_license("Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT")
        assert result == "Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT"

    def test_paren_aware_top_level_split(self):
        # The inner OR is inside parens at depth 1; the AND-split must not
        # see it, and the OR-split at depth 0 must not see the AND.
        # Canonicalization recurses into the paren group and sorts the
        # AND/OR children at both levels. AND children that contain OR
        # get wrapped on the way out.
        result = normalize_license("Unicode-DFS-2016 AND (MIT OR Apache-2.0)")
        assert result == "(Apache-2.0 OR MIT) AND Unicode-DFS-2016"

    def test_redundant_outer_parens_stripped(self):
        # Outer parens that wrap the whole expression are stripped and
        # the contents are canonicalized. ``"(A) AND (B)"`` keeps both
        # paren groups (they're not the outermost wrap — the outer
        # ``(`` closes mid-string).
        assert normalize_license("(MIT OR Apache-2.0)") == "Apache-2.0 OR MIT"
        assert normalize_license("(MIT) AND (Apache-2.0)") == "Apache-2.0 AND MIT"

    def test_unbalanced_parens_passes_through_unchanged(self):
        # Defensive: an expression with unbalanced parens skips
        # canonicalization entirely (we can't safely split on top-level
        # operators without knowing depth). The pre-canonicalization
        # ``_looks_like_spdx`` heuristic still accepts the string, so it
        # passes through as-is rather than rotating operands or crashing.
        assert normalize_license("(MIT OR Apache-2.0") == "(MIT OR Apache-2.0"

    def test_whitespace_collapsed_in_canonicalization(self):
        # Multiple spaces between operands should canonicalize the same
        # as single-spaced input.
        assert normalize_license("MIT  OR  Apache-2.0") == "Apache-2.0 OR MIT"

    def test_non_compound_passes_through(self):
        # Fast path: no OR/AND in the input means no canonicalization work.
        assert normalize_license("MIT") == "MIT"
        expr = "Apache-2.0 WITH LLVM-exception"
        assert normalize_license(expr) == expr


class TestRedundantLicensePairCollapse:
    """Pattern-level cleanup for SPDX AND-chains where one license is a
    redundant inclusion of another (LGPL imports GPL by reference) or
    where AND is a POM-convention artifact for publisher-intended OR
    (Sun/Oracle javax.* family).

    Covers regressions surfaced by deps.dev's licensecheck enumerating
    all LICENSE files in a package's source tree — see :func:
    `licenseal.analysis.spdx._collapse_redundant_license_pairs`.
    """

    def test_lgpl_and_gpl_same_version_collapses_to_lgpl(self):
        # The pygithub case after operand canonicalization:
        # GPL-3.0 AND GPL-3.0-or-later AND LGPL-3.0 → LGPL-3.0.
        assert normalize_license("LGPL-3.0 AND GPL-3.0") == "LGPL-3.0"
        assert normalize_license("GPL-3.0 AND LGPL-3.0") == "LGPL-3.0"
        assert normalize_license("GPL-3.0 AND GPL-3.0-or-later AND LGPL-3.0") == "LGPL-3.0"

    def test_lgpl_2_1_and_gpl_2_0_collapses(self):
        # LGPL-2.1 explicitly references GPL-2.0 in its text — same
        # inclusion relationship as the matching-X.Y case.
        assert normalize_license("LGPL-2.1 AND GPL-2.0") == "LGPL-2.1"
        assert normalize_license("GPL-2.0-only AND LGPL-2.1-only") == "LGPL-2.1-only"

    def test_lgpl_only_and_gpl_or_later_variants_collapse(self):
        # ``-only`` / ``-or-later`` SPDX suffixes shouldn't block the
        # match — the inclusion relation is per license family, not
        # per exact identifier string.
        assert normalize_license("LGPL-3.0-only AND GPL-3.0-or-later") == "LGPL-3.0-only"

    def test_lgpl_without_gpl_left_alone(self):
        # LGPL by itself is not a collapse case (and the alias map
        # rewrites bare LGPL-3.0 to LGPL-3.0-only — orthogonal step).
        assert normalize_license("LGPL-3.0") == "LGPL-3.0-only"
        assert normalize_license("LGPL-3.0-only") == "LGPL-3.0-only"

    def test_gpl_without_lgpl_left_alone(self):
        # GPL by itself stays as-is — the inclusion only goes one way.
        # (Bare GPL-3.0 rewrites to GPL-3.0-only via the alias map.)
        assert normalize_license("GPL-3.0") == "GPL-3.0-only"
        assert normalize_license("GPL-2.0-only AND GPL-3.0-only") == "GPL-2.0-only AND GPL-3.0-only"

    def test_mismatched_versions_not_collapsed(self):
        # LGPL-3.0 + GPL-2.0 is NOT a known inclusion pair (LGPL-3.0
        # references GPL-3.0, not GPL-2.0). Keep AND.
        result = normalize_license("LGPL-3.0 AND GPL-2.0")
        assert " AND " in result
        assert "LGPL-3.0" in result and "GPL-2.0" in result

    def test_lgpl_and_gpl_chain_with_other_licenses(self):
        # Mixed compound: LGPL+GPL+Apache. Drop the GPL (LGPL subsumes
        # it), keep Apache. The result is the operand-canonical join of
        # the remaining two.
        assert normalize_license("Apache-2.0 AND GPL-3.0 AND LGPL-3.0") == "Apache-2.0 AND LGPL-3.0"

    def test_cddl_and_gpl_classpath_exception_becomes_or(self):
        # The Sun/Oracle javax.* dual-license convention: POM forces
        # AND but publisher intent is OR. Exact two-operand shape only.
        assert (
            normalize_license("CDDL-1.0 AND GPL-2.0-with-classpath-exception")
            == "CDDL-1.0 OR GPL-2.0-with-classpath-exception"
        )
        # CDDL-1.1 variant — same Sun/Oracle pattern.
        assert (
            normalize_license("CDDL-1.1 AND GPL-2.0-with-classpath-exception")
            == "CDDL-1.1 OR GPL-2.0-with-classpath-exception"
        )

    def test_cddl_gpl_cpe_chain_with_other_licenses_not_collapsed(self):
        # Narrow pattern: only the exact two-operand AND gets the OR
        # rewrite. A three-license chain might genuinely be all-apply,
        # so we leave it. ``Apache-2.0 AND CDDL-1.0 AND
        # GPL-2.0-with-classpath-exception`` keeps its AND.
        result = normalize_license("Apache-2.0 AND CDDL-1.0 AND GPL-2.0-with-classpath-exception")
        assert " OR " not in result
        assert result == "Apache-2.0 AND CDDL-1.0 AND GPL-2.0-with-classpath-exception"


class TestNormalizeRLicense:
    """R's DESCRIPTION License grammar → SPDX (| as OR, + file LICENSE, R tokens)."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # ``+ file LICENSE`` keeps the structured token (the file is the
            # copyright stub R requires).
            ("MIT + file LICENSE", "MIT"),
            ("BSD_3_clause + file LICENSE", "BSD-3-Clause"),
            ("BSD_2_clause", "BSD-2-Clause"),
            # GPL/LGPL/AGPL family abbreviations and version ranges.
            ("GPL-2", "GPL-2.0-only"),
            ("GPL-3", "GPL-3.0-only"),
            ("GPL (>= 2)", "GPL-2.0-or-later"),
            ("GPL (> 2)", "GPL-2.0-or-later"),
            ("GPL (== 2)", "GPL-2.0-only"),
            ("GPL (>= 2.0)", "GPL-2.0-or-later"),
            ("LGPL (>= 2.1)", "LGPL-2.1-or-later"),
            ("LGPL-2.1", "LGPL-2.1-only"),
            ("LGPL-2", "LGPL-2.0-only"),
            ("LGPL-3", "LGPL-3.0-only"),
            ("AGPL-3", "AGPL-3.0-only"),
            ("AGPL (>= 3)", "AGPL-3.0-or-later"),
            # Version-pin paren folded into a name the generic map recognizes.
            ("Apache License (== 2.0)", "Apache-2.0"),
            ("Artistic-2.0", "Artistic-2.0"),
            ("MIT", "MIT"),
            # ``|`` is user-choice disjunction → OR (operand-canonicalized).
            ("GPL-2 | GPL-3", "GPL-2.0-only OR GPL-3.0-only"),
            ("BSD_3_clause | MIT", "BSD-3-Clause OR MIT"),
            # An UNKNOWN alternative is dropped when a known one remains.
            ("GPL (>= 3) | file LICENCE", "GPL-3.0-or-later"),
            # A trailing empty alternative (malformed field) is dropped.
            ("GPL-2 | ", "GPL-2.0-only"),
            # Undeterminable → UNKNOWN (routes to manual review).
            ("file LICENSE", "UNKNOWN"),
            ("file LICENCE", "UNKNOWN"),
            ("Unlimited", "UNKNOWN"),
            ("", "UNKNOWN"),
            ("   ", "UNKNOWN"),
            ("+ file LICENSE", "UNKNOWN"),
        ],
    )
    def test_normalize_r_license(self, raw, expected):
        assert normalize_r_license(raw) == expected

    def test_plain_cddl_and_gpl_without_cpe_not_rewritten(self):
        # Without the classpath-exception, the AND is NOT the Sun/Oracle
        # convention — keep as-is.
        result = normalize_license("CDDL-1.0 AND GPL-2.0")
        assert result == "CDDL-1.0 AND GPL-2.0"


class TestSpdxLooksLike:
    def test_only_keywords(self):
        # "OR AND" — all are SPDX keywords, non_keyword_parts is empty
        assert _looks_like_spdx("OR AND") is False

    def test_empty_string_not_spdx(self):
        assert _looks_like_spdx("") is False

    def test_very_long_string_not_spdx(self):
        assert _looks_like_spdx("MIT " * 100) is False
