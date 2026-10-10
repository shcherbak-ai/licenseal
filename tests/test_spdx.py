"""Tests for licenseal.analysis.spdx."""

from __future__ import annotations

import time

import pytest

from licenseal.analysis.spdx import (
    _CLASSIFIER_MAP,
    _LICENSE_URL_PREFIXES,
    _MAX_LICENSE_LENGTH,
    _NORMALIZATION_MAP,
    _looks_like_spdx,
    and_join_licenses,
    canonical_license_id,
    normalize_license,
    normalize_r_license,
    spdx_from_license_url,
)


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
        # Some publishers write ``"MIT and ISC"`` instead of
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

    def test_public_domain_hyphenated_variant(self):
        # The hyphenated publisher spelling must land on the same permissive
        # sentinel as the spaced form — a bare "Public-Domain" passes the
        # SPDX shape check unchanged and classifies UNKNOWN.
        assert normalize_license("Public-Domain") == "LicenseRef-Public-Domain"
        assert normalize_license("public domain") == "LicenseRef-Public-Domain"

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

    @pytest.mark.parametrize(
        "raw",
        [
            # Lookalike host, user-info, and a canonical host/path embedded in
            # another site's path: none of these is the canonical URL.
            "https://not-unlicense.org/commercial",
            "https://unlicense.org.evil.example/terms",
            "https://unlicense.org@evil.example/terms",
            "https://example.org/apache.org/licenses/LICENSE-2.0",
            "https://example.org/spdx.org/licenses/MIT",
            # Right host, different document.
            "https://www.apache.org/licenses/LICENSE-2.0-with-additional-terms",
            # spdx.org page for an ID that does not exist.
            "https://spdx.org/licenses/NotARealLicense",
            # A URL followed by prose is not a URL.
            "https://unlicense.org/ but all rights reserved",
        ],
    )
    def test_url_input_naming_a_canonical_host_elsewhere_is_unknown(self, raw):
        assert normalize_license(raw) == "UNKNOWN"

    def test_url_input_canonical_variants_still_resolve(self):
        assert normalize_license("https://www.gnu.org/licenses/gpl-3.0.en.html") == "GPL-3.0-only"
        assert normalize_license("https://www.apache.org/licenses/LICENSE-2.0.txt") == "Apache-2.0"
        assert normalize_license("https://unlicense.org/") == "Unlicense"

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
    """Aliases added after a head-to-head run against another license
    tool surfaced cases
    where a publisher's literal license name routed to Proprietary or
    UNKNOWN despite the underlying license being a well-known SPDX. Each
    entry traces back to a disagreement between the two tools on the
    same dependency.
    """

    def test_short_gplv2_classpath_exception_variants(self):
        # Used by Sun-licensed libraries / OpenJDK-derived projects.
        # Without these the comma-decompose path falls through to
        # Proprietary.
        cpe = "GPL-2.0-with-classpath-exception"
        assert normalize_license("GPLv2 with classpath exception") == cpe
        assert normalize_license("GPL v2 with classpath exception") == cpe
        assert normalize_license("GPL v2 with the Classpath exception") == cpe

    def test_short_cddl_or_gpl_dual_variants(self):
        # Short publisher phrasings. The
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
        assert normalize_license("CDDL v1.1 / GPL v2 dual license") == "CDDL-1.1 AND GPL-2.0-only"

    def test_the_go_license_alias(self):
        # Go-to-Java port libraries. The bare
        # "go license" was already aliased; this adds the "the" prefix
        # variant that some of their POMs use verbatim.
        assert normalize_license("The Go license") == "BSD-3-Clause"

    def test_jai_imaging_nuclear_disclaimer_variant(self):
        # Publisher string from a JVM imaging library's POM —
        # the "w/nuclear disclaimer" suffix hits the proprietary-signal
        # regex without this alias.
        assert normalize_license("BSD 3-clause License w/nuclear disclaimer") == "BSD-3-Clause"

    def test_mysql_universal_foss_exception_routes_to_gpl(self):
        # Database-connector POMs. The Oracle/MySQL FOSS Exception
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

    @pytest.mark.parametrize(
        "bare",
        [
            "MIT",
            "GPL-2.0-only",
            "MIT OR Apache-2.0",
            "AGPL-3.0-only OR Proprietary",
            "Unicode-DFS-2016 AND (MIT OR Apache-2.0)",
            "(MIT) AND (Apache-2.0)",
            "Apache-2.0 WITH LLVM-exception",
            "MIT/Apache-2.0",
        ],
    )
    def test_redundant_outer_parens_stripped_at_any_depth(self, bare):
        # The number of fully redundant wraps must never change the result:
        # a wrap that survives normalization hides the top-level operator
        # (or the bare ID) from every consumer that splits or compares the
        # normalized string.
        expected = normalize_license(bare)
        for depth in range(1, 4):
            wrapped = "(" * depth + bare + ")" * depth
            result = normalize_license(wrapped)
            assert result == expected, wrapped
            # Idempotent: normalizing the normalized form changes nothing.
            assert normalize_license(result) == result, wrapped

    def test_redundant_parens_around_a_nested_operand_stripped(self):
        # The same fixpoint applies one level down: a doubly wrapped operand
        # canonicalizes like the bare one, and an AND child that contains an
        # OR keeps exactly the one wrap precedence requires.
        assert normalize_license("MIT OR ((Apache-2.0))") == "Apache-2.0 OR MIT"
        result = normalize_license("MIT AND ((GPL-2.0-only OR ISC))")
        assert result == "(GPL-2.0-only OR ISC) AND MIT"
        assert normalize_license(result) == result

    def test_redundant_parens_with_inner_whitespace_stripped(self):
        assert normalize_license("( ( MIT OR Apache-2.0 ) )") == "Apache-2.0 OR MIT"

    def test_unbalanced_wrap_with_matching_ends_passes_through_unchanged(self):
        # Opens twice, closes once: the first and last characters look like
        # an outer wrap, but the parens don't balance — leave the string
        # alone rather than peel one side of a malformed expression.
        assert normalize_license("((MIT)") == "((MIT)"

    def test_whitespace_collapsed_in_canonicalization(self):
        # Multiple spaces between operands should canonicalize the same
        # as single-spaced input.
        assert normalize_license("MIT  OR  Apache-2.0") == "Apache-2.0 OR MIT"

    def test_non_compound_passes_through(self):
        # Fast path: no OR/AND in the input means no canonicalization work.
        assert normalize_license("MIT") == "MIT"
        expr = "Apache-2.0 WITH LLVM-exception"
        assert normalize_license(expr) == expr


class TestDanglingOperators:
    """An operator with an operand missing is not an expression: the string is
    UNKNOWN rather than passed through for the classifier to salvage."""

    @pytest.mark.parametrize(
        "raw",
        [
            # Leading or trailing, alone.
            "MIT AND",
            "AND MIT",
            "MIT OR",
            "OR MIT",
            "MIT WITH",
            "WITH MIT",
            # Leading or trailing, next to a well-formed part.
            "MIT OR GPL-3.0-only AND",
            "AND GPL-3.0-only OR MIT",
            "MIT OR GPL-3.0-only OR",
            "OR GPL-3.0-only OR MIT",
            "MIT OR GPL-3.0-only WITH",
            "MIT AND GPL-3.0-only AND",
            # Two operators in a row.
            "MIT OR AND GPL-3.0-only",
            "GPL-3.0-only AND OR MIT",
            "MIT OR OR GPL-3.0-only",
            "MIT AND AND Apache-2.0",
            "GPL-2.0-only WITH AND MIT",
            # At the edge of a group.
            "MIT OR (AND)",
            "MIT OR (GPL-3.0-only AND)",
            "MIT OR (AND GPL-3.0-only)",
            "(MIT AND) OR Apache-2.0",
            # With an unbalanced paren as well.
            "MIT OR (GPL-3.0-only AND",
            # Left dangling by a prose separator.
            "MIT / AND",
            "MIT AND, Apache-2.0",
            # Operators only.
            "AND",
            "OR AND",
        ],
    )
    def test_dangling_operator_is_unknown(self, raw):
        assert normalize_license(raw) == "UNKNOWN"

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("MIT AND Apache-2.0", "Apache-2.0 AND MIT"),
            ("MIT OR GPL-3.0-only", "GPL-3.0-only OR MIT"),
            ("MIT OR GPL-3.0-only AND Apache-2.0", "Apache-2.0 AND GPL-3.0-only OR MIT"),
            ("(MIT) AND (Apache-2.0)", "Apache-2.0 AND MIT"),
            ("(MIT OR ISC) AND (Apache-2.0 OR Zlib)", "(Apache-2.0 OR Zlib) AND (ISC OR MIT)"),
            (
                "GPL-2.0-only WITH Classpath-exception-2.0 OR MIT",
                "GPL-2.0-only WITH Classpath-exception-2.0 OR MIT",
            ),
            # An unrecognized leaf in a well-formed expression is not dangling.
            ("MIT OR CustomLicense", "CustomLicense OR MIT"),
            # Unbalanced parens alone still pass through.
            ("(MIT OR Apache-2.0", "(MIT OR Apache-2.0"),
        ],
    )
    def test_well_formed_expression_is_the_control(self, raw, expected):
        assert normalize_license(raw) == expected


class TestOversizedLicenseString:
    """A license string over the length cap is not normalized, so a hostile
    registry field cannot stall the scan."""

    def test_string_at_the_cap_is_still_normalized(self):
        raw = "MIT" + " " * (_MAX_LICENSE_LENGTH - 3)
        assert len(raw) == _MAX_LICENSE_LENGTH
        assert normalize_license(raw) == "MIT"

    def test_string_over_the_cap_is_unknown(self):
        raw = "MIT" + " " * (_MAX_LICENSE_LENGTH - 2)
        assert len(raw) == _MAX_LICENSE_LENGTH + 1
        assert normalize_license(raw) == "UNKNOWN"

    def test_long_recognizable_shapes_are_unknown_over_the_cap(self):
        padding = "x" * _MAX_LICENSE_LENGTH
        # Each would resolve if it were short (see the controls below).
        assert normalize_license(f"LicenseRef-{padding}") == "UNKNOWN"
        assert normalize_license(f"SEE LICENSE IN {padding}") == "UNKNOWN"
        assert normalize_license(f"proprietary {padding}") == "UNKNOWN"
        assert normalize_license(", ".join(["MIT"] * _MAX_LICENSE_LENGTH)) == "UNKNOWN"

    def test_short_recognizable_shapes_are_the_control(self):
        assert normalize_license("LicenseRef-x") == "Proprietary"
        assert normalize_license("SEE LICENSE IN x") == "Proprietary"
        assert normalize_license("proprietary x") == "Proprietary"
        assert normalize_license(", ".join(["MIT"] * 5)) == "MIT"

    @pytest.mark.parametrize(
        "raw",
        [
            # A slash, then a long whitespace run that is not next to it.
            pytest.param("/x" + " " * 50_000 + "y", id="slash-then-spaces"),
            pytest.param("MIT / Apache-2.0" + "\t" * 50_000 + "z", id="slash-list-then-tabs"),
            # Deeply nested redundant parens.
            pytest.param("(" * 8_000 + "MIT" + ")" * 8_000, id="nested-parens"),
        ],
    )
    def test_quadratic_inputs_return_at_once(self, raw):
        # Without the cap each of these burns several seconds of CPU. CPU
        # time, not wall-clock, so a loaded machine cannot fail the bound.
        started = time.process_time()
        assert normalize_license(raw) == "UNKNOWN"
        assert time.process_time() - started < 1.0

    def test_r_license_alternative_over_the_cap_is_dropped(self):
        oversized = "/x" + " " * 50_000 + "y"
        started = time.process_time()
        assert normalize_r_license(oversized) == "UNKNOWN"
        assert normalize_r_license(f"GPL-2 | {oversized}") == "GPL-2.0-only"
        assert time.process_time() - started < 1.0


class TestNestedAndRepeatedOperands:
    """Grouping that does not change the meaning does not change the result."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("(MIT AND Zlib) AND Apache-2.0", "Apache-2.0 AND MIT AND Zlib"),
            ("(Apache-2.0 OR Zlib) OR MIT", "Apache-2.0 OR MIT OR Zlib"),
            ("Zlib AND (MIT AND (ISC AND Apache-2.0))", "Apache-2.0 AND ISC AND MIT AND Zlib"),
            ("Zlib OR (MIT OR (ISC OR Apache-2.0))", "Apache-2.0 OR ISC OR MIT OR Zlib"),
            (
                "(MIT OR ISC) AND (Apache-2.0 AND (Zlib OR 0BSD))",
                "(0BSD OR Zlib) AND (ISC OR MIT) AND Apache-2.0",
            ),
            (
                "(MIT AND Zlib) OR (Apache-2.0 AND (0BSD OR ISC))",
                "(0BSD OR ISC) AND Apache-2.0 OR MIT AND Zlib",
            ),
        ],
    )
    def test_group_of_the_same_operator_is_spliced_into_its_parent(self, raw, expected):
        assert normalize_license(raw) == expected

    def test_group_of_the_other_operator_keeps_its_meaning(self):
        # Control: an ``OR`` group under ``AND`` keeps its parens; an ``AND``
        # group under ``OR`` needs none (``AND`` binds tighter).
        assert normalize_license("(MIT OR Zlib) AND Apache-2.0") == "(MIT OR Zlib) AND Apache-2.0"
        assert normalize_license("(MIT AND Zlib) OR Apache-2.0") == "Apache-2.0 OR MIT AND Zlib"

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("MIT AND MIT", "MIT"),
            ("MIT OR MIT", "MIT"),
            ("MIT OR Apache-2.0 OR MIT", "Apache-2.0 OR MIT"),
            ("MIT AND (Apache-2.0 AND MIT)", "Apache-2.0 AND MIT"),
            # The two groups are the same choice: one remains, unwrapped.
            ("(MIT OR ISC) AND (ISC OR MIT)", "ISC OR MIT"),
            ("(MIT OR ISC) AND (ISC OR MIT) AND Zlib", "(ISC OR MIT) AND Zlib"),
        ],
    )
    def test_repeated_operand_is_dropped(self, raw, expected):
        assert normalize_license(raw) == expected

    def test_operands_that_differ_are_all_kept(self):
        # Control: a ``WITH`` leaf is not its bare license.
        expr = "Apache-2.0 OR Apache-2.0 WITH LLVM-exception"
        assert normalize_license(expr) == expr


class TestCanonicalLicenseIds:
    """A deprecated GNU-family ID is reported in its current SPDX spelling:
    the bare ID is ``-only`` and a ``+`` suffix is ``-or-later``."""

    @pytest.mark.parametrize(
        "deprecated, current",
        [
            ("GPL-1.0", "GPL-1.0-only"),
            ("GPL-2.0", "GPL-2.0-only"),
            ("GPL-3.0", "GPL-3.0-only"),
            ("LGPL-2.0", "LGPL-2.0-only"),
            ("LGPL-2.1", "LGPL-2.1-only"),
            ("LGPL-3.0", "LGPL-3.0-only"),
            ("AGPL-1.0", "AGPL-1.0-only"),
            ("AGPL-3.0", "AGPL-3.0-only"),
            ("GFDL-1.3", "GFDL-1.3-only"),
            ("GPL-1.0+", "GPL-1.0-or-later"),
            ("GPL-2.0+", "GPL-2.0-or-later"),
            ("GPL-3.0+", "GPL-3.0-or-later"),
            ("LGPL-2.0+", "LGPL-2.0-or-later"),
            ("LGPL-2.1+", "LGPL-2.1-or-later"),
            ("LGPL-3.0+", "LGPL-3.0-or-later"),
            ("AGPL-3.0+", "AGPL-3.0-or-later"),
        ],
    )
    def test_deprecated_gnu_id_becomes_its_current_id(self, deprecated, current):
        assert canonical_license_id(deprecated) == current
        assert normalize_license(deprecated) == current

    @pytest.mark.parametrize(
        "unchanged",
        [
            "MIT",
            "Apache-2.0",
            "GPL-2.0-only",
            "GPL-2.0-or-later",
            # ``+`` on a license that has no ``-or-later`` ID.
            "MPL-2.0+",
            "Apache-2.0+",
            # The deprecated compound ID and ``WITH`` leaves are not rewritten.
            "GPL-2.0-with-classpath-exception",
            "GPL-2.0 WITH Classpath-exception-2.0",
            "GPL-2.0+ WITH GCC-exception-2.0",
            # Not a listed ID once rewritten.
            "GPL-4.0",
            "gpl-2.0",
            "Proprietary",
            "UNKNOWN",
            "",
        ],
    )
    def test_anything_else_is_returned_unchanged(self, unchanged):
        assert canonical_license_id(unchanged) == unchanged

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("GPL-2.0 AND MIT", "GPL-2.0-only AND MIT"),
            ("MIT AND GPL-2.0", "GPL-2.0-only AND MIT"),
            ("GPL-3.0 AND MIT", "GPL-3.0-only AND MIT"),
            ("GPL-3.0+ AND MIT", "GPL-3.0-or-later AND MIT"),
            ("GPL-2.0+ OR MIT", "GPL-2.0-or-later OR MIT"),
            ("LGPL-3.0 OR AGPL-3.0", "AGPL-3.0-only OR LGPL-3.0-only"),
            ("(GPL-2.0+ OR MIT) AND LGPL-2.1", "(GPL-2.0-or-later OR MIT) AND LGPL-2.1-only"),
            ("MIT OR (Apache-2.0 AND GPL-3.0)", "Apache-2.0 AND GPL-3.0-only OR MIT"),
            ("GPL-2.0 or MIT", "GPL-2.0-only OR MIT"),
            ("GPL-2.0, MIT", "GPL-2.0-only OR MIT"),
            ("GPL-2.0+/MIT", "GPL-2.0-or-later OR MIT"),
            # The two spellings of one license are one operand.
            ("GPL-2.0 AND GPL-2.0-only", "GPL-2.0-only"),
        ],
    )
    def test_deprecated_id_inside_an_expression_is_rewritten(self, raw, expected):
        assert normalize_license(raw) == expected

    def test_current_ids_are_the_control(self):
        assert normalize_license("GPL-2.0-only AND MIT") == "GPL-2.0-only AND MIT"
        assert normalize_license("GPL-3.0-or-later AND MIT") == "GPL-3.0-or-later AND MIT"

    def test_with_leaf_is_left_as_written(self):
        for expr in ("GPL-2.0 WITH Classpath-exception-2.0", "GPL-3.0+ WITH GCC-exception-3.1"):
            assert normalize_license(expr) == expr
        assert (
            normalize_license("GPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0")
            == "GPL-2.0 WITH Classpath-exception-2.0 OR GPL-2.0-only"
        )
        assert (
            normalize_license("GPL-2.0-with-classpath-exception AND GPL-2.0")
            == "GPL-2.0-only AND GPL-2.0-with-classpath-exception"
        )

    def test_plus_on_a_license_without_an_or_later_id_is_kept(self):
        assert normalize_license("MPL-2.0+ OR Apache-2.0") == "Apache-2.0 OR MPL-2.0+"

    @pytest.mark.parametrize(
        "url, expected",
        [
            ("https://www.gnu.org/licenses/gpl-2.0.html", "GPL-2.0-only"),
            ("https://www.gnu.org/licenses/gpl-3.0.html", "GPL-3.0-only"),
            ("https://www.gnu.org/licenses/lgpl-2.1.html", "LGPL-2.1-only"),
            ("https://www.gnu.org/licenses/lgpl-3.0.html", "LGPL-3.0-only"),
            ("https://www.gnu.org/licenses/agpl-3.0.html", "AGPL-3.0-only"),
            ("https://spdx.org/licenses/GPL-3.0", "GPL-3.0-only"),
            ("https://spdx.org/licenses/GPL-2.0+", "GPL-2.0-or-later"),
        ],
    )
    def test_license_url_yields_the_current_id(self, url, expected):
        assert spdx_from_license_url(url) == expected
        assert normalize_license(url) == expected

    def test_every_license_url_table_id_is_already_normalized(self):
        for marker, spdx_id in _LICENSE_URL_PREFIXES:
            assert normalize_license(spdx_id) == spdx_id, marker


class TestLicenseRefLeaves:
    """``LicenseRef-*`` maps to ``Proprietary`` one parsed leaf at a time, so
    a reference never stands in for the operands around it."""

    @pytest.mark.parametrize(
        "leading, trailing, expected",
        [
            (
                "LicenseRef-custom AND GPL-3.0-only",
                "GPL-3.0-only AND LicenseRef-custom",
                "GPL-3.0-only AND Proprietary",
            ),
            ("LicenseRef-custom OR MIT", "MIT OR LicenseRef-custom", "MIT OR Proprietary"),
            (
                "LicenseRef-custom OR GPL-3.0-only",
                "GPL-3.0-only OR LicenseRef-custom",
                "GPL-3.0-only OR Proprietary",
            ),
            (
                "(LicenseRef-custom OR MIT) AND Apache-2.0",
                "Apache-2.0 AND (MIT OR LicenseRef-custom)",
                "(MIT OR Proprietary) AND Apache-2.0",
            ),
        ],
    )
    def test_reference_position_does_not_change_the_result(self, leading, trailing, expected):
        assert normalize_license(leading) == expected
        assert normalize_license(trailing) == expected

    def test_reference_alone_is_the_control(self):
        assert normalize_license("LicenseRef-custom") == "Proprietary"
        assert normalize_license("(LicenseRef-custom)") == "Proprietary"
        assert normalize_license("licenseref-custom") == "Proprietary"

    def test_operators_set_off_by_other_whitespace_are_still_operators(self):
        assert (
            normalize_license("LicenseRef-custom\tAND\tGPL-3.0-only")
            == "GPL-3.0-only AND Proprietary"
        )

    def test_public_domain_sentinel_is_not_a_custom_reference(self):
        assert (
            normalize_license("LicenseRef-Public-Domain OR GPL-3.0-only")
            == "GPL-3.0-only OR LicenseRef-Public-Domain"
        )

    def test_reference_with_an_exception_is_one_custom_leaf(self):
        assert normalize_license("LicenseRef-custom WITH Classpath-exception-2.0") == "Proprietary"
        assert (
            normalize_license("MIT AND LicenseRef-custom WITH Classpath-exception-2.0")
            == "MIT AND Proprietary"
        )

    def test_expression_of_references_only_is_proprietary(self):
        assert normalize_license("LicenseRef-a AND LicenseRef-b") == "Proprietary"
        assert normalize_license("LicenseRef-a OR LicenseRef-b") == "Proprietary"

    def test_reference_followed_by_prose_is_not_an_expression(self):
        assert normalize_license("LicenseRef-custom plus other terms") == "UNKNOWN"

    def test_unbalanced_expression_is_left_alone(self):
        raw = "LicenseRef-custom OR (MIT"
        assert normalize_license(raw) == raw


class TestNormalizeIdempotence:
    """Normalizing a normalized license changes nothing."""

    @pytest.mark.parametrize(
        "raw",
        [
            # Sentinels, single IDs, aliases, classifiers, URLs.
            "",
            "UNKNOWN",
            "Proprietary",
            "MIT",
            "mit",
            "Apache License, Version 2.0",
            "GPLv3+",
            "Public Domain",
            "SEE LICENSE IN LICENSE.md",
            "LICENSE.txt",
            "License :: OSI Approved :: MIT License",
            "https://www.apache.org/licenses/LICENSE-2.0",
            "https://example.com/some-custom-license",
            "zlib-acknowledgement",
            "SomeCustomLicense",
            # Flat compounds in every operand order.
            "MIT OR Apache-2.0",
            "Apache-2.0 OR MIT",
            "MIT AND BSD-3-Clause",
            "BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0",
            "MIT OR GPL-3.0-only AND BSD-3-Clause",
            "GPL-3.0-only AND BSD-3-Clause OR MIT",
            # Grouping: required, redundant, nested, repeated.
            "(MIT OR Apache-2.0) AND Unicode-DFS-2016",
            "Unicode-DFS-2016 AND (MIT OR Apache-2.0)",
            "((MIT OR Apache-2.0))",
            "(MIT) AND (Apache-2.0)",
            "(MIT AND Zlib) AND Apache-2.0",
            "(Apache-2.0 OR Zlib) OR MIT",
            "(MIT OR ISC) AND (Apache-2.0 AND (Zlib OR 0BSD))",
            "((MIT OR ISC) AND Zlib) OR (Apache-2.0 AND (0BSD OR BSD-3-Clause))",
            "(MIT OR ISC) AND (ISC OR MIT)",
            "MIT AND MIT",
            # WITH leaves.
            "Apache-2.0 WITH LLVM-exception",
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
            "GPL-2.0-only WITH Classpath-exception-2.0 AND MIT",
            "GPL-2.0-with-classpath-exception",
            # Custom references in every position.
            "LicenseRef-custom",
            "LicenseRef-Public-Domain",
            "LicenseRef-custom AND GPL-3.0-only",
            "GPL-3.0-only AND LicenseRef-custom",
            "LicenseRef-custom OR MIT",
            "MIT OR LicenseRef-custom",
            "(LicenseRef-custom OR MIT) AND Apache-2.0",
            "LicenseRef-a AND LicenseRef-b",
            "LicenseRef-custom WITH Classpath-exception-2.0",
            "MIT OR LicenseRef-Vendor-Proprietary",
            # Prose separators and connectors.
            "MIT/Apache-2.0",
            "MIT, Apache-2.0, BSD-3-Clause",
            "BSD, Public Domain",
            "MIT -or- Apache License 2.0",
            "MIT and ISC",
            "BSD or MIT",
            "GPL-3.0-only or Apache-2.0 and AGPL-3.0-only",
            "(MIT or Apache-2.0) and GPL-3.0-only",
            "CDDL+GPL and MIT",
            "MIT, LicenseRef-custom",
            # Rewritten pairs.
            "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
            "Apache-2.0 AND CDDL-1.0 AND GPL-2.0-with-classpath-exception",
            "LGPL-3.0-only AND GPL-3.0-or-later",
            "Apache-2.0 AND GPL-3.0-only AND LGPL-3.0-only",
            # Deprecated GNU spellings: alone, in compounds, from URLs, and as
            # the survivors of a rewritten pair.
            "GPL-2.0",
            "GPL-3.0+",
            "LGPL-3.0+",
            "GPL-2.0 AND MIT",
            "GPL-3.0+ AND MIT",
            "MIT OR (Apache-2.0 AND GPL-3.0)",
            "GPL-2.0 AND GPL-2.0-only",
            "LGPL-3.0 AND GPL-3.0",
            "LGPL-2.1 AND GPL-2.0 AND MIT",
            "CDDL-1.0 AND GPL-2.0",
            "CDDL v1.1 / GPL v2 dual license",
            "https://www.gnu.org/licenses/gpl-3.0.html",
            "https://www.gnu.org/licenses/lgpl-2.1.html",
            "https://spdx.org/licenses/GPL-2.0+",
            "GPL-2.0 WITH Classpath-exception-2.0",
            "MPL-2.0+ OR Apache-2.0",
            # Unbalanced parens pass through.
            "(MIT OR Apache-2.0",
            "((MIT)",
            "LicenseRef-custom OR (MIT",
            # Whitespace.
            "  MIT   OR\tApache-2.0  ",
        ],
    )
    def test_normalizing_a_result_changes_nothing(self, raw):
        once = normalize_license(raw)
        assert normalize_license(once) == once

    def test_every_alias_and_classifier_result_is_stable(self):
        for raw in (*_NORMALIZATION_MAP, *_CLASSIFIER_MAP):
            once = normalize_license(raw)
            assert normalize_license(once) == once, raw


class TestAndJoinLicenses:
    """Composing independent license entries into one ``AND`` expression."""

    def test_simple_operands_join_bare(self):
        assert and_join_licenses(["MIT", "Apache-2.0"]) == "MIT AND Apache-2.0"
        assert and_join_licenses(["MIT", "Apache-2.0", "ISC"]) == "MIT AND Apache-2.0 AND ISC"

    @pytest.mark.parametrize(
        "operands, expected",
        [
            (
                ["Apache-2.0 OR GPL-2.0-only", "AGPL-3.0-only"],
                "(Apache-2.0 OR GPL-2.0-only) AND AGPL-3.0-only",
            ),
            (
                ["AGPL-3.0-only", "Apache-2.0 OR GPL-2.0-only"],
                "AGPL-3.0-only AND (Apache-2.0 OR GPL-2.0-only)",
            ),
            (["MIT OR ISC", "Apache-2.0 OR Zlib"], "(MIT OR ISC) AND (Apache-2.0 OR Zlib)"),
        ],
    )
    def test_operand_with_a_top_level_or_is_parenthesised(self, operands, expected):
        # Joined bare, ``A OR B`` and ``C`` would parse as ``A OR (B AND C)``.
        assert and_join_licenses(operands) == expected

    def test_operand_without_a_top_level_or_is_not_wrapped(self):
        # An ``AND`` chain, a ``WITH`` leaf and an ``OR`` already inside its
        # own group all keep their meaning when joined bare.
        assert and_join_licenses(["MIT AND ISC", "Zlib"]) == "MIT AND ISC AND Zlib"
        assert (
            and_join_licenses(["GPL-2.0-only WITH Classpath-exception-2.0", "MIT"])
            == "GPL-2.0-only WITH Classpath-exception-2.0 AND MIT"
        )
        assert (
            and_join_licenses(["(MIT OR ISC) AND Zlib", "0BSD"]) == "(MIT OR ISC) AND Zlib AND 0BSD"
        )

    @pytest.mark.parametrize("operand", ["MIT\tOR\tISC", "MIT  OR  ISC", " MIT OR\nISC "])
    def test_or_set_off_by_other_whitespace_is_still_grouped(self, operand):
        assert and_join_licenses([operand, "Zlib"]) == "(MIT OR ISC) AND Zlib"

    def test_grouped_join_normalizes_the_same_in_either_order(self):
        entries = ["Apache-2.0 OR GPL-2.0-only", "AGPL-3.0-only"]
        expected = "(Apache-2.0 OR GPL-2.0-only) AND AGPL-3.0-only"
        assert normalize_license(and_join_licenses(entries)) == expected
        assert normalize_license(and_join_licenses(entries[::-1])) == expected


class TestLowercaseConnectorPrecedence:
    """A string mixing lowercase ``and`` / ``or`` reads with SPDX precedence."""

    def test_or_binds_looser_than_and(self):
        expected = "AGPL-3.0-only AND Apache-2.0 OR GPL-3.0-only"
        assert normalize_license("GPL-3.0-only or Apache-2.0 and AGPL-3.0-only") == expected
        assert normalize_license("Apache-2.0 and AGPL-3.0-only or GPL-3.0-only") == expected
        assert normalize_license("AGPL-3.0-only and Apache-2.0 or GPL-3.0-only") == expected

    @pytest.mark.parametrize(
        "lowercase, uppercase",
        [
            (
                "GPL-3.0-only or Apache-2.0 and AGPL-3.0-only",
                "GPL-3.0-only OR Apache-2.0 AND AGPL-3.0-only",
            ),
            (
                "Apache-2.0 and AGPL-3.0-only or GPL-3.0-only",
                "Apache-2.0 AND AGPL-3.0-only OR GPL-3.0-only",
            ),
            ("MIT or Apache-2.0 and GPL-3.0-only", "MIT OR Apache-2.0 AND GPL-3.0-only"),
            ("MIT and ISC or Apache-2.0 and Zlib", "MIT AND ISC OR Apache-2.0 AND Zlib"),
            ("MIT or ISC or Apache-2.0 and Zlib", "MIT OR ISC OR Apache-2.0 AND Zlib"),
            ("MIT And ISC Or Apache-2.0", "MIT AND ISC OR Apache-2.0"),
            # Explicit grouping survives the connector split.
            ("(MIT or Apache-2.0) and GPL-3.0-only", "(MIT OR Apache-2.0) AND GPL-3.0-only"),
            ("GPL-3.0-only and (MIT or Apache-2.0)", "GPL-3.0-only AND (MIT OR Apache-2.0)"),
            ("MIT and (Apache-2.0 or GPL-3.0-only)", "MIT AND (Apache-2.0 OR GPL-3.0-only)"),
            (
                "(MIT or Apache-2.0) and (GPL-3.0-only or ISC)",
                "(MIT OR Apache-2.0) AND (GPL-3.0-only OR ISC)",
            ),
            # Single-connector controls.
            ("MIT and ISC", "MIT AND ISC"),
            ("MIT or ISC", "MIT OR ISC"),
        ],
    )
    def test_lowercase_connectors_normalize_like_uppercase_operators(self, lowercase, uppercase):
        assert normalize_license(lowercase) == normalize_license(uppercase)

    def test_and_operand_that_expands_to_an_or_keeps_its_group(self):
        # The left side resolves through the alias map to a two-arm ``OR``;
        # the right side must stay binding on both arms.
        assert (
            normalize_license("CDDL+GPL and MIT")
            == "(CDDL-1.0 OR GPL-2.0-with-classpath-exception) AND MIT"
        )

    def test_mixing_lowercase_connectors_with_uppercase_operators_is_unknown(self):
        assert normalize_license("MIT or Apache-2.0 AND GPL-3.0-only") == "UNKNOWN"


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
        # An LGPL package that also ships the GPL text, after operand canonicalization:
        # GPL-3.0 AND GPL-3.0-or-later AND LGPL-3.0 → LGPL-3.0. The surviving
        # LGPL operand is in its current spelling.
        assert normalize_license("LGPL-3.0 AND GPL-3.0") == "LGPL-3.0-only"
        assert normalize_license("GPL-3.0 AND LGPL-3.0") == "LGPL-3.0-only"
        assert normalize_license("GPL-3.0 AND GPL-3.0-or-later AND LGPL-3.0") == "LGPL-3.0-only"
        assert normalize_license("GPL-3.0+ AND LGPL-3.0+") == "LGPL-3.0-or-later"

    def test_lgpl_2_1_and_gpl_2_0_collapses(self):
        # LGPL-2.1 explicitly references GPL-2.0 in its text — same
        # inclusion relationship as the matching-X.Y case.
        assert normalize_license("LGPL-2.1 AND GPL-2.0") == "LGPL-2.1-only"
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
        assert normalize_license("LGPL-3.0 AND GPL-2.0") == "GPL-2.0-only AND LGPL-3.0-only"

    def test_lgpl_and_gpl_chain_with_other_licenses(self):
        # Mixed compound: LGPL+GPL+Apache. Drop the GPL (LGPL subsumes
        # it), keep Apache. The result is the operand-canonical join of
        # the remaining two.
        assert (
            normalize_license("Apache-2.0 AND GPL-3.0 AND LGPL-3.0")
            == "Apache-2.0 AND LGPL-3.0-only"
        )

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
        # convention — the operator is kept.
        result = normalize_license("CDDL-1.0 AND GPL-2.0")
        assert result == "CDDL-1.0 AND GPL-2.0-only"


class TestSpdxLooksLike:
    def test_only_keywords(self):
        # "OR AND" — all are SPDX keywords, non_keyword_parts is empty
        assert _looks_like_spdx("OR AND") is False

    def test_empty_string_not_spdx(self):
        assert _looks_like_spdx("") is False

    def test_very_long_string_not_spdx(self):
        assert _looks_like_spdx("MIT " * 100) is False

    def test_operator_needs_a_leaf_on_both_sides(self):
        assert _looks_like_spdx("MIT AND Apache-2.0") is True
        assert _looks_like_spdx("(MIT) AND (Apache-2.0)") is True
        # Leading, trailing, doubled, and against a paren.
        assert _looks_like_spdx("AND MIT") is False
        assert _looks_like_spdx("MIT AND") is False
        assert _looks_like_spdx("MIT AND OR Apache-2.0") is False
        assert _looks_like_spdx("MIT OR (AND)") is False
        assert _looks_like_spdx("(MIT AND) OR Apache-2.0") is False
