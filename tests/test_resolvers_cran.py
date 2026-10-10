"""Tests for the R / CRAN resolver (official ``PACKAGES`` index)."""

from __future__ import annotations

import textwrap

import httpx
import pytest
import respx

from licenseal.analysis.compatibility import check_compatibility
from licenseal.models import CompatibilityVerdict, Dependency, Ecosystem
from licenseal.resolvers.cran import (
    _CRAN_INDEX_URL,
    _extract_pinned_version,
    fetch_cran_index,
    index_edge_names,
    resolve_r_license,
)
from licenseal.resolvers.http import RegistryCache

# A small CRAN ``PACKAGES`` index (DCF), same shape as the real one — including a
# continuation-wrapped field, base-package edges (filtered), and the license
# grammars licenseal must translate.
_INDEX_DCF = textwrap.dedent(
    """\
    Package: dplyr
    Version: 1.2.1
    Depends: R (>= 4.1.0)
    Imports: cli (>= 3.6.2), generics, methods, rlang (>=
            1.1.7)
    Suggests: testthat (>= 3.1.5), knitr
    License: MIT + file LICENSE
    MD5sum: deadbeef

    Package: cli
    Version: 3.6.6
    Imports: utils
    License: MIT + file LICENSE

    Package: rlang
    Version: 1.2.0
    License: MIT + file LICENSE

    Package: generics
    Version: 0.1.4
    License: MIT + file LICENSE

    Package: knitr
    Version: 1.50
    License: GPL-2 | GPL-3

    Package: KernSmooth
    Version: 2.23-26
    License: Unlimited

    Package: Rtsne
    Version: 0.17
    License: file LICENSE

    Package: nolic
    Version: 1.0
    """
)


def _r_dep(name: str, version: str = "", source: str = "") -> Dependency:
    return Dependency(name=name, version_constraint=version, ecosystem=Ecosystem.R, source=source)


def _index() -> dict:
    with httpx.Client() as client:
        return fetch_cran_index(client, fetcher=lambda url, c: {"text": _INDEX_DCF})


class TestExtractPinnedVersion:
    def test_double_equals(self):
        assert _extract_pinned_version("==2.0.0") == "2.0.0"

    def test_hyphenated_version(self):
        assert _extract_pinned_version("==1.6-1") == "1.6-1"

    def test_range_returns_none(self):
        assert _extract_pinned_version(">= 1.0") is None
        assert _extract_pinned_version("*") is None

    def test_multi_empty_space_return_none(self):
        assert _extract_pinned_version(">= 1.0, < 2.0") is None
        assert _extract_pinned_version("") is None
        assert _extract_pinned_version("==") is None
        assert _extract_pinned_version("==1 0") is None


class TestFetchCranIndex:
    def test_parses_records(self):
        idx = _index()
        assert set(idx) >= {"dplyr", "cli", "rlang", "knitr"}
        assert idx["dplyr"]["Version"] == "1.2.1"
        assert idx["dplyr"]["License"] == "MIT + file LICENSE"
        # Continuation line joined into the Imports value.
        assert "rlang (>= 1.1.7)" in idx["dplyr"]["Imports"]

    def test_non_dict_response(self):
        with httpx.Client() as client:
            assert fetch_cran_index(client, fetcher=lambda url, c: None) == {}

    def test_empty_or_non_string_text(self):
        with httpx.Client() as client:
            assert fetch_cran_index(client, fetcher=lambda url, c: {"text": ""}) == {}
            assert fetch_cran_index(client, fetcher=lambda url, c: {"text": 123}) == {}

    def test_record_without_package_skipped(self):
        # A leading non-package DCF record (no ``Package`` field) is ignored.
        dcf = "Foo: bar\n\nPackage: cli\nVersion: 1.0\nLicense: MIT\n"
        with httpx.Client() as client:
            idx = fetch_cran_index(client, fetcher=lambda url, c: {"text": dcf})
        assert set(idx) == {"cli"}

    @respx.mock
    def test_through_registry_cache(self):
        # End-to-end via RegistryCache.fetch_text (the production text path).
        respx.get(_CRAN_INDEX_URL).mock(return_value=httpx.Response(200, text=_INDEX_DCF))
        cache = RegistryCache()
        with httpx.Client() as client:
            idx = fetch_cran_index(client, fetcher=cache.fetch_text)
        assert idx["dplyr"]["License"] == "MIT + file LICENSE"


class TestIndexEdgeNames:
    def test_prod_edges_filter_base(self):
        # dplyr: Depends R (base) + Imports cli/generics/methods(base)/rlang.
        assert index_edge_names(_index()["dplyr"]) == ["cli", "generics", "rlang"]

    def test_suggests_not_followed(self):
        edges = index_edge_names(_index()["dplyr"])
        assert "testthat" not in edges and "knitr" not in edges

    def test_dedup_and_no_edge_fields(self):
        assert index_edge_names({"Imports": "cli, cli"}) == ["cli"]
        assert index_edge_names({"License": "MIT"}) == []


class TestResolveRLicense:
    def test_in_index_license_and_pinned_version(self):
        info = resolve_r_license(_r_dep("dplyr", "==1.2.1"), _index())
        assert info.license_id == "MIT"
        assert info.license_raw == "MIT + file LICENSE"
        assert info.resolved_version == "1.2.1"
        assert info.from_registry is True

    def test_unpinned_uses_index_version(self):
        info = resolve_r_license(_r_dep("cli", ">= 1.0"), _index())
        assert info.resolved_version == "3.6.6"  # index's current version

    def test_grammar_translations(self):
        idx = _index()
        assert resolve_r_license(_r_dep("knitr"), idx).license_id == "GPL-2.0-only OR GPL-3.0-only"
        assert resolve_r_license(_r_dep("KernSmooth"), idx).license_id == "UNKNOWN"  # Unlimited
        assert resolve_r_license(_r_dep("Rtsne"), idx).license_id == "UNKNOWN"  # file LICENSE

    def test_missing_license_field_unknown(self):
        info = resolve_r_license(_r_dep("nolic"), _index())
        assert info.license_id == "UNKNOWN"
        assert info.license_raw == ""
        assert info.from_registry is True

    @staticmethod
    def _resolve_declared(declared: str):
        """Resolve a package whose index record declares ``declared``, through the cache."""
        respx.get(_CRAN_INDEX_URL).mock(
            return_value=httpx.Response(
                200, text=f"Package: pkg\nVersion: 1.0\nLicense: {declared}\n"
            )
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            index = fetch_cran_index(client, fetcher=cache.fetch_text)
        return resolve_r_license(_r_dep("pkg"), index)

    @pytest.mark.parametrize(
        "declared, license_id, verdict",
        [
            # The file is the template CRAN requires for these: no extra terms.
            ("MIT + file LICENSE", "MIT", CompatibilityVerdict.COMPATIBLE),
            ("BSD_2_clause + file LICENSE", "BSD-2-Clause", CompatibilityVerdict.COMPATIBLE),
            ("BSD_3_clause + file LICENCE", "BSD-3-Clause", CompatibilityVerdict.COMPATIBLE),
            # On any other license the file adds terms nobody read.
            (
                "Apache License (== 2.0) + file LICENSE",
                "Apache-2.0 AND UNKNOWN",
                CompatibilityVerdict.UNKNOWN,
            ),
            (
                "LGPL (>= 2.1) + file LICENSE",
                "LGPL-2.1-or-later AND UNKNOWN",
                CompatibilityVerdict.UNKNOWN,
            ),
            (
                "Artistic-2.0 + file LICENSE",
                "Artistic-2.0 AND UNKNOWN",
                CompatibilityVerdict.UNKNOWN,
            ),
            # A license that is a violation by itself stays one.
            ("GPL-3 + file LICENSE", "GPL-3.0-only AND UNKNOWN", CompatibilityVerdict.INCOMPATIBLE),
            (
                "AGPL (>= 3) + file LICENSE",
                "AGPL-3.0-or-later AND UNKNOWN",
                CompatibilityVerdict.INCOMPATIBLE,
            ),
            # Controls: the same licenses without the file.
            ("Apache License (== 2.0)", "Apache-2.0", CompatibilityVerdict.COMPATIBLE),
            ("GPL-3", "GPL-3.0-only", CompatibilityVerdict.INCOMPATIBLE),
            # An alternative without extra terms is still electable.
            (
                "Apache License (== 2.0) + file LICENSE | MIT + file LICENSE",
                "Apache-2.0 AND UNKNOWN OR MIT",
                CompatibilityVerdict.COMPATIBLE,
            ),
            (
                "LGPL-3 + file LICENSE | Artistic-2.0 + file LICENSE",
                "Artistic-2.0 AND UNKNOWN OR LGPL-3.0-only AND UNKNOWN",
                CompatibilityVerdict.UNKNOWN,
            ),
            # Nothing named before the file: opaque, as before.
            ("file LICENSE", "UNKNOWN", CompatibilityVerdict.UNKNOWN),
            ("Unlimited + file LICENSE", "UNKNOWN", CompatibilityVerdict.UNKNOWN),
        ],
    )
    @respx.mock
    def test_file_license_terms_on_a_dependency(self, declared, license_id, verdict):
        info = self._resolve_declared(declared)
        assert info.license_id == license_id
        assert info.license_raw == declared
        assert check_compatibility("MIT", info).verdict == verdict

    @respx.mock
    def test_file_license_terms_route_a_compatible_license_to_review(self):
        # GPL-3.0-only alone suits a GPL-3.0-only project; the unread terms
        # beside it still have to be reviewed.
        info = self._resolve_declared("GPL-3 + file LICENSE")
        result = check_compatibility("GPL-3.0-only", info)
        assert result.verdict == CompatibilityVerdict.UNKNOWN
        assert result.reason == (
            "pkg uses GPL-3.0-only AND UNKNOWN; the consumer cannot avoid UNKNOWN, which "
            "did not resolve to a recognized license — manual review required"
        )

    def test_not_in_index_unknown(self):
        info = resolve_r_license(_r_dep("nonexistent"), _index())
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False
