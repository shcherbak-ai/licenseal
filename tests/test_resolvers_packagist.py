"""Tests for the Packagist license resolver."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.http import (
    _PACKAGIST_VERSION_KEEP,
    RegistryCache,
    _trim_for_cache,
    _trim_packagist,
)
from licenseal.resolvers.packagist import (
    _extract_homepage_url,
    _extract_pinned_version,
    _extract_repository_url,
    _license_field_to_raw,
    _normalize_repository_url,
    _packagist_url,
    _select_version_entry,
    _versions_from_response,
    fetch_packagist_dependencies,
    resolve_php_license,
)
from licenseal.resolvers.version_selection import select_php_version

_FIXTURES = Path(__file__).parent / "fixtures" / "registry-responses" / "packagist"


def _php_dep(
    name: str = "monolog/monolog",
    version: str = "==3.5.0",
    group: DependencyGroup = DependencyGroup.PROD,
) -> Dependency:
    return Dependency(name=name, version_constraint=version, ecosystem=Ecosystem.PHP, group=group)


# ---------------------------------------------------------------------------
# _extract_pinned_version
# ---------------------------------------------------------------------------


class TestExtractPinnedVersion:
    def test_double_equals_form(self):
        assert _extract_pinned_version("==3.5.0") == "3.5.0"

    def test_v_prefix_stripped(self):
        # ``v3.5.0`` and ``3.5.0`` denote the same Composer release; the
        # pinned extractor returns the canonical (un-prefixed) form so
        # the lockfile-license map lookup is shape-stable.
        assert _extract_pinned_version("==v3.5.0") == "3.5.0"

    def test_unpinned_range_returns_none(self):
        assert _extract_pinned_version("^3.0") is None
        assert _extract_pinned_version("~3.5") is None
        assert _extract_pinned_version("3.*") is None
        assert _extract_pinned_version(">=3.0 <4.0") is None

    def test_or_constraint_returns_none(self):
        assert _extract_pinned_version("^2.0 || ^3.0") is None

    def test_dev_branch_returns_none(self):
        # Bare ``dev-main`` is not pinned in licenseal's internal sense
        # (no ``==`` prefix); resolver picks latest stable instead.
        assert _extract_pinned_version("dev-main") is None

    def test_empty_returns_none(self):
        assert _extract_pinned_version("") is None
        assert _extract_pinned_version("==") is None


# ---------------------------------------------------------------------------
# _normalize_repository_url
# ---------------------------------------------------------------------------


class TestNormalizeRepositoryUrl:
    def test_github_https_dotgit_stripped(self):
        assert (
            _normalize_repository_url("https://github.com/Seldaek/monolog.git")
            == "https://github.com/Seldaek/monolog"
        )

    def test_github_ssh_rewritten_to_https(self):
        assert (
            _normalize_repository_url("git@github.com:Seldaek/monolog.git")
            == "https://github.com/Seldaek/monolog"
        )

    def test_gitlab_ssh_rewritten(self):
        assert (
            _normalize_repository_url("git@gitlab.com:group/project.git")
            == "https://gitlab.com/group/project"
        )

    def test_bitbucket_ssh_rewritten(self):
        assert (
            _normalize_repository_url("git@bitbucket.org:team/repo.git")
            == "https://bitbucket.org/team/repo"
        )

    def test_git_plus_prefix_stripped(self):
        assert (
            _normalize_repository_url("git+https://github.com/x/y.git") == "https://github.com/x/y"
        )

    def test_git_scheme_rewritten_to_https(self):
        assert _normalize_repository_url("git://github.com/x/y.git") == "https://github.com/x/y"

    def test_fragment_stripped(self):
        assert (
            _normalize_repository_url("https://github.com/x/y.git#tag") == "https://github.com/x/y"
        )

    def test_empty_returns_empty(self):
        assert _normalize_repository_url("") == ""
        assert _normalize_repository_url("   ") == ""


# ---------------------------------------------------------------------------
# _packagist_url
# ---------------------------------------------------------------------------


class TestPackagistUrl:
    def test_lowercased(self):
        assert (
            _packagist_url("Monolog/Monolog")
            == "https://repo.packagist.org/p2/monolog/monolog.json"
        )


# ---------------------------------------------------------------------------
# _extract_repository_url / _extract_homepage_url / _license_field_to_raw
# (defensive type-check branches)
# ---------------------------------------------------------------------------


class TestExtractRepositoryUrl:
    def test_extracts_normalized_url(self):
        entry = {"source": {"type": "git", "url": "git@github.com:x/y.git"}}
        assert _extract_repository_url(entry) == "https://github.com/x/y"

    def test_non_dict_source_returns_empty(self):
        assert _extract_repository_url({"source": "not-a-dict"}) == ""

    def test_non_string_url_returns_empty(self):
        assert _extract_repository_url({"source": {"url": None}}) == ""

    def test_missing_source_returns_empty(self):
        assert _extract_repository_url({}) == ""


class TestExtractHomepageUrl:
    def test_extracts_normalized(self):
        assert _extract_homepage_url({"homepage": "https://example.com/"}) == "https://example.com/"

    def test_blank_homepage_returns_empty(self):
        assert _extract_homepage_url({"homepage": "   "}) == ""

    def test_missing_homepage_returns_empty(self):
        assert _extract_homepage_url({}) == ""

    def test_non_string_homepage_returns_empty(self):
        assert _extract_homepage_url({"homepage": 42}) == ""


class TestLicenseFieldToRaw:
    def test_bare_string(self):
        assert _license_field_to_raw("MIT") == "MIT"

    def test_single_entry_array(self):
        assert _license_field_to_raw(["Apache-2.0"]) == "Apache-2.0"

    def test_multi_entry_array_joined(self):
        assert _license_field_to_raw(["MIT", "Apache-2.0"]) == "MIT OR Apache-2.0"

    def test_empty_array_returns_empty(self):
        assert _license_field_to_raw([]) == ""

    def test_array_with_only_blanks_returns_empty(self):
        assert _license_field_to_raw(["", "  "]) == ""

    def test_unsupported_type_returns_empty(self):
        assert _license_field_to_raw(None) == ""
        assert _license_field_to_raw({"x": 1}) == ""


# ---------------------------------------------------------------------------
# _select_version_entry — fallback branches
# ---------------------------------------------------------------------------


class TestSelectVersionEntry:
    def test_empty_entries_returns_none(self):
        assert _select_version_entry([], "^1.0", None) is None

    def test_pinned_no_match_falls_back_to_first(self):
        # Pinned ``==9.9.9`` against entries that don't include 9.9.9 — the
        # selector returns the first (highest) entry as a best-effort.
        entries = [{"version": "3.5.0"}, {"version": "2.9.0"}]
        assert _select_version_entry(entries, "==9.9.9", "9.9.9") == entries[0]

    def test_empty_spec_returns_first(self):
        entries = [{"version": "3.5.0"}, {"version": "2.9.0"}]
        assert _select_version_entry(entries, "", None) == entries[0]

    def test_unparseable_range_falls_back_to_first(self):
        # ``dev-main`` isn't a published-version range — selector hits the
        # fall-through-to-first path.
        entries = [{"version": "3.5.0"}, {"version": "2.9.0"}]
        assert _select_version_entry(entries, "dev-main", None) == entries[0]

    def test_pinned_matches_via_version_normalized_fallback(self):
        # Entry only carries ``version_normalized`` (the 4-segment form).
        entries = [{"version_normalized": "3.5.0.0"}]
        assert _select_version_entry(entries, "==3.5.0.0", "3.5.0.0") == entries[0]

    def test_range_picks_match(self):
        entries = [{"version": "3.5.0"}, {"version": "2.9.0"}]
        # ``^3.0`` matches 3.5.0.
        assert _select_version_entry(entries, "^3.0", None) == entries[0]

    def test_range_no_match_falls_back_to_first(self):
        # ``^4.0`` against entries that only have ``<4.0`` versions —
        # selector returns first entry as best-effort.
        entries = [{"version": "3.5.0"}, {"version": "2.9.0"}]
        assert _select_version_entry(entries, "^4.0", None) == entries[0]

    def test_published_skips_non_string_versions(self):
        # Defensive: skip entries with non-string ``version`` when building
        # the published-versions list for the range selector.
        entries = [{"version": None}, {"version": "3.5.0"}]
        assert _select_version_entry(entries, "^3.0", None) == entries[1]


# ---------------------------------------------------------------------------
# _versions_from_response
# ---------------------------------------------------------------------------


class TestVersionsFromResponse:
    def test_extracts_descending_list(self):
        data = json.loads((_FIXTURES / "monolog" / "monolog.json").read_text())
        entries = _versions_from_response(data, "monolog/monolog")
        assert [e["version"] for e in entries] == ["3.5.0", "2.9.0"]

    def test_missing_package_returns_empty(self):
        assert _versions_from_response({"packages": {}}, "monolog/monolog") == []

    def test_lowercase_lookup(self):
        # Packagist is case-insensitive; lookup uses lowercase.
        data = json.loads((_FIXTURES / "monolog" / "monolog.json").read_text())
        entries = _versions_from_response(data, "Monolog/Monolog")
        assert len(entries) == 2

    def test_non_dict_packages_returns_empty(self):
        assert _versions_from_response({"packages": []}, "x/y") == []


# ---------------------------------------------------------------------------
# resolve_php_license — lockfile-first path
# ---------------------------------------------------------------------------


class TestResolveLockfileFirst:
    def test_lockfile_hit_returns_without_http(self):
        # Critical regression test: a lockfile hit MUST NOT trigger any
        # HTTP fetch. We assert this by counting respx route matches.
        route = respx.routes
        with respx.mock(assert_all_called=False) as mock:
            packagist_route = mock.get(_packagist_url("monolog/monolog"))
            dep = _php_dep("monolog/monolog", "==3.5.0")
            lockfile_map = {("monolog/monolog", "3.5.0"): "MIT"}
            with httpx.Client() as client:
                info = resolve_php_license(dep, client, lockfile_license_map=lockfile_map)
            assert info.license_id == "MIT"
            assert info.license_raw == "MIT"
            assert info.resolved_version == "3.5.0"
            assert info.from_registry is True
            assert packagist_route.call_count == 0
        # Silence "unused" — accessing routes inside the with-block.
        _ = route

    def test_empty_lockfile_entry_falls_back_to_packagist(self):
        with respx.mock as mock:
            mock.get(_packagist_url("monolog/monolog")).mock(
                return_value=httpx.Response(
                    200,
                    json=json.loads((_FIXTURES / "monolog" / "monolog.json").read_text()),
                )
            )
            dep = _php_dep("monolog/monolog", "==3.5.0")
            lockfile_map = {("monolog/monolog", "3.5.0"): ""}
            with httpx.Client() as client:
                info = resolve_php_license(dep, client, lockfile_license_map=lockfile_map)
            assert info.license_id == "MIT"
            assert info.from_registry is True

    def test_no_lockfile_map_falls_through(self):
        with respx.mock as mock:
            mock.get(_packagist_url("monolog/monolog")).mock(
                return_value=httpx.Response(
                    200,
                    json=json.loads((_FIXTURES / "monolog" / "monolog.json").read_text()),
                )
            )
            dep = _php_dep("monolog/monolog", "==3.5.0")
            with httpx.Client() as client:
                info = resolve_php_license(dep, client)
            assert info.license_id == "MIT"
            assert info.resolved_version == "3.5.0"
            assert info.repository_url == "https://github.com/Seldaek/monolog"


# ---------------------------------------------------------------------------
# resolve_php_license — Packagist fallback path
# ---------------------------------------------------------------------------


class TestResolvePackagistFallback:
    @respx.mock
    def test_pinned_match_extracts_license(self):
        respx.get(_packagist_url("monolog/monolog")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "monolog" / "monolog.json").read_text()),
            )
        )
        dep = _php_dep("monolog/monolog", "==2.9.0")
        with httpx.Client() as client:
            info = resolve_php_license(dep, client)
        assert info.license_id == "MIT"
        assert info.resolved_version == "2.9.0"
        # SSH-form source URL gets rewritten to HTTPS.
        assert info.repository_url == "https://github.com/Seldaek/monolog"

    @respx.mock
    def test_unpinned_range_picks_highest_match(self):
        respx.get(_packagist_url("monolog/monolog")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "monolog" / "monolog.json").read_text()),
            )
        )
        dep = _php_dep("monolog/monolog", "^3.0")
        with httpx.Client() as client:
            info = resolve_php_license(dep, client)
        assert info.resolved_version == "3.5.0"

    @respx.mock
    def test_404_returns_unknown(self):
        respx.get(_packagist_url("nope/nope")).mock(return_value=httpx.Response(404))
        dep = _php_dep("nope/nope", "==1.0.0")
        with httpx.Client() as client:
            info = resolve_php_license(dep, client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_empty_versions_list_returns_unknown(self):
        respx.get(_packagist_url("vendor/empty")).mock(
            return_value=httpx.Response(200, json={"packages": {"vendor/empty": []}})
        )
        dep = _php_dep("vendor/empty", "==1.0.0")
        with httpx.Client() as client:
            info = resolve_php_license(dep, client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is False

    @respx.mock
    def test_entry_without_version_field_yields_empty_resolved_version(self):
        # Matched entry carries ``version_normalized`` but no ``version``
        # field — resolver returns the license without a resolved_version.
        respx.get(_packagist_url("vendor/pkg")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "packages": {
                        "vendor/pkg": [
                            {
                                "version_normalized": "1.0.0.0",
                                "license": ["MIT"],
                            }
                        ]
                    }
                },
            )
        )
        dep = _php_dep("vendor/pkg", "==1.0.0.0")
        with httpx.Client() as client:
            info = resolve_php_license(dep, client)
        assert info.license_id == "MIT"
        assert info.resolved_version == ""

    @respx.mock
    def test_entry_with_empty_license_returns_unknown(self):
        # The matched entry exists but its license field is empty — the
        # resolver still surfaces from_registry=True (entry was found)
        # but the license_id is UNKNOWN.
        respx.get(_packagist_url("vendor/pkg")).mock(
            return_value=httpx.Response(
                200,
                json={"packages": {"vendor/pkg": [{"version": "1.0.0", "license": []}]}},
            )
        )
        dep = _php_dep("vendor/pkg", "==1.0.0")
        with httpx.Client() as client:
            info = resolve_php_license(dep, client)
        assert info.license_id == "UNKNOWN"
        assert info.from_registry is True


# ---------------------------------------------------------------------------
# fetch_packagist_dependencies — manifest-only transitive walker
# ---------------------------------------------------------------------------


class TestFetchPackagistDependencies:
    @respx.mock
    def test_extracts_require_children(self):
        respx.get(_packagist_url("monolog/monolog")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "monolog" / "monolog.json").read_text()),
            )
        )
        with httpx.Client() as client:
            children = fetch_packagist_dependencies(
                "monolog/monolog",
                "3.5.0",
                client,
                parent_depth=0,
                parent_group=DependencyGroup.PROD,
            )
        names = {c.name for c in children}
        # ``psr/log`` is in require; platform pseudo-packages filtered out.
        assert names == {"psr/log"}
        assert children[0].depth == 1
        assert children[0].group == DependencyGroup.PROD
        assert children[0].ecosystem == Ecosystem.PHP

    @respx.mock
    def test_404_returns_empty(self):
        respx.get(_packagist_url("vendor/missing")).mock(return_value=httpx.Response(404))
        with httpx.Client() as client:
            children = fetch_packagist_dependencies(
                "vendor/missing", "1.0.0", client, parent_depth=0
            )
        assert children == []

    @respx.mock
    def test_unmatched_version_returns_empty(self):
        respx.get(_packagist_url("monolog/monolog")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "monolog" / "monolog.json").read_text()),
            )
        )
        with httpx.Client() as client:
            children = fetch_packagist_dependencies(
                "monolog/monolog", "99.0.0", client, parent_depth=0
            )
        assert children == []

    @respx.mock
    def test_match_via_version_normalized(self):
        # When ``version`` is missing but ``version_normalized`` carries the
        # 4-segment Composer form, the walker still matches.
        respx.get(_packagist_url("vendor/pkg")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "packages": {
                        "vendor/pkg": [
                            {
                                "version_normalized": "1.0.0.0",
                                "require": {"vendor/child": "^1.0"},
                            }
                        ]
                    }
                },
            )
        )
        with httpx.Client() as client:
            children = fetch_packagist_dependencies("vendor/pkg", "1.0.0.0", client, parent_depth=0)
        assert [c.name for c in children] == ["vendor/child"]

    @respx.mock
    def test_non_dict_require_returns_empty(self):
        respx.get(_packagist_url("vendor/pkg")).mock(
            return_value=httpx.Response(
                200,
                json={"packages": {"vendor/pkg": [{"version": "1.0.0", "require": "not-a-dict"}]}},
            )
        )
        with httpx.Client() as client:
            children = fetch_packagist_dependencies("vendor/pkg", "1.0.0", client, parent_depth=0)
        assert children == []

    @respx.mock
    def test_dedupes_child_names(self):
        # When a require dict has a name plus a casing variant, the dedupe
        # ``seen`` set drops the second occurrence.
        respx.get(_packagist_url("vendor/pkg")).mock(
            return_value=httpx.Response(
                200,
                json={
                    "packages": {
                        "vendor/pkg": [
                            {
                                "version": "1.0.0",
                                "require": {
                                    "vendor/child": "^1.0",
                                    "Vendor/Child": "^1.5",
                                    "bad-no-slash": "^1.0",
                                    "vendor/bad-spec": 42,
                                },
                            }
                        ]
                    }
                },
            )
        )
        with httpx.Client() as client:
            children = fetch_packagist_dependencies("vendor/pkg", "1.0.0", client, parent_depth=0)
        names = sorted(c.name for c in children)
        # Casing dedupe → only one ``vendor/child``. The non-slashed name
        # is skipped. ``vendor/bad-spec`` survives but with empty spec
        # (its child_spec wasn't a string).
        assert names == ["vendor/bad-spec", "vendor/child"]
        bad_spec_dep = next(c for c in children if c.name == "vendor/bad-spec")
        assert bad_spec_dep.version_constraint == ""


# ---------------------------------------------------------------------------
# RegistryCache keep-set regression — ensure trim doesn't drop fields the
# resolver reads. Per feedback_resolver_cache_keep_set: ANY new registry
# field must be in the keep-set AND verified through RegistryCache.fetch.
# ---------------------------------------------------------------------------


class TestRegistryCacheTrim:
    def test_keep_set_covers_resolver_read_fields(self):
        # Spec the contract: every field the Packagist resolver reads must
        # appear in _PACKAGIST_VERSION_KEEP. This is a structural check —
        # if a future resolver patch reads a new field, the test fails so
        # the keep-set gets updated.
        expected = frozenset(
            {"version", "version_normalized", "license", "source", "homepage", "require"}
        )
        assert expected == _PACKAGIST_VERSION_KEEP

    def test_trim_packagist_preserves_resolver_fields(self):
        raw = {
            "packages": {
                "vendor/pkg": [
                    {
                        "version": "1.0.0",
                        "version_normalized": "1.0.0.0",
                        "license": ["MIT"],
                        "source": {"type": "git", "url": "https://x.example/y.git"},
                        "homepage": "https://x.example/y",
                        "require": {"php": "^8.0"},
                        # Fields the resolver doesn't read — must be trimmed.
                        "description": "X" * 1000,
                        "authors": [{"name": "Anon"}],
                        "autoload": {"psr-4": {"X\\\\": "src/"}},
                    }
                ]
            }
        }
        trimmed = _trim_packagist(raw)
        entry = trimmed["packages"]["vendor/pkg"][0]
        assert set(entry.keys()) == _PACKAGIST_VERSION_KEEP
        assert "description" not in entry
        assert "authors" not in entry

    def test_trim_dispatch_recognizes_packagist_url(self):
        url = "https://repo.packagist.org/p2/vendor/pkg.json"
        data = {"packages": {"vendor/pkg": [{"version": "1.0", "description": "y"}]}}
        trimmed = _trim_for_cache(url, data)
        assert trimmed is not None
        entry = trimmed["packages"]["vendor/pkg"][0]
        assert "description" not in entry

    def test_trim_non_dict_packages_returns_empty(self):
        # Defensive: ``packages`` carried as a non-dict (publisher error
        # or wrong endpoint shape).
        trimmed = _trim_packagist({"packages": "not-a-dict"})
        assert trimmed == {"packages": {}}

    def test_trim_skips_non_string_key_and_non_list_entries(self):
        raw = {
            "packages": {
                123: [{"version": "1.0"}],  # non-string key
                "vendor/pkg": "not-a-list",  # non-list entries
                "vendor/ok": [{"version": "1.0", "drop_me": True}],
            }
        }
        trimmed = _trim_packagist(raw)
        # Only ``vendor/ok`` survives.
        assert list(trimmed["packages"].keys()) == ["vendor/ok"]

    def test_trim_skips_non_dict_entry_in_list(self):
        raw = {
            "packages": {
                "vendor/pkg": [
                    "not-a-dict",
                    {"version": "1.0"},
                ]
            }
        }
        trimmed = _trim_packagist(raw)
        # Non-dict entries dropped; the dict entry survives.
        assert trimmed["packages"]["vendor/pkg"] == [{"version": "1.0"}]

    def test_select_php_version_picks_highest_matching(self):
        # Caret range against a descending Packagist version list.
        published = ["3.5.0", "3.4.0", "2.9.0"]
        assert select_php_version("^3.0", published) == "3.5.0"

    def test_select_php_version_pinned_match(self):
        published = ["3.5.0", "3.4.0", "2.9.0"]
        assert select_php_version("2.9.0", published) == "2.9.0"

    def test_select_php_version_dev_branch_returns_none(self):
        published = ["3.5.0"]
        # ``dev-*`` and ``*-dev`` aliases aren't published-version ranges;
        # caller falls back to latest stable.
        assert select_php_version("dev-main", published) is None
        assert select_php_version("1.x-dev", published) is None

    def test_select_php_version_star_returns_none(self):
        assert select_php_version("*", ["1.0.0"]) is None

    def test_select_php_version_empty_returns_none(self):
        assert select_php_version("", ["1.0.0"]) is None
        assert select_php_version("   ", ["1.0.0"]) is None

    def test_select_php_version_strips_v_prefix(self):
        # Composer publishes ``v3.5.0`` decoratively; matching must work
        # against the stripped form.
        published = ["v3.5.0", "v3.4.0"]
        assert select_php_version("^3.0", published) == "3.5.0"

    def test_select_php_version_strips_v_prefix_from_spec(self):
        # Composer constraint specs can also carry a ``v`` prefix
        # (``^v3.0`` is occasionally seen); the selector strips it before
        # npm-spec parsing so the match still works.
        published = ["3.5.0", "3.4.0"]
        assert select_php_version("^v3.0", published) == "3.5.0"
        # ``~v3.4.0`` after stripping is ``~3.4.0`` which npm interprets
        # as ``>=3.4.0 <3.5.0`` (this is one of the documented divergences
        # from Composer's broader ``~3.4`` semantics).
        assert select_php_version("~v3.4.0", published) == "3.4.0"

    @respx.mock
    def test_resolver_works_through_registry_cache(self):
        # End-to-end: route the resolver fetcher through RegistryCache.fetch
        # so the trim runs in the production path. Without the keep-set
        # covering ``license`` / ``source`` / ``homepage`` / ``version``,
        # the resolver would silently return UNKNOWN.
        respx.get(_packagist_url("monolog/monolog")).mock(
            return_value=httpx.Response(
                200,
                json=json.loads((_FIXTURES / "monolog" / "monolog.json").read_text()),
            )
        )
        cache = RegistryCache()
        dep = _php_dep("monolog/monolog", "==3.5.0")
        with httpx.Client() as client:
            info = resolve_php_license(dep, client, fetcher=cache.fetch)
        assert info.license_id == "MIT"
        assert info.resolved_version == "3.5.0"
        assert info.repository_url == "https://github.com/Seldaek/monolog"
