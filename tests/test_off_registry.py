"""Dependencies that do not come from a package registry.

A dependency declared from a git repository, a direct URL, or a path outside
the scanned directory is one UNKNOWN row that carries its origin. No registry
is asked about it under any name, and a review keyed on the origin clears it.
A path inside the scanned directory is the project's own code and is no row.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.discovery._origin import (
    git_origin,
    hosted_git_origin,
    path_origin,
    strip_credentials,
    url_origin,
)
from licenseal.discovery.npm._specs import npm_spec_origin
from licenseal.discovery.r.description import _remote_origins
from licenseal.models import Dependency, Ecosystem, LicenseInfo
from licenseal.review import (
    REVIEW_FILE_NAME,
    FlaggedEntry,
    apply_reviewed_licenses,
    flagged_entries_from_json_report,
    info_review_key,
    load_review_file,
    merge_review_template,
    render_review_template,
    review_key,
    source_review_key,
)
from tests._helpers import _check_json, _write


def _refuse_everything_else() -> None:
    """Answer 404 to any request no earlier route matched, so that it is on record."""
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


def _requests_mentioning(*names: str) -> list[str]:
    """URL of every request made whose URL or body mentions one of ``names``."""
    hits: list[str] = []
    for call in respx.calls:
        request = call.request
        text = f"{request.url} {request.content.decode('utf-8', 'replace')}".lower()
        hits += [str(request.url) for name in names if name.lower() in text]
    return hits


def _rows(data: dict) -> dict[str, dict]:
    return {dep["name"]: dep for dep in data["dependencies"]}


def _mock_gem(name: str, version: str, license_id: str = "MIT") -> None:
    respx.get(f"https://rubygems.org/api/v2/rubygems/{name}/versions/{version}.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": name,
                "number": version,
                "licenses": [license_id],
                "dependencies": {"runtime": [], "development": []},
            },
        )
    )


def _mock_hex(name: str, version: str, license_id: str = "MIT") -> None:
    respx.get(f"https://hex.pm/api/packages/{name}").mock(
        return_value=httpx.Response(
            200,
            json={
                "meta": {"licenses": [license_id], "links": {}},
                "latest_stable_version": version,
            },
        )
    )
    respx.get(f"https://hex.pm/api/packages/{name}/releases/{version}").mock(
        return_value=httpx.Response(200, json={"requirements": {}})
    )


def _mock_cran(*packages: tuple[str, str, str]) -> None:
    respx.get("https://cran.r-project.org/src/contrib/PACKAGES").mock(
        return_value=httpx.Response(
            200,
            text="\n".join(
                f"Package: {name}\nVersion: {version}\nLicense: {license_id}\n"
                for name, version, license_id in packages
            ),
        )
    )


# --------------------------------------------------------------- origin strings


class TestOriginStrings:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://example.org/a/b.git", "https://example.org/a/b.git"),
            ("https://token@example.org/a/b.git", "https://example.org/a/b.git"),
            ("https://user:p%40ss@example.org/a/b.git", "https://example.org/a/b.git"),
            ("ssh://git@example.org/a/b.git", "ssh://example.org/a/b.git"),
            ("git@example.org:a/b.git", "example.org:a/b.git"),
            (
                "https://example.org/pkg.whl?token=s3cret#sha256=ab",
                "https://example.org/pkg.whl#sha256=ab",
            ),
            ("  https://example.org/x  ", "https://example.org/x"),
            ("../relative/path", "../relative/path"),
            # An ``@`` after the host is part of the path, not user-info.
            ("https://example.org/a/b@v1", "https://example.org/a/b@v1"),
        ],
    )
    def test_strip_credentials(self, url, expected):
        assert strip_credentials(url) == expected

    def test_git_origin(self):
        assert git_origin("https://example.org/r.git") == "git+https://example.org/r.git"
        assert (
            git_origin("https://example.org/r.git", " abc ") == "git+https://example.org/r.git@abc"
        )
        # A prefix already on the URL is not doubled, and names the VCS.
        assert git_origin("git+https://t@example.org/r.git", "v1") == (
            "git+https://example.org/r.git@v1"
        )
        assert git_origin("hg+https://example.org/r", "tip") == "hg+https://example.org/r@tip"
        assert git_origin("https://example.org/r", vcs="svn") == "svn+https://example.org/r"

    def test_url_origin(self):
        assert url_origin("https://u:p@example.org/p.tgz") == "https://example.org/p.tgz"
        assert url_origin("https://example.org/p.tgz", "sha512-xyz") == (
            "https://example.org/p.tgz#sha512-xyz"
        )
        # A recorded hash replaces a fragment; without one the fragment stays.
        assert url_origin("https://example.org/p.tgz#sha1", "sha512-xyz") == (
            "https://example.org/p.tgz#sha512-xyz"
        )
        assert url_origin("https://example.org/p.tgz#sha256=ab") == (
            "https://example.org/p.tgz#sha256=ab"
        )

    def test_hosted_git_origin(self):
        assert hosted_git_origin("github.com", " /me/repo/ ", "v2") == (
            "git+https://github.com/me/repo@v2"
        )

    def test_path_inside_the_scanned_directory_is_own_code(self, tmp_path):
        nested = tmp_path / "services" / "api"
        nested.mkdir(parents=True)
        for written in (".", "./lib", "lib/x", "..", "../shared", "file:../shared", "file:."):
            assert path_origin(written, nested, tmp_path) is None, written
        # An empty path is the directory of the file that holds it.
        assert path_origin("  ", nested, tmp_path) is None

    def test_path_outside_the_scanned_directory_is_reported_as_written(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        for written in ("..", "../sibling", "../../elsewhere/pkg", r"..\sibling"):
            assert path_origin(written, project, project) == written, written
        assert path_origin("file:../sibling", project, project) == "../sibling"

    @pytest.mark.parametrize(
        ("written", "expected"),
        [
            ("/opt/pkgs/a", "/opt/pkgs/a"),
            ("~/pkgs/a", "~/pkgs/a"),
            (r"C:\pkgs\a", r"C:\pkgs\a"),
            ("C:pkgs", "C:pkgs"),
            (r"\\example.invalid\share\a", r"\\example.invalid\share\a"),
            ("//example.invalid/share/a", "//example.invalid/share/a"),
            ("file:///opt/pkgs/a.whl", "/opt/pkgs/a.whl"),
            ("file://localhost/opt/pkgs/a.whl", "/opt/pkgs/a.whl"),
        ],
    )
    def test_rooted_path_is_never_resolved(self, tmp_path, monkeypatch, written, expected):
        def _refuse(self, *args, **kwargs):
            raise AssertionError(f"resolve() called on {self}")

        monkeypatch.setattr(Path, "resolve", _refuse)
        assert path_origin(written, tmp_path, tmp_path) == expected

    def test_path_the_filesystem_cannot_resolve_is_not_own_code(self, tmp_path, monkeypatch):
        def _fail(self, *args, **kwargs):
            raise OSError("link loop")

        monkeypatch.setattr(Path, "resolve", _fail)
        assert path_origin("loop/pkg", tmp_path, tmp_path) == "loop/pkg"


class TestNpmSpecOrigin:
    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("^1.2.3", ""),
            ("latest", ""),
            ("1.x || >=2.5.0", ""),
            ("", ""),
            ("@scope/name", ""),
            ("./local", ""),
            ("../local#x", ""),
            ("git+https://tok@example.org/a/b.git", "git+https://example.org/a/b.git"),
            ("git+https://example.org/a/b.git#v1.0", "git+https://example.org/a/b.git@v1.0"),
            ("git+ssh://git@example.org:a/b.git#abc", "git+ssh://example.org:a/b.git@abc"),
            ("git://example.org/a/b.git#semver:^1", "git+git://example.org/a/b.git@semver:^1"),
            ("https://example.org/a/b.git#abc", "git+https://example.org/a/b.git@abc"),
            ("https://example.org/a/b-1.0.tgz", "https://example.org/a/b-1.0.tgz"),
            ("http://u:p@example.org/b.tgz?x=1", "http://example.org/b.tgz"),
            ("github:me/repo", "git+https://github.com/me/repo"),
            ("github:me/repo#main", "git+https://github.com/me/repo@main"),
            ("gitlab:me/repo#v1", "git+https://gitlab.com/me/repo@v1"),
            ("bitbucket:me/repo", "git+https://bitbucket.org/me/repo"),
            ("gist:0123abc", "git+https://gist.github.com/0123abc"),
            ("me/repo", "git+https://github.com/me/repo"),
            ("me/repo#feature/x", "git+https://github.com/me/repo@feature/x"),
        ],
    )
    def test_spec(self, spec, expected):
        assert npm_spec_origin(spec) == expected


class TestRemotesField:
    def test_every_remote_type(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        origins = _remote_origins(
            """
            me/plain,
            github::me/tagged@v1.0,
            me/pulled#12,
            me/mono/subdir@abc,
            gitlab::team/glpkg@main,
            bitbucket::team/bbpkg,
            git::https://tok@example.org/repos/gitpkg.git@v2,
            git::https://example.org/repos/bare.git,
            svn::https://example.org/svn/svnpkg,
            url::https://example.org/src/urlpkg_1.0.tar.gz?token=s3cret,
            local::../outside,
            local::pkgs/inside,
            bioc::release/BiocPkg,
            bioc::user:pw@3.18/Private#abc,
            renamed=me/other-repo,
            cran::fromcran,
            odd::thing,
            justaname,
            not a remote
            """,
            project,
            project,
        )
        assert origins == {
            "plain": "git+https://github.com/me/plain",
            "tagged": "git+https://github.com/me/tagged@v1.0",
            "pulled": "git+https://github.com/me/pulled",
            "mono": "git+https://github.com/me/mono@abc",
            "glpkg": "git+https://gitlab.com/team/glpkg@main",
            "bbpkg": "git+https://bitbucket.org/team/bbpkg",
            "gitpkg": "git+https://example.org/repos/gitpkg.git@v2",
            "bare": "git+https://example.org/repos/bare.git",
            "svnpkg": "svn+https://example.org/svn/svnpkg",
            "urlpkg": "https://example.org/src/urlpkg_1.0.tar.gz",
            "outside": "../outside",
            "inside": None,
            "biocpkg": "Bioconductor",
            "private": "Bioconductor",
            "renamed": "git+https://github.com/me/other-repo",
        }

    def test_no_remotes_field(self, tmp_path):
        assert _remote_origins("", tmp_path, tmp_path) == {}


class TestOffRegistryReason:
    def test_reason_names_the_origin(self):
        from licenseal.analysis.compatibility import check_compatibility

        result = check_compatibility("MIT", _info(origin="git+https://example.org/edge.git@abc"))
        assert result.reason == (
            "edge comes from an off-registry source (git+https://example.org/edge.git@abc); "
            "its license is not looked up — manual review required"
        )

    def test_very_long_origin_is_capped_in_the_reason(self):
        from licenseal.analysis.compatibility import check_compatibility

        origin = "https://example.org/" + "a" * 500 + "  spaced\nout"
        result = check_compatibility("MIT", _info(origin=origin))
        shown = result.reason.split("(", 1)[1].split(")", 1)[0]
        assert len(shown) == 200
        assert shown.endswith("…")
        assert shown.startswith("https://example.org/aaaa")
        # The row keeps the whole string.
        assert result.license_info.dependency.origin == origin


# ------------------------------------------------------------------ review keys


def _info(
    name: str = "edge", *, origin: str = "", version: str = "1.0.0", eco: Ecosystem = Ecosystem.RUBY
) -> LicenseInfo:
    return LicenseInfo(
        dependency=Dependency(name, f"=={version}" if version else "", eco, origin=origin),
        license_id="UNKNOWN",
        license_raw="",
        resolved_version=version,
    )


_ORIGIN = "git+https://example.org/edge.git@0123abc"


class TestSourceReviewKey:
    def test_key_holds_ecosystem_canonical_name_and_origin(self):
        key = source_review_key(Ecosystem.PYTHON, "My_Pkg", f"  {_ORIGIN} ")
        assert key == f"off-registry python:my-pkg from {_ORIGIN}"
        assert (
            source_review_key("ruby", "Edge", _ORIGIN) == f"off-registry ruby:edge from {_ORIGIN}"
        )

    def test_info_key_by_kind_of_row(self):
        assert info_review_key(_info(origin=_ORIGIN)) == f"off-registry ruby:edge from {_ORIGIN}"
        # The version is not part of an off-registry key.
        assert info_review_key(_info(origin=_ORIGIN, version="")) == (
            f"off-registry ruby:edge from {_ORIGIN}"
        )
        assert info_review_key(_info()) == "ruby:edge@1.0.0"
        assert info_review_key(_info(version="")) == ""

    def test_no_package_or_version_text_makes_a_registry_key_equal_a_source_key(self):
        # A registry key always starts with ``<ecosystem>:``; a source key
        # starts with a word no ecosystem is named.
        crafted = review_key("ruby", f"edge from {_ORIGIN.rsplit('@', 1)[0]}", "0123abc")
        assert crafted != source_review_key("ruby", "edge", _ORIGIN)
        assert not any(source_review_key(e, "x", "y").startswith(f"{e.value}:") for e in Ecosystem)


def _review_file(tmp_path: Path, body: str) -> Path:
    return _write(tmp_path / REVIEW_FILE_NAME, body)


class TestLoadReviewFileWithSource:
    def test_source_entry_needs_no_version(self, tmp_path):
        _review_file(
            tmp_path,
            f"""\
            [[review]]
            ecosystem = "ruby"
            package = "Edge"
            source = "{_ORIGIN}"
            license = "MIT"
            note = "read LICENSE at that commit"
            """,
        )
        contents = load_review_file(tmp_path)
        key = f"off-registry ruby:edge from {_ORIGIN}"
        assert contents.licenses == {key: "MIT"}
        assert contents.notes == {key: "read LICENSE at that commit"}
        assert contents.versions == {}

    def test_source_entry_can_also_name_a_version(self, tmp_path):
        _review_file(
            tmp_path,
            f"""\
            [[review]]
            ecosystem = "ruby"
            package = "edge"
            version = " 1.0.0 "
            source = "{_ORIGIN}"
            license = ""
            """,
        )
        contents = load_review_file(tmp_path)
        key = f"off-registry ruby:edge from {_ORIGIN}"
        assert contents.incomplete == [key]
        assert contents.versions == {key: "1.0.0"}

    @pytest.mark.parametrize("source", ['""', '"   "', "7", "[]"])
    def test_source_must_be_a_non_empty_string(self, tmp_path, source):
        _review_file(
            tmp_path,
            f"""\
            [[review]]
            ecosystem = "ruby"
            package = "edge"
            version = "1.0.0"
            source = {source}
            license = "MIT"
            """,
        )
        with pytest.raises(click.ClickException, match="empty or non-string 'source'"):
            load_review_file(tmp_path)

    @pytest.mark.parametrize("version", ['""', "3"])
    def test_version_beside_a_source_must_still_be_a_version(self, tmp_path, version):
        _review_file(
            tmp_path,
            f"""\
            [[review]]
            ecosystem = "ruby"
            package = "edge"
            version = {version}
            source = "{_ORIGIN}"
            license = "MIT"
            """,
        )
        with pytest.raises(click.ClickException, match="missing a string 'version'"):
            load_review_file(tmp_path)

    def test_entry_without_source_still_needs_a_version(self, tmp_path):
        _review_file(
            tmp_path,
            """\
            [[review]]
            ecosystem = "ruby"
            package = "edge"
            license = "MIT"
            """,
        )
        with pytest.raises(click.ClickException, match="missing a string 'version'"):
            load_review_file(tmp_path)

    def test_two_entries_for_one_source_are_a_duplicate(self, tmp_path):
        stanza = f"""\
            [[review]]
            ecosystem = "ruby"
            package = "edge"
            source = "{_ORIGIN}"
            license = "MIT"
            """
        _review_file(tmp_path, stanza + stanza.replace('license = "MIT"', 'version = "2.0"'))
        with pytest.raises(click.ClickException) as raised:
            load_review_file(tmp_path)
        assert f"duplicate review entry for ruby:edge from {_ORIGIN}." in raised.value.message

    def test_same_package_from_two_sources_and_from_the_registry(self, tmp_path):
        _review_file(
            tmp_path,
            f"""\
            [[review]]
            ecosystem = "ruby"
            package = "edge"
            source = "{_ORIGIN}"
            license = "MIT"

            [[review]]
            ecosystem = "ruby"
            package = "edge"
            source = "git+https://example.org/edge.git@ffff999"
            license = "Apache-2.0"

            [[review]]
            ecosystem = "ruby"
            package = "edge"
            version = "1.0.0"
            license = "BSD-3-Clause"
            """,
        )
        assert load_review_file(tmp_path).licenses == {
            f"off-registry ruby:edge from {_ORIGIN}": "MIT",
            "off-registry ruby:edge from git+https://example.org/edge.git@ffff999": "Apache-2.0",
            "ruby:edge@1.0.0": "BSD-3-Clause",
        }


class TestApplyReviewsBySource:
    def _apply(self, tmp_path: Path, body: str, infos: list[LicenseInfo]) -> None:
        _review_file(tmp_path, body)
        contents = load_review_file(tmp_path)
        apply_reviewed_licenses(infos, contents, {info_review_key(info) for info in infos})

    _BY_SOURCE = f"""\
        [[review]]
        ecosystem = "ruby"
        package = "edge"
        source = "{_ORIGIN}"
        license = "MIT"
        note = "read at that commit"
        """

    def test_source_entry_applies_to_the_row_with_that_origin(self, tmp_path):
        info = _info(origin=_ORIGIN)
        self._apply(tmp_path, self._BY_SOURCE, [info])
        assert info.reviewed_license_id == "MIT"
        assert info.review_note == "read at that commit"

    def test_source_entry_applies_whatever_version_the_row_has(self, tmp_path):
        info = _info(origin=_ORIGIN, version="")
        self._apply(tmp_path, self._BY_SOURCE, [info])
        assert info.reviewed

    def test_another_commit_declaring_the_same_version_is_not_covered(self, tmp_path):
        other = _info(origin="git+https://example.org/edge.git@ffff999")
        with pytest.raises(click.ClickException, match="did not match any resolved package"):
            self._apply(tmp_path, self._BY_SOURCE, [other])
        assert not other.reviewed

    def test_source_entry_never_applies_to_a_registry_row(self, tmp_path):
        registry = _info()
        with pytest.raises(click.ClickException) as raised:
            self._apply(tmp_path, self._BY_SOURCE, [registry])
        assert not registry.reviewed
        assert "A stanza with a `source` key applies only to that exact source" in (
            raised.value.message
        )

    def test_version_entry_never_applies_to_an_off_registry_row(self, tmp_path):
        row = _info(origin=_ORIGIN)
        body = """\
            [[review]]
            ecosystem = "ruby"
            package = "edge"
            version = "1.0.0"
            license = "MIT"
            """
        with pytest.raises(click.ClickException, match="did not match any resolved package"):
            self._apply(tmp_path, body, [row])
        assert not row.reviewed

    def test_version_beside_the_source_must_match_the_row(self, tmp_path):
        body = self._BY_SOURCE + '        version = "1.0.0"\n'
        matching = _info(origin=_ORIGIN, version="1.0.0")
        self._apply(tmp_path, body, [matching])
        assert matching.reviewed

        moved = _info(origin=_ORIGIN, version="1.1.0")
        with pytest.raises(click.ClickException, match="did not match any resolved package"):
            self._apply(tmp_path, body, [moved])
        assert not moved.reviewed


def _entry(**fields: str) -> FlaggedEntry:
    values = {
        "ecosystem": "ruby",
        "name": "edge",
        "version": "1.0.0",
        "detected_license": "UNKNOWN",
        "license_raw": "",
        "verdict": "unknown",
    }
    return FlaggedEntry(**(values | fields))


class TestScaffoldSourceEntries:
    def test_source_line_is_written_after_the_version(self):
        text = render_review_template([_entry(origin=_ORIGIN)], include_header=False)
        assert text == (
            "# detected: UNKNOWN\n"
            "# status: unknown\n"
            "[[review]]\n"
            'ecosystem = "ruby"\n'
            'package = "edge"\n'
            'version = "1.0.0"\n'
            f'source = "{_ORIGIN}"\n'
            'license = ""\n'
            'note = ""\n'
        )

    def test_no_version_line_when_the_row_has_no_version(self):
        text = render_review_template([_entry(origin=_ORIGIN, version="")], include_header=False)
        assert "version" not in text
        assert f'source = "{_ORIGIN}"\n' in text

    @pytest.mark.parametrize(
        "origin",
        [
            'path"with"quotes',
            "back\\slash",
            'x"\nlicense = "MIT',
            'x"\n\n[[review]]\necosystem = "ruby"\npackage = "evil"\nversion = "1"\nlicense = "MIT',
            "line\u2028separator",
            "tab\there",
        ],
    )
    def test_origin_is_written_as_one_escaped_string(self, tmp_path, origin):
        # The origin comes from a scanned file or a saved report: it must load
        # back as the same string and never add or fill in a stanza.
        _review_file(tmp_path, render_review_template([_entry(origin=origin, version="")]))
        contents = load_review_file(tmp_path)
        assert contents.licenses == {}
        assert contents.incomplete == [source_review_key("ruby", "edge", origin)]

    def test_merge_skips_a_source_entry_already_in_the_file(self, tmp_path):
        existing = render_review_template([_entry(origin=_ORIGIN)])
        _review_file(tmp_path, existing)
        keys = load_review_file(tmp_path).all_keys
        merged, appended = merge_review_template(
            existing,
            [
                _entry(origin=_ORIGIN),
                _entry(origin="git+https://example.org/edge.git@ffff999"),
                _entry(),
            ],
            keys,
        )
        assert appended == 2
        _review_file(tmp_path, merged)
        assert sorted(load_review_file(tmp_path).incomplete) == sorted(
            [
                f"off-registry ruby:edge from {_ORIGIN}",
                "off-registry ruby:edge from git+https://example.org/edge.git@ffff999",
                "ruby:edge@1.0.0",
            ]
        )

    def test_report_rows_are_read_with_their_origin(self, tmp_path):
        report = tmp_path / "report.json"
        row = {"ecosystem": "ruby", "verdict": "unknown", "license": "UNKNOWN"}
        report.write_text(
            json.dumps(
                {
                    "dependencies": [
                        row | {"name": "pinned", "resolved_version": "1.0.0", "origin": _ORIGIN},
                        row | {"name": "unpinned", "resolved_version": "", "origin": "../lib"},
                        row | {"name": "badver", "resolved_version": 7, "origin": "../lib"},
                        row | {"name": "registry", "resolved_version": "2.0.0", "origin": ""},
                        row | {"name": "older-report", "resolved_version": "3.0.0"},
                        row | {"name": "badorigin", "resolved_version": "", "origin": ["x"]},
                        row | {"name": "nothing", "resolved_version": ""},
                    ]
                }
            ),
            encoding="utf-8",
        )
        entries, unscaffoldable = flagged_entries_from_json_report(report)
        assert [(e.name, e.version, e.origin) for e in entries] == [
            ("pinned", "1.0.0", _ORIGIN),
            ("unpinned", "", "../lib"),
            ("badver", "", "../lib"),
            ("registry", "2.0.0", ""),
            ("older-report", "3.0.0", ""),
        ]
        assert unscaffoldable == ["ruby:badorigin", "ruby:nothing"]


# ------------------------------------------------------------------------- Ruby

_EDGE_ORIGIN = "git+https://git.example.org/team/edge-fork.git@0123abcd"


def _ruby_project(root: Path) -> Path:
    """A git gem with a registry dependency of its own, beside a registry gem."""
    _write(
        root / "Gemfile",
        """\
        source "https://rubygems.org"
        gem "regular"
        gem "edge-fork", git: "https://tok3n@git.example.org/team/edge-fork.git", branch: "main"
        """,
    )
    _write(
        root / "Gemfile.lock",
        """\
        GIT
          remote: https://tok3n@git.example.org/team/edge-fork.git
          revision: 0123abcd
          branch: main
          specs:
            edge-fork (1.0.0)
              shared-child (~> 2.0)

        GEM
          remote: https://rubygems.org/
          specs:
            regular (1.0.0)
            shared-child (2.1.0)

        DEPENDENCIES
          edge-fork!
          regular
        """,
    )
    _mock_gem("regular", "1.0.0")
    _mock_gem("shared-child", "2.1.0")
    _refuse_everything_else()
    return root


class TestRubyGitGem:
    @respx.mock
    def test_git_gem_is_one_unknown_row_with_its_origin(self, tmp_path):
        result, data = _check_json(_ruby_project(tmp_path))
        assert result.exit_code == 1
        rows = _rows(data)
        assert set(rows) == {"regular", "edge-fork", "shared-child"}
        edge = rows["edge-fork"]
        assert edge["origin"] == _EDGE_ORIGIN
        assert (edge["license"], edge["verdict"]) == ("UNKNOWN", "unknown")
        assert edge["resolved_version"] == "1.0.0"
        assert edge["source"] == "Gemfile"
        # The registry page of that name describes another gem.
        assert edge["package_url"] == ""
        assert edge["reason"] == (
            f"edge-fork comes from an off-registry source ({_EDGE_ORIGIN}); "
            "its license is not looked up — manual review required"
        )
        assert edge["actionability"] == {
            "investigate_url": "",
            "next_steps": [
                f"Read the license of the code at {_EDGE_ORIGIN}; no registry is consulted for it",
                "Record it in licenseal.review.toml, in a stanza whose `source` is this "
                "dependency's `origin`",
            ],
        }
        # The registry gems are unaffected, and the one the git gem pulls in
        # names it as its ancestor.
        assert (rows["regular"]["origin"], rows["regular"]["license"]) == ("", "MIT")
        assert rows["shared-child"]["direct_ancestors"] == ["edge-fork"]
        assert rows["shared-child"]["license"] == "MIT"

    @respx.mock
    def test_nothing_is_requested_for_the_git_gem(self, tmp_path):
        _check_json(_ruby_project(tmp_path), "--dev")
        assert _requests_mentioning("edge-fork") == []
        # The registry gems were looked up, so the check is not vacuous.
        assert _requests_mentioning("shared-child")

    @respx.mock
    def test_credentials_in_the_remote_reach_no_output(self, tmp_path):
        project = _ruby_project(tmp_path)
        for fmt in ("table", "json", "markdown"):
            result = CliRunner().invoke(main, ["check", "--path", str(project), "-f", fmt])
            assert "tok3n" not in result.output, fmt
            assert "git.example.org/team/edge-fork.git@0123abcd" in result.output, fmt

    @respx.mock
    def test_table_and_markdown_say_the_row_is_off_registry(self, tmp_path):
        project = _ruby_project(tmp_path)
        for fmt in ("table", "markdown"):
            out = project / f"report.{fmt}"
            CliRunner().invoke(main, ["check", "--path", str(project), "-f", fmt, "-o", str(out)])
            text = " ".join(out.read_text(encoding="utf-8").split())
            assert f"edge-fork comes from an off-registry source ({_EDGE_ORIGIN})" in text, fmt

    @respx.mock
    def test_review_keyed_on_the_origin_passes_strict(self, tmp_path):
        project = _ruby_project(tmp_path)
        _review_file(
            project,
            f"""\
            [[review]]
            ecosystem = "ruby"
            package = "edge-fork"
            source = "{_EDGE_ORIGIN}"
            license = "MIT"
            note = "LICENSE read at that commit"
            """,
        )
        result, data = _check_json(project)
        assert result.exit_code == 0
        edge = _rows(data)["edge-fork"]
        assert (edge["reviewed"], edge["license"], edge["verdict"]) == (True, "MIT", "compatible")
        assert edge["detected_license"] == "UNKNOWN"
        assert data["summary"]["reviewed"] == 1

        # The Reviewed section keeps the reviewed source in view.
        markdown = CliRunner().invoke(main, ["check", "--path", str(project), "-f", "markdown"])
        assert f"UNKNOWN (source: {_EDGE_ORIGIN})" in markdown.output

    @respx.mock
    def test_review_keyed_on_the_version_does_not_cover_the_git_gem(self, tmp_path):
        project = _ruby_project(tmp_path)
        _review_file(
            project,
            """\
            [[review]]
            ecosystem = "ruby"
            package = "edge-fork"
            version = "1.0.0"
            license = "MIT"
            """,
        )
        result = CliRunner().invoke(main, ["check", "--path", str(project)])
        assert result.exit_code == 1
        assert "Reviewed licenses did not match any resolved package versions" in result.output
        assert "ruby:edge-fork@1.0.0" in result.output

    @respx.mock
    def test_review_of_another_commit_does_not_cover_this_one(self, tmp_path):
        project = _ruby_project(tmp_path)
        _review_file(
            project,
            """\
            [[review]]
            ecosystem = "ruby"
            package = "edge-fork"
            version = "1.0.0"
            source = "git+https://git.example.org/team/edge-fork.git@ffff9999"
            license = "MIT"
            """,
        )
        result = CliRunner().invoke(main, ["check", "--path", str(project)])
        assert result.exit_code == 1
        assert "did not match any resolved package versions" in result.output

    @respx.mock
    def test_reviewed_as_copyleft_is_a_violation_with_no_registry_step(self, tmp_path):
        project = _ruby_project(tmp_path)
        _write(project / "edge.gemspec", 'Gem::Specification.new { |s| s.license = "MIT" }\n')
        _review_file(
            project,
            f"""\
            [[review]]
            ecosystem = "ruby"
            package = "edge-fork"
            source = "{_EDGE_ORIGIN}"
            license = "GPL-3.0-only"
            """,
        )
        _, data = _check_json(project)
        edge = _rows(data)["edge-fork"]
        assert edge["verdict"] == "incompatible"
        assert edge["actionability"] == {
            "investigate_url": "https://spdx.org/licenses/GPL-3.0-only.html",
            "next_steps": ["GPL-3.0-only is incompatible with the project license"],
        }

    @respx.mock
    def test_init_review_file_from_report_scaffolds_the_source(self, tmp_path):
        project = _ruby_project(tmp_path)
        _check_json(project)
        result = CliRunner().invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(project),
                "--from-report",
                str(project / "report.json"),
            ],
        )
        assert result.exit_code == 0
        scaffold = (project / REVIEW_FILE_NAME).read_text(encoding="utf-8")
        assert 'package = "edge-fork"\n' in scaffold
        assert 'version = "1.0.0"\n' in scaffold
        assert f'source = "{_EDGE_ORIGIN}"\n' in scaffold
        assert "could not be scaffolded" not in result.output

        # Filled in, the scaffold is what makes the strict check pass.
        (project / REVIEW_FILE_NAME).write_text(
            scaffold.replace('license = ""', 'license = "MIT"'), encoding="utf-8", newline="\n"
        )
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == 1

    @respx.mock
    def test_init_review_file_live_scan_scaffolds_the_declared_source(self, tmp_path):
        # Without a lockfile the origin is what the Gemfile declares: the
        # repository and the branch.
        _write(
            tmp_path / "Gemfile",
            """\
            source "https://rubygems.org"
            gem "edge-fork", git: "https://git.example.org/team/edge-fork.git", branch: "main"
            """,
        )
        _refuse_everything_else()
        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        scaffold = (tmp_path / REVIEW_FILE_NAME).read_text(encoding="utf-8")
        declared = "git+https://git.example.org/team/edge-fork.git@main"
        assert f'source = "{declared}"\n' in scaffold
        assert "version" not in scaffold
        assert _requests_mentioning("edge-fork") == []

        (tmp_path / REVIEW_FILE_NAME).write_text(
            scaffold.replace('license = ""', 'license = "MIT"'), encoding="utf-8", newline="\n"
        )
        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert _rows(data)["edge-fork"]["origin"] == declared
        assert _requests_mentioning("edge-fork") == []


class TestRubyGemSources:
    @respx.mock
    def test_gemfile_source_options_without_a_lockfile(self, tmp_path):
        project = tmp_path / "project"
        _write(
            project / "Gemfile",
            """\
            source "https://rubygems.org"
            gem "by-ref", git: "https://git.example.org/by-ref.git", ref: "abc123", tag: "v9"
            gem "by-tag", "~> 2.0", git: "https://git.example.org/by-tag.git", tag: "v2.0"
            gem "computed-git", git: REPO_URL
            gem "hub", github: "team/hub"
            gem "hub-short", github: "solo"
            gem "hub-url", github: "https://github.com/team/hub-url/pull/7"
            gem "computed-hub", github: HUB
            gem "snippet", gist: "0123abc"
            gem "bucket", bitbucket: "team/bucket", branch: "next"
            gem "outside", path: "../outside"
            gem "inside", path: "engines/inside"
            gem "computed-path", path: File.expand_path("x", __dir__)
            group :development do
              gem "dev-fork", git: "https://git.example.org/dev-fork.git"
            end
            """,
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict")
        assert result.exit_code == 0
        assert {name: row["origin"] for name, row in _rows(data).items()} == {
            "by-ref": "git+https://git.example.org/by-ref.git@abc123",
            "by-tag": "git+https://git.example.org/by-tag.git@v2.0",
            "computed-git": "unrecorded source",
            "hub": "git+https://github.com/team/hub.git",
            "hub-short": "git+https://github.com/solo/solo.git",
            "hub-url": "git+https://github.com/team/hub-url/pull/7",
            "computed-hub": "unrecorded source",
            "snippet": "git+https://gist.github.com/0123abc.git",
            "bucket": "git+https://bitbucket.org/team/bucket.git@next",
            "outside": "../outside",
            "computed-path": "unrecorded source",
            "dev-fork": "git+https://git.example.org/dev-fork.git",
        }
        rows = _rows(data)
        assert all(row["license"] == "UNKNOWN" for row in rows.values())
        # A version constraint beside the source is not a recorded version.
        assert rows["by-tag"]["resolved_version"] == ""
        assert rows["dev-fork"]["group"] == "dev"
        assert respx.calls.call_count == 0

    @respx.mock
    def test_lockfile_source_sections(self, tmp_path):
        project = tmp_path / "project"
        _write(project / "Gemfile", 'source "https://rubygems.org"\ngem "regular"\n')
        _write(
            project / "Gemfile.lock",
            """\
            GIT
              remote: https://git.example.org/pinned.git
              revision: 0123abc
              specs:
                pinned (1.0.0)

            GIT
              specs:
                gitless (0.1.0)

            PATH
              remote: ../outside
              specs:
                outside (0.2.0)

            PATH
              remote: engines/inside
              specs:
                inside (0.3.0)
                  regular

            PATH
              specs:
                pathless (0.4.0)

            PLUGIN SOURCE
              remote: https://plugins.example.org/source
              type: custom
              specs:
                plugged (0.5.0)

            PLUGIN SOURCE
              remote: vendor-dir/../../plugin-outside
              type: local
              specs:
                plugged-path (0.6.0)

            PLUGIN SOURCE
              remote: https://git.example.org/plugin.git
              revision: beef
              specs:
                plugged-git (0.7.0)

            GEM
              remote: https://rubygems.org/
              specs:
                regular (1.0.0)

            DEPENDENCIES
              regular
            """,
        )
        _mock_gem("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert {name: row["origin"] for name, row in _rows(data).items()} == {
            "pinned": "git+https://git.example.org/pinned.git@0123abc",
            "gitless": "unrecorded source",
            "outside": "../outside",
            "pathless": "unrecorded source",
            "plugged": "https://plugins.example.org/source",
            "plugged-path": "vendor-dir/../../plugin-outside",
            "plugged-git": "git+https://git.example.org/plugin.git@beef",
            "regular": "",
        }
        assert (
            _requests_mentioning("pinned", "gitless", "outside", "inside", "pathless", "plugged")
            == []
        )

    @respx.mock
    def test_path_gem_that_is_a_workspace_gem_still_counts_as_filtered(self, tmp_path):
        _write(
            tmp_path / "Gemfile", 'gem "own-engine", path: "engines/own-engine"\ngem "regular"\n'
        )
        _write(
            tmp_path / "engines" / "own-engine" / "own-engine.gemspec",
            'Gem::Specification.new do |s|\n  s.name = "own-engine"\nend\n',
        )
        _mock_gem("regular", "1.0.0")
        respx.get("https://rubygems.org/api/v1/gems/regular.json").mock(
            return_value=httpx.Response(
                200, json={"name": "regular", "version": "1.0.0", "licenses": ["MIT"]}
            )
        )
        _refuse_everything_else()
        result = CliRunner().invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert "Excluded 1 local Ruby workspace package reference(s)" in result.output
        assert _requests_mentioning("own-engine") == []


# -------------------------------------------------------------------------- Hex


class TestHexOffRegistry:
    @respx.mock
    def test_mix_lock_git_dep(self, tmp_path):
        _write(
            tmp_path / "mix.exs",
            """\
            defmodule M.MixProject do
              def project, do: [app: :m, deps: deps()]
              defp deps do
                [{:regular, "~> 1.0"}, {:edge_fork, github: "team/edge_fork", branch: "main"}]
              end
            end
            """,
        )
        _write(
            tmp_path / "mix.lock",
            """\
            %{
              "regular": {:hex, :regular, "1.0.0", "h", [:mix], [], "hexpm", "h2"},
              "edge_fork": {:git, "https://github.com/team/edge_fork.git", "0123abcd", []},
            }
            """,
        )
        _mock_hex("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        edge = _rows(data)["edge_fork"]
        origin = "git+https://github.com/team/edge_fork.git@0123abcd"
        assert (edge["origin"], edge["license"], edge["source"]) == (origin, "UNKNOWN", "mix.exs")
        assert edge["package_url"] == ""
        assert _requests_mentioning("edge_fork") == []

        _review_file(
            tmp_path,
            f"""\
            [[review]]
            ecosystem = "hex"
            package = "edge_fork"
            source = "{origin}"
            license = "Apache-2.0"
            """,
        )
        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert _rows(data)["edge_fork"]["reviewed"] is True

    @respx.mock
    def test_mix_exs_without_a_lockfile(self, tmp_path):
        project = tmp_path / "project"
        _write(
            project / "mix.exs",
            """\
            defmodule M.MixProject do
              def project, do: [app: :m, deps: deps()]
              defp deps do
                [
                  {:regular, "~> 1.0"},
                  {:edge_fork, git: "https://git.example.org/edge_fork.git", tag: "v1.2"},
                  {:outside, path: "../outside"},
                  {:inside, path: "apps/inside"}
                ]
              end
            end
            """,
        )
        _mock_hex("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert {name: row["origin"] for name, row in _rows(data).items()} == {
            "regular": "",
            "edge_fork": "git+https://git.example.org/edge_fork.git@v1.2",
            "outside": "../outside",
        }
        assert _requests_mentioning("edge_fork", "outside", "inside") == []

    @respx.mock
    def test_rebar_git_dep_with_and_without_a_lockfile(self, tmp_path):
        _write(
            tmp_path / "rebar.config",
            """\
            {deps, [
                {regular, "1.0.0"},
                {edge_fork, {git, "https://git.example.org/edge_fork.git", {tag, "v1.2"}}}
            ]}.
            """,
        )
        _mock_hex("regular", "1.0.0")
        _refuse_everything_else()
        _, data = _check_json(tmp_path, "--no-strict")
        assert (
            _rows(data)["edge_fork"]["origin"] == "git+https://git.example.org/edge_fork.git@v1.2"
        )

        _write(
            tmp_path / "rebar.lock",
            """\
            {"1.2.0",
            [{<<"regular">>,{pkg,<<"regular">>,<<"1.0.0">>},0},
             {<<"edge_fork">>,{git,"https://git.example.org/edge_fork.git",{ref,"0123abcd"}},0}]}.
            """,
        )
        _, data = _check_json(tmp_path, "--no-strict")
        rows = _rows(data)
        # The lockfile records the commit the tag resolved to.
        assert rows["edge_fork"]["origin"] == "git+https://git.example.org/edge_fork.git@0123abcd"
        assert rows["edge_fork"]["license"] == "UNKNOWN"
        assert rows["regular"]["license"] == "MIT"
        assert _requests_mentioning("edge_fork") == []

    @respx.mock
    def test_erlang_mk_git_dep(self, tmp_path):
        _write(
            tmp_path / "Makefile",
            """\
            PROJECT = app
            DEPS = regular edge_fork
            dep_regular = hex 1.0.0
            dep_edge_fork = git https://git.example.org/edge_fork 1.8.1
            include erlang.mk
            """,
        )
        _mock_hex("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path, "--no-strict")
        assert result.exit_code == 0
        rows = _rows(data)
        assert rows["edge_fork"]["origin"] == "git+https://git.example.org/edge_fork@1.8.1"
        assert (rows["edge_fork"]["license"], rows["edge_fork"]["source"]) == (
            "UNKNOWN",
            "Makefile",
        )
        assert _requests_mentioning("edge_fork") == []


# ---------------------------------------------------------------------------- R


class TestROffRegistry:
    @respx.mock
    def test_renv_lock_github_package(self, tmp_path):
        _write(
            tmp_path / "DESCRIPTION",
            "Package: proj\nLicense: MIT\nImports: regular, edgefork\n",
        )
        (tmp_path / "renv.lock").write_text(
            json.dumps(
                {
                    "Packages": {
                        "regular": {
                            "Package": "regular",
                            "Version": "1.0.0",
                            "Source": "Repository",
                            "Repository": "CRAN",
                        },
                        "edgefork": {
                            "Package": "edgefork",
                            "Version": "0.9.0",
                            "Source": "GitHub",
                            "RemoteHost": "api.github.com",
                            "RemoteUsername": "team",
                            "RemoteRepo": "edgefork",
                            "RemoteRef": "main",
                            "RemoteSha": "0123abcd",
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        # CRAN has a package of the same name under another license.
        _mock_cran(("regular", "1.0.0", "MIT + file LICENSE"), ("edgefork", "0.9.0", "GPL-3"))
        _refuse_everything_else()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        edge = _rows(data)["edgefork"]
        origin = "git+https://github.com/team/edgefork@0123abcd"
        assert (edge["origin"], edge["license"], edge["resolved_version"]) == (
            origin,
            "UNKNOWN",
            "0.9.0",
        )
        assert edge["source"] == "DESCRIPTION"
        assert _rows(data)["regular"]["license"] == "MIT"

        _review_file(
            tmp_path,
            f"""\
            [[review]]
            ecosystem = "r"
            package = "edgefork"
            version = "0.9.0"
            source = "{origin}"
            license = "MIT"
            """,
        )
        result, _ = _check_json(tmp_path)
        assert result.exit_code == 0

    @respx.mock
    def test_only_off_registry_packages_fetch_no_index(self, tmp_path):
        (tmp_path / "renv.lock").write_text(
            json.dumps(
                {"Packages": {"edgefork": {"Package": "edgefork", "Source": "Bioconductor"}}}
            ),
            encoding="utf-8",
        )
        _refuse_everything_else()
        result, data = _check_json(tmp_path, "--no-strict")
        assert result.exit_code == 0
        assert _rows(data)["edgefork"]["origin"] == "Bioconductor"
        assert respx.calls.call_count == 0

    @respx.mock
    def test_description_remotes_without_a_lockfile(self, tmp_path):
        project = tmp_path / "project"
        _write(
            project / "DESCRIPTION",
            """\
            Package: proj
            License: MIT
            Imports: regular, edgefork (>= 0.9), localpkg, ownpkg
            Suggests: devfork
            Remotes: team/edgefork@v0.9, local::../localpkg, local::pkgs/ownpkg,
                gitlab::team/devfork
            """,
        )
        # CRAN has same-named packages for the two forks; neither is used.
        _mock_cran(
            ("regular", "1.0.0", "MIT + file LICENSE"),
            ("edgefork", "0.9.0", "GPL-3"),
            ("devfork", "2.0.0", "GPL-3"),
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict")
        assert result.exit_code == 0
        rows = _rows(data)
        assert {name: (row["origin"], row["license"]) for name, row in rows.items()} == {
            "regular": ("", "MIT"),
            "edgefork": ("git+https://github.com/team/edgefork@v0.9", "UNKNOWN"),
            "localpkg": ("../localpkg", "UNKNOWN"),
            "devfork": ("git+https://gitlab.com/team/devfork", "UNKNOWN"),
        }
        # No version comes from the index for a package that is not CRAN's.
        assert rows["edgefork"]["resolved_version"] == ""
        assert rows["devfork"]["group"] == "dev"

    @respx.mock
    def test_remote_that_is_a_workspace_package_still_counts_as_filtered(self, tmp_path):
        _write(
            tmp_path / "DESCRIPTION",
            "Package: proj\nImports: regular, ownpkg\nRemotes: local::pkgs/ownpkg\n",
        )
        _write(tmp_path / "pkgs" / "ownpkg" / "DESCRIPTION", "Package: ownpkg\nType: Package\n")
        _mock_cran(("regular", "1.0.0", "MIT + file LICENSE"))
        _refuse_everything_else()
        result = CliRunner().invoke(main, ["check", "--path", str(tmp_path), "-f", "json"])
        assert "Excluded 1 local R workspace package reference(s)" in result.output


# -------------------------------------------------------------------------- npm


def _npm_manifest(root: Path, dependencies: dict[str, str], **extra: object) -> None:
    (root / "package.json").parent.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "app", "license": "MIT", "dependencies": dependencies} | extra),
        encoding="utf-8",
    )


def _mock_npm_package(name: str, version: str, license_id: str = "MIT") -> None:
    meta = {"name": name, "version": version, "license": license_id}
    respx.get(f"https://registry.npmjs.org/{name}").mock(
        return_value=httpx.Response(200, json={"versions": {version: meta}})
    )
    for suffix in ("latest", version):
        respx.get(f"https://registry.npmjs.org/{name}/{suffix}").mock(
            return_value=httpx.Response(200, json=meta)
        )


class TestNpmManifestSpecs:
    _SPECS = {
        "git-fork": "git+https://tok3n@git.example.org/team/git-fork.git#v1.2.0",
        "hub-fork": "team/hub-fork#main",
        "tarball-fork": "https://dl.example.org/tarball-fork-1.0.0.tgz",
        "aliased-fork": "npm:real-name@github:team/aliased",
        "regular": "^1.0.0",
    }
    _ORIGINS = {
        "git-fork": "git+https://git.example.org/team/git-fork.git@v1.2.0",
        "hub-fork": "git+https://github.com/team/hub-fork@main",
        "tarball-fork": "https://dl.example.org/tarball-fork-1.0.0.tgz",
        "real-name": "git+https://github.com/team/aliased",
        "regular": "",
    }

    @respx.mock
    @pytest.mark.parametrize("flags", [(), ("--no-transitive",)])
    def test_git_shorthand_and_tarball_specs_are_unknown_without_a_lookup(self, tmp_path, flags):
        _npm_manifest(tmp_path, self._SPECS)
        # The public registry owns every one of these names.
        for name in ("git-fork", "hub-fork", "tarball-fork", "aliased-fork", "real-name"):
            _mock_npm_package(name, "9.9.9", "MIT")
        _mock_npm_package("regular", "1.0.0", "MIT")
        result, data = _check_json(tmp_path, *flags)
        assert result.exit_code == 1
        rows = _rows(data)
        assert {name: row["origin"] for name, row in rows.items()} == self._ORIGINS
        for name, row in rows.items():
            expected = ("MIT", "1.0.0") if name == "regular" else ("UNKNOWN", "")
            assert (row["license"], row["resolved_version"]) == expected, name
        assert rows["git-fork"]["source"] == "package.json"
        assert (
            _requests_mentioning("git-fork", "hub-fork", "tarball-fork", "aliased", "real-name")
            == []
        )
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_registry_and_git_declarations_of_one_name_are_two_rows(self, tmp_path):
        _npm_manifest(tmp_path / "a", {"shared": "^1.0.0"}, name="a")
        _npm_manifest(tmp_path / "b", {"shared": "github:team/shared#abc"}, name="b")
        _mock_npm_package("shared", "1.0.0", "MIT")
        result, data = _check_json(tmp_path, "--no-strict")
        assert result.exit_code == 0
        assert sorted(
            (d["name"], d["origin"], d["license"], d["source"]) for d in data["dependencies"]
        ) == [
            ("shared", "", "MIT", "a/package.json"),
            ("shared", "git+https://github.com/team/shared@abc", "UNKNOWN", "b/package.json"),
        ]


class TestPnpmLockOffRegistry:
    @respx.mock
    def test_packages_from_git_a_tarball_and_a_directory(self, tmp_path):
        project = tmp_path / "project"
        _npm_manifest(
            project,
            {
                "regular": "^1.0.0",
                "git-fork": "git+https://git.example.org/team/git-fork.git#main",
                "hub-fork": "github:team/hub-fork",
                "tarball-fork": "https://dl.example.org/tarball-fork-1.0.0.tgz",
            },
        )
        _write(
            project / "pnpm-lock.yaml",
            """\
            lockfileVersion: '9.0'
            packages:
              regular@1.0.0:
                resolution: {integrity: sha512-reg}
              via-git@2.0.0:
                resolution: {integrity: sha512-via}
              git-fork@git+https://git.example.org/team/git-fork.git#0123abcd:
                resolution:
                  commit: 0123abcd
                  repo: https://tok3n@git.example.org/team/git-fork.git
                  type: git
                version: 1.2.0
              hub-fork@https://codeload.github.com/team/hub-fork/tar.gz/4567cdef:
                resolution: {tarball: https://codeload.github.com/team/hub-fork/tar.gz/4567cdef}
                version: 0.4.0
              tarball-fork@https://dl.example.org/tarball-fork-1.0.0.tgz:
                resolution: {integrity: sha512-tar, tarball: https://dl.example.org/tarball-fork-1.0.0.tgz}
                version: 1.0.0
              dir-outside@file:../dir-outside:
                resolution: {directory: ../dir-outside, type: directory}
              tgz-outside@file:../tgz-outside.tgz:
                resolution: {integrity: sha512-tgz, tarball: file:../tgz-outside.tgz}
                version: 3.0.0
              dir-inside@file:packages/dir-inside:
                resolution: {directory: packages/dir-inside, type: directory}
              spec-only@file:../spec-only:
                version: 0.0.1
              odd-git@git+ssh://git@git.example.org/team/odd-git.git#beef:
                version: 0.0.2
              odd-tarball@tarball:something:
                version: 0.0.3
              member@workspace:packages/member: {}
              linked@link:../linked: {}
            snapshots:
              regular@1.0.0: {}
              via-git@2.0.0: {}
              git-fork@git+https://git.example.org/team/git-fork.git#0123abcd:
                dependencies:
                  via-git: 2.0.0
            """,
        )
        _mock_npm_package("regular", "1.0.0")
        _mock_npm_package("via-git", "2.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        rows = _rows(data)
        assert {name: (row["origin"], row["resolved_version"]) for name, row in rows.items()} == {
            "regular": ("", "1.0.0"),
            "via-git": ("", "2.0.0"),
            # The lockfile records the commit, the tarball, and the integrity.
            "git-fork": ("git+https://git.example.org/team/git-fork.git@0123abcd", "1.2.0"),
            "hub-fork": ("https://codeload.github.com/team/hub-fork/tar.gz/4567cdef", "0.4.0"),
            "tarball-fork": ("https://dl.example.org/tarball-fork-1.0.0.tgz#sha512-tar", "1.0.0"),
        }
        assert rows["git-fork"]["source"] == "package.json"
        # The registry package only the git dependency pulls in is still reported.
        assert rows["via-git"]["direct_ancestors"] == ["git-fork"]
        assert all(
            row["license"] == ("UNKNOWN" if row["origin"] else "MIT") for row in rows.values()
        )
        assert (
            _requests_mentioning(
                "git-fork",
                "hub-fork",
                "tarball-fork",
                "dir-",
                "tgz-",
                "spec-only",
                "odd-",
                "member",
            )
            == []
        )
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_packages_no_manifest_declares_keep_their_origin(self, tmp_path):
        # A lockfile with no manifest beside it: nothing is dropped, and the
        # path, git, and unreadable forms each say what the lockfile records.
        project = tmp_path / "project"
        _write(
            project / "pnpm-lock.yaml",
            """\
            lockfileVersion: '9.0'
            packages:
              dir-outside@file:../dir-outside:
                resolution: {directory: ../dir-outside, type: directory}
              tgz-outside@file:../tgz-outside.tgz:
                resolution: {integrity: sha512-tgz, tarball: file:../tgz-outside.tgz}
                version: 3.0.0
              dir-inside@file:packages/dir-inside:
                resolution: {directory: packages/dir-inside, type: directory}
              spec-only@file:../spec-only:
                version: 0.0.1
              odd-git@git+ssh://git@git.example.org/team/odd-git.git#beef:
                version: 0.0.2
              odd-tarball@tarball:something:
                version: 0.0.3
              no-commit@git+https://git.example.org/team/no-commit.git:
                resolution: {repo: https://git.example.org/team/no-commit.git, type: git}
                version: [1]
              dup@file:../dup:
                resolution: {directory: ../dup, type: directory}
              /dup@file:../dup:
                resolution: {directory: ../dup, type: directory}
              member@workspace:packages/member: {}
              linked@link:../linked: {}
            """,
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert {
            name: (row["origin"], row["resolved_version"]) for name, row in _rows(data).items()
        } == {
            "dir-outside": ("../dir-outside", ""),
            "tgz-outside": ("../tgz-outside.tgz", "3.0.0"),
            "spec-only": ("../spec-only", "0.0.1"),
            "odd-git": ("git+ssh://git.example.org/team/odd-git.git@beef", "0.0.2"),
            "odd-tarball": ("tarball:something", "0.0.3"),
            "no-commit": ("git+https://git.example.org/team/no-commit.git", ""),
            "dup": ("../dup", ""),
        }
        assert len(data["dependencies"]) == 7
        assert respx.calls.call_count == 0

    @respx.mock
    def test_version_6_git_entry_keyed_by_repository_path(self, tmp_path):
        _npm_manifest(tmp_path, {"regular": "^1.0.0", "old-fork": "github:team/old-fork"})
        _write(
            tmp_path / "pnpm-lock.yaml",
            """\
            lockfileVersion: '6.0'
            packages:
              /regular@1.0.0:
                resolution: {integrity: sha512-reg}
              /@scope/scoped@2.0.0:
                resolution: {integrity: sha512-sc}
              github.com/team/old-fork/0123abcd:
                resolution: {tarball: https://codeload.github.com/team/old-fork/tar.gz/0123abcd}
                name: old-fork
                version: 0.3.0
                dependencies:
                  '@scope/scoped': 2.0.0
              git.example.org/team/typed/89ab:
                resolution: {commit: 89ab, repo: https://git.example.org/team/typed.git, type: git}
                name: typed
                version: 0.1.0
              github.com/team/nameless/ffff:
                resolution: {tarball: https://codeload.github.com/team/nameless/tar.gz/ffff}
              github.com/team/unlocated/eeee:
                name: unlocated
              '@broken':
                resolution: {integrity: sha512-x}
            """,
        )
        _mock_npm_package("regular", "1.0.0")
        _mock_npm_package("@scope/scoped", "2.0.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path, "--no-strict")
        assert result.exit_code == 0
        rows = _rows(data)
        assert {name: row["origin"] for name, row in rows.items()} == {
            "regular": "",
            "@scope/scoped": "",
            "old-fork": "https://codeload.github.com/team/old-fork/tar.gz/0123abcd",
            # Not declared by the manifest, so not reached from a direct
            # dependency: dropped with the other orphans.
        }
        assert rows["old-fork"]["resolved_version"] == "0.3.0"
        assert rows["@scope/scoped"]["direct_ancestors"] == ["old-fork"]
        assert _requests_mentioning("old-fork", "typed", "nameless", "unlocated") == []
