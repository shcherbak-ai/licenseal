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
from licenseal.discovery._walk import scan_exclusions
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
from tests._helpers import _check_json, _dirs, _file_diagnostics, _write


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

    def test_path_to_a_directory_the_scan_walks_is_own_code(self, tmp_path):
        nested = tmp_path / "services" / "api"
        _dirs(tmp_path, "services/api/lib/x", "services/shared")
        for written in (".", "./lib", "lib/x", "..", "../shared", "file:../shared", "file:."):
            assert path_origin(written, nested, tmp_path) is None, written
        # An empty path is the directory of the file that holds it.
        assert path_origin("  ", nested, tmp_path) is None

    def test_path_inside_the_scanned_directory_that_the_scan_does_not_read(self, tmp_path):
        _dirs(tmp_path, "libs", "vendor/kept", "third_party/sub/crate", "tools/env/lib")
        (tmp_path / "libs" / "pkg-1.0.tar.gz").write_bytes(b"")
        (tmp_path / "third_party" / "sub" / ".git").write_text("gitdir: elsewhere\n")
        (tmp_path / "tools" / "env" / "pyvenv.cfg").write_text("")
        for written in (
            "libs/pkg-1.0.tar.gz",  # an archive: a file is not scanned
            "vendor",  # a name the walk skips, and what is under it
            "vendor/kept",
            "third_party/sub",  # a nested repository, and what is under it
            "third_party/sub/crate",
            "tools/env",  # a virtualenv
            "tools/env/lib",
            "libs/missing",  # not there
        ):
            assert path_origin(written, tmp_path, tmp_path) == written, written
        assert path_origin("third_party", tmp_path, tmp_path) is None
        assert path_origin("tools", tmp_path, tmp_path) is None

    def test_path_into_an_excluded_directory_is_not_own_code(self, tmp_path):
        _dirs(tmp_path, "generated/client", "kept")
        assert path_origin("generated/client", tmp_path, tmp_path) is None
        with scan_exclusions(frozenset({(tmp_path / "generated").resolve()})):
            assert path_origin("generated/client", tmp_path, tmp_path) == "generated/client"
            assert path_origin("generated", tmp_path, tmp_path) == "generated"
            assert path_origin("kept", tmp_path, tmp_path) is None
        # The exclusions end with the scan they belong to.
        assert path_origin("generated", tmp_path, tmp_path) is None
        with scan_exclusions(frozenset({tmp_path.resolve()})):
            assert path_origin("kept", tmp_path, tmp_path) == "kept"

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
            ("ssh://git@example.org/a/b.git#abc", "git+ssh://example.org/a/b.git@abc"),
            ("git@example.org:a/b.git#v2", "git+example.org:a/b.git@v2"),
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
        _dirs(project, "pkgs/inside")
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
        _dirs(project, "engines/inside")
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
        _dirs(project, "engines/inside")
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
        _dirs(project, "apps/inside")
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
        _dirs(project, "pkgs/ownpkg")
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
        _dirs(project, "packages/dir-inside")
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


# ----------------------------------------------------------------------- Python


def _mock_pypi_release(name: str, version: str, license_id: str = "MIT") -> None:
    """Answer PyPI's project and version endpoints for ``name`` at ``version``."""
    payload = {
        "info": {"license": license_id, "version": version, "classifiers": [], "requires_dist": []},
        "releases": {version: []},
    }
    for url in (
        f"https://pypi.org/pypi/{name}/json",
        f"https://pypi.org/pypi/{name}/{version}/json",
    ):
        respx.get(url).mock(return_value=httpx.Response(200, json=payload))


def _origins(data: dict) -> dict[str, str]:
    return {dep["name"]: dep["origin"] for dep in data["dependencies"]}


_PY_FORKS = ("wheel-fork", "git-fork", "localonly", "dev-fork", "grp-fork", "rel-fork")


class TestPythonDirectReferences:
    """PEP 508 direct references: one UNKNOWN row each, and no PyPI request."""

    @respx.mock
    @pytest.mark.parametrize("flags", [(), ("--no-transitive",)])
    def test_pyproject_pep621_references(self, tmp_path, flags):
        project = tmp_path / "project"
        _dirs(project, "libs/own-lib")
        _write(
            project / "pyproject.toml",
            """\
            [project]
            name = "app"
            license = "MIT"
            dependencies = [
                "regular",
                "wheel-fork @ https://dl.example.org/w/wheel_fork-2.0-py3-none-any.whl#sha256=0123abcd",
                "git-fork[extra] @ git+https://tok3n@git.example.org/team/git-fork.git@v1.2#egg=x",
                "localonly @ file:///opt/pkgs/localonly",
                "rel-fork @ file:../rel-fork",
                "own-lib @ file:./libs/own-lib",
            ]

            [project.optional-dependencies]
            dev = ["dev-fork @ git+https://git.example.org/team/dev-fork.git"]

            [dependency-groups]
            test = ["grp-fork @ git+ssh://git@git.example.org/team/grp-fork.git@abc123"]
            """,
        )
        # PyPI owns every one of these names, under another license.
        for name in (*_PY_FORKS, "own-lib"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        _mock_pypi_release("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", *flags)
        assert result.exit_code == 1
        assert _origins(data) == {
            "regular": "",
            "wheel-fork": "https://dl.example.org/w/wheel_fork-2.0-py3-none-any.whl#sha256=0123abcd",
            "git-fork": "git+https://git.example.org/team/git-fork.git@v1.2",
            "localonly": "/opt/pkgs/localonly",
            "rel-fork": "../rel-fork",
            "dev-fork": "git+https://git.example.org/team/dev-fork.git",
            "grp-fork": "git+ssh://git.example.org/team/grp-fork.git@abc123",
        }
        rows = _rows(data)
        for name in _PY_FORKS:
            assert (rows[name]["license"], rows[name]["resolved_version"]) == ("UNKNOWN", ""), name
            assert rows[name]["source"] == "pyproject.toml"
        assert (rows["regular"]["license"], rows["regular"]["resolved_version"]) == ("MIT", "1.0.0")
        assert rows["dev-fork"]["group"] == "dev"
        assert _requests_mentioning(*_PY_FORKS, "own-lib") == []
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_setup_cfg_and_setup_py_references(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "vendor-src/cfg-own")
        _write(
            project / "setup.cfg",
            """\
            [metadata]
            name = app
            license = MIT

            [options]
            install_requires =
                regular
                cfg-fork @ https://dl.example.org/cfg_fork-1.0.tar.gz
                cfg-own @ file:./vendor-src/cfg-own

            [options.extras_require]
            dev =
                cfg-dev-fork @ git+https://git.example.org/team/cfg-dev-fork.git@main
            """,
        )
        _write(
            project / "sub" / "setup.py",
            """\
            from setuptools import setup

            setup(
                name="sub",
                install_requires=[
                    "py-fork @ git+https://git.example.org/team/py-fork.git@v3",
                    "py-own @ file:.",
                ],
                extras_require={"test": ["py-test-fork @ https://dl.example.org/py_test_fork.zip"]},
            )
            """,
        )
        forks = ("cfg-fork", "cfg-dev-fork", "py-fork", "py-test-fork")
        for name in (*forks, "cfg-own", "py-own"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        _mock_pypi_release("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            "cfg-fork": "https://dl.example.org/cfg_fork-1.0.tar.gz",
            "cfg-dev-fork": "git+https://git.example.org/team/cfg-dev-fork.git@main",
            "py-fork": "git+https://git.example.org/team/py-fork.git@v3",
            "py-test-fork": "https://dl.example.org/py_test_fork.zip",
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert rows["py-fork"]["source"] == "sub/setup.py"
        assert _requests_mentioning(*forks, "cfg-own", "py-own") == []

    @respx.mock
    def test_review_keyed_on_the_reference_clears_the_row(self, tmp_path):
        _write(
            tmp_path / "pyproject.toml",
            """\
            [project]
            name = "app"
            license = "MIT"
            dependencies = ["Git_Fork @ git+https://git.example.org/team/git-fork.git@v1.2"]
            """,
        )
        _refuse_everything_else()
        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])
        assert result.exit_code == 0
        scaffold = (tmp_path / REVIEW_FILE_NAME).read_text(encoding="utf-8")
        assert 'source = "git+https://git.example.org/team/git-fork.git@v1.2"\n' in scaffold
        (tmp_path / REVIEW_FILE_NAME).write_text(
            scaffold.replace('license = ""', 'license = "BSD-3-Clause"'),
            encoding="utf-8",
            newline="\n",
        )
        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert _rows(data)["Git_Fork"]["license"] == "BSD-3-Clause"
        assert respx.calls.call_count == 0


class TestPythonSourceTables:
    """Poetry, uv, and Pipfile source tables."""

    @respx.mock
    def test_poetry_git_path_and_url_tables(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "libs/path-inside", "tools/dev-inside")
        _write(
            project / "pyproject.toml",
            """\
            [tool.poetry]
            name = "app"
            license = "MIT"

            [[tool.poetry.source]]
            name = "internal"
            url = "https://pypi.internal.example.org/simple"

            [tool.poetry.dependencies]
            python = "^3.11"
            regular = ">=1.0"
            mirrored = { version = ">=2.0", source = "internal" }
            git-rev = { git = "https://tok3n@git.example.org/team/git-rev.git", rev = "0123abc" }
            git-tag = { git = "https://git.example.org/team/git-tag.git", tag = "v1.0" }
            git-branch = { git = "https://git.example.org/team/git-branch.git", branch = "main" }
            git-bare = { git = "https://git.example.org/team/git-bare.git" }
            url-dep = { url = "https://dl.example.org/url_dep-1.0.tar.gz" }
            path-outside = { path = "../path-outside", develop = true }
            path-inside = { path = "libs/path-inside" }
            multi = [
                { version = "^1.0", python = "<3.12" },
                { git = "https://git.example.org/team/multi.git", python = ">=3.12" },
            ]
            bad-git = { git = 7 }

            [tool.poetry.group.dev.dependencies]
            dev-git = { git = "https://git.example.org/team/dev-git.git" }
            dev-inside = { path = "tools/dev-inside" }
            """,
        )
        forks = (
            "git-rev",
            "git-tag",
            "git-branch",
            "git-bare",
            "url-dep",
            "path-outside",
            "multi",
            "bad-git",
            "dev-git",
        )
        for name in (*forks, "path-inside", "dev-inside"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        _mock_pypi_release("regular", "1.0.0")
        # An alternate index is not an off-registry source: the name is
        # looked up on PyPI.
        _mock_pypi_release("mirrored", "2.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict", "--no-require-lockfile")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            "mirrored": "",
            "git-rev": "git+https://git.example.org/team/git-rev.git@0123abc",
            "git-tag": "git+https://git.example.org/team/git-tag.git@v1.0",
            "git-branch": "git+https://git.example.org/team/git-branch.git@main",
            "git-bare": "git+https://git.example.org/team/git-bare.git",
            "url-dep": "https://dl.example.org/url_dep-1.0.tar.gz",
            "path-outside": "../path-outside",
            "multi": "git+https://git.example.org/team/multi.git",
            "bad-git": "unrecorded source",
            "dev-git": "git+https://git.example.org/team/dev-git.git",
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert rows["mirrored"]["license"] == "MIT"
        assert rows["dev-git"]["group"] == "dev"
        assert _requests_mentioning(*forks, "path-inside", "dev-inside") == []
        assert _requests_mentioning("mirrored")
        # The value that is not a string is on record. The other entry says
        # that the two registry requirements were resolved without a lockfile.
        assert _file_diagnostics(data) == [
            {
                "path": "pyproject.toml",
                "reason": "an entry of tool.poetry.dependencies has an unexpected type; ignored",
                "severity": "gap",
            }
        ]

    @respx.mock
    def test_uv_sources(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "libs/path-inside")
        _write(
            project / "pyproject.toml",
            """\
            [project]
            name = "app"
            license = "MIT"
            dependencies = [
                "regular",
                "indexed",
                "Git.Fork>=1.0",
                "url-fork",
                "path-outside",
                "path-inside",
                "member",
                "per-os",
                "already @ git+https://git.example.org/team/already.git@v1",
            ]

            [dependency-groups]
            dev = ["dev-fork"]

            [tool.uv.workspace]
            members = ["packages/*"]

            [[tool.uv.index]]
            name = "internal"
            url = "https://pypi.internal.example.org/simple"

            [tool.uv.sources]
            indexed = { index = "internal" }
            git-fork = { git = "https://git.example.org/team/git-fork.git", tag = "v1.0" }
            url-fork = { url = "https://dl.example.org/url_fork-1.0-py3-none-any.whl" }
            path-outside = { path = "../path-outside", editable = true }
            path-inside = { path = "libs/path-inside" }
            member = { workspace = true }
            per-os = [
                { index = "internal", marker = "os_name != 'nt'" },
                { git = "https://git.example.org/team/per-os.git", marker = "os_name == 'nt'" },
                "not a table",
            ]
            already = { git = "https://git.example.org/team/other.git" }
            dev-fork = { git = "https://git.example.org/team/dev-fork.git", branch = "main" }
            shared-fork = { git = "https://git.example.org/team/shared-fork.git", rev = "abc" }
            overridden = { git = "https://git.example.org/team/overridden.git" }
            """,
        )
        # A workspace member inherits the root's sources; its own win.
        _write(
            project / "packages" / "member" / "pyproject.toml",
            """\
            [project]
            name = "member"
            dependencies = ["shared-fork", "overridden", "regular"]

            [tool.uv.sources]
            overridden = { index = "internal" }
            """,
        )
        forks = ("git-fork", "url-fork", "path-outside", "per-os", "already", "dev-fork")
        for name in (*forks, "shared-fork", "path-inside", "member"):
            _mock_pypi_release(name.replace("git-fork", "Git.Fork"), "9.9.9", "GPL-3.0-only")
        for name in ("regular", "indexed", "overridden"):
            _mock_pypi_release(name, "1.0.0")
        _refuse_everything_else()
        result = CliRunner().invoke(
            main,
            ["check", "--path", str(project), "--dev", "--no-strict", "-f", "json"],
        )
        assert result.exit_code == 0
        assert "Excluded 1 local Python workspace package reference(s)" in result.output
        data = json.loads(result.output[result.output.index("{") :])
        assert _origins(data) == {
            "regular": "",
            "indexed": "",
            "overridden": "",
            "Git.Fork": "git+https://git.example.org/team/git-fork.git@v1.0",
            "url-fork": "https://dl.example.org/url_fork-1.0-py3-none-any.whl",
            "path-outside": "../path-outside",
            "per-os": "git+https://git.example.org/team/per-os.git",
            # The requirement's own direct reference wins over the table.
            "already": "git+https://git.example.org/team/already.git@v1",
            "dev-fork": "git+https://git.example.org/team/dev-fork.git@main",
            "shared-fork": "git+https://git.example.org/team/shared-fork.git@abc",
        }
        rows = _rows(data)
        assert rows["shared-fork"]["source"] == "packages/member/pyproject.toml"
        assert rows["Git.Fork"]["resolved_version"] == ""
        assert rows["dev-fork"]["group"] == "dev"
        assert _requests_mentioning(*forks, "git.fork", "shared-fork", "path-inside") == []
        assert _requests_mentioning("indexed") and _requests_mentioning("overridden")

    @respx.mock
    def test_pipfile_git_path_and_file_entries(self, tmp_path):
        project = tmp_path / "project"
        _write(
            project / "Pipfile",
            """\
            [packages]
            regular = "*"
            git-fork = { git = "https://tok3n@git.example.org/team/git-fork.git", ref = "v1.2" }
            hg-fork = { hg = "https://hg.example.org/team/hg-fork" }
            file-url = { file = "https://dl.example.org/file_url-1.0.tar.gz" }
            file-path = { file = "../wheels/file_path-1.0-py3-none-any.whl" }
            file-uri = { file = "file:///opt/wheels/file_uri-1.0-py3-none-any.whl" }
            path-outside = { path = "../path-outside", editable = true }
            itself = { path = ".", editable = true }

            [dev-packages]
            dev-fork = { git = "https://git.example.org/team/dev-fork.git" }
            """,
        )
        forks = (
            "git-fork",
            "hg-fork",
            "file-url",
            "file-path",
            "file-uri",
            "path-outside",
            "dev-fork",
        )
        for name in (*forks, "itself"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        _mock_pypi_release("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            "git-fork": "git+https://git.example.org/team/git-fork.git@v1.2",
            "hg-fork": "hg+https://hg.example.org/team/hg-fork",
            "file-url": "https://dl.example.org/file_url-1.0.tar.gz",
            "file-path": "../wheels/file_path-1.0-py3-none-any.whl",
            "file-uri": "/opt/wheels/file_uri-1.0-py3-none-any.whl",
            "path-outside": "../path-outside",
            "dev-fork": "git+https://git.example.org/team/dev-fork.git",
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert rows["git-fork"]["source"] == "Pipfile"
        assert _requests_mentioning(*forks, "itself") == []


class TestPythonRequirementsFiles:
    @respx.mock
    def test_url_vcs_and_path_lines(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "plugins/own-plugin", "vendor-src/own-vendored")
        # An archive inside the project is not something the scan reads.
        (project / "local_archive-1.0.tar.gz").write_bytes(b"")
        _write(
            project / "requirements.txt",
            """\
            --index-url https://pypi.internal.example.org/simple
            regular==1.0.0 --hash=sha256:aaaa
            named-fork @ https://dl.example.org/named_fork-2.0-py3-none-any.whl
            rel-named @ ../rel-named
            spaced-ref @ ../dir with space/spaced-ref ; python_version >= "3.9"
            git+https://tok3n@git.example.org/team/egg-fork.git@v1.2#egg=egg-fork&subdirectory=pkg
            git+https://git.example.org/team/vcs-fork.git@main
            hg+https://hg.example.org/team/hg-fork
            https://dl.example.org/wheels/wheel_fork-3.1-py3-none-any.whl --hash=sha256:bbbb
            https://dl.example.org/src/sdist-fork-0.9.tar.gz#sha256=cccc
            https://dl.example.org/src/snapshot.zip
            -e git+https://git.example.org/team/editable-fork.git#egg=editable-fork
            --editable=../editable-outside
            -e ../extras-outside[test,docs]
            -e .
            -e ./plugins/own-plugin
            ./vendor-src/own-vendored
            ../wheels/outside_wheel-1.0-py3-none-any.whl
            ..
            local_archive-1.0.tar.gz
            C:\\wheelhouse\\win_wheel-1.0-py3-none-any.whl
            """,
        )
        forks = (
            "named-fork",
            "rel-named",
            "spaced-ref",
            "egg-fork",
            "vcs-fork",
            "hg-fork",
            "wheel_fork",
            "sdist-fork",
            "snapshot",
            "editable-fork",
            "editable-outside",
            "extras-outside",
            "outside_wheel",
            "win_wheel",
        )
        for name in (*forks, "own-plugin", "own-vendored", "local_archive", "git", "https"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        _mock_pypi_release("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            "named-fork": "https://dl.example.org/named_fork-2.0-py3-none-any.whl",
            "rel-named": "../rel-named",
            "spaced-ref": "../dir with space/spaced-ref",
            # Named by ``#egg=``, by the archive's file name, or by the last
            # path segment.
            "egg-fork": "git+https://git.example.org/team/egg-fork.git@v1.2",
            "vcs-fork": "git+https://git.example.org/team/vcs-fork.git@main",
            "hg-fork": "hg+https://hg.example.org/team/hg-fork",
            "wheel_fork": "https://dl.example.org/wheels/wheel_fork-3.1-py3-none-any.whl#sha256:bbbb",
            "sdist-fork": "https://dl.example.org/src/sdist-fork-0.9.tar.gz#sha256=cccc",
            "snapshot": "https://dl.example.org/src/snapshot.zip",
            "editable-fork": "git+https://git.example.org/team/editable-fork.git",
            "editable-outside": "../editable-outside",
            "extras-outside": "../extras-outside",
            "outside_wheel": "../wheels/outside_wheel-1.0-py3-none-any.whl",
            "..": "..",
            "local_archive": "local_archive-1.0.tar.gz",
            "win_wheel": "C:\\wheelhouse\\win_wheel-1.0-py3-none-any.whl",
        }
        rows = _rows(data)
        assert (rows["regular"]["license"], rows["regular"]["resolved_version"]) == ("MIT", "1.0.0")
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert rows["egg-fork"]["source"] == "requirements.txt"
        assert _requests_mentioning(*forks, "own-", "local_archive") == []
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_editable_install_of_the_project_itself_is_not_a_dependency(self, tmp_path):
        _write(tmp_path / "requirements-dev.txt", "-e .\n-e .[test]\n--editable .\n.\n")
        _refuse_everything_else()
        result, data = _check_json(tmp_path, "--dev")
        assert result.exit_code == 0
        assert data["dependencies"] == []
        assert respx.calls.call_count == 0

    @respx.mock
    def test_relative_path_is_taken_from_the_file_that_names_it(self, tmp_path):
        project = tmp_path / "project"
        _write(project / "requirements.txt", "-r reqs/more.txt\n")
        # ``../libs/inside`` is inside the project from ``reqs/``; two levels
        # up is not.
        _write(project / "reqs" / "more.txt", "../libs/inside\n../../outside\n")
        _dirs(project, "libs/inside")
        _refuse_everything_else()
        _, data = _check_json(project, "--no-strict")
        assert [(d["name"], d["origin"], d["source"]) for d in data["dependencies"]] == [
            ("outside", "../../outside", "reqs/more.txt")
        ]


class TestPythonLockfiles:
    @respx.mock
    def test_uv_lock_git_url_path_and_directory_entries(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "libs/dir-inside", "libs/editable-inside")
        names = (
            "regular",
            "mirrored",
            "git-fork",
            "url-fork",
            "sdist-fork",
            "bare-url",
            "dir-outside",
            "path-outside",
            "dir-inside",
            "editable-outside",
            "editable-inside",
            "bad-source",
        )
        _write(
            project / "pyproject.toml",
            '[project]\nname = "app"\nlicense = "MIT"\ndependencies = '
            + json.dumps(list(names))
            + "\n\n[tool.uv.sources]\n"
            + 'dir-inside = { path = "libs/dir-inside" }\n'
            + 'editable-inside = { path = "libs/editable-inside", editable = true }\n',
        )
        _write(
            project / "uv.lock",
            """\
            version = 1

            [[package]]
            name = "app"
            version = "0.1.0"
            source = { virtual = "." }

            [[package]]
            name = "regular"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "mirrored"
            version = "2.0.0"
            source = { registry = "https://pypi.internal.example.org/simple" }

            [[package]]
            name = "git-fork"
            version = "1.2.0"
            source = { git = "https://tok3n@git.example.org/team/git-fork.git?rev=v1.2#0123abcd" }
            dependencies = [{ name = "via-git" }]

            [[package]]
            name = "via-git"
            version = "3.0.0"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "url-fork"
            version = "2.0"
            source = { url = "https://dl.example.org/w/url_fork-2.0-py3-none-any.whl" }

            [[package.wheels]]
            url = "https://dl.example.org/w/url_fork-2.0-py3-none-any.whl"
            hash = "sha256:89ab"

            [[package]]
            name = "sdist-fork"
            version = "0.9"
            source = { url = "https://dl.example.org/s/sdist_fork-0.9.tar.gz" }
            sdist = { url = "https://dl.example.org/s/sdist_fork-0.9.tar.gz", hash = "sha256:cdef" }

            [[package]]
            name = "bare-url"
            version = "0.1"
            source = { url = "https://dl.example.org/s/bare_url-0.1.zip" }
            wheels = ["not a table", { url = "x" }]

            [[package]]
            name = "dir-outside"
            version = "0.1.0"
            source = { directory = "../dir-outside" }

            [[package]]
            name = "path-outside"
            version = "0.2.0"
            source = { path = "../wheels/path_outside-0.2.0-py3-none-any.whl" }

            [[package]]
            name = "dir-inside"
            version = "0.3.0"
            source = { directory = "libs/dir-inside" }

            [[package]]
            name = "editable-outside"
            source = { editable = "../editable-outside" }

            [[package]]
            name = "editable-inside"
            version = "0.4.0"
            source = { editable = "libs/editable-inside" }

            [[package]]
            name = "bad-source"
            version = "0.5.0"
            source = { git = 7 }
            """,
        )
        forks = (
            "git-fork",
            "url-fork",
            "sdist-fork",
            "bare-url",
            "dir-outside",
            "path-outside",
            "editable-outside",
            "bad-source",
        )
        for name in (*forks, "dir-inside", "editable-inside"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        for name, version in (("regular", "1.0.0"), ("mirrored", "2.0.0"), ("via-git", "3.0.0")):
            _mock_pypi_release(name, version)
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        rows = _rows(data)
        assert {name: (row["origin"], row["resolved_version"]) for name, row in rows.items()} == {
            "regular": ("", "1.0.0"),
            "mirrored": ("", "2.0.0"),
            "via-git": ("", "3.0.0"),
            "git-fork": ("git+https://git.example.org/team/git-fork.git@0123abcd", "1.2.0"),
            "url-fork": (
                "https://dl.example.org/w/url_fork-2.0-py3-none-any.whl#sha256:89ab",
                "2.0",
            ),
            "sdist-fork": ("https://dl.example.org/s/sdist_fork-0.9.tar.gz#sha256:cdef", "0.9"),
            "bare-url": ("https://dl.example.org/s/bare_url-0.1.zip", "0.1"),
            "dir-outside": ("../dir-outside", "0.1.0"),
            "path-outside": ("../wheels/path_outside-0.2.0-py3-none-any.whl", "0.2.0"),
            "editable-outside": ("../editable-outside", ""),
            "bad-source": ("unrecorded source", "0.5.0"),
        }
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert all(rows[name]["license"] == "MIT" for name in ("regular", "mirrored", "via-git"))
        # The registry package only the git dependency pulls in names it.
        assert rows["via-git"]["direct_ancestors"] == ["git-fork"]
        assert rows["git-fork"]["source"] == "pyproject.toml"
        assert _requests_mentioning(*forks, "dir-inside", "editable-inside") == []
        assert _requests_mentioning("mirrored")
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_poetry_lock_git_url_directory_and_file_sources(self, tmp_path):
        project = tmp_path / "project"
        names = (
            "regular",
            "mirrored",
            "git-fork",
            "git-unresolved",
            "url-fork",
            "url-two-files",
            "dir-outside",
            "file-outside",
            "dir-inside",
            "odd-source",
            "no-url",
        )
        _write(
            project / "pyproject.toml",
            '[tool.poetry]\nname = "app"\nlicense = "MIT"\n\n[tool.poetry.dependencies]\n'
            + "".join(f'{name} = "*"\n' for name in names if name != "dir-inside")
            + 'dir-inside = { path = "libs/dir-inside" }\n',
        )
        _write(
            project / "libs" / "dir-inside" / "pyproject.toml",
            '[tool.poetry]\nname = "dir-inside"\n\n[tool.poetry.dependencies]\nvia-inside = "*"\n',
        )
        _write(
            project / "poetry.lock",
            """\
            [[package]]
            name = "regular"
            version = "1.0.0"

            [[package]]
            name = "mirrored"
            version = "2.0.0"

            [package.source]
            type = "legacy"
            url = "https://pypi.internal.example.org/simple"
            reference = "internal"

            [[package]]
            name = "git-fork"
            version = "1.2.0"

            [package.dependencies]
            via-git = ">=3"

            [package.source]
            type = "git"
            url = "https://tok3n@git.example.org/team/git-fork.git"
            reference = "main"
            resolved_reference = "0123abcd"

            [[package]]
            name = "via-git"
            version = "3.0.0"

            [[package]]
            name = "git-unresolved"
            version = "0.1.0"

            [package.source]
            type = "git"
            url = "https://git.example.org/team/git-unresolved.git"
            reference = "v0.1"

            [[package]]
            name = "url-fork"
            version = "2.0"
            files = [{ file = "url_fork-2.0-py3-none-any.whl", hash = "sha256:89ab" }]

            [package.source]
            type = "url"
            url = "https://dl.example.org/w/url_fork-2.0-py3-none-any.whl"

            [[package]]
            name = "url-two-files"
            version = "2.1"
            files = [{ file = "a.whl", hash = "sha256:1" }, { file = "b.whl", hash = "sha256:2" }]

            [package.source]
            type = "url"
            url = "https://dl.example.org/w/url_two_files-2.1.zip"

            [[package]]
            name = "dir-outside"
            version = "0.1.0"

            [package.source]
            type = "directory"
            url = "../dir-outside"

            [[package]]
            name = "file-outside"
            version = "0.2.0"

            [package.source]
            type = "file"
            url = "../wheels/file_outside-0.2.0-py3-none-any.whl"

            [[package]]
            name = "dir-inside"
            version = "0.3.0"

            [package.dependencies]
            via-inside = "*"

            [package.source]
            type = "directory"
            url = "libs/dir-inside"

            [[package]]
            name = "via-inside"
            version = "4.0.0"

            [[package]]
            name = "odd-source"
            version = "0.4.0"

            [package.source]
            type = "hg"
            url = "https://hg.example.org/team/odd-source"

            [[package]]
            name = "no-url"
            version = "0.5.0"

            [package.source]
            type = "git"

            [metadata]
            lock-version = "2.0"
            """,
        )
        forks = (
            "git-fork",
            "git-unresolved",
            "url-fork",
            "url-two-files",
            "dir-outside",
            "file-outside",
            "odd-source",
            "no-url",
        )
        for name in (*forks, "dir-inside"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        for name, version in (
            ("regular", "1.0.0"),
            ("mirrored", "2.0.0"),
            ("via-git", "3.0.0"),
            ("via-inside", "4.0.0"),
        ):
            _mock_pypi_release(name, version)
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        rows = _rows(data)
        assert {name: (row["origin"], row["resolved_version"]) for name, row in rows.items()} == {
            "regular": ("", "1.0.0"),
            "mirrored": ("", "2.0.0"),
            "via-git": ("", "3.0.0"),
            "via-inside": ("", "4.0.0"),
            "git-fork": ("git+https://git.example.org/team/git-fork.git@0123abcd", "1.2.0"),
            "git-unresolved": ("git+https://git.example.org/team/git-unresolved.git@v0.1", "0.1.0"),
            "url-fork": (
                "https://dl.example.org/w/url_fork-2.0-py3-none-any.whl#sha256:89ab",
                "2.0",
            ),
            "url-two-files": ("https://dl.example.org/w/url_two_files-2.1.zip", "2.1"),
            "dir-outside": ("../dir-outside", "0.1.0"),
            "file-outside": ("../wheels/file_outside-0.2.0-py3-none-any.whl", "0.2.0"),
            "odd-source": ("https://hg.example.org/team/odd-source", "0.4.0"),
            "no-url": ("unrecorded source", "0.5.0"),
        }
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert rows["via-git"]["direct_ancestors"] == ["git-fork"]
        # ``dir-inside`` is the project's own code: no row. The registry
        # package it needs is a dependency its own manifest declares.
        assert rows["via-inside"]["source"] == "libs/dir-inside/pyproject.toml"
        assert rows["via-inside"]["direct_ancestors"] == []
        assert _requests_mentioning(*forks, "dir-inside") == []
        assert _requests_mentioning("mirrored")
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_pipfile_lock_git_path_and_file_entries(self, tmp_path):
        project = tmp_path / "project"
        _write(project / "Pipfile", '[packages]\nregular = "*"\n')
        (project / "Pipfile.lock").write_text(
            json.dumps(
                {
                    "_meta": {"pipfile-spec": 6},
                    "default": {
                        "regular": {"version": "==1.0.0", "hashes": ["sha256:aa"]},
                        "git-fork": {
                            "git": "https://tok3n@git.example.org/team/git-fork.git",
                            "ref": "0123abcd",
                            "version": "==1.2.0",
                        },
                        "file-fork": {"file": "https://dl.example.org/file_fork-1.0.tar.gz"},
                        "path-outside": {"path": "../path-outside", "editable": True},
                        "itself": {"path": ".", "editable": True},
                    },
                    "develop": {
                        "dev-fork": {
                            "git": "https://git.example.org/team/dev-fork.git",
                            "ref": "beef",
                        },
                        "noversion": {"hashes": []},
                    },
                }
            ),
            encoding="utf-8",
        )
        forks = ("git-fork", "file-fork", "path-outside", "dev-fork")
        for name in (*forks, "itself"):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
        _mock_pypi_release("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict")
        assert result.exit_code == 0
        rows = _rows(data)
        assert {name: (row["origin"], row["resolved_version"]) for name, row in rows.items()} == {
            "regular": ("", "1.0.0"),
            "git-fork": ("git+https://git.example.org/team/git-fork.git@0123abcd", "1.2.0"),
            "file-fork": ("https://dl.example.org/file_fork-1.0.tar.gz", ""),
            "path-outside": ("../path-outside", ""),
            "dev-fork": ("git+https://git.example.org/team/dev-fork.git@beef", ""),
        }
        assert rows["dev-fork"]["group"] == "dev"
        assert _requests_mentioning(*forks, "itself") == []

        without_dev, data = _check_json(project, "--no-strict")
        assert without_dev.exit_code == 0
        assert "dev-fork" not in _rows(data)


class TestPythonAlternateIndex:
    @respx.mock
    def test_local_version_from_a_mirror_is_looked_up_on_pypi(self, tmp_path):
        # A ``+local`` build pinned from an internal mirror is not an
        # off-registry source: PyPI is asked for the name, and its license
        # is what is reported.
        _write(
            tmp_path / "requirements.txt",
            "--extra-index-url https://m.example.org/simple\nmirrored==2.1.0+cu124\n",
        )
        respx.get("https://pypi.org/pypi/mirrored/2.1.0+cu124/json").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://pypi.org/pypi/mirrored/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "info": {"license": "BSD-3-Clause", "version": "2.1.0", "requires_dist": []},
                    "releases": {"2.1.0": []},
                },
            )
        )
        _refuse_everything_else()
        result, data = _check_json(tmp_path, "--no-transitive")
        assert result.exit_code == 0
        row = _rows(data)["mirrored"]
        assert (row["origin"], row["license"]) == ("", "BSD-3-Clause")
        assert _requests_mentioning("mirrored")


class TestLockfileCannotClearADeclaredSource:
    """A dependency every manifest declares off-registry stays off-registry."""

    _LOCK = """\
        version = 1

        [[package]]
        name = "app"
        version = "0.1.0"
        source = { virtual = "." }

        [[package]]
        name = "git-fork"
        version = "1.2.0"
        source = { registry = "https://pypi.org/simple" }
        """

    @respx.mock
    def test_stale_lockfile_entry_takes_the_declared_origin(self, tmp_path):
        _write(
            tmp_path / "pyproject.toml",
            """\
            [project]
            name = "app"
            license = "MIT"
            dependencies = ["git-fork @ git+https://git.example.org/team/git-fork.git@v1.2"]
            """,
        )
        _write(tmp_path / "uv.lock", self._LOCK)
        # PyPI has a release of that name and version.
        _mock_pypi_release("git-fork", "1.2.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        row = _rows(data)["git-fork"]
        assert row["origin"] == "git+https://git.example.org/team/git-fork.git@v1.2"
        assert (row["license"], row["resolved_version"]) == ("UNKNOWN", "1.2.0")
        assert _requests_mentioning("git-fork") == []

    @respx.mock
    def test_name_also_declared_as_a_registry_requirement_follows_the_lockfile(self, tmp_path):
        _write(
            tmp_path / "pyproject.toml",
            '[project]\nname = "app"\nlicense = "MIT"\ndependencies = ["git-fork>=1.0"]\n',
        )
        _write(
            tmp_path / "tools" / "requirements.txt",
            "git-fork @ git+https://git.example.org/team/git-fork.git@v1.2\n",
        )
        _write(tmp_path / "uv.lock", self._LOCK)
        _mock_pypi_release("git-fork", "1.2.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert [(d["name"], d["origin"], d["license"]) for d in data["dependencies"]] == [
            ("git-fork", "", "MIT")
        ]


# ------------------------------------------------- Ruby: Gemfile blocks, rockets


def _mock_gem_latest(name: str, version: str = "1.0.0", license_id: str = "MIT") -> None:
    """Answer rubygems.org for an unpinned ``name``: latest version, then that version."""
    respx.get(f"https://rubygems.org/api/v1/gems/{name}.json").mock(
        return_value=httpx.Response(
            200, json={"name": name, "version": version, "licenses": [license_id]}
        )
    )
    _mock_gem(name, version, license_id)


class TestRubyGemfileSourceBlocks:
    """``git … do`` / ``github … do`` / ``path … do`` without a lockfile."""

    _GEMFILE = """\
        source "https://rubygems.org"
        gem "regular"

        git "https://tok3n@git.example.org/team/mono.git", branch: "stable" do
          gem "git-a"
          gem "git-b", "~> 2.0"
          group :development do
            gem "git-dev"
          end
          gem "own-option", path: "../own-option"
        end

        git("https://git.example.org/team/paren.git", :tag => "v3") do |repo|
          gem "git-paren"
        end

        github "team/hub" do
          gem "hub-a"
        end

        github "team/hub-ref", ref: "abc123" do
          gem "hub-ref"
        end

        path "../components" do
          gem "path-outside"
        end

        path "engines" do
          gem "path-inside"
        end

        git REPO_URL do
          gem "git-computed"
        end

        source "https://gems.internal.example.org" do
          gem "mirrored"
        end

        platforms :ruby do
          gem "platform-gem"
        end

        gem "after-blocks"
        """

    _FORKS = (
        "git-a",
        "git-b",
        "git-dev",
        "own-option",
        "git-paren",
        "hub-a",
        "hub-ref",
        "path-outside",
        "git-computed",
    )

    @respx.mock
    def test_gems_in_a_source_block_are_unknown_without_a_lookup(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "engines")
        _write(project / "Gemfile", self._GEMFILE)
        # rubygems.org owns every one of these names, under another license.
        for name in (*self._FORKS, "path-inside"):
            _mock_gem_latest(name, "9.9.9", "GPL-3.0-only")
        for name in ("regular", "mirrored", "platform-gem", "after-blocks"):
            _mock_gem_latest(name)
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict")
        assert result.exit_code == 0
        mono = "git+https://git.example.org/team/mono.git@stable"
        assert _origins(data) == {
            "regular": "",
            "git-a": mono,
            "git-b": mono,
            "git-dev": mono,
            # The line's own source option wins over the block.
            "own-option": "../own-option",
            "git-paren": "git+https://git.example.org/team/paren.git@v3",
            "hub-a": "git+https://github.com/team/hub.git",
            "hub-ref": "git+https://github.com/team/hub-ref.git@abc123",
            "path-outside": "../components",
            "git-computed": "unrecorded source",
            # Another gem server is not a repository or a path: its gems, and
            # the ones after the blocks close, are registry gems.
            "mirrored": "",
            "platform-gem": "",
            "after-blocks": "",
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in self._FORKS)
        assert all(
            rows[name]["license"] == "MIT"
            for name in ("regular", "mirrored", "platform-gem", "after-blocks")
        )
        assert rows["git-dev"]["group"] == "dev"
        assert rows["git-a"]["source"] == "Gemfile"
        assert _requests_mentioning(*self._FORKS, "path-inside") == []
        assert _requests_mentioning("mirrored")
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_strict_check_fails_until_the_block_gem_is_reviewed(self, tmp_path):
        _write(
            tmp_path / "Gemfile",
            """\
            github "team/hub", tag: "v1.4.0" do
              gem "hub-a"
            end
            """,
        )
        _mock_gem_latest("hub-a", "9.9.9", "MIT")
        _refuse_everything_else()
        result, _ = _check_json(tmp_path)
        assert result.exit_code == 1

        _review_file(
            tmp_path,
            """\
            [[review]]
            ecosystem = "ruby"
            package = "hub-a"
            source = "git+https://github.com/team/hub.git@v1.4.0"
            license = "MIT"
            """,
        )
        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert _rows(data)["hub-a"]["reviewed"] is True
        assert respx.calls.call_count == 0

    @respx.mock
    def test_lockfile_supplies_the_commit_for_a_block_gem(self, tmp_path):
        _write(
            tmp_path / "Gemfile",
            """\
            source "https://rubygems.org"
            git "https://git.example.org/team/mono.git", branch: "stable" do
              group :test do
                gem "git-test"
              end
            end
            """,
        )
        _write(
            tmp_path / "Gemfile.lock",
            """\
            GIT
              remote: https://git.example.org/team/mono.git
              revision: 0123abcd
              branch: stable
              specs:
                git-test (0.3.0)

            DEPENDENCIES
              git-test!
            """,
        )
        _refuse_everything_else()
        _, data = _check_json(tmp_path, "--dev", "--no-strict")
        row = _rows(data)["git-test"]
        assert row["origin"] == "git+https://git.example.org/team/mono.git@0123abcd"
        assert (row["group"], row["resolved_version"], row["source"]) == ("dev", "0.3.0", "Gemfile")

        _, data = _check_json(tmp_path, "--no-strict")
        assert data["dependencies"] == []

    @respx.mock
    def test_stale_lockfile_cannot_make_a_block_gem_a_registry_gem(self, tmp_path):
        _write(
            tmp_path / "Gemfile",
            """\
            source "https://rubygems.org"
            path "../components" do
              gem "path-outside"
            end
            """,
        )
        _write(
            tmp_path / "Gemfile.lock",
            """\
            GEM
              remote: https://rubygems.org/
              specs:
                path-outside (1.0.0)

            DEPENDENCIES
              path-outside
            """,
        )
        _mock_gem("path-outside", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        row = _rows(data)["path-outside"]
        assert (row["origin"], row["license"]) == ("../components", "UNKNOWN")
        assert _requests_mentioning("path-outside") == []


class TestRubyHashRocketSources:
    @respx.mock
    def test_hash_rocket_and_keyword_options_are_read_alike(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "engines/rocket-own")
        _write(
            project / "Gemfile",
            """\
            source "https://rubygems.org"
            gem "regular", :require => false
            gem "rocket-git", :git => "https://tok3n@git.example.org/team/rocket-git.git",
                              :branch => "main"
            gem "rocket-hub", ">= 1.0", :github => "team/rocket-hub", :ref => "abc"
            gem "rocket-path", :path => "../rocket-path"
            gem "rocket-own", :path => "./engines/rocket-own"
            gem "rocket-computed", :git => REPO, :tag => "v1"
            gem "rocket-sym-rev", :git => "https://git.example.org/team/sym.git", :branch => :main
            gem "keyword-git", git: "https://git.example.org/team/keyword-git.git", tag: "v2"
            gem "mixed", :github => "team/mixed", tag: "v5"
            gem "rocket-dev", :git => "https://git.example.org/team/rocket-dev.git", :group => :test
            """,
        )
        forks = (
            "rocket-git",
            "rocket-hub",
            "rocket-path",
            "rocket-computed",
            "rocket-sym-rev",
            "keyword-git",
            "mixed",
            "rocket-dev",
        )
        for name in (*forks, "rocket-own"):
            _mock_gem_latest(name, "9.9.9", "GPL-3.0-only")
        _mock_gem_latest("regular")
        _refuse_everything_else()
        result, data = _check_json(project, "--dev", "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            "rocket-git": "git+https://git.example.org/team/rocket-git.git@main",
            "rocket-hub": "git+https://github.com/team/rocket-hub.git@abc",
            "rocket-path": "../rocket-path",
            "rocket-computed": "unrecorded source",
            "rocket-sym-rev": "git+https://git.example.org/team/sym.git",
            "keyword-git": "git+https://git.example.org/team/keyword-git.git@v2",
            "mixed": "git+https://github.com/team/mixed.git@v5",
            "rocket-dev": "git+https://git.example.org/team/rocket-dev.git",
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert rows["regular"]["license"] == "MIT"
        assert rows["rocket-dev"]["group"] == "dev"
        assert _requests_mentioning(*forks, "rocket-own") == []
        assert "tok3n" not in json.dumps(data)


# --------------------------------------------------- npm: lockfiles, path specs

_NPMJS = "https://registry.npmjs.org"
_GIT_FORK = "git+ssh://git.example.org/team/git-fork.git@0123abcd"


def _versions(data: dict) -> dict[str, tuple[str, str]]:
    return {d["name"]: (d["origin"], d["resolved_version"]) for d in data["dependencies"]}


class TestNpmPathSpecs:
    @respx.mock
    def test_file_link_and_bare_path_specs_without_a_lockfile(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "packages/dir-inside", "packages/bare-inside")
        _npm_manifest(
            project,
            {
                "regular": "^1.0.0",
                "dir-outside": "file:../dir-outside",
                "link-outside": "link:../link-outside",
                "portal-outside": "portal:../portal-outside",
                "bare-outside": "../bare-outside",
                "rooted": "/opt/pkgs/rooted",
                "dir-inside": "file:./packages/dir-inside",
                "bare-inside": "./packages/bare-inside",
                "member": "workspace:^",
                "scp-fork": "git@git.example.org:team/scp-fork.git#v1",
            },
        )
        forks = ("dir-outside", "link-outside", "portal-outside", "bare-outside", "rooted")
        for name in (*forks, "dir-inside", "bare-inside", "member", "scp-fork"):
            _mock_npm_package(name, "9.9.9", "GPL-3.0-only")
        _mock_npm_package("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            "dir-outside": "../dir-outside",
            "link-outside": "../link-outside",
            "portal-outside": "../portal-outside",
            "bare-outside": "../bare-outside",
            "rooted": "/opt/pkgs/rooted",
            "scp-fork": "git+git.example.org:team/scp-fork.git@v1",
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in (*forks, "scp-fork"))
        assert _requests_mentioning(*forks, "inside", "member", "scp-fork") == []


class TestNpmLockfilesOffRegistry:
    """A lockfile entry that was not fetched from a registry is an UNKNOWN row."""

    _SPECS = {
        "regular": "^1.0.0",
        "mirrored": "^2.0.0",
        "git-fork": "git+ssh://git@git.example.org/team/git-fork.git#semver:^1.2.0",
        "hub-fork": "github:team/hub-fork#main",
        "tarball-fork": "https://dl.example.org/tarball-fork-1.0.0.tgz",
        "dir-outside": "file:../dir-outside",
        "dir-inside": "file:packages/dir-inside",
    }
    _FORKS = ("git-fork", "hub-fork", "tarball-fork", "dir-outside")

    def _project(self, tmp_path: Path, **specs: str) -> Path:
        project = tmp_path / "project"
        _dirs(project, "packages/dir-inside", "packages/portal-inside", "vendor-tgz")
        (project / "vendor-tgz" / "tgz-inside-0.4.0.tgz").write_bytes(b"")
        _npm_manifest(project, self._SPECS | specs)
        # The public registry owns every one of the fork names.
        for name in (*self._FORKS, "dir-inside", *specs):
            _mock_npm_package(name, "9.9.9", "GPL-3.0-only")
        _mock_npm_package("regular", "1.0.0")
        _mock_npm_package("mirrored", "2.0.0")
        _mock_npm_package("via-git", "3.0.0")
        return project

    def _assert_forks_unknown_and_unrequested(self, data: dict, *more: str) -> None:
        rows = _rows(data)
        forks = (*self._FORKS, *more)
        assert all(rows[name]["license"] == "UNKNOWN" for name in forks)
        assert all(rows[name]["license"] == "MIT" for name in ("regular", "mirrored", "via-git"))
        # The registry package only the git dependency needs is still reported.
        assert rows["via-git"]["direct_ancestors"] == ["git-fork"]
        assert rows["git-fork"]["source"] == "package.json"
        assert _requests_mentioning(*forks, "dir-inside") == []
        # Another registry is not an off-registry source: the public one is asked.
        assert _requests_mentioning("mirrored")

    @respx.mock
    def test_package_lock_v3(self, tmp_path):
        project = self._project(
            tmp_path,
            **{
                "tgz-outside": "file:../tgz-outside-0.3.0.tgz",
                "tgz-inside": "file:vendor-tgz/tgz-inside-0.4.0.tgz",
                "@team/ghp": "^3.0.0",
                "bundled": "^5.0.0",
            },
        )
        _mock_npm_package("@team/ghp", "3.0.0")
        _mock_npm_package("bundled", "5.0.0")
        registry = f"{_NPMJS}/{{0}}/-/{{0}}-{{1}}.tgz"
        packages = {
            "": {"name": "app"},
            "node_modules/regular": {
                "version": "1.0.0",
                "resolved": registry.format("regular", "1.0.0"),
            },
            "node_modules/mirrored": {
                "version": "2.0.0",
                "resolved": "https://npm.internal.example.org/repo/npm/mirrored/-/mirrored-2.0.0.tgz",
            },
            "node_modules/@team/ghp": {
                "version": "3.0.0",
                "resolved": "https://npm.pkg.github.com/download/@team/ghp/3.0.0/0a1b2c",
            },
            "node_modules/bundled": {"version": "5.0.0", "inBundle": True},
            "node_modules/git-fork": {
                "version": "1.2.3",
                "resolved": "git+ssh://git@git.example.org/team/git-fork.git#0123abcd",
                "dependencies": {"via-git": "^3.0.0"},
            },
            "node_modules/via-git": {
                "version": "3.0.0",
                "resolved": registry.format("via-git", "3.0.0"),
            },
            "node_modules/hub-fork": {
                "version": "0.4.0",
                "resolved": "git+ssh://git@github.com/team/hub-fork.git#4567cdef",
            },
            "node_modules/tarball-fork": {
                "version": "1.0.0",
                "resolved": "https://dl.example.org/tarball-fork-1.0.0.tgz",
                "integrity": "sha512-tar",
            },
            "node_modules/dir-outside": {"resolved": "../dir-outside", "link": True},
            "../dir-outside": {"name": "dir-outside", "version": "0.1.0"},
            "node_modules/dir-inside": {"resolved": "packages/dir-inside", "link": True},
            "packages/dir-inside": {"name": "dir-inside", "version": "0.2.0"},
            "node_modules/tgz-outside": {
                "version": "0.3.0",
                "resolved": "file:../tgz-outside-0.3.0.tgz",
                "integrity": "sha512-tgz",
            },
            "node_modules/tgz-inside": {
                "version": "0.4.0",
                "resolved": "file:vendor-tgz/tgz-inside-0.4.0.tgz",
            },
            "node_modules/unresolved-link": {"link": True},
            "node_modules/untargeted-link": {"resolved": "../untargeted", "link": True},
        }
        (project / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8"
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            "regular": ("", "1.0.0"),
            "mirrored": ("", "2.0.0"),
            "@team/ghp": ("", "3.0.0"),
            "bundled": ("", "5.0.0"),
            "via-git": ("", "3.0.0"),
            "git-fork": (_GIT_FORK, "1.2.3"),
            "hub-fork": ("git+ssh://github.com/team/hub-fork.git@4567cdef", "0.4.0"),
            "tarball-fork": ("https://dl.example.org/tarball-fork-1.0.0.tgz#sha512-tar", "1.0.0"),
            # A linked directory outside the project takes its version from
            # the directory's own entry.
            "dir-outside": ("../dir-outside", "0.1.0"),
            "tgz-outside": ("../tgz-outside-0.3.0.tgz", "0.3.0"),
            # An archive is not scanned, wherever it lies.
            "tgz-inside": ("vendor-tgz/tgz-inside-0.4.0.tgz", "0.4.0"),
        }
        self._assert_forks_unknown_and_unrequested(data, "tgz-outside", "tgz-inside")
        assert _requests_mentioning("tgz-inside", "untargeted") == []

    @respx.mock
    def test_package_lock_v1(self, tmp_path):
        project = self._project(tmp_path, **{"url-resolved": "^2.0.0"})
        registry = f"{_NPMJS}/{{0}}/-/{{0}}-{{1}}.tgz"
        tree = {
            "regular": {"version": "1.0.0", "resolved": registry.format("regular", "1.0.0")},
            "mirrored": {
                "version": "2.0.0",
                "resolved": "https://npm.internal.example.org/mirrored/-/mirrored-2.0.0.tgz",
            },
            "git-fork": {
                "version": "git+ssh://git@git.example.org/team/git-fork.git#0123abcd",
                "from": "git-fork@git+ssh://git@git.example.org/team/git-fork.git#semver:^1.2.0",
                "requires": {"via-git": "^3.0.0"},
            },
            "via-git": {"version": "3.0.0", "resolved": registry.format("via-git", "3.0.0")},
            "hub-fork": {
                "version": "github:team/hub-fork#4567cdef",
                "from": "github:team/hub-fork",
            },
            "tarball-fork": {
                "version": "https://dl.example.org/tarball-fork-1.0.0.tgz",
                "integrity": "sha512-tar",
            },
            "dir-outside": {"version": "file:../dir-outside"},
            "dir-inside": {"version": "file:packages/dir-inside"},
            "url-resolved": {
                "version": "2.0.0",
                "resolved": "https://dl.example.org/url-resolved-2.0.0.tar.gz",
                "integrity": "sha512-url",
            },
        }
        (project / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 1, "dependencies": tree}), encoding="utf-8"
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            "regular": ("", "1.0.0"),
            "mirrored": ("", "2.0.0"),
            "via-git": ("", "3.0.0"),
            # In this format the spec stands where the version would.
            "git-fork": (_GIT_FORK, ""),
            "hub-fork": ("git+https://github.com/team/hub-fork@4567cdef", ""),
            "tarball-fork": ("https://dl.example.org/tarball-fork-1.0.0.tgz", ""),
            "dir-outside": ("../dir-outside", ""),
            "url-resolved": (
                "https://dl.example.org/url-resolved-2.0.0.tar.gz#sha512-url",
                "2.0.0",
            ),
        }
        self._assert_forks_unknown_and_unrequested(data, "url-resolved")

    @respx.mock
    def test_package_lock_v1_with_only_the_projects_own_code_is_not_a_gap(self, tmp_path):
        _dirs(tmp_path, "packages/dir-inside")
        _npm_manifest(tmp_path, {"dir-inside": "file:packages/dir-inside"})
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {"dir-inside": {"version": "file:packages/dir-inside"}},
                }
            ),
            encoding="utf-8",
        )
        _refuse_everything_else()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert (data["dependencies"], data["diagnostics"]) == ([], [])

    @respx.mock
    def test_yarn_classic(self, tmp_path):
        project = self._project(tmp_path)
        _write(
            project / "yarn.lock",
            """\
            # yarn lockfile v1


            regular@^1.0.0:
              version "1.0.0"
              resolved "https://registry.yarnpkg.com/regular/-/regular-1.0.0.tgz#aaaa"
              integrity sha512-reg

            mirrored@^2.0.0:
              version "2.0.0"
              resolved "https://npm.internal.example.org/mirrored/-/mirrored-2.0.0.tgz#bbbb"

            "git-fork@git+ssh://git@git.example.org/team/git-fork.git#semver:^1.2.0":
              version "1.2.3"
              resolved "git+ssh://git@git.example.org/team/git-fork.git#0123abcd"
              dependencies:
                via-git "^3.0.0"

            via-git@^3.0.0:
              version "3.0.0"
              resolved "https://registry.yarnpkg.com/via-git/-/via-git-3.0.0.tgz#cccc"

            "hub-fork@github:team/hub-fork#main":
              version "0.4.0"
              resolved "https://codeload.github.com/team/hub-fork/tar.gz/4567cdef"

            "tarball-fork@https://dl.example.org/tarball-fork-1.0.0.tgz":
              version "1.0.0"
              resolved "https://dl.example.org/tarball-fork-1.0.0.tgz#dddd"
              integrity sha512-tar
              dependencies:
                regular "^1.0.0"
              peerDependenciesMeta:
                regular "^1.0.0"

            "dir-outside@file:../dir-outside":
              version "0.1.0"

            "dir-inside@file:packages/dir-inside":
              version "0.2.0"
            """,
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            "regular": ("", "1.0.0"),
            "mirrored": ("", "2.0.0"),
            "via-git": ("", "3.0.0"),
            "git-fork": (_GIT_FORK, "1.2.3"),
            # The tarball of the commit the shorthand resolved to.
            "hub-fork": ("https://codeload.github.com/team/hub-fork/tar.gz/4567cdef", "0.4.0"),
            "tarball-fork": ("https://dl.example.org/tarball-fork-1.0.0.tgz#sha512-tar", "1.0.0"),
            # No ``resolved`` line: the spec in the entry's header says where.
            "dir-outside": ("../dir-outside", "0.1.0"),
        }
        self._assert_forks_unknown_and_unrequested(data)

    @respx.mock
    def test_yarn_berry(self, tmp_path):
        project = self._project(
            tmp_path,
            **{
                "portal-inside": "portal:packages/portal-inside",
                "patched": "^4.0.0",
                "patched-fork": "https://git.example.org/team/patched-fork.git#commit=beef",
                "scp-fork": "git@git.example.org:team/scp-fork.git",
                "exec-thing": "exec:./gen.js",
                "plain": "^6.0.0",
            },
        )
        _mock_npm_package("patched", "4.0.0")
        _mock_npm_package("plain", "6.0.0")
        locator = "::locator=app%40workspace%3A."
        fork_patch = (
            "patched-fork@patch:patched-fork@https%3A//git.example.org/team/patched-fork.git"
            "%23commit=beef#./p.patch" + locator
        )
        _write(
            project / "yarn.lock",
            f"""\
            __metadata:
              version: 8

            "regular@npm:^1.0.0":
              version: 1.0.0
              resolution: "regular@npm:1.0.0"

            "mirrored@npm:^2.0.0":
              version: 2.0.0
              resolution: "mirrored@npm:2.0.0"

            "git-fork@git+ssh://git@git.example.org/team/git-fork.git#semver:^1.2.0":
              version: 1.2.3
              resolution: "git-fork@ssh://git@git.example.org/team/git-fork.git#commit=0123abcd"
              dependencies:
                via-git: "npm:^3.0.0"

            "via-git@npm:^3.0.0":
              version: 3.0.0
              resolution: "via-git@npm:3.0.0"

            "hub-fork@github:team/hub-fork#main":
              version: 0.4.0
              resolution: "hub-fork@https://github.com/team/hub-fork.git#commit=4567cdef"

            "tarball-fork@https://dl.example.org/tarball-fork-1.0.0.tgz":
              version: 1.0.0
              resolution: "tarball-fork@https://dl.example.org/tarball-fork-1.0.0.tgz"
              checksum: 10c0/abcdef

            "dir-outside@file:../dir-outside{locator}":
              version: 0.1.0
              resolution: "dir-outside@file:../dir-outside#../dir-outside::hash=ab&locator=x"

            "dir-inside@file:packages/dir-inside{locator}":
              version: 0.2.0
              resolution: "dir-inside@file:packages/dir-inside#packages/dir-inside::hash=cd"

            "portal-inside@portal:packages/portal-inside{locator}":
              version: 0.0.0-use.local
              resolution: "portal-inside@portal:packages/portal-inside{locator}"

            "patched@patch:patched@npm%3A4.0.0#./patches/patched.patch::version=4.0.0":
              version: 4.0.0
              resolution: "patched@patch:patched@npm%3A4.0.0#./patches/patched.patch::version=4.0.0"

            "{fork_patch}":
              version: 0.5.0
              resolution: "{fork_patch}"

            "scp-fork@git@git.example.org:team/scp-fork.git":
              version: 0.6.0
              resolution: "scp-fork@git@git.example.org:team/scp-fork.git#commit=89ab"

            "exec-thing@exec:./gen.js":
              version: 0.7.0
              resolution: "exec-thing@exec:./gen.js"

            "plain@^6.0.0":
              version: 6.0.0

            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
            """,
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            "regular": ("", "1.0.0"),
            "mirrored": ("", "2.0.0"),
            "via-git": ("", "3.0.0"),
            "patched": ("", "4.0.0"),
            "plain": ("", "6.0.0"),
            "git-fork": (_GIT_FORK, "1.2.3"),
            "hub-fork": ("git+https://github.com/team/hub-fork.git@4567cdef", "0.4.0"),
            "tarball-fork": ("https://dl.example.org/tarball-fork-1.0.0.tgz#10c0/abcdef", "1.0.0"),
            "dir-outside": ("../dir-outside", "0.1.0"),
            # A patch of a git dependency is that git dependency.
            "patched-fork": ("git+https://git.example.org/team/patched-fork.git@beef", "0.5.0"),
            "scp-fork": ("git+git.example.org:team/scp-fork.git@89ab", "0.6.0"),
            # A protocol the parser does not know is an origin as written.
            "exec-thing": ("exec:./gen.js", "0.7.0"),
        }
        self._assert_forks_unknown_and_unrequested(data, "patched-fork", "scp-fork", "exec-thing")
        assert _requests_mentioning("portal-inside") == []
        assert _requests_mentioning("patched") and _requests_mentioning("plain")

    @respx.mock
    def test_bun_lock(self, tmp_path):
        project = self._project(tmp_path, **{"@scope/git-scoped": "github:team/git-scoped"})
        packages = {
            "regular": ["regular@1.0.0", "", {}, "sha512-reg"],
            "mirrored": ["mirrored@2.0.0", "https://npm.internal.example.org/", {}, "sha512-mir"],
            "git-fork": [
                "git-fork@git+ssh://git@git.example.org/team/git-fork.git#0123abcd",
                {"dependencies": {"via-git": "^3.0.0"}},
                "0123abcd",
            ],
            "via-git": ["via-git@3.0.0", "", {}, "sha512-via"],
            "hub-fork": ["hub-fork@github:team/hub-fork#4567cde", {}, "team-hub-fork-4567cde"],
            "tarball-fork": ["tarball-fork@https://dl.example.org/tarball-fork-1.0.0.tgz", {}],
            "dir-outside": ["dir-outside@file:../dir-outside", {}],
            "dir-inside": ["dir-inside@file:packages/dir-inside", {}],
            "@scope/git-scoped": [
                "@scope/git-scoped@git+ssh://git@git.example.org/team/git-scoped.git#beef",
                {},
                "beef",
            ],
            "member": ["member@workspace:packages/member"],
        }
        (project / "bun.lock").write_text(
            json.dumps({"lockfileVersion": 1, "packages": packages}), encoding="utf-8"
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            "regular": ("", "1.0.0"),
            "mirrored": ("", "2.0.0"),
            "via-git": ("", "3.0.0"),
            "git-fork": (_GIT_FORK, ""),
            "hub-fork": ("git+https://github.com/team/hub-fork@4567cde", ""),
            "tarball-fork": ("https://dl.example.org/tarball-fork-1.0.0.tgz", ""),
            "dir-outside": ("../dir-outside", ""),
            # The ``@`` of the git user is not the end of a scoped name.
            "@scope/git-scoped": ("git+ssh://git.example.org/team/git-scoped.git@beef", ""),
        }
        self._assert_forks_unknown_and_unrequested(data, "@scope/git-scoped")
        assert _requests_mentioning("member") == []

    @respx.mock
    @pytest.mark.parametrize("lockfile", ["package-lock.json", "yarn.lock"])
    def test_lockfile_does_not_turn_an_unknown_manifest_row_into_a_clean_one(
        self, tmp_path, lockfile
    ):
        # The manifest says git; the lockfile lists the same name as a plain
        # registry tarball. The row stays UNKNOWN, with the declared source.
        _npm_manifest(tmp_path, {"git-fork": "github:team/git-fork#v1.2.0"})
        tarball = f"{_NPMJS}/git-fork/-/git-fork-1.2.0.tgz"
        if lockfile == "package-lock.json":
            packages = {"node_modules/git-fork": {"version": "1.2.0", "resolved": tarball}}
            content = json.dumps({"lockfileVersion": 3, "packages": packages})
        else:
            content = (
                "# yarn lockfile v1\n\n\ngit-fork@^1.2.0:\n"
                f'  version "1.2.0"\n  resolved "{tarball}#aa"\n'
            )
        (tmp_path / lockfile).write_text(content, encoding="utf-8")
        _mock_npm_package("git-fork", "1.2.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path)
        assert result.exit_code == 1
        row = _rows(data)["git-fork"]
        assert row["origin"] == "git+https://github.com/team/git-fork@v1.2.0"
        assert (row["license"], row["resolved_version"]) == ("UNKNOWN", "1.2.0")
        assert _requests_mentioning("git-fork") == []


# ------------------------------------------------------------------ Rust: Cargo

_CRATES_IO_INDEX = "registry+https://github.com/rust-lang/crates.io-index"
_TEAM = "https://git.example.org/team"


def _mock_crate(
    name: str, version: str, license_id: str = "MIT", requires: tuple[str, ...] = ()
) -> None:
    """Answer crates.io for ``name``: its newest version, license, and dependencies."""
    base = f"https://crates.io/api/v1/crates/{name}"
    respx.get(base).mock(
        return_value=httpx.Response(200, json={"crate": {"max_stable_version": version}})
    )
    respx.get(f"{base}/{version}").mock(
        return_value=httpx.Response(200, json={"version": {"num": version, "license": license_id}})
    )
    respx.get(f"{base}/{version}/dependencies").mock(
        return_value=httpx.Response(
            200,
            json={
                "dependencies": [
                    {"crate_id": child, "kind": "normal", "req": "^1.0", "optional": False}
                    for child in requires
                ]
            },
        )
    )


def _cargo_lock(*packages: tuple[str, str, str, tuple[str, ...]]) -> str:
    """Cargo.lock text from ``(name, version, source, dependencies)`` packages.

    An empty ``source`` writes no ``source`` line: a crate built from a path.
    """
    blocks = []
    for name, version, source, dependencies in packages:
        lines = ["[[package]]", f'name = "{name}"', f'version = "{version}"']
        if source:
            lines.append(f'source = "{source}"')
        if dependencies:
            lines.append(f"dependencies = {json.dumps(list(dependencies))}")
        blocks.append("\n".join(lines))
    return "version = 3\n\n" + "\n\n".join(blocks) + "\n"


class TestCargoManifestSources:
    """Cargo.toml without a Cargo.lock."""

    _FORKS = {
        "git-fork": f"git+{_TEAM}/git-fork.git@0123abcd",
        "tag-fork": f"git+{_TEAM}/tag-fork@v2.0.0",
        "branch-fork": f"git+{_TEAM}/branch-fork@next",
        "bare-fork": f"git+{_TEAM}/bare-fork",
        "real-fork": f"git+{_TEAM}/real-fork",
        "build-fork": f"git+{_TEAM}/build-fork",
        "unix-fork": f"git+{_TEAM}/unix-fork",
        "dir-outside": "../dir-outside",
        "versioned-outside": "../versioned-outside",
    }

    @staticmethod
    def _project(tmp_path: Path) -> Path:
        project = tmp_path / "project"
        _dirs(project, "crates/dir-inside")
        _write(
            project / "Cargo.toml",
            """\
            [package]
            name = "app"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            regular = "1.0"
            mirrored = { version = "2.0", registry = "internal" }
            tag-fork = { git = "https://git.example.org/team/tag-fork", tag = "v2.0.0" }
            branch-fork = { git = "https://git.example.org/team/branch-fork", branch = "next" }
            bare-fork = { git = "https://git.example.org/team/bare-fork" }
            renamed = { package = "real-fork", git = "https://git.example.org/team/real-fork" }
            dir-outside = { path = "../dir-outside" }
            versioned-outside = { path = "../versioned-outside", version = "0.4" }
            dir-inside = { path = "crates/dir-inside" }

            [dependencies.git-fork]
            git = "https://user:tok3n@git.example.org/team/git-fork.git"
            rev = "0123abcd"
            branch = "ignored-beside-rev"

            [build-dependencies]
            build-fork = { git = "https://git.example.org/team/build-fork" }

            [dev-dependencies]
            dev-fork = { git = "https://git.example.org/team/dev-fork" }

            [target.'cfg(unix)'.dependencies]
            unix-fork = { git = "https://git.example.org/team/unix-fork" }
            """,
        )
        return project

    def _mock_registry(self) -> None:
        # crates.io owns every one of the fork names, under another license.
        for name in (*self._FORKS, "renamed", "dev-fork", "dir-inside"):
            _mock_crate(name, "9.9.9", "GPL-3.0-only")
        _mock_crate("regular", "1.0.0")
        _mock_crate("mirrored", "2.0.0")
        _refuse_everything_else()

    @respx.mock
    def test_git_and_path_dependencies_are_unknown_rows(self, tmp_path):
        project = self._project(tmp_path)
        self._mock_registry()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {"regular": "", "mirrored": "", **self._FORKS}
        rows = _rows(data)
        for name in self._FORKS:
            assert (rows[name]["license"], rows[name]["resolved_version"]) == ("UNKNOWN", "")
            assert rows[name]["source"] == "Cargo.toml"
        # A ``registry`` key names another registry, which is not an
        # off-registry source: crates.io is asked.
        assert rows["mirrored"]["license"] == "MIT"
        assert _requests_mentioning("mirrored")
        assert _requests_mentioning(*self._FORKS, "renamed", "dev-fork", "dir-inside") == []
        assert "tok3n" not in json.dumps(data)

    @respx.mock
    def test_unknown_rows_fail_a_strict_scan(self, tmp_path):
        project = self._project(tmp_path)
        self._mock_registry()
        result, data = _check_json(project)
        assert result.exit_code == 1
        assert data["summary"]["unknown"] == len(self._FORKS)

    @respx.mock
    def test_dev_git_dependency_is_a_dev_row(self, tmp_path):
        project = self._project(tmp_path)
        self._mock_registry()
        result, data = _check_json(project, "--no-strict", "--dev")
        assert result.exit_code == 0
        row = _rows(data)["dev-fork"]
        assert (row["origin"], row["group"]) == (f"git+{_TEAM}/dev-fork", "dev")
        assert _requests_mentioning("dev-fork") == []

    @respx.mock
    def test_patch_and_replace_redirect_registry_crates(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "crates/local-patch", "crates/own-deep")
        _write(
            project / "Cargo.toml",
            """\
            [package]
            name = "app"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            regular = "1.0"
            patched = "1.0"
            replaced = "2.0"
            local-patch = "3.0"
            repinned = "1.0"

            [patch.crates-io]
            patched = { git = "https://git.example.org/team/patched", branch = "fix" }
            local-patch = { path = "crates/local-patch" }
            deep-patch = { git = "https://git.example.org/team/deep-patch" }
            own-deep = { path = "crates/own-deep" }
            repinned = { version = "1.0.5", registry = "internal" }

            [replace]
            "replaced:2.0.0" = { path = "../replaced" }
            """,
        )
        # ``regular`` needs two crates the manifest redirects, and a plain one.
        _mock_crate("regular", "1.0.0", requires=("deep-patch", "own-deep", "plain-child"))
        _mock_crate("plain-child", "1.0.0")
        _mock_crate("repinned", "1.0.0")
        redirected = ("patched", "replaced", "local-patch", "deep-patch", "own-deep")
        for name in redirected:
            _mock_crate(name, "9.9.9", "GPL-3.0-only")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            "plain-child": "",
            # An entry that only names another registry is not a redirect.
            "repinned": "",
            "patched": f"git+{_TEAM}/patched@fix",
            "replaced": "../replaced",
            # Redirected wherever it appears in the graph, not only where it
            # is declared. A redirect to a directory the scan walks is the
            # project's own code: no row.
            "deep-patch": f"git+{_TEAM}/deep-patch",
        }
        rows = _rows(data)
        assert rows["deep-patch"]["direct_ancestors"] == ["regular"]
        assert all(
            rows[name]["license"] == "UNKNOWN" for name in ("patched", "replaced", "deep-patch")
        )
        assert _requests_mentioning(*redirected) == []


class TestCargoLockSources:
    """What a Cargo.lock records, read beside the Cargo.toml that declares it."""

    _OFF_REGISTRY = {
        "git-fork": (f"git+{_TEAM}/git-fork.git@0123abcd", "0.5.0"),
        "dir-outside": ("../dir-outside", "0.2.0"),
        "patched": (f"git+{_TEAM}/patched@89abcdef", "1.0.9"),
        "deep-patch": ("../deep-patch", "0.7.0"),
    }
    _REGISTRY = {
        "regular": "1.0.3",
        "mirrored": "2.0.1",
        "sparse-mirrored": "2.1.0",
        "via-git": "3.0.0",
        "via-path": "1.1.0",
        "via-own": "1.2.0",
    }

    def _project(self, tmp_path: Path) -> Path:
        project = tmp_path / "project"
        _dirs(project, "crates/dir-inside")
        _write(
            project / "Cargo.toml",
            """\
            [package]
            name = "app"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            regular = "1.0"
            mirrored = { version = "2.0", registry = "internal" }
            sparse-mirrored = { version = "2.1", registry = "sparse-internal" }
            git-fork = { git = "https://git.example.org/team/git-fork.git", branch = "main" }
            dir-outside = { path = "../dir-outside" }
            dir-inside = { path = "crates/dir-inside" }
            patched = "1.0"

            [patch.crates-io]
            patched = { git = "https://git.example.org/team/patched" }
            deep-patch = { path = "../deep-patch" }
            """,
        )
        internal = "https://cargo.internal.example.org/index"
        roots = ("regular", "mirrored", "sparse-mirrored", "git-fork", "dir-outside")
        (project / "Cargo.lock").write_text(
            _cargo_lock(
                ("app", "0.1.0", "", (*roots, "dir-inside", "patched")),
                ("regular", "1.0.3", _CRATES_IO_INDEX, ("deep-patch",)),
                ("mirrored", "2.0.1", f"registry+{internal}", ()),
                ("sparse-mirrored", "2.1.0", f"sparse+{internal}/", ()),
                (
                    "git-fork",
                    "0.5.0",
                    f"git+{_TEAM}/git-fork.git?branch=main#0123abcd",
                    ("via-git",),
                ),
                ("via-git", "3.0.0", _CRATES_IO_INDEX, ()),
                ("dir-outside", "0.2.0", "", ("via-path",)),
                ("via-path", "1.1.0", _CRATES_IO_INDEX, ()),
                ("dir-inside", "0.1.0", "", ("via-own",)),
                ("via-own", "1.2.0", _CRATES_IO_INDEX, ()),
                ("patched", "1.0.9", f"git+{_TEAM}/patched#89abcdef", ()),
                ("deep-patch", "0.7.0", "", ()),
            ),
            encoding="utf-8",
        )
        for name, version in self._REGISTRY.items():
            _mock_crate(name, version)
        # crates.io owns the other names too, at the locked versions.
        for name, (_origin, version) in self._OFF_REGISTRY.items():
            _mock_crate(name, version, "GPL-3.0-only")
        _mock_crate("dir-inside", "0.1.0", "GPL-3.0-only")
        _refuse_everything_else()
        return project

    @respx.mock
    def test_git_and_path_crates_are_rows_at_the_locked_version(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            **{name: ("", version) for name, version in self._REGISTRY.items()},
            **self._OFF_REGISTRY,
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in self._OFF_REGISTRY)
        assert all(rows[name]["license"] == "MIT" for name in self._REGISTRY)
        # What a git or path crate pulls in from the registry names it, and
        # so does what the project's own path crate pulls in.
        assert rows["via-git"]["direct_ancestors"] == ["git-fork"]
        assert rows["via-path"]["direct_ancestors"] == ["dir-outside"]
        assert rows["via-own"]["direct_ancestors"] == ["dir-inside"]
        assert rows["deep-patch"]["direct_ancestors"] == ["regular"]
        assert rows["git-fork"]["source"] == "Cargo.toml"
        assert _requests_mentioning(*self._OFF_REGISTRY, "dir-inside") == []
        # A crate locked from another registry is looked up on crates.io.
        assert _requests_mentioning("sparse-mirrored")

    @respx.mock
    def test_review_keyed_on_the_origin_clears_each_row(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project)
        assert result.exit_code == 1
        stanzas = "".join(
            f'[[review]]\necosystem = "rust"\npackage = "{dep["name"]}"\n'
            f'source = "{dep["origin"]}"\nlicense = "MIT"\nnote = "read at that source"\n\n'
            for dep in data["dependencies"]
            if dep["origin"]
        )
        (project / REVIEW_FILE_NAME).write_text(stanzas, encoding="utf-8", newline="\n")
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == len(self._OFF_REGISTRY)
        assert _requests_mentioning(*self._OFF_REGISTRY) == []


# ---------------------------------------------------------------- PHP: Composer

_VENDOR_GIT = "https://git.example.org/acme"


def _mock_packagist(name: str, version: str = "1.0.0", license_id: str = "MIT") -> None:
    respx.get(f"https://repo.packagist.org/p2/{name}.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "packages": {name: [{"version": version, "license": [license_id], "require": {}}]}
            },
        )
    )


_COMPOSER_REPOSITORIES = [
    {
        "type": "package",
        "package": {
            "name": "acme/inline-git",
            "version": "1.2.0",
            "source": {
                "type": "git",
                "url": "https://tok3n@git.example.org/acme/inline-git.git",
                "reference": "v1.2.0",
            },
        },
    },
    {
        "type": "package",
        "package": [
            {
                "name": "acme/inline-zip",
                "version": "2.0.0",
                "dist": {
                    "type": "zip",
                    "url": "https://dl.example.org/inline-zip-2.0.0.zip",
                    "shasum": "abc123",
                },
            },
            {"name": "acme/inline-bare", "version": "0.1.0"},
            {
                "name": "acme/inline-own",
                "version": "0.2.0",
                "dist": {"type": "path", "url": "lib/inline-own"},
            },
        ],
    },
    {"type": "path", "url": "./packages/*"},
    {"type": "path", "url": "../outside-lib"},
    {"type": "vcs", "url": f"{_VENDOR_GIT}/vcs-fork"},
    {"type": "hg", "url": "https://hg.example.org/acme/hg-fork"},
    {"type": "composer", "url": "https://packages.internal.example.org"},
]

_COMPOSER_REQUIRE = {
    "php": "^8.1",
    "acme/regular": "^1.0",
    "acme/mirrored": "^1.0",
    "acme/inline-git": "^1.2",
    "acme/inline-zip": "^2.0",
    "acme/inline-bare": "*",
    "acme/inline-own": "*",
    "acme/own-lib": "*",
    "acme/vcs-fork": "dev-main",
    "acme/hg-fork": "dev-default",
    "acme/outside-lib": "*",
}


def _composer_project(tmp_path: Path, repositories: object = None) -> Path:
    """A composer.json that takes packages from every kind of repository."""
    project = tmp_path / "project"
    _dirs(project, "lib/inline-own")
    manifest = {
        "name": "acme/app",
        "license": "MIT",
        "repositories": _COMPOSER_REPOSITORIES if repositories is None else repositories,
        "require": _COMPOSER_REQUIRE,
        "require-dev": {"acme/own-lib": "*"},
    }
    _write(project / "composer.json", json.dumps(manifest))
    # The project's own package, held by the ``packages/*`` path repository.
    own = {"name": "acme/own-lib", "require": {"acme/own-dep": "^1.0"}}
    _write(project / "packages" / "own-lib" / "composer.json", json.dumps(own))
    return project


class TestComposerManifestSources:
    """composer.json without a composer.lock."""

    _INLINE = {
        "acme/inline-git": f"git+{_VENDOR_GIT}/inline-git.git@v1.2.0",
        "acme/inline-zip": "https://dl.example.org/inline-zip-2.0.0.zip#abc123",
        "acme/inline-bare": "unrecorded source",
    }
    # Looked up on Packagist: registry packages, and the packages of a
    # ``vcs`` repository or of a ``path`` repository outside the scanned
    # directory, which composer.json does not name.
    _LOOKED_UP = (
        "acme/regular",
        "acme/mirrored",
        "acme/own-dep",
        "acme/vcs-fork",
        "acme/hg-fork",
        "acme/outside-lib",
    )

    @respx.mock
    @pytest.mark.parametrize("as_map", [False, True], ids=["list", "map"])
    def test_inline_packages_are_rows_and_own_path_packages_are_not(self, tmp_path, as_map):
        repositories: object = _COMPOSER_REPOSITORIES
        if as_map:
            repositories = {f"repo-{i}": repo for i, repo in enumerate(_COMPOSER_REPOSITORIES)}
        project = _composer_project(tmp_path, repositories)
        for name in self._LOOKED_UP:
            _mock_packagist(name)
        for name in (*self._INLINE, "acme/inline-own", "acme/own-lib"):
            _mock_packagist(name, "9.9.9", "GPL-3.0-only")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict", "--dev")
        assert result.exit_code == 0
        assert _origins(data) == {**dict.fromkeys(self._LOOKED_UP, ""), **self._INLINE}
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in self._INLINE)
        assert all(rows[name]["resolved_version"] == "" for name in self._INLINE)
        assert rows["acme/own-dep"]["source"] == "packages/own-lib/composer.json"
        assert _requests_mentioning("inline-", "own-lib") == []
        assert all(_requests_mentioning(name) for name in self._LOOKED_UP)
        assert "tok3n" not in json.dumps(data)
        # The inline package at a path inside the scanned directory, and both
        # requirements on the package the path repository holds.
        assert "Excluded 3 local PHP workspace package reference(s)" in result.output

    @respx.mock
    def test_malformed_repository_entries_are_read_as_absent(self, tmp_path):
        project = tmp_path / "project"
        manifest = {
            "name": "acme/app",
            "license": "MIT",
            "repositories": [
                "packagist.org",
                {"type": "package", "package": "not a table"},
                {"type": "package", "package": [{"version": "1.0.0"}, 7]},
                {"type": "path", "url": 7},
                {"type": "vcs", "url": None},
            ],
            "require": {"acme/regular": "^1.0"},
        }
        _write(project / "composer.json", json.dumps(manifest))
        _write(project / "composer.lock", json.dumps({"packages": []}))
        _mock_packagist("acme/regular")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {"acme/regular": ""}

    @respx.mock
    def test_repositories_that_are_not_a_list_or_a_map_declare_nothing(self, tmp_path):
        project = tmp_path / "project"
        manifest = {"repositories": "none", "require": {"acme/regular": "^1.0"}}
        _write(project / "composer.json", json.dumps(manifest))
        _mock_packagist("acme/regular")
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {"acme/regular": ""}


def _lock_entry(name: str, version: str, **fields: object) -> dict:
    return {"name": name, "version": version, "license": ["MIT"], **fields}


class TestComposerLockSources:
    """composer.lock, read beside the composer.json that declares the repositories."""

    _OFF_REGISTRY = {
        "acme/vcs-fork": ("git+git.example.org:acme/vcs-fork.git@0123abcd", "dev-main"),
        # The repository URL is reported as the lockfile writes it.
        "acme/hg-fork": ("hg+https://hg.example.org/acme/hg-fork/@tip", "dev-default"),
        "acme/inline-git": (f"git+{_VENDOR_GIT}/inline-git.git@89abcdef", "1.2.0"),
        "acme/inline-zip": ("https://dl.example.org/inline-zip-2.0.0.zip#abc123", "2.0.0"),
        "acme/inline-bare": ("unrecorded source", "0.1.0"),
        "acme/outside-lib": ("../outside-lib", "dev-main"),
        # An archive from an ``artifact`` repository: its dist is a path.
        "acme/zipped": ("artifacts/acme-zipped-3.0.0.zip", "3.0.0"),
    }
    _REGISTRY = {
        "acme/regular": "1.0.0",
        "acme/mirrored": "1.4.0",
        "acme/child": "1.1.0",
        "acme/via-vcs": "1.0.0",
        "acme/own-dep": "1.0.0",
        "acme/odd-dist": "1.0.0",
    }

    def _lock(self) -> dict:
        hub = "https://github.com/acme"
        internal = "https://packages.internal.example.org/dist"
        return {
            "packages": [
                _lock_entry(
                    "acme/regular",
                    "v1.0.0",
                    source={"type": "git", "url": f"{hub}/regular.git", "reference": "aaa"},
                    dist={"type": "zip", "url": f"{hub}/regular/zipball/aaa", "shasum": ""},
                    require={"php": "^8.1", "acme/child": "^1.0"},
                ),
                _lock_entry("acme/child", "1.1.0"),
                _lock_entry("acme/mirrored", "1.4.0", dist={"type": "zip", "url": internal}),
                _lock_entry(
                    "acme/vcs-fork",
                    "dev-main",
                    source={
                        "type": "git",
                        "url": "git@git.example.org:acme/vcs-fork.git",
                        "reference": "0123abcd",
                    },
                    dist={"type": "zip", "url": f"{_VENDOR_GIT}/vcs-fork/zipball/0123abcd"},
                    license=["GPL-3.0-only"],
                    require={"acme/via-vcs": "^1.0"},
                ),
                _lock_entry("acme/via-vcs", "1.0.0"),
                _lock_entry(
                    "acme/hg-fork",
                    "dev-default",
                    source={
                        "type": "hg",
                        "url": "https://hg.example.org/acme/hg-fork/",
                        "reference": "tip",
                    },
                ),
                _lock_entry(
                    "acme/inline-git",
                    "1.2.0",
                    source={
                        "type": "git",
                        "url": f"{_VENDOR_GIT}/inline-git.git",
                        "reference": "89abcdef",
                    },
                ),
                _lock_entry(
                    "acme/inline-zip",
                    "2.0.0",
                    dist={
                        "type": "zip",
                        "url": "https://dl.example.org/inline-zip-2.0.0.zip",
                        "shasum": "abc123",
                    },
                ),
                _lock_entry("acme/inline-bare", "0.1.0", source={"type": "git"}, dist="none"),
                _lock_entry(
                    "acme/inline-own", "0.2.0", dist={"type": "path", "url": "lib/inline-own"}
                ),
                _lock_entry(
                    "acme/outside-lib",
                    "dev-main",
                    dist={"type": "path", "url": "../outside-lib", "reference": "xyz"},
                    license=["GPL-3.0-only"],
                ),
                _lock_entry(
                    "acme/own-lib", "dev-main", dist={"type": "path", "url": "packages/own-lib"}
                ),
                _lock_entry("acme/own-dep", "1.0.0"),
                _lock_entry(
                    "acme/zipped",
                    "3.0.0",
                    dist={"type": "zip", "url": "artifacts/acme-zipped-3.0.0.zip", "shasum": "ff"},
                    license=["GPL-3.0-only"],
                ),
                # Not a string where the URL goes: read as a registry entry.
                _lock_entry("acme/odd-dist", "1.0.0", dist={"type": "zip", "url": 7}),
            ],
            "packages-dev": [],
        }

    def _project(self, tmp_path: Path, repositories: object = None) -> Path:
        project = _composer_project(tmp_path, repositories)
        _write(project / "composer.lock", json.dumps(self._lock()))
        # Packagist owns every name, under another license.
        for name in (*self._OFF_REGISTRY, *self._REGISTRY, "acme/own-lib", "acme/inline-own"):
            _mock_packagist(name, "9.9.9", "GPL-3.0-only")
        _refuse_everything_else()
        return project

    @respx.mock
    def test_entries_from_declared_repositories_are_unknown_rows(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project, "--no-strict", "--dev")
        assert result.exit_code == 0
        assert _versions(data) == {
            **{name: ("", version) for name, version in self._REGISTRY.items()},
            **self._OFF_REGISTRY,
        }
        rows = _rows(data)
        # The license the lockfile records for such an entry is not used.
        assert all(rows[name]["license"] == "UNKNOWN" for name in self._OFF_REGISTRY)
        assert all(rows[name]["license"] == "MIT" for name in self._REGISTRY)
        assert rows["acme/via-vcs"]["direct_ancestors"] == ["acme/vcs-fork"]
        assert rows["acme/vcs-fork"]["source"] == "composer.json"
        # The lockfile answers for every name it holds: nothing is asked.
        assert respx.calls.call_count == 0

    @respx.mock
    def test_without_declared_repositories_the_same_entries_are_registry_rows(self, tmp_path):
        # The lockfile alone does not say that an entry came from a
        # version-control repository: only a path entry does.
        project = self._project(tmp_path, repositories=[])
        result, data = _check_json(project, "--no-strict", "--dev")
        origins = _origins(data)
        # A path entry and a local archive say what they are by themselves.
        assert origins.pop("acme/outside-lib") == "../outside-lib"
        assert origins.pop("acme/zipped") == "artifacts/acme-zipped-3.0.0.zip"
        assert "acme/inline-own" not in origins
        assert "acme/own-lib" not in origins
        assert set(origins.values()) == {""}
        # As a registry row it has the license the lockfile records.
        assert _rows(data)["acme/vcs-fork"]["license"] == "GPL-3.0-only"
        assert result.exit_code == 1

    @respx.mock
    def test_review_keyed_on_the_locked_commit_clears_the_row(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project)
        assert result.exit_code == 1
        stanzas = "".join(
            f'[[review]]\necosystem = "php"\npackage = "{dep["name"]}"\n'
            f'source = "{dep["origin"]}"\nlicense = "MIT"\nnote = "read at that source"\n\n'
            for dep in data["dependencies"]
            if dep["origin"]
        )
        (project / REVIEW_FILE_NAME).write_text(stanzas, encoding="utf-8", newline="\n")
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == len(self._OFF_REGISTRY)
        assert respx.calls.call_count == 0

    @respx.mock
    def test_lockfile_without_a_manifest_beside_it(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "lib/inline-own", "packages/own-lib")
        _write(project / "composer.lock", json.dumps(self._lock()))
        _refuse_everything_else()
        _result, data = _check_json(project, "--no-strict")
        origins = _origins(data)
        assert origins.pop("acme/outside-lib") == "../outside-lib"
        assert origins.pop("acme/zipped") == "artifacts/acme-zipped-3.0.0.zip"
        assert set(origins.values()) == {""}
        assert respx.calls.call_count == 0


# ------------------------------------------------- .NET: project references


def _mock_nuspec(name: str, version: str, license_id: str = "MIT") -> None:
    lower = name.lower()
    respx.get(f"https://api.nuget.org/v3-flatcontainer/{lower}/{version}/{lower}.nuspec").mock(
        return_value=httpx.Response(
            200,
            text=(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
                f"<metadata><id>{name}</id><version>{version}</version>"
                f'<license type="expression">{license_id}</license></metadata></package>'
            ),
        )
    )


_APP_CSPROJ = """\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <LibsDir>..\\..\\..\\libs</LibsDir>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Regular.Lib" Version="1.0.0" />
    <PackageReference Include="Pinned.Lib" />
    <ProjectReference Include="..\\..\\..\\Shared\\Shared.csproj" />
    <ProjectReference Include="$(LibsDir)\\ByProperty\\ByProperty.fsproj" />
    <ProjectReference Include="$(SolutionDir)Unlocated\\Unlocated.csproj" />
    <ProjectReference Include="$(RepoRoot)src\\Sibling\\SIBLING.csproj" />
    <ProjectReference Include="$(MSBuildThisFileDirectory)..\\Sibling\\Sibling.csproj" />
    <ProjectReference Include="..\\Sibling\\Sibling.csproj; ..\\..\\..\\Listed\\Listed.csproj" />
  </ItemGroup>
</Project>
"""


class TestDotnetProjectReferences:
    """A ``<ProjectReference>`` is a row only when it leaves the scanned directory."""

    _OUTSIDE = {
        "Shared": "..\\..\\..\\Shared\\Shared.csproj",
        # Located through the project's own property, reported as written.
        "ByProperty": "$(LibsDir)\\ByProperty\\ByProperty.fsproj",
        # A property the project file does not define, and no project file of
        # that name in the scanned tree: not shown to be inside.
        "Unlocated": "$(SolutionDir)Unlocated\\Unlocated.csproj",
        "Listed": "..\\..\\..\\Listed\\Listed.csproj",
    }

    @staticmethod
    def _project(tmp_path: Path) -> Path:
        project = tmp_path / "project"
        _write(project / "src" / "App" / "App.csproj", _APP_CSPROJ)
        # Central package versions: one for a package, one that happens to
        # carry the name of a referenced project.
        _write(
            project / "Directory.Packages.props",
            """\
            <Project>
              <ItemGroup>
                <PackageVersion Include="Pinned.Lib" Version="2.0.0" />
                <PackageVersion Include="Shared" Version="9.9.9" />
              </ItemGroup>
            </Project>
            """,
        )
        _write(
            project / "src" / "Sibling" / "Sibling.csproj", '<Project Sdk="Microsoft.NET.Sdk" />\n'
        )
        return project

    def _mock_registry(self) -> None:
        _mock_nuspec("Regular.Lib", "1.0.0")
        _mock_nuspec("Pinned.Lib", "2.0.0")
        # NuGet owns every one of the project names, under another license.
        for name in (*self._OUTSIDE, "Sibling"):
            _mock_nuspec(name, "9.9.9", "GPL-3.0-only")
        _refuse_everything_else()

    @respx.mock
    def test_reference_outside_the_scanned_directory_is_an_unknown_row(self, tmp_path):
        project = self._project(tmp_path)
        self._mock_registry()
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            "Regular.Lib": ("", "1.0.0"),
            "Pinned.Lib": ("", "2.0.0"),
            # No version is taken from the central package versions.
            **{name: (origin, "") for name, origin in self._OUTSIDE.items()},
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in self._OUTSIDE)
        assert rows["Shared"]["source"] == "src/App/App.csproj"
        assert _requests_mentioning(*self._OUTSIDE, "Sibling") == []

    @respx.mock
    def test_unknown_rows_fail_a_strict_scan_until_reviewed(self, tmp_path):
        # The two registry references have no lockfile; that is accepted here
        # so that the unknown rows alone decide the exit code.
        project = self._project(tmp_path)
        self._mock_registry()
        result, data = _check_json(project, "--no-require-lockfile")
        assert result.exit_code == 1
        # A path holds backslashes: the stanza is written by the scaffold.
        report = project / "report.json"
        result = CliRunner().invoke(
            main, ["init-review-file", "--path", str(project), "--from-report", str(report)]
        )
        assert result.exit_code == 0
        scaffold = (project / REVIEW_FILE_NAME).read_text(encoding="utf-8")
        assert 'source = "..\\\\..\\\\..\\\\Shared\\\\Shared.csproj"\n' in scaffold
        (project / REVIEW_FILE_NAME).write_text(
            scaffold.replace('license = ""', 'license = "MIT"'), encoding="utf-8", newline="\n"
        )
        result, data = _check_json(project, "--no-require-lockfile")
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == len(self._OUTSIDE)
        assert _requests_mentioning(*self._OUTSIDE, "Sibling") == []


# -------------------------------------------------------- Maven: system scope


class TestMavenSystemScope:
    """A ``system``-scoped dependency is a local JAR: no repository is asked."""

    _LOCAL = {
        "com.vendor:outside-jar": "${libs.dir}/outside-jar-3.1.jar",
        "com.vendor:jdk-tools": "${java.home}/../lib/tools.jar",
        # A JAR is not something the scan reads, wherever it lies.
        "com.vendor:inside-jar": "${basedir}/lib/inside-jar-2.0.jar",
        "com.vendor:pathless": "unrecorded source",
    }

    @staticmethod
    def _project(tmp_path: Path) -> Path:
        project = tmp_path / "project"
        _write(
            project / "pom.xml",
            """\
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>org.example</groupId>
              <artifactId>app</artifactId>
              <version>1.0.0</version>
              <properties>
                <libs.dir>${project.basedir}/../libs</libs.dir>
              </properties>
              <dependencies>
                <dependency>
                  <groupId>org.example</groupId>
                  <artifactId>regular</artifactId>
                  <version>1.0</version>
                </dependency>
                <dependency>
                  <groupId>com.vendor</groupId>
                  <artifactId>outside-jar</artifactId>
                  <version>3.1</version>
                  <scope>system</scope>
                  <systemPath>${libs.dir}/outside-jar-3.1.jar</systemPath>
                </dependency>
                <dependency>
                  <groupId>com.vendor</groupId>
                  <artifactId>jdk-tools</artifactId>
                  <version>1.8</version>
                  <scope>system</scope>
                  <systemPath>${java.home}/../lib/tools.jar</systemPath>
                </dependency>
                <dependency>
                  <groupId>com.vendor</groupId>
                  <artifactId>inside-jar</artifactId>
                  <version>2.0</version>
                  <scope>system</scope>
                  <systemPath>${basedir}/lib/inside-jar-2.0.jar</systemPath>
                </dependency>
                <dependency>
                  <groupId>com.vendor</groupId>
                  <artifactId>pathless</artifactId>
                  <version>1.0</version>
                  <scope>system</scope>
                </dependency>
              </dependencies>
            </project>
            """,
        )
        respx.get(
            "https://repo.maven.apache.org/maven2/org/example/regular/1.0/regular-1.0.pom"
        ).mock(
            return_value=httpx.Response(
                200,
                text=(
                    '<project xmlns="http://maven.apache.org/POM/4.0.0">'
                    "<groupId>org.example</groupId><artifactId>regular</artifactId>"
                    "<version>1.0</version>"
                    "<licenses><license><name>MIT</name></license></licenses></project>"
                ),
            )
        )
        # The registry dependency's own graph is served, so nothing under it
        # is recorded as unread.
        respx.get(
            "https://api.deps.dev/v3/systems/MAVEN/packages/org.example%3Aregular/versions/1.0"
            ":dependencies"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "nodes": [
                        {
                            "versionKey": {
                                "system": "MAVEN",
                                "name": "org.example:regular",
                                "version": "1.0",
                            },
                            "relation": "SELF",
                        }
                    ]
                },
            )
        )
        _refuse_everything_else()
        return project

    @respx.mock
    def test_local_jar_outside_the_scanned_directory_is_an_unknown_row(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project, "--no-strict", "--dev")
        assert result.exit_code == 0
        assert _versions(data) == {
            "org.example:regular": ("", "1.0"),
            **{name: (origin, "") for name, origin in self._LOCAL.items()},
        }
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in self._LOCAL)
        assert all(rows[name]["group"] == "dev" for name in self._LOCAL)
        assert rows["org.example:regular"]["license"] == "MIT"
        assert _requests_mentioning("vendor", "-jar", "jdk-tools", "pathless") == []

    @respx.mock
    def test_system_scope_is_left_out_without_dev(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert _origins(data) == {"org.example:regular": ""}
        assert _requests_mentioning("vendor", "-jar", "jdk-tools", "pathless") == []


# ------------------------------- paths inside the scan that nothing reads


class TestPathsInsideTheScanThatNothingReads:
    """A path dependency is the project's own code only when the scan reads it.

    That is a directory inside the scanned directory that the walk enters.
    An archive, a directory under a name the walk skips, a nested
    repository, an excluded directory, and a path that is not there are
    dependencies like a path outside the scanned directory.
    """

    _UNREAD = {
        "wheel-own": "./wheels/wheel_own-1.0-py3-none-any.whl",
        "vendored-py": "./vendor/vendored-py",
        "submodule-py": "./third_party/submodule-py",
        "missing-py": "./libs/missing-py",
        "sdist_own": "./sdists/sdist_own-2.0.tar.gz",
        "tgz-own": "./tarballs/tgz-own-1.0.0.tgz",
        "vendored-node": "./vendor/vendored-node",
        "vendored-gem": "vendor/gems/vendored-gem",
    }
    _OWN = ("walked-py", "generated-py", "walked-node", "walked-gem")

    def _project(self, tmp_path: Path) -> Path:
        project = tmp_path / "project"
        _dirs(
            project,
            "wheels",
            "sdists",
            "tarballs",
            "vendor/vendored-py",
            "vendor/vendored-node",
            "vendor/gems/vendored-gem",
            "third_party/submodule-py",
            "libs/walked-py",
            "generated/generated-py",
            "packages/walked-node",
            "components/walked-gem",
        )
        (project / "wheels" / "wheel_own-1.0-py3-none-any.whl").write_bytes(b"")
        (project / "sdists" / "sdist_own-2.0.tar.gz").write_bytes(b"")
        (project / "tarballs" / "tgz-own-1.0.0.tgz").write_bytes(b"")
        (project / "third_party" / "submodule-py" / ".git").write_text("gitdir: elsewhere\n")
        _write(
            project / "pyproject.toml",
            """\
            [project]
            name = "app"
            version = "1.0"
            license = "MIT"
            dependencies = [
                "regular>=1.0",
                "wheel-own @ file:./wheels/wheel_own-1.0-py3-none-any.whl",
                "vendored-py @ file:./vendor/vendored-py",
                "submodule-py @ file:./third_party/submodule-py",
                "missing-py @ file:./libs/missing-py",
                "walked-py @ file:./libs/walked-py",
                "generated-py @ file:./generated/generated-py",
            ]
            """,
        )
        _write(project / "requirements.txt", "./sdists/sdist_own-2.0.tar.gz\n")
        _npm_manifest(
            project,
            {
                "tgz-own": "file:./tarballs/tgz-own-1.0.0.tgz",
                "vendored-node": "file:./vendor/vendored-node",
                "walked-node": "file:./packages/walked-node",
            },
        )
        _write(
            project / "Gemfile",
            """\
            source "https://rubygems.org"
            gem "vendored-gem", path: "vendor/gems/vendored-gem"
            gem "walked-gem", path: "components/walked-gem"
            """,
        )
        # The registries own every one of these names, under another license.
        for name in (*self._UNREAD, *self._OWN):
            _mock_pypi_release(name, "9.9.9", "GPL-3.0-only")
            _mock_npm_package(name, "9.9.9", "GPL-3.0-only")
            _mock_gem_latest(name, "9.9.9", "GPL-3.0-only")
        _mock_pypi_release("regular", "1.0.0")
        _refuse_everything_else()
        return project

    @respx.mock
    def test_archives_skipped_directories_and_missing_paths_are_unknown_rows(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _origins(data) == {"regular": "", **self._UNREAD}
        rows = _rows(data)
        assert all(rows[name]["license"] == "UNKNOWN" for name in self._UNREAD)
        assert _requests_mentioning(*self._UNREAD, *self._OWN) == []

    @respx.mock
    def test_path_into_an_excluded_directory_is_an_unknown_row(self, tmp_path):
        project = self._project(tmp_path)
        result, data = _check_json(project, "--no-strict", "--exclude-dirs", "generated")
        assert result.exit_code == 0
        assert _origins(data) == {
            "regular": "",
            **self._UNREAD,
            "generated-py": "./generated/generated-py",
        }
        assert _requests_mentioning(*self._UNREAD, *self._OWN) == []

    @respx.mock
    def test_such_a_row_fails_a_strict_scan_until_it_is_reviewed(self, tmp_path):
        # The registry requirements beside these rows have no lockfile; that
        # is accepted here so that the unknown rows alone decide the exit code.
        project = self._project(tmp_path)
        result, data = _check_json(project, "--no-require-lockfile")
        assert result.exit_code == 1
        report = project / "report.json"
        result = CliRunner().invoke(
            main, ["init-review-file", "--path", str(project), "--from-report", str(report)]
        )
        assert result.exit_code == 0
        scaffold = (project / REVIEW_FILE_NAME).read_text(encoding="utf-8")
        assert 'source = "./wheels/wheel_own-1.0-py3-none-any.whl"\n' in scaffold
        (project / REVIEW_FILE_NAME).write_text(
            scaffold.replace('license = ""', 'license = "MIT"'), encoding="utf-8", newline="\n"
        )
        result, data = _check_json(project, "--no-require-lockfile")
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == len(self._UNREAD)
        assert _requests_mentioning(*self._UNREAD, *self._OWN) == []


# ------------------------- Composer repositories that do not name their packages


def _repository_gap(*kinds: str) -> str:
    listed = ", ".join(f"`{kind}`" for kind in kinds)
    return (
        f"declares repositories ({listed}) without naming their packages, and no composer.lock "
        "was read for it: those packages cannot be told from registry packages and may have "
        "been resolved from Packagist"
    )


class TestComposerRepositoryGap:
    """A repository composer.json cannot map to packages is a gap without a lockfile."""

    @staticmethod
    def _project(tmp_path: Path, repositories: list, require: dict | None = None) -> Path:
        project = tmp_path / "project"
        _dirs(project, "packages", "vendor/kept")
        manifest = {
            "name": "acme/app",
            "license": "MIT",
            "repositories": repositories,
            "require": {"acme/regular": "^1.0"} if require is None else require,
        }
        _write(project / "composer.json", json.dumps(manifest))
        _mock_packagist("acme/regular")
        _refuse_everything_else()
        return project

    @staticmethod
    def _gaps(data: dict) -> list[tuple[str, str]]:
        return [(d["path"], d["reason"]) for d in data["diagnostics"] if d["severity"] == "gap"]

    @respx.mock
    @pytest.mark.parametrize(
        ("repositories", "kinds"),
        [
            ([{"type": "vcs", "url": "https://git.example.org/acme/fork"}], ("vcs",)),
            ([{"type": "github", "url": "https://github.com/acme/fork"}], ("github",)),
            ([{"type": "artifact", "url": "artifacts/"}], ("artifact",)),
            ([{"type": "path", "url": "../outside-lib"}], ("path",)),
            ([{"type": "path", "url": "../libs/*"}], ("path",)),
            # In the scanned directory, under a directory nothing scans.
            ([{"type": "path", "url": "vendor/kept"}], ("path",)),
            (
                [
                    {"type": "vcs", "url": "https://git.example.org/acme/one"},
                    {"type": "path", "url": "../outside-lib"},
                    {"type": "vcs", "url": "https://git.example.org/acme/two"},
                ],
                ("vcs", "path"),
            ),
        ],
        ids=["vcs", "github", "artifact", "path-outside", "path-glob", "path-unread", "several"],
    )
    def test_gap_fails_a_strict_scan_that_is_otherwise_clean(self, tmp_path, repositories, kinds):
        # A composer.json with no composer.lock is also recorded as lacking
        # a lockfile. That is accepted here (it is then an estimate, not a
        # gap), so that the repository gap is the one gap left.
        project = self._project(tmp_path, repositories)
        result, data = _check_json(project, "--no-strict", "--no-require-lockfile")
        assert result.exit_code == 0
        assert self._gaps(data) == [("composer.json", _repository_gap(*kinds))]
        assert data["summary"]["gaps"] == 1
        # Every row resolves to a permissive license: the gap alone fails.
        assert {d["license"] for d in data["dependencies"]} == {"MIT"}
        result, _ = _check_json(project, "--no-require-lockfile")
        assert result.exit_code == 1
        assert _repository_gap(*kinds) in result.output

    @respx.mock
    @pytest.mark.parametrize(
        "repositories",
        [
            [],
            [{"type": "composer", "url": "https://packages.internal.example.org"}],
            [{"type": "path", "url": "packages/*"}],
            [{"type": "path", "url": "./packages"}],
            [{"type": "path", "url": 7}, {"packagist.org": False}],
            [
                {
                    "type": "package",
                    "package": {"name": "acme/inline", "version": "1.0.0", "source": {}},
                }
            ],
        ],
        ids=["none", "composer", "path-glob-read", "path-read", "malformed", "package"],
    )
    def test_repositories_the_file_maps_to_packages_are_no_gap(self, tmp_path, repositories):
        project = self._project(tmp_path, repositories)
        result, data = _check_json(project, "--no-require-lockfile")
        assert result.exit_code == 0
        assert self._gaps(data) == []

    @respx.mock
    def test_no_gap_when_nothing_is_looked_up_on_the_registry(self, tmp_path):
        inline = {
            "type": "package",
            "package": {"name": "acme/inline", "version": "1.0.0", "source": {}},
        }
        vcs = {"type": "vcs", "url": "https://git.example.org/acme/fork"}
        project = self._project(tmp_path, [inline, vcs], require={"acme/inline": "*", "php": "^8"})
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert self._gaps(data) == []
        assert respx.calls.call_count == 0

    @respx.mock
    def test_composer_lock_beside_the_file_closes_the_gap(self, tmp_path):
        project = self._project(tmp_path, [{"type": "vcs", "url": "https://example.org/a/fork"}])
        lock = {"packages": [_lock_entry("acme/regular", "1.0.0")]}
        _write(project / "composer.lock", json.dumps(lock))
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert self._gaps(data) == []

    @respx.mock
    def test_direct_only_scan_reads_no_lockfile_so_the_gap_stays(self, tmp_path):
        project = self._project(tmp_path, [{"type": "vcs", "url": "https://example.org/a/fork"}])
        lock = {"packages": [_lock_entry("acme/regular", "1.0.0")]}
        _write(project / "composer.lock", json.dumps(lock))
        result, data = _check_json(project, "--no-transitive")
        assert result.exit_code == 1
        assert self._gaps(data) == [("composer.json", _repository_gap("vcs"))]


# ------------------------------------------------ Go: local-path replacements


def _mock_go_module(module: str, version: str, license_id: str = "MIT") -> None:
    """Answer the module proxy for one Go module; deps.dev is :func:`_mock_go_licenses`."""
    respx.get(f"https://proxy.golang.org/{module}/@v/{version}.mod").mock(
        return_value=httpx.Response(200, text=f"module {module}\n")
    )
    _GO_LICENSES[module, version] = license_id


_GO_LICENSES: dict[tuple[str, str], str] = {}


def _mock_go_licenses() -> None:
    """Answer the deps.dev batch lookup from the modules mocked so far."""

    def batch(request: httpx.Request) -> httpx.Response:
        responses = []
        for item in json.loads(request.content)["requests"]:
            key = item["versionKey"]
            entry: dict = {"request": {"versionKey": key}}
            license_id = _GO_LICENSES.get((key["name"], key["version"]))
            if license_id:
                entry["version"] = {"versionKey": key, "licenses": [license_id], "links": []}
            responses.append(entry)
        return httpx.Response(200, json={"responses": responses, "nextPageToken": ""})

    respx.post("https://api.deps.dev/v3alpha/versionbatch").mock(side_effect=batch)


class TestGoLocalReplacements:
    """A module replaced by a local path is a row unless the scan reads that path."""

    _UNREAD = {
        "example.org/outside": "../outside",
        "example.org/vendored": "./vendor/vendored",
        "example.org/missing": "./missing",
        "example.org/rooted": "/opt/go/rooted",
    }

    def _project(self, tmp_path: Path, *, go_sum: bool) -> Path:
        project = tmp_path / "project"
        _dirs(project, "vendor/vendored", "internal/walked")
        _write(project / "internal" / "walked" / "go.mod", "module example.org/walked-elsewhere\n")
        _write(
            project / "go.mod",
            """\
            module example.com/app

            go 1.22

            require (
                example.org/regular v1.0.0
                example.org/outside v0.1.0
                example.org/vendored v0.2.0
                example.org/missing v0.3.0
                example.org/rooted v0.4.0
                example.org/walked v0.5.0
            )

            replace (
                example.org/outside => ../outside
                example.org/vendored => ./vendor/vendored
                example.org/missing => ./missing
                example.org/rooted => /opt/go/rooted
                example.org/walked => ./internal/walked
            )
            """,
        )
        _write(project / "LICENSE", "MIT License\n")
        if go_sum:
            _write(
                project / "go.sum",
                "example.org/regular v1.0.0 h1:h\nexample.org/regular v1.0.0/go.mod h1:h\n",
            )
        _GO_LICENSES.clear()
        _mock_go_module("example.org/regular", "v1.0.0")
        # The public index knows every replaced module, under another license.
        for module, version in (
            ("example.org/outside", "v0.1.0"),
            ("example.org/vendored", "v0.2.0"),
            ("example.org/missing", "v0.3.0"),
            ("example.org/rooted", "v0.4.0"),
            ("example.org/walked", "v0.5.0"),
        ):
            _mock_go_module(module, version, "GPL-3.0-only")
        _mock_go_licenses()
        _refuse_everything_else()
        return project

    @respx.mock
    @pytest.mark.parametrize("go_sum", [True, False], ids=["go.sum", "no-go.sum"])
    def test_module_replaced_by_a_path_the_scan_does_not_read_is_an_unknown_row(
        self, tmp_path, go_sum
    ):
        project = self._project(tmp_path, go_sum=go_sum)
        result, data = _check_json(project, "--no-strict")
        assert result.exit_code == 0
        assert _versions(data) == {
            "example.org/regular": ("", "v1.0.0"),
            **{module: (origin, "") for module, origin in self._UNREAD.items()},
        }
        rows = _rows(data)
        assert all(rows[module]["license"] == "UNKNOWN" for module in self._UNREAD)
        assert rows["example.org/outside"]["source"] == "go.mod"
        assert rows["example.org/regular"]["license"] == "MIT"
        # Neither deps.dev nor the module proxy is asked about a replaced
        # module, the one the scan reads included.
        assert _requests_mentioning(*self._UNREAD, "example.org/walked") == []

    @respx.mock
    def test_unknown_rows_fail_a_strict_scan_until_reviewed(self, tmp_path):
        project = self._project(tmp_path, go_sum=True)
        result, data = _check_json(project)
        assert result.exit_code == 1
        stanzas = "".join(
            f'[[review]]\necosystem = "go"\npackage = "{dep["name"]}"\n'
            f'source = "{dep["origin"]}"\nlicense = "MIT"\nnote = "read at that path"\n\n'
            for dep in data["dependencies"]
            if dep["origin"]
        )
        (project / REVIEW_FILE_NAME).write_text(stanzas, encoding="utf-8", newline="\n")
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert data["summary"]["reviewed"] == len(self._UNREAD)

    @respx.mock
    def test_dev_tool_replaced_by_a_local_path_follows_the_dev_flag(self, tmp_path):
        project = tmp_path / "project"
        _write(
            project / "go.mod",
            """\
            module example.com/app

            go 1.24

            require example.org/gen v1.0.0

            replace example.org/gen => ../gen

            tool example.org/gen/cmd/gen
            """,
        )
        _refuse_everything_else()
        result, data = _check_json(project, "--no-strict")
        assert (result.exit_code, data["dependencies"]) == (0, [])
        result, data = _check_json(project, "--no-strict", "--dev")
        row = _rows(data)["example.org/gen"]
        assert (row["origin"], row["group"], row["license"]) == ("../gen", "dev", "UNKNOWN")
        assert respx.calls.call_count == 0


# ------------------------------------------- the stderr counts of a check


class TestUnresolvedAndOffRegistryCounts:
    """Off-registry rows were never looked up: they are not failed lookups."""

    _FAILED = "package(s) could not be resolved from registries."
    _OFF_REGISTRY = "package(s) come from an off-registry source and were not looked up."

    @respx.mock
    def test_each_kind_is_counted_on_its_own_line(self, tmp_path):
        _npm_manifest(
            tmp_path,
            {
                "regular": "^1.0.0",
                "unpublished": "^1.0.0",
                "git-fork": "github:team/git-fork#v1",
                "tarball-fork": "https://dl.example.org/tarball-fork-1.0.0.tgz",
            },
        )
        _mock_npm_package("regular", "1.0.0")
        _refuse_everything_else()
        result, data = _check_json(tmp_path, "--no-strict")
        assert result.exit_code == 0
        assert data["summary"]["unknown"] == 3
        # The registry had no ``unpublished``; the two forks were not asked for.
        assert f"Warning: 1 {self._FAILED}" in result.output
        assert f"Warning: 2 {self._OFF_REGISTRY}" in result.output

    @respx.mock
    def test_off_registry_rows_alone_are_not_failed_lookups(self, tmp_path):
        _npm_manifest(tmp_path, {"regular": "^1.0.0", "git-fork": "github:team/git-fork#v1"})
        _mock_npm_package("regular", "1.0.0")
        _refuse_everything_else()
        result, _ = _check_json(tmp_path, "--no-strict")
        assert result.exit_code == 0
        assert self._FAILED not in result.output
        assert f"Warning: 1 {self._OFF_REGISTRY}" in result.output

    @respx.mock
    def test_failed_lookups_alone_say_nothing_of_off_registry_sources(self, tmp_path):
        _npm_manifest(tmp_path, {"regular": "^1.0.0", "unpublished": "^1.0.0"})
        _mock_npm_package("regular", "1.0.0")
        _refuse_everything_else()
        result, _ = _check_json(tmp_path, "--no-strict")
        assert result.exit_code == 0
        assert f"Warning: 1 {self._FAILED}" in result.output
        assert self._OFF_REGISTRY not in result.output


# ------------------------------------- exclusions reach the lockfile pass


class TestExcludedDirectoryInTheLockfilePass:
    @respx.mock
    def test_path_crate_in_an_excluded_directory_is_a_row_at_its_locked_version(self, tmp_path):
        project = tmp_path / "project"
        _dirs(project, "generated/forked")
        _write(
            project / "Cargo.toml",
            """\
            [package]
            name = "app"
            version = "0.1.0"
            license = "MIT"

            [dependencies]
            regular = "1.0"
            forked = { path = "generated/forked" }
            """,
        )
        (project / "Cargo.lock").write_text(
            _cargo_lock(
                ("app", "0.1.0", "", ("regular", "forked")),
                ("regular", "1.0.3", _CRATES_IO_INDEX, ()),
                ("forked", "0.3.0", "", ("via-fork",)),
                ("via-fork", "2.0.0", _CRATES_IO_INDEX, ()),
            ),
            encoding="utf-8",
        )
        _mock_crate("regular", "1.0.3")
        _mock_crate("via-fork", "2.0.0")
        _mock_crate("forked", "0.3.0", "GPL-3.0-only")
        _refuse_everything_else()

        # Walked: the project's own crate. No row, and it is still named by
        # the registry crate it pulls in.
        _, data = _check_json(project, "--no-strict")
        assert "forked" not in _rows(data)
        assert _rows(data)["via-fork"]["direct_ancestors"] == ["forked"]

        # Excluded: nothing scans it, so it is a row, at the version the
        # lockfile records for it.
        _, data = _check_json(project, "--no-strict", "--exclude-dirs", "generated")
        assert _versions(data)["forked"] == ("generated/forked", "0.3.0")
        assert _rows(data)["via-fork"]["direct_ancestors"] == ["forked"]
        assert _requests_mentioning("forked") == []
