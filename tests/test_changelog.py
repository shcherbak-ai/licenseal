"""Every version of the changelog has a compare link and the notes of its GitHub
release, and CITATION.cff repeats its date; scripts/date_release.py dates a release."""

from __future__ import annotations

import datetime
import importlib.util
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

import licenseal

_ROOT = Path(__file__).resolve().parent.parent
_CHANGELOG = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
_CITATION = (_ROOT / "CITATION.cff").read_text(encoding="utf-8")
_COMPARE = "https://github.com/shcherbak-ai/licenseal/compare/"
_SCRIPT = _ROOT / "scripts" / "release_notes.py"
_DATE_RELEASE = _ROOT / "scripts" / "date_release.py"


def _ref(version: str) -> str:
    """What a comparison ends at: the version's tag, or ``HEAD`` for unreleased work."""
    return "HEAD" if version == "Unreleased" else f"v{version}"


def test_each_version_links_to_its_comparison_with_the_one_before():
    versions = re.findall(r"^## \[(.+?)\]", _CHANGELOG, re.MULTILINE)
    links = dict(re.findall(r"^\[(.+?)\]: (\S+)$", _CHANGELOG, re.MULTILINE))
    # The links stand at the end of the file, newest first like the sections:
    # a new version's link goes on top.
    assert list(links) == versions
    for version, previous in zip(versions, versions[1:], strict=False):
        assert links[version] == f"{_COMPARE}v{previous}...{_ref(version)}"
    # The oldest section follows a release that the changelog does not list.
    oldest = versions[-1]
    assert re.fullmatch(rf"{re.escape(_COMPARE)}v[\d.]+\.\.\.v{re.escape(oldest)}", links[oldest])


def test_citation_file_names_the_package_version_and_its_release_date():
    released = dict(re.findall(r"^## \[(.+?)\] - (\d{4}-\d{2}-\d{2})$", _CHANGELOG, re.MULTILINE))
    (version,) = re.findall(r"^version: (\S+)$", _CITATION, re.MULTILINE)
    (date,) = re.findall(r"^date-released: (\S+)$", _CITATION, re.MULTILINE)
    assert version == licenseal.__version__
    # ``cz bump`` rewrites the version (``version_files`` in pyproject.toml), and
    # scripts/date_release.py writes the day into the changelog heading and
    # here. Run as the last of the ``pre_bump_hooks``, this stops a bump whose
    # two dates differ.
    assert date == released[version]


def _script(path: Path) -> Iterator[ModuleType]:
    """A script of ``scripts/``, loaded by its path for the length of a test."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        del sys.modules[path.stem]


@pytest.fixture
def release_notes() -> Iterator[ModuleType]:
    """scripts/release_notes.py, which the publish workflow runs."""
    yield from _script(_SCRIPT)


@pytest.fixture
def date_release() -> Iterator[ModuleType]:
    """scripts/date_release.py, one of the ``pre_bump_hooks``."""
    yield from _script(_DATE_RELEASE)


def test_each_release_has_the_notes_of_its_github_release(release_notes):
    # The publish workflow takes them before it uploads anything, so a version
    # without notes would stop its release; at a bump, this stops it earlier.
    versions = re.findall(r"^## \[(.+?)\] - \d{4}-\d{2}-\d{2}$", _CHANGELOG, re.MULTILINE)
    for version in versions:
        notes = release_notes.release_notes(_CHANGELOG, version)
        assert notes in _CHANGELOG
        assert notes == notes.strip() + "\n"
        assert not re.search(r"^## \[|^\[[^\]]+\]: ", notes, re.MULTILINE)


_RELEASES = (
    "# Changelog\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/).\n\n"
    "## [Unreleased]\n\n- C\n\n"
    "## [1.1.0] - 2026-11-09\n\n### Fixed\n\n- B — not in [1.0.0]\n\n"
    "## [1.0.0] - 2026-11-02\n\n### Added\n\n- A\n\n"
    f"[Unreleased]: {_COMPARE}v1.1.0...HEAD\n"
    f"[1.1.0]: {_COMPARE}v1.0.0...v1.1.0\n"
    f"[1.0.0]: {_COMPARE}v0.4.2...v1.0.0\n"
)


def test_the_notes_of_a_release_are_its_section(release_notes):
    # Up to the next section, or for the oldest, up to the links
    assert release_notes.release_notes(_RELEASES, "1.1.0") == "### Fixed\n\n- B — not in [1.0.0]\n"
    assert release_notes.release_notes(_RELEASES, "1.0.0") == "### Added\n\n- A\n"


@pytest.mark.parametrize(
    ("changelog", "version", "error"),
    [
        # Not released
        (_RELEASES, "1.2.0", "no dated section"),
        # Not yet named and dated for its release
        (_RELEASES, "Unreleased", "no dated section"),
        # Only the start of a version
        (_RELEASES, "1.1", "no dated section"),
        # The dots are dots
        (_RELEASES, "1x1x0", "no dated section"),
        # Headings only
        (
            _RELEASES.replace("### Fixed\n\n- B — not in [1.0.0]\n\n", "### Fixed\n\n"),
            "1.1.0",
            "empty",
        ),
    ],
)
def test_a_release_without_notes_stops(release_notes, changelog: str, version: str, error: str):
    with pytest.raises(ValueError, match=error):
        release_notes.release_notes(changelog, version)


def test_the_script_prints_the_notes_in_utf8_or_says_why_not(
    release_notes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary
):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_bytes(_RELEASES.encode("utf-8"))
    monkeypatch.setattr(release_notes, "_CHANGELOG", changelog)
    assert release_notes.main(["1.1.0"]) == 0
    assert capsysbinary.readouterr() == ("### Fixed\n\n- B — not in [1.0.0]\n".encode(), b"")
    assert release_notes.main(["1.2.0"]) == 1
    out, err = capsysbinary.readouterr()
    assert out == b""
    assert b"no dated section" in err
    assert release_notes.main([]) == 1
    assert b"Usage" in capsysbinary.readouterr().err


# CITATION.cff as the hook finds it: the version rewritten, the date not yet.
_CITATION_BUMPED = "cff-version: 1.2.0\nversion: 1.2.0\ndate-released: 2026-11-09\n"
_LINK = f"[Unreleased]: {_COMPARE}v1.1.0...HEAD"


def test_a_bump_names_and_dates_the_unreleased_section(date_release, release_notes):
    # A mention of the section in an entry is not its heading.
    entry = "- C, under `## [Unreleased]` until [Unreleased] is out\n"
    changelog = _RELEASES.replace("- C\n", entry)
    dated, cited = date_release.date_release(
        changelog, _CITATION_BUMPED, "1.2.0", "v1.2.0", "2026-11-16", "1.1.0"
    )
    assert dated == changelog.replace("## [Unreleased]\n", "## [1.2.0] - 2026-11-16\n").replace(
        _LINK, f"[1.2.0]: {_COMPARE}v1.1.0...v1.2.0"
    )
    assert cited == _CITATION_BUMPED.replace("2026-11-09", "2026-11-16")
    assert release_notes.release_notes(dated, "1.2.0") == entry
    # Run again after a later hook stopped the bump, it names and dates the
    # section again.
    again, cited_again = date_release.date_release(
        dated, cited, "1.2.1", "v1.2.1", "2026-11-17", "1.1.0"
    )
    assert again == dated.replace("1.2.0", "1.2.1").replace("2026-11-16", "2026-11-17")
    assert cited_again == _CITATION_BUMPED.replace("2026-11-09", "2026-11-17")


@pytest.mark.parametrize(
    ("changelog", "citation", "error"),
    [
        # Nothing above the version before
        (
            _RELEASES.replace("## [Unreleased]\n\n- C\n\n", "").replace(f"{_LINK}\n", ""),
            _CITATION_BUMPED,
            "no changes above the section of 1.1.0",
        ),
        # Headings only: nothing to release
        (_RELEASES.replace("- C\n", "### Fixed\n"), _CITATION_BUMPED, "is empty"),
        # The section twice, e.g. after a merge
        (
            _RELEASES.replace("## [Unreleased]\n", "## [Unreleased]\n\n- D\n\n## [Unreleased]\n"),
            _CITATION_BUMPED,
            "more than one",
        ),
        # A line that only looks like the compare link
        (
            _RELEASES.replace(_LINK, "[Unreleased]: notes...below"),
            _CITATION_BUMPED,
            "no compare link",
        ),
        # A citation file without its date
        (_RELEASES, "cff-version: 1.2.0\nversion: 1.2.0\n", "no `date-released`"),
    ],
)
def test_a_bump_stops_on_a_changelog_or_citation_it_cannot_date(
    date_release, changelog: str, citation: str, error: str
):
    with pytest.raises(ValueError, match=error):
        date_release.date_release(changelog, citation, "1.2.0", "v1.2.0", "2026-11-16", "1.1.0")


def test_the_hook_dates_both_files_or_neither(
    date_release, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    changelog = tmp_path / "CHANGELOG.md"
    citation = tmp_path / "CITATION.cff"
    # commitizen writes the files it bumps with CRLF on Windows.
    changelog.write_bytes(_RELEASES.replace("\n", "\r\n").encode("utf-8"))
    citation.write_bytes(b"cff-version: 1.2.0\r\nversion: 1.2.0\r\n")
    monkeypatch.setattr(date_release, "_CHANGELOG", changelog)
    monkeypatch.setattr(date_release, "_CITATION", citation)
    for name in ("CZ_PRE_NEW_VERSION", "CZ_PRE_CURRENT_VERSION", "CZ_PRE_NEW_TAG_VERSION"):
        monkeypatch.delenv(name, raising=False)
    assert date_release.main() == 1
    assert "hook of `cz bump`" in capsys.readouterr().err
    monkeypatch.setenv("CZ_PRE_NEW_VERSION", "1.2.0")
    monkeypatch.setenv("CZ_PRE_CURRENT_VERSION", "1.1.0")
    # The changelog could be dated, the citation file not: neither is written.
    before = changelog.read_bytes()
    assert date_release.main() == 1
    assert "no `date-released`" in capsys.readouterr().err
    assert changelog.read_bytes() == before
    citation.write_bytes(_CITATION_BUMPED.replace("\n", "\r\n").encode("utf-8"))
    assert date_release.main() == 0
    day = datetime.date.today().isoformat()
    assert capsys.readouterr().out == f"Dated 1.2.0: {day} (CHANGELOG.md, CITATION.cff)\n"
    # In the repository's line ends, with the tag commitizen would give
    assert changelog.read_bytes() == (
        _RELEASES.replace("## [Unreleased]\n", f"## [1.2.0] - {day}\n")
        .replace(_LINK, f"[1.2.0]: {_COMPARE}v1.1.0...v1.2.0")
        .encode("utf-8")
    )
    assert citation.read_bytes() == _CITATION_BUMPED.replace("2026-11-09", day).encode("utf-8")
