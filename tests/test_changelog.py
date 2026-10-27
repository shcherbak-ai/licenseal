"""Every version of the changelog has a compare link and the notes of its GitHub
release, and CITATION.cff repeats its date."""

from __future__ import annotations

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
    # ``cz bump`` rewrites the version (``version_files`` in pyproject.toml) and
    # leaves the date: the release change writes the day into the changelog
    # heading and here. Run as the last of the ``pre_bump_hooks``, this stops a
    # bump that forgot either.
    assert date == released[version]


@pytest.fixture
def release_notes() -> Iterator[ModuleType]:
    """scripts/release_notes.py, which the publish workflow runs."""
    spec = importlib.util.spec_from_file_location(_SCRIPT.stem, _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SCRIPT.stem] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        del sys.modules[_SCRIPT.stem]


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
