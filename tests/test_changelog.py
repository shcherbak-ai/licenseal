"""Every version of the changelog has a compare link, and CITATION.cff repeats its date."""

from __future__ import annotations

import re
from pathlib import Path

import licenseal

_ROOT = Path(__file__).resolve().parent.parent
_CHANGELOG = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
_CITATION = (_ROOT / "CITATION.cff").read_text(encoding="utf-8")
_COMPARE = "https://github.com/shcherbak-ai/licenseal/compare/"


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
