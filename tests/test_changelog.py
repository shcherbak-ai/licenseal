"""Every version of the changelog has a compare link, in the order of the versions."""

from __future__ import annotations

import re
from pathlib import Path

_CHANGELOG = (Path(__file__).resolve().parent.parent / "CHANGELOG.md").read_text(encoding="utf-8")
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
