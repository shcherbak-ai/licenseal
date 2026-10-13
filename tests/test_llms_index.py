"""The llms.txt index in zensical.toml lists every page, as the page describes itself."""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_PROJECT = tomllib.loads((_ROOT / "zensical.toml").read_text(encoding="utf-8"))["project"]


def _nav_pages(entries: list[object]) -> list[str]:
    """The pages of the navigation in order, those of nested groups included."""
    pages: list[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            for target in entry.values():
                pages += _nav_pages(target if isinstance(target, list) else [target])
        else:
            pages.append(str(entry))
    return pages


def _indexed() -> dict[str, str]:
    """Each page the index lists, in order, with its line of description."""
    return {
        page: note
        for entries in _PROJECT["plugins"]["llmstxt"]["sections"].values()
        for entry in entries
        for page, note in entry.items()
    }


def test_index_lists_every_page_but_the_home_page_in_nav_order():
    # A page added to ``nav`` goes into a section of
    # ``[project.plugins.llmstxt.sections]`` as well, at the same place.
    assert list(_indexed()) == [page for page in _nav_pages(_PROJECT["nav"]) if page != "index.md"]


def test_index_describes_each_page_as_its_front_matter_does():
    docs = _ROOT / _PROJECT["docs_dir"]
    for page, note in _indexed().items():
        _, front_matter, _ = (docs / page).read_text(encoding="utf-8").split("---\n", 2)
        assert note == yaml.safe_load(front_matter)["description"], page
