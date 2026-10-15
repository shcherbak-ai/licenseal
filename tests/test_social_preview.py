"""The documentation site is shared with the repository's social preview.

A link to a page shows the picture on other sites: the site's template
(``overrides/main.html``) names a copy of it in ``docs/``, which
``inv social-preview`` writes with the picture in ``social/``.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATE = _ROOT / "overrides" / "main.html"
_SHARE_IMAGE = "assets/social-preview.png"


def test_the_share_image_is_the_social_preview():
    site_copy = (_ROOT / "docs" / _SHARE_IMAGE).read_bytes()
    picture = (_ROOT / "social" / "github-social-preview.png").read_bytes()
    assert site_copy == picture, "the site's share image is stale: run `uv run inv social-preview`"
    # No build checks the address of a meta tag.
    named = f'content="{{{{ config.site_url }}}}{_SHARE_IMAGE}"'
    assert named in _TEMPLATE.read_text(encoding="utf-8")
