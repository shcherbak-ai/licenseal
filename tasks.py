"""Invoke automation tasks for licenseal development.

List them with ``uv run inv --list``.
"""

from __future__ import annotations

import shutil
import socket
import tempfile
from pathlib import Path

from invoke import task
from invoke.context import Context
from invoke.exceptions import Exit

_ROOT = Path(__file__).parent

# The site generator runs as a tool at the versions pinned in the constraints
# file. It is not a dependency of the package, so it is not in uv.lock.
_ZENSICAL = "uvx --constraints .github/docs-constraints.txt zensical"

# The repository's social preview: the drawing, and the picture made from it.
_SOCIAL_PREVIEW = _ROOT / "social" / "github-social-preview.svg"

# The browsers that can take that picture, by the names they have on a PATH
# and by where Windows and macOS install them.
_BROWSER_NAMES = (
    "chrome",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "msedge",
    "microsoft-edge",
)
_BROWSER_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)


def _find_browser() -> str | None:
    """A Chrome, Edge or Chromium on this machine, or ``None``."""
    for name in _BROWSER_NAMES:
        if found := shutil.which(name):
            return found
    return next((path for path in _BROWSER_PATHS if Path(path).is_file()), None)


def _port_in_use(port: int) -> bool:
    """Whether something already answers on ``localhost:port``."""
    for family, kind, proto, _, address in socket.getaddrinfo(
        "localhost", port, type=socket.SOCK_STREAM
    ):
        with socket.socket(family, kind, proto) as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(address) == 0:
                return True
    return False


# =============================================================================
# Documentation Tasks
# =============================================================================


@task
def docs(c: Context, clean: bool = False) -> None:
    """
    Build the documentation site into site/ in strict mode, as CI does.

    The build fails on a link or an anchor that does not resolve. It reuses
    the build cache, so it can run while ``docs-live`` is serving.

    Args:
        clean: Rebuild from nothing. Stop ``docs-live`` first: it holds the cache.

    Example:
        uv run inv docs
        uv run inv docs --clean
    """
    flags = "--strict --clean" if clean else "--strict"
    with c.cd(str(_ROOT)):
        c.run(f"{_ZENSICAL} build {flags}")


@task(name="docs-live")
def docs_live(c: Context, port: int = 9000) -> None:
    """
    Serve the documentation site locally, rebuilding it when a page changes.

    Args:
        port: Port number for the preview server (default: 9000)

    Example:
        uv run inv docs-live
        uv run inv docs-live --port 9001
    """
    if _port_in_use(port):
        raise Exit(
            f"Port {port} is in use by another program. Pass a free one: "
            f"uv run inv docs-live --port {port + 1}",
            code=1,
        )
    with c.cd(str(_ROOT)):
        c.run(f"{_ZENSICAL} serve --dev-addr localhost:{port}")


# =============================================================================
# Image Tasks
# =============================================================================


@task(name="social-preview")
def social_preview(c: Context, browser: str = "") -> None:
    """
    Render social/github-social-preview.png from the SVG beside it.

    A headless Chrome, Edge or Chromium takes the picture, at 1280 by 640 pixels.

    Args:
        browser: Path of the browser, where none is found

    Example:
        uv run inv social-preview
        uv run inv social-preview --browser /usr/bin/brave-browser
    """
    browser = browser or _find_browser() or ""
    if not browser:
        raise Exit(
            "No Chrome, Edge or Chromium was found. Name one: "
            "uv run inv social-preview --browser PATH",
            code=1,
        )
    png = _SOCIAL_PREVIEW.with_suffix(".png")
    with tempfile.TemporaryDirectory() as scratch:
        shot = Path(scratch) / png.name
        # The browser takes absolute paths only, and exits with 0 when it
        # wrote nothing. --disable-lcd-text keeps the coloured fringes of
        # sub-pixel text rendering out of the picture.
        result = c.run(
            f'"{browser}" --headless --disable-lcd-text --hide-scrollbars'
            " --force-device-scale-factor=1 --window-size=1280,640"
            f' "--screenshot={shot}" "{_SOCIAL_PREVIEW.as_uri()}"',
            hide=True,
            warn=True,
        )
        if not shot.is_file():
            raise Exit(f"{browser} wrote no image.\n{result.stderr}", code=1)
        shutil.copyfile(shot, png)
    print(f"Wrote {png.relative_to(_ROOT).as_posix()}")
