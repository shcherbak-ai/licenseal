"""Invoke automation tasks for licenseal development.

List them with ``uv run inv --list``.
"""

from __future__ import annotations

from pathlib import Path

from invoke import task
from invoke.context import Context

_ROOT = Path(__file__).parent

# The site generator runs as a tool at the versions pinned in the constraints
# file. It is not a dependency of the package, so it is not in uv.lock.
_ZENSICAL = "uvx --constraints .github/docs-constraints.txt zensical"


# =============================================================================
# Documentation Tasks
# =============================================================================


@task
def docs(c: Context) -> None:
    """Build the documentation site into site/, as CI does (strict, full rebuild)."""
    with c.cd(str(_ROOT)):
        c.run(f"{_ZENSICAL} build --strict --clean")


@task(name="docs-live")
def docs_live(c: Context, port: int = 8000) -> None:
    """
    Serve the documentation site locally, rebuilding it when a page changes.

    Args:
        port: Port number for the preview server (default: 8000)

    Example:
        uv run inv docs-live
        uv run inv docs-live --port 9000
    """
    with c.cd(str(_ROOT)):
        c.run(f"{_ZENSICAL} serve --dev-addr localhost:{port}")
