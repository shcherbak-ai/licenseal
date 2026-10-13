"""Invoke automation tasks for licenseal development.

List them with ``uv run inv --list``.
"""

from __future__ import annotations

import socket
from pathlib import Path

from invoke import task
from invoke.context import Context
from invoke.exceptions import Exit

_ROOT = Path(__file__).parent

# The site generator runs as a tool at the versions pinned in the constraints
# file. It is not a dependency of the package, so it is not in uv.lock.
_ZENSICAL = "uvx --constraints .github/docs-constraints.txt zensical"


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
