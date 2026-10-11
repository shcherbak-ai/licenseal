"""Origin strings for dependencies that do not come from a package registry.

A dependency declared from a git repository, a direct URL, or a path outside
the scanned directory has no registry record. It is reported as one row whose
license is UNKNOWN, and no registry is asked about it under any name. Its
``Dependency.origin`` identifies the source in one normalized string, as
specific as the manifest or lockfile allows:

* a repository: ``git+<url>@<commit>`` when a lockfile records the commit,
  else ``git+<url>@<ref>`` for a declared tag, branch, or revision, else
  ``git+<url>``;
* a direct URL: ``<url>#<hash>`` when a hash is recorded, else ``<url>``;
* a path: the path as written.

Credentials never reach an origin: the user-info part of a URL and its query
string are removed.

A path the scan reads is the project's own code and gets no row at all;
:func:`path_origin` returns ``None`` for it. The scan reads a path when it
resolves to a directory of the scanned tree that the walk enters: the
manifests there are read like any other. A path the scan does not read is a
dependency wherever it is: a path outside the scanned directory, an archive
file, a directory the walk skips or the user excluded, a path that does not
exist.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._walk import is_walked_directory

# What an origin reads when a lockfile marks a package as not coming from the
# registry and records nothing that locates it.
UNRECORDED = "unrecorded source"

# ``scheme://user:secret@host`` — everything up to the last ``@`` of the
# authority is user-info.
_USERINFO_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/?#]*@")
# ``user@host:path``, the scp-like form git accepts in place of a URL.
_SCP_USER_RE = re.compile(r"^[^/@:\s]+@(?=[^/:\s]+:)")
_QUERY_RE = re.compile(r"\?[^#]*")
_VCS_PREFIX_RE = re.compile(r"^(?P<vcs>git|hg|svn|bzr)\+")
# A drive-qualified path (``C:\dir``, ``C:dir``).
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def strip_credentials(url: str) -> str:
    """Return ``url`` without user-info and without a query string.

    A token is written into a URL as user-info (``https://token@host/…``) or
    as a query parameter (``…?private_token=…``). Neither is needed to say
    where a dependency comes from, so both are dropped whatever they hold.
    """
    url = _USERINFO_RE.sub(r"\g<scheme>", url.strip())
    url = _SCP_USER_RE.sub("", url)
    return _QUERY_RE.sub("", url)


def git_origin(url: str, revision: str = "", *, vcs: str = "git") -> str:
    """Origin of a repository: ``<vcs>+<url>``, plus ``@<revision>`` when known.

    ``url`` may already carry a ``git+`` (or ``hg+`` / ``svn+`` / ``bzr+``)
    prefix; it is not doubled. ``revision`` is the commit a lockfile records,
    or the tag, branch, or revision a manifest declares.
    """
    prefixed = _VCS_PREFIX_RE.match(url.strip())
    if prefixed:
        vcs = prefixed.group("vcs")
        url = url.strip()[prefixed.end() :]
    origin = f"{vcs}+{strip_credentials(url)}"
    revision = revision.strip()
    return f"{origin}@{revision}" if revision else origin


def url_origin(url: str, digest: str = "") -> str:
    """Origin of a direct URL: the URL, plus ``#<digest>`` when a hash is recorded.

    A fragment already on ``url`` is replaced by ``digest`` when one is given
    and kept otherwise (a hash is written there in several formats).
    """
    cleaned = strip_credentials(url)
    digest = digest.strip()
    if digest:
        return f"{cleaned.split('#', 1)[0]}#{digest}"
    return cleaned


def hosted_git_origin(host: str, repository: str, revision: str = "") -> str:
    """Origin of a ``user/repo`` shorthand on a git hosting site."""
    return git_origin(f"https://{host}/{repository.strip().strip('/')}", revision)


def path_origin(path: str, base_dir: Path, scan_root: Path) -> str | None:
    """Origin of a path dependency, or ``None`` when it is the project's own code.

    ``path`` is as written in a file that lives in ``base_dir``; a ``file:``
    scheme is dropped. A relative path is resolved against ``base_dir``. It
    is part of the scanned project, and not a dependency row, only when it
    lands on a directory inside ``scan_root`` that the scan walks. Every
    other path is returned as written: one outside ``scan_root``, a file (an
    archive is not scanned), a directory the walk does not enter (a skipped
    name such as ``vendor``, a nested repository, an excluded directory), and
    a path that does not exist.

    A rooted, drive-qualified, UNC, or home-relative path is never resolved:
    on Windows the first filesystem call on such a path can reach a network
    share. It is reported as written.
    """
    written = path.strip()
    if written.startswith("file:"):
        written = written[len("file:") :]
        if written.startswith("//"):
            # ``file://<host>/<path>``: the host, usually empty, is not part
            # of the path.
            written = "/" + written[2:].partition("/")[2]
    written = written or "."
    normalized = written.replace("\\", "/")
    if normalized.startswith(("/", "~")) or _DRIVE_RE.match(normalized):
        return written
    try:
        resolved = (base_dir / normalized).resolve()
        root = scan_root.resolve()
        own = resolved.is_relative_to(root) and is_walked_directory(resolved, root)
    except (OSError, ValueError, RuntimeError):
        # A link loop or a name the filesystem rejects: not shown to be the
        # project's own code.
        return written
    return None if own else written
