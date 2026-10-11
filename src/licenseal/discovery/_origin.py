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

import posixpath
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
# The prefix of a repository origin, whatever version-control system it names.
_ANY_VCS_PREFIX_RE = re.compile(r"^[a-z][a-z0-9]*\+")
# A drive-qualified path (``C:\dir``, ``C:dir``).
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
# What a repository URL starts with besides its host and path.
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_URL_USER_RE = re.compile(r"^[^/@]+@")


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


def _is_rooted(path: str) -> bool:
    """Whether a path, written with forward slashes, is taken from no directory."""
    return path.startswith(("/", "~")) or bool(_DRIVE_RE.match(path))


def repository_key(url: str) -> str:
    """A repository URL in a form two spellings of one repository share.

    Host and path, lowercased, without scheme, user, ``.git``, or a trailing
    slash; ``git@host:path`` reads as ``host/path``.
    """
    key = url.strip().lower()
    if "://" in key:
        key = _URL_USER_RE.sub("", _URL_SCHEME_RE.sub("", key))
    else:
        key = _URL_USER_RE.sub("", key).replace(":", "/", 1)
    return key.rstrip("/").removesuffix(".git")


def _location(origin: str) -> tuple[str, str] | None:
    """The kind of place an origin names and the place itself, or ``None``.

    A repository and a URL are returned as their :func:`repository_key`,
    without the revision or the hash; a path as written, with forward
    slashes. ``None`` for an origin that names no place: an unrecorded
    source, or a lockfile's source label (``Bioconductor``).
    """
    if origin == UNRECORDED or origin.isalpha():
        return None
    repository = _ANY_VCS_PREFIX_RE.match(origin)
    if repository:
        # The revision follows the first ``@`` after the scheme: an origin
        # holds no user-info, and a tag can itself hold an ``@``.
        location = origin[repository.end() :]
        revision_at = location.find("@", location.find("://") + 1)
        return "repository", repository_key(location if revision_at < 0 else location[:revision_at])
    if "://" in origin:
        return "url", repository_key(origin.partition("#")[0])
    return "path", origin.replace("\\", "/")


def _is_archive_of(url: str, repository: str) -> bool:
    """Whether a URL is served by a repository's host from under that repository's path.

    Both are :func:`repository_key` forms. A lockfile can record a commit of
    ``host/user/repo`` as the archive the host builds for it
    (``codeload.host/user/repo/tar.gz/<commit>``).
    """
    url_host, _, url_path = url.partition("/")
    host, _, path = repository.partition("/")
    return (url_host == host or url_host.endswith(f".{host}")) and f"/{path}/" in f"/{url_path}/"


def _same_path(locked: str, declared: str, declared_dir: str, locked_dir: str | None) -> bool:
    """Whether a lockfile's path and a manifest's path name one place.

    Each is relative to the directory of the file that writes it. When
    ``locked_dir`` is not known, the lockfile is taken to sit beside the
    manifest it locks or in a directory above it (a workspace root): the two
    are one place when the lockfile's path, taken from the manifest's
    directory or from one above it, is the manifest's. A rooted,
    drive-qualified, or home-relative path is taken from no directory: it is
    one place only with itself.
    """
    if _is_rooted(locked) or _is_rooted(declared):
        return posixpath.normpath(locked) == posixpath.normpath(declared)
    target = posixpath.normpath(posixpath.join(declared_dir, declared))
    if locked_dir is not None:
        return posixpath.normpath(posixpath.join(locked_dir, locked)) == target
    directory = declared_dir
    while posixpath.normpath(posixpath.join(directory, locked)) != target:
        if not directory:
            return False
        directory = posixpath.dirname(directory)
    return True


def same_source(
    locked: str, declared: str, declared_dir: str = "", locked_dir: str | None = None
) -> bool | None:
    """Whether the origin a lockfile records and the origin a manifest declares are one source.

    One source is one repository, whatever commit, tag, or branch each origin
    names; one URL, whatever hash; or one path. ``declared_dir`` is the
    directory of the declaring manifest, relative to the scanned directory,
    and ``locked_dir`` the directory the lockfile's path is written from,
    when that is known. ``None`` when either origin names no place that can
    be compared.
    """
    first, second = _location(locked), _location(declared)
    if first is None or second is None:
        return None
    (locked_kind, locked_place), (declared_kind, declared_place) = first, second
    if locked_kind == declared_kind == "path":
        return _same_path(locked_place, declared_place, declared_dir, locked_dir)
    if locked_kind == declared_kind:
        return locked_place == declared_place
    places = {locked_kind: locked_place, declared_kind: declared_place}
    if places.keys() == {"repository", "url"}:
        return _is_archive_of(places["url"], places["repository"])
    # A path is never a repository or a URL.
    return False


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
    if _is_rooted(normalized):
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
