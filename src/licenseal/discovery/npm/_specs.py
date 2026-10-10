"""Classify npm dependency specs that do not name a registry release.

A ``package.json`` dependency is normally ``name: <semver range or tag>``. It
can also point at a git repository (``git+https://…``, ``github:user/repo``,
the bare ``user/repo`` shorthand), at a tarball URL, or at a path
(``file:../dir``). A lockfile records where each package was fetched from in
the same vocabulary. A dependency from a repository, a tarball URL, or a path
is not the registry package of its name: it gets an origin (see
:mod:`licenseal.discovery._origin`) and is never looked up.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._origin import git_origin, hosted_git_origin, path_origin, url_origin

# The hosting shorthands npm expands, and the host each one names.
_HOSTED_PREFIXES = {
    "github:": "github.com",
    "gitlab:": "gitlab.com",
    "bitbucket:": "bitbucket.org",
    "gist:": "gist.github.com",
}

_GIT_URL_PREFIXES = ("git+", "git://", "ssh://")

# ``user@host:path``, the scp-like form of a git remote.
_SCP_GIT_RE = re.compile(r"[^/@:\s]+@[^/:\s]+:\S+")

# ``user/repo``, optionally with ``#<commit-ish>``: npm reads it as a GitHub
# repository. A path (``./dir``, ``../dir``, ``~/dir``, ``/dir``) and a scoped
# name (``@scope/name``) are not this form.
_GITHUB_SHORTHAND_RE = re.compile(r"[^\s/@:#.~][^\s/@:#]*/[^\s/@:#]+(?:#.*)?")

# Specs that name a directory or an archive on disk, by protocol or as a
# bare path.
_PATH_PROTOCOLS = ("file:", "link:", "portal:")
_BARE_PATH_PREFIXES = ("./", "../", "/", "~/", ".\\", "..\\")

# A tarball in the layout every npm registry serves:
# ``<registry>/<name>/-/<file>.tgz``.
_REGISTRY_TARBALL_RE = re.compile(r"/-/[^/]+\.tgz$")
# A registry that serves its tarballs under another path.
_REGISTRY_DOWNLOAD_PREFIXES = ("https://npm.pkg.github.com/download/",)


def path_spec(spec: str) -> str | None:
    """The path a spec names, or ``None`` when it does not name one.

    ``file:``, ``link:``, and ``portal:`` specs name a path, and so does a
    spec written as a bare relative, rooted, or home-relative path.
    """
    for protocol in _PATH_PROTOCOLS:
        if spec.startswith(protocol):
            return spec[len(protocol) :]
    return spec if spec.startswith(_BARE_PATH_PREFIXES) or spec in (".", "..") else None


def git_spec_origin(spec: str) -> str:
    """Origin of a spec that names a git repository by URL or hosting prefix.

    Empty for any other spec. The ``#<commit-ish>`` (or ``#semver:<range>``)
    fragment is the revision. A ``.git`` URL without the ``git+`` prefix is
    still a repository.
    """
    spec = spec.strip()
    location, _, fragment = spec.partition("#")
    for prefix, host in _HOSTED_PREFIXES.items():
        if spec.startswith(prefix):
            return hosted_git_origin(host, location[len(prefix) :], fragment)
    if (
        spec.startswith(_GIT_URL_PREFIXES)
        or _SCP_GIT_RE.fullmatch(location)
        or (spec.startswith(("http://", "https://")) and location.endswith(".git"))
    ):
        return git_origin(location, fragment)
    return ""


def npm_spec_origin(spec: str) -> str:
    """Origin an npm dependency spec declares; empty for a registry spec.

    A git URL, a hosting shorthand (``github:user/repo`` or a bare
    ``user/repo``), and a tarball URL are origins. A path spec is not
    handled here: see :func:`path_spec`.
    """
    spec = spec.strip()
    git = git_spec_origin(spec)
    if git:
        return git
    if spec.startswith(("http://", "https://")):
        return url_origin(spec)
    if _GITHUB_SHORTHAND_RE.fullmatch(spec):
        location, _, fragment = spec.partition("#")
        return hosted_git_origin("github.com", location, fragment)
    return ""


def npm_resolved_origin(
    resolved: str, integrity: str, lock_dir: Path, scan_root: Path
) -> str | None:
    """Origin of the location a lockfile records for a package (its ``resolved``).

    Empty when there is none, and for a registry tarball: on
    registry.npmjs.org, or on any other registry, recognised by the tarball
    layout registries share. A git URL is a repository at the commit in its
    fragment. Any other ``http(s)`` URL is a direct tarball, with
    ``integrity`` as its hash. Anything else is a path, relative to
    ``lock_dir``: ``None`` when it is inside ``scan_root``.
    """
    resolved = resolved.strip()
    if not resolved:
        return ""
    git = git_spec_origin(resolved)
    if git:
        return git
    if resolved.startswith(("http://", "https://")):
        location = resolved.partition("#")[0].partition("?")[0]
        if _REGISTRY_TARBALL_RE.search(location) or location.startswith(
            _REGISTRY_DOWNLOAD_PREFIXES
        ):
            return ""
        return url_origin(resolved, integrity)
    path = path_spec(resolved)
    return path_origin(resolved if path is None else path, lock_dir, scan_root)
