"""Classify npm dependency specs that do not name a registry release.

A ``package.json`` dependency is normally ``name: <semver range or tag>``. It
can also point at a git repository (``git+https://…``, ``github:user/repo``,
the bare ``user/repo`` shorthand) or at a tarball URL. Such a dependency is
not the registry package of its name: it gets an origin (see
:mod:`licenseal.discovery._origin`) and is never looked up.
"""

from __future__ import annotations

import re

from licenseal.discovery._origin import git_origin, hosted_git_origin, url_origin

# The hosting shorthands npm expands, and the host each one names.
_HOSTED_PREFIXES = {
    "github:": "github.com",
    "gitlab:": "gitlab.com",
    "bitbucket:": "bitbucket.org",
    "gist:": "gist.github.com",
}

_GIT_URL_PREFIXES = ("git+", "git://")

# ``user/repo``, optionally with ``#<commit-ish>``: npm reads it as a GitHub
# repository. A path (``./dir``, ``../dir``, ``~/dir``, ``/dir``) and a scoped
# name (``@scope/name``) are not this form.
_GITHUB_SHORTHAND_RE = re.compile(r"[^\s/@:#.~][^\s/@:#]*/[^\s/@:#]+(?:#.*)?")


def npm_spec_origin(spec: str) -> str:
    """Origin an npm dependency spec declares; empty for a registry spec.

    The ``#<commit-ish>`` (or ``#semver:<range>``) fragment of a git spec is
    its revision. A ``.git`` URL without the ``git+`` prefix is still a
    repository; any other ``http(s)`` URL is a tarball.
    """
    spec = spec.strip()
    location, _, fragment = spec.partition("#")
    for prefix, host in _HOSTED_PREFIXES.items():
        if spec.startswith(prefix):
            return hosted_git_origin(host, location[len(prefix) :], fragment)
    if spec.startswith(_GIT_URL_PREFIXES) or (
        spec.startswith(("http://", "https://")) and location.endswith(".git")
    ):
        return git_origin(location, fragment)
    if spec.startswith(("http://", "https://")):
        return url_origin(spec)
    if _GITHUB_SHORTHAND_RE.fullmatch(spec):
        return hosted_git_origin("github.com", location, fragment)
    return ""
