"""Discover Python dependencies from requirements*.txt files."""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path

from licenseal.discovery._read import (
    decode_text,
    record_unfollowed_reference,
    rejected_path_reference,
)
from licenseal.discovery._walk import walk_project_files_matching
from licenseal.discovery.python import DEV_GROUP_NAMES, requirement_dependency
from licenseal.models import Dependency, DependencyGroup

# pip's comment rule: ``#`` starts a comment at the start of a line or after
# whitespace. A ``#fragment`` glued to a URL (``...repo.git#egg=name``) is not
# a comment and survives.
_COMMENT_RE = re.compile(r"(^|\s+)#.*$")

# ``-r <file>`` / ``--requirement <file>``: the named file's requirements are
# part of this one. The short option takes its value with or without a space,
# the long one after a space or ``=``. ``-c`` / ``--constraint`` is not an
# include: a constraints file only pins versions and adds no requirement.
_INCLUDE_RE = re.compile(r"^(?:-r\s*|--requirement(?:\s+|=))(?P<target>\S.*)$")

# ``-e <target>`` / ``--editable <target>``: an editable install of a path or
# a VCS URL. The target is read like any other requirement.
_EDITABLE_RE = re.compile(r"^(?:-e\s*|--editable(?:\s+|=))(?P<target>\S.*)$")

# Per-requirement options that follow the requirement on its line
# (``--hash=sha256:…``, ``--config-settings …``).
_LINE_OPTIONS_RE = re.compile(r"\s+--\S.*$")
_HASH_OPTION_RE = re.compile(r"\s--hash[=\s]\s*(?P<hash>\S+)")


def _is_dev_file(filename: str) -> bool:
    """Check if a requirements filename indicates dev dependencies."""
    stem = Path(filename).stem.lower()
    # requirements-dev.txt, requirements_test.txt, dev-requirements.txt, etc.
    parts = re.split(r"[-_]", stem)
    return bool(set(parts) & DEV_GROUP_NAMES)


def _is_requirements_file(filename: str) -> bool:
    """Whether ``filename`` matches the requirements*.txt or *-requirements.txt patterns."""
    return (filename.startswith("requirements") and filename.endswith(".txt")) or filename.endswith(
        "-requirements.txt"
    )


def _resolved(path: Path) -> Path | None:
    """``path.resolve()``, or ``None`` when the filesystem cannot resolve it.

    A symlink loop in the scanned tree makes ``resolve()`` raise on some
    Python versions; that must not end the scan.
    """
    try:
        return path.resolve()
    except (OSError, ValueError, RuntimeError):
        return None


def _included_file(including: Path, value: str, scan_root: Path) -> Path | None:
    """Return the file a ``-r`` line names, or record why it is not followed.

    The checks that need only the text come first, so the filesystem is never
    asked about a value they refuse: a URL (which pip would download) and a
    rooted, drive-qualified, UNC, or device path. What is left is relative to
    the including file. It is followed when it resolves to a file inside the
    scanned directory, through any ``..`` segment or link on the way: a
    requirements file is turned into registry lookups, so one outside the
    scan is not read on a scanned file's say-so.
    """
    if len(value) > 1 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    if "://" in value:
        record_unfollowed_reference(including, value, "is a URL")
        return None
    if rejected_path_reference(including, value):
        return None
    target = _resolved(including.parent / value)
    if target is not None and not target.is_relative_to(scan_root):
        record_unfollowed_reference(including, value, "is outside the scanned directory")
        return None
    if target is None or not target.is_file():
        record_unfollowed_reference(including, value, "is not a file")
        return None
    return target


def _parse_requirements_file(
    root: Path, group: DependencyGroup, project_path: Path
) -> list[Dependency]:
    """Parse a requirements file and every file it includes with ``-r``.

    Each requirement takes ``group``, the classification of ``root``, however
    many includes lie between them; ``source`` names the file that declares
    it. Includes are read breadth-first and each file once, so a cycle ends.

    Decoding is handled by :func:`licenseal.discovery._read.decode_text`: a
    leading BOM picks the codec (so a UTF-16/UTF-32 ``requirements.txt`` — e.g.
    a Windows ``pip freeze > requirements.txt`` — parses instead of being
    dropped), then strict UTF-8, then a latin-1 fallback so a stray non-UTF-8
    byte in a comment can't take the whole file's ASCII dependency lines down
    with it. An unreadable file is skipped (returns no deps) without crashing
    the scan; the skip / fallback is surfaced as a read diagnostic.
    """
    deps = []
    scan_root = _resolved(project_path) or project_path
    seen = {_resolved(root)}
    # Paths come from os.walk rooted at project_path, so relative_to is safe.
    pending = deque([(root, root.relative_to(project_path).as_posix())])
    while pending:
        filepath, source = pending.popleft()
        text = decode_text(filepath)
        if text is None:
            continue

        for raw_line in text.splitlines():
            # Strip the comment before the URL test below, so a URL inside a
            # trailing comment doesn't drop the requirement it annotates.
            line = _COMMENT_RE.sub("", raw_line).strip()
            include = _INCLUDE_RE.match(line)
            if include:
                target = _included_file(filepath, include.group("target").strip(), scan_root)
                if target is not None and target not in seen:
                    seen.add(target)
                    pending.append((target, target.relative_to(scan_root).as_posix()))
                continue
            editable = _EDITABLE_RE.match(line)
            if editable:
                line = editable.group("target").strip()
            # Skip comments, empty lines, and every other option line
            elif not line or line.startswith("-"):
                continue

            # A URL, a VCS URL, or a path is a requirement like any other: it
            # is a row with an origin, or the project's own code. A relative
            # path is taken from the directory of the file that names it.
            recorded = _HASH_OPTION_RE.search(line)
            dep = requirement_dependency(
                _LINE_OPTIONS_RE.sub("", line),
                group,
                source,
                filepath.parent,
                scan_root,
                digest=recorded.group("hash") if recorded else "",
            )
            if dep is not None:
                deps.append(dep)

    return deps


def discover_requirements_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Dependency]:
    """Discover dependencies from requirements*.txt files in the project tree.

    Walks the tree (mirroring pyproject / cargo / npm discovery) so nested
    requirements files — e.g. ``packages/foo/requirements-dev.txt`` in a
    monorepo — are picked up. Matches both ``requirements*.txt`` and
    ``*-requirements.txt`` filename conventions. Dev vs. prod is decided by
    :func:`_is_dev_file`, so ``requirements-dev.txt`` / ``-test.txt`` /
    ``-ci.txt`` / ``-lint.txt`` / ``-docs.txt`` flow to DEV automatically.

    A ``-r`` / ``--requirement`` line is followed, whatever the included file
    is called. Its requirements take the dev/prod classification of the file
    the walk found, not of their own name; a requirement reached from both a
    prod and a dev file is emitted once for each, and the aggregator keeps
    the prod one. An include that cannot be followed is a gap on the file
    that names it. ``-c`` / ``--constraint`` files are never read.

    Each emitted dep carries the project-relative path of its declaring
    file in ``source`` (e.g. ``packages/foo/requirements-dev.txt``), so
    callers can tell which of several same-named files declared a dep in
    monorepo layouts.
    """
    deps: list[Dependency] = []
    for req_file in walk_project_files_matching(
        project_path, _is_requirements_file, exclude_paths=exclude_paths
    ):
        group = DependencyGroup.DEV if _is_dev_file(req_file.name) else DependencyGroup.PROD
        deps.extend(_parse_requirements_file(req_file, group, project_path))
    return deps
