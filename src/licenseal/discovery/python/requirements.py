"""Discover Python dependencies from requirements*.txt files."""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files_matching
from licenseal.discovery.python import DEV_GROUP_NAMES, parse_pep508_dep
from licenseal.models import Dependency, DependencyGroup, Ecosystem


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


def _parse_requirements_file(
    filepath: Path, group: DependencyGroup, source: str
) -> list[Dependency]:
    """Parse a single requirements file.

    Decoding is handled by :func:`licenseal.discovery._read.decode_text`: a
    leading BOM picks the codec (so a UTF-16/UTF-32 ``requirements.txt`` — e.g.
    a Windows ``pip freeze > requirements.txt`` — parses instead of being
    dropped), then strict UTF-8, then a latin-1 fallback so a stray non-UTF-8
    byte in a comment can't take the whole file's ASCII dependency lines down
    with it. An unreadable file is skipped (returns no deps) without crashing
    the scan; the skip / fallback is surfaced as a read diagnostic.
    """
    deps = []

    text = decode_text(filepath)
    if text is None:
        return deps

    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Skip comments, empty lines, options, URLs, and -r includes
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Skip URL-based deps (git+, http://, etc.)
        if "://" in line or line.startswith("git+"):
            continue

        name, version, extras = parse_pep508_dep(line)
        if name:
            deps.append(
                Dependency(
                    name=name,
                    version_constraint=version,
                    ecosystem=Ecosystem.PYTHON,
                    group=group,
                    source=source,
                    extras=extras,
                )
            )

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
        # Paths come from os.walk rooted at project_path, so relative_to is safe.
        source = req_file.relative_to(project_path).as_posix()
        deps.extend(_parse_requirements_file(req_file, group, source))
    return deps
