"""Shared filesystem walker for ecosystem discovery.

Every ecosystem (Python, Rust, npm) walks the project tree looking for a
specific manifest file (``pyproject.toml``, ``Cargo.toml``, ``package.json``,
``setup.py``). The skip set is the same for all of them — VCS dirs, virtual
envs, caches, common build/dist outputs, and the conventional ``examples``
/ ``fixtures`` / ``vendor`` directories.
"""

from __future__ import annotations

import contextlib
import contextvars
import os
from collections.abc import Callable, Iterator
from pathlib import Path

from licenseal.discovery._read import record_walk_error

# Names auto-skipped at every depth during discovery. Unified across all
# ecosystems so a name like ``vendor`` or ``build`` is treated consistently
# whether the project is Python, Rust, or npm. Virtualenvs are *not* in this
# list — they're detected structurally via the ``pyvenv.cfg`` marker so we
# also catch non-conventional names (``env/``, ``env-3.11/``, ``.venv-dev/``,
# …) without false-positive risk on legitimately-named source dirs.
BASE_SKIP_DIRS: frozenset[str] = frozenset(
    {
        # VCS / caches
        ".git",
        ".tox",
        ".nox",
        "__pycache__",
        "node_modules",
        # Sample / fixture trees that frequently carry intentionally-broken or
        # frozen manifests not representative of the project's real deps.
        "examples",
        "fixtures",
        "__fixtures__",
        # Build / distribution / vendoring outputs.
        "build",
        "dist",
        "target",
        ".eggs",
        "site-packages",
        "vendor",
        # PEP 582 (pdm) installs the full package tree — each with its own
        # ``pyproject.toml`` — under this directory at the project root. Same
        # failure mode as ``node_modules`` for npm.
        "__pypackages__",
        ".pdm-build",
        # JS framework build outputs that ship a synthetic ``package.json`` in
        # their bundle dir (``{"type": "module"}`` / ``"commonjs"``) and would
        # otherwise pollute discovery.
        ".next",
        ".nuxt",
        ".svelte-kit",
        # Yarn Berry state/cache (``.yarn/sdks`` carries TS SDK package.json
        # files) and legacy package-manager install trees.
        ".yarn",
        "bower_components",
        "jspm_packages",
    }
)


# Context-scoped cache for a single full-tree walk, shared across every
# ecosystem predicate within one discovery pass. Each ecosystem looks for its
# own manifest names, but the traversal and skip logic are identical — so
# without this cache an N-ecosystem scan walks the whole tree N times, and the
# wall time grows roughly linearly as ecosystems are added. Inside
# ``shared_walk_cache()`` the first walk materializes the full file list and
# every later ``walk_project_files*`` call filters that list in memory. The
# contextvar auto-clears on context exit (no cross-scan staleness) and defaults
# to ``None``, so callers *outside* the context walk fresh exactly as before.
_WALK_CACHE: contextvars.ContextVar[dict[tuple[str, frozenset[Path]], list[Path]] | None] = (
    contextvars.ContextVar("_WALK_CACHE", default=None)
)


@contextlib.contextmanager
def shared_walk_cache() -> Iterator[None]:
    """Reuse one full-tree walk across all ``walk_project_files*`` calls within.

    Re-entrant: if a cache is already active (e.g. the CLI wraps both
    ``detect_project_license`` and ``discover_all_dependencies`` so they share a
    single walk), the inner context reuses the outer cache rather than starting
    a fresh — and otherwise empty — one.
    """
    if _WALK_CACHE.get() is not None:
        yield
        return
    token = _WALK_CACHE.set({})
    try:
        yield
    finally:
        _WALK_CACHE.reset(token)


def _cached_project_files(
    project_path: Path,
    exclude_paths: frozenset[Path],
) -> list[Path] | None:
    """Full file list under ``project_path``, walked once per active context.

    Returns ``None`` when no :func:`shared_walk_cache` context is active, so
    the caller falls back to its own predicate-filtered walk (the historical
    behavior — identical results, no full-list materialization).
    """
    cache = _WALK_CACHE.get()
    if cache is None:
        return None
    key = (str(project_path), exclude_paths)
    files = cache.get(key)
    if files is None:
        files = _walk(project_path, lambda _name: True, exclude_paths=exclude_paths)
        cache[key] = files
    return files


def _walk(
    project_path: Path,
    predicate: Callable[[str], bool],
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Walk ``project_path`` returning every file whose name matches ``predicate``.

    Skips ``BASE_SKIP_DIRS``, symlinked directories, any subdirectory that
    contains its own ``.git`` (file or dir — handles regular nested repos
    and submodules alike), any subdirectory that contains a ``pyvenv.cfg``
    (PEP 405 virtualenv marker — catches arbitrary venv names without
    blacklisting), and any directory whose resolved path is in
    ``exclude_paths``. ``exclude_paths`` must contain pre-resolved absolute
    paths; the CLI handler is responsible for resolving relative user input
    against ``--path``.
    """
    if exclude_paths and project_path.resolve() in exclude_paths:
        return []

    results: list[Path] = []
    try:
        walk = os.walk(project_path, topdown=True, followlinks=False, onerror=record_walk_error)
    except OSError:
        return results
    while True:
        try:
            dirpath, dirnames, filenames = next(walk)
        except StopIteration:
            break
        except PermissionError:
            break

        kept: list[str] = []
        for name in dirnames:
            if name in BASE_SKIP_DIRS:
                continue
            child = Path(dirpath, name)
            if child.is_symlink():
                continue
            # A child with its own `.git` is a separate repo (cloned dep,
            # vendored fork, submodule) — scanning it as part of the parent
            # almost always produces noise.
            if (child / ".git").exists():
                continue
            # PEP 405: every venv/virtualenv-created environment carries a
            # ``pyvenv.cfg`` at its root. Detect by marker rather than name
            # so we catch `.venv/`, `venv/`, `env/`, `env-3.11/`, etc.
            if (child / "pyvenv.cfg").exists():
                continue
            if exclude_paths and child.resolve() in exclude_paths:
                continue
            kept.append(name)
        dirnames[:] = sorted(kept)
        for fname in filenames:
            if predicate(fname):
                results.append(Path(dirpath) / fname)

    return results


def walk_project_files(
    project_path: Path,
    filename: str,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Walk ``project_path`` returning every path to a file named ``filename``.

    Exact-match form. For glob-style matching (e.g. ``requirements*.txt``)
    use :func:`walk_project_files_matching` with a predicate.

    Returns paths in ``os.walk`` order (root first, then depth-first), so the
    root manifest — if present — sorts ahead of nested ones.
    """
    cached = _cached_project_files(project_path, exclude_paths)
    if cached is not None:
        return [path for path in cached if path.name == filename]
    return _walk(project_path, lambda fname: fname == filename, exclude_paths=exclude_paths)


def walk_project_files_matching(
    project_path: Path,
    name_predicate: Callable[[str], bool],
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Walk ``project_path`` returning every file whose basename matches the predicate.

    Used by ecosystems that look for multiple filename shapes (e.g.
    Python's ``requirements*.txt`` and ``*-requirements.txt``). Same skip
    behavior as :func:`walk_project_files`.
    """
    cached = _cached_project_files(project_path, exclude_paths)
    if cached is not None:
        return [path for path in cached if name_predicate(path.name)]
    return _walk(project_path, name_predicate, exclude_paths=exclude_paths)
