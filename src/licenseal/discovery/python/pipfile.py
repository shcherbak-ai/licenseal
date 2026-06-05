"""Discover Python dependencies from Pipfile (Pipenv manifest)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from licenseal.discovery._read import load_toml
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _pipfile_version(spec: Any) -> str:
    """Extract the version constraint from a Pipfile dep spec.

    Pipfile uses ``"*"`` to mean "any version" — treat that as an empty
    constraint so downstream resolution falls back to the registry's
    latest, mirroring how Poetry's ``"*"`` and PEP 621's missing-spec are
    handled elsewhere in discovery.
    """
    if isinstance(spec, str):
        return "" if spec == "*" else spec
    if isinstance(spec, dict):
        version = spec.get("version", "")
        if not isinstance(version, str) or version == "*":
            return ""
        return version
    return ""


def _pipfile_extras(spec: Any) -> frozenset[str]:
    if isinstance(spec, dict):
        extras = spec.get("extras")
        if isinstance(extras, list):
            return frozenset(e for e in extras if isinstance(e, str))
    return frozenset()


def _is_non_registry(spec: Any) -> bool:
    """Pipfile entries with ``git`` / ``path`` / ``file`` source aren't on PyPI."""
    if isinstance(spec, dict):
        return any(k in spec for k in ("git", "path", "file"))
    return False


def discover_pipfile_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Dependency]:
    """Discover dependencies from every ``Pipfile`` in the project tree.

    Pipfile uses two top-level sections: ``[packages]`` for production and
    ``[dev-packages]`` for development. Each entry's value can be a string
    version spec or a table carrying ``version`` plus optional ``extras``
    / ``git`` / ``path`` / ``file``. Non-registry sources (git/path/file)
    have no PyPI metadata to license-resolve and are skipped.
    """
    deps: list[Dependency] = []
    for pf in walk_project_files(project_path, "Pipfile", exclude_paths=exclude_paths):
        data = load_toml(pf)
        if data is None:
            continue
        source = pf.relative_to(project_path).as_posix()
        for section, group in (
            ("packages", DependencyGroup.PROD),
            ("dev-packages", DependencyGroup.DEV),
        ):
            entries = data.get(section, {})
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                # tomllib guarantees string keys, so no per-key isinstance check.
                if _is_non_registry(spec):
                    continue
                deps.append(
                    Dependency(
                        name=name,
                        version_constraint=_pipfile_version(spec),
                        ecosystem=Ecosystem.PYTHON,
                        group=group,
                        source=source,
                        extras=_pipfile_extras(spec),
                    )
                )
    return deps
