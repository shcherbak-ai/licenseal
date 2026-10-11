"""Discover Python dependencies from Pipfile (Pipenv manifest)."""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import load_toml, typed_field
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python import source_table_origin, table_spec
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def discover_pipfile_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Dependency]:
    """Discover dependencies from every ``Pipfile`` in the project tree.

    Pipfile uses two top-level sections: ``[packages]`` for production and
    ``[dev-packages]`` for development. Each entry's value can be a string
    version spec or a table carrying ``version`` plus optional ``extras``
    / ``git`` / ``path`` / ``file``. An entry with ``git`` (or ``hg`` /
    ``svn`` / ``bzr``), ``path``, or ``file`` is not a PyPI package: it is
    returned with an origin and no version constraint, unless its path is
    one that the scan reads, which makes it the project's own code.

    Pipfile uses ``"*"`` to mean "any version" — treated as an empty
    constraint so downstream resolution falls back to the registry's latest.

    A section that is not a table, and a spec that is neither form, are
    recorded as gaps and read as absent: the section declares nothing, the
    dependency is unconstrained. The rest of the file is still read.
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
            entries = typed_field(pf, data, section, dict) or {}
            for name, spec in entries.items():
                # tomllib guarantees string keys, so no per-key isinstance check.
                what = f"an entry of {section}"
                origin = (
                    source_table_origin(pf, spec, what, pf.parent, project_path)
                    if isinstance(spec, dict)
                    else ""
                )
                if origin is None:
                    continue
                version, extras = table_spec(pf, spec, what)
                deps.append(
                    Dependency(
                        name=name,
                        version_constraint="" if origin or version == "*" else version,
                        ecosystem=Ecosystem.PYTHON,
                        group=group,
                        source=source,
                        origin=origin,
                        extras=extras,
                    )
                )
    return deps
