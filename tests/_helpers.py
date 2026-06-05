"""Shared test helpers — small constructors that would otherwise duplicate."""

from __future__ import annotations

from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _java_dep(
    name: str = "com.example:simple",
    version: str = "1.0.0",
    group: DependencyGroup = DependencyGroup.PROD,
    source: str = "",
) -> Dependency:
    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.JAVA,
        group=group,
        source=source,
    )
