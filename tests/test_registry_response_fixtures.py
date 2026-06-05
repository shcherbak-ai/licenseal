"""Resolver regression tests against curated registry response fixtures.

Each fixture under `tests/fixtures/registry-responses/` captures a real-world
shape that triggered a resolver bug. These tests pin the bug fix in place: if
the resolver regresses, the assertion here fails before users see UNKNOWN
licenses in the wild.

When adding a new fixture, follow the layout convention in
`tests/fixtures/registry-responses/AGENTS.md`.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.models import Dependency, Ecosystem
from licenseal.resolvers.npm_registry import resolve_npm_license
from licenseal.resolvers.pypi import resolve_python_license

_PYPI_FIXTURES = Path(__file__).parent / "fixtures" / "registry-responses" / "pypi"
_NPM_FIXTURES = Path(__file__).parent / "fixtures" / "registry-responses" / "npm"


def _load(relpath: str) -> dict:
    """Load a curated registry-response JSON by relative path under pypi/."""
    return json.loads((_PYPI_FIXTURES / relpath).read_text(encoding="utf-8"))


def _resolve(dep: Dependency) -> object:
    with httpx.Client() as client:
        return resolve_python_license(dep, client)


@respx.mock
def test_attrs_sparse_per_version_falls_back_to_project_level() -> None:
    """attrs 24.3.0's per-version JSON has no license metadata; fall back to
    the project-level endpoint where license_expression is populated."""
    respx.get("https://pypi.org/pypi/attrs/24.3.0/json").mock(
        return_value=httpx.Response(200, json=_load("attrs/24.3.0.json"))
    )
    respx.get("https://pypi.org/pypi/attrs/json").mock(
        return_value=httpx.Response(200, json=_load("attrs/project.json"))
    )
    dep = Dependency(name="attrs", version_constraint="==24.3.0", ecosystem=Ecosystem.PYTHON)
    li = _resolve(dep)
    assert li.license_id == "MIT"
    assert li.from_registry is True
    assert li.resolved_version == "24.3.0"


@respx.mock
def test_maturin_sparse_per_version_falls_back_to_project_level() -> None:
    """maturin 1.9.4 publishes 'MIT OR Apache-2.0' at the project level only.
    Compound license_expression should round-trip through normalization."""
    respx.get("https://pypi.org/pypi/maturin/1.9.4/json").mock(
        return_value=httpx.Response(200, json=_load("maturin/1.9.4.json"))
    )
    respx.get("https://pypi.org/pypi/maturin/json").mock(
        return_value=httpx.Response(200, json=_load("maturin/project.json"))
    )
    dep = Dependency(name="maturin", version_constraint="==1.9.4", ecosystem=Ecosystem.PYTHON)
    li = _resolve(dep)
    assert li.license_id == "Apache-2.0 OR MIT"


@respx.mock
def test_python_dateutil_dual_license_falls_through_to_classifier() -> None:
    """python-dateutil 2.9.0.post0 puts 'Dual License' in the legacy field —
    a marker that doesn't normalize to a real SPDX. Resolver must skip it
    and consult the trove classifiers (Apache + BSD)."""
    respx.get("https://pypi.org/pypi/python-dateutil/2.9.0.post0/json").mock(
        return_value=httpx.Response(200, json=_load("python-dateutil/2.9.0.post0.json"))
    )
    dep = Dependency(
        name="python-dateutil",
        version_constraint="==2.9.0.post0",
        ecosystem=Ecosystem.PYTHON,
    )
    li = _resolve(dep)
    # The first License classifier wins under current resolver logic. Either
    # Apache-2.0 or BSD-3-Clause is acceptable — UNKNOWN is not.
    assert li.license_id in {"Apache-2.0", "BSD-3-Clause"}, (
        f"expected fallback to a classifier license, got {li.license_id!r}"
    )


@respx.mock
def test_scipy_style_copyright_text_falls_through_to_classifier() -> None:
    """Some packages stuff the entire MIT/BSD license text (or a copyright
    notice) into the legacy `license` field. The junk-detector must catch
    this and route to classifiers."""
    respx.get("https://pypi.org/pypi/scipy/1.12.0/json").mock(
        return_value=httpx.Response(200, json=_load("scipy-junk-license/1.12.0.json"))
    )
    dep = Dependency(name="scipy", version_constraint="==1.12.0", ecosystem=Ecosystem.PYTHON)
    li = _resolve(dep)
    assert li.license_id == "BSD-3-Clause"


@respx.mock
def test_attrs_repository_url_extracted_from_project_urls() -> None:
    """When per-version metadata is sparse, repository URL also has to come
    from the project-level fallback."""
    respx.get("https://pypi.org/pypi/attrs/24.3.0/json").mock(
        return_value=httpx.Response(200, json=_load("attrs/24.3.0.json"))
    )
    respx.get("https://pypi.org/pypi/attrs/json").mock(
        return_value=httpx.Response(200, json=_load("attrs/project.json"))
    )
    dep = Dependency(name="attrs", version_constraint="==24.3.0", ecosystem=Ecosystem.PYTHON)
    li = _resolve(dep)
    assert li.repository_url == "https://github.com/python-attrs/attrs"


@respx.mock
def test_npm_lockfile_pinning_form_resolves() -> None:
    """Regression for the npm resolver dropping `==X.Y.Z` lockfile-derived
    specs. The npm lockfile parsers emit version_constraint='==1.2.3'; the
    resolver must treat that as a pinned version (same as the Rust resolver).

    Without the fix, every npm dep coming from a lockfile resolved to UNKNOWN
    because `==1.2.3` is invalid npm semver and the constraint path failed."""
    respx.get("https://registry.npmjs.org/react/18.3.1").mock(
        return_value=httpx.Response(
            200, json=json.loads((_NPM_FIXTURES / "react" / "18.3.1.json").read_text())
        )
    )
    dep = Dependency(name="react", version_constraint="==18.3.1", ecosystem=Ecosystem.NPM)
    with httpx.Client() as client:
        li = resolve_npm_license(dep, client)
    assert li.license_id == "MIT"
    assert li.from_registry is True
    assert li.resolved_version == "18.3.1"


def test_all_pypi_fixtures_are_well_formed() -> None:
    """Every fixture must parse as JSON and contain at minimum an `info` block.

    Cheap sanity check that catches bad commits before the per-shape tests
    run, with a clear failure message pointing at the offending file.
    """
    fixtures = sorted(_PYPI_FIXTURES.rglob("*.json"))
    assert fixtures, f"no PyPI fixtures found under {_PYPI_FIXTURES}"
    for path in fixtures:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            pytest.fail(f"{path.relative_to(_PYPI_FIXTURES)}: invalid JSON ({exc})")
        info = data.get("info")
        assert isinstance(info, dict), (
            f"{path.relative_to(_PYPI_FIXTURES)}: missing/invalid 'info' block"
        )
        assert info.get("name"), f"{path.relative_to(_PYPI_FIXTURES)}: 'info.name' missing"
