"""Shared test helpers — small constructors that would otherwise duplicate."""

from __future__ import annotations

import json
import textwrap
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner, Result

from licenseal.cli import main
from licenseal.discovery import discover_all_dependencies
from licenseal.discovery._read import ReadDiagnostic, collect_read_diagnostics
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.transitive import resolve_transitive

# Path values a scan target could write into a manifest to point outside the
# local tree: UNC in both slash styles, the two device namespaces, drive-
# qualified (absolute and drive-relative) and rooted. Each carries the
# ``example.invalid`` marker so ``_record_path_io`` can spot it.
_NON_RELATIVE_PATH_VALUES = (
    r"\\example.invalid\share\target",
    "//example.invalid/share/target",
    r"\\?\UNC\example.invalid\share\target",
    r"\\.\pipe\example.invalid",
    r"C:\example.invalid\target",
    "C:/example.invalid/target",
    "C:example.invalid",
    "/example.invalid/target",
    r"\example.invalid\target",
)

# Nesting depth no supported interpreter's JSON / TOML / YAML parser can recurse
# through, whether it bounds recursion by a frame count or by stack space.
_DEEP = 200_000

_PATH_IO_METHODS = (
    "resolve",
    "exists",
    "is_file",
    "is_dir",
    "stat",
    "open",
    "read_bytes",
    "read_text",
)


def _record_path_io(monkeypatch: pytest.MonkeyPatch, marker: str) -> list[tuple[str, str]]:
    """Record every ``Path`` filesystem call as ``(method, path)``.

    A call on a path containing ``marker`` is recorded and then refused with
    ``OSError`` rather than delegated, so a regression fails the test without
    the path ever reaching the operating system.
    """
    calls: list[tuple[str, str]] = []

    def _install(name: str) -> None:
        original = getattr(Path, name)

        def recorder(self, *args, **kwargs):
            calls.append((name, str(self)))
            if marker in str(self):
                raise OSError(f"{name}() reached a forbidden path")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, name, recorder)

    for name in _PATH_IO_METHODS:
        _install(name)
    return calls


def _write(path: Path, content: str) -> Path:
    """Write dedented ``content`` to ``path`` with LF line endings; return ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8", newline="\n")
    return path


def _gaps(diags: list[ReadDiagnostic]) -> set[tuple[Path, str]]:
    """The ``(path, reason)`` pairs recorded, all of which must be gaps."""
    assert all(diag.is_gap for diag in diags)
    return {(diag.path, diag.reason) for diag in diags}


def _no_registry(url: str, client: httpx.Client) -> None:
    """Stand-in fetcher: every registry lookup fails, so only files are read."""
    return None


def _resolve(
    project: Path, *, include_dev: bool = True
) -> tuple[set[tuple[str, str, DependencyGroup]], list[ReadDiagnostic]]:
    """Scan ``project`` from its files alone: discovery, then transitive resolution.

    Returns the ``(name, version, group)`` rows and everything recorded on
    the read-diagnostics sink. No registry answers, so a direct dependency a
    lockfile does not pin comes back with its manifest constraint.
    """
    with collect_read_diagnostics() as diags:
        direct, _ = discover_all_dependencies(project)
        with httpx.Client() as client:
            deps = resolve_transitive(
                direct,
                project,
                include_dev=include_dev,
                max_depth=50,
                client=client,
                fetcher=_no_registry,
                pom_fetcher=_no_registry,
            )
    return {(d.name, d.version_constraint, d.group) for d in deps}, diags


def _mock_pypi(name: str, license_str: str, version: str = "1.0.0") -> None:
    """Answer PyPI's project and version endpoints for ``name``; no dependencies."""
    payload = {
        "info": {"license": license_str, "version": version, "classifiers": [], "requires_dist": []}
    }
    for url in (
        f"https://pypi.org/pypi/{name}/json",
        f"https://pypi.org/pypi/{name}/{version}/json",
    ):
        respx.get(url).mock(return_value=httpx.Response(200, json=payload))


def _mock_npm(name: str, license_str: str, version: str = "1.0.0") -> None:
    """Answer the npm registry's endpoints for ``name``; no dependencies."""
    meta = {"license": license_str, "version": version}
    respx.get(f"https://registry.npmjs.org/{name}").mock(
        return_value=httpx.Response(200, json={"versions": {version: meta}})
    )
    for suffix in ("latest", version):
        respx.get(f"https://registry.npmjs.org/{name}/{suffix}").mock(
            return_value=httpx.Response(200, json=meta)
        )


def _check_json(project: Path, *flags: str) -> tuple[Result, dict]:
    """Run ``licenseal check`` on ``project``; return the result and the JSON report."""
    out = project / "report.json"
    result = CliRunner().invoke(
        main, ["check", "--path", str(project), *flags, "-f", "json", "-o", str(out)]
    )
    return result, json.loads(out.read_text(encoding="utf-8"))


def _assert_gap_fails_only_strict(
    project: Path,
    gapped: Path,
    reason: str,
    rows: list[tuple[str, str]],
    *,
    repair: Callable[[], object],
) -> None:
    """One analysis gap on ``gapped``, beside manifests that resolve to ``rows``.

    ``--no-strict`` passes and reports the ``(name, license)`` rows and the
    gap; ``--strict`` fails and names it on stderr. ``repair`` then removes
    the cause, and the same scan passes ``--strict`` with no gap: the control
    that shows the gap, and nothing else, is what failed it.
    """
    shown = gapped.relative_to(project).as_posix()

    lenient, data = _check_json(project, "--no-strict", "--dev")
    assert lenient.exit_code == 0
    assert sorted((d["name"], d["license"]) for d in data["dependencies"]) == sorted(rows)
    assert data["summary"]["gaps"] == 1
    assert data["diagnostics"] == [{"path": shown, "reason": reason, "severity": "gap"}]

    strict, data = _check_json(project, "--strict", "--dev")
    assert strict.exit_code == 1
    assert f"Warning: {shown}: {reason}" in strict.output
    assert "1 manifest(s) could not be fully analyzed" in strict.output
    assert "fails --strict" in strict.output
    assert data["summary"]["gaps"] == 1

    repair()
    control, data = _check_json(project, "--strict", "--dev")
    assert control.exit_code == 0
    assert data["summary"]["gaps"] == 0
    assert data["diagnostics"] == []


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
