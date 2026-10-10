"""Shared test helpers — small constructors that would otherwise duplicate."""

from __future__ import annotations

from pathlib import Path

import pytest

from licenseal.models import Dependency, DependencyGroup, Ecosystem

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
