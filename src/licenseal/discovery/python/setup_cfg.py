"""Discover Python dependencies from setup.cfg files."""

from __future__ import annotations

import configparser
from pathlib import Path

from licenseal.discovery._read import decode_text, record_parse_failure
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.python import DEV_GROUP_NAMES, requirement_dependency
from licenseal.discovery.python.requirements import referenced_requirements
from licenseal.models import Dependency, DependencyGroup

# What starts an option value that names files instead of listing requirements.
_FILE_DIRECTIVE = "file:"


def _parse_setup_cfg(setup_cfg: Path, source: str, scan_root: Path) -> list[Dependency]:
    """Parse a single setup.cfg file into Dependencies."""
    text = decode_text(setup_cfg)
    if text is None:
        return []
    config = configparser.ConfigParser()
    try:
        config.read_string(text)
        # Values are interpolated when read, so a stray ``%`` raises here
        # rather than in ``read_string``.
        install_requires = config.get("options", "install_requires", fallback="")
        extras_require = (
            config.items("options.extras_require")
            if config.has_section("options.extras_require")
            else []
        )
    except configparser.Error:
        # Malformed setup.cfg (duplicate option/section, bad interpolation).
        # Match every other Python discovery parser and the sibling
        # ``detect_project_license_setup_cfg`` below: fail soft to no deps
        # rather than aborting the whole scan on one unparseable manifest.
        record_parse_failure(setup_cfg, "INI")
        return []

    # [options] install_requires
    deps = _option_deps(install_requires, DependencyGroup.PROD, source, setup_cfg, scan_root)

    # [options.extras_require]
    for extra_name, extra_deps_str in extras_require:
        group = (
            DependencyGroup.DEV if extra_name.lower() in DEV_GROUP_NAMES else DependencyGroup.PROD
        )
        deps.extend(_option_deps(extra_deps_str, group, source, setup_cfg, scan_root))

    return deps


def _option_deps(
    value: str, group: DependencyGroup, source: str, setup_cfg: Path, scan_root: Path
) -> list[Dependency]:
    """The dependencies one option value declares, a requirement to a line.

    A line that starts with ``file:`` is the setuptools directive: it names
    the files that hold the requirements, separated by commas and relative
    to the directory of the setup.cfg. Each is read like a ``-r`` include of
    a requirements file. ``file://`` starts a URL, which is a requirement.
    """
    deps: list[Dependency] = []
    for line in value.strip().splitlines():
        line = line.strip()
        if line.startswith(_FILE_DIRECTIVE) and not line.startswith("file://"):
            for name in line[len(_FILE_DIRECTIVE) :].split(","):
                if name.strip():
                    deps.extend(referenced_requirements(setup_cfg, name.strip(), group, scan_root))
            continue
        dep = _parse_dep_line(line, group, source, setup_cfg.parent, scan_root)
        if dep:
            deps.append(dep)
    return deps


def discover_setup_cfg_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Dependency]:
    """Discover dependencies from every setup.cfg in the project tree.

    Walks recursively (mirroring the other Python manifest walkers) so a
    nested legacy package's ``setup.cfg`` is covered. Each emitted dep carries
    the project-relative path of its declaring file in ``source``.
    """
    deps: list[Dependency] = []
    for setup_cfg in walk_project_files(project_path, "setup.cfg", exclude_paths=exclude_paths):
        # Paths come from os.walk rooted at project_path, so relative_to is safe.
        source = setup_cfg.relative_to(project_path).as_posix()
        deps.extend(_parse_setup_cfg(setup_cfg, source, project_path))
    return deps


def detect_project_license_setup_cfg(setup_cfg: Path) -> str:
    """Return the license one ``setup.cfg`` declares for its project, or ``""``.

    Reads ``[metadata] license`` (a raw SPDX-ish string) and falls back to
    the first ``License :: OSI Approved :: *`` trove classifier in
    ``[metadata] classifiers`` if the bare license field is empty.

    A value is interpolated when it is read, as setuptools reads it. One that
    cannot be (a stray ``%``, as in ``license = 100% free``, or a reference
    to an option that is not there) declares no usable license. Nothing is
    recorded for it: dependency discovery reads the same file, and records a
    gap when a value it needs cannot be read.
    """
    text = decode_text(setup_cfg)
    if text is None:
        return ""
    config = configparser.ConfigParser()
    try:
        config.read_string(text)
    except configparser.Error:
        record_parse_failure(setup_cfg, "INI")
        return ""

    try:
        license_val = config.get("metadata", "license", fallback="").strip()
        if license_val:
            return license_val
        classifiers = config.get("metadata", "classifiers", fallback="")
    except configparser.InterpolationError:
        return ""
    for line in classifiers.splitlines():
        line = line.strip()
        if line.startswith("License :: OSI Approved ::"):
            return line.split("::")[-1].strip()

    return ""


def _parse_dep_line(
    line: str, group: DependencyGroup, source: str, base_dir: Path, scan_root: Path
) -> Dependency | None:
    """Parse a single dependency line from setup.cfg.

    A direct reference (``name @ <url>``) is a dependency with an origin; one
    to a path that the scan reads is the project's own code and yields None.
    """
    if not line or line.startswith("#"):
        return None
    return requirement_dependency(line, group, source, base_dir, scan_root)
