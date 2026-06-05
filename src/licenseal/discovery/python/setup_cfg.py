"""Discover Python dependencies from setup.cfg files."""

from __future__ import annotations

import configparser
from pathlib import Path

from licenseal.discovery._read import decode_text, record_parse_failure
from licenseal.discovery.python import DEV_GROUP_NAMES, parse_pep508_dep
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def discover_setup_cfg_dependencies(project_path: Path) -> list[Dependency]:
    """Discover dependencies from setup.cfg in project."""
    setup_cfg = project_path / "setup.cfg"
    if not setup_cfg.exists():
        return []

    text = decode_text(setup_cfg)
    if text is None:
        return []
    config = configparser.ConfigParser()
    try:
        config.read_string(text)
    except configparser.Error:
        # Malformed setup.cfg (duplicate option/section, bad interpolation).
        # Match every other Python discovery parser and the sibling
        # ``detect_project_license_setup_cfg`` below: fail soft to no deps
        # rather than aborting the whole scan on one unparseable manifest.
        record_parse_failure(setup_cfg, "INI")
        return []

    deps: list[Dependency] = []

    # [options] install_requires
    install_requires = config.get("options", "install_requires", fallback="")
    for line in install_requires.strip().splitlines():
        dep = _parse_dep_line(line.strip(), DependencyGroup.PROD)
        if dep:
            deps.append(dep)

    # [options.extras_require]
    if config.has_section("options.extras_require"):
        dev_names = DEV_GROUP_NAMES
        for extra_name, extra_deps_str in config.items("options.extras_require"):
            group = DependencyGroup.DEV if extra_name.lower() in dev_names else DependencyGroup.PROD
            for line in extra_deps_str.strip().splitlines():
                dep = _parse_dep_line(line.strip(), group)
                if dep:
                    deps.append(dep)

    return deps


def detect_project_license_setup_cfg(project_path: Path) -> str:
    """Detect the project's own license from setup.cfg.

    Reads ``[metadata] license`` (a raw SPDX-ish string) and falls back to
    the first ``License :: OSI Approved :: *`` trove classifier in
    ``[metadata] classifiers`` if the bare license field is empty.
    """
    setup_cfg = project_path / "setup.cfg"
    if not setup_cfg.exists():
        return ""

    text = decode_text(setup_cfg)
    if text is None:
        return ""
    config = configparser.ConfigParser()
    try:
        config.read_string(text)
    except configparser.Error:
        record_parse_failure(setup_cfg, "INI")
        return ""

    license_val = config.get("metadata", "license", fallback="").strip()
    if license_val:
        return license_val

    classifiers = config.get("metadata", "classifiers", fallback="")
    for line in classifiers.splitlines():
        line = line.strip()
        if line.startswith("License :: OSI Approved ::"):
            return line.split("::")[-1].strip()

    return ""


def _parse_dep_line(line: str, group: DependencyGroup) -> Dependency | None:
    """Parse a single dependency line from setup.cfg."""
    if not line or line.startswith("#"):
        return None

    name, version, extras = parse_pep508_dep(line)
    if not name:
        return None

    return Dependency(
        name=name,
        version_constraint=version,
        ecosystem=Ecosystem.PYTHON,
        group=group,
        source="setup.cfg",
        extras=extras,
    )
