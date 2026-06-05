"""Ruby / RubyGems dependency discovery."""

from __future__ import annotations

from licenseal.discovery.ruby.gemfile import discover_gemfile_dependencies
from licenseal.discovery.ruby.gemspec import (
    detect_project_license_gemspec,
    discover_gemspec_dependencies,
    workspace_gemspec_names,
)
from licenseal.discovery.ruby.lockfiles import (
    find_gemfile_lockfiles,
    parse_gemfile_lock,
)

__all__ = [
    "detect_project_license_gemspec",
    "discover_gemfile_dependencies",
    "discover_gemspec_dependencies",
    "find_gemfile_lockfiles",
    "parse_gemfile_lock",
    "workspace_gemspec_names",
]
