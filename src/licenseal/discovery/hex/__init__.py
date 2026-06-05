"""Hex (Elixir / Erlang) dependency discovery.

Both Elixir (``mix.exs`` / ``mix.lock``) and Erlang (``rebar.config`` /
``rebar.lock``) resolve packages from the single ``hex.pm`` registry, so they
share one :class:`~licenseal.models.Ecosystem` value (``HEX``) and one resolver.
"""

from __future__ import annotations

from licenseal.discovery.hex.erlang_mk import (
    discover_erlang_mk_dependencies,
    workspace_erlang_mk_project_names,
    workspace_hex_names,
)
from licenseal.discovery.hex.mix_exs import (
    collect_dev_direct_names,
    detect_project_license_mix_exs,
    discover_mix_exs_dependencies,
    workspace_mix_names,
)
from licenseal.discovery.hex.mix_lock import (
    attach_direct_sources,
    find_mix_lockfiles,
    is_off_registry_marker,
    parse_mix_lock,
)
from licenseal.discovery.hex.rebar_config import discover_rebar_config_dependencies
from licenseal.discovery.hex.rebar_lock import find_rebar_lockfiles, parse_rebar_lock

__all__ = [
    "attach_direct_sources",
    "collect_dev_direct_names",
    "detect_project_license_mix_exs",
    "discover_erlang_mk_dependencies",
    "discover_mix_exs_dependencies",
    "discover_rebar_config_dependencies",
    "find_mix_lockfiles",
    "find_rebar_lockfiles",
    "is_off_registry_marker",
    "parse_mix_lock",
    "parse_rebar_lock",
    "workspace_erlang_mk_project_names",
    "workspace_hex_names",
    "workspace_mix_names",
]
