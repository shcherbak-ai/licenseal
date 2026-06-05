"""\\.NET ecosystem discovery (NuGet + Paket).

Two package managers share one ``Ecosystem.DOTNET`` enum value because both
produce .NET artifacts pulled from the same registry (``api.nuget.org``).
The distinction matters only at discovery time:

* **NuGet** is the canonical package manager. Direct dependencies live in
  ``.csproj`` / ``.fsproj`` / ``.vbproj`` files (modern SDK-style XML) or
  legacy ``packages.config`` XML. Versions can be centralized via
  ``Directory.Packages.props`` (Central Package Management). Resolved
  graphs live in ``packages.lock.json`` (opt-in committed lockfile,
  NuGet 4.9+) or ``project.assets.json`` (always emitted by
  ``dotnet restore``).

* **Paket** is an alternative package manager popular in F# and some
  enterprise .NET shops. Manifest is ``paket.dependencies`` (text format);
  resolved lockfile is ``paket.lock``. Paket points at ``api.nuget.org``
  for NUGET-group sources, so the registry path is shared with NuGet.

Both share workspace-local filtering: a ``.csproj`` ``<ProjectReference>``
pointing at an in-tree sibling is a local project reference, not a NuGet
package — same shape as Maven multi-module ``<modules>`` linkage or Go
workspace ``go.work``.

XML parsing uses ``defusedxml.ElementTree`` to neutralize XML-bomb and
external-entity attack vectors — necessary because manifest files in a
scan target are, by definition, untrusted input.
"""

from __future__ import annotations

from licenseal.discovery.dotnet.csproj import (
    detect_project_license_csproj,
    discover_csproj_dependencies,
)
from licenseal.discovery.dotnet.directory_build_props import (
    closest_build_props,
    find_directory_build_props,
)
from licenseal.discovery.dotnet.directory_packages_props import (
    CpmData,
    closest_cpm_data,
    find_directory_packages_props,
    lookup_version,
)
from licenseal.discovery.dotnet.lockfiles import (
    discover_nuget_lockfile_dependencies,
    find_nuget_lockfiles,
    parse_packages_lock_json,
    parse_project_assets_json,
)
from licenseal.discovery.dotnet.packages_config import (
    discover_packages_config_dependencies,
)
from licenseal.discovery.dotnet.paket import (
    discover_paket_dependencies,
    find_paket_lockfiles,
    parse_paket_lock,
)

__all__ = [
    "CpmData",
    "closest_build_props",
    "closest_cpm_data",
    "detect_project_license_csproj",
    "discover_csproj_dependencies",
    "discover_nuget_lockfile_dependencies",
    "discover_packages_config_dependencies",
    "discover_paket_dependencies",
    "find_directory_build_props",
    "find_directory_packages_props",
    "find_nuget_lockfiles",
    "find_paket_lockfiles",
    "lookup_version",
    "parse_packages_lock_json",
    "parse_paket_lock",
    "parse_project_assets_json",
]
