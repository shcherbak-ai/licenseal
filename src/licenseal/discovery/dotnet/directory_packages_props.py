"""Parse ``Directory.Packages.props`` for NuGet Central Package Management.

Central Package Management (CPM) — introduced in NuGet 5.10 (2020) — is
the .NET analog to Maven's ``<dependencyManagement>``. A single
``Directory.Packages.props`` file at the workspace root (or per-subtree)
declares the version each NuGet package should resolve to, so individual
``.csproj`` files no longer carry ``Version=`` attributes:

.. code-block:: xml

    <!-- Directory.Packages.props at repo root -->
    <Project>
        <PropertyGroup>
            <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
        </PropertyGroup>
        <ItemGroup>
            <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
            <PackageVersion Include="Serilog" Version="3.1.1" />
            <GlobalPackageReference Include="StyleCop.Analyzers" Version="1.2.0-beta.556" />
        </ItemGroup>
    </Project>

Each ``.csproj`` then references without versions:

.. code-block:: xml

    <PackageReference Include="Newtonsoft.Json" />
    <PackageReference Include="Serilog" />
    <!-- StyleCop.Analyzers is automatically applied via GlobalPackageReference -->

MSBuild's CPM rules:

1. **Closest-ancestor wins.** A ``.csproj`` consults the nearest ancestor
   ``Directory.Packages.props`` walking up the directory tree. A
   subdirectory's ``Directory.Packages.props`` overrides a more-distant
   ancestor's — same semantics as ``Directory.Build.props``.

2. **GlobalPackageReference is implicit.** Every project under the props
   file's directory gets these packages applied as if they had explicit
   ``<PackageReference>`` entries. Most commonly used for analyzers
   (StyleCop.Analyzers, SonarAnalyzer) and source-link tooling.

3. **PackageVersion only supplies versions.** It does NOT add the package
   as a dependency — only the project's ``<PackageReference>`` decides
   that. Versions for packages not referenced by any project are dead
   metadata.

This module reads CPM files but does NOT stitch them back into the
``.csproj`` parser's output — that's the discovery aggregator's
responsibility (so the cross-file coordination has a single owner and
the parsers stay self-contained).

``Directory.Build.props`` (general MSBuild settings, NOT CPM) is parsed
separately by :mod:`.directory_build_props`. Both files coexist commonly
at the same level; the two concerns are kept apart so a project mixing
the two doesn't get version metadata muddled with build settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree as DefusedET

from licenseal.discovery._read import read_xml_bytes, record_parse_failure
from licenseal.discovery._walk import walk_project_files
from licenseal.discovery.dotnet.csproj import _strip_ns

_PROPS_FILENAME = "Directory.Packages.props"


@dataclass
class CpmData:
    """Parsed contents of one ``Directory.Packages.props`` file.

    ``versions`` maps ``package_id_lowercased -> version_string`` (NuGet
    package IDs are case-insensitive per spec; we lowercase the key but
    preserve the casing-as-authored separately if needed downstream).

    ``global_package_refs`` lists packages applied to every project under
    this props file's directory subtree, mapped (by as-authored Include) to
    their declared versions. They behave as implicit
    ``<PackageReference PrivateAssets="all" />`` entries — build-time tooling
    (analyzers, source-link) that never flows to consumers — so the aggregator
    (``_stitch_dotnet_versions``) materializes them as direct DEV dependencies,
    deduped across the projects they apply to.
    """

    versions: dict[str, str] = field(default_factory=dict)
    global_package_refs: dict[str, str] = field(default_factory=dict)


def _parse_directory_packages_props(raw: str | bytes) -> CpmData | None:
    """Parse one ``Directory.Packages.props`` XML into :class:`CpmData`.

    Accepts raw bytes (preferred — the XML prolog / BOM picks the encoding)
    or already-decoded text. Returns ``None`` on malformed XML /
    billion-laughs / XXE. ``<PackageVersion>`` becomes a ``versions`` entry;
    ``<GlobalPackageReference>`` becomes a ``global_package_refs`` entry. Items
    without an ``Include`` or ``Version`` attribute are skipped (malformed
    entries).
    """
    try:
        root = DefusedET.fromstring(raw)
    except Exception:  # noqa: BLE001 - defusedxml raises many entity classes
        return None

    data = CpmData()
    for child in root:
        if _strip_ns(child.tag) != "ItemGroup":
            continue
        for item in child:
            item_local = _strip_ns(item.tag)
            include = (item.get("Include") or "").strip()
            version = (item.get("Version") or "").strip()
            if not include or not version:
                continue
            key = include.lower()
            if item_local == "PackageVersion":
                data.versions[key] = version
            elif item_local == "GlobalPackageReference":
                # Key by the as-authored Include (not lowercased): unlike
                # PackageVersion, global refs aren't looked up by the csproj
                # parser, and the materialized Dependency should carry the
                # package's real casing for display. NuGet resolution is
                # case-insensitive, and the aggregator dedupes case-folded.
                data.global_package_refs[include] = version
    return data


def find_directory_packages_props(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> dict[Path, CpmData]:
    """Walk ``project_path`` collecting every ``Directory.Packages.props``.

    Returns a map ``{directory_containing_file → CpmData}``. The directory
    key (not the file path itself) is what's needed by the closest-
    ancestor lookup: a ``.csproj`` at ``a/b/c/Proj.csproj`` looks for the
    nearest ancestor among the map keys (``a/b/c/``, ``a/b/``, ``a/``, …)
    and uses the corresponding ``CpmData``.

    Files that fail to parse (malformed XML, billion-laughs) are silently
    skipped — the corresponding subtree falls back to whatever ancestor
    CPM file (if any) is still valid.
    """
    out: dict[Path, CpmData] = {}
    for path in walk_project_files(project_path, _PROPS_FILENAME, exclude_paths=exclude_paths):
        raw = read_xml_bytes(path)
        if raw is None:
            continue
        data = _parse_directory_packages_props(raw)
        if data is None:
            record_parse_failure(path, "XML")
            continue
        out[path.parent] = data
    return out


def closest_cpm_data(
    csproj_path: Path,
    cpm_files: dict[Path, CpmData],
) -> CpmData | None:
    """Return the ``CpmData`` whose directory is the closest ancestor of ``csproj_path``.

    Iterates ``csproj_path``'s parent chain — first the immediate parent,
    then grandparent, then great-grandparent, etc. — and returns the
    first ``CpmData`` whose directory matches. Returns ``None`` when
    no ancestor in the parents chain has a registered props file.

    MSBuild's actual closest-ancestor rule walks upward including the
    project's own directory; we mirror that.
    """
    if not cpm_files:
        return None
    for ancestor in [csproj_path.parent, *csproj_path.parent.parents]:
        if ancestor in cpm_files:
            return cpm_files[ancestor]
    return None


def lookup_version(
    package_id: str,
    csproj_path: Path,
    cpm_files: dict[Path, CpmData],
) -> str:
    """Return the CPM-declared version for ``package_id`` at ``csproj_path``.

    Returns the empty string when no CPM file applies, or when the
    applicable file doesn't declare a version for this package. The
    aggregator uses this to fill missing ``Version=`` attributes on
    ``<PackageReference>`` entries discovered by the ``.csproj`` parser.

    Matches case-insensitively per the NuGet spec.
    """
    data = closest_cpm_data(csproj_path, cpm_files)
    if data is None:
        return ""
    return data.versions.get(package_id.lower(), "")
