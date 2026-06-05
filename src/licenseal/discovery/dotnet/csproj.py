"""Parse .NET project files into direct ``Dependency`` entries.

A .NET project declares its direct dependencies in ``<PackageReference>``
elements inside ``<ItemGroup>`` blocks of its project file. Three file
extensions share the same schema:

* ``.csproj`` — C# projects (the common case)
* ``.fsproj`` — F# projects
* ``.vbproj`` — VB.NET projects

Two project-file flavors exist:

1. **SDK-style** (``.NET Core`` 1.0+ / ``.NET 5``+ / modern .NET Framework
   migrations). The root element carries an ``Sdk="…"`` attribute
   (``Microsoft.NET.Sdk``, ``Microsoft.NET.Sdk.Web``, ``Microsoft.NET.Sdk.Razor``,
   etc.) and the XML has NO namespace. Dependencies look like:

   .. code-block:: xml

       <Project Sdk="Microsoft.NET.Sdk">
           <PropertyGroup>
               <TargetFramework>net8.0</TargetFramework>
           </PropertyGroup>
           <ItemGroup>
               <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
               <PackageReference Include="Serilog">
                   <Version>3.1.1</Version>
               </PackageReference>
               <PackageReference Include="xunit" Version="2.6.1" PrivateAssets="all" />
               <ProjectReference Include="..\\Other.Project\\Other.csproj" />
           </ItemGroup>
       </Project>

2. **Legacy** (.NET Framework, pre-SDK-style). The root carries the
   MSBuild 2003 namespace (``http://schemas.microsoft.com/developer/msbuild/2003``)
   and dependencies historically lived in ``packages.config`` (separate
   file, parsed by :mod:`.packages_config`). Some hybrid projects still
   carry ``<PackageReference>`` elements; we handle both shapes by namespace-
   stripping every tag before matching.

Coordinate format on ``Dependency.name``: ``"Package.Name"`` (case-preserved
during discovery; lowercased only for canonical-name / review-key matching
because NuGet package IDs are case-insensitive per spec).

Group attribution heuristics (the .NET equivalents of Maven's scope
mapping):

* Plain ``<PackageReference Include="X" Version="Y" />`` → PROD
* ``PrivateAssets="all"`` (won't be propagated to consumers, typically
  analyzers + test frameworks like xunit/nunit/MSTest) → DEV
* ``Condition="…Configuration…Debug…"`` or ``Condition="…IsTestProject…"``
  patterns → DEV (heuristic — full MSBuild condition evaluation is out of
  scope, same trade-off Trivy and license-checker tools make)
* ``IncludeAssets="all"`` and other normal usage attributes → PROD

``<ProjectReference>`` elements point at other in-tree ``.csproj`` files
and are NOT NuGet dependencies. They are emitted by the workspace-local
filter scan (the project IDs become workspace-local sentinels) but never
appear as ``Dependency`` rows.

MSBuild property expansion (``$(PropertyName)``) is performed in a single
locally-resolvable pass against the project's own ``<PropertyGroup>``
blocks. ``Directory.Build.props`` and ``Directory.Packages.props`` from
ancestor directories are NOT consulted in this initial parser — that is
the responsibility of :mod:`.directory_packages_props` and
:mod:`.directory_build_props` in follow-up iterations. Unresolved tokens
stay literal (the resolver routes them to UNKNOWN, which is the correct
posture: a missing property means the build pipeline supplies the value
elsewhere and licenseal cannot fabricate it).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree.ElementTree import Element  # nosec B405

from defusedxml import ElementTree as DefusedET

from licenseal.discovery._read import read_xml_bytes, record_parse_failure
from licenseal.discovery._walk import walk_project_files_matching
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Legacy .NET Framework project files use this MSBuild 2003 namespace.
# SDK-style projects have no namespace. We strip the prefix off every tag
# before matching so both shapes route through the same parser.
_MSBUILD_NS_PREFIX_RE = re.compile(r"^\{http://schemas\.microsoft\.com/developer/msbuild/2003\}")

# ``$(Property)`` substitution token. Captures the inner name. Unlike
# Maven's ``${…}`` syntax, MSBuild uses parentheses.
_PROPERTY_RE = re.compile(r"\$\(([^)]+)\)")

# File extensions we treat as .NET project files. All three share the
# MSBuild schema; ``.vcxproj`` (C++) and ``.shproj`` (shared) are
# intentionally NOT included — they don't carry NuGet PackageReferences.
_PROJECT_EXTENSIONS = (".csproj", ".fsproj", ".vbproj")

# Heuristic substrings in MSBuild ``Condition="…"`` attributes that mark
# a package as DEV-only. The full MSBuild condition grammar is out of
# scope; we recognize the common test/debug patterns and conservatively
# leave everything else PROD.
_DEV_CONDITION_HINTS = (
    "configuration)' == 'debug'",
    "configuration)' == 'test'",
    "istestproject)' == 'true'",
    "istestproject) == 'true'",
)


def _strip_ns(tag: str) -> str:
    """Remove the MSBuild XML namespace prefix from a tag name."""
    return _MSBUILD_NS_PREFIX_RE.sub("", tag)


@dataclass
class _CsprojDep:
    """One ``<PackageReference>`` entry extracted from a project file."""

    package_id: str
    version: str
    group: DependencyGroup


@dataclass
class _CsprojData:
    """Structured project-file content used by the discovery path."""

    project_id: str = ""
    """The ``<PackageId>`` (when authoring a package) or root project name
    fallback (file stem). Used by the workspace-local filter to mark
    in-tree projects."""

    package_refs: list[_CsprojDep] = field(default_factory=list)
    project_refs: list[str] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)
    license_expression: str = ""
    license_url: str = ""


def _expand_properties(value: str, properties: dict[str, str]) -> str:
    """Substitute ``$(name)`` tokens with values from ``properties``.

    Unknown property names stay literal in the output. Single-pass — no
    nested-property resolution at this layer. The version-extractor in
    the resolver detects any remaining ``$(…)`` token and routes the dep
    to UNKNOWN, which is the correct posture for build-time-only
    properties (CI version stamps, MSBuild tasks, etc.) that licenseal
    cannot fabricate from manifest content alone.
    """
    if not value or "$(" not in value:
        return value

    def replace(match: re.Match[str]) -> str:
        name = match.group(1).strip()
        return properties.get(name, match.group(0))

    return _PROPERTY_RE.sub(replace, value)


def _is_dev_package_ref(
    package_ref_el: Element | None,
    *,
    private_assets: str,
    condition: str,
) -> bool:
    """Classify a ``<PackageReference>`` as DEV or PROD via attribute hints.

    ``PrivateAssets="all"`` is the canonical signal for analyzer +
    test-framework packages (xunit, nunit, MSTest, StyleCop.Analyzers,
    SonarAnalyzer, etc.) that don't flow to consumers. ``Condition``
    patterns matching Debug or IsTestProject also mark DEV; everything
    else is PROD.
    """
    del package_ref_el  # placeholder; structural hints currently only via attrs
    if private_assets.strip().lower() == "all":
        return True
    cond_normalized = condition.lower().replace(" ", "")
    return any(hint.replace(" ", "") in cond_normalized for hint in _DEV_CONDITION_HINTS)


def _parse_property_group(group_el: Element, into: dict[str, str]) -> None:
    """Merge ``<PropertyGroup>`` child elements into ``into``.

    MSBuild's last-write-wins semantics applies for multi-PropertyGroup
    files; we honor that by allowing later writes to overwrite earlier.
    Empty / whitespace-only values are skipped (they would otherwise
    mask a meaningful inherited value at the resolver layer).
    """
    for child in group_el:
        name = _strip_ns(child.tag)
        value = (child.text or "").strip()
        if value:
            into[name] = value


def _read_version(
    package_ref_el: Element,
    *,
    properties: dict[str, str],
) -> str:
    """Extract the ``Version`` for a ``<PackageReference>``.

    Two shapes are allowed by MSBuild:

    1. ``<PackageReference Include="X" Version="1.2.3" />`` — attribute form.
    2. ``<PackageReference Include="X"><Version>1.2.3</Version></PackageReference>``
       — nested-element form (used when a property must be expanded across
       multiple lines, or to keep a stable XML for diff-friendly history).

    Both are tried in order. Property tokens are expanded against the
    project's own ``<PropertyGroup>`` blocks; ancestor
    ``Directory.Build.props`` properties are handled separately.

    Returns the empty string when no version is declared — that's the
    Central Package Management case (a sibling ``Directory.Packages.props``
    supplies the version). The CPM stitching layer fills the gap; this
    parser intentionally leaves it for that layer to handle.
    """
    attr = package_ref_el.get("Version", "") or ""
    if attr.strip():
        return _expand_properties(attr.strip(), properties)
    for child in package_ref_el:
        if _strip_ns(child.tag) == "Version":
            text = (child.text or "").strip()
            if text:
                return _expand_properties(text, properties)
    return ""


def _parse_csproj(raw: str | bytes, *, source_path: Path) -> _CsprojData | None:
    """Parse one project-file XML into a :class:`_CsprojData`.

    Accepts raw bytes (preferred — the XML prolog / BOM picks the encoding)
    or already-decoded text. Returns ``None`` on malformed XML /
    billion-laughs-style entity expansion / empty file. Defensive: this runs
    on attacker-controlled input (the scanned project's own files).
    """
    try:
        root = DefusedET.fromstring(raw)
    except Exception:  # noqa: BLE001 - defusedxml raises many entity classes
        return None

    data = _CsprojData()
    # The file stem is the project-ID fallback (used by the workspace-local
    # filter when ``<PackageId>`` is absent — the common case for non-library
    # projects).
    data.project_id = source_path.stem

    for child in root:
        local = _strip_ns(child.tag)
        if local == "PropertyGroup":
            _parse_property_group(child, data.properties)
        elif local == "ItemGroup":
            for item in child:
                item_local = _strip_ns(item.tag)
                if item_local == "PackageReference":
                    pkg_id = (item.get("Include") or "").strip()
                    if not pkg_id:
                        continue
                    version = _read_version(item, properties=data.properties)
                    private_assets = item.get("PrivateAssets") or ""
                    condition = item.get("Condition") or ""
                    group = (
                        DependencyGroup.DEV
                        if _is_dev_package_ref(
                            item,
                            private_assets=private_assets,
                            condition=condition,
                        )
                        else DependencyGroup.PROD
                    )
                    data.package_refs.append(
                        _CsprojDep(
                            package_id=pkg_id,
                            version=version,
                            group=group,
                        )
                    )
                elif item_local == "ProjectReference":
                    ref = (item.get("Include") or "").strip()
                    if ref:
                        data.project_refs.append(ref)

    # Promote authored-package license metadata from PropertyGroup into
    # explicit fields. Only ``<PackageLicenseExpression>`` carries SPDX
    # directly; ``<PackageLicenseUrl>`` is the legacy URL form (mapped
    # later via ``analysis/spdx.spdx_from_license_url``).
    data.license_expression = data.properties.get("PackageLicenseExpression", "")
    data.license_url = data.properties.get("PackageLicenseUrl", "")

    # ``<PackageId>`` overrides the file-stem project_id when present (an
    # authored-package project may use a different ID than its file name).
    if "PackageId" in data.properties:
        data.project_id = data.properties["PackageId"]

    return data


def _discover_workspace_local_project_ids(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> set[str]:
    """Collect ``project_id`` for every in-tree .NET project file.

    Used to filter ``<PackageReference Include="X" />`` entries where ``X``
    matches an in-tree project's ID — that would be a workspace-local
    project pulled in via NuGet by mistake (rare but observed in
    migration-state codebases). The primary filtering happens via
    ``<ProjectReference>`` which is structurally a different element;
    this set guards the corner-case overlap.

    Mirrors the Java workspace-local pattern. Test-fixture project files
    are NOT excluded here yet — that filter is a follow-up if the .NET
    stress-test surfaces analogous issues (other ecosystems exclude the
    conventional test-fixture dirs: the JVM's ``src/test/``, Go's
    ``testdata/``).
    """
    local: set[str] = set()
    for project_file in _walk_project_files(project_path, exclude_paths=exclude_paths):
        raw = read_xml_bytes(project_file)
        if raw is None:
            continue
        data = _parse_csproj(raw, source_path=project_file)
        if data is None:
            record_parse_failure(project_file, "XML")
            continue
        # ``project_id`` defaults to the file stem (always non-empty), so a
        # successfully-parsed project file always contributes an id.
        local.add(data.project_id)
    return local


def _walk_project_files(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every ``.csproj`` / ``.fsproj`` / ``.vbproj`` under the project tree."""

    def _match(name: str) -> bool:
        return name.endswith(_PROJECT_EXTENSIONS)

    return walk_project_files_matching(project_path, _match, exclude_paths=exclude_paths)


def discover_csproj_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct ``<PackageReference>`` dependencies under ``project_path``.

    Walks every ``.csproj``, ``.fsproj``, and ``.vbproj`` in the tree
    (subject to the shared ``exclude_paths`` set), parses each, and emits
    one :class:`Dependency` per ``<PackageReference>``. Returns
    ``(deps, filtered_count)`` where ``filtered_count`` is the number of
    refs dropped because they pointed at an in-tree workspace-local
    project ID (the rare corner case where a NuGet package shares a name
    with a sibling project).

    Project files are read as raw bytes and parsed encoding-aware (the XML
    prolog / BOM picks the encoding), so the UTF-8 / UTF-16 BOMs that Visual
    Studio and other tools have historically written are handled rather than
    crashing or dropping the file.
    """
    workspace_local = _discover_workspace_local_project_ids(
        project_path, exclude_paths=exclude_paths
    )
    out: list[Dependency] = []
    filtered = 0

    for project_file in _walk_project_files(project_path, exclude_paths=exclude_paths):
        raw = read_xml_bytes(project_file)
        if raw is None:
            continue
        data = _parse_csproj(raw, source_path=project_file)
        if data is None:
            record_parse_failure(project_file, "XML")
            continue
        source = project_file.relative_to(project_path).as_posix()
        for ref in data.package_refs:
            if ref.package_id in workspace_local:
                filtered += 1
                continue
            out.append(
                Dependency(
                    name=ref.package_id,
                    version_constraint=ref.version,
                    ecosystem=Ecosystem.DOTNET,
                    group=ref.group,
                    source=source,
                )
            )

    return out, filtered


def detect_project_license_csproj(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Return the scanned project's own license declaration, if any.

    Authored-package projects (NuGet packages that ARE the project, not
    consuming applications) carry license metadata in their root
    ``.csproj``:

    * ``<PackageLicenseExpression>MIT</PackageLicenseExpression>`` — modern
      SPDX expression. Direct hit.
    * ``<PackageLicenseUrl>https://…</PackageLicenseUrl>`` — legacy URL.
      Mapped via the shared ``analysis/spdx.spdx_from_license_url``
      pattern table; unmapped URLs return the empty string.
    * Neither present → return empty string. Application projects (not
      packages) fall through to other detection paths (e.g., the LICENSE
      file probe).

    Walks all project files in the tree and uses the first one with a
    non-empty license declaration. Authored-package projects typically
    have exactly one such file at the repo root or under ``src/``.
    """
    from licenseal.analysis.spdx import normalize_license, spdx_from_license_url

    for project_file in _walk_project_files(project_path, exclude_paths=exclude_paths):
        raw = read_xml_bytes(project_file)
        if raw is None:
            continue
        data = _parse_csproj(raw, source_path=project_file)
        if data is None:
            record_parse_failure(project_file, "XML")
            continue
        if data.license_expression:
            normalized = normalize_license(data.license_expression)
            if normalized and normalized != "UNKNOWN":
                return normalized
        if data.license_url:
            mapped = spdx_from_license_url(data.license_url)
            if mapped:
                return mapped
    return ""
