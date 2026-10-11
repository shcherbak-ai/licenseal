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
  analyzers + test frameworks), written as an
  attribute or as a ``<PrivateAssets>all</PrivateAssets>`` child element
  → DEV
* A ``Condition`` that is, as a whole, a Debug / Test configuration or an
  IsTestProject comparison (``'$(Configuration)' == 'Debug'``) → DEV
  (heuristic — full MSBuild condition evaluation is out of scope, the same
  trade-off other manifest scanners make). A condition that only
  contains such a comparison (``… Or '$(Configuration)' == 'Release'``)
  is PROD. The ``Condition`` of the reference and the one of its enclosing
  ``<ItemGroup>`` are each tested this way: the reference is included only
  when both hold, so either one being a DEV condition makes it DEV.
* ``IncludeAssets="all"`` and other normal usage attributes → PROD

``<Choose>`` blocks: the items of every ``<When>`` / ``<Otherwise>`` branch
are read, nested ``<Choose>`` blocks included. Branch conditions are not
evaluated, so the references of all branches are unioned (the posture the
lockfile parsers take for target frameworks). A ``<PropertyGroup>`` inside
a branch is not read: which branch a build takes is unknown, so its values
never reach the project's property scope.

``<ProjectReference>`` elements point at other project files and are NOT
NuGet dependencies: nothing is looked up for them. One that points into a
directory of the scanned tree that the scan walks is the project's own code
and is no row (the project IDs of the in-tree project files are
workspace-local sentinels). Any other one (outside the scanned directory,
under a directory the walk skips, or not there) is a ``Dependency`` named
after the referenced project file, with the path as written as its origin.
A path that cannot be
located, because it holds a ``$(Property)`` the project file does not
define, is the project's own code when the scanned tree has a project file
of that name. An ``Include`` with wildcards (``tests/**/*.csproj``) is
judged by the directory its literal part names, and a row for it is named
by the pattern, never by a file stem cut out of it.

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
from collections import deque
from dataclasses import dataclass, field
from itertools import takewhile
from pathlib import Path, PureWindowsPath
from xml.etree.ElementTree import Element  # nosec B405

from defusedxml import ElementTree as DefusedET

from licenseal.discovery._origin import path_origin
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

# MSBuild ``Condition="…"`` values that mark a package as DEV-only, in the
# form they are compared in: lowercased, spaces removed. The full MSBuild
# condition grammar is out of scope; we recognize the common test/debug
# comparisons and conservatively leave everything else PROD. The match is on
# the whole condition — one of these combined with anything else (``Or``,
# ``And``, a second comparison) is not a DEV condition.
_DEV_CONDITIONS = frozenset(
    {
        "'$(configuration)'=='debug'",
        "'$(configuration)'=='test'",
        "'$(istestproject)'=='true'",
        "$(istestproject)=='true'",
    }
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


def _is_dev_condition(condition: str) -> bool:
    """True when ``condition`` is, as a whole, one of the DEV-only comparisons."""
    return condition.lower().replace(" ", "") in _DEV_CONDITIONS


def _is_dev_package_ref(
    package_ref_el: Element | None,
    *,
    private_assets: str,
    condition: str,
) -> bool:
    """Classify a ``<PackageReference>`` as DEV or PROD via attribute hints.

    ``PrivateAssets="all"`` is the canonical signal for analyzer +
    test-framework packages that don't flow to consumers. A ``Condition``
    that is exactly one of the Debug / Test / IsTestProject comparisons
    also marks DEV; everything else is PROD.
    """
    del package_ref_el  # placeholder; structural hints currently only via attrs
    if private_assets.strip().lower() == "all":
        return True
    return _is_dev_condition(condition)


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


def _read_metadata(item_el: Element, name: str) -> str:
    """Return item metadata ``name`` from its attribute or its child element.

    Two shapes are allowed by MSBuild for any metadata of an item:

    1. ``<PackageReference Include="X" Version="1.2.3" />`` — attribute form.
    2. ``<PackageReference Include="X"><Version>1.2.3</Version></PackageReference>``
       — nested-element form (used when a property must be expanded across
       multiple lines, or to keep a stable XML for diff-friendly history).

    Both are tried in order. Returns the empty string when neither carries
    a value.
    """
    attr = (item_el.get(name) or "").strip()
    if attr:
        return attr
    for child in item_el:
        if _strip_ns(child.tag) == name:
            text = (child.text or "").strip()
            if text:
                return text
    return ""


def _read_version(
    package_ref_el: Element,
    *,
    properties: dict[str, str],
) -> str:
    """Extract the ``Version`` for a ``<PackageReference>``.

    Property tokens are expanded against the project's own
    ``<PropertyGroup>`` blocks; ancestor ``Directory.Build.props``
    properties are handled separately.

    Returns the empty string when no version is declared — that's the
    Central Package Management case (a sibling ``Directory.Packages.props``
    supplies the version). The CPM stitching layer fills the gap; this
    parser intentionally leaves it for that layer to handle.
    """
    return _expand_properties(_read_metadata(package_ref_el, "Version"), properties)


def _parse_item_group(group_el: Element, data: _CsprojData) -> None:
    """Collect the package and project references of one ``<ItemGroup>``."""
    # An item is included only when the group's ``Condition`` and its own both
    # hold, so a DEV-only condition on the group makes every reference in it
    # DEV, whatever the reference's own condition says.
    group_is_dev = _is_dev_condition(group_el.get("Condition") or "")
    for item in group_el:
        item_local = _strip_ns(item.tag)
        if item_local == "PackageReference":
            pkg_id = (item.get("Include") or "").strip()
            if not pkg_id:
                continue
            group = (
                DependencyGroup.DEV
                if group_is_dev
                or _is_dev_package_ref(
                    item,
                    private_assets=_read_metadata(item, "PrivateAssets"),
                    condition=item.get("Condition") or "",
                )
                else DependencyGroup.PROD
            )
            data.package_refs.append(
                _CsprojDep(
                    package_id=pkg_id,
                    version=_read_version(item, properties=data.properties),
                    group=group,
                )
            )
        elif item_local == "ProjectReference":
            ref = (item.get("Include") or "").strip()
            if ref:
                data.project_refs.append(ref)


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

    # The root's children first, in document order, then the ``<When>`` /
    # ``<Otherwise>`` branches of each ``<Choose>`` (a branch can nest another
    # ``<Choose>``). A queue rather than recursion: nesting depth comes from
    # the file. Every branch is read, so the references of all of them are
    # unioned; only the root's own ``<PropertyGroup>`` blocks set properties.
    containers = deque([root])
    while containers:
        container = containers.popleft()
        for child in container:
            local = _strip_ns(child.tag)
            if local == "PropertyGroup" and container is root:
                _parse_property_group(child, data.properties)
            elif local == "ItemGroup":
                _parse_item_group(child, data)
            elif local == "Choose":
                containers.extend(child)

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
    """Collect ``project_id`` for every in-tree .NET project file, as identity keys.

    NuGet ids are compared without regard to case, so the ids are returned
    as ``Ecosystem.identity`` keys, and a package id is looked up in the set
    by its own key.

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
        local.add(Ecosystem.DOTNET.identity(data.project_id))
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


# MSBuild properties that name the directory of the project file itself.
# The first two end in a path separator.
_PROJECT_DIR_PROPERTIES = {
    "MSBuildThisFileDirectory": "",
    "ProjectDir": "",
    "MSBuildProjectDirectory": ".",
}

# The wildcard characters of an item ``Include`` (``**`` is two of the first).
_WILDCARDS = frozenset("*?")


def _literal_prefix(pattern: str) -> str:
    """The directory a wildcard ``Include`` names before its first wildcard segment.

    ``tests/**/*.csproj`` → ``tests``; ``Lib*/*.csproj`` → the empty path,
    which is the directory of the project file itself.
    """
    segments = pattern.replace("\\", "/").split("/")
    return "/".join(takewhile(_WILDCARDS.isdisjoint, segments))


def _file_name_matcher(file_name: str) -> re.Pattern[str]:
    """Matcher for a referenced file name, in which ``*`` and ``?`` are wildcards."""
    return re.compile(re.escape(file_name).replace(r"\*", ".*").replace(r"\?", "."))


def _project_reference_dependencies(
    data: _CsprojData,
    project_file: Path,
    scan_root: Path,
    source: str,
    local_file_names: set[str],
) -> list[Dependency]:
    """One dependency per ``<ProjectReference>`` to a project the scan does not read.

    A referenced project file in a directory of ``scan_root`` that the scan
    walks is the project's own code and is skipped. The path is read with
    the project's own ``$(Property)`` values filled in. An ``Include`` can
    list several paths, separated by ``;``; each is judged by itself.

    A path with wildcards (``tests/**/*.csproj``) names many project files.
    It is judged by the directory its literal part names, the part before
    the first segment that holds a wildcard: when the scan walks that
    directory, the projects the pattern matches are ones it reads.

    A path that still holds a ``$(…)`` token cannot be located: it is the
    project's own code when ``local_file_names`` (the lowercased names of the
    project files of the scanned tree) has a name the referenced file name
    matches, and is reported otherwise.

    The dependency is named after the referenced project file, or is named
    by the pattern as written when the path has wildcards, and carries the
    path as written as its origin.
    """
    properties = {**_PROJECT_DIR_PROPERTIES, **data.properties}
    out: list[Dependency] = []
    for include in data.project_refs:
        for written in filter(None, (part.strip() for part in include.split(";"))):
            expanded = _expand_properties(written, properties)
            wildcard = not _WILDCARDS.isdisjoint(expanded)
            if "$(" in expanded:
                matcher = _file_name_matcher(PureWindowsPath(expanded).name.lower())
                inside = any(matcher.fullmatch(name) for name in local_file_names)
            else:
                # The scan reads the referenced projects when it walks the
                # directory that holds them.
                directory = (
                    _literal_prefix(expanded) if wildcard else str(PureWindowsPath(expanded).parent)
                )
                inside = path_origin(directory, project_file.parent, scan_root) is None
            if inside:
                continue
            out.append(
                Dependency(
                    name=written if wildcard else PureWindowsPath(expanded).stem or written,
                    version_constraint="",
                    ecosystem=Ecosystem.DOTNET,
                    group=DependencyGroup.PROD,
                    source=source,
                    origin=written,
                )
            )
    return out


def _dependencies_from_refs(
    refs: list[_CsprojDep],
    *,
    source: str,
    workspace_local: set[str],
) -> tuple[list[Dependency], int]:
    """Turn the ``<PackageReference>`` items of one file into ``Dependency`` rows.

    ``source`` is the declaring file's path relative to the scan root.
    Returns ``(deps, filtered_count)``; a reference whose ID is an in-tree
    project's is filtered rather than emitted.
    """
    out: list[Dependency] = []
    filtered = 0
    for ref in refs:
        if Ecosystem.DOTNET.identity(ref.package_id) in workspace_local:
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


def discover_csproj_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct ``<PackageReference>`` dependencies under ``project_path``.

    Walks every ``.csproj``, ``.fsproj``, and ``.vbproj`` in the tree
    (subject to the shared ``exclude_paths`` set), parses each, and emits
    one :class:`Dependency` per ``<PackageReference>``, and one per
    ``<ProjectReference>`` to a project the scan does not read. Returns
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

    project_files = _walk_project_files(project_path, exclude_paths=exclude_paths)
    local_file_names = {project_file.name.lower() for project_file in project_files}
    for project_file in project_files:
        raw = read_xml_bytes(project_file)
        if raw is None:
            continue
        data = _parse_csproj(raw, source_path=project_file)
        if data is None:
            record_parse_failure(project_file, "XML")
            continue
        source = project_file.relative_to(project_path).as_posix()
        deps, dropped = _dependencies_from_refs(
            data.package_refs,
            source=source,
            workspace_local=workspace_local,
        )
        out.extend(deps)
        out.extend(
            _project_reference_dependencies(
                data, project_file, project_path, source, local_file_names
            )
        )
        filtered += dropped

    return out, filtered


def detect_project_license_csproj(project_file: Path) -> str:
    """Return the license one project file declares for its package, or ``""``.

    Authored-package projects (NuGet packages that ARE the project, not
    consuming applications) carry license metadata in their project file:

    * ``<PackageLicenseExpression>MIT</PackageLicenseExpression>`` — modern
      SPDX expression, returned as declared.
    * ``<PackageLicenseUrl>https://…</PackageLicenseUrl>`` — legacy URL,
      returned as declared when there is no expression. The license
      normalizer maps a URL of a canonical license page to its SPDX ID and
      recognises no other URL.
    * Neither present → the empty string (an application project).
    """
    raw = read_xml_bytes(project_file)
    if raw is None:
        return ""
    data = _parse_csproj(raw, source_path=project_file)
    if data is None:
        record_parse_failure(project_file, "XML")
        return ""
    return data.license_expression or data.license_url
