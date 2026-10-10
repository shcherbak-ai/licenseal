"""Parse ``Directory.Build.props`` for inheritable MSBuild properties and items.

``Directory.Build.props`` is MSBuild's repo-wide property mechanism — a
single file at the workspace root (or per-subtree) supplies properties
imported by every ``.csproj`` / ``.fsproj`` / ``.vbproj`` under it. The
common use case in license-discovery context is the centralized
``Version`` token used inside ``<PackageReference Version="$(LibVersion)" />``:

.. code-block:: xml

    <!-- Directory.Build.props at repo root -->
    <Project>
        <PropertyGroup>
            <NewtonsoftVersion>13.0.1</NewtonsoftVersion>
            <SerilogVersion>3.1.1</SerilogVersion>
        </PropertyGroup>
    </Project>

Each ``.csproj`` then references:

.. code-block:: xml

    <PackageReference Include="Newtonsoft.Json" Version="$(NewtonsoftVersion)" />
    <PackageReference Include="Serilog" Version="$(SerilogVersion)" />

MSBuild's inheritance rules mirror those of ``Directory.Packages.props``:

1. **Closest-ancestor wins.** A ``.csproj`` consults the nearest ancestor
   ``Directory.Build.props`` walking up the directory tree.
2. **Multiple ancestors merge.** Properties from the immediate parent
   override more-distant ones, but properties unique to a more-distant
   ancestor still flow through. MSBuild calls this "imported merge."

   *This parser captures one file at a time*; the aggregator is
   responsible for merging the ancestor chain (closest-overrides-farthest
   for keys that exist in multiple files, union for keys that don't
   collide).

A separate ``Directory.Build.targets`` file exists for build-target
overrides; it occasionally carries property definitions too but the
canonical home for properties is ``.props``. We support both filenames
because property declarations there are valid MSBuild and appear in
real-world repos.

Either file can also declare ``<PackageReference>`` items — a package
every project beneath it references (analyzers, source-link tooling, a
shared library). :func:`discover_directory_build_dependencies` emits those
as direct dependencies; the aggregator stitches their versions the same
way it does for a project file's references.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from defusedxml import ElementTree as DefusedET

from licenseal.discovery._read import (
    read_xml_bytes,
    record_parse_failure,
    rejected_path_reference,
)
from licenseal.discovery._walk import walk_project_files_matching
from licenseal.discovery.dotnet.csproj import (
    _dependencies_from_refs,
    _discover_workspace_local_project_ids,
    _parse_csproj,
    _strip_ns,
)
from licenseal.models import Dependency

_PROPS_FILENAMES = ("Directory.Build.props", "Directory.Build.targets")


def _is_build_file(name: str) -> bool:
    """True for the two file names MSBuild imports into every project beneath them."""
    return name in _PROPS_FILENAMES


def _parse_directory_build_props(raw: str | bytes) -> dict[str, str] | None:
    """Parse one ``Directory.Build.props`` XML into a property map.

    Returns ``None`` on malformed XML / billion-laughs / XXE. Returns a
    possibly-empty dict on a valid file with no usable properties.
    Empty / whitespace-only property values are skipped — they would
    otherwise mask a meaningful value supplied by a more-distant
    ancestor or by the project's own ``<PropertyGroup>``.

    Property values are NOT expanded against each other at this layer —
    nested ``$(X)`` tokens stay literal. The aggregator handles cross-
    file expansion when it stitches properties into a project's effective
    property scope.

    Note: this function returns properties for the single file only. The
    caller (``find_directory_build_props``) handles ``<Import>`` traversal
    so this function can be unit-tested in isolation.
    """
    try:
        root = DefusedET.fromstring(raw)
    except Exception:  # noqa: BLE001 - defusedxml raises many entity classes
        return None

    out: dict[str, str] = {}
    for child in root:
        if _strip_ns(child.tag) != "PropertyGroup":
            continue
        for prop in child:
            name = _strip_ns(prop.tag)
            value = (prop.text or "").strip()
            if value:
                out[name] = value
    return out


def _parse_imports(raw: str | bytes) -> list[str]:
    """Return the ``Project="..."`` attribute of every ``<Import>`` element.

    MSBuild's ``Directory.Build.props`` commonly imports sibling
    ``.props`` files (xunit uses ``<Import Project="Versions.props" />``,
    .NET Foundation projects use ``<Import Project="build/Common.props" />``).
    We follow these imports to pick up version properties they declare.

    Returns the raw ``Project="..."`` value as-authored — the caller
    resolves it against the importing file's directory. Returns an empty
    list on parse failure (the caller fall-through is safe — no imports
    means no chain to follow).
    """
    try:
        root = DefusedET.fromstring(raw)
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    for child in root:
        if _strip_ns(child.tag) != "Import":
            continue
        project = child.get("Project")
        if isinstance(project, str) and project.strip():
            out.append(project.strip())
    return out


# Cap import-following depth to defend against pathological circular
# import chains in attacker-controlled scan targets. Real-world chains
# rarely exceed 2-3 levels (Directory.Build.props imports Versions.props
# which imports nothing further).
_MAX_IMPORT_DEPTH = 5


def find_directory_build_props(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> dict[Path, dict[str, str]]:
    """Walk ``project_path`` collecting every ``Directory.Build.props`` / ``.targets``.

    Returns a map ``{directory → properties}``. When both a ``.props``
    and a ``.targets`` file exist in the same directory, ``.props``
    takes precedence (MSBuild's actual behavior is that ``.props`` is
    imported BEFORE ``.targets``, so ``.targets``-declared properties
    win for collisions — but in license-discovery practice, ``.props``
    is where versions live and ``.targets`` rarely overrides them. The
    aggregator can be made stricter if real-world stress tests surface
    a counterexample).

    Each ``Directory.Build.props`` may carry ``<Import Project="..."/>``
    directives pulling in sibling ``.props`` files (xunit's
    ``Versions.props`` pattern, .NET Foundation's ``build/Common.props``
    pattern). We follow these imports up to :data:`_MAX_IMPORT_DEPTH`
    levels deep so the version variables declared in the imported file
    are visible to the property-scope lookup.
    """
    out: dict[Path, dict[str, str]] = {}

    # Two-pass so that within the same directory, ``.props`` wins over
    # ``.targets`` (the more-common ordering).
    by_dir: dict[Path, dict[str, dict[str, str]]] = {}
    for path in walk_project_files_matching(
        project_path, _is_build_file, exclude_paths=exclude_paths
    ):
        raw = read_xml_bytes(path)
        if raw is None:
            continue
        props = _parse_directory_build_props(raw)
        if props is None:
            record_parse_failure(path, "XML")
            continue
        # Follow <Import Project="..."> chains. Properties from imports
        # are merged INTO the current props dict; the file's own values
        # take precedence on collision (MSBuild's import-before-self
        # semantics — Imports execute first, the file's own
        # PropertyGroups overwrite).
        imported_props = _resolve_imports(path, raw)
        merged_props = {**imported_props, **props}
        by_dir.setdefault(path.parent, {})[path.name] = merged_props

    for directory, files in by_dir.items():
        merged: dict[str, str] = {}
        # Apply .targets first, then .props so .props wins for collisions.
        if "Directory.Build.targets" in files:
            merged.update(files["Directory.Build.targets"])
        if "Directory.Build.props" in files:
            merged.update(files["Directory.Build.props"])
        if merged:
            out[directory] = merged

    return out


def _iter_imported_files(
    importing_path: Path,
    importing_data: str | bytes,
    *,
    depth: int = 0,
    visited: frozenset[Path] = frozenset(),
) -> Iterator[tuple[Path, bytes]]:
    """Recursively follow ``<Import Project="..."/>`` chains.

    Yields ``(path, raw)`` for every transitively-imported file that could
    be read, in MSBuild's evaluation order: an imported file's own imports
    come before the file itself, and the imports of one file come in the
    order they are listed.

    Cycle defense: ``visited`` tracks already-loaded paths; a re-entry
    short-circuits. Depth defense: caps at :data:`_MAX_IMPORT_DEPTH`.

    Paths are resolved against ``importing_path``'s parent directory
    (MSBuild's standard relative-path semantics). MSBuild property
    tokens like ``$(MSBuildThisFileDirectory)`` in import paths are
    NOT expanded (those would require a full MSBuild engine); the
    import is silently skipped when the target doesn't resolve.

    Only relative import paths are followed (parent ``..`` references
    included). A rooted, drive-qualified, UNC or device path is
    recorded as a gap on the importing file and never reaches the
    filesystem.
    """
    if depth >= _MAX_IMPORT_DEPTH:
        return
    for project in _parse_imports(importing_data):
        # MSBuild property tokens in import paths can't be safely
        # resolved here (we'd need the full importing-file's scope
        # which itself depends on imports — chicken/egg). Skip any
        # path that still contains ``$(``.
        if "$(" in project:
            continue
        # Only relative imports are followed. The check is lexical and
        # precedes ``resolve()``, which is itself filesystem I/O.
        if rejected_path_reference(importing_path, project):
            continue
        # MSBuild paths use Windows-style backslashes in many real
        # files; convert for cross-platform resolution.
        normalized = project.replace("\\", "/")
        candidate = (importing_path.parent / normalized).resolve()
        if candidate in visited or not candidate.is_file():
            continue
        raw = read_xml_bytes(candidate)
        if raw is None:
            continue
        # Nested imports inside the imported file come first.
        yield from _iter_imported_files(
            candidate,
            raw,
            depth=depth + 1,
            visited=visited | {candidate},
        )
        yield candidate, raw


def _resolve_imports(importing_path: Path, importing_data: str | bytes) -> dict[str, str]:
    """Return the union of all ``<PropertyGroup>`` properties from imported files.

    Files are merged in the order :func:`_iter_imported_files` yields them,
    so nested-imported values flow in first, the imported file's own values
    overwrite them, and later-listed imports win over earlier ones in the
    same file (matches MSBuild's evaluation order).
    """
    accumulated: dict[str, str] = {}
    for candidate, raw in _iter_imported_files(importing_path, importing_data):
        sub_props = _parse_directory_build_props(raw)
        if sub_props is None:
            record_parse_failure(candidate, "XML")
            continue
        accumulated.update(sub_props)
    return accumulated


def discover_directory_build_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover ``<PackageReference>`` items of ``Directory.Build.props`` / ``.targets``.

    MSBuild imports these files into every project beneath their directory,
    so a reference declared in one — or in a file it ``<Import>``s — is a
    direct dependency of those projects. Each reference is emitted once,
    with the ``Directory.Build`` file as its source (also for a reference
    that sits in an imported file), whether or not a project file lies
    beneath it. The file is parsed like a project file, so ``<Choose>``
    branches, ``PrivateAssets`` and ``Condition`` are read the same way.

    Versions are left as declared: the aggregator fills a missing one from
    Central Package Management and expands ``$(Property)`` tokens against
    the property scope of the ``Directory.Build`` file's directory.

    Returns ``(deps, filtered_count)`` like
    :func:`.csproj.discover_csproj_dependencies`.
    """
    workspace_local = _discover_workspace_local_project_ids(
        project_path, exclude_paths=exclude_paths
    )
    out: list[Dependency] = []
    filtered = 0
    for path in walk_project_files_matching(
        project_path, _is_build_file, exclude_paths=exclude_paths
    ):
        raw = read_xml_bytes(path)
        if raw is None:
            continue
        source = path.relative_to(project_path).as_posix()
        for file_path, file_raw in (*_iter_imported_files(path, raw), (path, raw)):
            data = _parse_csproj(file_raw, source_path=file_path)
            if data is None:
                record_parse_failure(file_path, "XML")
                continue
            deps, dropped = _dependencies_from_refs(
                data.package_refs, source=source, workspace_local=workspace_local
            )
            out.extend(deps)
            filtered += dropped
    return out, filtered


def closest_build_props(
    csproj_path: Path,
    build_props: dict[Path, dict[str, str]],
) -> dict[str, str]:
    """Return the effective property scope for ``csproj_path``.

    Walks the parent chain from ``csproj_path``'s directory upward,
    merging properties from each ancestor's ``Directory.Build.props``.
    Closer ancestors override farther ones (MSBuild's closest-wins
    semantics).

    Returns an empty dict when no ``Directory.Build.props`` applies.
    """
    if not build_props:
        return {}
    # Collect ancestors in order from closest to farthest, then merge in
    # reverse so the closest write wins.
    ancestors_with_props: list[dict[str, str]] = []
    for ancestor in [csproj_path.parent, *csproj_path.parent.parents]:
        if ancestor in build_props:
            ancestors_with_props.append(build_props[ancestor])
    merged: dict[str, str] = {}
    for props in reversed(ancestors_with_props):
        merged.update(props)
    return merged
