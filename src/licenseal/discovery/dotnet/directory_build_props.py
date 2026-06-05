"""Parse ``Directory.Build.props`` for inheritable MSBuild properties.

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
"""

from __future__ import annotations

from pathlib import Path

from defusedxml import ElementTree as DefusedET

from licenseal.discovery._read import read_xml_bytes, record_parse_failure
from licenseal.discovery._walk import walk_project_files_matching
from licenseal.discovery.dotnet.csproj import _strip_ns

_PROPS_FILENAMES = ("Directory.Build.props", "Directory.Build.targets")


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

    def _match(name: str) -> bool:
        return name in _PROPS_FILENAMES

    # Two-pass so that within the same directory, ``.props`` wins over
    # ``.targets`` (the more-common ordering).
    by_dir: dict[Path, dict[str, dict[str, str]]] = {}
    for path in walk_project_files_matching(project_path, _match, exclude_paths=exclude_paths):
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
        imported_props = _resolve_imports(path, raw, depth=0)
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


def _resolve_imports(
    importing_path: Path,
    importing_data: str | bytes,
    *,
    depth: int,
    visited: frozenset[Path] = frozenset(),
) -> dict[str, str]:
    """Recursively follow ``<Import Project="..."/>`` chains.

    Returns the union of all ``<PropertyGroup>`` properties from the
    transitively-imported files. Closer (deeper-imported) properties
    win over farther in the same way Python's chained ``dict.update``
    works in the caller — but within the import-chain itself, leaf
    files are written first, then earlier links overwrite.

    Cycle defense: ``visited`` tracks already-loaded paths; a re-entry
    short-circuits. Depth defense: caps at :data:`_MAX_IMPORT_DEPTH`.

    Paths are resolved against ``importing_path``'s parent directory
    (MSBuild's standard relative-path semantics). MSBuild property
    tokens like ``$(MSBuildThisFileDirectory)`` in import paths are
    NOT expanded (those would require a full MSBuild engine); the
    import is silently skipped when the target doesn't resolve.
    """
    if depth >= _MAX_IMPORT_DEPTH:
        return {}
    import_paths = _parse_imports(importing_data)
    if not import_paths:
        return {}
    accumulated: dict[str, str] = {}
    for raw in import_paths:
        # MSBuild property tokens in import paths can't be safely
        # resolved here (we'd need the full importing-file's scope
        # which itself depends on imports — chicken/egg). Skip any
        # path that still contains ``$(``.
        if "$(" in raw:
            continue
        # MSBuild paths use Windows-style backslashes in many real
        # files; convert for cross-platform resolution.
        normalized = raw.replace("\\", "/")
        candidate = (importing_path.parent / normalized).resolve()
        if candidate in visited or not candidate.is_file():
            continue
        raw = read_xml_bytes(candidate)
        if raw is None:
            continue
        sub_props = _parse_directory_build_props(raw)
        if sub_props is None:
            record_parse_failure(candidate, "XML")
            continue
        # Recurse for nested imports inside the imported file.
        nested = _resolve_imports(
            candidate,
            raw,
            depth=depth + 1,
            visited=visited | {candidate},
        )
        # Nested-imported values flow in first; the imported file's own
        # values overwrite. The result then merges into ``accumulated``
        # — later-listed imports win over earlier ones in the same file
        # (matches MSBuild's evaluation order).
        accumulated.update({**nested, **sub_props})
    return accumulated


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
