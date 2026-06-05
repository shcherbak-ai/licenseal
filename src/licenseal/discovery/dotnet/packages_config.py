"""Parse legacy ``packages.config`` files into direct ``Dependency`` entries.

``packages.config`` is the pre-NuGet-3 manifest format used by .NET
Framework projects (typically pre-2017). It is a separate XML file sitting
alongside the ``.csproj`` (one per project) rather than inline like the
modern ``<PackageReference>`` form. Shape:

.. code-block:: xml

    <?xml version="1.0" encoding="utf-8"?>
    <packages>
        <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
        <package id="NUnit" version="3.13.3" targetFramework="net48"
                 developmentDependency="true" />
    </packages>

Each ``<package>`` carries:

* ``id`` (required) — NuGet package ID. Case-insensitive per the NuGet
  spec; preserved as-authored for display but matched case-insensitively
  by the canonical-name pipeline.
* ``version`` (required) — concrete version (no ranges in this format).
* ``targetFramework`` (optional) — TFM the dep was installed for. Captured
  but not used at discovery time (transitive resolution handles TFM-union
  semantics elsewhere).
* ``developmentDependency`` (optional) — ``"true"`` marks the dep as a
  build-time/test-only dependency, mapped to ``DependencyGroup.DEV``.

Many real-world ``packages.config`` files coexist alongside an
``.csproj`` that ALSO carries ``<PackageReference>`` entries (during
migration from the legacy format to the modern SDK-style). The cross-
format dedup happens in the discovery aggregator, not here — this parser
emits every entry it sees and leaves dedup as the orchestrator's
responsibility.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element  # nosec B405

from defusedxml import ElementTree as DefusedET

from licenseal.discovery._read import read_xml_bytes, record_parse_failure
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem


def _parse_packages_config(raw: str | bytes) -> list[Dependency] | None:
    """Parse one ``packages.config`` XML into a list of :class:`Dependency`.

    Accepts raw bytes (preferred — the XML prolog / BOM picks the encoding)
    or already-decoded text. Returns ``None`` on malformed XML /
    billion-laughs-style entity expansion / XXE entity references. Returns an
    empty list on a valid file with no ``<package>`` entries.

    ``packages.config`` has no XML namespace and no parent-property
    inheritance, so this parser is much simpler than ``.csproj`` parsing.
    """
    try:
        root = DefusedET.fromstring(raw)
    except Exception:  # noqa: BLE001 - defusedxml raises many entity classes
        return None

    if root.tag != "packages":
        return []

    out: list[Dependency] = []
    for child in root:
        if child.tag != "package":
            continue
        dep = _dependency_from_package_element(child)
        if dep is not None:
            out.append(dep)
    return out


def _dependency_from_package_element(el: Element) -> Dependency | None:
    """Build a :class:`Dependency` from a single ``<package>`` element.

    Returns ``None`` when ``id`` is missing/blank — that's a malformed
    entry the resolver couldn't act on anyway.
    """
    package_id = (el.get("id") or "").strip()
    if not package_id:
        return None
    version = (el.get("version") or "").strip()
    dev_marker = (el.get("developmentDependency") or "").strip().lower()
    group = DependencyGroup.DEV if dev_marker == "true" else DependencyGroup.PROD
    return Dependency(
        name=package_id,
        version_constraint=version,
        ecosystem=Ecosystem.DOTNET,
        group=group,
        source="",  # set by the discovery wrapper below
    )


def discover_packages_config_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover ``packages.config`` dependencies under ``project_path``.

    Walks every ``packages.config`` file (subject to ``exclude_paths``),
    parses each, and emits one :class:`Dependency` per ``<package>``.
    Returns ``(deps, filtered_count)``. ``filtered_count`` is always 0
    here — ``packages.config`` has no workspace-local concept (each file
    belongs to its own project; cross-project NuGet references aren't
    expressible in this format).

    Files are read as raw bytes and parsed encoding-aware (the XML prolog /
    BOM picks the encoding), so the UTF-8 / UTF-16 BOMs that Visual Studio /
    NuGet tooling has historically written are handled rather than dropping
    the file.
    """
    out: list[Dependency] = []
    for cfg in walk_project_files(project_path, "packages.config", exclude_paths=exclude_paths):
        raw = read_xml_bytes(cfg)
        if raw is None:
            continue
        deps = _parse_packages_config(raw)
        if deps is None:
            record_parse_failure(cfg, "XML")
            continue
        if not deps:
            continue
        source = cfg.relative_to(project_path).as_posix()
        for dep in deps:
            out.append(
                Dependency(
                    name=dep.name,
                    version_constraint=dep.version_constraint,
                    ecosystem=dep.ecosystem,
                    group=dep.group,
                    source=source,
                )
            )
    return out, 0
