"""Parse Maven ``pom.xml`` files into direct ``Dependency`` entries.

A Maven project declares its direct dependencies in ``<dependencies>``
blocks of ``pom.xml``. The schema is XML with a stable namespace
(``http://maven.apache.org/POM/4.0.0``):

.. code-block:: xml

    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <groupId>com.example</groupId>
        <artifactId>myproject</artifactId>
        <version>1.0.0</version>
        <parent>
            <groupId>com.example</groupId>
            <artifactId>my-parent</artifactId>
            <version>1.0.0</version>
        </parent>
        <properties>
            <lib.version>1.2.3</lib.version>
        </properties>
        <modules>
            <module>core</module>
            <module>web</module>
        </modules>
        <dependencies>
            <dependency>
                <groupId>com.example.other</groupId>
                <artifactId>some-lib</artifactId>
                <version>${lib.version}</version>
                <scope>compile</scope>
            </dependency>
        </dependencies>
        <licenses>
            <license>
                <name>Apache License, Version 2.0</name>
                <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
            </license>
        </licenses>
    </project>

Maven's resolution model is the most complex of the ecosystems licenseal
covers — parent-POM inheritance, ``<dependencyManagement>`` version
centralization, BOM imports via ``<scope>import</scope>``, and ``${…}``
property expansion across the inheritance chain. licenseal intentionally
does NOT reimplement that resolution engine: discovery emits direct deps
with locally-expandable properties, and the transitive walker offloads
full resolution to ``deps.dev``'s ``:dependencies`` endpoint (which
mirrors the algorithm ``mvn`` itself uses).

XML parsing uses ``defusedxml.ElementTree`` to neutralize XML-bomb and
external-entity attack vectors — necessary because pom.xml in a scan
target is, by definition, untrusted input.

Scope-to-group mapping (per the Maven scope semantics):

* ``compile`` / ``runtime`` / empty (defaults to ``compile``) → PROD
* ``test`` / ``provided`` / ``system`` → DEV
* ``import`` → skipped entirely (a BOM-import marker, valid only inside
  ``<dependencyManagement>``; not a real dependency)

Multi-module workspaces are detected via the in-tree ``<modules>`` graph
plus each module's own ``<artifactId>`` + ``<groupId>`` (with the Maven
spec's fallback to the parent's ``<groupId>`` when the child omits it).
Workspace-local module coordinates are filtered before emission so a
sibling reference like ``com.example:core`` in another module's pom.xml
doesn't try to register-resolve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree as DefusedET

from licenseal.discovery._read import read_xml_bytes, record_parse_failure
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Maven POM XML lives in this namespace (stable since Maven 2).
_POM_NS = "http://maven.apache.org/POM/4.0.0"
_POM_NS_PREFIX = "{" + _POM_NS + "}"

# ``${name}`` substitution token. Captures the inner name. Matches Maven's
# real property syntax (single ``$`` followed by ``{…}``).
_PROPERTY_RE = re.compile(r"\$\{([^}]+)\}")

# Cap on recursive property-substitution passes. Maven's resolution is
# multi-pass (a property's value can itself reference another property —
# e.g., a BOM's ``${jackson.version.dataformat}`` expands to
# ``${jackson.version}`` which expands to ``"2.20.2"``). Single-pass
# would leave the intermediate literal behind and the version-extractor
# would route the dep to UNKNOWN. Cap is a safety net against circular
# references (``foo=${bar}; bar=${foo}``) — Maven itself caps similarly.
_MAX_PROPERTY_EXPANSION_PASSES = 5


@dataclass
class _PomDep:
    """One ``<dependency>`` entry extracted from a pom.xml.

    ``is_import`` flags BOM-import markers (``<type>pom</type>`` +
    ``<scope>import</scope>``). Per Maven semantics these belong inside
    ``<dependencyManagement>``; the parser sets the flag wherever the
    shape appears so the discovery loop filters them out regardless of
    block — they declare *managed versions for other deps*, not deps
    themselves.
    """

    group_id: str
    artifact_id: str
    version: str
    scope: str
    is_import: bool


@dataclass
class _PomData:
    """Structured pom.xml content used by the discovery + license paths."""

    group_id: str = ""
    artifact_id: str = ""
    version: str = ""
    parent_group_id: str = ""
    parent_artifact_id: str = ""
    parent_version: str = ""
    properties: dict[str, str] = field(default_factory=dict)
    dependencies: list[_PomDep] = field(default_factory=list)
    # ``<dependencyManagement><dependencies>`` entries — managed versions
    # plus BOM-import markers (``<scope>import</scope>`` + ``<type>pom</type>``,
    # surfaced with ``is_import=True``). The discovery layer uses non-import
    # entries to resolve versions for ``<dependencies>`` whose own ``<version>``
    # was omitted (the BOM-consumer pattern); the transitive walker uses
    # both shapes when walking the parent chain for managed versions.
    managed_dependencies: list[_PomDep] = field(default_factory=list)
    # ``(name, url)`` pairs from each ``<license>`` block. The URL is
    # almost always populated in real POMs (Maven publishing guidelines
    # require it) and is the most reliable SPDX-identification path
    # when the ``<name>`` is non-canonical ("non-standard", "see
    # LICENSE", legacy publisher prose). URLs like
    # ``http://www.apache.org/licenses/LICENSE-2.0`` are structured
    # references — not prose. ``deps.dev`` only surfaces the name,
    # which is why licenseal's direct Maven Central path can recover
    # licenses ``deps.dev`` cannot.
    licenses: list[tuple[str, str]] = field(default_factory=list)


def _strip_ns(tag: str) -> str:
    """Strip any ``{namespace}`` prefix from an ElementTree tag.

    ElementTree returns tags in ``{namespace}localname`` form when a
    default namespace is declared. POMs declare the Maven namespace —
    most commonly ``http://maven.apache.org/POM/4.0.0``, but Maven 4
    POMs use ``http://maven.apache.org/POM/4.1.0`` and some legacy
    fixtures (or hand-authored test poms) declare other or no
    namespaces. Strip any ``{…}`` prefix uniformly so downstream code
    can compare against ``"dependency"`` rather than the fully-
    qualified form.
    """
    if tag.startswith("{"):
        end = tag.find("}")
        if end >= 0:
            return tag[end + 1 :]
    return tag


def _findtext(element, child_name: str) -> str:
    """Return the text content of ``<element><child_name>...</child_name></element>``, or "".

    Tolerates both namespaced (``{ns}child_name``) and bare-name children.
    Matches the first child found; ignores duplicates.
    """
    for child in element:
        if _strip_ns(child.tag) == child_name:
            return (child.text or "").strip()
    return ""


def _findall(element, child_name: str) -> list:
    """Return all direct children of ``element`` with local name ``child_name``."""
    out: list = []
    for child in element:
        if _strip_ns(child.tag) == child_name:
            out.append(child)
    return out


def _parse_pom(raw: str | bytes) -> _PomData | None:
    """Parse pom.xml content into structured data.

    Accepts raw bytes (preferred — ``fromstring`` then honors the document's
    ``<?xml … encoding="…"?>`` prolog / BOM) or already-decoded text. Uses
    ``defusedxml`` to block XML bombs and external-entity attacks.

    Returns ``None`` when the bytes aren't parseable XML (truncated, non-XML, or
    a blocked entity-expansion attack) so the caller can record it as an
    analysis gap. A *valid* document that simply isn't a ``<project>`` returns
    an empty ``_PomData`` (no gap — it's well-formed, just not a POM).
    """
    try:
        root = DefusedET.fromstring(raw)
    except DefusedET.ParseError:
        return None
    except DefusedET.EntitiesForbidden:
        # Malicious POM with declared entities — refuse to parse but don't crash.
        return None

    if _strip_ns(root.tag) != "project":
        return _PomData()

    data = _PomData()
    data.group_id = _findtext(root, "groupId")
    data.artifact_id = _findtext(root, "artifactId")
    data.version = _findtext(root, "version")

    for parent_el in _findall(root, "parent"):
        data.parent_group_id = _findtext(parent_el, "groupId")
        data.parent_artifact_id = _findtext(parent_el, "artifactId")
        data.parent_version = _findtext(parent_el, "version")
        break  # POMs have at most one <parent>

    # Per Maven spec: when a child POM omits <groupId> or <version>, those
    # are inherited from <parent>. Fill the gap so consumers see complete
    # coordinates without doing the inheritance walk themselves.
    if not data.group_id and data.parent_group_id:
        data.group_id = data.parent_group_id
    if not data.version and data.parent_version:
        data.version = data.parent_version

    for props_el in _findall(root, "properties"):
        for prop_el in props_el:
            # Every XML element has a non-empty tag, so ``_strip_ns`` always
            # returns a non-empty property name here.
            data.properties[_strip_ns(prop_el.tag)] = (prop_el.text or "").strip()
        break

    for licenses_el in _findall(root, "licenses"):
        for license_el in _findall(licenses_el, "license"):
            name = _findtext(license_el, "name")
            url = _findtext(license_el, "url")
            if name or url:
                data.licenses.append((name, url))
        break

    for deps_el in _findall(root, "dependencies"):
        for dep_el in _findall(deps_el, "dependency"):
            group_id = _findtext(dep_el, "groupId")
            artifact_id = _findtext(dep_el, "artifactId")
            version = _findtext(dep_el, "version")
            scope = _findtext(dep_el, "scope")
            dep_type = _findtext(dep_el, "type")
            is_import = scope == "import" and dep_type == "pom"
            if group_id and artifact_id:
                data.dependencies.append(
                    _PomDep(
                        group_id=group_id,
                        artifact_id=artifact_id,
                        version=version,
                        scope=scope,
                        is_import=is_import,
                    )
                )
        break

    # ``<dependencyManagement><dependencies>`` — managed versions and BOM
    # markers. Same parsing shape as ``<dependencies>``; the discovery
    # layer uses this block to fill in versions for ``<dependencies>``
    # entries whose own ``<version>`` was omitted (a child POM with both
    # blocks declares the dep twice — once with version in DM, once
    # without in ``<dependencies>``). We collect from BOTH the top-level
    # ``<dependencyManagement>`` and from every ``<profiles><profile>``
    # — for license-scanning the profile-activation conditions
    # (JDK version, OS, system property) are irrelevant; any managed
    # version we can find resolves a coord that would otherwise UNKNOWN.
    _collect_managed_dependencies(root, data)

    for profiles_el in _findall(root, "profiles"):
        for profile_el in _findall(profiles_el, "profile"):
            _collect_managed_dependencies(profile_el, data)
        break

    return data


def _collect_managed_dependencies(parent_el, data: _PomData) -> None:
    """Append every ``<dependencyManagement><dependencies><dependency>``
    entry under ``parent_el`` to ``data.managed_dependencies``.

    ``parent_el`` is either the ``<project>`` root (top-level DM) or a
    ``<profile>`` element (profile-conditional DM). Same parsing shape
    in both contexts; we coalesce the lot so the resolver's DM lookup
    has one flat list to search.
    """
    for dm_el in _findall(parent_el, "dependencyManagement"):
        for deps_el in _findall(dm_el, "dependencies"):
            for dep_el in _findall(deps_el, "dependency"):
                group_id = _findtext(dep_el, "groupId")
                artifact_id = _findtext(dep_el, "artifactId")
                version = _findtext(dep_el, "version")
                scope = _findtext(dep_el, "scope")
                dep_type = _findtext(dep_el, "type")
                is_import = scope == "import" and dep_type == "pom"
                if group_id and artifact_id:
                    data.managed_dependencies.append(
                        _PomDep(
                            group_id=group_id,
                            artifact_id=artifact_id,
                            version=version,
                            scope=scope,
                            is_import=is_import,
                        )
                    )
            break
        break


def _project_properties(
    pom: _PomData,
    inherited_props: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the set of resolvable ``${…}`` substitution values.

    Resolves the four standard ``project.*`` variables Maven exposes by
    default, plus every entry under ``<properties>``, plus any properties
    inherited from ancestor POMs via the optional ``inherited_props``
    argument.

    Maven's actual semantics: closer-to-the-reference wins on conflicts.
    Implementation: ``inherited_props`` carries properties contributed by
    descendant POMs already processed (when the caller is walking up the
    parent chain), so the merge order is ``pom.properties`` first, then
    ``inherited_props`` overrides. When ``inherited_props`` is ``None``
    the result is identical to the pre-inheritance behavior (used by
    discovery, which doesn't have access to a parent chain).

    Two-pass expansion: ``pom.version`` itself may use Maven's
    CI-friendly ``${revision}`` pattern (declared in ``<properties>``
    rather than baked into ``<version>``); ``${revision}`` is often
    defined in a parent POM rather than locally. Without two-pass
    expansion against the merged property set, ``project.version`` would
    surface as the literal ``${revision}`` and any DM entry referencing
    ``${project.version}`` (the common BOM-import shape) would fail to
    resolve.
    """
    base_props: dict[str, str] = dict(pom.properties)
    if inherited_props:
        # Local POM properties win on conflict — only fill gaps with
        # inherited values.
        for k, v in inherited_props.items():
            base_props.setdefault(k, v)
    expanded_version = _expand_properties(pom.version, base_props)
    expanded_parent_version = _expand_properties(pom.parent_version, base_props)
    props: dict[str, str] = {
        "project.groupId": pom.group_id,
        "project.artifactId": pom.artifact_id,
        "project.version": expanded_version,
        "project.parent.version": expanded_parent_version,
    }
    # User-defined properties (local + inherited, local-wins) override
    # project.* defaults if they happen to share a name. Maven itself
    # behaves this way.
    props.update(base_props)
    return props


def _expand_properties(value: str, props: dict[str, str]) -> str:
    """Expand ``${name}`` tokens against ``props``, recursively up to
    :data:`_MAX_PROPERTY_EXPANSION_PASSES` passes.

    Multi-pass handles nested references — a property whose value is
    itself another ``${…}`` reference (e.g., a BOM's DM entry version
    ``${jackson.version.dataformat}`` whose property body is
    ``${jackson.version}`` whose body is the literal ``"2.20.2"``).
    Single-pass would leave the intermediate literal in place and the
    version-extractor would route the dep to UNKNOWN.

    Unresolved tokens (referencing a property not in ``props`` —
    typically one defined in an external parent POM) are left literal.
    The downstream version-extractor rejects literal ``${…}`` tokens and
    emits UNKNOWN, which is the correct posture: licenseal can't know
    which version the full Maven resolver would pick without the parent
    chain.

    Termination: stops early when a pass produces no change (fixed point)
    or after the cap (catches circular references like ``foo=${bar};
    bar=${foo}``).
    """
    if not value or "${" not in value:
        return value

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in props:
            return props[name]
        return match.group(0)

    for _ in range(_MAX_PROPERTY_EXPANSION_PASSES):
        previous = value
        value = _PROPERTY_RE.sub(_sub, value)
        if value == previous or "${" not in value:
            break
    return value


def _scope_to_group(scope: str) -> DependencyGroup:
    """Map a Maven dependency scope to ``DependencyGroup``.

    Per the Maven Dependency Mechanism docs:

    * ``compile`` (default when ``<scope>`` is omitted) — shipped, transitive: PROD
    * ``runtime`` — shipped at runtime, transitive: PROD
    * ``test`` — test-only, non-transitive: DEV
    * ``provided`` — compile-time only (Servlet API, JDK modules, …), non-
      transitive at runtime: DEV (the consumer ships their own provider)
    * ``system`` — deprecated, local-filesystem JAR: DEV (compile-time only,
      same posture as ``provided``)
    * ``import`` — BOM marker, only valid in ``<dependencyManagement>`` —
      handled separately (skipped from emission entirely)
    """
    if scope in ("test", "provided", "system"):
        return DependencyGroup.DEV
    return DependencyGroup.PROD


def _discover_workspace_local_artifacts(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> set[str]:
    """Collect ``{groupId}:{artifactId}`` coordinates of workspace-local artifacts.

    Multi-module Maven projects link parent → submodule via ``<modules>``
    blocks; each submodule has its own ``pom.xml``. Sibling references
    (e.g. ``com.example:server`` declared by ``server/pom.xml`` and required
    by ``client/pom.xml``) would 404 on Maven Central / deps.dev because
    those artifacts aren't published publicly. Filter them out before
    registry resolution — same posture as the Go workspace-local module-path
    filter (:func:`licenseal.discovery.go.go_mod._discover_workspace_local_module_paths`).

    Per the Maven spec, a child POM that omits ``<groupId>`` inherits its
    ``<parent><groupId>``. The ``_parse_pom`` helper applies that fallback,
    so the coordinates we collect here are always complete.
    """
    return set(_discover_workspace_local_pom_paths(project_path, exclude_paths=exclude_paths))


def _is_test_fixture_pom(pom_path: Path) -> bool:
    """True if ``pom_path`` lives under a Maven test/IT fixtures directory.

    Maven convention: ``src/test/`` for unit-test fixtures, ``src/it/``
    for integration-test fixtures. POMs under these paths are test data
    — frequently declaring fake or intentionally-colliding coordinates
    (some projects ship fixtures whose ``<artifactId>`` collides with
    the real reactor root). They must be excluded from the workspace-
    local parent-chain index, otherwise the walker can land on a fixture
    instead of the real reactor sibling and the DM search returns empty.
    """
    parts = pom_path.parts
    return any(parts[i] == "src" and parts[i + 1] in ("test", "it") for i in range(len(parts) - 1))


def _discover_workspace_local_pom_paths(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> dict[str, Path]:
    """Return a ``{groupId:artifactId → pom.xml-path}`` map for in-tree poms.

    Reactor multi-module projects routinely reference *other in-tree
    poms* as ``<parent>`` (submodule's parent = the reactor root, which
    is itself a workspace-local artifact). The parent-chain
    ``<dependencyManagement>`` walk must consult those local poms
    directly rather than try to fetch them from Maven Central, where
    they are not (yet) published — that's the typical reason a real
    multi-module scan generated dozens of UNKNOWNs before this fix.

    Same key set as :func:`_discover_workspace_local_artifacts`, plus
    the on-disk path so the walker can read each parent. POMs under
    ``src/test/`` or ``src/it/`` are filtered out — see
    :func:`_is_test_fixture_pom` for the rationale.
    """
    out: dict[str, Path] = {}
    for pom_path in walk_project_files(project_path, "pom.xml", exclude_paths=exclude_paths):
        if _is_test_fixture_pom(pom_path):
            continue
        data = read_xml_bytes(pom_path)
        if data is None:
            continue
        pom = _parse_pom(data)
        if pom is None:
            record_parse_failure(pom_path, "XML")
            continue
        if pom.group_id and pom.artifact_id:
            out[f"{pom.group_id}:{pom.artifact_id}"] = pom_path
    return out


def discover_pom_xml_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct Maven dependencies from every ``pom.xml`` in the tree.

    Returns ``(deps, filtered_count)``. ``deps`` is a flat list with one
    ``Dependency`` per ``<dependency>`` after applying:

    * Property expansion (local ``${…}`` tokens — see :func:`_expand_properties`)
    * Scope-to-group mapping (``compile``/``runtime`` → PROD; ``test`` / ``provided``
      / ``system`` → DEV)
    * BOM-import filter (``<scope>import</scope>`` + ``<type>pom</type>`` skipped)
    * Workspace-local filter (sibling-artifact coordinates dropped, count
      surfaced in ``filtered_count``)

    Coordinate format on ``Dependency.name`` is ``"groupId:artifactId"``
    (Maven canonical, colon-joined). Matches the ``api.deps.dev`` ``name``
    field exactly so no translation layer is needed in the resolver.
    """
    workspace_local = _discover_workspace_local_artifacts(project_path, exclude_paths=exclude_paths)

    out: list[Dependency] = []
    filtered = 0
    for pom_path in walk_project_files(project_path, "pom.xml", exclude_paths=exclude_paths):
        data = read_xml_bytes(pom_path)
        if data is None:
            continue
        pom = _parse_pom(data)
        if pom is None:
            record_parse_failure(pom_path, "XML")
            continue
        props = _project_properties(pom)
        source = pom_path.relative_to(project_path).as_posix()

        # Local <dependencyManagement> index, keyed by group:artifact.
        # When a <dependencies> entry omits <version>, Maven looks here
        # first (then walks the parent chain — the network walk is in the
        # transitive walker, this is the local cheap lookup). Cached per
        # POM since walking the managed list per dep would be O(n²).
        # ``setdefault``: first hit wins so the top-level DM block
        # (always active in Maven) takes precedence over profile-DM
        # entries for the same coord (which may or may not be active
        # depending on build-time conditions). Profile DM only fills
        # coords the top-level DM doesn't mention.
        local_dm: dict[str, str] = {}
        for managed in pom.managed_dependencies:
            if managed.is_import:
                continue
            mg = _expand_properties(managed.group_id, props)
            ma = _expand_properties(managed.artifact_id, props)
            mv = _expand_properties(managed.version, props)
            if mg and ma and mv and "${" not in mv:
                local_dm.setdefault(f"{mg}:{ma}", mv)

        for dep in pom.dependencies:
            if dep.is_import:
                # BOM marker — let the transitive walker handle the BOM's
                # managed versions; nothing to emit here.
                continue
            group_id = _expand_properties(dep.group_id, props)
            artifact_id = _expand_properties(dep.artifact_id, props)
            version = _expand_properties(dep.version, props)
            coord = f"{group_id}:{artifact_id}"
            # Local <dependencyManagement> fill-in: if the <dependency>
            # omitted <version>, look up the managed version in this
            # POM's own DM block. This is the in-file BOM-consumer
            # pattern (a reactor module that declares both <dependencies>
            # and <dependencyManagement>). Parent-POM DM resolution
            # happens at the transitive-walker layer.
            if not version and coord in local_dm:
                version = local_dm[coord]
            if coord in workspace_local:
                filtered += 1
                continue
            out.append(
                Dependency(
                    name=coord,
                    version_constraint=version,
                    ecosystem=Ecosystem.JAVA,
                    group=_scope_to_group(dep.scope),
                    source=source,
                )
            )
    return out, filtered


def detect_project_license_pom_xml(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Return the project's own license name from the root ``pom.xml``.

    Reads the shallowest ``pom.xml`` (the project root) and returns the
    first declared ``<licenses><license><name>…</name></license>``. Multi-
    license POMs join names with " AND " (conservative — all licenses
    apply simultaneously, matching the SPDX-expression ``AND`` semantics
    used elsewhere in licenseal).

    Returns "" if no pom.xml is found or no ``<licenses>`` block is
    declared. Caller (``discover.__init__.detect_project_license``) falls
    back to the next ecosystem's detector or to "Proprietary".
    """
    root_pom = project_path / "pom.xml"
    if not root_pom.is_file():
        # Fall back to shallowest pom.xml found by the walker (handles
        # repos whose Maven module isn't at the repo root).
        candidates = sorted(
            walk_project_files(project_path, "pom.xml", exclude_paths=exclude_paths),
            key=lambda p: len(p.parts),
        )
        if not candidates:
            return ""
        root_pom = candidates[0]

    data = read_xml_bytes(root_pom)
    if data is None:
        return ""
    pom = _parse_pom(data)
    if pom is None:
        record_parse_failure(root_pom, "XML")
        return ""
    if not pom.licenses:
        return ""
    # Use the name when populated; fall back to the URL otherwise (some
    # POMs omit the name and rely on the URL alone, esp. for SPDX-style
    # identifiers like ``https://spdx.org/licenses/MIT``).
    names = [name or url for name, url in pom.licenses]
    if len(names) == 1:
        return names[0]
    return " AND ".join(names)
