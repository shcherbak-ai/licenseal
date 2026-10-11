"""Dependency discovery across ecosystems."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from licenseal.analysis.compatibility import is_recognised_project_license
from licenseal.analysis.spdx import normalize_license, normalize_r_license
from licenseal.discovery._walk import (
    scan_exclusions,
    shared_walk_cache,
    walk_project_files_matching,
)
from licenseal.discovery.dotnet import (
    closest_build_props,
    detect_project_license_csproj,
    discover_csproj_dependencies,
    discover_directory_build_dependencies,
    discover_packages_config_dependencies,
    discover_paket_dependencies,
    find_directory_build_props,
    find_directory_packages_props,
    lookup_version,
)
from licenseal.discovery.dotnet.csproj import _PROJECT_EXTENSIONS
from licenseal.discovery.dotnet.directory_packages_props import _PROPS_FILENAME
from licenseal.discovery.go.go_mod import discover_go_mod_dependencies
from licenseal.discovery.hex import (
    detect_project_license_mix_exs,
    discover_erlang_mk_dependencies,
    discover_mix_exs_dependencies,
    discover_rebar_config_dependencies,
    workspace_hex_names,
)
from licenseal.discovery.java import (
    detect_project_license_pom_xml,
    discover_build_gradle_dependencies,
    discover_pom_xml_dependencies,
)
from licenseal.discovery.npm.package_json import (
    detect_project_license_package_json,
    discover_npm_dependencies,
)
from licenseal.discovery.php import (
    detect_project_license_composer_json,
    discover_composer_dependencies,
)
from licenseal.discovery.python.pipfile import discover_pipfile_dependencies
from licenseal.discovery.python.pyproject import (
    detect_project_license_pyproject,
    discover_pyproject_dependencies,
)
from licenseal.discovery.python.requirements import discover_requirements_dependencies
from licenseal.discovery.python.setup_cfg import (
    detect_project_license_setup_cfg,
    discover_setup_cfg_dependencies,
)
from licenseal.discovery.python.setup_py import (
    detect_project_license_setup_py,
    discover_setup_py_dependencies,
)
from licenseal.discovery.r import (
    detect_project_license_description,
    discover_description_dependencies,
    workspace_r_names,
)
from licenseal.discovery.ruby import (
    detect_project_license_gemspec,
    discover_gemfile_dependencies,
    discover_gemspec_dependencies,
    workspace_gemspec_names,
)
from licenseal.discovery.rust.cargo_toml import (
    detect_project_license_cargo_toml,
    discover_cargo_toml_dependencies,
)
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# ``$(PropertyName)`` substitution token used by MSBuild — same regex as
# the csproj parser uses internally, duplicated here so the aggregator
# can stitch ``Directory.Build.props`` properties into versions after
# the csproj parser has emitted dep entries.
_MSBUILD_PROPERTY_RE = re.compile(r"\$\(([^)]+)\)")


@dataclass(frozen=True)
class ProjectLicense:
    """The license the scanned project's dependencies are judged against.

    ``license`` is the SPDX form of what a manifest in the scanned directory
    declares, and ``source`` that manifest's file name. When no such manifest
    declares a license the compatibility check recognises, ``license`` is
    ``"Proprietary"`` and ``source`` is empty.

    ``declared`` holds ``(manifest, value as declared)`` for the manifest that
    decides, followed by every other manifest in the scanned directory whose
    license differs from it. It is empty when nothing is declared, has more
    than one entry when manifests disagree, and has entries beside an empty
    ``source`` when the deciding value is not a recognised license.
    """

    license: str = "Proprietary"
    source: str = ""
    declared: tuple[tuple[str, str], ...] = ()


def _named(filename: str) -> Callable[[str], bool]:
    """Name test for a manifest that has one fixed file name."""
    return lambda name: name == filename


# The manifests that can declare the project's own license, in the order they
# are consulted: a test for the file name, the probe that reads the declared
# value from one such file, and what turns that value into SPDX. pyproject.toml
# comes first as the modern canonical source, and setup.py ahead of the other
# ecosystems so legacy Python projects still surface their license. Only R's
# license grammar needs a normalizer of its own.
#
# A .NET solution usually has no project file in its root: its projects live
# in subdirectories and take shared package properties, the license among
# them, from the root ``Directory.Build.props``, which MSBuild imports into
# each of them. That file is the same XML as a project file and is read by
# the same probe: the properties of its own ``<PropertyGroup>`` elements,
# whatever their ``Condition``, and nothing it imports. A project file in the
# scanned directory is consulted first, as its own property overrides the
# imported one.
_PROJECT_LICENSE_MANIFESTS: tuple[
    tuple[Callable[[str], bool], Callable[[Path], str], Callable[[str], str]], ...
] = (
    (_named("pyproject.toml"), detect_project_license_pyproject, normalize_license),
    (_named("setup.cfg"), detect_project_license_setup_cfg, normalize_license),
    (_named("setup.py"), detect_project_license_setup_py, normalize_license),
    (_named("package.json"), detect_project_license_package_json, normalize_license),
    (_named("Cargo.toml"), detect_project_license_cargo_toml, normalize_license),
    (_named("pom.xml"), detect_project_license_pom_xml, normalize_license),
    (
        lambda name: name.endswith(_PROJECT_EXTENSIONS),
        detect_project_license_csproj,
        normalize_license,
    ),
    (_named("Directory.Build.props"), detect_project_license_csproj, normalize_license),
    (_named("composer.json"), detect_project_license_composer_json, normalize_license),
    (lambda name: name.endswith(".gemspec"), detect_project_license_gemspec, normalize_license),
    (_named("mix.exs"), detect_project_license_mix_exs, normalize_license),
    (_named("DESCRIPTION"), detect_project_license_description, normalize_r_license),
)


def detect_project_license(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> ProjectLicense:
    """Detect the project's own license from the manifests in ``project_path`` itself.

    Only files directly in the scanned directory are read. A manifest further
    down belongs to a sub-package and its license is that package's: letting
    it decide would judge every dependency of the project against whichever
    nested package the walk reached first.

    The first manifest in ``_PROJECT_LICENSE_MANIFESTS`` order that declares a
    license decides. A value the compatibility check does not recognise is
    not used: the project is then judged as ``Proprietary``, the strictest
    row, like a project that declares nothing.
    """
    # The walk is the one dependency discovery shares, which is what
    # ``exclude_paths`` is for here: an excluded directory holds no file of
    # the scanned directory itself.
    with shared_walk_cache():
        root_files = [
            path
            for path in walk_project_files_matching(
                project_path, lambda _name: True, exclude_paths=exclude_paths
            )
            if path.parent == project_path
        ]
    declarations: list[tuple[str, str, str]] = []
    for is_manifest, probe, normalize in _PROJECT_LICENSE_MANIFESTS:
        for path in root_files:
            if is_manifest(path.name):
                declared = probe(path)
                if declared:
                    declarations.append((path.name, declared, normalize(declared)))
    if not declarations:
        return ProjectLicense()
    manifest, declared, spdx = declarations[0]
    reported = (
        (manifest, declared),
        *((name, value) for name, value, other in declarations[1:] if other != spdx),
    )
    if is_recognised_project_license(spdx):
        return ProjectLicense(license=spdx, source=manifest, declared=reported)
    return ProjectLicense(declared=reported)


def discover_all_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    lockfiles_read: bool = True,
) -> tuple[list[Dependency], dict[str, int]]:
    """Discover all dependencies in a project across ecosystems.

    Returns ``(deduped_deps, local_filter_counts)``. A package that several
    manifests declare with different version constraints is in
    ``deduped_deps`` once per constraint; two declarations with the same
    constraint are one entry that carries the extras of both and is PROD
    when either is. ``local_filter_counts``
    is keyed by ecosystem name (``"python"``, ``"npm"``, ``"rust"``, ``"go"``,
    ``"java"``) and holds the number of deps removed from each ecosystem
    because their name matched a workspace-local package. Ecosystems that
    filtered zero deps are still present with value ``0``. The Go filter
    covers both implicit monorepos (any in-tree ``go.mod``'s declared
    module) and explicit Go workspaces (``go.work`` ``use`` directives).
    The Java filter covers multi-module Maven projects (``<modules>`` +
    per-submodule ``pom.xml`` artifact coordinates); the Gradle side has
    no workspace-local filter (see :mod:`.java.build_gradle` docstring).

    ``lockfiles_read`` is false for a scan that will not read lockfiles (a
    direct-only scan). A manifest that needs its lockfile to say where a
    package comes from is then a gap even when that lockfile exists.

    Every per-ecosystem discover/workspace probe below walks the project tree;
    wrapping them in :func:`shared_walk_cache` collapses the ~25 walks into a
    single one, so scan time no longer grows linearly with ecosystem count.
    """
    with shared_walk_cache(), scan_exclusions(exclude_paths):
        return _discover_all_dependencies(
            project_path, exclude_paths=exclude_paths, lockfiles_read=lockfiles_read
        )


def _discover_all_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
    lockfiles_read: bool = True,
) -> tuple[list[Dependency], dict[str, int]]:
    deps: list[Dependency] = []

    # Python sources
    py_deps, py_filtered = discover_pyproject_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    deps.extend(py_deps)
    deps.extend(discover_requirements_dependencies(project_path, exclude_paths=exclude_paths))
    deps.extend(discover_setup_cfg_dependencies(project_path, exclude_paths=exclude_paths))
    deps.extend(discover_setup_py_dependencies(project_path, exclude_paths=exclude_paths))
    deps.extend(discover_pipfile_dependencies(project_path, exclude_paths=exclude_paths))

    # npm sources
    npm_deps, npm_filtered = discover_npm_dependencies(project_path, exclude_paths=exclude_paths)
    deps.extend(npm_deps)

    # Rust sources
    rust_deps, rust_filtered = discover_cargo_toml_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    deps.extend(rust_deps)

    # Go sources
    go_deps, go_filtered = discover_go_mod_dependencies(project_path, exclude_paths=exclude_paths)
    deps.extend(go_deps)

    # Java / JVM sources (Maven + Gradle). Gradle side has no workspace-local
    # filter, so ``java_filtered`` is just the Maven multi-module filter count.
    maven_deps, maven_filtered = discover_pom_xml_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    deps.extend(maven_deps)
    gradle_deps, _ = discover_build_gradle_dependencies(project_path, exclude_paths=exclude_paths)
    deps.extend(gradle_deps)

    # .NET sources (NuGet + Paket). The csproj parser emits deps with
    # potentially-empty versions (Central Package Management projects
    # declare ``<PackageReference Include="X" />`` without a Version
    # attribute) and potentially-literal ``$(Property)`` tokens (when a
    # property is supplied by an ancestor ``Directory.Build.props``). We
    # stitch both layers here so each parser stays self-contained. The
    # references a ``Directory.Build.props`` / ``.targets`` declares itself
    # go through the same stitching, after the project files' own.
    csproj_deps, csproj_filtered = discover_csproj_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    build_file_deps, build_file_filtered = discover_directory_build_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    cpm_files = find_directory_packages_props(project_path, exclude_paths=exclude_paths)
    build_props_files = find_directory_build_props(project_path, exclude_paths=exclude_paths)
    csproj_deps = _stitch_dotnet_versions(
        csproj_deps + build_file_deps,
        project_path=project_path,
        cpm_files=cpm_files,
        build_props_files=build_props_files,
    )
    deps.extend(csproj_deps)
    packages_config_deps, _ = discover_packages_config_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    deps.extend(packages_config_deps)
    paket_deps, _ = discover_paket_dependencies(project_path, exclude_paths=exclude_paths)
    deps.extend(paket_deps)

    # PHP / Composer sources
    php_deps, php_filtered = discover_composer_dependencies(
        project_path, exclude_paths=exclude_paths, lockfiles_read=lockfiles_read
    )
    deps.extend(php_deps)

    # Ruby / RubyGems sources. The gemspec layer publishes the workspace-
    # internal gem-name set (monorepo gemspecs reference each other); pass
    # it to the Gemfile parser so sibling references are filtered before
    # any registry lookup.
    ruby_workspace_names = workspace_gemspec_names(project_path, exclude_paths=exclude_paths)
    gemspec_deps, gemspec_filtered = discover_gemspec_dependencies(
        project_path,
        exclude_paths=exclude_paths,
        workspace_names=ruby_workspace_names,
    )
    deps.extend(gemspec_deps)
    gemfile_deps, gemfile_filtered = discover_gemfile_dependencies(
        project_path,
        exclude_paths=exclude_paths,
        workspace_names=ruby_workspace_names,
    )
    deps.extend(gemfile_deps)
    ruby_filtered = gemspec_filtered + gemfile_filtered

    # Hex sources (Elixir Mix + Erlang rebar3 + erlang.mk; one hex.pm registry).
    # Monorepo apps reference each other (Mix umbrella in_umbrella:/path:, or
    # erlang.mk monorepo sub-apps), so collect the in-tree app-name set —
    # mix.exs `app:` ∪ erlang.mk `PROJECT` — and filter sibling references
    # before any hex.pm lookup.
    hex_workspace_names = workspace_hex_names(project_path, exclude_paths=exclude_paths)
    mix_deps, mix_filtered = discover_mix_exs_dependencies(
        project_path,
        exclude_paths=exclude_paths,
        workspace_names=hex_workspace_names,
    )
    deps.extend(mix_deps)
    rebar_deps, rebar_filtered = discover_rebar_config_dependencies(
        project_path,
        exclude_paths=exclude_paths,
        workspace_names=hex_workspace_names,
    )
    deps.extend(rebar_deps)
    erlang_mk_deps, erlang_mk_filtered = discover_erlang_mk_dependencies(
        project_path,
        exclude_paths=exclude_paths,
        workspace_names=hex_workspace_names,
    )
    deps.extend(erlang_mk_deps)
    hex_filtered = mix_filtered + rebar_filtered + erlang_mk_filtered

    # R / CRAN sources (DESCRIPTION manifest; renv.lock / packrat.lock are
    # resolved in the transitive stage). Multi-package R repos reference sibling
    # packages by name, so collect the in-tree DESCRIPTION ``Package:`` set and
    # filter those before any CRAN lookup.
    r_workspace_names = workspace_r_names(project_path, exclude_paths=exclude_paths)
    r_deps, r_filtered = discover_description_dependencies(
        project_path,
        exclude_paths=exclude_paths,
        workspace_names=r_workspace_names,
    )
    deps.extend(r_deps)

    # Deduplicate, preserving discovery order. Two declarations are one
    # dependency when they name the same package (``identity``, the
    # ecosystem's own rule) with the same version constraint. Manifests that
    # ask for different versions of a package each keep their declaration, so
    # each version is resolved and reported under the manifest that asks for
    # it. A dependency declared from a git repository, a URL, or a path is
    # not the registry package of the same name and takes no version from a
    # registry: its origin is part of the key, and its constraint is not.
    index_by_key: dict[tuple[str, str, str, str], int] = {}
    unique: list[Dependency] = []
    for dep in deps:
        constraint = "" if dep.origin else dep.version_constraint.strip()
        key = (dep.ecosystem.value, dep.identity, constraint, dep.origin)
        existing_index = index_by_key.get(key)
        if existing_index is None:
            index_by_key[key] = len(unique)
            unique.append(dep)
            continue

        # The same requirement, declared twice. Every extra either
        # declaration asks for is needed. It ships when either declaration
        # does, and a production declaration is then the one reported.
        existing = unique[existing_index]
        kept = existing
        if existing.group == DependencyGroup.DEV and dep.group == DependencyGroup.PROD:
            kept = dep
        unique[existing_index] = replace(kept, extras=existing.extras | dep.extras)

    local_filter_counts = {
        "python": py_filtered,
        "npm": npm_filtered,
        "rust": rust_filtered,
        "go": go_filtered,
        "java": maven_filtered,
        "dotnet": csproj_filtered + build_file_filtered,
        "php": php_filtered,
        "ruby": ruby_filtered,
        "hex": hex_filtered,
        "r": r_filtered,
    }
    return unique, local_filter_counts


def _expand_with_scope(value: str, scope: dict[str, str]) -> str:
    """Expand ``$(Name)`` tokens in ``value`` against the property ``scope``."""

    def _replace(match: re.Match[str]) -> str:
        return scope.get(match.group(1).strip(), match.group(0))

    return _MSBUILD_PROPERTY_RE.sub(_replace, value)


def _stitch_dotnet_versions(
    deps: list[Dependency],
    *,
    project_path: Path,
    cpm_files: dict,
    build_props_files: dict,
) -> list[Dependency]:
    """Fill in versions for .NET deps that need cross-file resolution.

    Two passes:

    1. **Central Package Management (CPM) stitching.** Deps with an empty
       ``version_constraint`` come from ``<PackageReference Include="X" />``
       (no Version attribute). Walk to the closest-ancestor
       ``Directory.Packages.props`` and adopt its declared
       ``<PackageVersion>``.

    2. **MSBuild property expansion.** Deps whose ``version_constraint``
       still contains a literal ``$(PropertyName)`` token (because the
       csproj parser couldn't resolve it against its own ``<PropertyGroup>``)
       get a second resolution pass against the closest-ancestor
       ``Directory.Build.props`` chain. Properties from a closer ancestor
       override more-distant ones; unresolved tokens remain literal and
       the resolver routes the dep to UNKNOWN.

    ``deps`` holds the references of project files and of
    ``Directory.Build.props`` / ``.targets`` files; for the latter both
    lookups start at the ``Directory.Build`` file's own directory. Deps
    from the other .NET sources (``packages.config``,
    ``paket.dependencies``) are never passed in — they don't participate
    in CPM or Directory.Build.props inheritance.
    """
    if not cpm_files and not build_props_files:
        return deps

    out: list[Dependency] = []
    for dep in deps:
        # A project reference (it has an origin) is not a package: it takes
        # no version from either file.
        if dep.ecosystem != Ecosystem.DOTNET or not dep.source or dep.origin:
            out.append(dep)
            continue
        # Reconstruct the declaring file's absolute path from the dep's
        # source field (relative posix path).
        csproj_path = project_path / dep.source
        new_version = dep.version_constraint

        if not new_version and cpm_files:
            cpm_version = lookup_version(dep.name, csproj_path, cpm_files)
            if cpm_version:
                new_version = cpm_version

        if "$(" in new_version and build_props_files:
            scope = closest_build_props(csproj_path, build_props_files)
            if scope:
                new_version = _expand_with_scope(new_version, scope)

        if new_version == dep.version_constraint:
            out.append(dep)
        else:
            out.append(
                Dependency(
                    name=dep.name,
                    version_constraint=new_version,
                    ecosystem=dep.ecosystem,
                    group=dep.group,
                    source=dep.source,
                    depth=dep.depth,
                    direct_ancestors=dep.direct_ancestors,
                    extras=dep.extras,
                )
            )

    # 3. Materialize GlobalPackageReference entries. A Directory.Packages.props
    #    can declare packages applied implicitly to every project under its
    #    subtree — as if each carried an explicit
    #    <PackageReference PrivateAssets="all" /> — most commonly analyzers and
    #    source-link tooling. The csproj parser never sees them, so without this
    #    they'd be silently dropped and never license-checked. Emit one direct
    #    DEV row per (props file, package); the aggregator's dedupe collapses a
    #    package shared across props files, and an explicit PROD reference to the
    #    same package still wins over this DEV row.
    for props_dir, data in cpm_files.items():
        if not data.global_package_refs:
            continue
        # props_dir is always under project_path (find_directory_packages_props
        # walks within it), so relative_to can't raise.
        source = (props_dir / _PROPS_FILENAME).relative_to(project_path).as_posix()
        for name, version in data.global_package_refs.items():
            out.append(
                Dependency(
                    name=name,
                    version_constraint=version,
                    ecosystem=Ecosystem.DOTNET,
                    group=DependencyGroup.DEV,
                    source=source,
                    depth=0,
                    direct_ancestors=(),
                )
            )
    return out
