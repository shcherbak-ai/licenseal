"""Dependency discovery across ecosystems."""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._walk import shared_walk_cache
from licenseal.discovery.dotnet import (
    closest_build_props,
    detect_project_license_csproj,
    discover_csproj_dependencies,
    discover_packages_config_dependencies,
    discover_paket_dependencies,
    find_directory_build_props,
    find_directory_packages_props,
    lookup_version,
)
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


def detect_project_license(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    """Detect the project's own license from available sources.

    The per-source ``detect_*`` probes below each walk the project tree for
    their manifest; wrapping them in :func:`shared_walk_cache` collapses those
    into a single walk.
    """
    with shared_walk_cache():
        return _detect_project_license(project_path, exclude_paths=exclude_paths)


def _detect_project_license(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> str:
    # Resolution order: pyproject.toml (PEP 621) → setup.cfg → setup.py
    # → package.json → Cargo.toml. pyproject takes priority because it's the
    # modern canonical source; setup.py runs ahead of npm/cargo so legacy
    # Python projects still surface their license.
    license_str = detect_project_license_pyproject(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_setup_cfg(project_path)
    if not license_str:
        license_str = detect_project_license_setup_py(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_package_json(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_cargo_toml(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_pom_xml(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_csproj(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_composer_json(
            project_path, exclude_paths=exclude_paths
        )
    if not license_str:
        license_str = detect_project_license_gemspec(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_mix_exs(project_path, exclude_paths=exclude_paths)
    if not license_str:
        license_str = detect_project_license_description(project_path, exclude_paths=exclude_paths)
    return license_str


def discover_all_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], dict[str, int]]:
    """Discover all dependencies in a project across ecosystems.

    Returns ``(deduped_deps, local_filter_counts)``. ``local_filter_counts``
    is keyed by ecosystem name (``"python"``, ``"npm"``, ``"rust"``, ``"go"``,
    ``"java"``) and holds the number of deps removed from each ecosystem
    because their name matched a workspace-local package. Ecosystems that
    filtered zero deps are still present with value ``0``. The Go filter
    covers both implicit monorepos (any in-tree ``go.mod``'s declared
    module) and explicit Go workspaces (``go.work`` ``use`` directives).
    The Java filter covers multi-module Maven projects (``<modules>`` +
    per-submodule ``pom.xml`` artifact coordinates); the Gradle side has
    no workspace-local filter (see :mod:`.java.build_gradle` docstring).

    Every per-ecosystem discover/workspace probe below walks the project tree;
    wrapping them in :func:`shared_walk_cache` collapses the ~25 walks into a
    single one, so scan time no longer grows linearly with ecosystem count.
    """
    with shared_walk_cache():
        return _discover_all_dependencies(project_path, exclude_paths=exclude_paths)


def _discover_all_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], dict[str, int]]:
    deps: list[Dependency] = []

    # Python sources
    py_deps, py_filtered = discover_pyproject_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    deps.extend(py_deps)
    deps.extend(discover_requirements_dependencies(project_path, exclude_paths=exclude_paths))
    deps.extend(discover_setup_cfg_dependencies(project_path))
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
    # stitch both layers here so each parser stays self-contained.
    csproj_deps, csproj_filtered = discover_csproj_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    cpm_files = find_directory_packages_props(project_path, exclude_paths=exclude_paths)
    build_props_files = find_directory_build_props(project_path, exclude_paths=exclude_paths)
    csproj_deps = _stitch_dotnet_versions(
        csproj_deps,
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
        project_path, exclude_paths=exclude_paths
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

    # Deduplicate: preserve discovery order, but prefer prod over dev for the same package.
    index_by_key: dict[tuple[str, str], int] = {}
    unique: list[Dependency] = []
    for dep in deps:
        key = (dep.name.lower(), dep.ecosystem.value)
        existing_index = index_by_key.get(key)
        if existing_index is None:
            index_by_key[key] = len(unique)
            unique.append(dep)
            continue

        existing = unique[existing_index]
        if existing.group == DependencyGroup.DEV and dep.group == DependencyGroup.PROD:
            unique[existing_index] = dep

    local_filter_counts = {
        "python": py_filtered,
        "npm": npm_filtered,
        "rust": rust_filtered,
        "go": go_filtered,
        "java": maven_filtered,
        "dotnet": csproj_filtered,
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

    Deps from non-csproj .NET sources (``packages.config``,
    ``paket.dependencies``) are untouched — they don't participate in
    CPM or Directory.Build.props inheritance.
    """
    if not cpm_files and not build_props_files:
        return deps

    out: list[Dependency] = []
    for dep in deps:
        if dep.ecosystem != Ecosystem.DOTNET or not dep.source:
            out.append(dep)
            continue
        # Reconstruct the absolute csproj path from the dep's source
        # field (relative posix path).
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
