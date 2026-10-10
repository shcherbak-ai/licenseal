"""Transitive dependency resolution.

Strategy: lockfile-first, with recursive registry walk as fallback. When a
lockfile is present (`uv.lock`, `poetry.lock`, `Pipfile.lock`,
`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`), we parse it directly —
that's the actually-shipped graph. Without a lockfile, we BFS from the
manifest's direct deps via the registry's per-version dependency metadata.

Notes on registry-recursion fallback:

- The result is an estimate of the graph the project installs. Every row the
  fallback adds, and every direct dep whose manifest constraint is not an
  exact pin, is marked ``version_estimated``; each manifest that declares a
  direct dep resolved this way is recorded as lacking a lockfile (see
  :func:`_record_missing_lockfiles`).

- Multiple versions of the same package coexist in the output when paths
  resolve to different concrete versions (e.g. ``lodash@^4`` and ``lodash@^3``
  in different sub-trees both surface in the report). Each version is
  license-resolved independently — important because the same package can
  ship under different licenses across majors.
- Python env markers are ignored (treated as always-true) by design — a
  Windows-only or Python-3.13-only dep still ships in the source distribution,
  so its license obligations still apply.
- npm ``peerDependencies`` and ``optionalDependencies`` are followed; only
  ``devDependencies`` are gated by ``--dev``.
"""

from __future__ import annotations

import contextvars
import re
from collections.abc import Callable, Container, Iterable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import click
import httpx

from licenseal._concurrency import map_with_context
from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import (
    decode_text,
    read_xml_bytes,
    record_missing_lockfile,
    record_parse_failure,
    record_unlisted_dependencies,
    record_unread_dependencies,
)
from licenseal.discovery._walk import walk_project_files, with_scan_exclusions
from licenseal.discovery.dotnet import (
    find_nuget_lockfiles,
    find_paket_lockfiles,
    parse_nuget_lockfile,
    parse_paket_lock,
)
from licenseal.discovery.dotnet.csproj import (
    _discover_workspace_local_project_ids,
)
from licenseal.discovery.go.go_mod import (
    _discover_workspace_local_module_paths,  # noqa: PLC2701
    _parse_go_mod,  # noqa: PLC2701
    apply_replaces,
    lists_all_requirements,
)
from licenseal.discovery.go.lockfile import find_go_lockfiles, parse_go_sum_entries
from licenseal.discovery.hex.erlang_mk import workspace_hex_names
from licenseal.discovery.hex.mix_exs import (
    collect_dev_direct_names as _collect_hex_dev_direct_names,
)
from licenseal.discovery.hex.mix_lock import (
    attach_direct_sources as _attach_hex_direct_sources,
)
from licenseal.discovery.hex.mix_lock import (
    find_mix_lockfiles,
    parse_mix_lock,
)
from licenseal.discovery.hex.rebar_lock import find_rebar_lockfiles, parse_rebar_lock
from licenseal.discovery.java.gradle_lockfile import (
    find_gradle_lockfiles,
    parse_gradle_lockfile,
)
from licenseal.discovery.java.pom_xml import (
    _discover_workspace_local_pom_paths,  # noqa: PLC2701
    _expand_properties,  # noqa: PLC2701
    _parse_pom,  # noqa: PLC2701
    _PomData,  # noqa: PLC2701
    _project_properties,  # noqa: PLC2701
)
from licenseal.discovery.npm.lockfiles import find_npm_lockfiles, parse_npm_lockfile
from licenseal.discovery.php.lockfiles import (
    find_composer_lockfiles,
    parse_composer_lockfile,
)
from licenseal.discovery.python.lockfiles import (
    find_python_lockfiles,
    parse_python_lockfile,
)
from licenseal.discovery.r._lock import (
    attach_direct_sources as _attach_r_direct_sources,
)
from licenseal.discovery.r._lock import build_lock_dependencies
from licenseal.discovery.r.description import (
    collect_dev_direct_names as _collect_r_dev_direct_names,
)
from licenseal.discovery.r.description import workspace_r_names
from licenseal.discovery.r.packrat import find_packrat_lockfiles, parse_packrat_lock
from licenseal.discovery.r.renv_lock import find_renv_lockfiles, parse_renv_lock
from licenseal.discovery.ruby.gemfile import collect_dev_direct_names
from licenseal.discovery.ruby.gemspec import workspace_gemspec_names
from licenseal.discovery.ruby.lockfiles import (
    attach_direct_sources as _attach_ruby_direct_sources,
)
from licenseal.discovery.ruby.lockfiles import (
    find_gemfile_lockfiles,
    parse_gemfile_lock,
)
from licenseal.discovery.rust.cargo_toml import cargo_sources
from licenseal.discovery.rust.lockfiles import find_rust_lockfiles, parse_cargo_lock
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.cran import CranIndex, fetch_cran_index, index_edge_names
from licenseal.resolvers.cran import (
    _extract_pinned_version as _extract_r_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.crates_io import (
    _extract_pinned_version as _extract_rust_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.crates_io import (
    fetch_rust_dependencies,
)
from licenseal.resolvers.deps_dev import (
    fetch_maven_dependencies,
)
from licenseal.resolvers.hex import (
    _extract_pinned_version as _extract_hex_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.hex import (
    _hex_package_url,  # noqa: PLC2701
    _latest_version,  # noqa: PLC2701
    fetch_hex_dependencies,
)
from licenseal.resolvers.http import (
    Fetcher,
    encode_module_proxy_path,
    fetch_go_mod_text,
    fetch_registry_json,
    fetch_registry_text,
    object_field,
)
from licenseal.resolvers.maven_central import (
    _MAX_PARENT_DEPTH,  # noqa: PLC2701
    _extract_pinned_version_maven,  # noqa: PLC2701
    _fetch_pom,  # noqa: PLC2701
)
from licenseal.resolvers.npm_registry import (
    _extract_pinned_version as _extract_npm_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.npm_registry import (
    fetch_npm_dependencies,
)
from licenseal.resolvers.nuget import (
    _declares_exact_version_nuget,
    _extract_pinned_version_nuget,
    fetch_nuget_dependencies,
)
from licenseal.resolvers.packagist import (
    _extract_pinned_version as _extract_php_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.packagist import (
    _packagist_url,  # noqa: PLC2701
    _versions_from_response,  # noqa: PLC2701
    fetch_packagist_dependencies,
)
from licenseal.resolvers.pypi import (
    _extract_pinned_version as _extract_python_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.pypi import (
    fetch_python_dependencies,
)
from licenseal.resolvers.rubygems import (
    _extract_pinned_version as _extract_ruby_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.rubygems import (
    _rubygems_gem_url,  # noqa: PLC2701
    fetch_rubygems_dependencies,
)
from licenseal.resolvers.version_selection import (
    resolve_npm_spec,
    select_php_version,
    select_python_version,
)

# What tells an exact version from a range, per ecosystem: each returns
# something truthy for a lockfile entry (``==X.Y.Z``) and for the ecosystem's
# exact-pin form in a manifest. Go is absent: ``go.mod`` and ``go.sum`` name
# exact versions only.
_EXACT_VERSION_CHECKS: dict[Ecosystem, Callable[[str], str | bool | None]] = {
    Ecosystem.PYTHON: _extract_python_pinned_version,
    Ecosystem.NPM: _extract_npm_pinned_version,
    Ecosystem.RUST: _extract_rust_pinned_version,
    Ecosystem.JAVA: _extract_pinned_version_maven,
    Ecosystem.DOTNET: _declares_exact_version_nuget,
    Ecosystem.PHP: _extract_php_pinned_version,
    Ecosystem.RUBY: _extract_ruby_pinned_version,
    Ecosystem.HEX: _extract_hex_pinned_version,
    Ecosystem.R: _extract_r_pinned_version,
}


def declares_exact_version(dep: Dependency) -> bool:
    """Whether ``dep``'s constraint fixes the version reported for it.

    True for a lockfile entry and for an exact pin in a manifest. False for a
    range and for no constraint at all: the version then reported is the one
    licenseal picks from what the registry publishes.
    """
    check = _EXACT_VERSION_CHECKS.get(dep.ecosystem)
    return check is None or bool(check(dep.version_constraint))


def flag_version_estimate(dep: Dependency) -> Dependency:
    """Return ``dep`` marked ``version_estimated`` unless its constraint is exact.

    A dep with an origin is returned as it is: no registry is asked about it,
    so no version is picked for it.
    """
    if dep.origin or declares_exact_version(dep):
        return dep
    return replace(dep, version_estimated=True)


# Manifests of tools that have no lockfile format licenseal reads. A project
# that uses one cannot supply a lockfile, so none is asked of it.
_MANIFESTS_WITHOUT_LOCKFILE_FORMAT = frozenset({"pom.xml", "packages.config", "Makefile"})


def _record_missing_lockfiles(project_path: Path, deps: list[Dependency]) -> None:
    """Record each manifest that declares one of ``deps`` as lacking a lockfile.

    ``deps`` are the direct deps resolved through the registry because no
    lockfile covers them. A manifest is recorded once, however many of them
    it declares. Nothing is recorded for a dep with an origin (it is not
    resolved through the registry, and a lockfile would not change its row),
    for a dep without a manifest path, or for a manifest of a tool with no
    lockfile format: Maven ``pom.xml``, NuGet ``packages.config``, an
    erlang.mk ``Makefile``.
    """
    for source in sorted({d.source for d in deps if not d.origin}):
        manifest = _manifest_path(project_path, source)
        if manifest is not None and manifest.name not in _MANIFESTS_WITHOUT_LOCKFILE_FORMAT:
            record_missing_lockfile(manifest)


def _manifest_path(project_path: Path, source: str) -> Path | None:
    """The manifest a direct dep's ``source`` names, or None for a dep built without one."""
    return project_path / source if source else None


def _record_unread_dependencies(
    project_path: Path, source: str, packages: Iterable[tuple[str, str]]
) -> None:
    """Record, on the manifest at ``source``, each package whose dependencies were not read.

    ``packages`` are the ``(name, version)`` pairs a registry walk reached
    from a direct dep that manifest declares and could not expand. Each is a
    gap on the manifest, once however many of its direct deps reach it.
    """
    manifest = _manifest_path(project_path, source)
    if manifest is None:
        return
    for name, version in sorted(set(packages)):
        record_unread_dependencies(manifest, name, version)


@with_scan_exclusions
def resolve_transitive(
    direct_deps: list[Dependency],
    project_path: Path,
    *,
    include_dev: bool,
    max_depth: int,
    client: httpx.Client,
    max_workers: int = 16,
    fetcher: Fetcher = fetch_registry_json,
    pom_fetcher: Fetcher = fetch_registry_text,
    on_wave: Callable[[int], None] | None = None,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Dependency]:
    """Return direct + transitive deps, deduplicated by (ecosystem, name, version).

    `direct_deps` should contain ALL direct deps the project declares (both
    prod and dev), regardless of `include_dev`. The lockfile path needs both
    sets to attribute group by reachability and to drop dev-only chains when
    `include_dev=False`. The registry-walk fallback respects `include_dev` by
    seeding only the matching deps.

    Lockfile-first per ecosystem. When the lockfile is missing for an
    ecosystem, fall back to recursive registry resolution. A lockfile is
    read whether or not `direct_deps` has an entry for its ecosystem; when
    none of its packages is a direct dep, they are kept as PROD with no
    ancestors rather than dropped.

    `fetcher` is the URL fetch function the walker (and its child resolvers)
    will use. The CLI passes a :class:`~licenseal.resolvers.http.RegistryCache`-backed
    fetcher so popular URLs (``/pypi/numpy/json`` etc.) are pulled once even
    when many sibling deps reference them. Default is plain HTTPS.
    """
    ecosystems_present = {dep.ecosystem for dep in direct_deps}

    def names_by_group(eco: Ecosystem, group: DependencyGroup) -> set[str]:
        """Lowercased names of direct deps in `direct_deps` matching ecosystem + group."""
        return {d.name.lower() for d in direct_deps if d.ecosystem == eco and d.group == group}

    out: list[Dependency] = []
    handled: set[Ecosystem] = set()

    # Manifest-source map for lockfile-derived direct deps. The lockfile parser
    # constructs Dependency objects from scratch and doesn't know which manifest
    # file each direct dep was declared in; we copy that here so the report's
    # Source column stays accurate for direct entries.
    sources_by_key: dict[tuple[Ecosystem, str], str] = {
        (d.ecosystem, d.name.lower()): d.source for d in direct_deps if d.source
    }

    def _stamp_sources(deps: list[Dependency]) -> list[Dependency]:
        return [
            replace(d, source=sources_by_key.get((d.ecosystem, d.name.lower()), ""))
            if d.depth == 0
            else d
            for d in deps
        ]

    # --- lockfile-first ---

    # When a lockfile covers an ecosystem we still need to walk direct deps
    # the lockfile didn't include (typically nested manifests in subdirs that
    # weren't part of the root install workspace — e.g. ``container/x/package.json``
    # alongside a root-only ``pnpm-lock.yaml``). The lockfile gives the precise
    # resolved graph for what's in it; the registry walk fills in what's not.
    #
    # ``lockfile_names`` is the union of every name the lockfile mentions,
    # registry-sourced or not. For Rust this includes ``[patch.crates-io]``
    # overrides (git/path-sourced deps) — they're in the lockfile but
    # can't be license-resolved here. Treating them as uncovered would
    # cause the registry walker to fetch the unpatched crates.io version
    # and walk its different transitive set (phantom-version bug — see
    # ``parse_cargo_lock`` docstring). Anything actually in the lockfile,
    # registry or not, is considered covered.
    def _walk_uncovered(
        ecosystem: Ecosystem,
        lockfile_output: list[Dependency],
        lockfile_names: set[str],
        origins: Mapping[str, str | None] | None = None,
    ) -> list[Dependency]:
        covered = lockfile_names | {d.name.lower() for d in lockfile_output if d.depth == 0}
        uncovered = [
            d
            for d in direct_deps
            if d.ecosystem == ecosystem
            and d.name.lower() not in covered
            and (include_dev or d.group != DependencyGroup.DEV)
        ]
        if not uncovered:
            return []
        _record_missing_lockfiles(project_path, uncovered)
        return _walk_registry(
            uncovered,
            ecosystem,
            project_path=project_path,
            max_depth=max_depth,
            client=client,
            max_workers=max_workers,
            fetcher=fetcher,
            on_wave=on_wave,
            origins=origins,
        )

    # A lockfile is read whenever it exists, whether or not discovery found a
    # direct dep for its ecosystem: the manifest beside it can be missing, or
    # declare its dependencies in a form discovery does not read. What a
    # lockfile's packages are attributed to when none of them is a discovered
    # direct dep is each parser's call; none of them drops the whole file.
    py_locks = find_python_lockfiles(project_path, exclude_paths=exclude_paths)
    if py_locks:
        locked: list[Dependency] = []
        for py_lock in py_locks:
            locked.extend(
                _stamp_sources(
                    parse_python_lockfile(
                        py_lock,
                        prod_root_names=names_by_group(Ecosystem.PYTHON, DependencyGroup.PROD),
                        dev_root_names=names_by_group(Ecosystem.PYTHON, DependencyGroup.DEV),
                        include_dev=include_dev,
                        scan_root=project_path,
                    )
                )
            )
        out.extend(locked)
        out.extend(_walk_uncovered(Ecosystem.PYTHON, locked, set()))
        handled.add(Ecosystem.PYTHON)

    npm_locks = find_npm_lockfiles(project_path, exclude_paths=exclude_paths)
    if npm_locks:
        locked = []
        for npm_lock in npm_locks:
            locked.extend(
                _stamp_sources(
                    parse_npm_lockfile(
                        npm_lock,
                        prod_root_names=names_by_group(Ecosystem.NPM, DependencyGroup.PROD),
                        dev_root_names=names_by_group(Ecosystem.NPM, DependencyGroup.DEV),
                        include_dev=include_dev,
                        scan_root=project_path,
                    )
                )
            )
        out.extend(locked)
        out.extend(_walk_uncovered(Ecosystem.NPM, locked, set()))
        handled.add(Ecosystem.NPM)

    # What the Cargo.toml files say about crates that are not registry
    # releases. A Cargo.lock gives no location for a crate built from a path,
    # and a registry walk knows nothing of a ``[patch]``; both need it.
    cargo = cargo_sources(project_path, exclude_paths=exclude_paths)
    rust_locks = find_rust_lockfiles(project_path, exclude_paths=exclude_paths)
    if rust_locks:
        locked = []
        rust_known_names: set[str] = set()
        for rust_lock in rust_locks:
            # A path dependency that the scan reads has no row, but
            # the lockfile records the registry crates it pulls in. It is a
            # root of the lockfile graph all the same; without it those
            # crates are unreachable and dropped as orphans.
            lock_deps, lock_known = parse_cargo_lock(
                rust_lock,
                prod_root_names=names_by_group(Ecosystem.RUST, DependencyGroup.PROD)
                | cargo.prod_roots,
                dev_root_names=names_by_group(Ecosystem.RUST, DependencyGroup.DEV)
                | cargo.dev_roots,
                include_dev=include_dev,
                origins=cargo.origins,
            )
            locked.extend(_stamp_sources(lock_deps))
            rust_known_names.update(lock_known)
        out.extend(locked)
        out.extend(_walk_uncovered(Ecosystem.RUST, locked, rust_known_names, cargo.patches))
        handled.add(Ecosystem.RUST)

    if Ecosystem.JAVA in ecosystems_present or find_gradle_lockfiles(
        project_path, exclude_paths=exclude_paths
    ):
        # Java transitive resolution: lockfile-first (Gradle), else
        # deps.dev ``:dependencies`` walk per direct dep. Maven has no
        # native lockfile, so most Maven projects take the deps.dev
        # path; mixed Maven+Gradle monorepos take both (Gradle lockfile
        # covers Gradle-resolved deps; Maven directs go through deps.dev).
        direct_java_deps = [d for d in direct_deps if d.ecosystem == Ecosystem.JAVA]
        out.extend(
            _resolve_java_transitive(
                direct_java_deps=direct_java_deps,
                project_path=project_path,
                exclude_paths=exclude_paths,
                include_dev=include_dev,
                client=client,
                max_workers=max_workers,
                fetcher=fetcher,
                pom_fetcher=pom_fetcher,
            )
        )
        handled.add(Ecosystem.JAVA)

    if (
        Ecosystem.DOTNET in ecosystems_present
        or find_nuget_lockfiles(project_path, exclude_paths=exclude_paths)
        or find_paket_lockfiles(project_path, exclude_paths=exclude_paths)
    ):
        # .NET transitive resolution: lockfile-first (NuGet
        # ``packages.lock.json`` / ``project.assets.json`` AND Paket's
        # ``paket.lock``), else deps.dev ``:dependencies`` walk per direct
        # dep. Same lockfile-first posture as Java's Gradle path. Mixed
        # NuGet + Paket workspaces walk both lockfile flavors.
        direct_dotnet_deps = [d for d in direct_deps if d.ecosystem == Ecosystem.DOTNET]
        out.extend(
            _resolve_dotnet_transitive(
                direct_dotnet_deps=direct_dotnet_deps,
                project_path=project_path,
                exclude_paths=exclude_paths,
                include_dev=include_dev,
                client=client,
                max_workers=max_workers,
                fetcher=pom_fetcher,
            )
        )
        handled.add(Ecosystem.DOTNET)

    # PHP transitive resolution: composer.lock is authoritative when
    # present — it embeds the full edge graph AND an explicit ``dev``
    # boolean per entry (no reachability re-inference needed, unlike
    # npm's multi-tool lockfile soup). Without a lockfile, fall through
    # to the registry-walk fallback that calls
    # :func:`fetch_packagist_dependencies` per resolved dep.
    composer_locks = find_composer_lockfiles(project_path, exclude_paths=exclude_paths)
    if composer_locks:
        direct_php_names = {d.name.lower() for d in direct_deps if d.ecosystem == Ecosystem.PHP}
        direct_source_by_name = {
            d.name.lower(): d.source
            for d in direct_deps
            if d.ecosystem == Ecosystem.PHP and d.source
        }
        locked: list[Dependency] = []
        # Every name a lockfile holds is covered by it, the project's own
        # path packages included: none of them is walked from the registry.
        php_lock_names: set[str] = set()
        for composer_lock in composer_locks:
            lock_deps, license_map = parse_composer_lockfile(
                composer_lock,
                direct_names=direct_php_names,
                include_dev=include_dev,
                scan_root=project_path,
            )
            php_lock_names.update(name for name, _version in license_map)
            for dep in lock_deps:
                if dep.depth == 0:
                    source = direct_source_by_name.get(dep.name.lower(), "")
                    if source:
                        locked.append(replace(dep, source=source))
                    else:
                        locked.append(dep)
                else:
                    locked.append(dep)
        out.extend(locked)
        out.extend(_walk_uncovered(Ecosystem.PHP, locked, php_lock_names))
        handled.add(Ecosystem.PHP)

    # Ruby transitive resolution: Gemfile.lock is authoritative when
    # present — the GEM/GIT/PATH/DEPENDENCIES grammar carries the
    # full edge graph in a fully static format. Group attribution
    # comes from the Gemfile (Gemfile.lock has no dev/prod marker
    # of its own); we collect the DEV-only direct names from
    # discovery and propagate via reverse-BFS in the lockfile parser.
    gemfile_locks = find_gemfile_lockfiles(project_path, exclude_paths=exclude_paths)
    if gemfile_locks:
        ruby_workspace = workspace_gemspec_names(project_path, exclude_paths=exclude_paths)
        direct_ruby_names = {d.name.lower() for d in direct_deps if d.ecosystem == Ecosystem.RUBY}
        dev_direct_ruby_names = collect_dev_direct_names(
            [d for d in direct_deps if d.ecosystem == Ecosystem.RUBY]
        )
        direct_source_by_name = {
            d.name.lower(): d.source
            for d in direct_deps
            if d.ecosystem == Ecosystem.RUBY and d.source
        }
        locked: list[Dependency] = []
        for gemfile_lock in gemfile_locks:
            lock_deps = parse_gemfile_lock(
                gemfile_lock,
                direct_names=direct_ruby_names,
                dev_direct_names=dev_direct_ruby_names,
                include_dev=include_dev,
                scan_root=project_path,
            )
            # Drop workspace-internal lockfile entries — monorepo
            # siblings (one in-tree gem referencing another) are not
            # published gems we'd want to look up.
            lock_deps = [d for d in lock_deps if d.name.lower() not in ruby_workspace]
            locked.extend(_attach_ruby_direct_sources(lock_deps, direct_source_by_name))
        out.extend(locked)
        out.extend(_walk_uncovered(Ecosystem.RUBY, locked, set()))
        handled.add(Ecosystem.RUBY)

    # Hex transitive resolution. mix.lock (Elixir) carries the full edge
    # graph and is parsed edge-aware (reverse-BFS group propagation from
    # the mix.exs dev-name set). rebar.lock (Erlang) carries only depth
    # levels — no edges — so it's level/section-based (Pipfile.lock shape).
    # Both feed one ``Ecosystem.HEX`` graph; dev attribution comes from the
    # manifest (mix.exs / rebar.config), never the lock.
    mix_locks = find_mix_lockfiles(project_path, exclude_paths=exclude_paths)
    rebar_locks = find_rebar_lockfiles(project_path, exclude_paths=exclude_paths)
    if mix_locks or rebar_locks:
        hex_workspace = workspace_hex_names(project_path, exclude_paths=exclude_paths)
        direct_hex_names = {d.name.lower() for d in direct_deps if d.ecosystem == Ecosystem.HEX}
        dev_direct_hex_names = _collect_hex_dev_direct_names(
            [d for d in direct_deps if d.ecosystem == Ecosystem.HEX]
        )
        direct_source_by_name = {
            d.name.lower(): d.source
            for d in direct_deps
            if d.ecosystem == Ecosystem.HEX and d.source
        }

        def _attach_and_filter(lock_deps: list[Dependency]) -> list[Dependency]:
            # Drop workspace-internal entries — umbrella siblings aren't
            # published on hex.pm — then stamp manifest sources.
            kept = [d for d in lock_deps if d.name.lower() not in hex_workspace]
            return _attach_hex_direct_sources(kept, direct_source_by_name)

        locked = []
        for mix_lock in mix_locks:
            locked.extend(
                _attach_and_filter(
                    parse_mix_lock(
                        mix_lock,
                        direct_names=direct_hex_names,
                        dev_direct_names=dev_direct_hex_names,
                        include_dev=include_dev,
                        scan_root=project_path,
                    )
                )
            )
        for rebar_lock in rebar_locks:
            locked.extend(
                _attach_and_filter(
                    parse_rebar_lock(
                        rebar_lock,
                        dev_direct_names=dev_direct_hex_names,
                        include_dev=include_dev,
                    )
                )
            )
        out.extend(locked)
        out.extend(_walk_uncovered(Ecosystem.HEX, locked, set()))
        handled.add(Ecosystem.HEX)

    # R / CRAN transitive resolution. renv.lock / packrat.lock (when present)
    # give the pinned closure; direct deps a lock doesn't cover — and
    # manifest-only projects with no lock — have their closure walked locally
    # over the parsed CRAN ``PACKAGES`` index (``cran_index``). Lock discovery is
    # unconditional (renv.lock / packrat.lock commonly exist WITHOUT a
    # DESCRIPTION — analysis projects, web apps — so a project can be
    # R-via-lockfile-only with zero R direct deps from manifests).
    renv_locks = find_renv_lockfiles(project_path, exclude_paths=exclude_paths)
    packrat_locks = find_packrat_lockfiles(project_path, exclude_paths=exclude_paths)
    r_direct = [d for d in direct_deps if d.ecosystem == Ecosystem.R]
    if renv_locks or packrat_locks or r_direct:
        out.extend(
            _resolve_r_transitive(
                direct_r_deps=r_direct,
                project_path=project_path,
                exclude_paths=exclude_paths,
                include_dev=include_dev,
                client=client,
                fetcher=pom_fetcher,
                renv_locks=renv_locks,
                packrat_locks=packrat_locks,
            )
        )
        handled.add(Ecosystem.R)

    if Ecosystem.GO in ecosystems_present or find_go_lockfiles(
        project_path, exclude_paths=exclude_paths
    ):
        # Go's transitive resolution: parse go.sum for the universe of
        # pinned modules; fetch each module's go.mod from proxy.golang.org
        # concurrently to build the edge graph; run reverse-BFS for
        # reachability-based group + ancestor attribution. Same machinery
        # the other ecosystems use — the only Go-specific cost is the
        # extra fetch per module (go.sum has no edges; deps.dev's
        # ``GetDependencies`` endpoint isn't available for Go — only npm,
        # Cargo, Maven, PyPI per Google's docs; the Go module proxy is
        # the canonical source the ``go`` toolchain itself consults).
        go_deps = [d for d in direct_deps if d.ecosystem == Ecosystem.GO]
        # A module replaced by a local path the scan does not read is a row
        # as it stands: no go.sum lists it, and the proxy is not asked for it.
        out.extend(
            d for d in go_deps if d.origin and (include_dev or d.group != DependencyGroup.DEV)
        )
        direct_go_deps = [d for d in go_deps if not d.origin]
        out.extend(
            _resolve_go_transitive(
                direct_go_deps=direct_go_deps,
                project_path=project_path,
                exclude_paths=exclude_paths,
                include_dev=include_dev,
                client=client,
                max_workers=max_workers,
                fetcher=fetcher,
            )
        )
        handled.add(Ecosystem.GO)

    # --- registry-recursion fallback per unhandled ecosystem ---

    for ecosystem in ecosystems_present - handled:
        seeds = [
            d
            for d in direct_deps
            if d.ecosystem == ecosystem and (include_dev or d.group != DependencyGroup.DEV)
        ]
        if not seeds:
            continue
        _record_missing_lockfiles(project_path, seeds)
        walked = _walk_registry(
            seeds,
            ecosystem,
            project_path=project_path,
            max_depth=max_depth,
            client=client,
            max_workers=max_workers,
            fetcher=fetcher,
            on_wave=on_wave,
            origins=cargo.patches if ecosystem == Ecosystem.RUST else None,
        )
        out.extend(walked)

    return _dedupe(_keep_declared_origins(out, direct_deps))


def _keep_declared_origins(
    deps: list[Dependency], direct_deps: list[Dependency]
) -> list[Dependency]:
    """Give a lockfile's row for a direct dep the origin its manifests declare.

    A dependency that every manifest declares from a git repository, a URL,
    or a path is not a registry package, whatever a lockfile records under
    its name. A lockfile that is stale, or that does not say where a package
    came from, must not turn the UNKNOWN row the manifest calls for into a
    registry lookup: a direct row without an origin takes the declared one.
    A name that some manifest also declares as a registry requirement is
    left as the lockfile has it. A row that takes an origin is not a version
    estimate: no registry is asked about it.
    """
    declared: dict[tuple[Ecosystem, str], str] = {}
    registry_names: set[tuple[Ecosystem, str]] = set()
    for dep in direct_deps:
        key = (dep.ecosystem, _canonical_name(dep))
        if dep.origin:
            declared.setdefault(key, dep.origin)
        else:
            registry_names.add(key)
    for key in registry_names:
        declared.pop(key, None)
    if not declared:
        return deps
    out: list[Dependency] = []
    for dep in deps:
        origin = declared.get((dep.ecosystem, _canonical_name(dep)), "")
        out.append(
            replace(dep, origin=origin, version_estimated=False)
            if origin and dep.depth == 0 and not dep.origin
            else dep
        )
    return out


_GO_PROXY_URL = "https://proxy.golang.org"


_GoModFetcher = Callable[[str, httpx.Client], "dict[str, str] | None"]


def _resolve_go_transitive(
    *,
    direct_go_deps: list[Dependency],
    project_path: Path,
    exclude_paths: frozenset[Path],
    include_dev: bool,
    client: httpx.Client,
    max_workers: int,
    fetcher: Fetcher,  # noqa: ARG001 (kept for signature parity with other ecosystems' branches)
    go_mod_fetcher: _GoModFetcher = fetch_go_mod_text,
) -> list[Dependency]:
    """Edge-aware Go transitive resolution.

    Approach:
      1. Build the module universe: every ``go.sum`` row, plus every direct
         requirement from ``go.mod`` at the version it requires, whether or
         not ``go.sum`` has a row for it. No version is selected among the
         ``go.sum`` rows of one module.
      2. Fetch each module's ``go.mod`` from ``proxy.golang.org`` to learn
         its direct require edges. Best-effort: proxy fetches that fail
         leave that module as a leaf in the edge graph (no outgoing edges).
         Skipped when there is no direct dep to attribute anything to.
      3. Build the edge dict (lowercased names) and run
         :func:`compute_direct_ancestors` from PROD-root and DEV-root direct
         deps. Resulting attribution mirrors the npm/Rust/Python lockfile
         path: reachable from a PROD root → PROD; only from a DEV root →
         DEV; orphaned → fall back to PROD (conservative).
      4. Apply ``--no-dev`` filter using the reachability result.

    Direct go deps carry their group already (PROD by default; DEV when
    matched by ``tool`` directive in ``go_mod.py``). A DEV direct that a PROD
    root also reaches is PROD, like any other module a PROD root reaches.

    A row is a direct dep (depth 0, with its manifest as source) only at the
    version ``go.mod`` requires. A ``go.sum`` row for another version of a
    required module is kept as a row of its own, attributed like any module
    of that name. The modules a direct requires are rows only when ``go.sum``
    lists them: nothing is added from the proxy. Where that leaves a
    requirement's own dependencies out of the report, its ``go.mod`` is
    recorded as a gap (see :func:`_record_unlisted_go_requirements`).
    """
    # Manifest of each requirement, keyed as go.mod states it.
    direct_sources = {(d.name, d.version_constraint): d.source for d in direct_go_deps}
    prod_root_names = {d.name.lower() for d in direct_go_deps if d.group == DependencyGroup.PROD}
    dev_root_names = {d.name.lower() for d in direct_go_deps if d.group == DependencyGroup.DEV}

    # Workspace-local modules (in-tree go.mod modules + go.work `use` targets)
    # must be filtered from the transitive output too, not just from the
    # direct-discovery output. Workspaces frequently leave entries in
    # ``go.sum`` for sibling modules (because the toolchain populated them
    # when those siblings were imported as versioned requires), so without
    # this filter the transitive walker re-introduces them. Discovery
    # already applies the same filter at its emission point; this is the
    # symmetric apply on the lockfile-derived universe.
    workspace_local = _discover_workspace_local_module_paths(
        project_path, exclude_paths=exclude_paths
    )

    # ---- 1. enumerate the module universe ----
    go_locks = find_go_lockfiles(project_path, exclude_paths=exclude_paths)
    entries: list[tuple[str, str]] = []
    seen_entries: set[tuple[str, str]] = set()
    if go_locks:
        for go_lock in go_locks:
            for mod_ver in parse_go_sum_entries(go_lock):
                if mod_ver in seen_entries:
                    continue
                if mod_ver[0] in workspace_local:
                    continue
                seen_entries.add(mod_ver)
                entries.append(mod_ver)
    # Checked against the go.sum rows alone, before the requirements join them.
    _record_unlisted_go_requirements(
        project_path, exclude_paths, workspace_local, frozenset(seen_entries)
    )
    # Every direct requirement is part of the universe, whatever go.sum holds:
    # a nested module can have no go.sum of its own, a go.sum can list a
    # requirement only as a ``/go.mod`` row, or pin another version of it.
    # Added after the go.sum rows, so that where go.sum has another version
    # of a required module, the required version's go.mod supplies the
    # module's edges (see :func:`_fetch_go_edge_graph`).
    for d in direct_go_deps:
        if d.name in workspace_local:
            continue
        key = (d.name, d.version_constraint)
        if key in seen_entries:
            continue
        seen_entries.add(key)
        entries.append(key)
    if not entries:
        return []

    # ---- 2. fetch each module's go.mod, extract edges ----
    # Edges only attribute modules to direct deps. With none (a go.sum whose
    # go.mod is missing or requires nothing), every module is an orphan
    # whatever the graph says, so nothing is fetched.
    edges = (
        _fetch_go_edge_graph(entries, client, max_workers, go_mod_fetcher) if direct_go_deps else {}
    )

    # ---- 3. attribute group + direct_ancestors ----
    # name_case preserves the original-case module path so the reverse-BFS's
    # ancestor labels match the labels in the report.
    name_case = {mod.lower(): mod for mod, _ in entries}
    # Every direct is in ``entries`` (step 1) unless it is workspace-local,
    # and a workspace-local module is not a root.
    prod_roots = {n: name_case[n] for n in prod_root_names if n in name_case}
    dev_roots = {n: name_case[n] for n in dev_root_names if n in name_case}
    prod_anc = compute_direct_ancestors(edges, prod_roots)
    dev_anc = compute_direct_ancestors(edges, dev_roots)

    out: list[Dependency] = []
    for module_path, version in entries:
        lower = module_path.lower()
        is_direct = (module_path, version) in direct_sources
        if lower in prod_root_names:
            group = DependencyGroup.PROD
            ancestors: tuple[str, ...] = ()
        elif lower in prod_anc:
            # Checked before DEV-root membership: a ``tool`` module that a
            # production module also requires ships. It is still a direct
            # dep, so it carries no ancestors.
            group = DependencyGroup.PROD
            ancestors = () if lower in dev_root_names else prod_anc[lower]
        elif lower in dev_root_names:
            group = DependencyGroup.DEV
            ancestors = ()
        elif lower in dev_anc:
            group = DependencyGroup.DEV
            ancestors = dev_anc[lower]
        else:
            # Orphan (no incoming path from any direct root, e.g. because the
            # proxy fetch for its parent failed). Fall back to PROD to avoid
            # silently dropping the dep on a partial fetch.
            group = DependencyGroup.PROD
            ancestors = ()

        if group == DependencyGroup.DEV and not include_dev:
            continue

        out.append(
            Dependency(
                name=module_path,
                version_constraint=version,
                ecosystem=Ecosystem.GO,
                group=group,
                depth=0 if is_direct else 1,
                direct_ancestors=ancestors,
                source=direct_sources.get((module_path, version), ""),
            )
        )
    return out


def _record_unlisted_go_requirements(
    project_path: Path,
    exclude_paths: frozenset[Path],
    workspace_local: set[str],
    locked: frozenset[tuple[str, str]],
) -> None:
    """Record a gap on each ``go.mod`` whose requirements' own dependencies are unknown.

    ``locked`` holds the ``go.sum`` rows. A requirement with a row has the
    modules it depends on in ``go.sum`` too. One without a row is reported on
    its own, which is the whole set only when ``go.mod`` lists those modules
    itself: from ``go 1.17`` on it does (see :func:`lists_all_requirements`).
    Below that, or with no ``go`` directive, they are missing from the report.

    Requirements that are not scanned — replaced by a local path, or modules
    of this workspace — need no row and are not counted.
    """
    for go_mod in walk_project_files(project_path, "go.mod", exclude_paths=exclude_paths):
        text = decode_text(go_mod)
        if text is None or lists_all_requirements(text):
            continue
        requires, replaces, _ = _parse_go_mod(text)
        unlocked = [
            requirement
            for requirement in apply_replaces(requires, replaces)
            if requirement[0] not in workspace_local and requirement not in locked
        ]
        if unlocked:
            record_unlisted_dependencies(
                go_mod,
                "lists only direct requirements (its go directive is below 1.17 or absent) "
                f"and a go.sum row is missing for {len(unlocked)} of them",
                "commit an up-to-date go.sum to include it",
            )


def _resolve_r_transitive(
    *,
    direct_r_deps: list[Dependency],
    project_path: Path,
    exclude_paths: frozenset[Path],
    include_dev: bool,
    client: httpx.Client,
    fetcher: Fetcher,
    renv_locks: list[Path],
    packrat_locks: list[Path],
) -> list[Dependency]:
    """Resolve the R dependency graph from lockfiles and/or the CRAN index.

    renv.lock / packrat.lock (when present) give the pinned closure directly via
    the edge-aware lock parsers. Direct deps a lock doesn't cover — and
    manifest-only projects with no lock at all — have their closure walked
    locally over the parsed CRAN ``PACKAGES`` index (``cran_index``), so the
    only network cost is the single index fetch. Group / depth / ancestor
    attribution reuses :func:`build_lock_dependencies`.
    """
    r_workspace = workspace_r_names(project_path, exclude_paths=exclude_paths)
    direct_r_names = {d.name.lower() for d in direct_r_deps}
    dev_direct_r_names = _collect_r_dev_direct_names(direct_r_deps)
    direct_source_by_name = {d.name.lower(): d.source for d in direct_r_deps if d.source}

    def _attach_and_filter(lock_deps: list[Dependency]) -> list[Dependency]:
        # Drop workspace-internal entries — multi-package R repo siblings aren't
        # published to CRAN — then stamp manifest sources onto direct entries.
        kept = [d for d in lock_deps if d.name.lower() not in r_workspace]
        return _attach_r_direct_sources(kept, direct_source_by_name)

    out: list[Dependency] = []
    for renv_lock in renv_locks:
        out.extend(
            _attach_and_filter(
                parse_renv_lock(
                    renv_lock,
                    direct_names=direct_r_names,
                    dev_direct_names=dev_direct_r_names,
                    include_dev=include_dev,
                    scan_root=project_path,
                )
            )
        )
    for packrat_lock in packrat_locks:
        out.extend(
            _attach_and_filter(
                parse_packrat_lock(
                    packrat_lock,
                    direct_names=direct_r_names,
                    dev_direct_names=dev_direct_r_names,
                    include_dev=include_dev,
                    scan_root=project_path,
                )
            )
        )

    # Direct deps no lock covered (manifest-only project, or a nested DESCRIPTION
    # beside a root-only lock): walk their closure over the CRAN index.
    covered = {d.name.lower() for d in out}
    uncovered = [
        d
        for d in direct_r_deps
        if d.name.lower() not in covered
        and d.name.lower() not in r_workspace
        and (include_dev or d.group != DependencyGroup.DEV)
    ]
    if uncovered:
        # Manifest-only / lock-uncovered closure walks the CRAN index locally;
        # fetch + parse it lazily (only when there's something to walk).
        _record_missing_lockfiles(project_path, uncovered)
        cran_index = fetch_cran_index(client, fetcher=fetcher)
        out.extend(_attach_and_filter(_r_index_closure(uncovered, cran_index, include_dev)))
    return out


def _r_index_closure(
    direct_deps: list[Dependency],
    cran_index: CranIndex,
    include_dev: bool,
) -> list[Dependency]:
    """Walk the transitive closure of ``direct_deps`` over the CRAN index.

    BFS follows the runtime/build edges (:func:`index_edge_names`) recorded in
    the index; versions are the index's current versions (R licenses are
    version-stable), so every row from the index is ``version_estimated``.
    Direct deps absent from the index (off-CRAN / archived) are still seeded
    so they surface and resolve to UNKNOWN at the license stage.
    A direct dep with an origin is not a CRAN package: it keeps its origin,
    takes no version from the index, has no edges, and is not an estimate.
    Attribution reuses :func:`build_lock_dependencies`: direct deps are the
    roots, the Suggests/Enhances subset the dev roots.
    """
    spec_info: dict[str, tuple[str, str, str | None]] = {}
    edges: dict[str, set[str]] = {}
    prod_roots = {d.name.lower() for d in direct_deps if d.group == DependencyGroup.PROD}
    dev_roots = {d.name.lower() for d in direct_deps if d.group == DependencyGroup.DEV}

    def _seed(name: str) -> None:
        lower = name.lower()
        if lower in spec_info:
            return
        record = cran_index.get(lower)
        orig = record.get("Package", name) if record else name
        version = record.get("Version", "").strip() if record else ""
        spec_info[lower] = (orig, version, "")

    for dep in direct_deps:
        if dep.origin:
            spec_info.setdefault(dep.name.lower(), (dep.name, "", dep.origin))
        else:
            _seed(dep.name)

    frontier = prod_roots | dev_roots
    seen: set[str] = set(frontier)
    while frontier:
        nxt: set[str] = set()
        for node in frontier:
            record = None if spec_info[node][2] else cran_index.get(node)
            children: set[str] = set()
            if record is not None:
                for child in index_edge_names(record):
                    child_lower = child.lower()
                    _seed(child)
                    children.add(child_lower)
                    if child_lower not in seen:
                        seen.add(child_lower)
                        nxt.add(child_lower)
            edges[node] = children
        frontier = nxt

    closure = build_lock_dependencies(
        spec_info,
        edges,
        direct_names=prod_roots | dev_roots,
        dev_direct_names=dev_roots,
        include_dev=include_dev,
    )
    return [dep if dep.origin else replace(dep, version_estimated=True) for dep in closure]


# A transitive deps fetcher returns ``(nodes, edges, unread)``: ``nodes`` is a
# list of ``(name, version)``, ``edges`` a list of ``(parent_name,
# parent_version, child_name, child_version)``, and ``unread`` the ``(name,
# version)`` of each package whose own dependencies could not be read. Maven
# and NuGet fetchers share this shape, so they share this ecosystem-neutral
# alias rather than borrowing each other's name.
_TransitiveDepsFetcher = Callable[
    ...,
    tuple[list[tuple[str, str]], list[tuple[str, str, str, str]], list[tuple[str, str]]],
]


def _promote_directs_reached_from_prod(
    out: list[Dependency],
    start: int,
    reached: Container[str],
) -> None:
    """Make the direct deps in ``out[start:]`` PROD when a PROD direct reaches them.

    ``reached`` holds the lowercased names a PROD direct reaches. The Maven
    and NuGet walks emit every direct with its declared group before the
    graph is fetched, and skip a graph node that is also a direct. A DEV
    direct that a PROD direct pulls in ships, so production wins — the same
    rule the lockfile parsers apply.
    """
    for index in range(start, len(out)):
        if out[index].name.lower() in reached:
            out[index] = replace(out[index], group=DependencyGroup.PROD)


def _resolve_dotnet_transitive(
    *,
    direct_dotnet_deps: list[Dependency],
    project_path: Path,
    exclude_paths: frozenset[Path],
    include_dev: bool,
    client: httpx.Client,
    max_workers: int,
    fetcher: Fetcher,
    deps_fetcher: _TransitiveDepsFetcher = fetch_nuget_dependencies,
) -> list[Dependency]:
    """Edge-aware .NET transitive resolution.

    Two-path:

    1. **Lockfile-first** — ``packages.lock.json`` and ``project.assets.json``
       (NuGet) plus ``paket.lock`` (Paket). The lockfile parsers union
       across TFMs per the locked-in plan decision. Each NuGet lockfile
       carries its own edges, so ``parse_nuget_lockfile`` attributes group
       + ancestors per lockfile by reachability from the direct deps of the
       whole scan (PROD wins over DEV; unreachable → PROD). ``paket.lock``
       entries take their group from the Paket group they are listed in.

    2. **Recursive nuspec walk** — for direct .NET deps not covered by
       any lockfile (a ``.csproj`` project where ``dotnet restore``
       hasn't been run, the common case for source-only repos), walk
       each direct dep's ``.nuspec`` ``<dependencies>`` block from the
       NuGet flatcontainer, unioning across TFM groups (matches the
       lockfile parsers' posture). deps.dev's ``GetDependencies`` is
       documented for npm / Cargo / Maven / PyPI only — the NuGet URL
       returns 404, so we read nuspecs directly from
       ``api.nuget.org``. Walking is depth-first per direct dep,
       parallelized across directs; merge subgraphs, dedupe by
       ``(name_lower, version)``, then run reachability attribution.

    Workspace-local filter: in-tree ``.csproj`` files declare their own
    project IDs via ``<PackageId>`` or fall back to the file stem. Those
    IDs aren't published packages, so any ``<PackageReference>`` and any
    walker-resolved node matching one is filtered.

    NuGet package IDs are case-insensitive per spec; comparison uses
    ``.lower()`` everywhere. Orphan transitives → PROD fallback,
    conservative (matches the Java + Go paths).
    """
    workspace_local_ids = _discover_workspace_local_project_ids(
        project_path, exclude_paths=exclude_paths
    )
    workspace_local_lower = {wid.lower() for wid in workspace_local_ids}

    direct_source_by_name = {d.name.lower(): d.source for d in direct_dotnet_deps if d.source}

    out: list[Dependency] = []
    covered_names: set[str] = set()

    # ---- NuGet lockfile path ----
    # Each lockfile is attributed on its own edges, against the direct deps of
    # the whole scan. A workspace-local entry stays in the graph the parser
    # walks (its children are reached through it) but is not emitted.
    direct_prod_names = {
        d.name.lower() for d in direct_dotnet_deps if d.group == DependencyGroup.PROD
    }
    direct_dev_names = {
        d.name.lower() for d in direct_dotnet_deps if d.group == DependencyGroup.DEV
    }
    for nuget_lock in find_nuget_lockfiles(project_path, exclude_paths=exclude_paths):
        for dep in parse_nuget_lockfile(
            nuget_lock,
            prod_root_names=direct_prod_names,
            dev_root_names=direct_dev_names,
            include_dev=include_dev,
        ):
            lower = dep.name.lower()
            if lower in workspace_local_lower:
                continue
            covered_names.add(lower)
            if dep.depth == 0:
                dep = replace(dep, source=direct_source_by_name.get(lower, ""))
            out.append(dep)

    # ---- Paket lockfile path ----
    paket_prod_names: set[str] = set()
    for paket_lock in find_paket_lockfiles(project_path, exclude_paths=exclude_paths):
        for dep in parse_paket_lock(paket_lock, project_path=project_path):
            if dep.name.lower() in workspace_local_lower:
                continue
            if not include_dev and dep.group == DependencyGroup.DEV:
                continue
            lower = dep.name.lower()
            if dep.group == DependencyGroup.PROD:
                paket_prod_names.add(lower)
            if lower in covered_names:
                continue
            covered_names.add(lower)
            source = direct_source_by_name.get(lower, dep.source)
            out.append(
                Dependency(
                    name=dep.name,
                    version_constraint=dep.version_constraint,
                    ecosystem=Ecosystem.DOTNET,
                    group=dep.group,
                    source=source,
                )
            )
    # A name is reported once, from the first lockfile that has it. When that
    # entry is DEV and a Paket production group lists the same package, the
    # skipped entry is the one that ships: production wins.
    out = [
        replace(d, group=DependencyGroup.PROD)
        if d.group == DependencyGroup.DEV and d.name.lower() in paket_prod_names
        else d
        for d in out
    ]

    # ---- deps.dev :dependencies path for uncovered directs ----
    direct_uncovered = [
        d
        for d in direct_dotnet_deps
        if d.name.lower() not in covered_names
        and d.name.lower() not in workspace_local_lower
        and (include_dev or d.group != DependencyGroup.DEV)
    ]
    if not direct_uncovered:
        return out
    _record_missing_lockfiles(project_path, direct_uncovered)

    # Direct deps whose version parses to a concrete NuGet pin can be
    # walked; ones that don't (unresolved $() tokens, floating versions)
    # still surface in the output so the license resolver sees them. A
    # version taken from a range is an estimate; a bare version or
    # ``[1.2.3]`` is the version NuGet restores.
    walkable: list[tuple[Dependency, str]] = []
    first_direct = len(out)
    for d in direct_uncovered:
        declared = flag_version_estimate(d)
        pinned = _extract_pinned_version_nuget(d.version_constraint)
        if pinned is None:
            out.append(declared)
            continue
        walkable.append((d, pinned))
        out.append(replace(declared, version_constraint=f"=={pinned}"))

    if not walkable:
        return out

    merged_nodes: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}

    def _one(
        entry: tuple[Dependency, str],
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str, str, str]], list[tuple[str, str]]]:
        direct, pinned = entry
        return deps_fetcher(direct.name, pinned, client, fetcher=fetcher)

    # Propagate the active tethered scope into the edge-fetch workers — a bare
    # pool fetches in an empty context and bypasses the egress policy.
    subgraphs = map_with_context(_one, walkable, max_workers)
    for (direct, _pinned), (nodes, edge_tuples, unread) in zip(walkable, subgraphs, strict=True):
        # A package whose nuspec could not be read leaves a hole under the
        # direct dep it was reached from: a gap on that dep's manifest.
        _record_unread_dependencies(
            project_path,
            direct.source,
            (pkg for pkg in unread if pkg[0].lower() not in workspace_local_lower),
        )
        for node_name, node_version in nodes:
            if node_name.lower() in workspace_local_lower:
                continue
            merged_nodes.add((node_name, node_version))
        for from_name, _from_ver, to_name, _to_ver in edge_tuples:
            if (
                from_name.lower() in workspace_local_lower
                or to_name.lower() in workspace_local_lower
            ):
                continue
            edges.setdefault(from_name.lower(), set()).add(to_name.lower())

    # ---- Reachability attribution ----
    prod_root_names = {d.name.lower() for d, _ in walkable if d.group == DependencyGroup.PROD}
    dev_root_names = {d.name.lower() for d, _ in walkable if d.group == DependencyGroup.DEV}
    name_case: dict[str, str] = {d.name.lower(): d.name for d, _ in walkable}
    for node_name, _ in merged_nodes:
        name_case.setdefault(node_name.lower(), node_name)

    prod_roots = {n: name_case[n] for n in prod_root_names if n in name_case}
    dev_roots = {n: name_case[n] for n in dev_root_names if n in name_case}
    prod_anc = compute_direct_ancestors(edges, prod_roots)
    dev_anc = compute_direct_ancestors(edges, dev_roots)
    _promote_directs_reached_from_prod(out, first_direct, prod_anc)

    direct_lower = {d.name.lower() for d, _ in walkable}
    for node_name, node_version in merged_nodes:
        lower = node_name.lower()
        if lower in direct_lower:
            continue
        if lower in prod_anc:
            group = DependencyGroup.PROD
            ancestors = prod_anc[lower]
        elif lower in dev_anc:
            group = DependencyGroup.DEV
            ancestors = dev_anc[lower]
        else:
            group = DependencyGroup.PROD
            ancestors = ()

        out.append(
            Dependency(
                name=node_name,
                # A node without a version is a package the nuspec names with
                # no version that can be pinned: reported, resolved UNKNOWN.
                version_constraint=f"=={node_version}" if node_version else "",
                ecosystem=Ecosystem.DOTNET,
                group=group,
                depth=1,
                direct_ancestors=ancestors,
                version_estimated=True,
            )
        )
    return out


def _accumulate_parent_properties(
    pom: _PomData,
    workspace_local_poms: dict[str, Path],
    client: httpx.Client,
    fetcher: Fetcher,
    max_depth: int = _MAX_PARENT_DEPTH,
) -> dict[str, str]:
    """Walk ``pom``'s parent chain and return the merged user-defined
    property dict (closer-to-leaf wins on conflicts).

    Maven's actual property-resolution semantics: when a POM references
    ``${foo}``, the value is looked up in the POM's own ``<properties>``
    first, then walks the parent chain. This helper computes that merged
    set in one pass so subsequent DM searches at ``pom`` can resolve
    references that reach into ancestor-defined properties (the
    canonical case: Maven's CI-friendly versioning where ``${revision}``
    and ``${changelist}`` are defined in the reactor root but used
    throughout submodules).

    Workspace-local parents (the reactor-multi-module pattern) are read
    from disk; external parents go through the shared ``_fetch_pom`` (which
    routes through Maven Central + the fallback public registries).
    Stops on the first parent that isn't reachable. The walk caps at
    :data:`_MAX_PARENT_DEPTH` to bound network cost on pathological POMs.

    Returns only user-defined properties. The ``project.*`` slots are
    computed per-level by :func:`_project_properties` (they depend on
    the level's own metadata, not on inherited values).
    """
    accumulated: dict[str, str] = dict(pom.properties)
    current = pom
    for _ in range(max_depth):
        if not (current.parent_group_id and current.parent_artifact_id):
            break
        parent_coord = f"{current.parent_group_id}:{current.parent_artifact_id}"
        parent_pom: _PomData | None
        if parent_coord in workspace_local_poms:
            parent_pom = _read_local_pom(workspace_local_poms[parent_coord])
        elif current.parent_version:
            # Expand the parent version against what we've accumulated so
            # far (child + closer ancestors). Skips if still unresolved.
            pv = _expand_properties(current.parent_version, accumulated)
            if "${" in pv:
                break
            parent_pom = _fetch_pom(
                current.parent_group_id,
                current.parent_artifact_id,
                pv,
                client,
                fetcher,
            )
        else:
            break
        if parent_pom is None:
            break
        # Parent's properties fill gaps — closer (already in `accumulated`) wins.
        for k, v in parent_pom.properties.items():
            accumulated.setdefault(k, v)
        current = parent_pom
    return accumulated


def _search_dm_for_coord(
    pom: _PomData,
    coord: str,
    inherited_props: dict[str, str] | None = None,
) -> tuple[str, bool]:
    """Search a POM's ``<dependencyManagement>`` for a managed version.

    Returns ``(version, found_bom_import)`` — when ``found_bom_import``
    is True, the caller can follow the BOM imports (separately surfaced
    so the caller controls whether to incur the extra network round-trip).
    The ``version`` is empty when no direct (non-import) DM entry matches
    the coord, or when the matched entry's version is itself an
    unresolved ``${…}`` property.

    ``inherited_props`` carries properties from ``pom``'s parent chain
    (see :func:`_accumulate_parent_properties`), used when a DM entry's
    version references a property defined upstream.

    First-match wins on duplicate coords within a single DM block. Maven
    itself uses last-match within a block; the deviation is benign for
    license scanning (the same coord declared twice in one DM block is
    a publisher error and yields the same license either way) and the
    rest of the resolver is built on first-match semantics.
    """
    props = _project_properties(pom, inherited_props=inherited_props)
    has_bom = False
    for managed in pom.managed_dependencies:
        mg = _expand_properties(managed.group_id, props)
        ma = _expand_properties(managed.artifact_id, props)
        if not (mg and ma):
            continue
        if managed.is_import:
            has_bom = True
            continue
        if f"{mg}:{ma}" != coord:
            continue
        mv = _expand_properties(managed.version, props)
        if mv and "${" not in mv:
            return (mv, has_bom)
    return ("", has_bom)


def _iter_bom_imports(
    pom: _PomData,
    inherited_props: dict[str, str] | None = None,
) -> Iterator[tuple[str, str, str]]:
    """Yield each ``(group, artifact, version)`` BOM-import in ``pom``.

    Filters out import entries whose coordinates won't resolve (empty
    fields or unresolved ``${…}`` versions). The caller is expected to
    fetch each BOM POM and search ITS ``<dependencyManagement>`` for
    managed versions. BOMs-of-BOMs are followed recursively up to
    :data:`_MAX_BOM_DEPTH` to bound network traffic; most ecosystem
    BOMs either flatten or only nest one level.

    ``inherited_props`` carries properties from ``pom``'s parent chain
    so that BOM-import versions like ``${project.version}`` (which
    expands to a parent-defined ``${revision}``) resolve correctly.
    """
    props = _project_properties(pom, inherited_props=inherited_props)
    for managed in pom.managed_dependencies:
        if not managed.is_import:
            continue
        bg = _expand_properties(managed.group_id, props)
        ba = _expand_properties(managed.artifact_id, props)
        bv = _expand_properties(managed.version, props)
        if bg and ba and bv and "${" not in bv:
            yield (bg, ba, bv)


def _read_local_pom(pom_path: Path) -> _PomData | None:
    """Parse an in-tree pom.xml; return ``None`` on read / parse failure."""
    data = read_xml_bytes(pom_path)
    if data is None:
        return None
    pom = _parse_pom(data)
    if pom is None:
        record_parse_failure(pom_path, "XML")
        return None
    return pom


# Cap on BOM-import chain depth. Real-world chains rarely exceed 2
# (a project-BOM that imports an upstream-BOM). Higher cap than this
# is mostly defensive against pathological / circular constructions.
_MAX_BOM_DEPTH = 5


def _search_bom_chain(
    pom: _PomData,
    coord: str,
    workspace_local_poms: dict[str, Path],
    client: httpx.Client,
    fetcher: Fetcher,
    depth_remaining: int,
    inherited_props: dict[str, str] | None = None,
) -> str:
    """Search ``pom``'s DM (and its full BOM-import chain) for ``coord``.

    BOMs that themselves import other BOMs are followed recursively,
    capped at :data:`_MAX_BOM_DEPTH` levels deep. Workspace-local BOMs
    (a project that publishes its own BOM module alongside the consumer
    POMs in the same reactor) are read from disk rather than fetched.

    Returns the first managed version found in the chain (Maven's
    actual lookup order: local-first, then BOMs left-to-right), or
    ``""`` when exhausted.

    ``inherited_props`` is the property dict for ``pom`` carrying values
    from ``pom``'s parent chain. When the search recurses into a BOM,
    the BOM gets its OWN inherited_props computed via
    :func:`_accumulate_parent_properties` — BOMs do not inherit from
    their importer's context (per Maven's import-scope semantics).
    """
    version, has_bom = _search_dm_for_coord(pom, coord, inherited_props=inherited_props)
    if version:
        return version
    if not has_bom or depth_remaining <= 0:
        return ""
    for bg, ba, bv in _iter_bom_imports(pom, inherited_props=inherited_props):
        bom_coord = f"{bg}:{ba}"
        if bom_coord in workspace_local_poms:
            bom_pom = _read_local_pom(workspace_local_poms[bom_coord])
        else:
            bom_pom = _fetch_pom(bg, ba, bv, client, fetcher)
        if bom_pom is None:
            continue
        # The recursed-into BOM has its own parent chain — compute its
        # inherited properties from scratch (BOMs imported via
        # <scope>import</scope> do not inherit the importer's context;
        # they get their own ancestor properties).
        bom_inherited = _accumulate_parent_properties(
            bom_pom,
            workspace_local_poms,
            client,
            fetcher,
        )
        nested = _search_bom_chain(
            bom_pom,
            coord,
            workspace_local_poms,
            client,
            fetcher,
            depth_remaining - 1,
            inherited_props=bom_inherited,
        )
        if nested:
            return nested
    return ""


def _resolve_property_in_version(
    version_constraint: str,
    source_pom_path: Path,
    workspace_local_poms: dict[str, Path],
    client: httpx.Client,
    fetcher: Fetcher,
) -> str:
    """Expand a literal ``${prop}`` version token via the parent property chain.

    Discovery expands ``${…}`` against the local POM's own ``<properties>``
    only — if the property is defined upstream (a parent's ``<properties>``
    block, or the reactor root's ``${revision}`` slot), discovery leaves
    the literal in place. This helper walks the parent chain, accumulates
    the merged property dict (closer-to-leaf wins, per Maven semantics),
    and re-expands the token. Returns the resolved string, or ``""`` when
    the property still can't be resolved after the full walk.

    Companion to :func:`_resolve_managed_version`: the latter handles the
    versionless-dep case (BOM-managed version), this one handles the
    property-token case (shared-version-property / CI-friendly pattern).
    Both paths route through the same workspace-local + Maven Central
    fetchers and benefit from the registry cache.
    """
    pom = _read_local_pom(source_pom_path)
    if pom is None:
        return ""
    inherited = _accumulate_parent_properties(
        pom,
        workspace_local_poms,
        client,
        fetcher,
    )
    # Layer ``project.*`` slots onto the merged ancestor properties so
    # ``${project.version}`` / ``${project.groupId}`` resolve correctly.
    props = _project_properties(pom, inherited_props=inherited)
    expanded = _expand_properties(version_constraint, props)
    if "${" in expanded or not expanded:
        return ""
    return expanded


def _resolve_managed_version(
    coord: str,
    source_pom_path: Path,
    workspace_local_poms: dict[str, Path],
    client: httpx.Client,
    fetcher: Fetcher,
) -> str:
    """Find ``coord``'s managed version by walking the parent + BOM chain.

    Maven's resolution model for a child POM's versionless
    ``<dependency>`` searches:

    1. The local POM's ``<dependencyManagement>`` (already done by
       :func:`discover_pom_xml_dependencies`).
    2. Each BOM imported by the local POM (``<scope>import</scope>``
       entries in DM).
    3. The parent POM's DM (and its BOMs).
    4. Each ancestor's DM (and their BOMs), recursively.

    ``coord`` is the ``"groupId:artifactId"`` we're hunting. Returns the
    first matching version found (Maven's actual semantics), or ``""``
    when the chain is exhausted. Cap at :data:`_MAX_PARENT_DEPTH`
    parents; BOM imports are followed one level deep at v1.

    ``workspace_local_poms`` maps in-tree ``groupId:artifactId`` to the
    on-disk ``pom.xml`` path. When the parent chain steps into a
    workspace-local coord (reactor multi-module pattern: submodule's
    parent IS the reactor root, which isn't published to a registry),
    we read that pom from disk instead of trying the network. This is
    the common case for multi-module reactors where the root carries
    the full ``<dependencyManagement>`` and submodules omit versions.

    All Maven Central POM fetches route through the shared registry
    cache, so a parent shared by N sibling deps is fetched exactly
    once per scan.
    """
    current = _read_local_pom(source_pom_path)
    if current is None:
        return ""

    # Walk current + parents, searching each level's DM (and that level's
    # full BOM-import chain, recursively) for the coord. First hit wins.
    #
    # At each level, ``inherited_props`` is computed by walking that
    # level's OWN parent chain (Maven's "closer-wins" property semantics:
    # when DM at level L references ``${foo}``, the value comes from L's
    # own properties first, then L's parent's, etc.). The per-level walk
    # is cheap because the registry cache dedupes POM fetches across
    # iterations and the workspace-local read is just a file open.
    for _ in range(_MAX_PARENT_DEPTH + 1):
        inherited = _accumulate_parent_properties(
            current,
            workspace_local_poms,
            client,
            fetcher,
        )
        version = _search_bom_chain(
            current,
            coord,
            workspace_local_poms,
            client,
            fetcher,
            _MAX_BOM_DEPTH,
            inherited_props=inherited,
        )
        if version:
            return version

        # Step to parent. If the parent is a workspace-local artifact
        # (the reactor-root pattern), read it from disk rather than
        # going to Maven Central where it isn't published.
        if not (current.parent_group_id and current.parent_artifact_id):
            return ""

        parent_coord = f"{current.parent_group_id}:{current.parent_artifact_id}"
        if parent_coord in workspace_local_poms:
            parent_pom = _read_local_pom(workspace_local_poms[parent_coord])
            if parent_pom is None:
                return ""
            current = parent_pom
            continue

        # Workspace-local lookup didn't match → try Maven Central
        # (with the fallback registries inside ``_fetch_pom``).
        if not current.parent_version:
            return ""
        # Expand the parent version against current's accumulated
        # ancestor properties so a ``<parent><version>${revision}</version>``
        # expression can resolve when ``${revision}`` is defined in a
        # higher ancestor (the CI-friendly versioning pattern).
        parent_version = _expand_properties(current.parent_version, inherited)
        if "${" in parent_version:
            return ""
        parent_pom = _fetch_pom(
            current.parent_group_id,
            current.parent_artifact_id,
            parent_version,
            client,
            fetcher,
        )
        if parent_pom is None:
            return ""
        current = parent_pom

    return ""


def _resolve_java_transitive(
    *,
    direct_java_deps: list[Dependency],
    project_path: Path,
    exclude_paths: frozenset[Path],
    include_dev: bool,
    client: httpx.Client,
    max_workers: int,
    fetcher: Fetcher,
    pom_fetcher: Fetcher = fetch_registry_text,
    deps_fetcher: _TransitiveDepsFetcher = fetch_maven_dependencies,
) -> list[Dependency]:
    """Java transitive resolution.

    Two-path:

    1. **Gradle lockfile** (``gradle.lockfile``): when present, the
       file-line entries give the full resolved-version set with
       classpath-based group attribution. No registry calls needed for
       what the lockfile covers. Multi-project Gradle builds may carry
       one lockfile per subproject; we union them.

    2. **deps.dev ``:dependencies``**: for direct Java deps not in any
       Gradle lockfile, hit ``api.deps.dev``'s MAVEN ``GetDependencies``
       endpoint per direct dep, in parallel. The response is the
       fully-resolved subgraph rooted at that dep, so each of its nodes
       is attributed, by ``(name, version)``, to that direct: PROD when
       a PROD direct's subgraph lists it, otherwise DEV, with the
       listing directs as its ancestors. A DEV direct is PROD when a
       PROD direct's subgraph lists it at the version it declares. The
       PROD rows of a walk that includes the DEV directs are therefore
       the rows of a walk without them.

    Workspace-local filter: multi-module Maven projects link parent →
    submodule via ``<modules>``; sibling artifact coordinates aren't
    published on Maven Central, so any in-tree ``groupId:artifactId``
    is filtered from both lockfile output and the deps.dev walk's nodes.

    Direct deps whose ``version_constraint`` doesn't parse to a concrete
    Maven pin (range syntax, unresolved ``${…}``, …) are emitted as-is
    so the license resolver gets a chance with the raw value — it'll
    typically UNKNOWN out, which is the right signal.

    A node of the same name as a direct is not a second row when that
    direct's own row stands for it: any version for a PROD direct, the
    declared version for a DEV direct. Another version of a DEV direct's
    artifact that a PROD direct pulls in is a PROD transitive.

    ``deps_fetcher`` returns a structured ``(nodes, edges, unread)`` tuple
    rather than a raw response dict, so the ``fetcher`` JSON-fetcher is passed
    *into* it as a keyword arg — the cache trim ``_trim_deps_dev_dependencies``
    runs against the URL-keyed cache that wraps it. The edges are not used
    here. A direct whose graph deps.dev did not return in full is in
    ``unread`` and is recorded as a gap on its manifest. Tests inject a
    custom ``deps_fetcher`` to drive the merge and attribution paths without
    going through respx.
    """
    workspace_local_poms = _discover_workspace_local_pom_paths(
        project_path, exclude_paths=exclude_paths
    )
    workspace_local = set(workspace_local_poms)

    direct_source_by_name = {d.name.lower(): d.source for d in direct_java_deps if d.source}

    out: list[Dependency] = []
    covered_names: set[str] = set()

    # ---- Gradle lockfile path ----
    for lockfile in find_gradle_lockfiles(project_path, exclude_paths=exclude_paths):
        for dep in parse_gradle_lockfile(lockfile, include_dev=include_dev):
            if dep.name in workspace_local:
                continue
            lower = dep.name.lower()
            covered_names.add(lower)
            source = direct_source_by_name.get(lower, "")
            out.append(replace(dep, source=source) if source else dep)

    # ---- deps.dev :dependencies path for uncovered directs ----
    direct_uncovered = [
        d
        for d in direct_java_deps
        if d.name.lower() not in covered_names
        and d.name not in workspace_local
        and (include_dev or d.group != DependencyGroup.DEV)
    ]
    # A dependency with an origin is a local file: it is a row as it stands,
    # with no managed version to look up and no subgraph to walk.
    out.extend(d for d in direct_uncovered if d.origin)
    direct_uncovered = [d for d in direct_uncovered if not d.origin]
    if not direct_uncovered:
        return out
    # Recorded for Gradle build files only: Maven has no lockfile format.
    _record_missing_lockfiles(project_path, direct_uncovered)

    # ---- Parent-chain version resolution ----
    # Two patterns are handled here, both requiring a walk up the parent
    # chain that discovery's local-only expansion can't do:
    #
    # (A) Empty ``version_constraint`` — the BOM-consumer pattern: child
    #     POM declares the dep without ``<version>``, and the version is
    #     supplied by a ``<parent>``'s ``<dependencyManagement>`` (or by
    #     a BOM imported into that DM via ``<scope>import</scope>``).
    #     Resolved by :func:`_resolve_managed_version`.
    # (B) Literal ``${…}`` token in ``version_constraint`` — the shared-
    #     version-property / CI-friendly versioning pattern: child POM
    #     declares ``<version>${some.version}</version>`` but
    #     ``some.version`` is defined in a parent POM's ``<properties>``
    #     block, not the child's. Resolved by
    #     :func:`_resolve_property_in_version`.
    #
    # Without these, every BOM-consuming or property-referencing dep
    # surfaces as UNKNOWN. Resolution is grouped by source POM: deps
    # from the same POM share the same parent chain, and the
    # ``RegistryCache`` further dedupes the actual Maven Central
    # fetches across sibling poms.
    dm_resolved: list[Dependency] = []
    for d in direct_uncovered:
        # Both lookups read ``d.source`` as a POM. A dependency declared in
        # a Gradle build file has no POM to walk, so it keeps its version
        # as declared (empty when the build leaves it to a BOM).
        if d.source.rsplit("/", 1)[-1] != "pom.xml":
            dm_resolved.append(d)
            continue
        if not d.version_constraint:
            managed_version = _resolve_managed_version(
                d.name,
                project_path / d.source,
                workspace_local_poms,
                client,
                pom_fetcher,
            )
            if managed_version:
                dm_resolved.append(replace(d, version_constraint=managed_version))
            else:
                dm_resolved.append(d)
        elif "${" in d.version_constraint:
            resolved = _resolve_property_in_version(
                d.version_constraint,
                project_path / d.source,
                workspace_local_poms,
                client,
                pom_fetcher,
            )
            if resolved:
                dm_resolved.append(replace(d, version_constraint=resolved))
            else:
                dm_resolved.append(d)
        else:
            dm_resolved.append(d)
    direct_uncovered = dm_resolved

    # Direct deps whose version parses to a concrete Maven pin can be
    # walked; ones that don't (range syntax, unresolved ``${…}``) still
    # surface in the output so the license resolver sees them. A pin is
    # exact whether the declaration states it or the parent chain manages it.
    walkable: list[tuple[Dependency, str]] = []
    first_direct = len(out)
    for d in direct_uncovered:
        pinned = _extract_pinned_version_maven(d.version_constraint)
        if pinned is None:
            out.append(replace(d, version_estimated=True))
            continue
        walkable.append((d, pinned))
        out.append(replace(d, version_constraint=f"=={pinned}"))

    if not walkable:
        return out

    def _one(entry: tuple[Dependency, str]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        direct, pinned = entry
        nodes, _edges, unread = deps_fetcher(direct.name, pinned, client, fetcher=fetcher)
        return nodes, unread

    # ---- Attribution by subgraph ----
    # deps.dev resolves each direct's subgraph on its own, so a node belongs
    # to the directs whose subgraph lists it, at the version listed there.
    # Nodes are keyed by (name, version): a version only a DEV direct pulls
    # in is DEV even when a PROD direct pulls in another version of the same
    # artifact. Attribution by name would make it PROD, and the PROD rows of
    # a walk that includes the DEV directs would then exceed the rows of a
    # walk that leaves them out.
    prod_owners: dict[tuple[str, str], set[str]] = {}
    dev_owners: dict[tuple[str, str], set[str]] = {}
    node_names: dict[tuple[str, str], str] = {}
    # Propagate the active tethered scope into the fetch workers — a bare
    # pool fetches in an empty context and bypasses the egress policy.
    subgraphs = map_with_context(_one, walkable, max_workers)
    for (direct, _pinned), (nodes, unread) in zip(walkable, subgraphs, strict=True):
        # deps.dev did not return this direct's whole graph: a gap on the
        # manifest that declares it, Maven ``pom.xml`` included.
        _record_unread_dependencies(project_path, direct.source, unread)
        owners = prod_owners if direct.group == DependencyGroup.PROD else dev_owners
        for node_name, node_version in nodes:
            if node_name in workspace_local:
                continue
            key = (node_name.lower(), node_version)
            node_names.setdefault(key, node_name)
            owners.setdefault(key, set()).add(direct.name)

    prod_direct_names = {d.name.lower() for d, _ in walkable if d.group == DependencyGroup.PROD}
    dev_direct_keys = {
        (d.name.lower(), pinned) for d, pinned in walkable if d.group == DependencyGroup.DEV
    }
    dev_direct_names = {name for name, _ in dev_direct_keys}
    # A DEV direct ships when a PROD direct pulls in the version it declares.
    _promote_directs_reached_from_prod(
        out, first_direct, {name for name, _ in dev_direct_keys & prod_owners.keys()}
    )

    for key, node_name in node_names.items():
        lower, node_version = key
        if lower in prod_direct_names or key in dev_direct_keys:
            # A direct's own row stands for the node: a PROD direct's for any
            # version of its artifact, a DEV direct's for the version it
            # declares (promoted above when a PROD direct pulls that in).
            continue
        if key in prod_owners:
            group, owners = DependencyGroup.PROD, prod_owners[key]
        elif lower in dev_direct_names:
            # Another version of a DEV direct, pulled in by DEV directs only.
            continue
        else:
            group, owners = DependencyGroup.DEV, dev_owners[key]

        # No emission-time ``include_dev`` filter here: DEV direct deps
        # are already filtered out of ``direct_uncovered`` upstream, so
        # ``dev_owners`` is empty when ``include_dev=False`` — no DEV
        # transitive can reach this point under that mode.

        out.append(
            Dependency(
                name=node_name,
                version_constraint=f"=={node_version}",
                ecosystem=Ecosystem.JAVA,
                group=group,
                depth=1,
                direct_ancestors=tuple(sorted(owners)),
                version_estimated=True,
            )
        )
    return out


def _fetch_go_edge_graph(
    entries: list[tuple[str, str]],
    client: httpx.Client,
    max_workers: int,
    go_mod_fetcher: _GoModFetcher,
) -> dict[str, set[str]]:
    """Fetch each module's go.mod from ``proxy.golang.org`` concurrently.

    Returns ``{lower(module_path): {lower(child_module_path), ...}}``: each
    module's ``require`` entries, without that module's own ``replace``
    directives. Modules whose proxy fetch fails get an empty edge set (treated as
    leaves by reverse-BFS — they still appear in the output via go.sum,
    but with no transitive contribution). ``go_mod_fetcher`` is decoupled
    from the JSON-API ``fetcher`` because proxy.golang.org serves plain
    text, not JSON — the default ``fetch_go_mod_text`` wraps the body as
    ``{"text": "..."}`` for shape uniformity with the registry-cache layer.
    """
    edges: dict[str, set[str]] = {}

    def _one(mod_ver: tuple[str, str]) -> tuple[str, set[str]]:
        module_path, version = mod_ver
        url = f"{_GO_PROXY_URL}/{encode_module_proxy_path(module_path)}/@v/{version}.mod"
        data = go_mod_fetcher(url, client)
        if not isinstance(data, dict):
            return (module_path.lower(), set())
        text = data.get("text", "")
        if not isinstance(text, str) or not text:
            return (module_path.lower(), set())
        # The ``replace`` directives of this go.mod are not applied: Go honours
        # them only in the main module, so the module's requirements are its
        # edges as written.
        requires, _replaces, _tools = _parse_go_mod(text)
        return (module_path.lower(), {req_path.lower() for req_path, _ in requires})

    # Propagate the active tethered scope into the go.mod-fetch workers — a bare
    # pool fetches in an empty context and bypasses the egress policy.
    # Results come back in ``entries`` order: when a module path is listed at
    # several versions, the last one's requirements are its edges.
    for name, children in map_with_context(_one, entries, max_workers):
        edges[name] = children
    return edges


def _walk_registry(
    seeds: list[Dependency],
    ecosystem: Ecosystem,
    *,
    project_path: Path,
    max_depth: int,
    client: httpx.Client,
    max_workers: int = 16,
    fetcher: Fetcher,
    on_wave: Callable[[int], None] | None = None,
    origins: Mapping[str, str | None] | None = None,
) -> list[Dependency]:
    """BFS from `seeds` via per-version dependency metadata.

    ``origins`` maps a lowercased package name to the origin a manifest
    redirects that package to (a Cargo ``[patch]``). A package the walk
    reaches under such a name is not the registry's: it is a row with that
    origin, and nothing is requested for it. A name mapped to ``None`` is
    the project's own code and is no row.

    Processes each BFS level in parallel via a ThreadPoolExecutor so multiple
    in-flight registry requests overlap. Wave dedup uses ``(name, spec)`` so
    *different* specs of the same name (e.g. ``lodash@^4`` and ``lodash@^3``)
    both get resolved and emitted — preserving version multiplicity which a
    license scanner needs to surface. Identical-spec duplicates within a wave
    are collapsed (true waste). The post-fetch ``visited`` check (keyed by
    resolved version) drops the case where two different specs happen to
    resolve to the same concrete version.

    A streaming variant (each completed task's children enqueued immediately,
    no wave boundary) was prototyped and measured slower than the wave
    structure on real large-scan workloads. Reason: wave boundaries create
    natural pauses between levels that keep us under PyPI's rate-limit
    threshold, while sustained streaming pressure trips the limiter more
    often, triggering 429 retries with backoff that outweigh any wave-stall
    savings.

    Most of the walker's real-world cost is duplicate URL fetches:
    on large dep graphs a majority of the walker's HTTP calls target a URL
    it has already pulled (different specs of the same name converge on the
    same ``/pypi/{name}/json`` etc.). A :class:`RegistryCache`-backed
    ``fetcher`` collapses those into one round-trip.

    Every row is marked ``version_estimated``, except a seed whose manifest
    pins it exactly: the walk picks the versions, no lockfile does.

    A node whose dependency list the registry did not give is a hole in the
    graph under every seed that reaches it. It is recorded as a gap on the
    manifests of those seeds (under ``project_path``), the node itself
    included when it is a seed.

    Records the graph it follows so that, after BFS terminates, every row can
    be stamped with its group and with the seeds that reach it. A node of
    that graph is a package at one resolved version (with its extras), not a
    package name: when ``lodash@^4`` and ``lodash@^3`` resolve to two
    versions, each row carries the seeds that pull in that version, and a
    version only a dev seed reaches is DEV even when production uses another
    one. Attribution by name would give a version reached through a dev seed
    the ancestors and the PROD group of the version production uses, so a
    walk seeded with dev deps would report more PROD rows than the same walk
    seeded without them.
    """
    # Dedup keys include `extras` because two paths reaching the same
    # (name, version) with different requested extras pull in *different*
    # `requires_dist` subsets — `pkg` vs `pkg[extra]` produces
    # different child sets. Without extras in the key, the second visit
    # would be silently skipped and we'd miss the extras-gated deps.
    # Python is the only ecosystem with extras; for npm/Rust deps.extras
    # is always the empty frozenset so the key collapses to the prior
    # shape and behavior is unchanged.
    # The origin is part of the key too: a dependency declared from a git
    # repository, a URL, or a path is not the registry package of that name.
    DedupKey = tuple[str, str, frozenset[str], str]  # noqa: N806  (PEP 695-style local type alias)

    def _key(dep: Dependency) -> DedupKey:
        return (dep.name.lower(), dep.version_constraint, dep.extras, dep.origin)

    visited: set[DedupKey] = set()
    out: list[Dependency] = []
    # The graph, for attribution after the walk. A node is a row of ``out``
    # and is keyed like one: by the version the row is emitted with.
    # ``node_of_spec`` maps every spec processed so far to the node it
    # resolved to (an unresolved spec is its own node); ``child_specs`` maps
    # each expanded node to the specs it requires.
    node_of_spec: dict[DedupKey, DedupKey] = {}
    child_specs: dict[DedupKey, list[DedupKey]] = {}
    # Nodes whose dependency list could not be read, with the name and
    # version to report them under.
    unread: dict[DedupKey, tuple[str, str]] = {}
    depth_capped = False
    progress_total = 0

    def _walk_one(snapshot: contextvars.Context, dep: Dependency) -> _WalkResult:
        result = snapshot.run(_walk_one_inner, dep, ecosystem, max_depth, client, fetcher)
        if not origins:
            return result
        walked, resolved_version, children, complete = result
        return (walked, resolved_version, _redirect_children(children, origins), complete)

    current_level: list[Dependency] = list(seeds)
    while current_level:
        wave: list[Dependency] = []
        seen_in_wave: set[DedupKey] = set()
        for dep in current_level:
            spec_key = _key(dep)
            if spec_key in node_of_spec or spec_key in seen_in_wave:
                continue
            seen_in_wave.add(spec_key)
            wave.append(dep)
        if not wave:
            break
        snapshots = [contextvars.copy_context() for _ in wave]
        worker_count = min(len(wave), max_workers)
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            results = list(pool.map(_walk_one, snapshots, wave))
        next_level: list[Dependency] = []
        for dep, resolved_version, children, complete in results:
            # Decided on the declared constraint, before it is rewritten to
            # the version picked for it. A transitive is always the walk's
            # pick; a seed is unless its manifest pins it exactly. A dep with
            # an origin has no version picked for it at all.
            estimated = not dep.origin and (dep.depth > 0 or not declares_exact_version(dep))
            if not resolved_version:
                node_of_spec[_key(dep)] = _key(dep)
                out.append(replace(dep, version_estimated=estimated))
                continue
            resolved = replace(
                dep, version_constraint=f"=={resolved_version}", version_estimated=estimated
            )
            node = node_of_spec[_key(dep)] = _key(resolved)
            if node in visited:
                continue
            visited.add(node)
            out.append(resolved)
            progress_total += 1
            if dep.depth >= max_depth:
                depth_capped = True
                continue
            if not complete:
                unread[node] = (dep.name, resolved_version)
            child_specs[node] = [_key(child) for child in children]
            next_level.extend(children)
        if on_wave is not None:
            on_wave(progress_total)
        current_level = next_level

    if depth_capped:
        click.echo(
            f"Warning: transitive walk for {ecosystem.value} hit max-depth={max_depth}; "
            "deeper deps may be missing.",
            err=True,
        )

    # Every child spec of an expanded node went through a later wave, and every
    # seed through the first, so each has a node.
    edges = {node: {node_of_spec[spec] for spec in specs} for node, specs in child_specs.items()}
    seed_roots = {node_of_spec[_key(seed)]: seed.name for seed in seeds}
    prod_roots = {
        node_of_spec[_key(seed)]: seed.name for seed in seeds if seed.group == DependencyGroup.PROD
    }
    ancestors = compute_direct_ancestors(edges, seed_roots)
    prod_reached = compute_direct_ancestors(edges, prod_roots)

    # Each unread node is a gap on every manifest one of whose seeds reaches
    # it. A manifest's reach is its seeds' own nodes plus what they lead to.
    if unread:
        for source in sorted({seed.source for seed in seeds}):
            roots = {node_of_spec[_key(seed)]: seed.name for seed in seeds if seed.source == source}
            reached = roots.keys() | compute_direct_ancestors(edges, roots).keys()
            _record_unread_dependencies(
                project_path, source, (unread[node] for node in unread.keys() & reached)
            )

    def _attributed_group(dep: Dependency) -> DependencyGroup:
        """A dep is PROD iff it is a prod seed or one reaches it; else a transitive is DEV.

        That holds for a seed too: a DEV seed that a PROD seed also pulls in,
        at the same version, ships with production. The walk emits it once,
        as the seed, so without this the PROD occurrence would be lost. A
        seed no prod seed reaches keeps its declared group.

        A transitive falls back to the BFS-assigned group when ancestor info
        is missing (cycle artifacts, disconnected nodes) so we never demote
        to DEV without evidence.
        """
        node = _key(dep)
        if node in prod_roots or node in prod_reached:
            return DependencyGroup.PROD
        if dep.depth == 0 or node not in ancestors:
            return dep.group
        return DependencyGroup.DEV

    return [
        replace(dep, group=_attributed_group(dep))
        if dep.depth == 0
        else replace(
            dep,
            direct_ancestors=ancestors.get(_key(dep), ()),
            group=_attributed_group(dep),
        )
        for dep in out
    ]


# (dep, resolved_version_or_empty, children, whether the children are the whole list)
_WalkResult = tuple[Dependency, str, list[Dependency], bool]


def _redirect_children(
    children: list[Dependency], origins: Mapping[str, str | None]
) -> list[Dependency]:
    """Give each child a manifest redirects its declared origin; drop own code."""
    out: list[Dependency] = []
    for child in children:
        key = child.name.lower()
        if key not in origins:
            out.append(child)
            continue
        origin = origins[key]
        if origin is not None:
            out.append(replace(child, origin=origin, version_constraint=""))
    return out


def _walk_one_inner(
    dep: Dependency,
    ecosystem: Ecosystem,
    max_depth: int,
    client: httpx.Client,
    fetcher: Fetcher,
) -> _WalkResult:
    """Resolve one BFS node: pick a version, then fetch its declared deps.

    A dependency with an origin is not a registry package: nothing is fetched
    for it, and it is a row as it stands.

    The last element of the result is False when the registry did not give
    the node's whole dependency list. A node that is not expanded (it has an
    origin, no version resolved for it, or it is at the depth cap) has
    nothing to be incomplete.
    """
    if dep.origin:
        return (dep, "", [], True)
    resolved_version = _resolve_version(dep, ecosystem, client, fetcher)
    if not resolved_version or dep.depth >= max_depth:
        return (dep, resolved_version, [], True)
    if ecosystem == Ecosystem.PYTHON:
        # Pass the dep's own extras so its requires_dist's `extra ==`
        # markers evaluate against the correct context: e.g. when this dep
        # was reached as `pkg[extra]`, we want the extra-gated deps to come out.
        children, complete = fetch_python_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
            requested_extras=dep.extras,
        )
    elif ecosystem == Ecosystem.RUST:
        children, complete = fetch_rust_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    elif ecosystem == Ecosystem.PHP:
        children, complete = fetch_packagist_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    elif ecosystem == Ecosystem.RUBY:
        children, complete = fetch_rubygems_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    elif ecosystem == Ecosystem.HEX:
        # `effective_registry_name` is the real hex.pm package for a `hex:`-
        # renamed dep, else just the name.
        children, complete = fetch_hex_dependencies(
            dep.effective_registry_name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    else:
        children, complete = fetch_npm_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    return (dep, resolved_version, children, complete)


def _resolve_version(
    dep: Dependency,
    ecosystem: Ecosystem,
    client: httpx.Client,
    fetcher: Fetcher,
) -> str:
    """Resolve a dep's version constraint to an exact version (best effort)."""
    spec = dep.version_constraint.strip()
    if ecosystem == Ecosystem.PYTHON:
        pinned = _extract_python_pinned_version(spec)
        if pinned:
            return pinned
        if not spec:
            data = fetcher(f"https://pypi.org/pypi/{dep.name}/json", client)
            if data is None:
                return ""
            v = object_field(data, "info").get("version", "")
            return v if isinstance(v, str) else ""
        # range — query project metadata, pick highest matching. `releases`
        # comes as a list[str] when served through `RegistryCache` (trimmed
        # for memory) and as a dict[str, ...] when fetched directly; iterate
        # either shape uniformly.
        data = fetcher(f"https://pypi.org/pypi/{dep.name}/json", client)
        if data is None:
            return ""
        releases = data.get("releases", [])
        keys = (
            [k for k in releases if isinstance(k, str)]
            if isinstance(releases, (dict, list))
            else []
        )
        return select_python_version(spec, keys) or ""

    if ecosystem == Ecosystem.RUST:
        pinned = _extract_rust_pinned_version(spec)
        if pinned:
            return pinned
        data = fetcher(f"https://crates.io/api/v1/crates/{dep.name}", client)
        if data is None:
            return ""
        crate = object_field(data, "crate")
        v = crate.get("max_stable_version") or crate.get("newest_version") or ""
        return v if isinstance(v, str) else ""

    if ecosystem == Ecosystem.PHP:
        pinned = _extract_php_pinned_version(spec)
        if pinned:
            return pinned.lstrip("v")
        data = fetcher(_packagist_url(dep.name), client)
        if data is None:
            return ""
        entries = _versions_from_response(data, dep.name)
        if not entries:
            return ""
        if not spec or spec == "*":
            first_version = entries[0].get("version", "")
            if isinstance(first_version, str):
                return first_version.lstrip("v")
            return ""
        published_versions: list[str] = []
        for entry in entries:
            v = entry.get("version")
            if isinstance(v, str):
                published_versions.append(v.lstrip("v"))
        return select_php_version(spec, published_versions) or ""

    if ecosystem == Ecosystem.RUBY:
        pinned = _extract_ruby_pinned_version(spec)
        if pinned:
            return pinned
        # Unpinned: ask the v1 latest-version endpoint. RubyGems doesn't
        # expose a Cargo-style ``max_stable_version`` field, but the v1
        # ``/gems/{name}.json`` body's top-level ``version`` is exactly that.
        data = fetcher(_rubygems_gem_url(dep.name), client)
        if data is None:
            return ""
        v = data.get("version", "")
        return v if isinstance(v, str) else ""

    if ecosystem == Ecosystem.HEX:
        pinned = _extract_hex_pinned_version(spec)
        if pinned:
            return pinned
        # Unpinned: read the package endpoint's latest_stable_version, under the
        # real hex.pm package name for a `hex:`-renamed dep.
        data = fetcher(_hex_package_url(dep.effective_registry_name), client)
        if not isinstance(data, dict):
            return ""
        return _latest_version(data)

    pinned = _extract_npm_pinned_version(spec)
    if pinned:
        return pinned
    if not spec:
        data = fetcher(f"https://registry.npmjs.org/{dep.name}/latest", client)
        if data is None:
            return ""
        v = data.get("version", "")
        return v if isinstance(v, str) else ""
    data = fetcher(f"https://registry.npmjs.org/{dep.name}", client)
    if data is None:
        return ""
    return resolve_npm_spec(data, spec)


_PYTHON_NAME_NORMALIZE_RE = re.compile(r"[-_.]+")


def _canonical_name(dep: Dependency) -> str:
    """Return the dedupe-stable name for ``dep``.

    PEP 503 folds runs of ``-``, ``_``, and ``.`` in Python package names to
    a single ``-`` and lowercases, so ``foo-bar``, ``foo_bar``, and
    ``foo.bar`` all refer to the same PyPI distribution. npm / Rust have no
    equivalent rule (``my-pkg`` and ``my_pkg`` are different packages on
    those registries), so for them we only lowercase.
    """
    if dep.ecosystem == Ecosystem.PYTHON:
        return _PYTHON_NAME_NORMALIZE_RE.sub("-", dep.name).lower()
    return dep.name.lower()


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    """Deduplicate by (ecosystem, canonical-name, version_constraint, origin).

    The origin is part of the key: two commits of one repository that declare
    the same version are two rows, and so are a registry package and a git
    dependency of the same name.

    Direct deps (depth=0) take precedence over transitive entries with the same
    name+version, so a dep declared at the top level keeps an empty
    `direct_ancestors` (it IS direct). For transitive winners, ancestors from
    every duplicate entry are unioned so a dep reached by multiple paths
    accumulates all of them.

    Group follows production precedence: when any duplicate is PROD the
    winner is PROD, whichever entry came first. Two lockfiles can attribute
    the same package differently (dev-only in one subproject, shipped by
    another), and the result must not depend on the order they were read in.

    A version is estimated only when every duplicate is: a lockfile entry or
    an exact pin for the same version fixes it, whichever entry came first.

    When the same (ecosystem, name) appears with both resolved (``==X.Y.Z``)
    and unresolved specs, the unresolved variants are dropped. They arise
    when the registry walker resolves one occurrence successfully (e.g. from
    a manifest with ``^4.17.21``) but fails on a parallel occurrence (e.g.
    from a peerDep with ``^4 || ^5`` the registry returned a 404 for); the
    unresolved entry is a phantom of the resolved one, not a distinct package.
    Ancestors from any dropped unresolved entries are still merged into the
    surviving resolved entries so reachability info isn't lost.
    """
    filtered = _drop_phantom_unresolved(deps)

    chosen: dict[tuple[Ecosystem, str, str, str], Dependency] = {}
    merged: dict[tuple[Ecosystem, str, str, str], set[str]] = {}
    prod_keys: set[tuple[Ecosystem, str, str, str]] = set()
    exact_keys: set[tuple[Ecosystem, str, str, str]] = set()
    for dep in filtered:
        key = (dep.ecosystem, _canonical_name(dep), dep.version_constraint, dep.origin)
        existing = chosen.get(key)
        if existing is None or existing.depth > dep.depth:
            chosen[key] = dep
        merged.setdefault(key, set()).update(dep.direct_ancestors)
        if dep.group == DependencyGroup.PROD:
            prod_keys.add(key)
        if not dep.version_estimated:
            exact_keys.add(key)

    out: list[Dependency] = []
    used: set[tuple[Ecosystem, str, str, str]] = set()
    for dep in filtered:
        key = (dep.ecosystem, _canonical_name(dep), dep.version_constraint, dep.origin)
        if key in used:
            continue
        used.add(key)
        winner = chosen[key]
        if key in prod_keys:
            winner = replace(winner, group=DependencyGroup.PROD)
        if key in exact_keys:
            winner = replace(winner, version_estimated=False)
        if winner.depth == 0:
            out.append(winner)
        else:
            out.append(replace(winner, direct_ancestors=tuple(sorted(merged[key]))))
    return out


def _drop_phantom_unresolved(deps: list[Dependency]) -> list[Dependency]:
    """For each (ecosystem, name), if any entry is pinned (``==X.Y.Z``),
    drop entries that aren't pinned and merge their ancestors into the
    surviving resolved entries.

    Name normalization is PEP 503 for Python (so dash/underscore/dot
    variants of the same distribution name collide) — a discovery-side
    unresolved entry can then phantom-drop against a lockfile-side pinned
    entry even if they spell the name differently.

    An entry with an origin is neither: it is not the registry package of its
    name, so it is never dropped in favour of a pinned one and never makes an
    unpinned registry entry a phantom.
    """
    resolved_names: set[tuple[Ecosystem, str]] = {
        (d.ecosystem, _canonical_name(d))
        for d in deps
        if d.version_constraint.startswith("==") and not d.origin
    }

    phantom_ancestors: dict[tuple[Ecosystem, str], set[str]] = {}
    survivors: list[Dependency] = []
    for dep in deps:
        key = (dep.ecosystem, _canonical_name(dep))
        is_pinned = dep.version_constraint.startswith("==")
        if not is_pinned and not dep.origin and key in resolved_names:
            phantom_ancestors.setdefault(key, set()).update(dep.direct_ancestors)
            continue
        survivors.append(dep)

    if not phantom_ancestors:
        return survivors

    return [
        replace(
            d,
            direct_ancestors=tuple(
                sorted(
                    set(d.direct_ancestors)
                    | phantom_ancestors.get((d.ecosystem, _canonical_name(d)), set())
                )
            ),
        )
        if d.version_constraint.startswith("==")
        and not d.origin
        and (d.ecosystem, _canonical_name(d)) in phantom_ancestors
        else d
        for d in survivors
    ]
