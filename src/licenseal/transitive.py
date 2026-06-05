"""Transitive dependency resolution.

Strategy: lockfile-first, with recursive registry walk as fallback. When a
lockfile is present (`uv.lock`, `poetry.lock`, `Pipfile.lock`,
`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`), we parse it directly —
that's the actually-shipped graph. Without a lockfile, we BFS from the
manifest's direct deps via the registry's per-version dependency metadata.

Notes on registry-recursion fallback:

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
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import click
import httpx

from licenseal._concurrency import map_with_context
from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._read import read_xml_bytes, record_parse_failure
from licenseal.discovery.dotnet import (
    discover_nuget_lockfile_dependencies,
    find_paket_lockfiles,
    parse_paket_lock,
)
from licenseal.discovery.dotnet.csproj import (
    _discover_workspace_local_project_ids,
)
from licenseal.discovery.go.go_mod import (
    _discover_workspace_local_module_paths,  # noqa: PLC2701
    _parse_go_mod,  # noqa: PLC2701
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
from licenseal.discovery.hex.mix_lock import (
    is_off_registry_marker as _is_hex_off_registry,
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
from licenseal.discovery.ruby.lockfiles import (
    is_off_registry_marker as _is_ruby_off_registry,
)
from licenseal.discovery.rust.lockfiles import find_rust_lockfiles, parse_cargo_lock
from licenseal.models import Dependency, DependencyGroup, Ecosystem
from licenseal.resolvers.cran import CranIndex, fetch_cran_index, index_edge_names
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
    ecosystem, fall back to recursive registry resolution.

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
        return _walk_registry(
            uncovered,
            ecosystem,
            max_depth=max_depth,
            client=client,
            max_workers=max_workers,
            fetcher=fetcher,
            on_wave=on_wave,
        )

    if Ecosystem.PYTHON in ecosystems_present:
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
                        )
                    )
                )
            out.extend(locked)
            out.extend(_walk_uncovered(Ecosystem.PYTHON, locked, set()))
            handled.add(Ecosystem.PYTHON)

    if Ecosystem.NPM in ecosystems_present:
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
                        )
                    )
                )
            out.extend(locked)
            out.extend(_walk_uncovered(Ecosystem.NPM, locked, set()))
            handled.add(Ecosystem.NPM)

    if Ecosystem.RUST in ecosystems_present:
        rust_locks = find_rust_lockfiles(project_path, exclude_paths=exclude_paths)
        if rust_locks:
            locked = []
            rust_known_names: set[str] = set()
            for rust_lock in rust_locks:
                lock_deps, lock_known = parse_cargo_lock(
                    rust_lock,
                    prod_root_names=names_by_group(Ecosystem.RUST, DependencyGroup.PROD),
                    dev_root_names=names_by_group(Ecosystem.RUST, DependencyGroup.DEV),
                    include_dev=include_dev,
                )
                locked.extend(_stamp_sources(lock_deps))
                rust_known_names.update(lock_known)
            out.extend(locked)
            out.extend(_walk_uncovered(Ecosystem.RUST, locked, rust_known_names))
            handled.add(Ecosystem.RUST)

    if Ecosystem.JAVA in ecosystems_present:
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

    if Ecosystem.DOTNET in ecosystems_present:
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

    if Ecosystem.PHP in ecosystems_present:
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
            for composer_lock in composer_locks:
                lock_deps, _license_map = parse_composer_lockfile(
                    composer_lock,
                    direct_names=direct_php_names,
                    include_dev=include_dev,
                )
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
            out.extend(_walk_uncovered(Ecosystem.PHP, locked, set()))
            handled.add(Ecosystem.PHP)

    if Ecosystem.RUBY in ecosystems_present:
        # Ruby transitive resolution: Gemfile.lock is authoritative when
        # present — the GEM/GIT/PATH/DEPENDENCIES grammar carries the
        # full edge graph in a fully static format. Group attribution
        # comes from the Gemfile (Gemfile.lock has no dev/prod marker
        # of its own); we collect the DEV-only direct names from
        # discovery and propagate via reverse-BFS in the lockfile parser.
        gemfile_locks = find_gemfile_lockfiles(project_path, exclude_paths=exclude_paths)
        if gemfile_locks:
            ruby_workspace = workspace_gemspec_names(project_path, exclude_paths=exclude_paths)
            direct_ruby_names = {
                d.name.lower() for d in direct_deps if d.ecosystem == Ecosystem.RUBY
            }
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
                )
                # Drop workspace-internal lockfile entries — monorepo
                # siblings (one in-tree gem referencing another) are not
                # published gems we'd want to look up.
                lock_deps = [d for d in lock_deps if d.name.lower() not in ruby_workspace]
                locked.extend(_attach_ruby_direct_sources(lock_deps, direct_source_by_name))
            out.extend(locked)
            out.extend(_walk_uncovered(Ecosystem.RUBY, locked, set()))
            handled.add(Ecosystem.RUBY)

    if Ecosystem.HEX in ecosystems_present:
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
    # DESCRIPTION — analysis projects, Shiny apps — so a project can be
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

    if Ecosystem.GO in ecosystems_present:
        # Go's transitive resolution: parse go.sum for the universe of
        # pinned modules; fetch each module's go.mod from proxy.golang.org
        # concurrently to build the edge graph; run reverse-BFS for
        # reachability-based group + ancestor attribution. Same machinery
        # the other ecosystems use — the only Go-specific cost is the
        # extra fetch per module (go.sum has no edges; deps.dev's
        # ``GetDependencies`` endpoint isn't available for Go — only npm,
        # Cargo, Maven, PyPI per Google's docs; the Go module proxy is
        # the canonical source the ``go`` toolchain itself consults).
        direct_go_deps = [d for d in direct_deps if d.ecosystem == Ecosystem.GO]
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
        walked = _walk_registry(
            seeds,
            ecosystem,
            max_depth=max_depth,
            client=client,
            max_workers=max_workers,
            fetcher=fetcher,
            on_wave=on_wave,
        )
        out.extend(walked)

    return _dedupe(out)


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
      1. Discover the pinned-module universe from ``go.sum`` (or just the
         direct deps if no go.sum is present).
      2. Fetch each module's ``go.mod`` from ``proxy.golang.org`` to learn
         its direct require edges. Best-effort: proxy fetches that fail
         leave that module as a leaf in the edge graph (no outgoing edges).
      3. Build the edge dict (lowercased names) and run
         :func:`compute_direct_ancestors` from PROD-root and DEV-root direct
         deps. Resulting attribution mirrors the npm/Rust/Python lockfile
         path: reachable from a PROD root → PROD; only from a DEV root →
         DEV; orphaned → fall back to PROD (conservative).
      4. Apply ``--no-dev`` filter using the reachability result.

    Direct go deps carry their group already (PROD by default; DEV when
    matched by ``tool`` directive in ``go_mod.py``).
    """
    direct_module_paths = {d.name for d in direct_go_deps}
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

    # ---- 1. enumerate the pinned-module universe ----
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
    if not entries:
        # No go.sum (or empty) — fall back to the direct deps from go.mod.
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
    edges = _fetch_go_edge_graph(entries, client, max_workers, go_mod_fetcher)

    # ---- 3. attribute group + direct_ancestors ----
    # name_case preserves the original-case module path so the reverse-BFS's
    # ancestor labels match the labels in the report.
    name_case = {mod.lower(): mod for mod, _ in entries}
    # Direct module paths must be in name_case too (they're always in entries
    # via the go.sum + direct-fallback above, but be defensive).
    for d in direct_go_deps:
        name_case.setdefault(d.name.lower(), d.name)
    prod_roots = {n: name_case[n] for n in prod_root_names if n in name_case}
    dev_roots = {n: name_case[n] for n in dev_root_names if n in name_case}
    prod_anc = compute_direct_ancestors(edges, prod_roots)
    dev_anc = compute_direct_ancestors(edges, dev_roots)

    direct_source_by_name = {d.name.lower(): d.source for d in direct_go_deps if d.source}

    out: list[Dependency] = []
    for module_path, version in entries:
        lower = module_path.lower()
        is_direct = module_path in direct_module_paths
        if lower in prod_root_names:
            group = DependencyGroup.PROD
            ancestors: tuple[str, ...] = ()
        elif lower in dev_root_names:
            group = DependencyGroup.DEV
            ancestors = ()
        elif lower in prod_anc:
            group = DependencyGroup.PROD
            ancestors = prod_anc[lower]
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
                source=direct_source_by_name.get(lower, "") if is_direct else "",
            )
        )
    return out


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
    version-stable). Direct deps absent from the index (off-CRAN / archived) are
    still seeded so they surface and resolve to UNKNOWN at the license stage.
    Attribution reuses :func:`build_lock_dependencies`: direct deps are the
    roots, the Suggests/Enhances subset the dev roots.
    """
    spec_info: dict[str, tuple[str, str, bool]] = {}
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
        spec_info[lower] = (orig, version, False)

    for dep in direct_deps:
        _seed(dep.name)

    frontier = prod_roots | dev_roots
    seen: set[str] = set(frontier)
    while frontier:
        nxt: set[str] = set()
        for node in frontier:
            record = cran_index.get(node)
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

    return build_lock_dependencies(
        spec_info,
        edges,
        direct_names=prod_roots | dev_roots,
        dev_direct_names=dev_roots,
        include_dev=include_dev,
    )


# A transitive deps fetcher returns ``(nodes, edges)``: ``nodes`` is a list of
# ``(name, version)`` and ``edges`` is a list of ``(parent_name, parent_version,
# child_name, child_version)``. Maven and NuGet fetchers share this shape, so
# they share this ecosystem-neutral alias rather than borrowing each other's name.
_TransitiveDepsFetcher = Callable[
    ...,
    tuple[list[tuple[str, str]], list[tuple[str, str, str, str]]],
]


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
       across TFMs per the locked-in plan decision; each lockfile carries
       enough edge data for ``compute_direct_ancestors`` to attribute
       group + ancestors via reachability.

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
    nuget_lockfile_deps, _ = discover_nuget_lockfile_dependencies(
        project_path, exclude_paths=exclude_paths
    )
    direct_dotnet_names_lower = {d.name.lower() for d in direct_dotnet_deps}
    for dep in nuget_lockfile_deps:
        if dep.name.lower() in workspace_local_lower:
            continue
        lower = dep.name.lower()
        if lower in direct_dotnet_names_lower:
            matching_direct = next(d for d in direct_dotnet_deps if d.name.lower() == lower)
            if not include_dev and matching_direct.group == DependencyGroup.DEV:
                continue
            covered_names.add(lower)
            out.append(
                Dependency(
                    name=dep.name,
                    version_constraint=dep.version_constraint,
                    ecosystem=Ecosystem.DOTNET,
                    group=matching_direct.group,
                    source=matching_direct.source,
                )
            )
        else:
            covered_names.add(lower)
            out.append(
                Dependency(
                    name=dep.name,
                    version_constraint=dep.version_constraint,
                    ecosystem=Ecosystem.DOTNET,
                    group=DependencyGroup.PROD,
                    depth=1,
                )
            )

    # ---- Paket lockfile path ----
    for paket_lock in find_paket_lockfiles(project_path, exclude_paths=exclude_paths):
        for dep in parse_paket_lock(paket_lock, project_path=project_path):
            if dep.name.lower() in workspace_local_lower:
                continue
            if not include_dev and dep.group == DependencyGroup.DEV:
                continue
            lower = dep.name.lower()
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

    # Direct deps whose version parses to a concrete NuGet pin can be
    # walked; ones that don't (unresolved $() tokens, floating versions)
    # still surface in the output so the license resolver sees them.
    walkable: list[tuple[Dependency, str]] = []
    for d in direct_uncovered:
        pinned = _extract_pinned_version_nuget(d.version_constraint)
        if pinned is None:
            out.append(d)
            continue
        walkable.append((d, pinned))
        out.append(replace(d, version_constraint=f"=={pinned}"))

    if not walkable:
        return out

    merged_nodes: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}

    def _one(
        entry: tuple[Dependency, str],
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str, str, str]]]:
        direct, pinned = entry
        return deps_fetcher(direct.name, pinned, client, fetcher=fetcher)

    # Propagate the active tethered scope into the edge-fetch workers — a bare
    # pool fetches in an empty context and bypasses the egress policy.
    for nodes, edge_tuples in map_with_context(_one, walkable, max_workers):
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
                version_constraint=f"=={node_version}",
                ecosystem=Ecosystem.DOTNET,
                group=group,
                depth=1,
                direct_ancestors=ancestors,
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
    """Edge-aware Java transitive resolution.

    Two-path:

    1. **Gradle lockfile** (``gradle.lockfile``): when present, the
       file-line entries give the full resolved-version set with
       classpath-based group attribution. No registry calls needed for
       what the lockfile covers. Multi-project Gradle builds may carry
       one lockfile per subproject; we union them.

    2. **deps.dev ``:dependencies``**: for direct Java deps not in any
       Gradle lockfile, hit ``api.deps.dev``'s MAVEN ``GetDependencies``
       endpoint per direct dep, in parallel. The response is the
       fully-resolved subgraph rooted at that dep; merge subgraphs
       across all directs, dedupe by ``(name, version)``, then run
       :func:`compute_direct_ancestors` from PROD-root and DEV-root
       directs for reachability-based attribution (same machinery as
       the Go path).

    Workspace-local filter: multi-module Maven projects link parent →
    submodule via ``<modules>``; sibling artifact coordinates aren't
    published on Maven Central, so any in-tree ``groupId:artifactId``
    is filtered from both lockfile output and the deps.dev walk's nodes.

    Direct deps whose ``version_constraint`` doesn't parse to a concrete
    Maven pin (range syntax, unresolved ``${…}``, …) are emitted as-is
    so the license resolver gets a chance with the raw value — it'll
    typically UNKNOWN out, which is the right signal.

    Orphan transitives (reachable from no direct root, usually because
    one direct's ``:dependencies`` fetch failed) fall back to PROD —
    conservative, same as the Go path.

    ``deps_fetcher`` returns a structured ``(nodes, edges)`` tuple rather
    than a raw response dict, so the ``fetcher`` JSON-fetcher is passed
    *into* it as a keyword arg — the cache trim ``_trim_deps_dev_dependencies``
    runs against the URL-keyed cache that wraps it. Tests inject a custom
    ``deps_fetcher`` to drive the merge / reachability paths without
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
    if not direct_uncovered:
        return out

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
        if not d.source:
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
    # surface in the output so the license resolver sees them.
    walkable: list[tuple[Dependency, str]] = []
    for d in direct_uncovered:
        pinned = _extract_pinned_version_maven(d.version_constraint)
        if pinned is None:
            out.append(d)
            continue
        walkable.append((d, pinned))
        out.append(replace(d, version_constraint=f"=={pinned}"))

    if not walkable:
        return out

    merged_nodes: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {}

    def _one(
        entry: tuple[Dependency, str],
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str, str, str]]]:
        direct, pinned = entry
        return deps_fetcher(direct.name, pinned, client, fetcher=fetcher)

    # Propagate the active tethered scope into the edge-fetch workers — a bare
    # pool fetches in an empty context and bypasses the egress policy.
    for nodes, edge_tuples in map_with_context(_one, walkable, max_workers):
        for node_name, node_version in nodes:
            if node_name in workspace_local:
                continue
            merged_nodes.add((node_name, node_version))
        for from_name, _from_ver, to_name, _to_ver in edge_tuples:
            if from_name in workspace_local or to_name in workspace_local:
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

    direct_lower = {d.name.lower() for d, _ in walkable}
    for node_name, node_version in merged_nodes:
        lower = node_name.lower()
        if lower in direct_lower:
            # Already emitted as a direct dep above. Skip — we don't
            # want to double-emit at depth=1.
            continue
        if lower in prod_anc:
            group = DependencyGroup.PROD
            ancestors = prod_anc[lower]
        elif lower in dev_anc:
            group = DependencyGroup.DEV
            ancestors = dev_anc[lower]
        else:
            # Orphan: reachable from no root. Conservative PROD default,
            # mirrors the Go-side fallback for the same scenario.
            group = DependencyGroup.PROD
            ancestors = ()

        # No emission-time ``include_dev`` filter here: DEV direct deps
        # are already filtered out of ``direct_uncovered`` upstream, so
        # ``dev_roots`` and ``dev_anc`` are empty when ``include_dev=False``
        # — no DEV transitive can reach this point under that mode.

        out.append(
            Dependency(
                name=node_name,
                version_constraint=f"=={node_version}",
                ecosystem=Ecosystem.JAVA,
                group=group,
                depth=1,
                direct_ancestors=ancestors,
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

    Returns ``{lower(module_path): {lower(child_module_path), ...}}``.
    Modules whose proxy fetch fails get an empty edge set (treated as
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
        requires, replaces, _tools = _parse_go_mod(text)
        children: set[str] = set()
        for req_path, _req_version in requires:
            target = replaces.get(req_path, (req_path, _req_version))
            if target is None:
                continue
            children.add(target[0].lower())
        return (module_path.lower(), children)

    # Propagate the active tethered scope into the go.mod-fetch workers — a bare
    # pool fetches in an empty context and bypasses the egress policy.
    for name, children in map_with_context(_one, entries, max_workers):
        edges[name] = children
    return edges


def _walk_registry(
    seeds: list[Dependency],
    ecosystem: Ecosystem,
    *,
    max_depth: int,
    client: httpx.Client,
    max_workers: int = 16,
    fetcher: Fetcher,
    on_wave: Callable[[int], None] | None = None,
) -> list[Dependency]:
    """BFS from `seeds` via per-version dependency metadata.

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

    Records the parent->child edge graph (by lowercased name) during the walk
    so that, after BFS terminates, we can reverse-traverse from each seed to
    stamp every transitive with the set of direct ancestors that reach it.
    Tracking edges by name (not by resolved version) is intentional: callers
    want "which direct dep brings in `certifi`", and answering at the name
    level survives version multiplicity.
    """
    # Dedup keys include `extras` because two paths reaching the same
    # (name, version) with different requested extras pull in *different*
    # `requires_dist` subsets — `pkg` vs `pkg[extra]` produces
    # different child sets. Without extras in the key, the second visit
    # would be silently skipped and we'd miss the extras-gated deps.
    # Python is the only ecosystem with extras; for npm/Rust deps.extras
    # is always the empty frozenset so the key collapses to the prior
    # shape and behavior is unchanged.
    DedupKey = tuple[str, str, frozenset[str]]  # noqa: N806  (PEP 695-style local type alias)
    visited: set[DedupKey] = set()
    processed_specs: set[DedupKey] = set()
    out: list[Dependency] = []
    edges: dict[str, set[str]] = {}
    seed_name_case: dict[str, str] = {s.name.lower(): s.name for s in seeds}
    # Per-name group of seed deps. Used after BFS to attribute each
    # transitive's group by *reachability* (prod-reachable wins) rather than
    # by BFS-arrival order — important when a transitive is reached via both
    # prod and dev chains, where the original arrival order would otherwise
    # silently bury the prod attribution.
    seed_groups: dict[str, DependencyGroup] = {s.name.lower(): s.group for s in seeds}
    depth_capped = False
    progress_total = 0

    def _walk_one(snapshot: contextvars.Context, dep: Dependency) -> _WalkResult:
        return snapshot.run(_walk_one_inner, dep, ecosystem, max_depth, client, fetcher)

    current_level: list[Dependency] = list(seeds)
    while current_level:
        wave: list[Dependency] = []
        seen_in_wave: set[DedupKey] = set()
        for dep in current_level:
            spec_key = (dep.name.lower(), dep.version_constraint, dep.extras)
            if spec_key in processed_specs or spec_key in seen_in_wave:
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
        for dep, resolved_version, children in results:
            processed_specs.add((dep.name.lower(), dep.version_constraint, dep.extras))
            if not resolved_version:
                out.append(dep)
                continue
            key = (dep.name.lower(), resolved_version, dep.extras)
            if key in visited:
                continue
            visited.add(key)
            out.append(replace(dep, version_constraint=f"=={resolved_version}"))
            progress_total += 1
            if dep.depth >= max_depth:
                depth_capped = True
                continue
            edges.setdefault(dep.name.lower(), set()).update(c.name.lower() for c in children)
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

    ancestors = compute_direct_ancestors(edges, seed_name_case)
    prod_seed_names: set[str] = {
        name for name, group in seed_groups.items() if group == DependencyGroup.PROD
    }

    def _attributed_group(transitive: Dependency) -> DependencyGroup:
        """A transitive is PROD iff any prod seed reaches it; else DEV.

        Falls back to the BFS-assigned group when ancestor info is missing
        (cycle artifacts, disconnected nodes) so we never demote to DEV
        without evidence.
        """
        own_ancestors = ancestors.get(transitive.name.lower(), ())
        if not own_ancestors:
            return transitive.group
        if any(a.lower() in prod_seed_names for a in own_ancestors):
            return DependencyGroup.PROD
        return DependencyGroup.DEV

    return [
        dep
        if dep.depth == 0
        else replace(
            dep,
            direct_ancestors=ancestors.get(dep.name.lower(), ()),
            group=_attributed_group(dep),
        )
        for dep in out
    ]


# (dep, resolved_version_or_empty, children)
_WalkResult = tuple[Dependency, str, list[Dependency]]


def _walk_one_inner(
    dep: Dependency,
    ecosystem: Ecosystem,
    max_depth: int,
    client: httpx.Client,
    fetcher: Fetcher,
) -> _WalkResult:
    """Resolve one BFS node: pick a version, then fetch its declared deps."""
    resolved_version = _resolve_version(dep, ecosystem, client, fetcher)
    if not resolved_version or dep.depth >= max_depth:
        return (dep, resolved_version, [])
    if ecosystem == Ecosystem.PYTHON:
        # Pass the dep's own extras so its requires_dist's `extra ==`
        # markers evaluate against the correct context: e.g. when this dep
        # was reached as `pkg[extra]`, we want the extra-gated deps to come out.
        children = fetch_python_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
            requested_extras=dep.extras,
        )
    elif ecosystem == Ecosystem.RUST:
        children = fetch_rust_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    elif ecosystem == Ecosystem.PHP:
        children = fetch_packagist_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    elif ecosystem == Ecosystem.RUBY:
        # Off-registry gems never reach here: _resolve_version returns "" for
        # them, so the ``not resolved_version`` early-return above fires first.
        children = fetch_rubygems_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    elif ecosystem == Ecosystem.HEX:
        # Off-registry deps never reach here (same reason as Ruby above).
        # `effective_registry_name` is the real hex.pm package for a `hex:`-
        # renamed dep, else just the name.
        children = fetch_hex_dependencies(
            dep.effective_registry_name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    else:
        children = fetch_npm_dependencies(
            dep.name,
            resolved_version,
            client,
            parent_depth=dep.depth,
            parent_group=dep.group,
            fetcher=fetcher,
        )
    return (dep, resolved_version, children)


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
            info = data.get("info", {}) or {}
            v = info.get("version", "")
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
        crate = data.get("crate", {}) or {}
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
        if _is_ruby_off_registry(dep.source):
            return ""
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
        if _is_hex_off_registry(dep.source):
            return ""
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
    """Deduplicate by (ecosystem, canonical-name, version_constraint).

    Direct deps (depth=0) take precedence over transitive entries with the same
    name+version, so a dep declared at the top level keeps an empty
    `direct_ancestors` (it IS direct). For transitive winners, ancestors from
    every duplicate entry are unioned so a dep reached by multiple paths
    accumulates all of them.

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

    chosen: dict[tuple[Ecosystem, str, str], Dependency] = {}
    merged: dict[tuple[Ecosystem, str, str], set[str]] = {}
    for dep in filtered:
        key = (dep.ecosystem, _canonical_name(dep), dep.version_constraint)
        existing = chosen.get(key)
        if existing is None or existing.depth > dep.depth:
            chosen[key] = dep
        merged.setdefault(key, set()).update(dep.direct_ancestors)

    out: list[Dependency] = []
    used: set[tuple[Ecosystem, str, str]] = set()
    for dep in filtered:
        key = (dep.ecosystem, _canonical_name(dep), dep.version_constraint)
        if key in used:
            continue
        used.add(key)
        winner = chosen[key]
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
    """
    resolved_names: set[tuple[Ecosystem, str]] = {
        (d.ecosystem, _canonical_name(d)) for d in deps if d.version_constraint.startswith("==")
    }

    phantom_ancestors: dict[tuple[Ecosystem, str], set[str]] = {}
    survivors: list[Dependency] = []
    for dep in deps:
        key = (dep.ecosystem, _canonical_name(dep))
        is_pinned = dep.version_constraint.startswith("==")
        if not is_pinned and key in resolved_names:
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
        and (d.ecosystem, _canonical_name(d)) in phantom_ancestors
        else d
        for d in survivors
    ]
