"""CLI entry point for licenseal."""

from __future__ import annotations

import contextvars
import hashlib
import sys
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import files
from pathlib import Path

import click
import httpx
import tethered
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from licenseal.analysis.compatibility import analyze, check_compatibility
from licenseal.discovery import detect_project_license, discover_all_dependencies
from licenseal.discovery._read import ReadDiagnostic, collect_read_diagnostics
from licenseal.discovery._walk import shared_walk_cache
from licenseal.discovery.php.lockfiles import (
    LockfileLicenseMap,
    extract_composer_lock_licenses,
    find_composer_lockfiles,
)
from licenseal.discovery.ruby.lockfiles import (
    is_off_registry_marker as _ruby_is_off_registry,
)
from licenseal.models import (
    AnalysisReport,
    CompatibilityVerdict,
    Dependency,
    DependencyGroup,
    Ecosystem,
    LicenseInfo,
    ReportDiagnostic,
)
from licenseal.report import render_json, render_markdown, render_table
from licenseal.resolvers.cran import fetch_cran_index, resolve_r_license
from licenseal.resolvers.crates_io import (
    _extract_pinned_version as _extract_rust_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.crates_io import resolve_rust_license
from licenseal.resolvers.deps_dev import (
    _extract_maven_pinned_version,  # noqa: PLC2701
    bulk_resolve_licenses,
    resolve_go_license,
)
from licenseal.resolvers.deps_dev import (
    _extract_pinned_version as _extract_go_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.hex import resolve_hex_license
from licenseal.resolvers.http import RegistryCache
from licenseal.resolvers.maven_central import resolve_maven_central_license
from licenseal.resolvers.npm_registry import (
    _extract_pinned_version as _extract_npm_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.npm_registry import resolve_npm_license
from licenseal.resolvers.nuget import (
    _extract_pinned_version_nuget,  # noqa: PLC2701
    resolve_nuget_license,
)
from licenseal.resolvers.packagist import resolve_php_license
from licenseal.resolvers.pypi import (
    _extract_pinned_version as _extract_python_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.pypi import resolve_python_license
from licenseal.resolvers.rubygems import (
    _extract_pinned_version as _extract_ruby_pinned_version,  # noqa: PLC2701
)
from licenseal.resolvers.rubygems import resolve_ruby_license
from licenseal.review import (
    REVIEW_FILE_NAME,
    apply_reviewed_licenses,
    flagged_entries_from_json_report,
    flagged_entries_from_results,
    load_review_file,
    merge_review_template,
    render_review_template,
    review_key,
)
from licenseal.transitive import resolve_transitive

_STDERR_CONSOLE = Console(stderr=True)

_DEFAULT_MAX_WORKERS = 16
_REGISTRY_HOSTS = [
    "pypi.org:443",
    "files.pythonhosted.org:443",
    "registry.npmjs.org:443",
    "crates.io:443",
    "api.deps.dev:443",
    "proxy.golang.org:443",
    "repo.maven.apache.org:443",
    # Fallback Maven registries — queried only when Maven Central 404s on
    # a parent POM. See :data:`maven_central._FALLBACK_POM_REGISTRIES`
    # and SECURITY.md for the inclusion criterion. tethered allow rules are
    # host:port-granular, so ``dl.google.com:443`` permits the whole host even
    # though licenseal only ever requests its ``/dl/android/maven2`` path — it
    # is the broadest entry here, included solely for that Maven mirror.
    "dl.google.com:443",
    "repo.jenkins-ci.org:443",
    # NuGet flatcontainer — canonical .NET package registry. Serves the
    # raw .nuspec XML at the v3-flatcontainer endpoint; see
    # :mod:`resolvers.nuget` and SECURITY.md.
    "api.nuget.org:443",
    # Packagist v2 metadata — canonical Composer / PHP package registry.
    # Serves per-package version-history JSON at /p2/{vendor}/{package}.json.
    # Donation-funded; the PHP resolver is lockfile-first to minimise load.
    "repo.packagist.org:443",
    # RubyGems v2/v1 metadata — canonical Ruby package registry. Serves
    # per-version JSON at /api/v2/rubygems/{name}/versions/{version}.json
    # and latest-version JSON at /api/v1/gems/{name}.json. See SECURITY.md.
    "rubygems.org:443",
    # hex.pm — canonical Hex (Elixir / Erlang) package registry. Serves
    # package metadata at /api/packages/{name} (license + links + latest
    # version) and release edges at /api/packages/{name}/releases/{version}.
    # deps.dev does not index Hex, so this is the only source. See SECURITY.md.
    "hex.pm:443",
    # cran.r-project.org — official CRAN. licenseal fetches the PACKAGES index
    # (License + dependency edges for every current package) once per scan and
    # resolves all R packages locally from it — no per-package requests, no
    # community mirror. deps.dev does not index CRAN. See SECURITY.md.
    "cran.r-project.org:443",
]
_REQUEST_TIMEOUT_SECONDS = 10.0
_PROJECT_URL = "https://github.com/shcherbak-ai/licenseal"
_TETHERED_HINT = (
    f"licenseal requires pypi.org:443, files.pythonhosted.org:443, "
    f"registry.npmjs.org:443, crates.io:443, api.deps.dev:443, "
    f"proxy.golang.org:443, repo.maven.apache.org:443, "
    f"dl.google.com:443, repo.jenkins-ci.org:443, api.nuget.org:443, "
    f"repo.packagist.org:443, rubygems.org:443, hex.pm:443, and "
    f"cran.r-project.org:443. "
    f"See {_PROJECT_URL}#security-model"
)


@click.group()
@click.version_option(package_name="licenseal")
def main() -> None:
    """licenseal - License compatibility checker for your project's dependencies."""


def _package_version() -> str:
    """Return the installed package version for request identification."""
    try:
        return version("licenseal")
    except PackageNotFoundError:
        return "0.0.0"


def _http_headers(command_name: str) -> dict[str, str]:
    """Build polite HTTP headers for registry requests."""
    return {
        "Accept": "application/json",
        "User-Agent": f"licenseal/{_package_version()} ({_PROJECT_URL}; {command_name})",
    }


def _worker_count(dep_count: int, max_workers: int) -> int:
    """Cap concurrency to the number of dependencies being resolved.

    Floored at 1 because ``ThreadPoolExecutor(max_workers=0)`` raises
    ``ValueError``. Callers normally short-circuit before this is reached
    on empty deps, but this guard keeps a future caller from tripping it.
    """
    return max(1, min(dep_count, max_workers))


class _PhaseTimings:
    """Wall-clock per scan phase, for the end-of-scan timing summary.

    Companion to the per-host traffic summary: the host counts say *where*
    the requests went, this says *which phase* the wall-clock went to
    (discovery vs. transitive walk vs. batch pre-pass vs. per-dep
    resolution), so a slow scan explains itself without profiling.
    """

    def __init__(self) -> None:
        self.entries: list[tuple[str, float]] = []

    def record(self, name: str, seconds: float) -> None:
        """Record one completed phase's duration."""
        self.entries.append((name, seconds))

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        """Time the enclosed block and record it under ``name``."""
        started = time.perf_counter()
        try:
            yield
        finally:
            self.record(name, time.perf_counter() - started)

    def summary_line(self) -> str:
        """Render the recorded phases as a single stderr summary line."""
        joined = ", ".join(f"{name} {seconds:.1f}s" for name, seconds in self.entries)
        return f"Phase timings: {joined}"


def _should_fail(report: AnalysisReport, strict: bool, *, had_analysis_gaps: bool = False) -> bool:
    """Return whether the command should exit non-zero.

    Reviewed deps are excluded from the failure check. A reviewed entry
    (``licenseal.review.toml`` stanza applied) is the user's explicit
    accept-and-document mechanism — the rationale lives in the ``note``
    field. Without this filter, a reviewed warning would force the user
    into one of three bad options: un-review (lose the audit trail),
    override ``license`` to something it isn't (audit fraud), or
    ``--no-strict`` (lose the CI gate entirely). Filtering reviewed
    entries lets all three properties coexist.

    ``had_analysis_gaps`` is set when a manifest couldn't be read or parsed
    (a dependency-bearing file lost to the scan). That's an *incomplete
    analysis* — morally an UNKNOWN, since the scan can't vouch for what it
    never saw — so ``--strict`` fails on it just like an unknown license.
    """

    def _unreviewed(results: list) -> bool:
        return any(not r.license_info.reviewed for r in results)

    if _unreviewed(report.violations):
        return True
    if not strict:
        return False
    if had_analysis_gaps:
        return True
    return _unreviewed(report.warnings) or _unreviewed(report.unknown)


def _registries_unreachable(
    license_infos: list[LicenseInfo], *, attempted: int, succeeded: int
) -> bool:
    """Return whether every registry lookup failed and nothing resolved.

    True only when the scan issued at least one registry request, *not one*
    returned usable data, and *not one* dependency resolved from any source.
    That is a tooling failure ("the scan couldn't run") — no network, a proxy /
    firewall blocking egress, or a registry-wide outage — not a license finding,
    so it is handled as a hard error regardless of ``--strict``. Otherwise the
    whole dependency set would render as UNKNOWN and pass silently under
    ``--no-strict``: a green CI that audited nothing.

    The fetch counts, not ``from_registry`` alone, are what make this safe: a
    project whose only deps are unresolvable in principle (git / path / workspace
    specs, or a metadata fetch that returned 200 but matched no version) also has
    every ``from_registry`` False, yet the registry answered. ``succeeded > 0``
    catches that reached-but-unresolved case; ``attempted == 0`` catches the
    issued-no-request case (deps short-circuited, or resolved from a lockfile /
    batch / index with no per-dep fetch); and the ``from_registry`` guard keeps a
    partial outage — some deps resolved via the batch, the tail's per-package
    fetches failed — on the normal per-dep UNKNOWN / strict path instead of
    failing the whole scan.

    A failed fetch here is any that returned no usable body — a connection
    error, a timeout, or a persistent 4xx/5xx alike. Distinguishing a genuine
    connection failure from a registry that answered with an error (so the
    message could name the precise cause) is a deliberate follow-up; for the
    gate decision the outcome is the same — nothing was audited.
    """
    if not license_infos:
        return False
    if attempted == 0 or succeeded > 0:
        return False
    return not any(li.from_registry for li in license_infos)


def _resolve_excludes(project_path: Path, exclude_dirs: tuple[str, ...]) -> frozenset[Path]:
    """Resolve each ``--exclude-dirs`` value against ``project_path`` to an absolute path.

    Each value is comma-split first so the user can pass either form:
    ``--exclude-dirs a,b`` (one invocation, multiple paths) or
    ``--exclude-dirs a --exclude-dirs b`` (Click multiple=True repetition).
    Non-existent paths are kept as-is (resolved with ``strict=False``) so a
    user-supplied path that doesn't match anything just no-ops, matching
    gitignore semantics.
    """
    resolved: set[Path] = set()
    for value in exclude_dirs:
        for raw in value.split(","):
            piece = raw.strip()
            if not piece:
                continue
            candidate = Path(piece)
            if not candidate.is_absolute():
                candidate = project_path / candidate
            resolved.add(candidate.resolve())
    return frozenset(resolved)


def _discover_dependencies(
    project_path: Path,
    include_dev: bool,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Dependency]:
    """Discover project dependencies and apply dev filtering."""
    deps, _ = discover_all_dependencies(project_path, exclude_paths=exclude_paths)
    if not include_dev:
        return [dep for dep in deps if dep.group != DependencyGroup.DEV]
    return deps


def _read_diagnostics_view(
    diagnostics: list[ReadDiagnostic], project_path: Path
) -> list[ReportDiagnostic]:
    """Dedup + relativize raw read diagnostics into report-facing values.

    De-duplicates ``(path, reason)`` — a single ``pom.xml`` is read by several
    passes, so the same anomaly can be recorded more than once — and shows paths
    relative to the scan root when possible. Shared by the stderr drain and the
    JSON report's ``diagnostics`` array so both see exactly the same set.
    """
    seen: set[tuple[str, str]] = set()
    view: list[ReportDiagnostic] = []
    for diag in diagnostics:
        try:
            shown = diag.path.relative_to(project_path).as_posix()
        except ValueError:
            shown = str(diag.path)
        if (shown, diag.reason) in seen:
            continue
        seen.add((shown, diag.reason))
        view.append(
            ReportDiagnostic(
                path=shown,
                reason=diag.reason,
                severity="gap" if diag.is_gap else "recovered",
            )
        )
    return view


def _echo_read_diagnostics(view: list[ReportDiagnostic]) -> int:
    """Echo a deduped diagnostics view to stderr; return the distinct-gap count.

    A *silent* skip is a silent false-negative (a dropped dependency reads as
    "no problem"), so every anomaly is echoed. Returns the number of distinct
    manifests lost to *gaps* (unreadable / unparseable / blind subtree),
    excluding latin-1 *recoveries* — the caller folds this into the ``--strict``
    exit decision and a one-line summary.
    """
    gap_paths: set[str] = set()
    for diag in view:
        click.echo(f"Warning: {diag.path}: {diag.reason}", err=True)
        if diag.severity == "gap":
            gap_paths.add(diag.path)
    return len(gap_paths)


def _resolve_license_infos(
    deps: list[Dependency],
    max_workers: int,
    command_name: str,
    *,
    transitive: bool = False,
    project_path: Path | None = None,
    include_dev: bool = False,
    max_depth: int = 50,
    all_direct_deps: list[Dependency] | None = None,
    exclude_paths: frozenset[Path] = frozenset(),
    timings: _PhaseTimings | None = None,
) -> list[LicenseInfo]:
    """Resolve dependency licenses from registries.

    With `transitive=True`, the dep list is first expanded via lockfile-first
    transitive resolution (`licenseal.transitive.resolve_transitive`) before
    license resolution. `all_direct_deps` is the unfiltered direct-dep list
    (both prod and dev) — the lockfile path needs it to attribute group by
    reachability and to drop dev-only chains when `include_dev=False`. The
    transitive walk runs inside the same `tethered.scope()` block so its
    registry calls are policy-checked too.

    ``timings`` collects per-phase wall-clock for the caller's end-of-scan
    summary; when omitted, phases are recorded into a discarded instance.
    """
    if timings is None:
        timings = _PhaseTimings()
    if not deps and not (transitive and project_path is not None):
        # No direct deps AND no transitive walk possible → skip the
        # tethered.scope / progress / threadpool setup entirely. When a
        # transitive walk IS possible we proceed even with zero direct deps:
        # a lockfile-only project (an R ``renv.lock`` / ``packrat.lock`` with no
        # DESCRIPTION — common for analysis projects / Shiny apps) has deps to
        # surface that come solely from the lockfile. The empty list flows
        # cleanly through ``analyze()`` and the renderers, so the caller still
        # emits a valid (empty) report.
        return []
    try:
        with (
            tethered.scope(
                allow=_REGISTRY_HOSTS,
                label="licenseal.resolve",
                hint=_TETHERED_HINT,
            ),
            # Keep httpx's default ``trust_env=True`` so ``HTTP(S)_PROXY`` is
            # honored — licenseal must work behind a corporate egress proxy,
            # common in the compliance-focused orgs that run it. This exposes no
            # credentials: httpx (>=0.28) never reads ``~/.netrc`` implicitly —
            # only via an explicit ``NetRCAuth``, which licenseal does not use —
            # and licenseal sets no ``Authorization`` header. The proxy sees only
            # the same package-coordinate requests every registry does.
            httpx.Client(
                timeout=_REQUEST_TIMEOUT_SECONDS,
                headers=_http_headers(command_name),
            ) as client,
        ):
            # One URL cache for the whole scan. The walker hammers a
            # narrow set of URLs (popular transitives are referenced by
            # many parents at different specs), and the license-resolution
            # pass then hits the same URLs again.
            # Sharing one cache between the two phases turns the second
            # wave of fetches into in-memory dict lookups. See
            # `licenseal.resolvers.http.RegistryCache`.
            registry_cache = RegistryCache()
            if transitive and project_path is not None:
                # Indeterminate progress: BFS frontier is open-ended, total
                # only known once the walk terminates. Single in-place line.
                with (
                    timings.phase("transitive walk"),
                    Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        TimeElapsedColumn(),
                        console=_STDERR_CONSOLE,
                        transient=True,
                    ) as walk_progress,
                ):
                    walk_task = walk_progress.add_task("Walking dep tree...", total=None)

                    def _on_wave(count: int) -> None:
                        walk_progress.update(
                            walk_task,
                            description=f"Walking dep tree: {count} deps resolved",
                        )

                    # Every per-ecosystem ``find_*_lockfiles`` probe inside
                    # resolve_transitive walks the project tree; share a single
                    # walk across them so the transitive layer doesn't re-walk
                    # once per ecosystem (same regression the discovery phase had).
                    with shared_walk_cache():
                        deps = resolve_transitive(
                            all_direct_deps if all_direct_deps is not None else deps,
                            project_path,
                            include_dev=include_dev,
                            max_depth=max_depth,
                            client=client,
                            max_workers=max_workers,
                            fetcher=registry_cache.fetch,
                            pom_fetcher=registry_cache.fetch_text,
                            on_wave=_on_wave,
                            exclude_paths=exclude_paths,
                        )

            # Cross-ecosystem batch pre-pass against ``api.deps.dev``'s
            # ``/v3alpha/versionbatch`` endpoint. Each POST returns at
            # most 100 entries (server-side cap, verified empirically —
            # see ``resolvers.deps_dev._BATCH_CHUNK_SIZE``), so a scan of
            # N batchable deps takes ⌈N/100⌉ POSTs; every ecosystem's
            # chunks fan out through one shared threadpool (capped at
            # ``_BATCH_MAX_WORKERS``) so polyglot scans overlap their batch
            # POSTs instead of paying one sequential pool round per
            # ecosystem. The result is one ``(name, version)``-keyed cache
            # per ecosystem; per-dep resolution checks it first and falls
            # back to the per-package official-registry resolver when the
            # batch entry is absent or came back without licenses
            # ("non-standard" included).
            #
            # For Go, ``None`` cache entries are authoritative (deps.dev
            # IS the canonical source for Go licenses): "version doesn't
            # exist on deps.dev" → return UNKNOWN without further fetch.
            # For Python/npm/Rust/Java/NuGet/Ruby, ``None`` is only
            # advisory: the official registries remain authoritative and
            # the per-package fallback runs. (.NET keeps the NuGet
            # flatcontainer as Tier 1; the batch fills its Tier 2 — see
            # ``resolve_nuget_license``. Ruby off-registry deps, GIT / PATH
            # sourced, are filtered out up front: their license can't be
            # resolved from rubygems.org at all.)
            batch_pre_pass_started = time.perf_counter()
            batch_caches = bulk_resolve_licenses(
                {
                    "GO": [d for d in deps if d.ecosystem == Ecosystem.GO],
                    "PYPI": [d for d in deps if d.ecosystem == Ecosystem.PYTHON],
                    "NPM": [d for d in deps if d.ecosystem == Ecosystem.NPM],
                    "CARGO": [d for d in deps if d.ecosystem == Ecosystem.RUST],
                    "MAVEN": [d for d in deps if d.ecosystem == Ecosystem.JAVA],
                    "NUGET": [d for d in deps if d.ecosystem == Ecosystem.DOTNET],
                    "RUBYGEMS": [
                        d
                        for d in deps
                        if d.ecosystem == Ecosystem.RUBY and not _ruby_is_off_registry(d.source)
                    ],
                },
                client,
                max_workers=max_workers,
            )
            go_batch_cache = batch_caches["GO"]
            python_batch_cache = batch_caches["PYPI"]
            npm_batch_cache = batch_caches["NPM"]
            rust_batch_cache = batch_caches["CARGO"]
            java_batch_cache = batch_caches["MAVEN"]
            dotnet_batch_cache = batch_caches["NUGET"]
            ruby_batch_cache = batch_caches["RUBYGEMS"]

            # PHP lockfile-license pre-pass. composer.lock is unique among
            # supported lockfiles in embedding a structured SPDX ``license``
            # field per package, so this map lets the Packagist resolver
            # answer most queries without any HTTP fetch. deps.dev does NOT
            # index Packagist (only Cargo / Go / Maven / npm / NuGet / PyPI /
            # RubyGems), and Packagist has no batch endpoint — the lockfile
            # map is the equivalent batch-style pre-pass for PHP.
            php_lockfile_licenses: LockfileLicenseMap = {}
            if project_path is not None:
                for lockfile in find_composer_lockfiles(project_path, exclude_paths=exclude_paths):
                    php_lockfile_licenses.update(extract_composer_lock_licenses(lockfile))

            # R / CRAN license pre-pass. CRAN publishes the official PACKAGES
            # index (License + dependency edges for every current package);
            # fetch + parse it once here so the per-dep resolver is a local map
            # lookup with no per-package requests. deps.dev doesn't index CRAN,
            # so this index is the official equivalent of a batch pre-pass.
            r_deps = [d for d in deps if d.ecosystem == Ecosystem.R]
            cran_index = (
                fetch_cran_index(client, fetcher=registry_cache.fetch_text) if r_deps else {}
            )
            # The PHP lockfile map and CRAN index above are the batch-style
            # pre-passes for ecosystems deps.dev doesn't cover, so they share
            # the phase with the deps.dev versionbatch POSTs.
            timings.record("batch pre-pass", time.perf_counter() - batch_pre_pass_started)

            def _from_advisory_cache(
                cache: dict[tuple[str, str], LicenseInfo | None],
                dep: Dependency,
                pinned: str | None,
            ) -> LicenseInfo | None:
                """Look up the deps.dev batch result for non-authoritative ecosystems.

                Returns the rebound ``LicenseInfo`` when the batch produced a
                real SPDX answer; returns ``None`` so the caller can fall
                back to the per-package official-registry resolver when the
                batch entry is missing, explicitly ``None`` (deps.dev says
                "version doesn't exist" — not authoritative for these
                ecosystems), or carries ``license_id == "UNKNOWN"`` (deps.dev
                had the version but no license data, or only filtered
                ``"non-standard"`` entries).
                """
                if pinned is None:
                    return None
                cached = cache.get((dep.name, pinned))
                if cached is None or cached.license_id == "UNKNOWN":
                    return None
                return replace(cached, dependency=dep)

            def _resolve(dep: Dependency) -> LicenseInfo:
                if dep.ecosystem == Ecosystem.PYTHON:
                    cached = _from_advisory_cache(
                        python_batch_cache,
                        dep,
                        _extract_python_pinned_version(dep.version_constraint),
                    )
                    if cached is not None:
                        return cached
                    return resolve_python_license(dep, client, fetcher=registry_cache.fetch)
                if dep.ecosystem == Ecosystem.RUST:
                    cached = _from_advisory_cache(
                        rust_batch_cache,
                        dep,
                        _extract_rust_pinned_version(dep.version_constraint),
                    )
                    if cached is not None:
                        return cached
                    return resolve_rust_license(dep, client, fetcher=registry_cache.fetch)
                if dep.ecosystem == Ecosystem.GO:
                    pinned = _extract_go_pinned_version(dep.version_constraint)
                    if pinned is not None:
                        key = (dep.name, pinned)
                        if key in go_batch_cache:
                            cached = go_batch_cache[key]
                            if cached is None:
                                # Batch confirmed (name, version) doesn't
                                # exist on deps.dev. No further fetch —
                                # return UNKNOWN.
                                return LicenseInfo(
                                    dependency=dep,
                                    license_id="UNKNOWN",
                                    license_raw="",
                                    from_registry=False,
                                )
                            return replace(cached, dependency=dep)
                    # Either the dep's version is unparseable (resolve_go_license
                    # will return UNKNOWN without a fetch), or it wasn't in the
                    # batch cache (the whole batch failed or this dep was
                    # somehow filtered out). Single-version GET handles both.
                    return resolve_go_license(dep, client, fetcher=registry_cache.fetch)
                if dep.ecosystem == Ecosystem.JAVA:
                    cached = _from_advisory_cache(
                        java_batch_cache,
                        dep,
                        _extract_maven_pinned_version(dep.version_constraint),
                    )
                    if cached is not None:
                        return cached
                    # Maven Central serves raw POM XML; deps.dev's MAVEN
                    # endpoint serves JSON. Different cache trims, so the
                    # resolver takes both fetchers separately. Same
                    # ``RegistryCache`` instance backs both — URLs are
                    # distinct, so the cache dict is shared cleanly.
                    return resolve_maven_central_license(
                        dep,
                        client,
                        fetcher=registry_cache.fetch_text,
                        json_fetcher=registry_cache.fetch,
                    )
                if dep.ecosystem == Ecosystem.RUBY:
                    # Off-registry (GIT / PATH-sourced) gems can't be
                    # resolved via rubygems.org; short-circuit before
                    # touching the batch or per-package resolver. Drop the
                    # internal off-registry marker from ``source`` so it
                    # doesn't surface in the report's Source column — these
                    # deps have no manifest-path source, like a transitive.
                    if _ruby_is_off_registry(dep.source):
                        return LicenseInfo(
                            dependency=replace(dep, source=""),
                            license_id="UNKNOWN",
                            license_raw="",
                            from_registry=False,
                        )
                    cached = _from_advisory_cache(
                        ruby_batch_cache,
                        dep,
                        _extract_ruby_pinned_version(dep.version_constraint),
                    )
                    if cached is not None:
                        return cached
                    return resolve_ruby_license(dep, client, fetcher=registry_cache.fetch)
                if dep.ecosystem == Ecosystem.PHP:
                    # Lockfile-first PHP path: when composer.lock carried
                    # an SPDX license for this (name, version) pin, the
                    # resolver returns it without any HTTP fetch. Falls
                    # back to Packagist for manifest-only deps or empty
                    # lockfile license fields. No deps.dev pre-pass —
                    # Packagist isn't indexed by deps.dev.
                    return resolve_php_license(
                        dep,
                        client,
                        lockfile_license_map=php_lockfile_licenses,
                        fetcher=registry_cache.fetch,
                    )
                if dep.ecosystem == Ecosystem.HEX:
                    # Hex / Elixir: hex.pm only (deps.dev doesn't index Hex,
                    # so no batch pre-pass). The resolver short-circuits
                    # off-registry (git/path) deps to UNKNOWN and drops the
                    # internal marker from the reported source.
                    return resolve_hex_license(dep, client, fetcher=registry_cache.fetch)
                if dep.ecosystem == Ecosystem.R:
                    # R / CRAN: resolve from the official PACKAGES index fetched
                    # once above (a local map lookup). Off-registry
                    # (GitHub/Bioconductor/Local) and archived / off-CRAN
                    # packages resolve to UNKNOWN.
                    return resolve_r_license(dep, cran_index)
                if dep.ecosystem == Ecosystem.DOTNET:
                    # Mode-C: deps.dev batch (pre-populated) → NuGet
                    # flatcontainer nuspec → deps.dev v3 single-version GET.
                    # The batch cache check is hoisted here so all the
                    # ecosystems share the same dispatch shape; the
                    # remaining two tiers live in ``resolve_nuget_license``.
                    cached = _from_advisory_cache(
                        dotnet_batch_cache,
                        dep,
                        _extract_pinned_version_nuget(dep.version_constraint),
                    )
                    if cached is not None:
                        return cached
                    return resolve_nuget_license(
                        dep,
                        client,
                        fetcher=registry_cache.fetch_text,
                        json_fetcher=registry_cache.fetch,
                    )
                cached = _from_advisory_cache(
                    npm_batch_cache,
                    dep,
                    _extract_npm_pinned_version(dep.version_constraint),
                )
                if cached is not None:
                    return cached
                return resolve_npm_license(dep, client, fetcher=registry_cache.fetch)

            # tethered.scope() stores its stack in a ContextVar; per PEP 567,
            # ContextVars do not cross the thread boundary, so worker threads
            # start in an empty context. Re-entering scope inside the worker
            # (decorator / with-block) would enforce *our* scope but lose any
            # ancestor scope a host may have wrapped us in — silently bypassing
            # the host's policy. We instead snapshot the active context once
            # per task on the main thread so each worker enters an independent
            # copy that carries the full host-plus-licenseal scope stack
            # (a single shared Context cannot be entered concurrently by
            # multiple threads).
            snapshots = [contextvars.copy_context() for _ in deps]
            with (
                timings.phase("license resolution"),
                Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]Resolving licenses"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                    console=_STDERR_CONSOLE,
                    transient=True,
                ) as resolve_progress,
                ThreadPoolExecutor(max_workers=_worker_count(len(deps), max_workers)) as pool,
            ):
                task = resolve_progress.add_task("Resolving licenses", total=len(deps))
                results: list[LicenseInfo] = []
                for info in pool.map(lambda c, dep: c.run(_resolve, dep), snapshots, deps):
                    results.append(info)
                    resolve_progress.advance(task)
            # Wholesale-unreachability gate. The pool has joined, so the cache
            # counters are final. If every registry request failed and nothing
            # resolved, the scan didn't *run* — abort with a hard error (same
            # tier as an egress-policy block) rather than emit a report of
            # all-UNKNOWN that would pass under --no-strict.
            if _registries_unreachable(
                results,
                attempted=registry_cache.fetches_attempted,
                succeeded=registry_cache.fetches_succeeded,
            ):
                raise click.ClickException(
                    f"Could not resolve any of the {len(results)} dependencies: all "
                    f"{registry_cache.fetches_attempted} registry request(s) failed. The "
                    "package registries are unreachable or not responding — typically no "
                    "network connectivity, a proxy or firewall blocking egress, or a "
                    "registry outage. Refusing to report every dependency as UNKNOWN from "
                    f"a scan that resolved nothing.\n{_TETHERED_HINT}"
                )
            # Traffic summary so a slow scan explains itself: a large
            # crates.io share means the 1 req/s fallback tail dominated
            # wall-clock; a large PyPI/npm share means a no-lockfile
            # transitive walk. Covers every per-URL fetch this scan issued
            # (transitive walk + per-package resolution); deps.dev batch
            # POSTs are excluded — bounded at ~⌈deps/100⌉, never dominant.
            if registry_cache.fetches_attempted:
                by_host = ", ".join(
                    f"{host}: {count}"
                    for host, count in registry_cache.fetches_by_host.most_common()
                )
                click.echo(
                    f"Per-package registry requests: "
                    f"{registry_cache.fetches_attempted} ({by_host})",
                    err=True,
                )
            return results
    except tethered.EgressBlocked as exc:
        raise click.ClickException(
            f"{exc}\n"
            "If a host tethered policy is in effect (tethered.activate() or an "
            "enclosing tethered.scope()), include the hosts above in its allowlist."
        ) from exc


@main.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project directory to scan.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json", "markdown"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Write the rendered report to FILE instead of stdout. UTF-8 encoded; "
        "table-format output is rendered without ANSI escapes. Default "
        "(omitted) keeps stdout behavior for shell pipelines / CI."
    ),
)
@click.option(
    "--dev/--no-dev",
    "include_dev",
    default=False,
    show_default=True,
    help="Include dev dependencies in analysis.",
)
@click.option(
    "--max-workers",
    type=click.IntRange(1, 32),
    default=_DEFAULT_MAX_WORKERS,
    show_default=True,
    help="Maximum concurrent registry requests.",
)
@click.option(
    "--strict/--no-strict",
    default=True,
    show_default=True,
    help=(
        "Whether warnings, unknowns, and analysis gaps (manifests that couldn't "
        "be read or parsed) fail CI in addition to violations. Violations always "
        "fail regardless of this flag."
    ),
)
@click.option(
    "--transitive/--no-transitive",
    default=True,
    show_default=True,
    help=(
        "Resolve and check transitive dependencies in addition to direct ones. "
        "Pass --no-transitive for direct-only (e.g. when publishing a library "
        "where you only ship your own deps)."
    ),
)
@click.option(
    "--max-depth",
    type=click.IntRange(1, 100),
    default=50,
    show_default=True,
    help="Maximum transitive depth (only meaningful with --transitive).",
)
@click.option(
    "--exclude-dirs",
    "exclude_dirs",
    multiple=True,
    type=click.UNPROCESSED,
    help=(
        "Skip these subdirectories during discovery. Accepts one or more paths "
        "(comma-separated) relative to --path or absolute; may also be repeated. "
        "Subdirectories that contain their own .git are skipped automatically "
        "without needing this flag."
    ),
)
def check(
    path: Path,
    output_format: str,
    output_file: Path | None,
    include_dev: bool,
    max_workers: int,
    strict: bool,
    transitive: bool,
    max_depth: int,
    exclude_dirs: tuple[str, ...],
) -> None:
    """Scan dependencies and assess license compliance."""
    if not transitive:
        ctx = click.get_current_context()
        if ctx.get_parameter_source("max_depth") is not click.core.ParameterSource.DEFAULT:
            raise click.UsageError(
                "--max-depth has no effect with --no-transitive; remove one or the other."
            )

    started_at = time.perf_counter()
    timings = _PhaseTimings()
    project_path = path.resolve()
    exclude_paths = _resolve_excludes(project_path, exclude_dirs)

    # The read-diagnostics sink spans BOTH discovery and the transitive walk —
    # a manifest or lockfile skipped/decoded-via-fallback in either phase is
    # surfaced rather than silently dropped. ``shared_walk_cache`` wraps only
    # discovery (the transitive layer manages its own walk cache internally).
    with collect_read_diagnostics() as read_diags:
        with timings.phase("discovery"), shared_walk_cache():
            detected_license = (
                detect_project_license(project_path, exclude_paths=exclude_paths) or "Proprietary"
            )
            all_deps, local_filter_counts = discover_all_dependencies(
                project_path, exclude_paths=exclude_paths
            )
        deps = all_deps if include_dev else [d for d in all_deps if d.group != DependencyGroup.DEV]

        # Data-driven over the full Ecosystem enum (not a hardcoded subset):
        # every ecosystem with a workspace-local filter count surfaces here, so
        # the echo can't silently drop one when a new ecosystem is added.
        # ``.label`` is the human-readable name; ``local_filter_counts`` is
        # keyed by enum value.
        for ecosystem in Ecosystem:
            filtered = local_filter_counts.get(ecosystem.value, 0)
            if filtered:
                click.echo(
                    f"Excluded {filtered} local {ecosystem.label} workspace package "
                    "reference(s) from resolution (not published to the registry).",
                    err=True,
                )

        if deps:
            if transitive:
                click.echo(
                    f"Found {len(deps)} direct dependencies. Resolving transitive graph...",
                    err=True,
                )
            else:
                click.echo(f"Found {len(deps)} dependencies. Resolving licenses...", err=True)
        else:
            # Zero deps after filtering — common for stdlib-only libraries or
            # `--no-dev` against a project with only dev-group deps. Skip the
            # resolution stage but still render the report so callers asking
            # for `-f json` get a valid (empty-but-well-formed) document and
            # the detected project license isn't silently dropped.
            click.echo("No dependencies to resolve.", err=True)
        license_infos = _resolve_license_infos(
            deps,
            max_workers,
            "check",
            transitive=transitive,
            project_path=project_path,
            include_dev=include_dev,
            max_depth=max_depth,
            all_direct_deps=all_deps,
            exclude_paths=exclude_paths,
            timings=timings,
        )

    # Companion line to the per-host traffic summary above it: phases, not
    # hosts. Always at least the discovery entry, so never an empty line.
    click.echo(timings.summary_line(), err=True)

    diag_view = _read_diagnostics_view(read_diags, project_path)
    gap_count = _echo_read_diagnostics(diag_view)
    if gap_count:
        click.echo(
            f"Warning: {gap_count} manifest(s) could not be fully analyzed; their "
            "dependencies may be missing from this report"
            + (" (fails --strict)." if strict else "."),
            err=True,
        )

    failed = sum(1 for li in license_infos if not li.from_registry)
    if failed:
        click.echo(f"Warning: {failed} package(s) could not be resolved from registries.", err=True)

    contents = load_review_file(project_path)
    if contents.incomplete:
        click.echo(
            "Warning: incomplete review entries were not applied: "
            + ", ".join(contents.incomplete),
            err=True,
        )

    report = analyze(detected_license, license_infos)

    if contents.licenses or contents.notes:
        flagged_keys = {
            review_key(
                r.license_info.dependency.ecosystem,
                r.license_info.dependency.name,
                r.license_info.resolved_version,
            )
            for r in report.results
            if (r.verdict != CompatibilityVerdict.COMPATIBLE and r.license_info.resolved_version)
        }
        apply_reviewed_licenses(license_infos, contents, flagged_keys)
        # Re-classify only the overridden infos in place; the rest is unchanged.
        for index, info in enumerate(license_infos):
            if info.reviewed:
                report.results[index] = check_compatibility(detected_license, info)

    report.elapsed_seconds = time.perf_counter() - started_at
    report.read_diagnostics = diag_view

    if output_file is not None:
        rendered = _render_report_to_string(report, output_format, project_path)
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            raise click.ClickException(f"Failed to write report to {output_file}: {exc}") from exc
        click.echo(f"Wrote {output_format} report to {output_file}", err=True)
    elif output_format == "table":
        render_table(report, Console(), project_path=project_path)
    elif output_format == "json":
        click.echo(render_json(report))
    elif output_format == "markdown":
        click.echo(render_markdown(report))

    skill_hint = _project_skill_staleness_hint(project_path)
    if skill_hint is not None:
        click.echo(skill_hint, err=True)

    if _should_fail(report, strict, had_analysis_gaps=gap_count > 0):
        sys.exit(1)


def _render_report_to_string(report: AnalysisReport, output_format: str, project_path: Path) -> str:
    """Render the report to a string for file output.

    Table format goes through a non-terminal Rich Console so ANSI escapes
    aren't written to disk. JSON / markdown are already string renderers.
    """
    if output_format == "json":
        return render_json(report) + "\n"
    if output_format == "markdown":
        return render_markdown(report) + "\n"
    console = Console(force_terminal=False, color_system=None, width=120)
    with console.capture() as capture:
        render_table(report, console, project_path=project_path)
    return capture.get()


@main.command("init-review-file")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project directory to scan.",
)
@click.option(
    "--dev/--no-dev",
    "include_dev",
    default=False,
    show_default=True,
    help="Include dev dependencies in analysis.",
)
@click.option(
    "--max-workers",
    type=click.IntRange(1, 32),
    default=_DEFAULT_MAX_WORKERS,
    show_default=True,
    help="Maximum concurrent registry requests.",
)
@click.option(
    "--from-report",
    "from_report",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Read flagged dependencies from a saved JSON report instead of resolving live.",
)
@click.option(
    "--merge",
    "merge",
    is_flag=True,
    help="Merge new flagged entries into an existing review file (preserves existing entries).",
)
@click.option(
    "--exclude-dirs",
    "exclude_dirs",
    multiple=True,
    type=click.UNPROCESSED,
    help=(
        "Skip these subdirectories during discovery. Accepts one or more paths "
        "(comma-separated) relative to --path or absolute; may also be repeated. "
        "Subdirectories that contain their own .git are skipped automatically "
        "without needing this flag."
    ),
)
def init_review_file(
    path: Path,
    include_dev: bool,
    max_workers: int,
    from_report: Path | None,
    merge: bool,
    exclude_dirs: tuple[str, ...],
) -> None:
    """Generate or extend `licenseal.review.toml` for flagged dependencies."""
    if from_report is not None:
        ctx = click.get_current_context()
        inert = [
            flag
            for flag, param in (
                ("--dev/--no-dev", "include_dev"),
                ("--max-workers", "max_workers"),
                ("--exclude-dirs", "exclude_dirs"),
            )
            if ctx.get_parameter_source(param) is not click.core.ParameterSource.DEFAULT
        ]
        if inert:
            verb = "has" if len(inert) == 1 else "have"
            raise click.UsageError(
                f"{', '.join(inert)} {verb} no effect with --from-report "
                "(the report is already resolved)."
            )

    project_path = path.resolve()
    review_file = project_path / REVIEW_FILE_NAME
    exclude_paths = _resolve_excludes(project_path, exclude_dirs)

    if from_report is not None:
        flagged, unscaffoldable = flagged_entries_from_json_report(from_report)
    else:
        with collect_read_diagnostics() as read_diags:
            deps = _discover_dependencies(project_path, include_dev, exclude_paths=exclude_paths)
            if deps:
                click.echo(f"Found {len(deps)} dependencies. Resolving licenses...", err=True)
            else:
                # Zero deps → zero flagged entries → second early-return
                # below fires with the proper "nothing to review" message.
                click.echo("No dependencies to resolve.", err=True)
            license_infos = _resolve_license_infos(deps, max_workers, "init-review-file")
            report = analyze(
                detect_project_license(project_path, exclude_paths=exclude_paths) or "Proprietary",
                license_infos,
            )
            flagged, unscaffoldable = flagged_entries_from_results(report.results)
        _echo_read_diagnostics(_read_diagnostics_view(read_diags, project_path))

    if not flagged:
        click.echo("No reviewable flagged dependencies found.", err=True)
        _warn_unscaffoldable(unscaffoldable)
        return

    if review_file.exists() and not merge:
        raise click.ClickException(
            f"{REVIEW_FILE_NAME} already exists. Use --merge to add new flagged entries, "
            "or delete the file to start fresh."
        )

    if review_file.exists():
        existing_contents = load_review_file(project_path)
        existing_text = review_file.read_text(encoding="utf-8")
        merged_text, appended = merge_review_template(
            existing_text, flagged, existing_contents.all_keys
        )
        if appended == 0:
            click.echo("No new flagged dependencies to add.", err=True)
            _warn_unscaffoldable(unscaffoldable)
            return
        review_file.write_text(merged_text, encoding="utf-8")
        suffix = "y" if appended == 1 else "ies"
        click.echo(f"Appended {appended} review entr{suffix} to {REVIEW_FILE_NAME}.")
    else:
        review_file.write_text(render_review_template(flagged), encoding="utf-8")
        suffix = "y" if len(flagged) == 1 else "ies"
        click.echo(f"Wrote {REVIEW_FILE_NAME} with {len(flagged)} review entr{suffix}.")
    _warn_unscaffoldable(unscaffoldable)


_SKILL_NAME = "licenseal-review"
_SKILL_FILENAME = "SKILL.md"
_SKILL_VERSION_MARKER = "<!-- licenseal-skill-version:"
_SKILL_HASH_MARKER = "<!-- licenseal-skill-body-sha256:"


def _bundled_skill_body() -> str:
    """Return the skill text bundled with this licenseal release."""
    return (files("licenseal.data") / "claude_skill.md").read_text(encoding="utf-8")


def _project_skill_file(project_path: Path) -> Path:
    """Path to the project-local installed skill.

    licenseal installs the skill **only inside the project** (``.claude/skills``),
    never globally, so the tool never reads or writes outside the project
    directory — keeping its footprint non-intrusive and the skill committable
    alongside the code it audits.
    """
    return project_path / ".claude" / "skills" / _SKILL_NAME / _SKILL_FILENAME


def _render_installed_skill(body: str, skill_version: str) -> str:
    """Append provenance markers so a later install can tell a pristine prior
    install (safe to refresh in place) from a hand-edited one.

    The markers are HTML comments at the end of the file, so the YAML
    frontmatter stays at line 1 and Claude Code renders nothing extra.
    """
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return (
        f"{body}\n"
        f"{_SKILL_VERSION_MARKER} {skill_version} -->\n"
        f"{_SKILL_HASH_MARKER} {body_hash} -->\n"
    )


def _marker_value(text: str, marker: str) -> str | None:
    """Extract VALUE from an ``<!-- marker: VALUE -->`` comment, or None."""
    start = text.find(marker)
    if start == -1:
        return None
    start += len(marker)
    end = text.find("-->", start)
    if end == -1:
        return None
    return text[start:end].strip()


def _parse_installed_skill(text: str) -> tuple[str | None, str | None, bool]:
    """Return ``(stamped_version, body, is_pristine)`` for an installed skill.

    All three come from the trailing provenance markers:

    - ``stamped_version`` — the licenseal version recorded at install time, or
      ``None`` when the file carries no markers (hand-written, or predates
      stamping). It is provenance only; freshness is judged by ``body``.
    - ``body`` — the skill content with the marker block stripped, or ``None``
      when there are no markers. Compare it to ``_bundled_skill_body()`` to
      decide whether a refresh is warranted.
    - ``is_pristine`` — True only when ``body`` still hashes to the value
      recorded at install (nobody edited it), so a refresh can overwrite it
      in place without ``--force``.
    """
    sep = "\n" + _SKILL_VERSION_MARKER
    idx = text.find(sep)
    if idx == -1:
        return None, None, False
    body, trailer = text[:idx], text[idx:]
    stamped_version = _marker_value(trailer, _SKILL_VERSION_MARKER)
    recorded_hash = _marker_value(trailer, _SKILL_HASH_MARKER)
    if stamped_version is None or recorded_hash is None:
        return None, None, False
    pristine = hashlib.sha256(body.encode("utf-8")).hexdigest() == recorded_hash
    return stamped_version, body, pristine


def _project_skill_staleness_hint(project_path: Path) -> str | None:
    """Return a refresh hint if the project's installed skill is out of date,
    else ``None``.

    Only the project-local ``.claude/skills`` copy is considered — the same
    directory ``check`` already reads — so this never reaches outside the
    scanned project. Freshness is judged by **content**, not version number,
    so a licenseal release that doesn't change the skill never nags. Read-only
    and best-effort: it never writes and never raises. A project with no
    installed skill (the common case) sees nothing, as do hand-written or
    hand-edited skills.
    """
    path = _project_skill_file(project_path)
    try:
        if not path.is_file():
            return None
        stamped_version, installed_body, _ = _parse_installed_skill(
            path.read_text(encoding="utf-8")
        )
        if stamped_version is None or installed_body is None:
            return None  # unstamped / hand-written: not ours to manage
        if installed_body == _bundled_skill_body():
            return None  # content already current
    except OSError:
        return None
    return (
        f"Installed Claude skill (from licenseal {stamped_version}) is out of date; "
        f"run `licenseal install-skill` to refresh it for licenseal {_package_version()}."
    )


@main.command("install-skill")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project directory to install into (.claude/skills/). Default: current dir.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite a hand-edited skill (an unedited prior install refreshes without it).",
)
def install_skill(path: Path, force: bool) -> None:
    """Install or refresh the bundled Claude Code skill into the project.

    Writes ``<project>/.claude/skills/licenseal-review/SKILL.md``. licenseal
    installs the skill **only inside the project** — never globally — so it
    stays non-intrusive and the skill can be committed alongside the code it
    audits. Claude Code discovers project skills by scanning ``.claude/skills``
    for ``SKILL.md`` files, so it is picked up automatically. The skill walks
    an agent through running ``licenseal check``, investigating flagged
    dependencies with the user, writing ``licenseal.review.toml``, and
    re-verifying.

    Re-running after a licenseal upgrade refreshes a pristine prior install
    in place — no ``--force`` needed. ``--force`` is only required to
    overwrite a skill that looks hand-edited (or predates version stamping).
    """
    body = _bundled_skill_body()
    current_version = _package_version()
    rendered = _render_installed_skill(body, current_version)

    target_file = _project_skill_file(path)
    target_file.parent.mkdir(parents=True, exist_ok=True)

    if target_file.exists():
        existing = target_file.read_text(encoding="utf-8")
        stamped_version, installed_body, pristine = _parse_installed_skill(existing)
        if installed_body == body and stamped_version == current_version:
            click.echo(f"licenseal skill already up to date ({current_version}).")
            return
        if pristine or force:
            target_file.write_text(rendered, encoding="utf-8")
            if stamped_version and stamped_version != current_version:
                click.echo(
                    f"Refreshed licenseal skill {stamped_version} → {current_version} "
                    f"at {target_file}"
                )
            else:
                click.echo(f"Updated licenseal skill at {target_file}")
            return
        raise click.ClickException(
            f"{target_file} already exists and looks hand-modified "
            "(or predates version stamping). Use --force to overwrite."
        )

    target_file.write_text(rendered, encoding="utf-8")
    click.echo(f"Installed licenseal skill {current_version} at {target_file}")


def _warn_unscaffoldable(unscaffoldable: list[str]) -> None:
    """Emit a stderr note for flagged deps that couldn't be scaffolded.

    Fires only when the list is non-empty. The review-file format keys
    overrides by ``(ecosystem, name, resolved_version)``, so a flagged
    dep with no resolved version cannot be reviewed away — usually a
    sign of a manifest typo, yanked release, or registry-side issue
    that warrants user attention.
    """
    if not unscaffoldable:
        return
    sample = ", ".join(sorted(unscaffoldable)[:5])
    if len(unscaffoldable) > 5:
        sample += f", … (+{len(unscaffoldable) - 5} more)"
    suffix = "y" if len(unscaffoldable) == 1 else "ies"
    click.echo(
        f"Note: {len(unscaffoldable)} flagged dependenc{suffix} could not be "
        f"scaffolded (no resolved version, usually a manifest typo / yanked "
        f"release / registry miss): {sample}.",
        err=True,
    )
