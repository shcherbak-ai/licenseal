# Agents

Instructions for AI coding agents working on this codebase.

## Project

licenseal — CLI tool that scans dependency manifests for Python (PyPI), JavaScript / TypeScript (npm), Rust (crates.io), Go (deps.dev), Java / JVM (Maven Central + deps.dev), .NET (NuGet.org + deps.dev), PHP (Packagist), Ruby (RubyGems + deps.dev), Elixir / Erlang (Hex / hex.pm), and R / CRAN (cran.r-project.org), resolves licenses from those registries, and checks compatibility against the project's license.

## Philosophy

- Keep `licenseal` narrow: it is a license checker, not a policy exception manager. Transitive scanning is the default; `--no-transitive` opts out.
- Prefer strict, fail-closed behavior over permissive guesses.
- Manual review can override flagged findings when a maintainer has better license information than the resolver, but it is not a hidden legal approval system.
- Do not expand the tool into legal workflow or approval tracking unless the user explicitly asks for that tradeoff.

## Architecture

```text
src/licenseal/
  cli.py                      Click CLI entry point
  models.py                   Dataclasses and enums (Dependency, LicenseInfo, RiskLevel, etc.)
  report.py                   Output renderers (table, JSON, markdown) with hierarchical layout
  review.py                   licenseal.review.toml loading, validation, templating
  transitive.py               Transitive resolution: lockfile-first + registry-recursion fallback
  _graph.py                   Reverse-BFS helper for direct-ancestor attribution
  analysis/
    spdx.py                   License string → SPDX ID normalization
    risk.py                   SPDX ID → RiskLevel classification
    compatibility.py          Project-vs-dependency compatibility matrix
  discovery/
    __init__.py               Aggregates all discovery sources
    python/
      pyproject.py            PEP 621 / Poetry / PEP 735
      requirements.py         requirements*.txt
      setup_cfg.py            setup.cfg
      setup_py.py             setup.py (static `ast.parse`, never executed; literal `setup(...)` license / install_requires / extras_require args)
      pipfile.py              Pipfile (Pipenv manifest)
      lockfiles.py            uv.lock, poetry.lock, Pipfile.lock parsers (transitive; edge-aware for uv/poetry, section-based for Pipfile)
    npm/
      package_json.py         package.json (recursive, skips node_modules; filters workspace-internal names)
      lockfiles.py            package-lock.json (v1 + v2/v3), pnpm-lock.yaml, yarn.lock parsers (transitive, edge-aware)
    rust/
      cargo_toml.py           Cargo.toml ([dependencies], target.<cfg>.*; [workspace.dependencies] is a version catalog — entries emitted only when a member references them via `workspace = true`, CPM-style stitching)
      lockfiles.py            Cargo.lock parser (transitive, edge-aware; registry-sourced crates only)
    go/
      go_mod.py               go.mod parser (require blocks, replace directives incl. local-path drop, // indirect, tool directive for Go 1.24+ DEV attribution, go.work `use` block for workspace-local module discovery)
      lockfile.py             go.sum parser (.zip + /go.mod row dedup; the edge graph and group attribution live in transitive.py via proxy.golang.org go.mod fetches)
    java/
      pom_xml.py              Maven pom.xml parser (multi-module reactor, parent chain, <dependencyManagement>, BOM imports, ${…} property expansion, workspace-local sibling filter)
      build_gradle.py         build.gradle[.kts] heuristic text parser (static-string dependency declarations; variable interpolation and version catalogs deliberately not supported — see ecosystem-doc)
      gradle_lockfile.py      gradle.lockfile parser (classpath-attributed PROD/DEV split; supersedes the build.gradle heuristic when present)
    dotnet/
      csproj.py               .csproj / .fsproj / .vbproj (SDK-style + legacy MSBuild-namespace; <PackageReference>; PrivateAssets="all" / Condition → DEV; CPM versionless refs + $(Property) tokens stitched in discovery.__init__)
      packages_config.py      packages.config (legacy NuGet 2.x)
      directory_packages_props.py  Directory.Packages.props (Central Package Management <PackageVersion> + implicit GlobalPackageReference DEV rows)
      directory_build_props.py     Directory.Build.props / .targets (MSBuild property inheritance via closest-ancestor chain + <Import> resolution)
      paket.py                paket.dependencies + paket.lock (Paket package manager; NUGET group resolves through api.nuget.org)
      lockfiles.py            packages.lock.json + project.assets.json parsers (transitive; per-TFM resolved graph unioned across target frameworks)
    php/
      composer_json.py        composer.json parser (require + require-dev; platform pseudo-packages filtered; license-field array → OR-joined disjunction)
      lockfiles.py            composer.lock parser (packages + packages-dev; trusts explicit `dev` flag; extracts embedded SPDX license map for lockfile-first resolver)
    ruby/
      gemfile.py              Static Gemfile parser (line-oriented regex + block-nesting state machine; never executes Ruby; git/path/github sources flagged off-registry; dev attribution from :development/:test groups)
      gemspec.py              Static *.gemspec parser (regex-only; `license` / `licenses` extraction; runtime vs development add_*_dependency split; workspace-internal name filter for multi-gemspec monorepos)
      lockfiles.py            Gemfile.lock parser (2/4/6-space indent contract per Bundler's grammar; platform suffix stripped; off-registry marker on GIT/PATH/PLUGIN SOURCE specs)
    hex/
      mix_exs.py              Static mix.exs parser (Elixir; flat `deps` tuple list, never executed; `only: :dev|:test` → dev; git/github/path/in_umbrella off-registry; `package` `licenses` → project license; umbrella `app:` workspace filter)
      mix_lock.py             mix.lock parser (Elixir map literal; edge-aware via the 6th tuple element → reverse-BFS group attribution; `:git`/`:path` off-registry; shared `_split_top_level`/`_strip_line_comments`/off-registry-marker term helpers)
      rebar_config.py         Static rebar.config parser (Erlang terms; top-level `{deps,…}` → prod, `{profiles,[{test|dev,…}]}` → dev; `{pkg,…}` hex-rename; `{git,…}` off-registry)
      rebar_lock.py           rebar.lock parser (Erlang terms; level/section-based — depth levels, NO edges, like Pipfile.lock; level-0 grouped by rebar.config profile, level-≥1 conservative PROD with no ancestors)
      erlang_mk.py            Static erlang.mk Makefile parser (DEPS/REL_DEPS prod, TEST/BUILD/DOC/SHELL_DEPS dev, LOCAL_DEPS=OTP skipped; `dep_<name> = hex VER | git URL`; gated on `include erlang.mk`, never parses erlang.mk itself; manifest-only → registry walk; PROJECT-name monorepo workspace filter unioned with Mix umbrella apps)
    r/
      _dcf.py                 Debian-control-file (DCF) parser shared by DESCRIPTION + packrat.lock
      description.py          DESCRIPTION manifest (Imports/Depends/LinkingTo → prod, Suggests/Enhances → dev; filters the `R` pseudo-package + base-priority packages not on CRAN; project `License` via normalize_r_license)
      renv_lock.py            renv.lock parser (JSON; `Requirements` edges → reverse-BFS; GitHub/Bioconductor/Local → off-registry)
      packrat.py              packrat/packrat.lock parser (DCF; `Requires` edges; `Source: CRAN` on-registry, else off)
      _lock.py                shared edge-attribution (reverse-BFS group/ancestors) + off-registry marker for both R lockfiles
  resolvers/
    pypi.py                   PyPI JSON API + PEP 658 wheel-metadata fallback + transitive deps fetcher
    npm_registry.py           npm registry API + transitive deps fetcher
    crates_io.py              crates.io JSON API + transitive deps fetcher
    deps_dev.py               api.deps.dev v3alpha batch + v3 stable single-version (single cross-ecosystem batch pre-pass for Python/npm/Rust/Go/NuGet/Java/Ruby license resolution — all ecosystems' chunks share one pool; Maven :dependencies endpoint for Java transitive resolution — note: deps.dev's GetDependencies is documented for npm/Cargo/Maven/PyPI only, NOT Go/NuGet/RubyGems)
    maven_central.py          Maven Central raw POM XML fetch + parent-chain walk + URL-prefix license-fallback + deps.dev fallback; hard-coded fallback-registry list for parents not on Central (Google Android Maven, Jenkins)
    nuget.py                  NuGet flatcontainer raw `.nuspec` XML (modern `<license type="expression">` direct SPDX; legacy `<licenseUrl>` → `spdx_from_license_url` URL-pattern map, no body fetch); deps.dev NUGET batch + v3 single-version GET fallback (cli dispatch); recursive nuspec-based transitive walk
    packagist.py              Packagist v2 metadata JSON fetch (per-package version-history); lockfile-first design — consults composer.lock's embedded SPDX license map before any HTTP call
    rubygems.py               RubyGems.org v2 per-version endpoint primary (`/api/v2/rubygems/{name}/versions/{version}.json`); v1 latest-version fallback for unpinned (`/api/v1/gems/{name}.json`); deps.dev RUBYGEMS batch pre-pass
    hex.py                    hex.pm package endpoint (`/api/packages/{name}` — package-level `meta.licenses`/`meta.links`/`latest_stable_version`) + release endpoint (`/api/packages/{name}/releases/{version}` — transitive `requirements` edges); hex.pm-only (deps.dev does not index Hex), no batch pre-pass
    cran.py                   Official CRAN PACKAGES index (`cran.r-project.org/src/contrib/PACKAGES` — fetched + parsed once per scan into a name→record map; License + edges for every current package); resolve license + transitive closure from the local map, no per-package requests; R license-grammar → SPDX via `analysis.spdx.normalize_r_license`
    http.py                   Shared registry HTTP behavior + per-scan RegistryCache (URL dedup, response trimming, in-flight collapse) + PEP 658 sidecar fetch
    version_selection.py      Range-aware version selection helpers
```

`LicenseInfo` keeps `license_id` as the detected license. A reviewed override goes in `reviewed_license_id`; the `effective_license_id` property returns the override when set, otherwise the detected one. Compatibility analysis and reports operate on the effective license; both stay visible side by side in the report.

`Dependency` carries `depth` (0 for direct, ≥1 for transitive) and `direct_ancestors: tuple[str, ...]` — the depth-0 deps that pull the entry in. Reports nest transitives under their alphabetically-first direct ancestor; shared transitives carry an `(also: X, Y)` annotation. JSON output exposes the full ancestor list.

Review keys are `<ecosystem>:<canonical-name>@<version>`. Python names are PEP 503 normalized (`-_.` collapsed and lowercased); npm names are lowercased.

## Architecture: manifest + registry only

**This is the load-bearing architectural constraint.** licenseal reads two kinds of input:

1. **Manifests on disk** — files in the scan target's source tree that declare dependencies: `pyproject.toml`, `requirements*.txt`, `setup.cfg`, `setup.py`, `Pipfile`, `package.json`, `Cargo.toml`, `go.mod`, `go.work`, `pom.xml`, `build.gradle[.kts]`, `.csproj` / `.fsproj` / `.vbproj`, `packages.config`, `Directory.Packages.props`, `Directory.Build.props` / `.targets`, `paket.dependencies`, `composer.json`, `mix.exs`, `rebar.config`, erlang.mk `Makefile`, the corresponding lockfiles (`mix.lock`, `rebar.lock`, …), and the project's own license declaration where the manifest format carries one.
2. **Registry APIs over HTTPS** — read-only metadata endpoints listed in SECURITY.md: PyPI JSON, npm registry, crates.io API, deps.dev v3/v3alpha, proxy.golang.org `go.mod` text, Maven Central POM XML, NuGet flatcontainer `.nuspec` XML, Packagist v2 metadata JSON, RubyGems v1/v2 JSON, hex.pm package / release JSON, plus the hard-coded Maven fallback registries (Google Android, Jenkins) configured in `resolvers/maven_central.py:_FALLBACK_POM_REGISTRIES`. PEP 658 wheel-metadata sidecars served by `files.pythonhosted.org` count as registry endpoints — they're a standardized HTTPS mechanism PyPI exposes for reading wheel metadata without downloading the wheel itself.

That is the complete input surface. licenseal does **not**:

- Download or inspect **artifact bodies** — `.jar`, `.whl`, `.tar.gz`, `.crate`, `.tgz`, `.aar`, `.war`, `.gem`, `.egg`, `.zip`, or any other built/source archive. Even when the artifact contains structured fields a registry doesn't expose (Maven's `MANIFEST.MF` `Bundle-License` header, a wheel's bundled `METADATA` file when not served as a PEP 658 sidecar, etc.), licenseal does not fetch the body to read them.
- **Install, build, or execute** scan-target code or its dependencies — no `pip install`, `npm install`, `cargo build`, `mvn`, `gradle`, `setup.py`, `npm` lifecycle scripts, or any other package-author code. This is a stricter line than "manifest + registry only" (an attacker who got us to download a malicious JAR would still execute no code), but the two rules are complementary: installs are one obvious way to leave the safe surface; artifact-body reads are another.
- **Extract license identifiers from free-form prose** — LICENSE file contents, copyright headers, README mentions. Soft textual signals can only route a dep toward manual review, never to a permissive verdict. The two ecosystem-official exceptions are PEP 658 `License:` / `License-Expression:` headers (RFC 5322, structured) and deps.dev's `licensecheck` SPDX template matching (Google operates the indexer, runs the matcher server-side, and exposes only the structured SPDX result in the response) — both are reads of *structured registry fields*, not prose extraction by licenseal.
- **Trust scan-target POMs to declare additional registry URLs.** Maven's `<repositories>` block is read by real `mvn` to discover where to fetch parent / dependency POMs. licenseal does not honor it: an attacker controlling a POM could redirect license-resolution fetches to attacker-controlled hosts (Server-Side Request Forgery + cross-artifact license misinformation). When a project's deps live on registries beyond Maven Central, the registry must be in the hard-coded `_FALLBACK_POM_REGISTRIES` list (criterion in SECURITY.md), reviewed once at code level.

When implementing a new ecosystem or extending an existing one, every license-resolution path must terminate at a structured field in a manifest or a registry-served response. "Just read the JAR for the Bundle-License," "honor the POM's `<repositories>` block to find this parent," and "scan the README for an SPDX hint" are out of scope. The principle is restated in SECURITY.md in the network-allowlist context.

## Pipeline

`cli.check()` runs: detect project license → discover direct deps (both prod and dev — `--dev` only filters at the end) → expand the dep list via `transitive.resolve_transitive` (default; lockfile-first when one of the supported lockfiles is present, recursive registry walk otherwise) → resolve licenses via live registry lookups → analyze → optionally apply `licenseal.review.toml` overrides for flagged deps and re-classify only the overridden subset → render report. `--no-transitive` skips the expansion step.

Lockfile parsers extract per-package dependency edges (`uv.lock` `dependencies = [...]`, poetry.lock `[package.dependencies]`, package-lock.json / pnpm / yarn `dependencies` fields), then `_graph.compute_direct_ancestors` runs reverse-BFS from each root set to attribute group + direct ancestors per package: a transitive reachable from a `prod` direct dep is `prod`; otherwise `dev` if reachable from a `dev` direct dep; otherwise dropped as an orphan. With `--no-dev`, dev-only chains never reach the report. `Pipfile.lock` is the exception: it carries no per-package edges, so group is attributed by section (`default` → PROD, `develop` → DEV) and transitives' `direct_ancestors` stays empty.

`cli.init_review_file()` runs: detect project license → discover direct deps → resolve licenses (or read flagged entries from a `--from-report` JSON file) → scaffold or merge `licenseal.review.toml` stanzas for flagged dependencies. With `--merge`, existing entries are preserved verbatim and only missing flagged entries are appended.

If no project license is detected, it defaults to "Proprietary" (treated as permissive risk level — a proprietary project can use permissive dependencies but not copyleft). Proprietary licenses on *dependencies* are always flagged for manual review regardless of the project's license — `compatibility._check_compat` short-circuits before the matrix in that case because custom commercial terms can't be auto-classified.

The PyPI JSON API at `/pypi/{name}/{version}/json` supports PEP 639's `License-Expression` (since the [warehouse PEP 639 implementation](https://github.com/pypi/warehouse/issues/16620) landed late 2024) alongside the legacy `license` field and classifiers — and the vast majority of Python deps (~97% in measured stress-test corpora) resolve cleanly through one of those three fields. A small minority (~3% in our corpus) hit an indexer gap where all three JSON fields come back null even though the wheel's own `METADATA` file (PEP 643) carries clean license data — affected packages cluster around organizations that publish via newer build pipelines with PEP 639 syntax, plus some vendor-proprietary wheels using LicenseRef-* identifiers. The exact trigger isn't documented externally; it's a PyPI-side issue, not a deliberate design choice. For those gap cases, `resolve_python_license` falls back to PEP 658's `.metadata` sidecar (`fetch_pep658_metadata` in `resolvers/http.py`) — the officially-standardized HTTPS mechanism for reading the wheel's canonical `METADATA` file directly. The fallback reads `License-Expression:` first, then a short single-line legacy `License:` value (guarded by length + `_is_junk_license` prose-marker filter). Long license-text bodies don't survive the header parser (it stops at the first blank line and skips RFC 5322 continuation lines) — the no-prose-extraction rule still applies. The wheel URL is preserved through the cache (`_trim_pypi` flattens it into a `wheel_url` key) so the fallback works on the cached production path.

Strict mode is the default for `licenseal check`: violations, warnings, unknowns, and analysis gaps all fail the command. `--no-strict` demotes warnings, unknowns, and gaps to CI-passable, **but violations always fail regardless of this flag** — a violation means the matrix found a definite legal incompatibility (e.g., a GPL dep in an MIT project) and silencing it via `--no-strict` would defeat the purpose of the verdict. An **analysis gap** is a manifest/lockfile that couldn't be read or parsed (or a directory that couldn't be traversed); every read+parse routes through `discovery/_read.py`, which records the gap on a context-scoped sink that the CLI drains to stderr after the scan. A gap is morally an UNKNOWN — the scan can't vouch for what it never saw — so strict fails on it; a non-UTF-8 file that's still recovered via latin-1 fallback warns but is not a gap. Reviewed entries (`licenseal.review.toml` stanza applied) are excluded from the failure check at every level — an explicit review is the user's accept-and-document mechanism, and the rationale lives in the `note` field. Reviewed deps still appear in their respective `warnings` / `violations` / `unknown` counters; only the CI exit code is suppressed for them. Independently of strict mode, if every registry request fails and not one dependency resolves (no connectivity, blocked egress, or a registry-wide outage), `check` aborts with a hard `ClickException` (`_registries_unreachable` in `cli.py`, fed by `RegistryCache`'s per-scan fetch tallies) — reporting an all-UNKNOWN scan as advisory under `--no-strict` would be a false clean. Partial failures (at least one dep resolved, or any fetch returned data) stay on the per-dep UNKNOWN path.

Dev dependencies are excluded by default and included only when `--dev` is set. Go has no general dev/prod marker in `go.mod` (every entry in a `require` block ships with the project, and `// indirect` is a tooling annotation rather than a dev signal); the only declarative dev marker is the Go 1.24+ `tool` directive (covered in detail below). On Go projects that don't use the `tool` directive, `--dev` and `--no-dev` produce identical reports.

**Batch-first license resolution.** For every ecosystem that deps.dev indexes (Python / npm / Rust / Go / NuGet / Java / Ruby), `cli.check` issues a single combined `POST /v3alpha/versionbatch` pre-pass against `api.deps.dev` (`resolvers/deps_dev.bulk_resolve_licenses`, keyed by deps.dev system identifier) before the per-dep resolution map runs, populating per-ecosystem `(name, version) → LicenseInfo | None` caches. The endpoint accepts up to 5000 `(name, version)` pairs per request but caps each response at **exactly 100 entries regardless of request size** — the excess deps come back silently absent from `responses` (verified empirically: request 101 → 100 returned, request 1000 → 100 returned). So `_BATCH_CHUNK_SIZE` in `resolvers/deps_dev.py` is pinned to 100. **Do not raise it:** a chunk larger than 100 silently drops the tail of every batch (those deps fall through to the per-package path at best, or resolve to UNKNOWN at worst) — it is a load-bearing API limit, not a throughput tunable. A scan of N pinned deps fans out across ⌈N/100⌉ POSTs — every ecosystem's chunks through ONE shared threadpool whose width is capped at `_BATCH_MAX_WORKERS = 8` (`min(chunks, max_workers, _BATCH_MAX_WORKERS)`) **independently of `--max-workers`**: each POST is a heavyweight server-side license scan over up to 100 packages, so the batch endpoint is held to a lower concurrency than the per-package GETs that `--max-workers` otherwise governs. Polyglot scans overlap their per-ecosystem batches inside that same ceiling instead of paying one sequential pool round per ecosystem — the cap bounds the *combined* in-flight POST count, so ecosystems share the budget rather than multiplying it. `--max-workers` still throttles the batch *downward* (a lower value is respected); the cap only bounds the ceiling. **Don't remove the cap** in a "let `--max-workers` drive all concurrency" cleanup — it's the deliberate, documented per-endpoint knob the concurrency note in `resolvers/http.py` anticipates. Per-dep dispatch checks the cache first and falls back to the per-package official-registry resolver (`resolve_python_license`, `resolve_npm_license`, `resolve_rust_license`, `resolve_maven_central_license`, `resolve_nuget_license`, `resolve_ruby_license`) when the cache entry is absent, came back without licenses, or carries `license_id == "UNKNOWN"`. **Authoritative-vs-advisory cache semantics:** for Go (no manifest license field — deps.dev IS the canonical source), a `None` cache entry is authoritative (return UNKNOWN without further fetch). For Python / npm / Rust / Java / NuGet / Ruby, `None` is advisory — PyPI / npm registry / crates.io / Maven Central / NuGet flatcontainer / RubyGems remain available and the per-package fallback always runs.

Go's canonical license-declaration mechanism is the `LICENSE` file at module root (Go has no manifest field for license, by design — the language is decentralized-publishing). deps.dev (the Google-operated Open Source Insights project) runs Google's `licensecheck` library — high-confidence Sørensen-Dice SPDX template matching against canonical license texts — over each module's LICENSE file at the version's tagged commit and emits structured SPDX identifiers in the response's `licenses` array. This is the canonical Go-ecosystem reader of the canonical Go-ecosystem declaration — not prose extraction (which scans loose textual mentions in non-canonical fields); the no-prose-extraction rule explicitly carves out ecosystem-official template matchers operating on the conventional declaration site (see the refined `feedback_no_prose_license_extraction` memory). For Python / npm / Rust the same template-matcher output is treated as one of several equally-trustworthy registry signals: the per-package fallback reads the publisher-declared SPDX field directly (`pyproject.toml`'s `License-Expression`, `package.json`'s `license`, `Cargo.toml`'s `license`), and `analysis/spdx.normalize_license` operand-canonicalizes both sources so equivalent expressions (`MIT OR Apache-2.0` vs `Apache-2.0 OR MIT`) compare equal regardless of provenance.

Go transitive resolution is edge-aware, mirroring the npm/Rust/Python lockfile path. `go.sum` enumerates the pinned-module universe but carries no edge data, so `transitive.py`'s `_resolve_go_transitive` fetches each module's own `go.mod` from `proxy.golang.org/<encoded-module>/@v/<version>.mod` (uppercase letters case-encoded as `!<lc>` per the proxy spec). deps.dev's `GetDependencies` sub-resource is documented as available only for npm, Cargo, Maven, and PyPI (not Go), so proxy.golang.org is the only canonical source for Go edges — it's the same endpoint the `go` toolchain itself consults during builds. Edges are parsed from each fetched go.mod's `require` block, then `_graph.compute_direct_ancestors` runs reverse-BFS from prod and dev root sets to attribute group + `direct_ancestors` per package. Orphan modules (proxy fetch failed) fall back to PROD as a conservative default rather than being dropped.

Go's dev/prod distinction comes from two sources, both handled in `discovery/go/go_mod.py`:

- **`tool` directive** (Go 1.24+): the `tool ( ... )` block lists import paths of build-time tooling (`stringer`, code generators, etc.). Each tool entry is matched to its require'd module by longest-prefix lookup; the matched module is emitted as `DependencyGroup.DEV`. Transitives reachable only from a DEV root inherit DEV via the reverse-BFS attribution; `--no-dev` drops them.
- **`// indirect` marker** is NOT a dev signal — it just means the dep was added by `go mod tidy` for a transitive's sake. Treated as PROD.

Test-only deps (imported only by `*_test.go` files) are NOT separable from production deps in go.mod metadata — both appear in the same `require` block. Distinguishing them would require source-code analysis, which is out of scope for a metadata-only scanner.

**Workspace-local filter.** Go projects use the LICENSE-file-of-the-module convention, so cross-module requires within a monorepo (e.g. `cli/go.mod` requiring `server` declared in `server/go.mod`) would 404 on deps.dev because those modules aren't published publicly. `_discover_workspace_local_module_paths` in `discovery/go/go_mod.py` collects workspace-local module paths from two sources: (a) every in-tree `go.mod`'s `module <path>` declaration (covers implicit-monorepo layouts), and (b) `go.work`'s `use <dir>` directives at the project root (covers explicit multi-module workspaces, including `use ../sibling` targets outside the project tree). The same set is applied at two places — discovery filters direct deps whose name matches a workspace-local path before emission, and `transitive.py`'s `_resolve_go_transitive` re-applies it when iterating `go.sum` (necessary because workspace siblings sometimes leave entries in `go.sum` when they were previously imported as versioned requires; without this second filter those entries leak into the transitive output and waste registry calls).

Discovery walks the project tree recursively. The walker skips a unified set of directory names regardless of ecosystem — VCS / cache dirs (`.git`, `.tox`, `.nox`, `__pycache__`, `node_modules`), sample / fixture trees (`examples`, `fixtures`, `__fixtures__`), build / dist / vendor outputs (`build`, `dist`, `target`, `.eggs`, `site-packages`, `vendor`), PEP 582 / pdm trees (`__pypackages__`, `.pdm-build`), JS framework build outputs that ship a synthetic `package.json` (`.next`, `.nuxt`, `.svelte-kit`), and Yarn Berry state / legacy package-manager trees (`.yarn`, `bower_components`, `jspm_packages`). Virtualenvs are detected *structurally* via the PEP 405 `pyvenv.cfg` marker rather than by name, so `.venv/`, `venv/`, `env/`, `env-3.11/`, `.venv-dev/`, and any other naming convention are all skipped without false positives on legitimately-named source dirs. It also skips any subdirectory that has its own `.git` (file or directory), so cloned dependencies, vendored forks, and submodules are treated as separate projects. Additional subtrees can be excluded with `--exclude-dirs PATH[,PATH...]` (comma-separated and/or repeatable, available on both `check` and `init-review-file`); paths are relative to `--path` or absolute.

## Adding a new ecosystem

A new ecosystem (e.g. Maven, NuGet, RubyGems, Swift PM) touches every list below. Partial wiring silently drops deps on whichever path is missed, so go through all of it.

### Codebase

1. **Enum + label.** Add the new value to `models.Ecosystem` **and its display label to `_ECOSYSTEM_LABELS`** (same module). The CLI workspace-filter echo iterates the enum and reads `.label`, so a missing label fails `test_every_ecosystem_has_a_label` rather than silently dropping a per-ecosystem line (the drift that left `.NET`/`Ruby`/`Hex` unannounced before the echo was made data-driven).
2. **Discovery package.** Create `discovery/<eco>/` with one module per manifest format. Each exports `discover_<format>_dependencies(project_path, *, exclude_paths) -> (list[Dependency], int)` (the int is the workspace-internal filter count) and, when the manifest can carry the project's own license, `detect_project_license_<format>`. Use `discovery._walk.walk_project_files` so the shared skip-dir set applies. Read every manifest through `discovery._read` — `decode_text` (text), `read_xml_bytes` + `record_parse_failure` (XML), or `load_json` / `load_toml` / `load_yaml` (structured) — never raw `read_text` / `json.loads`. The loaders are BOM/encoding-aware (Windows PowerShell writes UTF-16/UTF-8-BOM manifests) and record an unreadable or unparseable file as an analysis gap; a bare `read_text` silently drops the file on the first non-UTF-8 byte (and several parsers caught only `OSError`, so it could also crash). On a parse failure the structured loaders return `None`; XML callers must call `record_parse_failure(path, "XML")` themselves since their parse step is separate from the read.
3. **Lockfile parsers.** Add `discovery/<eco>/lockfiles.py` with `find_<eco>_lockfiles(...)` and one parser per format. Parsers must extract per-package dependency edges so `_graph.compute_direct_ancestors` can attribute group + ancestors by reachability. Only fall back to section-based attribution when the format genuinely has no edge data (Pipfile.lock style); set `direct_ancestors=()` there.
4. **Discovery aggregator.** Wire the new discover function into `discovery.__init__.discover_all_dependencies` (extend `local_filter_counts` under the new key) and the detect function into the resolution chain in `detect_project_license`.
5. **Resolver.** Add `resolvers/<eco>.py` with `resolve_<eco>_license(dep, client, *, fetcher)`, `_extract_pinned_version`, and `fetch_<eco>_dependencies(name, version, client, *, parent_depth, parent_group, fetcher)` for the registry walker. Identifier extraction is structured-fields-only — see the no-prose-extraction rule.
6. **Registry cache.** Add `_<ECO>_*_KEEP` frozensets in `resolvers/http.py` listing every field the resolver and walker read, write a `_trim_<eco>(...)` helper, and dispatch on the URL host in `_trim_for_cache`. Resolver unit tests bypass `_trim_for_cache`; also add a test that exercises the resolver through `RegistryCache.fetch` so the keep-set is verified end-to-end.
7. **Transitive walker.** In `transitive.resolve_transitive`, add a lockfile-first branch mirroring existing ecosystems (parse lock → `_walk_uncovered` for direct deps the lockfile missed). Add ecosystem branches in `_resolve_version` and `_walk_one_inner`. If the ecosystem has its own name-normalization rule (PEP 503-style), branch in `_canonical_name`.
8. **CLI.** Add the registry host to `_REGISTRY_HOSTS`, update the `tethered` `hint`, and add a dispatch case in the `_resolve` closure. (The workspace-filter echo is data-driven off `Ecosystem` / `.label` — no per-ecosystem edit needed there beyond the label in step 1.)
9. **Report.** Add a branch in `report._package_url` for the registry's web URL.
10. **Review.** If the ecosystem has its own name-normalization rule, branch in `review.canonical_name`.

### Tests

100% coverage is required, so every code path above needs a test. At minimum:

- `tests/test_discovery_<eco>.py` per manifest format, including the workspace-internal filter path.
- `tests/test_lockfiles_<eco>.py` covering edge-aware group attribution (prod-reachable, dev-only, orphan-drop) and any format quirks (patched / git / path sources, alias renames, etc.).
- `tests/test_resolvers.py` additions for the new resolver, **including** at least one test routed through `RegistryCache.fetch` (not just `fetch_registry_json`) so the cache keep-set is exercised.
- `tests/test_transitive.py` additions for the new lockfile-first path and registry-walk fallback.
- `tests/fixtures/registry-responses/` — captured real-world response snippets matching the trimmed-cache shape.
- Update any test that enumerates ecosystems explicitly (e.g. `test_registry_response_fixtures.py`).

All HTTP is mocked with `respx` — no real network requests.

### Stress-test repos

Add at least one `<eco>`-only repo under `licenseal-scans/` (gitignored) plus one polyglot repo that includes the new ecosystem. Pick repos with non-trivial lockfile graphs so the edge-attribution paths actually fire. Then run the four-stage stress-test protocol below in **both** `--no-dev` and `--dev` modes:

- Save pre-change baselines (`<repo>.scan_baseline.json`, `<repo>.scan_baseline_dev.json`) before the change.
- JSON parity in both modes against the baselines.
- **Per-ecosystem verification:** count deps per `ecosystem` field in the fresh JSON for every polyglot repo and confirm the new ecosystem appears with the expected magnitude. A new ecosystem that silently returns zero deps will pass total-count parity if another ecosystem absorbs the slack — only per-ecosystem counts catch that.
- Markdown report path (non-empty, expected row count).
- Gap-fill loop via `init-review-file` end-to-end.

Same untrusted-code rules apply: manifests and lockfiles only — never install, run, or import scan-target code.

## Rules

- Python 3.10+. `from __future__ import annotations` in every file.
- ruff (line length 100), ty (default rules; `[tool.ty.src]` scopes it to `src/`).
- Network egress is wrapped in `tethered.scope(allow=..., label="licenseal.resolve", hint=...)` — the package-maintainer pattern. `hint` is a human-readable string surfaced by tethered when a host policy blocks the call; it should explain *why* the listed hosts are needed and point at the security-model docs so users get an actionable error instead of a bare hostname. Never call `tethered.activate()` from library code: `activate()` is process-wide and reserved for the host application or local dev. `scope()` intersects with any host policy, so embedding licenseal cannot widen its egress. `tethered.scope()` keeps its policy in a `ContextVar`, which does **not** cross thread boundaries (PEP 567): a registry fetch issued from a bare `ThreadPoolExecutor` worker runs in an empty context and silently bypasses the scope (fail-open). Every fetching threadpool must therefore propagate the caller's context into its workers — route new pools through `licenseal._concurrency.map_with_context` (one `copy_context()` snapshot per task, since a single `Context` can't be entered by two threads at once), the same way the resolution loop (`cli.py`) and the transitive wave-walker do. A raw `pool.map` over a fetcher reopens the egress hole and won't be caught by the unit tests unless a host `tethered.activate()` happens to cover it.
- Requests carry only dependency coordinates `(system, name, version)` plus a static `User-Agent` — never manifest/lockfile contents, file paths, the project name, or credentials. Don't add an `Authorization` header or read `.netrc` / `.npmrc` / `.pypirc` / keyring (no `httpx.NetRCAuth`); the resolution client keeps httpx's `trust_env` default, so `HTTP(S)_PROXY` is honored (licenseal works behind a corporate egress proxy) but `.netrc` is never read implicitly (httpx ≥ 0.28). See SECURITY.md *What leaves the process*.
- License identifiers come only from structured registry fields — PEP 639 `license_expression`, the legacy `license` field when it's an identifier rather than file contents, trove classifiers, lockfile entries. Don't recover identifiers by pattern-matching free-form license-text bodies (LICENSE file contents, copyright headers); those are spoofable and can only safely route deps toward manual review, never to a permissive verdict.
- Changes to risk classifications (`analysis/risk.py`), the compat matrix, or reason strings (`analysis/compatibility.py`) ripple into committed docs that embed matrix semantics by hand. Review and update each in the same change — none are auto-generated, and they drift silently:
  - `README.md` — Compatibility matrix table + Risk levels table.
  - `src/licenseal/data/claude_skill.md` — per-verdict walkthrough (the WARNING / INCOMPATIBLE / UNKNOWN bullets in step 4) and the concrete-examples table. Each matrix cell that can flag a dep must be reachable through a per-dep question pattern in this file.
  - `JSON_OUTPUT.md` — the `risk` enum line and the sample `reason` string.
  - `LICENSES.md` — the sample `reason` string in the Details section.
- 100% test coverage required. Run with parallel workers: `uv run pytest -n 8 --cov=licenseal --cov-report=term-missing` (`pytest-xdist` is in the dev deps; `-n 8` cuts wall-clock by ~4-5×).
- Tests use `respx` to mock HTTP calls. Never make real network requests in tests.
- Keep it simple. No unnecessary abstractions, helpers, or error handling for impossible cases.
- When two ecosystems share an identical type or helper, give the shared definition a domain-neutral name both reference (e.g. `_TransitiveDepsFetcher`), rather than aliasing one ecosystem's name to another's (`_DotnetDepsFetcher = _MavenDepsFetcher`). The cross-domain alias couples the two and makes the borrowed name lie about its scope.
- No specific stress-test repository or package names in source or test comments. Describe the pattern (`large Python projects`, `Cargo workspaces`, `packages with extras-heavy transitives`) instead of the project where you happened to observe it.
- No hardcoded benchmark numbers in comments (MB, timings, `~3.3x` style speedups). They go stale and add noise to readers who aren't running the same workload.
- When stress-testing licenseal against external repositories, treat them as untrusted code. Read their manifest and lockfile contents only; never install their dependencies, run their setup or build scripts, execute their code, or import their packages. licenseal is metadata-only — there's no legitimate development reason to execute code from a scan target, and doing so opens an arbitrary-code-execution surface from third-party projects on local disk.
- Branch from `dev`, PR to `dev`. `main` is releases only.

## Verification

Run the full pre-commit suite and the tests before submitting changes:

```bash
uv run pre-commit run --all-files
uv run pytest -n 8 --cov=licenseal --cov-report=term-missing
```

`pre-commit` is the authoritative static gate and mirrors CI — it runs ruff (check + format), ty, bandit, markdownlint, interrogate, vulture, and the SPDX-ID validator. Running only `ruff check` / `ty check` skips bandit, markdownlint, and the SPDX validator, so a green local run can still fail CI. `pytest` is not a pre-commit hook; run it separately (100% coverage required).

### Stress-testing on real repos

For changes that touch discovery, resolvers, analysis, report rendering, or the review flow, also stress-test against cloned third-party repos. Keep them under `licenseal-scans/` (gitignored) — at minimum one Python-only, one npm-only, one Rust-only, and one polyglot project. Treat scan targets as untrusted code: read manifests and lockfiles only; never install their deps, run their scripts, or import their packages.

If `licenseal-scans/` is missing or doesn't contain coverage for the ecosystems the change touches, ask the user which repos to clone before proceeding. Do not pick repos unilaterally and do not skip the stress-test stages silently.

Skip repos whose primary purpose is distributing offensive payloads, malware samples, exploit binaries, or operational pentest tradecraft (e.g., `metasploit-framework`, `theZoo`, `vx-underground` mirrors, named NSA/APT-toolkit dumps, RAT/loader/stealer source, pentest-tradecraft skill packs). The on-disk binaries trip AV mid-walk — leaving locked directory shells that only release on reboot — and ship no manifest-only signal for licenseal anyway. Filter by repo description and topic tags before cloning, not after; this applies equally to manual clones and to batch-clone scripts under `licenseal-scans/`.

**Conventions for stress-test runs:**

- All scratch artifacts (fresh scans, comparison scripts, filled review files, probes) live under `licenseal-scans/`. Never write them to the repo root.
- Report licenseal-side issues only (parser bugs, dropped deps, classification regressions, format-path failures). The scanned repo's actual license findings are not part of the stress-test output.
- Save a pre-change baseline per repo before starting: `licenseal-scans/<repo>.scan_baseline.json` for `--no-dev` and `<repo>.scan_baseline_dev.json` for `--dev`.

Run all four stages per repo touched by the change:

**1. JSON parity in both modes.** `--no-dev` is the default; `--dev` exercises dev-discovery, dev-reachability attribution, and the dev→warning downgrade paths — run both.

```bash
uv run licenseal check -p licenseal-scans/<repo> --no-dev -f json --no-strict -o licenseal-scans/_fresh_<repo>.json
uv run licenseal check -p licenseal-scans/<repo> --dev    -f json --no-strict -o licenseal-scans/_fresh_<repo>_dev.json
```

Diff against the baselines on (a) `summary` totals, (b) the set of `(ecosystem, name)` keys, and (c) per-dep `(license, risk, verdict)` tuples. Zero diff confirms no regression. Any diff has to be explained by the change.

**2. Per-ecosystem verification (polyglot repos).** Total-count parity hides per-ecosystem bugs — verify each present ecosystem actually fired its expected pipeline path (Python lockfile parsed, npm seeds planted, Rust crates resolved, etc.) by counting deps per `ecosystem` field in the fresh JSON and comparing to the baseline per-ecosystem.

**3. Markdown report path.**

```bash
uv run licenseal check -p licenseal-scans/<repo> --no-dev -f markdown --no-strict -o licenseal-scans/_fresh_<repo>.md
```

Confirm the file is non-empty, starts with a heading, and contains the expected number of table rows (≈ `summary.total` + header rows).

**4. Gap-fill loop (review mechanism).** Validates `init-review-file` end-to-end.

```bash
mkdir -p licenseal-scans/_review_tmp/<repo>
uv run licenseal init-review-file -p licenseal-scans/_review_tmp/<repo> --from-report licenseal-scans/_fresh_<repo>.json
```

If the command emits `Note: N flagged dependencies could not be scaffolded ...`, record N — those deps have no resolved version and can't be keyed by the review file. Replace every `license = ""` with `license = "MIT"` in the generated scaffold, drop the filled file at `licenseal-scans/<repo>/licenseal.review.toml`, then re-run `check --no-dev -f json`. Expected:

- `summary.reviewed` equals the number of filled stanzas
- `summary.warnings + violations + unknown` drops by the same number
- residual flagged count equals N (the unscaffoldable ones)

Remove the dropped `licenseal.review.toml` from the scan repo after the test — clones don't accumulate state between runs.
