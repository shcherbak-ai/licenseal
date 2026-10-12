# Agents

Instructions for AI coding agents working on this codebase.

## Project

licenseal — CLI tool that scans dependency manifests for Python (PyPI), JavaScript / TypeScript (npm), Rust (crates.io), Go (deps.dev), Java / JVM (Maven Central + deps.dev), .NET (NuGet.org + deps.dev), PHP (Packagist), Ruby (RubyGems + deps.dev), Elixir / Erlang (Hex / hex.pm), and R / CRAN (cran.r-project.org), resolves licenses from those registries, and checks compatibility against the project's license.

## Philosophy

- Keep `licenseal` narrow: it is a license checker, not a policy exception manager. Transitive scanning is the default; `--no-transitive` opts out.
- Prefer strict, fail-closed behavior over permissive guesses.
- Manual review can override flagged findings when a maintainer has better license information than the resolver.
- Do not expand the tool into legal workflow or approval tracking unless the user explicitly asks for that tradeoff.

## Architecture

```text
src/licenseal/
  cli.py                      Click CLI entry point
  models.py                   Dataclasses and enums (Dependency, LicenseInfo, RiskLevel, Ecosystem)
  report.py                   Output renderers (table, JSON, Markdown) with hierarchical layout
  review.py                   licenseal.review.toml loading, validation, templating
  transitive.py               Transitive resolution: lockfile first, registry walk for what no lockfile covers
  _graph.py                   Reverse BFS for group and direct-ancestor attribution (`compute_direct_ancestors`)
  _concurrency.py             `map_with_context`: thread-pool fan-out that carries the caller's context into each worker
  analysis/
    spdx.py                   License string → SPDX expression (`normalize_license`, `normalize_r_license`)
    risk.py                   SPDX ID → RiskLevel classification
    compatibility.py          Project-versus-dependency compatibility matrix
  data/                       Package data: the bundled review skill (`claude_skill.md`) and the vendored SPDX ID list
  discovery/
    __init__.py               `discover_all_dependencies`; `detect_project_license` for the manifests of the scanned directory
    _origin.py                Origin strings for git, URL, and path dependencies (`git_origin`, `url_origin`, `path_origin`)
    _read.py                  Every manifest and lockfile read and parse; records analysis gaps; `rejected_path_reference`
    _walk.py                  `walk_project_files`, the shared directory walk and its skip rules; `is_walked_directory`
    python/
      pyproject.py            pyproject.toml (PEP 621, Poetry, PEP 735, `[tool.uv.sources]`)
      requirements.py         requirements*.txt; follows `-r` includes inside the scanned directory, never reads `-c` constraints
      setup_cfg.py            setup.cfg (dependencies from every file in the tree, project license from the scanned directory's file only)
      setup_py.py             setup.py, read with `ast.parse` and never executed
      pipfile.py              Pipfile
      lockfiles.py            uv.lock and poetry.lock (edge-aware), Pipfile.lock (section-based)
    npm/
      package_json.py         package.json (recursive, skips node_modules, filters workspace-internal names)
      _specs.py               Classifies an npm spec or a lockfile `resolved` value: registry, git, tarball URL, or path (`path_spec`)
      lockfiles.py            package-lock.json (v1, v2/v3), pnpm-lock.yaml (v6, v9), yarn.lock (v1, Berry), bun.lock; `find_npm_lockfiles`
    rust/
      cargo_toml.py           Cargo.toml (`[workspace.dependencies]` is a version catalog); `cargo_sources` feeds the Cargo.lock pass and the registry walk
      lockfiles.py            Cargo.lock (edge-aware)
    go/
      go_mod.py               go.mod (`require`, `replace`, `// indirect`, the Go 1.24+ `tool` directive) and go.work `use`
      lockfile.py             go.sum; the edge graph and group attribution live in transitive.py
    java/
      pom_xml.py              pom.xml (multi-module reactor, parent chain, `<dependencyManagement>`, BOM imports, `${…}` properties)
      build_gradle.py         build.gradle[.kts], a text parser for static-string declarations; USAGE.md lists what it skips
      gradle_lockfile.py      gradle.lockfile (PROD/DEV split by classpath)
    dotnet/
      csproj.py               .csproj / .fsproj / .vbproj (SDK-style and legacy); CPM versions and `$(Property)` tokens are stitched in discovery/__init__.py
      packages_config.py      packages.config (legacy NuGet 2.x)
      directory_packages_props.py  Directory.Packages.props (Central Package Management)
      directory_build_props.py     Directory.Build.props / .targets (property inheritance, `<Import>` resolution, their own `<PackageReference>` items)
      paket.py                paket.dependencies and paket.lock; the more-indented lines under a lock package are edges, never packages
      lockfiles.py            packages.lock.json and project.assets.json (edge-aware, unioned across target frameworks)
    php/
      composer_json.py        composer.json (`require`, `require-dev`, `repositories`)
      lockfiles.py            composer.lock, with the embedded license map the resolver reads before any request
    ruby/
      gemfile.py              Gemfile, a static line parser that never executes Ruby
      gemspec.py              *.gemspec (regex-only)
      lockfiles.py            Gemfile.lock
    hex/
      mix_exs.py              mix.exs, a static parser; the file is never executed
      mix_lock.py             mix.lock (edge-aware); its term helpers are shared with mix_exs.py and the rebar parsers
      rebar_config.py         rebar.config (Erlang terms)
      rebar_lock.py           rebar.lock (depth levels, no edges, like Pipfile.lock); `source_origin`
      erlang_mk.py            erlang.mk Makefile, gated on `include erlang.mk`; erlang.mk itself is never parsed
    r/
      _dcf.py                 Debian-control-file (DCF) parser shared by DESCRIPTION and packrat.lock
      description.py          DESCRIPTION
      renv_lock.py            renv.lock (edge-aware)
      packrat.py              packrat/packrat.lock (edge-aware)
      _lock.py                Edge attribution and hosted-repository origins shared by the two R lockfiles
  resolvers/
    pypi.py                   PyPI JSON API, PEP 658 wheel-metadata fallback, dependency fetcher
    npm_registry.py           npm registry API, dependency fetcher
    crates_io.py              crates.io API, dependency fetcher; `_resolve_version` resolves a range against the non-yanked versions
    deps_dev.py               deps.dev license batch (`bulk_resolve_licenses`), single lookup, Maven `:dependencies` (documented for npm, Cargo, Maven, PyPI only)
    maven_central.py          Maven Central POMs with parent chain, the hard-coded fallback registries, deps.dev fallback; `estimate_gradle_version`
    nuget.py                  NuGet flatcontainer `.nuspec` (license, recursive dependency walk); `_resolve_version` turns a declared range into a version
    packagist.py              Packagist v2 metadata; composer.lock's license map is consulted before any request
    rubygems.py               RubyGems v2 per-version endpoint, v1 latest-version endpoint for an unpinned gem, the version list when a version must be chosen
    hex.py                    hex.pm package endpoint (licenses, releases) and release endpoint (requirements); no deps.dev batch
    cran.py                   CRAN `PACKAGES` index, fetched once per scan; license and transitive closure from the local map
    http.py                   Retries, per-host rate limits, the per-scan `RegistryCache` (URL dedup, response trimming), PEP 658 sidecar fetch
    version_selection.py      Version grammar of every ecosystem: `satisfies`, `select_version`, `is_prerelease`, `concrete_maven_version`
```

The *Per-ecosystem resolution detail* section of `USAGE.md` is the specification for which dependencies are dev and which are off-registry. Change it in the same change as the parser.

**Licenses.**

- `LicenseInfo.license_id` is the detected license and `reviewed_license_id` a reviewed override. The `effective_license_id` property returns the override when set, otherwise the detected one. Compatibility analysis and reports use the effective license, and reports show both.
- When a source lists several licenses without defining the list (a RubyGems / Hex `licenses` array, several PyPI license classifiers, a comma- or slash-separated list in one license string), the resolver also sets `all_apply_license_id` (`analysis.spdx.read_license_array` for an array, `all_apply_reading` for a list inside one string). `compatibility._check_compat` judges both readings and reports UNKNOWN when the verdicts differ.
- A source that defines its separator says so in the call (a Cargo license passes `slash_is_choice=True`).

**Rows.**

- `Dependency.depth` is 0 for a direct dep and ≥1 for a transitive; `direct_ancestors: tuple[str, ...]` holds the depth-0 deps that pull the entry in. Reports nest a transitive under its alphabetically-first direct ancestor, with an `(also: X, Y)` annotation when it has others; JSON carries the full list.
- Each result is exactly one row, and no two results of a scan agree on ecosystem, identity, resolved version, and origin (`cli._merge_duplicate_rows`).

**Off-registry dependencies.** An off-registry dependency is one declared from a git repository, a direct URL, or a path the scan does not read. Its `Dependency.origin` holds the source as one normalized string built by `discovery/_origin.py` (`git_origin`, `url_origin`, `path_origin`), which also strips URL credentials; `origin` is empty for a registry package. `path_origin` returns `None` for a path the scan reads (`_walk.is_walked_directory`): that is the project's own code, and the parser emits no dependency for it.

- An off-registry dependency is never turned into a registry request: `cli._resolve` answers UNKNOWN for it before any resolver runs, the deps.dev batch is built from the dependencies without an origin, and the registry walk neither resolves nor expands it. Any new code path that builds a request from a `Dependency` must skip `dep.origin` the same way.
- The origin is part of a row's identity. A package that one manifest declares off-registry and another declares as a registry requirement is two rows; a path that resolves rows by package name alone must keep the two apart.
- An alternate index or registry is not an origin: those names resolve against the public registry.

**Direct deps and lock coverage.**

- `discover_all_dependencies` keeps one direct dep per `(ecosystem, identity, version constraint)`, and per `(ecosystem, identity, origin)` for an off-registry dependency, so a package can have several direct deps. Code that needs the direct deps of a package groups them with `transitive._declarations`, never with a name-keyed map.
- A lockfile covers a declaration only at a version that satisfies it and from the source the declaration names. `transitive._covers` is the one comparison (`_meets` for versions, `_origin.same_source` for origins), and `False` is its only answer that means not covered (`None`, for a pair that cannot be compared, counts as covered).
- The uncovered declarations go through the registry walk, with a missing-lockfile diagnostic on their manifests.

**Estimates.** Neither flag is a diagnostic, and neither plays a part in `cli._should_fail`.

- `Dependency.version_estimated` is True when licenseal picked the reported version from a registry instead of taking it from a lockfile entry or an exact pin in a manifest (`transitive.flag_version_estimate`).
- `LicenseInfo.license_estimated` is True when `license_id` was read from metadata that describes a release other than `resolved_version`; the R, Hex, and Python resolvers set it. A resolver that reads a package-level or latest-release field for a pinned version must set it.

**Versions.** The version grammar of every ecosystem lives in `resolvers/version_selection.py`: `satisfies(ecosystem, version, constraint)` and `select_version(ecosystem, constraint, published)`.

- When selection returns nothing the dependency is UNKNOWN with no version. A resolver must not fall back to the latest release or to the first entry of a response, whose license belongs to another version.
- Whether a Maven or Gradle version string names one version is decided in one place, `concrete_maven_version`. A second reading of Maven versions must not be added beside it.
- A resolver that puts a manifest's version text into a URL must check which spellings its registry answers for (a NuGet version is normalized first; a RubyGems pin is looked up under the published spelling when the spelling as written misses).

**Package identity.**

- Never compare package names with a bare `.lower()`. `Ecosystem.identity(name)` (`models.py`) is the one rule for which names are the same package, and every key that tells packages apart is built with it: review keys, dedupe, the direct-dep name sets and edge graphs of the lockfile parsers, lock coverage, workspace-name filters, and report nesting.
- Any path that renders review entries must pass them through `review.writable_entries` first: a lone surrogate in a name, version, or source makes the whole TOML file unloadable.
- The identity is the name as written for Go, Java, npm, and Ruby, case-folded for .NET, PHP, Rust, Hex, and R, and PEP 503 for Python (`-_.` collapsed and lowercased).
- Review keys are `<ecosystem>:<identity>@<version>`, built from `effective_registry_name`: a Hex dep that `mix.exs` renames is keyed on the hex.pm package, and the JSON report carries that name as `registry_name`. An off-registry dependency is keyed `off-registry <ecosystem>:<canonical-name> from <origin>` instead (`review.source_review_key`).

## Architecture: manifest + registry only

licenseal reads two kinds of input and nothing else:

1. **Manifests and lockfiles on disk** (listed in USAGE.md), and the project's own license declaration where a manifest carries one.
2. **Registry APIs over HTTPS**: the read-only endpoints listed in SECURITY.md, the Maven fallback registries in `resolvers/maven_central.py:_FALLBACK_POM_REGISTRIES`, and PEP 658 `.metadata` files on `files.pythonhosted.org`, which hold a wheel's metadata without the wheel.

licenseal does **not**:

- **Download or inspect artifact bodies**: `.jar`, `.whl`, `.tar.gz`, `.crate`, `.tgz`, `.aar`, `.war`, `.gem`, `.egg`, `.zip`, or any other built or source archive, even for a structured field no registry exposes (the `Bundle-License` header of a JAR's `MANIFEST.MF`, a wheel's `METADATA` when it is not served as a PEP 658 sidecar).
- **Install, build, or execute** the scanned project's code or its dependencies: no `pip install`, `npm install`, `cargo build`, `mvn`, `gradle`, `setup.py`, `npm` lifecycle scripts, or any other package-author code.
- **Extract license identifiers from free-form prose** (LICENSE file contents, copyright headers, README mentions). This is the no-prose-extraction rule: such text is spoofable, and a soft textual signal can only route a dep toward manual review, never to a permissive verdict. Two reads of structured registry fields are not prose extraction: PEP 658 `License:` / `License-Expression:` headers, and deps.dev's `licensecheck` result, which the server computes and returns as SPDX identifiers.
- **Trust a scanned POM's `<repositories>` block.** A POM could redirect license-resolution fetches to a host its author controls (server-side request forgery, and wrong licenses for other artifacts). A registry beyond Maven Central must be in the hard-coded `_FALLBACK_POM_REGISTRIES` list (criterion in SECURITY.md), reviewed at code level.

Every license-resolution path must terminate at a structured field in a manifest or a registry-served response.

## Pipeline

`cli.check()` runs:

1. Detect the project license.
2. Discover direct deps, prod and dev (`--dev` only filters at the end).
3. Expand the dep list with `transitive.resolve_transitive`: lockfile-first when a supported lockfile is present, a recursive registry walk otherwise. `--no-transitive` skips this step; in its place `transitive.resolve_declared_versions` gives each `pom.xml` dependency the version its parent chain supplies.
4. Resolve licenses through registry lookups.
5. Analyze.
6. Apply `licenseal.review.toml` entries to flagged deps and re-classify only the reviewed ones.
7. Render the report.

A direct dependency must resolve to one version in both modes: the registry walk and the ecosystem's license resolver resolve a declaration through one shared function. Put a lookup that fixes a declared version where both paths call it, never inside the graph walk.

**Group attribution.** Dev dependencies are excluded unless `--dev` is set. Lockfile parsers extract per-package dependency edges, and `_graph.compute_direct_ancestors` runs a reverse BFS from the prod and the dev direct deps to attribute group and direct ancestors: a transitive reachable from a `prod` direct dep is `prod`; otherwise `dev` if reachable from a `dev` direct dep; otherwise dropped as an orphan. With `--no-dev`, dev-only chains never reach the report.

- Production takes precedence on every path: a `dev` direct dep that a `prod` direct dep reaches is `prod`.
- `--dev` only adds rows; it must never turn a row that `--no-dev` reports as `prod` into `dev`.
- In the registry walks attribution is per resolved version, not per name.
- `Pipfile.lock` carries no per-package edges, so group is attributed by section (`default` → PROD, `develop` → DEV) and `direct_ancestors` stays empty.

**Lockfiles.**

- A lockfile is parsed whenever it exists, with the two npm exceptions `find_npm_lockfiles` makes. `resolve_transitive` gates each lockfile branch on the lockfile being found, never on discovery having produced a direct dep for that ecosystem.
- When none of a lockfile's packages is a discovered direct dep, the parser keeps every package as `prod` with no ancestors instead of dropping the whole file as orphans (a format with its own dev/prod split keeps it).
- A lockfile's entry for one of the project's own packages is never a row.

**`init-review-file`.** `cli.init_review_file()` runs the same scan as `check` (both call `cli._scan_licenses`), or reads flagged entries from a `--from-report` JSON file, then scaffolds or merges `licenseal.review.toml` entries for the flagged dependencies. Keep the live scaffold on that shared function, never on a resolution path of its own, so that it holds the rows `check` flags under the keys `check` matches reviews on. With `--merge`, existing entries are preserved verbatim and only missing flagged entries are appended.

**Project license.**

- It is read only from manifests in the scanned directory itself (`discovery.detect_project_license`, in the order of `_PROJECT_LICENSE_MANIFESTS`); a manifest in a subdirectory never supplies it.
- `cli._detect_project_license` prints the value and the file, and warns when the value is not a license the compatibility check recognises or when manifests in the scanned directory disagree.
- When none is detected it defaults to `Proprietary` (permissive risk level: a proprietary project can use permissive dependencies but not copyleft), and the reports say that it is assumed (`AnalysisReport.project_license_assumption`).
- A project license with a top-level `OR` is judged against the strictest of its arms, and an arm that does not classify counts as a `Proprietary` arm.
- A `Proprietary` license on a *dependency* is always flagged for manual review, whatever the project license: `compatibility._check_compat` short-circuits before the matrix, because custom commercial terms cannot be auto-classified.

**PyPI license fallback.** When the per-version endpoint (`/pypi/{name}/{version}/json`) carries no license in `License-Expression`, the legacy `license` field, or the classifiers, `resolve_python_license` reads the release's PEP 658 `.metadata` sidecar (`fetch_pep658_metadata` in `resolvers/http.py`).

- The sidecar is the selected release's own metadata, so it is read before the project-level endpoint (`/pypi/{name}/json`, which describes the latest release).
- A license borrowed from the project-level endpoint is marked `license_estimated`.
- The fallback reads `License-Expression:` first, then a short single-line legacy `License:` value (guarded by length and the `_is_junk_license` prose-marker filter). A legacy `License:` value with any continuation line is rejected whole, so the first line of a license text never becomes the identifier: callers of `_parse_pep658_headers` must judge the whole folded value, never its first line.
- `_trim_pypi` must keep the wheel URL (it flattens it into a `wheel_url` key), or the fallback fails on the cached path.
- A release that PyPI answers 404 for (`RegistryCache.not_found`: a build from another index, a `+local` version), pinned or selected by a range, is reported at that version with the license of a stand-in release, marked `license_estimated`. Any other failed lookup borrows nothing from another release, and `resolved_version` is never a stand-in's version.

**What fails `check`.**

- Violations always fail, with or without `--no-strict`.
- Warnings, unknowns, and analysis gaps fail in strict mode, the default; `--no-strict` stops them failing.
- A reviewed dep (a `licenseal.review.toml` entry applied) never fails, whatever its verdict. It is re-classified by its reviewed license and counted under that verdict.
- When every registry request fails and not one dependency resolves, `check` aborts with a `ClickException` in either mode (`_registries_unreachable` in `cli.py`, fed by `RegistryCache`'s per-scan fetch tallies). A partial failure (at least one dep resolved, or any fetch returned data) stays on the per-dep UNKNOWN path.

**Analysis gaps.** An analysis gap is something the scan could not read: a manifest or lockfile that could not be read, decoded, or parsed, a directory that could not be traversed, a reference to another file that was not followed, a value of a type its format does not allow, or a lockfile that cannot be used.

- Every read and parse goes through `discovery/_read.py`, which records the gap on a context-scoped sink that the CLI drains to stderr after the scan.
- Not gaps: a non-UTF-8 text, JSON, or YAML file recovered through the latin-1 fallback, which warns (a TOML file gets no such fallback), and a lockfile in a version its parser was not written for that is read on a best-effort basis.
- A manifest whose direct deps were resolved through a registry walk because no lockfile covers them is a gap (`record_missing_lockfile`). So is one that declares an off-registry dependency no lockfile holds a row for: nothing is fetched for it, so only a lockfile lists what it requires. This is the one gap a flag accepts: `check --no-require-lockfile` reports it with severity `"estimate"`, outside `summary.gaps` and the strict failure.
- A package whose dependency list a registry walk could not read is a gap whatever `--require-lockfile` says (`record_unread_dependencies`). Every edge fetcher returns completeness beside the children it found, and an empty list must never stand for "could not be determined".

**Batch-first license resolution.** Before the per-dep resolution, `cli.check` sends the pinned deps of every ecosystem deps.dev indexes (Python, npm, Rust, Go, NuGet, Java, Ruby) to `POST /v3alpha/versionbatch` on `api.deps.dev` in one combined pre-pass (`resolvers/deps_dev.bulk_resolve_licenses`), which fills per-ecosystem `(name, version) → LicenseInfo | None` caches.

- `_BATCH_CHUNK_SIZE` stays 100. Do not raise it: the endpoint returns at most 100 entries per request and silently drops the rest.
- `_BATCH_MAX_WORKERS = 8` caps the batch POSTs in flight across all ecosystems, which share one pool of width `min(chunks, max_workers, _BATCH_MAX_WORKERS)`; a lower `--max-workers` still applies. Do not remove it: each POST is a server-side license scan of up to 100 packages.
- Per-dep dispatch reads the cache first. For Go a `None` entry is authoritative, UNKNOWN with no further fetch, because deps.dev is Go's only license source. For the other six `None` is advisory: when the entry is absent, has no licenses, or is `UNKNOWN`, they fall back to their own resolver (`resolve_python_license`, `resolve_npm_license`, `resolve_rust_license`, `resolve_maven_central_license`, `resolve_nuget_license`, `resolve_ruby_license`).
- A `licenses` array that holds deps.dev's `non-standard` marker, alone or beside classified entries, has no usable entries and resolves to UNKNOWN, in the batch and in every single-version lookup (`deps_dev._license_entries`).
- `analysis/spdx.normalize_license` orders operands, so `MIT OR Apache-2.0` from one source and `Apache-2.0 OR MIT` from another compare equal.

**Go.** Edges and dev/prod attribution:

- The module universe is every `go.sum` row plus every direct requirement discovery read from `go.mod` (after `replace`), at the required version. No version is selected among `go.sum` rows.
- `go.sum` carries no edge data, so `transitive._resolve_go_transitive` fetches each module's own `go.mod` from `proxy.golang.org/<encoded-module>/@v/<encoded-version>.mod` (module path and version encoded by `encode_module_proxy_path`), parses its `require` block, and runs `_graph.compute_direct_ancestors` from the prod and the dev direct deps. When the universe holds a module at several versions, edges come from the version the scanned `go.mod` requires.
- A fetched `go.mod`'s own `replace` directives are never applied to its edges: Go honours `replace` only in the main module.
- A module that no direct dep reaches (for example because its parent's proxy fetch failed) is PROD, not dropped.
- A `go.mod` below `go 1.17`, or with no `go` directive, lists direct requirements only: `_record_unlisted_go_requirements` records an analysis gap on it when one of its scanned requirements has no `go.sum` row.
- The Go 1.24+ `tool` directive is the only dev marker (`discovery/go/go_mod.py`). Each tool import path is matched to its required module by longest prefix, and that module is `DependencyGroup.DEV`; transitives reachable only from a DEV direct dep are DEV, and a tool module that a PROD direct dep also requires is PROD. Without the directive, `--dev` and `--no-dev` produce identical reports.
- `// indirect` is not a dev signal: the module is PROD.
- Test-only deps (imported only by `*_test.go` files) share the `require` block with production deps; telling them apart needs source-code analysis, which is out of scope.
- **`replace`.** `_parse_go_mod` reads the single-line and the `replace ( … )` block form; a directive that names a version applies only to a requirement on that version. A module replacement is emitted under the replacement's path and version. A local-path replacement drops the requirement when the scan reads that path, and otherwise emits it under the module's own name with the path as `origin`. Only the scanned project's own `go.mod` files are read for `replace`; `go.work` `replace` is not read.
- **Workspace-local modules** are not published, so a lookup for one fails. `_discover_workspace_local_module_paths` (`discovery/go/go_mod.py`) collects them from every in-tree `go.mod`'s `module <path>` declaration and from the relative `use <dir>` directives of the scanned directory's `go.work`, targets outside the project tree included. The set is applied twice: discovery drops the direct deps whose name matches, and `_resolve_go_transitive` drops matching `go.sum` rows, which a sibling once imported as a versioned requirement can leave behind.

**Paths taken from manifest content.** Four parsers follow a path written inside a manifest: `<Import Project="…">` in `Directory.Build.props` / `.targets`, `go.work` `use`, `-r` / `--requirement` in a requirements file, and a setuptools `file:` directive (`setup.cfg` `install_requires` / `extras_require`, `[tool.setuptools.dynamic]` in `pyproject.toml`).

- Each passes the raw value to `discovery/_read.py:rejected_path_reference` before joining or resolving it. A rooted, drive-qualified, UNC, or device value is rejected and recorded as a gap on the manifest that contains it.
- The check is lexical and must stay ahead of every filesystem call: `Path.resolve()` is itself I/O, and on Windows a UNC path reaching it can open an SMB connection.
- For `<Import>` and `go.work` `use`, relative values are followed, `..` included.
- A requirements include and a `file:` directive (`requirements.referenced_requirements`) are followed only when they resolve to a file inside the scanned directory, and a URL is refused on its text.
- Any new parser that follows a content-derived path must use the same guard.

**Directory walk.** Discovery uses `discovery._walk.walk_project_files`, which skips the directory names listed in USAGE.md, any directory with a `pyvenv.cfg` or its own `.git`, symlinked directories, and `--exclude-dirs` paths.

## Adding a new ecosystem

A new ecosystem (e.g. Swift PM) touches every list below. Partial wiring silently drops deps on whichever path is missed, so go through all of it.

### Codebase

1. **Enum + label.**
   - Add the new value to `models.Ecosystem` and its display label to `_ECOSYSTEM_LABELS` (same module). The CLI workspace-filter echo iterates the enum and reads `.label`, so a missing label fails `test_every_ecosystem_has_a_label`.
   - Decide its identity rule: add it to `_CASE_FOLDING_ECOSYSTEMS` only when its registry treats names that differ in case as one package (`test_every_ecosystem_has_a_rule` fails until the choice is made).
2. **Discovery package.** Create `discovery/<eco>/` with one module per manifest format.
   - Each exports `discover_<format>_dependencies(project_path, *, exclude_paths) -> (list[Dependency], int)` (the int is the workspace-internal filter count) and, when the manifest can carry the project's own license, `detect_project_license_<format>(manifest_path) -> str`, which reads the declared value from that one file and never walks the tree.
   - Use `discovery._walk.walk_project_files` so the shared skip-dir set applies.
   - Read every manifest through `discovery._read` — `decode_text` (text), `read_xml_bytes` + `record_parse_failure` (XML), or `load_json` / `load_toml` / `load_yaml` (structured) — never raw `read_text` / `json.loads`. The loaders are BOM/encoding-aware and record an unreadable, undecodable, or unparseable file as an analysis gap.
   - On a parse failure the structured loaders return `None`; XML callers must call `record_parse_failure(path, "XML")` themselves since their parse step is separate from the read.
   - File content must never raise out of a parser, and a parsed document is untrusted in its types too: take the top level of a JSON / YAML document through `root_table`, read every section and field that leads to a dependency row, a pinned version, or a graph edge with `typed_field`, and record an entry of the wrong type with `record_unexpected_type`.
   - Never call `.get()` / `.items()` on, or iterate, a value whose type has not been checked.
   - If the format can name another file to read (an import, an include, a workspace directory), pass the raw value to `rejected_path_reference` before joining or resolving it.
3. **Lockfile parsers.** Add `discovery/<eco>/lockfiles.py` with `find_<eco>_lockfiles(...)` and one parser per format.
   - Parsers must extract per-package dependency edges so `_graph.compute_direct_ancestors` can attribute group + ancestors by reachability. Only fall back to section-based attribution when the format genuinely has no edge data (Pipfile.lock style); set `direct_ancestors=()` there.
   - A lockfile the parser cannot use must be a gap, never an empty result:
     - when the format declares a version, call `check_lockfile_version` before parsing (pass `unreadable_below` only with positive evidence that older versions are laid out differently; "not on the list" is never a reason to skip);
     - pass the number of entries the file holds and the number the parser read to `record_unread_entries` before any dev, workspace, or orphan filtering;
     - decode a line-oriented lockfile with `decode_lockfile_text`, which rejects merge-conflict markers.
   - A lockfile with no entries, and one that filters down to nothing, must stay clean.
4. **Discovery aggregator.**
   - Wire the new discover function into `discovery.__init__.discover_all_dependencies` (extend `local_filter_counts` under the new key).
   - Wire the detect function into `_PROJECT_LICENSE_MANIFESTS` (with the file-name test of its manifest and the normalizer for its license grammar), which `detect_project_license` applies to the files of the scanned directory only.
5. **Resolver.** Add `resolvers/<eco>.py` with `resolve_<eco>_license(dep, client, *, fetcher)`, `_extract_pinned_version`, and `fetch_<eco>_dependencies(name, version, client, *, parent_depth, parent_group, fetcher)` for the registry walk.
   - The fetcher returns `(children, complete)`: `complete` is False when the dependency list could not be determined, and the entries that could be read are returned all the same.
   - Identifier extraction is structured-fields-only — see the no-prose-extraction rule.
   - A registry response is untrusted input and must never raise out of a resolver or the registry walk: the fetch helpers in `resolvers/http.py` return a JSON object (`dict`) or `None`, and below the top level every field is type-checked before use (`object_field` for a nested object, `isinstance(value, str)` before a value reaches `normalize_license` or `LicenseInfo`).
   - Dependency names and versions go into URLs as declared, percent-encoded with `quote_coordinate` (`resolvers/http.py`); never strip or rewrite them to make a request succeed.
   - Don't wrap resolution in a broad `except`: `tethered.EgressBlocked` must propagate and abort the scan.
6. **Registry cache.**
   - Add `_<ECO>_*_KEEP` frozensets in `resolvers/http.py` listing every field the resolver and the registry walk read, write a `_trim_<eco>(...)` helper, and dispatch on the URL host in `_trim_for_cache`.
   - Resolver unit tests bypass `_trim_for_cache`; also add a test that exercises the resolver through `RegistryCache.fetch` so the keep-set is verified end-to-end.
   - A trim reduces well-formed values only: a dependency field of the wrong type is cached as it is, never as an empty list or map, or the registry walk reads a response it could not use as a package without dependencies.
7. **Transitive resolution.** In `transitive.resolve_transitive`, add a lockfile-first branch mirroring existing ecosystems (parse lock → `_stamp_sources` → `_walk_uncovered` for the direct deps the lockfile does not cover).
   - Register the ecosystem's grammar in `version_selection._GRAMMARS`, which lock coverage reads.
   - Gate the branch on the lockfile being found, not on `ecosystems_present`, and make the parser keep its packages as PROD when none of them is a discovered direct dep (never drop the whole file).
   - Add ecosystem branches in `_resolve_version` and `_walk_one_inner`.
   - State the ecosystem's name rule in `Ecosystem.identity` (step 1) and key every name set and graph on it.
   - Register the ecosystem's exact-pin check in `_EXACT_VERSION_CHECKS` so a range-declared direct dep is marked `version_estimated`. An ecosystem with its own fallback function (not `_walk_registry`) sets the flag on the rows it adds and calls `_record_missing_lockfiles` with every direct dep no lockfile covers, off-registry dependencies included (it records the two kinds under their own reasons).
8. **CLI.**
   - Add the registry host to `_REGISTRY_HOSTS`.
   - Update the `tethered` `hint`.
   - Add a dispatch case in the `_resolve` closure.
9. **Report.** Add a branch in `report._package_url` for the registry's web URL.
10. **Review.** Nothing to wire: `review.canonical_name` applies `Ecosystem.identity`. If the registry publishes a package under another name than the manifest's, set `Dependency.registry_name` so the review key and the report URL use it.

### Tests

Every code path above needs a test (100% coverage is required). At minimum:

- `tests/test_discovery_<eco>.py` per manifest format, including the workspace-internal filter path.
- `tests/test_lockfiles_<eco>.py` covering edge-aware group attribution (prod-reachable, dev-only, orphan-drop, no direct dep in the lockfile) and any format quirks (patched / git / path sources, alias renames, etc.).
- `tests/test_lockfile_gaps.py` and `tests/test_manifest_type_gaps.py` additions for the new formats: a newer and an unlisted version (read, non-gap diagnostic), a newer version with no readable entry (gap), a version known not to be readable where there is one (gap), no readable entry, merge-conflict markers (line-oriented formats), a value of the wrong type in each section and entry, and the cases that must stay clean (an empty lockfile, one filtered down to nothing).
- `tests/test_resolvers.py` additions for the new resolver, including at least one test routed through `RegistryCache.fetch` (not only `fetch_registry_json`) so the cache keep-set is exercised.
- `tests/test_transitive.py` additions for the new lockfile-first path and registry-walk fallback.
- `tests/fixtures/registry-responses/` — captured real-world response snippets matching the trimmed-cache shape.
- Update any test that enumerates ecosystems explicitly (e.g. `test_registry_response_fixtures.py`).

### Stress-test repos

Add at least one `<eco>`-only repo plus one polyglot repo that includes the new ecosystem to the local stress corpus (`licenseal-scans/corpus.json`, gitignored). Pick repos with non-trivial lockfile graphs so the edge-attribution paths fire. Then run the four stages under *Stress-testing on real repos* in both modes, checking the per-ecosystem count of the new ecosystem.

## Rules

- Python 3.10+. `from __future__ import annotations` in every file.
- ruff (line length 100), ty (default rules; `[tool.ty.src]` scopes it to `src/`).
- Network egress goes through `tethered.scope(allow=..., label="licenseal.resolve", hint=...)`. `scope()` intersects with any host policy, so embedding licenseal cannot widen its egress. Never call `tethered.activate()` from library code: it is process-wide and reserved for the host application or local dev.
- `cli._TETHERED_HINT` is the text tethered shows when a host policy blocks a call. It explains why the listed hosts are needed and must link to the *Network egress* heading of SECURITY.md: a test checks that the link's fragment is a heading of that file and that the section lists every host.
- Every thread pool that fetches must carry the caller's context into its workers: route a new pool through `licenseal._concurrency.map_with_context`. The scope lives in a `ContextVar`, which does not cross thread boundaries, so a raw `pool.map` worker runs outside it and bypasses the allowlist, and the unit tests do not catch that.
- Requests carry only dependency coordinates `(system, name, version)` plus a static `User-Agent`, never manifest or lockfile contents, file paths, the project name, or credentials. Don't add an `Authorization` header or read `.netrc` / `.npmrc` / `.pypirc` / keyring (no `httpx.NetRCAuth`). The resolution client keeps httpx's `trust_env` default, so `HTTP(S)_PROXY` is honored but `.netrc` is never read implicitly (httpx ≥ 0.28). See SECURITY.md *What leaves the process*.
- License identifiers come only from structured fields; see *Architecture: manifest + registry only*.
- Dependency names, versions, license strings, reasons, manifest paths, and review-file strings are untrusted text. Escape them only where they are rendered, with the helpers of `report.py`: `_printable` (control characters, bidirectional marks and controls, line separators, and lone surrogates) under every table, Markdown, and stderr string, the message of a `ClickException` included; `_escape_md` for Markdown; `Text` cells or `_rich_escape` for the console (never interpolate them into a Rich markup tag); `_url_quote` for anything placed in a URL. Never sanitise them in discovery, the data model, or JSON: removing a character can turn one package coordinate into another.
- The table report (`report.render_table`) must show every column at any width. Give a free-text column `overflow="fold"` and a fixed-vocabulary column `no_wrap=True` as well, and pass each table through `_fit_table` before printing it: off a terminal it widens the console to the table's natural width, on a narrow terminal it lets the columns shrink below their minimum widths. Any non-ASCII glyph the report draws itself needs an entry in `_ASCII_GLYPHS`, because a stdout under a legacy code page cannot encode it; `-o` files are always UTF-8.
- Changes to risk classifications (`analysis/risk.py`), the compat matrix, or reason strings (`analysis/compatibility.py`) ripple into committed docs that embed matrix semantics by hand. Review and update each in the same change; none is generated:
  - `README.md` — Compatibility matrix table + Risk levels table, and the text between them (pair-level overrides, `OR`, the dev downgrade).
  - `USAGE.md` — the *License expressions* section (the exception list and the worked verdicts).
  - `src/licenseal/data/claude_skill.md` — per-verdict walkthrough (the WARNING / INCOMPATIBLE / UNKNOWN bullets in step 4) and the concrete-examples table. Each matrix cell that can flag a dep must be reachable through a per-dep question pattern in this file.
  - `JSON_OUTPUT.md` — the `risk` and `verdict` enum lines, their descriptions, and the sample `reason` string.
  - `LICENSES.md` — the sample `reason` string in the Details section.
- 100% test coverage is required; the command is under *Verification*.
- Tests use `respx` to mock HTTP calls. Never make real network requests in tests.
- hex.pm 429s are handled by `_HostRateLimitWindow` (`resolvers/http.py`), not by the retry budget. `resolvers/http.py` never imports the CLI: it reports a pause through `RegistryCache.on_rate_limit_pause`, which the CLI prints through `_STDERR_CONSOLE` so the line is not written into a live progress display. A test that makes `hex.pm` answer 429 must take the `fake_registry_clock` fixture (`tests/conftest.py`) so the pause advances a fake clock instead of sleeping.
- Keep it simple. No unnecessary abstractions, helpers, or error handling for impossible cases.
- When two ecosystems share an identical type or helper, give the shared definition a domain-neutral name both reference (e.g. `_TransitiveDepsFetcher`), rather than aliasing one ecosystem's name to another's (`_DotnetDepsFetcher = _MavenDepsFetcher`).
- No specific stress-test repository or package names in source or test comments. Describe the pattern (`large Python projects`, `Cargo workspaces`, `packages with extras-heavy transitives`) instead of the project where you happened to observe it.
- No hardcoded benchmark numbers in comments (MB, timings, `~3.3x` style speedups). They go stale.
- External repositories used for stress-testing are untrusted code. Clone and scan them only through the Docker harness in `scripts/stress/`; never clone one onto the host filesystem. Read their manifest and lockfile contents only; never install their dependencies, run their setup or build scripts, execute their code, or import their packages.
- Branch from `dev`, PR to `dev`. `main` is releases only.

## Documentation and package description

- `README.md` is the overview with the visuals; the reference is `USAGE.md`. Use relative links for repository files and images under `assets/`; keep external and GitHub service URLs absolute.
- `PYPI.md` is the short package description selected by `project.readme` in `pyproject.toml`. Keep its summary, supported ecosystems, and commands aligned with the CLI, and use absolute HTTPS links to public documentation. Builds use it directly; do not introduce README link rewriting during release.
- Follow [CONTRIBUTING.md](CONTRIBUTING.md#readme-links-and-images) when updating documentation or visuals, including example accuracy and preview checks.

## Verification

Run the full pre-commit suite and the tests before submitting changes:

```bash
uv run pre-commit run --all-files
uv run pytest -n 8 --cov=licenseal --cov-report=term-missing
```

`pre-commit` is the authoritative static gate and mirrors CI — it runs ruff (check + format), ty, bandit, markdownlint, deptry, interrogate, vulture, and the SPDX-ID validator. Running only `ruff check` / `ty check` skips bandit, markdownlint, and the SPDX validator, so a green local run can still fail CI. `pytest` is not a pre-commit hook; run it separately.

### Stress-testing on real repos

For changes that touch discovery, resolvers, analysis, report rendering, or the review flow, also stress-test against third-party repos — at minimum one Python-only, one npm-only, one Rust-only, and one polyglot project. The untrusted-code rule under *Rules* applies.

The harness in `scripts/stress/` keeps clones in the `licenseal-corpus` Docker volume and scans them in a Linux container that mounts the working tree's `src/` read-only, so scans always exercise the current code; only licenseal's own output is written to `licenseal-scans/` (gitignored).

```bash
uv run python scripts/stress/stress.py build      # runner image; rebuild when pyproject.toml or uv.lock changes
uv run python scripts/stress/stress.py clone      # shallow-clone the corpus into the volume
uv run python scripts/stress/stress.py inventory  # manifests + lockfiles per clone
```

The corpus list is local: `licenseal-scans/corpus.json`, in the format of `scripts/stress/corpus.example.json`. If it is missing or doesn't cover the ecosystems the change touches, ask the user which repos to add before proceeding. Do not pick repos unilaterally and do not skip the stress-test stages silently. Every action accepts `--only repo1,repo2`.

Skip repos whose primary purpose is distributing offensive payloads, malware samples, exploit binaries, or operational pentest tradecraft. Filter by repo description and topic tags before cloning; this applies to one-off clones and to corpus entries alike.

**Conventions for stress-test runs:**

- All scratch artifacts (fresh scans, comparison scripts, filled review files, probes) live under `licenseal-scans/`. Never write them to the repo root.
- Report licenseal-side issues only (parser bugs, dropped deps, classification regressions, format-path failures). The scanned repo's actual license findings are not part of the stress-test output.
- Baseline and post-change runs both go through the harness. A scan run on the host is not comparable with one run in the container.
- Save a pre-change baseline per repo before starting: `stress.py baseline` writes `licenseal-scans/<repo>.scan_baseline.json` for `--no-dev` and `<repo>.scan_baseline_dev.json` for `--dev`, and keeps an existing baseline unless `--force` is passed. Repos without a lockfile resolve against live registry state, so retake their baselines immediately before the change.

Run all four stages per repo touched by the change:

**1. JSON parity in both modes.** `--no-dev` is the default; `--dev` exercises dev-discovery, dev-reachability attribution, and the dev→warning downgrade paths — run both.

```bash
uv run python scripts/stress/stress.py fresh   # _fresh_<repo>.json and _fresh_<repo>_dev.json
uv run python scripts/stress/stress.py diff    # fresh vs baseline, written to _diff_summary.md
```

`diff` compares (a) `summary` totals and the project license with its source, (b) the set of `(ecosystem, name, version, origin)` keys, (c) per-dep `(license, detected_license, risk, verdict, group, depth, estimated)` tuples, and (d) the diagnostics as `(path, severity, reason)`. Zero diff confirms no regression. Any diff has to be explained by the change.

**2. Per-ecosystem verification (polyglot repos).** Total-count parity hides per-ecosystem bugs — verify each present ecosystem actually fired its expected pipeline path by comparing the per-ecosystem counts from `stress.py report --label fresh` with `stress.py report --label baseline`. The report also notes any ecosystem whose manifests are present in a clone but contribute zero dependencies.

**3. Markdown report path.**

```bash
uv run python scripts/stress/stress.py markdown   # _fresh_<repo>.md
```

Confirm each file is non-empty, starts with a heading, and contains the expected number of table rows (≈ `summary.total` + header rows).

**4. Review loop.** Validates `init-review-file` end-to-end.

```bash
uv run python scripts/stress/stress.py gapfill
```

Per repo, this scaffolds a review file from `_fresh_<repo>.json`, replaces every `license = ""` with `license = "MIT"`, places the filled file in the clone, re-runs `check --no-dev -f json`, and removes the file again, so clones don't accumulate state between runs. N is the sum of the counts from the `Note: N flagged dependencies could not be scaffolded ...` lines, one line per reason — those deps have no resolved version and can't be keyed by the review file, or have a name, version, or source a TOML file cannot hold. Expected:

- `summary.reviewed` equals the number of filled entries
- `summary.warnings + violations + unknown` drops by the same number
- residual flagged count equals N (the unscaffoldable ones)
