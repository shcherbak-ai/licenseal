# licenseal — Usage & reference

Full CLI reference, resolution behavior, and per-ecosystem detail. For the overview, install, and the "why," see the [README](README.md). For the security/egress model see [SECURITY.md](SECURITY.md); for the JSON schema see [JSON_OUTPUT.md](JSON_OUTPUT.md).

## Commands

```bash
licenseal check                 # scan the current project and gate on the result
licenseal init-review-file      # scaffold a licenseal.review.toml for flagged deps
licenseal install-skill         # install the Claude Code review skill into the project
licenseal --version             # print the version and exit
```

### `licenseal check` options

| Flag | Default | Notes |
|---|---|---|
| `--path PATH`, `-p PATH` | `.` | Directory to scan |
| `--format FMT`, `-f FMT` | `table` | `table`, `json`, or `markdown` |
| `--output FILE`, `-o FILE` | — | Write report to FILE instead of stdout |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--strict / --no-strict` | `--strict` | Fail closed on warnings + unknowns + analysis gaps (violations always fail) |
| `--require-lockfile / --no-require-lockfile` | `--require-lockfile` | Whether a manifest whose dependencies no lockfile covers is an analysis gap. `--no-require-lockfile` accepts the registry estimate and reports it without failing. No effect with `--no-transitive`. |
| `--transitive / --no-transitive` | `--transitive` | Full-tree scan vs direct deps only |
| `--max-depth N` | `50` | Cap the depth of a registry walk (see [Transitive scanning](#transitive-scanning)), 1 to 100. A usage error with `--no-transitive` |
| `--max-workers N` | `16` | Concurrent registry requests, 1 to 32 |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery. Comma-separated and/or repeated flag (relative to `--path` or absolute). Subdirectories that contain their own `.git` are skipped automatically. |

### `licenseal init-review-file` options

| Flag | Default | Notes |
|---|---|---|
| `--path PATH`, `-p PATH` | `.` | Project directory, where `licenseal.review.toml` is written. Without `--from-report` it is scanned as `check` scans it by default |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--from-report PATH` | — | Read flagged deps from a saved JSON report (offline, no registry round-trip). A usage error together with `--dev` / `--no-dev`, `--max-workers`, or `--exclude-dirs`, which only apply to a scan |
| `--merge` | — | Add new flagged entries to an existing review file (preserves existing entries). Without it the command fails rather than overwrite an existing file |
| `--max-workers N` | `16` | Concurrent registry requests, 1 to 32 |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery (same semantics as `check`) |

## Common usage

```bash
licenseal check                              # full-tree scan (default; lockfile-first, registry fallback)
licenseal check --no-transitive              # direct deps only (use when publishing a library)
licenseal check --dev                        # also include dev dependencies
licenseal check --no-strict                  # advisory mode — don't fail on warnings/unknowns/gaps (violations still fail)
licenseal check --no-require-lockfile        # no lockfile committed — accept versions and transitives estimated from the registry
licenseal check -f json -o report.json       # machine-readable output for CI tooling
licenseal check -f markdown -o LICENSES.md   # PR-comment-friendly Markdown audit
licenseal check --exclude-dirs third_party,scratch  # skip subtrees not already in the default skip set
```

## Project license

Every verdict compares a dependency's license with the project's own. licenseal reads the project license from the manifests in the scanned directory itself (the `--path` root), never from a subdirectory.

- The first manifest that declares a license decides, in this order: `pyproject.toml`, `setup.cfg`, `setup.py`, `package.json`, `Cargo.toml`, `pom.xml`, `.csproj` / `.fsproj` / `.vbproj`, `Directory.Build.props`, `composer.json`, `*.gemspec`, `mix.exs`, `DESCRIPTION`. When root manifests declare different licenses, a `Warning:` names each file and its value.
- `check` and `init-review-file` print the value and its file on stderr (`Project license: MIT (from pyproject.toml).`). The table and Markdown reports show the same, and JSON carries the file as `project_license_source`.
- When no manifest in the scanned directory declares a license, the project is checked as `Proprietary` (a closed-source project can use permissive dependencies but not copyleft ones), and the stderr line and the reports say the license is assumed. To check one package of a monorepo against its own license, scan it with `--path`.
- A declared value that is not a recognised license (`"license": "-"`, a sentence) is not used: a `Warning:` names the file and the value, and the project is checked as `Proprietary`.

## Output & the CI gate

`licenseal check` exits non-zero when there are violations, warnings, unresolved licenses, or analysis gaps — that's the CI gate.

- An **analysis gap** is something the scan could not read, so a dependency may be missing from the report. Each gap is a `Warning:` on stderr and is recorded in the report: an **Analysis gaps** section and a count on the summary line in the table and Markdown formats, `summary.gaps` and `diagnostics` in JSON. Gaps fail strict mode like an unknown. The kinds:
  - a manifest or lockfile that cannot be read (permission or I/O error, or larger than 128 MiB), decoded, or parsed, and a directory that cannot be traversed;
  - a value of a type its format does not allow (`"dependencies": []` in `package.json`): the value is ignored and the rest of the file is read;
  - a lockfile that cannot be used: a format version licenseal does not read (`pnpm-lock.yaml` below `lockfileVersion` 6), no entry in a readable form, or merge-conflict markers. Its direct dependencies are resolved through the registry instead. These checks do not cover `Cargo.lock`, `go.sum`, `packages.lock.json`, `project.assets.json`, `paket.lock`, or `rebar.lock`;
  - a reference to another file that is not followed: an MSBuild `<Import>` or `go.work` `use` that is not a relative path, or a requirements `-r` include that is a URL, is not a relative path, is not a file, or leaves the scanned directory;
  - a manifest whose dependencies no lockfile covers (next point);
  - a package whose dependency list the registry did not return during a registry walk: the package is reported, and what it requires may be missing. `--no-require-lockfile` does not waive this one;
  - two ecosystem-specific cases described under [Per-ecosystem resolution detail](#per-ecosystem-resolution-detail): a `composer.json` with repositories and no `composer.lock`, and a `go.mod` below `go 1.17` with `go.sum` rows missing.
- **A manifest without a lockfile.** When a manifest declares a direct dependency that no lockfile covers (there is no lockfile, the lockfile does not list it, or it lists it only at a version the declaration does not admit), that dependency and everything under it are resolved through the registry, and the result is an estimate of what the project installs. With `--require-lockfile` (the default) the manifest is an analysis gap. With `--no-require-lockfile` it is still reported, with severity `estimate` in JSON `diagnostics` and under an **Estimates** section in the table and Markdown formats, and does not fail. Not covered: a manifest of a tool with no lockfile format (Maven `pom.xml`, NuGet `packages.config`, an erlang.mk `Makefile`), whose rows are marked as estimates, where licenseal picked the version, without a diagnostic; Go; an [off-registry dependency](#off-registry-dependencies); a manifest whose only uncovered dependencies are dev dependencies in a scan without `--dev`; and `--no-transitive`.
- A lockfile in a newer format version than licenseal was written for is read on a best-effort basis, with a warning that does not fail.
- A manifest or lockfile written as UTF-16 or UTF-32 with a byte-order mark is read in that encoding. A text, JSON, or YAML file that is not valid UTF-8 is read through a latin-1 fallback with a warning that does not fail; a TOML file that is not valid UTF-8 is an analysis gap.
- `--no-strict` demotes warnings / unknowns / gaps to advisory. **Violations always fail** — they're definite legal incompatibilities and the flag won't silence them.
- If **every** registry lookup fails and not one dependency resolves (no network, blocked egress, registry-wide outage), `check` aborts with an error and a non-zero exit rather than reporting an all-UNKNOWN scan; this is not demotable by `--no-strict`.

The `-o / --output FILE` flag writes the rendered report to a file (UTF-8, no ANSI escapes for table format). The file is written **before** the strict-mode gate runs, so CI can publish the artifact even when `check` exits non-zero. Since the report itself doesn't reach the terminal, a failing check then also prints the summary and the findings that failed it (plus the number of analysis gaps) to stderr, so CI logs and pre-commit output show why without opening the file. JSON is the stable machine-readable format — see [JSON_OUTPUT.md](JSON_OUTPUT.md) for the schema.

The table and Markdown formats escape the strings that come from registries and scanned files (control characters, and Markdown and HTML syntax), so a package name or a license string cannot add a link, markup, or a table column. JSON reports the original strings.

Piped, or written with `-o`, the table is at its full width with one line per dependency. On a terminal narrower than the table, cells wrap and no column is dropped. When stdout's encoding cannot represent the report's glyphs (a legacy Windows code page), `OK`, `!`, and `X` are printed for ✓, ⚠, and ✗.

## Transitive scanning

Transitive is the default. `--no-transitive` audits only the dependencies you declared directly: it takes no rows from a lockfile and reports no transitive. The walk uses a **lockfile-first** strategy:

1. If a lockfile is present, it is the source of truth: `uv.lock`, `poetry.lock`, or `Pipfile.lock` (Python); `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, `yarn.lock`, or `bun.lock` (npm); `Cargo.lock` (Rust); `go.sum` (Go); `gradle.lockfile` (Gradle); `packages.lock.json`, `project.assets.json`, or `paket.lock` (.NET); `composer.lock` (PHP); `Gemfile.lock` (Ruby); `mix.lock` / `rebar.lock` (Hex); `renv.lock` / `packrat.lock` (R). Lockfiles encode the actually-resolved graph, so this path is precise and offline-fast.
   - A lockfile covers a direct dependency only when it holds that package at a version the declaration admits: `shared>=2` is covered by a locked `2.4.0`, not by a locked `1.0.0`. A locked version that cannot be compared with the declaration covers it too: a declaration with no constraint, a tag or a branch, and any range when the locked version is a prerelease. A declaration no lockfile covers is resolved through the registry (step 2), and its manifest is recorded as lacking a lockfile.
   - A lockfile is read wherever it is found in the scanned tree, with or without a manifest beside it. A sample or test-data lockfile outside the [auto-skipped directories](#discovery-auto-skipped-directories) therefore adds its packages to the report; exclude its directory with `--exclude-dirs`. Two npm exceptions: a lockfile under a directory named `test` or `tests` is not read, and when one directory holds several npm lockfiles only the first of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` is read.
2. When no lockfile covers a dependency, licenseal falls back to a recursive registry walk: each dep's per-version metadata is fetched and walked breadth-first in parallel (per `--max-workers`), down to `--max-depth`. What the walk reports is an estimate: the versions are the ones the registries publish at scan time, not the ones the project installs. Every row it adds is marked as estimated (see [Resolution semantics](#resolution-semantics)), and the manifest it starts from is an analysis gap unless `--no-require-lockfile` is passed.

A report has one row per package, resolved version, and origin. Multiple versions of the same package coexist — a graph can legitimately contain `lodash@4.x` and `lodash@3.x` via different paths, each license-resolved independently — and so do the versions that different manifests of one tree ask for.

The report nests transitives directly beneath the depth-0 dependency that pulls them in, so a flagged transitive traces back to the direct dep you'd remove to drop it. Direct deps are listed alphabetically; under each, transitives appear in their own alphabetical run with a tree-style indent. Transitives shared across multiple direct deps are listed once under the alphabetically-first ancestor with an `(also: X, Y)` annotation; the full list is always in JSON under `direct_ancestors` (plus `depth` and `is_transitive`). Group is attributed by reachability: a transitive reached from a `prod` direct dep is `prod`, otherwise `dev` if reached from a dev dep, otherwise dropped — so `--no-dev` reports cleanly omit dev-only chains. Production wins: a dependency declared as dev that a `prod` dependency also pulls in is `prod`, and `--dev` adds rows without changing a `prod` row to `dev`. The packages of a lockfile that holds none of the direct dependencies found in the manifests are all reported, as `prod` unless the lockfile format records its own dev/prod split.

### Per-ecosystem resolution detail

What each ecosystem reads, how it tells dev from production, what it treats as an [off-registry dependency](#off-registry-dependencies), and what it does not evaluate.

- **Python**: PEP 508 environment markers are intentionally ignored (treated as always-true): license obligations don't depend on `python_version` or `sys_platform`. Extras are followed, from the `uv.lock` edges when there is one. In `requirements*.txt` and `*-requirements.txt`, a `-r` include is followed inside the scanned directory, and the included requirements are dev or production by the file the chain starts from; `-c` constraints files are not read, and a requirements file under another name that nothing includes is not scanned. Off-registry: a URL, VCS, or local-path requirement (`name @ <url>`, `git+https://…`, `./pkg.whl`), a Poetry `git` / `url` / `path` dependency, a `[tool.uv.sources]` `git` / `url` / `path` entry, a `Pipfile` VCS or path entry, and the corresponding sources in `uv.lock`, `poetry.lock`, and `Pipfile.lock`.
- **npm**: `peerDependencies` and `optionalDependencies` are walked alongside `dependencies` (they end up in your installed `node_modules`); `devDependencies` are gated by `--dev`. A package installed under an npm alias is reported under its real name. Off-registry: a git URL, a hosting shorthand (`github:user/repo`, a bare `user/repo`), a tarball URL, and a `file:` / `link:` / `portal:` path the scan does not read, in `package.json` and in every lockfile format. One exception: a lockfile's `resolved` tarball URL in the layout registries serve (`<host>/<name>/-/<file>.tgz`, on any host) is a package of another registry, looked up on registry.npmjs.org. In monorepos and pnpm workspaces, packages defined locally by another `package.json` in the tree are filtered out (they aren't published); a stderr line reports how many were excluded.
- **Rust**: with a `Cargo.lock` the locked graph is used as-is; without one, the registry walk does not follow the optional (feature-gated) dependencies of the crates it visits. Off-registry: a `git = …` dependency, a `path = …` the scan does not read, and a crate that a `[patch]` or `[replace]` entry points at either. A path crate that `Cargo.lock` reaches only through another path crate the scan does not read is not reported.
- **Go**: `go.mod` has no general prod/dev distinction — everything in a `require` block ships. The Go 1.24+ `tool` directive is the *only* declarative dev marker (a `tool` module that a production module also requires is `prod`); `// indirect` is **not** a dev signal, and test-only deps can't be separated from production deps. With a `go.sum`, the report is its modules plus every `go.mod` requirement at the required version; no version is chosen among `go.sum` rows, so a row for another version of a module stays in the report. A `go.mod` with a `go` directive below 1.17, or none, lists direct requirements only: when one of them has no `go.sum` row, what it depends on is missing and the `go.mod` is an analysis gap; committing an up-to-date `go.sum` removes it. `replace` directives of the scanned `go.mod` are applied: a requirement replaced by another module is scanned as that module, and one replaced by a local path is the project's own code when the scan reads that path and off-registry otherwise. Not applied: `replace` directives in a dependency's `go.mod` and in `go.work`. `go.work` `use` directories are followed only when they are relative paths.
- **Java/JVM**: Maven (`pom.xml`) and Gradle (`gradle.lockfile`, `build.gradle`, `build.gradle.kts`). Licenses come from deps.dev and from POM XML at Maven Central, with two hard-coded fallback registries (`dl.google.com` for Android/Jetpack/Firebase, `repo.jenkins-ci.org` for Jenkins); transitive expansion is offloaded to deps.dev's `:dependencies` endpoint. BOM imports and the `<dependencyManagement>` parent chain are walked (up to 5 levels of parent + 5 of BOM-of-BOM nesting), including `${revision}`-style property inheritance, with and without `--no-transitive`. Multi-module reactors filter out in-tree sibling artifacts.
  - Maven `compile` / `runtime` map to PROD and `test` / `provided` / `system` to DEV. A `system`-scoped dependency is a local JAR and is off-registry. Dependencies inside `<profiles>` are included from every profile; activation conditions are not evaluated.
  - Gradle build files are read by a text-parse heuristic that surfaces only static-string `dependencies { … }` declarations. Version catalogs, variable interpolation, `platform(...)` references, and dynamic blocks are not evaluated (doing so would require running the Gradle configuration phase, which executes scan-target code).
  - Gradle PROD configurations: `implementation`, `api`, `compile`, `runtime`, `runtimeOnly`, `compileOnly`, `compileOnlyApi`, `compileClasspath`, `runtimeClasspath`, `providedCompile`, `providedRuntime`, `annotationProcessor`, `kapt`, `ksp`, `kaptTest`, `releaseImplementation`, `releaseApi`, `releaseRuntimeOnly`, `shadow`. DEV: `testImplementation`, `testApi`, `testCompileOnly`, `testRuntimeOnly`, `testCompileClasspath`, `testRuntimeClasspath`, `androidTestImplementation`, `androidTestApi`, `androidTestCompileOnly`, `androidTestRuntimeOnly`, `testFixturesApi`, `testFixturesImplementation`, `debugImplementation`, `debugApi`, `debugRuntimeOnly`, `developmentOnly`, `checkstyle`, `spotbugs`, `pmd`, `detekt`, `jacocoAgent`, `jacocoAnt`. A declaration under any other configuration name is skipped.
  - A Gradle coordinate declared without a version (a BOM or a plugin supplies it) is reported at the artifact's latest release, as an estimate, when no `gradle.lockfile` covers it.
- **.NET**: NuGet (`.csproj` / `.fsproj` / `.vbproj`, `packages.config`, `Directory.Packages.props` for Central Package Management, `Directory.Build.props` / `.targets`, `packages.lock.json`, `project.assets.json`) and Paket (`paket.dependencies`, `paket.lock`). Licenses come from deps.dev and from the package's `.nuspec` (`<license type="expression">`, or a legacy `<licenseUrl>` mapped via known URL patterns). Transitive expansion is lockfile-first (`packages.lock.json` / `project.assets.json` if `dotnet restore` ran; `paket.lock` for Paket), and otherwise a recursive walk of each package's `.nuspec` dependencies, up to 32 levels; that walk reports every version it reaches and does not unify them as a restore would. Per-TFM graphs are **unioned across all target frameworks** — a Windows-only GPL'd dep still surfaces.
  - CPM `<PackageVersion>` is stitched into versionless `<PackageReference>` entries, and `$(Property)` version tokens are expanded from the project file and the `Directory.Build` files above it. References in every branch of a `<Choose>` block are included; conditions are not evaluated.
  - DEV: `PrivateAssets="all"`; a `Condition` on the reference or its `<ItemGroup>` that is a Debug / Test configuration or `IsTestProject` comparison; a `<GlobalPackageReference>`; a Paket group named `Test`, `Build`, or `Tools`, or whose name ends in `test`.
  - A `<ProjectReference>` to a project the scan reads is the project's own code; any other one is off-registry. A package whose ID is that of a project in the scanned tree is not reported.
  - Not read: `nuget.config` `<packageSources>` (no NuGet source other than `api.nuget.org` is queried); a project file's own `<Import>`; a `<ProjectReference>` declared in a `Directory.Build` file; Paket `git`, `github`, `gist`, and `http` sources. `<Import>` chains in `Directory.Build` files are followed only for relative paths.
- **PHP**: Composer (`composer.json`, `composer.lock`). **Lockfile-first**: `composer.lock` entries embed a structured SPDX `license` field, so the resolver answers from the lockfile without HTTP when the pin matches. Without a lockfile it falls back to Packagist's per-version metadata; a locked or exact version Packagist does not list resolves to `UNKNOWN`, never to the license of another release. An entry under `packages-dev` is dev. Platform pseudo-packages (names without a `/`: `php`, `ext-*`, `lib-*`, `hhvm`) are filtered out. Off-registry, read from `composer.lock`: a path package the scan does not read, and a package that comes from a version-control, `package`, or `artifact` repository declared in `composer.json`. Without a `composer.lock`, licenseal cannot tell which packages a version-control or `artifact` repository provides, so they are looked up on Packagist by name and the `composer.json` is an analysis gap; scan with the `composer.lock` to close it. A `composer.lock` with no `composer.json` beside it cannot identify them either: only its path packages and `artifact` archives are off-registry.
- **Ruby**: RubyGems (`Gemfile`, `*.gemspec`, `Gemfile.lock`). deps.dev's batch endpoint runs first; rubygems.org fills the gap. A `Gemfile` gem is dev only when every group it belongs to is `:development` or `:test`; a gem in any other group, in a mixed list, or in no group is production, and so is one whose group name is not written as a literal. A gemspec `add_development_dependency` is dev. Off-registry: `GIT`, `PATH`, and `PLUGIN SOURCE` specs in `Gemfile.lock`, and a `Gemfile` gem declared with a `git` / `github` / `gist` / `bitbucket` / `path` option or block.
- **Hex (Elixir/Erlang)**: Mix (`mix.exs`, `mix.lock`), rebar3 (`rebar.config`, `rebar.lock`), erlang.mk (`Makefile`). hex.pm-only (deps.dev doesn't index Hex); license from the structured `meta.licenses` array, which hex.pm keeps per package and not per release. DEV: a `mix.exs` dep whose `only:` does not include `:prod`, the rebar `test` / `dev` profiles, and erlang.mk `TEST_DEPS`, `BUILD_DEPS`, `DOC_DEPS`, and `SHELL_DEPS`. Off-registry: a `mix.lock` entry that is not a `:hex` tuple, `git:` / `github:` / `path:` in `mix.exs`, a source tuple other than `{pkg, …}` in `rebar.config` and `rebar.lock`, and an erlang.mk dep fetched with `git`, `hg`, `svn`, `cp`, or `ln`. Umbrella apps are the project's own code. hex.pm allows 100 unauthenticated API requests per minute, so a project with more than 100 Hex packages pauses until the limit resets (about a minute per further 100 packages); each pause is announced on stderr. The waiting is bounded: packages still rate limited when it ends resolve to `UNKNOWN`, and a `Warning:` gives their number.
- **R / CRAN**: `DESCRIPTION` (`Imports` / `Depends` / `LinkingTo` prod; `Suggests` / `Enhances` dev) and `renv.lock` / `packrat.lock`. The official CRAN `PACKAGES` index is fetched once per scan; license and transitive closure resolve locally from it. The index lists the current version of each package only, so a package pinned to another version is reported at the pinned version with the license of the current one, marked as an estimate. R's license grammar (`GPL (>= 2)`, `MIT + file LICENSE`) is translated to SPDX (a bare `file LICENSE` → UNKNOWN). Off-registry: a lockfile package from GitHub, GitLab, Bitbucket, git, a URL, a local path, or Bioconductor, and a package named by the `Remotes` field of `DESCRIPTION`.
- **Cycles**: detected via `(ecosystem, name, version)` visited-set; cycles terminate cleanly.
- **Depth cap**: `--max-depth 50` by default. It bounds the registry walks of Python, npm, Rust, PHP, Ruby, and Hex. It does not bound a lockfile's graph, the deps.dev graph of a Maven or Gradle dependency, or the NuGet `.nuspec` walk, which has its own limit of 32 levels. Reaching the cap emits a stderr warning and stops expansion past that level.

## Resolution semantics

- Exact pins (`==2.28.1`, `18.2.0`) are reported at that exact version.
- Empty version constraints resolve against the registry's latest published release. A NuGet reference with no version, and a `pom.xml` dependency with no version that the parent chain does not manage either, are reported with no version and resolve to `UNKNOWN`.
- A range resolves to the highest published release inside it, read in the grammar of its ecosystem (PEP 440, npm, Cargo, RubyGems, Hex, Composer). A prerelease is selected only when the range admits prereleases; Python, like pip, also takes one when no release is inside the range. NuGet resolves as a restore does: a bare version or a range with an inclusive lower bound resolves to that bound, any other range to the lowest published release inside it, and a floating version (`1.*`) to the highest release it matches.
- Not resolved, and reported as `UNKNOWN` with no version: a constraint that is not written in its ecosystem's grammar; a range that no published version satisfies; a Composer branch constraint (`dev-main`); a Maven or Gradle version range, dynamic version, or `RELEASE` / `LATEST` marker (`[1.0,2.0)`, `1.+`, `latest.release`); a NuGet version holding an unresolved MSBuild property. No constraint falls back to the latest release.
- Go and R have no range to resolve. `go.mod` names exact versions. A `DESCRIPTION` constraint other than `(== x)` is not evaluated: the CRAN index lists one version of each package, and that version is the one reported.
- **Estimated versions.** A version that licenseal picked from a registry is marked: `~1.2.3` in the table and Markdown formats, with a legend line under the table, and `"estimated": ["version"]` in JSON. That is every transitive row that does not come from a lockfile and every direct dependency declared with a range or with no constraint. A row a lockfile supplies, an exact pin, a Maven version the parent chain manages, and a Go version are not marked.
- **Estimated licenses.** A license read from metadata that describes another release than the reported one is marked `~MIT`, and `"license"` in the JSON `estimated` array. This applies where a registry does not serve the license per release: an R package pinned to a version other than the one the CRAN index lists; a Hex package reported at a release other than the one published last; a Python release that declares no license in its own PyPI metadata or wheel metadata and takes the one of the project's latest release; and a pinned Python release that PyPI does not have. A license estimate is not a finding by itself, and the license is judged like any other: an estimated `GPL-3.0-only` in an MIT project is a violation.
- A registry lookup that cannot produce a license resolves that one dependency to `UNKNOWN` and the scan continues. A failed lookup of a pinned release is never answered with the metadata of another release.

licenseal is a license resolver, not a dependency resolver. It does not evaluate Python environment markers, `Requires-Python`, npm `engines`, or transitive-version conflict resolution beyond first-encountered-wins. That keeps resolution fast and predictable but does not model environment-specific installability.

## License expressions

How a declared license string is read before the matrix and the pair-level overrides in the [README](README.md) apply.

- **`WITH` exceptions** are matched against a fixed list.
  - `Classpath-exception-2.0` and `Classpath-exception-2.0-short` on a GPL license make the term weak copyleft.
  - An exception that only adds a permission leaves the term judged as its bare license: `Autoconf-exception-2.0`, `Autoconf-exception-3.0`, `Bison-exception-2.2`, `Bootloader-exception`, `Font-exception-2.0`, `GCC-exception-2.0`, `GCC-exception-3.1`, `Libtool-exception`, `Linux-syscall-note`, `LLVM-exception`, `OCaml-LGPL-linking-exception`, `Swift-exception`, `Universal-FOSS-exception-1.0`, `WxWindows-exception-3.1`. In addition, `Apache-2.0 WITH LLVM-exception` is compatible in a `GPL-2.0-only` project.
  - Any other text after `WITH` is read as terms nobody evaluated: the term is a violation when its bare license is one, and unknown otherwise.
- **Operands that did not resolve.** In an `AND`, an operand that is a violation makes the dependency a violation whatever the others are (`GPL-3.0-only AND UNKNOWN` in an MIT project); otherwise an operand that did not resolve makes it unknown. In an `OR`, a choice that did not resolve is never the one taken (`MIT OR CustomLicense` is judged as `MIT`).
- **Malformed expressions** (`MIT AND GPL-3.0-only AND`, `MIT OR (GPL-3.0-only`) are reported with the license `UNKNOWN`. The dependency is a violation when a license the string names is one, and unknown otherwise.
- **License lists.** When a source gives several licenses for one package, the list is read by what that source defines:
  - **A choice**: a Composer `license` array, `/` in a Cargo `license` field, `|` in an R `License` field, npm's legacy `licenses` array.
  - **All apply**: several `<license>` entries in a Maven POM, and a deps.dev `licenses` array with several entries (other than for a RubyGems package). Two rewrites apply to a deps.dev array only: a GPL entry beside the LGPL entry of the same version is dropped, as the text the LGPL refers to, and one CDDL entry plus `GPL-2.0-with-classpath-exception` is read as that dual license (`OR`). A deps.dev array that contains its `non-standard` marker is not used; the dependency is resolved from its own registry.
  - **Not defined by the source**: a RubyGems or Hex array with more than one entry, several distinct PyPI license classifiers, and a comma- or slash-separated list inside one license string (`MIT, GPL-3.0-only`; in an R `License` field such a list is `UNKNOWN`). Such a list is judged twice, as a choice and with every entry applying. When both readings give the same verdict, that verdict is reported; when they differ, the verdict is `unknown` and the reason asks you to confirm which holds and record it in `licenseal.review.toml`. The exception is `Ruby` with `BSD-2-Clause`, which the Ruby license itself offers as a choice.
- **R `+ file LICENSE`.** The file is never fetched. After `MIT`, `BSD_2_clause`, or `BSD_3_clause` it is the copyright notice those templates require, and the result is the license alone. After any other license it holds further terms, so `GPL-3 + file LICENSE` is reported as `GPL-3.0-only AND UNKNOWN`.
- **The project's own license.** With a top-level `OR`, a dependency has to be compatible with each arm, and an arm licenseal does not recognize is judged as `Proprietary`.

## Supported ecosystems

| Language | Registry | Manifest files | Lockfiles |
| --- | --- | --- | --- |
| Python | PyPI | `pyproject.toml` (PEP 621, PEP 735, Poetry), `requirements*.txt`, `setup.cfg`, `setup.py`, `Pipfile` | `uv.lock`, `poetry.lock`, `Pipfile.lock` |
| JavaScript / TypeScript | npm | `package.json` (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`) | `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` |
| Rust | crates.io | `Cargo.toml` (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[target.<cfg>.*]`, `[workspace.dependencies]` via `workspace = true` references) | `Cargo.lock` |
| Go | deps.dev (license) + proxy.golang.org (edges) | `go.mod` (`require`, `replace`, `tool` directive) | `go.sum` |
| Java / JVM | Maven Central + deps.dev; fallback `dl.google.com`, `repo.jenkins-ci.org` | Maven `pom.xml`; Gradle `build.gradle`, `build.gradle.kts` (text heuristic) | `gradle.lockfile` |
| .NET | NuGet.org `.nuspec` + deps.dev; Paket via `api.nuget.org` | `.csproj` / `.fsproj` / `.vbproj`, `packages.config`, `Directory.Packages.props`, `Directory.Build.props` / `.targets`, `paket.dependencies` | `packages.lock.json`, `project.assets.json`, `paket.lock` |
| PHP | Packagist (lockfile-first) | `composer.json` | `composer.lock` |
| Ruby | RubyGems + deps.dev | `Gemfile`, `*.gemspec` | `Gemfile.lock` |
| Elixir / Erlang | Hex (`hex.pm`) | `mix.exs`, `rebar.config`, erlang.mk `Makefile` | `mix.lock`, `rebar.lock` |
| R | CRAN (`PACKAGES` index) | `DESCRIPTION` | `renv.lock`, `packrat/packrat.lock` |

## Discovery: auto-skipped directories

The walker skips a unified set of directory names at every depth — same list for all ecosystems:

- **VCS / caches**: `.git`, `.tox`, `.nox`, `__pycache__`, `node_modules`
- **Sample / fixture trees**: `examples`, `fixtures`, `__fixtures__`
- **Build / dist / vendoring outputs**: `build`, `dist`, `target`, `.eggs`, `site-packages`, `vendor`, `__pypackages__`, `.pdm-build`
- **JS framework build outputs & legacy package-manager trees**: `.next`, `.nuxt`, `.svelte-kit`, `.yarn`, `bower_components`, `jspm_packages`

Virtualenvs are detected **structurally** via the PEP 405 `pyvenv.cfg` marker rather than by name, so `.venv/`, `venv/`, `env/`, `env-3.11/`, and any other naming convention are skipped without false positives. Any subdirectory with its own `.git` (file or directory) is skipped automatically — cloned dependencies, vendored forks, and submodules are treated as separate projects. A symlinked directory is not entered. Use `--exclude-dirs` for subtrees not already covered.

## Off-registry dependencies

A dependency whose source is a **git repository**, a **direct URL** (a wheel, an sdist, a tarball), or a **path the scan does not read** does not come from a package registry. One policy applies in every ecosystem:

- It is reported as one row whose license is `UNKNOWN`. No registry request is made for it under any name, and nothing is downloaded: a registry package of the same name is a different package, and a private name is never sent to a public registry. The row fails strict mode until it is reviewed.
- Its JSON `origin` field names the source, as specific as the files allow: `git+<url>@<commit>` when a lockfile records the commit, otherwise `git+<url>@<ref>` or `git+<url>`; `<url>#<hash>` or `<url>` for a direct URL; a path as written; the lockfile's own source label (`Bioconductor`) or `unrecorded source` when the files record no location. Credentials in a URL are removed.
- A path dependency is the project's own code only when **the scan reads it**: the path is a directory inside the scanned directory that the scan walks. It is then not reported, and its manifests are scanned like any other. Every other path is a row: a path outside the scanned directory, an archive file (a wheel, a tarball, a JAR), and a directory the scan skips (`vendor/`, a nested repository, an `--exclude-dirs` path).
- When a lockfile records the registry packages an off-registry dependency pulls in, those are reported and name it in `direct_ancestors`. Without a lockfile, what an off-registry dependency itself depends on is not reported.
- **Not read:** a declaration that redirects a registry package to another source from outside the package's own entry. These are npm `overrides`, Yarn `resolutions`, and pnpm `overrides` in `package.json`; `[tool.uv]` `override-dependencies` and `constraint-dependencies`; a Maven `system` scope that a `<dependencyManagement>` entry supplies; and Cargo's `.cargo/config.toml`. Such a package is looked up on the registry under its name, unless a lockfile records a git, URL, or path source for it.
- An **alternate index or registry** is not an off-registry source. A package pinned to a Poetry `source`, a uv index, a `Gemfile` `source` block, a Cargo `registry`, or a private npm registry is looked up on the public registry under the same name, and the license of the public package is what is reported (see [SECURITY.md](SECURITY.md#what-leaves-the-process)).

Which declarations count as off-registry is listed per ecosystem under [Per-ecosystem resolution detail](#per-ecosystem-resolution-detail). To clear such a row, review it by its source: see [Manual review file](#manual-review-file).

## Manual review file

When a dependency is flagged but you have better license information than the resolver (e.g. you've read the bundled `LICENSE` file), record the override in `licenseal.review.toml` at the project root:

```toml
[[review]]
ecosystem = "python"
package = "mystery-lib"
version = "1.0.0"
license = "MIT"
note = "confirmed from packaged LICENSE file"
```

Workflow:

1. `licenseal check -f json -o report.json` — capture flagged deps
2. `licenseal init-review-file --from-report report.json` — scaffold blank entries offline
3. Fill in `license` (and optionally `note`) for each entry
4. `licenseal check` again — overrides apply

`licenseal init-review-file` without `--from-report` does steps 1 and 2 in one go: it runs the scan `check` runs by default and scaffolds an entry for each flagged dependency, direct or transitive. For a `check` run with other options (`--no-transitive`, another `--max-depth`), scaffold from that run's report with `--from-report`. A flagged registry dependency with no resolved version gets no stanza, since there is no version to key a review on; a stderr `Note:` names it.

An [off-registry dependency](#off-registry-dependencies) has no registry version to key a review on, so its entry is keyed on its source. The stanza carries a `source` key holding the row's `origin` string, and `version` is optional. `init-review-file` writes it:

```toml
[[review]]
ecosystem = "ruby"
package = "edge-fork"
source = "git+https://git.example.org/team/edge-fork.git@0123abcd"
license = "MIT"
note = "LICENSE read at that commit"
```

When new flagged dependencies appear later, run `licenseal init-review-file --merge` to **add new stanzas** to the existing file. Existing entries are preserved verbatim.

Rules at a glance:

- The match key is the resolved `ecosystem:name@version`. `package` is compared the way the ecosystem's registry compares names: exactly, upper and lower case included, for Go, Java, npm, and Ruby; without regard to case for .NET, PHP, Rust, Hex, and R; with PEP 503 normalization for Python. A Hex dependency that `mix.exs` declares under another name than its hex.pm package is matched on the hex.pm name.
- An entry with a `source` key matches on ecosystem, package, and `source`, compared with the row's `origin` exactly, and on `version` when the entry has one. A review keyed on a commit applies to that commit only. One keyed on a **branch or a tag** (all a manifest without a lockfile can say), on a bare repository URL, on a URL without a hash, or on a path keeps applying when the code there changes; pin a commit, or commit a lockfile, to get an immutable key.
- Reviews can only override flagged dependencies, never compatible ones.
- A filled-in entry that matches no reported row, and an invalid entry (a missing or mistyped key, an unknown ecosystem, a license that is not a well-formed license expression, a duplicate), fails the command. The IDs inside the expression are not checked: a mistyped one is accepted, and the dependency is then classified as unknown. An entry whose `license` is empty is not applied, and `check` names it in a `Warning:`.
- `licenseal.review.toml` and the report passed to `--from-report` must be UTF-8; write the report with `-o report.json` rather than a shell redirect.
- Reports keep both the detected and reviewed licenses visible; JSON exposes `detected_license`, `reviewed_license`, `effective_license`, `reviewed`, and `review_note`.
- **Strict-mode exit code** skips reviewed entries. A reviewed dep is classified by its reviewed license, but `licenseal check --strict` passes because the review IS the accept-and-document mechanism. Unreviewed warnings / violations / unknowns still fail. **Analysis gaps** are not part of the review mechanism — close them by fixing the file, committing a lockfile, or passing `--no-require-lockfile`.

Reviewed entries appear in their own report section:

> **Summary:** 0 violations, 0 warnings, 0 unknown, 4 ok (of which 1 reviewed)

| Package | Detected | Reviewed | Note |
| --- | --- | --- | --- |
| mystery-lib (1.0.0) | UNKNOWN (raw: Custom internal license) | MIT | confirmed from packaged LICENSE file |

Because a malicious entry can mark a copyleft dependency as MIT and pass strict mode, treat `licenseal.review.toml` as security-relevant: require code review on every change, document each override's rationale in `note`, and re-validate periodically. (See [SECURITY.md](SECURITY.md).)

## Claude Code skill

licenseal ships a [Claude Code](https://claude.com/claude-code) skill that drives the review workflow interactively — runs `licenseal check`, walks you through each flagged dep, fills in `licenseal.review.toml` from your decisions, and re-verifies that the gaps closed.

```bash
licenseal install-skill                  # <project>/.claude/skills/licenseal-review/SKILL.md
licenseal install-skill --path ../other  # install into another project directory
licenseal install-skill --force          # overwrite a hand-edited skill
```

The skill installs **only inside the project** (`.claude/skills/`), never globally — licenseal never reads or writes outside the project directory, so the skill can be committed alongside the code it audits. Claude Code discovers it automatically; invoke `/licenseal-review` to run it. It consumes the `actionability` block emitted on every flagged dep in the JSON report (`investigate_url` + verdict-aware `next_steps`); the URL trust model is documented in [JSON_OUTPUT.md](JSON_OUTPUT.md).

**Keeping the skill current.** The installed `SKILL.md` is a snapshot, so upgrading the package doesn't update it automatically. When the bundled skill actually changes in a release, the next `licenseal check` prints a one-line reminder, and re-running `install-skill` rewrites an unedited install in place (no `--force` needed). The reminder is content-based (a release that doesn't touch the skill stays quiet), checks only the project-local `.claude/skills`, and is strictly read-only — so it never fires for users who run licenseal without the skill installed.
