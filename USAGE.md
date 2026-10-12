# licenseal — Usage & reference

Full CLI reference, resolution behavior, and per-ecosystem detail. For the overview and install, see the [README](README.md); for the security and egress model, [SECURITY.md](SECURITY.md); for the JSON schema, [JSON_OUTPUT.md](JSON_OUTPUT.md).

## Commands

```bash
licenseal check                 # scan the current project and exit non-zero when the check fails
licenseal init-review-file      # scaffold a licenseal.review.toml for flagged dependencies
licenseal install-skill         # install the Claude Code review skill into the project
licenseal --version             # print the version and exit
```

### `licenseal check` options

| Flag | Default | Notes |
|---|---|---|
| `--path DIRECTORY`, `-p DIRECTORY` | `.` | Directory to scan |
| `--format FMT`, `-f FMT` | `table` | `table`, `json`, or `markdown` |
| `--output FILE`, `-o FILE` | — | Write the report to FILE instead of stdout |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--strict / --no-strict` | `--strict` | Also fail on warnings, unknowns, and [analysis gaps](#output--the-ci-gate) (violations always fail) |
| `--require-lockfile / --no-require-lockfile` | `--require-lockfile` | Whether a [manifest without a lockfile](#output--the-ci-gate) is an analysis gap. `--no-require-lockfile` accepts the estimated or incomplete result and reports it without failing. No effect with `--no-transitive`. |
| `--transitive / --no-transitive` | `--transitive` | Full-tree scan, or direct dependencies only |
| `--max-depth N` | `50` | Cap the depth of a registry walk (see [Transitive scanning](#transitive-scanning)), 1 to 100. A usage error with `--no-transitive` |
| `--max-workers N` | `16` | Concurrent registry requests, 1 to 32 |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery. Comma-separated, repeatable, relative to `--path` or absolute. A subdirectory with its own `.git` is skipped without it. |

### `licenseal init-review-file` options

| Flag | Default | Notes |
|---|---|---|
| `--path DIRECTORY`, `-p DIRECTORY` | `.` | Project directory, where `licenseal.review.toml` is written. Without `--from-report` it is scanned as `check` scans it by default |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--from-report FILE` | — | Read flagged dependencies from a saved JSON report instead of scanning (no registry request). A usage error together with `--dev` / `--no-dev`, `--max-workers`, or `--exclude-dirs`, which only apply to a scan |
| `--merge` | — | Add new flagged entries to an existing review file; existing entries are kept. Without it, the command stops with an error rather than change an existing file |
| `--max-workers N` | `16` | Concurrent registry requests, 1 to 32 |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery, as for `check` |

## Common usage

```bash
licenseal check                              # full-tree scan (default; lockfile-first, registry fallback)
licenseal check --no-transitive              # direct dependencies only (use when publishing a library)
licenseal check --dev                        # also include dev dependencies
licenseal check --no-strict                  # don't fail on warnings, unknowns, or analysis gaps (violations still fail)
licenseal check --no-require-lockfile        # no lockfile committed: accept versions and transitives estimated from the registry
licenseal check -f json -o report.json       # machine-readable output for CI tooling
licenseal check -f markdown -o LICENSES.md   # Markdown audit, suitable for a PR comment
licenseal check --exclude-dirs third_party,scratch  # skip subtrees not already in the default skip set
```

## Project license

Every verdict compares a dependency's license with the project's own. licenseal reads the project license from the manifests in the scanned directory (`--path`), never from a subdirectory.

- The first manifest that declares a license decides, in this order: `pyproject.toml`, `setup.cfg`, `setup.py`, `package.json`, `Cargo.toml`, `pom.xml`, `.csproj` / `.fsproj` / `.vbproj`, `Directory.Build.props`, `composer.json`, `*.gemspec`, `mix.exs`, `DESCRIPTION`. When manifests there declare different licenses, a `Warning:` names each file and its value; it does not fail the check.
- `check`, and `init-review-file` when it scans, print the value and its file on stderr (`Project license: MIT (from pyproject.toml).`). The table and Markdown reports show the same, and JSON carries the file as `project_license_source`.
- When no manifest in the scanned directory declares a license, the project is checked as `Proprietary` (a closed-source project can use permissive dependencies but not copyleft ones), and the stderr line and the reports say the license is assumed. To check one package of a monorepo against its own license, scan it with `--path`.
- A declared value that is not a recognised license (`"license": "-"`, a sentence) is not used: the project is checked as `Proprietary`, and a `Warning:` names the file and the value; it does not fail the check.

## Output & the CI gate

`licenseal check` exits non-zero when a dependency is **flagged** (a violation, a warning, or an unknown license) or the scan has **analysis gaps**. That is **strict mode**, the default. A flagged dependency stops failing once it is [reviewed](#manual-review-file).

- `--no-strict` stops warnings, unknowns, and analysis gaps from failing the check. Violations always fail.
- If every registry lookup fails and not one dependency resolves (no network, blocked egress, a registry-wide outage), `check` aborts with an error and a non-zero exit instead of reporting every dependency as `UNKNOWN`, with or without `--no-strict`.

An **analysis gap** is something the scan could not read, so a dependency may be missing from the report. Each gap is a `Warning:` on stderr and is recorded in the report: an **Analysis gaps** section and a count on the summary line in the table and Markdown formats, `summary.gaps` and `diagnostics` in JSON. The kinds:

- a manifest or lockfile that cannot be read (permission or I/O error, or larger than 128 MiB), decoded, or parsed, and a directory that cannot be traversed;
- a value of a type its format does not allow (`"dependencies": []` in `package.json`): the value is ignored and the rest of the file is read;
- a lockfile that cannot be used: a format version licenseal does not read (`pnpm-lock.yaml` below `lockfileVersion` 6), no entry in a readable form, or merge-conflict markers. The direct dependencies it would have covered are resolved through the registry instead. These three checks are not made for `Cargo.lock`, `go.sum`, `packages.lock.json`, `project.assets.json`, `paket.lock`, or `rebar.lock`: an entry of one of those that cannot be read is skipped without a diagnostic;
- a reference to another file that is not followed: an MSBuild `<Import>` or `go.work` `use` that is not a relative path, or a requirements `-r` include or setuptools `file:` directive that is a URL, is not a relative path, is not a file, or leaves the scanned directory;
- a package whose dependency list the registry did not return during a registry walk: the package is reported, and what it requires may be missing. `--no-require-lockfile` does not waive this one;
- two ecosystem-specific cases described under [Per-ecosystem resolution detail](#per-ecosystem-resolution-detail): a `composer.json` with repositories and no `composer.lock`, and a `go.mod` below `go 1.17` with `go.sum` rows missing;
- a **manifest without a lockfile**: one that declares a direct dependency no lockfile covers. There is no lockfile, the lockfile does not list the dependency, or it lists it only at a version the declaration does not admit (the exact rule is under [Transitive scanning](#transitive-scanning)).
  - That dependency and everything under it are resolved through the registry, and the result is an estimate of what the project installs. An [off-registry dependency](#off-registry-dependencies) that no lockfile records counts too.
  - With `--require-lockfile` (the default) the manifest is an analysis gap. With `--no-require-lockfile` it is listed under **Estimates** in the table and Markdown formats, has severity `estimate` in JSON `diagnostics`, and does not fail.
  - Exempt, with no diagnostic: Go; `--no-transitive`; a manifest whose only uncovered dependencies are dev dependencies in a scan without `--dev`; and a manifest of a tool with no lockfile format (Maven `pom.xml`, NuGet `packages.config`, an erlang.mk `Makefile`), whose rows are still marked as estimates where licenseal picked the version.

Format versions and encodings:

- A lockfile in a newer format version than licenseal was written for is read on a best-effort basis, with a `Warning:` that does not fail.
- A manifest or lockfile written as UTF-16 or UTF-32 with a byte-order mark is read in that encoding. A text, JSON, or YAML file that is not valid UTF-8 is read through a latin-1 fallback, with a `Warning:` that does not fail. A TOML file that is not valid UTF-8 is an analysis gap, and so is a text, JSON, YAML, or TOML file that holds NUL characters, as UTF-16 without a byte-order mark does.

`-o FILE` writes the report as UTF-8 (the table without ANSI escapes). The file is written even when findings or analysis gaps fail the check, so CI can publish it (an error, such as an invalid review file or unreachable registries, writes none); a failing check then also prints the summary and the findings that failed it, with the number of analysis gaps, to stderr.

The table and Markdown formats escape the strings that come from registries and scanned files (control characters, and Markdown and HTML syntax), so a package name or a license string cannot add a link, markup, or a table column. JSON reports the original strings.

Piped, or written with `-o`, the table is at its full width with one line per dependency. On a terminal narrower than the table, cells wrap and no column is dropped. When stdout's encoding cannot represent the report's glyphs (a legacy Windows code page), `OK`, `!`, and `X` are printed for ✓, ⚠, and ✗.

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

These directory names are skipped at every depth, in every ecosystem:

- **VCS / caches**: `.git`, `.tox`, `.nox`, `__pycache__`, `node_modules`
- **Sample / fixture trees**: `examples`, `fixtures`, `__fixtures__`
- **Build / dist / vendoring outputs**: `build`, `dist`, `target`, `.eggs`, `site-packages`, `vendor`, `__pypackages__`, `.pdm-build`
- **JS framework build outputs & legacy package-manager trees**: `.next`, `.nuxt`, `.svelte-kit`, `.yarn`, `bower_components`, `jspm_packages`

A virtualenv (any directory holding `pyvenv.cfg`) is skipped whatever its name. A subdirectory with its own `.git` (file or directory) is skipped: cloned dependencies, vendored forks, and submodules are separate projects. A symlinked directory is not entered. Use `--exclude-dirs` for any other subtree.

## Transitive scanning

Transitive is the default. `--no-transitive` audits only the dependencies you declared directly: it takes no rows from a lockfile and reports no transitive. Resolution is **lockfile-first**:

1. If a lockfile is present (see [Supported ecosystems](#supported-ecosystems)), it is the source of truth.
   - A lockfile **covers** a direct dependency only when it holds that package at a version the declaration admits: `shared>=2` is covered by a locked `2.4.0`, not by a locked `1.0.0`. A locked version that cannot be compared with the declaration covers it too: a declaration with no constraint, a tag or a branch, and any range when the locked version is a prerelease. A declaration no lockfile covers is resolved through the registry (step 2).
   - A lockfile is read wherever it is found in the scanned tree, with or without a manifest beside it. A sample or test-data lockfile outside the [auto-skipped directories](#discovery-auto-skipped-directories) therefore adds its packages to the report; exclude its directory with `--exclude-dirs`. Two npm exceptions: a lockfile under a directory named `test` or `tests` is not read, and when one directory holds several npm lockfiles only the first of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` is read.
2. When no lockfile covers a dependency, licenseal falls back to a **registry walk**: each dependency's per-version metadata is fetched, breadth-first and in parallel (`--max-workers`), down to `--max-depth`.
   - What the walk reports is an estimate: the versions are the ones the registries publish at scan time, not the ones the project installs. Every row it adds is marked as estimated (see [Resolution semantics](#resolution-semantics)), and its manifest is a [manifest without a lockfile](#output--the-ci-gate).
   - `--max-depth` (default 50) bounds the registry walks of Python, npm, Rust, PHP, Ruby, and Hex. It does not bound a lockfile's graph, the deps.dev graph of a Maven or Gradle dependency, or the NuGet `.nuspec` walk, which has its own limit of 32 levels. A walk that reaches the cap stops there; a `Warning:` says deeper dependencies may be missing, and it does not fail the check.

A report has one row per package, resolved version, and origin. Several versions of one package can be in it, each with its own license lookup: a graph can hold `lodash@4.x` and `lodash@3.x` through different paths, and the manifests of one tree can ask for different versions.

The table and Markdown layout:

- Direct dependencies are listed alphabetically, each with its transitives indented beneath it, also alphabetically, so a flagged transitive leads back to the direct dependency you would remove to drop it.
- A transitive that several direct dependencies pull in is listed once, under the alphabetically first, with an `(also: X, Y)` annotation. JSON has the full list in `direct_ancestors` (with `depth` and `is_transitive`).

Whether a row is `prod` or `dev`:

- A transitive is `prod` when a production dependency pulls it in, otherwise `dev` when a dev dependency does, otherwise not reported. A scan without `--dev` therefore leaves out what only dev dependencies pull in.
- A dependency declared as dev that a production dependency also pulls in is `prod`, and `--dev` adds rows without changing a `prod` row to `dev`.
- When a lockfile holds none of the direct dependencies found in the manifests, all its packages are reported, as `prod` unless the lockfile format records its own dev/prod split.

## Off-registry dependencies

An **off-registry dependency** is one whose source is a **git repository**, a **direct URL** (a wheel, an sdist, a tarball), or a **path the scan does not read**: it does not come from a package registry. One policy applies in every ecosystem:

- It is reported as one row whose license is `UNKNOWN`. No registry request is made for it under any name, and nothing is downloaded: a registry package of the same name is a different package. The row fails strict mode until it is reviewed.
- Its JSON `origin` field names the source, as specific as the files allow: `git+<url>@<commit>` when a lockfile records the commit, otherwise `git+<url>@<ref>` or `git+<url>`; `<url>#<hash>` or `<url>` for a direct URL; a path as written; the lockfile's own source label (`Bioconductor`) or `unrecorded source` when the files record no location. Credentials in a URL are removed.
- A path dependency is the project's own code only when **the scan reads it**: the path is a directory inside the scanned directory that discovery does not skip. It is then not reported, and its manifests are scanned like any other. Every other path is a row: a path outside the scanned directory, an archive file (a wheel, a tarball, a JAR), and a directory the scan skips (`vendor/`, a nested repository, an `--exclude-dirs` path).
- A name that one manifest takes from a registry and another from a repository, or that two manifests take from two repositories, is one row per source: a lockfile entry covers only a declaration from its own source (one repository whatever the commit, one URL, one path).
- When a lockfile records the registry packages an off-registry dependency pulls in, those are reported and name it in `direct_ancestors`. Without a lockfile that records it, what an off-registry dependency itself depends on is not reported, and the manifest that declares it is a [manifest without a lockfile](#output--the-ci-gate). A Mix `path:` dependency and a .NET project reference are exempt when their lockfile is present.
- **Not read:** npm `overrides`, Yarn `resolutions`, and pnpm `overrides` in `package.json`; `[tool.uv]` `override-dependencies` and `constraint-dependencies`; a Maven `system` scope that a `<dependencyManagement>` entry supplies; Cargo's `.cargo/config.toml`. A package these redirect to another source is looked up on the registry under its name, unless a lockfile the scan reads records a git, URL, or path source for it (`--no-transitive` reads no lockfile).
- An **alternate index or registry** is not an off-registry source. A package pinned to a Poetry `source`, a uv index, a `Gemfile` `source` block, a Cargo `registry`, or a private npm registry is looked up on the public registry under the same name, and the license of the public package is what is reported (see [SECURITY.md](SECURITY.md#what-leaves-the-process)).

Which declarations are off-registry is listed per ecosystem below. To clear such a row, review it by its source: see [Manual review file](#manual-review-file).

## Per-ecosystem resolution detail

For each ecosystem: what is read beyond the files listed under [Supported ecosystems](#supported-ecosystems) (**Reads**), which dependencies are dev (**Dev**), which are [off-registry](#off-registry-dependencies) (**Off-registry**), and what is not evaluated (**Not evaluated**). The hosts contacted are in [SECURITY.md](SECURITY.md#network-egress).

- **Python**
  - **Reads**: requirements files named `requirements*.txt` or `*-requirements.txt`. A `-r` include is followed inside the scanned directory, and a setuptools `file:` directive (`install_requires = file: reqs.in` in `setup.cfg`, `[tool.setuptools.dynamic]` in `pyproject.toml`) is followed like one. Extras are followed, from the `uv.lock` edges when there is one.
  - **Dev**: an extra, a dependency group, or a Poetry group named `dev`, `test`, `tests`, `testing`, `lint`, `ci`, or `docs`, and a dependency group one of those includes; a requirements file whose name has one of those words set off by `-` or `_` (`requirements-dev.txt`); `Pipfile` `dev-packages`. Included requirements are dev or production by the file the chain starts from, and those of a `file:` directive by the option that names the file.
  - **Off-registry**: a URL, VCS, or local-path requirement (`name @ <url>`, `git+https://…`, `./pkg.whl`), a Poetry `git` / `url` / `path` dependency, a `[tool.uv.sources]` `git` / `url` / `path` entry, a `Pipfile` VCS or path entry, and the corresponding sources in `uv.lock`, `poetry.lock`, and `Pipfile.lock`.
  - **Not evaluated**: PEP 508 environment markers (treated as always true) and `Requires-Python`. `-c` constraints files are not read, and a requirements file under another name that nothing includes is not scanned.
- **npm**
  - **Reads**: `peerDependencies` and `optionalDependencies` as production, like `dependencies`. A package installed under an npm alias is reported under its real name. A package that another `package.json` in the tree defines (a monorepo or pnpm workspace member) is not reported; a stderr line says how many were excluded.
  - **Dev**: `devDependencies`.
  - **Off-registry**: a git URL, a hosting shorthand (`github:user/repo`, a bare `user/repo`), a tarball URL, and a `file:` / `link:` / `portal:` or bare path (`../pkg`, `C:\pkg`, `pkg-1.0.0.tgz`) the scan does not read, in `package.json` and in every lockfile format. One exception: a lockfile's `resolved` tarball URL in the layout registries serve (`<host>/<name>/-/<file>.tgz`, on any host) is a package of another registry, looked up on registry.npmjs.org.
  - **Not evaluated**: `engines`.
- **Rust**
  - **Reads**: with a `Cargo.lock`, the locked graph as it is.
  - **Dev**: `[dev-dependencies]`. `[build-dependencies]` are production.
  - **Off-registry**: a `git = …` dependency, a `path = …` the scan does not read, and a crate that a `[patch]` or `[replace]` entry points at either.
  - **Not evaluated**: without a `Cargo.lock`, the optional (feature-gated) dependencies of the crates the registry walk visits. A path crate that `Cargo.lock` reaches only through another path crate the scan does not read is not reported.
- **Go**
  - **Reads**: with a `go.sum`, its modules plus every `go.mod` requirement at the required version; no version is chosen among `go.sum` rows, so a row for another version of a module stays in the report. `replace` directives of the scanned `go.mod` are applied: a requirement replaced by another module is scanned as that module. So are the `replace` directives of a `go.work` in the scanned directory, for the modules it lists with `use`; they override those modules' own. `go.work` `use` directories are followed only when they are relative paths.
  - **Dev**: only a module named by a `tool` directive (Go 1.24+), unless a production module also requires it. `// indirect` is not a dev marker, and test-only requirements cannot be told from production ones.
  - **Off-registry**: a requirement replaced by a local path the scan does not read (one it reads is the project's own code). A path written in `go.work` is relative to `go.work`.
  - **Not evaluated**: `replace` directives in a dependency's `go.mod`, and a `go.work` below the scanned directory. A `go.mod` with a `go` directive below 1.17, or none, lists direct requirements only: when one of them has no `go.sum` row, what it depends on is missing and the `go.mod` is an analysis gap; committing an up-to-date `go.sum` removes it.
- **Java/JVM**
  - **Reads**: in a `pom.xml`, BOM imports and the `<dependencyManagement>` parent chain, including `${revision}`-style property inheritance, with and without `--no-transitive`, and the dependencies of every profile in `<profiles>`. In a Gradle build file, which is read as text, the static-string declarations of a `dependencies { … }` block. A Gradle coordinate declared without a version (a BOM or a plugin supplies it) is reported at the artifact's latest release, as an estimate, when no `gradle.lockfile` covers it. An artifact that another module of the scanned build defines is not reported.
  - **Dev**: Maven scopes `test`, `provided`, and `system`; `compile` and `runtime` are production. Gradle goes by configuration name, and a declaration under a name in neither list is skipped:
    - production: `implementation`, `api`, `compile`, `runtime`, `runtimeOnly`, `compileOnly`, `compileOnlyApi`, `compileClasspath`, `runtimeClasspath`, `providedCompile`, `providedRuntime`, `annotationProcessor`, `kapt`, `ksp`, `kaptTest`, `releaseImplementation`, `releaseApi`, `releaseRuntimeOnly`, `shadow`;
    - dev: `testImplementation`, `testApi`, `testCompileOnly`, `testRuntimeOnly`, `testCompileClasspath`, `testRuntimeClasspath`, `androidTestImplementation`, `androidTestApi`, `androidTestCompileOnly`, `androidTestRuntimeOnly`, `testFixturesApi`, `testFixturesImplementation`, `debugImplementation`, `debugApi`, `debugRuntimeOnly`, `developmentOnly`, `checkstyle`, `spotbugs`, `pmd`, `detekt`, `jacocoAgent`, `jacocoAnt`.
  - **Off-registry**: a Maven `system`-scoped dependency, which is a local JAR.
  - **Not evaluated**: profile activation conditions; a parent chain or BOM nesting deeper than 5 levels; in a Gradle build file, version catalogs, variable interpolation, `platform(...)` references, and dynamic blocks.
- **.NET**
  - **Reads**: a `<PackageVersion>` of Central Package Management as the version of a versionless `<PackageReference>`, and `$(Property)` version tokens expanded from the project file and the `Directory.Build` files above it. References in every branch of a `<Choose>` block are included, and the graphs of all target frameworks are merged, so a dependency of one framework only is still reported. `<Import>` chains in `Directory.Build` files are followed for relative paths only. A package whose ID is that of a project in the scanned tree is not reported.
  - **Dev**: `PrivateAssets="all"`; a `Condition` on the reference or its `<ItemGroup>` that is a Debug / Test configuration or `IsTestProject` comparison; a `<GlobalPackageReference>`; a Paket group named `Test`, `Build`, or `Tools`, or whose name ends in `test`.
  - **Off-registry**: a `<ProjectReference>` to a project the scan does not read (one it reads is the project's own code).
  - **Not evaluated**: `<Choose>` conditions; a `.nuspec` license given as a file (`<license type="file">`), which is not read; `nuget.config` `<packageSources>` (no NuGet source other than `api.nuget.org` is queried); a project file's own `<Import>`; a `<ProjectReference>` declared in a `Directory.Build` file; Paket `git`, `github`, `gist`, and `http` sources. Without a lockfile, the walk of each package's `.nuspec` dependencies reports every version it reaches and does not unify them as a restore would.
- **PHP**
  - **Reads**: the license of a locked package from the `license` field of its `composer.lock` entry, and from Packagist when the entry has none or there is no lockfile. A locked or exact version Packagist does not list resolves to `UNKNOWN`, never to the license of another release. Platform packages (names without a `/`: `php`, `ext-*`, `lib-*`, `hhvm`) are not reported.
  - **Dev**: `require-dev` in `composer.json`, and `packages-dev` in `composer.lock`.
  - **Off-registry**: read from `composer.lock`: a path package the scan does not read, and a package that comes from a version-control, `package`, or `artifact` repository declared in `composer.json`. In a `composer.lock` with no `composer.json` beside it, only path packages and `artifact` archives are off-registry.
  - **Not evaluated**: without a `composer.lock`, which packages a version-control or `artifact` repository provides. They are looked up on Packagist by name and the `composer.json` is an analysis gap; scanning with the `composer.lock` removes it.
- **Ruby**
  - **Dev**: a `Gemfile` gem only when every group it belongs to is `:development` or `:test`; a gem in any other group, in a mixed list, or in no group is production, and so is one whose group name is not written as a literal. A gemspec `add_development_dependency`.
  - **Off-registry**: `GIT`, `PATH`, and `PLUGIN SOURCE` specs in `Gemfile.lock`, and a `Gemfile` gem declared with a `git` / `github` / `gist` / `bitbucket` / `path` option or block.
- **Hex (Elixir/Erlang)**
  - **Dev**: a `mix.exs` dependency whose `only:` does not include `:prod`; the rebar `test` and `dev` profiles; erlang.mk `TEST_DEPS`, `BUILD_DEPS`, `DOC_DEPS`, and `SHELL_DEPS`.
  - **Off-registry**: a `mix.lock` entry that is not a `:hex` tuple; `git:` / `github:` / `path:` in `mix.exs`; a source tuple other than `{pkg, …}` in `rebar.config` and `rebar.lock`; an erlang.mk dependency fetched by a method other than `hex`. Umbrella apps are the project's own code.
- **R / CRAN**
  - **Reads**: `Imports`, `Depends`, and `LinkingTo` in `DESCRIPTION` as production. R's license grammar (`GPL (>= 2)`, `MIT + file LICENSE`) is translated to SPDX; a bare `file LICENSE` is `UNKNOWN`.
  - **Dev**: `Suggests` and `Enhances` in `DESCRIPTION`.
  - **Off-registry**: a lockfile package from GitHub, GitLab, Bitbucket, git, a URL, a local path, or Bioconductor, and a package named by the `Remotes` field of `DESCRIPTION`.
  - **Not evaluated**: the license of a version other than the current one. The CRAN index lists the current version of each package only, so a package pinned to another version is reported at the pinned version with the license of the current one, marked as an estimate.

## Resolution semantics

- Exact pins (`==2.28.1`, `18.2.0`) are reported at that exact version.
- An empty version constraint resolves to the registry's latest published release. A NuGet reference with no version, and a `pom.xml` dependency with no version that the parent chain does not manage either, are reported with no version and resolve to `UNKNOWN`.
- A range resolves to the highest published release inside it, read in the grammar of its ecosystem (PEP 440, npm, Cargo, RubyGems, Hex, Composer). A prerelease is selected only when the range admits prereleases; Python, like pip, also takes one when no release is inside the range. NuGet resolves as a restore does: a bare version or a range with an inclusive lower bound resolves to that bound, any other range to the lowest published release inside it, and a floating version (`1.*`) to the highest release it matches.
- Not resolved, and reported as `UNKNOWN` with no version: a constraint that is not written in its ecosystem's grammar; a range that no published version satisfies; a Composer branch constraint (`dev-main`); a Maven or Gradle version range, dynamic version, or `RELEASE` / `LATEST` marker (`[1.0,2.0)`, `1.+`, `latest.release`); a NuGet version holding an unresolved MSBuild property. None of these falls back to the latest release.
- Go and R have no range to resolve. `go.mod` names exact versions. A `DESCRIPTION` constraint other than `(== x)` is not evaluated: the CRAN index lists one version of each package, and that version is the one reported.
- **Estimated versions.** A version that licenseal picked from a registry is marked: `~1.2.3` in the table and Markdown formats, with a legend line under the table, and `"estimated": ["version"]` in JSON. That is every transitive row that does not come from a lockfile and every direct dependency declared with a range or with no constraint. A row a lockfile supplies, an exact pin, a Maven version the parent chain manages, and a Go version are not marked.
- **Estimated licenses.** A license read from metadata that describes another release than the reported one is marked `~MIT`, and `"license"` in the JSON `estimated` array. The mark is not a finding by itself, and the license is judged like any other: an estimated `GPL-3.0-only` in an MIT project is a violation. A license is an estimate where a registry does not serve it per release:
  - an R package pinned to a version other than the one the CRAN index lists;
  - a Hex package reported at a release other than the one published last;
  - a Python release that declares no license in its own PyPI metadata or wheel metadata, which takes the license of the project's latest release;
  - a Python release that PyPI does not have.
- A registry lookup that cannot produce a license resolves that one dependency to `UNKNOWN` and the scan continues. Apart from the cases above, a failed lookup of a pinned release is never answered with the metadata of another release.
- **Rate limits.** hex.pm allows 100 unauthenticated API requests per minute, so a project with more than 100 Hex packages pauses until the limit resets (about a minute per further 100 packages); each pause is announced on stderr. The waiting is bounded: packages still rate limited when it ends resolve to `UNKNOWN`, and a `Warning:` that is not an analysis gap gives their number. Requests to crates.io are spaced one second apart, which slows a Rust scan that has no `Cargo.lock`.

licenseal is a license resolver, not a dependency resolver: it does not resolve version conflicts between transitive requirements, and it does not model what a given environment would install.

## How licenseal decides

licenseal classifies each dependency license into a risk level and compares that risk against the [project license](#project-license).

| Project \ Dependency | Permissive | Weak Copyleft | Strong Copyleft | Network Copyleft |
| --- | --- | --- | --- | --- |
| **Permissive** | OK | Warning | Violation | Violation |
| **Weak Copyleft** | OK | OK | Violation | Violation |
| **Strong Copyleft** | OK | OK | OK | Warning |
| **Network Copyleft** | OK | OK | OK | OK |

**Pair-level overrides** strengthen the matrix where two licenses are documented as legally incompatible:

- Violation: a GPLv3-family dependency (`GPL-3.0-*`, `LGPL-3.0-*`, `AGPL-3.0-*`) in a `GPL-2.0-only` project, or a `GPL-2.0-only` dependency in a `GPL-3.0-*` / `AGPL-3.0-*` project.
- Violation: `Apache-2.0` in a `GPL-2.0-only` project.
- Violation: `EPL-1.0`, `CDDL-*`, or `MPL-1.1` in any GPL-family project (`GPL-2.0-*`, `GPL-3.0-*`, `AGPL-3.0-*`).
- Warning: `EPL-2.0` in a GPL-family project, because its GPL compatibility depends on a secondary-license designation that package metadata cannot reveal.

`-or-later` forms are exempt where the upgrade clause resolves the conflict. A deprecated GNU identifier is read by its SPDX meaning: a bare `GPL-2.0` is `GPL-2.0-only`, and `GPL-2.0+` is `GPL-2.0-or-later`.

| Risk level | Examples | Meaning |
| --- | --- | --- |
| Permissive | MIT, BSD, Apache-2.0, ISC | No significant restrictions |
| Weak Copyleft | LGPL, MPL-2.0, EPL, CDDL, GPL with Classpath exception | File-scope reciprocity; linking from other files is usually allowed |
| Strong Copyleft | GPL, OSL, EUPL, CC-BY-SA | Share-alike obligations can extend to the derivative work |
| Network Copyleft | AGPL-3.0-only | Strong copyleft with network-use source-offer obligations |
| Unknown | SSPL, BUSL, Elastic, FSL, Parity, PolyForm, CC-BY-NC, CC-BY-ND, `BSD-3-Clause-No-Military-License` and the other use-restricted BSD variants, Unicode-TOU; missing or unrecognized licenses; an unrecognized `WITH` exception on a license that is not strong or network copyleft | Cannot be auto-classified; routed to manual review |

## License expressions

How a declared license string is read before the matrix and the pair-level overrides [above](#how-licenseal-decides) apply.

- **`OR` expressions.** The dependency gets the verdict of the choice that suits the project best, each choice judged as a whole: `GPL-3.0-only OR MIT` in a `GPL-2.0-only` project is compatible through its MIT choice. The report's Risk column shows its least restrictive choice.
- **`WITH` exceptions** are matched against a fixed list.
  - `Classpath-exception-2.0` and `Classpath-exception-2.0-short` on a GPL license make that license weak copyleft.
  - An exception that only adds a permission leaves the license judged without it: `Autoconf-exception-2.0`, `Autoconf-exception-3.0`, `Bison-exception-2.2`, `Bootloader-exception`, `Font-exception-2.0`, `GCC-exception-2.0`, `GCC-exception-3.1`, `Libtool-exception`, `Linux-syscall-note`, `LLVM-exception`, `OCaml-LGPL-linking-exception`, `Swift-exception`, `Universal-FOSS-exception-1.0`, `WxWindows-exception-3.1`. In addition, `Apache-2.0 WITH LLVM-exception` is compatible in a `GPL-2.0-only` project.
  - Any other text after `WITH` is an exception nobody evaluated: the license is a violation when it is one without the exception, and unknown otherwise.
- **Operands that did not resolve.** In an `AND`, an operand that is a violation makes the dependency a violation whatever the others are (`GPL-3.0-only AND UNKNOWN` in an MIT project); otherwise an operand that did not resolve makes it unknown. In an `OR`, a choice that did not resolve is never the one taken (`MIT OR CustomLicense` is judged as `MIT`).
- **Malformed expressions** (`MIT AND GPL-3.0-only AND`, `MIT OR (GPL-3.0-only`) are reported with the license `UNKNOWN`. The dependency is a violation when a license the string names is one, and unknown otherwise.
- **License lists.** When a source gives several licenses for one package, the list is read by what that source defines:
  - **A choice**: a Composer `license` array, `/` in a Cargo `license` field, `|` in an R `License` field, npm's legacy `licenses` array.
  - **All apply**: several `<license>` entries in a Maven POM, and a deps.dev `licenses` array with several entries (other than for a RubyGems package). Two rewrites apply to a deps.dev array only: a GPL entry beside the LGPL entry of the same version (or GPL-2.0 beside LGPL-2.1) is dropped, because the LGPL refers to the GPL text, and one CDDL entry plus `GPL-2.0-with-classpath-exception` is read as that dual license (`OR`). A deps.dev array that contains its `non-standard` marker is not used; the dependency is resolved from its own registry.
  - **Not defined by the source**: a RubyGems or Hex array with more than one entry, several distinct PyPI license classifiers, and a comma- or slash-separated list inside one license string (`MIT, GPL-3.0-only`; in an R `License` field such a list is `UNKNOWN`). Such a list is judged twice, as a choice and with every entry applying. When both readings give the same verdict, that verdict is reported; when they differ, the verdict is `unknown` and the reason asks you to confirm which holds and record it in `licenseal.review.toml`. The exception is `Ruby` with `BSD-2-Clause`, which the Ruby license itself offers as a choice.
- **R `+ file LICENSE`.** The file is never fetched. After `MIT`, `BSD_2_clause`, or `BSD_3_clause` it is the copyright notice those templates require, and the result is the license alone. After any other license it holds further terms, so `GPL-3 + file LICENSE` is reported as `GPL-3.0-only AND UNKNOWN`.
- **The project's own license.** With a top-level `OR`, a dependency has to be compatible with each arm, and an arm licenseal does not recognize is judged as `Proprietary`.
- **Dev dependencies.** A violation on a dev dependency is reported as a warning; one whose license did not fully resolve is unknown instead.

## Manual review file

When a dependency is flagged but you have better license information than the resolver (you have read the bundled `LICENSE` file, say), record it as an entry in `licenseal.review.toml` in the scanned directory:

```toml
[[review]]
ecosystem = "python"
package = "mystery-lib"
version = "1.0.0"
license = "MIT"
note = "confirmed from packaged LICENSE file"
```

Workflow:

1. `licenseal check -f json -o report.json` saves a report with the flagged dependencies.
2. `licenseal init-review-file --from-report report.json` scaffolds an empty entry for each, without scanning.
3. Fill in `license` (and optionally `note`) in each entry.
4. Run `licenseal check` again: the entries apply.

`licenseal init-review-file` without `--from-report` does steps 1 and 2 in one go: it runs the scan `check` runs by default and scaffolds an entry for each flagged dependency, direct or transitive. For a `check` run with other options (`--no-transitive`, another `--max-depth`), scaffold from that run's report with `--from-report`. A flagged registry dependency with no resolved version gets no entry, since there is no version to key one on; a stderr `Note:` names it.

An [off-registry dependency](#off-registry-dependencies) has no registry version either, so its entry is keyed on its source: it carries a `source` key holding the row's `origin` string, and `version` is optional. `init-review-file` writes it:

```toml
[[review]]
ecosystem = "ruby"
package = "edge-fork"
source = "git+https://git.example.org/team/edge-fork.git@0123abcd"
license = "MIT"
note = "LICENSE read at that commit"
```

When new flagged dependencies appear later, `licenseal init-review-file --merge` adds entries for them to the existing file and leaves the existing entries as they are.

Rules:

- An entry matches the row with its `ecosystem`, `package`, and resolved `version`. `package` is compared the way the ecosystem's registry compares names: exactly, upper and lower case included, for Go, Java, npm, and Ruby; without regard to case for .NET, PHP, Rust, Hex, and R; with PEP 503 normalization for Python. A Hex dependency that `mix.exs` declares under another name than its hex.pm package is matched on the hex.pm name.
- An entry with a `source` key matches on ecosystem, package, and `source`, compared with the row's `origin` exactly, and on `version` when the entry has one. An entry keyed on a commit applies to that commit only. One keyed on a **branch or a tag** (all a manifest without a lockfile can say), on a bare repository URL, on a URL without a hash, or on a path keeps applying when the code there changes; pin a commit, or commit a lockfile, to get an immutable key.
- `license` is a license expression. Each license in it must be an SPDX identifier (current or deprecated), a source-available license licenseal recognises (`BUSL-`, `FSL-`, `PolyForm-`, …), `Proprietary`, or a `LicenseRef-` reference; an exception after `WITH` is not checked against a list. A comma- or slash-separated list is not accepted: join the licenses with `OR` or `AND`.
- These fail the command: an entry that matches a compatible dependency (only a flagged one can be overridden); a filled-in entry that matches no reported row (an old version after an upgrade, or a dev dependency in a scan without `--dev`); a missing `ecosystem`, `package`, or `version` (`version` is optional beside `source`), or a value that is not a string; an unknown ecosystem; a duplicate; a `license` that breaks the rule above.
- An entry whose `license` is empty is not applied, and `check` names it in a `Warning:` that is not an analysis gap.
- `licenseal.review.toml` and the report passed to `--from-report` must be UTF-8; write the report with `-o report.json` rather than a shell redirect.
- A reviewed dependency never fails the check, whatever verdict its reviewed license gets. Unreviewed warnings, violations, and unknowns still fail. An analysis gap cannot be reviewed: fix the file, commit a lockfile, or pass `--no-require-lockfile`.
- Reports show both the detected and the reviewed license; JSON has `detected_license`, `reviewed_license`, `effective_license`, `reviewed`, and `review_note`.

Reviewed dependencies have their own report section:

> **Summary:** 0 violations, 0 warnings, 0 unknown, 4 ok (of which 1 reviewed)

| Package | Detected | Reviewed | Note |
| --- | --- | --- | --- |
| mystery-lib (1.0.0) | UNKNOWN (raw: Custom internal license) | MIT | confirmed from packaged LICENSE file |

An entry can mark a copyleft dependency as MIT and pass strict mode, so treat `licenseal.review.toml` as security-relevant: require code review on every change, give the reason for each entry in `note`, and re-validate periodically (see [SECURITY.md](SECURITY.md)).

## Claude Code skill

licenseal ships a [Claude Code](https://claude.com/claude-code) skill that drives the review workflow interactively: it runs `licenseal check`, walks you through each flagged dependency, fills in `licenseal.review.toml` from your decisions, and re-runs the check to show what is still flagged.

```bash
licenseal install-skill                  # <project>/.claude/skills/licenseal-review/SKILL.md
licenseal install-skill --path ../other  # install into another project directory
licenseal install-skill --force          # overwrite a hand-edited skill
```

The skill is written only inside the project (`.claude/skills/`), never globally, so it can be committed with the code it audits. Claude Code discovers it automatically; invoke `/licenseal-review` to run it.

**Keeping the skill current.** The installed `SKILL.md` is a snapshot, so upgrading the package does not update it. When the bundled skill changes in a release, the next `licenseal check` prints a one-line reminder, and re-running `install-skill` rewrites an unedited install in place (no `--force` needed).
