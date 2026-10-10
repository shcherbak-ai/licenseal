# licenseal — Usage & reference

Full CLI reference, resolution behavior, and per-ecosystem detail. For the overview, install, and the "why," see the [README](README.md). For the security/egress model see [SECURITY.md](SECURITY.md); for the JSON schema see [JSON_OUTPUT.md](JSON_OUTPUT.md).

## Commands

```bash
licenseal check                 # scan the current project and gate on the result
licenseal init-review-file      # scaffold a licenseal.review.toml for flagged deps
licenseal install-skill         # install the Claude Code review skill into the project
```

### `licenseal check` options

| Flag | Default | Notes |
|---|---|---|
| `--path PATH`, `-p PATH` | `.` | Directory to scan |
| `--format FMT`, `-f FMT` | `table` | `table`, `json`, or `markdown` |
| `--output FILE`, `-o FILE` | — | Write report to FILE instead of stdout |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--strict / --no-strict` | `--strict` | Fail closed on warnings + unknowns + analysis gaps (violations always fail) |
| `--transitive / --no-transitive` | `--transitive` | Full-tree scan vs direct deps only |
| `--max-depth N` | `50` | Cap transitive recursion (only meaningful with `--transitive`) |
| `--max-workers N` | `16` | Concurrent registry requests |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery. Comma-separated and/or repeated flag (relative to `--path` or absolute). Subdirectories that contain their own `.git` are skipped automatically. |
| `--version` | — | Print version and exit |

### `licenseal init-review-file` options

| Flag | Default | Notes |
|---|---|---|
| `--path PATH`, `-p PATH` | `.` | Project directory |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--from-report PATH` | — | Read flagged deps from a saved JSON report (offline, no registry round-trip) |
| `--merge` | — | Add new flagged entries to an existing review file (preserves existing entries) |
| `--max-workers N` | `16` | Concurrent registry requests |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery (same semantics as `check`) |

## Common usage

```bash
licenseal check                              # full-tree scan (default; lockfile-first, registry fallback)
licenseal check --no-transitive              # direct deps only (use when publishing a library)
licenseal check --dev                        # also include dev dependencies
licenseal check --no-strict                  # advisory mode — don't fail on warnings/unknowns/gaps (violations still fail)
licenseal check -f json -o report.json       # machine-readable output for CI tooling
licenseal check -f markdown -o LICENSES.md   # PR-comment-friendly Markdown audit
licenseal check --exclude-dirs third_party,scratch  # skip subtrees not already in the default skip set
```

## Output & the CI gate

`licenseal check` exits non-zero when there are violations, warnings, unresolved licenses, or analysis gaps — that's the CI gate.

- An **analysis gap** is a dependency manifest or lockfile that couldn't be read (permission / I/O error), decoded (a UTF-16 or UTF-32 byte-order mark on bytes that are not valid in that encoding, or a `pom.xml` whose prolog names a multi-byte or unknown encoding), or parsed (malformed XML / JSON / TOML / YAML / INI, a JSON / TOML / YAML document nested too deeply to parse, or a `setup.py` that is not valid Python 3), a directory that couldn't be traversed, or a manifest that points at another file through a path that is not followed (an MSBuild `<Import>` or `go.work` `use` value that is not a relative path) — each is surfaced as a `Warning:` on stderr so a dropped dependency is never silent. Gaps fail strict mode like an unknown; a non-UTF-8 file recovered via latin-1 fallback warns but does not fail, with or without a UTF-8 byte-order mark. The report itself records them too, on stdout and in an `-o` file: the table and Markdown formats add the gap count to the summary line and an **Analysis gaps** section listing each file with its reason (both appear only when there is a gap), and JSON carries `summary.gaps` and `diagnostics`. In the table and Markdown formats a file outside the scanned directory is named by its file name only, so a saved report does not depend on where the project was checked out.
- Text, JSON, YAML, and TOML manifests and lockfiles written as UTF-16 or UTF-32 with a byte-order mark, or as UTF-8 with one (what a Windows shell redirect produces), are read in that encoding; this includes `pyproject.toml` and the other TOML files. XML manifests are decoded by the XML parser from their own prolog or byte-order mark.
- `--no-strict` demotes warnings / unknowns / gaps to advisory. **Violations always fail** — they're definite legal incompatibilities and the flag won't silence them.
- If **every** registry lookup fails and not one dependency resolves (no network, blocked egress, registry-wide outage), `check` aborts with an error and a non-zero exit rather than reporting an all-UNKNOWN scan; this is not demotable by `--no-strict`.

The `-o / --output FILE` flag writes the rendered report to a file (UTF-8, no ANSI escapes for table format). The file is written **before** the strict-mode gate runs, so CI can publish the artifact even when `check` exits non-zero. Since the report itself doesn't reach the terminal, a failing check then also prints the summary and the findings that failed it (plus the number of analysis gaps) to stderr, so CI logs and pre-commit output show why without opening the file. JSON is the stable machine-readable format — see [JSON_OUTPUT.md](JSON_OUTPUT.md) for the schema.

The table and Markdown formats escape the strings that come from registries and scanned files (package names, versions, license strings, manifest paths, review notes) for display. Control characters are shown as `\xNN`; line breaks and tabs become a space. Markdown reports backslash-escape `\`, `` ` ``, `[`, `]`, `<`, `>`, and `|`, so a string cannot add a link, an image, HTML, or a table column. Link URLs carry the name percent-encoded. JSON reports the original strings.

The table is laid out for where it goes, and never drops a column:

- **Not a terminal** (a pipe, a CI log) **or an `-o` file**: the table is written at its full width, one line per dependency, with no cell wrapped or cut short. Lines can be longer than 80 columns.
- **A terminal narrower than the table**: package names, manifest paths, and license expressions fold over several lines; the Ecosystem, Group, Risk, and Status columns stay whole. Below 80 columns those fold too.

When stdout's encoding cannot represent the report's glyphs (a redirected stdout under a legacy Windows code page such as cp1252), the table and Markdown formats print `OK`, `!`, and `X` for ✓, ⚠, and ✗, and `+-` for the tree branch; any other character the encoding lacks is printed as `?`. An `-o` file is always UTF-8 and keeps the original glyphs, and JSON is plain ASCII.

## Transitive scanning

Transitive is the default. `--no-transitive` audits only the manifests you declared directly. The walk uses a **lockfile-first** strategy:

1. If a lockfile is present, it is the source of truth: `uv.lock`, `poetry.lock`, or `Pipfile.lock` (Python); `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, or `yarn.lock` (npm); `Cargo.lock` (Rust); `go.sum` (Go); `gradle.lockfile` (Gradle); `composer.lock` (PHP); `Gemfile.lock` (Ruby); `mix.lock` / `rebar.lock` (Hex); `renv.lock` / `packrat.lock` (R). Lockfiles encode the actually-resolved graph, so this path is precise and offline-fast. `composer.lock` is uniquely informative: each entry embeds a structured SPDX `license` field, so the Packagist resolver answers most queries without any HTTP fetch.
   A lockfile is read wherever it is found in the scanned tree, including when no manifest yields a direct dependency for its ecosystem: a lockfile with no manifest beside it, a Gradle build that declares everything through a version catalog, a `PackageReference` kept in `Directory.Build.props`. When none of a lockfile's packages is a direct dependency found in the manifests, none of them is dropped. A format that records its own dev/prod split (`Pipfile.lock` sections, `composer.lock` `packages-dev`, `gradle.lockfile` test classpaths, `paket.lock` groups) keeps it; in every other format licenseal cannot tell which packages are dev-only or which direct dependency pulls each one in, so all of them are reported as `prod`, generally as transitives with an empty `direct_ancestors`. Consequently a sample or test-data lockfile outside the [auto-skipped directories](#discovery-auto-skipped-directories) adds its packages to the report; exclude its directory with `--exclude-dirs`.
2. When no lockfile exists for an ecosystem, licenseal falls back to recursive registry walks: each dep's per-version metadata is fetched and walked breadth-first in parallel (per `--max-workers`). Multiple resolved versions of the same package coexist in the output — a graph can legitimately contain `lodash@4.x` and `lodash@3.x` via different paths, each license-resolved independently because a package can ship under different licenses across majors.

The report nests transitives directly beneath the depth-0 dependency that pulls them in, so a flagged transitive traces back to the direct dep you'd remove to drop it. Direct deps are listed alphabetically; under each, transitives appear in their own alphabetical run with a tree-style indent. Transitives shared across multiple direct deps are listed once under the alphabetically-first ancestor with an `(also: X, Y)` annotation; the full list is always in JSON under `direct_ancestors` (plus `depth` and `is_transitive`). Every dependency is exactly one row, so the table and Markdown reports have as many rows as JSON's `summary.total`: an ancestor is matched within the transitive's own ecosystem, and when several direct rows share an ecosystem and name (two locked versions of one package) their transitives are listed under the one with the first version. Group is attributed by reachability: a transitive reached from a `prod` direct dep is `prod`, otherwise `dev` if reached from a dev dep, otherwise dropped — so `--no-dev` reports cleanly omit dev-only chains. (A lockfile that contains none of the direct deps is the exception described above: nothing in it is dropped.) Production wins: a dependency declared as dev that a `prod` dependency also pulls in is reported as `prod`, and a package that one lockfile reaches only from dev dependencies and another reaches from production is `prod`. `--dev` adds rows; it never changes a `prod` row to `dev`.

### Per-ecosystem resolution detail

- **Python**: PEP 508 environment markers are intentionally ignored (treated as always-true). License obligations don't depend on `python_version` or `sys_platform`, so missing a marker-gated copyleft would be a compliance gap. Extras are followed: with a `uv.lock`, packages installed through an extra (`django[argon2]` → `argon2-cffi`) come from the lockfile's `[package.optional-dependencies]` edges for every extra requested in the lock. In `requirements*.txt`, comments are stripped by pip's rule (`#` at the start of a line or after whitespace); URL / VCS requirements, local wheel / archive / directory paths, and option lines (`-r`, `-c`, `-e`, `--index-url`, …) are skipped and not followed.
- **npm**: `peerDependencies` and `optionalDependencies` are walked alongside `dependencies` (they end up in your installed `node_modules`); `devDependencies` are gated by `--dev`. With a lockfile, optional edges are read in every supported format (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` Classic and Berry), so a package reached only through an optional edge is kept together with its own dependencies. A package installed under an npm alias is reported under its real name. In monorepos and pnpm workspaces, packages defined locally by another `package.json` in the tree are filtered out (they aren't published); a stderr line reports how many were excluded.
- **Rust**: without a `Cargo.lock`, the registry walk does not follow the optional (feature-gated) dependencies of the crates it visits, so a crate enabled only through a feature is not reported; with a `Cargo.lock`, the locked graph is used as-is.
- **Go**: `go.mod` has no general prod/dev distinction — everything in a `require` block ships. The Go 1.24+ `tool` directive is the *only* declarative dev marker (paths there are matched longest-prefix to their module and emitted as `dev`); a `tool` module that a production module also requires is `prod`. `// indirect` is **not** a dev signal. Test-only deps can't be separated from production deps (go.mod doesn't track that). On pre-1.24 projects or projects without `tool` entries, `--dev` and `--no-dev` produce identical reports. `go.work` `use` directories are followed only when they are relative paths (`..` included); a rooted, drive-qualified, UNC, or device path is never opened and is reported as an analysis gap on `go.work`.
- **Java/JVM**: Maven (`pom.xml`) and Gradle (`gradle.lockfile`, `build.gradle`, `build.gradle.kts`). Direct deps and license fields come from POM XML at Maven Central, with two hard-coded fallback registries (`dl.google.com` for Android/Jetpack/Firebase, `repo.jenkins-ci.org` for Jenkins parents) when Central 404s; transitive expansion is offloaded to deps.dev's `:dependencies` endpoint. BOM consumers (`<scope>import</scope>`) and the `<dependencyManagement>` parent chain are walked end-to-end (up to 5 levels of parent + 5 of BOM-of-BOM nesting), including `${revision}`-style property inheritance. Maven `compile`/`runtime` map to PROD and `test`/`provided`/`system` to DEV. Gradle configurations are mapped by a fixed table: `implementation`, `api`, `runtimeOnly`, `compileOnly`, `compileOnlyApi`, the annotation-processor configurations, `releaseImplementation`, `releaseApi`, `releaseRuntimeOnly`, and `shadow` map to PROD; `testImplementation` and the other test and Android-test configurations, `testFixturesApi`, `testFixturesImplementation`, `debugImplementation`, `debugApi`, `debugRuntimeOnly`, `developmentOnly`, and the code-quality tool configurations map to DEV. Declarations under any other Gradle configuration name are skipped. Dependencies declared inside Maven `<profiles>` are included from every profile with the same scope mapping; activation conditions (`activeByDefault`, JDK, OS, property) are not evaluated. Profile `<properties>` expand `${…}` tokens in profile-declared dependencies only, and only for names the POM's own `<properties>` do not define. Multi-module reactors filter out in-tree sibling artifacts. Gradle without a `gradle.lockfile` falls back to a text-parse heuristic that surfaces only static-string `dependencies { … }` declarations, in the Groovy and Kotlin DSLs. A coordinate declared without a version (`'group:artifact'`, or the map form without `version` — the usual shape when a BOM or a dependency-management plugin supplies versions) is reported with no version and resolves to UNKNOWN: only a `gradle.lockfile` records the version the build selects. Version catalogs, variable interpolation, `platform(...)` / `enforcedPlatform(...)` references, and dynamic blocks are not evaluated (doing so would require running the Gradle configuration phase, which executes scan-target code).
- **.NET**: NuGet (`.csproj` / `.fsproj` / `.vbproj`, `packages.config`, `Directory.Packages.props` for Central Package Management, `Directory.Build.props` / `.targets`, `packages.lock.json`, `project.assets.json`) and Paket (`paket.dependencies`, `paket.lock`). Per-dep resolution: (1) raw `.nuspec` XML from NuGet flatcontainer — modern `<license type="expression">` parsed directly, legacy `<licenseUrl>` mapped via known-URL-patterns; (2) deps.dev `versionbatch` for NUGET; (3) deps.dev v3 single-version GET. Transitive expansion is lockfile-first (`packages.lock.json` / `project.assets.json` if `dotnet restore` ran; `paket.lock` for Paket), with deps.dev's `:dependencies` endpoint as the fallback. Per-TFM graphs are **unioned across all target frameworks** — a Windows-only GPL'd dep still surfaces. With a NuGet lockfile, group and the direct ancestors shown for each transitive follow the lockfile's dependency edges from the references found in the project files: a package reached only from dev references is dev (left out without `--dev`), a dev reference that a production package also depends on is production, and a package that no discovered reference reaches is production. CPM `<PackageVersion>` is stitched into versionless `<PackageReference>` entries. `PrivateAssets="all"` and `Condition`-based Debug / IsTestProject patterns map to DEV. `nuget.config` `<packageSources>` are NOT honored (every resolution goes through `api.nuget.org`). `<Import Project="…">` chains in `Directory.Build.props` / `.targets` are followed only for relative paths (`..` included); a rooted, drive-qualified, UNC, or device path is never opened and is reported as an analysis gap on the importing file.
- **PHP**: Composer (`composer.json`, `composer.lock`). **Lockfile-first**: composer.lock entries embed a structured SPDX `license` field, so the resolver answers from the lockfile without HTTP when the pin matches. Falls back to Packagist's `/p2/{vendor}/{package}.json` per-version metadata for manifest-only mode. Group attribution trusts composer.lock's explicit per-entry `dev: true`. Platform pseudo-packages (names without a `/`: `php`, `ext-*`, `lib-*`, `hhvm`) and `dist.type == "path"` workspace siblings are filtered out; a `vendor/package` name is always scanned, including vendors that start with `php-`, `ext-`, or `lib-`. No deps.dev pre-pass and no batch endpoint, so the lockfile-first design minimises load on this donation-funded registry.
- **Ruby**: RubyGems (`Gemfile`, `*.gemspec`, `Gemfile.lock`). deps.dev `RUBYGEMS` batch runs first to amortise load; rubygems.org v2 per-version / v1 latest fills the gap. `licenses` is a structured SPDX array. Off-registry gems (`GIT` / `PATH` in `Gemfile.lock`) short-circuit to UNKNOWN. A `Gemfile` gem is dev only when every group it belongs to is `:development` or `:test`; a gem in any other group (`:production`, `:staging`, or a custom group such as `:assets`), in a mixed list (`group :production, :test`), or in no group is production. Group options such as `optional: true` are not group names, and nested `group` blocks and a per-line `group:` / `groups:` add up. A group name is read from a `:symbol`, a quoted string (`group "test"`, `group: "test"`), or a `%i[...]` / `%w[...]` word list in any bracket delimiter (`groups: %i[development test]`, `group *%w[development test]`); a name written any other way (a constant, a method call, a word list combined with another expression) is treated as production. A gemspec `add_development_dependency` is dev.
- **Hex (Elixir/Erlang)**: Mix (`mix.exs`, `mix.lock`), rebar3 (`rebar.config`, `rebar.lock`), erlang.mk (`Makefile`). hex.pm-only (deps.dev doesn't index Hex); license from the structured `meta.licenses` array. Dev attribution from `only: :dev|:test`, rebar `test`/`dev` profiles, and erlang.mk `TEST_DEPS`. Off-registry deps (`:git` / `:path` / `{git,…}`) short-circuit to UNKNOWN. hex.pm allows 100 unauthenticated API requests per minute and has no batch endpoint, so a project with more than 100 Hex packages pauses each time the limit is reached until hex.pm's reported reset time (up to about a minute per further 100 packages), then continues. The waiting is bounded: it stops after three pauses in a row with no successful response in between, or after ten full-length pauses in total, and packages still rate limited after that resolve to UNKNOWN.
- **R / CRAN**: `DESCRIPTION` (`Imports` / `Depends` / `LinkingTo` prod; `Suggests` / `Enhances` dev) and `renv.lock` / `packrat.lock`. The official CRAN `PACKAGES` index is fetched once per scan; license and transitive closure resolve locally from it. R's license grammar (`GPL (>= 2)`, `MIT + file LICENSE`) is translated to SPDX (a bare `file LICENSE` with no preceding token → UNKNOWN). GitHub/Bioconductor/Local sources short-circuit to UNKNOWN.
- **Cycles**: detected via `(ecosystem, name, version)` visited-set; cycles terminate cleanly.
- **Depth cap**: `--max-depth 50` by default. Reaching the cap emits a stderr warning and stops expansion past that level.

## Resolution semantics

- Exact pins (`==2.28.1`, `18.2.0`) resolve against that exact registry release.
- Empty version constraints resolve against the registry's latest published release.
- Supported non-exact constraints (`>=`, `<=`, `!=`, `~=`, `^`, `~`, ranges, `||`, wildcards) resolve to the highest published version within the declared range.
- Unsupported or unsafe-to-interpret specs resolve to `UNKNOWN` instead of guessing.
- A registry lookup that cannot produce a license resolves that one dependency to `UNKNOWN` and the scan continues. This covers an HTTP 200 whose body is not a JSON object, a license, version, or metadata field of an unexpected type (well-formed fields beside it are still read), and a dependency name or version that cannot be put in a request URL, such as one containing an ASCII control character. A lookup never strips or rewrites the name to make the request succeed; the dependency is reported under the name it was discovered with. A response that is not a JSON object and a request that cannot be built count as failed lookups under the every-lookup-fails rule in [Output & the CI gate](#output--the-ci-gate): a scan in which no lookup succeeds and nothing resolves still ends with that error.

licenseal is a license resolver, not a dependency resolver. It does not evaluate Python environment markers, `Requires-Python`, npm `engines`, or transitive-version conflict resolution beyond first-encountered-wins. That keeps resolution fast and predictable but does not model environment-specific installability.

## Supported ecosystems

| Language | Registry | Manifest files | Lockfiles |
| --- | --- | --- | --- |
| Python | PyPI | `pyproject.toml` (PEP 621, PEP 735, Poetry), `requirements*.txt`, `setup.cfg`, `setup.py`, `Pipfile` | `uv.lock`, `poetry.lock`, `Pipfile.lock` |
| JavaScript / TypeScript | npm | `package.json` (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`) | `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, `yarn.lock` |
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

Virtualenvs are detected **structurally** via the PEP 405 `pyvenv.cfg` marker rather than by name, so `.venv/`, `venv/`, `env/`, `env-3.11/`, and any other naming convention are skipped without false positives. Any subdirectory with its own `.git` (file or directory) is skipped automatically — cloned dependencies, vendored forks, and submodules are treated as separate projects. Use `--exclude-dirs` for subtrees not already covered.

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

Each scaffolded stanza is preceded by `# detected:`, `# status:`, and (when it differs from the detected license) `# raw:` comment lines. Their values are collapsed to a single line and truncated at 200 characters; the full registry string is the `license_raw` field of the JSON report.

When new flagged dependencies appear later, run `licenseal init-review-file --merge` to **add new stanzas** to the existing file. Existing entries are preserved verbatim.

Rules at a glance:

- The match key is the resolved `ecosystem:name@version` (Python names use PEP 503 normalization).
- Reviews can only override flagged dependencies, never compatible ones.
- Unmatched, incomplete, or invalid entries fail the command — they are never silently ignored.
- `licenseal.review.toml` and the report passed to `--from-report` must be UTF-8. A file in another encoding (UTF-16 from a Windows shell redirect, for example) ends the command with an error that names the file; write the report with `-o report.json` rather than `>`.
- Reports keep both the detected and reviewed licenses visible; JSON exposes `detected_license`, `reviewed_license`, `effective_license`, `reviewed`, and `review_note`.
- **Strict-mode exit code** skips reviewed entries: a reviewed dep stays in its `warning` / `incompatible` / `unknown` bucket (the counter is by classification), but `licenseal check --strict` passes because the review IS the accept-and-document mechanism. Unreviewed warnings / violations / unknowns still fail. **Analysis gaps** are not part of the review mechanism — close them by fixing the file's encoding or syntax, or the path it references.

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

**Keeping the skill current.** The installed `SKILL.md` is a snapshot, so upgrading the package doesn't update it automatically. When the bundled skill actually changes in a release, the next `licenseal check` prints a one-line reminder, and re-running `install-skill` rewrites an unedited install in place (no `--force` needed). The reminder is content-based (a release that doesn't touch the skill stays quiet), checks only the project-local `.claude/skills`, and is strictly read-only — so it never fires for users who run licenseal without the skill installed. A `SKILL.md` that is not UTF-8 text is treated as hand-edited: `check` ignores it, and `install-skill` replaces it only with `--force`.
