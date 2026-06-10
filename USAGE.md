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

- An **analysis gap** is a dependency manifest or lockfile that couldn't be read (permission / I/O error) or parsed (malformed XML / JSON / TOML / YAML / INI), or a directory that couldn't be traversed — each is surfaced as a `Warning:` on stderr so a dropped dependency is never silent. Gaps fail strict mode like an unknown; a non-UTF-8 file recovered via latin-1 fallback warns but does not fail.
- `--no-strict` demotes warnings / unknowns / gaps to advisory. **Violations always fail** — they're definite legal incompatibilities and the flag won't silence them.
- If **every** registry lookup fails and not one dependency resolves (no network, blocked egress, registry-wide outage), `check` aborts with an error and a non-zero exit rather than reporting an all-UNKNOWN scan; this is not demotable by `--no-strict`.

The `-o / --output FILE` flag writes the rendered report to a file (UTF-8, no ANSI escapes for table format). The file is written **before** the strict-mode gate runs, so CI can publish the artifact even when `check` exits non-zero. JSON is the stable machine-readable format — see [JSON_OUTPUT.md](JSON_OUTPUT.md) for the schema.

## Transitive scanning

Transitive is the default. `--no-transitive` audits only the manifests you declared directly. The walk uses a **lockfile-first** strategy:

1. If a lockfile is present, it is the source of truth: `uv.lock`, `poetry.lock`, or `Pipfile.lock` (Python); `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, or `yarn.lock` (npm); `Cargo.lock` (Rust); `go.sum` (Go); `gradle.lockfile` (Gradle); `composer.lock` (PHP); `Gemfile.lock` (Ruby); `mix.lock` / `rebar.lock` (Hex); `renv.lock` / `packrat.lock` (R). Lockfiles encode the actually-resolved graph, so this path is precise and offline-fast. `composer.lock` is uniquely informative: each entry embeds a structured SPDX `license` field, so the Packagist resolver answers most queries without any HTTP fetch.
2. When no lockfile exists for an ecosystem, licenseal falls back to recursive registry walks: each dep's per-version metadata is fetched and walked breadth-first in parallel (per `--max-workers`). Multiple resolved versions of the same package coexist in the output — a graph can legitimately contain `lodash@4.x` and `lodash@3.x` via different paths, each license-resolved independently because a package can ship under different licenses across majors.

The report nests transitives directly beneath the depth-0 dependency that pulls them in, so a flagged transitive traces back to the direct dep you'd remove to drop it. Direct deps are listed alphabetically; under each, transitives appear in their own alphabetical run with a tree-style indent. Transitives shared across multiple direct deps are listed once under the alphabetically-first ancestor with an `(also: X, Y)` annotation; the full list is always in JSON under `direct_ancestors` (plus `depth` and `is_transitive`). Group is attributed by reachability: a transitive reached from a `prod` direct dep is `prod`, otherwise `dev` if reached from a dev dep, otherwise dropped — so `--no-dev` reports cleanly omit dev-only chains.

### Per-ecosystem resolution detail

- **Python**: PEP 508 environment markers are intentionally ignored (treated as always-true). License obligations don't depend on `python_version` or `sys_platform`, so missing a marker-gated copyleft would be a compliance gap.
- **npm**: `peerDependencies` and `optionalDependencies` are walked alongside `dependencies` (they end up in your installed `node_modules`); `devDependencies` are gated by `--dev`. In monorepos and pnpm workspaces, packages defined locally by another `package.json` in the tree are filtered out (they aren't published); a stderr line reports how many were excluded.
- **Go**: `go.mod` has no general prod/dev distinction — everything in a `require` block ships. The Go 1.24+ `tool` directive is the *only* declarative dev marker (paths there are matched longest-prefix to their module and emitted as `dev`). `// indirect` is **not** a dev signal. Test-only deps can't be separated from production deps (go.mod doesn't track that). On pre-1.24 projects or projects without `tool` entries, `--dev` and `--no-dev` produce identical reports.
- **Java/JVM**: Maven (`pom.xml`) and Gradle (`gradle.lockfile`, `build.gradle`, `build.gradle.kts`). Direct deps and license fields come from POM XML at Maven Central, with two hard-coded fallback registries (`dl.google.com` for Android/Jetpack/Firebase, `repo.jenkins-ci.org` for Jenkins parents) when Central 404s; transitive expansion is offloaded to deps.dev's `:dependencies` endpoint. BOM consumers (`<scope>import</scope>`) and the `<dependencyManagement>` parent chain are walked end-to-end (up to 5 levels of parent + 5 of BOM-of-BOM nesting), including `${revision}`-style property inheritance. Maven `compile`/`runtime` and Gradle `implementation`/`api`/`runtimeOnly` map to PROD; `test`/`provided`/`system` map to DEV. Multi-module reactors filter out in-tree sibling artifacts. Gradle without a `gradle.lockfile` falls back to a text-parse heuristic that surfaces only static-string `dependencies { … }` declarations — version catalogs, variable interpolation, and dynamic blocks are not evaluated (doing so would require running the Gradle configuration phase, which executes scan-target code).
- **.NET**: NuGet (`.csproj` / `.fsproj` / `.vbproj`, `packages.config`, `Directory.Packages.props` for Central Package Management, `Directory.Build.props` / `.targets`, `packages.lock.json`, `project.assets.json`) and Paket (`paket.dependencies`, `paket.lock`). Per-dep resolution: (1) raw `.nuspec` XML from NuGet flatcontainer — modern `<license type="expression">` parsed directly, legacy `<licenseUrl>` mapped via known-URL-patterns; (2) deps.dev `versionbatch` for NUGET; (3) deps.dev v3 single-version GET. Transitive expansion is lockfile-first (`packages.lock.json` / `project.assets.json` if `dotnet restore` ran; `paket.lock` for Paket), with deps.dev's `:dependencies` endpoint as the fallback. Per-TFM graphs are **unioned across all target frameworks** — a Windows-only GPL'd dep still surfaces. CPM `<PackageVersion>` is stitched into versionless `<PackageReference>` entries. `PrivateAssets="all"` and `Condition`-based Debug / IsTestProject patterns map to DEV. `nuget.config` `<packageSources>` are NOT honored (every resolution goes through `api.nuget.org`).
- **PHP**: Composer (`composer.json`, `composer.lock`). **Lockfile-first**: composer.lock entries embed a structured SPDX `license` field, so the resolver answers from the lockfile without HTTP when the pin matches. Falls back to Packagist's `/p2/{vendor}/{package}.json` per-version metadata for manifest-only mode. Group attribution trusts composer.lock's explicit per-entry `dev: true`. Platform pseudo-packages (`php`, `ext-*`, `lib-*`, `hhvm`) and `dist.type == "path"` workspace siblings are filtered out. No deps.dev pre-pass and no batch endpoint, so the lockfile-first design minimises load on this donation-funded registry.
- **Ruby**: RubyGems (`Gemfile`, `*.gemspec`, `Gemfile.lock`). deps.dev `RUBYGEMS` batch runs first to amortise load; rubygems.org v2 per-version / v1 latest fills the gap. `licenses` is a structured SPDX array. Off-registry gems (`GIT` / `PATH` in `Gemfile.lock`) short-circuit to UNKNOWN. Dev attribution from `:development` / `:test` groups and `add_development_dependency`.
- **Hex (Elixir/Erlang)**: Mix (`mix.exs`, `mix.lock`), rebar3 (`rebar.config`, `rebar.lock`), erlang.mk (`Makefile`). hex.pm-only (deps.dev doesn't index Hex); license from the structured `meta.licenses` array. Dev attribution from `only: :dev|:test`, rebar `test`/`dev` profiles, and erlang.mk `TEST_DEPS`. Off-registry deps (`:git` / `:path` / `{git,…}`) short-circuit to UNKNOWN.
- **R / CRAN**: `DESCRIPTION` (`Imports` / `Depends` / `LinkingTo` prod; `Suggests` / `Enhances` dev) and `renv.lock` / `packrat.lock`. The official CRAN `PACKAGES` index is fetched once per scan; license and transitive closure resolve locally from it. R's license grammar (`GPL (>= 2)`, `MIT + file LICENSE`) is translated to SPDX (a bare `file LICENSE` with no preceding token → UNKNOWN). GitHub/Bioconductor/Local sources short-circuit to UNKNOWN.
- **Cycles**: detected via `(ecosystem, name, version)` visited-set; cycles terminate cleanly.
- **Depth cap**: `--max-depth 50` by default. Reaching the cap emits a stderr warning and stops expansion past that level.

## Resolution semantics

- Exact pins (`==2.28.1`, `18.2.0`) resolve against that exact registry release.
- Empty version constraints resolve against the registry's latest published release.
- Supported non-exact constraints (`>=`, `<=`, `!=`, `~=`, `^`, `~`, ranges, `||`, wildcards) resolve to the highest published version within the declared range.
- Unsupported or unsafe-to-interpret specs resolve to `UNKNOWN` instead of guessing.

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

When new flagged dependencies appear later, run `licenseal init-review-file --merge` to **add new stanzas** to the existing file. Existing entries are preserved verbatim.

Rules at a glance:

- The match key is the resolved `ecosystem:name@version` (Python names use PEP 503 normalization).
- Reviews can only override flagged dependencies, never compatible ones.
- Unmatched, incomplete, or invalid entries fail the command — they are never silently ignored.
- Reports keep both the detected and reviewed licenses visible; JSON exposes `detected_license`, `reviewed_license`, `effective_license`, `reviewed`, and `review_note`.
- **Strict-mode exit code** skips reviewed entries: a reviewed dep stays in its `warning` / `incompatible` / `unknown` bucket (the counter is by classification), but `licenseal check --strict` passes because the review IS the accept-and-document mechanism. Unreviewed warnings / violations / unknowns still fail. **Analysis gaps** are not part of the review mechanism — close them by fixing the file's encoding or syntax.

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
