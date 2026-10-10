# Changelog

All notable changes to this project will be documented in this file. Each version listed corresponds to a release published on [PyPI](https://pypi.org/project/licenseal/).

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned for release as 1.0.0 and updated as work lands. Everything below is relative to 0.4.2.

Most of these changes close cases where a scan passed although it had missed dependencies, misread a license, or skipped a file without saying so. A check that passes on 0.4.2 can therefore fail on this version with no change to the project. A `licenseal.review.toml` entry can also stop matching, which is an error, when its dependency is now reported at another version or is no longer reported. Every change of that kind is listed under **Breaking changes**, together with changes to report values and install requirements.

### Breaking changes

#### Install requirements

- `httpx` 0.28 or newer is required (was 0.27). The guarantee that credentials in `~/.netrc` are never read holds from that version on.

#### Dependencies that were missed are now reported

New rows can carry new findings.

- **Lockfiles without a matching manifest.** A lockfile is read wherever it is found, including when no manifest yields a direct dependency for its ecosystem: a directory that holds only lockfiles, or a Gradle build that declares everything through a version catalog. Such scans were empty and passed. When none of a lockfile's packages is a discovered direct dependency, all of them are reported as `prod`. A sample or test-data lockfile outside the auto-skipped directories now adds its packages to the report; exclude its directory with `--exclude-dirs`.
- **Python.** `setup.cfg` is read at any depth, not only in the scanned directory. `-r` / `--requirement` includes in requirements files are followed when they stay inside the scanned directory. A requirement followed by a comment that contains a URL is no longer dropped.
- **npm.** In a Yarn Classic `yarn.lock`, a package reached only through `optionalDependencies` is kept, with everything below it. In `pnpm-lock.yaml`, a package installed under an npm alias is reported under its real name, where it was dropped.
- **Java.** Dependencies declared inside Maven `<profiles>` are included from every profile; activation conditions are not evaluated. A Gradle coordinate declared without a version (`'group:artifact'`) is reported, where such a build file produced no dependencies at all; it resolves to UNKNOWN unless a `gradle.lockfile` pins it. Gradle's `compileOnlyApi`, `release*`, and `shadow` configurations are read as production, and the `debug*`, `developmentOnly`, and `testFixtures*` configurations as dev.
- **.NET.** `<PackageReference>` items in `Directory.Build.props` / `.targets`, in the files those import, and inside `<Choose>` branches are read. A `paket.lock` package line that ends in options (`- restriction: …`) is read at its pinned version. A reference whose `Condition` names Debug among other configurations (`Debug Or Release`) is production; only a condition that is, as a whole, a Debug / Test comparison is dev.
- **Go.** `replace ( … )` blocks are applied, and a `replace` with a version on its left side applies to that version only. A `go.mod` requirement that a non-empty `go.sum` has no row for is reported.
- **Rust.** The crates.io crates that `Cargo.lock` reaches only through a `git` or `path` dependency are reported.
- **PHP.** A package whose vendor name starts with `php-`, `ext-`, or `lib-` is no longer filtered out as a platform requirement. Without a `composer.lock`, a version other than the newest now resolves its license and its dependencies: Packagist's minified metadata was read without being expanded, so those versions came back with no license and no children.
- **Ruby.** A gem is dev only when every group it belongs to is `:development` or `:test`. Gems in any other group (`:production`, `:staging`, a custom group such as `:assets`) or in a mixed list were dropped as dev-only.
- **Hex.** `rebar.config` dependencies under a profile other than `test` and `dev` are production dependencies. Only top-level `deps` and `profiles` terms are read, not a `deps` list inside an `overrides` entry.

#### Dependencies that are no longer reported, or are reported differently

- **Rust.** Without a `Cargo.lock`, the registry walk no longer follows optional (feature-gated) dependencies, which it used to expand for every crate it visited. A crate enabled only through a feature is not reported in that mode. On a large lock-less workspace the scan went from 1,499 rows and 49 minutes to 92 rows and under 5 minutes.
- **Ruby.** A development or test group written as a string (`group "test"`) or as a word list (`groups: %i[development test]`) is recognised, so its gems are dev and leave the default scan.
- **.NET.** With `packages.lock.json` or `project.assets.json`, group and `direct_ancestors` follow the lockfile's dependency edges: a package reached only through a `PrivateAssets="all"` reference is dev, and a `PrivateAssets="all"` reference that a production package depends on is production. In `paket.lock`, the dependency-constraint lines under a package are no longer reported as packages.
- **Python.** A local wheel, archive, or directory path in a requirements file is skipped. It used to become a dependency named after its first path segment and was looked up on PyPI.
- **Go.** With a `go.sum`, a row at a version other than the one `go.mod` requires is a transitive, not a direct dependency. `replace` directives in a dependency's own `go.mod` are no longer applied; Go honours them only in the main module.
- **Production wins.** A dependency that is declared as dev and is also pulled in by a production dependency is `prod` everywhere: in the registry walk, when several lockfiles are merged, for Go `tool` modules, in the Maven and NuGet walks, and in `paket.lock`. `--dev` adds rows and never turns a `prod` row into `dev`. Without a lockfile, group and `direct_ancestors` are attributed per resolved version, so a version that only a dev dependency pulls in is `dev`.

#### Stricter license reading

- **PyPI wheel metadata.** A folded `License-Expression` header is read whole; `MIT` continued by `AND GPL-3.0-only` on the next line used to resolve to MIT. A license text pasted into the legacy `License` field is UNKNOWN, where its first line was taken as the license. For a pinned release whose JSON carries no license, that release's own wheel metadata is read before the license of the project's latest release is borrowed.
- **License URLs.** A license URL is matched on its parsed host and path. A lookalike domain, a canonical path on another site, and prose that mentions a license host no longer resolve to that license.
- **Use-restricted licenses.** `BSD-3-Clause-No-Military-License`, `BSD-3-Clause-No-Nuclear-License`, `BSD-3-Clause-No-Nuclear-License-2014`, `BSD-Protection`, and `Unicode-TOU` are UNKNOWN, for a dependency and as the project's own license. They were classified as permissive.
- **Compound expressions.** License entries joined with `AND` keep their grouping: `Apache-2.0 OR GPL-2.0-only` joined with `AGPL-3.0-only` was read as `Apache-2.0 OR (GPL-2.0-only AND AGPL-3.0-only)` and came back compatible. Lowercase `and` / `or` are read with SPDX precedence. A custom `LicenseRef-*` is mapped per operand, so `LicenseRef-custom AND GPL-3.0-only` is a violation under a permissive project, where the reference used to swallow the rest of the expression. Each `OR` arm is judged as a whole: under `GPL-2.0-only`, `Apache-2.0 OR AGPL-1.0-only` is a warning, where one arm supplied the risk class and the other the clean conflict check. Redundant parentheses around the project's license no longer change the result.
- **Deprecated GNU license IDs.** `GPL-2.0`, `GPL-3.0+`, `LGPL-3.0`, and the other deprecated GNU spellings are read as their current IDs wherever they appear: inside an expression, from a license URL, from a NuGet `<licenseUrl>`, and in the project's license. The version-conflict rules for GPL-family projects now apply to them. Reported license strings change accordingly (`GPL-2.0` → `GPL-2.0-only`, `GPL-3.0+` → `GPL-3.0-or-later`) in `license`, `detected_license`, `effective_license`, and `project_license`.
- **Unreadable license strings.** A license string with a dangling operator (`MIT OR GPL-3.0-only AND`) is UNKNOWN; its well-formed part used to be accepted. A license string longer than 1,000 characters is UNKNOWN. A review entry with either is rejected.
- **Dev dependencies.** For a dev dependency, a pair-level conflict under a project license the compatibility matrix has no row for is UNKNOWN instead of a warning.

#### Files that cannot be analyzed fail strict mode

Each of these is now an analysis gap on the file, reported on stderr and in the report:

- A `setup.py` that is not valid Python 3, which was treated as declaring nothing. A malformed `setup.cfg` in a subdirectory is a gap as well, now that those files are read.
- A manifest or lockfile value of a type its format does not allow (`"dependencies": []` in `package.json`). It used to be skipped silently or to end the scan with a traceback. The files covered are listed in [USAGE.md](USAGE.md).
- A lockfile the parser cannot use: a `pnpm-lock.yaml` with `lockfileVersion` below 6, a lockfile none of whose entries can be read, and a line-oriented lockfile with merge-conflict markers. The direct dependencies are then resolved through the registry, as before, but no longer silently.
- A requirements `-r` include that is a URL, is not a relative path, is not a file, or leaves the scanned directory.
- An MSBuild `<Import>` in a `Directory.Build` file, or a `go.work` `use` directory, that is not a relative path. Such a path is no longer opened at all; on Windows a UNC value could reach a network share.

#### Report output

- **Markdown and table.** Every dependency is one row, so the table has as many rows as JSON's `summary.total`; transitives used to repeat under each direct row that shared a name. When a scan has analysis gaps, the summary line carries the gap count and an **Analysis gaps** section lists each file with its reason. Strings from registries and scanned files are escaped: control characters appear as `\xNN`, and Markdown syntax in a package name, license, or note is backslash-escaped. A checked-in `LICENSES.md` changes where any of this applies.
- **Table.** Off a terminal and in an `-o` file, the table is written at its full width, one line per dependency, with no column dropped and no cell cut short; lines can be longer than 80 columns. In a CI log the Status column used to be cropped.
- **JSON.** `package_url` percent-encodes the name and version. The URL of a well-formed name is unchanged.

### Added

- hex.pm's limit of 100 unauthenticated requests per minute is waited out: a project with more than 100 Hex packages pauses until the registry's reported reset time and then continues, where every package past the limit used to resolve to UNKNOWN. The waiting is bounded.
- TOML manifests and lockfiles written as UTF-16, UTF-32, or UTF-8 with a byte-order mark are read.
- A lockfile in a format version newer than licenseal was written for is read on a best-effort basis and reported with a warning that does not fail strict mode. Yarn Berry lockfiles up to metadata version 10 are read without one.

### Fixed

- Inputs that ended the scan with a traceback and no report now produce an analysis gap or an UNKNOWN row, and the scan continues: a manifest whose bytes are not valid for the encoding its byte-order mark names; a `pom.xml` whose prolog names a multi-byte or unknown encoding; a JSON, TOML, or YAML document nested too deeply to parse; a registry response that is JSON but not an object, or holds a field of an unexpected type; a dependency name or version that cannot be put in a request URL (a control character, a lone surrogate); a `Retry-After` header that is not a decimal number; a requirement whose environment marker crashes the PEP 508 parser.
- A `licenseal.review.toml`, a `--from-report` file, or an installed skill file that is not UTF-8 or cannot be parsed ends the command with an error that names the file.
- `init-review-file` writes every scaffold field so that it parses back unchanged. A multi-line license string from a registry used to be written partly as live TOML, which could leave a scaffold that did not parse, or plant a pre-filled review entry for another dependency.
- The table report no longer fails when a dependency name contains `[`, and terminal escape sequences in registry strings no longer reach the terminal.
- With stdout redirected under a legacy code page such as cp1252, the table and Markdown formats print ASCII replacements for the glyphs the encoding lacks instead of failing with no output.
- `check` printed "No dependencies to resolve." before the lockfiles were read. It now says so only when the scan found nothing.
- `CITATION.cff` carries the 0.4.2 release date.

## [0.4.2] - 2026-09-26

Documentation and package metadata only; CLI behavior is unchanged.

### Changed

- Refreshed the README with a workflow header, an illustrative CLI report, and a transitive-dependency diagram. Repository documentation and image links now use relative paths for local and branch previews.
- The PyPI description now comes from a concise, standalone `PYPI.md` with absolute documentation links. Builds use it directly without rewriting README URLs.

## [0.4.1] - 2026-09-25

### Fixed

- `check --output` no longer fails without saying why. The report goes to the file, so CI logs and pre-commit hooks used to show only the exit code; a failing check now also prints to stderr the summary line, each unreviewed finding that failed the check (violations, plus warnings and unknowns under `--strict`), the number of manifests that couldn't be analyzed, and the report's path. Exit codes, the written report, and checks that pass or run without `--output` (which print the full report) are unchanged.

## [0.4.0] - 2026-09-25

### Changed

- The Markdown report no longer includes the scan's run time (`**Completed in:**`), so a checked-in `LICENSES.md` only changes when the scan results do. The table output still shows the run time, and the JSON report keeps `elapsed_seconds`.

### Fixed

- `uv.lock` scans now include packages installed through extras (`django[argon2]` → `argon2-cffi` and everything below it). uv records those edges in `[package.optional-dependencies]`, which the parser didn't read, so every package reachable only through a requested extra was dropped as an orphan — silently, with no analysis gap. Extras requested by the project (in its dependencies, its own extras, or its dependency groups) or by other packages, including extras nested inside extras, are followed; extras nobody requests stay out. This also works for non-package projects (e.g. `tool.uv.package = false`, or a root without a build system), whose lockfile entry is `source = { virtual = "<path>" }`: the parser only recognized `virtual = true` as the project, so the extras requested in such a project's own extras and dependency groups would have been missed.
- Files written by `check --output`, `init-review-file`, and `install-skill` now use LF line endings on every platform. On Windows they were written with CRLF, so a checked-in report, review file, or installed skill changed line endings depending on the platform that generated it.

## [0.3.0] - 2026-06-10

### Added

- End-of-scan phase timing summary on stderr (`Phase timings: discovery …s, transitive walk …s, batch pre-pass …s, license resolution …s`) — the companion to the per-host traffic summary: the host counts say where the requests went, the phase line says where the wall-clock went. Together they make a slow scan diagnosable at a glance (a long `transitive walk` means a no-lockfile registry walk; a long `license resolution` alongside a large `crates.io` request share means the policy-mandated 1 req/s fallback tail).

### Changed

- The deps.dev batch pre-pass now fans every ecosystem's `versionbatch` chunks through one shared threadpool instead of running up to seven sequential per-ecosystem rounds. Polyglot scans overlap their batch POSTs while the combined in-flight POST count keeps the same ceiling a single-ecosystem scan has, so the endpoint sees no more concurrent load than before. On polyglot stress repos the batch phase median dropped ~40% (npm + Python: 2.2s → 1.3s; Rust + npm + Python: 1.5s → 0.9s). Scan output is unchanged — verified per-dependency on one repo per supported ecosystem (all ten), each in both `--no-dev` and `--dev` modes.

## [0.2.1] - 2026-06-10

### Added

- End-of-scan registry traffic summary on stderr (`Per-package registry requests: N (host: n, …)`), so a slow scan explains itself — a large `crates.io` share means the policy-mandated 1 req/s fallback tail dominated; a large PyPI/npm share means a no-lockfile transitive walk.

### Fixed

- Cargo `[workspace.dependencies]` is now treated as the version catalog it is: an entry becomes a dependency only when a workspace member references it with `dep = { workspace = true }` (group attribution from the referencing table, version stitched from the catalog — the same model as .NET Central Package Management). Previously every catalog entry was emitted as a direct prod dependency, so entries no member referenced — absent from `Cargo.lock` by definition — sent the transitive resolver on a crates.io registry walk of dependency trees the project never builds. On a large real-world Rust workspace this fabricated 789 phantom packages (36% of the Rust rows), three spurious GPL violations, and a 47-minute scan that now completes in ~20 seconds. Member-side `workspace = true` references also now carry their declaring table's dev/prod group instead of being dropped.

## [0.2.0] - 2026-06-10

### Added

- Pair-level compatibility overrides for license pairs the coarse risk matrix cannot express. GPL-family version conflicts (a GPLv3-family dependency — `GPL-3.0-*`, `LGPL-3.0-*`, `AGPL-3.0-*` — in a `GPL-2.0-only` project, or a `GPL-2.0-only` dependency in a `GPL-3.0-*` / `AGPL-3.0-*` project), `Apache-2.0` in a `GPL-2.0-only` project, and FSF-documented GPL-incompatible weak copyleft (`EPL-1.0`, `CDDL-*`, `MPL-1.1`) in any GPL-family project now report violations instead of false-clean `compatible` verdicts. `EPL-2.0` in a GPL-family project reports a warning, because its GPL compatibility depends on a secondary-license designation that package metadata cannot reveal. `-or-later` forms are exempt where the upgrade clause resolves the conflict, and an `OR` expression escapes when a conflict-free arm is electable. The overrides only ever strengthen the matrix verdict, and they apply to every arm of a multi-licensed project.

### Changed

- `GPL-2.0-with-classpath-exception` and `GPL-* WITH Classpath-exception-*` now classify as weak copyleft instead of strong copyleft — the Classpath exception permits linking independent modules regardless of their license. OpenJDK-derived and `javax.*` / `jakarta.*` artifacts in permissive projects now report warnings instead of false violations (which failed CI even under `--no-strict`).
- A dual-licensed project (top-level `OR`, e.g. `AGPL-3.0-only OR Proprietary`) is now checked against the strictest of its arms: dependencies must be compatible with every license the project distributes under, so the commercial arm of an open-core project flags copyleft dependencies instead of silently passing them.

### Fixed

- The aopalliance license URL now resolves to the permissive `LicenseRef-Public-Domain` sentinel instead of a bare `Public-Domain` string that no risk rule recognized, which routed a known public-domain artifact to manual review. The hyphenated `public-domain` publisher spelling normalizes the same way.
