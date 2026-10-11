# Changelog

All notable changes to this project will be documented in this file. Each version listed corresponds to a release published on [PyPI](https://pypi.org/project/licenseal/).

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned for release as 1.0.0 and updated as work lands. Everything below is relative to 0.4.2.

Most of these changes close cases where a scan passed although it had missed dependencies, misread a license, or skipped a file without saying so. A check that passes on 0.4.2 can therefore fail on this version with no change to the project. A `licenseal.review.toml` entry can also stop matching, which is an error, when its dependency is now reported at another version or is no longer reported. Every change of that kind is listed under **Breaking changes**, together with changes to defaults, report values, the review file, and install requirements.

Three of them reach almost every project: a project without a lockfile fails strict mode unless `--no-require-lockfile` is passed, the project's own license is read only from the scanned directory, and a dependency installed from git, a URL, or a path is reported as UNKNOWN instead of being looked up by name.

### Breaking changes

#### Install requirements

- `httpx` 0.28 or newer is required (was 0.27). The guarantee that credentials in `~/.netrc` are never read holds from that version on.

#### Projects without a lockfile

- **A missing lockfile fails strict mode.** When a manifest's dependencies are resolved from the registry because no lockfile covers them, that manifest is an analysis gap: it counts in `summary.gaps`, and `check` exits 1 under `--strict`, the default. Commit a lockfile, or pass the new `--no-require-lockfile` to accept the estimate; the manifest is then listed with severity `estimate` and does not fail the check. A direct dependency that an existing lockfile does not cover counts the same way; see [Package names and versions](#package-names-and-versions) for what covering means. Not affected: `pom.xml`, `packages.config`, and an erlang.mk `Makefile`, which have no lockfile format licenseal reads; Go; and `--no-transitive` scans, which read no lockfile.
- **Estimated versions are marked.** A version licenseal chose from a registry (for a declared range, for no constraint, or for a transitive found by walking the registry) is shown as `~1.2.3` in the table and Markdown reports, with a legend line, and has `"version"` in the JSON `estimated` array.
- **A declared range resolves to a version inside it** for Rust, Ruby, Hex, PHP, and .NET, where the registry's latest release was taken whatever the range said. Rust, Ruby, Hex, and PHP take the highest matching release. NuGet takes the lowest, as NuGet itself does, and the highest for a floating version (`1.*`). A constraint that cannot be read, a range no published version satisfies, a Composer branch constraint (`dev-main`), and a Composer exact version that Packagist does not list resolve to UNKNOWN with no version; they used to take the latest release or the first entry. A bare version in a `Gemfile`, `mix.exs`, `rebar.config`, or `composer.json` is an exact pin.
- **A dependency list the registry did not return is a gap.** When a package's own dependencies cannot be read (a failed request, a malformed response, a deps.dev graph returned with an error, a `requires_dist` entry that does not parse, an unreadable `.nuspec`, NuGet's 32-level nesting limit), the manifest that leads to the package is an analysis gap. Such a package used to look like one with no dependencies. `--no-require-lockfile` does not waive this gap.
- **Gradle without a `gradle.lockfile`.** A coordinate declared with no version is reported at the artifact's latest release, marked as an estimate, and its dependencies are scanned. A dynamic version (`1.+`, `latest.release`) is UNKNOWN with no version; its literal text used to be sent to the registries.

#### Package names and versions

- **Names are compared the way each registry compares them.** In Go, Java, npm, and Ruby, two names that differ only in case are two packages: each is reported with its own license, where one used to stand for both. A `licenseal.review.toml` entry for those ecosystems must spell `package` exactly as the report does; an entry in another case stops matching, which is an error. .NET, PHP, Rust, Hex, and R names are compared without regard to case and Python names by PyPI's normalisation rule, as before.
- **Every declared version is scanned.** When manifests in one tree declare a package with different version constraints, each one is resolved, walked, and reported under its own manifest. Only the first used to be scanned, so the other version and everything below it were missing.
- **A lockfile covers a dependency only at a version its manifest admits.** A lockfile used to cover a declared dependency whenever it held a package of that name. A manifest that is ahead of its lockfile, or that pins another version than a lockfile elsewhere in the tree, is now resolved from the registry for that dependency and reported as lacking a lockfile, which is a gap under the default `--require-lockfile`. A locked prerelease is accepted for any range, since whether a range admits one depends on settings licenseal does not read.
- **A locked row is a direct dependency only at a declared version.** Another locked version of a directly declared package, such as a nested copy in an npm lockfile or a second major in `Cargo.lock`, is a transitive: in JSON its `depth` is 1 and its `source` is empty. An unresolved requirement is no longer hidden behind a resolved row of the same name unless that row's version satisfies it.
- **.NET reports every distinct version.** A package pinned at different versions in two `paket.lock` groups is one row per version, where the first entry won. The `.nuspec` walk reports another version of a directly referenced package as its own row. The production rows of a `--dev` scan now equal the rows of a `--no-dev` scan.
- **Hex.** A review of a dependency that `mix.exs` renames is keyed on its hex.pm package name, not on the local name; an entry written under the local name must be scaffolded again.

#### The project's own license

- **Only manifests in the scanned directory decide it.** The project license, which every dependency is judged against, is read from the manifests directly in the `--path` directory and never from a nested package. With none declaring one the project is checked as `Proprietary`, as before. A monorepo whose license came from a sub-package gets different verdicts; scan the sub-package with `--path` to use its license.
- **An unrecognised declared value is judged as `Proprietary`**, with a warning that names the file and the value. It used to make every dependency UNKNOWN.
- **An unrecognised arm of a dual license is a `Proprietary` arm.** Project `AGPL-3.0-only OR Commercial` used to drop the unrecognised arm, so copyleft dependencies passed. They are violations now, as under `AGPL-3.0-only OR Proprietary`.
- **A `Directory.Build.props` in the scanned directory can declare it.** Its `PackageLicenseExpression`, or `PackageLicenseUrl`, is read after the project files in that directory. A .NET solution that declares its license only there was checked as `Proprietary`.
- `check` and `init-review-file` print the file the project license came from, and warn when manifests in the scanned directory declare different licenses. JSON has a new top-level `project_license_source`, and the table and Markdown reports show the file beside the project license, so the header of a checked-in `LICENSES.md` changes once.

#### Dependencies that do not come from a registry

- **One rule for every ecosystem.** A dependency installed from a git repository, a direct URL, or a local path is reported as one UNKNOWN row that carries its `origin`, and no registry is asked about it. Before, such a dependency was dropped, reported UNKNOWN with no way to review it, or looked up on the public registry under the same name, depending on the ecosystem and the file; the lookup could report a private fork with the public package's license. The rule covers Python direct references (`name @ url`), Poetry `git` / `url` / `path`, `[tool.uv.sources]`, `uv.lock`, `poetry.lock`, `Pipfile`, `Pipfile.lock`, and URL, VCS, and path lines in requirements files; npm git, tarball-URL, `file:`, `link:`, and `portal:` specs, with or without a lockfile; `Gemfile` `git` / `github` / `path` blocks and options; Cargo `git` and `path` dependencies and `[patch]` / `[replace]` entries; Composer packages that a `composer.lock` records from a version-control, `package`, `path`, or `artifact` repository; Hex and R dependencies declared from a repository or a path; Maven `system`-scoped dependencies; a .NET `<ProjectReference>`; and a Go module that `replace` points at a local path.
- **A local path is the project's own code only when the scan reads it.** A path dependency on a directory the scan walks gets no row; that directory's own manifest is scanned. Any other path is a row: one outside the scanned directory, an archive (a wheel, an npm tarball, a JAR), a directory under a skipped name such as `vendor/`, a nested repository, an `--exclude-dirs` directory, and a path that does not exist. A .NET `<ProjectReference>` written as a wildcard pattern is judged by the directory its literal part names.
- **Alternate registries are unchanged.** A package from a private index or mirror (a Poetry `source`, a uv index, a `Gemfile` `source` block, a Cargo alternate registry) is still resolved from the public registry by name. Crates that `Cargo.lock` records from an alternate registry are now reported; they were dropped.
- `GIST` sections of `paket.lock` are no longer read as NuGet packages.

#### The review file

- **Off-registry dependencies are reviewed by source.** A `licenseal.review.toml` stanza for an off-registry dependency carries a `source` key holding the row's `origin`, and `version` is optional beside it. Only a stanza with `source` matches such a row, and a stanza with `source` never matches a registry package. `init-review-file` writes the `source` line. A review keyed on a branch or a tag keeps applying when the branch moves; a commit pin or a lockfile gives a key that does not.
- **`init-review-file` scans as `check` does.** Without `--from-report` it used to resolve direct dependencies only and to ignore lockfiles, so it missed flagged transitives and could write a version that `check` does not report; the next `check` then failed with "did not match any resolved package versions". It now reads lockfiles and the transitive graph with `check`'s defaults, prints the same progress lines and warnings, and takes correspondingly longer.
- A review entry whose license has unpaired parentheses is rejected. It used to be accepted as an override that could not be classified.

#### Dependencies that were missed are now reported

New rows can carry new findings.

- **Lockfiles without a matching manifest.** A lockfile is read wherever it is found, including when no manifest yields a direct dependency for its ecosystem: a directory that holds only lockfiles, or a Gradle build that declares everything through a version catalog. Such scans were empty and passed. When none of a lockfile's packages is a discovered direct dependency, all of them are reported as `prod`. A sample or test-data lockfile outside the auto-skipped directories now adds its packages to the report; exclude its directory with `--exclude-dirs`.
- **Python.** `setup.cfg` is read at any depth, not only in the scanned directory. `-r` / `--requirement` includes in requirements files are followed when they stay inside the scanned directory. A requirement followed by a comment that contains a URL is no longer dropped.
- **npm.** In a Yarn Classic `yarn.lock`, a package reached only through `optionalDependencies` is kept, with everything below it. In `pnpm-lock.yaml`, a package installed under an npm alias is reported under its real name, where it was dropped.
- **Java.** Dependencies declared inside Maven `<profiles>` are included from every profile; activation conditions are not evaluated. A Gradle coordinate declared without a version (`'group:artifact'`) is reported, where such a build file produced no dependencies at all. Gradle's `compileOnlyApi`, `release*`, and `shadow` configurations are read as production, and the `debug*`, `developmentOnly`, and `testFixtures*` configurations as dev.
- **.NET.** `<PackageReference>` items in `Directory.Build.props` / `.targets`, in the files those import, and inside `<Choose>` branches are read. A `paket.lock` package line that ends in options (`- restriction: …`) is read at its pinned version. A reference whose `Condition` names Debug among other configurations (`Debug Or Release`) is production; only a condition that is, as a whole, a Debug / Test comparison is dev. A dependency that a `.nuspec` declares with no usable version is reported as UNKNOWN, where it was dropped.
- **Go.** `replace ( … )` blocks are applied, and a `replace` with a version on its left side applies to that version only. A `go.mod` requirement that a non-empty `go.sum` has no row for is reported.
- **Rust.** The crates.io crates that `Cargo.lock` reaches only through a `git` or `path` dependency are reported, under that dependency's own row.
- **PHP.** A package whose vendor name starts with `php-`, `ext-`, or `lib-` is no longer filtered out as a platform requirement. Without a `composer.lock`, a version other than the newest now resolves its license and its dependencies: Packagist's minified metadata was read without being expanded, so those versions came back with no license and no children.
- **Ruby.** A gem is dev only when every group it belongs to is `:development` or `:test`. Gems in any other group (`:production`, `:staging`, a custom group such as `:assets`) or in a mixed list were dropped as dev-only.
- **Hex.** `rebar.config` dependencies under a profile other than `test` and `dev` are production dependencies. Only top-level `deps` and `profiles` terms are read, not a `deps` list inside an `overrides` entry.

#### Dependencies that are no longer reported, or are reported differently

- **Rust.** Without a `Cargo.lock`, the registry walk no longer follows optional (feature-gated) dependencies, which it used to expand for every crate it visited. A crate enabled only through a feature is not reported in that mode. On a large lock-less workspace the scan went from 1,499 rows and 49 minutes to 92 rows and under 5 minutes.
- **Ruby.** A development or test group written as a string (`group "test"`) or as a word list (`groups: %i[development test]`) is recognised, so its gems are dev and leave the default scan.
- **.NET.** With `packages.lock.json` or `project.assets.json`, group and `direct_ancestors` follow the lockfile's dependency edges: a package reached only through a `PrivateAssets="all"` reference is dev, and a `PrivateAssets="all"` reference that a production package depends on is production. In `paket.lock`, the dependency-constraint lines under a package are no longer reported as packages. A `<PackageReference>` inside an `<ItemGroup>` whose `Condition` is, as a whole, a Debug / Test comparison is dev, like one that carries the condition itself.
- **Python.** A local wheel, archive, or directory path in a requirements file is no longer read as a package named after its first path segment and looked up on PyPI.
- **Go.** With a `go.sum`, a row at a version other than the one `go.mod` requires is a transitive, not a direct dependency. `replace` directives in a dependency's own `go.mod` are no longer applied; Go honours them only in the main module.
- **Production wins.** A dependency that is declared as dev and is also pulled in by a production dependency is `prod` everywhere: in the registry walk, when several lockfiles are merged, for Go `tool` modules, in the Maven and NuGet walks, and in `paket.lock`. `--dev` adds rows and never turns a `prod` row into `dev`. Without a lockfile, group and `direct_ancestors` are attributed per resolved version, so a version that only a dev dependency pulls in is `dev`.

#### Stricter license reading

- **PyPI wheel metadata.** A folded `License-Expression` header is read whole; `MIT` continued by `AND GPL-3.0-only` on the next line used to resolve to MIT. A license text pasted into the legacy `License` field is UNKNOWN, where its first line was taken as the license. For a pinned release whose JSON carries no license, that release's own wheel metadata is read before the license of the project's latest release is borrowed.
- **License URLs.** A license URL is matched on its parsed host and path. A lookalike domain, a canonical path on another site, and prose that mentions a license host no longer resolve to that license.
- **Use-restricted licenses.** `BSD-3-Clause-No-Military-License`, `BSD-3-Clause-No-Nuclear-License`, `BSD-3-Clause-No-Nuclear-License-2014`, `BSD-Protection`, and `Unicode-TOU` are UNKNOWN, for a dependency and as the project's own license. They were classified as permissive.
- **Compound expressions.** License entries joined with `AND` keep their grouping: `Apache-2.0 OR GPL-2.0-only` joined with `AGPL-3.0-only` was read as `Apache-2.0 OR (GPL-2.0-only AND AGPL-3.0-only)` and came back compatible. Lowercase `and` / `or` are read with SPDX precedence. A custom `LicenseRef-*` is mapped per operand, so `LicenseRef-custom AND GPL-3.0-only` is a violation under a permissive project, where the reference used to swallow the rest of the expression. Each `OR` arm is judged as a whole: under `GPL-2.0-only`, `Apache-2.0 OR AGPL-1.0-only` is a warning, where one arm supplied the risk class and the other the clean conflict check. Redundant parentheses around the project's license no longer change the result.
- **Deprecated GNU license IDs.** `GPL-2.0`, `GPL-3.0+`, `LGPL-3.0`, and the other deprecated GNU spellings are read as their current IDs wherever they appear: inside an expression, from a license URL, from a NuGet `<licenseUrl>`, and in the project's license. The version-conflict rules for GPL-family projects now apply to them. Reported license strings change accordingly (`GPL-2.0` → `GPL-2.0-only`, `GPL-3.0+` → `GPL-3.0-or-later`) in `license`, `detected_license`, `effective_license`, and `project_license`.
- **Malformed license strings.** A license string with a dangling operator or unpaired parentheses (`MIT OR GPL-3.0-only AND`, `(MIT OR Apache-2.0`) is never compatible: it is a violation when a license it names is one, and UNKNOWN otherwise. Its well-formed part used to be accepted. A license string longer than 1,000 characters is UNKNOWN. A review entry with any of these is rejected.
- **`WITH` exceptions.** Whatever followed `WITH` used to be ignored unless it was a Classpath exception, and any `WITH` suffix switched the pair-level conflict rules off. Now only exceptions licenseal recognises change how a license is judged. The two Classpath exceptions, matched exactly, relax a GPL license to weak copyleft. Fourteen permission-only SPDX exceptions (`LLVM-exception`, `GCC-exception-3.1`, `Bison-exception-2.2`, and others) are judged as the bare license, pair-level conflicts included, with one stated effect: `Apache-2.0 WITH LLVM-exception` is compatible in a `GPL-2.0-only` project. A license with any other exception is that license plus terms nobody evaluated: a violation when the bare license is one, UNKNOWN otherwise. `Apache-2.0 WITH Commons-Clause` no longer passes.
- **License lists with no stated meaning.** A RubyGems or Hex `licenses` array with several entries, and a comma- or slash-separated list inside one license string, do not say whether the licenses are alternatives or all apply. They were read as alternatives, so the most permissive entry decided. Such a list is now judged both ways: when both readings give the same verdict, that is the verdict, and when they differ the dependency is UNKNOWN until the reading is recorded in `licenseal.review.toml`. An entry licenseal does not recognise counts as an unresolved license, so `GPL-3.0-only, acme internal license` is a violation in a permissive project. A list whose source defines it keeps that meaning: a Composer array and a Cargo `/` are alternatives, and a deps.dev array is a conjunction. The pair `Ruby` with `BSD-2-Clause` is read as alternatives, because the Ruby license itself offers that choice. `license_raw` shows such an array comma-separated, where it was joined with `OR`.
- **PyPI classifiers.** When PyPI metadata has no usable `license` field, every license classifier is read, where the first one was taken; several distinct ones follow the list rule above. A `license` field that says the package is proprietary is no longer replaced by a classifier.
- **deps.dev answers.** `GPL-3.0-only AND LGPL-3.0-only` used to be collapsed to `LGPL-3.0-only`, and the CDDL / GPL-with-Classpath conjunction rewritten to `OR`, in every license string. Both rewrites now apply only to a multi-entry license array from deps.dev, which is what they were written for; a declared or reviewed expression keeps its operators. A deps.dev array that mixes a license with `non-standard` is no longer reported as that license: the dependency is resolved from its own registry, and a Go module, which has no other source, is UNKNOWN.
- **CRAN.** A license written `<license> + file LICENSE`, on a license other than MIT or BSD, is reported as `<license> AND UNKNOWN`: the file adds terms licenseal does not read.
- **A license taken from another release is marked.** Three registries can only answer with metadata for a release other than the one reported: CRAN's index describes the current version of a package, hex.pm serves the license of the release published last, and a PyPI release that declares no license takes the latest release's. Such a license has `~` before it in the table and Markdown reports and `"license"` in the JSON `estimated` array. The mark does not fail a scan.
- **A pinned PyPI release is never swapped for the latest one.** A pinned release that PyPI does not have (a build from another index, a `+local` version) is reported at its pinned version with its license marked as above; it used to be reported as the project's latest release, so a review entry keyed on that version must be keyed again. When the lookup of a pinned release fails for another reason (a server error, a timeout), the dependency is UNKNOWN at its pinned version.
- **Dev dependencies.** For a dev dependency, a pair-level conflict under a project license the compatibility matrix has no row for is UNKNOWN instead of a warning.

#### Files that cannot be analyzed fail strict mode

Each of these is now an analysis gap on the file, reported on stderr and in the report. A manifest resolved without a lockfile, and a dependency list the registry did not return, are gaps too; see [Projects without a lockfile](#projects-without-a-lockfile).

- A TOML manifest or lockfile that is not valid UTF-8. It used to be read through the latin-1 fallback, which TOML does not allow. A file with a byte-order mark is read as before.
- A `go.mod` whose `go` directive is below 1.17, or missing, with a requirement that has no `go.sum` row: the modules that requirement depends on are not in the report. From Go 1.17 on, a `go.mod` lists every module the build needs and is not affected.
- A `composer.json` that declares a version-control, `artifact`, or unread `path` repository and has no `composer.lock`: the packages such a repository provides cannot be told from registry packages and may have been resolved from Packagist.
- A `setup.py` that is not valid Python 3, which was treated as declaring nothing. A malformed `setup.cfg` in a subdirectory is a gap as well, now that those files are read.
- A manifest or lockfile value of a type its format does not allow (`"dependencies": []` in `package.json`). It used to be skipped silently or to end the scan with a traceback. The files covered are listed in [USAGE.md](USAGE.md).
- A lockfile the parser cannot use: a `pnpm-lock.yaml` with `lockfileVersion` below 6, a lockfile none of whose entries can be read, and a line-oriented lockfile with merge-conflict markers. The direct dependencies are then resolved through the registry, as before, but no longer silently.
- A requirements `-r` include that is a URL, is not a relative path, is not a file, or leaves the scanned directory.
- An MSBuild `<Import>` in a `Directory.Build` file, or a `go.work` `use` directory, that is not a relative path. Such a path is no longer opened at all; on Windows a UNC value could reach a network share.

#### Report output

- **Markdown and table.** Every dependency is one row, so the table has as many rows as JSON's `summary.total`; transitives used to repeat under each direct row that shared a name. When a scan has analysis gaps, the summary line carries the gap count and an **Analysis gaps** section lists each file with its reason. Strings from registries and scanned files are escaped: control characters appear as `\xNN`, and Markdown syntax in a package name, license, or note is backslash-escaped. A checked-in `LICENSES.md` changes where any of this applies.
- **Table.** Off a terminal and in an `-o` file, the table is written at its full width, one line per dependency, with no column dropped and no cell cut short; lines can be longer than 80 columns. In a CI log the Status column used to be cropped.
- **JSON.** New fields: `estimated`, `origin`, and `registry_name` on every dependency, and a top-level `project_license_source`. The `dependencies` array has one row per ecosystem, name, resolved version, and origin, in every scan mode. `diagnostics[].severity` can be `"estimate"`. `package_url` percent-encodes the name and version (the URL of a well-formed name is unchanged) and is empty for an off-registry dependency. `source` names the declaring manifest for a direct dependency read from a Ruby, Hex, or R lockfile, where it was empty.
- **Markdown and table, with estimates.** Estimated versions and licenses carry the `~` marker, explained by one legend line. With `--no-require-lockfile`, manifests resolved without a lockfile are listed in their own section and counted on the summary line.

### Added

- hex.pm's limit of 100 unauthenticated requests per minute is waited out: a project with more than 100 Hex packages pauses until the registry's reported reset time and then continues, where every package past the limit used to resolve to UNKNOWN. Each pause is announced on stderr with its length. The waiting is bounded, and lookups abandoned because the limit never lifted are counted in a closing warning.
- `check --no-require-lockfile` accepts dependencies resolved without a lockfile as estimates; see [Projects without a lockfile](#projects-without-a-lockfile).
- `init-review-file` scaffolds reviewable entries for dependencies from git, a URL, or a path.
- `check` reports dependencies from an off-registry source on their own stderr line. The `could not be resolved from registries` warning counts failed lookups only.
- TOML manifests and lockfiles written as UTF-16, UTF-32, or UTF-8 with a byte-order mark are read.
- A lockfile in a format version newer than licenseal was written for is read on a best-effort basis and reported with a warning that does not fail strict mode. Yarn Berry lockfiles up to metadata version 10 are read without one.

### Fixed

- Inputs that ended the scan with a traceback and no report now produce an analysis gap or an UNKNOWN row, and the scan continues: a manifest whose bytes are not valid for the encoding its byte-order mark names; a `pom.xml` whose prolog names a multi-byte or unknown encoding; a JSON, TOML, or YAML document nested too deeply to parse; a registry response that is JSON but not an object, or holds a field of an unexpected type; a dependency name or version that cannot be put in a request URL (a control character, a lone surrogate); a `Retry-After` header that is not a decimal number; a requirement whose environment marker crashes the PEP 508 parser; a `setup.cfg` whose license holds a stray `%` (`license = 100% free`), which is read as declaring no license.
- A `licenseal.review.toml`, a `--from-report` file, or an installed skill file that is not UTF-8 or cannot be parsed ends the command with an error that names the file.
- `init-review-file` writes every scaffold field so that it parses back unchanged. A multi-line license string from a registry used to be written partly as live TOML, which could leave a scaffold that did not parse, or plant a pre-filled review entry for another dependency. A dependency whose name, version, or source a TOML file cannot hold (a lone surrogate) gets no stanza and is named in a note; it used to make the whole file unloadable.
- A project of the scanned tree that another manifest names in a different case is no longer looked up on the public registry: a .NET package reference to an in-tree project, and a Cargo dependency on a workspace crate.
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
