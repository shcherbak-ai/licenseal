# Changelog

All notable changes to this project will be documented in this file. Each version listed corresponds to a release published on [PyPI](https://pypi.org/project/licenseal/).

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.2] - 2026-10-27

### Security

- `certifi` 2026.10.19 or newer is required. licenseal checks the registries' certificates against certifi's bundle, and installing licenseal with pip kept an older certifi already in the environment. Older bundles trust root CAs whose intermediate keys were compromised ([GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2)), so someone on the network path could have answered registry requests with licenses of their choosing. A bundle named by `SSL_CERT_FILE` or `SSL_CERT_DIR` is still used in certifi's place.

## [1.0.1] - 2026-10-15

### Changed

- `tethered` 1.0.0 or newer is required (was 0.5.1).

### Fixed

- **A scan runs behind a proxy on another host.** With `HTTPS_PROXY` or `ALL_PROXY` set, or on Windows and macOS a proxy in the system's settings, every scan stopped with `Blocked by tethered: <proxy> is not in the allow list`: licenseal's egress allowlist held the registry hosts but not the proxy that carried the requests to them, and no setting could add it. licenseal now chooses the proxy itself, sends the registry requests through it, and allows its host and port; see [Proxies](https://licenseal.shcherbak.ai/security/network/#proxies). A proxy on `127.0.0.1` or `::1` was not affected.

## [1.0.0] - 2026-10-14

Most of the changes since 0.4.2 close cases where a scan passed although it had missed dependencies, misread a license, or skipped a file without saying so. A check that passes on 0.4.2 can therefore fail on 1.0.0 with no change to the project. A `licenseal.review.toml` entry can also stop matching, which is an error, when its dependency is now reported at another version or is no longer reported. Every change of that kind is listed under **Breaking changes**, together with changes to defaults, report values, the review file, and install requirements.

### Upgrading from 0.4.x

Follow the [1.0.0 migration guide](https://licenseal.shcherbak.ai/guides/migrate-to-v1/). It says what to change in a project, in its `licenseal.review.toml`, in a checked-in `LICENSES.md`, and in a script that reads the JSON report, and how to stay on 0.4.2 until that is done.

### Breaking changes

#### Install requirements

- Python 3.11 or newer is required (was 3.10). Python 3.10 reached end of life in October 2026.
- `httpx` 0.28 or newer is required (was 0.27). The guarantee that credentials in `~/.netrc` are never read holds from that version on.

#### Projects without a lockfile

- **A missing lockfile fails strict mode.** When a manifest's dependencies are resolved from the registry because no lockfile covers them, that manifest is an [analysis gap](https://licenseal.shcherbak.ai/concepts/check-failures/#analysis-gaps): it counts in `summary.gaps`, and `check` exits 1 under `--strict`, the default.
    - Commit a lockfile, or pass the new `--no-require-lockfile` to accept the estimate; the manifest is then listed with severity `estimate` and does not fail the check.
    - A direct dependency that an existing lockfile does not cover counts the same way; see [Package names and versions](#package-names-and-versions) for what covering means.
    - Not affected: `pom.xml`, `packages.config`, and an erlang.mk `Makefile`, which have no lockfile format licenseal reads; Go; and `--no-transitive` scans, which read no lockfile.
- **Estimated versions are marked.** A version licenseal chose from a registry (for a declared range, for no constraint, or for a transitive found by walking the registry) is shown as `~1.2.3` in the table and Markdown reports, with a legend line, and has `"version"` in the JSON `estimated` array.
- **A declared range resolves to a version inside it** for Rust, Ruby, Hex, PHP, and .NET; the registry's latest release used to be taken whatever the range said. Rust, Ruby, Hex, and PHP take the highest matching release. NuGet takes the lowest, as NuGet itself does, and the highest for a floating version (`1.*`). A constraint that cannot be read, a range no published version satisfies, a Composer branch constraint (`dev-main`), and a Composer exact version that Packagist does not list resolve to UNKNOWN with no version; they used to take the latest release or the first entry. A bare version in a `Gemfile`, `mix.exs`, `rebar.config`, or `composer.json` is an exact pin.
- **npm and Cargo ranges hold every bound.** A range with a prerelease bound used to lose its other bounds: `>=2.0.0-rc.1 <2.0.0` resolved to `2.0.0`, and `<2.0.0` could select a prerelease of `2.0.0`. Both now resolve as npm and Cargo read them, which also decides whether a lockfile covers such a range. A Cargo requirement `=1.2` or `=1` is the range Cargo reads it as, marked as an estimate; crates.io used to be asked for the literal version `1.2`. A malformed npm hyphen range is UNKNOWN; it used to end the scan with a traceback.
- **An exact pin resolves under the spelling the registry lists.** A RubyGems or NuGet pin written with other segments than the published version (`1.2` for `1.2.0`, or `1.2.0.0`) names that release. Such a row was UNKNOWN or lacked its dependencies. It is reported under the published spelling, and NuGet versions are requested and reported in NuGet's normalized form, so a review entry keyed on another spelling must be keyed again.
- **A dependency list the registry did not return is a gap.** When a package's own dependencies cannot be read (a failed request, a malformed response, an unreadable `.nuspec`), the manifest that leads to the package is an analysis gap. Such a package used to look like one with no dependencies. `--no-require-lockfile` does not waive this gap.
- **Gradle without a `gradle.lockfile`.** A coordinate declared with no version is reported at the artifact's latest release, marked as an estimate, and its dependencies are scanned. A dynamic version (`1.+`, `latest.release`) is UNKNOWN with no version; its literal text used to be sent to the registries.

#### Package names and versions

- **Names are compared the way each registry compares them.** In Go, Java, npm, and Ruby, two names that differ only in case are two packages: each is reported with its own license; one used to stand for both. A `licenseal.review.toml` entry for those ecosystems must spell `package` exactly as the report does; an entry in another case stops matching, which is an error. .NET, PHP, Rust, Hex, and R names are compared without regard to case and Python names by PyPI's normalisation rule, as before.
- **Names and versions are percent-encoded in every registry URL.** A dependency name or version containing `/../`, `?`, `#`, or `%xx` could make a lookup return another package's metadata, and the row passed with that package's license. One that would still address another resource is not sent: the dependency is UNKNOWN under its declared name. The URL of a well-formed name is unchanged.
- **Every declared version is scanned.** When manifests in one tree declare a package with different version constraints, each one is resolved, walked, and reported under its own manifest. Only the first used to be scanned, so the other version and everything below it were missing.
- **A lockfile covers a dependency only at a version its manifest admits.** A lockfile used to cover a declared dependency whenever it held a package of that name. A manifest that is ahead of its lockfile, or that pins another version than a lockfile elsewhere in the tree, is now resolved from the registry for that dependency and counts as a manifest without a lockfile, an analysis gap under the default `--require-lockfile`. A locked prerelease is accepted for any range, since whether a range admits one depends on settings licenseal does not read.
- **A locked row is a direct dependency only at a declared version.** Another locked version of a directly declared package, such as a nested copy in an npm lockfile or a second major in `Cargo.lock`, is a transitive: in JSON its `depth` is 1 and its `source` is empty. A requirement that did not resolve is reported even when a row of the same name resolved at a version that does not satisfy it.
- **.NET reports every distinct version.** A package pinned at different versions in two `paket.lock` groups is one row per version; the first entry used to win. The `.nuspec` walk reports another version of a directly referenced package as its own row. The production rows of a `--dev` scan now equal the rows of a `--no-dev` scan.
- **Hex.** A review entry for a dependency that `mix.exs` renames is keyed on its hex.pm package name, not on the local name; an entry written under the local name must be scaffolded again.

#### The project's own license

- **Only manifests in the scanned directory decide it.** The project license, which every dependency is judged against, is read from the manifests in the scanned directory itself and never from a nested package. With none declaring one the project is checked as `Proprietary`, as before. A monorepo whose license came from a sub-package gets different verdicts; scan the sub-package with `--path` to use its license.
- **An unrecognised declared value is judged as `Proprietary`**, with a warning that names the file and the value. It used to make every dependency UNKNOWN.
- **An unrecognised arm of a dual license is a `Proprietary` arm.** Project `AGPL-3.0-only OR Commercial` used to drop the unrecognised arm, so copyleft dependencies passed. They are violations now, as under `AGPL-3.0-only OR Proprietary`.
- **A `Directory.Build.props` in the scanned directory can declare it.** Its `PackageLicenseExpression`, or `PackageLicenseUrl`, is read after the project files in that directory. A .NET solution that declares its license only there was checked as `Proprietary`.
- `check`, and `init-review-file` when it scans, print the file the project license came from, and warn when manifests in the scanned directory declare different licenses. JSON has a new top-level `project_license_source`, and the table and Markdown reports show the file beside the project license, or say that `Proprietary` is assumed and why, so the header of a checked-in `LICENSES.md` changes once.

#### Dependencies that do not come from a registry

- **One rule for every ecosystem.** An off-registry dependency (one installed from a git repository, a direct URL, or a local path) is reported as one UNKNOWN row that carries its `origin`, and no registry is asked about it. Before, such a dependency was dropped, reported UNKNOWN with no way to review it, or looked up on the public registry under the same name, depending on the ecosystem and the file; the lookup could report a private fork with the public package's license. The forms recognised in each ecosystem are listed on each [ecosystem page](https://licenseal.shcherbak.ai/ecosystems/). A name that one manifest takes from such a source and another from the registry, or that two manifests take from two different repositories, is one row per source.
- **A local path is the project's own code only when the scan reads it.** A path dependency on a directory the scan walks gets no row; that directory's own manifest is scanned. Any other path is a row: one outside the scanned directory, an archive (a wheel, an npm tarball, a JAR), a directory under a skipped name such as `vendor/`, a nested repository, an `--exclude-dirs` directory, and a path that does not exist.
- **Alternate registries are unchanged.** A package from a private index or mirror (a Poetry `source`, a uv index, a `Gemfile` `source` block, a Cargo alternate registry) is still resolved from the public registry by name. Crates that `Cargo.lock` records from an alternate registry are now reported; they were dropped.
- **An off-registry dependency that no lockfile records is a gap.** Nothing is fetched for a git, URL, or path dependency, so only a lockfile lists what it requires. A manifest that declares one with no lockfile entry for it is an analysis gap, which `--no-require-lockfile` accepts like any other. A Mix `path:` dependency and a .NET project reference are exempt when the project's `mix.lock` or NuGet lockfile is present.
- `GIST` sections of `paket.lock` are no longer read as NuGet packages.

#### The review file

- **Off-registry dependencies are reviewed by source.** A `licenseal.review.toml` entry for an off-registry dependency carries a `source` key holding the row's `origin`, and `version` is optional beside it. Only an entry with `source` matches such a row, and an entry with `source` never matches a registry package. `init-review-file` writes the `source` line. A review keyed on a branch or a tag keeps applying when the branch moves; a commit pin or a lockfile gives a key that does not.
- **`init-review-file` scans as `check` does.** Without `--from-report` it used to resolve direct dependencies only and to ignore lockfiles, so it missed flagged transitives and could write a version that `check` does not report; the next `check` then failed with "did not match any resolved package versions". It now reads lockfiles and the transitive graph with `check`'s defaults, and takes correspondingly longer.
- A review entry whose license has unpaired parentheses is rejected. It used to be accepted as an override that could not be classified.
- **A review entry's license must name a license.** An entry whose `license` holds something that is no license, such as the typo `MTI`, is rejected with an error that names the entry and the operand. Accepted: an SPDX identifier, current or deprecated; a source-available license licenseal recognises (`BUSL-`, `FSL-`, `PolyForm-`, …); `Proprietary`; a `LicenseRef-` reference. An exception after `WITH` is not checked against a list. Such an entry used to be accepted, and the dependency passed strict mode as reviewed.
- A review entry whose `license` is a comma- or slash-separated list is rejected; write the expression with `OR` or `AND`. It used to be read as a choice.

#### Dependencies that were missed are now reported

New rows can carry new findings.

- **Lockfiles without a matching manifest.** A lockfile is read wherever it is found, including when no manifest yields a direct dependency for its ecosystem: a directory that holds only lockfiles, or a Gradle build that declares everything through a version catalog. Such scans were empty and passed. When none of a lockfile's packages is a discovered direct dependency, all of them are reported, as `prod` unless the format records its own dev/prod split. A sample or test-data lockfile outside the auto-skipped directories now adds its packages to the report; exclude its directory with `--exclude-dirs`.
- **Python.** `setup.cfg` is read at any depth, not only in the scanned directory. `-r` / `--requirement` includes in requirements files are followed when they stay inside the scanned directory, and so is a setuptools `file:` directive (`install_requires = file: reqs.in` in `setup.cfg`, `[tool.setuptools.dynamic]` in `pyproject.toml`). A requirement followed by a comment that contains a URL is no longer dropped.
- **npm.** In a Yarn Classic `yarn.lock`, a package reached only through `optionalDependencies` is kept, with everything below it. In `pnpm-lock.yaml`, a package installed under an npm alias is reported under its real name; it used to be dropped.
- **Java.** Dependencies declared inside Maven `<profiles>` are included from every profile; activation conditions are not evaluated. A Gradle coordinate declared without a version (`'group:artifact'`) is reported; such a build file used to produce no dependencies at all. Gradle's `compileOnlyApi`, `shadow`, `releaseApi`, `releaseImplementation`, and `releaseRuntimeOnly` configurations are read as production, and `debugApi`, `debugImplementation`, `debugRuntimeOnly`, `developmentOnly`, `testFixturesApi`, and `testFixturesImplementation` as dev.
- **Maven and Gradle versions.** A version that names one release is resolved whatever it looks like: a release-train name, a version that starts with a letter, the hard requirement `[1.0]`, Gradle's strict `1.0!!`. Such rows were UNKNOWN, and their dependencies were not scanned. `RELEASE`, `LATEST`, and other text that is not a version are no longer sent to deps.dev. A Gradle coordinate written with an artifact type (`group:artifact:1.0@aar`) is reported at its version (previously the type stayed inside the version and the row was UNKNOWN); one with a type and no version was missing from the report.
- **.NET.** `<PackageReference>` items in `Directory.Build.props` / `.targets`, in the files those import, and inside `<Choose>` branches are read. A `paket.lock` package line that ends in options (`- restriction: …`) is read at its pinned version. A reference whose `Condition` names Debug among other configurations (`Debug Or Release`) is production; only a condition that is, as a whole, a Debug / Test comparison is dev. A dependency that a `.nuspec` declares with no usable version is reported as UNKNOWN; it used to be dropped.
- **Go.** `replace ( … )` blocks are applied, and a `replace` with a version on its left side applies to that version only. A `go.mod` requirement that a non-empty `go.sum` has no row for is reported.
- **Rust.** The crates.io crates that `Cargo.lock` reaches only through a `git` or `path` dependency are reported, under that dependency's own row.
- **PHP.** A package whose vendor name starts with `php-`, `ext-`, or `lib-` is no longer filtered out as a platform requirement. Without a `composer.lock`, a version other than the newest now resolves its license and its dependencies: Packagist's minified metadata was read without being expanded, so those versions came back with no license and no children.
- **Ruby.** A gem is dev only when every group it belongs to is `:development` or `:test`. Gems in any other group (`:production`, `:staging`, a custom group such as `:assets`) or in a mixed list were dropped as dev-only.
- **Hex.** `rebar.config` dependencies under a profile other than `test` and `dev` are production dependencies. Only top-level `deps` and `profiles` terms are read, not a `deps` list inside an `overrides` entry. `mix.exs` options are read in every spelling of their key (`only:`, `"only":`, `{:only, …}`), so a dev-only or renamed dependency written that way is no longer read as a plain production one.

#### Dependencies that are no longer reported, or are reported differently

- **Rust.** Without a `Cargo.lock`, the registry walk no longer follows optional (feature-gated) dependencies, which it used to expand for every crate it visited. A crate enabled only through a feature is not reported in that mode.
- **Ruby.** A development or test group written as a string (`group "test"`) or as a word list (`groups: %i[development test]`) is recognised, so its gems are dev and leave the default scan.
- **.NET.** With `packages.lock.json` or `project.assets.json`, group and `direct_ancestors` follow the lockfile's dependency edges: a package reached only through a `PrivateAssets="all"` reference is dev, and a `PrivateAssets="all"` reference that a production package depends on is production. In `paket.lock`, the dependency-constraint lines under a package are no longer reported as packages. A `<PackageReference>` inside an `<ItemGroup>` whose `Condition` is, as a whole, a Debug / Test comparison is dev, like one that carries the condition itself.
- **Python.** A local wheel, archive, or directory path in a requirements file is no longer read as a package named after its first path segment and looked up on PyPI.
- **Go.** With a `go.sum`, a row at a version other than the one `go.mod` requires is a transitive, not a direct dependency. `replace` directives in a dependency's own `go.mod` are no longer applied; Go honours them only in the main module. `replace` directives in a `go.work` in the scanned directory are applied to the modules it lists with `use`, and override those modules' own; they used to be ignored, so a module that `go.work` redirects to a local path was looked up on deps.dev and the Go module proxy. When `go.sum` lists several versions of a required module, `direct_ancestors` and the `prod` / `dev` group follow the required version's `go.mod`; they could follow another version's.
- **R.** A `DESCRIPTION` requirement written `(== x)` is reported at `x`, with its license marked as an estimate when CRAN's index lists another version. The default scan used to report the indexed version.
- **The project's own packages.** A project of the scanned tree that another manifest names in a different case has no row and is no longer looked up on the public registry: a .NET package reference to an in-tree project, and a Cargo dependency on a workspace crate. It used to be a row with the license of whatever registry package has that name (for .NET, in a `--no-transitive` scan).
- **Production wins.** A dependency that is declared as dev and is also pulled in by a production dependency is `prod` everywhere: in the registry walk, when several lockfiles are merged, for Go `tool` modules, in the Maven and NuGet walks, and in `paket.lock`. `--dev` adds rows and never turns a `prod` row into `dev`.

#### Stricter license reading

- **PyPI wheel metadata.** A folded `License-Expression` header is read whole; `MIT` continued by `AND GPL-3.0-only` on the next line used to resolve to MIT. A license text pasted into the legacy `License` field is UNKNOWN; its first line used to be taken as the license. For a pinned release whose JSON carries no license, that release's own wheel metadata is read before the license of the project's latest release is borrowed. A wheel-metadata lookup that fails borrows nothing: the release is UNKNOWN unless deps.dev has that version.
- **License URLs.** A license URL is matched on its parsed host and path. A lookalike domain, a canonical path on another site, and prose that mentions a license host no longer resolve to that license.
- **Use-restricted licenses.** `BSD-3-Clause-No-Military-License`, `BSD-3-Clause-No-Nuclear-License`, `BSD-3-Clause-No-Nuclear-License-2014`, `BSD-Protection`, and `Unicode-TOU` are UNKNOWN for a dependency; they were classified as permissive. As the project's own license they are not recognised, and the project is checked as `Proprietary`.
- **Compound expressions.**
    - License entries joined with `AND` keep their grouping: `Apache-2.0 OR GPL-2.0-only` joined with `AGPL-3.0-only` was read as `Apache-2.0 OR (GPL-2.0-only AND AGPL-3.0-only)` and came back compatible.
    - Lowercase `and` / `or` are read with SPDX precedence.
    - A custom `LicenseRef-*` is mapped per operand, so `LicenseRef-custom AND GPL-3.0-only` is a violation under a permissive project; the reference used to swallow the rest of the expression.
    - Each `OR` choice is judged as a whole: under `GPL-2.0-only`, `Apache-2.0 OR AGPL-1.0-only` is a warning; one choice used to supply the risk class and the other the clean conflict check.
    - Redundant parentheses around the project's license no longer change the result.
    - An `OR` gets exactly the verdict of the choice the project can take: `Apache-2.0 OR EPL-2.0` in a `GPL-2.0-only` project is the EPL-2.0 warning; it used to be a violation.
- **Deprecated GNU license IDs.** `GPL-2.0`, `GPL-3.0+`, `LGPL-3.0`, and the other deprecated GNU spellings are read as their current IDs wherever they appear: inside an expression, before a `WITH` exception, from a license URL, from a NuGet `<licenseUrl>`, and in the project's license. The version-conflict rules for GPL-family projects now apply to them. Reported license strings change accordingly (`GPL-2.0` → `GPL-2.0-only`, `GPL-3.0+` → `GPL-3.0-or-later`) in `license`, `detected_license`, `effective_license`, and `project_license`. A deprecated compound ID (`GPL-3.0-with-GCC-exception` and the six like it) is judged as its `WITH` spelling, so the version-conflict rules apply to it too; it is shown as declared.
- **Malformed license strings.** A license string with a dangling operator or unpaired parentheses (`MIT OR GPL-3.0-only AND`, `(MIT OR Apache-2.0`) is never compatible: it is a violation when a license it names is one, and UNKNOWN otherwise. Its well-formed part used to be accepted. A license string longer than 1,000 characters is UNKNOWN. A review entry with any of these is rejected. A violating license joined by `AND` to text that is no license (`AGPL-3.0-only AND Some Custom Terms`) is a violation, and so is one in a string of IDs with no operator between them (`MIT GPL-3.0-only`).
- **`WITH` exceptions.** Whatever followed `WITH` used to be ignored unless it was a Classpath exception, and any `WITH` suffix switched the pair-level conflict rules off. Now only exceptions licenseal recognises change how a license is judged: the two Classpath exceptions relax a GPL license to weak copyleft, fourteen permission-only SPDX exceptions are judged as the bare license, and `Apache-2.0 WITH LLVM-exception` is compatible in a `GPL-2.0-only` project. A license with any other exception is a violation when the bare license is one and UNKNOWN otherwise: `Apache-2.0 WITH Commons-Clause` no longer passes.
- **License lists with no stated meaning.** A RubyGems or Hex `licenses` array with several entries, and a comma- or slash-separated list inside one license string, were read as alternatives, so the most permissive entry decided. Such a list is now judged both as alternatives and with every entry applying: when the verdicts differ, the dependency is UNKNOWN until the reading is recorded in `licenseal.review.toml`. A list whose source defines it keeps that meaning (a Composer array and a Cargo `/` are alternatives; a deps.dev array is a conjunction), and the pair `Ruby` with `BSD-2-Clause` is read as alternatives. `license_raw` shows such an array comma-separated; it used to be joined with `OR`.
- **PyPI classifiers.** When PyPI metadata has no usable `license` field, every license classifier is read (previously only the first); several distinct ones follow the list rule above.
- **A declared proprietary license is kept.** A license field or name that says `Proprietary`, `Commercial License`, `Closed source`, or `Internal use only` is reported as `Proprietary`. A permissive PyPI classifier, a Maven `<url>`, or a NuGet `<licenseUrl>` no longer replaces it.
- **deps.dev answers.** `GPL-3.0-only AND LGPL-3.0-only` used to be collapsed to `LGPL-3.0-only`, and the CDDL / GPL-with-Classpath conjunction rewritten to `OR`, in every license string. Both rewrites now apply only to a multi-entry license array from deps.dev; a declared or reviewed expression keeps its operators. A deps.dev array that mixes a license with `non-standard` is no longer reported as that license: the dependency is resolved from its own registry, and a Go module, which has no other source, is UNKNOWN.
- **CRAN.** A license written `<license> + file LICENSE`, on a license other than MIT or BSD, is reported as `<license> AND UNKNOWN`: the file adds terms licenseal does not read.
- **A license taken from another release is marked.** Three registries can only answer with metadata for a release other than the one reported: CRAN's index describes the current version of a package, hex.pm serves the license of the release published last, and a PyPI release that declares no license takes the latest release's. Such a license has `~` before it in the table and Markdown reports and `"license"` in the JSON `estimated` array. The mark does not fail a scan.
- **A pinned PyPI release is never swapped for the latest one.** A pinned release that PyPI does not have (a build from another index, a `+local` version) is reported at its pinned version with its license marked as above; it used to be reported as the project's latest release, so a review entry keyed on that version must be keyed again. When the lookup of a pinned release fails for another reason (a server error, a timeout), the dependency is UNKNOWN at its pinned version unless deps.dev has that version.

#### Files that cannot be analyzed fail strict mode

Each of these is now an analysis gap on the file, reported on stderr and in the report. A manifest without a lockfile, and a dependency list the registry did not return, are analysis gaps too; see [Projects without a lockfile](#projects-without-a-lockfile).

- A TOML manifest or lockfile that is not valid UTF-8. It used to be read through the latin-1 fallback, which TOML does not allow. A file with a byte-order mark is read as before.
- A `go.mod` whose `go` directive is below 1.17, or missing, with a requirement that has no `go.sum` row: the modules that requirement depends on are not in the report. From Go 1.17 on, a `go.mod` lists every module the build needs and is not affected.
- A `composer.json` that declares a version-control, `artifact`, or unread `path` repository and has no `composer.lock`: the packages such a repository provides cannot be told from registry packages and may have been resolved from Packagist.
- A `setup.py` that is not valid Python 3, which was treated as declaring nothing. A malformed `setup.cfg` in a subdirectory is a gap as well, now that those files are read.
- A manifest or lockfile value of a type its format does not allow (`"dependencies": []` in `package.json`). It used to be skipped silently or to end the scan with a traceback.
- A lockfile the parser cannot use: a `pnpm-lock.yaml` with `lockfileVersion` below 6, a lockfile none of whose entries can be read, and a line-oriented lockfile with merge-conflict markers. The direct dependencies are then resolved through the registry, as before, but no longer silently.
- A requirements `-r` include, or a setuptools `file:` directive, that is a URL, is not a relative path, is not a file, or leaves the scanned directory.
- A manifest or lockfile read as text that holds NUL characters: a binary file, or UTF-16 without a byte-order mark. It used to be read as an empty file.
- An MSBuild `<Import>` in a `Directory.Build` file, or a `go.work` `use` directory, that is not a relative path. Such a path is no longer opened at all; on Windows a UNC value could reach a network share.

#### Report output

- **Markdown and table.** Every dependency is one row, so the table has as many rows as JSON's `summary.total`; transitives used to repeat under each direct row that shared a name. When a scan has analysis gaps, the summary line carries the gap count and an **Analysis gaps** section lists each file with its reason. Strings from registries and scanned files are escaped: control characters appear as `\xNN` (line breaks and tabs as a space), and Markdown syntax in a package name, license, or note is backslash-escaped. A checked-in `LICENSES.md` changes where any of this applies.
- **Table.** Off a terminal and in an `-o` file, the table is written at its full width, one line per dependency, with no column dropped and no cell cut short; lines can be longer than 80 columns. In a CI log the Status column used to be cropped.
- **JSON.** New fields: `estimated`, `origin`, and `registry_name` on every dependency, and a top-level `project_license_source`. The `dependencies` array has one row per ecosystem, name, resolved version, and origin, in every scan mode. `diagnostics[].severity` can be `"estimate"`. `package_url` percent-encodes the name and version (the URL of a well-formed name is unchanged) and is empty for an off-registry dependency. `source` names the declaring manifest for a direct dependency read from a Ruby, Hex, or R lockfile; it used to be empty.

### Added

- A documentation site, at <https://licenseal.shcherbak.ai/>, built from the Markdown pages under `docs/`. It replaces `USAGE.md` and `JSON_OUTPUT.md`, which now only say where each of their sections went, and holds the detail of the security model, which `SECURITY.md` summarises. Its pages are listed for language models and coding agents at <https://licenseal.shcherbak.ai/llms.txt>, each with a Markdown copy.
- hex.pm's limit of 100 unauthenticated requests per minute is waited out: a project with more than 100 Hex packages pauses until the registry's reported reset time and then continues; every package past the limit used to resolve to UNKNOWN. Each pause is announced on stderr with its length. The waiting is bounded, and lookups abandoned because the limit never lifted are counted in a closing warning.
- `check --no-require-lockfile` accepts dependencies resolved without a lockfile as estimates; see [Projects without a lockfile](#projects-without-a-lockfile).
- `check` reports dependencies from an off-registry source on their own stderr line. The `could not be resolved from registries` warning counts failed lookups only.
- TOML manifests and lockfiles written as UTF-16, UTF-32, or UTF-8 with a byte-order mark are read.
- A lockfile in a format version newer than licenseal was written for is read on a best-effort basis and reported with a warning that does not fail strict mode. Yarn Berry lockfiles up to metadata version 10 are read without one.
- Python 3.15 is supported, and the test matrix runs on it. PyYAML publishes no wheel for 3.15 yet, so installing licenseal there builds PyYAML from source. That needs no compiler, but fails where source builds are switched off (`pip --only-binary :all:`, `uv --no-build`).

### Fixed

- Inputs that ended the scan with a traceback and no report (a manifest in a broken encoding, a registry response of an unexpected shape, a name that cannot be put in a URL, and similar) now produce an analysis gap or an UNKNOWN row, and the scan continues. A `setup.cfg` license that holds a stray `%` (`license = 100% free`) is read as declaring no license.
- A `licenseal.review.toml`, a `--from-report` file, or an installed skill file that is not UTF-8 or cannot be parsed ends the command with an error that names the file.
- `init-review-file` writes every scaffold field so that it parses back unchanged. A multi-line license string from a registry used to be written partly as live TOML, which could leave a scaffold that did not parse, or plant a pre-filled review entry for another dependency. A dependency whose name, version, or source a TOML file cannot hold (a lone surrogate) gets no entry and is named in a note; it used to make the whole file unloadable.
- The table report no longer fails when a dependency name contains `[`, and terminal escape sequences in registry strings no longer reach the terminal, in the reports or in the messages on stderr. Bidirectional control characters and line separators are shown escaped as well, and Markdown escapes `*`.
- The table report prints a reason as written. On a terminal, the number inside a license ID (`GPL-3.0-only`), a quoted value, or a path in a details, analysis-gap, or estimate line used to be highlighted, in colours that mean a verdict elsewhere in the report.
- A range resolves to the same row with and without `--no-transitive` for PyPI, npm, and RubyGems. The two modes could report different versions or licenses when a version's own registry endpoint answered 404.
- With stdout redirected under a legacy code page such as cp1252, the table and Markdown formats print ASCII replacements for the glyphs the encoding lacks instead of failing with no output.
- `check` printed "No dependencies to resolve." before the lockfiles were read. It now says so only when the scan found nothing.
- `--no-transitive` reports a `pom.xml` dependency at the version its parent chain supplies (`<dependencyManagement>`, an imported BOM, a `${property}`), as the default scan does. Those rows were UNKNOWN with no version.
- A Go module version that contains an uppercase letter is requested from the module proxy at the correct URL.
- The hint printed when a request to a host is blocked links to the section of `SECURITY.md` that lists the hosts. Its link pointed at a heading that did not exist.
- The `--help` screens show each command's summary whole, show the default of `--path` and `--format`, and say which options a command rejects together (`--max-depth` with `--no-transitive`; `--dev` / `--no-dev`, `--max-workers`, and `--exclude-dirs` with `--from-report`). Help text only: no option, default, or exit code changed.

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

[1.0.2]: https://github.com/shcherbak-ai/licenseal/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/shcherbak-ai/licenseal/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/shcherbak-ai/licenseal/compare/v0.4.2...v1.0.0
[0.4.2]: https://github.com/shcherbak-ai/licenseal/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/shcherbak-ai/licenseal/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/shcherbak-ai/licenseal/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/shcherbak-ai/licenseal/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/shcherbak-ai/licenseal/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/shcherbak-ai/licenseal/compare/v0.1.2...v0.2.0

<!-- The documentation site includes this file, and nests a list item only at four spaces. -->
<!-- markdownlint-configure-file { "ul-indent": { "indent": 4 } } -->
