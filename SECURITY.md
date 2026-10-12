# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in licenseal, please report it **privately** using [GitHub's private vulnerability reporting](https://github.com/shcherbak-ai/licenseal/security/advisories/new). Please avoid opening public issues for security vulnerabilities. Confirmed vulnerabilities will be addressed in a patch release.

## Trust boundaries

licenseal is a license-assessment tool, not a security primitive. It reads manifests, calls public registries (read-only), and writes only the local outputs a user asks for (a report, a `licenseal.review.toml` scaffold, or the project-local Claude review skill): no code execution, no privileged operations.

### Manifest + registry only

licenseal's input is **manifests and lockfiles on disk** plus **HTTPS reads from a fixed allowlist of public registries**. It does not:

- download or inspect an artifact (`.jar`, `.whl`, `.tar.gz`, `.crate`, `.tgz`, or any other built or source archive), even when the artifact holds a structured field that no registry exposes, such as the `Bundle-License` header of a JAR's `MANIFEST.MF`;
- install or execute code of the scanned project (no `pip install`, `npm install`, `mvn`, `gradle`, `setup.py`, or lifecycle scripts);
- contact a registry that a scanned file declares, such as a POM's `<repositories>` (see [Network egress](#network-egress)).

Four manifest constructs name other files to read. Each is followed only when its value is a relative path:

- An MSBuild `<Import Project="…">` in `Directory.Build.props` / `.targets`, and a `go.work` `use` directory, are followed through `..`, so the file read can be outside the scanned directory.
- A `-r` / `--requirement` line in a requirements file, and a setuptools `file:` directive in `setup.cfg` or `pyproject.toml`, are followed only when they resolve to a file inside the scanned directory. A URL is never fetched, and `-c` / `--constraint` files are never read.

A rooted, drive-qualified, UNC, or device path is rejected by a lexical check before any filesystem call (on Windows, the first call on such a path can open a connection to a network share), and the manifest that contains it is reported as an analysis gap.

### Network egress

Outbound network access is restricted to fourteen hosts by [`tethered`](https://github.com/shcherbak-ai/tethered), an egress allowlist applied to every registry request:

| Host | Registry (operator) | What is requested | Used for |
| --- | --- | --- | --- |
| `pypi.org:443` | PyPI (Python Software Foundation) | `/pypi/{name}/{version}/json` for a release; `/pypi/{name}/json` for the project's latest release | Python packages |
| `files.pythonhosted.org:443` | PyPI's file host (same operator) | A wheel's PEP 658 `.metadata` file; the wheel itself is never downloaded | A Python license, when PyPI's JSON carries no usable one |
| `registry.npmjs.org:443` | npm registry | Package metadata, by name or by name and version | npm packages |
| `crates.io:443` | crates.io | Crate metadata, by name or by name and version | Rust crates |
| `api.deps.dev:443` | deps.dev (Google) | Three requests, listed below | Licenses of Go, Python, npm, Rust, Java, .NET, and Ruby packages; Java dependency graphs |
| `proxy.golang.org:443` | Go module proxy | A module version's `go.mod` | The requirements of Go modules |
| `repo.maven.apache.org:443` | Maven Central (Sonatype) | POM XML and `maven-metadata.xml` version lists in the standard `/maven2/` layout | Java packages |
| `dl.google.com:443` | Google Android Maven (Google) | The same files under `/dl/android/maven2/` | Java packages that Maven Central has no usable answer for |
| `repo.jenkins-ci.org:443` | Jenkins Project public repository (Continuous Delivery Foundation) | The same files under `/public/` | The same, asked after `dl.google.com` |
| `api.nuget.org:443` | NuGet.org (.NET Foundation, Microsoft) | `/v3-flatcontainer/{id}/{version}/{id}.nuspec`; `/v3-flatcontainer/{id}/index.json` for a version list | .NET packages |
| `repo.packagist.org:443` | Packagist | `/p2/{vendor}/{package}.json`, a package's version history | PHP packages; the only network source for them |
| `rubygems.org:443` | RubyGems.org (Ruby Central) | `/api/v2/rubygems/{name}/versions/{version}.json`; `/api/v1/gems/{name}.json` for the latest version; `/api/v1/versions/{name}.json` for a version list | Ruby gems |
| `hex.pm:443` | Hex.pm | `/api/packages/{name}`; `/api/packages/{name}/releases/{version}` for a release's dependencies | Elixir and Erlang packages; the only source for them |
| `cran.r-project.org:443` | CRAN | `/src/contrib/PACKAGES`, once per scan | R packages; the only source for them |

Conditions and license sources, by host:

- `pypi.org`: a release's license is read from that release's own JSON, then from its wheel metadata on `files.pythonhosted.org`, and only then from the project's latest release, which the report marks as an estimate. A release that PyPI answers `404` for (a build from another index, a `+local` version) takes the license of a release PyPI does have, marked as an estimate. A lookup that fails any other way is not answered from another release.
- `crates.io`: direct requests are serialized at one per second, to match crates.io's published data-access guidance.
- `api.deps.dev`: the only license source for Go, so a miss there is UNKNOWN; for the other six ecosystems a miss falls through to the ecosystem's own registry. Three requests:
  - `POST /v3alpha/versionbatch` with up to 100 `{system, name, version}` entries per request, for Go, Python (`PYPI`), npm (`NPM`), Rust (`CARGO`), Java (`MAVEN`), .NET (`NUGET`), and Ruby (`RUBYGEMS`) packages;
  - `GET /v3/systems/{system}/packages/{name}/versions/{version}` for one package version, as a fallback;
  - for Java only, `GET /v3/systems/MAVEN/packages/{name}/versions/{version}:dependencies`, the resolved dependency graph of each direct Maven or Gradle dependency that no `gradle.lockfile` covers.
- `repo.maven.apache.org`: the license of every Java dependency that the deps.dev batch does not answer, and the parent and BOM POMs that manage a `pom.xml` dependency's version. A version list is read only to find the latest release of a Gradle coordinate declared with no version. `dl.google.com` and then `repo.jenkins-ci.org` are asked whenever Central gives no usable answer for a POM or a version list.
- `api.nuget.org`: the license of every .NET dependency that the deps.dev batch does not answer, and the dependency graph when no lockfile covers a reference. The license is the `.nuspec`'s `<license type="expression">`, or a legacy `<licenseUrl>` looked up in a table of known license URLs. A version list is requested only to resolve a range with no inclusive lower bound, or a floating version.
- `repo.packagist.org`: asked when no `composer.lock` entry carries the package's license, which is then the `license` array of the version's entry.
- `rubygems.org`: the license of a gem that the deps.dev batch does not answer, from the `licenses` array.
- `hex.pm`: the license is the `meta.licenses` array of the package response, which also holds the package's links and the version and publication time of each release. hex.pm keeps that array per package and overwrites it each time a release is published, so for a release other than the one published last the license is marked as an estimate. No credentials are sent to raise hex.pm's rate limit, and a package still rate limited when the bounded wait ends is UNKNOWN (see [USAGE.md](USAGE.md#resolution-semantics)).
- `cran.r-project.org`: the index holds the `License` and the dependencies (`Imports` / `Depends` / `LinkingTo` / `Suggests` / `Enhances`) of every current source package. Every R package is resolved locally from it, with no per-package request and no community mirror. It lists current versions only: a package pinned to another version is reported at its pinned version with the current license, marked as an estimate, and a package the index does not list (archived, or from Bioconductor or GitHub) is UNKNOWN. `License` is translated from R's grammar (`GPL (>= 2)`, `MIT + file LICENSE`) to SPDX; a bare `file LICENSE` is UNKNOWN.

Three rules hold for every host:

- **No registry or source that a scanned file declares is contacted**: not a Maven `<repositories>` block, a `nuget.config` `<packageSources>` entry, a Composer `repositories` entry, a `Gemfile` `source`, or a Hex `repo:` or organisation. A scanned file could otherwise send requests to a host of its choosing and feed back a false license.
- **A license is read only from a structured field** of a response, never extracted from prose.
- **An off-registry dependency is never requested** (see [What leaves the process](#what-leaves-the-process)).

A license read from the metadata of another release is marked as an estimate and does not fail a scan by itself, so a license change between the two releases shows only as that mark. See [USAGE.md](USAGE.md#resolution-semantics).

The allowlist is hard-coded: a host is added only in a licenseal release, with security review. The two Maven fallback hosts are listed in `src/licenseal/resolvers/maven_central.py:_FALLBACK_POM_REGISTRIES`. Such a host must be run by a recognized vendor, be public-read, use the standard `/maven2/` layout, and serve a meaningful fraction of the open-source JVM artifacts that are not on Central.

The restriction is a `tethered.scope()` around resolution, and it is context-local: licenseal does not flip a process-wide switch on its host. If you embed it in an app that already calls `tethered.activate()` or wraps the call in an outer `tethered.scope()`, the effective policy is the **intersection** of all active policies. For a tamper-resistant ceiling, the host can use `tethered.activate(locked=True)`. The scope is propagated into the worker threads that resolve licenses and walk registries, so every registry request, including the deps.dev batch POSTs, is checked against the policy.

### What leaves the process

licenseal sends **only package coordinates and fixed registry-index requests**, plus a static client identifier. It never sends manifest or lockfile contents, file paths, the scanned project's name, environment variables, credentials, or telemetry; there is no licenseal-operated endpoint.

A dependency's **name and version** are sent to the public registries that the table above lists for its ecosystem. Two rules decide which dependencies are sent:

- **An off-registry dependency is never sent.** A dependency whose source is a git repository, a direct URL, or a path is reported as UNKNOWN with no network request under any name, and nothing is downloaded from its source. The guarantee holds for the source forms that [USAGE.md](USAGE.md#per-ecosystem-resolution-detail) lists for each ecosystem. It does not hold in two cases, where the package is looked up on the public registry by name:
  - a package redirected to git, a URL, or a path by a declaration that [USAGE.md](USAGE.md#off-registry-dependencies) lists as not read, when no lockfile that the scan reads records that source (`--no-transitive` reads no lockfile);
  - a Composer package from a version-control or `artifact` repository, or from a `path` repository the scan does not read, in a project scanned without its `composer.lock` (or with `--no-transitive`). `composer.json` names the repository but not the packages it provides, so their names are sent to Packagist like any other requirement, and the scan reports that `composer.json` as an analysis gap.
- **A package pinned to an alternate index or registry is sent to the public one**: a Poetry `source`, a uv index, a `Gemfile` `source` block, a Cargo `registry`, a private npm registry, a `+local` version from an internal mirror. licenseal does not query the alternate registry, so it looks the name up on the public registry and reports the public package's license. A private package that exists only on an internal registry therefore has its **name and version disclosed** to the public registry. It resolves to UNKNOWN when the public registry has no such package, or to the license of a public package of the same name when it has one.

The coordinates of a Java artifact that Maven Central does not serve, a private one included, are sent to `dl.google.com` and `repo.jenkins-ci.org` as well.

What a request carries:

- **Request payloads** are one of:
  - a fixed registry-index URL that carries no coordinates (the CRAN `PACKAGES` index);
  - a package-coordinate lookup: `name` and `version`, or `name` only for a latest-version or version-list lookup. A GET lookup puts them, with the scope or group, in the URL path;
  - the deps.dev batch POST body, exactly `{"versionKey": {"system", "name", "version"}}` per entry;
  - a metadata URL that the registry provided (the PEP 658 `.metadata` URL, whose path encodes only the wheel's name and version).
- **Headers** are static: `Accept`, and a `User-Agent` of `licenseal/<version> (<project-url>; <subcommand>)`, where `<subcommand>` is the literal CLI command (`check` / `init-review-file`), not user data.
- **No credentials are read or sent.** licenseal reads no `.npmrc`, `.pypirc`, or keyring, and sets no `Authorization` header. `~/.netrc` is never read (httpx 0.28 or newer does not read it implicitly, and licenseal does not opt in). Standard `HTTP(S)_PROXY` environment proxies are honored (httpx's `trust_env` default), so licenseal works behind a corporate egress proxy; the proxy sees only the requests described above.

An off-registry source is written to a report or a scaffolded review file with the user-info part of a URL and its query string removed, so a token embedded in a repository or download URL reaches neither file.

### Manual review file

`licenseal.review.toml` is a maintainer-approved override file. A malicious entry can mark a copyleft dependency as MIT and pass `licenseal check` in strict mode. Treat it as security-relevant:

- Require code review on every change to `licenseal.review.toml`.
- Give the reason for each entry in its `note` field.
- Re-validate entries periodically when their resolved versions change upstream.

`composer.lock` decides a license directly too: the `license` field an entry embeds is used without a Packagist request, so an edited entry changes the verdict for that package. Review changes to `composer.lock` the same way.

## Recommendations

For embedded use, the host's `tethered.activate(allow=[...])` allowlist must include licenseal's fourteen registry hosts: `pypi.org:443`, `files.pythonhosted.org:443`, `registry.npmjs.org:443`, `crates.io:443`, `api.deps.dev:443`, `proxy.golang.org:443`, `repo.maven.apache.org:443`, `dl.google.com:443`, `repo.jenkins-ci.org:443`, `api.nuget.org:443`, `repo.packagist.org:443`, `rubygems.org:443`, `hex.pm:443`, `cran.r-project.org:443`.
