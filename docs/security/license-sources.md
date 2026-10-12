---
title: "License sources"
description: "For each registry host: when it is asked, which field a license is read from, and when the license is an estimate."
---

# License sources

This page says when each host of the [allowlist](network.md) is asked, and where its answer holds the license.

- `pypi.org`: a release's license is read from that release's own JSON, then from its wheel metadata on `files.pythonhosted.org`, and only then from the project's latest release, which the report marks as an estimate. A release that PyPI answers `404` for (a build from another index, a `+local` version) takes the license of a release PyPI does have, marked as an estimate. A lookup that fails any other way is not answered from another release.
- `registry.npmjs.org`: the license of an npm package that the deps.dev batch does not answer, from the `license` field, or from the legacy `licenses` array when there is none.
- `crates.io`: the license of a crate that the deps.dev batch does not answer, from the `license` field of the version. Direct requests are serialized at one per second.
- `api.deps.dev`: the only license source for Go, so a miss there is UNKNOWN; for the other six ecosystems a miss falls through to the ecosystem's own registry. Three requests:
  - `POST /v3alpha/versionbatch` with up to 100 `{system, name, version}` entries per request, for Go, Python (`PYPI`), npm (`NPM`), Rust (`CARGO`), Java (`MAVEN`), .NET (`NUGET`), and Ruby (`RUBYGEMS`) packages;
  - `GET /v3/systems/{system}/packages/{name}/versions/{version}` for one package version, as a fallback;
  - for Java only, `GET /v3/systems/MAVEN/packages/{name}/versions/{version}:dependencies`, the resolved dependency graph of each direct Maven or Gradle dependency that no `gradle.lockfile` covers.
- `proxy.golang.org`: no license is read from it. It gives the `go.mod` of a module version, for the module's requirements.
- `repo.maven.apache.org`: the license of every Java dependency that the deps.dev batch does not answer, and the parent and BOM POMs that manage a `pom.xml` dependency's version. A version list is read only to find the latest release of a Gradle coordinate declared with no version. `dl.google.com` and then `repo.jenkins-ci.org` are asked whenever Central gives no usable answer for a POM or a version list.
- `api.nuget.org`: the license of every .NET dependency that the deps.dev batch does not answer, and the dependency graph when no lockfile covers a reference. The license is the `.nuspec`'s `<license type="expression">`, or a legacy `<licenseUrl>` looked up in a table of known license URLs. A version list is requested only to resolve a range with no inclusive lower bound, or a floating version.
- `repo.packagist.org`: asked when no `composer.lock` entry carries the package's license, which is then the `license` array of the version's entry.
- `rubygems.org`: the license of a gem that the deps.dev batch does not answer, from the `licenses` array.
- `hex.pm`: the license is the `meta.licenses` array of the package response, which also holds the package's links and the version and publication time of each release. hex.pm keeps that array per package and overwrites it each time a release is published, so for a release other than the one published last the license is marked as an estimate. No credentials are sent to raise hex.pm's rate limit, and a package still rate limited when the bounded wait ends is UNKNOWN (see [Versions and estimates](../concepts/version-resolution.md#failed-lookups-and-rate-limits)).
- `cran.r-project.org`: the index holds the `License` and the dependencies (`Imports` / `Depends` / `LinkingTo` / `Suggests` / `Enhances`) of every current source package. Every R package is resolved locally from it, with no per-package request and no community mirror. It lists current versions only: a package pinned to another version is reported at its pinned version with the current license, marked as an estimate, and a package the index does not list (archived, or from Bioconductor or GitHub) is UNKNOWN. `License` is translated from R's grammar (`GPL (>= 2)`, `MIT + file LICENSE`) to SPDX; a bare `file LICENSE` is UNKNOWN.

A license read from the metadata of another release is marked as an estimate and does not fail a scan by itself, so a license change between the two releases shows only as that mark. See [Versions and estimates](../concepts/version-resolution.md#estimates). How a license string is then read is under [License expressions](../concepts/license-expressions.md).
