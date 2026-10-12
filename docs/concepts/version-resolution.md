---
title: "Versions and estimates"
description: "Which version of a dependency licenseal reports, when a version or a license is an estimate, and what happens when a lookup fails."
---

# Versions and estimates

licenseal is a license resolver, not a dependency resolver: it does not resolve version conflicts between transitive requirements, and it does not model what a given environment would install. A [lockfile](dependency-resolution.md) gives the installed versions. Without one, the rules below decide which version is reported.

## Which version is reported

- Exact pins (`==2.28.1`, `18.2.0`) are reported at that exact version.
- An empty version constraint resolves to the registry's latest published release. A NuGet reference with no version, and a `pom.xml` dependency with no version that the parent chain does not manage either, are reported with no version and resolve to `UNKNOWN`.
- A range resolves to the highest published release inside it, read in the grammar of its ecosystem (PEP 440, npm, Cargo, RubyGems, Hex, Composer). A prerelease is selected only when the range admits prereleases; Python, like pip, also takes one when no release is inside the range. NuGet resolves as a restore does: a bare version or a range with an inclusive lower bound resolves to that bound, any other range to the lowest published release inside it, and a floating version (`1.*`) to the highest release it matches.
- Not resolved, and reported as `UNKNOWN` with no version: a constraint that is not written in its ecosystem's grammar; a range that no published version satisfies; a Composer branch constraint (`dev-main`); a Maven or Gradle version range, dynamic version, or `RELEASE` / `LATEST` marker (`[1.0,2.0)`, `1.+`, `latest.release`); a NuGet version holding an unresolved MSBuild property. None of these falls back to the latest release.
- Go and R have no range to resolve. `go.mod` names exact versions. A `DESCRIPTION` constraint other than `(== x)` is not evaluated: the CRAN index lists one version of each package, and that version is the one reported.

## Estimates

- **Estimated versions.** A version that licenseal picked from a registry is marked: `~1.2.3` in the table and Markdown formats, with a legend line under the table, and `"estimated": ["version"]` in JSON. That is every transitive row that does not come from a lockfile and every direct dependency declared with a range or with no constraint. A row a lockfile supplies, an exact pin, a Maven version the parent chain manages, and a Go version are not marked.
- **Estimated licenses.** A license read from metadata that describes another release than the reported one is marked `~MIT`, and `"license"` in the JSON `estimated` array. The mark is not a finding by itself, and the license is judged like any other: an estimated `GPL-3.0-only` in an MIT project is a violation. A license is an estimate where a registry does not serve it per release:
  - an R package pinned to a version other than the one the CRAN index lists;
  - a Hex package reported at a release other than the one published last;
  - a Python release that declares no license in its own PyPI metadata or wheel metadata, which takes the license of the project's latest release;
  - a Python release that PyPI does not have.

## Failed lookups and rate limits

- A registry lookup that cannot produce a license resolves that one dependency to `UNKNOWN` and the scan continues. Apart from the cases above, a failed lookup of a pinned release is never answered with the metadata of another release.
- **Rate limits.** hex.pm allows 100 unauthenticated API requests per minute, so a project with more than 100 Hex packages pauses until the limit resets (about a minute per further 100 packages); each pause is announced on stderr. The waiting is bounded: packages still rate limited when it ends resolve to `UNKNOWN`, and a `Warning:` that is not an [analysis gap](check-failures.md#analysis-gaps) gives their number. Requests to crates.io are spaced one second apart, which slows a Rust scan that has no `Cargo.lock`.
