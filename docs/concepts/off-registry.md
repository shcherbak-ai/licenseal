---
title: "Off-registry dependencies"
description: "How licenseal reports a dependency that comes from a git repository, a URL, or a path instead of a package registry."
---

# Off-registry dependencies

An **off-registry dependency** is one whose source is a **git repository**, a **direct URL** (a wheel, an sdist, a tarball), or a **path the scan does not read**: it does not come from a package registry. One policy applies in every ecosystem. Which declarations are off-registry is listed on each [ecosystem page](../ecosystems/index.md).

## How it is reported

- It is reported as one row whose license is `UNKNOWN`. No registry request is made for it under any name, and nothing is downloaded: a registry package of the same name is a different package. The row fails [strict mode](check-failures.md) until it is reviewed.
- Its JSON `origin` field names the source, as specific as the files allow: `git+<url>@<commit>` when a lockfile records the commit, otherwise `git+<url>@<ref>` or `git+<url>`; `<url>#<hash>` or `<url>` for a direct URL; a path as written; the lockfile's own source label (`Bioconductor`) or `unrecorded source` when the files record no location. Credentials in a URL are removed.
- A name that one manifest takes from a registry and another from a repository, or that two manifests take from two repositories, is one row per source: a lockfile entry [covers](dependency-resolution.md) only a declaration from its own source (one repository whatever the commit, one URL, one path).
- When a lockfile records the registry packages an off-registry dependency pulls in, those are reported and name it in `direct_ancestors`. Without a lockfile that records it, what an off-registry dependency itself depends on is not reported, and the manifest that declares it is a [manifest without a lockfile](check-failures.md#a-manifest-without-a-lockfile). A Mix `path:` dependency and a .NET project reference are exempt when their lockfile is present.

To clear such a row, review it by its source: see [Review flagged dependencies](../guides/review-findings.md#an-off-registry-dependency).

## Path dependencies

A path dependency is the project's own code only when **the scan reads it**: the path is a directory inside the scanned directory that discovery does not skip. It is then not reported, and its manifests are scanned like any other. Every other path is a row: a path outside the scanned directory, an archive file (a wheel, a tarball, a JAR), and a directory the scan skips (`vendor/`, a nested repository, an `--exclude-dirs` path). The skipped directories are listed under [What is scanned](discovery.md#directories-that-are-skipped).

## What is not read

These declarations are not read: npm `overrides`, Yarn `resolutions`, and pnpm `overrides` in `package.json`; `[tool.uv]` `override-dependencies` and `constraint-dependencies`; a Maven `system` scope that a `<dependencyManagement>` entry supplies; Cargo's `.cargo/config.toml`. A package these redirect to another source is looked up on the registry under its name, unless a lockfile the scan reads records a git, URL, or path source for it (`--no-transitive` reads no lockfile).

## Alternate registries

An **alternate index or registry** is not an off-registry source. A package pinned to a Poetry `source`, a uv index, a `Gemfile` `source` block, a Cargo `registry`, or a private npm registry is looked up on the public registry under the same name, and the license of the public package is what is reported (see [What leaves the process](../security/data-sent.md#which-dependencies-are-sent)).
