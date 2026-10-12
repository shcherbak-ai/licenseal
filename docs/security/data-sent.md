---
title: "What leaves the process"
description: "What licenseal sends to public registries, what it never sends, and when a private package's name is disclosed."
---

# What leaves the process

licenseal sends **only package coordinates (a name and a version) and fixed registry-index requests**, plus a static client identifier. It never sends manifest or lockfile contents, file paths, environment variables, credentials, or telemetry; there is no licenseal-operated endpoint. The scanned project's own name is sent only when a manifest lists the project among its own dependencies.

## What a request carries

- **Request payloads** are one of:
  - a fixed registry-index URL that carries no coordinates (the CRAN `PACKAGES` index);
  - a package-coordinate lookup: `name` and `version`, or `name` only for a latest-version or version-list lookup. A GET lookup puts them, with the scope or group, in the URL path;
  - the deps.dev batch POST body, exactly `{"versionKey": {"system", "name", "version"}}` per entry;
  - a metadata URL that the registry provided (the PEP 658 `.metadata` URL, whose path encodes only the wheel's name and version).
- **Headers** are static: `Accept`, and a `User-Agent` of `licenseal/<version> (<project-url>; <subcommand>)`, where `<project-url>` is the URL of licenseal's own repository and `<subcommand>` is the literal CLI command (`check` / `init-review-file`), not user data.
- **No credentials are read or sent.** licenseal reads no `.npmrc`, `.pypirc`, or keyring, and sets no `Authorization` header. `~/.netrc` is never read.
- **Proxies.** Standard `HTTP(S)_PROXY` environment proxies are honored, so licenseal works behind a corporate egress proxy; the proxy sees only the requests described above.

## Which dependencies are sent

A dependency's **name and version** are sent to the public registries that [Network egress](network.md) lists for its ecosystem. Two rules decide which dependencies are sent:

- **An off-registry dependency is never sent.** A dependency whose source is a git repository, a direct URL, or a path is reported as UNKNOWN with no network request under any name, and nothing is downloaded from its source. The guarantee holds for the source forms listed under *Off-registry dependencies* on each [ecosystem page](../ecosystems/index.md). It does not hold in two cases, where the package is looked up on the public registry by name:
  - a package redirected to git, a URL, or a path by a declaration that [Off-registry dependencies](../concepts/off-registry.md#what-is-not-read) lists as not read, when no lockfile that the scan reads records that source (`--no-transitive` reads no lockfile);
  - a Composer package from a version-control or `artifact` repository, or from a `path` repository the scan does not read, in a project scanned without its `composer.lock` (or with `--no-transitive`). `composer.json` names the repository but not the packages it provides, so their names are sent to Packagist like any other requirement, and the scan reports that `composer.json` as an [analysis gap](../concepts/check-failures.md#analysis-gaps).
- **A package pinned to an alternate index or registry is sent to the public one**: a Poetry `source`, a uv index, a `Gemfile` `source` block, a Cargo `registry`, a private npm registry, a `+local` version from an internal mirror. licenseal does not query the alternate registry, so it looks the name up on the public registry and reports the public package's license.

The coordinates of a Java artifact that Maven Central does not serve, a private one included, are sent to `dl.google.com` and `repo.jenkins-ci.org` as well.

## Private packages

A private package that exists only on an internal registry therefore has its **name and version disclosed** to the public registry. It resolves to UNKNOWN when the public registry has no such package, or to the license of a public package of the same name when it has one.

No option turns the registry lookup off, for one package or for all. If the name of an internal package must not reach a public registry, keep the manifests and lockfiles that list it out of the scan; [`--exclude-dirs`](../concepts/discovery.md#exclude-a-directory) skips a directory.

## Sources in reports

An off-registry source is written to a report or a scaffolded review file with the user-info part of a URL and its query string removed, so a token embedded in a repository or download URL reaches neither file.
