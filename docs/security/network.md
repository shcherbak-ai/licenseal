---
title: "Network egress"
description: "The fourteen public registry hosts licenseal can contact, what each is asked, and the rules that hold for all of them."
---

# Network egress

Outbound network access is restricted to fourteen hosts by [`tethered`](https://github.com/shcherbak-ai/tethered), an egress allowlist applied to every registry request:

| Host | Registry (operator) | What is requested | Used for |
| --- | --- | --- | --- |
| `pypi.org:443` | PyPI (Python Software Foundation) | `/pypi/{name}/{version}/json` for a release; `/pypi/{name}/json` for the project's latest release | Python packages |
| `files.pythonhosted.org:443` | PyPI's file host (same operator) | A wheel's PEP 658 `.metadata` file; the wheel itself is never downloaded | A Python license, when PyPI's JSON carries no usable one |
| `registry.npmjs.org:443` | npm registry | Package metadata, by name or by name and version | npm packages |
| `crates.io:443` | crates.io | Crate metadata, by name or by name and version | Rust crates |
| `api.deps.dev:443` | deps.dev (Google) | Three requests, listed under [License sources](license-sources.md) | Licenses of Go, Python, npm, Rust, Java, .NET, and Ruby packages; Java dependency graphs |
| `proxy.golang.org:443` | Go module proxy | A module version's `go.mod` | The requirements of Go modules |
| `repo.maven.apache.org:443` | Maven Central (Sonatype) | POM XML and `maven-metadata.xml` version lists in the standard `/maven2/` layout | Java packages |
| `dl.google.com:443` | Google Android Maven (Google) | The same files under `/dl/android/maven2/` | Java packages that Maven Central has no usable answer for |
| `repo.jenkins-ci.org:443` | Jenkins Project public repository (Continuous Delivery Foundation) | The same files under `/public/` | The same, asked after `dl.google.com` |
| `api.nuget.org:443` | NuGet.org (.NET Foundation, Microsoft) | `/v3-flatcontainer/{id}/{version}/{id}.nuspec`; `/v3-flatcontainer/{id}/index.json` for a version list | .NET packages |
| `repo.packagist.org:443` | Packagist | `/p2/{vendor}/{package}.json`, a package's version history | PHP packages; the only network source for them |
| `rubygems.org:443` | RubyGems.org (Ruby Central) | `/api/v2/rubygems/{name}/versions/{version}.json`; `/api/v1/gems/{name}.json` for the latest version; `/api/v1/versions/{name}.json` for a version list | Ruby gems |
| `hex.pm:443` | Hex.pm | `/api/packages/{name}`; `/api/packages/{name}/releases/{version}` for a release's dependencies | Elixir and Erlang packages; the only source for them |
| `cran.r-project.org:443` | CRAN | `/src/contrib/PACKAGES`, once per scan | R packages; the only source for them |

How each host's answer becomes a license is in [License sources](license-sources.md).

## The allowlist

The allowlist is hard-coded: a host is added only in a licenseal release, with security review. It is enforced inside the licenseal process, and a request to any other host is blocked. The restriction is a `tethered.scope()` around resolution, and the scope is propagated into the worker threads that resolve licenses and walk registries, so every registry request, including the deps.dev batch POSTs, is checked against the policy.

A Maven fallback host (`dl.google.com`, `repo.jenkins-ci.org`) must be run by a recognized vendor, be public-read, use the standard `/maven2/` layout, and serve a meaningful fraction of the open-source JVM artifacts that are not on Central.

## Rules for every host

- **No registry or source that a scanned file declares is contacted**: not a Maven `<repositories>` block, a `nuget.config` `<packageSources>` entry, a Composer `repositories` entry, a `Gemfile` `source`, or a Hex `repo:` or organisation. A scanned file could otherwise send requests to a host of its choosing and feed back a false license.
- **A license is read only from a structured field** of a response, never extracted from prose.
- **An off-registry dependency is never requested** (see [What leaves the process](data-sent.md#which-dependencies-are-sent)).

## Embedding licenseal

When licenseal runs inside another Python application, the scope is context-local: licenseal does not flip a process-wide switch on the application that embeds it. If that application already calls `tethered.activate()` or wraps the call in an outer `tethered.scope()`, the effective policy is the **intersection** of all active policies. For a tamper-resistant ceiling, the embedding application can use `tethered.activate(locked=True)`.

For embedded use, the embedding application's `tethered.activate(allow=[...])` allowlist must include licenseal's fourteen registry hosts, each with its port as the table above writes it.
