---
title: "Network egress"
description: "The fourteen public registry hosts licenseal can contact, what each is asked, and the rules that hold for all of them."
---

# Network egress

Outbound network access is restricted to fourteen hosts:

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

The allowlist is hard-coded: a host is added only in a licenseal release, with security review. Every registry request, the deps.dev batch POSTs included, goes through one HTTP client. It refuses a request to a host and port outside the table, or over plain HTTP, before it opens a connection, and it follows no redirects. A refused request stops the scan with an error that names the host. The one other host licenseal connects to is a [proxy](#proxies) that the environment names.

In development, the test suite runs under [tethered](https://github.com/shcherbak-ai/tethered) with no host allowed, and scans of real repositories run under it with only these fourteen allowed, so a request to any other host fails the run.

A Maven fallback host (`dl.google.com`, `repo.jenkins-ci.org`) must be run by a recognized vendor, be public-read, use the standard `/maven2/` layout, and serve a meaningful fraction of the open-source JVM artifacts that are not on Central.

## Proxies

Registry requests go through the proxy that `HTTPS_PROXY` names, or `ALL_PROXY` when `HTTPS_PROXY` is not set. On Windows and macOS, when neither is set, they go through the proxy in the system's settings; a proxy auto-configuration (PAC) script is not read, so where the system's proxy comes from one, set `HTTPS_PROXY`. A registry host that `NO_PROXY` lists is reached directly, and `NO_PROXY=*` turns the proxy off; the system's list of exceptions is not read. `HTTP_PROXY` is not used: every registry is reached over HTTPS.

Through a proxy, the requests still name only the hosts above, and the allowlist checks the host each request names. The proxy sees only the requests listed under [What leaves the process](data-sent.md#what-a-request-carries).

## Rules for every host

- **No registry or source that a scanned file declares is contacted**: not a Maven `<repositories>` block, a `nuget.config` `<packageSources>` entry, a Composer `repositories` entry, a `Gemfile` `source`, or a Hex `repo:` or organisation. A scanned file could otherwise send requests to a host of its choosing and feed back a false license.
- **A license is read only from a structured field** of a response, never extracted from prose.
- **An off-registry dependency is never requested** (see [What leaves the process](data-sent.md#which-dependencies-are-sent)).

## Embedding licenseal

When licenseal runs inside another Python application, it changes nothing outside its own HTTP client: it installs no audit hook and turns on no process-wide policy.

An application that restricts its own egress, for example with tethered, must allow licenseal's fourteen registry hosts, each with its port as the table above writes it, and the [proxy](#proxies) when one is set. licenseal's worker threads run in copies of the calling thread's context, so a `tethered.scope()` that the application enters around the call holds in them too.
