---
title: "Go"
description: "Go: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# Go

What licenseal reads in a Go module. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** [deps.dev](../security/license-sources.md) for licenses, proxy.golang.org for a module's requirements
- **Manifests:** `go.mod` (`require`, `replace`, `tool` directive)
- **Lockfiles:** `go.sum`

## What is read

- With a `go.sum`, the report holds its modules plus every `go.mod` requirement at the required version; no version is chosen among `go.sum` rows, so a row for another version of a module stays in the report.
- `replace` directives of the scanned `go.mod` are applied: a requirement replaced by another module is scanned as that module. So are the `replace` directives of a `go.work` in the scanned directory, for the modules it lists with `use`; they override those modules' own.
- `go.work` `use` directories are followed only when they are relative paths.

## Dev dependencies

Only a module named by a `tool` directive (Go 1.24+) is a dev dependency, unless a production module also requires it. `// indirect` is not a dev marker, and test-only requirements cannot be told from production ones.

## Off-registry dependencies

A requirement replaced by a local path the scan does not read is reported as an [off-registry dependency](../concepts/off-registry.md) (one it reads is the project's own code). A path written in `go.work` is relative to `go.work`.

## Not evaluated

- `replace` directives in a dependency's `go.mod`, and a `go.work` below the scanned directory.
- A `go.mod` with a `go` directive below 1.17, or none, lists direct requirements only: when one of them has no `go.sum` row, what it depends on is missing and the `go.mod` is an [analysis gap](../concepts/check-failures.md#analysis-gaps); committing an up-to-date `go.sum` removes it.

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
