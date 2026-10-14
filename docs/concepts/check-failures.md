---
title: "What fails a check"
description: "Strict mode, flagged dependencies, analysis gaps, and manifests without a lockfile: what makes licenseal check exit non-zero."
---

# What fails a check

`licenseal check` exits non-zero when a dependency is **flagged** (a [violation, a warning, or an unknown license](verdicts.md)) or the scan has **analysis gaps**. That is **strict mode**, the default. A flagged dependency stops failing once it is [reviewed](../guides/review-findings.md).

`--no-strict` stops warnings, unknowns, and analysis gaps from failing the check. Violations always fail.

| Finding | Default (`--strict`) | `--no-strict` |
| --- | --- | --- |
| Violation | fails | fails |
| Warning | fails | passes |
| Unknown license | fails | passes |
| Analysis gap | fails | passes |
| Reviewed dependency | passes | passes |

What to do about each is in [Fix a failing check](../guides/fix-a-failing-check.md).

## When the scan cannot run

If every registry lookup fails and not one dependency resolves (no network, blocked egress, a registry-wide outage), `check` aborts with an error and a non-zero exit instead of reporting every dependency as `UNKNOWN`, with or without `--no-strict`. The hosts it has to reach are listed under [Network egress](../security/network.md).

## Analysis gaps

An **analysis gap** is something the scan could not read, so a dependency may be missing from the report. Each gap is a `Warning:` on stderr and is recorded in the report: an **Analysis gaps** section and a count on the summary line in the table and Markdown formats, `summary.gaps` and [`diagnostics`](../reference/json-diagnostics.md) in JSON. The kinds:

- a manifest or lockfile that cannot be read (permission or I/O error, or larger than 128 MiB), decoded, or parsed, and a directory that cannot be traversed;
- a value of a type its format does not allow (`"dependencies": []` in `package.json`): the value is ignored and the rest of the file is read;
- a lockfile that cannot be used: a format version licenseal does not read (`pnpm-lock.yaml` below `lockfileVersion` 6), no entry in a readable form, or merge-conflict markers.
    - The direct dependencies it would have covered are resolved through the registry instead.
    - These three checks are not made for `Cargo.lock`, `go.sum`, `packages.lock.json`, `project.assets.json`, `paket.lock`, or `rebar.lock`: an entry of one of those that cannot be read is skipped without a diagnostic;
- a reference to another file that is not followed:
    - an MSBuild `<Import>` or `go.work` `use` that is not a relative path;
    - a requirements `-r` include or setuptools `file:` directive that is a URL, is not a relative path, is not a file, or leaves the scanned directory;
- a package whose dependency list the registry did not return during a [registry walk](dependency-resolution.md): the package is reported, and what it requires may be missing. `--no-require-lockfile` does not waive this one;
- two ecosystem-specific cases: a `composer.json` with repositories and no `composer.lock` (see [PHP](../ecosystems/php.md)), and a `go.mod` below `go 1.17` with `go.sum` rows missing (see [Go](../ecosystems/go.md));
- a [manifest without a lockfile](#a-manifest-without-a-lockfile), described below.

## A manifest without a lockfile

A **manifest without a lockfile** is one that declares a direct dependency no lockfile covers. There is no lockfile, the lockfile does not list the dependency, or it lists it only at a version the declaration does not admit (the exact rule is under [Dependency resolution](dependency-resolution.md)).

- That dependency and everything under it are resolved through the registry, and the result is an [estimate](version-resolution.md#estimates) of what the project installs. An [off-registry dependency](off-registry.md) that no lockfile records counts too.
- With `--require-lockfile` (the default) the manifest is an analysis gap. With `--no-require-lockfile` it is listed under **Estimates** in the table and Markdown formats, has severity `estimate` in JSON `diagnostics`, and does not fail.
- Exempt, with no diagnostic:
    - Go;
    - `--no-transitive`;
    - a manifest whose only uncovered dependencies are dev dependencies in a scan without `--dev`;
    - a manifest of a tool with no lockfile format (Maven `pom.xml`, NuGet `packages.config`, an erlang.mk `Makefile`), whose rows are still marked as estimates where licenseal picked the version.

## Format versions and encodings

- A lockfile in a newer format version than licenseal was written for is read on a best-effort basis, with a `Warning:` that does not fail.
- A manifest or lockfile written as UTF-16 or UTF-32 with a byte-order mark is read in that encoding. A text, JSON, or YAML file that is not valid UTF-8 is read through a latin-1 fallback, with a `Warning:` that does not fail. A TOML file that is not valid UTF-8 is an analysis gap, and so is a text, JSON, YAML, or TOML file that holds NUL characters, as UTF-16 without a byte-order mark does.
