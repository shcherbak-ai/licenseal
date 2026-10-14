---
title: "Dependency resolution"
description: "How licenseal finds the whole dependency tree: from the lockfile first, and from the registry where no lockfile covers a dependency."
---

# Dependency resolution

licenseal reports the whole dependency tree: what the manifests declare and everything those dependencies pull in. Resolution is **lockfile-first**:

<figure markdown>
![A declared dependency is looked for in a lockfile. When a lockfile covers it, the locked version and its dependencies are reported as they are. When none does, licenseal walks the registry, marks the versions it picks as estimates, and reports the manifest as an analysis gap, or as an estimate with --no-require-lockfile.](../assets/resolution-flow.svg)
</figure>

1. If a lockfile is present (see [Supported ecosystems](../ecosystems/index.md)), it is the source of truth.
    - A lockfile **covers** a direct dependency only when it holds that package at a version the declaration admits: `shared>=2` is covered by a locked `2.4.0`, not by a locked `1.0.0`. A locked version that cannot be compared with the declaration covers it too: a declaration with no constraint, a tag or a branch, and any range when the locked version is a prerelease. A declaration no lockfile covers is resolved through the registry (step 2).
    - A lockfile is read [wherever it is found](discovery.md#lockfiles-are-read-wherever-they-are-found) in the scanned tree.
2. When no lockfile covers a dependency, licenseal falls back to a **registry walk**: each dependency's per-version metadata is fetched, breadth-first and in parallel (`--max-workers`), down to `--max-depth`.
    - What the walk reports is an estimate: the versions are the ones the registries publish at scan time, not the ones the project installs. Every row it adds is marked as estimated (see [Versions and estimates](version-resolution.md)), and its manifest is a [manifest without a lockfile](check-failures.md#a-manifest-without-a-lockfile).
    - `--max-depth` (default 50) bounds the registry walks of Python, npm, Rust, PHP, Ruby, and Hex. It does not bound a lockfile's graph, the [deps.dev](../security/license-sources.md) graph of a Maven or Gradle dependency, or the NuGet `.nuspec` walk, which has its own limit of 32 levels. A walk that reaches the cap stops there; a `Warning:` says deeper dependencies may be missing, and it does not fail the check.

## Direct dependencies only

Transitive is the default. `--no-transitive` audits only the dependencies you declared directly: it takes no rows from a lockfile and reports no transitive.

## Production or dev

- A transitive is `prod` when a production dependency pulls it in, otherwise `dev` when a dev dependency does, otherwise not reported. A scan without `--dev` therefore leaves out what only dev dependencies pull in.
- A dependency declared as dev that a production dependency also pulls in is `prod`, and `--dev` adds rows without changing a `prod` row to `dev`.
- When a lockfile holds none of the direct dependencies found in the manifests, all its packages are reported, as `prod` unless the lockfile format records its own dev/prod split.

Which declarations count as dev is listed on each [ecosystem page](../ecosystems/index.md). What a dev dependency does to a verdict is under [How licenseal decides](verdicts.md#dev-dependencies).
