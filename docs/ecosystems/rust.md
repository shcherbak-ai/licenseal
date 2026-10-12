---
title: "Rust"
description: "Rust: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# Rust

What licenseal reads in a Cargo project. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** crates.io
- **Manifests:** `Cargo.toml` (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[target.<cfg>.*]`, `[workspace.dependencies]` via `workspace = true` references)
- **Lockfiles:** `Cargo.lock`

## What is read

With a `Cargo.lock`, the locked graph is reported as it is.

## Dev dependencies

`[dev-dependencies]` are dev dependencies. `[build-dependencies]` are production.

## Off-registry dependencies

These are reported as [off-registry dependencies](../concepts/off-registry.md):

- a `git = …` dependency;
- a `path = …` the scan does not read;
- a crate that a `[patch]` or `[replace]` entry points at either.

## Not evaluated

- Without a `Cargo.lock`, the optional (feature-gated) dependencies of the crates the [registry walk](../concepts/dependency-resolution.md) visits.
- A path crate that `Cargo.lock` reaches only through another path crate the scan does not read is not reported.
- Cargo's `.cargo/config.toml` is not read: see [What is not read](../concepts/off-registry.md#what-is-not-read).

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Failed lookups and rate limits](../concepts/version-resolution.md#failed-lookups-and-rate-limits), for the pace of crates.io requests in a scan without a `Cargo.lock`
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
