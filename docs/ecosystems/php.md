---
title: "PHP"
description: "PHP: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# PHP

What licenseal reads in a Composer project. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** Packagist, asked only for what `composer.lock` does not give
- **Manifests:** `composer.json`
- **Lockfiles:** `composer.lock`

## What is read

- The license of a locked package is read from the `license` field of its `composer.lock` entry, and from Packagist when the entry has none or there is no lockfile.
- A locked or exact version Packagist does not list resolves to `UNKNOWN`, never to the license of another release.
- Platform packages (names without a `/`: `php`, `ext-*`, `lib-*`, `hhvm`) are not reported.

## Dev dependencies

`require-dev` in `composer.json`, and `packages-dev` in `composer.lock`, are dev dependencies.

## Off-registry dependencies

These are read from `composer.lock` and reported as [off-registry dependencies](../concepts/off-registry.md):

- a path package the scan does not read;
- a package that comes from a version-control, `package`, or `artifact` repository declared in `composer.json`.

In a `composer.lock` with no `composer.json` beside it, only path packages and `artifact` archives are off-registry.

## Not evaluated

Without a `composer.lock`, licenseal cannot tell which packages a version-control or `artifact` repository provides. They are looked up on Packagist by name and the `composer.json` is an [analysis gap](../concepts/check-failures.md#analysis-gaps); scanning with the `composer.lock` removes it.

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Files that decide a verdict](../security/index.md#files-that-decide-a-verdict), for the weight a `composer.lock` entry carries
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
