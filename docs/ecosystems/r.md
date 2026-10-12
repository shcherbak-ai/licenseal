---
title: "R"
description: "R: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# R

What licenseal reads in an R package. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** CRAN (`PACKAGES` index)
- **Manifests:** `DESCRIPTION`
- **Lockfiles:** `renv.lock`, `packrat/packrat.lock`

## What is read

- `Imports`, `Depends`, and `LinkingTo` in `DESCRIPTION` are read as production.
- R's license grammar (`GPL (>= 2)`, `MIT + file LICENSE`) is translated to SPDX; a bare `file LICENSE` is `UNKNOWN`. See [License expressions](../concepts/license-expressions.md#r-file-license).

## Dev dependencies

`Suggests` and `Enhances` in `DESCRIPTION` are dev dependencies.

## Off-registry dependencies

These are reported as [off-registry dependencies](../concepts/off-registry.md):

- a lockfile package from GitHub, GitLab, Bitbucket, git, a URL, a local path, or Bioconductor;
- a package named by the `Remotes` field of `DESCRIPTION`.

## Not evaluated

The license of a version other than the current one. The CRAN index lists the current version of each package only, so a package pinned to another version is reported at the pinned version with the license of the current one, marked as an [estimate](../concepts/version-resolution.md#estimates).

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
