---
title: "JavaScript and TypeScript"
description: "JavaScript and TypeScript: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# JavaScript and TypeScript

What licenseal reads in an npm project. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** npm
- **Manifests:** `package.json` (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`)
- **Lockfiles:** `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`

## What is read

- `peerDependencies` and `optionalDependencies` are read as production, like `dependencies`.
- A package installed under an npm alias is reported under its real name.
- A package that another `package.json` in the tree defines (a monorepo or pnpm workspace member) is not reported; a stderr line says how many were excluded.

## Dev dependencies

`devDependencies` are dev dependencies.

## Off-registry dependencies

These are reported as [off-registry dependencies](../concepts/off-registry.md), in `package.json` and in every lockfile format:

- a git URL;
- a hosting shorthand (`github:user/repo`, a bare `user/repo`);
- a tarball URL;
- a `file:` / `link:` / `portal:` or bare path (`../pkg`, `C:\pkg`, `pkg-1.0.0.tgz`) the scan does not read.

One exception: a lockfile's `resolved` tarball URL in the layout registries serve (`<host>/<name>/-/<file>.tgz`, on any host) is a package of another registry, looked up on registry.npmjs.org.

## Not evaluated

- `engines`.
- `overrides`, Yarn `resolutions`, and pnpm `overrides` in `package.json` are not read: see [What is not read](../concepts/off-registry.md#what-is-not-read).

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [What is scanned](../concepts/discovery.md#lockfiles-are-read-wherever-they-are-found), for which npm lockfile is read when a directory holds several
- [Alternate registries](../concepts/off-registry.md#alternate-registries), for a package from a private npm registry
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
