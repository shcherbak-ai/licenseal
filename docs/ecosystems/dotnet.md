---
title: ".NET"
description: ".NET: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# .NET

What licenseal reads in a .NET project. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** NuGet.org (the `.nuspec` of a package) and [deps.dev](../security/license-sources.md); Paket dependencies are looked up on `api.nuget.org` too
- **Manifests:** `.csproj` / `.fsproj` / `.vbproj`, `packages.config`, `Directory.Packages.props`, `Directory.Build.props` / `.targets`, `paket.dependencies`
- **Lockfiles:** `packages.lock.json`, `project.assets.json`, `paket.lock`

## What is read

- A `<PackageVersion>` of Central Package Management is read as the version of a versionless `<PackageReference>`, and `$(Property)` version tokens are expanded from the project file and the `Directory.Build` files above it.
- References in every branch of a `<Choose>` block are included, and the graphs of all target frameworks are merged, so a dependency of one framework only is still reported.
- `<Import>` chains in `Directory.Build` files are followed for relative paths only.
- A package whose ID is that of a project in the scanned tree is not reported.

## Dev dependencies

These count as dev dependencies:

- a reference with `PrivateAssets="all"`;
- a reference with a `Condition`, on itself or on its `<ItemGroup>`, that is a Debug / Test configuration or `IsTestProject` comparison;
- a `<GlobalPackageReference>`;
- a package of a Paket group named `Test`, `Build`, or `Tools`, or whose name ends in `test`.

## Off-registry dependencies

A `<ProjectReference>` to a project the scan does not read is reported as an [off-registry dependency](../concepts/off-registry.md) (one it reads is the project's own code).

## Not evaluated

- `<Choose>` conditions.
- A `.nuspec` license given as a file (`<license type="file">`), which is not read.
- `nuget.config` `<packageSources>`: no NuGet source other than `api.nuget.org` is queried.
- A project file's own `<Import>`.
- A `<ProjectReference>` declared in a `Directory.Build` file.
- Paket `git`, `github`, `gist`, and `http` sources.
- Without a lockfile, the walk of each package's `.nuspec` dependencies reports every version it reaches and does not unify them as a restore would.

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
