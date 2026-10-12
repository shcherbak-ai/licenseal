---
title: "What is scanned"
description: "Which directory licenseal scans, the directories it skips, how to exclude one, and how to scan one package of a monorepo."
---

# What is scanned

`licenseal check` scans the directory given with `--path` (the current directory by default) and every directory below it. One scan covers every [ecosystem](../ecosystems/index.md) found there; each ecosystem page lists the manifests and lockfiles that are read.

## Directories that are skipped

These directory names are skipped at every depth, in every ecosystem:

- **VCS / caches**: `.git`, `.tox`, `.nox`, `__pycache__`, `node_modules`
- **Sample / fixture trees**: `examples`, `fixtures`, `__fixtures__`
- **Build / dist / vendoring outputs**: `build`, `dist`, `target`, `.eggs`, `site-packages`, `vendor`, `__pypackages__`, `.pdm-build`
- **JS framework build outputs & legacy package-manager trees**: `.next`, `.nuxt`, `.svelte-kit`, `.yarn`, `bower_components`, `jspm_packages`

A virtualenv (any directory holding `pyvenv.cfg`) is skipped whatever its name. A subdirectory with its own `.git` (file or directory) is skipped: cloned dependencies, vendored forks, and submodules are separate projects. A symlinked directory is not entered.

## Exclude a directory

Use `--exclude-dirs` for any other subtree. It takes a comma-separated list, can be repeated, and a path is relative to `--path` or absolute:

```bash
licenseal check --exclude-dirs third_party,scratch
```

A path dependency that points into a skipped or excluded directory is reported as an [off-registry dependency](off-registry.md#path-dependencies).

## Lockfiles are read wherever they are found

A lockfile is read wherever it is found in the scanned tree, with or without a manifest beside it. A sample or test-data lockfile outside the skipped directories therefore adds its packages to the report; exclude its directory with `--exclude-dirs`. Two npm exceptions: a lockfile under a directory named `test` or `tests` is not read, and when one directory holds several npm lockfiles only the first of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` is read.

## Monorepos

Scan the repository root. The manifests of every package below it are read, and every dependency is judged against one [project license](project-license.md), which is read from the root only.

To check one package against its own license, scan it with `--path`:

```bash
licenseal check --path packages/api
```

A lockfile above the scanned directory is not read. When the package's lockfile is at the repository root, its manifest is a [manifest without a lockfile](check-failures.md#a-manifest-without-a-lockfile) in that scan: pass `--no-require-lockfile` to accept versions estimated from the registry.

## Files outside the scanned directory

Two references are followed out of the scanned directory, and only when they are relative paths: an MSBuild `<Import>` in a `Directory.Build` file, and a `go.work` `use` directory. See the [security model](../security/index.md#manifests-and-registries-only).
