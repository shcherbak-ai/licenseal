---
title: "Supported ecosystems"
description: "The ten ecosystems licenseal scans, with the registry, manifest files and lockfiles read for each."
---

# Supported ecosystems

One scan covers every ecosystem found under the scanned directory.

| Language | Registry | Manifest files | Lockfiles |
| --- | --- | --- | --- |
| [Python](python.md) | PyPI | `pyproject.toml` (PEP 621, PEP 735, Poetry), `requirements*.txt`, `setup.cfg`, `setup.py`, `Pipfile` | `uv.lock`, `poetry.lock`, `Pipfile.lock` |
| [JavaScript / TypeScript](npm.md) | npm | `package.json` (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`) | `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` |
| [Rust](rust.md) | crates.io | `Cargo.toml` (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[target.<cfg>.*]`, `[workspace.dependencies]` via `workspace = true` references) | `Cargo.lock` |
| [Go](go.md) | deps.dev, Go module proxy | `go.mod` (`require`, `replace`, `tool` directive) | `go.sum` |
| [Java / JVM](java.md) | Maven Central | Maven `pom.xml`; Gradle `build.gradle`, `build.gradle.kts` | `gradle.lockfile` |
| [.NET](dotnet.md) | NuGet.org | `.csproj` / `.fsproj` / `.vbproj`, `packages.config`, `Directory.Packages.props`, `Directory.Build.props` / `.targets`, `paket.dependencies` | `packages.lock.json`, `project.assets.json`, `paket.lock` |
| [PHP](php.md) | Packagist | `composer.json` | `composer.lock` |
| [Ruby](ruby.md) | RubyGems | `Gemfile`, `*.gemspec` | `Gemfile.lock` |
| [Elixir / Erlang](hex.md) | Hex | `mix.exs`, `rebar.config`, erlang.mk `Makefile` | `mix.lock`, `rebar.lock` |
| [R](r.md) | CRAN | `DESCRIPTION` | `renv.lock`, `packrat/packrat.lock` |

Each page says which dependencies are dev and which are [off-registry](../concepts/off-registry.md), and, for every ecosystem but Ruby and Elixir / Erlang, what is read beyond these files and what is not evaluated.

- Every host that is asked, the deps.dev license index among them, is listed under [Network egress](../security/network.md).
- Which directories are read, which are skipped, and how to exclude one is under [What is scanned](../concepts/discovery.md).
