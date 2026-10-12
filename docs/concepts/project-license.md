---
title: "Project license"
description: "Where licenseal reads your project's own license from, and what it assumes when it finds none."
---

# Project license

Every verdict compares a dependency's license with the project's own. licenseal reads the project license from the manifests in the scanned directory (`--path`), never from a subdirectory.

## Where it is read from

- The first manifest that declares a license decides, in this order: `pyproject.toml`, `setup.cfg`, `setup.py`, `package.json`, `Cargo.toml`, `pom.xml`, `.csproj` / `.fsproj` / `.vbproj`, `Directory.Build.props`, `composer.json`, `*.gemspec`, `mix.exs`, `DESCRIPTION`. When manifests there declare different licenses, a `Warning:` names each file and its value; it does not fail the check.
- `check`, and `init-review-file` when it scans, print the value and its file on stderr (`Project license: MIT (from pyproject.toml).`). The table and Markdown reports show the same, and JSON carries the file as `project_license_source`.

## When no license is found

- When no manifest in the scanned directory declares a license, the project is checked as `Proprietary` (a closed-source project can use permissive dependencies but not copyleft ones), and the stderr line and the reports say the license is assumed.
- A declared value that is not a recognised license (`"license": "-"`, a sentence) is not used: the project is checked as `Proprietary`, and a `Warning:` names the file and the value; it does not fail the check.

No option sets the project license. A project whose manifests are not in the list above (a Go module, a Gradle build, a `Gemfile` without a gemspec) is therefore checked as `Proprietary`. How a `Proprietary` project is judged is under [How licenseal decides](verdicts.md#the-matrix).

## A dual-licensed project

With a top-level `OR` in the project's own license, a dependency has to be compatible with each arm, and an arm licenseal does not recognize is judged as `Proprietary`.

## One package of a monorepo

To check one package of a monorepo against its own license, scan it with `--path`: see [Monorepos](discovery.md#monorepos).
