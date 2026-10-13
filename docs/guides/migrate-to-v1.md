---
title: "Migrate to 1.0.0"
description: "What to change in a project, its review file, its checked-in report, and its scripts when upgrading licenseal from 0.4.x to 1.0.0."
---

# Migrate to 1.0.0

licenseal 1.0.0 closes cases where a 0.4.x scan passed although it had missed dependencies, misread a license, or skipped a file without saying so. A check that passes on 0.4.2 can therefore fail on 1.0.0 with no change to the project. This page says what to do, in the order a first run brings it up. Every change is listed in the [changelog](../changelog.md).

## Before you upgrade

- **Python 3.11 or newer is required.** On Python 3.10, `pip` and `uv` keep installing 0.4.2.
- **`httpx` 0.28 or newer is required.** This matters only where licenseal shares an environment with packages that pin `httpx` lower, as it can when it is a dev dependency of the project. `uvx`, `uv tool install`, and `pipx` give licenseal an environment of its own.
- **`uvx licenseal check` runs the newest release**, so a CI job that calls it runs 1.0.0 from its next run. To stay on 0.4.2 until the project is migrated, pin the version: `uvx licenseal@0.4.2 check`, or `licenseal<1` where it is a project dependency.

## Run the check

```bash
licenseal check
```

The sections below are what a first run on 1.0.0 can bring up, in the order to deal with them.

### The review file is rejected

`check` stops with an `Error:` line and writes no report while `licenseal.review.toml` holds an entry it cannot apply. 1.0.0 rejects more entries than 0.4.x did.

**A `license` that names no license.** A typo (`MTI`), unpaired parentheses, and a comma- or slash-separated list are rejected. Correct the value, and join several licenses with `OR` or `AND`. What is accepted is under [Rules](../reference/review-file.md#rules).

**An entry for a dependency that is no longer flagged** (`Review entries can only override flagged dependencies`). Its license now resolves, or is now judged compatible. Delete the entry.

**An entry that matches no row** (`Reviewed licenses did not match any resolved package versions`). The dependency is now reported at another version, under another spelling of its name, or not at all:

- for Go, Java, npm, and Ruby, `package` must be spelled exactly as the report spells it, upper and lower case included;
- a Hex dependency that `mix.exs` renames is keyed on its hex.pm package name;
- a NuGet or RubyGems version is reported as the registry publishes it (`1.2.0` for `1.2`), and a pinned PyPI release that PyPI does not have is reported at the pinned version, no longer at the latest release;
- a dependency from git, a URL, or a path is keyed on its source: see [Git, URL, and path dependencies](#git-url-and-path-dependencies).

To find the new key of an unmatched entry, run `licenseal init-review-file --merge`. It adds an empty entry, keyed as 1.0.0 reports the row, for each flagged dependency that has none. Where the reviewed license still holds for that row, move `license` and `note` into the new entry; then delete the old one. [After an upgrade](review-findings.md#after-an-upgrade) has the rule for a version that changed.

### The project license reads `Proprietary`

The `Project license:` line, on stderr and above the table, names the license every dependency is judged against and the file it was read from. 1.0.0 reads it from a manifest in the scanned directory only; 0.4.x also took it from a nested package.

- When the line says `Proprietary (assumed: …)` and the project has a license, declare it in a [manifest of the scanned directory](../concepts/project-license.md#where-it-is-read-from), or scan the package that declares it with [`--path`](../concepts/discovery.md#monorepos).
- A declared value that is not a recognised license is checked as `Proprietary`, and a `Warning:` names the file and the value. So is an arm of a dual license that is not recognised (`AGPL-3.0-only OR Commercial`): copyleft dependencies of such a project, which used to pass, are violations.

### An analysis gap

- **A manifest without a lockfile** fails the check by default. Commit an up-to-date lockfile, or pass `--no-require-lockfile` to accept versions estimated from the registry. A lockfile that is behind its manifest counts, and so does a git, URL, or path dependency that no lockfile records. The rule and its exemptions are under [A manifest without a lockfile](../concepts/check-failures.md#a-manifest-without-a-lockfile).
- **A file that cannot be read** fails the check where 0.4.x skipped it or guessed: a TOML file that is not UTF-8, a `setup.py` that is not valid Python 3, a lockfile with merge-conflict markers, and the other kinds listed under [Analysis gaps](../concepts/check-failures.md#analysis-gaps). Fix the file, or [exclude its directory](../concepts/discovery.md#exclude-a-directory) when it is not part of the project.

### Git, URL, and path dependencies

An [off-registry dependency](../concepts/off-registry.md) is one `UNKNOWN` row, and no registry is asked about it. 0.4.x dropped some of these and looked others up on the public registry under the same name.

Review each one by its source. `licenseal init-review-file --merge` (without `--merge` when the project has no review file yet) scaffolds an entry with a `source` key. An older entry without that key no longer matches the row: delete it. See [An off-registry dependency](review-findings.md#an-off-registry-dependency).

### New findings

1.0.0 reports dependencies that 0.4.x missed and reads licenses more strictly, so a report can hold new flagged rows. Deal with each as with any other finding: see [Fix a failing check](fix-a-failing-check.md). The changelog lists the cases under [Dependencies that were missed are now reported](../changelog.md#dependencies-that-were-missed-are-now-reported) and [Stricter license reading](../changelog.md#stricter-license-reading).

A lockfile is read wherever it is found. When a sample or test-data lockfile adds rows to the report, [exclude its directory](../concepts/discovery.md#exclude-a-directory).

## After the check passes

- **A checked-in `LICENSES.md`.** Regenerate it with `licenseal check -f markdown -o LICENSES.md`: the header, the escaping, and the row layout changed.
- **A script that reads the JSON report.** No field was removed or renamed. `estimated`, `origin`, and `registry_name` are new on every dependency, and `project_license_source` at the top level. Three values a script may depend on changed: a deprecated GNU license ID is reported as its current one (`GPL-2.0` as `GPL-2.0-only`), `package_url` is empty for an off-registry dependency, and with `--no-require-lockfile` a diagnostic can have the severity `"estimate"`, which does not fail the check. The others are under [Report output](../changelog.md#report-output), and every field is in the [JSON report](../reference/json-report.md) reference.
- **The Claude Code skill.** When the project has the skill installed, `check` prints a reminder that it is out of date. Run `licenseal install-skill`, with `--force` to overwrite a skill you have edited.
- **A 0.4.2 pin** that you added before upgrading: remove it.
