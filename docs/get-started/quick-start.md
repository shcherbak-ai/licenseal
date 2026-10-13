---
title: "Quick start"
description: "Run a first licenseal scan, install the command, and learn what makes the check fail."
---

# Quick start

## Run a scan

In your project's directory:

```bash
uvx licenseal check
```

[`uvx`](https://docs.astral.sh/uv/) runs licenseal without installing it. licenseal reads the manifests and lockfiles under the directory (`pyproject.toml`, `package-lock.json`, and the like), looks up dependency licenses in public registry metadata, and prints a [report](read-the-report.md). It needs Python 3.11 or newer and outbound HTTPS to the [registries](../security/network.md).

> [!NOTE]
> **Private packages.** A package that comes from a private registry is looked up by name on the public one too, which discloses its name and version. If your project has internal packages, read [What leaves the process](../security/data-sent.md#private-packages) first.

## Install it

```bash
uv tool install licenseal    # or: pipx install licenseal
```

In a Python project, it can be a dev dependency instead:

```bash
uv add --dev licenseal       # or: pip install licenseal
```

Then run `licenseal check` (`uv run licenseal check` when it is a project dependency).

## When the check fails

The exit code is non-zero when a dependency is [flagged](../concepts/check-failures.md) (a [violation, a warning, or an unknown license](../concepts/verdicts.md) that nobody has [reviewed](../guides/review-findings.md)) or the scan has analysis gaps (something it could not read).

The most common first failure is a manifest without an up-to-date lockfile. Commit the lockfile, or pass `--no-require-lockfile` to accept versions [estimated](../concepts/version-resolution.md#estimates) from the registry. For every other failure, see [Fix a failing check](../guides/fix-a-failing-check.md).

## Defaults

- The whole dependency tree is scanned, without dev dependencies. `--no-transitive` scans direct dependencies only; `--dev` adds dev dependencies.
- Violations always fail. Warnings, unknown licenses, and analysis gaps fail too, unless you pass `--no-strict`.
- The project license is read from a manifest in the scanned directory, never from a nested package. If that does not give a recognised license, the project is checked as `Proprietary`: permissive dependencies pass, copyleft ones are flagged ([details](../concepts/project-license.md)).

The full rule is in [What fails a check](../concepts/check-failures.md), and every option in the [CLI reference](../reference/cli.md).

## Next

- [Read the report](read-the-report.md)
- [Run it in CI](../guides/ci.md)
- [Review flagged dependencies](../guides/review-findings.md)
