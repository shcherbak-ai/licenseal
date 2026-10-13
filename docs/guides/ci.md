---
title: "Run it in CI"
description: "Add licenseal to a CI pipeline: the workflow, lockfiles, publishing the report, and adjusting the gate."
---

# Run it in CI

## GitHub Actions

```yaml
# .github/workflows/licenseal.yml
name: License compatibility
on: [push, pull_request]
jobs:
  licenseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: astral-sh/setup-uv@v10.3.0
      - run: uvx licenseal check
```

The job fails when the check fails: see [Fix a failing check](fix-a-failing-check.md). Any other CI system works the same way: run `uvx licenseal check` in the repository, with outbound HTTPS to the [registry hosts](../security/network.md). Package names and versions are sent to those hosts: see [What leaves the process](../security/data-sent.md).

## Commit your lockfiles

A manifest without an up-to-date lockfile is an [analysis gap](../concepts/check-failures.md#a-manifest-without-a-lockfile), and fails the check. Commit the lockfile, or pass `--no-require-lockfile` to accept versions estimated from the registry.

## Publish the report

```bash
licenseal check -f markdown -o LICENSES.md   # a Markdown audit, for a PR comment or the repository
licenseal check -f json -o report.json       # for tooling
```

The file is written even when findings or analysis gaps fail the check, so CI can publish it; the findings that failed the check are also printed to stderr. A later step has to run after a failed one to publish it. In GitHub Actions:

```yaml
      - run: uvx licenseal check -f markdown -o LICENSES.md
      - if: always()
        run: cat LICENSES.md >> "$GITHUB_STEP_SUMMARY"
```

The JSON format is described in the [JSON report](../reference/json-report.md) reference.

## Adjust the gate

- `--no-strict` stops warnings, unknown licenses, and analysis gaps from failing the check. Violations always fail.
- `--dev` also scans dev dependencies. It only adds rows. A violation on a dev dependency is reported as a warning, which still fails the check unless you pass `--no-strict`.

A finding that you have looked into is cleared with a [review](review-findings.md), not with a flag.

## Next

- [Claude Code skill](claude-code-skill.md)
- [Fix a failing check](fix-a-failing-check.md)
- [Review flagged dependencies](review-findings.md)
