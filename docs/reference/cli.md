---
title: "CLI reference"
description: "Every licenseal command and option, with defaults and exit codes."
---

# CLI reference

```bash
licenseal check                 # scan the current project and exit non-zero when the check fails
licenseal init-review-file      # scaffold a licenseal.review.toml for flagged dependencies
licenseal install-skill         # install the Claude Code review skill into the project
licenseal --version             # print the version and exit
```

## `licenseal check`

| Flag | Default | Notes |
|---|---|---|
| `--path DIRECTORY`, `-p DIRECTORY` | `.` | Directory to scan (see [What is scanned](../concepts/discovery.md)) |
| `--format FMT`, `-f FMT` | `table` | `table`, `json`, or `markdown` |
| `--output FILE`, `-o FILE` | — | Write the report to FILE instead of stdout |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--strict / --no-strict` | `--strict` | Also fail on warnings, unknowns, and [analysis gaps](../concepts/check-failures.md#analysis-gaps) (violations always fail). See [What fails a check](../concepts/check-failures.md) |
| `--require-lockfile / --no-require-lockfile` | `--require-lockfile` | Whether a [manifest without a lockfile](../concepts/check-failures.md#a-manifest-without-a-lockfile) is an analysis gap. `--no-require-lockfile` accepts the estimated or incomplete result and reports it without failing. No effect with `--no-transitive`. |
| `--transitive / --no-transitive` | `--transitive` | Full-tree scan, or direct dependencies only |
| `--max-depth N` | `50` | Cap the depth of a registry walk (see [Dependency resolution](../concepts/dependency-resolution.md)), 1 to 100. A usage error with `--no-transitive` |
| `--max-workers N` | `16` | Concurrent registry requests, 1 to 32 |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery, beyond the [directories that are always skipped](../concepts/discovery.md#directories-that-are-skipped). Comma-separated, repeatable, relative to `--path` or absolute. A subdirectory with its own `.git` is skipped without it. |

Common invocations:

```bash
licenseal check                              # full-tree scan (default; lockfile-first, registry fallback)
licenseal check --no-transitive              # direct dependencies only (use when publishing a library)
licenseal check --dev                        # also include dev dependencies
licenseal check --no-strict                  # don't fail on warnings, unknowns, or analysis gaps (violations still fail)
licenseal check --no-require-lockfile        # no lockfile committed: accept versions and transitives estimated from the registry
licenseal check -f json -o report.json       # machine-readable output for CI tooling
licenseal check -f markdown -o LICENSES.md   # Markdown audit, suitable for a PR comment
licenseal check --exclude-dirs third_party,scratch  # skip subtrees not already in the default skip set
```

## `licenseal init-review-file`

| Flag | Default | Notes |
|---|---|---|
| `--path DIRECTORY`, `-p DIRECTORY` | `.` | Project directory, where `licenseal.review.toml` is written. Without `--from-report` it is scanned as `check` scans it by default |
| `--dev / --no-dev` | `--no-dev` | Include dev dependencies |
| `--from-report FILE` | — | Read [flagged](../concepts/check-failures.md) dependencies from a saved JSON report instead of scanning (no registry request). A usage error together with `--dev` / `--no-dev`, `--max-workers`, or `--exclude-dirs`, which only apply to a scan |
| `--merge` | — | Add new flagged entries to an existing review file; existing entries are kept. Without it, the command stops with an error rather than change an existing file |
| `--max-workers N` | `16` | Concurrent registry requests, 1 to 32 |
| `--exclude-dirs PATH[,PATH...]` | — | Skip subdirectories during discovery, as for `check` |

The workflow is in [Review flagged dependencies](../guides/review-findings.md).

## `licenseal install-skill`

| Flag | Default | Notes |
|---|---|---|
| `--path DIRECTORY`, `-p DIRECTORY` | `.` | Project directory to install into (`.claude/skills/`) |
| `--force` | — | Overwrite a hand-edited skill. An unedited earlier install is refreshed without it |

See [Claude Code skill](../guides/claude-code-skill.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The check passed, or the command did what it was asked |
| `1` | The check failed (see [What fails a check](../concepts/check-failures.md)), or the command ended with an error |
| `2` | A usage error: an unknown command or option, a value an option does not accept (a `--path` that is not a directory, `--max-workers 99`), or a combination the command rejects |

An error prints an `Error:` line on stderr and no report; a failed check prints the report. [Fix a failing check](../guides/fix-a-failing-check.md) covers both.

## Environment

The standard `HTTP(S)_PROXY` environment variables are honored: see [What leaves the process](../security/data-sent.md#what-a-request-carries).
