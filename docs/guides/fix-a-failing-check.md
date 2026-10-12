---
title: "Fix a failing check"
description: "What to do when licenseal check fails: a violation, a warning, an unknown license, an analysis gap, a review entry that no longer matches, or a scan that could not run."
---

# Fix a failing check

`licenseal check` gives the reason for a failure under the table, in the **Details** and **Analysis gaps** sections, and on stderr. Find the symptom below.

## A violation (✗)

The dependency's license is incompatible with the project license. **Details** gives the reason.

- Look at the `Project license:` line above the table first. `Proprietary (assumed: …)` means licenseal found no license for your project: see [Project license](../concepts/project-license.md).
- Remove or replace the dependency. A transitive is indented under the direct dependency that pulls it in, which is the one to replace or upgrade.
- If the detected license is wrong, or you have a reason to accept it, record a [review](review-findings.md).

`--no-strict` does not let a violation pass.

## A warning (⚠)

The combination may be acceptable, but licenseal cannot tell. Most often it is a weak-copyleft dependency in a permissive project. Read the reason, decide, and record the decision as a [review](review-findings.md).

`--no-strict` lets every warning pass, together with unknown licenses and analysis gaps.

## An unknown license (`?`)

licenseal could not read or classify the license. **Details** says which of these it is:

| Cause | What to do |
| --- | --- |
| The registry gives no license for the package, or a value that is not a recognised license | Read the package's license yourself and record it as a [review](review-findings.md) |
| A source-available or use-restricted license (BUSL, SSPL, Elastic, …), which has no [risk level](../concepts/verdicts.md#risk-levels) | Read its terms and record a review |
| An [off-registry dependency](../concepts/off-registry.md): a git repository, a URL, or a path | [Review it by its source](review-findings.md#an-off-registry-dependency) |
| A version that did not resolve: a typo, or a range no release satisfies | Correct the declaration: see [Which version is reported](../concepts/version-resolution.md#which-version-is-reported) |
| A license list that can be read as a choice or as all applying | Confirm which holds and record it: see [License lists](../concepts/license-expressions.md#license-lists) |
| A registry lookup that failed or was rate limited | Run the scan again |

## An analysis gap

The scan could not read something, so dependencies may be missing from the report. Each gap is listed under **Analysis gaps** with its file and the reason. A gap cannot be reviewed.

- **A manifest without a lockfile.** Commit an up-to-date lockfile, or pass `--no-require-lockfile` to accept versions estimated from the registry.
- **A file that cannot be read or parsed.** Fix the file. If it is not part of your project (a sample, test data), [exclude its directory](../concepts/discovery.md#exclude-a-directory).
- Every kind of gap is listed under [Analysis gaps](../concepts/check-failures.md#analysis-gaps).

## A review entry that no longer matches

`Reviewed licenses did not match any resolved package versions` means that an entry of `licenseal.review.toml` matches no row of this scan, usually because an upgrade moved the dependency to another version. No report is written until the entry is corrected: see [After an upgrade](review-findings.md#after-an-upgrade).

## The scan could not run

`Could not resolve any of the … dependencies` means that every registry request failed: no network, a proxy or firewall that blocks the registries, or a registry outage. The job needs outbound HTTPS to the hosts listed under [Network egress](../security/network.md). The standard `HTTP(S)_PROXY` environment variables are honored.

## An error instead of a report

Exit code `1` with an `Error:` line on stderr and no report is an error, not a failed check: an invalid review file, say, or unreachable registries. Exit code `2` is a usage error: an unknown command or option, a value an option does not accept, or a combination the command rejects.

## A slow scan

A scan is slow when it has to ask a registry about each package in turn: a manifest without a lockfile, above all a Rust project without a `Cargo.lock`, and a project with more than 100 Hex packages. Commit the lockfiles. The limits are under [Failed lookups and rate limits](../concepts/version-resolution.md#failed-lookups-and-rate-limits).
