---
title: "Read the report"
description: "What each column of the licenseal report shows, what is printed under the table, what to do about a flagged row, and how to write the report to a file."
---

# Read the report

<figure markdown>
![licenseal report for an illustrative MIT project: client, transport and parser are compatible; certs, brought in through client under GPL-3.0-only, is a violation. Summary: 1 violation, 3 ok.](../assets/licenseal-report.svg)
<figcaption>Illustrative packages. The report is licenseal's own output.</figcaption>
</figure>

`licenseal check` prints a table. `-f markdown` and `-f json` give the same report as Markdown or as [JSON](../reference/json-report.md).

A line above the table names the [project license](../concepts/project-license.md) that every row is judged against, and the file it was read from. `Proprietary (assumed: …)` means that licenseal found no license for the project.

## The table

| Column | What it shows |
| --- | --- |
| Package | The package and the version that was checked. A transitive dependency is indented under the direct dependency that pulls it in |
| Ecosystem | `python`, `npm`, `rust`, `go`, `java`, `dotnet`, `php`, `ruby`, `hex`, or `r` |
| Group | `prod` or `dev` |
| Source | The manifest that declares a direct dependency. Empty for a transitive |
| License | The license, as an SPDX expression; `UNKNOWN` when none could be read. For a [reviewed dependency](../guides/review-findings.md), the reviewed license |
| Risk | The [risk level](../concepts/verdicts.md#risk-levels): `permissive`, `weak-copyleft`, `strong-copyleft`, `network-copyleft`, or `unknown` |
| Status | The [verdict](../concepts/verdicts.md): ✓ compatible, ⚠ warning, ✗ violation, `?` unknown |

A `~` before a version or a license marks an [estimate](../concepts/version-resolution.md#estimates).

A report has one row per package, resolved version, and origin (the repository, URL, or path of an [off-registry dependency](../concepts/off-registry.md)). Several versions of one package can be in it, each with its own license lookup: a graph can hold `lodash@4.x` and `lodash@3.x` through different paths, and the manifests of one tree can ask for different versions.

- Direct dependencies are listed alphabetically, each with its transitives indented beneath it, also alphabetically, so a flagged transitive leads back to the direct dependency you would remove to drop it.
- A transitive that several direct dependencies pull in is listed once, under the alphabetically first, with an `(also: X, Y)` annotation. JSON has the full list in `direct_ancestors` (with `depth` and `is_transitive`).

Piped, or written with `-o`, the table is at its full width with one line per dependency. On a terminal narrower than the table, cells wrap and no column is dropped. When stdout's encoding cannot represent the report's glyphs (a legacy Windows code page), `OK`, `!`, and `X` are printed for ✓, ⚠, and ✗.

## Under the table

- **Summary**: how many dependencies are violations, warnings, unknown, and ok, how many of them are reviewed, and the number of analysis gaps and estimated manifests.
- **Analysis gaps** and **Estimates**: each file the scan could not fully read, or whose dependencies were estimated, with the reason. See [What fails a check](../concepts/check-failures.md#analysis-gaps).
- **Details**: the reason for every dependency that is not compatible.
- **Reviewed**: each [reviewed dependency](../guides/review-findings.md), with its detected license, its reviewed license, and the note.

## A flagged row

A row marked ⚠, ✗, or `?` is flagged, and by default it fails the check. **Details** gives the reason.

- [How licenseal decides](../concepts/verdicts.md) says what each verdict means.
- [Fix a failing check](../guides/fix-a-failing-check.md) says what to do, symptom by symptom.
- [Review flagged dependencies](../guides/review-findings.md) shows how to record a decision about a dependency you have looked into.

## Write it to a file

`-o FILE` writes the report as UTF-8 (the table without ANSI escapes). The file is written even when findings or analysis gaps fail the check, so CI can publish it (an error, such as an invalid review file or unreachable registries, writes none); a failing check then also prints the summary and the findings that failed it, with the number of analysis gaps, to stderr.

The table and Markdown formats escape the strings that come from registries and scanned files (control characters, and Markdown and HTML syntax), so a package name or a license string cannot add a link, markup, or a table column. JSON reports the original strings.
