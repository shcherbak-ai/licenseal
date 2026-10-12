---
title: "Review file"
description: "The keys of a licenseal.review.toml entry and the rules an entry must meet."
---

# Review file

`licenseal.review.toml` sits in the scanned directory and holds one `[[review]]` entry per reviewed dependency. [Review flagged dependencies](../guides/review-findings.md) shows how to create and fill it.

## Keys

| Key | Required | Value |
| --- | --- | --- |
| `ecosystem` | yes | `python`, `npm`, `rust`, `go`, `java`, `dotnet`, `php`, `ruby`, `hex`, or `r` |
| `package` | yes | The package's name, compared the way its registry compares names |
| `version` | yes, unless `source` is set | The resolved version the entry applies to |
| `source` | for an [off-registry dependency](../concepts/off-registry.md) | The row's `origin` string: the `origin` field of the [JSON report](json-dependency-fields.md) |
| `license` | to apply the entry | A license expression. Left empty or left out, the entry is not applied, and `check` names it in a `Warning:` |
| `note` | no | The reason for the decision |

## Rules

- An entry matches the row with its `ecosystem`, `package`, and resolved `version`. `package` is compared the way the ecosystem's registry compares names: exactly, upper and lower case included, for Go, Java, npm, and Ruby; without regard to case for .NET, PHP, Rust, Hex, and R; with PEP 503 normalization for Python. A Hex dependency that `mix.exs` declares under another name than its hex.pm package is matched on the hex.pm name.
- An entry with a `source` key matches on ecosystem, package, and `source`, compared with the row's `origin` exactly, and on `version` when the entry has one. An entry keyed on a commit applies to that commit only. One keyed on a **branch or a tag** (all a manifest without a lockfile can say), on a bare repository URL, on a URL without a hash, or on a path keeps applying when the code there changes; pin a commit, or commit a lockfile, to get an immutable key.
- `license` is a license expression. Each license in it must be an SPDX identifier (current or deprecated), a source-available license licenseal recognises (`BUSL-`, `FSL-`, `PolyForm-`, …), `Proprietary`, or a `LicenseRef-` reference; an exception after `WITH` is not checked against a list. A comma- or slash-separated list is not accepted: join the licenses with `OR` or `AND`.
- These fail the command:
  - an entry that matches a compatible dependency (only a flagged one can be overridden);
  - a filled-in entry that matches no reported row (an old version after an upgrade, or a dev dependency in a scan without `--dev`): see [After an upgrade](../guides/review-findings.md#after-an-upgrade);
  - a missing `ecosystem`, `package`, or `version` (`version` is optional beside `source`), or a value that is not a string;
  - an unknown ecosystem;
  - a duplicate;
  - a `license` that breaks the rule above.
- An entry whose `license` is empty is not applied, and `check` names it in a `Warning:` that is not an analysis gap.
- `licenseal.review.toml` and the report passed to `--from-report` must be UTF-8; write the report with `-o report.json` rather than a shell redirect.
- A reviewed dependency never fails the check, whatever verdict its reviewed license gets. Unreviewed warnings, violations, and unknowns still fail. An [analysis gap](../concepts/check-failures.md#analysis-gaps) cannot be reviewed: fix the file, commit a lockfile, or pass `--no-require-lockfile`.
- Reports show both the detected and the reviewed license; JSON has `detected_license`, `reviewed_license`, `effective_license`, `reviewed`, and `review_note`.
