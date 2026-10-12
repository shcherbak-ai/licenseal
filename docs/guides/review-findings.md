---
title: "Review flagged dependencies"
description: "Record a reviewed license for a flagged dependency in licenseal.review.toml, so that the check passes and the decision stays on record."
---

# Review flagged dependencies

A [flagged](../concepts/check-failures.md) dependency stops failing the check once you record a decision about it in `licenseal.review.toml`, in the scanned directory. The file is checked in, so the decision stays on record.

```bash
licenseal init-review-file
```

The command runs the scan `check` runs by default and scaffolds an empty entry for each flagged dependency, direct or transitive. Fill in `license` (and optionally `note`) in each entry, and run `licenseal check` again: the entries apply.

```toml
[[review]]
ecosystem = "python"
package = "mystery-lib"
version = "1.0.0"
license = "MIT"
note = "confirmed from packaged LICENSE file"
```

## What to put in `license`

- **You have better license information than licenseal** (you have read the bundled `LICENSE` file, say): give the license you found, as in the entry above.
- **The detected license is right and you accept it** (a weak-copyleft dependency that you use unmodified, say): give the detected license, and the reason in `note`.

```toml
[[review]]
ecosystem = "python"
package = "certifi"
version = "2026.7.22"
license = "MPL-2.0"
note = "Used unmodified; MPL-2.0 covers changes to its own files only"
```

The keys of an entry and the rules it must meet are in the [review file reference](../reference/review-file.md). To be walked through the review instead of editing the file by hand, use the [Claude Code skill](claude-code-skill.md).

## From a saved report

For a `check` run with other options (`--no-transitive`, another `--max-depth`), scaffold from that run's report:

1. `licenseal check -f json -o report.json` saves a report with the flagged dependencies.
2. `licenseal init-review-file --from-report report.json` scaffolds an empty entry for each, without scanning.
3. Fill in `license` (and optionally `note`) in each entry.
4. Run `licenseal check` again: the entries apply.

## New findings later

When new flagged dependencies appear later, `licenseal init-review-file --merge` adds entries for them to the existing file and leaves the existing entries as they are.

## After an upgrade

An entry applies to one version. When an upgrade moves the dependency to another version, the entry matches no row, and `check` stops with an error (`Reviewed licenses did not match any resolved package versions`) and writes no report.

- If the new version has the same license, change the entry's `version`.
- Otherwise, or when the dependency is gone, delete the entry and scan again. The dependency is then flagged for a fresh review, and `init-review-file --merge` scaffolds its entry.

The same error appears when the scan leaves the dependency out: a dev dependency in a scan without `--dev`, a transitive with `--no-transitive`, an excluded directory. Scan with the options the review was made with.

## A dependency with no version

A flagged registry dependency with no resolved version gets no entry, since there is no version to key one on; a stderr `Note:` names it. The usual cause is a typo in the manifest, a yanked release, or a version the registry does not have. Correct the declaration so that the version resolves: see [Which version is reported](../concepts/version-resolution.md#which-version-is-reported).

## An off-registry dependency

An [off-registry dependency](../concepts/off-registry.md) has no registry version, so its entry is keyed on its source: it carries a `source` key holding the row's `origin` string (the `origin` field of the JSON report, not the table's Source column), and `version` is optional. `init-review-file` writes it:

```toml
[[review]]
ecosystem = "ruby"
package = "edge-fork"
source = "git+https://git.example.org/team/edge-fork.git@0123abcd"
license = "MIT"
note = "LICENSE read at that commit"
```

## What a review does to the report

A reviewed dependency never fails the check, whatever verdict its reviewed license gets. Reports show both the detected and the reviewed license, and reviewed dependencies have their own report section:

> **Summary:** 0 violations, 0 warnings, 0 unknown, 4 ok (of which 1 reviewed)

| Package | Detected | Reviewed | Note |
| --- | --- | --- | --- |
| mystery-lib (1.0.0) | UNKNOWN (raw: Custom internal license) | MIT | confirmed from packaged LICENSE file |

> [!WARNING]
> An entry can mark a copyleft dependency as MIT and pass [strict mode](../concepts/check-failures.md), so treat `licenseal.review.toml` as security-relevant: require code review on every change, give the reason for each entry in `note`, and re-validate periodically (see [Security model](../security/index.md#files-that-decide-a-verdict)).
