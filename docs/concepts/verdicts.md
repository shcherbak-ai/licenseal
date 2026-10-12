---
title: "How licenseal decides"
description: "The four verdicts, the risk level of each license family, the compatibility matrix, and the rules for specific license pairs."
---

# How licenseal decides

licenseal classifies each dependency license into a risk level and compares that risk against the [project license](project-license.md). The result is one of four verdicts:

| Verdict | In the report | Meaning |
| --- | --- | --- |
| Compatible | ✓, counted as `ok` | The license is compatible with the project license |
| Warning | ⚠ | The combination may be acceptable, but licenseal cannot tell: a person has to decide |
| Violation | ✗, `incompatible` in JSON | The license is incompatible with the project license |
| Unknown | `?` | The license is missing or cannot be classified: a person has to read it |

A dependency with any verdict but compatible is **flagged**. What a flagged dependency does to the exit code is under [What fails a check](check-failures.md).

## Risk levels

| Risk level | Examples | Meaning |
| --- | --- | --- |
| Permissive | MIT, BSD, Apache-2.0, ISC | No significant restrictions |
| Weak Copyleft | LGPL, MPL-2.0, EPL, CDDL, GPL with Classpath exception | File-scope reciprocity; linking from other files is usually allowed |
| Strong Copyleft | GPL, OSL, EUPL, CC-BY-SA | Share-alike obligations can extend to the derivative work |
| Network Copyleft | AGPL-3.0-only | Strong copyleft with network-use source-offer obligations |
| Unknown | SSPL, BUSL, Elastic, FSL, PolyForm, CC-BY-NC | Cannot be auto-classified; routed to manual review |

Unknown holds three kinds of license:

- source-available and use-restricted licenses: SSPL, BUSL, Elastic, FSL, Parity, PolyForm, CC-BY-NC, CC-BY-ND, `BSD-3-Clause-No-Military-License` and the other use-restricted BSD variants, Unicode-TOU;
- missing or unrecognized licenses;
- an unrecognized `WITH` exception on a license that is not strong or network copyleft.

## The matrix

| Project \ Dependency | Permissive | Weak Copyleft | Strong Copyleft | Network Copyleft |
| --- | --- | --- | --- | --- |
| **Permissive** | OK | Warning | Violation | Violation |
| **Weak Copyleft** | OK | OK | Violation | Violation |
| **Strong Copyleft** | OK | OK | OK | Warning |
| **Network Copyleft** | OK | OK | OK | OK |

- OK is the verdict compatible.
- A dependency of unknown risk has no column: its verdict is unknown.
- A project checked as `Proprietary`, and one under a source-available license (BUSL, SSPL, Elastic, FSL, Parity, PolyForm), is judged by the **Permissive** row: permissive dependencies are compatible, weak copyleft is a warning, and strong or network copyleft is a violation.

## Pair-level overrides

**Pair-level overrides** strengthen the matrix where two licenses are documented as legally incompatible:

- Violation: a GPLv3-family dependency (`GPL-3.0-*`, `LGPL-3.0-*`, `AGPL-3.0-*`) in a `GPL-2.0-only` project, or a `GPL-2.0-only` dependency in a `GPL-3.0-*` / `AGPL-3.0-*` project.
- Violation: `Apache-2.0` in a `GPL-2.0-only` project.
- Violation: `EPL-1.0`, `CDDL-*`, or `MPL-1.1` in any GPL-family project (`GPL-2.0-*`, `GPL-3.0-*`, `AGPL-3.0-*`).
- Warning: `EPL-2.0` in a GPL-family project, because its GPL compatibility depends on a secondary-license designation that package metadata cannot reveal.

`-or-later` forms are exempt where the upgrade clause resolves the conflict. A deprecated GNU identifier is read by its SPDX meaning: a bare `GPL-2.0` is `GPL-2.0-only`, and `GPL-2.0+` is `GPL-2.0-or-later`.

## Dev dependencies

A violation on a dev dependency is reported as a warning; one whose license did not fully resolve is unknown instead. A dev dependency whose license is `Proprietary` is a warning too. Dev dependencies are scanned only with `--dev`.

## See also

- [License expressions](license-expressions.md): how a license string with `OR`, `AND`, or `WITH` in it is read.
- [What fails a check](check-failures.md): what each verdict does to the exit code.
- [Review flagged dependencies](../guides/review-findings.md): record a decision about a flagged dependency.
