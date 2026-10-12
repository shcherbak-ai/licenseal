---
title: "License expressions"
description: "How licenseal reads a license string: OR, AND and WITH, malformed expressions, license lists, and R's file LICENSE."
---

# License expressions

A registry gives a license as a string, which can name several licenses. This page says how that string is read before the [matrix and the pair-level overrides](verdicts.md) apply.

## `OR`, `AND`, and `WITH`

- **`OR` expressions.** The dependency gets the verdict of the choice that suits the project best, each choice judged as a whole: `GPL-3.0-only OR MIT` in a `GPL-2.0-only` project is compatible through its MIT choice. The report's Risk column shows its least restrictive choice.
- **`WITH` exceptions** are matched against a fixed list.
  - `Classpath-exception-2.0` and `Classpath-exception-2.0-short` on a GPL license make that license weak copyleft.
  - An exception that only adds a permission leaves the license judged without it: `Autoconf-exception-2.0`, `Autoconf-exception-3.0`, `Bison-exception-2.2`, `Bootloader-exception`, `Font-exception-2.0`, `GCC-exception-2.0`, `GCC-exception-3.1`, `Libtool-exception`, `Linux-syscall-note`, `LLVM-exception`, `OCaml-LGPL-linking-exception`, `Swift-exception`, `Universal-FOSS-exception-1.0`, `WxWindows-exception-3.1`. In addition, `Apache-2.0 WITH LLVM-exception` is compatible in a `GPL-2.0-only` project.
  - Any other text after `WITH` is an exception nobody evaluated: the license is a violation when it is one without the exception, and unknown otherwise.
- **Operands that did not resolve.** In an `AND`, an operand that is a violation makes the dependency a violation whatever the others are (`GPL-3.0-only AND UNKNOWN` in an MIT project); otherwise an operand that did not resolve makes it unknown. In an `OR`, a choice that did not resolve is never the one taken (`MIT OR CustomLicense` is judged as `MIT`).
- **Malformed expressions** (`MIT AND GPL-3.0-only AND`, `MIT OR (GPL-3.0-only`) are reported with the license `UNKNOWN`. The dependency is a violation when a license the string names is one, and unknown otherwise.

## License lists

When a source gives several licenses for one package, the list is read by what that source defines:

- **A choice**: a Composer `license` array, `/` in a Cargo `license` field, `|` in an R `License` field, npm's legacy `licenses` array.
- **All apply**: several `<license>` entries in a Maven POM, and a [deps.dev](../security/license-sources.md) `licenses` array with several entries (other than for a RubyGems package).
  - Two rewrites apply to a deps.dev array only: a GPL entry beside the LGPL entry of the same version (or GPL-2.0 beside LGPL-2.1) is dropped, because the LGPL refers to the GPL text, and one CDDL entry plus `GPL-2.0-with-classpath-exception` is read as that dual license (`OR`).
  - A deps.dev array that contains its `non-standard` marker is not used; the dependency is resolved from its own registry.
- **Not defined by the source**: a RubyGems or Hex array with more than one entry, several distinct PyPI license classifiers, and a comma- or slash-separated list inside one license string (`MIT, GPL-3.0-only`; in an R `License` field such a list is `UNKNOWN`). Such a list is judged twice, as a choice and with every entry applying. When both readings give the same verdict, that verdict is reported; when they differ, the verdict is `unknown` and the reason asks you to confirm which holds and record it in [`licenseal.review.toml`](../guides/review-findings.md). The exception is `Ruby` with `BSD-2-Clause`, which the Ruby license itself offers as a choice.

## R `+ file LICENSE`

The file is never fetched. After `MIT`, `BSD_2_clause`, or `BSD_3_clause` it is the copyright notice those templates require, and the result is the license alone. After any other license it holds further terms, so `GPL-3 + file LICENSE` is reported as `GPL-3.0-only AND UNKNOWN`.

## See also

- [Project license](project-license.md#a-dual-licensed-project): how an `OR` in the project's own license is read.
- [How licenseal decides](verdicts.md#dev-dependencies): what changes for a dev dependency.
