---
title: "Diagnostics"
description: "The diagnostics block of the JSON report: what the scan could not read, read with a caveat, or estimated."
---

# Diagnostics

The `diagnostics` array of the [JSON report](json-report.md). Each entry is something the scan could not read, read with a caveat, or estimated: the same set printed as `Warning:` lines on stderr. The array is empty on a clean scan, and `(path, reason)` pairs are de-duplicated. The table and Markdown reports list the `gap` entries in an **Analysis gaps** section and the `estimate` entries in an **Estimates** section; they name a file outside the scanned directory by its file name only, where JSON gives its absolute path.

```json
"diagnostics": [
  { "path": "packages/api/requirements.txt", "reason": "could not be read (PermissionError); skipped", "severity": "gap" },
  { "path": "pom.xml", "reason": "is not valid XML; skipped", "severity": "gap" },
  { "path": "web/package.json", "reason": "\"dependencies\" has an unexpected type; ignored", "severity": "gap" },
  { "path": "web/pnpm-lock.yaml", "reason": "declares a lockfile version that is not supported; skipped", "severity": "gap" },
  { "path": "web/package.json", "reason": "the dependencies of left-pad 1.3.0 could not be read from the registry; its transitive dependencies may be missing", "severity": "gap" },
  { "path": "requirements-dev.txt", "reason": "decoded as latin-1 (not valid UTF-8); non-ASCII content may be wrong", "severity": "recovered" },
  { "path": "yarn.lock", "reason": "declares a lockfile version newer than the parser knows; read on a best-effort basis", "severity": "recovered" },
  { "path": "tools/package.json", "reason": "declares dependencies that no lockfile covers; their versions and transitive dependencies are estimated from the registry", "severity": "estimate" }
]
```

| Field | Type | Description |
| --- | --- | --- |
| `path` | string | Offending file, relative to the scanned directory when under it (else absolute): a manifest, a lockfile, or a directory that could not be traversed. A diagnostic about a package in the dependency graph is on the manifest that declares the direct dependency leading to it. |
| `reason` | string | Human-readable cause. The kinds are listed in [What fails a check](../concepts/check-failures.md). |
| `severity` | `"gap"` \| `"recovered"` \| `"estimate"` | `gap` = the analysis is incomplete: counted in `summary.gaps`, fails strict mode. `recovered` = read with a caveat (a file decoded through the latin-1 fallback, or a lockfile in a format version the parser was not written for): not counted, does not fail. `estimate` = a manifest without a lockfile, in a scan run with `--no-require-lockfile`: not counted, does not fail. The same diagnostic is a `gap` under the default `--require-lockfile`. |
