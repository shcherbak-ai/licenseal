---
title: "JSON report"
description: "The JSON document that licenseal check -f json writes: an example, the top-level fields, and the summary block."
---

# JSON report

`licenseal check -f json` emits a single JSON object intended as a stable contract for CI scripts and downstream tooling. The schema is stable across patch and minor releases; breaking shape changes (renames, removals, type changes) are called out in the [changelog](../changelog.md).

## Example

```json
{
  "project_license": "MIT",
  "project_license_source": "pyproject.toml",
  "elapsed_seconds": 0.42,
  "summary": {
    "total": 56,
    "ok": 54,
    "warnings": 1,
    "violations": 0,
    "unknown": 1,
    "reviewed": 0,
    "gaps": 0
  },
  "dependencies": [
    {
      "name": "certifi",
      "registry_name": "",
      "ecosystem": "python",
      "group": "prod",
      "depth": 1,
      "direct_ancestors": ["httpx"],
      "is_transitive": true,
      "source": "",
      "source_url": "",
      "origin": "",
      "license": "MPL-2.0",
      "license_raw": "MPL-2.0",
      "detected_license": "MPL-2.0",
      "reviewed_license": "",
      "effective_license": "MPL-2.0",
      "reviewed": false,
      "review_note": "",
      "resolved_version": "2026.4.22",
      "estimated": [],
      "repository_url": "https://github.com/certifi/python-certifi",
      "homepage_url": "https://github.com/certifi/python-certifi",
      "package_url": "https://pypi.org/project/certifi/",
      "license_url": "https://spdx.org/licenses/MPL-2.0.html",
      "risk": "weak-copyleft",
      "verdict": "warning",
      "reason": "certifi uses MPL-2.0 — weak copyleft license — modifications to the licensed files must remain under the same license; linking from other files is allowed. Review whether this is acceptable for your MIT project",
      "actionability": {
        "investigate_url": "https://spdx.org/licenses/MPL-2.0.html",
        "next_steps": [
          "Verify license terms at https://spdx.org/licenses/MPL-2.0.html",
          "Confirm license text at https://github.com/certifi/python-certifi/blob/HEAD/LICENSE",
          "Decide whether the license is acceptable for the project's context"
        ]
      }
    }
  ],
  "diagnostics": []
}
```

## Top-level fields

| Field | Type | Description |
| --- | --- | --- |
| `project_license` | string | SPDX license of the scanned project, as declared by a manifest in the scanned directory itself, or `"Proprietary"` when none declares a recognised license (see [Project license](../concepts/project-license.md)). |
| `project_license_source` | string | File name of the manifest in the scanned directory that supplied `project_license` (`"pyproject.toml"`, `"package.json"`, `"App.csproj"`, `"Directory.Build.props"`, …). `""` when `Proprietary` is assumed. |
| `elapsed_seconds` | number | Wall-clock seconds for the run. |
| `summary` | object | Verdict counts. |
| `dependencies` | array of object | Each scanned dependency (see [Dependency fields](json-dependency-fields.md)). Sorted alphabetically by `(ecosystem, name)`. |
| `diagnostics` | array of object | What the scan could not read, read with a caveat, or estimated (see [Diagnostics](json-diagnostics.md)). Empty on a clean scan. |

## `summary` block

| Field | Type | Description |
| --- | --- | --- |
| `total` | int | Total dependencies scanned. |
| `ok` | int | Count where `verdict == "compatible"`. |
| `warnings` | int | Count where `verdict == "warning"`. |
| `violations` | int | Count where `verdict == "incompatible"`. |
| `unknown` | int | Count where `verdict == "unknown"`. |
| `reviewed` | int | Entries with a [review](../guides/review-findings.md) applied. Each is still counted under the verdict of its reviewed license, so a non-zero `violations` can pass [strict mode](../concepts/check-failures.md); filter `dependencies` on `reviewed` to count what fails. |
| `gaps` | int | Number of distinct `path` values among the `diagnostics` entries of severity `gap`. Each is an **analysis gap**: something the scan could not read, so dependencies may be missing from this report and `total` counts only those that were read. Non-zero `gaps` fails strict mode. The kinds are listed in [What fails a check](../concepts/check-failures.md). |
