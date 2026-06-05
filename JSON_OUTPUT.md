# JSON Output Schema

`licenseal check -f json` emits a single JSON object intended as a stable contract for CI scripts and downstream tooling. The schema is stable across patch and minor releases; breaking shape changes (renames, removals, type changes) are called out in the [CHANGELOG](CHANGELOG.md).

## Example

```json
{
  "project_license": "MIT",
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
      "ecosystem": "python",
      "group": "prod",
      "depth": 1,
      "direct_ancestors": ["httpx"],
      "is_transitive": true,
      "source": "",
      "source_url": "",
      "license": "MPL-2.0",
      "license_raw": "MPL-2.0",
      "detected_license": "MPL-2.0",
      "reviewed_license": "",
      "effective_license": "MPL-2.0",
      "reviewed": false,
      "review_note": "",
      "resolved_version": "2026.4.22",
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
| `project_license` | string | Detected SPDX license of the scanned project, or `"Proprietary"` if none detected. |
| `elapsed_seconds` | number | Wall-clock seconds for the run. |
| `summary` | object | Verdict counts. |
| `dependencies` | array of object | Each scanned dependency. Sorted alphabetically by `(ecosystem, name)`. |
| `diagnostics` | array of object | Manifest read/parse anomalies surfaced during the scan (see [`diagnostics` block](#diagnostics-block)). Empty on a clean scan. |

## `summary` block

| Field | Type | Description |
| --- | --- | --- |
| `total` | int | Total dependencies scanned. |
| `ok` | int | Count where `verdict == "compatible"`. |
| `warnings` | int | Count where `verdict == "warning"`. |
| `violations` | int | Count where `verdict == "incompatible"`. |
| `unknown` | int | Count where `verdict == "unknown"`. |
| `reviewed` | int | Dependencies with a manual review override applied. Reviewed deps still appear in `warnings` / `violations` / `unknown` (the verdict counters are by classification, not by acceptance state), but the strict-mode CI exit code skips them — the review file `note` is the audit trail. |
| `gaps` | int | Distinct manifests lost to an **analysis gap** — unreadable or unparseable files whose dependencies are missing from this report (see [`diagnostics` block](#diagnostics-block)). `total` therefore counts deps from successfully-parsed files only. Non-zero `gaps` fails strict mode. |

## `diagnostics` block

Each entry is a manifest/lockfile read or parse anomaly surfaced during the scan — the same set printed as `Warning:` lines on stderr, included here so a consumer reading only the JSON can see what the scan couldn't. The array is empty on a clean scan, and `(path, reason)` pairs are de-duplicated.

```json
"diagnostics": [
  { "path": "packages/api/requirements.txt", "reason": "could not be read (PermissionError); skipped", "severity": "gap" },
  { "path": "pom.xml", "reason": "is not valid XML; skipped", "severity": "gap" },
  { "path": "requirements-dev.txt", "reason": "decoded as latin-1 (not valid UTF-8); non-ASCII content may be wrong", "severity": "recovered" }
]
```

| Field | Type | Description |
| --- | --- | --- |
| `path` | string | Offending file, project-relative when under the scan root (else absolute). |
| `reason` | string | Human-readable cause (unreadable, unparseable, untraversable directory, or latin-1 fallback). |
| `severity` | `"gap"` \| `"recovered"` | `gap` = a dependency-bearing file was lost (incomplete analysis — counted in `summary.gaps`, fails `--strict`). `recovered` = decoded with a caveat (latin-1 fallback) but the ASCII dependency lines survived — a warning, not a gap. |

## Per-dependency fields

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Package name as published on the registry. |
| `ecosystem` | `"python"` \| `"npm"` \| `"rust"` \| `"go"` \| `"java"` \| `"dotnet"` \| `"php"` \| `"ruby"` \| `"hex"` \| `"r"` | Origin ecosystem. |
| `group` | `"prod"` \| `"dev"` | Production or development. Reachability-based for transitives. |
| `depth` | int | `0` for direct deps, `1` for transitives. A binary direct/transitive signal, not a tree level. |
| `direct_ancestors` | array of string | Depth-0 dependencies that pull this entry in (sorted). Empty for direct deps. |
| `is_transitive` | bool | Equivalent to `depth > 0`. |
| `source` | string | Project-relative path to the manifest file the direct dep was declared in (e.g. `pyproject.toml`, `requirements-dev.txt`, `packages/foo/Cargo.toml`, `MCP/requirements.txt`). Uses forward slashes on all platforms. Empty for transitives. Disambiguates same-named manifests at different paths in monorepo layouts. |
| `source_url` | string | Project-relative URL form of `source` for clickable rendering. Empty when `source` is empty. |
| `license` | string | Effective SPDX expression. Equal to `effective_license`. |
| `license_raw` | string | Original license string from the registry, before normalization. |
| `detected_license` | string | SPDX expression detected from registry metadata. |
| `reviewed_license` | string | SPDX expression supplied via `licenseal.review.toml`, or empty. |
| `effective_license` | string | `reviewed_license` if non-empty, else `detected_license`. |
| `reviewed` | bool | Whether a review override applied. |
| `review_note` | string | Reviewer note from `licenseal.review.toml`. |
| `resolved_version` | string | Concrete version checked (e.g. `"2026.4.22"`). |
| `repository_url` | string | Source-repo URL from the registry's structured field (e.g. PyPI `project_urls`, npm `repository`, crates.io `repository`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `homepage_url` | string | Package-author-supplied homepage (e.g. PyPI `home_page`, npm `homepage`, crates.io `homepage`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `package_url` | string | Registry / docs page for the dependency's ecosystem (e.g. `https://pypi.org/project/{name}/`, `https://www.npmjs.com/package/{name}`, `https://crates.io/crates/{name}`, `https://pkg.go.dev/{module}`, `https://www.nuget.org/packages/{name}`, `https://packagist.org/packages/{name}`, `https://rubygems.org/gems/{name}`, `https://hex.pm/packages/{name}`, `https://cran.r-project.org/package={name}`). |
| `license_url` | string | `https://spdx.org/licenses/{id}.html`. For compound SPDX expressions (`OR` / `AND` / `WITH`), resolves to a representative component: lowest-risk for `OR`, highest-risk for `AND`, base for `WITH`. Empty when no component is a known SPDX ID. |
| `risk` | `"permissive"` \| `"weak-copyleft"` \| `"strong-copyleft"` \| `"network-copyleft"` \| `"unknown"` | Risk tier. |
| `verdict` | `"compatible"` \| `"warning"` \| `"incompatible"` \| `"unknown"` | Compatibility verdict. |
| `reason` | string | Human-readable explanation for non-compatible verdicts. Empty for `compatible`. |
| `actionability` | object \| absent | Present only on flagged deps (`verdict != "compatible"`). See _Actionability block_ below. |

## URL fields and trust

For agents and tooling that follow URLs from the report, the four URL fields fall into two trust tiers:

- **Safe to trust** — `package_url` and `license_url`. Both are deterministically constructed by licenseal from a known ID + canonical host (registry or spdx.org). They never carry attacker-supplied content.
- **Registry-provenance, treat as untrusted content** — `repository_url` and `homepage_url`. The registry passes through whatever the package author wrote. A compromised package can point either field at any URL. Agents that fetch these URLs should sandbox the request and validate response content before acting on it. Stricter agents may prefer `repository_url` over `homepage_url` (structured VCS data is usually a tighter signal than a homepage), but neither is validated.

## Actionability block

Present on every dep where `verdict` is `"warning"`, `"incompatible"`, or `"unknown"`. Omitted on compatible deps to keep the output compact.

| Field | Type | Description |
| --- | --- | --- |
| `investigate_url` | string | Best single URL for an investigation: `license_url` → `repository_url` → `homepage_url` → `package_url`, taking the first non-empty. Always present (worst case it equals `package_url`). |
| `next_steps` | array of string | Verdict-aware action list. Only contains steps whose required URLs are populated, so an agent can act on each step verbatim. URLs in `next_steps` that point at a LICENSE path (e.g. `https://github.com/owner/repo/blob/HEAD/LICENSE`) are **heuristic** — registries don't expose the bundled file directly. If the URL 404s, the agent should try common filename variants (`LICENSE.md`, `LICENSE.txt`, `COPYING`) under the same path before falling back to navigating the file tree at `repository_url`. |
