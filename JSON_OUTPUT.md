# JSON Output Schema

`licenseal check -f json` emits a single JSON object intended as a stable contract for CI scripts and downstream tooling. The schema is stable across patch and minor releases; breaking shape changes (renames, removals, type changes) are called out in the [CHANGELOG](CHANGELOG.md).

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
| `project_license` | string | SPDX license of the scanned project, as declared by a manifest in the scanned directory itself (never a nested one), or `"Proprietary"` when none declares a recognised license. |
| `project_license_source` | string | Project-relative path of the manifest that supplied `project_license` (`"pyproject.toml"`, `"package.json"`, `"App.csproj"`, …). `""` when no manifest in the scanned directory declares a recognised license and `Proprietary` is assumed. |
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
| `gaps` | int | Distinct manifests with an **analysis gap** — unreadable, undecodable, or unparseable files whose dependencies are missing from this report, manifests that reference another file that was not followed, files holding a value of a type their format does not allow, which was read as absent, or lockfiles that were skipped because they declare a version known not to be readable, hold no entry that can be read, or contain merge-conflict markers (see [`diagnostics` block](#diagnostics-block)). `total` therefore counts only the deps that could be read. Non-zero `gaps` fails strict mode. |

## `diagnostics` block

Each entry is a manifest/lockfile read or parse anomaly surfaced during the scan — the same set printed as `Warning:` lines on stderr, included here so a consumer reading only the JSON can see what the scan couldn't. The array is empty on a clean scan, and `(path, reason)` pairs are de-duplicated. The table and Markdown reports list the `gap` entries in an **Analysis gaps** section (file and reason) and add the gap count to their summary line; they name a file outside the scan root by its file name only, where JSON gives its absolute path.

```json
"diagnostics": [
  { "path": "packages/api/requirements.txt", "reason": "could not be read (PermissionError); skipped", "severity": "gap" },
  { "path": "pom.xml", "reason": "is not valid XML; skipped", "severity": "gap" },
  { "path": "web/package.json", "reason": "\"dependencies\" has an unexpected type; ignored", "severity": "gap" },
  { "path": "web/pnpm-lock.yaml", "reason": "declares a lockfile version that is not supported; skipped", "severity": "gap" },
  { "path": "requirements-dev.txt", "reason": "decoded as latin-1 (not valid UTF-8); non-ASCII content may be wrong", "severity": "recovered" },
  { "path": "yarn.lock", "reason": "declares a lockfile version newer than the parser knows; read on a best-effort basis", "severity": "recovered" }
]
```

| Field | Type | Description |
| --- | --- | --- |
| `path` | string | Offending file, project-relative when under the scan root (else absolute). |
| `reason` | string | Human-readable cause (unreadable, undecodable, unparseable, untraversable directory, a reference to another file that was not followed; a value of an unexpected type; a lockfile that declares a version known not to be readable, holds no entry that can be read, or contains merge-conflict markers; or, without being a gap, latin-1 fallback or a lockfile read on a best-effort basis because it declares a version the parser was not written for). A reference is not followed when it is not a relative path, or, for a requirements `-r` include, when it is a URL, is not a file, or leaves the scanned directory; the entry is on the file that contains the reference. A document nested too deeply to parse is reported as not valid in its format. A `go.mod` whose `go` directive is below 1.17 or absent, with requirements that have no `go.sum` row, is a gap too (`lists only direct requirements … a go.sum row is missing for N of them; …`): the file was read, but what those requirements depend on is listed nowhere. A TOML file that is not valid UTF-8 is a gap (`is not valid UTF-8, which TOML requires; skipped`): TOML requires UTF-8, so it gets no latin-1 fallback. A value of an unexpected type is named by its section (`"dependencies"`, `project.optional-dependencies`) or as an entry of it (`an entry of "packages"`), never by the file's own text; several such values in one section are one entry. |
| `severity` | `"gap"` \| `"recovered"` | `gap` = a dependency-bearing file was lost, or part of it could not be read (incomplete analysis — counted in `summary.gaps`, fails `--strict`). `recovered` = read with a caveat — a warning, not a gap, and not counted in `summary.gaps`: a text, JSON, or YAML file decoded through the latin-1 fallback, whose ASCII dependency lines survived, or a lockfile that declares a version the parser was not written for (newer, or otherwise not on its list) and was read on a best-effort basis. |

## Per-dependency fields

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Package name as published on the registry. Reported verbatim, like every other string field: the table and Markdown formats escape control characters and markup for display, JSON does not rewrite them (a control character appears as a JSON `\uXXXX` escape, and so does a lone surrogate). |
| `ecosystem` | `"python"` \| `"npm"` \| `"rust"` \| `"go"` \| `"java"` \| `"dotnet"` \| `"php"` \| `"ruby"` \| `"hex"` \| `"r"` | Origin ecosystem. |
| `group` | `"prod"` \| `"dev"` | Production or development. Reachability-based for transitives. |
| `depth` | int | `0` for direct deps, `1` for transitives. A binary direct/transitive signal, not a tree level. |
| `direct_ancestors` | array of string | Depth-0 dependencies that pull this entry in (sorted). Empty for direct deps. |
| `is_transitive` | bool | Equivalent to `depth > 0`. |
| `source` | string | Project-relative path to the manifest file the direct dep was declared in (e.g. `pyproject.toml`, `requirements-dev.txt`, `packages/foo/Cargo.toml`, `MCP/requirements.txt`). Uses forward slashes on all platforms. Empty for transitives. Disambiguates same-named manifests at different paths in monorepo layouts. |
| `source_url` | string | Project-relative URL form of `source` for clickable rendering. Empty when `source` is empty. |
| `license` | string | Effective SPDX expression. Equal to `effective_license`. |
| `license_raw` | string | Original license string from the registry, before normalization. |
| `detected_license` | string | SPDX expression detected from registry metadata. A custom `LicenseRef-*` operand reads `Proprietary`, and a deprecated GNU ID reads as its current ID (`GPL-2.0` → `GPL-2.0-only`, `GPL-2.0+` → `GPL-2.0-or-later`); `license_raw` keeps the declared string. |
| `reviewed_license` | string | SPDX expression supplied via `licenseal.review.toml`, or empty. |
| `effective_license` | string | `reviewed_license` if non-empty, else `detected_license`. |
| `reviewed` | bool | Whether a review override applied. |
| `review_note` | string | Reviewer note from `licenseal.review.toml`. |
| `resolved_version` | string | Concrete version checked (e.g. `"2026.4.22"`). Empty when the lookup yielded no usable version. |
| `repository_url` | string | Source-repo URL from the registry's structured field (e.g. PyPI `project_urls`, npm `repository`, crates.io `repository`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `homepage_url` | string | Package-author-supplied homepage (e.g. PyPI `home_page`, npm `homepage`, crates.io `homepage`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `package_url` | string | Registry / docs page for the dependency's ecosystem (e.g. `https://pypi.org/project/{name}/`, `https://www.npmjs.com/package/{name}`, `https://crates.io/crates/{name}`, `https://pkg.go.dev/{module}`, `https://www.nuget.org/packages/{name}`, `https://packagist.org/packages/{name}`, `https://rubygems.org/gems/{name}`, `https://hex.pm/packages/{name}`, `https://cran.r-project.org/package={name}`). The name and version are percent-encoded into the URL (`/`, `@`, and `+` are kept), so the URL of a well-formed name reads as shown and any other character cannot change the host or add a query or fragment. |
| `license_url` | string | `https://spdx.org/licenses/{id}.html`. For compound SPDX expressions (`OR` / `AND` / `WITH`), resolves to a representative component: lowest-risk for `OR`, highest-risk for `AND`, base for `WITH`. Empty when no component is a known SPDX ID. |
| `risk` | `"permissive"` \| `"weak-copyleft"` \| `"strong-copyleft"` \| `"network-copyleft"` \| `"unknown"` | Risk tier of the dependency's license, the same under every project license. For an `OR` expression it is the least restrictive choice; `verdict` and `reason` describe the choice the project can take, which can be a stricter one. For a malformed expression that names a violation (`MIT AND GPL-3.0-only AND`), `license` is `UNKNOWN` while `risk` and `verdict` are those of the licenses it names applying together, and `reason` quotes the declared string. |
| `verdict` | `"compatible"` \| `"warning"` \| `"incompatible"` \| `"unknown"` | Compatibility verdict. |
| `reason` | string | Human-readable explanation for non-compatible verdicts. Empty for `compatible`. |
| `actionability` | object \| absent | Present only on flagged deps (`verdict != "compatible"`). See _Actionability block_ below. |

## URL fields and trust

For agents and tooling that follow URLs from the report, the four URL fields fall into two trust tiers:

- **Safe to trust** — `package_url` and `license_url`. Both are deterministically constructed by licenseal from a known ID + canonical host (registry or spdx.org). `license_url` is emitted only for IDs in the SPDX list; `package_url` carries the package name and version percent-encoded in its path, so neither can point at another host.
- **Registry-provenance, treat as untrusted content** — `repository_url` and `homepage_url`. The registry passes through whatever the package author wrote. A compromised package can point either field at any URL. Agents that fetch these URLs should sandbox the request and validate response content before acting on it. Stricter agents may prefer `repository_url` over `homepage_url` (structured VCS data is usually a tighter signal than a homepage), but neither is validated.

## Actionability block

Present on every dep where `verdict` is `"warning"`, `"incompatible"`, or `"unknown"`. Omitted on compatible deps to keep the output compact.

| Field | Type | Description |
| --- | --- | --- |
| `investigate_url` | string | Best single URL for an investigation: `license_url` → `repository_url` → `homepage_url` → `package_url`, taking the first non-empty. Always present (worst case it equals `package_url`). |
| `next_steps` | array of string | Verdict-aware action list. Only contains steps whose required URLs are populated, so an agent can act on each step verbatim. URLs in `next_steps` that point at a LICENSE path (e.g. `https://github.com/owner/repo/blob/HEAD/LICENSE`) are **heuristic** — registries don't expose the bundled file directly. If the URL 404s, the agent should try common filename variants (`LICENSE.md`, `LICENSE.txt`, `COPYING`) under the same path before falling back to navigating the file tree at `repository_url`. |
