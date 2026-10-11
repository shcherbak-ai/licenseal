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
| `project_license` | string | SPDX license of the scanned project, as declared by a manifest in the scanned directory itself, or `"Proprietary"` when none declares a license, or the first one that does declares a value that is not a recognised license (see [USAGE.md](USAGE.md#project-license)). |
| `project_license_source` | string | File name of the manifest in the scanned directory that supplied `project_license` (`"pyproject.toml"`, `"package.json"`, `"App.csproj"`, `"Directory.Build.props"`, …). `""` when `Proprietary` is assumed. |
| `elapsed_seconds` | number | Wall-clock seconds for the run. |
| `summary` | object | Verdict counts. |
| `dependencies` | array of object | Each scanned dependency. Sorted alphabetically by `(ecosystem, name)`. `(ecosystem, name, resolved_version, origin)` is a key: no two entries agree on all four (see [Per-dependency fields](#per-dependency-fields)). |
| `diagnostics` | array of object | Manifest read/parse anomalies surfaced during the scan (see [`diagnostics` block](#diagnostics-block)). Empty on a clean scan. |

## `summary` block

| Field | Type | Description |
| --- | --- | --- |
| `total` | int | Total dependencies scanned. |
| `ok` | int | Count where `verdict == "compatible"`. |
| `warnings` | int | Count where `verdict == "warning"`. |
| `violations` | int | Count where `verdict == "incompatible"`. |
| `unknown` | int | Count where `verdict == "unknown"`. |
| `reviewed` | int | Dependencies with a manual review override applied. A reviewed dep is counted by the verdict of its reviewed license (the verdict counters are by classification, not by acceptance state): in `ok` when the project can take that license, and still in `warnings` / `violations` / `unknown` when the reviewed license is one of those. The strict-mode CI exit code skips reviewed deps either way — the review file `note` is the audit trail. |
| `gaps` | int | Distinct files with an **analysis gap**, which are the `diagnostics` entries of severity `gap`: something the scan could not read, so dependencies may be missing from this report and `total` counts only the deps that could be read. Non-zero `gaps` fails strict mode. The kinds are listed in [USAGE.md](USAGE.md#output--the-ci-gate). |

## `diagnostics` block

Each entry is a manifest/lockfile read or parse anomaly surfaced during the scan — the same set printed as `Warning:` lines on stderr, included here so a consumer reading only the JSON can see what the scan couldn't. The array is empty on a clean scan, and `(path, reason)` pairs are de-duplicated. The table and Markdown reports list the `gap` entries in an **Analysis gaps** section and the `estimate` entries in an **Estimates** section; they name a file outside the scan root by its file name only, where JSON gives its absolute path.

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
| `path` | string | Offending file, project-relative when under the scan root (else absolute): a manifest, a lockfile, or a directory that could not be traversed. A diagnostic about a package in the dependency graph is on the manifest that declares the direct dependency leading to it. |
| `reason` | string | Human-readable cause. The kinds are listed in [USAGE.md](USAGE.md#output--the-ci-gate). |
| `severity` | `"gap"` \| `"recovered"` \| `"estimate"` | `gap` = the analysis is incomplete: counted in `summary.gaps`, fails `--strict`. `recovered` = read with a caveat (a file decoded through the latin-1 fallback, or a lockfile in a format version the parser was not written for): a warning, not counted, does not fail. `estimate` = a manifest whose dependencies no lockfile covers, in a scan run with `--no-require-lockfile`: not counted, does not fail. The same diagnostic is a `gap` under the default `--require-lockfile`. |

## Per-dependency fields

One entry per package, resolved version, and origin: no two entries of `dependencies` have the same `ecosystem`, `name`, `resolved_version`, and `origin`. `name` is compared the way the ecosystem's registry compares names, so in .NET, PHP, Rust, Hex, R, and Python two spellings of one package are one entry. Declarations that resolve to the same version are merged: the entry is `prod` when any of them is, direct when any is, and carries the `source` of the first direct declaration.

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Package name as published on the registry. Reported verbatim, like every other string field: the table and Markdown formats escape control characters and markup for display, JSON does not. |
| `registry_name` | string | Empty unless the package is published under another name than `name`: a Hex dependency that `mix.exs` renames (`{:my_alias, "~> 1.0", hex: :real_pkg}`) has the local name in `name` and the hex.pm package here. That is the `package` a [review entry](USAGE.md#manual-review-file) for it must carry. |
| `ecosystem` | `"python"` \| `"npm"` \| `"rust"` \| `"go"` \| `"java"` \| `"dotnet"` \| `"php"` \| `"ruby"` \| `"hex"` \| `"r"` | Origin ecosystem. |
| `group` | `"prod"` \| `"dev"` | Production or development. Reachability-based for transitives. |
| `depth` | int | `0` for direct deps, `1` for transitives. A binary direct/transitive signal, not a tree level. Every row of a `gradle.lockfile` or a `paket.lock` is `0`: those files do not tell direct from transitive. |
| `direct_ancestors` | array of string | Depth-0 dependencies that pull this entry in (sorted). Empty for direct deps, and for a transitive whose ancestors the lockfile does not tell. |
| `is_transitive` | bool | Equivalent to `depth > 0`. |
| `source` | string | Project-relative path to the manifest file the direct dep was declared in (e.g. `pyproject.toml`, `requirements-dev.txt`, `packages/foo/Cargo.toml`). Uses forward slashes on all platforms. Empty for transitives, and for a lockfile row that no scanned manifest declares at its version (such a row of a `paket.lock` carries the path of the `paket.lock`). Disambiguates same-named manifests at different paths in monorepo layouts. |
| `source_url` | string | The same project-relative path as `source`, for use as a relative link; it is not percent-encoded. Empty when `source` is empty. |
| `origin` | string | Empty for a registry package. For an [off-registry dependency](USAGE.md#off-registry-dependencies), the source it comes from, in one string: `git+<url>@<commit>` (or `@<ref>`), `<url>#<hash>`, a path as written, a lockfile's own source label (`Bioconductor`), or `unrecorded source`. Credentials in a URL are removed. Such a row is never looked up on a registry: its `license` is `UNKNOWN` unless reviewed, its `package_url` is empty, and a review of it is keyed on this string (the `source` key of a `licenseal.review.toml` stanza). |
| `license` | string | Effective SPDX expression. Equal to `effective_license`. |
| `license_raw` | string | Original license string from the registry, before normalization. A deps.dev `licenses` array with several entries is shown joined with `AND`; a RubyGems or Hex array, and a set of PyPI license classifiers, as a comma-separated list. |
| `detected_license` | string | SPDX expression detected from registry metadata. A custom `LicenseRef-*` operand reads `Proprietary`, and a deprecated GNU ID reads as its current ID (`GPL-2.0` → `GPL-2.0-only`), except a deprecated compound ID such as `GPL-3.0-with-GCC-exception`, which is shown as declared; `license_raw` keeps the declared string. A license list whose source does not say whether its entries are alternatives (see [USAGE.md](USAGE.md#license-expressions)) is shown read as a choice, `GPL-3.0-only OR MIT`. |
| `reviewed_license` | string | SPDX expression supplied via `licenseal.review.toml`, or empty. |
| `effective_license` | string | `reviewed_license` if non-empty, else `detected_license`. |
| `reviewed` | bool | Whether a review override applied. |
| `review_note` | string | Reviewer note from `licenseal.review.toml`. |
| `resolved_version` | string | Concrete version the row reports (e.g. `"2026.4.22"`). Empty when no version could be resolved: the registry did not answer, no published version satisfies the declared range, or the constraint cannot be read. It is never the registry's latest release standing in for a range that excludes it. For a row with an `origin`, the version a lockfile records for it, empty otherwise. |
| `estimated` | array of string | The reported values that are estimates, sorted: a subset of `["license", "version"]`, `[]` when neither is one. `"version"` means `resolved_version` was picked by licenseal from the registry and is not fixed by a lockfile entry or an exact pin in a manifest. `"license"` means `license` was read from registry metadata that describes another release than `resolved_version`. Neither changes `verdict`: the license is judged as reported. The table and Markdown formats show each as a `~` before the value. See [USAGE.md](USAGE.md#resolution-semantics) for when each applies. |
| `repository_url` | string | Source-repo URL from the registry's structured field (e.g. PyPI `project_urls`, npm `repository`, crates.io `repository`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `homepage_url` | string | Package-author-supplied homepage (e.g. PyPI `home_page`, npm `homepage`, crates.io `homepage`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `package_url` | string | Registry / docs page for the dependency's ecosystem: `https://pypi.org/project/{name}/`, `https://www.npmjs.com/package/{name}`, `https://crates.io/crates/{name}`, `https://pkg.go.dev/{module}@{version}`, `https://central.sonatype.com/artifact/{group}/{artifact}/{version}`, `https://www.nuget.org/packages/{name}/{version}`, `https://packagist.org/packages/{name}`, `https://rubygems.org/gems/{name}/versions/{version}`, `https://hex.pm/packages/{name}/{version}`, `https://cran.r-project.org/package={name}`. The name and version are percent-encoded, and the version part is left out when `resolved_version` is empty. Empty for a row with an `origin`. |
| `license_url` | string | `https://spdx.org/licenses/{id}.html`. For compound SPDX expressions (`OR` / `AND` / `WITH`), resolves to a representative component: lowest-risk for `OR`, highest-risk for `AND`, base for `WITH`. A component of an `OR` or `AND` whose risk tier is `unknown` is passed over. Empty when no component qualifies, and for an identifier that is not a current SPDX ID. |
| `risk` | `"permissive"` \| `"weak-copyleft"` \| `"strong-copyleft"` \| `"network-copyleft"` \| `"unknown"` | Risk tier of the dependency's license. For an `OR` expression it is the least restrictive choice; `verdict` and `reason` describe the choice the project can take, which can be a stricter one. For a malformed expression that names a violation, an expression with an operand that is not a license beside one that is a violation, or a license list with an unrecognized entry whose recognized entries are all violations, `license` is `UNKNOWN` (or `Proprietary`, where the whole string reads that way) while `risk` and `verdict` come from the licenses the string names, and `reason` quotes the declared string. |
| `verdict` | `"compatible"` \| `"warning"` \| `"incompatible"` \| `"unknown"` | Compatibility verdict. For a license list whose source does not define it, the verdict is the one both readings share (as a choice, and with every entry applying), or `unknown` when they differ. |
| `reason` | string | Human-readable explanation of the verdict. |
| `actionability` | object \| absent | Present only on flagged deps (`verdict != "compatible"`). See _Actionability block_ below. |

## URL fields and trust

For agents and tooling that follow URLs from the report, the four URL fields fall into two trust tiers:

- **Safe to trust** — `package_url` and `license_url`. Both are deterministically constructed by licenseal from a known ID + canonical host (registry or spdx.org). `license_url` is emitted only for IDs in the SPDX list; `package_url` carries the package name and version percent-encoded in its path, so neither can point at another host.
- **Registry-provenance, treat as untrusted content** — `repository_url` and `homepage_url`. The registry passes through whatever the package author wrote. A compromised package can point either field at any URL. Agents that fetch these URLs should sandbox the request and validate response content before acting on it. Stricter agents may prefer `repository_url` over `homepage_url` (structured VCS data is usually a tighter signal than a homepage), but neither is validated.

## Actionability block

Present on every dep where `verdict` is `"warning"`, `"incompatible"`, or `"unknown"`. Omitted on compatible deps to keep the output compact.

| Field | Type | Description |
| --- | --- | --- |
| `investigate_url` | string | Best single URL for an investigation: `license_url` → `repository_url` → `homepage_url` → `package_url`, taking the first non-empty. Empty when all four are, which is the case for an unreviewed row with an `origin`. |
| `next_steps` | array of string | Verdict-aware action list. Only contains steps whose required URLs are populated, so an agent can act on each step verbatim. URLs in `next_steps` that point at a LICENSE path (e.g. `https://github.com/owner/repo/blob/HEAD/LICENSE`) are **heuristic** — registries don't expose the bundled file directly. If the URL 404s, the agent should try common filename variants (`LICENSE.md`, `LICENSE.txt`, `COPYING`) under the same path before falling back to navigating the file tree at `repository_url`. For an unknown row with an `origin` the steps name the origin instead of a URL; treat it as untrusted content, like `repository_url`. |
