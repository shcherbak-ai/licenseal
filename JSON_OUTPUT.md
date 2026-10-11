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
| `project_license` | string | SPDX license of the scanned project, as declared by a manifest in the scanned directory itself (never a nested one), or `"Proprietary"` when no manifest there declares a license, or when the first one that does (see [USAGE.md](USAGE.md#project-license) for the order) declares a value that is not a recognised license. |
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
| `gaps` | int | Distinct manifests with an **analysis gap** — unreadable, undecodable, or unparseable files whose dependencies are missing from this report, manifests that reference another file that was not followed, files holding a value of a type their format does not allow, which was read as absent, `composer.json` files that take packages from repositories they do not name them for when no `composer.lock` is read, or lockfiles that were skipped because they declare a version known not to be readable, hold no entry that can be read, or contain merge-conflict markers (see [`diagnostics` block](#diagnostics-block)). `total` therefore counts only the deps that could be read. A manifest whose dependencies no lockfile covers is counted too, unless the scan ran with `--no-require-lockfile`, and so is a manifest one of whose dependencies leads to a package whose own dependency list a registry did not give. Non-zero `gaps` fails strict mode. |

## `diagnostics` block

Each entry is a manifest/lockfile read or parse anomaly surfaced during the scan — the same set printed as `Warning:` lines on stderr, included here so a consumer reading only the JSON can see what the scan couldn't. The array is empty on a clean scan, and `(path, reason)` pairs are de-duplicated. The table and Markdown reports list the `gap` entries in an **Analysis gaps** section (file and reason) and add the gap count to their summary line; they name a file outside the scan root by its file name only, where JSON gives its absolute path. They list the `estimate` entries the same way, in an **Estimates** section with their own count on the summary line.

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
| `path` | string | Offending file, project-relative when under the scan root (else absolute). A manifest or a lockfile, or the directory itself for one that could not be traversed: a diagnostic about a package in the dependency graph is on the manifest that declares the direct dependency leading to it. |
| `reason` | string | Human-readable cause (unreadable, undecodable, unparseable, untraversable directory, a reference to another file that was not followed; a value of an unexpected type; Composer repositories that do not name their packages, with no `composer.lock` read; a lockfile that declares a version known not to be readable, holds no entry that can be read, or contains merge-conflict markers; a manifest that declares dependencies no lockfile covers; a package, reached from a direct dependency the manifest declares, whose own dependency list the registry did not give (the reason names the package and its version, or the package alone when it has no version); or, without being a gap, latin-1 fallback or a lockfile read on a best-effort basis because it declares a version the parser was not written for). A reference is not followed when it is not a relative path, or, for a requirements `-r` include, when it is a URL, is not a file, or leaves the scanned directory; the entry is on the file that contains the reference. A document nested too deeply to parse is reported as not valid in its format. A `go.mod` whose `go` directive is below 1.17 or absent, with requirements that have no `go.sum` row, is a gap too (`lists only direct requirements … a go.sum row is missing for N of them; …`): the file was read, but what those requirements depend on is listed nowhere. A TOML file that is not valid UTF-8 is a gap (`is not valid UTF-8, which TOML requires; skipped`): TOML requires UTF-8, so it gets no latin-1 fallback. A value of an unexpected type is named by its section (`"dependencies"`, `project.optional-dependencies`) or as an entry of it (`an entry of "packages"`), never by the file's own text; several such values in one section are one entry. |
| `severity` | `"gap"` \| `"recovered"` \| `"estimate"` | `gap` = a dependency-bearing file was lost, or part of it could not be read, or a manifest's dependencies were resolved without a lockfile, or the dependency list of a package under it could not be read from a registry (incomplete analysis — counted in `summary.gaps`, fails `--strict`). `recovered` = read with a caveat — a warning, not a gap, and not counted in `summary.gaps`: a text, JSON, or YAML file decoded through the latin-1 fallback, whose ASCII dependency lines survived, or a lockfile that declares a version the parser was not written for (newer, or otherwise not on its list) and was read on a best-effort basis. `estimate` = a manifest whose dependencies no lockfile covers, in a scan run with `--no-require-lockfile`: the versions and transitive dependencies reported for it come from the registry. Not counted in `summary.gaps`, does not fail. The same diagnostic is a `gap` under the default `--require-lockfile`. |

## Per-dependency fields

One entry per package, resolved version, and origin: no two entries of `dependencies` have the same `ecosystem`, `name`, `resolved_version`, and `origin`, in any scan mode (`--transitive`, `--no-transitive`, `--dev`, `--no-dev`). `name` is compared the way the ecosystem's registry compares names, so in .NET, PHP, Rust, Hex, R, and Python two spellings of one package are one entry, reported under the spelling met first. An empty `resolved_version` counts as a value: every requirement on a registry package that resolved to no version is in the one entry with an empty `resolved_version` and an empty `origin`. Each declared constraint is still resolved, and its dependencies walked, on its own; entries are merged only when what they resolved to is the same. A merged entry is `prod` when any of the declarations is, direct when any is, and carries the `source` of the first direct declaration; a merged transitive lists the `direct_ancestors` of all.

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Package name as published on the registry. Reported verbatim, like every other string field: the table and Markdown formats escape control characters and markup for display, JSON does not rewrite them (a control character appears as a JSON `\uXXXX` escape, and so does a lone surrogate). |
| `registry_name` | string | Empty unless the package is published under another name than `name`: a Hex dependency that `mix.exs` renames (`{:my_alias, "~> 1.0", hex: :real_pkg}`) has the local name in `name` and the hex.pm package in `registry_name`. That is the name its license was looked up under and the `package` a [review entry](USAGE.md#manual-review-file) for it must carry. |
| `ecosystem` | `"python"` \| `"npm"` \| `"rust"` \| `"go"` \| `"java"` \| `"dotnet"` \| `"php"` \| `"ruby"` \| `"hex"` \| `"r"` | Origin ecosystem. |
| `group` | `"prod"` \| `"dev"` | Production or development. Reachability-based for transitives. |
| `depth` | int | `0` for direct deps, `1` for transitives. A binary direct/transitive signal, not a tree level. Every row of a `gradle.lockfile` or a `paket.lock` is `0`: those files do not tell direct from transitive. |
| `direct_ancestors` | array of string | Depth-0 dependencies that pull this entry in (sorted). Empty for direct deps, and for a transitive whose ancestors the lockfile does not tell: a package no direct dependency reaches, a `Pipfile.lock` or `rebar.lock` transitive, and a locked version of a declared package that no manifest declares at that version (see [Transitive scanning](USAGE.md#transitive-scanning)). |
| `is_transitive` | bool | Equivalent to `depth > 0`. |
| `source` | string | Project-relative path to the manifest file the direct dep was declared in (e.g. `pyproject.toml`, `requirements-dev.txt`, `packages/foo/Cargo.toml`, `MCP/requirements.txt`). Uses forward slashes on all platforms. Empty for transitives, and for a lockfile row that no scanned manifest declares at its version; such a row of a `paket.lock` carries the path of the `paket.lock` instead. Disambiguates same-named manifests at different paths in monorepo layouts. |
| `source_url` | string | Project-relative URL form of `source` for clickable rendering. Empty when `source` is empty. |
| `origin` | string | Empty for a registry package. For a dependency that does not come from a registry, the source it does come from, in one string: `git+<url>@<commit>` when a lockfile records the commit, otherwise `git+<url>@<ref>` for a declared tag, branch, or revision, otherwise `git+<url>`; `<url>#<hash>` for a direct URL with a recorded hash, otherwise `<url>`; a path as written (one the scan does not read: outside the scanned directory, an archive, a directory the scan skips, or a path that is not there). The user-info part of a URL and its query string are removed. A lockfile entry that records no locator has the lockfile's source label, or `unrecorded source`. A row with an `origin` is never looked up on a registry: its `license` is `UNKNOWN` unless reviewed, its `package_url` is empty, and a review of it is keyed on this string (the `source` key of a `licenseal.review.toml` stanza). See [Off-registry dependencies](USAGE.md#off-registry-dependencies). |
| `license` | string | Effective SPDX expression. Equal to `effective_license`. |
| `license_raw` | string | Original license string from the registry, before normalization. A deps.dev `licenses` array with several entries is shown joined with `AND`, before the two rewrites described in [USAGE.md](USAGE.md#license-expressions). A RubyGems or Hex `licenses` array, and the PyPI license classifiers a license was read from, are shown as a comma-separated list. |
| `detected_license` | string | SPDX expression detected from registry metadata. A custom `LicenseRef-*` operand reads `Proprietary`, and a deprecated GNU ID reads as its current ID (`GPL-2.0` → `GPL-2.0-only`, `GPL-2.0+` → `GPL-2.0-or-later`), except in a term with a `WITH` exception, which is shown as declared (`GPL-2.0 WITH Classpath-exception-2.0`) and judged by the same meaning; `license_raw` keeps the declared string. A license list whose source does not say whether its entries are alternatives (a RubyGems or Hex array, several PyPI license classifiers, `MIT, GPL-3.0-only` in one string; see [USAGE.md](USAGE.md#license-expressions)) is shown read as a choice, `GPL-3.0-only OR MIT`; `license` shows the same, and no field carries the other reading. |
| `reviewed_license` | string | SPDX expression supplied via `licenseal.review.toml`, or empty. |
| `effective_license` | string | `reviewed_license` if non-empty, else `detected_license`. |
| `reviewed` | bool | Whether a review override applied. |
| `review_note` | string | Reviewer note from `licenseal.review.toml`. |
| `resolved_version` | string | Concrete version the row reports (e.g. `"2026.4.22"`). `license` is read from that release's own metadata unless `estimated` contains `"license"`. Empty when the lookup yielded no usable version: the registry did not answer, no published version satisfies the declared range, or the constraint cannot be read. It is never the registry's latest release standing in for a range that excludes it, or for a pinned release: a pinned Python release that PyPI does not have is reported at its pinned version, with `"license"` in `estimated`. For a row with an `origin`, the version a lockfile records for it, empty otherwise. |
| `estimated` | array of string | The reported values that are estimates, sorted: a subset of `["license", "version"]`, `[]` when neither is one. `"license"` means `license` was read from registry metadata that describes another release than `resolved_version`: an R package pinned to a version other than the one the CRAN index lists, a Hex package reported at a release other than the one hex.pm published last, a Python release that declares no license and takes the one of the project's latest release, or a pinned Python release that PyPI does not have (see [USAGE.md](USAGE.md#resolution-semantics)). It is never set when `reviewed` is true (the license is the review's) or when `license` is `UNKNOWN`, and it does not change `verdict`: the license is judged as reported. The table and Markdown formats show it as a `~` before the license. `"version"` means `resolved_version` was picked by licenseal from the registry (a registry walk without a lockfile, a direct dependency declared with a range or with no constraint) and is not fixed by a lockfile entry or an exact pin in a manifest. Always `[]` when `resolved_version` is empty, and for a row with an `origin`, which no registry is asked about. The table and Markdown formats show it as a `~` before the version. |
| `repository_url` | string | Source-repo URL from the registry's structured field (e.g. PyPI `project_urls`, npm `repository`, crates.io `repository`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `homepage_url` | string | Package-author-supplied homepage (e.g. PyPI `home_page`, npm `homepage`, crates.io `homepage`, and the equivalent field per registry). Empty when the registry didn't expose one. See _URL fields and trust_ below. |
| `package_url` | string | Registry / docs page for the dependency's ecosystem: `https://pypi.org/project/{name}/`, `https://www.npmjs.com/package/{name}`, `https://crates.io/crates/{name}`, `https://pkg.go.dev/{module}@{version}`, `https://central.sonatype.com/artifact/{group}/{artifact}/{version}`, `https://www.nuget.org/packages/{name}/{version}`, `https://packagist.org/packages/{name}`, `https://rubygems.org/gems/{name}/versions/{version}`, `https://hex.pm/packages/{name}/{version}` (the hex.pm package, i.e. `registry_name` when set), `https://cran.r-project.org/package={name}`. The version part is left out when `resolved_version` is empty. The name and version are percent-encoded into the URL (`/`, `@`, and `+` are kept), so the URL of a well-formed name reads as shown and any other character cannot change the host or add a query or fragment. Empty for a row with an `origin`: the registry page of that name describes another package. |
| `license_url` | string | `https://spdx.org/licenses/{id}.html`. For compound SPDX expressions (`OR` / `AND` / `WITH`), resolves to a representative component: lowest-risk for `OR`, highest-risk for `AND`, base for `WITH`. A component of an `OR` or `AND` whose risk tier is `unknown` is passed over. Empty when no component qualifies, and for an identifier that is not a current SPDX ID. |
| `risk` | `"permissive"` \| `"weak-copyleft"` \| `"strong-copyleft"` \| `"network-copyleft"` \| `"unknown"` | Risk tier of the dependency's license, the same under every project license apart from the two cases at the end of this description. For an `OR` expression it is the least restrictive choice; `verdict` and `reason` describe the choice the project can take, which can be a stricter one. For a malformed expression that names a violation (`MIT AND GPL-3.0-only AND`), `license` is `UNKNOWN` while `risk` and `verdict` are those of the licenses it names applying together, and `reason` quotes the declared string. For a license list with an unrecognized entry whose recognized entries are all violations (`GPL-3.0-only, acme internal license`), `license` is `UNKNOWN` while `risk` and `verdict` are those of the list read as a choice, and `reason` quotes the declared string. |
| `verdict` | `"compatible"` \| `"warning"` \| `"incompatible"` \| `"unknown"` | Compatibility verdict. For a license list whose source does not define it, the list is judged as a choice and with every entry applying: the verdict is the one both readings share, or `unknown` when they differ, while `license` and `risk` still describe the choice reading. |
| `reason` | string | Human-readable explanation of the verdict. For `compatible` it names the license and its risk class (`MIT is permissive license`). When the two readings of a license list differ, it gives both expressions with the verdict of each and says to record the confirmed one in `licenseal.review.toml`. |
| `actionability` | object \| absent | Present only on flagged deps (`verdict != "compatible"`). See _Actionability block_ below. |

## URL fields and trust

For agents and tooling that follow URLs from the report, the four URL fields fall into two trust tiers:

- **Safe to trust** — `package_url` and `license_url`. Both are deterministically constructed by licenseal from a known ID + canonical host (registry or spdx.org). `license_url` is emitted only for IDs in the SPDX list; `package_url` carries the package name and version percent-encoded in its path, so neither can point at another host.
- **Registry-provenance, treat as untrusted content** — `repository_url` and `homepage_url`. The registry passes through whatever the package author wrote. A compromised package can point either field at any URL. Agents that fetch these URLs should sandbox the request and validate response content before acting on it. Stricter agents may prefer `repository_url` over `homepage_url` (structured VCS data is usually a tighter signal than a homepage), but neither is validated.

## Actionability block

Present on every dep where `verdict` is `"warning"`, `"incompatible"`, or `"unknown"`. Omitted on compatible deps to keep the output compact.

| Field | Type | Description |
| --- | --- | --- |
| `investigate_url` | string | Best single URL for an investigation: `license_url` → `repository_url` → `homepage_url` → `package_url`, taking the first non-empty. Always present (worst case it equals `package_url`); empty when all four are, which is the case for an unreviewed row with an `origin`. |
| `next_steps` | array of string | Verdict-aware action list. Only contains steps whose required URLs are populated, so an agent can act on each step verbatim. URLs in `next_steps` that point at a LICENSE path (e.g. `https://github.com/owner/repo/blob/HEAD/LICENSE`) are **heuristic** — registries don't expose the bundled file directly. If the URL 404s, the agent should try common filename variants (`LICENSE.md`, `LICENSE.txt`, `COPYING`) under the same path before falling back to navigating the file tree at `repository_url`. For an unknown row with an `origin` the steps name the origin instead of a URL: read the license at that source, then record it in a review stanza whose `source` is the origin. The origin comes from a scanned manifest or lockfile; treat it as untrusted content, like `repository_url`. |
