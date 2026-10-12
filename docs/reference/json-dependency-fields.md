---
title: "Dependency fields"
description: "Every field of a dependencies entry in the JSON report."
---

# Dependency fields

The fields of each entry of `dependencies` in the [JSON report](json-report.md).

One entry per package, resolved version, and origin: no two entries of `dependencies` have the same `ecosystem`, `name`, `resolved_version`, and `origin`. `name` is compared the way the ecosystem's registry compares names, so in .NET, PHP, Rust, Hex, R, and Python two spellings of one package are one entry. Declarations that resolve to the same version are merged: the entry is `prod` when any of them is, direct when any is, and carries the `source` of the first direct declaration.

String fields are reported verbatim: the table and Markdown formats escape control characters and markup for display, JSON does not.

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Package name as the manifest or lockfile writes it (see `registry_name`); a package installed under an npm alias is reported under its real name. |
| `registry_name` | string | Empty unless the package is published under another name than `name`: a Hex dependency that `mix.exs` renames (`{:my_alias, "~> 1.0", hex: :real_pkg}`) has the local name in `name` and the hex.pm package here. That is the `package` a [review entry](review-file.md) for it must carry. |
| `ecosystem` | `"python"` \| `"npm"` \| `"rust"` \| `"go"` \| `"java"` \| `"dotnet"` \| `"php"` \| `"ruby"` \| `"hex"` \| `"r"` | Ecosystem of the package. |
| `group` | `"prod"` \| `"dev"` | Production or development. A transitive is `prod` when a production dependency pulls it in. |
| `depth` | int | `0` for a direct dependency, `1` for a transitive. A binary direct/transitive signal, not a tree level. Every entry from a `gradle.lockfile` or a `paket.lock` is `0`: those files do not tell direct from transitive. |
| `direct_ancestors` | array of string | Depth-0 dependencies that pull this entry in (sorted). Empty for a direct dependency, and for a transitive whose ancestors the lockfile does not tell. |
| `is_transitive` | bool | Equivalent to `depth > 0`. |
| `source` | string | Path, relative to the scanned directory, of the manifest that declares the direct dependency (e.g. `pyproject.toml`, `requirements-dev.txt`, `packages/foo/Cargo.toml`). Uses forward slashes on all platforms. Empty for a transitive, and for a lockfile package that no scanned manifest declares at its version (such a package of a `paket.lock` carries the path of the `paket.lock`). |
| `source_url` | string | Identical to `source`, for use as a relative link; it is not percent-encoded. |
| `origin` | string | Empty for a registry package. For an [off-registry dependency](../concepts/off-registry.md), the source it comes from, in one string: `git+<url>@<commit>` (or `@<ref>`), `<url>#<hash>`, a path as written, a lockfile's own source label (`Bioconductor`), or `unrecorded source`. Credentials in a URL are removed. For such an entry `license` is `UNKNOWN` unless reviewed, `package_url` is empty, and a review is keyed on this string: it goes in the `source` key of the review entry, which is not the `source` field above. |
| `license` | string | Effective SPDX expression. Equal to `effective_license`. |
| `license_raw` | string | Original license string from the registry, before normalization. A deps.dev `licenses` array with several entries is shown joined with `AND`; a RubyGems or Hex array, and a set of PyPI license classifiers, as a comma-separated list. |
| `detected_license` | string | SPDX expression detected from registry metadata. A custom `LicenseRef-*` operand reads `Proprietary`, and a deprecated GNU ID reads as its current ID (`GPL-2.0` → `GPL-2.0-only`), except a deprecated compound ID such as `GPL-3.0-with-GCC-exception`, which is shown as declared; `license_raw` keeps the declared string. A license list whose source does not say whether its entries are alternatives (see [License expressions](../concepts/license-expressions.md)) is shown read as a choice, `GPL-3.0-only OR MIT`. |
| `reviewed_license` | string | SPDX expression from `licenseal.review.toml`, normalized, or empty. |
| `effective_license` | string | `reviewed_license` if non-empty, else `detected_license`. |
| `reviewed` | bool | Whether a review entry applied. |
| `review_note` | string | Reviewer note from `licenseal.review.toml`. |
| `resolved_version` | string | Concrete version the entry reports (e.g. `"2026.4.22"`). Empty when no version could be resolved: the registry did not answer, no published version satisfies the declared range, or the constraint cannot be read. For an entry with an `origin`, the version a lockfile records for it, empty otherwise. |
| `estimated` | array of string | The reported values that are estimates, sorted: a subset of `["license", "version"]`, `[]` when neither is one. `"version"` means `resolved_version` was picked by licenseal from the registry and is not fixed by a lockfile entry or an exact pin in a manifest. `"license"` means `license` was read from registry metadata that describes another release than `resolved_version`. Neither changes `verdict`: the license is judged as reported. The table and Markdown formats show each as a `~` before the value. See [Versions and estimates](../concepts/version-resolution.md) for when each applies. |
| `repository_url` | string | Source-repo URL from the registry's structured field (e.g. PyPI `project_urls`, npm `repository`, crates.io `repository`, and the equivalent field per registry). Empty when the registry didn't expose one. See [URLs and next steps](json-urls.md). |
| `homepage_url` | string | Package-author-supplied homepage (e.g. PyPI `home_page`, npm `homepage`, crates.io `homepage`, and the equivalent field per registry). Empty when the registry didn't expose one. See [URLs and next steps](json-urls.md). |
| `package_url` | string | The package's page on its registry (`https://pypi.org/project/{name}/`, …). The name and version are percent-encoded. The Go, Maven, NuGet, RubyGems, and Hex pages carry the version, left out when `resolved_version` is empty; the others never do. Empty for an entry with an `origin`. |
| `license_url` | string | `https://spdx.org/licenses/{id}.html`. For compound SPDX expressions (`OR` / `AND` / `WITH`), resolves to a representative component: lowest-risk for `OR`, highest-risk for `AND`, base for `WITH`. A component of an `OR` or `AND` whose risk tier is `unknown` is passed over. Empty when no component qualifies, and for an identifier that is not a current SPDX ID. |
| `risk` | `"permissive"` \| `"weak-copyleft"` \| `"strong-copyleft"` \| `"network-copyleft"` \| `"unknown"` | Risk tier of the dependency's license. For an `OR` expression it is the least restrictive choice; `verdict` and `reason` describe the choice the project can take, which can be a stricter one. `license` can be `UNKNOWN` (or `Proprietary`, where the whole string reads that way) while `risk` and `verdict` report a violation: when the declared string is a malformed expression, an `AND` expression with an operand that is not a license, or a license list with an unrecognized entry, and a license it names is a violation (in a list, every recognized entry), `risk` and `verdict` come from the licenses it names and `reason` quotes the declared string. |
| `verdict` | `"compatible"` \| `"warning"` \| `"incompatible"` \| `"unknown"` | Compatibility verdict; `incompatible` is what the rest of this site calls a violation. For a license list whose source does not define it, the verdict is the one both readings share (as a choice, and with every entry applying), or `unknown` when they differ. |
| `reason` | string | Human-readable explanation of the verdict. |
| `actionability` | object \| absent | Present only on flagged entries (`verdict != "compatible"`). See [URLs and next steps](json-urls.md#actionability-block). |
