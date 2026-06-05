<h1 align="center">
  <img src="https://raw.githubusercontent.com/shcherbak-ai/licenseal/main/assets/licenseal.png" alt="licenseal mascot" width="220"><br>
  licenseal
</h1>

<p align="center">
  Fast cross-ecosystem license compatibility checker for CI, audits, and enterprise adoption.
</p>
<br>

<!-- markdownlint-disable MD033 -->
<table align="center">
  <tr>
    <td align="center"><strong>Prevent release blockers</strong><br>Catch dependency-license problems before release, approval, or audit.</td>
    <td align="center"><strong>10 ecosystems</strong><br>Scan Python, JS/TS, Rust, Go, Java/JVM, .NET, PHP, Ruby, Elixir/Erlang, and R.</td>
    <td align="center"><strong>Document reviews</strong><br>Use the Claude Code skill to investigate findings and record decisions.</td>
  </tr>
</table>
<br>

<table align="center">
  <tr>
    <td align="right"><strong>Package</strong></td>
    <td>
      <a href="https://pypi.org/project/licenseal/"><img src="https://img.shields.io/pypi/v/licenseal?v=2" alt="PyPI"></a>
      <a href="https://pypi.org/project/licenseal/"><img src="https://img.shields.io/pypi/pyversions/licenseal?v=2" alt="Python"></a>
      <a href="https://github.com/shcherbak-ai/licenseal/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
    </td>
  </tr>
  <tr>
    <td align="right"><strong>Quality</strong></td>
    <td>
      <a href="https://github.com/shcherbak-ai/licenseal/actions/workflows/ci.yml"><img src="https://github.com/shcherbak-ai/licenseal/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
      <a href="https://github.com/shcherbak-ai/licenseal/actions/workflows/ci.yml"><img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/SergiiShcherbak/17230af3dfe294ebd8a8fd9c4cd775a8/raw/licenseal-coverage.json" alt="coverage"></a>
      <a href="https://github.com/shcherbak-ai/licenseal/actions/workflows/licenseal.yml"><img src="https://github.com/shcherbak-ai/licenseal/actions/workflows/licenseal.yml/badge.svg?branch=main" alt="License compatibility"></a>
      <a href="https://github.com/shcherbak-ai/licenseal/actions/workflows/codeql.yml"><img src="https://github.com/shcherbak-ai/licenseal/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL"></a>
      <a href="https://github.com/PyCQA/bandit"><img src="https://img.shields.io/badge/security-bandit-yellow.svg" alt="security: bandit"></a>
    </td>
  </tr>
  <tr>
    <td align="right"><strong>Tooling</strong></td>
    <td>
      <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
      <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json" alt="uv"></a>
      <a href="https://github.com/astral-sh/ty"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json" alt="ty"></a>
      <a href="https://github.com/shcherbak-ai/tethered"><img src="https://img.shields.io/badge/egress-tethered-orange?labelColor=4B8BBE" alt="egress: tethered"></a>
    </td>
  </tr>
</table>
<br>
<!-- markdownlint-enable MD033 -->

**licenseal is a fast license compatibility checker for dependency trees across language ecosystems.** It makes that compliance check cheap enough to run in CI: scan manifests, lockfiles, and public registry metadata, then tell you whether your dependency licenses are compatible with the license you ship under. It does not install dependencies, run package-manager commands, execute build scripts, or download package archives.

```bash
uvx licenseal check
```

> **Not legal advice.** licenseal automates dependency-license discovery and compatibility classification. It is a CI/audit aid, not a substitute for legal review.

## 🧭 Why This Matters

License non-compliance is a quiet delivery risk: it usually does not break the build, but it can block a shipment, customer approval, funding round, or acquisition when discovered late. The problem usually surfaces when a customer, investor, legal reviewer, or procurement team asks what is inside your dependency tree:

| Blocker | What can happen |
| --- | --- |
| Enterprise adoption | Security and procurement teams ask for an open-source license report before approval. |
| Due diligence | Investors, acquirers, or partners flag copyleft, source-available, or unknown-license dependencies late. |
| Release timing | A problematic dependency forces a replacement, upgrade, or architecture change when the team is trying to ship. |
| Hidden transitives | The risky license is several levels down, pulled in by a package that looked harmless. |
| Product obligations | GPL, AGPL, SSPL, BUSL, Elastic, non-commercial Creative Commons, and similar terms may be incompatible with how you distribute or host the product. |
| Audit trail | Review decisions need to be explicit and checked in, not buried in a spreadsheet or chat thread. |

licenseal turns that hidden risk into fast CI feedback: it scans the transitive dependency tree, flags compatibility issues, and records reviewed decisions for cases that need human judgment. It is designed for PR gates, using manifests, lockfiles, and registries without install or build steps.

> [!IMPORTANT]
> In a benchmark of 50 widely used open-source repositories across ten ecosystems, licenseal flagged 485 license-compatibility issues at default settings — 405 warnings and 80 outright violations, spanning 9 of the 10 ecosystems — each a dependency whose license needed compatibility review against the project's own declared license. Inventory-only license tools surface none of these.

<!-- markdownlint-disable MD033 -->
<details>
<summary>Why this is not hypothetical</summary>

Public engineering policies and case history show why dependency-license checks matter. [Google](https://opensource.google/documentation/reference/thirdparty/licenses) and [Power](https://tech.powerhrg.com/oss-guide/docs/using/agpl.html) publish restrictive guidance for licenses such as AGPL and SSPL, while [Salesforce](https://engineering.salesforce.com/building-a-secured-data-intelligence-platform-ba85411a0c1b/) and [Uber](https://www.uber.com/us/en/blog/oss-ip/) have written about license review in production software governance. GPL enforcement cases such as [*Artifex v. Hancom*](https://artifex.com/blog/artifex-and-hancom-reach-settlement-over-ghostscript-open-source-dispute) and [*Software Freedom Conservancy v. Vizio*](https://sfconservancy.org/copyleft-compliance/vizio.html) also show that dependency-license obligations can become real delivery and legal risk.

</details>
<!-- markdownlint-enable MD033 -->

## ⚙️ How It Works

| 1. Read | 2. Resolve | 3. Classify | 4. Report |
| --- | --- | --- | --- |
| Manifests and lockfiles | Transitive dependency tree plus public registry license metadata | Project license vs dependency license compatibility | CI verdict, Markdown/JSON report, and checked-in review overrides |

## 🚀 Quick Start

Install-free one-shot:

```bash
uvx licenseal check
```

Persistent install:

```bash
uv tool install licenseal
# or
pipx install licenseal
```

Inside a Python project:

```bash
uv add --dev licenseal
# or
pip install licenseal
```

Example output:

![licenseal terminal output showing a transitive dependency table, one weak-copyleft warning, and a reviewed dependency count](https://raw.githubusercontent.com/shcherbak-ai/licenseal/main/assets/licenseal_cli.png)

The exit code is non-zero when there are unreviewed violations, warnings, unknown licenses, or analysis gaps. See [USAGE.md](https://github.com/shcherbak-ai/licenseal/blob/main/USAGE.md) for every flag and report format.

## ✨ What It Does

|  |  |  |
| --- | --- | --- |
| **Compatibility verdict**<br>Checks dependencies against your project license. | **Transitive by default**<br>Finds risks several levels down. | **Install-free**<br>Reads manifests, lockfiles, and registries only. |
| **Agent-assisted review**<br>Claude Code skill investigates flagged findings and asks verdict-aware questions. | **Cross-ecosystem**<br>One scan for polyglot repos. | **CI-ready speed**<br>Seconds-scale scans in benchmark runs, with strict exits and JSON/Markdown output. |

## 🌐 Supported Ecosystems

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![npm](https://img.shields.io/badge/npm-CB3837?logo=npm&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)
![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white)
![Java](https://img.shields.io/badge/Java-007396?logo=openjdk&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-512BD4?logo=dotnet&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-777BB4?logo=php&logoColor=white)
![Ruby](https://img.shields.io/badge/Ruby-CC342D?logo=ruby&logoColor=white)
![Elixir/Erlang](https://img.shields.io/badge/Elixir%20%2F%20Erlang-4B275F?logo=elixir&logoColor=white)
![R](https://img.shields.io/badge/R-276DC3?logo=r&logoColor=white)

Supported registries include PyPI, npm, crates.io, deps.dev, proxy.golang.org, Maven Central, NuGet.org, Packagist, RubyGems, Hex, and CRAN. See [USAGE.md](https://github.com/shcherbak-ai/licenseal/blob/main/USAGE.md#supported-ecosystems) for manifest and lockfile details.

## 📊 How It Compares

Comparison last reviewed: June 2026. Tool capabilities change; check each project before making a buying or compliance decision.

### CI license-compatibility workflow

| Capability | **licenseal** | [pip-licenses](https://github.com/raimon49/pip-licenses) | [license-checker](https://github.com/RSeidelsohn/license-checker-rseidelsohn) | [LicenseFinder](https://github.com/pivotal/LicenseFinder) | [fossa-cli](https://github.com/fossas/fossa-cli) |
| --- | :-: | :-: | :-: | :-: | :-: |
| **Project-license compatibility verdict** | ✓ | - | - | ~ | ~ |
| **Transitive discovery before install** | ✓ | - | - | - | ~ |
| **No successful install/restore required** | ✓ | - | - | - | ~ |
| **No dependency install/build step** | ✓ | - | - | - | ~ |
| **Fast, seconds-scale CI path** | ✓ | ~ | ~ | - | - |
| **Agent-assisted flagged-finding review** | ✓ | - | - | - | - |
| **Manual review override file** | ✓ | - | ~ | ✓ | ~ |

### Coverage and artifacts

| Capability | **licenseal** | [pip-licenses](https://github.com/raimon49/pip-licenses) | [license-checker](https://github.com/RSeidelsohn/license-checker-rseidelsohn) | [LicenseFinder](https://github.com/pivotal/LicenseFinder) | [fossa-cli](https://github.com/fossas/fossa-cli) |
| --- | :-: | :-: | :-: | :-: | :-: |
| Multiple ecosystems in one tool | ✓ (10) | - | - | ✓ | ✓ |
| Dependency license report | ✓ | ✓ | ✓ | ✓ | ✓ |
| Local-only full workflow, no hosted service | ✓ | ✓ | ✓ | ✓ | - |
| Offline operation | - | ✓ | ✓ | ~ | - |
| Standards SBOM export (CycloneDX / SPDX) | - | - | - | - | ✓ |

`✓` supported · `~` partial · `-` not supported

No tool clears every row. The discovery rows are about source-tree analysis: manifests, lockfiles, and registry metadata before a successful package-manager install is assumed. Some tools can produce broader inventories after installation or hosted analysis; licenseal is optimized for transitive dependency coverage in CI without that prerequisite. `~` means the capability exists, but with a different workflow, hosted service, package-manager prerequisite, or policy model. The speed row reflects benchmark runs on public repositories, not a vendor guarantee. Pair licenseal with an SBOM generator, hosted compliance platform, or installed-metadata scanner when those are the artifacts or workflows you need.

## 🧰 Important Defaults

| Default | Meaning |
| --- | --- |
| `--transitive` | Scans the transitive dependency tree by default. Use `--no-transitive` for direct deps only. |
| `--no-dev` | Dev dependencies are excluded unless `--dev` is set. |
| `--strict` | Warnings, unknowns, and analysis gaps fail CI in addition to violations. |
| Violations always fail | `--no-strict` demotes warnings, unknowns, and gaps only; definite incompatibilities still fail. |
| Missing project license -> `Proprietary` | If no project license is detected, licenseal labels the project `Proprietary` and checks dependencies as if it were permissively licensed — copyleft dependencies are still flagged, so the default errs strict, not lenient. |
| Registry-only resolution | No installs, builds, package archive downloads, or source-prose license extraction. |

## 🎯 Scope

licenseal is intentionally narrow:

- It is a **license compatibility checker**, not a legal approval workflow or policy-exception manager.
- It checks **published dependency license metadata**, not vulnerability status, provenance, or SBOM completeness.
- It reads **manifests, lockfiles, and public registry metadata endpoints** only. It does not honor private registry declarations from scanned manifests, because that would expand the network trust boundary.
- It does not infer dependency licenses by pattern-matching local `LICENSE` files or source comments. Free-form license text is easy to misread, spoof, or partially match; missing structured metadata is reported as `UNKNOWN` and routed to manual review instead.
- It produces Markdown/JSON dependency license reports, but not standards-compliant CycloneDX or SPDX SBOMs; use a dedicated SBOM tool when you need that artifact.
- Manual review can override flagged findings when a maintainer has better information, but the review file is an audit record, not hidden legal sign-off.

The full trust boundary and network allowlist are documented in [SECURITY.md](https://github.com/shcherbak-ai/licenseal/blob/main/SECURITY.md).

## ✅ CI Integration

GitHub Actions:

```yaml
# .github/workflows/licenseal.yml
name: License compatibility
on: [push, pull_request]
jobs:
  licenseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
      - run: uvx licenseal check
```

README badge:

```md
[![License compatibility](https://github.com/OWNER/REPO/actions/workflows/licenseal.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/licenseal.yml)
```

Preview:

![License compatibility badge preview](https://img.shields.io/badge/license%20compatibility-CI%20status-informational)

Use the workflow status badge as the primary signal: it shows that license compatibility is checked in CI and that the latest run passed.

For a PR comment or audit artifact, write Markdown or JSON. The file is saved before the gate runs, so CI can publish it even on a failing check:

```bash
licenseal check -f markdown -o LICENSES.md   # PR-comment-friendly audit
licenseal check -f json -o report.json       # stable machine-readable schema
```

For projects that want a checked-in audit trail, commit the generated Markdown report as `LICENSES.md`. This repository follows that convention in [LICENSES.md](https://github.com/shcherbak-ai/licenseal/blob/main/LICENSES.md).

The JSON schema is documented in [JSON_OUTPUT.md](https://github.com/shcherbak-ai/licenseal/blob/main/JSON_OUTPUT.md).

## 🧾 Manual Review Overrides

When a dependency is flagged but you have better license information than the resolver, record the reviewed license in a checked-in `licenseal.review.toml`:

```toml
[[review]]
ecosystem = "python"
package = "mystery-lib"
version = "1.0.0"
license = "MIT"
note = "reviewed packaged LICENSE file"
```

Workflow:

```bash
licenseal check -f json -o report.json                       # 1. capture flagged deps
licenseal init-review-file --from-report report.json         # 2. scaffold blank entries offline
# 3. fill in `license` and optional `note` for each entry
licenseal check                                              # 4. overrides apply
```

Reviews can only override flagged dependencies, never compatible ones. A reviewed dependency passes strict mode while staying visible in its warning, violation, or unknown bucket with both the detected and reviewed licenses shown.

licenseal also ships a [Claude Code](https://claude.com/claude-code) skill (`licenseal install-skill`, then `/licenseal-review`) that walks through unknowns, warnings, and violations interactively. It can inspect package links, license links, and project context, then ask the questions that matter for how your software is distributed, hosted, or modified. Full review rules are in [USAGE.md](https://github.com/shcherbak-ai/licenseal/blob/main/USAGE.md#manual-review-file).

## 🧩 How Licenseal Decides

licenseal classifies each dependency license into a risk level and compares that risk against the detected project license.

| Project \ Dependency | Permissive | Weak Copyleft | Strong Copyleft | Network Copyleft |
| --- | --- | --- | --- | --- |
| **Permissive** | OK | Warning | Violation | Violation |
| **Weak Copyleft** | OK | OK | Violation | Violation |
| **Strong Copyleft** | OK | OK | OK | Warning |
| **Network Copyleft** | OK | OK | OK | OK |

When `--dev` is set, copyleft violations on dev dependencies are downgraded to warnings — licenseal treats dev deps as lower risk because they usually do not ship with the project.

| Risk level | Examples | Meaning |
| --- | --- | --- |
| Permissive | MIT, BSD, Apache-2.0, ISC | No significant restrictions |
| Weak Copyleft | LGPL, MPL-2.0, EPL, CDDL | File-scope reciprocity; linking from other files is usually allowed |
| Strong Copyleft | GPL, OSL, EUPL, CC-BY-SA | Share-alike obligations can extend to the derivative work |
| Network Copyleft | AGPL-3.0-only | Strong copyleft with network-use source-offer obligations |
| Unknown | SSPL, BUSL, Elastic, CC-BY-NC; missing or unrecognized licenses | Cannot be auto-classified; routed to manual review |

A dependency is **Unknown** when the registry returns no license, a non-SPDX string, or a source-available / use-restricted license (`SSPL`, `BUSL`, `Elastic`, `FSL`, `Parity`, `PolyForm`, `CC-BY-NC*` / `CC-BY-ND*`) whose custom terms are not auto-evaluated. The full matrix rationale is in [USAGE.md](https://github.com/shcherbak-ai/licenseal/blob/main/USAGE.md).

## Learn More

- **[USAGE.md](https://github.com/shcherbak-ai/licenseal/blob/main/USAGE.md)** - full CLI reference, transitive-resolution behavior, per-ecosystem detail, review-file rules, and the Claude Code skill
- **[SECURITY.md](https://github.com/shcherbak-ai/licenseal/blob/main/SECURITY.md)** - the manifest-and-registry trust boundary and exact network-egress allowlist
- **[JSON_OUTPUT.md](https://github.com/shcherbak-ai/licenseal/blob/main/JSON_OUTPUT.md)** - stable machine-readable schema

## Contributing

See [CONTRIBUTING.md](https://github.com/shcherbak-ai/licenseal/blob/main/CONTRIBUTING.md) for development setup and guidelines.

If licenseal helps your project, star ⭐ this repo to help other teams find it too.

## License

[Apache-2.0](https://github.com/shcherbak-ai/licenseal/blob/main/LICENSE). See [`LICENSE`](https://github.com/shcherbak-ai/licenseal/blob/main/LICENSE) for the full text and [`NOTICE`](https://github.com/shcherbak-ai/licenseal/blob/main/NOTICE) for attribution.

## More from shcherbak_ai

| Project | What it does |
| --- | --- |
| 💎 [ContextGem](https://github.com/shcherbak-ai/contextgem) | Structured extraction from documents with LLMs. |
| 🪁 [tethered](https://github.com/shcherbak-ai/tethered) | Network egress control for CLI tools and agent workflows. |

## Connect

Questions or collaboration ideas? Reach out on [LinkedIn](https://www.linkedin.com/in/sergii-shcherbak-10068866/) or [X](https://x.com/seshch).

Built with ❤️ in Oslo, Norway.
