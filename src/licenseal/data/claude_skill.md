---
name: licenseal-review
description: Audit a project's dependency licenses with licenseal — scan deps, establish project context (distribution / commercial / linkage), walk the user through flagged warnings / violations / unknowns with verdict-aware questions, record explicit reviews with documented rationale in licenseal.review.toml, and save LICENSES.md as the audit deliverable. Honest assessment — reviewed entries pass CI; real incompatibilities stay flagged.
when_to_use: Trigger only when the user explicitly wants to audit or review their project's dependency licenses, investigate licenseal-flagged dependencies, resolve license warnings / violations / unknowns, or generate or extend licenseal.review.toml. Do NOT trigger for a one-off "what license does package X use?" identification, general licensing discussion, or a single-dependency lookup — only for a full dependency-license compatibility audit or acting on flagged deps.
---

# licenseal review

## Prerequisites

Determine the right invocation for `licenseal` **before** running anything else. Detect the project tooling from the project root and pick the matching invocation:

| Signal | Invocation to use everywhere below |
| --- | --- |
| `uv.lock` exists, or `pyproject.toml` has `[tool.uv]` / dependency-groups, or `.python-version` exists | `uv run licenseal ...` |
| `poetry.lock` exists | `poetry run licenseal ...` |
| `pdm.lock` exists | `pdm run licenseal ...` |
| `pipenv` `Pipfile.lock` exists | `pipenv run licenseal ...` |
| None of the above | `licenseal ...` (assumes a global install via `uv tool install` / `pipx install` / `pip install`, or an activated venv) |

Verify the chosen invocation with `<invocation> --version` (e.g. `uv run licenseal --version`), and use that prefix for every `licenseal` command below.

If the chosen invocation fails:

- For a tool-managed project (uv / poetry / pdm / pipenv), licenseal isn't a project dependency. Ask the user to add it: `uv add licenseal --dev` (or the equivalent for their tool).
- For an unmanaged project, ask the user to install globally: `uv tool install licenseal` (recommended) or `pipx install licenseal` or `pip install licenseal`.

## Posture

This skill produces an honest license-compatibility assessment; it does **not** try to make every flagged dependency pass. Some dependencies stay flagged after it runs: that is the correct outcome when an incompatibility is real and the user has no override evidence.

- The review file overrides **detection** ("the resolver got the license wrong, here's the actual SPDX ID I confirmed") or records an **accepted** verdict with a documented rationale. A reviewed dependency is classified by its reviewed license: a detection override to a license the project can take is reported as compatible, and a dependency reviewed under a license that still classifies as `warning`, `incompatible`, or `unknown` keeps that classification in the report. Strict mode treats a reviewed entry as passing; the `note` is the audit trail.
- Project context (SaaS / library / internal / commercial, gathered in step 3) can change which obligations apply. Use it to ask the right question for each dependency, never to manufacture an exception that doesn't apply.
- Unreviewed flagged dependencies left at the end are an output of the audit: they tell the user what they still need to act on (remove, replace, accept the legal risk, or seek legal review).
- When in doubt, leave the dependency unreviewed. It is a question the user can revisit; a wrong review entry is a silent audit-trail problem.

## Procedure

### 1. Run the scan

Ask the user once whether dev dependencies are in scope. If they are, use `--dev` in place of `--no-dev` in every `licenseal check` command of this procedure.

Pick a temp path for the scan JSON, `$SCAN_FILE` below. It is used until the end of step 7.

| Shell | Suggested temp path |
| --- | --- |
| bash / zsh | `SCAN_FILE=$(mktemp)` |
| PowerShell | `$SCAN_FILE = (New-TemporaryFile).FullName` |

Then, from the project root (the scanned directory):

```bash
licenseal check --no-dev -f json --no-strict -o "$SCAN_FILE"
```

Keep the command's stderr: step 2 reads its `Warning:` lines.

- A non-zero exit with the JSON written is expected when violations exist.
- On a re-audit the command can fail and write no JSON, because `licenseal.review.toml` holds filled entries that no longer apply:
  - `Reviewed licenses did not match any resolved package versions`: the listed entries are for a version or `source` the project no longer resolves, or for a dependency this scan leaves out (a dev dependency in a scan without `--dev`).
  - `Review entries can only override flagged dependencies`: the listed entries match dependencies that are now compatible.

  Show the user the listed entries. If this scan ran without `--dev`, run it once with `--dev`: an entry that is no longer listed is for a dev dependency, so keep it and use `--dev` here and in every later command. An entry that is still listed is stale: note its `license` and `note`, delete it from the file, and run the scan again. A dependency that is flagged at its new version or source is walked in step 4 like any other: tell the user what the deleted entry recorded and ask whether it still holds.

### 2. Read the summary

Parse `$SCAN_FILE`. Every field used below is named here; the full schema is in licenseal's documentation (<https://shcherbak-ai.github.io/licenseal/reference/json-report/>), which is not installed with this skill, so do not look for it locally. Report to the user:

- `project_license`, and `project_license_source`: the manifest in the scanned directory that declared it. When `project_license_source` is `""`, say that the project was checked as `Proprietary`.
- `summary.total` dependencies scanned
- `summary.warnings + summary.violations + summary.unknown` flagged
- `summary.gaps` analysis gaps

Then:

- Flagged total and `summary.gaps` both `0`: the project is clean for the project license shown. Say so and stop.
- Flagged `0` and `summary.gaps > 0`: the project is **not** clean. Handle the gaps as below, and stop.
- Flagged above `0`: handle any gaps as below, and continue.

**Analysis gaps.** A gap is an incomplete analysis, not a license finding: in strict mode it fails `check` by itself, and no review entry clears it. Each gap is an entry of the top-level `diagnostics[]` with `severity: "gap"`, a `path` and a `reason`; ignore entries of severity `recovered`, and treat `estimate` as already accepted. Tell the user each gap's `path` and `reason`, that it must be settled outside the review file, and what to do:

| `reason` starts with | Meaning | What to do |
| --- | --- | --- |
| `declares dependencies that no lockfile covers` | There is no lockfile, or the lockfile holds no version the manifest's declaration admits. licenseal picked versions and transitive dependencies from the registry, so the report is an estimate for that manifest. Each such dependency carries `"estimated": ["version"]` (`~1.2.3` in the table and Markdown formats). | Ask the user which way to settle it: commit an up-to-date lockfile and re-scan from step 1, or accept the estimate by adding `--no-require-lockfile` to every later `licenseal check` in this procedure and in CI (the diagnostic then has `severity: "estimate"`, is not counted in `summary.gaps`, and does not fail strict mode). Do not choose for the user: a review based on estimated versions can miss the license of the version actually installed. |
| `declares off-registry dependencies that no lockfile records` | A git, URL, or path dependency has no lockfile entry, so what it depends on is missing from the report. | The same choice. |
| `the dependencies of <package>` | A registry did not return that package's dependency list, so what it requires may be missing from the report although the package itself is listed. | Run the scan again: it is usually a transient registry error or rate limit. If it persists (a Maven version deps.dev has not indexed, a NuGet dependency declared without a version that can be pinned), tell the user which package is affected. A lockfile removes the need for the registry walk; `--no-require-lockfile` does not accept this gap. |
| `declares repositories` | A `composer.json` takes packages from repositories that do not name them, and no `composer.lock` was read, so those packages may have been looked up on Packagist by name. | The user scans with the `composer.lock`. |
| anything else | licenseal could not read or parse a file (an unreadable manifest, a syntax error, an unsupported file), or a `go.mod` below `go 1.17` has no `go.sum` row for its requirements. | The user fixes the file; for the `go.mod` case, commits an up-to-date `go.sum`. |

**Licenses read from another release.** A dependency whose `estimated` array contains `"license"` (`~MIT` in the table and Markdown formats) is reported with a license that the registry records for another release than the one in `resolved_version`: an R package pinned to a version other than CRAN's current one, a Hex package at a release other than the one published last, or a PyPI release that declares no license of its own or is not on PyPI. It is not a finding and does not fail strict mode; a license change between the two releases shows only as this mark.

- Tell the user how many dependencies carry the mark.
- When one of them is flagged, confirm the license for the pinned release itself (step 4) before recording it.

**The project license must be the right one.** Every verdict is relative to `project_license`. Before step 3:

- `project_license_source` is `""`: the project was checked as `Proprietary`, so permissive dependencies pass and every copyleft dependency is flagged. No manifest in the scanned directory declares a license, or the first one that does declares a value licenseal does not recognise (stderr then has a `Warning:` naming the file and the value).
  - Ask the user whether the project really is proprietary.
  - If it is not (an open-source project whose license is declared only in a nested package or a `LICENSE` file, or with a value licenseal did not recognise), stop and ask them to declare the license in a manifest of the scanned directory, or to scan the sub-package with `--path`; then start again from step 1.
- Stderr has a `Warning:` that manifests declare different licenses: ask the user which license is right. If it is not `project_license`, stop until they have corrected the manifests; then start again from step 1.
- A dual-licensed project with one unrecognized arm (`AGPL-3.0-only OR Commercial`) is not in this state: licenseal judges that arm as `Proprietary`, so walk the copyleft findings as real.

### 3. Establish project context

#### 3a. Infer what you can from the codebase

Before asking the user, gather signals already in the repo:

- **Project's own license**: `project_license` in the scan JSON. licenseal reads it only from a manifest in the scanned directory, never from a nested package: to audit one package of a monorepo against its own license, scan that package with `--path`.
- **Library vs application**:
  - Python: `[project.scripts]` / `[project.entry-points]` in `pyproject.toml` → CLI / app. A `[project] name` with no scripts and a `src/<name>/` layout → library. Both possible.
  - npm: `bin` field in `package.json` → CLI / app. `main` / `exports` only → library. No `main` and a server framework dependency → app / SaaS.
  - Rust: `Cargo.toml` `[[bin]]` table → app. `[lib]` table → library. Both possible.
- **Distribution surface**: look for `.github/workflows/publish.yml`, `Dockerfile`, `Procfile`, deployment configs (`fly.toml`, `render.yaml`, `vercel.json`, `app.yaml`, …). Publishing workflow → distributed package. Deployment config → hosted service / SaaS.
- **Shipped artifacts**: a SaaS project still distributes when its code reaches third parties through one of these channels. The SaaS safe harbor for distribution-triggered copyleft holds only when *none* applies.
  - `browser-bundle`: browser-bundled JS (`webpack.config.*`, `vite.config.*`, `rollup.config.*`, `next.config.*`, `nuxt.config.*`, `svelte.config.*`, or a `build` script producing browser-bound output)
  - `desktop` / `mobile`: a desktop or mobile client (`electron-builder`, `tauri.conf.*`, `expo` / `app.json`, `react-native.config.*`)
  - `on-prem`: an on-prem / self-hosted tier (Helm charts, `install.sh`, `selfhost/` / `enterprise/` / `deploy/` directories)
  - `public-container`: public container images (CI pushing to Docker Hub / GHCR Public / ECR Public)
- **Linkage model**: Python and JS use **dynamic** linkage (runtime imports). Rust binaries use **static** linkage by default (the dependency is compiled into the artifact). This matters for LGPL: dynamic linkage is generally fine; a statically linked binary has to ship object files, switch to dynamic linkage, or use a different license.

#### 3b. Confirm with the user

Show the inferred picture in one short sentence, then ask what is still missing. Keep this to **2–3 questions max**:

1. *"It looks like a [library / CLI / web service / internal tool]. Distribution model: (a) library to other devs, (b) standalone app / CLI binary, (c) SaaS / hosted service, (d) internal-use only, (e) embedded / firmware? **If (c)**, also list any sub-channels that ship this code to third parties: browser-bundled JS sent to user agents, desktop client (Electron/Tauri), mobile app (React Native / Expo), on-prem / self-hosted tier (Helm chart, install script, customer-run deploy), public container images. Those are distribution channels even though the headline is SaaS."*
2. *"Is the project commercial (sold, monetized, used inside a paying business) or non-commercial (FOSS, hobby, research)?"*
3. **Only ask if** any flagged dependency has a source-available license (`SSPL-*`, `BUSL-*`, `Elastic-*`, `FSL-*`, `Parity-*`, `PolyForm-*`) — *"Does the project compete with the dependency vendor's commercial offering?"*

Store the answers as `context = {distribution, shipped_artifacts, commercial, competing}`. `shipped_artifacts` is the set of sub-channels from the SaaS follow-up (`browser-bundle`, `desktop`, `mobile`, `on-prem`, `public-container`); it is empty when distribution isn't SaaS or the SaaS is purely server-side. Step 4 uses them.

### 4. Walk through flagged dependencies

A flagged dependency has `verdict` in `{"warning", "incompatible", "unknown"}`. Skip one with `reviewed: true`: an earlier audit settled it. Walk **violations (`incompatible`) first, then warnings, then unknowns**. For each, show the user:

- `name@resolved_version` (`ecosystem`)
- `effective_license` (note `license_raw` separately if it differs)
- `verdict`, `risk`, and `reason`
- `actionability.investigate_url`

Choose the pattern below from verdict, risk, and project context: state the obligation, anchor it to the user's project context, then ask the targeted yes/no question. Every pattern ends in one of two outcomes:

- **Reviewable**: record a decision for step 6, as `{(ecosystem, name, version) -> (license, note)}`, or `{(ecosystem, name, origin) -> (license, note)}` for a dependency with a non-empty `origin`. `license` is the scan's `license` for the dependency unless the pattern says otherwise, and never `UNKNOWN`: without a license the user confirmed, leave unreviewed. `note` is the user's reason.
- **Leave unreviewed**: record nothing. The dependency stays flagged.

If no pattern fits and the user gives no concrete reason, leave unreviewed.

**`OR` dependencies.** When `license` is an `OR` expression, the verdict is that of the single choice that suits the project best, each choice checked as a whole. `risk` still reads the least restrictive choice, so `reason` can name a stricter license class than `risk` does: the lower-risk choice is then not open to this project (it has a pair-level conflict with the project license, or carries an unresolved operand). Use the pattern that matches the class or conflict named in `reason`, and ask about the choice it describes.

- **WARNING — weak copyleft dependency in permissive project** (`MPL-2.0`, `LGPL-*`, `EPL-*`, `CDDL-*`, GPL-with-Classpath-exception):
  - `context.distribution` ∈ {SaaS, internal} **and** `context.shipped_artifacts` is empty: obligations typically don't trigger.
    - Ask: *"This is a [SaaS / internal-use] project with no shipped artifacts, so {license}'s file-level / linking obligations don't usually apply. OK to mark as reviewed?"*
    - Yes → reviewable with that context in `note`. No → leave unreviewed.
  - `context.distribution` = library / app **and** Rust (static linkage):
    - Ask: *"{license} on a static-linked binary needs either dynamic linkage or shipping object files. How is this dependency linked in your build?"*
    - Dynamically linked, or object files are shipped → reviewable with the linkage in `note`. Otherwise → leave unreviewed.
  - `context.distribution` = library / app **and** Python / JS (dynamic linkage):
    - Ask: *"{license} is generally fine with dynamic linkage. Did you fork or modify the dependency's source? (MPL only requires disclosure of modifications to MPL-licensed files.)"*
    - Not modified → reviewable with that in `note`. Modified → leave unreviewed, or reviewable once the user has published the modifications as the license requires, with that in `note`.
  - License is `GPL-2.0-with-classpath-exception` or `GPL-* WITH Classpath-exception-2.0` / `Classpath-exception-2.0-short` (OpenJDK-derived and `javax.*` / `jakarta.*` artifacts): licenseal classifies the Classpath exception as weak copyleft because it permits linking independent modules regardless of their license.
    - Ask: *"The Classpath exception covers linking — are you linking against {name} unmodified, not modifying or forking the GPL portion itself?"*
    - Yes → reviewable with the linking rationale in `note`. No → leave unreviewed.

- **WARNING — network-copyleft dependency in strong-copyleft project** (`AGPL-*` dependency in a `GPL-*`, `OSL-*`, `EUPL-*`, `CC-BY-SA-*`, `ODbL-*` project):
  - AGPL-3.0 § 13 and GPL-3.0 § 13 explicitly permit the combination, but the AGPL portion's source-on-network-access obligation binds anyone who deploys the combined work over a network. The combination is legal; the project's *effective* obligations get stronger. An `AGPL-1.0-*` dependency is this warning in any strong-copyleft project, `GPL-2.0-only` included.
  - `context.distribution` = SaaS: AGPL terms bind downstream users of the deployed service.
    - Ask: *"AGPL requires source disclosure to network users of any deployment. Is publishing source for the SaaS deployment acceptable?"*
    - Yes → reviewable with that in `note`. No → leave unreviewed.
  - `context.distribution` ∈ {library, app, internal}: the AGPL trigger is dormant for non-network distribution.
    - Ask: *"The combination is legal under GPL § 13. Downstream SaaS deployers of your project will inherit AGPL's network-source obligation. OK to mark as reviewed with that documented?"*
    - Yes → reviewable with that in `note`. No → leave unreviewed.

- **WARNING — `EPL-2.0` dependency in a GPL-family project** (`GPL-2.0-*`, `GPL-3.0-*`, or `AGPL-3.0-*`; `reason` mentions "secondary license"):
  - EPL-2.0 is GPL-compatible only when the Eclipse contributor designated the GPL as a secondary license (EPL-2.0 § 3.2 / Exhibit A); package metadata can't reveal that designation, so licenseal warns instead of hard-failing.
  - Ask: *"Check {name}'s source headers or NOTICE file — does it designate the GNU GPL as a secondary license? (Most `jakarta.*` artifacts do.)"*
  - Yes → reviewable with the secondary-license grant in `note`. No or unverifiable → the combination is GPL-incompatible: leave unreviewed.

- **INCOMPATIBLE — pair-level conflict** (`reason` cites the FSF, an "upgrade clause", or "GPLv3-family terms"):
  - These license pairs are legally incompatible even though their risk levels would pass. The dependency's `risk` can even read `permissive`.
  - **GPLv3-family dependency (`GPL-3.0-*`, `LGPL-3.0-*`, `AGPL-3.0-*`) in a `GPL-2.0-only` project**, or **`GPL-2.0-only` dependency in a `GPL-3.0-*` / `AGPL-3.0-*` project**: version conflict with no upgrade clause to escape it. A deprecated bare ID in a manifest or registry (`GPL-2.0`, `LGPL-3.0`) is read as `-only` and reported that way; only a `+` suffix (`GPL-2.0+`) or an explicit `-or-later` carries the upgrade clause.
    - Ask: *"Is the project (or the dependency) actually licensed 'or later'?"*
    - The project is → the user fixes the project's manifest; start again from step 1.
    - A `GPL-2.0-only` dependency in a `GPL-3.0-*` / `AGPL-3.0-*` project is really `-or-later` → reviewable as a detection override, with the `-or-later` ID as `license` and where it was confirmed in `note`.
    - A GPLv3-family dependency in a `GPL-2.0-only` project is a violation with or without "or later": leave unreviewed. Neither → leave unreviewed.
  - **`Apache-2.0` dependency in a `GPL-2.0-only` project**: the FSF documents Apache-2.0 as GPLv2-incompatible. Leave unreviewed; the resolution is usually relicensing the project to `GPL-2.0-or-later` / `GPL-3.0` or replacing the dependency. `Apache-2.0 WITH LLVM-exception` is not flagged: that exception waives the conflicting sections for a combination with GPLv2 code.
  - **`EPL-1.0` / `CDDL-*` / `MPL-1.1` dependency in any GPL-family project** (`GPL-2.0-*`, `GPL-3.0-*`, `AGPL-3.0-*`): FSF-documented GPL-incompatible weak copyleft.
    - Ask: *"Many EPL/CDDL-era artifacts are dual-licensed (e.g. `CDDL OR GPL-2.0-with-classpath-exception`). Does {name} offer a second license the resolver missed?"*
    - Yes → reviewable with the full dual-license expression as `license`. No → leave unreviewed.

- **INCOMPATIBLE — copyleft / share-alike mismatch** (strong-copyleft or network-copyleft dependency in permissive or weak-copyleft project):
  - Covers `GPL-*`, `OSL-*`, `EUPL-*`, `CC-BY-SA-*`, `ODbL-*`, `CDLA-Sharing-*`, `Sleepycat`, `GFDL-*`, `RPL-*` dependencies in MIT / Apache / BSD / LGPL / MPL projects, plus `AGPL-*` dependencies in a permissive or weak-copyleft project (in a strong-copyleft project they are warnings — see above — and in an AGPL project they are compatible). Settle a special case first, then use the context branches.
  - **Special case — `OSL-*`**: OSL-3.0 § 5 ("External Deployment") treats running the program on a network-accessible server as a trigger, as AGPL does. The internal-use branch below applies *only* if the server is not externally accessible; on a SaaS deployment, leave unreviewed.
  - **Special case — `WITH <exception>`**: licenseal matches the text after `WITH` against a fixed list.
    - The Classpath exception classifies as weak copyleft: use the WARNING pattern above.
    - An exception that only adds a permission (`GCC-exception-3.1`, `Bison-exception-2.2`, `LLVM-exception`, `Linux-syscall-note`, and the other permission-only SPDX exceptions) is judged as its bare license, although it may permit the combination.
      - Ask: *"{license} flags as INCOMPATIBLE on its bare license, but {exception} was specifically designed to permit some combinations. Does the exception apply to your use (e.g. you're linking, not modifying the GPL portion itself)?"*
      - Confirmed → reviewable with the full `WITH` expression as `license`, so the audit trail names the exception (`license = "GPL-3.0-only WITH GCC-exception-3.1"`). Not confirmed → walk it as the bare license under the context branches.
    - Any other text after `WITH` is terms licenseal did not read, and it never lowers a verdict. Such a dependency lands here only when its bare license is itself the violation; `reason` then ends with *is not an exception licenseal recognizes, so the license is judged without it*. Walk it as the bare license under the context branches. Treat the exception as a way out only when the user has read its text and it grants the permission their use needs: then reviewable with the full `WITH` expression as `license` and where the text was read in `note`. When the bare license would pass, the dependency is UNKNOWN instead; see the unrecognized-exception pattern below.
  - **Special case — malformed license expression** (`license` is `UNKNOWN` or `Proprietary`, and `reason` says the declared string *is not a well-formed license expression*): the registry string has a dangling operator, unpaired parentheses, licenses with no operator between them, or an `AND` operand that is not a license (`MIT OR GPL-3.0-only AND`, `GPL-3.0-only AND Some Custom Terms`), so licenseal judged the licenses it names without the part it could not read.
    - Show the user `license_raw` and `actionability.investigate_url` and ask: *"{name} declares '{license_raw}', which is not a valid license expression. What does the package's own license file or documentation say — is it a choice between these licenses, or do they all apply?"*
    - A confirmed choice the project can take → reviewable with the corrected expression (`license = "MIT OR GPL-3.0-only"`) and where it was confirmed in `note`. They all apply, or nobody has confirmed → the violation stands: continue with the context branches for the copyleft license named in `reason`.
  - **Special case — license list with an unrecognized entry** (`license` is `UNKNOWN` and `reason` says the declared string is *a license list with an entry that did not resolve to a recognized license*): the registry string is a comma- or slash-separated list (`GPL-3.0-only, acme internal license`) whose recognized entries are all violations in this project.
    - Show the user `license_raw` and `actionability.investigate_url` and ask: *"{name} declares '{license_raw}'. What is the part licenseal could not read — a second license you may choose instead, extra terms on top of the first, or only a note?"*
    - A confirmed alternative license the project can take → reviewable with the full `OR` expression as `license`, each operand a value step 6 accepts, and where it was confirmed in `note`. Extra terms, a note, or nobody has confirmed → the violation stands: continue with the context branches for the license named in `reason`.
  - Context branch — `context.distribution` = internal-use only **and** `context.shipped_artifacts` is empty **and** the license trigger is distribution-based (`GPL-*`, `CC-BY-SA-*`, `EUPL-*`, `ODbL-*`, `CDLA-Sharing-*`, `Sleepycat`, `GFDL-*`, `RPL-*`): copyleft does not trigger without distribution.
    - Ask: *"This is internal-use only with no shipped artifacts, and {license} only triggers on distribution. Confirm you don't ship binaries / source externally?"*
    - Confirmed → reviewable with the internal-use rationale in `note`. Not confirmed → leave unreviewed.
  - Context branch — `context.distribution` = SaaS **and** `context.shipped_artifacts` is empty **and** the license is distribution-triggered strong copyleft other than AGPL / OSL (`GPL-*`, `CC-BY-SA-*`, `EUPL-*`, `ODbL-*`, `CDLA-Sharing-*`, `Sleepycat`, `GFDL-*`, `RPL-*`): server-side-only deployment, no distribution channel, so the copyleft trigger is dormant.
    - Ask: *"This is SaaS-only with no browser bundle, no on-prem / self-hosted tier, no desktop or mobile client, no public container image — none of {name}'s code paths reach a third party. {license}'s copyleft only triggers on distribution. OK to mark reviewed with the SaaS-only assumption captured in `note`?"*
    - Yes → reviewable with the assumption in `note` (e.g. `"SaaS-only, server-side, no shipped artifacts; copyleft trigger dormant. Re-audit if a shipped channel is added."`). Tell the user that this holds only while `shipped_artifacts` stays empty: adding an Electron client, an enterprise on-prem tier, a mobile app, or a browser-side bundle re-activates the obligation. No → leave unreviewed.
  - Context branch — `context.distribution` = SaaS **and** the license is AGPL: AGPL **does** trigger on SaaS regardless of `shipped_artifacts`.
    - Ask: *"{license} requires publishing modifications and full corresponding source for SaaS deployments. Is your project AGPL-licensed too, or is publishing source acceptable?"*
    - One of them applies → reviewable with that in `note`. Neither → leave unreviewed.
  - Context branch — `context.distribution` = library / app **or** `context.shipped_artifacts` is non-empty: hard incompatibility on every distribution path. Recommend removal or relicensing, and leave unreviewed. The one exception is independent confirmation that the detection is wrong (e.g. the user read the bundled LICENSE file and the resolver mis-identified it): then reviewable with the confirmed license as `license` and where it was read in `note`.

  **Across all INCOMPATIBLE branches**: reviewable only when there is a concrete reason the verdict is wrong (detection error, signed agreement, context-based exception that actually applies). The user not wanting the violation to fail CI is not a reason: leave unreviewed, and the user resolves it outside the review file (remove, replace, accept the risk, or seek legal review).

Only two UNKNOWN patterns ask the user what the license is: the off-registry pattern and the last one. In the others the license **is** identified: do not ask *"what's the actual license?"*.

When the user reports a license in one of those two patterns, write it as a value step 6 accepts. If that license would itself be flagged in this project, walk the pattern that covers it before recording, and record it only if that pattern ends reviewable. Otherwise → reviewable with that license as `license` and where the user read it in `note`.

- **UNKNOWN — license list with no stated meaning** (`reason` says the dependency *lists several licenses without stating whether they are alternatives*):
  - The source gave several licenses without saying whether you may pick one or must comply with all: a RubyGems or Hex `licenses` array, several PyPI license classifiers, or a comma- or slash-separated list in one license string (`license_raw` shows it). `license` shows the list as a choice; `reason` gives the verdict of that reading and of the reading where every entry applies, and they differ.
  - Point the user at `actionability.investigate_url` and ask: *"{name} lists {the licenses} without saying how they relate. What do the package's license file and README say — is it offered under either license at your choice, or do all of them apply to the code you use?"*
  - A choice, confirmed → reviewable with the `OR` expression from `reason` as `license` and where it was confirmed in `note`. The re-check then judges that expression as written.
  - All apply, confirmed → the `AND` expression is the real license, and `reason` already shows its verdict. When that verdict is a violation or a warning, walk the matching INCOMPATIBLE / WARNING pattern for the license that causes it, and record the `AND` expression as `license` only if that pattern ends reviewable; otherwise leave unreviewed.
  - Not confirmed → leave unreviewed.

- **UNKNOWN — R package whose license adds a file** (`ecosystem` is `r`, `license` is `<license> AND UNKNOWN`, and `license_raw` reads `<license> + file LICENSE`):
  - On CRAN, `+ file LICENSE` after a license other than MIT or BSD means the package's `LICENSE` file restricts or extends that license, and licenseal never reads the file.
  - Ask: *"{name} declares '{license_raw}'. Open its LICENSE file from {actionability.investigate_url} — what does it add to the named license?"*
  - It adds nothing that limits the project's use (a copyright-holder list, an attribution notice) → reviewable with the named license as `license` and what the file contains in `note`. It adds a restriction → reviewable only when the user confirms the project's use stays inside it, with that in `note`. Unread → leave unreviewed.
  - If the verdict is `incompatible` instead, the named license is itself the violation: walk it under the INCOMPATIBLE patterns above.

- **UNKNOWN — off-registry source** (`origin` is non-empty, `reason` says "comes from an off-registry source"):
  - The dependency is installed from a git repository, a direct URL, or a path the scan does not read (outside the project, an archive such as a wheel or a JAR, a vendored or excluded directory), not from the registry. licenseal makes no registry request for it, and the registry package of the same name is a different package: do not look the name up on the registry, and expect `package_url` and `actionability.investigate_url` to be empty.
  - Ask: *"{name} comes from {origin}. Can you read the license at that source and tell me what it is?"*
  - The user names it → record it as a license the user reports (above). Unknown → leave unreviewed.
  - The review is keyed on the `origin`, not on the version. When the `origin` of a git dependency ends in a branch or a tag rather than a commit, tell the user that the review keeps applying when that branch or tag moves, and that pinning a commit in the manifest or committing a lockfile makes the key immutable.

- **UNKNOWN — source-available** (`SSPL-*`, `BUSL-*`, `Elastic-*`, `FSL-*`, `Parity-*`, `PolyForm-*`):
  - `context.competing` unknown for this dependency → ask first: *"{license} restricts use that competes with {vendor}. Does your product compete with their commercial offering?"*
  - `context.commercial` = no **or** `context.competing` = no: source-available terms typically allow non-competing use. Ask: *"{license} restricts competing commercial use. You said this is [non-commercial / non-competing] — confirm and mark as reviewed?"* Confirmed → reviewable with that context in `note`. Not confirmed → leave unreviewed.
  - `context.commercial` = yes **and** `context.competing` = yes: real incompatibility. Recommend removal or an alternative, and leave unreviewed.

- **UNKNOWN — use-restricted SPDX ID** (`CC-BY-NC-*`, `CC-BY-ND-*`, `BSD-3-Clause-No-Military-License`, `BSD-3-Clause-No-Nuclear-License`, `BSD-3-Clause-No-Nuclear-License-2014`, `BSD-Protection`, `Unicode-TOU`; `license` is one of these IDs, `risk` reads `unknown`):
  - Its terms limit a kind of use (non-commercial only, no derivatives, an excluded field of use, or conditions on modified or redistributed copies) that licenseal does not evaluate.
  - Point the user at `actionability.investigate_url` and ask: *"{license} restricts how the software may be used or redistributed. Have you read the restriction, and does your project's use stay inside it?"*
  - The user confirms the use stays inside the restriction → reviewable as `license = "{license}"` with `note` recording why (e.g. `"non-commercial research project"`, `"used unmodified, not redistributed"`). The restriction applies, or the user is unsure → leave unreviewed.
  - `BSD-3-Clause-No-Nuclear-Warranty` is not in this group: it is a warranty disclaimer, classifies as permissive, and is not flagged.

- **UNKNOWN — unrecognized `WITH` exception** (`license` holds a `WITH` term, and `reason` says the text after `WITH` *is not an exception licenseal recognizes, so the terms it adds were not evaluated*; several such exceptions are named together as *are not exceptions licenseal recognizes, so the terms they add were not evaluated*):
  - The bare license would pass in this project, but the text after it is not on licenseal's list: it can be a real SPDX exception licenseal does not model, or a restriction written where an exception belongs (a rider that forbids selling the software, for example).
  - Point the user at `actionability.investigate_url` and ask: *"{license} carries '{exception}', which licenseal does not evaluate. Have you read it — does it only add permissions to the license, or does it limit how the software may be used or sold?"*
  - It only adds permissions → reviewable as `license = "{license}"` (the full `WITH` expression) with `note` recording where the exception text was read and what it permits. It restricts use → reviewable only when the user confirms the project's use stays inside the restriction, with that in `note`. Unread, or the user is unsure → leave unreviewed.

- **UNKNOWN / WARNING — proprietary dependency** (`license == "Proprietary"`, `reason` mentions "custom commercial terms cannot be auto-classified"):
  - The license is known to be proprietary, so ask about its **terms**, not its identity: permitted use, redistribution, royalties, and field-of-use limits.
  - **Dev-only dependency** (licenseal downgrades to WARNING): ask *"Is this a paid dev tool covered by your team's existing license or subscription?"* Yes → reviewable as `license = "Proprietary"` with `note` recording the licensing arrangement. No → leave unreviewed.
  - **Prod dependency, `context.distribution` = internal-use only**: ask *"What permits the internal use? (e.g. purchased license, bundled EULA, vendor portal subscription, free-for-non-commercial clause...)"* The user names a specific arrangement → reviewable with `note` recording it (a verifiable reference like `"licensed for internal use under MSA-2025-0042"` is ideal; a concise factual explanation like `"bundled EULA permits internal-only use"` is fine when no formal agreement exists). Otherwise → leave unreviewed.
  - **Prod dependency, `context.distribution` ∈ {library, app, SaaS}**: redistribution implications apply. Ask: *"For {name}, can you confirm — (1) redistribution is permitted under your license, (2) royalty obligations are accounted for, (3) any field-of-use restrictions (non-competing / non-commercial sub-clauses) don't apply to your product?"* All yes → reviewable with `note` documenting the answers (e.g. `"team license via vendor portal; EULA §3 permits redistribution in client binaries; no per-user royalty"`). Any uncertainty → leave unreviewed.
  - **`Proprietary` as one operand of a compound** (e.g. `license == "MIT AND Proprietary"`, verdict `unknown`): the operand is a custom-terms license, usually a `LicenseRef-*` reference, and `license_raw` shows the declared string. Ask the terms questions above about that operand. With recordable terms → reviewable with the full expression as `license` and the arrangement in `note`. Without → leave unreviewed.
  - **Never review a proprietary dependency without recordable terms.** The `note` must name *what permits the use*: an agreement reference, a quoted clause, a ToS URL, or a concise factual description of the binding terms. *"looks fine"* / *"we use it"* / *"we have a contract somewhere"* are not recordable terms. The test: a future reviewer reading the `note` alone can verify, or at least re-check, whether the use is still authorized.

- **UNKNOWN — none of the above** (the registry exposed no license, or one that is not an SPDX ID):
  - Ask: *"Can you check {actionability.investigate_url} and tell me the actual license?"* Wait for the answer.
  - The user names it → record it as a license the user reports (above). Unknown → leave unreviewed.

### 5. Scaffold (or extend) the review file

Always pass `--from-report "$SCAN_FILE"`: the scaffold then covers exactly the rows of the scan you walked the user through. Check whether `licenseal.review.toml` already exists in the scanned directory:

- **No review file yet** — scaffold a fresh one:

  ```bash
  licenseal init-review-file --from-report "$SCAN_FILE"
  ```

  This writes `licenseal.review.toml` with one `[[review]]` entry per flagged dependency that has a resolved version or an `origin`, each with `license = ""`. The entry of an off-registry dependency carries a `source` line holding its `origin`; that line is its key, and its `version` line is present only when the scan recorded a version.

- **A review file already exists** (a re-audit, or the project committed one earlier) — extend it with `--merge`:

  ```bash
  licenseal init-review-file --from-report "$SCAN_FILE" --merge
  ```

  Merge only appends. Every existing entry is preserved verbatim, and an empty entry is appended for each flagged dependency that has none under its key: `(ecosystem, name, version)`, or `(ecosystem, name, source)` for an entry with a `source` line. So a dependency whose version or source changed gets a new empty entry; its old filled entry was deleted in step 1. Never give two entries the same key: `check` rejects a duplicate.

  The command reports `Appended N review entr(y/ies)` or `No new flagged dependencies to add.` Without `--merge` it aborts with `licenseal.review.toml already exists`: re-run with the flag, and do **not** delete the file, which holds the existing audit trail.

If the command prints a `Note: N flagged dependencies could not be scaffolded (no resolved version, ...) ...` line, give those names to the user: they point to a problem at the source (manifest typo, yanked release, registry miss, a declared version range that no published version satisfies) that no review entry settles. A second `Note:` with the reason `a lone surrogate in the name, version, or source, which a TOML file cannot hold` names dependencies no review entry can be written for (a manifest or lockfile holds an unpaired `\uD800`–`\uDFFF` escape); they stay flagged, so tell the user to correct that name at its source.

### 6. Fill in the review file

For each `[[review]]` entry with `license = ""` (on a `--merge` run, only the appended ones; leave entries filled in earlier audits untouched), look up its `(ecosystem, package, version)`, or `(ecosystem, package, source)` when it has a `source` line, in the decisions from step 4.

- **A reviewable decision**: set `license` and `note` from it.
- **No decision**: leave `license = ""`. This is what "leave unreviewed" means throughout this skill: the entry stays in the file, the dependency stays flagged, and `check` prints a `Warning:` that names the incomplete entry.
- **An unfilled entry that matches no flagged dependency of this scan** (left from an earlier version or source): delete it. It is never an error, so it would stay in the file and draw that `Warning:` on every run.

Write `license` as one of the following (a value that is not a license fails the next `check`):

- an SPDX license ID, current or deprecated (`"MIT"`, `"Apache-2.0"`)
- a source-available ID licenseal recognises (`SSPL-*`, `BUSL-*`, `Elastic-*`, `FSL-*`, `Parity-*`, `PolyForm-*`)
- `"Proprietary"`, for a closed-source or custom-terms dependency the user has decided is acceptable
- a `LicenseRef-` reference
- an SPDX expression of those (`"MIT OR Apache-2.0"`, `"GPL-3.0-only WITH GCC-exception-3.1"`). A comma- or slash-separated list is rejected.

`package` is the report's `name` for that dependency, or its `registry_name` when that field is not empty (a Hex dependency that `mix.exs` renames is reviewed under the hex.pm package it is published as). Keep the `package` line as scaffolded: for Go, Java, npm, and Ruby it is matched exactly, upper and lower case included.

Fill `note` with the user's rationale, including the project-context detail that made the decision (e.g. `"reviewed: SaaS deployment, LGPL obligations don't apply"`).

### 7. Re-scan and confirm

```bash
licenseal check --no-dev -f json --no-strict
```

Use the flags chosen earlier here and in the strict run below (`--dev`, `--no-require-lockfile`). No `-o`: parse the JSON from stdout. Verify:

- `summary.reviewed` equals the number of filled entries in the file (more when one entry covers several rows that share its key).
- Each reviewed dependency carries `reviewed: true` and is classified by the license you recorded. A detection override to a license the project can take (`UNKNOWN` → `MIT`) now counts in `summary.ok`. A dependency reviewed under a license that is itself flagged (an accepted `MPL-2.0` warning, a `GPL-3.0-only` kept for internal use) stays in its `warnings` / `violations` / `unknown` counter.
- The number of flagged dependencies with `reviewed: false` equals:
  1. the unscaffoldable count from step 5, plus
  2. dependencies the user explicitly left undecided, plus
  3. confirmed incompatibilities: dependencies where no exception applied.

If the numbers do not add up for reasons 1 and 2, the entries probably reference wrong versions, or a `package` spelled differently from the scan's (a Go, Java, npm, or Ruby name in another case is another package): compare with `$SCAN_FILE` and fix.

Then run `licenseal check --no-dev` without `--no-strict`. It exits `0` only when no unreviewed flagged dependency and no analysis gap remains. Otherwise report what remains, so the user can act on it outside this skill: the names of the unreviewed flagged dependencies, and the gaps from `diagnostics[]` as in step 2. A manifest without a lockfile is settled as decided in step 2: a committed lockfile, or `--no-require-lockfile`.

Last, remove the scratch file: `rm "$SCAN_FILE"` (bash) / `Remove-Item $SCAN_FILE` (PowerShell).

### 8. Save the audit deliverable to LICENSES.md

```bash
licenseal check --no-dev -f markdown --no-strict -o LICENSES.md
```

1. Use the flags chosen earlier: `--dev` if dev dependencies are in scope, `--no-require-lockfile` if the user accepted estimates in step 2.
2. `LICENSES.md` in the scanned directory is the human-readable audit: all verdicts after review, the project license, the dependencies still flagged, the review entries that were applied, and any analysis gaps.
3. A non-zero exit with the file written is expected while unreviewed violations remain. `--no-strict` lets the command pass with gaps, so read the summary line of the saved file. If it contains `N analysis gap(s)`, the file has an **Analysis gaps** section naming each manifest, and the audit is incomplete until those are settled as in step 2. Tell the user which manifests are listed.
4. With `--no-require-lockfile`, the summary line also has `N estimated manifest(s)` and the file has an **Estimates** section.
5. Tell the user to commit `LICENSES.md` alongside `licenseal.review.toml`, the machine-readable state the next scan applies.

## URL trust model

- `package_url` (registry page) and `license_url` (spdx.org) are built deterministically by licenseal: safe to open.
- `repository_url` and `homepage_url` come from the registry, where a compromised package can put any URL. Don't fetch them, or any URL built from them: show them to the user instead. That covers `actionability.investigate_url` when it is one of the two, and the LICENSE links in `actionability.next_steps`.

## LICENSE file lookup

Steps in `actionability.next_steps` for warnings and unknowns may hold a link like `https://github.com/<owner>/<repo>/blob/HEAD/LICENSE`, built from `repository_url` by host:

- GitHub: `{repo}/blob/HEAD/LICENSE`
- GitLab: `{repo}/-/blob/HEAD/LICENSE`
- BitBucket Cloud: `{repo}/src/HEAD/LICENSE`
- Codeberg: `{repo}/src/branch/HEAD/LICENSE`

The path is a guess: licenseal can't verify that the file exists. When the user reports that the link does not exist, suggest these names at the same path, then the repository's file list:

- `LICENSE.md`, `LICENSE.txt`, `LICENCE`, `LICENCE.md`
- `COPYING`, `COPYING.md`, `COPYING.txt`

## Rules

- **Never fabricate licenses.** If the registry says nothing and the user doesn't know, leave the dependency unreviewed.
- **Don't mark a warning as reviewed without asking.** Even when the license looks fine, the user decides whether it suits their project's context.
- **One question per dependency, or per group of dependencies with the same license and pattern**, not a wall of options. Match the question to the verdict.
- **Don't record a license the dependency does not have in order to change its verdict.** The verdict is re-computed from the `license` you record, so `license = "MIT"` on a GPL dependency reports it as compatible and falsifies the audit trail. To accept a flagged license, record that license itself and put the reason in `note`.
- **Don't assume project context.** If the codebase signals are ambiguous (e.g. a library with deployment configs), ask the user. Never silently pick a distribution model that makes the licenses look better than they are.
- **Record context in `note`.** When the user's decision depended on project context ("we're SaaS", "internal-use only", "no competing product"), put that phrase in the `note`.
- **The review file records a detection override, or an accepted verdict with its rationale. Never write an entry to silence a real violation.** It stays flagged until the user removes or replaces the dependency, or accepts the risk outside the review file.

## Concrete examples — when (not) to write a review entry

| Situation | Review entry | Why |
| --- | --- | --- |
| Registry says `UNKNOWN`; user read the bundled `LICENSE` and confirmed it's `MIT` | ✅ `license = "MIT"` | Detection was wrong, user has direct evidence |
| Dependency has an `origin` (a git fork, a tarball URL, a vendored directory or archive, a path outside the project) and is `UNKNOWN`; user read the license at that source and it is `MIT` | ✅ `license = "MIT"` in the entry whose `source` is the dependency's `origin`, with `note` saying where the license was read | No registry describes this code; the review is the only license record, and it applies to that source only |
| Dependency is `GPL-3.0-only` in an MIT project; project is internal-use only, no distribution | ✅ `license = "GPL-3.0-only"` with `note = "internal-use only, no distribution"` | Context-based exception genuinely applies; record the rationale |
| Dependency is `GPL-3.0-only` in an MIT project; project ships a binary to customers | ❌ leave unreviewed | Real incompatibility; user must remove, replace, or relicense — outside this skill |
| Dependency is `GPL-3.0-only` in an MIT project; hosted SaaS, server-side only — no browser bundle, no desktop / mobile client, no on-prem tier, no public container image | ✅ `license = "GPL-3.0-only"` with `note = "SaaS-only, server-side, no shipped artifacts; GPL distribution trigger dormant. Re-audit if a shipped channel is added."` | Distribution-based copyleft doesn't trigger when no artifact reaches third parties; brittle if a shipped channel is later added |
| Dependency is `GPL-3.0-only` in an MIT project; SaaS that also bundles into browser-shipped JS, a desktop / mobile client, or an on-prem / self-hosted tier | ❌ leave unreviewed | Each shipped channel is its own distribution path; GPL trigger fires regardless of the SaaS headline |
| Dependency is `CC-BY-SA-4.0` in an MIT project; project is internal-use only | ✅ `license = "CC-BY-SA-4.0"` with `note = "internal-use only, no distribution; share-alike does not trigger"` | Share-alike is distribution-triggered; internal use is fine |
| Dependency is `EUPL-1.2` in an MIT project; project ships externally | ❌ leave unreviewed | EUPL is strong-copyleft, GPL-comparable; outside the EUPL compatibility list, the combination is a real incompatibility |
| Dependency is `OSL-3.0` in an MIT project; project is hosted SaaS | ❌ leave unreviewed | OSL § 5 treats network-accessible deployment as a trigger; the internal-use branch does not apply to externally reachable servers |
| Dependency is `AGPL-3.0-only`; project is hosted SaaS, not AGPL-licensed (project is MIT / Apache / LGPL) | ❌ leave unreviewed | AGPL triggers on SaaS; this is a real obligation, not a false alarm |
| Dependency is `AGPL-3.0-only` in a `GPL-3.0-or-later` project | ✅ `license = "AGPL-3.0-only"` with `note = "GPL-3.0 § 13 explicitly permits combining with AGPL-3.0; downstream SaaS deployers inherit AGPL's network-source obligation"` | A warning; legal per AGPL § 13 + GPL § 13 |
| Dependency is `AGPL-3.0-only` in a `GPL-2.0-only` project | ❌ leave unreviewed | GPLv2 has no § 13, so the pair is a violation. Only a wrong `-only` declaration (project is really "or later") is fixable — in the manifest, not the review file |
| Dependency is `Apache-2.0` in a `GPL-2.0-only` project (pair-level violation; `risk` reads `permissive`) | ❌ leave unreviewed | FSF-documented GPLv2-incompatibility; resolve by relicensing the project to "or later" / GPLv3 or replacing the dependency |
| Dependency is `CDDL-1.1` in a `GPL-3.0-only` project, and the user confirms it is dual-licensed `CDDL-1.1 OR GPL-2.0-with-classpath-exception` | ✅ `license = "CDDL-1.1 OR GPL-2.0-with-classpath-exception"` with `note` naming where the dual license is declared | Detection override: the resolver saw only the CDDL choice; the GPL-side choice resolves the conflict |
| Dependency is `AGPL-3.0-only OR EPL-1.0` in a `GPL-3.0-only` project (warning; `risk` reads `weak-copyleft`, `reason` names network copyleft); the user accepts the AGPL terms | ✅ `license = "AGPL-3.0-only OR EPL-1.0"` with `note = "taken under AGPL-3.0-only; GPL-3.0 § 13 permits the combination; downstream SaaS deployers inherit AGPL's network-source obligation"` | The EPL-1.0 choice is a pair-level violation, so the verdict is the AGPL choice's warning; the note records which choice is taken |
| Dependency is `MPL-2.0` (warning); project is SaaS and doesn't modify the dependency's source | ✅ `license = "MPL-2.0"` with `note = "SaaS, no modifications to MPL-licensed files"` | Context-based: MPL obligations don't trigger here |
| Dependency is `MPL-2.0`; user forked and modified the dependency's source files | ❌ leave unreviewed (or follow MPL: publish the modifications, then mark reviewed with that note) | MPL obligations *do* trigger on modified files; user must comply |
| Dependency declares `Proprietary`; user names a formal agreement covering production use | ✅ `license = "Proprietary"` with `note = "licensed under MSA-2025-0042 §4.2; redistribution in shipped client permitted"` | Terms-based exception with a verifiable reference |
| Dependency declares `Proprietary`; no formal agreement, but the user can describe what permits the use | ✅ `license = "Proprietary"` with `note = "bundled EULA permits free internal use for projects under 50 seats; ours is 12"` (or similar concise factual description naming the operative clause) | Audit-trail content is what matters, not paperwork format; the note has to be checkable, not formal |
| Dependency declares `Proprietary`; user says *"we use it"* / *"should be fine"* / *"we have a contract somewhere"* | ❌ leave unreviewed | Not recordable terms — a future reviewer can't verify the use without going back to the engineer who wrote the note |
| Dependency is `GPL-2.0-only WITH Classpath-exception-2.0` in an MIT project (e.g. an OpenJDK module pulled transitively) | ✅ `license = "GPL-2.0-only WITH Classpath-exception-2.0"` with `note = "Classpath exception permits linking from non-GPL code; linked unmodified"` | Classifies as weak copyleft (warning, not violation): the exception permits linking from differently-licensed projects. Confirm the user links rather than modifies the GPL portion |
| Dependency is `Apache-2.0 WITH Commons-Clause` in an MIT project (unknown; `reason` says the exception is not recognized); nobody has read the clause | ❌ leave unreviewed | The text after `WITH` is not judged as part of `Apache-2.0`; here it forbids selling the software, so the entry needs a confirmed, recorded reason the project's use stays inside it |
| A gem's `licenses` are `["MIT", "GPL-3.0-only"]` in an MIT project (unknown; `reason` gives a compatible choice reading and an incompatible all-apply reading); the user reads the gem's README, which offers it under either license | ✅ `license = "GPL-3.0-only OR MIT"` with `note = "README: dual-licensed, either license at the user's choice"` | The registry array did not say how the two relate; the confirmed reading is a choice, and the project takes the MIT choice |
| Same gem, but its license file says the GPL covers a bundled component that ships with it | ❌ leave unreviewed | Both licenses apply, so this is the GPL violation the all-apply reading describes; resolve the dependency rather than record it |
| `project_license_source` is `""` (the project was checked as `Proprietary`) on a project that is not proprietary | ❌ leave all unreviewed (for now) | Fix the project's own license declaration first, or scan the right sub-package with `--path`; flagged verdicts in this state reflect the missing project signal, not real conflicts |
| User says "I just want this to pass CI, the license is genuinely incompatible" | ❌ leave unreviewed | Accepting the risk is a policy decision made *outside* the review file |
