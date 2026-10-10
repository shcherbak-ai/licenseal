---
name: licenseal-review
description: Audit a project's dependency licenses with licenseal — scan deps, establish project context (distribution / commercial / linkage), walk the user through flagged warnings / violations / unknowns with verdict-aware questions, record explicit reviews with documented rationale in licenseal.review.toml, and save LICENSES.md as the audit deliverable. Honest assessment, not gap-closure — reviewed entries pass CI; real incompatibilities stay flagged.
when_to_use: Trigger only when the user explicitly wants to audit or review their project's dependency licenses, investigate licenseal-flagged dependencies, resolve license warnings / violations / unknowns, or generate or extend licenseal.review.toml. Do NOT trigger for a one-off "what license does package X use?" identification, general licensing discussion, or a single-dependency lookup — only for a full dependency-license compatibility audit or acting on flagged deps.
---

# licenseal review

Use this skill when the user wants to audit dependency licenses in any licenseal-supported project (Python, npm, Rust, Go, Java, .NET, PHP, Ruby, Hex, R), investigate licenseal-flagged dependencies, or generate / extend `licenseal.review.toml`.

## Prerequisites

Determine the right invocation for `licenseal` **before** running anything else. Most modern Python projects keep their CLIs inside a project venv (`uv`, `poetry`, `pdm`) rather than on the global PATH, so probing the bare `licenseal` command first usually fails noisily and tells you nothing useful. Detect the project tooling from the project root and pick the matching invocation:

| Signal | Invocation to use everywhere below |
| --- | --- |
| `uv.lock` exists, or `pyproject.toml` has `[tool.uv]` / dependency-groups, or `.python-version` exists | `uv run licenseal ...` |
| `poetry.lock` exists | `poetry run licenseal ...` |
| `pdm.lock` exists | `pdm run licenseal ...` |
| `pipenv` `Pipfile.lock` exists | `pipenv run licenseal ...` |
| None of the above | `licenseal ...` (assumes a global install via `uv tool install` / `pipx install` / `pip install`, or an activated venv) |

Verify the chosen invocation works with `<invocation> --version` (e.g. `uv run licenseal --version`). Use that exact prefix for every `licenseal` command in the rest of this skill — including the `init-review-file` and re-scan steps.

If the chosen invocation fails:

- For a tool-managed project (uv / poetry / pdm / pipenv), licenseal isn't a project dep. Ask the user to add it: `uv add licenseal --dev` (or the equivalent for their tool).
- For an unmanaged project, ask the user to install globally: `uv tool install licenseal` (recommended) or `pipx install licenseal` or `pip install licenseal`.

## Posture

This skill produces an honest license-compatibility assessment; it does **not** try to make every flagged dep pass. Some deps will remain flagged after this skill runs — that is the correct outcome when an incompatibility is real and the user has no override evidence.

Hold these principles throughout:

- The review file overrides **detection** ("the resolver got the license wrong, here's the actual SPDX ID I confirmed") or records an **accepted** verdict with a documented rationale. The verdict counter (warnings / violations / unknown) doesn't change — a reviewed dep that classifies as `warning` (or `violation` / `unknown`) keeps that classification in the report — but the CI gate (`licenseal check --strict`) treats reviewed entries as passing on the assumption that the `note` is the audit trail.
- Project context (SaaS / library / internal / commercial — gathered in step 3) can legitimately change which obligations apply, narrowing what's flagged. Use it to ask the *right* per-dep question — never to manufacture an exception that doesn't really apply.
- Residual **unreviewed** flagged deps after this skill are an **output**, not a failure mode. They tell the user exactly what they still need to act on (remove, replace, accept the legal risk, or seek legal review).
- When in doubt, leave the entry empty. A dep that stays unreviewed on the next scan is a question the user can revisit; a wrong review entry is a silent audit-trail problem.

## Procedure

### 1. Run the scan

Pick a platform-appropriate temp path for the scan JSON — call it `$SCAN_FILE` below. The file is reused through step 5 (so `init-review-file --from-report` doesn't have to re-resolve licenses over the network), then discarded.

| Shell | Suggested temp path |
| --- | --- |
| bash / zsh | `SCAN_FILE=$(mktemp)` |
| PowerShell | `$SCAN_FILE = (New-TemporaryFile).FullName` |

`mktemp` with no args works on both GNU coreutils (Linux) and BSD `mktemp` (macOS); the `--suffix=` flag is GNU-only and breaks on macOS. The file's extension doesn't matter — `init-review-file --from-report` reads the JSON regardless.

Then from the project root:

```bash
licenseal check --no-dev -f json --no-strict -o "$SCAN_FILE"
```

For projects whose dev dependencies also matter to the audit, use `--dev` instead (one scan, not two — `--dev` is a superset of `--no-dev`).

### 2. Read the summary

Parse `$SCAN_FILE`. The full top-level schema is described in the licenseal repo's `JSON_OUTPUT.md` (that file isn't shipped with this skill — don't try to open it locally; every field used below is named inline). Report concisely to the user:

- `project_license`, and `project_license_source`: the manifest in the scanned directory that declared it. An empty `project_license_source` means no manifest there declares a license licenseal recognises, and the project was checked as `Proprietary` — say so explicitly.
- `summary.total` deps scanned
- `summary.warnings + summary.violations + summary.unknown` flagged
- `summary.gaps` — manifests licenseal couldn't read or parse, whose dependencies no lockfile covers, or under which a package's own dependency list could not be read from a registry (the top-level `diagnostics[]` array names each one with a `reason`). A gap is an *incomplete* analysis, not a license finding: under the default `--strict` it fails CI on its own, and the review file **cannot** silence it.

If the flagged total **and** `summary.gaps` are both `0`, the project is clean — say so and stop. If flagged is `0` but `summary.gaps > 0`, the project is **not** clean: list the gap paths from `diagnostics[]` and treat resolving them (unreadable manifest, syntax error, unsupported file, a `go.mod` below `go 1.17` with no `go.sum` row for its requirements — commit an up-to-date `go.sum`) as the action item — the review file can't paper over them, and step 7's strict re-scan will fail until they're fixed.

**Manifests without a lockfile.** A gap whose `reason` starts with `declares dependencies that no lockfile covers` means licenseal read the manifest but had to pick versions and transitive dependencies from the registry, so the report is an estimate for it. Each such dependency carries `"estimated": ["version"]` in JSON (`~1.2.3` in the table and Markdown formats). Tell the user which manifests are affected and ask which way to settle it: commit a lockfile and re-scan (the report then describes what the project installs), or accept the estimate by adding `--no-require-lockfile` to every `licenseal check` in this workflow and in CI. With that flag the diagnostic stays in `diagnostics[]` with `severity: "estimate"`, is not counted in `summary.gaps`, and does not fail `--strict`. Do not choose for the user: a review based on estimated versions can miss the license of the version actually installed.

**Unread dependency lists.** A gap whose `reason` starts with `the dependencies of <package>` means a registry did not return that package's dependency list, so whatever it requires may be missing from the report even though the package itself is listed. It is usually a transient registry error or rate limit: run the scan again. If it persists (a Maven version deps.dev has not indexed, a NuGet dependency declared without a version that can be pinned), tell the user which package is affected. A lockfile removes the need for the registry walk; `--no-require-lockfile` does not accept this gap.

### 3. Establish project context

License compatibility is rarely "license A vs license B" in isolation — the obligations triggered by copyleft and source-available licenses depend on **how the project is used and distributed**. Skipping this step leads to false-alarm questions (telling a SaaS user their LGPL dep needs scrutiny that doesn't actually apply) or false-clean answers (waving through an AGPL dep on a hosted product).

#### 3a. Infer what you can from the codebase

Before asking the user, gather signals already in the repo:

- **Project's own license** — already in the scan JSON as `project_license`, read from the manifest named in `project_license_source`. No need to re-derive. licenseal reads it only from a manifest in the scanned directory, never from a nested package: to audit one package of a monorepo against its own license, scan that package with `--path`.
- **Library vs application**:
  - Python: `[project.scripts]` / `[project.entry-points]` in `pyproject.toml` → CLI / app. A `[project] name` with no scripts and a `src/<name>/` layout → library. Both possible.
  - npm: `bin` field in `package.json` → CLI / app. `main` / `exports` only → library. No `main` and a server framework dep → app / SaaS.
  - Rust: `Cargo.toml` `[[bin]]` table → app. `[lib]` table → library. Both possible.
- **Distribution surface** — look for `.github/workflows/publish.yml`, `Dockerfile`, `Procfile`, deployment configs (`fly.toml`, `render.yaml`, `vercel.json`, `app.yaml`, …). Publishing workflow → distributed package. Deployment config → hosted service / SaaS.
- **Shipped artifacts (channels even a SaaS distributes through)** — a SaaS-labelled project still distributes when its code reaches third parties via any of: browser-bundled JS (`webpack.config.*`, `vite.config.*`, `rollup.config.*`, `next.config.*`, `nuxt.config.*`, `svelte.config.*`, or a `build` script producing browser-bound output), a desktop or mobile client (`electron-builder`, `tauri.conf.*`, `expo` / `app.json`, `react-native.config.*`), an on-prem / self-hosted tier (Helm charts, `install.sh`, `selfhost/` / `enterprise/` / `deploy/` directories), or public container images (CI pushing to Docker Hub / GHCR Public / ECR Public). Each is its own distribution channel; the SaaS safe harbor for distribution-triggered copyleft only holds when *none* apply.
- **Linkage model** — language-defaulted: Python and JS use **dynamic** linkage (runtime imports). Rust binaries use **static** linkage by default (the dep is compiled into the artifact). This matters for LGPL: dynamic linkage is generally fine; static linkage requires either dynamic linkage, shipping object files, or a different license.

#### 3b. Confirm with the user

Show the inferred picture in one short sentence, then ask the remaining gaps. Keep this to **2–3 questions max**:

1. *"It looks like a [library / CLI / web service / internal tool]. Distribution model: (a) library to other devs, (b) standalone app / CLI binary, (c) SaaS / hosted service, (d) internal-use only, (e) embedded / firmware? **If (c)**, also list any sub-channels that ship this code to third parties: browser-bundled JS sent to user agents, desktop client (Electron/Tauri), mobile app (React Native / Expo), on-prem / self-hosted tier (Helm chart, install script, customer-run deploy), public container images. Those are distribution channels even though the headline is SaaS."*
2. *"Is the project commercial (sold, monetized, used inside a paying business) or non-commercial (FOSS, hobby, research)?"*
3. **Only ask if** any flagged dep has a source-available license (`SSPL-*`, `BUSL-*`, `Elastic-*`, `FSL-*`, `Parity-*`, `PolyForm-*`) — *"Does the project compete with the dep vendor's commercial offering?"*

Store the answers as `context = {distribution, shipped_artifacts, commercial, competing}`. `shipped_artifacts` is the set of sub-channels from the SaaS follow-up (`browser-bundle`, `desktop`, `mobile`, `on-prem`, `public-container`); empty when distribution isn't SaaS or the SaaS is purely server-side. You'll reference them in step 4.

### 4. Walk through flagged dependencies

A flagged dep has `verdict` in `{"warning", "incompatible", "unknown"}`. Group them by verdict and walk **violations first, then warnings, then unknowns**. For each, show the user:

- `name@resolved_version` (`ecosystem`)
- `effective_license` (note `license_raw` separately if it differs)
- `verdict`, `risk`, and `reason`
- `actionability.investigate_url` (the canonical link to investigate)

**Precondition — the project license must be the right one.** Every verdict is relative to `project_license`. If `project_license_source` is `""`, no manifest in the scanned directory declares a license licenseal recognises, and the project was checked as `Proprietary`: permissive dependencies pass and every copyleft dependency is flagged. That is right for a closed-source project. It is wrong for an open-source project whose license is declared only in a nested package or a `LICENSE` file, or with a value licenseal did not recognise (the scan's stderr then has a `Warning:` naming the file and the value). Before walking findings, confirm with the user that the project really is proprietary. If it is not, stop the walkthrough and ask them to declare the license in a manifest of the scanned directory (`pyproject.toml` / `package.json` / `Cargo.toml` / …), or to scan the sub-package with `--path`, then re-scan. A `Warning:` that manifests declare different licenses gets the same treatment: ask which is right and have the others corrected first. A dual-licensed project with one unrecognized arm (`AGPL-3.0-only OR Commercial`) is not in this state: licenseal judges the unrecognized arm as a `Proprietary` arm, so copyleft deps flag as INCOMPATIBLE against it. Walk those as real findings, and if the arm is misspelled, have the user fix the manifest.

**`OR` dependencies.** When `license` is an `OR` expression, the verdict is that of the single choice that suits the project best, and each choice is checked as a whole: risk level, pair-level conflict, and any operand that did not resolve. `risk` still reads the least restrictive choice, so `reason` can name a stricter license class than `risk` does. That means the lower-risk choice is not open to this project: it has a pair-level conflict with the project license, or it carries an unresolved operand. Use the pattern below that matches the class or conflict named in `reason`, and ask about the arm it describes. Example: `AGPL-3.0-only OR EPL-1.0` in a `GPL-3.0-only` project is a WARNING whose `reason` says network copyleft while `risk` reads `weak-copyleft` — `EPL-1.0` is a pair-level violation there, so walk it as the network-copyleft warning for the AGPL arm.

Frame the per-dep question by combining verdict, risk, and project context. The most common context-dependent patterns:

- **WARNING — weak copyleft dep in permissive project (MPL-2.0, LGPL-*, EPL-*, CDDL-*, GPL-with-Classpath-exception)**:
  - `context.distribution` ∈ {SaaS, internal} **and** `context.shipped_artifacts` is empty → obligations typically don't trigger. Ask: *"This is a [SaaS / internal-use] project with no shipped artifacts, so {license}'s file-level / linking obligations don't usually apply. OK to mark as reviewed?"*
  - `context.distribution` = library / app **and** Rust (static linkage) → ask: *"{license} on a static-linked binary needs either dynamic linkage or shipping object files. How is this dep linked in your build?"*
  - `context.distribution` = library / app **and** Python/JS (dynamic linkage) → ask: *"{license} is generally fine with dynamic linkage. Did you fork or modify the dep's source? (MPL only requires disclosure of *modifications* to MPL-licensed files.)"*
  - License is `GPL-2.0-with-classpath-exception` or `GPL-* WITH Classpath-exception-2.0` / `Classpath-exception-2.0-short` (OpenJDK-derived and `javax.*` / `jakarta.*` artifacts) → licenseal classifies the Classpath exception as weak copyleft because it permits linking independent modules regardless of their license. Ask: *"The Classpath exception covers linking — are you linking against {name} unmodified, not modifying or forking the GPL portion itself?"* If yes → reviewable with the linking rationale in `note`.

- **WARNING — network-copyleft dep in strong-copyleft project (`AGPL-*` dep in `GPL-*`, `OSL-*`, `EUPL-*`, `CC-BY-SA-*`, `ODbL-*` project)**:
  - This is the GPL+AGPL combinability cell. AGPL-3.0 § 13 and GPL-3.0 § 13 explicitly permit the combination, but the AGPL portion's source-on-network-access obligation binds anyone who deploys the combined work over a network. The combination is legal; the project's *effective* obligations get stronger.
  - **Note — GPL-2.0-only projects never land here**: the pair-override layer upgrades an AGPL-3.0 dep under a GPL-2.0-only project straight to INCOMPATIBLE (GPLv2 has no § 13), so this warning only fires for projects that can take the combination at v3. If `project_license` is a bare `GPL-*` string whose version you doubt, confirm it before reviewing: *"Is your {project_license} actually GPL-3.0-or-later?"*
  - `context.distribution` = SaaS → AGPL terms bind downstream users of the deployed service. Ask: *"AGPL requires source disclosure to network users of any deployment. Is publishing source for the SaaS deployment acceptable?"*
  - `context.distribution` ∈ {library, app, internal} → AGPL trigger is dormant for non-network distribution. Ask: *"The combination is legal under GPL § 13. Downstream SaaS deployers of your project will inherit AGPL's network-source obligation. OK to mark as reviewed with that documented?"*

- **WARNING — `EPL-2.0` dep in a GPL-family project** (`reason` mentions "secondary license"):
  - EPL-2.0 is GPL-compatible only when the Eclipse contributor designated the GPL as a secondary license (EPL-2.0 § 3.2 / Exhibit A); package metadata can't reveal that designation, so licenseal warns instead of hard-failing. Ask: *"Check {name}'s source headers or NOTICE file — does it designate the GNU GPL as a secondary license? (Most `jakarta.*` artifacts do.)"* If yes → reviewable with the secondary-license grant recorded in `note`. If no or unverifiable → the combination is GPL-incompatible; treat like a violation.

- **INCOMPATIBLE — pair-level conflict** (`reason` cites the FSF, an "upgrade clause", or "GPLv3-family terms" rather than the generic copyleft-mismatch text):
  - These come from the pair-override layer, not the coarse matrix: specific license pairs that are legally incompatible even though their risk levels would pass. The dep's `risk` can even read `permissive` — the conflict is between the *pair* of licenses.
  - **GPLv3-family dep (`GPL-3.0-*`, `LGPL-3.0-*`, `AGPL-3.0-*`) in a `GPL-2.0-only` project**, or **`GPL-2.0-only` dep in a `GPL-3.0-*` / `AGPL-3.0-*` project**: version conflict with no upgrade clause to escape it. A deprecated bare ID in a manifest or registry (`GPL-2.0`, `LGPL-3.0`) is read as `-only` and reported that way; only a `+` suffix (`GPL-2.0+`) or an explicit `-or-later` carries the upgrade clause. Only a detection error is reviewable — ask: *"Is the project (or dep) actually licensed 'or later'? If the manifest says `-only` or a bare `GPL-2.0` by mistake, fix the manifest rather than reviewing the dep."*
  - **`Apache-2.0` dep in a `GPL-2.0-only` project**: the FSF documents Apache-2.0 as GPLv2-incompatible. Resolution is usually relicensing the project to `GPL-2.0-or-later` / `GPL-3.0` or replacing the dep — not a review entry. `Apache-2.0 WITH LLVM-exception` is not flagged: that exception waives the conflicting sections for a combination with GPLv2 code.
  - **`EPL-1.0` / `CDDL-*` / `MPL-1.1` dep in any GPL-family project**: FSF-documented GPL-incompatible weak copyleft. Check for dual licensing first — ask: *"Many EPL/CDDL-era artifacts are dual-licensed (e.g. `CDDL OR GPL-2.0-with-classpath-exception`). Does {name} offer a second license the resolver missed?"* If yes → reviewable with the full dual-license expression; if no → real incompatibility.

- **INCOMPATIBLE — copyleft / share-alike mismatch (strong-copyleft or network-copyleft dep in permissive or weak-copyleft project)**:
  - Covers: `GPL-*`, `OSL-*`, `EUPL-*`, `CC-BY-SA-*`, `ODbL-*`, `CDLA-Sharing-*`, `Sleepycat`, `GFDL-*`, `RPL-*` deps in MIT / Apache / BSD / LGPL / MPL projects, plus `AGPL-*` deps in any project that isn't strong-copyleft (those are warnings — see above).
  - **Special case — OSL-\***: OSL-3.0 § 5 ("External Deployment") treats running the program on a network-accessible server as a trigger — same shape as AGPL. The "internal-use only" defense below applies *only* if the server is not externally accessible.
  - **Special case — `WITH <exception>`**: licenseal matches the text after `WITH` whole against a fixed list. The Classpath exception is already handled — `GPL-* WITH Classpath-exception-2.0` (or `Classpath-exception-2.0-short`) classifies as weak copyleft and lands in the WARNING bucket above, not here. An exception that only adds a permission (`Autoconf-exception-2.0`, `Autoconf-exception-3.0`, `Bison-exception-2.2`, `Bootloader-exception`, `Font-exception-2.0`, `GCC-exception-2.0`, `GCC-exception-3.1`, `Libtool-exception`, `Linux-syscall-note`, `LLVM-exception`, `OCaml-LGPL-linking-exception`, `Swift-exception`, `Universal-FOSS-exception-1.0`, `WxWindows-exception-3.1`) is judged as its bare license, pair-level conflicts included. licenseal models one effect among them: `Apache-2.0 WITH LLVM-exception` in a `GPL-2.0-only` project is compatible and never lands here, because `LLVM-exception` lets the Apache-2.0 sections that conflict with GPLv2 be waived for a combination with GPLv2 code. Others *loosen* the obligation in ways the coarse matrix does not model: `GCC-exception-3.1` permits linking from non-GPL code. If the flagged `license` contains `WITH` one of these, surface this to the user: *"{license} flags as INCOMPATIBLE on its bare license, but {exception} was specifically designed to permit some combinations. Does the exception apply to your use (e.g. you're linking, not modifying the GPL portion itself)?"* If confirmed, mark as reviewed using the full `WITH`-form expression so the audit trail names the exception (`license = "GPL-3.0-only WITH GCC-exception-3.1"`). Any other text after `WITH` is terms licenseal did not read, and it never lowers a verdict. Such a dep lands here only when its bare license is itself the violation (`GPL-3.0-only WITH <unrecognized>` in an MIT project, `Apache-2.0 WITH <unrecognized>` in a `GPL-2.0-only` project); `reason` then ends with *is not an exception licenseal recognizes, so the license is judged without it*. Walk it as the bare license under the branches below, and treat the exception as a way out only when the user has read its text and it grants the permission their use needs — then record the full `WITH` expression as `license` and where the text was read in `note`. When the bare license would pass, the term is UNKNOWN instead; see the unrecognized-exception bullet below.
  - **Special case — malformed license expression** (`license` is `UNKNOWN` and `reason` says the declared string *is not a well-formed license expression*): the registry string has an operator with nothing on one side of it, or parentheses that do not pair up (`MIT OR GPL-3.0-only AND`, `MIT OR (GPL-3.0-only`), so licenseal did not trust its `OR` as a choice and judged every license it names as applying together. Settle the detection first: show the user `license_raw` and `actionability.investigate_url` and ask: *"{name} declares '{license_raw}', which is not a valid license expression. What does the package's own license file or documentation say — is it a choice between these licenses, or do they all apply?"* A confirmed choice the project can take → reviewable with the corrected expression (`license = "MIT OR GPL-3.0-only"`) and `note` naming where it was confirmed. They all apply, or nobody has confirmed → the violation stands; continue with the context branches below for the copyleft license named in `reason`.
  - **Special case — license list with an unrecognized entry** (`license` is `UNKNOWN` and `reason` says the declared string is *a license list with an entry that did not resolve to a recognized license*): the registry string is a comma- or slash-separated list (`GPL-3.0-only, acme internal license`) in which licenseal recognizes some entries and not others, and every entry it recognizes is a violation in this project, so the dep is flagged whether the entries are alternatives or all apply. Settle the detection first: show the user `license_raw` and `actionability.investigate_url` and ask: *"{name} declares '{license_raw}'. What is the part licenseal could not read — a second license you may choose instead, extra terms on top of the first, or only a note?"* A confirmed alternative license the project can take → reviewable with the full `OR` expression as `license` and `note` naming where it was confirmed. Extra terms, a note, or nobody has confirmed → the violation stands; continue with the context branches below for the license named in `reason`.
  - `context.distribution` = internal-use only **and** `context.shipped_artifacts` is empty **and** license trigger is distribution-based (GPL-*, CC-BY-SA-*, EUPL-*, ODbL-*, CDLA-Sharing-*, Sleepycat, GFDL-*, RPL-*) → copyleft does not trigger without distribution. Ask: *"This is internal-use only with no shipped artifacts, and {license} only triggers on distribution. Confirm you don't ship binaries / source externally?"* If confirmed, this is reviewable (record the internal-use rationale in `note`).
  - `context.distribution` = SaaS **and** `context.shipped_artifacts` is empty **and** license is distribution-triggered strong-copyleft other than AGPL / OSL (`GPL-*`, `CC-BY-SA-*`, `EUPL-*`, `ODbL-*`, `CDLA-Sharing-*`, `Sleepycat`, `GFDL-*`, `RPL-*`) → server-side-only deployment, no distribution channel. Copyleft trigger is dormant. Ask: *"This is SaaS-only with no browser bundle, no on-prem / self-hosted tier, no desktop or mobile client, no public container image — none of {name}'s code paths reach a third party. {license}'s copyleft only triggers on distribution. OK to mark reviewed with the SaaS-only assumption captured in `note`?"* Reviewable; record the SaaS-only assumption in `note` (e.g. `"SaaS-only, server-side, no shipped artifacts; copyleft trigger dormant. Re-audit if a shipped channel is added."`). **Surface the brittleness explicitly:** the safe harbor depends on `shipped_artifacts` staying empty — adding an Electron client, an enterprise on-prem tier, a mobile app, or a browser-side bundle re-activates the obligation.
  - `context.distribution` = SaaS **and** license is AGPL → AGPL **does** trigger on SaaS regardless of `shipped_artifacts`. Ask: *"{license} requires publishing modifications and full corresponding source for SaaS deployments. Is your project AGPL-licensed too, or is publishing source acceptable?"* If neither applies, the dep stays flagged — do not write a review entry.
  - `context.distribution` = library / app **OR** `context.shipped_artifacts` is non-empty → hard incompatibility on every distribution path. Recommend removal or relicensing. **No review entry** unless the user has independent confirmation that the detection is wrong (e.g. they've read the bundled LICENSE file and the resolver mis-identified it).

  **Across all INCOMPATIBLE branches**: only write a review entry when there is a concrete reason it's wrong (detection error, signed agreement, context-based exception that actually applies). If the user just doesn't want the violation to fail CI, that is not a valid reason — the dep stays flagged and the user resolves it outside the review file (remove, replace, accept the risk, or seek legal review).

- **UNKNOWN — registry didn't expose / non-SPDX license**:
  - Ask: *"Can you check {actionability.investigate_url} and tell me the actual license?"* Wait for their answer; record it as the reviewed license. If unknown, leave unreviewed.

- **UNKNOWN — license list with no stated meaning** (`reason` says the dep *lists several licenses without stating whether they are alternatives*):
  - The licenses **are** identified — do not ask *"what's the actual license?"*. The source gave several of them without saying whether you may pick one or must comply with all: a RubyGems or Hex `licenses` array, several PyPI license classifiers, or a comma- or slash-separated list in one license string (`license_raw` shows it). `license` shows the list as a choice; `reason` gives the verdict of that reading and of the reading where every entry applies, and they differ. Point the user at `actionability.investigate_url` and ask: *"{name} lists {the licenses} without saying how they relate. What do the package's license file and README say — is it offered under either license at your choice, or do all of them apply to the code you use?"*
  - A choice, confirmed → reviewable with the `OR` expression from `reason` as `license` and `note` naming where it was confirmed. The re-check then judges that expression as written.
  - All apply, confirmed → the `AND` expression is the real license, and `reason` already shows its verdict. When that verdict is a violation or a warning, walk the matching INCOMPATIBLE / WARNING pattern for the license that causes it, and write the `AND` expression as a review entry only if that pattern makes it reviewable; otherwise leave it unreviewed.
  - Not confirmed → leave unreviewed.

- **UNKNOWN — R package whose license adds a file** (`ecosystem` is `r`, `license` is `<license> AND UNKNOWN`, and `license_raw` reads `<license> + file LICENSE`):
  - The named license **is** identified. On CRAN, `+ file LICENSE` after a license other than MIT or BSD means the package's `LICENSE` file restricts or extends that license, and licenseal never reads the file. Ask: *"{name} declares '{license_raw}'. Open its LICENSE file from {actionability.investigate_url} — what does it add to the named license?"*
  - It adds nothing that limits the project's use (a copyright-holder list, an attribution notice) → reviewable with the named license as `license` and `note` saying what the file contains. It adds a restriction → reviewable only when the user confirms the project's use stays inside it, with that recorded in `note`. Unread → leave unreviewed.
  - If the verdict is `incompatible` instead, the named license is itself the violation: walk it under the INCOMPATIBLE patterns above.

- **UNKNOWN — off-registry source** (`origin` is non-empty, `reason` says "comes from an off-registry source"):
  - The dependency is installed from a git repository, a direct URL, or a path the scan does not read (outside the project, an archive such as a wheel or a JAR, a vendored or excluded directory), not from the registry. licenseal makes no registry request for it, and the registry package of the same name is a different package: do not look the name up on the registry, and expect `package_url` and `actionability.investigate_url` to be empty. Ask: *"{name} comes from {origin}. Can you read the license at that source and tell me what it is?"* Record the answer as the reviewed license. If unknown, leave unreviewed.
  - The review is keyed on the `origin`, not on the version. When the `origin` of a git dependency ends in a branch or a tag rather than a commit, tell the user that the review keeps applying when that branch or tag moves, and that pinning a commit in the manifest or committing a lockfile makes the key immutable.

- **UNKNOWN — source-available (SSPL-*, BUSL-*, Elastic-*, FSL-*, Parity-*, PolyForm-*)**:
  - `context.commercial` = no **or** `context.competing` = no → source-available terms typically allow non-competing use. Ask: *"{license} restricts competing commercial use. You said this is [non-commercial / non-competing] — confirm and mark as reviewed?"*
  - `context.commercial` = yes **and** `context.competing` = yes → real incompatibility. Recommend removal / alternative.
  - `context.competing` unknown for this dep → ask explicitly per dep: *"{license} restricts use that competes with {dep vendor}. Does your product compete with their commercial offering?"*

- **UNKNOWN — use-restricted SPDX ID (`CC-BY-NC-*`, `CC-BY-ND-*`, `BSD-3-Clause-No-Military-License`, `BSD-3-Clause-No-Nuclear-License`, `BSD-3-Clause-No-Nuclear-License-2014`, `BSD-Protection`, `Unicode-TOU`)** (`license` is one of these IDs, `risk` reads `unknown`):
  - The license **is** identified — do not ask *"what's the actual license?"*. Its terms limit a kind of use (non-commercial only, no derivatives, an excluded field of use, or conditions on modified or redistributed copies) that licenseal does not evaluate. Point the user at `actionability.investigate_url` and ask: *"{license} restricts how the software may be used or redistributed. Have you read the restriction, and does your project's use stay inside it?"*
  - User confirms the use stays inside the restriction → reviewable as `license = "{license}"` with `note` recording why (e.g. `"non-commercial research project"`, `"used unmodified, not redistributed"`). The restriction applies, or the user is unsure → leave unreviewed.
  - `BSD-3-Clause-No-Nuclear-Warranty` is not in this group: it is a warranty disclaimer, classifies as permissive, and is not flagged.

- **UNKNOWN — unrecognized `WITH` exception** (`reason` says the text after `WITH` *is not an exception licenseal recognizes, so the terms it adds were not evaluated*; in a compound, `reason` names a `… WITH …` operand the consumer cannot avoid):
  - The license before `WITH` **is** identified — do not ask *"what's the actual license?"*. The bare license would pass in this project (a bare license that is a violation stays one — see the `WITH <exception>` special case under INCOMPATIBLE), but the text after it is not on licenseal's list, so the term does not get the bare license's verdict: it can be a real SPDX exception licenseal does not model, or a restriction written where an exception belongs (a rider that forbids selling the software, for example). Point the user at `actionability.investigate_url` and ask: *"{license} carries '{exception}', which licenseal does not evaluate. Have you read it — does it only add permissions to the license, or does it limit how the software may be used or sold?"*
  - It only adds permissions → reviewable as `license = "{license}"` (the full `WITH` expression) with `note` recording where the exception text was read and what it permits. It restricts use → reviewable only when the user confirms the project's use stays inside the restriction, with that recorded in `note`. Unread, or the user is unsure → leave unreviewed.

- **UNKNOWN / WARNING — proprietary dep** (`license == "Proprietary"`, `reason` mentions "custom commercial terms cannot be auto-classified"):
  - This is *not* the "detection found nothing" case — the license **is** known to be proprietary. The right question is about **terms**, not identity. Do not ask *"what's the actual license?"*; ask about permitted use, redistribution, royalties, and field-of-use limits.
  - **Dev-only dep** (licenseal downgrades to WARNING): ask *"Is this a paid dev tool covered by your team's existing license or subscription?"* If yes → reviewable as `license = "Proprietary"` with `note` recording the licensing arrangement.
  - **Prod dep, `context.distribution` = internal-use only**: ask *"What permits the internal use? (e.g. purchased license, bundled EULA, vendor portal subscription, free-for-non-commercial clause...)"* If the user names a specific arrangement → reviewable with `note` recording it (a verifiable reference like `"licensed for internal use under MSA-2025-0042"` is ideal; a concise factual explanation like `"bundled EULA permits internal-only use"` is fine when no formal agreement exists).
  - **Prod dep, `context.distribution` ∈ {library, app, SaaS}**: redistribution implications apply. Ask the user to confirm three specifics before reviewing: *"For {name}, can you confirm — (1) redistribution is permitted under your license, (2) royalty obligations are accounted for, (3) any field-of-use restrictions (non-competing / non-commercial sub-clauses) don't apply to your product?"* All-yes → reviewable with `note` documenting the answers (e.g. `"team license via vendor portal; EULA §3 permits redistribution in client binaries; no per-user royalty"`). Any uncertainty → leave unreviewed.
  - **`Proprietary` as one operand of a compound** (e.g. `license == "MIT AND Proprietary"`, verdict `unknown`): the operand is a custom-terms license, usually a `LicenseRef-*` reference, and `license_raw` shows the declared string. Ask the terms questions above about that operand. With recordable terms → reviewable with the full expression as `license` and the arrangement in `note`.
  - **Never review proprietary deps without recordable terms.** The `Proprietary` sentinel exists because terms vary per vendor; the `note` must name *what permits the use* — an agreement reference, a quoted clause, a ToS URL, or a concise factual description of the binding terms. *"looks fine"* / *"we use it"* / *"we have a contract somewhere"* are not recordable terms and create the audit-trail failure the review file is designed to prevent. The test: a future reviewer reading the `note` alone should be able to verify (or at least re-check) whether the use is still authorized, without going back to the engineer who wrote it.

The general pattern is: state the obligation, anchor it to the user's project context, then ask the targeted yes/no question. Collect decisions as `{(ecosystem, name, version) -> reviewed_license}`, and as `{(ecosystem, name, origin) -> reviewed_license}` for a dep with a non-empty `origin`. Only entries where the user supplied a concrete SPDX ID / expression go into the review file.

### 5. Scaffold (or extend) the review file

**First check whether `licenseal.review.toml` already exists at the project root.** `init-review-file` refuses to clobber an existing file, so the invocation differs:

- **No review file yet** — scaffold a fresh one:

  ```bash
  licenseal init-review-file --from-report "$SCAN_FILE"
  ```

  This writes `licenseal.review.toml` to the project root with one `[[review]]` stanza per flagged dep that has a resolved version or an `origin`, each with `license = ""`. The stanza of an off-registry dep carries a `source` line holding its `origin`; that line is its key, and its `version` line is present only when the scan recorded a version.

- **A review file already exists** (a re-audit, or the project committed one earlier) — extend it in place with `--merge`:

  ```bash
  licenseal init-review-file --from-report "$SCAN_FILE" --merge
  ```

  Merge is **append-only, keyed by `(ecosystem, name, version)`** (by `(ecosystem, name, source)` for a stanza with a `source` line): every existing stanza is preserved verbatim (filled-in reviews keep their `license` / `note`), and a fresh empty stanza is appended only for newly-flagged deps not already present. The command reports `Appended N review entr(y/ies)` or `No new flagged dependencies to add.` Without `--merge` it aborts with `licenseal.review.toml already exists` — that's the cue to re-run with the flag, **not** to delete the file (deleting discards the existing audit trail).

  **Merge does not reconcile stale entries.** If a previously-reviewed dep changed version, merge appends a *new* empty stanza for the new version and leaves the *old* filled stanza untouched — it can't tell they're the same dep. The old stanza then surfaces on the next `check` (step 7) as a `did not match any resolved package versions` error; resolve that by hand-editing the `version` field on the stale stanza — but only if the new version reports the same license (verify against the fresh scan first; if it changed, delete the stanza so the dep re-flags). Re-merging will not fix a stale pin. A stanza with a `source` line goes stale the same way when the dependency's commit, ref, URL, or path changes: the new source is different code, so ask the user to review it again before updating `source`.

If the command emits a `Note: N flagged dependencies could not be scaffolded (no resolved version) ...` line, surface those names to the user — they signal upstream issues (manifest typo, yanked release, registry miss) that the review file can't paper over.

### 6. Fill in the review file

For each empty `[[review]]` stanza in `licenseal.review.toml` — on a `--merge` run that's just the freshly-appended ones; leave already-filled stanzas from prior audits untouched — look up the dep's `(ecosystem, package, version)` triple (`(ecosystem, package, source)` when the stanza has a `source` line) in the decisions collected in step 4 and set `license = "<their answer>"`. Accepted values:

- a single SPDX ID (e.g. `"MIT"`, `"Apache-2.0"`)
- an SPDX expression (e.g. `"MIT OR Apache-2.0"`)
- `"Proprietary"` for closed-source / custom-terms deps the user has decided are acceptable

Optionally fill `note = "..."` with the user's rationale — especially the project-context detail that made the decision (e.g. `"reviewed: SaaS deployment, LGPL obligations don't apply"`), so the audit trail is durable.

Leave stanzas the user didn't decide on with `license = ""` (those stay flagged on the next scan).

### 7. Re-scan and confirm

```bash
licenseal check --no-dev -f json --no-strict
```

No `-o` here — pipe the JSON to stdout and parse it inline (one-off verification, no need for a second file). Once parsed, remove the step-1 scratch file: `rm "$SCAN_FILE"` (bash) / `Remove-Item $SCAN_FILE` (PowerShell).

Verify:

- `summary.reviewed` equals the number of stanzas you filled in
- The reviewed deps still appear in their respective `warnings` / `violations` / `unknown` counters — the review file overrides detection, not the verdict classification. A reviewed dep keeps whatever verdict it had; what changes is that it carries `reviewed: true` and the rationale lives in `note`.
- **Exit code**: `licenseal check` (default `--strict`) returns `0` when every flagged dep is either reviewed or compatible. The reviewed entries are excluded from the strict-mode failure check on the assumption that an explicit review is the user's accept-and-document mechanism. Verify this by running `licenseal check --no-dev` (no `--no-strict`) and confirming exit `0`. **One failure the review file can't clear:** if `summary.gaps > 0` (a manifest licenseal couldn't read or parse), `--strict` still exits non-zero no matter how many deps are reviewed — a gap is an incomplete analysis, not a flagged dep, so no review entry silences it. If the strict re-scan fails with a clean flagged count, check `summary.gaps` / `diagnostics[]` first: resolve the unreadable manifests, or accept them deliberately with `--no-strict` in CI — outside the review file. A manifest without a lockfile is settled as decided in step 2: a committed lockfile, or `--no-require-lockfile`.
- residual unreviewed flagged count equals:
  1. the unscaffoldable count from step 5, plus
  2. deps the user explicitly left undecided, plus
  3. **confirmed-real-incompatibilities** — deps where no exception applied and the user wisely chose not to write a fake review entry

If the math doesn't work out for reasons 1 and 2, the review entries probably reference wrong versions — diff against the original scan JSON and fix. **A non-zero unreviewed residual from reason 3 is the correct outcome**, not a problem to solve: report the residual count and the dep names to the user as the honest result of the audit, so they can act on it outside this skill.

### 8. Save the audit deliverable to LICENSES.md

```bash
licenseal check --no-dev -f markdown --no-strict -o LICENSES.md
```

`LICENSES.md` at the project root is licenseal's convention for the checked-in human-readable audit (licenseal itself ships one). The file captures the post-review state — all per-dep verdicts, the project license, residual flagged deps, the review entries that were applied, and any analysis gaps. `--no-strict` lets the command pass with gaps, so read the summary line of the saved file: if it ends with `N analysis gap(s)`, the file has an **Analysis gaps** section naming each manifest licenseal couldn't read or parse, or that has no lockfile, and the audit is incomplete until those are fixed. Tell the user which manifests are listed. If the user accepted estimates with `--no-require-lockfile`, pass it here too: the summary line then ends with `N estimated manifest(s)` and the file has an **Estimates** section instead. Commit it alongside `licenseal.review.toml`:

- `licenseal.review.toml` — machine-readable override state (what the next scan will apply).
- `LICENSES.md` — human-readable narrative for reviewers, auditors, and future-you.

If the project also audits dev deps, repeat with `--dev -o LICENSES-dev.md` (or whatever filename the project convention prefers).

## URL trust model

When showing URLs to the user, treat them differently:

- `package_url` (registry page) and `license_url` (spdx.org) are built deterministically by licenseal — safe to navigate.
- `repository_url` and `homepage_url` come from the registry, where a compromised package can put any URL. Don't fetch them yourself; show them to the user instead.

## LICENSE file lookup

Steps in `actionability.next_steps` for warnings and unknowns may embed a hint URL like `https://github.com/<owner>/<repo>/blob/HEAD/LICENSE`. The exact path shape depends on the host:

- GitHub: `{repo}/blob/HEAD/LICENSE`
- GitLab: `{repo}/-/blob/HEAD/LICENSE`
- BitBucket Cloud: `{repo}/src/HEAD/LICENSE`
- Codeberg: `{repo}/src/branch/HEAD/LICENSE`

The path is heuristic — licenseal can't verify the file exists. If the URL 404s, try these alternatives at the same host-specific path:

- `LICENSE.md`, `LICENSE.txt`, `LICENCE`, `LICENCE.md`
- `COPYING`, `COPYING.md`, `COPYING.txt`

If none resolve, navigate the repository file tree from the bare `repository_url`. Registries don't expose the bundled LICENSE file directly, so this convention-based lookup is the cleanest path an agent has.

## Rules

- **Never fabricate licenses.** If the registry says nothing and the user doesn't know, leave the entry empty rather than guessing.
- **Don't auto-fill warnings as reviewed without asking.** Even when the license looks fine, the user gets the final call on whether it suits their project's context.
- **Don't fetch `repository_url` or `homepage_url` content yourself**; show the URL to the user.
- **One question per dep**, not a wall of options. Match the question to the verdict.
- **Don't downgrade verdicts by changing the review note** — `license = "MIT"` overrides the detection, not the verdict-classification.
- **Don't assume project context.** If the codebase signals are ambiguous (e.g. a library with deployment configs), surface the ambiguity to the user — never silently pick a distribution model that makes the licenses look better than they are.
- **Record context in `note`.** When the user's decision depended on project context ("we're SaaS", "internal-use only", "no competing product"), capture that phrase in the `note` so the next reviewer / auditor sees the reasoning, not just the outcome.
- **The review file is for detection overrides only**, not for closing gaps. A genuine incompatibility stays in the report until the user actually resolves it (remove, replace, or accept the legal risk). Writing a review entry to silence a real violation is an audit-trail problem masquerading as a solution.

## Concrete examples — when (not) to write a review entry

| Situation | Write entry? | Why |
| --- | --- | --- |
| Registry says `UNKNOWN`; user read the bundled `LICENSE` and confirmed it's `MIT` | ✅ `license = "MIT"` | Detection was wrong, user has direct evidence |
| Dep has an `origin` (a git fork, a tarball URL, a vendored directory or archive, a path outside the project) and is `UNKNOWN`; user read the license at that source and it is `MIT` | ✅ `license = "MIT"` in the stanza whose `source` is the dep's `origin`, with `note` saying where the license was read | No registry describes this code; the review is the only license record, and it applies to that source only |
| Dep is `GPL-3.0-only` in an MIT project; project is internal-use only, no distribution | ✅ `license = "GPL-3.0-only"` with `note = "internal-use only, no distribution"` | Context-based exception genuinely applies; record the rationale |
| Dep is `GPL-3.0-only` in an MIT project; project ships a binary to customers | ❌ no entry | Real incompatibility; user must remove, replace, or relicense — outside this skill |
| Dep is `GPL-3.0-only` in an MIT project; hosted SaaS, server-side only — no browser bundle, no desktop / mobile client, no on-prem tier, no public container image | ✅ `license = "GPL-3.0-only"` with `note = "SaaS-only, server-side, no shipped artifacts; GPL distribution trigger dormant. Re-audit if a shipped channel is added."` | Distribution-based copyleft doesn't trigger when no artifact reaches third parties; brittle if a shipped channel is later added |
| Dep is `GPL-3.0-only` in an MIT project; SaaS that also bundles into browser-shipped JS, a desktop / mobile client, or an on-prem / self-hosted tier | ❌ no entry | Each shipped channel is its own distribution path; GPL trigger fires regardless of the SaaS headline |
| Dep is `CC-BY-SA-4.0` in an MIT project; project is internal-use only | ✅ `license = "CC-BY-SA-4.0"` with `note = "internal-use only, no distribution; share-alike does not trigger"` | Share-alike is distribution-triggered; internal use is fine |
| Dep is `EUPL-1.2` in an MIT project; project ships externally | ❌ no entry | EUPL is strong-copyleft, GPL-comparable; outside the EUPL compatibility list, the combination is a real incompatibility |
| Dep is `OSL-3.0` in an MIT project; project is hosted SaaS | ❌ no entry | OSL § 5 treats network-accessible deployment as a trigger; the "internal-use" defense does not apply to externally reachable servers |
| Dep is `AGPL-3.0-only`; project is hosted SaaS, not AGPL-licensed (project is MIT / Apache / LGPL) | ❌ no entry | AGPL triggers on SaaS; this is a real obligation, not a false alarm |
| Dep is `AGPL-3.0-only` in a `GPL-3.0-or-later` project | ✅ `license = "AGPL-3.0-only"` with `note = "GPL-3.0 § 13 explicitly permits combining with AGPL-3.0; downstream SaaS deployers inherit AGPL's network-source obligation"` | Warning under matrix; legal per AGPL § 13 + GPL § 13 |
| Dep is `AGPL-3.0-only` in a `GPL-2.0-only` project | ❌ no entry | GPLv2 has no § 13; the pair-override layer surfaces this as a violation directly. Only a wrong `-only` declaration (project is really "or later") is fixable — in the manifest, not the review file |
| Dep is `Apache-2.0` in a `GPL-2.0-only` project (pair-level violation; dep risk reads `permissive`) | ❌ no entry | FSF-documented GPLv2-incompatibility; resolve by relicensing the project to "or later" / GPLv3 or replacing the dep |
| Dep is `CDDL-1.1` in a `GPL-3.0-only` project, and the user confirms it is dual-licensed `CDDL-1.1 OR GPL-2.0-with-classpath-exception` | ✅ `license = "CDDL-1.1 OR GPL-2.0-with-classpath-exception"` with `note` naming where the dual license is declared | Detection override: the resolver saw only the CDDL arm; the GPL-side arm resolves the conflict |
| Dep is `AGPL-3.0-only OR EPL-1.0` in a `GPL-3.0-only` project (warning; `risk` reads `weak-copyleft`, `reason` names network copyleft); the user accepts the AGPL terms | ✅ `license = "AGPL-3.0-only OR EPL-1.0"` with `note = "taken under AGPL-3.0-only; GPL-3.0 § 13 permits the combination; downstream SaaS deployers inherit AGPL's network-source obligation"` | The EPL-1.0 choice is a pair-level violation, so the verdict is the AGPL choice's warning; the note records which choice is taken |
| Dep is `MPL-2.0` (warning); project is SaaS and doesn't modify the dep's source | ✅ `license = "MPL-2.0"` with `note = "SaaS, no modifications to MPL-licensed files"` | Context-based: MPL obligations don't trigger here |
| Dep is `MPL-2.0`; user forked and modified the dep's source files | ❌ no entry (or follow MPL: publish the modifications, then mark reviewed with that note) | MPL obligations *do* trigger on modified files; user must comply |
| Dep declares `Proprietary`; user names a formal agreement covering production use | ✅ `license = "Proprietary"` with `note = "licensed under MSA-2025-0042 §4.2; redistribution in shipped client permitted"` | Terms-based exception with a verifiable reference |
| Dep declares `Proprietary`; no formal agreement, but the user can describe what permits the use | ✅ `license = "Proprietary"` with `note = "bundled EULA permits free internal use for projects under 50 seats; ours is 12"` (or similar concise factual description naming the operative clause) | Audit-trail content is what matters, not paperwork format; the note has to be checkable, not formal |
| Dep declares `Proprietary`; user says *"we use it"* / *"should be fine"* / *"we have a contract somewhere"* | ❌ no entry | Not recordable terms — a future reviewer can't verify the use without going back to the engineer who wrote the note |
| Dep is `GPL-2.0-only WITH Classpath-exception-2.0` in an MIT project (e.g. an OpenJDK module pulled transitively) | ✅ `license = "GPL-2.0-only WITH Classpath-exception-2.0"` with `note = "Classpath exception permits linking from non-GPL code; linked unmodified"` | Classifies as weak copyleft (warning, not violation): the exception permits linking from differently-licensed projects. Confirm the user links rather than modifies the GPL portion |
| Dep is `Apache-2.0 WITH Commons-Clause` in an MIT project (unknown; `reason` says the exception is not recognized); nobody has read the clause | ❌ no entry | The text after `WITH` is not judged as part of `Apache-2.0`; here it forbids selling the software, so the entry needs a confirmed, recorded reason the project's use stays inside it |
| A gem's `licenses` are `["MIT", "GPL-3.0-only"]` in an MIT project (unknown; `reason` gives a compatible choice reading and an incompatible all-apply reading); the user reads the gem's README, which offers it under either license | ✅ `license = "GPL-3.0-only OR MIT"` with `note = "README: dual-licensed, either license at the user's choice"` | The registry array did not say how the two relate; the confirmed reading is a choice, and the project takes the MIT arm |
| Same gem, but its license file says the GPL covers a bundled component that ships with it | ❌ no entry | Both licenses apply, so this is the GPL violation the all-apply reading describes; resolve the dependency rather than record it |
| `project_license_source` is `""` (the project was checked as `Proprietary`) on a project that is not proprietary | ❌ no entries (yet) | Fix the project's own license declaration first, or scan the right sub-package with `--path`; flagged verdicts in this state reflect the missing project signal, not real conflicts |
| User says "I just want this to pass CI, the license is genuinely incompatible" | ❌ no entry | This is a policy decision (accept the risk) made *outside* the review file, not a detection override |
