# Changelog

All notable changes to this project will be documented in this file. Each version listed corresponds to a release published on [PyPI](https://pypi.org/project/licenseal/).

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] - 2026-06-10

### Added

- End-of-scan registry traffic summary on stderr (`Per-package registry requests: N (host: n, …)`), so a slow scan explains itself — a large `crates.io` share means the policy-mandated 1 req/s fallback tail dominated; a large PyPI/npm share means a no-lockfile transitive walk.

### Fixed

- Cargo `[workspace.dependencies]` is now treated as the version catalog it is: an entry becomes a dependency only when a workspace member references it with `dep = { workspace = true }` (group attribution from the referencing table, version stitched from the catalog — the same model as .NET Central Package Management). Previously every catalog entry was emitted as a direct prod dependency, so entries no member referenced — absent from `Cargo.lock` by definition — sent the transitive resolver on a crates.io registry walk of dependency trees the project never builds. On a large real-world Rust workspace this fabricated 789 phantom packages (36% of the Rust rows), three spurious GPL violations, and a 47-minute scan that now completes in ~20 seconds. Member-side `workspace = true` references also now carry their declaring table's dev/prod group instead of being dropped.

## [0.2.0] - 2026-06-10

### Added

- Pair-level compatibility overrides for license pairs the coarse risk matrix cannot express. GPL-family version conflicts (a GPLv3-family dependency — `GPL-3.0-*`, `LGPL-3.0-*`, `AGPL-3.0-*` — in a `GPL-2.0-only` project, or a `GPL-2.0-only` dependency in a `GPL-3.0-*` / `AGPL-3.0-*` project), `Apache-2.0` in a `GPL-2.0-only` project, and FSF-documented GPL-incompatible weak copyleft (`EPL-1.0`, `CDDL-*`, `MPL-1.1`) in any GPL-family project now report violations instead of false-clean `compatible` verdicts. `EPL-2.0` in a GPL-family project reports a warning, because its GPL compatibility depends on a secondary-license designation that package metadata cannot reveal. `-or-later` forms are exempt where the upgrade clause resolves the conflict, and an `OR` expression escapes when a conflict-free arm is electable. The overrides only ever strengthen the matrix verdict, and they apply to every arm of a multi-licensed project.

### Changed

- `GPL-2.0-with-classpath-exception` and `GPL-* WITH Classpath-exception-*` now classify as weak copyleft instead of strong copyleft — the Classpath exception permits linking independent modules regardless of their license. OpenJDK-derived and `javax.*` / `jakarta.*` artifacts in permissive projects now report warnings instead of false violations (which failed CI even under `--no-strict`).
- A dual-licensed project (top-level `OR`, e.g. `AGPL-3.0-only OR Proprietary`) is now checked against the strictest of its arms: dependencies must be compatible with every license the project distributes under, so the commercial arm of an open-core project flags copyleft dependencies instead of silently passing them.

### Fixed

- The aopalliance license URL now resolves to the permissive `LicenseRef-Public-Domain` sentinel instead of a bare `Public-Domain` string that no risk rule recognized, which routed a known public-domain artifact to manual review. The hyphenated `public-domain` publisher spelling normalizes the same way.
