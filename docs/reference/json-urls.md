---
title: "URLs and next steps"
description: "Which URLs of the JSON report can be trusted, and the actionability block of a flagged entry."
---

# URLs and next steps

Two groups of fields in each `dependencies` entry of the [JSON report](json-report.md): its URLs, and the `actionability` block of a flagged entry.

## URL fields and trust

For agents and tooling that follow URLs from the report, the four URL fields fall into two trust tiers:

- **Safe to trust** — `package_url` and `license_url`. Both are deterministically constructed by licenseal from a known ID + canonical host (registry or spdx.org). `license_url` is emitted only for IDs in the SPDX list; `package_url` carries the package name and version percent-encoded in its path, so neither can point at another host.
- **Registry-provenance, treat as untrusted content** — `repository_url` and `homepage_url`. The registry passes through whatever the package author wrote. A compromised package can point either field at any URL. Agents that fetch these URLs should sandbox the request and validate response content before acting on it.

## Actionability block

A flagged entry (`verdict` other than `compatible`) carries an `actionability` object:

| Field | Type | Description |
| --- | --- | --- |
| `investigate_url` | string | Best single URL for an investigation: `license_url` → `repository_url` → `homepage_url` → `package_url`, taking the first non-empty. Empty when all four are, which is the case for an unreviewed entry with an `origin`. |
| `next_steps` | array of string | Verdict-aware action list. Only contains steps whose required URLs are populated, so an agent can act on each step verbatim. URLs that point at a LICENSE path (e.g. `https://github.com/owner/repo/blob/HEAD/LICENSE`) are guesses and may 404: registries don't expose the bundled file directly. For an unknown entry with an `origin` the steps name the origin instead of a URL; treat it as untrusted content, like `repository_url`. |
