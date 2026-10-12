---
title: "Security model"
description: "What licenseal reads, what it never does, and which files can decide a verdict."
---

# Security model

licenseal is a license-assessment tool, not a security primitive. It reads manifests, calls public registries (read-only), and writes only the local outputs a user asks for (a report, a `licenseal.review.toml` scaffold, or the project-local Claude review skill): no code execution, no privileged operations.

<figure markdown>
![Manifests and lockfiles are read on your machine and never sent. licenseal sends only package names and versions, over HTTPS, to fourteen public registry hosts on a fixed allowlist. Requests to any other host are blocked, and nothing is installed, built, or downloaded as a package.](../assets/data-flow.svg)
</figure>

- [What leaves the process](data-sent.md): what a request carries, and when the name of a private package is sent to a public registry.
- [Network egress](network.md): the fourteen hosts licenseal can contact, what each is asked, and how the allowlist is enforced.
- [License sources](license-sources.md): where each host's answer holds the license.
- [What is scanned](../concepts/discovery.md): which directories are read and which are skipped. The files read are listed for each [ecosystem](../ecosystems/index.md).
- [Report output](../get-started/read-the-report.md#write-it-to-a-file): how strings from registries and scanned files are escaped in a report.
- [URL fields and trust](../reference/json-urls.md#url-fields-and-trust): which URLs of a JSON report an agent can follow.

A package from a private registry is looked up by name on the public one. Read [What leaves the process](data-sent.md#private-packages) before you scan a project with internal packages.

## Manifests and registries only

licenseal's input is **manifests and lockfiles on disk** plus **HTTPS reads from a fixed allowlist of public registries**. It does not:

- download or inspect an artifact (`.jar`, `.whl`, `.tar.gz`, `.crate`, `.tgz`, or any other built or source archive), even when the artifact holds a structured field that no registry exposes, such as the `Bundle-License` header of a JAR's `MANIFEST.MF`;
- install or execute code of the scanned project (no `pip install`, `npm install`, `mvn`, `gradle`, `setup.py`, or lifecycle scripts);
- contact a registry that a scanned file declares, such as a POM's `<repositories>` (see [Network egress](network.md#rules-for-every-host)).

Four manifest constructs name other files to read. Each is followed only when its value is a relative path:

- An MSBuild `<Import Project="…">` in `Directory.Build.props` / `.targets`, and a `go.work` `use` directory, are followed through `..`, so the file read can be outside the scanned directory.
- A `-r` / `--requirement` line in a requirements file, and a setuptools `file:` directive in `setup.cfg` or `pyproject.toml`, are followed only when they resolve to a file inside the scanned directory. A URL is never fetched, and `-c` / `--constraint` files are never read.

A rooted, drive-qualified, UNC, or device path is rejected by a lexical check before any filesystem call (on Windows, the first call on such a path can open a connection to a network share), and the manifest that contains it is reported as an [analysis gap](../concepts/check-failures.md#analysis-gaps).

## Files that decide a verdict

`licenseal.review.toml` is a maintainer-approved override file. A malicious entry can mark a copyleft dependency as MIT and pass `licenseal check` in [strict mode](../concepts/check-failures.md). Treat it as security-relevant:

- Require code review on every change to `licenseal.review.toml`.
- Give the reason for each entry in its `note` field.
- Re-validate entries periodically when their resolved versions change upstream.

`composer.lock` decides a license directly too: the `license` field an entry embeds is used without a Packagist request, so an edited entry changes the verdict for that package. Review changes to `composer.lock` the same way.

## Report a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/shcherbak-ai/licenseal/security/advisories/new).
