---
title: "How a scan works"
description: "The four steps of a licenseal scan: read the manifests and lockfiles, resolve the dependency tree, classify each license, and report a verdict."
---

# How a scan works

<figure markdown>
![How licenseal works, in four steps. Read: manifests and lockfiles. Resolve: the whole dependency tree. Classify: each license against yours. Report: a verdict CI can gate on. No dependency installs, no builds, no package downloads.](../assets/licenseal-how-it-works.svg)
</figure>

1. **Read.** licenseal finds the manifests and lockfiles under the scanned directory: see [What is scanned](discovery.md). The files it reads are listed for each [ecosystem](../ecosystems/index.md). It runs no package manager.
2. **Resolve.** A lockfile gives the dependency tree as it is installed. Where no lockfile covers a dependency, licenseal walks the registry and marks the versions it picks as estimates. See [Dependency resolution](dependency-resolution.md) and [Versions and estimates](version-resolution.md). A dependency that comes from a git repository, a URL, or a path is an [off-registry dependency](off-registry.md).
3. **Classify.** A package's license is read from public registry metadata, or from `composer.lock` for a locked PHP package. It is read as a [license expression](license-expressions.md), given a risk level, and compared with the [project license](project-license.md). See [How licenseal decides](verdicts.md).
4. **Report.** The result is a table, a Markdown file, or JSON, and an exit code that CI can gate on. See [What fails a check](check-failures.md).

Nothing is installed or built, and no package archive is downloaded. Every host that is contacted is listed under [Network egress](../security/network.md), and what is sent to it under [What leaves the process](../security/data-sent.md).
