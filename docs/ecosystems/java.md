---
title: "Java and the JVM"
description: "Java and the JVM: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# Java and the JVM

What licenseal reads in a Maven or Gradle build. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** Maven Central and [deps.dev](../security/license-sources.md); `dl.google.com` and `repo.jenkins-ci.org` as fallbacks
- **Manifests:** Maven `pom.xml`; Gradle `build.gradle`, `build.gradle.kts` (read as text)
- **Lockfiles:** `gradle.lockfile`

## What is read

- In a `pom.xml`: BOM imports and the `<dependencyManagement>` parent chain, including `${revision}`-style property inheritance, with and without `--no-transitive`, and the dependencies of every profile in `<profiles>`.
- In a Gradle build file, which is read as text: the static-string declarations of a `dependencies { … }` block.
- A Gradle coordinate declared without a version (a BOM or a plugin supplies it) is reported at the artifact's latest release, as an [estimate](../concepts/version-resolution.md#estimates), when no `gradle.lockfile` [covers](../concepts/dependency-resolution.md) it.
- An artifact that another module of the scanned build defines is not reported.

## Dev dependencies

Maven scopes `test`, `provided`, and `system` are dev; `compile` and `runtime` are production. Gradle goes by configuration name, and a declaration under a name in neither list is skipped:

- production: `implementation`, `api`, `compile`, `runtime`, `runtimeOnly`, `compileOnly`, `compileOnlyApi`, `compileClasspath`, `runtimeClasspath`, `providedCompile`, `providedRuntime`, `annotationProcessor`, `kapt`, `ksp`, `kaptTest`, `releaseImplementation`, `releaseApi`, `releaseRuntimeOnly`, `shadow`;
- dev: `testImplementation`, `testApi`, `testCompileOnly`, `testRuntimeOnly`, `testCompileClasspath`, `testRuntimeClasspath`, `androidTestImplementation`, `androidTestApi`, `androidTestCompileOnly`, `androidTestRuntimeOnly`, `testFixturesApi`, `testFixturesImplementation`, `debugImplementation`, `debugApi`, `debugRuntimeOnly`, `developmentOnly`, `checkstyle`, `spotbugs`, `pmd`, `detekt`, `jacocoAgent`, `jacocoAnt`.

## Off-registry dependencies

A Maven `system`-scoped dependency, which is a local JAR, is reported as an [off-registry dependency](../concepts/off-registry.md).

## Not evaluated

- Profile activation conditions.
- A parent chain or BOM nesting deeper than 5 levels.
- In a Gradle build file: version catalogs, variable interpolation, `platform(...)` references, and dynamic blocks.
- A Maven `system` scope that a `<dependencyManagement>` entry supplies is not read: see [What is not read](../concepts/off-registry.md#what-is-not-read).

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
