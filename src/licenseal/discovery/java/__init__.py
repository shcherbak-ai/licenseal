"""Java/JVM ecosystem discovery (Maven + Gradle).

Two build systems share one ``Ecosystem.JAVA`` enum value because both
produce JVM artifacts pulled from the same registry (Maven Central). The
distinction matters only at discovery time:

* **Maven**: ``pom.xml`` is structured XML with author-declared license
  metadata in ``<licenses>`` — the canonical Java/JVM license path. Multi-
  module Maven projects use ``<modules>`` + ``<parent>`` linkage; each
  submodule has its own ``pom.xml``. Parsed by :mod:`.pom_xml`.

* **Gradle**: two manifest formats — Groovy ``build.gradle`` and Kotlin
  ``build.gradle.kts``. Both declare dependencies in a ``dependencies {…}``
  block that is *code*, not data. We text-parse the static-string form
  heuristically (manifest-only, like other lightweight scanners);
  dynamic-version computations inside ``if``/``when``/variable
  interpolation are not visible. Multi-
  project Gradle builds use ``settings.gradle[.kts]`` ``include`` directives.
  Parsed by :mod:`.build_gradle`.

* **Gradle lockfile**: ``gradle.lockfile`` is a real lockfile — line-based
  ``group:artifact:version=classpath1,classpath2``. When present, the
  lockfile supersedes the heuristic manifest parse. Parsed by
  :mod:`.gradle_lockfile`.

No native Maven lockfile exists; Maven projects rely on registry / deps.dev
resolution at the transitive walker for their pinned-version closure.
"""

from __future__ import annotations

from licenseal.discovery.java.build_gradle import (
    discover_build_gradle_dependencies,
)
from licenseal.discovery.java.gradle_lockfile import (
    find_gradle_lockfiles,
    parse_gradle_lockfile,
)
from licenseal.discovery.java.pom_xml import (
    detect_project_license_pom_xml,
    discover_pom_xml_dependencies,
)

__all__ = [
    "detect_project_license_pom_xml",
    "discover_build_gradle_dependencies",
    "discover_pom_xml_dependencies",
    "find_gradle_lockfiles",
    "parse_gradle_lockfile",
]
