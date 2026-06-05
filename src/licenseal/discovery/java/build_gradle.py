"""Parse Gradle ``build.gradle`` / ``build.gradle.kts`` files for direct deps.

Gradle's manifest is *code* (Groovy or Kotlin), not data. A general parser
would need to evaluate the script — which is exactly the
arbitrary-code-execution surface licenseal refuses to incur. Instead we
text-parse the static-string dependency-declaration forms heuristically,
the manifest-only approach taken by several lightweight scanners.

Recognized declaration forms:

.. code-block:: gradle

    implementation 'com.example:some-lib:1.2.3'
    implementation("com.example:some-lib:1.2.3")
    implementation group: 'com.example', name: 'some-lib', version: '1.2.3'
    testImplementation 'com.example:test-lib:4.13.2'
    api libs.someLib                                  // version-catalog ref — NOT resolved
    implementation("com.example:some-lib:$libVersion")  // variable — NOT resolved

The first three forms are extracted faithfully. The last two are skipped:
version catalogs (``libs.…``) and variable interpolation (``$var``) would
require evaluating Gradle's full configuration phase, which is out of
scope. Projects that use these patterns should ship a ``gradle.lockfile``
— when present, the lockfile parser (:mod:`.gradle_lockfile`) supersedes
the heuristic and gives full coverage.

Configuration → ``DependencyGroup`` mapping (mirrors Maven scopes):

* ``implementation`` / ``api`` / ``compileOnly`` / ``runtimeOnly`` /
  ``annotationProcessor`` / ``kapt`` / ``ksp`` → PROD
* ``testImplementation`` / ``testRuntimeOnly`` / ``testCompileOnly`` /
  ``androidTestImplementation`` / ``checkstyle`` / ``spotbugs`` / ``pmd``
  / ``detekt`` → DEV

Multi-project Gradle builds use ``settings.gradle[.kts]`` ``include
'submodule'`` directives. Submodule artifact coordinates would normally
be filtered, but determining those coordinates without evaluating each
submodule's ``build.gradle`` is unreliable; the filter applies only to
artifact coordinates discoverable from in-tree pom.xml files (i.e.
mixed Maven+Gradle monorepos). For pure-Gradle monorepos, false-positive
cross-references are accepted — they'll surface as UNKNOWNs in the
report, which is the right signal for a heuristic discovery path.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files_matching
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Gradle build files come in two DSLs; both share the dependency-declaration
# syntax we care about.
_BUILD_GRADLE_NAMES: frozenset[str] = frozenset({"build.gradle", "build.gradle.kts"})

_DEV_CONFIGURATIONS = frozenset(
    {
        "testImplementation",
        "testApi",
        "testCompileOnly",
        "testRuntimeOnly",
        "testCompileClasspath",
        "testRuntimeClasspath",
        "androidTestImplementation",
        "androidTestApi",
        "androidTestCompileOnly",
        "androidTestRuntimeOnly",
        "checkstyle",
        "spotbugs",
        "pmd",
        "detekt",
        "jacocoAgent",
        "jacocoAnt",
    }
)

_PROD_CONFIGURATIONS = frozenset(
    {
        "implementation",
        "api",
        "compile",  # deprecated but still seen
        "runtime",  # deprecated but still seen
        "compileOnly",
        "runtimeOnly",
        "compileClasspath",
        "runtimeClasspath",
        "annotationProcessor",
        "kapt",
        "ksp",
        "kaptTest",  # debatable; treated PROD because Kotlin annotation processors
        "providedCompile",
        "providedRuntime",
    }
)

_KNOWN_CONFIGURATIONS = _DEV_CONFIGURATIONS | _PROD_CONFIGURATIONS

# Capture the four declaration shapes. The configuration name is the
# leading word; the dep coordinate(s) follow as either a single
# colon-separated string or as a Groovy-map argument list.
#
# Form 1 — single-string Groovy: ``configuration 'group:artifact:version'``
# Form 2 — single-string Kotlin: ``configuration("group:artifact:version")``
# Form 3 — Groovy map: ``configuration group: 'g', name: 'a', version: 'v'``
# Form 4 — Kotlin map: ``configuration(group = "g", name = "a", version = "v")``
#
# We use a single line-anchored regex that allows the configuration name
# to be followed by either an open-paren or whitespace then a string.
# Skip lines that obviously reference variables (``$``, ``libs.``,
# ``project(``, ``files(``, ``fileTree(``) — those aren't static strings.
_DEP_LINE_RE = re.compile(
    r"""
    ^[ \t]*
    (?P<config>[A-Za-z][A-Za-z0-9_]*)        # configuration name
    [ \t]*
    \(?                                      # optional opening paren (Kotlin)
    [ \t]*
    (?P<rest>.+?)                            # the rest of the line
    [ \t]*\)?                                # optional closing paren
    [ \t]*$
    """,
    re.VERBOSE,
)

# Single-string coordinate: ``"group:artifact:version"`` or ``'group:artifact:version'``.
# Allows colons inside the version (Maven classifier-style ``g:a:v:classifier``)
# — we still take the first three components. The version pattern excludes
# ``$`` so ``"g:a:$springVersion"`` is correctly skipped as a variable
# interpolation (the heuristic refuses to resolve those).
_COORD_STRING_RE = re.compile(
    r"""['"]
    (?P<group>[A-Za-z0-9_.\-]+)
    :
    (?P<artifact>[A-Za-z0-9_.\-]+)
    :
    (?P<version>[^:'"$]+?)
    (?::[^'"]*)?           # optional classifier suffix
    ['"]
    """,
    re.VERBOSE,
)

# Groovy / Kotlin map form: ``group: 'g', name: 'a', version: 'v'``
# or ``group = "g", name = "a", version = "v"``. We extract each piece
# by name to tolerate any argument order.
_MAP_KEY_RE = re.compile(
    r"""(?P<key>group|name|version)
        \s*[:=]\s*
        ['"](?P<value>[^'"]+)['"]
    """,
    re.VERBOSE,
)


def _config_to_group(config: str) -> DependencyGroup | None:
    """Map a Gradle configuration name to a DependencyGroup, or None if unknown.

    Unknown configurations (custom user-defined ones, plugin-defined ones
    like ``shadow``) return None and the line is skipped — we don't want to
    misclassify deps from configurations we don't recognize.
    """
    if config in _DEV_CONFIGURATIONS:
        return DependencyGroup.DEV
    if config in _PROD_CONFIGURATIONS:
        return DependencyGroup.PROD
    return None


def _extract_coord_from_rest(rest: str) -> tuple[str, str, str] | None:
    """Pull ``(groupId, artifactId, version)`` out of the rhs of a dep line.

    Recognizes either a single-string ``'g:a:v'`` form or a Groovy/Kotlin
    map form. Returns None when the rhs references a variable or method
    call instead of a literal coordinate (the heuristic's known blind
    spot).
    """
    # Reject obvious non-static patterns up front.
    if any(
        marker in rest
        for marker in ("project(", "files(", "fileTree(", "platform(", "enforcedPlatform(")
    ):
        return None
    # Variable interpolation or version-catalog reference — skip.
    # (We deliberately don't try to detect every variable shape; if
    # the regex below doesn't match a literal string, we return None
    # naturally.)

    coord_match = _COORD_STRING_RE.search(rest)
    if coord_match is not None:
        return (
            coord_match.group("group"),
            coord_match.group("artifact"),
            coord_match.group("version"),
        )

    map_matches = list(_MAP_KEY_RE.finditer(rest))
    if not map_matches:
        return None
    fields: dict[str, str] = {}
    for m in map_matches:
        fields[m.group("key")] = m.group("value")
    group = fields.get("group", "")
    artifact = fields.get("name", "")
    version = fields.get("version", "")
    if group and artifact:
        return (group, artifact, version)
    return None


def _parse_build_gradle(text: str) -> list[tuple[str, str, str, DependencyGroup]]:
    """Return ``(group, artifact, version, group_enum)`` tuples extracted from text.

    Heuristic line-based parse. Skips comments, ignores variable
    interpolation, and stops at lines that look like method calls into
    unsupported APIs (``project(...)``, ``platform(...)``, etc.).
    Duplicate-line tolerance: a single coord may be declared in multiple
    configurations; we emit one tuple per (config, coord) pair and let the
    caller dedupe by ``(name, version)`` with PROD-wins semantics.
    """
    out: list[tuple[str, str, str, DependencyGroup]] = []
    in_block_comment = False
    for raw_line in text.splitlines():
        line = raw_line
        # Strip block comments (``/* … */``) — naive single-line and
        # multi-line state machine. Doesn't handle nested or string-
        # embedded comment markers; heuristic, not authoritative.
        if in_block_comment:
            end_idx = line.find("*/")
            if end_idx < 0:
                continue
            line = line[end_idx + 2 :]
            in_block_comment = False
        start_idx = line.find("/*")
        if start_idx >= 0:
            end_idx = line.find("*/", start_idx + 2)
            if end_idx < 0:
                # Block comment open without close on this line — discard
                # everything from the marker onward and flag the state.
                line = line[:start_idx]
                in_block_comment = True
            else:
                line = line[:start_idx] + line[end_idx + 2 :]
        # Strip line comments (``// …``). Done after block-comment handling
        # so a ``//`` inside a `/* */` doesn't false-trigger.
        line_comment_idx = line.find("//")
        if line_comment_idx >= 0:
            line = line[:line_comment_idx]
        if not line.strip():
            continue
        match = _DEP_LINE_RE.match(line)
        if match is None:
            continue
        config = match.group("config")
        rest = match.group("rest")
        if config not in _KNOWN_CONFIGURATIONS:
            continue
        # _KNOWN_CONFIGURATIONS is the union of _PROD ∪ _DEV, so
        # ``_config_to_group`` is guaranteed non-None here.
        group = _config_to_group(config)
        assert group is not None
        coord = _extract_coord_from_rest(rest)
        if coord is None:
            continue
        out.append((coord[0], coord[1], coord[2], group))
    return out


def discover_build_gradle_dependencies(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> tuple[list[Dependency], int]:
    """Discover direct Gradle dependencies from every ``build.gradle[.kts]`` in the tree.

    Returns ``(deps, filtered_count)`` for parity with the other discovery
    functions. The filtered count is always 0 for Gradle (we don't apply a
    workspace-local filter on Gradle's side — see module docstring for why);
    the field stays in the signature for consistency.

    Dedup rule: if the same ``(groupId:artifactId, version)`` appears via
    multiple configurations (e.g. once as ``api`` and once as
    ``testImplementation``), the PROD attribution wins. Same posture as the
    Gradle lockfile parser's multi-classpath dedup.
    """
    seen: dict[tuple[str, str], tuple[DependencyGroup, str]] = {}
    for build_path in walk_project_files_matching(
        project_path, _BUILD_GRADLE_NAMES.__contains__, exclude_paths=exclude_paths
    ):
        text = decode_text(build_path)
        if text is None:
            continue
        source = build_path.relative_to(project_path).as_posix()
        for group_id, artifact_id, version, group_enum in _parse_build_gradle(text):
            name = f"{group_id}:{artifact_id}"
            key = (name, version)
            existing = seen.get(key)
            if existing is None or (
                existing[0] == DependencyGroup.DEV and group_enum == DependencyGroup.PROD
            ):
                seen[key] = (group_enum, source)

    out: list[Dependency] = []
    for (name, version), (group_enum, source) in seen.items():
        out.append(
            Dependency(
                name=name,
                version_constraint=version,
                ecosystem=Ecosystem.JAVA,
                group=group_enum,
                source=source,
            )
        )
    return out, 0
