"""Parse Gradle lockfiles (``gradle.lockfile``).

A Gradle lockfile is the precise pinned-version snapshot of every dep
resolved across every classpath configuration. When present (the project
opted into Gradle dependency locking), it's the source of truth — no
heuristic ``build.gradle`` parsing needed.

Format is line-based:

.. code-block::

    # This is a Gradle generated file for dependency locking.
    com.example:some-lib:1.2.3=compileClasspath,runtimeClasspath
    com.example:other-lib:1.2.3=compileClasspath,runtimeClasspath
    com.example:test-lib:4.13.2=testCompileClasspath,testRuntimeClasspath
    empty=annotationProcessor

The ``=<classpath-list>`` suffix tells us which classpaths the dep belongs
to. Mapping rule:

* Any non-test classpath in the list → PROD (the dep ships)
* Only test/check classpaths → DEV (test-only, doesn't ship)

The ``empty=<classpath>`` form appears when Gradle records that a
classpath was resolved but contained no deps — informational, no deps to
emit; skip silently.

Group attribution is *direct from the classpath list*, not reachability-
based. Gradle lockfiles carry no edge information (just resolved versions
and classpath membership), so ``direct_ancestors`` is left empty — same
posture as ``Pipfile.lock`` in the Python ecosystem.

Multi-project Gradle builds can ship one lockfile per subproject (or a
single root lockfile in newer Gradle versions). :func:`find_gradle_lockfiles`
walks for any of them.
"""

from __future__ import annotations

from pathlib import Path

from licenseal.discovery._read import decode_text
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# Classpath suffixes that indicate test/check scope. A dep that appears
# ONLY in these classpaths is DEV; any classpath outside this set (i.e.
# any production classpath) flips it to PROD. Conservative:
# ``annotationProcessor`` and ``kapt`` are PROD (they ship code-generated
# output into the main artifact).
_TEST_CLASSPATHS = frozenset(
    {
        "testCompileClasspath",
        "testRuntimeClasspath",
        "androidTestCompileClasspath",
        "androidTestRuntimeClasspath",
        "checkstyle",
        "spotbugs",
        "pmd",
        "jacocoAgent",
        "jacocoAnt",
        "detekt",
    }
)


def find_gradle_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return paths to every ``gradle.lockfile`` in the project tree."""
    return list(walk_project_files(project_path, "gradle.lockfile", exclude_paths=exclude_paths))


def parse_gradle_lockfile(
    path: Path,
    *,
    prod_root_names: set[str] | None = None,  # noqa: ARG001 (parity with other lockfile parsers)
    dev_root_names: set[str] | None = None,  # noqa: ARG001
    include_dev: bool = True,
) -> list[Dependency]:
    """Parse a single ``gradle.lockfile`` into ``Dependency`` entries.

    Returns deduped deps (one entry per ``groupId:artifactId@version``
    combination). Group is derived directly from the classpath suffix list
    — see module docstring.

    The ``prod_root_names`` / ``dev_root_names`` arguments are accepted for
    signature parity with the other ecosystems' lockfile parsers (which
    use them for reachability-based attribution). Gradle lockfiles carry
    no edges, so attribution is direct from the classpath suffix; these
    parameters are unused here. ``include_dev`` is honored: when False,
    pure-DEV deps are dropped from the output.
    """
    text = decode_text(path)
    if text is None:
        return []

    seen: dict[tuple[str, str], DependencyGroup] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Gradle records empty classpaths as ``empty=<classpath>`` — no dep.
        if line.startswith("empty="):
            continue
        if "=" not in line:
            continue
        coord, _, classpath_list = line.partition("=")
        coord = coord.strip()
        classpaths = {c.strip() for c in classpath_list.split(",") if c.strip()}
        if not classpaths:
            continue
        parts = coord.split(":")
        if len(parts) != 3:
            # Malformed line (lockfile vandalism, lockfile from a future
            # Gradle version with a different schema, etc.). Skip without
            # crashing — same defensive posture as the other lockfile
            # parsers.
            continue
        group_id, artifact_id, version = parts
        name = f"{group_id}:{artifact_id}"
        # If *every* classpath this dep appears in is a test/check
        # classpath, it's DEV. Otherwise PROD (any production classpath
        # promotes the dep to shipped).
        if classpaths.issubset(_TEST_CLASSPATHS):
            group = DependencyGroup.DEV
        else:
            group = DependencyGroup.PROD
        key = (name, version)
        # If the same dep appears multiple times (e.g. once per subproject
        # in a multi-project lockfile), promote to PROD if any sighting is
        # PROD — same reachability-style "PROD wins" rule used elsewhere.
        if key in seen and seen[key] == DependencyGroup.PROD:
            continue
        seen[key] = group

    out: list[Dependency] = []
    for (name, version), group in seen.items():
        if group == DependencyGroup.DEV and not include_dev:
            continue
        out.append(
            Dependency(
                name=name,
                version_constraint=f"=={version}",
                ecosystem=Ecosystem.JAVA,
                group=group,
            )
        )
    return out
