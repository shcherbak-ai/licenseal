"""Gemfile.lock parser.

Bundler's lockfile is a fully-static plain-text format with a well-defined
2/4/6-space indent contract that downstream dependency scanners all
parse identically. We mirror that grammar.

Top-level shape::

    GIT
      remote: <url>
      revision: <sha>
      specs:
        <name> (<version>)
          <child> (<constraint>)

    GEM
      remote: <url>
      specs:
        <name> (<version>[-<platform>])
          <child> (<constraint>)

    PATH
      remote: <relative-path>
      specs:
        <name> (<version>)

    DEPENDENCIES
      <name>[!]
      <name> (<constraint>)[!]

    PLATFORMS
      <platform>

    RUBY VERSION
    BUNDLED WITH
    CHECKSUMS

The ``!`` suffix on a DEPENDENCIES line means "pinned to a non-rubygems
source" (GIT/PATH); the resolved spec lives in its corresponding source
section. Platform-suffixed versions (``nokogiri (1.16.0-x86_64-linux)``)
canonicalize to the base version.

A GIT or PLUGIN SOURCE spec, and a PATH spec outside the scanned directory,
is not a rubygems.org gem: it is emitted with an ``origin`` (``remote`` plus
``revision`` for GIT, the path for PATH) and is never looked up. A PATH spec
inside the scanned directory is the project's own code: it stays in the edge
graph and gets no row.

Group attribution is the load-bearing reason for the ``dev_direct_names``
parameter. ``Gemfile.lock`` carries no dev/prod marker; the Gemfile-discovered
dev-name set is used as the DEV-root for reverse-BFS through the edge graph.
A dep reachable from any PROD root becomes PROD; otherwise from a DEV root
becomes DEV; otherwise (orphan) PROD by conservative default — matches the
posture used elsewhere for orphan attribution.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from licenseal._graph import compute_direct_ancestors
from licenseal.discovery._origin import UNRECORDED, git_origin, path_origin, url_origin
from licenseal.discovery._read import decode_lockfile_text, record_unread_entries
from licenseal.discovery._walk import walk_project_files
from licenseal.models import Dependency, DependencyGroup, Ecosystem

# RubyGems platform suffixes we recognize on lockfile spec lines. The
# Bundler regex strips ``-platform`` from ``version-platform`` so a spec
# like ``nokogiri (1.16.0-x86_64-linux)`` becomes name=nokogiri,
# version=1.16.0, platform=x86_64-linux. We discard the platform.
# A version segment cannot contain ``-`` per RubyGems version grammar,
# so the first ``-`` (if present) introduces the platform.


def find_gemfile_lockfiles(
    project_path: Path,
    *,
    exclude_paths: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Return every Gemfile.lock in the project tree.

    Monorepos sometimes ship multiple lockfiles (per-app Gemfile.lock plus
    the root one); walk the full tree.
    """
    return walk_project_files(project_path, "Gemfile.lock", exclude_paths=exclude_paths)


def _split_version_and_platform(token: str) -> tuple[str, str]:
    """Split ``1.16.0-x86_64-linux`` → (``1.16.0``, ``x86_64-linux``).

    A RubyGems version segment is ``[0-9]+(?:\\.[0-9]+)*(?:\\.?[a-z0-9]+)*``
    plus optional pre-release tags. The first ``-`` that separates the
    version from a platform suffix is the boundary. If there's no ``-``,
    the token is the version with empty platform.
    """
    if "-" not in token:
        return token, ""
    head, _, tail = token.partition("-")
    return head, tail


def _is_section_header(line: str) -> bool:
    """A section header starts at column 0, is all-uppercase / spaces."""
    if not line or line[0] in " \t":
        return False
    stripped = line.rstrip()
    return stripped == stripped.upper() and bool(stripped)


def _indent_level(line: str) -> int:
    """Return leading-space count of ``line``."""
    n = 0
    for ch in line:
        if ch == " ":
            n += 1
        else:
            break
    return n


def _section_origin(
    section: str, options: dict[str, str], lock_dir: Path, scan_root: Path
) -> str | None:
    """Origin of the specs of one source section; ``None`` for the project's own code.

    ``options`` holds the section's ``key: value`` lines (``remote``,
    ``revision``, ...). GEM specs are registry gems and have no origin.
    """
    if section == "GEM":
        return ""
    remote = options.get("remote", "")
    if not remote:
        return UNRECORDED
    if section == "GIT" or "revision" in options:
        return git_origin(remote, options.get("revision", ""))
    if section == "PATH" or "://" not in remote:
        return path_origin(remote, lock_dir, scan_root)
    return url_origin(remote)


def parse_gemfile_lock(
    path: Path,
    *,
    direct_names: set[str],
    dev_direct_names: set[str],
    include_dev: bool,
    scan_root: Path | None = None,
) -> list[Dependency]:
    """Parse ``Gemfile.lock`` into a list of Dependencies.

    ``direct_names`` is the lowercased set of gem names declared at the
    top level of any Gemfile in the project. Used to mark entries as
    depth=0 vs depth=1 and as roots for direct-ancestor attribution.

    ``dev_direct_names`` is the lowercased subset of ``direct_names``
    declared only in dev groups (``:development``, ``:test``). Used to
    attribute group via reverse-BFS through the edge graph.

    With ``include_dev=False``, DEV-attributed entries are filtered out
    (mirrors the PHP / Python posture).

    ``scan_root`` is the scanned directory, the lockfile's own directory when
    omitted. A PATH spec that resolves inside it gets no row.
    """
    text = decode_lockfile_text(path)
    if text is None:
        return []
    scan_root = scan_root or path.parent

    # Spec metadata: name_lower -> (name_orig, version, origin). The origin
    # is empty for a registry gem and None for a PATH spec of this project.
    spec_info: dict[str, tuple[str, str, str | None]] = {}
    # Edges: name_lower -> set of child name_lower.
    edges: dict[str, set[str]] = {}

    section: str = ""
    options: dict[str, str] = {}
    in_specs = False
    current_spec: str | None = None  # name_lower of the most recent 4-space spec
    # Lines where the lockfile names a gem: inside a ``specs:`` block, or
    # under DEPENDENCIES. A lockfile that has some and yields no spec was
    # not read.
    entries = 0

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            in_specs = False
            current_spec = None
            continue

        if _is_section_header(line):
            section = line.strip()
            options = {}
            in_specs = False
            current_spec = None
            continue

        if section in ("GEM", "GIT", "PATH", "PLUGIN SOURCE"):
            stripped = line.strip()
            if stripped == "specs:":
                in_specs = True
                current_spec = None
                continue
            if not in_specs:
                # Source-options lines (``remote:``, ``revision:``, ...).
                key, _, value = stripped.partition(":")
                options[key.strip()] = value.strip()
                continue
            entries += 1
            indent = _indent_level(line)
            content = stripped
            if indent == 4:
                # ``<name> (<version>[-<platform>])`` — a top-level spec
                # node in this source section.
                name, version = _parse_spec_line(content)
                if not name:
                    continue
                normalized = name.lower()
                origin = _section_origin(section, options, path.parent, scan_root)
                spec_info.setdefault(normalized, (name, version, origin))
                current_spec = normalized
                edges.setdefault(normalized, set())
            elif indent == 6 and current_spec is not None:
                # ``<child> (<constraint>)`` — edge from current_spec.
                child_name = _parse_dep_line(content)
                # pragma: no branch - 6-space lines always carry a name
                if child_name:  # pragma: no branch
                    edges[current_spec].add(child_name.lower())
            continue

        # ``DEPENDENCIES`` section: 2-space indent for each line, ``name``
        # or ``name (constraint)``, optional trailing ``!``. We don't
        # strictly need these entries — direct_names from the Gemfile is
        # the authoritative root set — but if direct_names is empty (no
        # Gemfile, library-only repo with just a gemspec), fall back here.
        if section == "DEPENDENCIES":
            entries += 1
            if _indent_level(line) == 2 and not direct_names:
                content = line.strip().rstrip("!").strip()
                child_name = _parse_dep_line(content)
                if child_name:  # pragma: no branch
                    direct_names = {*direct_names, child_name.lower()}

        # Other sections (PLATFORMS / RUBY VERSION / BUNDLED WITH / CHECKSUMS)
        # are informational — no per-line action needed.

    record_unread_entries(path, entries, len(spec_info))
    if not spec_info:
        return []

    # Attribute group via reverse-BFS. PROD roots first (a dep reachable
    # from any PROD root is PROD); then DEV roots; remainder defaults to PROD.
    name_case = {lower: orig for lower, (orig, _ver, _origin) in spec_info.items()}

    prod_root_names = direct_names - dev_direct_names
    dev_root_names = dev_direct_names & direct_names

    prod_reachable = _reachable(edges, prod_root_names)
    dev_reachable = _reachable(edges, dev_root_names) - prod_reachable

    # Ancestor attribution: BFS from each direct root through edges.
    roots_for_attribution = {n: name_case[n] for n in direct_names if n in name_case}
    ancestors = compute_direct_ancestors(edges, roots_for_attribution)

    out: list[Dependency] = []
    for normalized, (orig_name, version, origin) in spec_info.items():
        if origin is None:
            continue
        is_direct = normalized in direct_names
        if normalized in dev_reachable:
            group = DependencyGroup.DEV
        elif normalized in prod_reachable:
            group = DependencyGroup.PROD
        elif is_direct:  # pragma: no cover - direct deps are always reachable from their own root
            # Defensive fallback for a hypothetical direct dep that wasn't
            # placed in either reachable set. By construction every direct
            # name is in exactly one of prod_root_names or dev_root_names,
            # and `_reachable` includes the roots themselves, so this
            # branch is unreachable in practice.
            group = DependencyGroup.DEV if normalized in dev_root_names else DependencyGroup.PROD
        else:
            # Orphan transitive (no path from any root). Default to PROD —
            # conservative; matches Go's posture for proxy-fetch failures.
            group = DependencyGroup.PROD

        if group == DependencyGroup.DEV and not include_dev:
            continue

        version_constraint = f"=={version}" if version else ""
        dep = Dependency(
            name=orig_name,
            version_constraint=version_constraint,
            ecosystem=Ecosystem.RUBY,
            group=group,
            depth=0 if is_direct else 1,
            direct_ancestors=() if is_direct else ancestors.get(normalized, ()),
            origin=origin,
        )
        out.append(dep)
    return out


def _parse_spec_line(content: str) -> tuple[str, str]:
    """Parse a 4-space-indent spec line ``<name> (<version>[-<platform>])``.

    Returns ``("", "")`` on malformed input. Defensive against malformed
    Bundler output — real lockfiles always carry a name and parenthesized
    version on spec lines.
    """
    body = content.rstrip("!").rstrip()
    if not body:
        return "", ""
    if "(" not in body or ")" not in body:
        return body.strip(), ""
    name_part, _, rest = body.partition("(")
    version_part, _, _ = rest.partition(")")
    version, _platform = _split_version_and_platform(version_part.strip())
    return name_part.strip(), version


def _parse_dep_line(content: str) -> str:
    """Parse a 6-space-indent dep line ``<child> (<constraint>)``.

    Only the name is load-bearing for the edge graph; the constraint is
    discarded (the child's resolved version lives where it appears as its
    own 4-space spec). Defensive against missing parens / empty body.
    """
    body = content.strip().rstrip("!").rstrip()
    if not body:
        return ""
    if "(" not in body:
        return body
    name_part, _, _ = body.partition("(")
    return name_part.strip()


def _reachable(edges: dict[str, set[str]], roots: set[str]) -> set[str]:
    """Return every node reachable from any node in ``roots`` (BFS)."""
    if not roots:
        return set()
    reachable: set[str] = set(roots)
    front: set[str] = set(roots)
    while front:
        new_front: set[str] = set()
        for node in front:
            for child in edges.get(node, ()):
                if child in reachable:
                    continue
                reachable.add(child)
                new_front.add(child)
        front = new_front
    return reachable


def attach_direct_sources(
    deps: list[Dependency],
    direct_source_by_name: dict[str, str],
) -> list[Dependency]:
    """Stamp the discovery source path onto depth-0 lockfile-derived deps.

    Mirrors the PHP path: lockfile-parsed depth-0 entries get the matching
    Gemfile / gemspec source filename from discovery.
    """
    out: list[Dependency] = []
    for dep in deps:
        if dep.depth != 0:
            out.append(dep)
            continue
        source = direct_source_by_name.get(dep.name.lower(), "")
        if source:
            out.append(replace(dep, source=source))
        else:
            out.append(dep)
    return out
