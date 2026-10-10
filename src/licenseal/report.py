"""Report generation for license analysis."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import replace
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import quote, urlsplit

from rich.console import Console
from rich.markup import escape as _escape_markup
from rich.style import Style
from rich.table import Table
from rich.text import Text

from licenseal.analysis.risk import (
    KNOWN_SPDX_IDS,
    _split_top_level,
    _strip_outer_parens,
    classify_risk,
)
from licenseal.models import (
    AnalysisReport,
    CompatibilityResult,
    CompatibilityVerdict,
    Ecosystem,
    ReportDiagnostic,
    RiskLevel,
)

_SPDX_OPERATORS = {"AND", "OR", "WITH"}

_LINE_BREAKS_AND_TABS = re.compile(r"\r\n|[\n\r\t]")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MARKDOWN_SPECIALS = re.compile(r"[\\`\[\]<>|]")


def _printable(value: str) -> str:
    """Make a registry- or manifest-derived string safe to print.

    Names, versions, license strings, reasons and paths come from registries
    and scanned files. A C0 or C1 control character in one (an escape sequence,
    a carriage return) would otherwise act on the terminal or on whatever
    displays a saved report. Line breaks and tabs become a space; every other
    control character is shown as a ``\\xNN`` escape.

    Presentation only: the data model and the JSON report keep the original
    string, so a dependency's identity is never rewritten.
    """
    value = _LINE_BREAKS_AND_TABS.sub(" ", value)
    return _CONTROL_CHARS.sub(lambda match: f"\\x{ord(match.group()):02x}", value)


def _escape_md(value: str) -> str:
    """Escape a string for a Markdown table cell, link label, or list item.

    Backslash-escapes what would end the cell (``|``) or start markup the
    string must not introduce: a link or an image (``[``, ``]``), a code span
    (a backtick), raw HTML or an autolink (``<``, ``>``), and the backslash
    itself. Parentheses only act as link syntax directly after a closing
    bracket, which is escaped, so they are left alone.
    """
    return _MARKDOWN_SPECIALS.sub(r"\\\g<0>", _printable(value))


def _rich_escape(value: str) -> str:
    """Escape a string for interpolation into Rich console markup."""
    return _escape_markup(_printable(value))


def _url_quote(value: str) -> str:
    """Percent-encode a name, version, or path for use inside a URL.

    ``/``, ``@`` and ``+`` stay literal: scoped package names, module paths and
    versions with build metadata are written with them in registry URLs, so
    the URL of a well-formed name is unchanged. Everything else outside the
    unreserved set is encoded, so a name cannot add a query or fragment, close
    a Markdown link target or a console markup tag, or carry control characters
    into a link.
    """
    return quote(value, safe="/@+")


def _license_url(license_id: str) -> str:
    """Return the canonical SPDX license page URL, or empty string.

    The URL is only emitted when the license_id corresponds to a real SPDX
    license that has a page on spdx.org/licenses. We validate against the
    vendored canonical ID list so wrong-cased or invented strings (which
    would 404) produce no link rather than a broken one. The SPDX
    "or-later" suffix ``+`` is stripped — SPDX serves one page per base ID.

    Compound SPDX expressions (``OR`` / ``AND`` / ``WITH`` / parens) resolve
    to a single representative leaf: for ``OR`` the lowest-risk (most
    permissive) component, for ``AND`` the highest-risk (most restrictive),
    for ``WITH`` the base license. Agents that need the full expression can
    re-parse ``license_raw``.
    """
    direct = _spdx_canonical_url(license_id)
    if direct:
        return direct
    if not license_id or (" " not in license_id and "(" not in license_id):
        return ""
    leaf = _pick_url_leaf(license_id)
    return _spdx_canonical_url(leaf)


def _spdx_canonical_url(license_id: str) -> str:
    """URL for a single, simple SPDX ID; empty for compound or junk inputs."""
    if (
        not license_id
        or license_id in {"UNKNOWN", "NOASSERTION", "Proprietary"}
        or license_id in _SPDX_OPERATORS
        or license_id.startswith("LicenseRef-")
        or " " in license_id
        or "(" in license_id
        or ")" in license_id
    ):
        return ""
    base = license_id.rstrip("+")
    if base not in KNOWN_SPDX_IDS:
        return ""
    return f"https://spdx.org/licenses/{base}.html"


def _pick_url_leaf(expr: str) -> str:
    """Pick a representative SPDX leaf from a compound expression.

    Mirrors ``classify_risk``'s expression parser: strip outer parens, then
    split on the lowest-precedence operator (OR), then AND, then WITH.
    Returns "" only when no component resolves to a known SPDX ID.
    """
    expr = expr.strip()
    if not expr:
        return ""

    unwrapped = _strip_outer_parens(expr)
    if unwrapped != expr:
        return _pick_url_leaf(unwrapped)

    or_parts = _split_top_level(expr, " OR ")
    if len(or_parts) > 1:
        return _pick_from_parts(or_parts, prefer_lower=True)

    and_parts = _split_top_level(expr, " AND ")
    if len(and_parts) > 1:
        return _pick_from_parts(and_parts, prefer_lower=False)

    if " WITH " in expr:
        return _pick_url_leaf(expr.split(" WITH ", 1)[0])

    return expr


def _pick_from_parts(parts: list[str], *, prefer_lower: bool) -> str:
    """Pick the lowest- or highest-risk component that resolves to a URL."""
    candidates: list[tuple[str, int]] = []
    for part in parts:
        leaf = _pick_url_leaf(part)
        if not _spdx_canonical_url(leaf):
            continue
        risk = classify_risk(leaf)
        if risk == RiskLevel.UNKNOWN:
            continue
        candidates.append((leaf, risk.severity))
    if not candidates:
        return ""
    picker = min if prefer_lower else max
    return picker(candidates, key=lambda pair: pair[1])[0]


def _license_tokens(license_id: str) -> list[str]:
    """Split an SPDX expression into linkable tokens and operators."""
    if not license_id:
        return []
    return license_id.split()


def _package_url(result: CompatibilityResult) -> str:
    """Return the registry page for the resolved package.

    The name and version are percent-encoded (see :func:`_url_quote`), so the
    result is a well-formed URL on the registry's host whatever the name holds.
    """
    dep = result.license_info.dependency
    name = _url_quote(dep.name)
    version = _url_quote(result.license_info.resolved_version)
    if dep.ecosystem == Ecosystem.PYTHON:
        return f"https://pypi.org/project/{name}/"
    if dep.ecosystem == Ecosystem.RUST:
        return f"https://crates.io/crates/{name}"
    if dep.ecosystem == Ecosystem.GO:
        # ``name`` is the full module path (e.g. ``github.com/foo/bar``);
        # pkg.go.dev's URL convention is ``pkg.go.dev/{module_path}``.
        suffix = f"@{version}" if version else ""
        return f"https://pkg.go.dev/{name}{suffix}"
    if dep.ecosystem == Ecosystem.JAVA:
        # Sonatype Central is the canonical human-facing UI for Maven
        # Central artifacts. Coord is ``groupId:artifactId``; the URL
        # path uses ``/`` between group and artifact. Resolved version
        # is appended when known so users land on the exact version
        # licenseal scanned.
        group_id, _, artifact_id = dep.name.partition(":")
        if not group_id or not artifact_id:
            return ""
        suffix = f"/{version}" if version else ""
        return (
            "https://central.sonatype.com/artifact/"
            f"{_url_quote(group_id)}/{_url_quote(artifact_id)}{suffix}"
        )
    if dep.ecosystem == Ecosystem.DOTNET:
        # NuGet.org is the canonical .NET package UI. Package ID is flat
        # (no group separator); resolved version is appended via ``/``.
        suffix = f"/{version}" if version else ""
        return f"https://www.nuget.org/packages/{name}{suffix}"
    if dep.ecosystem == Ecosystem.PHP:
        # Packagist is the canonical Composer / PHP package UI.
        # Package ID is the ``vendor/package`` form (already lowercase).
        # Packagist's web URL uses the same path layout as the metadata
        # endpoint, minus the ``/p2`` prefix and ``.json`` suffix.
        return f"https://packagist.org/packages/{name}"
    if dep.ecosystem == Ecosystem.RUBY:
        # rubygems.org is the canonical Ruby gem UI. Names are case-
        # sensitive and used verbatim. Resolved version is appended via
        # ``/versions/{version}`` so users land on the exact version
        # licenseal scanned.
        suffix = f"/versions/{version}" if version else ""
        return f"https://rubygems.org/gems/{name}{suffix}"
    if dep.ecosystem == Ecosystem.HEX:
        # hex.pm is the canonical Hex (Elixir / Erlang) package UI. Names are
        # lowercase; the resolved version is appended via ``/{version}`` so
        # users land on the exact version licenseal scanned. A `hex:`-renamed
        # dep links to its real hex.pm package, not the local app-name alias.
        suffix = f"/{version}" if version else ""
        return f"https://hex.pm/packages/{_url_quote(dep.effective_registry_name)}{suffix}"
    if dep.ecosystem == Ecosystem.R:
        # CRAN's canonical package page. CRAN serves only the current version's
        # page (no per-version web URL), so no version suffix is appended.
        return f"https://cran.r-project.org/package={name}"
    return f"https://www.npmjs.com/package/{name}"


def _license_file_hint_url(repository_url: str) -> str:
    """Heuristic URL where the dep's LICENSE file likely lives.

    Registry APIs don't expose the bundled LICENSE file directly, so we
    construct the conventional path for hosts whose URL shape we know:

    * GitHub          → ``{repo}/blob/HEAD/LICENSE``
    * GitLab          → ``{repo}/-/blob/HEAD/LICENSE``
    * BitBucket Cloud → ``{repo}/src/HEAD/LICENSE``
    * Codeberg        → ``{repo}/src/branch/HEAD/LICENSE``

    ``HEAD`` is a server-side alias for the default branch on all four hosts
    (Codeberg follows Gitea/Forgejo's ``/src/branch/{ref}`` convention; the
    others use a flat ``HEAD`` slot), so callers don't need to know whether
    the branch is ``main`` or ``master``. Self-hosted GitLab / Gitea /
    Forgejo / BitBucket Server instances aren't matched — their hostnames
    are unknown to us — and fall back to the bare URL. Empty repository
    URL yields empty.
    """
    if not repository_url:
        return ""
    stripped = repository_url.rstrip("/")
    parsed = urlsplit(stripped)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"}:
        return stripped
    if host == "github.com":
        return f"{stripped}/blob/HEAD/LICENSE"
    if host == "gitlab.com":
        return f"{stripped}/-/blob/HEAD/LICENSE"
    if host == "bitbucket.org":
        return f"{stripped}/src/HEAD/LICENSE"
    if host == "codeberg.org":
        return f"{stripped}/src/branch/HEAD/LICENSE"
    return stripped


def _actionability(
    result: CompatibilityResult,
    *,
    license_url: str,
    repository_url: str,
    homepage_url: str,
    package_url: str,
) -> dict[str, Any] | None:
    """Build the per-dep actionability block for flagged deps.

    Returns ``None`` for compatible verdicts (keeps the JSON compact). For
    flagged deps emits ``investigate_url`` (the best single URL for an agent,
    falling through license → repo → homepage → package) plus
    ``next_steps``, a verdict-aware action list that only mentions URLs that
    are actually populated. When a repository URL is present, the relevant
    next_step embeds a license-file hint URL (see
    :func:`_license_file_hint_url`) so the agent has a concrete starting
    point rather than the repo root.
    """
    if result.verdict == CompatibilityVerdict.COMPATIBLE:
        return None
    investigate_url = license_url or repository_url or homepage_url or package_url
    steps: list[str] = []
    verdict = result.verdict
    license_id = result.license_info.effective_license_id or "the detected license"
    code_url = repository_url or homepage_url
    file_hint = _license_file_hint_url(code_url)
    if verdict == CompatibilityVerdict.UNKNOWN:
        if file_hint:
            steps.append(f"Inspect LICENSE file at {file_hint}")
        steps.append("Resolve dependency license manually; current detection found none")
    elif verdict == CompatibilityVerdict.WARNING:
        if license_url:
            steps.append(f"Verify license terms at {license_url}")
        if file_hint:
            steps.append(f"Confirm license text at {file_hint}")
        steps.append("Decide whether the license is acceptable for the project's context")
    else:
        steps.append(f"{license_id} is incompatible with the project license")
        if code_url:
            steps.append(f"Check newer versions or relicensing notes at {code_url}")
        steps.append(f"Consult registry at {package_url} for alternatives")
    return {"investigate_url": investigate_url, "next_steps": steps}


def _source_url(result: CompatibilityResult) -> str:
    """Return the manifest file path as a project-relative URL.

    Empty when the result has no source recorded — typically transitives, which
    aren't declared in any manifest. Markdown renderers turn the path into a
    relative link (clickable on GitHub PRs); JSON consumers can use it the same
    way.
    """
    return result.license_info.dependency.source


def _source_terminal_url(result: CompatibilityResult, project_path: Path | None) -> str:
    """Return an absolute `file://` URL for the source manifest.

    Empty when the result has no source or the caller didn't supply a
    `project_path`. Modern terminals (Windows Terminal, iTerm2, WezTerm) render
    `file://` links in OSC-8 hyperlinks as clickable.
    """
    src = result.license_info.dependency.source
    if not src or project_path is None:
        return ""
    return (project_path / src).resolve().as_uri()


def _package_label(result: CompatibilityResult) -> str:
    """Render the package label with the resolved version when available."""
    name = result.license_info.dependency.name
    resolved_version = result.license_info.resolved_version
    if not resolved_version:
        return name
    return f"{name} ({resolved_version})"


def _rich_link(label: str, url: str) -> Text:
    """Render a rich hyperlink when a URL is available.

    Built as ``Text`` with a link style, not as markup: neither the label nor
    the URL is parsed for console markup tags, so a ``[`` in a dependency name
    is just a character.
    """
    return Text(_printable(label), style=Style(link=url) if url else "")


def _markdown_link(label: str, url: str) -> str:
    """Render a markdown link when a URL is available.

    ``url`` must already be percent-encoded (see :func:`_url_quote`): a space
    or an unbalanced parenthesis in it would end the link target early.
    """
    escaped = _escape_md(label)
    if not url:
        return escaped
    return f"[{escaped}]({url})"


def _markdown_row(values: list[str]) -> str:
    """Render a compact markdown table row."""
    return f"|{'|'.join(values)}|"


def _rich_license_label(license_id: str) -> Text:
    """Render a license string with links for individual SPDX identifiers."""
    return Text(" ").join(
        _rich_link(token, _license_url(token)) for token in _license_tokens(license_id)
    )


def _markdown_license_label(license_id: str) -> str:
    """Render a license string with links for individual SPDX identifiers."""
    parts = []
    for token in _license_tokens(license_id):
        parts.append(_markdown_link(token, _license_url(token)))
    return " ".join(parts)


def _format_elapsed(seconds: float) -> str:
    """Format elapsed time for human-readable output."""
    return f"{seconds:.2f}s"


def _row_order(result: CompatibilityResult) -> tuple[str, str]:
    """Sort key for report rows: ecosystem, then case-insensitive name."""
    dep = result.license_info.dependency
    return (dep.ecosystem.value, dep.name.lower())


def _sorted_results(results: list[CompatibilityResult]) -> list[CompatibilityResult]:
    """Sort results alphabetically by ecosystem then name.

    Severity-driven visibility is provided by the Details section, which lists
    every non-compatible result with its reason; alphabetical ordering of the
    main table makes large transitive reports scannable.
    """
    return sorted(results, key=_row_order)


_VERDICT_ICONS = {
    CompatibilityVerdict.COMPATIBLE: "[green]\u2713[/green]",
    CompatibilityVerdict.WARNING: "[yellow]\u26a0[/yellow]",
    CompatibilityVerdict.INCOMPATIBLE: "[red]\u2717[/red]",
    CompatibilityVerdict.UNKNOWN: "[dim]?[/dim]",
}

_VERDICT_MD_ICONS = {
    CompatibilityVerdict.COMPATIBLE: "\u2713",
    CompatibilityVerdict.WARNING: "\u26a0",
    CompatibilityVerdict.INCOMPATIBLE: "\u2717",
    CompatibilityVerdict.UNKNOWN: "?",
}
_REPORT_NOTE = "Generated by licenseal check. Versions shown are the resolved releases checked."


def _risk_style(result: CompatibilityResult) -> str:
    risk = result.risk_level.value
    if result.verdict == CompatibilityVerdict.COMPATIBLE:
        return f"[green]{risk}[/green]"
    if result.verdict == CompatibilityVerdict.WARNING:
        return f"[yellow]{risk}[/yellow]"
    if result.verdict == CompatibilityVerdict.INCOMPATIBLE:
        return f"[red]{risk}[/red]"
    return f"[dim]{risk}[/dim]"


def _reviewed_results(results: list[CompatibilityResult]) -> list[CompatibilityResult]:
    """Return only reviewed results, preserving report sort order."""
    return [result for result in results if result.license_info.reviewed]


def _detected_license_label(result: CompatibilityResult) -> str:
    """Render the originally detected license with raw metadata when useful."""
    license_info = result.license_info
    detected = license_info.detected_license_id
    if license_info.license_raw and license_info.license_raw not in {"", detected}:
        return f"{detected} (raw: {license_info.license_raw})"
    return detected


_TRANSITIVE_PREFIX = "  └─ "

# ASCII stand-ins for the glyphs the report draws: the verdict icons and the
# tree branch of ``_TRANSITIVE_PREFIX``.
_ASCII_GLYPHS = {"✓": "OK", "⚠": "!", "✗": "X", "└": "+", "─": "-"}

# Below this width a terminal has no room left for the text columns once the
# fixed-vocabulary columns are laid out whole.
_COMPACT_TERMINAL_WIDTH = 80


def _glyphs(text: str, encoding: str) -> str:
    """Return ``text``, with ASCII glyphs if ``encoding`` lacks the report's own.

    A redirected stdout takes the locale's code page, and a legacy one (cp1252
    on a Western-locale Windows) has no check mark and no box-drawing
    characters: writing them would raise after the whole scan has run. The
    glyphs are swapped together, so a report never mixes the two sets.
    """
    try:
        "".join(_ASCII_GLYPHS).encode(encoding)
    except UnicodeEncodeError:
        return text.translate(str.maketrans(_ASCII_GLYPHS))
    return text


def _fit_table(console: Console, table: Table) -> None:
    """Keep every column of ``table`` in view, whatever the console's width.

    Off a terminal (a pipe, a CI log, an ``-o`` file) nothing bounds the line
    length, so the console is widened to the table's natural width: no cell
    wraps or is cut short.

    On a terminal too narrow for the columns' minimum widths, the table would
    be cropped at the right edge, which loses whole columns. The minimums are
    dropped instead, so the text columns fold further; below
    ``_COMPACT_TERMINAL_WIDTH`` the fixed-vocabulary columns fold as well.
    """
    measured = console.measure(table, options=console.options.update_width(sys.maxsize))
    if not console.is_terminal:
        console.width = max(console.width, measured.maximum)
    elif measured.minimum > console.width:
        keep_whole = console.width >= _COMPACT_TERMINAL_WIDTH
        table.columns[:] = [
            replace(column, min_width=None, no_wrap=column.no_wrap and keep_whole)
            for column in table.columns
        ]


def _grouped_results(results: list[CompatibilityResult]) -> list[CompatibilityResult]:
    """Order direct deps alphabetically; nest transitives under their first ancestor.

    Every result is listed exactly once. A transitive goes under its
    alphabetically-first direct ancestor (a sorted tuple, so this is
    deterministic), matched within its own ecosystem: a transitive always
    shares its ancestors' ecosystem, so a same-named direct dep in another
    ecosystem is not its parent. When several direct rows share an ecosystem
    and name (two locked versions of one package), they are ordered by
    resolved version and the transitives go under the first. Transitives
    whose first ancestor isn't represented in the report (which shouldn't
    happen post-orphan-filter, but defensively) appear at the end.
    """
    direct = sorted(
        [r for r in results if not r.license_info.dependency.is_transitive],
        key=lambda r: (*_row_order(r), r.license_info.resolved_version),
    )
    direct_keys = {
        (r.license_info.dependency.ecosystem, r.license_info.dependency.name) for r in direct
    }
    by_first_ancestor: dict[tuple[Ecosystem, str], list[CompatibilityResult]] = {}
    orphans: list[CompatibilityResult] = []
    for r in results:
        dep = r.license_info.dependency
        if not dep.is_transitive:
            continue
        key = (dep.ecosystem, dep.direct_ancestors[0]) if dep.direct_ancestors else None
        if key in direct_keys:
            by_first_ancestor.setdefault(key, []).append(r)
        else:
            orphans.append(r)
    out: list[CompatibilityResult] = []
    for d in direct:
        out.append(d)
        dep = d.license_info.dependency
        # ``pop``, not ``get``: a bucket is emitted under the first direct row
        # that claims it and never again.
        out.extend(sorted(by_first_ancestor.pop((dep.ecosystem, dep.name), []), key=_row_order))
    out.extend(sorted(orphans, key=_row_order))
    return out


_GAP_NOTE = "their dependencies may be missing from this report"


def _gap_diagnostics(report: AnalysisReport) -> list[ReportDiagnostic]:
    """Diagnostics for manifests the scan could not fully analyze.

    Leaves out recovered reads (a latin-1 fallback): those lost no dependency.
    """
    return [d for d in report.read_diagnostics if d.severity == "gap"]


def _gap_count(gaps: list[ReportDiagnostic]) -> int:
    """Distinct manifests among ``gaps``; one file can carry several diagnostics."""
    return len({d.path for d in gaps})


def _gap_summary(gaps: list[ReportDiagnostic]) -> str:
    """Gap count for a summary line, e.g. ``2 analysis gaps``."""
    count = _gap_count(gaps)
    return f"{count} analysis gap{'s' if count != 1 else ''}"


def _gap_file(path: str) -> tuple[str, str]:
    """Return ``(label, relative URL)`` for the file a gap was recorded on.

    A file outside the scan root (reached through ``..`` from a manifest)
    arrives as an absolute path, which differs between machines and checkouts.
    A saved report must not depend on where the project was scanned, so such a
    file is named by its last component and gets no link.
    """
    if PurePath(path).is_absolute():
        return f"{PurePath(path).name} (outside the project directory)", ""
    return path, _url_quote(path)


def _gap_rows(gaps: list[ReportDiagnostic]) -> list[tuple[str, str, str]]:
    """``(file label, relative URL, reason)`` for each gap, sorted.

    Sorted on what is shown, so the order depends neither on the order the
    files were visited in nor on the absolute path of a file outside the root.
    """
    return sorted((*_gap_file(d.path), d.reason) for d in gaps)


def _other_ancestors_suffix(result: CompatibilityResult) -> str:
    """Return ' (also: X, Y)' for transitives shared across multiple direct deps."""
    dep = result.license_info.dependency
    if not dep.is_transitive or len(dep.direct_ancestors) <= 1:
        return ""
    others = list(dep.direct_ancestors[1:])
    head = ", ".join(others[:2])
    if len(others) > 2:
        return f" (also: {head} +{len(others) - 2} more)"
    return f" (also: {head})"


def render_table(
    report: AnalysisReport,
    console: Console | None = None,
    project_path: Path | None = None,
) -> None:
    """Render the analysis report as a rich table.

    Direct deps are listed alphabetically; their transitives appear nested
    immediately beneath, indented in the Package column. Transitives shared
    across multiple direct deps are listed once under their alphabetically-
    first ancestor with an "(also: X)" suffix.

    `project_path` is used to build absolute `file://` URLs for the Source
    column so modern terminals can make manifest paths clickable.
    """
    console = console or Console()

    console.print()
    console.print(
        Text.assemble("  Project license: ", (_printable(report.project_license), "bold"))
    )
    console.print()

    # Every column folds rather than truncates. The fixed-vocabulary columns
    # are kept whole (``no_wrap``) for as long as ``_fit_table`` leaves them so.
    table = Table(show_header=True, header_style="bold", pad_edge=True)
    table.add_column("Package", style="cyan", min_width=20, overflow="fold")
    table.add_column("Ecosystem", min_width=8, overflow="fold", no_wrap=True)
    table.add_column("Group", min_width=5, overflow="fold", no_wrap=True)
    table.add_column("Source", min_width=12, overflow="fold")
    table.add_column("License", min_width=12, overflow="fold")
    table.add_column("Risk", min_width=14, overflow="fold", no_wrap=True)
    table.add_column("Status", justify="center", min_width=6, overflow="fold", no_wrap=True)

    grouped = _grouped_results(report.results)

    for result in grouped:
        dep = result.license_info.dependency
        table.add_row(
            Text.assemble(
                _glyphs(_TRANSITIVE_PREFIX, console.encoding) if dep.is_transitive else "",
                _rich_link(_package_label(result), _package_url(result)),
                _printable(_other_ancestors_suffix(result)),
            ),
            dep.ecosystem.value,
            dep.group.value,
            _rich_link(dep.source, _source_terminal_url(result, project_path))
            if dep.source
            else "",
            _rich_license_label(result.license_info.effective_license_id),
            _risk_style(result),
            _glyphs(_VERDICT_ICONS[result.verdict], console.encoding),
        )

    _fit_table(console, table)
    console.print(table)
    console.print()

    # Summary line
    n_ok = len(report.ok)
    n_warn = len(report.warnings)
    n_viol = len(report.violations)
    n_unk = len(report.unknown)
    n_reviewed = len(report.reviewed)

    parts = []
    if n_viol:
        parts.append(f"[red]{n_viol} violation{'s' if n_viol != 1 else ''}[/red]")
    if n_warn:
        parts.append(f"[yellow]{n_warn} warning{'s' if n_warn != 1 else ''}[/yellow]")
    if n_unk:
        parts.append(f"[dim]{n_unk} unknown[/dim]")
    parts.append(f"[green]{n_ok} ok[/green]")

    summary = ", ".join(parts)
    if n_reviewed:
        summary += f" [cyan](of which {n_reviewed} reviewed)[/cyan]"
    gaps = _gap_diagnostics(report)
    if gaps:
        summary += f", [yellow]{_gap_summary(gaps)}[/yellow]"
    console.print(f"  Summary: {summary}")
    console.print(
        f"  Completed in: [bold]{_format_elapsed(report.elapsed_seconds)}[/bold]",
        highlight=False,
    )
    console.print()

    if gaps:
        console.print(f"  [bold]Analysis gaps[/bold] ({_GAP_NOTE}):")
        for label, _, reason in _gap_rows(gaps):
            console.print(f"    {_rich_escape(label)}: {_rich_escape(reason)}")
        console.print()

    # Show reasons for non-ok results
    detail_results = [r for r in grouped if r.verdict != CompatibilityVerdict.COMPATIBLE]
    if detail_results:
        console.print("  [bold]Details:[/bold]")
        for result in detail_results:
            icon = _glyphs(_VERDICT_ICONS[result.verdict], console.encoding)
            console.print(f"    {icon} {_rich_escape(result.reason)}")
        console.print()

    reviewed_results = _reviewed_results(grouped)
    if reviewed_results:
        console.print("  [bold]Reviewed:[/bold]")
        review_table = Table(show_header=True, header_style="bold", pad_edge=True)
        review_table.add_column("Package", style="cyan", min_width=20, overflow="fold")
        review_table.add_column("Detected", min_width=18, overflow="fold")
        review_table.add_column("Reviewed", min_width=12, overflow="fold")
        review_table.add_column("Note", min_width=18, overflow="fold")
        for result in reviewed_results:
            review_table.add_row(
                _rich_link(_package_label(result), _package_url(result)),
                Text(_printable(_detected_license_label(result))),
                _rich_license_label(result.license_info.reviewed_license_id),
                Text(_printable(result.license_info.review_note)),
            )
        _fit_table(console, review_table)
        console.print(review_table)
        console.print()

    console.print(f"  [dim]{_REPORT_NOTE}[/dim]")
    console.print()


def _summary_text(report: AnalysisReport) -> str:
    """Plain-text verdict counts, e.g. ``0 violations, 2 warnings, 0 unknown, 15 ok``."""
    n_viol = len(report.violations)
    n_warn = len(report.warnings)
    summary = (
        f"{n_viol} violation{'s' if n_viol != 1 else ''}, "
        f"{n_warn} warning{'s' if n_warn != 1 else ''}, "
        f"{len(report.unknown)} unknown, {len(report.ok)} ok"
    )
    if report.reviewed:
        summary += f" (of which {len(report.reviewed)} reviewed)"
    return summary


def render_check_failure(
    report: AnalysisReport,
    failing: list[CompatibilityResult],
    *,
    gap_count: int,
    output_file: Path,
) -> str:
    """Explain a failed check whose report went to a file (``--output``).

    Nothing else reaches the terminal in that case, so CI logs and pre-commit
    output would show only the exit code. ``failing`` holds the unreviewed
    findings that failed the check; ``gap_count`` the manifests that couldn't
    be analyzed (already listed in the warnings printed before this).
    """
    lines = [f"License check failed: {_summary_text(report)}"]
    lines += [f"  {_VERDICT_MD_ICONS[r.verdict]} {_printable(r.reason)}" for r in failing]
    if gap_count:
        lines.append(
            f"  {gap_count} manifest(s) could not be fully analyzed (see the warnings above)"
        )
    lines.append(f"Full report: {output_file}")
    return "\n".join(lines)


def render_json(report: AnalysisReport) -> str:
    """Render the analysis report as JSON."""
    data = _report_to_dict(report)
    return json.dumps(data, indent=2)


def render_markdown(report: AnalysisReport, *, encoding: str = "utf-8") -> str:
    """Render the analysis report as markdown.

    Direct deps alphabetical; transitives nested beneath their first ancestor
    via a `└─ ` prefix in the Package cell. Shared transitives carry an
    `(also: X)` suffix.

    ``encoding`` is that of the stream the text is headed for. A saved report
    is UTF-8; for a stdout that cannot represent the report as written, the
    verdict icons and the tree branch are replaced by ASCII (see
    :func:`_glyphs`).
    """
    lines: list[str] = []
    lines.append("# License Analysis Report")
    lines.append("")
    lines.append(f"**Project license:** {_escape_md(report.project_license)}")
    lines.append("")

    headers = ["Package", "Ecosystem", "Group", "Source", "License", "Risk", "Status"]
    separators = [
        "---------",
        "-----------",
        "-------",
        "--------",
        "---------",
        "------",
        "--------",
    ]
    lines.append(_markdown_row(headers))
    lines.append(_markdown_row(separators))

    grouped = _grouped_results(report.results)
    for result in grouped:
        dep = result.license_info.dependency
        icon = _VERDICT_MD_ICONS[result.verdict]
        link = _markdown_link(_package_label(result), _package_url(result))
        suffix = _escape_md(_other_ancestors_suffix(result))
        package_cell = (
            f"{_TRANSITIVE_PREFIX}{link}{suffix}" if dep.is_transitive else f"{link}{suffix}"
        )
        lines.append(
            _markdown_row(
                [
                    package_cell,
                    dep.ecosystem.value,
                    dep.group.value,
                    _markdown_link(dep.source, _url_quote(_source_url(result))),
                    _markdown_license_label(result.license_info.effective_license_id),
                    result.risk_level.value,
                    icon,
                ]
            )
        )

    lines.append("")

    # No run time here, unlike the table output: the Markdown report is meant
    # to be checked in (LICENSES.md), so it must depend only on the findings.
    gaps = _gap_diagnostics(report)
    summary = _summary_text(report)
    if gaps:
        summary += f", {_gap_summary(gaps)}"
    lines.append(f"**Summary:** {summary}")

    if gaps:
        lines.append("")
        lines.append("## Analysis gaps")
        lines.append("")
        lines.append(f"These manifests could not be fully analyzed; {_GAP_NOTE}.")
        lines.append("")
        lines.append(_markdown_row(["File", "Reason"]))
        lines.append(_markdown_row(["------", "--------"]))
        for label, url, reason in _gap_rows(gaps):
            lines.append(_markdown_row([_markdown_link(label, url), _escape_md(reason)]))

    detail_results = [r for r in grouped if r.verdict != CompatibilityVerdict.COMPATIBLE]
    if detail_results:
        lines.append("")
        lines.append("## Details")
        lines.append("")
        for result in detail_results:
            icon = _VERDICT_MD_ICONS[result.verdict]
            lines.append(f"- {icon} {_escape_md(result.reason)}")

    reviewed_results = _reviewed_results(grouped)
    if reviewed_results:
        lines.append("")
        lines.append("## Reviewed")
        lines.append("")
        lines.append(_markdown_row(["Package", "Detected", "Reviewed", "Note"]))
        lines.append(_markdown_row(["---------", "----------", "----------", "----"]))
        for result in reviewed_results:
            lines.append(
                _markdown_row(
                    [
                        _markdown_link(_package_label(result), _package_url(result)),
                        _escape_md(_detected_license_label(result)),
                        _markdown_license_label(result.license_info.reviewed_license_id),
                        _escape_md(result.license_info.review_note),
                    ]
                )
            )

    lines.append("")
    lines.append(f"_{_REPORT_NOTE.replace('licenseal check', '`licenseal check`')}_")
    return _glyphs("\n".join(lines).rstrip("\n"), encoding)


def _report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    """Convert report to a serializable dict.

    ``summary.gaps`` counts distinct manifests lost to an analysis gap
    (unreadable / unparseable), and the top-level ``diagnostics`` array lists
    every surfaced read/parse anomaly — so a CI consumer reading only the JSON
    can see what the scan couldn't. Both are always present (``0`` / ``[]`` on
    a clean scan); the table and Markdown reports list the gaps only when
    there are any.
    """
    return {
        "project_license": report.project_license,
        "elapsed_seconds": report.elapsed_seconds,
        "summary": {
            "total": len(report.results),
            "ok": len(report.ok),
            "warnings": len(report.warnings),
            "violations": len(report.violations),
            "unknown": len(report.unknown),
            "reviewed": len(report.reviewed),
            "gaps": _gap_count(_gap_diagnostics(report)),
        },
        "dependencies": [_dep_to_dict(r) for r in _sorted_results(report.results)],
        "diagnostics": [
            {"path": d.path, "reason": d.reason, "severity": d.severity}
            for d in report.read_diagnostics
        ],
    }


def _dep_to_dict(r: CompatibilityResult) -> dict[str, Any]:
    """Render a single compatibility result as the JSON dep dict."""
    license_url = _license_url(r.license_info.effective_license_id)
    repository_url = r.license_info.repository_url
    homepage_url = r.license_info.homepage_url
    package_url = _package_url(r)
    out: dict[str, Any] = {
        "name": r.license_info.dependency.name,
        "ecosystem": r.license_info.dependency.ecosystem.value,
        "group": r.license_info.dependency.group.value,
        "depth": r.license_info.dependency.display_depth,
        "direct_ancestors": list(r.license_info.dependency.direct_ancestors),
        "is_transitive": r.license_info.dependency.is_transitive,
        "source": r.license_info.dependency.source,
        "source_url": _source_url(r),
        "license": r.license_info.effective_license_id,
        "license_raw": r.license_info.license_raw,
        "detected_license": r.license_info.detected_license_id,
        "reviewed_license": r.license_info.reviewed_license_id,
        "effective_license": r.license_info.effective_license_id,
        "reviewed": r.license_info.reviewed,
        "review_note": r.license_info.review_note,
        "resolved_version": r.license_info.resolved_version,
        "repository_url": repository_url,
        "homepage_url": homepage_url,
        "package_url": package_url,
        "license_url": license_url,
        "risk": r.risk_level.value,
        "verdict": r.verdict.value,
        "reason": r.reason,
    }
    actionability = _actionability(
        r,
        license_url=license_url,
        repository_url=repository_url,
        homepage_url=homepage_url,
        package_url=package_url,
    )
    if actionability is not None:
        out["actionability"] = actionability
    return out
