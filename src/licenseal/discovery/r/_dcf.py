"""Minimal Debian-control-file (DCF) parser.

R's ``DESCRIPTION`` manifest and the legacy ``packrat/packrat.lock`` both use
DCF: records separated by blank lines, each a set of ``Field: value`` pairs
where a value continues onto subsequent whitespace-indented lines. We read only
structured fields (no R execution), consistent with the manifest-only rule.
"""

from __future__ import annotations


def parse_dcf(text: str) -> list[dict[str, str]]:
    """Parse DCF ``text`` into a list of records (field name → joined value).

    Continuation lines (leading whitespace) are appended to the current field's
    value separated by a single space. Blank lines separate records. Field names
    are kept verbatim (case-sensitive, as R writes them). A line that is neither
    a continuation nor a ``Field: value`` pair is skipped.
    """
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_field: str | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip():
            if current:
                records.append(current)
                current = {}
                last_field = None
            continue
        if raw_line[0] in (" ", "\t"):
            if last_field is not None:
                current[last_field] = f"{current[last_field]} {raw_line.strip()}".strip()
            continue
        field, sep, value = raw_line.partition(":")
        if not sep:
            continue
        field = field.strip()
        current[field] = value.strip()
        last_field = field
    if current:
        records.append(current)
    return records


def parse_package_list(value: str) -> list[tuple[str, str]]:
    """Parse a DCF dependency field into ``(name, version_constraint)`` pairs.

    The field is a comma-separated list of ``name`` or ``name (>= 1.2.3)``
    entries (``Imports`` / ``Depends`` / ``Suggests`` / ``LinkingTo`` /
    ``Enhances`` in a DESCRIPTION, ``Requires`` in a packrat.lock). The
    parenthesized version constraint is returned without its parens, or ``""``
    when absent. Empty entries are skipped.
    """
    out: list[tuple[str, str]] = []
    for raw_entry in value.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        name, _, rest = entry.partition("(")
        name = name.strip()
        if not name:
            continue
        constraint = rest.rstrip(")").strip() if rest else ""
        out.append((name, constraint))
    return out
