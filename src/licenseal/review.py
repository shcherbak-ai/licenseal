"""Manual license review file (`licenseal.review.toml`) handling.

The review file lets a maintainer override the license of a dependency that
the resolver could not classify cleanly. Each entry is keyed on the resolved
ecosystem+package@version triple, so reviews never apply across versions.

A dependency that does not come from a registry (a git repository, a direct
URL, a path that the scan does not read) is keyed on ecosystem, package, and
its origin instead: the entry carries a ``source`` key holding the origin
string. The two kinds of key never match each other's rows.

The package of a key is compared the way its ecosystem's registry compares
names (:meth:`licenseal.models.Ecosystem.identity`): exactly for Go, Java,
npm, and Ruby, without regard to case for .NET, PHP, Rust, Hex, and R, and
PEP 503 normalized for Python. A Hex dependency is keyed on the package it
is published as on hex.pm, not on the name ``mix.exs`` gives it.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import click

from licenseal.analysis.compatibility import (
    _SOURCE_AVAILABLE_PROJECT_PREFIXES,  # noqa: PLC2701
)
from licenseal.analysis.risk import DEPRECATED_SPDX_IDS, KNOWN_SPDX_IDS
from licenseal.analysis.spdx import normalize_license
from licenseal.models import CompatibilityResult, CompatibilityVerdict, Ecosystem, LicenseInfo
from licenseal.report import _printable  # noqa: PLC2701

if sys.version_info >= (3, 11):
    import tomllib  # pragma: no cover - Python 3.10 takes the other arm
else:
    import tomli as tomllib  # ty: ignore[unresolved-import]  # pragma: no cover


REVIEW_FILE_NAME = "licenseal.review.toml"

_VALID_ECOSYSTEMS = frozenset(e.value for e in Ecosystem)

# SPDX's form for a license that another document defines:
# ``DocumentRef-<id>:LicenseRef-<id>``. Matched in either case, as a bare
# ``LicenseRef-`` is when it is normalized.
_EXTERNAL_LICENSE_REF_RE = re.compile(
    r"DocumentRef-[A-Za-z0-9.-]+:LicenseRef-[A-Za-z0-9.-]+", re.IGNORECASE
)


@dataclass
class FlaggedEntry:
    """A flagged dependency eligible for review templating."""

    ecosystem: str
    name: str
    version: str
    detected_license: str
    license_raw: str
    verdict: str
    # Origin of a dependency that does not come from a registry; empty for a
    # registry package. Such an entry is keyed on it, and ``version`` may be
    # empty.
    origin: str = ""


@dataclass
class ReviewFileContents:
    """Parsed and validated `licenseal.review.toml`."""

    licenses: dict[str, str] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    incomplete: list[str] = field(default_factory=list)
    # The ``version`` of each ``source``-keyed entry that names one. Such an
    # entry applies only to a row with that origin and that version.
    versions: dict[str, str] = field(default_factory=dict)

    @property
    def all_keys(self) -> set[str]:
        """Union of resolved review keys (licenses) and incomplete ones."""
        return set(self.licenses) | set(self.incomplete)


def canonical_name(ecosystem: Ecosystem | str, name: str) -> str:
    """Return the canonical package name used for review keys.

    The ecosystem's own identity rule decides: a name is kept as written
    where the registry tells names apart by case, and folded where it does
    not (see :meth:`Ecosystem.identity`).
    """
    return Ecosystem(ecosystem).identity(name.strip())


def review_key(ecosystem: Ecosystem | str, name: str, version_text: str) -> str:
    """Build the canonical review key for a resolved package version."""
    eco = ecosystem.value if isinstance(ecosystem, Ecosystem) else ecosystem
    return f"{eco}:{canonical_name(ecosystem, name)}@{version_text.strip()}"


def source_review_key(ecosystem: Ecosystem | str, name: str, source: str) -> str:
    """Build the review key for a dependency that does not come from a registry.

    ``source`` is the dependency's origin string. The key starts with a word
    no ecosystem is named, so it cannot equal a :func:`review_key` whatever
    the package, version, and source hold: an entry without ``source`` never
    matches an off-registry row, and an entry with one never matches a
    registry row.
    """
    eco = ecosystem.value if isinstance(ecosystem, Ecosystem) else ecosystem
    return f"off-registry {eco}:{canonical_name(ecosystem, name)} from {source.strip()}"


def info_review_key(info: LicenseInfo) -> str:
    """Return the key a review entry needs to apply to ``info``.

    Empty when no entry can: a registry package with no resolved version.

    The package of the key is the name the registry publishes it under. For
    a Hex dependency that ``mix.exs`` renames, that is the hex.pm package,
    so an entry stops applying when the local name is pointed at another
    package.
    """
    dep = info.dependency
    if dep.origin:
        return source_review_key(dep.ecosystem, dep.effective_registry_name, dep.origin)
    if not info.resolved_version:
        return ""
    return review_key(dep.ecosystem, dep.effective_registry_name, info.resolved_version)


def _shown_keys(keys: Iterable[str]) -> str:
    """Review keys for an error message: sorted, comma-separated, and escaped.

    A key holds a package, a version, or a source taken from the review file,
    so it is printed the way the reports print such strings.
    """
    return ", ".join(_printable(key) for key in sorted(keys))


def _is_license(operand: str) -> bool:
    """Whether an operand of a normalized expression names a license.

    A current or deprecated SPDX license ID, ``Proprietary``, a
    ``LicenseRef-`` reference, or an ID in one of the source-available
    families the compatibility check recognises by prefix: whatever
    licenseal itself reports as a license. A ``LicenseRef-`` that a
    ``DocumentRef-`` qualifies is a reference too, to a license another SPDX
    document defines. Anything else is a string that is no license at all,
    such as a mistyped ID.
    """
    license_id = operand.rstrip("+")
    return (
        license_id in KNOWN_SPDX_IDS
        or license_id in DEPRECATED_SPDX_IDS
        or license_id == "Proprietary"
        or license_id.startswith("LicenseRef-")
        or _EXTERNAL_LICENSE_REF_RE.fullmatch(license_id) is not None
        or license_id.startswith(_SOURCE_AVAILABLE_PROJECT_PREFIXES)
    )


def _operand_that_is_no_license(expression: str) -> str:
    """The first operand of a normalized expression that is not a license, or ``""``.

    What follows ``WITH`` is an exception, which is not checked against a
    list: a reviewer records an exception licenseal does not recognise once
    they have read it.
    """
    after_with = False
    for word in expression.replace("(", " ").replace(")", " ").split():
        if word in ("AND", "OR", "WITH"):
            after_with = word == "WITH"
        elif after_with:
            after_with = False
        elif not _is_license(word):
            return word
    return ""


# What separates the entries of a license list. No SPDX license or exception
# ID holds either character, and neither does a ``LicenseRef-``.
_LIST_SEPARATORS = (",", "/")


def _normalize_reviewed_license(raw_license: str, label: str) -> str:
    """Normalize the ``license`` of the review entry that ``label`` names, or reject it.

    A reviewed dependency does not fail the check, so an entry whose license
    is no expression, or names something that is no license, is an error
    instead of a review.

    A comma- or slash-separated list is no expression: it does not say
    whether its licenses are alternatives. The normalizer reads one as a
    choice, and a registry's list is then judged under both readings. A
    reviewed license is judged as written, under the one reading its author
    gave, so a list is rejected before it is normalized.
    """
    if any(separator in raw_license for separator in _LIST_SEPARATORS):
        raise click.ClickException(
            f"Invalid {REVIEW_FILE_NAME}: the license of the review entry for "
            f"{_printable(label)} holds a comma or a slash, so it is not a license expression. "
            "Write SPDX identifiers, joined with `OR` or `AND` when there are several: a list "
            "does not say whether its licenses are alternatives."
        )
    normalized = normalize_license(raw_license)
    if normalized == "UNKNOWN":
        raise click.ClickException(
            f"Invalid reviewed license {raw_license!r}. Use a valid SPDX ID or SPDX expression."
        )
    operand = _operand_that_is_no_license(normalized)
    if operand:
        raise click.ClickException(
            f"Invalid {REVIEW_FILE_NAME}: the license of the review entry for "
            f"{_printable(label)} names '{_printable(operand)}', which is not a license "
            "licenseal recognises. Use SPDX license IDs, `Proprietary`, or a `LicenseRef-` "
            "reference."
        )
    return normalized


def load_review_file(project_path: Path) -> ReviewFileContents:
    """Load reviewed license overrides from `licenseal.review.toml` when present."""
    review_file = project_path / REVIEW_FILE_NAME
    if not review_file.exists():
        return ReviewFileContents()

    try:
        with open(review_file, "rb") as f:
            data = tomllib.load(f)
    except OSError as exc:
        raise click.ClickException(f"Could not read {REVIEW_FILE_NAME}: {exc}.") from exc
    except UnicodeDecodeError as exc:
        raise click.ClickException(
            f"Invalid {REVIEW_FILE_NAME}: the file must be UTF-8 ({exc})."
        ) from exc
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        # RecursionError: tables or arrays nested too deeply to parse. A parse
        # error can quote what it found in the file.
        raise click.ClickException(f"Invalid {REVIEW_FILE_NAME}: {_printable(str(exc))}.") from exc

    entries = data.get("review", [])
    if not isinstance(entries, list):
        raise click.ClickException(f"Invalid {REVIEW_FILE_NAME}: expected [[review]] entries.")

    licenses: dict[str, str] = {}
    notes: dict[str, str] = {}
    incomplete: list[str] = []
    versions: dict[str, str] = {}
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: review entry {index} must be a table."
            )
        fields = cast("dict[str, Any]", entry)

        ecosystem = fields.get("ecosystem", "")
        package = fields.get("package", "")
        version_text = fields.get("version", "")
        source = fields.get("source")
        license_value = fields.get("license", "")
        note = fields.get("note", "")

        if not isinstance(ecosystem, str) or ecosystem not in _VALID_ECOSYSTEMS:
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: review entry {index} is missing a valid 'ecosystem'."
            )
        if not isinstance(package, str) or not package.strip():
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: review entry {index} is missing a string 'package'."
            )
        if source is not None and (not isinstance(source, str) or not source.strip()):
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: review entry {index} has an empty or "
                "non-string 'source'."
            )
        # ``version`` is the key of a registry entry and is required there. A
        # ``source``-keyed entry may leave it out; when present it must be a
        # version all the same.
        version_required = source is None or "version" in fields
        if version_required and (not isinstance(version_text, str) or not version_text.strip()):
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: review entry {index} is missing a string 'version'."
            )
        if not isinstance(license_value, str):
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: review entry {index} is missing a string 'license'."
            )
        if "note" in fields and not isinstance(note, str):
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: review entry {index} has a non-string 'note'."
            )

        if source is None:
            key = review_key(ecosystem, package, version_text)
            label = f"{ecosystem}:{package}@{version_text}"
        else:
            key = source_review_key(ecosystem, package, source)
            label = f"off-registry {ecosystem}:{package} from {source}"
        if key in seen:
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: duplicate review entry for {_printable(label)}."
            )
        seen.add(key)
        if source is not None and version_text.strip():
            versions[key] = version_text.strip()

        if not license_value.strip():
            incomplete.append(key)
            continue
        licenses[key] = _normalize_reviewed_license(license_value.strip(), label)
        if note.strip():
            notes[key] = note.strip()

    return ReviewFileContents(
        licenses=licenses, notes=notes, incomplete=incomplete, versions=versions
    )


def apply_reviewed_licenses(
    license_infos: list[LicenseInfo],
    contents: ReviewFileContents,
    flagged_keys: set[str],
) -> None:
    """Apply reviewed license overrides to resolved dependencies in place.

    Sets `reviewed_license_id` and `review_note` on matching infos. The
    detected license stays in `license_id` so reports can show both.

    A registry row matches the entry for its ecosystem, package, and resolved
    version. An off-registry row matches the ``source``-keyed entry for its
    ecosystem, package, and origin; when that entry also names a ``version``,
    the row's version must equal it.
    """
    if not contents.licenses and not contents.notes:
        return

    note_only = set(contents.notes) - set(contents.licenses)
    if note_only:
        raise click.ClickException(
            "Review notes require matching reviewed license entries: "
            + _shown_keys(note_only)
            + "."
        )

    matched: set[str] = set()
    ineligible: list[str] = []
    for info in license_infos:
        key = info_review_key(info)
        reviewed = contents.licenses.get(key)
        if not reviewed:
            continue
        if contents.versions.get(key, info.resolved_version) != info.resolved_version:
            continue
        if key not in flagged_keys:
            ineligible.append(key)
            continue
        info.reviewed_license_id = reviewed
        info.review_note = contents.notes.get(key, "")
        matched.add(key)

    if ineligible:
        raise click.ClickException(
            "Review entries can only override flagged dependencies; these match "
            "already-compatible dependencies and should be removed: " + _shown_keys(ineligible)
        )
    unmatched = set(contents.licenses) - matched
    if unmatched:
        raise click.ClickException(
            "Reviewed licenses did not match any resolved package versions: "
            + _shown_keys(unmatched)
            + "\nHint: a dependency upgrade likely moved past the pin. Open "
            "`licenseal.review.toml` and update the `version` field on the "
            "stale entry or entries above to the new resolved version, but only "
            "if the new version has the same `license` as the original review. "
            "Licenses may change between versions, and no report is written "
            "while a stale entry is present: to see what the new version "
            "reports, or if the dep is no longer in the dependency tree, "
            "delete the entry and scan again, so the dep is flagged for fresh "
            "review. An entry with a `source` "
            "key applies only to that exact source: when the commit, ref, "
            "URL, or path the dependency comes from has changed, review the "
            "new source and update `source` (and `version`, when the entry "
            "has one). `package` is compared the way the registry compares "
            "names: for go, java, npm, and ruby it must be spelled exactly as "
            "the report shows the dependency, upper and lower case included; "
            "for hex it is the package's name on hex.pm."
        )


def flagged_entries_from_results(
    results: list[CompatibilityResult],
) -> tuple[list[FlaggedEntry], list[str]]:
    """Extract flagged dependencies eligible for review templating.

    Returns ``(entries, unscaffoldable)`` where ``unscaffoldable`` lists
    ``"<ecosystem>:<name>"`` for flagged deps that lack a resolved version
    and therefore cannot be keyed in the review file. The CLI surfaces
    them so the user knows the gap exists — these are usually upstream
    resolution failures (typo, yanked package, name collision) worth
    investigating regardless of the review flow.

    An off-registry dependency is keyed on its origin, so it is always an
    entry, with or without a version.

    An entry is named the way its review key is: by the name the registry
    publishes the package under.
    """
    entries: list[FlaggedEntry] = []
    unscaffoldable: list[str] = []
    for result in results:
        if result.verdict == CompatibilityVerdict.COMPATIBLE:
            continue
        info = result.license_info
        if not info.resolved_version and not info.dependency.origin:
            unscaffoldable.append(f"{info.dependency.ecosystem.value}:{info.dependency.name}")
            continue
        entries.append(
            FlaggedEntry(
                ecosystem=info.dependency.ecosystem.value,
                name=info.dependency.effective_registry_name,
                version=info.resolved_version,
                detected_license=info.detected_license_id or "UNKNOWN",
                license_raw=info.license_raw or "",
                verdict=result.verdict.value,
                origin=info.dependency.origin,
            )
        )
    return _one_per_review_key(entries), unscaffoldable


def _one_per_review_key(entries: list[FlaggedEntry]) -> list[FlaggedEntry]:
    """Keep the first entry of each review key.

    A review file holds one stanza per key, and that stanza applies to every
    row with the key. Two flagged rows can share one: two manifests whose
    declarations of a package resolve to the same version, or two local
    names for one published package.
    """
    seen: set[str] = set()
    unique: list[FlaggedEntry] = []
    for entry in entries:
        key = _entry_review_key(entry)
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def flagged_entries_from_json_report(
    json_path: Path,
) -> tuple[list[FlaggedEntry], list[str]]:
    """Extract flagged dependencies from a saved JSON report.

    Lets `init-review-file` skip network resolution when a previous
    `licenseal check -f json` output is available. Returns
    ``(entries, unscaffoldable)`` — see :func:`flagged_entries_from_results`
    for the meaning of the second tuple element.
    """
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise click.ClickException(
            f"Invalid JSON report at {json_path}: the file must be UTF-8 ({exc}). "
            "`licenseal check -f json -o FILE` writes UTF-8."
        ) from exc
    except (OSError, json.JSONDecodeError, RecursionError) as exc:
        # RecursionError: a document nested too deeply to parse.
        raise click.ClickException(f"Invalid JSON report at {json_path}: {exc}.") from exc
    if not isinstance(data, dict):
        raise click.ClickException(f"Invalid JSON report at {json_path}: expected a JSON object.")
    deps = data.get("dependencies", [])
    if not isinstance(deps, list):
        raise click.ClickException(
            f"Invalid JSON report at {json_path}: 'dependencies' must be a list."
        )

    entries: list[FlaggedEntry] = []
    unscaffoldable: list[str] = []
    seen_rows: set[tuple[str, str, str, str]] = set()
    for raw in deps:
        if not isinstance(raw, dict):
            continue
        verdict = raw.get("verdict", "")
        if verdict == CompatibilityVerdict.COMPATIBLE.value:
            continue
        ecosystem = raw.get("ecosystem", "")
        if not isinstance(ecosystem, str) or ecosystem not in _VALID_ECOSYSTEMS:
            continue
        name = raw.get("name", "")
        if not isinstance(name, str) or not name:
            continue
        version_text = raw.get("resolved_version", "")
        if not isinstance(version_text, str):
            version_text = ""
        origin = raw.get("origin", "")
        if not isinstance(origin, str):
            origin = ""
        # A report holds one row per package, resolved version, and origin.
        # One that repeats a row, as a report written before that held can,
        # is read as if it did not.
        row = (ecosystem, canonical_name(ecosystem, name), version_text, origin)
        if row in seen_rows:
            continue
        seen_rows.add(row)
        # A package published under another name than the one the report
        # shows it by is keyed on the published name.
        registry_name = raw.get("registry_name")
        if isinstance(registry_name, str) and registry_name:
            name = registry_name
        if not version_text and not origin:
            unscaffoldable.append(f"{ecosystem}:{name}")
            continue
        detected = raw.get("detected_license") or raw.get("license") or "UNKNOWN"
        entries.append(
            FlaggedEntry(
                ecosystem=ecosystem,
                name=name,
                version=version_text,
                detected_license=str(detected),
                license_raw=str(raw.get("license_raw") or ""),
                verdict=str(verdict or "unknown"),
                origin=origin,
            )
        )
    return _one_per_review_key(entries), unscaffoldable


# Longest value shown on a generated ``#`` comment line. The comment is a hint
# for the reviewer; the full string stays in the scan report's own fields.
_COMMENT_VALUE_MAX = 200


def _comment_text(value: str) -> str:
    """One-line, bounded rendering of an untrusted value for a ``#`` comment.

    Registry and report strings are unbounded free text and may span lines.
    Anything after a line break in a comment would be parsed as live TOML, so
    every whitespace, control, and other non-printable character (a bare
    carriage return and the Unicode line separators included) collapses to a
    single space, and the result is capped.
    """
    text = "".join(ch if ch.isprintable() else " " for ch in value)
    text = " ".join(text.split())
    if len(text) > _COMMENT_VALUE_MAX:
        text = text[: _COMMENT_VALUE_MAX - 1] + "…"
    return text


def _toml_basic_string(value: str) -> str:
    """Serialize ``value`` as a quoted, single-line TOML basic string.

    Backslashes and double quotes are escaped, and every non-printable
    character (control characters and line separators included) is written as
    a ``\\uXXXX`` / ``\\UXXXXXXXX`` escape, so the value cannot close the
    string or start a new line and parses back unchanged. ``value`` must be
    one a TOML string can hold (:func:`toml_can_hold`).
    """
    parts: list[str] = []
    for ch in value:
        if ch in ('"', "\\"):
            parts.append("\\" + ch)
        elif ch.isprintable():
            parts.append(ch)
        elif ord(ch) <= 0xFFFF:
            parts.append(f"\\u{ord(ch):04X}")
        else:
            parts.append(f"\\U{ord(ch):08X}")
    return '"' + "".join(parts) + '"'


def toml_can_hold(value: str) -> bool:
    """Whether ``value`` can be written as a TOML string.

    False for a string holding a lone surrogate, which is what an unpaired
    ``\\uD800``-``\\uDFFF`` escape in a JSON manifest or report decodes to. A
    TOML string holds Unicode scalar values only: a surrogate is valid
    neither as a character nor as a ``\\uXXXX`` escape, and a file that
    contains one does not load.
    """
    return not any("\ud800" <= ch <= "\udfff" for ch in value)


def writable_entries(entries: list[FlaggedEntry]) -> tuple[list[FlaggedEntry], list[str]]:
    """Split ``entries`` into those a stanza can be written for and the rest.

    A stanza carries the entry's package, version, and source as TOML
    strings. An entry with a value TOML cannot hold (:func:`toml_can_hold`)
    gets no stanza, so that one such dependency does not leave the whole file
    unloadable. It is returned as ``"<ecosystem>:<name>"`` for the caller to
    report: no review can be recorded for it.
    """
    writable: list[FlaggedEntry] = []
    unwritable: list[str] = []
    for entry in entries:
        if all(toml_can_hold(value) for value in (entry.name, entry.version, entry.origin)):
            writable.append(entry)
        else:
            unwritable.append(f"{entry.ecosystem}:{entry.name}")
    return writable, unwritable


def render_review_template(
    entries: list[FlaggedEntry],
    *,
    include_header: bool = True,
) -> str:
    """Render a review template for the given flagged entries.

    Entry fields come from registry metadata, manifests, or a saved report
    and are written as data only: each comment stays one comment line and
    each value one escaped string, so an entry can never add, alter, or
    pre-fill a ``[[review]]`` stanza.

    An off-registry entry gets a ``source`` line holding its origin, which is
    what keys it; its ``version`` line is written only when it has a version.
    """
    if not entries:
        return ""
    lines: list[str] = []
    if include_header:
        lines.append("# Generated by `licenseal init-review-file`.")
        lines.append(
            "# Fill in `license` with a reviewed SPDX ID, SPDX expression, or `Proprietary`."
        )
        lines.append("")
    for entry in entries:
        detected = _comment_text(entry.detected_license) or "UNKNOWN"
        raw = _comment_text(entry.license_raw)
        lines.append(f"# detected: {detected}")
        lines.append(f"# status: {_comment_text(entry.verdict) or 'unknown'}")
        if raw and raw != detected:
            lines.append(f"# raw: {raw}")
        lines.append("[[review]]")
        lines.append(f"ecosystem = {_toml_basic_string(entry.ecosystem)}")
        lines.append(f"package = {_toml_basic_string(entry.name)}")
        if entry.version or not entry.origin:
            lines.append(f"version = {_toml_basic_string(entry.version)}")
        if entry.origin:
            lines.append(f"source = {_toml_basic_string(entry.origin)}")
        lines.append('license = ""')
        lines.append('note = ""')
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _entry_review_key(entry: FlaggedEntry) -> str:
    """The key the stanza scaffolded for ``entry`` loads under."""
    if entry.origin:
        return source_review_key(entry.ecosystem, entry.name, entry.origin)
    return review_key(entry.ecosystem, entry.name, entry.version)


def merge_review_template(
    existing_text: str,
    new_entries: list[FlaggedEntry],
    existing_keys: set[str],
) -> tuple[str, int]:
    """Append flagged entries that aren't already present.

    Returns the merged text and the number of stanzas appended.
    """
    pending = [e for e in new_entries if _entry_review_key(e) not in existing_keys]
    if not pending:
        return existing_text, 0
    appended = render_review_template(pending, include_header=False)
    if not existing_text:
        return appended, len(pending)
    if not existing_text.endswith("\n"):
        existing_text += "\n"
    return existing_text + "\n" + appended, len(pending)
