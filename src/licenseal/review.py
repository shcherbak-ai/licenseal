"""Manual license review file (`licenseal.review.toml`) handling.

The review file lets a maintainer override the license of a dependency that
the resolver could not classify cleanly. Each entry is keyed on the resolved
ecosystem+package@version triple, so reviews never apply across versions.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import click

from licenseal.analysis.spdx import normalize_license
from licenseal.models import CompatibilityResult, CompatibilityVerdict, Ecosystem, LicenseInfo

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # ty: ignore[unresolved-import]  # pragma: no cover


REVIEW_FILE_NAME = "licenseal.review.toml"

_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")
_VALID_ECOSYSTEMS = frozenset(e.value for e in Ecosystem)


@dataclass
class FlaggedEntry:
    """A flagged dependency eligible for review templating."""

    ecosystem: str
    name: str
    version: str
    detected_license: str
    license_raw: str
    verdict: str


@dataclass
class ReviewFileContents:
    """Parsed and validated `licenseal.review.toml`."""

    licenses: dict[str, str] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    incomplete: list[str] = field(default_factory=list)

    @property
    def all_keys(self) -> set[str]:
        """Union of resolved review keys (licenses) and incomplete ones."""
        return set(self.licenses) | set(self.incomplete)


def canonical_name(ecosystem: Ecosystem | str, name: str) -> str:
    """Return the canonical package name used for review keys.

    Python applies PEP 503 normalization (lowercase; runs of `-_.` collapse to `-`).
    """
    eco = ecosystem.value if isinstance(ecosystem, Ecosystem) else ecosystem
    stripped = name.strip()
    if eco == Ecosystem.PYTHON.value:
        return _PEP503_NORMALIZE_RE.sub("-", stripped).lower()
    return stripped.lower()


def review_key(ecosystem: Ecosystem | str, name: str, version_text: str) -> str:
    """Build the canonical review key for a resolved package version."""
    eco = ecosystem.value if isinstance(ecosystem, Ecosystem) else ecosystem
    return f"{eco}:{canonical_name(ecosystem, name)}@{version_text.strip()}"


def _normalize_reviewed_license(raw_license: str) -> str:
    normalized = normalize_license(raw_license)
    if normalized == "UNKNOWN":
        raise click.ClickException(
            f"Invalid reviewed license {raw_license!r}. Use a valid SPDX ID or SPDX expression."
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
    except tomllib.TOMLDecodeError as exc:
        raise click.ClickException(f"Invalid {REVIEW_FILE_NAME}: {exc}.") from exc

    entries = data.get("review", [])
    if not isinstance(entries, list):
        raise click.ClickException(f"Invalid {REVIEW_FILE_NAME}: expected [[review]] entries.")

    licenses: dict[str, str] = {}
    notes: dict[str, str] = {}
    incomplete: list[str] = []
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
        if not isinstance(version_text, str) or not version_text.strip():
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

        key = review_key(ecosystem, package, version_text)
        if key in seen:
            raise click.ClickException(
                f"Invalid {REVIEW_FILE_NAME}: duplicate review entry for "
                f"{ecosystem}:{package}@{version_text}."
            )
        seen.add(key)

        if not license_value.strip():
            incomplete.append(key)
            continue
        licenses[key] = _normalize_reviewed_license(license_value.strip())
        if note.strip():
            notes[key] = note.strip()

    return ReviewFileContents(licenses=licenses, notes=notes, incomplete=incomplete)


def apply_reviewed_licenses(
    license_infos: list[LicenseInfo],
    contents: ReviewFileContents,
    flagged_keys: set[str],
) -> None:
    """Apply reviewed license overrides to resolved dependencies in place.

    Sets `reviewed_license_id` and `review_note` on matching infos. The
    detected license stays in `license_id` so reports can show both.
    """
    if not contents.licenses and not contents.notes:
        return

    note_only = set(contents.notes) - set(contents.licenses)
    if note_only:
        raise click.ClickException(
            "Review notes require matching reviewed license entries: "
            + ", ".join(sorted(note_only))
            + "."
        )

    matched: set[str] = set()
    ineligible: list[str] = []
    for info in license_infos:
        if not info.resolved_version:
            continue
        key = review_key(
            info.dependency.ecosystem,
            info.dependency.name,
            info.resolved_version,
        )
        reviewed = contents.licenses.get(key)
        if not reviewed:
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
            "already-compatible dependencies and should be removed: "
            + ", ".join(sorted(ineligible))
        )
    unmatched = sorted(set(contents.licenses) - matched)
    if unmatched:
        raise click.ClickException(
            "Reviewed licenses did not match any resolved package versions: "
            + ", ".join(unmatched)
            + "\nHint: a dependency upgrade likely moved past the pin. Open "
            "`licenseal.review.toml` and update the `version` field on the "
            "stale stanza(s) above to the new resolved version — but ONLY if "
            "the new version still reports the same `license` as the original "
            "review. Licenses may change between versions, so verify against "
            "the latest scan first. If the license changed, or the dep is no "
            "longer in the dependency tree, delete the stanza so the next "
            "scan re-flags the dep for fresh review."
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
    """
    entries: list[FlaggedEntry] = []
    unscaffoldable: list[str] = []
    for result in results:
        if result.verdict == CompatibilityVerdict.COMPATIBLE:
            continue
        info = result.license_info
        if not info.resolved_version:
            unscaffoldable.append(f"{info.dependency.ecosystem.value}:{info.dependency.name}")
            continue
        entries.append(
            FlaggedEntry(
                ecosystem=info.dependency.ecosystem.value,
                name=info.dependency.name,
                version=info.resolved_version,
                detected_license=info.detected_license_id or "UNKNOWN",
                license_raw=info.license_raw or "",
                verdict=result.verdict.value,
            )
        )
    return entries, unscaffoldable


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
    except (OSError, json.JSONDecodeError) as exc:
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
    for raw in deps:
        if not isinstance(raw, dict):
            continue
        verdict = raw.get("verdict", "")
        if verdict == CompatibilityVerdict.COMPATIBLE.value:
            continue
        ecosystem = raw.get("ecosystem", "")
        if ecosystem not in _VALID_ECOSYSTEMS:
            continue
        name = raw.get("name", "")
        if not isinstance(name, str) or not name:
            continue
        version_text = raw.get("resolved_version", "")
        if not isinstance(version_text, str) or not version_text:
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
                verdict=verdict or "unknown",
            )
        )
    return entries, unscaffoldable


def render_review_template(
    entries: list[FlaggedEntry],
    *,
    include_header: bool = True,
) -> str:
    """Render a review template for the given flagged entries."""
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
        detected = entry.detected_license or "UNKNOWN"
        lines.append(f"# detected: {detected}")
        lines.append(f"# status: {entry.verdict}")
        if entry.license_raw and entry.license_raw != detected:
            lines.append(f"# raw: {entry.license_raw}")
        lines.append("[[review]]")
        lines.append(f'ecosystem = "{entry.ecosystem}"')
        lines.append(f'package = "{entry.name}"')
        lines.append(f'version = "{entry.version}"')
        lines.append('license = ""')
        lines.append('note = ""')
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def merge_review_template(
    existing_text: str,
    new_entries: list[FlaggedEntry],
    existing_keys: set[str],
) -> tuple[str, int]:
    """Append flagged entries that aren't already present.

    Returns the merged text and the number of stanzas appended.
    """
    pending = [
        e for e in new_entries if review_key(e.ecosystem, e.name, e.version) not in existing_keys
    ]
    if not pending:
        return existing_text, 0
    appended = render_review_template(pending, include_header=False)
    if not existing_text:
        return appended, len(pending)
    if not existing_text.endswith("\n"):
        existing_text += "\n"
    return existing_text + "\n" + appended, len(pending)
