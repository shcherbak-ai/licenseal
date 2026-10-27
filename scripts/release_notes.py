"""Print a version's section of the changelog: the notes of its GitHub release.

The publish workflow runs it in its build job, on the tagged commit and before
anything is published, with the version of the tag (``v1.0.2`` gives
``1.0.2``); once PyPI has the release, its last job creates the GitHub release,
named after the tag, with what the script printed. The notes are the text under
``## [<version>] - <date>``, up to the next section or the links at the end of
the file. A version without a dated section, or with an empty one, stops the
release before it reaches PyPI.

Run directly::

    uv run python scripts/release_notes.py 1.0.1
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def release_notes(changelog: str, version: str) -> str:
    """The text of the version's dated section, without its heading, ending in a newline.

    Raises ``ValueError`` when the changelog has no dated section of the
    version, or the section holds headings only.
    """
    # Whole lines only: a section heading at the start of a line, and the links
    # at the end of the file. A mention of a section in an entry is neither.
    heading = re.search(
        rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.MULTILINE
    )
    if heading is None:
        raise ValueError(f"CHANGELOG.md has no dated section `## [{version}] - <date>`.")
    end = re.compile(r"^(?:## \[|\[[^\]]+\]: )", re.MULTILINE).search(changelog, heading.end())
    text = changelog[heading.end() : end.start() if end else len(changelog)]
    if not any(line.strip() and not line.startswith("#") for line in text.splitlines()):
        raise ValueError(f"The section [{version}] of CHANGELOG.md is empty.")
    return text.strip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    """Print the notes of the version that the one argument names; 1 fails the step."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: release_notes.py VERSION, e.g. 1.0.2", file=sys.stderr)
        return 1
    try:
        notes = release_notes(_CHANGELOG.read_text(encoding="utf-8"), args[0])
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    # In UTF-8 with the changelog's line ends, whatever the console's encoding
    sys.stdout.buffer.write(notes.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
