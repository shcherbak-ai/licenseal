"""Render the README's terminal figure: licenseal's own report for an illustrative project.

The figure is not drawn by hand. The script writes a small project to a
temporary directory, answers the registry lookups from the table below
(nothing is requested from the network), runs ``licenseal check`` on it, and
typesets what the command printed as an SVG.

What is typeset is an excerpt of that output: the project license, the table
and the summary. The command line above it is added here. Every character and
its place on the terminal grid are licenseal's. Two things are drawn instead of
set in type, so that they do not depend on the reader's fonts: the table's
borders and the tree branch before a transitive dependency are lines.

Run from the repository root::

    uv run python scripts/render_readme_report.py

The figure is written to ``assets/licenseal-report.svg``; a path given as the
first argument is written instead. ``tests/test_readme_figure.py`` fails while
the committed figure is not what this script renders, so a change to the
report's layout is followed by a run of it.
"""

from __future__ import annotations

import html
import io
import json
import sys
import tempfile
import textwrap
from pathlib import Path
from unittest import mock

import httpx
from click.testing import CliRunner
from rich.console import Console
from rich.style import Style
from rich.text import Text

import licenseal.cli

OUT = Path(__file__).resolve().parent.parent / "assets" / "licenseal-report.svg"

# The illustrative project: ``app`` is MIT and requires ``client`` and
# ``parser``; ``client`` brings in ``transport``, which brings in ``certs``.
# Name: (version, license, what it requires).
PACKAGES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "client": ("2.4.0", "MIT", ("transport",)),
    "transport": ("1.8.2", "Apache-2.0", ("certs",)),
    "certs": ("3.1.0", "GPL-3.0-only", ()),
    "parser": ("0.9.1", "BSD-3-Clause", ()),
}
COMMAND = "uvx licenseal check"

# The terminal grid, in SVG units: a character cell and a line.
CELL = 8.4
LINE = 22.0
FONT_SIZE = 14
BASELINE = 15.5
PAD_X = 26.0
PAD_TOP = 20.0
PAD_BOTTOM = 18.0
# The tab on the window's top edge, which says where the command is run.
TAB_HEIGHT = 26.0
TAB_WIDTH = 92.0

GROUND = "#0c0c0e"
FRAME = "#2e2e33"
FONT = 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace'

# Which sides of its cell a box-drawing character reaches: up, down, left, right.
ARMS = {
    "─": "lr", "━": "lr", "│": "ud", "┃": "ud",
    "┌": "dr", "┏": "dr", "┐": "dl", "┓": "dl",
    "└": "ur", "┗": "ur", "┘": "ul", "┛": "ul",
    "├": "udr", "┡": "udr", "┣": "udr", "┤": "udl", "┩": "udl", "┫": "udl",
    "┬": "dlr", "┳": "dlr", "┴": "ulr", "┻": "ulr",
    "┼": "udlr", "╇": "udlr", "╋": "udlr",
}  # fmt: skip


def _write_project(root: Path) -> None:
    """Write the illustrative project: a manifest and the lockfile that pins its tree."""
    (root / "pyproject.toml").write_text(
        textwrap.dedent("""\
            [project]
            name = "app"
            version = "1.0.0"
            license = "MIT"
            dependencies = ["client", "parser"]
            """),
        encoding="utf-8",
    )
    lock = ["version = 1", ""]
    for name, (version, _license, requires) in PACKAGES.items():
        lock += ["[[package]]", f'name = "{name}"', f'version = "{version}"']
        if requires:
            entries = ", ".join(f'{{ name = "{required}" }}' for required in requires)
            lock.append(f"dependencies = [{entries}]")
        lock.append("")
    (root / "uv.lock").write_text("\n".join(lock), encoding="utf-8")


def _answer(_transport: httpx.HTTPTransport, request: httpx.Request) -> httpx.Response:
    """Answer a registry request from ``PACKAGES``; anything else is not found."""
    if request.url.host != "api.deps.dev" or request.method != "POST":
        return httpx.Response(404)
    responses = []
    for item in json.loads(request.content)["requests"]:
        key = item["versionKey"]
        entry: dict[str, object] = {"request": {"versionKey": key}}
        known = PACKAGES.get(key["name"])
        if known and known[0] == key["version"]:
            entry["version"] = {"versionKey": key, "licenses": [known[1]], "links": []}
        responses.append(entry)
    return httpx.Response(200, json={"responses": responses, "nextPageToken": ""})


def _scan() -> list[Text]:
    """Run ``licenseal check`` on the project and return its report, a styled line at a time."""
    # A terminal wide enough for the table to take the width it needs, and whose
    # capabilities do not come from the environment the script is run in.
    console = Console(
        record=True,
        width=200,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
        _environ={},
    )
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "app"
        project.mkdir()
        _write_project(project)
        with (
            mock.patch.object(httpx.HTTPTransport, "handle_request", _answer),
            mock.patch.object(licenseal.cli, "Console", lambda *_args, **_kwargs: console),
        ):
            result = CliRunner().invoke(licenseal.cli.main, ["check", "--path", str(project)])
    if result.exception and not isinstance(result.exception, SystemExit):
        raise result.exception
    return list(Text.from_ansi(console.export_text(styles=True)).split("\n"))


def _excerpt(lines: list[Text]) -> list[Text]:
    """The lines the figure shows, under the command that printed them."""
    shown = [Text.assemble("  ", ("$", "dim"), " ", (COMMAND, "bold")), Text()]
    plain = [line.plain for line in lines]
    first = next(i for i, text in enumerate(plain) if text.startswith("  Project license:"))
    last = next(i for i, text in enumerate(plain) if text.startswith("  Summary:"))
    return shown + lines[first : last + 1]


def _classes(style: Style) -> str:
    """The figure's classes for a style of the report: grey, but for what was caught."""
    # The report's colours, as the numbers of the terminal's eight: red and
    # yellow for a violation and a warning, green for what is compatible,
    # cyan for a package's name.
    number = style.color.number if style.color else None
    hue = None if number is None else number % 8
    if style.dim:
        tone = "dim"
    elif hue in {1, 3}:
        tone = "caught"
    elif hue == 2:
        tone = "ok"
    elif hue == 6 or style.bold:
        tone = "name"
    else:
        tone = "text"
    return f"{tone} bold" if style.bold else tone


def _runs(line: Text) -> list[tuple[int, str, Style]]:
    """Split a line into ``(column, characters, style)`` runs of one style."""
    runs: list[tuple[int, str, Style]] = []
    column = 0
    for segment in line.render(Console(width=10_000, file=io.StringIO())):
        if segment.text and segment.text != "\n":
            runs.append((column, segment.text, segment.style or Style()))
            column += len(segment.text)
    return runs


def _merged(spans: dict[float, list[tuple[float, float]]]) -> list[tuple[float, float, float]]:
    """Join the spans on each line that touch: ``(line, start, end)``."""
    joined: list[tuple[float, float, float]] = []
    for line, parts in sorted(spans.items()):
        start, end = None, None
        for low, high in sorted(parts):
            if end is not None and low <= end + 0.01:
                end = max(end, high)
                continue
            if start is not None and end is not None:
                joined.append((line, start, end))
            start, end = low, high
        if start is not None and end is not None:
            joined.append((line, start, end))
    return joined


def _word(word: str, column: int, row_top: float, style: Style) -> str:
    """Set one word of the report at its column."""
    x, y = PAD_X + column * CELL, row_top + BASELINE
    if len(word) == 1:
        # A lone character is centred in its cell: a mark can come from a wider font.
        place = f'x="{x + CELL / 2:.1f}" y="{y:.1f}" text-anchor="middle"'
    else:
        # A word is held to its cells, whatever the width of the reader's font.
        span = f'textLength="{len(word) * CELL:.1f}" lengthAdjust="spacing"'
        place = f'x="{x:.1f}" y="{y:.1f}" {span}'
    return f'<text class="{_classes(style)}" {place}>{html.escape(word, quote=False)}</text>'


def _typeset(lines: list[Text]) -> str:
    """Set the lines on the terminal grid, inside the figure's window."""
    columns = max(len(line.plain) for line in lines)
    width = PAD_X * 2 + columns * CELL
    top = TAB_HEIGHT + PAD_TOP
    height = top + len(lines) * LINE + PAD_BOTTOM

    words: list[str] = []
    # Lines drawn in place of box-drawing characters, by what they belong to:
    # horizontal spans keyed by their y, vertical spans keyed by their x.
    across: dict[str, dict[float, list[tuple[float, float]]]] = {"grid": {}, "tree": {}}
    down: dict[str, dict[float, list[tuple[float, float]]]] = {"grid": {}, "tree": {}}

    for row, line in enumerate(lines):
        row_top = top + row * LINE
        centre = row_top + LINE / 2
        for start, characters, style in _runs(line):
            # A branch is part of a package's cell and has its colour; a border has none.
            part = "tree" if style.color else "grid"
            word_start: int | None = None
            # One space past the end closes a word that the run ends with.
            for offset, character in enumerate(f"{characters} "):
                arms = ARMS.get(character, "")
                left = PAD_X + (start + offset) * CELL
                middle = left + CELL / 2
                if "l" in arms:
                    across[part].setdefault(centre, []).append((left, middle))
                if "r" in arms:
                    across[part].setdefault(centre, []).append((middle, left + CELL))
                if "u" in arms:
                    down[part].setdefault(middle, []).append((row_top, centre))
                if "d" in arms:
                    down[part].setdefault(middle, []).append((centre, row_top + LINE))
                if not (character.isspace() or arms):
                    word_start = offset if word_start is None else word_start
                elif word_start is not None:
                    word = characters[word_start:offset]
                    words.append(_word(word, start + word_start, row_top, style))
                    word_start = None

    rules = []
    for part in ("grid", "tree"):
        strokes = [f"M{start:.1f} {y:.1f}H{end:.1f}" for y, start, end in _merged(across[part])]
        strokes += [f"M{x:.1f} {start:.1f}V{end:.1f}" for x, start, end in _merged(down[part])]
        if strokes:
            rules.append(f'<path class="{part}" d="{"".join(strokes)}"/>')

    outline = (
        f"M0.5 0.5H{TAB_WIDTH:.1f}V{TAB_HEIGHT + 0.5:.1f}H{width - 0.5:.1f}V{height - 0.5:.1f}H0.5Z"
    )
    caught = next(name for name, (_v, license_id, _r) in PACKAGES.items() if "GPL" in license_id)
    return "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
            f'viewBox="0 0 {width:.0f} {height:.0f}" role="img" aria-labelledby="title desc">',
            '<title id="title">licenseal report: one violation, found through a dependency</title>',
            '<desc id="desc">Illustrative packages in an MIT project. The project requires client '
            "and parser. Client brings in transport and certs. Client, transport and parser are "
            f"compatible. {caught.capitalize()} uses {PACKAGES[caught][1]}, a strong copyleft "
            "license, and is a violation. Summary: 1 violation, 3 ok. Typeset from the output of "
            "licenseal check: the command, the project license, the table and the summary.</desc>",
            "<style>",
            f"text{{font-family:{FONT};font-size:{FONT_SIZE}px;fill:#d4d4d8}}",
            ".bold{font-weight:600}.name{fill:#fafafa}.dim{fill:#71717a}.ok{fill:#a1a1aa}",
            ".caught{fill:#fbbf24}.tab{fill:#a1a1aa;font-size:12px}",
            "path{fill:none;shape-rendering:crispEdges}",
            ".grid{stroke:#34343a}.tree{stroke:#63636b}",
            "</style>",
            f'<path d="{outline}" style="fill:{GROUND};stroke:{FRAME}"/>',
            f'<text class="tab" x="{TAB_WIDTH / 2:.1f}" y="17.5" text-anchor="middle">'
            "terminal</text>",
            *rules,
            *words,
            "</svg>",
            "",
        ]
    )


def render() -> str:
    """Scan the illustrative project and return the figure."""
    return _typeset(_excerpt(_scan()))


def main() -> None:
    """Write the figure."""
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
