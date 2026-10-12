"""The README's terminal figure is licenseal's own output, typeset by a script."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "render_readme_report.py"
_FIGURE = _ROOT / "docs" / "assets" / "licenseal-report.svg"


def test_committed_figure_is_what_the_script_renders():
    spec = importlib.util.spec_from_file_location(_SCRIPT.stem, _SCRIPT)
    assert spec is not None and spec.loader is not None
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)

    # A change to the report's layout changes the figure: render it again with
    # ``uv run python scripts/render_readme_report.py``.
    assert script.render() == _FIGURE.read_text(encoding="utf-8")
