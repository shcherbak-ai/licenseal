# Contributing

## Branch Strategy

- **`dev`** is the default development branch — all pull requests target `dev`
- `main` is reserved for releases

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/shcherbak-ai/licenseal.git
cd licenseal
git checkout dev
uv sync
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

## Pre-commit Hooks

Runs automatically on every commit:

- **ruff** — linting and formatting
- **ty** — type checking ([Astral's type checker](https://docs.astral.sh/ty/))
- **deptry** — dependency declaration/import consistency
- **bandit** — security analysis
- **markdownlint** — Markdown linting
- **interrogate** — docstring coverage on `src/`
- **vulture** — dead-code detection on `src/`
- **validate-spdx-ids** — verify SPDX IDs referenced in `src/licenseal/analysis/` exist in the vendored canonical list
- **file hygiene** — `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-toml`
- **commitizen** — commit messages follow Conventional Commits (`fix: …`, `feat: …`)

Manual run:

```bash
uv run pre-commit run --all-files
```

## Tests

```bash
uv run pytest -n 8 --cov=licenseal --cov-report=term-missing
```

100% test coverage is required. All new code must include tests.

## Code Style

- ruff format, line length 100
- ty (default rules; scoped to `src/` via `[tool.ty.src]`)
- `from __future__ import annotations` in every Python file
- The rules a change must keep are in [AGENTS.md](AGENTS.md).

## Pull Requests

1. Fork and branch from `dev`
2. All tests pass with 100% coverage
3. Pre-commit hooks pass
4. Submit PR to `dev`

## README links and images

Use relative paths for repository files in `README.md`, and keep images under `assets/`:

```markdown
[Security](SECURITY.md)
[Manual review](USAGE.md#manual-review-file)
![Description of the image](assets/example.svg)
```

For HTML images, use `src="assets/example.png"`. These paths work in local previews and follow the branch being viewed on GitHub. External links, badges, and GitHub service pages such as Actions, issues, and security advisories keep absolute URLs.

Give images descriptive alt text and check them at their README display size on light and dark backgrounds. Label fictional examples as illustrative. Render CLI excerpts with licenseal, and keep diagrams and captions consistent with the current verdicts, strict-mode behavior, and transitive-dependency attribution.

- `assets/licenseal-report.svg` is licenseal's own output for an illustrative project. Render it with `uv run python scripts/render_readme_report.py`; a test fails while the committed file is not what the script renders.
- `assets/licenseal-wordmark.svg` is pixel art, 104 by 20 pixels. Show it at a whole multiple of that size (`width="416"`), so its pixels stay square.
- The figures are drawn on their own dark ground, so one file serves both GitHub themes.

The package description is [PYPI.md](PYPI.md) (`project.readme` in `pyproject.toml`). Keep it short, use absolute HTTPS links, and update it when the summary, the ecosystems, or the install commands change. Screenshots and the overview stay in the README.

## Vendored SPDX license list

`src/licenseal/data/spdx-license-ids.json` is a vendored copy of the canonical SPDX identifier list (from [jslicense/spdx-license-ids](https://github.com/jslicense/spdx-license-ids), CC0-1.0). It backs the `validate-spdx-ids` hook and the runtime "is this a recognized SPDX ID?" check.

When SPDX publishes a new license-list release, refresh it in a dedicated commit:

```bash
uv run python scripts/update_spdx_list.py     # re-vendor the JSON from upstream
uv run python scripts/validate_spdx_ids.py    # confirm licenseal's alias / override targets still resolve
```

- If `validate_spdx_ids.py` reports a missing ID, an identifier licenseal references was renamed or removed upstream: update the corresponding entry in `analysis/spdx.py` or `analysis/risk.py` to a canonical ID.
- An ID that became deprecated goes into `DEPRECATED_SPDX_IDS` in `analysis/risk.py`, or a review entry that names it is rejected.
