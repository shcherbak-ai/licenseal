# Contributing

## Branch Strategy

- **`dev`** is the default development branch — all pull requests target `dev`
- `main` is reserved for releases

## Setup

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/shcherbak-ai/licenseal.git
cd licenseal
git checkout dev
uv sync
uv run pre-commit install
```

## Pre-commit Hooks

Runs automatically on every commit:

- **ruff** — linting and formatting
- **ty** — type checking ([Astral's type checker](https://docs.astral.sh/ty/))
- **bandit** — security analysis
- **markdownlint** — Markdown linting
- **interrogate** — docstring coverage on `src/`
- **vulture** — dead-code detection on `src/` (min confidence 60)
- **validate-spdx-ids** — verify SPDX IDs referenced in `src/licenseal/analysis/` exist in the vendored canonical list (gated by changes to `spdx.py`, `risk.py`, or the vendored JSON)
- **file hygiene** — `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-toml`
- **commitizen** — commit message format check (commit-msg stage)

Manual run:

```bash
uv run pre-commit run --all-files
```

## Vendored SPDX license list

`src/licenseal/data/spdx-license-ids.json` is a vendored copy of the canonical SPDX identifier list (from [jslicense/spdx-license-ids](https://github.com/jslicense/spdx-license-ids), CC0-1.0). It backs the `validate-spdx-ids` hook and the runtime "is this a recognized SPDX ID?" check.

When SPDX publishes a new license-list release, refresh it in a dedicated commit:

```bash
uv run python scripts/update_spdx_list.py     # re-vendor the JSON from upstream
uv run python scripts/validate_spdx_ids.py    # confirm licenseal's alias / override targets still resolve
```

If `validate_spdx_ids.py` reports a missing ID, an identifier licenseal references was renamed or removed upstream — update the corresponding entry in `analysis/spdx.py` or `analysis/risk.py` to a canonical ID.

## Tests

```bash
uv run pytest
uv run pytest --cov=licenseal --cov-report=term-missing
```

100% test coverage is required. All new code must include tests.

## Code Style

- ruff format, line length 100
- ty (default rules; scoped to `src/` via `[tool.ty.src]`)
- `from __future__ import annotations` in every Python file
- Target: Python 3.10

## Pull Requests

1. Fork and branch from `dev`
2. All tests pass with 100% coverage
3. Pre-commit hooks pass
4. Submit PR to `dev`
