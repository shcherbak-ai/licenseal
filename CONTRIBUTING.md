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
- **deptry** — dependency declaration/import consistency
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

## README links and images

Use relative paths for repository files in `README.md`, and keep images under `assets/`:

```markdown
[Security](SECURITY.md)
[Manual review](USAGE.md#manual-review-file)
![Description of the image](assets/example.svg)
```

For HTML images, use `src="assets/example.png"`. These paths work in local previews
and follow the branch being viewed on GitHub. External links, badges, and GitHub
service pages such as Actions, issues, and security advisories keep absolute URLs.

Give images descriptive alt text and check them at their README display size on light
and dark backgrounds. Label fictional examples as illustrative. Render CLI excerpts
with licenseal, and keep diagrams and captions consistent with the current verdicts,
strict-mode behavior, and transitive-dependency attribution.

The package description comes from [PYPI.md](PYPI.md), selected by `project.readme`
in `pyproject.toml`. Keep it short, with absolute HTTPS links to the current public
documentation. The full README remains the home for screenshots and detailed guidance.

Local builds and the [publish workflow](.github/workflows/publish.yml) both use plain
`uv build`. There is no link conversion or generated README. Update `PYPI.md` when its
brief product description, supported ecosystems, or installation instructions change.

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
