# Contributing

## Branch Strategy

- **`dev`** is the default development branch — all pull requests target `dev`
- `main` is reserved for releases

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/), and [Node.js](https://nodejs.org/) for the development tools that `package.json` lists: the stylesheet of the README preview and the agents' browser. None of them is part of the package.

```bash
git clone https://github.com/shcherbak-ai/licenseal.git
cd licenseal
git checkout dev
uv sync
npm ci
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

## Pre-commit Hooks

Runs automatically on every commit:

- **ruff** — linting and formatting
- **ty** — type checking ([Astral's type checker](https://docs.astral.sh/ty/))
- **deptry** — dependency declaration/import consistency
- **uv lock check** — `uv.lock` matches `pyproject.toml`
- **bandit** — security analysis
- **markdownlint** — Markdown linting
- **interrogate** — docstring coverage on `src/`
- **vulture** — dead-code detection on `src/`
- **validate-spdx-ids** — verify SPDX IDs referenced in `src/licenseal/analysis/` exist in the vendored canonical list
- **file hygiene** — `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-toml`
- **claude hooks tests** — the tests of the Claude Code hook in `.claude/hooks/` and of the settings that start it, with `node --test`
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

## Documentation

The user documentation is a site built from the Markdown pages under `docs/` with [Zensical](https://zensical.org/) (`zensical.toml`), and published to <https://licenseal.shcherbak.ai/> from `main`.

```bash
uv run inv docs-live   # preview at http://localhost:9000, rebuilt when a page changes (--port N for another port)
uv run inv docs        # what CI runs: fails on a broken link or anchor
```

Both are [Invoke](https://www.pyinvoke.org/) tasks in `tasks.py`; `uv run inv --list` lists them. They run Zensical with `uvx`, as a tool at the versions pinned in `.github/docs-constraints.txt`. It is not a dependency of the package.

- Change the page that states a behaviour in the same change as the behaviour. State a fact on one page and link to it from the others.
- Write GitHub-flavoured Markdown, with relative links between pages (`../concepts/verdicts.md`) and call-outs in GitHub's alert syntax (`> [!NOTE]`).
- Indent what belongs to a list item (a nested item, a further paragraph, a code block) by four spaces, and put a blank line before the item that follows such a paragraph or code block. GitHub reads two spaces the same way; the site does not. The same holds for `CHANGELOG.md`, which the site includes.
- A new page goes into the `nav` list of `zensical.toml`, and into a section of the `llms.txt` index in the same file (`[project.plugins.llmstxt.sections]`), at the same place and with the `description` of its front matter; a test fails until the two agree. The build writes that index to the root of the site, <https://licenseal.shcherbak.ai/llms.txt>, for language models and coding agents.
- The site sets no cookie and loads nothing from another host. Do not add a web font, analytics, or an embed, and do not set `repo_url`.

## README links and images

In `README.md`, link to the documentation site for anything it documents, and use relative paths for repository files. Images come from `docs/assets/` (shared with the site) or `assets/` (the README's own):

```markdown
[Contributing](CONTRIBUTING.md)
![Description of the image](docs/assets/example.svg)
```

For HTML images, use `src="docs/assets/example.png"`. These paths work in local previews and follow the branch being viewed on GitHub. External links, badges, and GitHub service pages such as Actions, issues, and security advisories keep absolute URLs.

Give images descriptive alt text and check them at their README display size on light and dark backgrounds. Label fictional examples as illustrative. Render CLI excerpts with licenseal, and keep diagrams and captions consistent with the current verdicts, strict-mode behavior, and transitive-dependency attribution.

- The README opens centred, in this order: the wordmark, the description as the heading, the tagline, the badges, a row of links to the main documentation pages, and the figure. A badge is a shields.io one, `flat-square` with `labelColor=18181b` and the wordmark's violet (`color=a78bfa`); the CI badge keeps its status colour.
- `docs/assets/licenseal-report.svg` is licenseal's own output for an illustrative project. Render it with `uv run python scripts/render_readme_report.py`; a test fails while the committed file is not what the script renders. It is animated with CSS: the command is typed and the report follows a line at a time, once, ending on the whole figure, and `prefers-reduced-motion` switches the animation off.
- `docs/assets/licenseal-wordmark.svg` is pixel art, 104 by 20 pixels. Show it at a whole multiple of that size (`width="416"`), so its pixels stay square.
- `assets/contextgem-wordmark.svg` and `assets/tethered-wordmark.svg` are the sibling projects' pixel names, drawn at twice their size in transparent images of one size (336 by 80), so the two share a baseline. Show them at that width.
- `assets/licenseal-separator.svg` is the pixel rule between the README's main parts, 223 by 11 pixels. Show it at twice that size (`width="446"`) with an empty `alt`, and keep section headings as text.
- The figures (`licenseal-report.svg`, `licenseal-how-it-works.svg`, `resolution-flow.svg`, `data-flow.svg`) are drawn on their own dark ground, so one file serves the site and both GitHub themes. Draw a new one in their style: hairlines, monospace labels, grey, amber only for what licenseal catches.
- `social/github-social-preview.png` is the picture a link to the repository is shown with on other sites. It is drawn in the SVG beside it as the game's share card from shcherbak.ai: the duck at work among the crates in pixel art, and on paper the wordmark, the README's heading, the tagline's claims, and the company's name. When one of those changes, change the SVG with it, render the picture again with `uv run inv social-preview` (the task needs Chrome, Edge, or Chromium; it also writes `docs/assets/social-preview.png`, the picture a link to the documentation site shows), and say so in the pull request: GitHub reads no file for the social preview, so a maintainer uploads the picture in the repository's settings.

Look at a change as GitHub will show it before pushing it. `uv run inv readme-preview` serves `README.md` in GitHub's light theme at <http://127.0.0.1:9100/> and in its dark theme at <http://127.0.0.1:9101/> (`--port N` serves them at N and N+1):

- The HTML is what GitHub's Markdown API returns for the file, so what GitHub removes from a README is removed here too.
- The look comes from github-markdown-css, in GitHub's colours, each page in its theme whatever the browser is set to. The column is as wide as GitHub's at 1280 pixels and wider, and below 768.
- A reload sends the README to GitHub again when it has changed, once for both pages. GitHub allows 60 of those an hour without a token.

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
