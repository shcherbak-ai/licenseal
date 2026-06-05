# Registry response fixtures — agent instructions

Instructions for agents adding or modifying registry-response fixtures. See
the root `AGENTS.md` for project-wide rules.

Curated JSON response bodies that registries return for specific edge-case
packages. Each fixture is named after the bug shape it locks in (sparse
per-version metadata, junk license text, dual classifiers, etc.). Tests in
`tests/test_registry_response_fixtures.py` mock the registry URL via
`respx`, hand the resolver a synthetic `Dependency`, and assert the
license the resolver extracts.

Currently PyPI-only. Add `crates_io/` or `npm/` subtrees alongside `pypi/`
when those resolvers grow comparable bug-shape fixtures.

## Conventions

- Name fixtures by the shape they pin, not by the package they came from.
  `attrs/24.3.0.json` is really a fixture for "PyPI sparse per-version
  metadata" — attrs is the carrier, not the subject. If attrs were
  unpublished tomorrow the fixture would still serve its purpose under
  any other package exhibiting the same shape.
- Keep only the fields the resolver actually reads: `name`, `version`,
  `license_expression`, `license`, `classifiers`, `home_page`,
  `project_urls`. Drop the rest of the PyPI envelope to keep diffs
  legible.
- One test per shape, named after what it asserts (e.g.
  `test_python_dateutil_dual_license_falls_through_to_classifier`).

## Two-file fixtures for fallback paths

When the bug shape is "per-version endpoint is sparse, fall back to
project-level," the fixture needs **two** files:

- `{name}/{version}.json` — served from `https://pypi.org/pypi/{name}/{version}/json`
- `{name}/project.json` — served from `https://pypi.org/pypi/{name}/json`

Both URLs must be mocked via `respx` in the same test. `attrs/` and
`maturin/` follow this pattern.

## Adding a fixture

1. Identify the bug or shape. Capture the registry's actual JSON
   (`curl https://pypi.org/pypi/{name}/{version}/json` is enough — only
   the `info` block is parsed).
2. Trim to the fields listed under Conventions above.
3. Add a test in `tests/test_registry_response_fixtures.py` that:
   - Mocks the relevant URL(s) via `respx.get(...).mock(...)`.
   - Calls `resolve_python_license` against a synthetic `Dependency`.
   - Asserts the expected `license_id`, and any other fields the bug
     touched (`from_registry`, `resolved_version`, `repository_url`).
4. The `test_all_pypi_fixtures_are_well_formed` guard runs over every
   JSON file under `pypi/`; new fixtures must parse and contain a
   non-empty `info.name`.

## Layout

```text
registry-responses/
└── pypi/
    ├── attrs/
    │   ├── 24.3.0.json          per-version: sparse, no license metadata
    │   └── project.json          project-level: license_expression "MIT"
    ├── maturin/
    │   ├── 1.9.4.json            per-version: sparse
    │   └── project.json          project-level: license_expression "MIT OR Apache-2.0"
    ├── python-dateutil/
    │   └── 2.9.0.post0.json      "Dual License" + two OSI classifiers
    └── scipy-junk-license/
        └── 1.12.0.json           copyright text in license field
```
