# Registry response fixtures — agent instructions

Instructions for agents adding or modifying registry-response fixtures. See the root `AGENTS.md` for project-wide rules.

Curated JSON response bodies that registries return for specific packages. Each fixture pins a *shape*: a pattern in a registry response that once caused a wrong result (sparse per-version metadata, junk license text, dual classifiers, etc.). Tests in `tests/test_registry_response_fixtures.py` and the `tests/test_resolvers_*.py` files mock the registry URL via `respx`, hand the resolver a synthetic `Dependency`, and assert what the resolver extracts.

Fixtures exist for PyPI, npm, Packagist, RubyGems, and Hex.

## Conventions

- The directory is the package the response came from (`scipy-junk-license/` also names its shape); the test name and the Layout comment say which shape it pins.
- Keep only the fields the resolver reads. For PyPI that is the `info` object with `name`, `version`, `license_expression`, `license`, `classifiers`, `home_page`, `project_urls`.
- One test per shape, named after what it asserts (e.g. `test_python_dateutil_dual_license_falls_through_to_classifier`).

## Two-file fixtures for fallback paths

When the shape is "per-version endpoint is sparse, fall back to project-level," the fixture needs **two** files:

- `{name}/{version}.json` — served from `https://pypi.org/pypi/{name}/{version}/json`
- `{name}/project.json` — served from `https://pypi.org/pypi/{name}/json`

Both URLs must be mocked via `respx` in the same test. `attrs/` and `maturin/` follow this pattern.

## Packagist fixtures are minified

`packagist/{vendor}/{package}.json` is a captured `repo.packagist.org/p2/{vendor}/{package}.json` response in the form the registry serves: a top-level `"minified": "composer/2.0"` marker, and a version list in which every entry after the first holds only the keys that differ from the entry before it (`"__unset"` for a key that entry does not have). Tests in `tests/test_resolvers_packagist.py` serve it via `respx`.

- Keep the marker and the entry order.
- Cut each entry to the keys in `_PACKAGIST_VERSION_KEEP` (`resolvers/http.py`), and nothing else: removing a whole key from every entry leaves the remaining deltas valid.
- Shorten the list only by dropping its tail. An entry depends on every entry before it, so removing one from the middle changes what the later ones mean.
- Do not expand it by hand. A hand-written fixture with every field on every entry does not exercise the expansion.

## Adding a fixture

1. Identify the shape. Capture the registry's actual JSON (for PyPI, `curl https://pypi.org/pypi/{name}/{version}/json`; only the `info` block is parsed).
2. Trim to the fields listed under Conventions above.
3. Add a test, in `tests/test_registry_response_fixtures.py` for PyPI, that:
   - Mocks the relevant URL(s) via `respx.get(...).mock(...)`.
   - Calls `resolve_python_license` against a synthetic `Dependency`.
   - Asserts the expected `license_id`, and any other fields the bug touched (`from_registry`, `resolved_version`, `repository_url`).
4. The `test_all_pypi_fixtures_are_well_formed` guard runs over every JSON file under `pypi/`; new fixtures must parse and contain a non-empty `info.name`.

## Layout

```text
hex/phoenix/1.7.10.json                release endpoint: requirements
hex/phoenix/package.json               package endpoint: meta.licenses, links, releases
npm/react/18.3.1.json                  per-version: license "MIT"
packagist/monolog/monolog.json         minified p2 response: newest 24 versions, kept keys only
pypi/attrs/24.3.0.json                 per-version: sparse, no license metadata
pypi/attrs/project.json                project-level: license_expression "MIT"
pypi/maturin/1.9.4.json                per-version: sparse
pypi/maturin/project.json              project-level: license_expression "MIT OR Apache-2.0"
pypi/python-dateutil/2.9.0.post0.json  "Dual License" + two OSI classifiers
pypi/scipy-junk-license/1.12.0.json    copyright text in license field
rubygems/json/2.7.0.json               per-version: licenses ["Ruby"]
rubygems/rails/7.1.3.json              per-version: licenses ["MIT"], with dependencies
rubygems/rails/latest.json             latest-version endpoint (unpinned gem)
rubygems/sidekiq/7.3.0.json            per-version: licenses ["LGPL-3.0"]
```
