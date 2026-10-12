---
title: "Python"
description: "Python: the files licenseal reads, what counts as a dev dependency, what is off-registry, and what is not evaluated."
---

# Python

What licenseal reads in a Python project. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** PyPI
- **Manifests:** `pyproject.toml` (PEP 621, PEP 735, Poetry), `requirements*.txt`, `setup.cfg`, `setup.py`, `Pipfile`
- **Lockfiles:** `uv.lock`, `poetry.lock`, `Pipfile.lock`

## What is read

- Requirements files are those named `requirements*.txt` or `*-requirements.txt`.
- A `-r` include is followed inside the scanned directory, and a setuptools `file:` directive (`install_requires = file: reqs.in` in `setup.cfg`, `[tool.setuptools.dynamic]` in `pyproject.toml`) is followed like one.
- Extras are followed, from the `uv.lock` edges when there is one.

## Dev dependencies

These count as dev dependencies:

- an extra, a dependency group, or a Poetry group named `dev`, `test`, `tests`, `testing`, `lint`, `ci`, or `docs`, and a dependency group one of those includes;
- a requirements file whose name has one of those words set off by `-` or `_` (`requirements-dev.txt`);
- `Pipfile` `dev-packages`.

Included requirements are dev or production by the file the chain starts from, and those of a `file:` directive by the option that names the file.

## Off-registry dependencies

These are reported as [off-registry dependencies](../concepts/off-registry.md):

- a URL, VCS, or local-path requirement (`name @ <url>`, `git+https://…`, `./pkg.whl`);
- a Poetry `git` / `url` / `path` dependency;
- a `[tool.uv.sources]` `git` / `url` / `path` entry;
- a `Pipfile` VCS or path entry;
- the corresponding sources in `uv.lock`, `poetry.lock`, and `Pipfile.lock`.

## Not evaluated

- PEP 508 environment markers (treated as always true) and `Requires-Python`.
- `-c` constraints files are not read, and a requirements file under another name that nothing includes is not scanned.
- `[tool.uv]` `override-dependencies` and `constraint-dependencies` are not read: see [What is not read](../concepts/off-registry.md#what-is-not-read).

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Alternate registries](../concepts/off-registry.md#alternate-registries), for a package pinned to a Poetry `source` or a uv index
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
