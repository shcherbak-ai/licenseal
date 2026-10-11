"""Resolve license information for Ruby gems from rubygems.org.

Three endpoints carry the load:

* ``GET /api/v2/rubygems/{name}/versions/{version}.json`` — primary, used
  whenever the lockfile pinned a specific version (the typical scan path).
  Returns ``{"licenses": ["MIT"], "source_code_uri": "...", "dependencies":
  {"runtime": [...], "development": [...]}}``.
* ``GET /api/v1/gems/{name}.json`` — for a gem with no pinned version (a
  manifest-only scan). Returns the latest version's metadata in the same
  shape (top-level ``licenses`` array etc.). The latest release is the one
  reported when it satisfies the declared requirement.
* ``GET /api/v1/versions/{name}.json`` — the gem's version list, requested
  only when the latest release is outside the declared requirement, to find
  the highest release inside it, and when an exact pin is not published
  under the spelling it is written in, to find the release it names.

Unlike PHP / Composer, ``Gemfile.lock`` carries no embedded SPDX license
field, so there is **no lockfile-license pre-pass** for Ruby — every dep
either hits the deps.dev batch cache (handled in the CLI dispatch) or
falls through to one of the rubygems.org endpoints here.

A gem with an ``origin`` (a ``GIT`` / ``PATH`` section in Gemfile.lock, a
``git:`` / ``path:`` gem in a Gemfile) is not a rubygems.org gem. The CLI
never passes one to this module.
"""

from __future__ import annotations

import json
import re

import httpx

from licenseal.analysis.spdx import read_license_array
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.resolvers.http import Fetcher, fetch_registry_json, fetch_registry_text
from licenseal.resolvers.version_selection import satisfies, select_version

_RUBYGEMS_REGISTRY_URL = "https://rubygems.org"

# A requirement that is a version and nothing else: ``gem "x", "1.2.3"``.
_BARE_VERSION_RE = re.compile(r"\d+(?:\.[0-9A-Za-z]+)*")


def _rubygems_version_url(name: str, version: str) -> str:
    """Per-version v2 endpoint URL."""
    return f"{_RUBYGEMS_REGISTRY_URL}/api/v2/rubygems/{name}/versions/{version}.json"


def _rubygems_gem_url(name: str) -> str:
    """Latest-version v1 endpoint URL (unpinned fallback)."""
    return f"{_RUBYGEMS_REGISTRY_URL}/api/v1/gems/{name}.json"


def _rubygems_versions_url(name: str) -> str:
    """Version-list v1 endpoint URL (every published version of a gem)."""
    return f"{_RUBYGEMS_REGISTRY_URL}/api/v1/versions/{name}.json"


def _extract_pinned_version(version_constraint: str) -> str | None:
    """Return the exact RubyGems version when the spec is pinned.

    Accepts three pin shapes:

    * ``==X.Y.Z`` — licenseal-internal form emitted by the lockfile parser.
    * ``= X.Y.Z`` — Gem::Requirement's native exact-pin operator, which
      appears in ``dependencies.runtime.requirements`` on the registry
      response. The walker propagates that constraint to children.
    * ``X.Y.Z`` — a bare version, which Gem::Requirement reads as ``=``
      (``gem "x", "1.2.3"`` in a Gemfile).

    Range / wildcard / multi-constraint shapes (``~> 1.2``, ``>= 1.0``,
    ``"~> 1.2", ">= 1.2.3"``) return None. RubyGems versions do not use a
    ``v`` prefix (unlike Packagist's optional decorative ``v``), so no
    prefix-stripping is needed.
    """
    spec = version_constraint.strip()
    if not spec or "," in spec:
        return None
    if _BARE_VERSION_RE.fullmatch(spec):
        return spec
    if spec.startswith("=="):
        candidate = spec[2:].strip()
        if not candidate or " " in candidate:
            return None
        return candidate
    if spec.startswith("="):
        candidate = spec[1:].strip()
        # pragma: no branch — ``=`` form is always one of two outcomes
        if not candidate or " " in candidate:  # pragma: no branch
            return None
        return candidate
    return None


def _license_entries(value: object) -> list[str]:
    """Entries of the registry ``licenses`` field.

    rubygems.org always returns ``licenses`` as an array of strings. A bare
    string is accepted defensively even though the v2/v1 endpoints never
    emit it.
    """
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def _extract_repository_url(entry: dict) -> str:
    """Return the publisher-declared ``source_code_uri``, or "" when absent.

    The homepage is surfaced separately via :func:`_extract_homepage_url`
    into ``LicenseInfo.homepage_url``; the two registry fields stay in
    their own slots rather than one falling back to the other.
    """
    src = entry.get("source_code_uri")
    if isinstance(src, str) and src.strip():
        return src.strip()
    return ""


def _extract_homepage_url(entry: dict) -> str:
    homepage = entry.get("homepage_uri")
    if isinstance(homepage, str) and homepage.strip():
        return homepage.strip()
    return ""


def _resolved_version_from_entry(entry: dict) -> str:
    """v2 endpoint uses ``number``; v1 uses ``version``. Read whichever exists."""
    number = entry.get("number")
    if isinstance(number, str) and number:
        return number
    version = entry.get("version")
    if isinstance(version, str) and version:
        return version
    return ""


def _unknown(dep: Dependency, *, from_registry: bool) -> LicenseInfo:
    return LicenseInfo(
        dependency=dep,
        license_id="UNKNOWN",
        license_raw="",
        from_registry=from_registry,
    )


def _published_versions(name: str, client: httpx.Client, text_fetcher: Fetcher) -> list[str]:
    """Every version number rubygems.org lists for a gem; empty when it lists none.

    The endpoint answers with a JSON array, so it is fetched as text (the
    JSON fetcher takes objects only) and parsed here. One number can be
    listed once per platform; the repeats are harmless to a selection.
    """
    data = text_fetcher(_rubygems_versions_url(name), client)
    text = data.get("text") if data is not None else None
    if not isinstance(text, str):
        return []
    try:
        entries = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(entries, list):
        return []
    return [
        entry["number"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("number"), str)
    ]


def _resolve_pin(
    name: str, spec: str, client: httpx.Client, fetcher: Fetcher, text_fetcher: Fetcher
) -> str | None:
    """The version an exact pin names, as rubygems.org spells it; None when ``spec`` is no pin.

    RubyGems compares versions with trailing zero segments ignored, so
    ``1.2``, ``1.2.0``, and ``1.2.0.0`` are one version, while the API
    answers only for the spelling the gem was published under. A lockfile
    entry (``==X``) is spelled as published and is returned as it is, with
    no request. A pin in a manifest or in another gem's requirements
    (``gem "x", "1.2"``, ``= 1.2``) is asked for as written first, which is
    the request its caller makes next; only when that misses is the gem's
    version list fetched, for the published version equal to the pin.

    A pin no published version equals is returned as written: its lookup
    then finds nothing, and the gem is UNKNOWN. The walker and the license
    resolver both resolve through here.
    """
    pinned = _extract_pinned_version(spec)
    if pinned is None or spec.strip().startswith("=="):
        return pinned
    if isinstance(fetcher(_rubygems_version_url(name, pinned), client), dict):
        return pinned
    published = _published_versions(name, client, text_fetcher)
    return select_version(Ecosystem.RUBY, f"= {pinned}", published) or pinned


def _select_version(
    name: str, spec: str, latest: dict, client: httpx.Client, text_fetcher: Fetcher
) -> str | None:
    """The version an unpinned ``spec`` resolves to, or None when there is none.

    ``latest`` is the gem's latest-release response. No requirement at all is
    that release (an empty string when the response names no version), and
    so is a requirement it satisfies: no further request.
    Only when the latest release is outside the requirement is the gem's
    version list fetched, for the highest release inside it.

    A requirement that cannot be read, or that no published version
    satisfies, resolves to nothing; it never falls back to the latest
    release. The walker and the license resolver both resolve through here.
    """
    newest = _resolved_version_from_entry(latest)
    if not spec.strip():
        return newest
    in_range = satisfies(Ecosystem.RUBY, newest, spec)
    if in_range is None:
        return None
    if in_range:
        return newest
    return select_version(Ecosystem.RUBY, spec, _published_versions(name, client, text_fetcher))


def _license_info(dep: Dependency, data: dict, version: str) -> LicenseInfo:
    """Build the result from one version's metadata (the v1 and v2 shapes agree)."""
    # A gemspec's ``licenses`` array does not say whether its entries are
    # alternatives or all apply, so both readings are kept.
    entries = _license_entries(data.get("licenses"))
    license_id, all_apply_license_id = read_license_array(entries)
    return LicenseInfo(
        dependency=dep,
        license_id=license_id,
        license_raw=", ".join(entries),
        repository_url=_extract_repository_url(data),
        homepage_url=_extract_homepage_url(data),
        resolved_version=_resolved_version_from_entry(data) or version,
        from_registry=True,
        all_apply_license_id=all_apply_license_id,
    )


def resolve_ruby_license(
    dep: Dependency,
    client: httpx.Client,
    *,
    lockfile_license_map: None = None,  # noqa: ARG001 — kept for cross-eco dispatch parity
    fetcher: Fetcher = fetch_registry_json,
    text_fetcher: Fetcher = fetch_registry_text,
) -> LicenseInfo:
    """Resolve license for a Ruby gem via rubygems.org.

    A pinned dep (``==X.Y.Z``, ``= X.Y.Z``, a bare version) hits the v2
    per-version endpoint, under the spelling the gem was published with
    (:func:`_resolve_pin`). An unpinned one is resolved to a version first
    (:func:`_select_version`): the latest release's own response answers
    when that release is the one selected, the per-version endpoint
    otherwise. A requirement that selects no version is UNKNOWN with no
    version.

    ``text_fetcher`` fetches the gem's version list, which is a JSON array.
    """
    name = dep.name
    version = _resolve_pin(name, dep.version_constraint, client, fetcher, text_fetcher)

    if version is None:
        latest = fetcher(_rubygems_gem_url(name), client)
        if not isinstance(latest, dict):
            return _unknown(dep, from_registry=False)
        version = _select_version(name, dep.version_constraint, latest, client, text_fetcher)
        if version is None:
            return _unknown(dep, from_registry=False)
        if version == _resolved_version_from_entry(latest):
            return _license_info(dep, latest, version)

    data = fetcher(_rubygems_version_url(name, version), client)
    if not isinstance(data, dict):
        return _unknown(dep, from_registry=False)
    return _license_info(dep, data, version)


def fetch_rubygems_dependencies(
    name: str,
    version: str,
    client: httpx.Client,
    *,
    parent_depth: int,
    parent_group: DependencyGroup = DependencyGroup.PROD,
    fetcher: Fetcher = fetch_registry_json,
) -> tuple[list[Dependency], bool]:
    """Fetch runtime dependencies of ``name@version`` from rubygems.org.

    Returns ``(children, complete)``. Used by the manifest-only transitive
    walker (no Gemfile.lock present). Reads only the ``dependencies.runtime``
    list — development dependencies aren't followed transitively (same
    posture as PHP / npm / Python).

    ``complete`` is False when the dependency list could not be determined:
    the fetch failed, ``dependencies`` is not an object, its ``runtime`` is
    not a list, or an entry is not an object naming a gem. The entries that
    could be read are returned all the same. A ``dependencies`` or a
    ``runtime`` that is absent or ``null`` declares nothing.
    """
    data = fetcher(_rubygems_version_url(name, version), client)
    if not isinstance(data, dict):
        return [], False
    deps_field = data.get("dependencies")
    if deps_field is None:
        return [], True
    if not isinstance(deps_field, dict):
        return [], False
    runtime = deps_field.get("runtime")
    if runtime is None:
        return [], True
    if not isinstance(runtime, list):
        return [], False
    complete = True
    out: list[Dependency] = []
    seen: set[str] = set()
    for entry in runtime:
        child_name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(child_name, str) or not child_name.strip():
            complete = False
            continue
        key = Ecosystem.RUBY.identity(child_name)
        if key in seen:
            continue
        seen.add(key)
        child_constraint = entry.get("requirements")
        constraint_str = child_constraint.strip() if isinstance(child_constraint, str) else ""
        out.append(
            Dependency(
                name=child_name.strip(),
                version_constraint=constraint_str,
                ecosystem=Ecosystem.RUBY,
                group=parent_group,
                depth=parent_depth + 1,
            )
        )
    return out, complete
