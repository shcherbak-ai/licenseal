"""Version-selection helpers for range-aware registry resolution.

Two layers. The first reads constraints: :func:`satisfies` tells whether a
version meets a constraint the way the constraint's own ecosystem reads both,
for all ten ecosystems, and :func:`is_prerelease` whether a version is a
prerelease. The second picks versions: :func:`select_version` returns the
published version a constraint resolves to, and the per-registry helpers
above it (PyPI, npm) do the same against the response shapes those
registries serve.
"""

from __future__ import annotations

import functools
import operator
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import Version as PackagingVersion
from semantic_version import NpmSpec
from semantic_version import Version as SemVer

from licenseal.models import Ecosystem

_UNSUPPORTED_NPM_PREFIXES = (
    "workspace:",
    "file:",
    "link:",
    "npm:",
    "git+",
    "git://",
    "http://",
    "https://",
)
_UNSUPPORTED_PYTHON_MARKERS = (" @ ", "://", "git+")

# Real npm semver accepts whitespace between comparison operators and version
# numbers (`">= 1.0.0 < 2.0.0"`), and multiple spaces between AND-combined
# range terms; the `semantic_version` library's NpmSpec accepts neither.
# Tighten operators against their version and collapse runs of whitespace to
# a single space so we accept what registries publish.
_NPM_OPERATOR_SPACE_RE = re.compile(r"(<=|>=|<|>|=|~|\^)\s+(?=\d|[xX*])")
_NPM_RUN_OF_WHITESPACE_RE = re.compile(r"\s+")


def select_python_version(version_constraint: str, published_versions: list[str]) -> str | None:
    """Select the highest published Python version that matches the constraint."""
    spec = version_constraint.strip()
    if not spec or any(marker in spec for marker in _UNSUPPORTED_PYTHON_MARKERS):
        return None

    # ``ValueError`` below covers ``InvalidVersion`` / ``InvalidSpecifier`` and
    # the plain ``ValueError`` a release segment raises when it has more digits
    # than the interpreter converts to an integer.
    candidates: dict[PackagingVersion, str] = {}
    for raw_version in published_versions:
        try:
            parsed = PackagingVersion(raw_version)
        except ValueError:
            continue
        candidates[parsed] = raw_version

    if not candidates:
        return None
    try:
        allowed = list(SpecifierSet(spec).filter(candidates, prereleases=None))
    except ValueError:
        return None
    if not allowed:
        return None
    return candidates[max(allowed)]


def _npm_spec(spec: str) -> NpmSpec | None:
    """Parse an npm range, or None when it is not one."""
    spec = _NPM_OPERATOR_SPACE_RE.sub(r"\1", spec)
    spec = _NPM_RUN_OF_WHITESPACE_RE.sub(" ", spec)
    try:
        return NpmSpec(spec)
    except ValueError:
        return None


def select_npm_version(version_constraint: str, published_versions: list[str]) -> str | None:
    """Select the highest published npm version that matches the constraint."""
    spec = version_constraint.strip()
    if not spec or spec.startswith(_UNSUPPORTED_NPM_PREFIXES):
        return None

    npm_spec = _npm_spec(spec)
    if npm_spec is None:
        return None

    candidates: list[tuple[SemVer, str]] = []
    for raw_version in published_versions:
        try:
            parsed = SemVer(raw_version.lstrip("v"))
        except ValueError:
            continue
        if npm_spec.match(parsed):
            candidates.append((parsed, raw_version))

    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def resolve_npm_spec(package_data: dict, version_constraint: str) -> str:
    """Resolve an npm version spec against the registry's ``/{name}`` response.

    Handles npm dist-tags (``"latest"``, ``"next"``, ``"beta"``, or any custom
    tag the publisher set) by consulting the response's ``dist-tags`` field
    first. Falls back to semver-range resolution via :func:`select_npm_version`
    against the ``versions`` map. Returns the resolved version string, or ""
    if no match.
    """
    spec = version_constraint.strip()
    dist_tags = package_data.get("dist-tags", {})
    if isinstance(dist_tags, dict):
        tag_version = dist_tags.get(spec)
        if isinstance(tag_version, str) and tag_version:
            return tag_version
    versions = package_data.get("versions", {})
    version_map = versions if isinstance(versions, dict) else {}
    return select_npm_version(spec, list(version_map)) or ""


# --- Range matching ------------------------------------------------------
#
# Each ecosystem reads version strings and constraint strings its own way. A
# grammar turns a version into a value that orders the way the ecosystem
# orders versions, and a constraint into a predicate over those values.
#
# A prerelease satisfies a constraint only where the ecosystem's resolver
# would consider it: when the constraint itself names a prerelease (PEP 440,
# npm, Cargo, RubyGems, Hex, NuGet), or reaches down to its stability
# (Composer). Maven ranges and Go and R requirements are plain comparisons.

_Matcher = Callable[[Any], bool]

_COMPARISONS: dict[str, Callable[[Any, Any], bool]] = {
    "=": operator.eq,
    "==": operator.eq,
    "!=": operator.ne,
    "<>": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}


@dataclass(frozen=True)
class _Grammar:
    """How one ecosystem reads versions and constraints.

    ``version`` parses a version string into an orderable value, or None when
    it is not a version of this ecosystem. ``prerelease`` tells whether such a
    value is a prerelease. ``matcher`` parses a non-empty constraint into a
    predicate over parsed versions, or None when the grammar does not read it.
    """

    version: Callable[[str], Any | None]
    prerelease: Callable[[Any], bool]
    matcher: Callable[[str], _Matcher | None]


def _compare(op: str, bound: Any) -> _Matcher:
    """Predicate ``version <op> bound``."""
    compare = _COMPARISONS[op]
    return lambda version: compare(version, bound)


def _any_of(alternatives: list[list[_Matcher]]) -> _Matcher:
    """Predicate true when every test of at least one alternative is."""
    return lambda version: any(all(test(version) for test in tests) for tests in alternatives)


# PEP 440 (Python).


def _python_version(text: str) -> PackagingVersion | None:
    try:
        return PackagingVersion(text)
    except ValueError:
        # ``InvalidVersion``, or a release segment with more digits than the
        # interpreter converts to an integer.
        return None


def _python_is_prerelease(version: PackagingVersion) -> bool:
    return version.is_prerelease


def _python_matcher(constraint: str) -> _Matcher | None:
    spec = constraint.strip()
    if any(marker in spec for marker in _UNSUPPORTED_PYTHON_MARKERS):
        return None
    if spec[0].isdigit():
        # A bare version pins it.
        spec = f"=={spec}"
    try:
        specifier = SpecifierSet(spec)
    except ValueError:
        return None
    prereleases = bool(specifier.prereleases)
    return lambda version: specifier.contains(version, prereleases=prereleases)


# Semantic Versioning: npm, Cargo, Hex, Go.


def _semver(text: str) -> SemVer | None:
    """Parse strict semver, without its build metadata: it never orders versions."""
    try:
        return SemVer(text).truncate("prerelease")
    except ValueError:
        return None


def _semver_is_prerelease(version: SemVer) -> bool:
    return bool(version.prerelease)


def _npm_version(text: str) -> SemVer | None:
    return _semver(text.removeprefix("v"))


def _npm_matcher(constraint: str) -> _Matcher | None:
    spec = constraint.strip()
    if spec.startswith(_UNSUPPORTED_NPM_PREFIXES):
        return None
    # ``==1.2.3`` is how a lockfile entry is written here: an exact version.
    npm_spec = _npm_spec(spec.removeprefix("=="))
    return None if npm_spec is None else npm_spec.match


def _cargo_matcher(constraint: str) -> _Matcher | None:
    """Cargo requirements: comma-separated comparators, a bare version is a caret."""
    spec = constraint.strip().removeprefix("==")
    if "||" in spec:
        return None
    comparators: list[str] = []
    for raw in spec.split(","):
        comparator = _NPM_OPERATOR_SPACE_RE.sub(r"\1", raw.strip())
        if len(comparator.split()) != 1:
            return None
        if comparator[0].isdigit() and "*" not in comparator:
            comparator = f"^{comparator}"
        comparators.append(comparator)
    npm_spec = _npm_spec(" ".join(comparators))
    return None if npm_spec is None else npm_spec.match


_HEX_COMPARATOR_RE = re.compile(
    r"(==|!=|>=|<=|~>|>|<)?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)


def _hex_matcher(constraint: str) -> _Matcher | None:
    """Elixir requirements: comparators joined by ``and`` / ``or``; bare means ``==``."""
    names_prerelease = False
    alternatives: list[list[_Matcher]] = []
    for alternative in re.split(r"\s+or\s+", constraint.strip()):
        tests: list[_Matcher] = []
        for raw in re.split(r"\s+and\s+", alternative):
            match = _HEX_COMPARATOR_RE.fullmatch(raw.strip())
            if match is None:
                return None
            op, major, minor, patch, prerelease = match.groups()
            bound = _semver(f"{major}.{minor or 0}.{patch or 0}{prerelease or ''}")
            # ``~>`` needs a minor to say which segment may grow.
            if bound is None or (op == "~>" and minor is None):
                return None
            names_prerelease = names_prerelease or bool(bound.prerelease)
            if op != "~>":
                tests.append(_compare(op or "==", bound))
            elif patch is None:
                tests.append(lambda v, b=bound: v >= b and v.major == b.major)
            else:
                tests.append(lambda v, b=bound: v >= b and (v.major, v.minor) == (b.major, b.minor))
        alternatives.append(tests)
    in_range = _any_of(alternatives)
    return lambda version: (names_prerelease or not version.prerelease) and in_range(version)


def _go_version(text: str) -> SemVer | None:
    text = text.strip()
    return _semver(text[1:].removesuffix("+incompatible")) if text.startswith("v") else None


def _go_matcher(constraint: str) -> _Matcher | None:
    """A ``go.mod`` requirement is a minimum: minimal version selection may raise it."""
    minimum = _go_version(constraint.strip().removeprefix("=="))
    return None if minimum is None else _compare(">=", minimum)


# RubyGems.

_GEM_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
_GEM_SEGMENT_RE = re.compile(r"[0-9]+|[A-Za-z]+")
_GEM_REQUIREMENT_RE = re.compile(r"(==|=|!=|>=|<=|~>|>|<)?\s*(\S+)")

_GemSegments = tuple["int | str", ...]


def _gem_segments(text: str) -> _GemSegments | None:
    """Split a gem version into its numeric and letter segments."""
    text = text.strip()
    if not _GEM_VERSION_RE.fullmatch(text):
        return None
    # RubyGems reads ``1.0-rc1`` as ``1.0.pre.rc1``.
    found = _GEM_SEGMENT_RE.findall(text.replace("-", ".pre."))
    return tuple(int(part) if part.isdigit() else part for part in found)


def _gem_release_length(segments: _GemSegments) -> int:
    """How many leading segments are numeric: the release part."""
    return next((i for i, s in enumerate(segments) if isinstance(s, str)), len(segments))


def _gem_canonical(segments: _GemSegments) -> _GemSegments:
    """Drop the zeros that end the release part and the prerelease part."""
    split = _gem_release_length(segments)
    release, prerelease = list(segments[:split]), list(segments[split:])
    for part in (release, prerelease):
        while part and part[-1] == 0:
            part.pop()
    return (*release, *prerelease)


def _gem_cmp(left: _GemSegments, right: _GemSegments) -> int:
    """Order two canonical gem versions; a letter segment sorts below a number."""
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        if a == b:
            continue
        if isinstance(a, str) != isinstance(b, str):
            return -1 if isinstance(a, str) else 1
        return -1 if a < b else 1  # ty: ignore[unsupported-operator]
    return 0


_gem_key = functools.cmp_to_key(_gem_cmp)


def _gem_version(text: str) -> Any | None:
    segments = _gem_segments(text)
    return None if segments is None else _gem_key(_gem_canonical(segments))


def _gem_is_prerelease(version: Any) -> bool:
    return _gem_release_length(version.obj) < len(version.obj)


def _gem_release(version: Any) -> Any:
    """The version without its prerelease part."""
    segments = version.obj
    return _gem_key(_gem_canonical(segments[: _gem_release_length(segments)]))


def _gem_pessimistic(segments: _GemSegments) -> _Matcher:
    """``~> X``: at least ``X``, below its bump (``5.3.1`` up to ``5.4``, ``5`` up to ``6``)."""
    bound = _gem_key(_gem_canonical(segments))
    release = list(segments[: _gem_release_length(segments)])
    if len(release) > 1:
        release.pop()
    release[-1] += 1  # ty: ignore[unsupported-operator]
    upper = _gem_key(_gem_canonical(tuple(release)))
    # The release of the candidate is compared, so that a prerelease of the
    # bump itself stays out.
    return lambda version: version >= bound and _gem_release(version) < upper


def _gem_matcher(constraint: str) -> _Matcher | None:
    """``Gem::Requirement``: comma-separated, a bare version means ``=``."""
    names_prerelease = False
    tests: list[_Matcher] = []
    for raw in constraint.split(","):
        match = _GEM_REQUIREMENT_RE.fullmatch(raw.strip())
        segments = _gem_segments(match.group(2)) if match else None
        if match is None or segments is None:
            return None
        bound = _gem_key(_gem_canonical(segments))
        names_prerelease = names_prerelease or _gem_is_prerelease(bound)
        if match.group(1) == "~>":
            tests.append(_gem_pessimistic(segments))
        else:
            tests.append(_compare(match.group(1) or "=", bound))
    # As in dependency resolution: a prerelease is a candidate only when the
    # requirement names one.
    return lambda version: (
        (names_prerelease or not _gem_is_prerelease(version))
        and all(test(version) for test in tests)
    )


# Composer.

_COMPOSER_STABILITY = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "stable": 4,
    "patch": 5,
    "pl": 5,
    "p": 5,
}
_COMPOSER_STABLE = _COMPOSER_STABILITY["stable"]
_COMPOSER_STABILITY_FLAGS = ("dev", "alpha", "beta", "rc", "stable")
_COMPOSER_OPERATORS = ("<=", ">=", "<>", "!=", "==", "<", ">", "=", "^", "~")
_COMPOSER_VERSION_RE = re.compile(
    r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p|dev)[._-]?(\d*))?"
    r"(?:\+[0-9A-Za-z.-]+)?",
    re.IGNORECASE,
)
_COMPOSER_WILDCARD_RE = re.compile(r"v?((?:\d+\.){0,3})[*x]", re.IGNORECASE)
_COMPOSER_OPERATOR_SPACE_RE = re.compile(r"(<=|>=|<>|!=|==|<|>|=|\^|~)\s+")
_COMPOSER_HYPHEN_RE = re.compile(r"(\S+)\s+-\s+(\S+)")

# Four numeric segments, then the stability rank and its number.
_ComposerVersion = tuple[int, int, int, int, int, int]
# What one comparator contributes: its tests, and the least stable version it names.
_ComposerAtom = tuple[list[_Matcher], int]


def _composer_parse(text: str) -> tuple[_ComposerVersion, int] | None:
    """Parse a Composer version; also return how many numeric segments it states."""
    match = _COMPOSER_VERSION_RE.fullmatch(text.strip())
    if match is None:
        return None
    numbers = [int(part) for part in match.group(1, 2, 3, 4) if part is not None]
    stability = _COMPOSER_STABILITY[(match.group(5) or "stable").lower()]
    return _composer_build(numbers, stability, int(match.group(6) or 0)), len(numbers)


def _composer_build(numbers: Iterable[int], stability: int, number: int) -> _ComposerVersion:
    major, minor, patch, fourth = (*numbers, 0, 0, 0, 0)[:4]
    return (major, minor, patch, fourth, stability, number)


def composer_version(text: str) -> _ComposerVersion | None:
    """Parse a Composer version (``1.2.3``, ``v2.0.0-beta1``); None for a branch."""
    parsed = _composer_parse(text)
    return None if parsed is None else parsed[0]


def _composer_is_prerelease(version: _ComposerVersion) -> bool:
    return version[4] < _COMPOSER_STABLE


def _composer_floor(numbers: Iterable[int]) -> _ComposerVersion:
    """The lowest version with these leading segments: its ``-dev`` build."""
    return _composer_build(numbers, 0, 0)


def _composer_bumped(numbers: list[int], index: int) -> _ComposerVersion:
    """Exclusive upper bound: segment ``index`` raised by one, the rest zeroed."""
    return _composer_floor([*numbers[:index], numbers[index] + 1])


def _composer_atom(atom: str) -> _ComposerAtom | None:
    """Read one comparator: a wildcard, ``^`` / ``~``, a comparison, or a bare version."""
    wildcard = _COMPOSER_WILDCARD_RE.fullmatch(atom)
    if wildcard is not None:
        prefix = [int(part) for part in wildcard.group(1).split(".") if part]
        if not prefix:
            return [], _COMPOSER_STABLE
        upper = _composer_bumped(prefix, len(prefix) - 1)
        return [_compare(">=", _composer_floor(prefix)), _compare("<", upper)], _COMPOSER_STABLE
    op = next((o for o in _COMPOSER_OPERATORS if atom.startswith(o)), "")
    parsed = _composer_parse(atom[len(op) :])
    if parsed is None:
        return None
    version, stated = parsed
    numbers = list(version[:stated])
    named = min(version[4], _COMPOSER_STABLE)
    # A bound that names a stable version stands for its lowest build, which
    # is how ``>=1.0`` admits and ``<2.0`` excludes the prereleases of each.
    edge = _composer_floor(version[:4]) if version[4] == _COMPOSER_STABLE else version
    if op == "^":
        # The first non-zero segment may not change.
        index = min(next((i for i, n in enumerate(numbers) if n), stated - 1), 2)
        return [_compare(">=", edge), _compare("<", _composer_bumped(numbers, index))], named
    if op == "~":
        # The last stated segment may grow.
        upper = _composer_bumped(numbers, max(stated - 2, 0))
        return [_compare(">=", edge), _compare("<", upper)], named
    if op in (">=", "<"):
        return [_compare(op, edge)], named
    return [_compare(op or "==", version)], named


def _composer_hyphen(low: str, high: str) -> _ComposerAtom | None:
    """``1.0 - 2.0``: inclusive, a partial upper bound covering all it prefixes."""
    lower, upper = _composer_parse(low), _composer_parse(high)
    if lower is None or upper is None:
        return None
    tests = [_compare(">=", _composer_floor(lower[0][:4]))]
    if upper[1] < 3:
        tests.append(_compare("<", _composer_bumped(list(upper[0][: upper[1]]), upper[1] - 1)))
    else:
        tests.append(_compare("<=", upper[0]))
    return tests, min(lower[0][4], upper[0][4], _COMPOSER_STABLE)


def _composer_matcher(constraint: str) -> _Matcher | None:
    """Composer constraints: space or comma is AND, ``|`` / ``||`` is OR."""
    floor = _COMPOSER_STABLE
    alternatives: list[list[_Matcher]] = []
    for alternative in re.split(r"\s*\|\|?\s*", constraint.strip()):
        text = _COMPOSER_OPERATOR_SPACE_RE.sub(r"\1", alternative.replace(",", " "))
        atoms = [_composer_hyphen(low, high) for low, high in _COMPOSER_HYPHEN_RE.findall(text)]
        for atom in _COMPOSER_HYPHEN_RE.sub(" ", text).split():
            version, _, flag = atom.partition("@")
            if flag:
                if flag.lower() not in _COMPOSER_STABILITY_FLAGS:
                    return None
                floor = min(floor, _COMPOSER_STABILITY[flag.lower()])
            atoms.append(_composer_atom(version or "*"))
        tests: list[_Matcher] = []
        for parsed in atoms:
            if parsed is None:
                return None
            tests.extend(parsed[0])
            floor = min(floor, parsed[1])
        if not atoms:
            return None
        alternatives.append(tests)
    in_range = _any_of(alternatives)
    # The stability a version must reach: what an ``@flag`` says, else that of
    # the least stable version the constraint names, else stable.
    return lambda version: version[4] >= floor and in_range(version)


# NuGet.

_NUGET_VERSION_RE = re.compile(
    r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?"
)
_NUGET_FLOATING_RE = re.compile(r"((?:\d+\.){0,3})\*(-\*)?")
_NUGET_INTERVAL_RE = re.compile(r"([\[(])\s*([^,\s]*)\s*(?:(,)\s*([^,\s]*)\s*)?([\])])")

# Four numeric segments, then ``(1,)`` for a release or ``(0, identifiers)``
# for a prerelease, so that a release sorts above its own prereleases.
_NugetVersion = tuple[Any, ...]


def _nuget_version(text: str) -> _NugetVersion | None:
    match = _NUGET_VERSION_RE.fullmatch(text.strip())
    if match is None:
        return None
    numbers = tuple(int(part or 0) for part in match.group(1, 2, 3, 4))
    label = match.group(5)
    if label is None:
        return (*numbers, (1,))
    # SemVer 2 precedence: a numeric identifier sorts below a textual one.
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part.lower()) for part in label.split(".")
    )
    return (*numbers, (0, identifiers))


def _nuget_is_prerelease(version: _NugetVersion) -> bool:
    return version[4][0] == 0


@dataclass(frozen=True)
class NugetRange:
    """A parsed NuGet version range.

    ``minimum`` is the text of an inclusive lower bound that lies inside the
    range: the version NuGet restores when it is published. It is the whole
    of a bare version or of ``[1.2.3]`` and the lower end of ``[1.0,2.0)``,
    and is empty when the range has no such bound (``(1.0,)``, ``(,2.0]``) or
    floats (``1.*``). ``exact`` tells a range that names one version from one
    that bounds several. A ``floating`` range resolves to its highest match;
    any other one to its lowest.
    """

    matches: _Matcher
    minimum: str = ""
    exact: bool = False
    floating: bool = False


def _nuget_bounded(bounds: list[tuple[str, _NugetVersion]]) -> _Matcher:
    """Predicate for a set of bounds; a prerelease needs a bound that names one."""
    names_prerelease = any(_nuget_is_prerelease(bound) for _, bound in bounds)
    return lambda version: (
        (names_prerelease or not _nuget_is_prerelease(version))
        and all(_COMPARISONS[op](version, bound) for op, bound in bounds)
    )


def parse_nuget_range(constraint: str) -> NugetRange | None:
    """Parse a NuGet range: a bare minimum, interval notation, or a floating version."""
    spec = constraint.strip()
    if spec.startswith("=="):
        # How a lockfile entry is written here: the one-version range.
        spec = f"[{spec[2:].strip()}]"
    floating = _NUGET_FLOATING_RE.fullmatch(spec)
    if floating is not None:
        prefix = tuple(int(part) for part in floating.group(1).split(".") if part)
        prereleases = floating.group(2) is not None
        return NugetRange(
            matches=lambda v: (
                v[: len(prefix)] == prefix and (prereleases or not _nuget_is_prerelease(v))
            ),
            floating=True,
        )
    interval = _NUGET_INTERVAL_RE.fullmatch(spec)
    if interval is None:
        # A bare version is an inclusive minimum, and the version restored.
        minimum = _nuget_version(spec)
        if minimum is None:
            return None
        return NugetRange(matches=_nuget_bounded([(">=", minimum)]), minimum=spec, exact=True)
    opening, low, comma, high, closing = interval.groups()
    if comma is None:
        # ``[1.2.3]`` is the one-version range; ``(1.2.3)`` is not a range.
        only = _nuget_version(low)
        if only is None or (opening, closing) != ("[", "]"):
            return None
        return NugetRange(matches=_nuget_bounded([("==", only)]), minimum=low, exact=True)
    bounds: list[tuple[str, _NugetVersion]] = []
    for text, op in (
        (low, ">=" if opening == "[" else ">"),
        (high, "<=" if closing == "]" else "<"),
    ):
        if text:
            bound = _nuget_version(text)
            if bound is None:
                return None
            bounds.append((op, bound))
    if not bounds:
        return None
    # An inclusive lower bound that its own range excludes (``[2.0,1.0]``) is
    # not a version to restore.
    inclusive = (
        bool(low)
        and opening == "["
        and all(_COMPARISONS[op](bounds[0][1], bound) for op, bound in bounds)
    )
    return NugetRange(matches=_nuget_bounded(bounds), minimum=low if inclusive else "")


def _nuget_matcher(constraint: str) -> _Matcher | None:
    parsed = parse_nuget_range(constraint)
    return None if parsed is None else parsed.matches


# Maven and Gradle.

_MAVEN_TOKEN_RE = re.compile(r"\d+|[a-z]+")
_MAVEN_NOT_A_VERSION_RE = re.compile(r"[\s$,()\[\]]")
_MAVEN_RELEASE_RANK = 6
_MAVEN_QUALIFIER_RANKS = {
    "alpha": 1,
    "beta": 2,
    "milestone": 3,
    "rc": 4,
    "cr": 4,
    "snapshot": 5,
    "ga": _MAVEN_RELEASE_RANK,
    "final": _MAVEN_RELEASE_RANK,
    "release": _MAVEN_RELEASE_RANK,
    "sp": 7,
}
_MAVEN_SHORT_QUALIFIERS = {"a": "alpha", "b": "beta", "m": "milestone"}
# Qualifiers Maven orders after a release and publishers use before one.
_MAVEN_PRERELEASE_WORDS = frozenset({"dev", "pre", "preview", "eap", "ea", "nightly", "canary"})
_MAVEN_RANGE = r"[\[(]\s*[^,\[\]()\s]*\s*(?:,\s*[^,\[\]()\s]*\s*)?[\])]"
_MAVEN_RANGE_RE = re.compile(r"([\[(])\s*([^,\[\]()\s]*)\s*(?:(,)\s*([^,\[\]()\s]*)\s*)?([\])])")
_MAVEN_RANGE_SET_RE = re.compile(rf"{_MAVEN_RANGE}(?:\s*,\s*{_MAVEN_RANGE})*")

_MavenTokens = tuple["int | str", ...]


def _maven_tokens(text: str) -> _MavenTokens | None:
    """Split a Maven version into numbers and lowercased qualifiers."""
    text = text.strip().lower()
    if _MAVEN_NOT_A_VERSION_RE.search(text):
        return None
    found = _MAVEN_TOKEN_RE.findall(text)
    tokens: list[int | str] = []
    for index, part in enumerate(found):
        if part.isdigit():
            tokens.append(int(part))
        elif found[index + 1 : index + 2] and found[index + 1].isdigit():
            # ``a1`` / ``b2`` / ``m3`` abbreviate alpha / beta / milestone.
            tokens.append(_MAVEN_SHORT_QUALIFIERS.get(part, part))
        else:
            tokens.append(part)
    return tuple(tokens) or None


def _maven_canonical(tokens: _MavenTokens) -> _MavenTokens:
    """Drop what ends a version without changing it: ``1.0.0`` and ``1.0-ga`` are ``1``."""
    end = len(tokens)
    while end and _maven_item(tokens[end - 1], None) in ((1, 0, ""), (0, _MAVEN_RELEASE_RANK, "")):
        end -= 1
    return tokens[:end]


def _maven_item(item: int | str | None, other: int | str | None) -> tuple[int, int, str]:
    """Sort key of one token; a missing token is zero beside a number, a release otherwise."""
    if item is None:
        return (1, 0, "") if isinstance(other, int) else (0, _MAVEN_RELEASE_RANK, "")
    if isinstance(item, int):
        return (1, item, "")
    rank = _MAVEN_QUALIFIER_RANKS.get(item)
    # An unknown qualifier sorts after every known one, alphabetically.
    return (0, 8, item) if rank is None else (0, rank, "")


def _maven_cmp(left: _MavenTokens, right: _MavenTokens) -> int:
    """Order two Maven versions: token by token, a number above any qualifier."""
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else None
        b = right[index] if index < len(right) else None
        key_a, key_b = _maven_item(a, b), _maven_item(b, a)
        if key_a != key_b:
            return -1 if key_a < key_b else 1
    return 0


_maven_key = functools.cmp_to_key(_maven_cmp)


def _maven_version(text: str) -> Any | None:
    tokens = _maven_tokens(text)
    return None if tokens is None else _maven_key(_maven_canonical(tokens))


def _maven_has_prefix(tokens: _MavenTokens, prefix: _MavenTokens) -> bool:
    """Whether a version starts with ``prefix``; segments it leaves out are zero."""
    return all(
        (tokens[index] if index < len(tokens) else 0) == part for index, part in enumerate(prefix)
    )


def _maven_is_prerelease(version: Any) -> bool:
    return any(
        isinstance(token, str)
        and (
            _MAVEN_QUALIFIER_RANKS.get(token, _MAVEN_RELEASE_RANK) < _MAVEN_RELEASE_RANK
            or token in _MAVEN_PRERELEASE_WORDS
        )
        for token in version.obj
    )


def is_gradle_dynamic_version(version: str) -> bool:
    """Whether a Gradle version is a dynamic one rather than a version.

    A prefix version (``1.+``, ``1.2.+``, a bare ``+``) and a ``latest.*``
    selector (``latest.release``, ``latest.integration``) each name a set of
    versions. One is never a version to ask a registry for.
    """
    spec = version.strip()
    return spec.endswith("+") or spec.startswith("latest.")


def _maven_matcher(constraint: str) -> _Matcher | None:
    """Maven ranges and Gradle's dynamic forms; a bare version is a minimum."""
    spec = constraint.strip()
    if spec in ("+", "latest.release", "latest.integration"):
        return lambda _version: True
    if spec.startswith("=="):
        spec = f"[{spec[2:].strip()}]"
    elif spec.endswith("!!"):
        # Gradle's shorthand for a strict version.
        spec = f"[{spec[:-2].strip()}]"
    if spec.endswith(".+"):
        prefix = _maven_tokens(spec[:-2])
        return None if prefix is None else (lambda version: _maven_has_prefix(version.obj, prefix))
    if spec[0] not in "[(":
        # Conflict resolution may raise a declared version, never lower it.
        minimum = _maven_version(spec)
        return None if minimum is None else _compare(">=", minimum)
    if not _MAVEN_RANGE_SET_RE.fullmatch(spec):
        return None
    alternatives: list[list[_Matcher]] = []
    for opening, low, comma, high, closing in _MAVEN_RANGE_RE.findall(spec):
        if not comma:
            # ``[1.0]`` is exactly that version; ``(1.0)`` is not a range.
            only = _maven_version(low)
            if only is None or (opening, closing) != ("[", "]"):
                return None
            alternatives.append([_compare("==", only)])
            continue
        tests: list[_Matcher] = []
        for text, op in (
            (low, ">=" if opening == "[" else ">"),
            (high, "<=" if closing == "]" else "<"),
        ):
            if text:
                bound = _maven_version(text)
                if bound is None:
                    return None
                tests.append(_compare(op, bound))
        if not tests:
            return None
        alternatives.append(tests)
    return _any_of(alternatives)


# R.

_R_VERSION_RE = re.compile(r"\d+(?:[.-]\d+)*")
_R_CONSTRAINT_RE = re.compile(r"(>=|<=|==|!=|>|<)\s*(\S+)")


def _r_version(text: str) -> tuple[int, ...] | None:
    text = text.strip()
    if not _R_VERSION_RE.fullmatch(text):
        return None
    return tuple(int(part) for part in re.split(r"[.-]", text))


def _r_matcher(constraint: str) -> _Matcher | None:
    match = _R_CONSTRAINT_RE.fullmatch(constraint.strip())
    bound = _r_version(match.group(2)) if match else None
    if match is None or bound is None:
        return None
    return _compare(match.group(1), bound)


def _never_prerelease(_version: Any) -> bool:
    return False


_GRAMMARS: dict[Ecosystem, _Grammar] = {
    Ecosystem.PYTHON: _Grammar(_python_version, _python_is_prerelease, _python_matcher),
    Ecosystem.NPM: _Grammar(_npm_version, _semver_is_prerelease, _npm_matcher),
    Ecosystem.RUST: _Grammar(_semver, _semver_is_prerelease, _cargo_matcher),
    Ecosystem.GO: _Grammar(_go_version, _semver_is_prerelease, _go_matcher),
    Ecosystem.JAVA: _Grammar(_maven_version, _maven_is_prerelease, _maven_matcher),
    Ecosystem.DOTNET: _Grammar(_nuget_version, _nuget_is_prerelease, _nuget_matcher),
    Ecosystem.PHP: _Grammar(composer_version, _composer_is_prerelease, _composer_matcher),
    Ecosystem.RUBY: _Grammar(_gem_version, _gem_is_prerelease, _gem_matcher),
    Ecosystem.HEX: _Grammar(_semver, _semver_is_prerelease, _hex_matcher),
    Ecosystem.R: _Grammar(_r_version, _never_prerelease, _r_matcher),
}


def satisfies(ecosystem: Ecosystem, version: str, constraint: str) -> bool | None:
    """Whether ``version`` satisfies ``constraint``, as ``ecosystem`` reads both.

    ``constraint`` is written the way the ecosystem's manifests write it
    (``>=2,<3``, ``^1.2``, ``~> 1.0``, ``[1.0,2.0)``); the ``==1.2.3`` form
    licenseal gives a lockfile entry is read as that exact version everywhere.
    An empty constraint is satisfied by anything.

    Returns None when the answer cannot be given: the constraint is not one
    the ecosystem's grammar reads (a URL, a branch, a dist-tag, an unresolved
    property), or ``version`` is not a version of that ecosystem.

    Prereleases follow each ecosystem's resolver: ``2.0.0-rc.1`` satisfies
    ``^1.0`` nowhere, and satisfies a range that would include it by order
    only when the range itself names a prerelease (in Composer, when the
    constraint's stability reaches it). Maven ranges, and Go and R
    requirements, are plain comparisons, so ``[1.0,2.0)`` holds ``2.0-rc1``.
    Build metadata never changes the answer.

    A bare version means what the ecosystem means by it: exactly that version
    (Python, npm, RubyGems, Hex, Composer), a caret range (Cargo), or a
    minimum (NuGet, Maven and Gradle, Go).
    """
    if not constraint.strip():
        return True
    grammar = _GRAMMARS[ecosystem]
    parsed = grammar.version(version)
    matcher = grammar.matcher(constraint)
    if parsed is None or matcher is None:
        return None
    return matcher(parsed)


def is_prerelease(ecosystem: Ecosystem, version: str) -> bool:
    """Whether ``version`` is a prerelease, as ``ecosystem`` reads versions.

    False for a release, and for text that is not a version of that
    ecosystem. A caller that got ``False`` from :func:`satisfies` uses this
    to tell a version outside the range from one a resolver may or may not
    take, depending on settings the constraint does not show.
    """
    grammar = _GRAMMARS[ecosystem]
    parsed = grammar.version(version)
    return parsed is not None and grammar.prerelease(parsed)


def select_version(
    ecosystem: Ecosystem, constraint: str, published: Iterable[str], *, lowest: bool = False
) -> str | None:
    """Pick the published version that ``constraint`` resolves to.

    The highest version in ``published`` that satisfies ``constraint`` (the
    lowest with ``lowest=True``, for registries that resolve a range to its
    minimum), a release before any prerelease: a prerelease is picked only
    when no release satisfies the constraint and the constraint admits it.
    An empty constraint picks the latest release.

    Returns None when the constraint is not understood or nothing published
    satisfies it. It never falls back to another version. Entries of
    ``published`` that are not versions are passed over.
    """
    grammar = _GRAMMARS[ecosystem]
    matcher = grammar.matcher(constraint) if constraint.strip() else (lambda _version: True)
    if matcher is None:
        return None
    candidates: list[tuple[bool, Any, str]] = []
    for raw in published:
        parsed = grammar.version(raw)
        if parsed is not None and matcher(parsed):
            candidates.append((not grammar.prerelease(parsed), parsed, raw))
    candidates = [candidate for candidate in candidates if candidate[0]] or candidates
    if not candidates:
        return None
    pick = min if lowest else max
    return pick(candidates, key=lambda candidate: candidate[1])[2]
