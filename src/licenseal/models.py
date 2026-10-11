"""Data models for licenseal."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

_PEP503_SEPARATORS_RE = re.compile(r"[-_.]+")


class Ecosystem(str, Enum):
    """Package ecosystem."""

    PYTHON = "python"
    NPM = "npm"
    RUST = "rust"
    GO = "go"
    JAVA = "java"
    DOTNET = "dotnet"
    PHP = "php"
    RUBY = "ruby"
    HEX = "hex"
    R = "r"

    @property
    def label(self) -> str:
        """Human-readable display label (e.g. for CLI workspace-filter messages)."""
        return _ECOSYSTEM_LABELS[self]

    def identity(self, name: str) -> str:
        """Return the key under which ``name`` is one package of this ecosystem.

        Two names are the same package exactly when their keys are equal, by
        the rule of the ecosystem's own registry:

        - Python: PEP 503. Case is folded and runs of ``-``, ``_``, and ``.``
          are one ``-``.
        - .NET, PHP, Rust, Hex, R: case is folded. NuGet ids and Packagist
          names are case-insensitive, and crates.io, hex.pm, and CRAN admit
          no two names that differ only in case.
        - Go, Java, npm, Ruby: the name as written. A Go module path, a Maven
          ``groupId:artifactId``, an npm package name, and a gem name that
          differ only in case are different packages.

        Every key that tells packages apart is built with this: review keys,
        the dedupe of discovered and resolved dependencies, the name sets and
        edge graphs of the lockfile parsers, and report nesting.
        """
        if self is Ecosystem.PYTHON:
            return _PEP503_SEPARATORS_RE.sub("-", name).lower()
        if self in _CASE_FOLDING_ECOSYSTEMS:
            return name.lower()
        return name


# Ecosystems whose registry treats names that differ only in case as one
# package. Python folds case too, as part of PEP 503.
_CASE_FOLDING_ECOSYSTEMS = frozenset(
    {Ecosystem.DOTNET, Ecosystem.PHP, Ecosystem.RUST, Ecosystem.HEX, Ecosystem.R}
)

# Display labels for the (few) user-facing spots that name an ecosystem — the
# enum value (``"r"``, ``"dotnet"``) isn't always the conventional spelling.
# Keep exhaustive: the CLI workspace-filter echo iterates ``Ecosystem`` and
# looks up ``.label``, so a missing entry surfaces immediately (the
# ``test_every_ecosystem_has_a_label`` test fails) rather than silently
# dropping a per-ecosystem line as the old hardcoded tuple did.
_ECOSYSTEM_LABELS: dict[Ecosystem, str] = {
    Ecosystem.PYTHON: "Python",
    Ecosystem.NPM: "npm",
    Ecosystem.RUST: "Rust",
    Ecosystem.GO: "Go",
    Ecosystem.JAVA: "Java/JVM",
    Ecosystem.DOTNET: ".NET",
    Ecosystem.PHP: "PHP",
    Ecosystem.RUBY: "Ruby",
    Ecosystem.HEX: "Hex",
    Ecosystem.R: "R",
}


class DependencyGroup(str, Enum):
    """Dependency group (production vs development)."""

    PROD = "prod"
    DEV = "dev"


class RiskLevel(str, Enum):
    """License risk classification."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak-copyleft"
    STRONG_COPYLEFT = "strong-copyleft"
    NETWORK_COPYLEFT = "network-copyleft"
    UNKNOWN = "unknown"

    @property
    def severity(self) -> int:
        """Numeric severity for sorting (higher = more restrictive)."""
        return _RISK_SEVERITY[self]


_RISK_SEVERITY: dict[RiskLevel, int] = {
    RiskLevel.PERMISSIVE: 0,
    RiskLevel.WEAK_COPYLEFT: 1,
    RiskLevel.STRONG_COPYLEFT: 2,
    RiskLevel.NETWORK_COPYLEFT: 3,
    RiskLevel.UNKNOWN: 4,
}


class CompatibilityVerdict(str, Enum):
    """Compatibility assessment result."""

    COMPATIBLE = "compatible"
    WARNING = "warning"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    """A discovered dependency."""

    name: str
    version_constraint: str
    ecosystem: Ecosystem
    group: DependencyGroup = DependencyGroup.PROD
    depth: int = 0
    direct_ancestors: tuple[str, ...] = ()
    source: str = ""
    # Where the dependency comes from when that is not the registry: a git
    # repository, a direct URL, or a path that the scan does not read, as
    # one normalized string (see `licenseal.discovery._origin`). Empty for a
    # registry package. A dependency with an origin is never looked up on a
    # registry: its license is UNKNOWN until a review keyed on the origin
    # supplies one.
    origin: str = ""
    # Name to query the registry under when it differs from `name`. Hex `hex:`
    # package-renames declare a local app name (`name` — used for the lock-edge
    # graph, dev attribution, workspace filter, and display) that differs from
    # the published hex.pm package; license resolution must use the latter.
    # Empty means "same as name" — the case for every ecosystem except a
    # renamed Hex dep.
    registry_name: str = ""
    # Extras requested for this dep (PEP 508). `pkg[extra]` → {"extra"}.
    # Used by the Python transitive walker to evaluate `extra == "x"`
    # markers in the dep's own requires_dist — child deps gated behind an
    # unrequested extra are skipped, matching what pip would actually
    # install. Empty for npm/Rust (those ecosystems express opt-in deps via
    # separate fields, not markers).
    extras: frozenset[str] = field(default_factory=frozenset)
    # True when the reported version was chosen by licenseal from a registry:
    # no lockfile entry and no exact pin in a manifest fixes it. Set by the
    # registry walks and for a direct dep declared with a range or with no
    # constraint; False for every row a lockfile supplies.
    version_estimated: bool = False

    @property
    def is_transitive(self) -> bool:
        """True when this dep was pulled in by another dep, not declared directly."""
        return self.depth > 0

    @property
    def display_depth(self) -> int:
        """Depth as reported in the public JSON contract: ``0`` direct, ``1`` transitive.

        ``depth`` is a binary signal everywhere downstream (``is_transitive`` is
        ``depth > 0``), but its raw value is not a uniform tree level: lockfile and
        edge-graph paths flatten every transitive to ``1`` while the registry-walk
        fallback records the true BFS level (``2``, ``3``, …). Serialization
        normalizes to the binary form here so the emitted number can't be misread
        as a tree depth. Resolution never reads this — only the report does — so
        the stored ``depth`` is left intact for the walker's max-depth cap and the
        dedup tiebreak, both of which rely on its true value.
        """
        return 1 if self.is_transitive else 0

    @property
    def identity(self) -> str:
        """Key of the package ``name`` stands for (see :meth:`Ecosystem.identity`)."""
        return self.ecosystem.identity(self.name)

    @property
    def effective_registry_name(self) -> str:
        """Registry-lookup name: the rename target when set, else ``name``.

        Only renamed Hex deps populate ``registry_name``; everywhere else this
        is just ``name``. Resolvers, the registry walker, the report URL, and
        review keys use this, so that hex.pm is asked about, and a review is
        written for, the real package, while the report and the lock-edge
        graph still key on the declared local name.
        """
        return self.registry_name or self.name


@dataclass
class LicenseInfo:
    """Resolved license information for a dependency."""

    dependency: Dependency
    license_id: str  # detected SPDX ID or raw string from registry
    license_raw: str  # original string from source
    reviewed_license_id: str = ""
    review_note: str = ""
    repository_url: str = ""
    homepage_url: str = ""
    resolved_version: str = ""
    from_registry: bool = False
    # Set when the source lists several licenses without saying whether they
    # are alternatives or all apply (a RubyGems / Hex ``licenses`` array, a
    # comma- or slash-separated list in one license string). ``license_id``
    # then holds the list read as a choice — the reading reports show — and
    # this holds it read as every entry applying. Compatibility is judged
    # under both. Empty when the source defines what its list means.
    all_apply_license_id: str = ""
    # True when ``license_id`` was read from metadata that describes a release
    # other than ``resolved_version``: a registry that keeps one license per
    # package (the CRAN index, hex.pm), or the latest PyPI release standing in
    # for one that declares nothing. False when the reported release is the
    # one the metadata describes.
    license_estimated: bool = False

    @property
    def detected_license_id(self) -> str:
        """The license originally detected from the registry."""
        return self.license_id

    @property
    def effective_license_id(self) -> str:
        """Reviewed license override if set, else the detected license."""
        return self.reviewed_license_id or self.license_id

    @property
    def is_unknown(self) -> bool:
        """True when the effective license is unknown / unparsed."""
        return self.effective_license_id in ("UNKNOWN", "NOASSERTION", "")

    @property
    def reviewed(self) -> bool:
        """True when a manual review override has been applied."""
        return bool(self.reviewed_license_id)


@dataclass
class CompatibilityResult:
    """Result of compatibility check for a single dependency."""

    license_info: LicenseInfo
    risk_level: RiskLevel
    verdict: CompatibilityVerdict
    reason: str = ""


@dataclass(frozen=True)
class ReportDiagnostic:
    """A surfaced read/parse anomaly as it appears in the report.

    ``path`` is project-relative when possible. ``severity`` is ``"gap"`` (a
    dependency-bearing manifest lost to the scan — incomplete analysis, fails
    ``--strict``), ``"recovered"`` (decoded with a caveat, e.g. a latin-1
    fallback that still recovered the ASCII dependency lines), or
    ``"estimate"`` (a manifest whose dependencies no lockfile covers, scanned
    with ``--no-require-lockfile``: reported, not a gap).
    """

    path: str
    reason: str
    severity: str


@dataclass
class AnalysisReport:
    """Complete analysis report."""

    project_license: str
    elapsed_seconds: float = 0.0
    results: list[CompatibilityResult] = field(default_factory=list)
    # Manifest read/parse anomalies surfaced during the scan (set by the CLI,
    # like ``elapsed_seconds``). Emitted in the JSON report's ``diagnostics``;
    # the gaps and the estimates among them are also listed in the table and
    # Markdown reports.
    read_diagnostics: list[ReportDiagnostic] = field(default_factory=list)
    # File name of the manifest in the scanned directory that supplied
    # ``project_license`` (set by the CLI, like ``elapsed_seconds``). Empty
    # when none declares a recognised license and ``Proprietary`` is assumed.
    project_license_source: str = ""
    # Why ``Proprietary`` is assumed, as a phrase the table and Markdown
    # reports show beside it (set by the CLI, like ``project_license_source``).
    # Empty when a manifest supplied ``project_license``.
    project_license_assumption: str = ""

    @property
    def violations(self) -> list[CompatibilityResult]:
        """Results with INCOMPATIBLE verdict."""
        return [r for r in self.results if r.verdict == CompatibilityVerdict.INCOMPATIBLE]

    @property
    def warnings(self) -> list[CompatibilityResult]:
        """Results with WARNING verdict."""
        return [r for r in self.results if r.verdict == CompatibilityVerdict.WARNING]

    @property
    def ok(self) -> list[CompatibilityResult]:
        """Results with COMPATIBLE verdict."""
        return [r for r in self.results if r.verdict == CompatibilityVerdict.COMPATIBLE]

    @property
    def unknown(self) -> list[CompatibilityResult]:
        """Results with UNKNOWN verdict."""
        return [r for r in self.results if r.verdict == CompatibilityVerdict.UNKNOWN]

    @property
    def reviewed(self) -> list[CompatibilityResult]:
        """Results that have a manual review override applied."""
        return [r for r in self.results if r.license_info.reviewed]
