"""Data models for licenseal."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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
    def effective_registry_name(self) -> str:
        """Registry-lookup name: the rename target when set, else ``name``.

        Only renamed Hex deps populate ``registry_name``; everywhere else this
        is just ``name``. Resolvers, the registry walker, and the report URL
        use this to reach hex.pm under the real package name while the report
        and the lock-edge graph still key on the declared local name.
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
    ``--strict``) or ``"recovered"`` (decoded with a caveat, e.g. a latin-1
    fallback that still recovered the ASCII dependency lines).
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
    # like ``elapsed_seconds``). Emitted in the JSON report's ``diagnostics``.
    read_diagnostics: list[ReportDiagnostic] = field(default_factory=list)

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
