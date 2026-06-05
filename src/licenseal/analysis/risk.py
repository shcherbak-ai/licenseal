"""License risk classification.

Classification is driven by:
* An **override map** (tried first) — explicit per-ID risk for the cases
  family patterns get wrong or don't cover: non-OSI source-available
  licenses (Elastic, SSPL, BUSL), the no-commercial-use CC variants
  (CC-BY-NC-*, CC-BY-ND-*), permissive licenses with no family prefix
  (Zlib, ISC, PostgreSQL, Beerware…), and ``Proprietary`` (project-side
  permissive sentinel).
* A small set of family **patterns** that map SPDX-ID name prefixes to
  risk levels (e.g. ``^GPL-`` → STRONG_COPYLEFT). The conventions are
  consistent enough across the SPDX namespace that patterns cover the
  vast majority of the ~700 IDs without per-ID enumeration.
* A vendored list of canonical SPDX IDs (``data/spdx-license-ids.json``,
  CC0-1.0 from github.com/jslicense/spdx-license-ids) — the *recognition*
  layer that backs the patterns. A *permissive* prefix match is only
  honoured when the ID is in this list; an unrecognised ID that merely
  shares a permissive prefix (``MIT-NonCommercial``, ``BSD-5-Clause``)
  routes to UNKNOWN rather than to a false-clean PERMISSIVE. Copyleft /
  source-available prefix matches are not gated — over-matching them only
  adds scrutiny, never removes it.

An ID matched by none of the above falls through to UNKNOWN.

Compound SPDX expressions (OR / AND / WITH / parens / ``+`` suffix) are
handled by a hand-rolled parser below; the simple-ID classifier above is
called recursively on each leaf.
"""

from __future__ import annotations

import json
import re
from importlib.resources import files

from licenseal.models import RiskLevel

# Load the vendored SPDX ID list once at import time. ``frozenset`` makes the
# membership test cheap and forbids accidental mutation.
KNOWN_SPDX_IDS: frozenset[str] = frozenset(
    json.loads((files("licenseal.data") / "spdx-license-ids.json").read_text(encoding="utf-8"))
)


# Family patterns: tried in declaration order; first match wins. Each pattern
# matches a *simple* SPDX ID (no spaces, parens, or `+`). The simple-ID
# classifier strips a trailing `+` before matching, so `MPL-2.0+` → MPL-2.0.
_RISK_PATTERNS: list[tuple[re.Pattern[str], RiskLevel]] = [
    # Source-available license families — must precede permissive patterns so
    # ``FSL-1.0-Apache-2.0`` (which contains ``Apache-2.0``) classifies as
    # source-available, not permissive. On the dep side this routes to
    # UNKNOWN → manual review (custom commercial-use restrictions are
    # consumer-context-dependent). The compatibility checker has a separate
    # override for these as PROJECT licenses.
    (re.compile(r"^BUSL-"), RiskLevel.UNKNOWN),
    (re.compile(r"^SSPL-"), RiskLevel.UNKNOWN),
    (re.compile(r"^Elastic-"), RiskLevel.UNKNOWN),
    (re.compile(r"^FSL-"), RiskLevel.UNKNOWN),
    (re.compile(r"^Parity-"), RiskLevel.UNKNOWN),
    (re.compile(r"^PolyForm-"), RiskLevel.UNKNOWN),
    # Network copyleft — must precede the GPL pattern since AGPL has its own.
    (re.compile(r"^AGPL-"), RiskLevel.NETWORK_COPYLEFT),
    # Strong copyleft. Share-alike on derivative works (CC-BY-SA, ODbL,
    # CDLA-Sharing) is strong copyleft — the share-alike obligation extends
    # to the whole derivative work, not just modifications of the licensed
    # file. OSL has an AGPL-flavoured external-deployment trigger but the
    # FSF documents it as plain strong copyleft. EUPL is "interoperable
    # copyleft" with a compatibility appendix; by itself its copyleft is
    # "comparable to the GPL's" per the FSF, so strong.
    (re.compile(r"^GPL-"), RiskLevel.STRONG_COPYLEFT),
    # GFDL (GNU Free Documentation License) is GPL-flavoured copyleft for docs.
    (re.compile(r"^GFDL-"), RiskLevel.STRONG_COPYLEFT),
    (re.compile(r"^OSL-"), RiskLevel.STRONG_COPYLEFT),
    (re.compile(r"^EUPL-"), RiskLevel.STRONG_COPYLEFT),
    (re.compile(r"^CC-BY-SA-"), RiskLevel.STRONG_COPYLEFT),
    (re.compile(r"^ODbL-"), RiskLevel.STRONG_COPYLEFT),
    (re.compile(r"^CDLA-Sharing"), RiskLevel.STRONG_COPYLEFT),
    # Weak copyleft — file-scope reciprocity: modifications to licensed files
    # must remain under the same license, but linking from other files is
    # allowed. Note: EPL-1.0, CDDL-*, and MPL-1.1 are weak copyleft but
    # GPL-incompatible by virtue of patent / choice-of-law / additional-
    # restriction clauses; the coarse matrix doesn't surface those pair-level
    # incompatibilities (documented in README "Limitations").
    (re.compile(r"^LGPL-"), RiskLevel.WEAK_COPYLEFT),
    (re.compile(r"^MPL-"), RiskLevel.WEAK_COPYLEFT),
    (re.compile(r"^EPL-"), RiskLevel.WEAK_COPYLEFT),
    (re.compile(r"^CDDL-"), RiskLevel.WEAK_COPYLEFT),
    # Permissive families
    (re.compile(r"^BSD"), RiskLevel.PERMISSIVE),
    (re.compile(r"^MIT"), RiskLevel.PERMISSIVE),
    (re.compile(r"^Apache-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^AFL-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^Artistic-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^BSL-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^BlueOak-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^CDLA-Permissive"), RiskLevel.PERMISSIVE),
    (re.compile(r"^CC-BY-\d"), RiskLevel.PERMISSIVE),  # plain CC-BY-N.M only
    (re.compile(r"^ECL-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^HPND"), RiskLevel.PERMISSIVE),
    (re.compile(r"^LPPL-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^OFL-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^OLDAP-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^PSF-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^Python-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^Unicode-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^ZPL-"), RiskLevel.PERMISSIVE),
    (re.compile(r"^X11"), RiskLevel.PERMISSIVE),
    (re.compile(r"^Zend-"), RiskLevel.PERMISSIVE),
]

# Overrides — explicit per-ID risk levels for cases the patterns don't fit.
_RISK_OVERRIDES: dict[str, RiskLevel] = {
    # Permissive licenses with no family prefix.
    "0BSD": RiskLevel.PERMISSIVE,
    "AAL": RiskLevel.PERMISSIVE,
    "Beerware": RiskLevel.PERMISSIVE,
    "bzip2-1.0.6": RiskLevel.PERMISSIVE,
    "CC0-1.0": RiskLevel.PERMISSIVE,
    "FTL": RiskLevel.PERMISSIVE,
    "ICU": RiskLevel.PERMISSIVE,
    "ISC": RiskLevel.PERMISSIVE,
    "Libpng": RiskLevel.PERMISSIVE,
    "libpng-2.0": RiskLevel.PERMISSIVE,
    "MS-PL": RiskLevel.PERMISSIVE,  # Microsoft Public License
    "NCSA": RiskLevel.PERMISSIVE,
    "NTP": RiskLevel.PERMISSIVE,
    "OpenSSL": RiskLevel.PERMISSIVE,
    "PHP-3.01": RiskLevel.PERMISSIVE,
    "PostgreSQL": RiskLevel.PERMISSIVE,
    "Sendmail": RiskLevel.PERMISSIVE,
    "Spencer-86": RiskLevel.PERMISSIVE,
    "Spencer-94": RiskLevel.PERMISSIVE,
    "Spencer-99": RiskLevel.PERMISSIVE,
    "Unlicense": RiskLevel.PERMISSIVE,
    "Vim": RiskLevel.PERMISSIVE,
    "W3C": RiskLevel.PERMISSIVE,
    "WTFPL": RiskLevel.PERMISSIVE,
    "Zlib": RiskLevel.PERMISSIVE,
    "zlib-acknowledgement": RiskLevel.PERMISSIVE,
    # Permissive non-SPDX project-side sentinels.
    "LicenseRef-Public-Domain": RiskLevel.PERMISSIVE,
    # Weak copyleft with no family prefix.
    "MS-RL": RiskLevel.WEAK_COPYLEFT,  # Microsoft Reciprocal License
    "IPL-1.0": RiskLevel.WEAK_COPYLEFT,  # IBM Public License
    # Strong copyleft with no family prefix.
    "RPL-1.1": RiskLevel.STRONG_COPYLEFT,  # Reciprocal Public License
    "RPL-1.5": RiskLevel.STRONG_COPYLEFT,
    # Sleepycat / Berkeley DB: source-disclosure obligation extends to "any
    # accompanying software that uses the DB software" — that's strong-
    # copyleft semantics (FSF: GPL-compatible, "similar in effect to the GPL").
    "Sleepycat": RiskLevel.STRONG_COPYLEFT,
    # Non-OSI source-available licenses — pattern-blind. We classify them as
    # UNKNOWN so the compatibility matrix routes them to manual review (custom
    # commercial-use restrictions can't be auto-evaluated against permissive
    # project licenses).
    "SSPL-1.0": RiskLevel.UNKNOWN,
    "BUSL-1.1": RiskLevel.UNKNOWN,
    "Elastic-2.0": RiskLevel.UNKNOWN,
    # Functional Source License (FSL). Source-available now, becomes the
    # named future license (MIT / ALv2) after a two-year delay; restricts
    # competing commercial use during the source-available window.
    "FSL-1.1-MIT": RiskLevel.UNKNOWN,
    "FSL-1.1-ALv2": RiskLevel.UNKNOWN,
    "Parity-6.0.0": RiskLevel.UNKNOWN,
    "Parity-7.0.0": RiskLevel.UNKNOWN,
    "PolyForm-Noncommercial-1.0.0": RiskLevel.UNKNOWN,
    "PolyForm-Small-Business-1.0.0": RiskLevel.UNKNOWN,
    # Creative Commons restrictive variants: non-commercial / no-derivatives.
    # The `^CC-BY-\d` pattern would otherwise grab CC-BY-NC-* incorrectly.
    "CC-BY-NC-1.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-2.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-2.5": RiskLevel.UNKNOWN,
    "CC-BY-NC-3.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-4.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-SA-1.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-SA-2.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-SA-2.5": RiskLevel.UNKNOWN,
    "CC-BY-NC-SA-3.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-SA-4.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-ND-1.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-ND-2.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-ND-2.5": RiskLevel.UNKNOWN,
    "CC-BY-NC-ND-3.0": RiskLevel.UNKNOWN,
    "CC-BY-NC-ND-4.0": RiskLevel.UNKNOWN,
    "CC-BY-ND-1.0": RiskLevel.UNKNOWN,
    "CC-BY-ND-2.0": RiskLevel.UNKNOWN,
    "CC-BY-ND-2.5": RiskLevel.UNKNOWN,
    "CC-BY-ND-3.0": RiskLevel.UNKNOWN,
    "CC-BY-ND-4.0": RiskLevel.UNKNOWN,
    # Proprietary — the custom-commercial-terms sentinel. Its risk is
    # genuinely UNKNOWN: licenseal can't reason about paid-use / no-redist /
    # field-of-use clauses. On the *dep* side, `_check_compat` short-circuits
    # a bare ``Proprietary`` to manual review; when it appears as one arm of a
    # compound (``AGPL-3.0-only OR Proprietary``) this UNKNOWN keeps it from
    # masquerading as the most-permissive OR branch and clearing the whole
    # expression. The *project*-side "a proprietary project may consume
    # permissive deps" convenience lives in compatibility._project_compat_risk,
    # not here — keeping it here let the convenience leak into dep-side OR
    # aggregation and silently relaxed copyleft-or-commercial dual licenses.
    "Proprietary": RiskLevel.UNKNOWN,
}


def classify_risk(spdx_id: str) -> RiskLevel:
    """Classify a normalized SPDX license ID into a risk level.

    Handles compound SPDX expressions:
    - OR: takes the least restrictive (user can choose the most permissive)
    - AND: takes the most restrictive (all conditions must be met)

    Respects SPDX precedence (AND binds tighter than OR) and parenthesized
    grouping such as ``(MIT OR Apache-2.0) AND Unicode-DFS-2016``.
    """
    if not spdx_id or spdx_id in ("UNKNOWN", "NOASSERTION"):
        return RiskLevel.UNKNOWN

    expr = spdx_id.strip()

    # Simple-ID fast path: no compound operators, no parens.
    if " " not in expr and "(" not in expr and ")" not in expr:
        # SPDX `+` suffix: `MPL-2.0+` classifies as MPL-2.0. Strip before lookup.
        base = expr.rstrip("+")
        if base in _RISK_OVERRIDES:
            return _RISK_OVERRIDES[base]
        for pattern, level in _RISK_PATTERNS:
            if pattern.match(base):
                # A family prefix can over-match an ID that is not a real SPDX
                # license (``MIT-NonCommercial``, ``BSD-5-Clause``). PERMISSIVE
                # is the only "clean" verdict, so a permissive prefix match must
                # be backed by a recognized SPDX ID — otherwise route to UNKNOWN
                # (manual review). Copyleft / source-available prefixes need no
                # such guard: over-matching them only adds scrutiny.
                if level == RiskLevel.PERMISSIVE and base not in KNOWN_SPDX_IDS:
                    return RiskLevel.UNKNOWN
                return level
        return RiskLevel.UNKNOWN

    # Compound expression handling.
    unwrapped = _strip_outer_parens(expr)
    if unwrapped != expr:
        return classify_risk(unwrapped)

    # Split at the lowest-precedence operator first so AND binds tighter
    # than OR per SPDX 3.0 grammar.
    or_parts = _split_top_level(expr, " OR ")
    if len(or_parts) > 1:
        return _aggregate(or_parts, prefer_lower=True)

    and_parts = _split_top_level(expr, " AND ")
    if len(and_parts) > 1:
        return _aggregate(and_parts, prefer_lower=False)

    if " WITH " in expr:
        base = expr.split(" WITH ", 1)[0].strip()
        return classify_risk(base)

    return RiskLevel.UNKNOWN


def _aggregate(parts: list[str], *, prefer_lower: bool) -> RiskLevel:
    risks = [classify_risk(p) for p in parts]
    known = [r for r in risks if r != RiskLevel.UNKNOWN]

    # OR: the consumer may elect any single arm, so an unresolvable arm is
    # harmless — pick the least-restrictive *known* license and drop unknowns.
    # All-unknown collapses to UNKNOWN (manual review).
    if prefer_lower:
        if not known:
            return RiskLevel.UNKNOWN
        return min(known, key=lambda r: r.severity)

    # AND: every arm binds simultaneously, so an unresolvable arm cannot be
    # dropped — it may carry restrictions we can't see. Route the whole
    # expression to UNKNOWN (manual review) UNLESS a known arm already pins a
    # copyleft incompatibility (STRONG/NETWORK), which is the more actionable
    # signal and must not be masked: an UNKNOWN verdict can pass under
    # ``--no-strict``, but a copyleft violation never does.
    worst_known = max(known, key=lambda r: r.severity) if known else RiskLevel.UNKNOWN
    if worst_known.severity >= RiskLevel.STRONG_COPYLEFT.severity:
        return worst_known
    if len(known) < len(risks):
        return RiskLevel.UNKNOWN
    return worst_known


def _strip_outer_parens(expr: str) -> str:
    """Return ``expr`` with a single matched outer pair of parens removed."""
    if not (expr.startswith("(") and expr.endswith(")")):
        return expr
    depth = 0
    for i, ch in enumerate(expr):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i < len(expr) - 1:
                return expr  # closing paren is not the final char
    if depth != 0:
        return expr  # unbalanced — leave alone
    return expr[1:-1].strip()


def _split_top_level(expr: str, sep: str) -> list[str]:
    """Split ``expr`` on ``sep``, ignoring occurrences inside parentheses."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    sep_len = len(sep)
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
            buf.append(ch)
            i += 1
        elif ch == ")":
            depth -= 1
            buf.append(ch)
            i += 1
        elif depth == 0 and expr[i : i + sep_len] == sep:
            parts.append("".join(buf).strip())
            buf = []
            i += sep_len
        else:
            buf.append(ch)
            i += 1
    parts.append("".join(buf).strip())
    return parts


def unavoidable_unresolved_licenses(spdx_id: str) -> list[str]:
    """Unresolved licenses the consumer is bound by however they elect the
    expression's ``OR`` choices.

    :func:`classify_risk` collapses each sub-expression to a single risk level
    and can hide an unresolved arm behind a recognized one (``GPL-3.0-only AND
    <custom>`` → STRONG_COPYLEFT). The compatibility layer uses this walk —
    where the project license is known — to re-surface an unresolved license the
    consumer can't escape, without softening a definite incompatibility.

    The walk mirrors :func:`classify_risk`'s parser with bind/elect semantics:

    * **leaf** → the leaf itself when it classifies UNKNOWN, else nothing.
    * **AND** → the union over arms: every arm binds, so any unresolved arm is
      unavoidable.
    * **OR** → nothing when *any* arm is fully resolved (the consumer elects
      that arm and avoids the rest); otherwise the union over arms, because
      every electable branch still leaves an unresolved license. This is why
      ``AGPL-3.0-only OR Proprietary`` (resolved AGPL arm) and ``(LGPL AND
      <custom>) OR MIT`` (resolved MIT arm) do not escalate, but ``(GPL AND
      <custom>) OR Proprietary`` (no fully-resolved arm) does.

    Returns ``[]`` when every binding license resolved.
    """
    expr = spdx_id.strip()
    unwrapped = _strip_outer_parens(expr)
    if unwrapped != expr:
        return unavoidable_unresolved_licenses(unwrapped)

    or_parts = _split_top_level(expr, " OR ")
    if len(or_parts) > 1:
        per_arm = [unavoidable_unresolved_licenses(p) for p in or_parts]
        if any(not arm for arm in per_arm):
            return []  # a fully-resolved arm is electable → the rest is avoidable
        return list(dict.fromkeys(tok for arm in per_arm for tok in arm))

    and_parts = _split_top_level(expr, " AND ")
    if len(and_parts) > 1:
        return list(
            dict.fromkeys(tok for p in and_parts for tok in unavoidable_unresolved_licenses(p))
        )

    return [expr] if classify_risk(expr) == RiskLevel.UNKNOWN else []
