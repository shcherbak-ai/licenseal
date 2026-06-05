"""CI sanity check: every SPDX ID we reference must be in the canonical list.

Catches typos in the risk override / pattern data + the spdx alias targets.
The canonical list is vendored at ``src/licenseal/data/spdx-license-ids.json``
(CC0-1.0, from github.com/jslicense/spdx-license-ids). Refresh with::

    uv run python scripts/update_spdx_list.py

Run directly::

    uv run python scripts/validate_spdx_ids.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the in-tree source importable without an installed editable.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from licenseal.analysis.risk import (  # noqa: E402
    _RISK_OVERRIDES,
    KNOWN_SPDX_IDS,
)
from licenseal.analysis.spdx import _CLASSIFIER_MAP, _NORMALIZATION_MAP  # noqa: E402

# Internal sentinels that aren't canonical SPDX IDs but we use deliberately.
_INTERNAL_SENTINELS = {
    "UNKNOWN",
    "NOASSERTION",
    "Proprietary",
    "LicenseRef-Public-Domain",
}

# Deprecated-but-real SPDX identifiers referenced deliberately. These carry
# upstream ``isDeprecatedLicenseId`` (so they're absent from the canonical
# list) yet are genuine SPDX IDs, not typos. ``GPL-2.0-with-classpath-exception``
# is the single-token alias for the GlassFish/javax dual-license shorthand; it
# keeps operand canonicalization and the CDDL+GPL ``AND``→``OR`` rewrite in
# ``analysis/spdx.py`` simple. The canonical ``GPL-2.0-only WITH
# Classpath-exception-2.0`` form is still recognized on input.
_INTENTIONAL_DEPRECATED_SPDX_IDS = {
    "GPL-2.0-with-classpath-exception",
}


def _is_valid_target(license_id: str) -> bool:
    """An ID is valid if it's in the canonical SPDX list, an internal
    sentinel, an intentional deprecated-but-real SPDX ID, or a
    ``LicenseRef-*`` identifier (SPDX namespace for references). Compound
    expressions are validated piece-wise by the runtime; this CI check only
    inspects bare IDs."""
    base = license_id.rstrip("+")
    if base in KNOWN_SPDX_IDS or base in _INTERNAL_SENTINELS:
        return True
    if base in _INTENTIONAL_DEPRECATED_SPDX_IDS:
        return True
    return base.startswith("LicenseRef-")


def main() -> int:
    errors: list[str] = []

    for license_id in _RISK_OVERRIDES:
        if not _is_valid_target(license_id):
            errors.append(f"_RISK_OVERRIDES key {license_id!r} is not a known SPDX ID")

    for label, src in (
        ("_NORMALIZATION_MAP target", _NORMALIZATION_MAP.values()),
        ("_CLASSIFIER_MAP target", _CLASSIFIER_MAP.values()),
    ):
        for target in src:
            # Skip compound expressions (the runtime decomposes them).
            if " " in target:
                continue
            if not _is_valid_target(target):
                errors.append(f"{label}: {target!r} is not a known SPDX ID")

    if errors:
        print("Invalid SPDX IDs found:")
        for err in errors:
            print(f"  {err}")
        return 1

    print(
        f"OK: {len(_RISK_OVERRIDES)} risk overrides + "
        f"{len(_NORMALIZATION_MAP)} alias targets + "
        f"{len(_CLASSIFIER_MAP)} classifier targets all reference canonical SPDX IDs."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
