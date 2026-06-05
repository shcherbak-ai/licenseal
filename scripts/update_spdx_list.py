"""Refresh the vendored SPDX license ID list.

Downloads ``index.json`` from github.com/jslicense/spdx-license-ids (CC0-1.0,
public domain) and writes it to ``src/licenseal/data/spdx-license-ids.json``.

Run::

    uv run python scripts/update_spdx_list.py

Re-run ``uv run python scripts/validate_spdx_ids.py`` afterwards to confirm
our overrides + alias targets still reference canonical IDs in the new list.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/jslicense/spdx-license-ids/main/index.json"
TARGET = (
    Path(__file__).resolve().parent.parent / "src" / "licenseal" / "data" / "spdx-license-ids.json"
)


def main() -> int:
    print(f"Fetching {SOURCE_URL}...")
    # Network call is reviewer-visible: the SOURCE_URL is hard-coded to the
    # SPDX-correct sibling repo. No other endpoints can be reached.
    request = urllib.request.Request(SOURCE_URL)  # noqa: S310
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310  # nosec B310
        payload = response.read()

    # Parse + re-dump so we normalise formatting (sorted, indented) — gives
    # a clean diff when a new SPDX release adds/removes IDs.
    ids = json.loads(payload)
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        print("Unexpected payload shape — expected JSON array of strings.")
        return 1

    ids = sorted(ids)
    TARGET.write_text(json.dumps(ids, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(ids)} SPDX IDs to {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
