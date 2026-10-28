"""Run licenseal's CLI under tethered with only the registry hosts allowed.

``harness.py`` starts every licenseal run through this script, so a request
that goes around licenseal's client to any other host fails the scan with
``Blocked by tethered`` instead of passing unseen. tethered is a development
dependency: licenseal itself ships no egress guard beyond its client's host
check.
"""

from __future__ import annotations

import tethered

from licenseal.cli import _REGISTRY_HOSTS, main  # noqa: PLC2701

tethered.activate(allow=_REGISTRY_HOSTS)
main(prog_name="licenseal")
