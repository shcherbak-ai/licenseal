"""SPDX license ID normalization."""

from __future__ import annotations

import re

# Cargo's pre-SPDX convention used `/` as a synonym for `OR` in license fields,
# producing strings like `MIT/Apache-2.0`. Many older crates still publish this
# form. Translate it to the SPDX equivalent before further processing.
_SLASH_OR_RE = re.compile(r"\s*/\s*")

# Publisher conventions that point at a bundled license file rather than
# declaring a license identifier:
#   - npm `"SEE LICENSE IN <filename>"`
#   - shorter `"See COPYING"` / `"See LICENSE"` (single-token file reference)
#   - bare `"LICENSE.txt"` / `"LICENSE.md"` (publisher mistake — they meant
#     to point at the file but stored its name)
# All are opaque to a metadata-only scanner → Proprietary → manual review.
# `_SEE_FILE_RE` is deliberately split into two alternatives so it doesn't
# match free-form prose like ``"see LICENSE for details"`` — the conservative
# comma-split path treats such strings as unparseable and leaves them UNKNOWN.
_SEE_FILE_RE = re.compile(
    r"^see\s+\S+$"
    r"|^see\s+licen[cs]e\s+in\s+\S+",
    re.IGNORECASE,
)
# Match a publisher who put the literal license-file name in the `license`
# field instead of an SPDX identifier — both with extension (``LICENSE.txt``,
# ``LICENCE.md``) and bare (``LICENSE``, ``COPYING``). The bare form trips up
# a regex anchored to ``\.\w+$`` so we list both shapes explicitly.
_LICENSE_FILENAME_RE = re.compile(
    r"^(?:licen[cs]e|copying)(?:\.\w+)?$",
    re.IGNORECASE,
)

# SPDX `LicenseRef-*` is the namespace for project-defined custom license
# references — by definition opaque to a generic classifier, so route to
# Proprietary. `LicenseRef-Public-Domain` is our internal permissive sentinel
# (see `risk.py`) so it's excluded from this rule.
_LICENSE_REF_RE = re.compile(r"^LicenseRef-(?!Public-Domain$)", re.IGNORECASE)

# Free-form "this is a commercial / proprietary license" signals. The alias
# map catches well-known FOSS license names by their many variants; anything
# that misses both that and the SPDX shape check but mentions one of these
# markers is almost certainly a vendor commercial license and should route
# to Proprietary instead of generic UNKNOWN. Applied with `search`, so it
# would also match inside compound expressions — `normalize_license` gates
# this check on the absence of SPDX compound operators.
_PROPRIETARY_SIGNAL_RE = re.compile(
    r"\bproprietary\b"
    r"|\beula\b"
    r"|\blicen[cs]e\s+agreement\b"
    r"|\bsoftware\s+license\b"
    r"|\bterms\s+of\s+service\b",
    re.IGNORECASE,
)

# Non-license descriptor phrases some publishers append to a comma list of
# real SPDX IDs — e.g. ``"BSD-3-Clause, Apache-2.0, dependency licenses"``,
# where the trailing phrase points at bundled third-party dependency licenses,
# not a license of the package itself. Recognized noise is dropped from the
# comma-OR decomposition so the real IDs aren't lost to the all-or-nothing
# guard. Only *recognized* noise is dropped: an unrecognized token might be a
# real license, so it still blocks the compound and routes to manual review
# (dropping it could silently relax the verdict — the no-prose-extraction rule).
_LICENSE_NOISE_RE = re.compile(
    r"^(?:and\s+|plus\s+|incl(?:\.|uding)?\s+|see\s+)?"
    r"(?:the\s+)?"
    r"(?:bundled\s+|vendored\s+|third[\s-]?party\s+|other\s+|its\s+|various\s+)?"
    r"dependenc(?:y|ies)"
    r"(?:[\s'’-]*licen[cs]es?)?$",
    re.IGNORECASE,
)

# Map common license strings/classifiers to SPDX identifiers.
# This covers the vast majority of packages on PyPI and npm.
_NORMALIZATION_MAP: dict[str, str] = {
    # MIT variants
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "the mit license (mit)": "MIT",
    "mit license (mit)": "MIT",
    "mit licence": "MIT",
    "expat": "MIT",
    "expat license": "MIT",
    "the expat license": "MIT",
    "mit-cmu": "MIT-CMU",
    "mit-0": "MIT-0",
    "mit no attribution": "MIT-0",
    # BSD variants
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 2 clause": "BSD-2-Clause",
    "bsd-2-clause license": "BSD-2-Clause",
    "bsd 2-clause license": "BSD-2-Clause",
    "bsd (2-clause)": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "the 2-clause bsd license": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd 3 clause": "BSD-3-Clause",
    "bsd-3-clause license": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause",
    "bsd licence 3": "BSD-3-Clause",  # British spelling, no hyphen
    "bsd license 3": "BSD-3-Clause",
    "bsd licence 2": "BSD-2-Clause",
    "bsd license 2": "BSD-2-Clause",
    "bsd licence": "BSD-3-Clause",  # British spelling, no version (defaults to most-common 3-clause)
    "the bsd licence": "BSD-3-Clause",
    # ``GNU General Public License, version 2, with the Classpath Exception`` —
    # the publisher's literal expanded form (with the extra comma before
    # "with"). Without this entry the comma-decompose path splits into
    # ``GNU General Public License`` + ``version 2`` + ``with the Classpath
    # Exception`` (the last hits a proprietary-signal-style fallback).
    "gnu general public license, version 2, with the classpath exception": "GPL-2.0-with-classpath-exception",
    "gnu general public license version 2 with the classpath exception": "GPL-2.0-with-classpath-exception",
    "gnu general public license, version 2 with the classpath exception": "GPL-2.0-with-classpath-exception",
    # Same compound with the parenthesized ``(GPL)`` infix — common in
    # publisher POMs that name-drop the abbreviation in the long form.
    "gnu general public license (gpl), version 2, with the classpath exception": "GPL-2.0-with-classpath-exception",
    "gnu general public license (gpl), version 2, with the classpath exception)": "GPL-2.0-with-classpath-exception",  # trailing paren from lmp's compound parser
    # ``with the GNU Classpath Exception`` (extra "GNU" word before "Classpath")
    # — used by ``jakarta.el-api`` and other Eclipse-foundation EPL+GPL deps.
    "gnu general public license, version 2 with the gnu classpath exception": "GPL-2.0-with-classpath-exception",
    "gnu general public license, version 2, with the gnu classpath exception": "GPL-2.0-with-classpath-exception",
    # Short publisher phrasings ("GPLv2 with classpath exception" without
    # the GNU prefix or "version 2" expansion). Used by Sun-licensed
    # libraries and OpenJDK-derived projects like nashorn-core. Without
    # these, the bare phrase trips ``Proprietary`` via the comma-decompose
    # path that doesn't recognize the abbreviation.
    "gplv2 with classpath exception": "GPL-2.0-with-classpath-exception",
    "gpl v2 with classpath exception": "GPL-2.0-with-classpath-exception",
    "gpl v2 with the classpath exception": "GPL-2.0-with-classpath-exception",
    # Same shape as the longer "Dual license consisting of..." entries
    # below, but the short publisher phrasing seen in Sun/Oracle and
    # Jenkins-bundled artifacts.
    "cddl or gpl 2 with classpath exception": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "cddl v1.1 / gpl v2 dual license": "CDDL-1.1 AND GPL-2.0",
    # Eclipse-foundation prose variant with ``v.`` (period after ``v``).
    "eclipse public license v. 1.0": "EPL-1.0",
    "eclipse public license v. 2.0": "EPL-2.0",
    # ``Dual license consisting of the CDDL v1.1 and GPL v2`` — the Sun /
    # OpenJDK / glassfish.org pattern (different phrasing than ``CDDL +
    # GPLv2 with classpath exception``); used by ``javax.json``,
    # ``stax-ex``, ``jersey-multipart``, and the broader JSR-spec API
    # family. Has the same legal substance as the CDDL+GPL+CPE compound.
    "dual license consisting of the cddl v1.1 and gpl v2": "CDDL-1.1 AND GPL-2.0-with-classpath-exception",
    "dual license consisting of the cddl v1.0 and gpl v2": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "dual license consisting of the cddl v1.1 and gpl 2": "CDDL-1.1 AND GPL-2.0-with-classpath-exception",
    "3-clause bsd": "BSD-3-Clause",
    "3 clause bsd": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "newbsd": "BSD-3-Clause",
    "modified bsd": "BSD-3-Clause",
    "modified bsd license": "BSD-3-Clause",
    "revised bsd": "BSD-3-Clause",
    "revised bsd license": "BSD-3-Clause",
    "the 3-clause bsd license": "BSD-3-Clause",
    "bsd license (3-clause)": "BSD-3-Clause",
    "the bsd license": "BSD-3-Clause",  # bare form → conservative default
    "bsd-3": "BSD-3-Clause",
    "bsd3": "BSD-3-Clause",
    "bsd (3-clause)": "BSD-3-Clause",
    # FreeBSD's official license is the 2-clause BSD form.
    "freebsd": "BSD-2-Clause",
    "the freebsd license": "BSD-2-Clause",
    "bsd2": "BSD-2-Clause",
    "bsd-4-clause": "BSD-4-Clause",
    "original bsd": "BSD-4-Clause",
    # Apache variants
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache v2.0": "Apache-2.0",
    "apache v2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache2.0": "Apache-2.0",
    "apache 2 license": "Apache-2.0",
    "apachev2": "Apache-2.0",
    "apachev2.0": "Apache-2.0",
    "apache license (2.0)": "Apache-2.0",
    "apache software license (apache 2.0)": "Apache-2.0",
    "asl": "Apache-2.0",  # Red Hat / Fedora abbreviation for Apache Software License
    "asl 2": "Apache-2.0",
    "aslv2": "Apache-2.0",
    "al2": "Apache-2.0",  # less common Apache 2.0 abbreviation
    "al 2.0": "Apache-2.0",
    "al-2.0": "Apache-2.0",
    "apache license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license v2.0": "Apache-2.0",
    "apache license v2": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "apache 2.0 license": "Apache-2.0",
    "apache 2.0 software license": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "apache software license, version 2.0": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "asl-2.0": "Apache-2.0",
    "apache-1.1": "Apache-1.1",
    "apache 1.1": "Apache-1.1",
    # ISC
    "isc": "ISC",
    "iscl": "ISC",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    # GPL variants
    "gpl": "GPL-3.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v2.0": "GPL-2.0-only",
    "gnu general public license version 2": "GPL-2.0-only",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu gplv2": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "gpl-3.0-or-later": "GPL-3.0-or-later",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gpl v3.0": "GPL-3.0-only",
    "gpl2": "GPL-2.0-only",
    "gpl3": "GPL-3.0-only",
    "gplv2+": "GPL-2.0-or-later",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-2+": "GPL-2.0-or-later",
    "gpl-3+": "GPL-3.0-or-later",
    "gpl-3.0+": "GPL-3.0-or-later",
    "gplv3+": "GPL-3.0-or-later",
    "gnu gpl": "GPL-3.0-only",  # bare/version-less, conservative default
    "gnu-gpl": "GPL-3.0-only",
    "gnu gpl 3": "GPL-3.0-only",
    "gnu gplv3+": "GPL-3.0-or-later",
    "gnu general public license": "GPL-3.0-only",  # bare/version-less
    "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license v3.0": "GPL-3.0-only",
    "gnu general public license version 3": "GPL-3.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu gplv3": "GPL-3.0-only",
    "gnu general public license (gpl)": "GPL-3.0-only",
    # LGPL variants
    "lgpl": "LGPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-2.1-only": "LGPL-2.1-only",
    "lgpl-2.1-or-later": "LGPL-2.1-or-later",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl-2.0": "LGPL-2.0-only",
    "lgpl-2.0-only": "LGPL-2.0-only",
    "lgpl-2.0-or-later": "LGPL-2.0-or-later",
    "lgplv2": "LGPL-2.0-only",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license version 2": "LGPL-2.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
    "lgpl 2.1": "LGPL-2.1-only",
    "lgpl v2.1": "LGPL-2.1-only",
    "lgpl-2.1+": "LGPL-2.1-or-later",
    "lgplv2+": "LGPL-2.0-or-later",
    "lgplv2.1+": "LGPL-2.1-or-later",
    "gnu lesser general public license v2.1 (lgplv2.1)": "LGPL-2.1-only",
    "gnu lesser general public license version 2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0-only": "LGPL-3.0-only",
    "lgpl-3.0-or-later": "LGPL-3.0-or-later",
    "lgpl-3.0-or-newer": "LGPL-3.0-or-later",
    "lgplv3": "LGPL-3.0-only",
    "lgpl v3": "LGPL-3.0-only",
    "lgplv3+": "LGPL-3.0-or-later",
    "lgpl v3+": "LGPL-3.0-or-later",
    "gnu lgpl": "LGPL-3.0-only",  # bare/version-less form, conservative
    "gnu lgpl v3": "LGPL-3.0-only",
    "gnu lgpl v3+": "LGPL-3.0-or-later",
    "gnu lesser general public license v3": "LGPL-3.0-only",
    "gnu lesser general public license v3.0": "LGPL-3.0-only",
    "gnu lesser general public license version 3": "LGPL-3.0-only",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    # AGPL
    "agpl": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "agpl-3.0-only": "AGPL-3.0-only",
    "agpl-3.0-or-later": "AGPL-3.0-or-later",
    "agpl-3.0+": "AGPL-3.0-or-later",  # SPDX `+` → -or-later, matching gpl-3.0+/lgpl-2.1+
    "agplv3": "AGPL-3.0-only",
    "agplv3+": "AGPL-3.0-or-later",
    "agpl v3": "AGPL-3.0-only",
    "agpl v3+": "AGPL-3.0-or-later",
    "gnu agpl": "AGPL-3.0-only",  # bare/version-less, conservative default
    "gnu agpl v3": "AGPL-3.0-only",
    "gnu agpl v3+": "AGPL-3.0-or-later",
    "gnu agplv3": "AGPL-3.0-only",
    "gnu affero gpl": "AGPL-3.0-only",
    "gnu affero general public license": "AGPL-3.0-only",  # bare/version-less
    "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3.0": "AGPL-3.0-only",
    "gnu affero general public license version 3": "AGPL-3.0-only",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    # The spelled-out "GNU AFFERO GPL <ver>" form — sibling of the existing
    # "gnu affero gpl" / "...v3" entries, just with the version as a bare
    # trailing number. Used by Artifex-published bindings (PyMuPDF et al.).
    "gnu affero gpl 3.0": "AGPL-3.0-only",
    "gnu affero gpl 3": "AGPL-3.0-only",
    # Artifex's dual license, declared as free-form prose in the PyPI
    # ``license`` field. The AGPL arm is the one that constrains a permissive
    # consumer, so map the whole string to the structured dual expression —
    # otherwise the prose slips through as an unmatchable pseudo-identifier and
    # the copyleft arm never reaches the risk engine. Same idiom as the
    # CDDL/GPL "dual license consisting of…" entries above.
    "dual licensed - gnu affero gpl 3.0 or artifex commercial license": "AGPL-3.0-only OR Proprietary",
    "artifex commercial license": "Proprietary",
    # MPL
    "mpl": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license": "MPL-2.0",  # bare/version-less, conservative
    "mozilla public license v2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mplv2.0": "MPL-2.0",
    "mpl v2.0": "MPL-2.0",
    "mpl v2": "MPL-2.0",
    "mplv2": "MPL-2.0",
    "mpl-1.0": "MPL-1.0",
    "mpl 1.0": "MPL-1.0",
    "mpl-1.1": "MPL-1.1",
    "mpl 1.1": "MPL-1.1",
    "mozilla public license 1.1": "MPL-1.1",
    # EPL
    "epl": "EPL-2.0",
    "epl-1.0": "EPL-1.0",
    "epl-2.0": "EPL-2.0",
    "eclipse public license 1.0": "EPL-1.0",
    "eclipse public license v1.0": "EPL-1.0",
    "eclipse public license - v 1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0",
    "eclipse public license v2.0": "EPL-2.0",
    "eclipse public license - v 2.0": "EPL-2.0",
    # Eclipse Distribution License is BSD-3-Clause text (Eclipse Foundation
    # state this equivalence explicitly).
    "edl 1.0": "BSD-3-Clause",
    "edl-1.0": "BSD-3-Clause",
    "eclipse distribution license 1.0": "BSD-3-Clause",
    "eclipse distribution license v1.0": "BSD-3-Clause",
    "eclipse distribution license - v 1.0": "BSD-3-Clause",
    # Common Public License (predecessor to EPL, used by older JVM libraries).
    "cpl": "CPL-1.0",
    "cpl-1.0": "CPL-1.0",
    "cpl 1.0": "CPL-1.0",
    "common public license": "CPL-1.0",
    "common public license version 1.0": "CPL-1.0",
    "common public license - v 1.0": "CPL-1.0",
    "common public license v1.0": "CPL-1.0",
    # Apache Foundation publisher variants surfaced by the Java corpus.
    # The alias map already has "the apache software license, version 2.0";
    # these are the parallel "license without 'Software'" variants and the
    # abbreviation "ASF" used by some Apache projects (cglib, etc.).
    "the apache license, version 2.0": "Apache-2.0",
    "the apache license version 2.0": "Apache-2.0",
    # The ``The Apache Software License`` family — the leading ``The`` is
    # NOT covered by the bare ``apache software license`` entry above, and
    # without it the comma-decompose path tries to normalize ``"The Apache
    # Software License"`` standalone, which hits a proprietary-signal
    # regex and returns Proprietary (false positive).
    "the apache software license": "Apache-2.0",
    "the apache software license, version 2.0": "Apache-2.0",
    "the apache software license version 2.0": "Apache-2.0",
    "the apache software license, version 1.1": "Apache-1.1",
    "asf 2.0": "Apache-2.0",
    "asf license 2.0": "Apache-2.0",
    "apache software foundation 2.0": "Apache-2.0",
    # CDDL long-form variants (the GlassFish family — javax.activation,
    # javax.annotation-api, jaxb-api). The long-form name's
    # parenthesized "(CDDL)" hint trips the comma-split heuristic
    # without an alias entry.
    "cddl": "CDDL-1.0",
    "cddl license": "CDDL-1.0",
    "common development and distribution license": "CDDL-1.0",
    "common development and distribution license (cddl) v1.0": "CDDL-1.0",
    "common development and distribution license (cddl) version 1.0": "CDDL-1.0",
    "common development and distribution license (cddl) 1.0": "CDDL-1.0",
    "common development and distribution license (cddl) 1.1": "CDDL-1.1",
    "common development and distribution license (cddl) v1.1": "CDDL-1.1",
    "common development and distribution license (cddl) version 1.1": "CDDL-1.1",
    # The GlassFish dual-license shorthand (CDDL + GPL-2.0-with-classpath-
    # exception) for javax.* APIs that Sun originally released under both.
    "cddl+gpl": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "cddl+gpl license": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "cddl + gpl": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "cddl/gplv2+ce": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    # Sun/Oracle ``javax.*`` API canonical publisher string — used verbatim by
    # ``javax.servlet-api``, ``javax.el-api``, ``javax.annotation-api``, the
    # ``com.sun.jersey:*`` family, and other JSR specification artifacts.
    # Without this entry the embedded ``+`` and free-form ``with classpath
    # exception`` clause trip every compound-decomposition branch and the
    # name falls through to UNKNOWN; the resolver then probes deps.dev,
    # which returns ``"non-standard"`` for these artifacts, and the result
    # gets classified as Proprietary — losing real CDDL+GPL+CPE signal.
    "cddl + gplv2 with classpath exception": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "cddl + gpl2 with classpath exception": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "cddl+gplv2 with classpath exception": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    "cddl + gpl with the classpath exception": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    # GPL-2.0-with-classpath-exception abbreviations seen in JVM API POMs.
    "gpl2 w/ cpe": "GPL-2.0-with-classpath-exception",
    "gpl2 w/cpe": "GPL-2.0-with-classpath-exception",
    "gplv2+ce": "GPL-2.0-with-classpath-exception",
    "gpl-2.0+ce": "GPL-2.0-with-classpath-exception",
    "gpl-2.0 with classpath exception": "GPL-2.0-with-classpath-exception",
    "gpl 2.0 with classpath exception": "GPL-2.0-with-classpath-exception",
    "gpl with the classpath exception": "GPL-2.0-with-classpath-exception",
    # Some JVM API artifacts declare a dual license: EPL 2.0 (current) OR
    # GPL-2.0-with-classpath-exception (legacy). Some POMs write "AND"
    # but the legal intent is OR (either license suffices). We keep
    # the publisher's literal AND to match what the POM said; the risk
    # engine classifies GPL-with-classpath as weak copyleft (the
    # exception grants LGPL-style linking permission), so the AND form
    # still aggregates to weak copyleft rather than a strong-copyleft
    # violation.
    "epl 2.0 and gpl2 w/ cpe": "EPL-2.0 AND GPL-2.0-with-classpath-exception",
    "cddl 1.1 and gpl2 w/ cpe": "CDDL-1.1 AND GPL-2.0-with-classpath-exception",
    "cddl 1.0 and gpl2 w/ cpe": "CDDL-1.0 AND GPL-2.0-with-classpath-exception",
    # BSD variant phrasing
    "the bsd 2-clause license": "BSD-2-Clause",
    "the bsd 3-clause license": "BSD-3-Clause",
    # Some publishers ship an MIT-text license under a non-standard name
    # (the literal phrase below is the publisher's own wording, mapped
    # to canonical MIT here).
    "bouncy castle licence": "MIT",
    "bouncy castle license": "MIT",
    "the bouncy castle licence": "MIT",
    # ICU / Unicode — Unicode-DFS-2016 is the canonical SPDX ID.
    "unicode/icu license": "Unicode-DFS-2016",
    "icu license": "Unicode-DFS-2016",
    "unicode license": "Unicode-DFS-2016",
    # Apple's stock license text is proprietary commercial terms; map to
    # the Proprietary sentinel so the compat engine's short-circuit fires
    # (the LicenseRef-* fallthrough at the bottom of normalize_license
    # would route here too, but a direct alias is more explicit).
    "apple license": "Proprietary",
    # Some publishers write EPL+LGPL dual licensing as AND in the POM
    # (over-conservative — either license is sufficient by their own
    # stated SPDX expression). Map the literal compound string to keep
    # the AND form rather than rewriting publisher intent.
    "eclipse public license - v 1.0 and gnu lesser general public license": "EPL-1.0 AND LGPL-2.1",
    "eclipse public license - v 2.0 and gnu lesser general public license": "EPL-2.0 AND LGPL-2.1",
    # EPL variants that appear as split halves of compound POM strings
    # ("EPL 2.0 AND GPL2 w/ CPE"); decompose-and-normalize needs each
    # half to map independently.
    "epl 2.0": "EPL-2.0",
    "epl 1.0": "EPL-1.0",
    # Apache split-half variants surfaced by "Apache Software License -
    # Version 2.0 AND ..." compound POM strings.
    "apache software license - version 2.0": "Apache-2.0",
    "apache software license version 2.0": "Apache-2.0",
    # ``Eclipse Public License, Version 1.0`` (and v2.0) — with the literal
    # comma. Without these direct aliases the comma-decompose path would
    # split into ``Eclipse Public License`` (unknown) + ``Version 1.0``
    # (passes ``_looks_like_spdx``) and emit a nonsense compound.
    "eclipse public license, version 1.0": "EPL-1.0",
    "eclipse public license, version 2.0": "EPL-2.0",
    # Eclipse Public License split-half variants surfaced by some JVM POMs.
    "eclipse public license - version 1.0": "EPL-1.0",
    "eclipse public license - version 2.0": "EPL-2.0",
    # LGPL variants surfaced by various JVM analysis / dataset libraries.
    # Some POMs spell "Licence" (British), or omit "General", or include a
    # version number in the name.
    "gnu lesser general public license": "LGPL-3.0-only",  # bare (version-less)
    "gnu lesser general public license 2.1": "LGPL-2.1-only",
    "gnu lesser general public license, version 2.1": "LGPL-2.1-only",
    "gnu lesser general public license 3.0": "LGPL-3.0-only",
    "gnu lesser general public license, version 3.0": "LGPL-3.0-only",
    # CDDL split-half variants for compound POMs like "CDDL 1.1 AND GPL2 w/ CPE"
    "cddl 1.0": "CDDL-1.0",
    "cddl 1.1": "CDDL-1.1",
    "cddl-1.0": "CDDL-1.0",
    "cddl-1.1": "CDDL-1.1",
    "gnu lesser general public licence": "LGPL-3.0-only",  # British spelling
    "gnu lesser general public licence 2.1": "LGPL-2.1-only",
    "gnu lesser public license": "LGPL-3.0-only",  # missing "General" — seen in some POMs
    "gnu general public library": "GPL-3.0-only",  # POM typo: "Library" → "License"
    # Mozilla variants
    "mozilla public license version 2.0": "MPL-2.0",
    "mozilla public license version 1.1": "MPL-1.1",
    # Universal Permissive License — used by some JVM / Java EE projects.
    "upl": "UPL-1.0",
    "upl-1.0": "UPL-1.0",
    "upl 1.0": "UPL-1.0",
    "universal permissive license, version 1.0": "UPL-1.0",
    "universal permissive license version 1.0": "UPL-1.0",
    "universal permissive license v1.0": "UPL-1.0",
    "the universal permissive license (upl)": "UPL-1.0",
    # "Go License" string used by some Go-to-Java ports — Go itself ships
    # under BSD-3-Clause, so map the bare phrase to BSD-3-Clause.
    "go license": "BSD-3-Clause",
    "the go license": "BSD-3-Clause",
    # JAI (Java Advanced Imaging) imaging library — publisher labels its
    # license with a "w/nuclear disclaimer" suffix the comma-decomposer
    # treats as a proprietary signal. The underlying license is BSD-3-Clause.
    "bsd 3-clause license w/nuclear disclaimer": "BSD-3-Clause",
    # Oracle/MySQL Universal FOSS Exception — proprietary-leaning umbrella
    # over a GPL-2.0 base. The exception modifies the licensee's
    # obligations but doesn't change the underlying license-family
    # classification; map to GPL-2.0-only so the risk engine routes it
    # correctly. (Compat with a permissive project is still a violation;
    # FOSS exception scope is documented separately and outside the
    # coarse-matrix.)
    "the gnu general public license, v2 with universal foss exception, v1.0": "GPL-2.0-only",
    # JCP / JSR specifications use these stock license texts. Treat as
    # proprietary since the spec licenses restrict implementation rights;
    # the Proprietary sentinel routes through the compat engine's
    # short-circuit (manual review required for spec-license terms).
    "spec evaluation license": "Proprietary",
    "spec implementation license": "Proprietary",
    "spec evaluation license and spec implementation license": "Proprietary",
    # SPDX list publishers spell BSD-3-Clause's full name with embedded
    # ``"New" or "Revised"`` — the lowercase "or" trips the compound
    # decomposer. Map the full publisher string directly.
    'bsd 3-clause "new" or "revised" license': "BSD-3-Clause",
    'bsd 3-clause "new" or "revised" license (bsd-3-clause)': "BSD-3-Clause",
    # Oracle Free Use Terms — proprietary commercial license used by some
    # vendor JDBC / JVM client libraries. Embedded "and" trips the
    # decomposer; map directly to the Proprietary sentinel so the compat
    # engine's short-circuit fires (manual review required for FUTC terms).
    "oracle free use terms and conditions (futc)": "Proprietary",
    "oracle free use terms and conditions": "Proprietary",
    # EUPL
    "eupl-1.2": "EUPL-1.2",
    "european union public license 1.2": "EUPL-1.2",
    # Public domain / Unlicense / CC0
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "public domain": "LicenseRef-Public-Domain",
    "public-domain": "LicenseRef-Public-Domain",  # hyphenated publisher variant
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "cc0 1.0": "CC0-1.0",
    "cc0 1.0 universal": "CC0-1.0",
    # PSF / Python
    "psf": "PSF-2.0",
    "psf2": "PSF-2.0",
    "psfl": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
    "psf 2.0": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "python software foundation license version 2": "PSF-2.0",
    "python software foundation license, version 2": "PSF-2.0",
    "python-2.0": "Python-2.0",
    "python-2.0.1": "Python-2.0.1",
    "psf license": "PSF-2.0",
    # Artistic
    "artistic-2.0": "Artistic-2.0",
    "artistic license": "Artistic-2.0",  # bare form, defaults to current version
    "artistic license 2.0": "Artistic-2.0",
    # 0BSD
    "0bsd": "0BSD",
    # BSL (Boost)
    "bsl-1.0": "BSL-1.0",
    "boost": "BSL-1.0",
    "boost software license": "BSL-1.0",
    "boost software license 1.0": "BSL-1.0",
    # Zlib
    "zlib": "Zlib",
    "zlib license": "Zlib",
    # WTFPL
    "wtfpl": "WTFPL",
    # LaTeX Project Public License — GUST Font License (GFL) is built on
    # LPPL-1.3c with additional font-specific addenda; treat as LPPL-1.3c for
    # risk purposes (OSI-approved permissive).
    "gust font license (gfl)": "LPPL-1.3c",
    "gust font license": "LPPL-1.3c",
    "lppl-1.3c": "LPPL-1.3c",
    # NCSA — University of Illinois/NCSA Open Source License. OSI permissive.
    "ncsa": "NCSA",
    "university of illinois/ncsa open source license": "NCSA",
    # Zope Public License (OSI-approved permissive, common on plone/zope deps)
    "zpl": "ZPL-2.1",
    "zpl-1.1": "ZPL-1.1",
    "zpl 1.1": "ZPL-1.1",
    "zpl-2.0": "ZPL-2.0",
    "zpl 2.0": "ZPL-2.0",
    "zpl-2.1": "ZPL-2.1",
    "zpl 2.1": "ZPL-2.1",
    "zope public license": "ZPL-2.1",
    # Proprietary / no license
    "proprietary": "Proprietary",
    # npm convention: "UNLICENSED" means "private package, not for redistribution".
    # Semantically Proprietary; treat as such so private workspace packages
    # don't generate UNKNOWN noise in reports.
    "unlicensed": "Proprietary",
    # Cargo convention: when a publisher means "see source tree for license
    # details" without committing to an SPDX ID. Routing to Proprietary
    # triggers manual review via the dep-side override.
    "non-standard": "Proprietary",
    "custom": "Proprietary",
    # Source-available SPDX IDs — canonicalize English/abbreviated forms to
    # the SPDX identifier so the SPDX ID flows through the pipeline and shows
    # up in reports. `risk.py` overrides classify them as UNKNOWN, which
    # routes them through the compatibility matrix to manual review.
    "elastic license 2.0": "Elastic-2.0",
    "elv2": "Elastic-2.0",
    "business source license 1.1": "BUSL-1.1",
    # Unhelpful markers that should fall through to classifiers
    "dual license": "UNKNOWN",
    # Unknown markers
    "unknown": "UNKNOWN",
    "": "UNKNOWN",
    # Bare "License" / "LICENSE" — publisher gestured at the bundled license
    # file rather than declaring an SPDX identifier. Treated the same as
    # ``LICENSE.txt`` / ``SEE LICENSE IN ...``: route to Proprietary for
    # manual review (the bundled file might be permissive, but a metadata-only
    # scanner can't tell, and elevating to scrutiny is the safe direction).
    "license": "Proprietary",
    "licence": "Proprietary",
    "license :: osi approved": "UNKNOWN",
}

# PyPI trove classifier to SPDX mapping
_CLASSIFIER_MAP: dict[str, str] = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    # Generic (version-less) GPL classifier — conservative pick is the
    # most-restrictive current GPL (GPL-3.0-only).
    "License :: OSI Approved :: GNU General Public License (GPL)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    # Generic (version-less) LGPL classifier — conservative pick is the
    # most-restrictive current LGPL (LGPL-3.0-only). Still weak copyleft, so
    # risk classification is unaffected vs. picking 2.0/2.1.
    "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License (LGPL)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "License :: OSI Approved :: Eclipse Public License 1.0 (EPL-1.0)": "EPL-1.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Artistic License": "Artistic-2.0",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
    "License :: OSI Approved :: University of Illinois/NCSA Open Source License": "NCSA",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
    "License :: Public Domain": "LicenseRef-Public-Domain",
}


# Canonical license URLs published by major projects → SPDX identifier.
# Used by both :func:`spdx_from_license_url` (the direct helper consumed
# by Maven POM ``<license><url>`` reads) and the URL-detection branch of
# :func:`normalize_license` (when a project-license detector returns a
# URL — common for Python ``setup.py`` / ``pyproject.toml`` that put
# ``license="https://www.apache.org/licenses/LICENSE-2.0"``).
#
# Match by URL prefix to absorb trailing punctuation, anchor fragments,
# and the ``.html`` / ``.txt`` / ``.md`` extension variants. Order matters:
# more specific prefixes first (LGPL/GPL family is the relevant case —
# ``lgpl-2.1`` before bare ``lgpl`` before ``gpl``).
_LICENSE_URL_PREFIXES: tuple[tuple[str, str], ...] = (
    # Apache Foundation
    ("apache.org/licenses/license-2.0", "Apache-2.0"),
    ("apache.org/licenses/license-1.1", "Apache-1.1"),
    ("apache.org/licenses/license-1.0", "Apache-1.0"),
    # GNU family
    ("gnu.org/licenses/lgpl-3.0", "LGPL-3.0"),
    ("gnu.org/licenses/lgpl-2.1", "LGPL-2.1"),
    ("gnu.org/licenses/lgpl-2.0", "LGPL-2.0"),
    ("gnu.org/licenses/lgpl", "LGPL-3.0"),
    ("gnu.org/licenses/gpl-3.0", "GPL-3.0"),
    ("gnu.org/licenses/gpl-2.0", "GPL-2.0"),
    ("gnu.org/licenses/gpl-1.0", "GPL-1.0"),
    ("gnu.org/licenses/gpl", "GPL-3.0"),
    ("gnu.org/licenses/agpl-3.0", "AGPL-3.0"),
    ("gnu.org/licenses/agpl", "AGPL-3.0"),
    ("gnu.org/copyleft/lesser", "LGPL-2.1"),
    ("gnu.org/copyleft/gpl", "GPL-3.0"),
    # OSI canonical
    ("opensource.org/licenses/mit", "MIT"),
    ("opensource.org/licenses/bsd-3-clause", "BSD-3-Clause"),
    ("opensource.org/licenses/bsd-2-clause", "BSD-2-Clause"),
    ("opensource.org/licenses/bsd-license", "BSD-2-Clause"),
    ("opensource.org/licenses/apache-2.0", "Apache-2.0"),
    ("opensource.org/licenses/mpl-2.0", "MPL-2.0"),
    ("opensource.org/licenses/cddl-1.0", "CDDL-1.0"),
    ("opensource.org/licenses/cddl1.1", "CDDL-1.1"),
    ("opensource.org/licenses/cddl1", "CDDL-1.0"),
    ("opensource.org/licenses/isc", "ISC"),
    # Eclipse Foundation
    ("eclipse.org/legal/epl-v20", "EPL-2.0"),
    ("eclipse.org/legal/epl-2.0", "EPL-2.0"),
    ("eclipse.org/legal/epl-v10", "EPL-1.0"),
    ("eclipse.org/legal/epl-1.0", "EPL-1.0"),
    ("eclipse.org/org/documents/epl-2.0", "EPL-2.0"),
    ("eclipse.org/org/documents/epl-v10", "EPL-1.0"),
    ("eclipse.org/org/documents/edl-v10", "BSD-3-Clause"),
    ("eclipse.org/org/documents/edl-1.0", "BSD-3-Clause"),
    # Mozilla
    ("mozilla.org/mpl/2.0", "MPL-2.0"),
    ("mozilla.org/mpl/1.1", "MPL-1.1"),
    ("mozilla.org/mpl/1.0", "MPL-1.0"),
    # GlassFish / Java legacy
    ("glassfish.dev.java.net/public/cddlv1.0", "CDDL-1.0"),
    ("glassfish.java.net/public/cddl-gplv2-ce", "GPL-2.0-with-classpath-exception"),
    ("oracle.com/technetwork/java/javase/terms/license", "Oracle-BCL"),
    # JSON.org (unique restrictive license)
    ("json.org/license", "JSON"),
    # Creative Commons
    ("creativecommons.org/publicdomain/zero/1.0", "CC0-1.0"),
    ("creativecommons.org/licenses/by/4.0", "CC-BY-4.0"),
    ("creativecommons.org/licenses/by-sa/4.0", "CC-BY-SA-4.0"),
    ("creativecommons.org/licenses/by/3.0", "CC-BY-3.0"),
    ("creativecommons.org/licenses/by-sa/3.0", "CC-BY-SA-3.0"),
    # Unlicense + public-domain markers
    ("unlicense.org", "Unlicense"),
    # SPDX canonical (some publishers point directly at SPDX) — special
    # cased: pull the ID from the path segment after this marker.
    ("spdx.org/licenses/", ""),
    # WTFPL
    ("wtfpl.net", "WTFPL"),
    ("www.wtfpl.net", "WTFPL"),
    # MIT-text license under a vendor-specific name (URL on a publisher
    # site that hosts MIT-equivalent terms).
    ("bouncycastle.org/licence", "MIT"),
    # Public-domain / aopalliance-style URLs. Emit the internal permissive
    # sentinel directly: a bare "Public-Domain" matches neither the risk
    # overrides nor any family pattern and would route a known
    # public-domain artifact to manual review.
    ("aopalliance.sourceforge.net/license", "LicenseRef-Public-Domain"),
)


def spdx_from_license_url(url: str) -> str:
    """Map a license URL to an SPDX identifier when the URL points at a
    canonical publisher / SPDX license page.

    Returns ``""`` when no canonical URL match is found. The caller treats
    that as "URL fallback didn't help."
    """
    if not url:
        return ""

    def _norm(s: str) -> str:
        s = s.strip()
        for prefix in ("https://", "http://"):
            if s.lower().startswith(prefix):
                s = s[len(prefix) :]
                break
        if s.lower().startswith("www."):
            s = s[4:]
        for sep in ("?", "#"):
            if sep in s:
                s = s.split(sep, 1)[0]
        for ext in (".html", ".htm", ".txt", ".md", ".php", ".json", ".xml"):
            if s.lower().endswith(ext):
                s = s[: -len(ext)]
        return s.rstrip("/")

    u_cased = _norm(url)
    u = u_cased.lower()
    if not u:
        return ""

    spdx_marker = "spdx.org/licenses/"
    idx = u.find(spdx_marker)
    if idx >= 0:
        tail = u_cased[idx + len(spdx_marker) :]
        # SPDX 3+ deprecated the ``+`` suffix in favor of ``-or-later``;
        # canonical risk classification strips ``+`` defensively, but the
        # license_id surfaced from URL extraction should already use the
        # base form. The risk-classifier handles either, but downstream
        # alias normalization is cleaner without the trailing ``+``.
        return tail.split("/", 1)[0].rstrip("+")

    for marker, spdx in _LICENSE_URL_PREFIXES:
        if marker in u:
            return spdx
    return ""


def _looks_like_url(value: str) -> bool:
    lower = value.lower()
    return lower.startswith(("http://", "https://"))


def _split_top_level(expr: str, sep: str) -> list[str]:
    """Split ``expr`` on ``sep`` at paren-depth 0 only.

    ``"A OR (B AND C) OR D"`` split on ``" OR "`` returns
    ``["A", "(B AND C)", "D"]`` — the inner ``OR``-less ``AND`` at
    depth 1 is not a split point. Used by the SPDX-operand
    canonicalizer below; the publisher's `OR`/`AND` placement carries
    grouping that surface-level string split would clobber.
    """
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    sep_len = len(sep)
    while i <= len(expr) - sep_len:
        c = expr[i]
        if c == "(":
            depth += 1
            i += 1
        elif c == ")":
            depth -= 1
            i += 1
        elif depth == 0 and expr[i : i + sep_len] == sep:
            parts.append(expr[start:i].strip())
            i += sep_len
            start = i
        else:
            i += 1
    parts.append(expr[start:].strip())
    return parts


def _strip_outer_parens(expr: str) -> str:
    """Strip ONE matched outer-paren wrap if the parens are the outermost grouping.

    ``"(A OR B)"`` → ``"A OR B"``; ``"(A) AND (B)"`` → unchanged (outer
    ``(`` closes before end-of-string). Repeated wraps like ``"((A))"``
    need repeated calls; the canonicalizer calls this from inside the
    recursive descent so each level peels one wrap.
    """
    if not (expr.startswith("(") and expr.endswith(")")):
        return expr
    depth = 0
    for i, c in enumerate(expr):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and i < len(expr) - 1:
                # Outer ``(`` closed before string end → these are NOT matched
                # outermost parens (e.g. ``"(A) AND (B)"``). Leave unchanged.
                return expr
    return expr[1:-1].strip()


def _canonicalize_spdx_operands(expr: str) -> str:
    """Sort OR/AND operands case-insensitively at every nesting level.

    SPDX's ``OR`` and ``AND`` operators are commutative — ``"MIT OR
    Apache-2.0"`` and ``"Apache-2.0 OR MIT"`` are semantically identical
    but compare as different strings, which silently inflates
    disagreement when comparing licenses sourced from different
    registries (Cargo.toml's publisher field vs deps.dev's
    ``licensecheck`` output is the canonical case — 90% of apparent Rust
    cross-source disagreement is operand-order, verified by
    ``licenseal-scans/_probe_deps_dev_rust_disagreement.py``).

    Algorithm:
    * ``OR`` binds looser than ``AND`` binds looser than ``WITH`` (SPDX
      precedence). We split first on top-level ``OR``, then ``AND`` for
      each operand, then leave ``WITH``-compounds as opaque leaves
      (``WITH`` is NOT commutative — ``"Apache-2.0 WITH LLVM-exception"``
      is a single leaf for the purposes of operand sorting).
    * At each ``OR`` / ``AND`` node, sort children case-insensitively
      after recursive canonicalization.
    * Re-serialize with the minimum parens needed: ``AND`` children that
      contain a top-level ``OR`` get wrapped; ``OR`` children never do
      (since ``OR`` is the lowest-precedence operator).

    Best-effort: returns ``expr`` unchanged if the input doesn't parse
    as a recognizable compound (no top-level operators or unbalanced
    parens). Whitespace inside the expression is collapsed to single
    spaces so ``"MIT  OR Apache-2.0"`` canonicalizes the same as the
    well-spaced form.
    """
    expr = " ".join(expr.split())
    if expr.count("(") != expr.count(")"):
        return expr
    if " OR " not in expr and " AND " not in expr:
        return expr
    return _canon(expr)


def _canon(expr: str) -> str:
    """Recursive worker for :func:`_canonicalize_spdx_operands`."""
    expr = _strip_outer_parens(expr.strip())
    or_parts = _split_top_level(expr, " OR ")
    if len(or_parts) > 1:
        canonical = sorted((_canon(p) for p in or_parts), key=str.lower)
        return " OR ".join(canonical)
    and_parts = _split_top_level(expr, " AND ")
    if len(and_parts) > 1:
        canonical: list[str] = []
        for p in and_parts:
            c = _canon(p)
            # Wrap children that contain a top-level ``OR`` so that the
            # serialized form is unambiguous to readers/tools that don't
            # apply SPDX precedence. ``AND``/``WITH`` children don't
            # need wrapping since ``AND`` binds tighter than ``OR``.
            if " OR " in c and len(_split_top_level(c, " OR ")) > 1:
                c = f"({c})"
            canonical.append(c)
        canonical.sort(key=str.lower)
        return " AND ".join(canonical)
    return expr


_LGPL_VARIANT_RE = re.compile(
    r"^LGPL-(?P<ver>\d+(?:\.\d+)*)(?:-only|-or-later)?$",
    re.IGNORECASE,
)
_GPL_VARIANT_RE = re.compile(
    r"^GPL-(?P<ver>\d+(?:\.\d+)*)(?:-only|-or-later)?$",
    re.IGNORECASE,
)
_CDDL_GPL_CPE_AND_RE = re.compile(r"^CDDL-\d+(?:\.\d+)* AND GPL-2\.0-with-classpath-exception$")


def _collapse_redundant_license_pairs(expr: str) -> str:
    """Rewrite AND-chains where one license is a redundant inclusion of another.

    Two patterns, both narrow and ecosystem-observed:

    * ``LGPL-X.Y AND GPL-X.Y`` → ``LGPL-X.Y``. The LGPL license text
      embeds the GPL by reference (LGPL packages routinely ship both
      LICENSE files), so deps.dev's ``licensecheck`` returns both when
      it scans the source tree. Complying with LGPL already satisfies
      GPL — the AND-join is the publisher-bundled-both pattern, not a
      dual-license declaration. Triggered when the AND-chain contains
      ``LGPL-X.Y[-only|-or-later]`` and any ``GPL-X.Y[-only|-or-later]``
      of the same X.Y; the GPL variants are dropped. The LGPL-2.1 +
      GPL-2.0 case is also covered (LGPL-2.1 explicitly references
      GPL-2.0). Without this, packages like ``PyGithub`` (LGPL-3.0
      publisher declaration; ships LICENSE.GPL alongside) classify as
      strong-copyleft / violation when AND-aggregated.

    * Exact ``CDDL-X.Y AND GPL-2.0-with-classpath-exception`` →
      ``CDDL-X.Y OR GPL-2.0-with-classpath-exception``. The
      Sun/Oracle dual-license shorthand used by ``javax.*`` APIs and
      most Jakarta EE specifications. Maven POM `<licenses>` has no
      OR operator, so the convention is to list both under AND even
      though publisher intent is OR (either license suffices). Narrow
      to the exact two-operand shape so we don't reinterpret AND in
      multi-license compounds that may genuinely intend all-apply.

    Operates on the operand-canonicalized form (called from
    :func:`normalize_license` after :func:`_canonicalize_spdx_operands`),
    so operand order is deterministic and string-matching is safe.
    """
    # Exact-shape Sun/Oracle javax.* pattern: rewrite AND → OR.
    if _CDDL_GPL_CPE_AND_RE.match(expr):
        return expr.replace(" AND ", " OR ", 1)

    if " AND " not in expr:
        return expr
    parts = _split_top_level(expr, " AND ")

    lgpl_versions: set[str] = set()
    gpl_indices: list[tuple[int, str]] = []
    for i, part in enumerate(parts):
        lgpl_match = _LGPL_VARIANT_RE.match(part)
        if lgpl_match:
            lgpl_versions.add(lgpl_match.group("ver"))
            continue
        gpl_match = _GPL_VARIANT_RE.match(part)
        if gpl_match:
            gpl_indices.append((i, gpl_match.group("ver")))

    if not lgpl_versions or not gpl_indices:
        return expr

    drop: set[int] = set()
    for idx, gpl_ver in gpl_indices:
        if gpl_ver in lgpl_versions:
            drop.add(idx)
            continue
        # LGPL-2.1 explicitly references GPL-2.0 — same inclusion relation.
        if gpl_ver == "2.0" and "2.1" in lgpl_versions:
            drop.add(idx)

    if not drop:
        return expr
    remaining = [p for j, p in enumerate(parts) if j not in drop]
    if len(remaining) == 1:
        return remaining[0]
    return " AND ".join(remaining)


def normalize_license(raw: str) -> str:
    """Normalize a license string to an SPDX identifier.

    Handles PyPI license fields, trove classifiers, npm license fields,
    and common variations. Compound SPDX expressions in the result are
    operand-canonicalized (``OR``/``AND`` children sorted
    case-insensitively at every level) so equality comparison reflects
    SPDX semantics rather than source string order. Known
    redundant-inclusion patterns (``LGPL+GPL`` of the same family,
    Sun/Oracle's ``CDDL+GPL-with-classpath-exception`` AND-shorthand for
    publisher-intended-OR dual licensing) are also collapsed — see
    :func:`_collapse_redundant_license_pairs`.
    """
    return _collapse_redundant_license_pairs(
        _canonicalize_spdx_operands(_normalize_license_inner(raw))
    )


def _normalize_license_inner(raw: str) -> str:
    """Source-string-to-SPDX mapping without operand canonicalization."""
    if not raw:
        return "UNKNOWN"

    stripped = raw.strip()

    # URL inputs: some publishers populate the ``license`` field with a
    # URL to the canonical license text (common in Python ``setup.py`` /
    # ``pyproject.toml`` and a few Maven ``<license><name>`` slots that
    # mistakenly hold the URL). Route through the URL-prefix table.
    if _looks_like_url(stripped):
        spdx = spdx_from_license_url(stripped)
        if spdx:
            return spdx
        # Unrecognized URL — fall through; nothing else below handles a
        # URL shape, so the function returns "UNKNOWN" at the bottom.
    # Strip a single set of outer parens if they wrap the whole
    # expression — common Java publisher convention is to write
    # ``(Apache-2.0 OR EPL-2.0)`` or ``(MIT)``. The compound-expression
    # branches below match without the wrap.
    if (
        stripped.startswith("(")
        and stripped.endswith(")")
        and stripped.count("(") == 1
        and stripped.count(")") == 1
    ):
        stripped = stripped[1:-1].strip()

    # Check classifier map first (exact match)
    if stripped in _CLASSIFIER_MAP:
        return _CLASSIFIER_MAP[stripped]

    # Direct alias lookup runs BEFORE slash-as-OR translation so license
    # names containing a literal slash (``"University of Illinois/NCSA Open
    # Source License"``) can match alias entries before the slash is
    # rewritten as ``OR``. Cargo's legacy `MIT/Apache-2.0` form still works
    # because it doesn't have an entry in the alias map and falls through
    # to the slash branch below.
    key = stripped.lower()
    if key in _NORMALIZATION_MAP:
        return _NORMALIZATION_MAP[key]

    # Translate Cargo's legacy slash-as-OR form before SPDX recognition.
    # Compound expressions like `MIT/Apache-2.0` are unwrapped here and
    # fall through to the compound classifier — no alias entry combines
    # licenses with OR/AND, so we don't re-lookup the translated form.
    # Recurse so each part is itself normalized — important for prose names
    # like ``"Eclipse Public License v2.0 / Eclipse Distribution License
    # v1.0"`` where the slash-OR alone doesn't produce SPDX IDs.
    if "/" in stripped and " OR " not in stripped and " AND " not in stripped:
        parts = [p.strip() for p in stripped.split("/")]
        normalized_parts = [normalize_license(p) for p in parts]
        if all(p != "UNKNOWN" for p in normalized_parts):
            return " OR ".join(normalized_parts)
        stripped = _SLASH_OR_RE.sub(" OR ", stripped)

    # File-pointer / filename-mistake / LicenseRef patterns are all anchored
    # at `^`, so they only fire on whole-string inputs (won't match inside a
    # compound expression).
    if _SEE_FILE_RE.match(stripped):
        return "Proprietary"
    if _LICENSE_FILENAME_RE.match(stripped):
        return "Proprietary"
    if _LICENSE_REF_RE.match(stripped):
        return "Proprietary"

    # Free-form proprietary signals (`\bproprietary\b`, EULA, "License
    # Agreement", etc.) use `search`, so we suppress them inside SPDX
    # compound expressions — otherwise `"MIT OR LicenseRef-NVIDIA-Proprietary"`
    # would lose its MIT branch.
    if (
        " OR " not in stripped
        and " AND " not in stripped
        and " WITH " not in stripped
        and _PROPRIETARY_SIGNAL_RE.search(stripped)
    ):
        return "Proprietary"

    # Comma-separated multi-license: PyPI publishers commonly express dual
    # licensing informally as `"BSD, Public Domain"` (pycryptodome) or
    # `"MIT, Apache-2.0"`. Treat as an OR compound only when every part
    # independently normalizes to a known license — that avoids splitting
    # license names that contain a legitimate comma (`"Apache License,
    # Version 2.0"` is already caught by the direct lookup above).
    if "," in stripped and " OR " not in stripped and " AND " not in stripped:
        parts = [p.strip() for p in stripped.split(",")]
        # Drop recognized non-license descriptor tokens (e.g. "dependency
        # licenses") so a comma list of real SPDX IDs isn't lost to the
        # all-or-nothing guard below just because the publisher tacked on a
        # bundled-deps note. Unrecognized tokens are NOT dropped (see
        # _LICENSE_NOISE_RE) — they still block the compound.
        parts = [p for p in parts if not _LICENSE_NOISE_RE.match(p)]
        normalized_parts = [normalize_license(p) for p in parts]
        if parts and all(p != "UNKNOWN" for p in normalized_parts):
            return " OR ".join(normalized_parts)

    # Informal " -or- " separator: same intent as comma-as-OR. Seen in PyPI
    # publisher prose like ``"MIT -or- Apache License 2.0"``. Conservative
    # split — only treat as compound when every part normalizes cleanly.
    if " -or- " in stripped and " OR " not in stripped and " AND " not in stripped:
        parts = [p.strip() for p in stripped.split(" -or- ")]
        normalized_parts = [normalize_license(p) for p in parts]
        if all(p != "UNKNOWN" for p in normalized_parts):
            return " OR ".join(normalized_parts)

    # Lowercase ``and`` / ``or`` connectors: publisher prose often uses
    # ``"MIT and ISC"`` or ``"BSD or MIT"`` instead of the SPDX-standard
    # uppercase keywords. Split case-insensitively so each side normalizes.
    for connector, joiner in ((" and ", " AND "), (" or ", " OR ")):
        if connector in stripped.lower() and " AND " not in stripped and " OR " not in stripped:
            lower = stripped.lower()
            parts: list[str] = []
            prev = 0
            pos = 0
            while True:
                idx = lower.find(connector, pos)
                if idx < 0:
                    break
                parts.append(stripped[prev:idx].strip())
                prev = idx + len(connector)
                pos = prev
            parts.append(stripped[prev:].strip())
            normalized_parts = [normalize_license(p) for p in parts if p]
            if len(normalized_parts) >= 2 and all(p != "UNKNOWN" for p in normalized_parts):
                return joiner.join(normalized_parts)

    # If it looks like a valid SPDX ID already (contains uppercase, hyphens),
    # return as-is
    if _looks_like_spdx(stripped):
        return stripped

    return "UNKNOWN"


def _looks_like_spdx(value: str) -> bool:
    """Heuristic: does this look like a valid SPDX expression?

    An SPDX expression is a sequence of license-ID *leaves* joined by the
    operators ``OR`` / ``AND`` / ``WITH``. Two shape rules follow from that
    grammar:

    * **Each non-operator token must be ID-shaped** — it must contain an
      uppercase letter, digit, or hyphen. The hyphen/digit branch catches
      all-lowercase SPDX IDs that SPDX defines this way
      (``zlib-acknowledgement``, ``cc-by-sa-4.0`` raw forms); without it an
      ``X OR Y`` compound where one side is such an ID would flunk even
      though the OR classifier would correctly pick the other branch.
    * **ID leaves must be separated by an operator** — a run of two or more
      adjacent non-operator tokens is prose, not an expression. Without this
      rule, capitalized vendor prose such as ``"Dual Licensed - GNU AFFERO
      GPL 3.0"`` or ``"Artifex Commercial License"`` slips through as a fake
      identifier (every word is individually ID-shaped) and pollutes the
      compatibility engine with an unmatchable pseudo-license that reads as
      ``UNKNOWN`` only after the matrix lookup, losing the real signal.
    """
    if len(value) > 200:
        return False
    parts = value.split()
    if not parts:
        return False
    spdx_keywords = {"OR", "AND", "WITH"}
    prev_was_leaf = False
    saw_leaf = False
    for tok in parts:
        if tok in spdx_keywords:
            prev_was_leaf = False
            continue
        # Strip grouping parens / the SPDX `+` suffix before shape-testing the
        # leaf, so `(MIT`, `Apache-2.0)`, and `GPL-2.0+` are judged on the ID.
        leaf = tok.strip("()").rstrip("+")
        if not any(c.isupper() or c.isdigit() or c == "-" for c in leaf):
            return False
        if prev_was_leaf:
            # Two ID leaves with no operator between them ⇒ prose.
            return False
        prev_was_leaf = True
        saw_leaf = True
    return saw_leaf


# --- R / CRAN license translation -------------------------------------------
#
# R's ``DESCRIPTION`` ``License:`` field is not SPDX. Its grammar:
#   * ``|`` separates alternatives the user may choose between (disjunction).
#   * ``+ file LICEN[CS]E`` points at a bundled file carrying the extra terms R
#     requires (e.g. the MIT copyright stub). When a recognized token precedes
#     it we keep the token; a bare ``file LICENSE`` is opaque to a metadata-only
#     scanner → UNKNOWN (manual review), per the no-prose-extraction rule.
#   * ``(>= N)`` / ``(== N)`` version constraints sit in parens after the name.
#   * tokens use R abbreviations (``GPL-2``, ``BSD_3_clause``, ``Unlimited``)
#     the generic normalizer misses — ``GPL-2`` even looks SPDX-shaped and would
#     pass straight through ``normalize_license`` unchanged.

_R_FILE_RE = re.compile(r"^file\s+\S+$", re.IGNORECASE)

# GPL / LGPL / AGPL with a parenthesized version range — ``GPL (>= 2)`` →
# or-later, ``LGPL (== 2.1)`` → that version only. ``AGPL``/``LGPL`` precede
# ``GPL`` in the alternation so the longer prefixes win.
_R_GPL_FAMILY_RE = re.compile(
    r"^(?P<fam>AGPL|LGPL|GPL)\s*\(\s*(?P<op>>=|>|==)\s*(?P<ver>\d+(?:\.\d+)?)\s*\)$",
    re.IGNORECASE,
)

# A trailing version-pin paren on a non-GPL name, e.g. ``Apache License (== 2.0)``.
# The version is captured so it can be folded into the name without a second scan.
_R_VERSION_PAREN_RE = re.compile(r"\(\s*(?:>=|>|==|<=|<)\s*(\d+(?:\.\d+)?)\s*\)")

# R license abbreviations that the generic ``normalize_license`` map misses or
# would mis-handle.
_R_LICENSE_ALIASES: dict[str, str] = {
    "gpl-2": "GPL-2.0-only",
    "gpl-3": "GPL-3.0-only",
    "lgpl-2": "LGPL-2.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3": "LGPL-3.0-only",
    "agpl-3": "AGPL-3.0-only",
    "bsd_2_clause": "BSD-2-Clause",
    "bsd_3_clause": "BSD-3-Clause",
    # ``Unlimited`` is an R keyword ("unlimited distribution"), not a license —
    # route to scrutiny rather than guessing a permissive verdict.
    "unlimited": "UNKNOWN",
}


def _r_spdx_version(ver: str) -> str:
    """Normalize an R license version to SPDX's ``X.Y`` shape (``2`` → ``2.0``)."""
    return ver if "." in ver else f"{ver}.0"


def _translate_r_operand(operand: str) -> str:
    """Translate one ``|``-separated R license alternative to an SPDX ID."""
    operand = operand.strip()
    if not operand:
        return "UNKNOWN"
    # ``<token> + file LICENSE`` — keep the structured token, drop the file ref.
    if "+" in operand:
        operand = operand.split("+", 1)[0].strip()
    # Bare ``file LICENSE`` / ``file LICENCE`` (or an empty head) is opaque.
    if not operand or _R_FILE_RE.match(operand):
        return "UNKNOWN"
    fam_match = _R_GPL_FAMILY_RE.match(operand)
    if fam_match:
        fam = fam_match.group("fam").upper()
        base = _r_spdx_version(fam_match.group("ver"))
        suffix = "-or-later" if fam_match.group("op") in (">=", ">") else "-only"
        return f"{fam}-{base}{suffix}"
    # Fold a trailing version-pin paren into the name so the generic normalizer
    # recognizes it (``Apache License (== 2.0)`` → ``Apache License 2.0``).
    paren = _R_VERSION_PAREN_RE.search(operand)
    if paren:
        operand = f"{operand[: paren.start()].strip()} {paren.group(1)}".strip()
    aliased = _R_LICENSE_ALIASES.get(operand.lower())
    if aliased is not None:
        return aliased
    return normalize_license(operand)


def normalize_r_license(raw: str) -> str:
    """Normalize an R ``DESCRIPTION`` ``License:`` string to an SPDX expression.

    R's ``|`` is a user-choice disjunction → ``OR``. Alternatives that resolve
    to UNKNOWN (a bare ``file LICENSE`` reference, the ``Unlimited`` keyword)
    are dropped when at least one alternative resolves cleanly — the user may
    elect the known branch. When every alternative is UNKNOWN the whole field
    is UNKNOWN (manual review).
    """
    if not raw or not raw.strip():
        return "UNKNOWN"
    operands = [_translate_r_operand(part) for part in raw.split("|")]
    known = [op for op in operands if op != "UNKNOWN"]
    if not known:
        return "UNKNOWN"
    if len(known) == 1:
        return known[0]
    return normalize_license(" OR ".join(known))
