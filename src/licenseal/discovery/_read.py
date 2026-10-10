"""Robust, encoding-aware, gap-surfacing file reads for discovery parsers.

Two jobs:

**1. Decode defensively.** Manifests in the wild aren't always UTF-8 — Windows
PowerShell 5.1 writes UTF-16 LE / UTF-8-with-BOM, and legacy single-byte
encodings show up inside comments. A naive ``read_text(encoding="utf-8")``
raises ``UnicodeDecodeError`` on the first bad byte, dropping the *whole* file
(every dependency it declares) over a stray byte in a discarded comment. The
loaders here BOM-detect, fall back to latin-1 for text, and hand XML raw bytes
to its encoding-aware parser. Nothing here raises on file content: bytes that
can't be decoded, and documents nested too deeply to parse, are recorded as
gaps like any other parse failure.

**2. Surface gaps, never silently.** For a license scanner a silent skip is the
worst error class: "0 problems" then means *either* "nothing wrong" *or* "I
couldn't look". So every read/parse failure is recorded on a context-scoped
sink, partitioned into:

* **gap** (``is_gap=True``) — a manifest that may declare dependencies was lost
  (unreadable, undecodable, unparseable, in a subtree we couldn't enter, or
  referenced through a path that is not followed). Analysis is *incomplete*;
  ``--strict`` treats this like an UNKNOWN and fails.
* **recovered** (``is_gap=False``) — decoded with a caveat (latin-1 fallback);
  the ASCII dependency lines survived, so analysis is complete but lossy for any
  non-ASCII content. Worth a warning, not a failure.

The CLI drains the sink to stderr after a scan. Outside an active sink
``_record`` is a no-op, so unit tests that call parsers directly need no setup.
"""

from __future__ import annotations

import codecs
import contextlib
import contextvars
import json
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # ty: ignore[unresolved-import]

__all__ = [
    "ReadDiagnostic",
    "collect_read_diagnostics",
    "decode_text",
    "load_json",
    "load_toml",
    "load_yaml",
    "read_bytes",
    "read_xml_bytes",
    "record_parse_failure",
    "record_walk_error",
    "rejected_path_reference",
]


# Largest manifest licenseal will read into memory. A real lockfile for a big
# monorepo runs to tens of megabytes; anything past this ceiling is either a
# mistake or a hand-crafted out-of-memory payload in a scanned repo, so it is
# recorded as a gap (incomplete analysis — surfaced, never silent) and skipped
# rather than buffered whole.
_MAX_MANIFEST_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class ReadDiagnostic:
    """A single non-fatal read/parse anomaly worth surfacing to the user.

    ``reason`` completes "``<path>``: ``<reason>``". ``is_gap`` marks whether a
    dependency-bearing file was *lost* (incomplete analysis → ``--strict``
    fails) versus merely *recovered with a caveat* (latin-1 fallback).
    """

    path: Path
    reason: str
    is_gap: bool


_DIAGNOSTICS: contextvars.ContextVar[list[ReadDiagnostic] | None] = contextvars.ContextVar(
    "_READ_DIAGNOSTICS", default=None
)


@contextlib.contextmanager
def collect_read_diagnostics() -> Iterator[list[ReadDiagnostic]]:
    """Activate the read-diagnostics sink for the enclosed block.

    Re-entrant like :func:`licenseal.discovery._walk.shared_walk_cache`: a
    nested call reuses the outer sink, so the CLI can wrap license detection,
    dependency discovery and the transitive walk and drain one combined list.
    The same ``(path, reason)`` may be appended more than once (a ``pom.xml`` is
    read by several passes) — de-duplicate at drain time.
    """
    existing = _DIAGNOSTICS.get()
    if existing is not None:
        yield existing
        return
    sink: list[ReadDiagnostic] = []
    token = _DIAGNOSTICS.set(sink)
    try:
        yield sink
    finally:
        _DIAGNOSTICS.reset(token)


def _record(path: Path, reason: str, *, is_gap: bool) -> None:
    sink = _DIAGNOSTICS.get()
    if sink is not None:
        sink.append(ReadDiagnostic(path=path, reason=reason, is_gap=is_gap))


def record_parse_failure(path: Path, fmt: str) -> None:
    """Record that ``path`` was read but couldn't be parsed as ``fmt`` (a gap).

    Used by callers whose parse step is separate from the read (e.g. the XML
    parsers, which decode bytes themselves). The structured loaders below
    (:func:`load_json` / :func:`load_toml` / :func:`load_yaml`) call this
    internally, so their callers only check for ``None``.
    """
    _record(path, f"is not valid {fmt}; skipped", is_gap=True)


def record_walk_error(exc: OSError) -> None:
    """Record a directory that couldn't be traversed (a gap).

    Wired as ``os.walk(onerror=...)``: a permission-denied / unreadable subtree
    is otherwise skipped silently, hiding any manifests it contains.
    """
    filename = getattr(exc, "filename", None)
    path = Path(filename) if filename else Path(".")
    _record(
        path,
        f"directory could not be traversed ({type(exc).__name__}); "
        "manifests under it were not scanned",
        is_gap=True,
    )


def rejected_path_reference(manifest: Path, value: str) -> bool:
    """Record a gap and return True when ``value`` is not a relative path.

    ``value`` is a path written inside ``manifest`` that a parser is about to
    follow (an MSBuild ``<Import>``, a Go workspace ``use`` directory). Only
    relative values are followed, ``..`` segments included. A rooted,
    drive-qualified, UNC (``\\\\host\\share``, ``//host/share``) or device
    (``\\\\?\\``, ``\\\\.\\``) value is rejected: on Windows the first filesystem
    call on such a path — ``Path.resolve()`` included — can reach a network
    share or a device.

    The check is lexical, so callers run it before joining ``value`` to
    anything. Backslashes are normalised first: the verdict is the same on
    Windows and POSIX.
    """
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or normalized[1:2] == ":":
        _record(
            manifest,
            f"references {value!r}, which is not a relative path; not followed",
            is_gap=True,
        )
        return True
    return False


def _over_size_cap(path: Path) -> bool:
    """Record a gap and return True when ``path`` exceeds the manifest size cap.

    Checked via ``stat`` *before* the file is opened, so an oversized manifest
    is never read into memory. May raise ``OSError`` (a missing/unstattable
    path) — callers run it inside their existing read ``try`` so that surfaces
    as the same "could not be read" gap.
    """
    if path.stat().st_size > _MAX_MANIFEST_BYTES:
        _record(
            path,
            f"exceeds the {_MAX_MANIFEST_BYTES // (1024 * 1024)} MiB manifest size cap; skipped",
            is_gap=True,
        )
        return True
    return False


def read_bytes(path: Path) -> bytes | None:
    """Read raw bytes, recording an OS read failure (permission, I/O) as a gap.

    The byte-level primitive behind every loader here. A file past the
    manifest size cap is recorded as a gap and skipped without being read
    into memory (see :func:`_over_size_cap`).
    """
    try:
        if _over_size_cap(path):
            return None
        return path.read_bytes()
    except OSError as exc:
        _record(path, f"could not be read ({type(exc).__name__}); skipped", is_gap=True)
        return None


# Byte-order marks that name a codec other than UTF-8. UTF-32 comes first
# because the UTF-32 LE BOM (``ff fe 00 00``) starts with the UTF-16 LE BOM
# (``ff fe``). The endianness-agnostic codecs (``utf-16`` / ``utf-32``) consume
# the BOM; the explicit ``-le`` / ``-be`` codecs would leave it in the decoded
# text as a leading U+FEFF.
_BOM_CODECS = (
    ((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE), "utf-32"),
    ((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE), "utf-16"),
)


def decode_text(path: Path) -> str | None:
    """Decode a text manifest to ``str``, or ``None`` if it can't be read or decoded.

    Strategy — deterministic, so a file decodes identically on every machine
    (no locale lookup, no charset sniffing):

    1. **UTF-16 / UTF-32 BOM** → exact codec (Windows redirection). Bytes that
       aren't valid in the codec the BOM names (a truncated file, an unpaired
       surrogate) have no fallback: single-byte decoding of a two- or four-byte
       encoding recovers nothing, so the file is recorded as a gap.
    2. **UTF-8** (strict), stripping a UTF-8 BOM — the overwhelmingly common case.
    3. **latin-1** fallback — never raises, maps every byte 1:1, so ASCII-only
       dependency lines survive a stray non-UTF-8 byte in a comment. Recorded as
       a *recovered* (non-gap) diagnostic. A UTF-8 BOM doesn't change this: the
       same bytes recover the same way with or without one.

    We deliberately do *not* replicate pip's ``locale.getpreferredencoding()``
    fallback: it would make the same bytes decode differently across machines,
    breaking scan reproducibility.
    """
    data = read_bytes(path)
    if data is None:
        return None
    for boms, codec in _BOM_CODECS:
        if data.startswith(boms):
            try:
                return data.decode(codec)
            except UnicodeDecodeError:
                label = codec.upper()
                _record(
                    path,
                    f"has a {label} byte-order mark but is not valid {label}; skipped",
                    is_gap=True,
                )
                return None
    try:
        # ``utf-8-sig`` strips a leading UTF-8 BOM and is plain UTF-8 without one.
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        _record(
            path,
            "decoded as latin-1 (not valid UTF-8); non-ASCII content may be wrong",
            is_gap=False,
        )
        return data.removeprefix(codecs.BOM_UTF8).decode("latin-1")


def read_xml_bytes(path: Path) -> bytes | None:
    """Read an XML manifest as raw bytes for an encoding-aware parser.

    XML is self-describing: ``ElementTree.fromstring`` honors the
    ``<?xml … encoding="…"?>`` prolog (or a BOM) when handed *bytes*, and
    defaults to UTF-8 when neither is present. Reading as UTF-8 text first would
    raise ``UnicodeDecodeError`` on a validly-encoded non-UTF-8 document and
    silently drop it. A read failure is recorded as a gap; the caller records
    any *parse* failure via :func:`record_parse_failure`.
    """
    return read_bytes(path)


def load_json(path: Path) -> Any | None:
    """Read + parse a JSON manifest, recording a read or parse failure as a gap.

    Decoding goes through :func:`decode_text` (BOM-aware, latin-1 safety net),
    so a stray byte can't drop an otherwise-valid lockfile. A document nested
    past the interpreter's recursion limit is a parse failure like any other.
    """
    raw = decode_text(path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError subclass
        record_parse_failure(path, "JSON")
        return None


def load_toml(path: Path) -> dict[str, Any] | None:
    """Read + parse a TOML manifest, recording a read or parse failure as a gap.

    Decoding goes through :func:`decode_text`, the same as the JSON and YAML
    loaders: TOML mandates UTF-8, but a manifest written through a Windows
    shell redirect arrives as UTF-16 or with a UTF-8 BOM, and ``tomllib``
    accepts neither on its own.
    """
    raw = decode_text(path)
    if raw is None:
        return None
    try:
        return tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, RecursionError):
        record_parse_failure(path, "TOML")
        return None


def load_yaml(path: Path) -> Any | None:
    """Read + parse a YAML manifest, recording a read or parse failure as a gap."""
    raw = decode_text(path)
    if raw is None:
        return None
    try:
        return yaml.safe_load(raw)
    except (yaml.YAMLError, RecursionError):
        record_parse_failure(path, "YAML")
        return None
