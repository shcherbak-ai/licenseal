"""Shared HTTP helpers for registry lookups."""

from __future__ import annotations

import json
import random
import threading
import time
from collections import Counter
from collections.abc import Callable
from functools import partial
from urllib.parse import quote, urlsplit
from xml.etree.ElementTree import Element  # nosec B405

import httpx
from defusedxml import ElementTree as DefusedET

_MAX_ATTEMPTS = 3
_INITIAL_BACKOFF_SECONDS = 0.25
_MAX_RETRY_AFTER_SECONDS = 5.0
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

# Decompression-bomb guard. httpx transparently inflates gzip/deflate/br
# response bodies, so a small compressed payload can expand to gigabytes in
# memory. The fetchers below stream the *decompressed* body and abort once it
# crosses this ceiling instead of buffering it whole. Set well above the
# largest legitimate registry response: an npm "packument" for a package with
# thousands of historical versions can run to tens of megabytes before
# licenseal trims it (see ``_trim_npm_project``).
_MAX_RESPONSE_BYTES = 256 * 1024 * 1024

Fetcher = Callable[[str, httpx.Client], "dict | None"]


# Most registries are governed by the CLI's ``--max-workers`` (default 16).
# crates.io is stricter: its published data-access policy asks API clients to
# identify themselves and keep direct API use to one request per second. Rust
# scans usually resolve exact pins through deps.dev's CARGO batch path and
# Cargo.lock, so this limiter only affects the crates.io fallback paths.
_CRATES_IO_MIN_INTERVAL_SECONDS = 1.0


class _HostRateLimiter:
    """Serialize requests so their start times are at least ``interval`` apart."""

    def __init__(self, interval_seconds: float) -> None:
        self._interval_seconds = interval_seconds
        self._next_allowed_at = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed_at:
                time.sleep(self._next_allowed_at - now)
                now = time.monotonic()
            self._next_allowed_at = now + self._interval_seconds


_HOST_RATE_LIMITERS = {
    "crates.io": _HostRateLimiter(_CRATES_IO_MIN_INTERVAL_SECONDS),
}


# hex.pm caps unauthenticated API clients at 100 requests per 60-second window
# per IP and reports the window in ``x-ratelimit-*`` response headers. It has
# no batch endpoint and deps.dev does not index Hex, so each package costs one
# request and a project with more packages than a window allows is certain to
# draw 429s. Pacing every request under the limit would slow the common small
# scan for nothing, so the limit is handled when it is hit: a 429 pauses all
# hex.pm requests until the window resets, then they resume.
_HEX_PM_WINDOW_SECONDS = 60.0
# One pause never outlasts a window by more than this allowance, whatever
# reset time the response reports.
_HEX_PM_MAX_PAUSE_SECONDS = _HEX_PM_WINDOW_SECONDS + 5.0
# Ceiling on all hex.pm pausing in one process: ten full-length pauses.
_HEX_PM_MAX_TOTAL_PAUSE_SECONDS = 10 * _HEX_PM_MAX_PAUSE_SECONDS
# Pauses in a row, with no non-429 response between them, after which the host
# is treated as not lifting its limit.
_HEX_PM_MAX_STALLED_PAUSES = 3
# Added to a reported reset time: it is in whole seconds, and the local clock
# may run slightly ahead of the server's.
_RATE_LIMIT_RESET_MARGIN_SECONDS = 1.0


class _HostRateLimitWindow:
    """Pause every request to a host until its rate-limit window reopens.

    ``defer`` is shown each response from the host. On a 429 it opens a pause
    lasting until the window reset the response reports, and ``acquire`` —
    called before every request to the host — sleeps out the rest of an open
    pause. Worker threads rate limited together share one pause rather than
    each opening their own.

    The waiting is bounded twice, so a host that never lifts its limit cannot
    hang a scan: at most ``max_stalled_pauses`` pauses in a row with no non-429
    response between them, and at most ``max_total_seconds`` of pausing over
    the life of the process. Past either bound ``defer`` declines and the
    caller's ordinary retry budget applies.

    ``defer`` takes an ``on_pause`` callback, called with the pause's length in
    seconds by the one call that opens a pause — not by the workers that then
    wait it out, so a pause is reported once.
    """

    def __init__(
        self, max_pause_seconds: float, max_total_seconds: float, max_stalled_pauses: int
    ) -> None:
        self._max_pause_seconds = max_pause_seconds
        self._max_stalled_pauses = max_stalled_pauses
        self._remaining_seconds = max_total_seconds
        self._stalled_pauses = 0
        self._resume_at = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            wait = self._resume_at - time.monotonic()
        # Sleep outside the lock: ``defer`` needs it while workers wait, and
        # the requests that resume together must not be serialized.
        if wait > 0:
            time.sleep(wait)

    def defer(
        self, response: httpx.Response, on_pause: Callable[[float], None] | None = None
    ) -> bool:
        """Return True when the request should be retried after the pause."""
        if response.status_code != 429:
            with self._lock:
                self._stalled_pauses = 0
            return False
        wait = self._seconds_until_reset(response)
        with self._lock:
            now = time.monotonic()
            if now < self._resume_at:
                # Another worker already opened the pause for this window.
                return True
            if self._stalled_pauses >= self._max_stalled_pauses or wait > self._remaining_seconds:
                return False
            self._stalled_pauses += 1
            self._remaining_seconds -= wait
            self._resume_at = now + wait
        # Outside the lock: the callback writes to the terminal, and the other
        # workers need the lock to learn that a pause is open.
        if on_pause is not None:
            on_pause(wait)
        return True

    def _seconds_until_reset(self, response: httpx.Response) -> float:
        reset = response.headers.get("x-ratelimit-reset", "").strip()
        if reset.isdecimal():
            wait = float(reset) - time.time() + _RATE_LIMIT_RESET_MARGIN_SECONDS
            if 0 < wait <= self._max_pause_seconds:
                return wait
        # No usable reset time (absent, malformed, already past by the local
        # clock, or further off than a window lasts): wait out a whole window.
        return self._max_pause_seconds


_HOST_RATE_LIMIT_WINDOWS = {
    "hex.pm": _HostRateLimitWindow(
        _HEX_PM_MAX_PAUSE_SECONDS, _HEX_PM_MAX_TOTAL_PAUSE_SECONDS, _HEX_PM_MAX_STALLED_PAUSES
    ),
}


def _respect_host_rate_limit(url: str) -> None:
    """Apply any host-specific registry rate limit before opening a request."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        # A registry-supplied link whose authority can't be parsed can't be
        # matched to a rate-limited host, so no limiter applies. Whether it
        # can be requested at all is for the client and the egress policy.
        return
    if host is None:
        return
    limiter = _HOST_RATE_LIMITERS.get(host.lower())
    if limiter is not None:
        limiter.acquire()
    window = _HOST_RATE_LIMIT_WINDOWS.get(host.lower())
    if window is not None:
        window.acquire()


class RateLimitReport:
    """What one scan is told about waiting on a registry's rate limit.

    ``on_pause(host, seconds)`` is called when requests to ``host`` start
    waiting for its rate-limit window to reset: once per pause, from the
    worker thread whose response opened it. ``abandoned`` counts, per host,
    the lookups that were still rate limited when the window's bounded waiting
    and the ordinary retry budget were both spent, and so returned nothing.
    """

    def __init__(self, on_pause: Callable[[str, float], None] | None = None) -> None:
        self._on_pause = on_pause
        self._lock = threading.Lock()
        self.abandoned: Counter[str] = Counter()

    def pause_started(self, host: str, seconds: float) -> None:
        """Report a pause of ``seconds`` that has just opened on ``host``."""
        if self._on_pause is not None:
            self._on_pause(host, seconds)

    def lookup_abandoned(self, host: str) -> None:
        """Count one lookup on ``host`` that ended rate limited."""
        with self._lock:
            self.abandoned[host] += 1


def _defer_to_rate_limit_window(
    url: str, response: httpx.Response, rate_limits: RateLimitReport | None = None
) -> bool:
    """Whether to retry a rate-limited request once its host's window reopens.

    Always False for a host without a rate-limit window. Only the JSON GET
    fetcher asks: it is the only one that reaches such a host. A pause this
    call opens is reported to ``rate_limits``.
    """
    host = (urlsplit(url).hostname or "").lower()
    window = _HOST_RATE_LIMIT_WINDOWS.get(host)
    if window is None:
        return False
    on_pause = None if rate_limits is None else partial(rate_limits.pause_started, host)
    return window.defer(response, on_pause)


def _note_rate_limited_out(
    url: str, response: httpx.Response, rate_limits: RateLimitReport | None
) -> None:
    """Count a lookup that ends on a 429 from a host with a rate-limit window.

    Called for the last response of a lookup whose retry budget is spent. For
    such a host that response is a 429 only when the window has also declined
    to wait any longer.
    """
    host = (urlsplit(url).hostname or "").lower()
    if rate_limits is not None and response.status_code == 429 and host in _HOST_RATE_LIMIT_WINDOWS:
        rate_limits.lookup_abandoned(host)


# Retries are jittered so the worker pool doesn't re-fire in lockstep. Without
# it, a burst of threads that all trip a per-window limiter at the same instant
# (a per-IP request quota, for example) back off the identical amount and retry
# as the same synchronized burst — reconstructing the spike that got them
# throttled. ``random`` is module-global and thread-safe in CPython (the
# C-level state update holds the GIL); it's the same jitter source urllib3
# uses. No seeding: real per-thread entropy is the whole point.


def _jittered_backoff(delay: float) -> float:
    """Full jitter: a uniform draw in ``[0, delay]``.

    Per the AWS "exponential backoff and jitter" study, full jitter is the
    contention-minimizing choice for a pool of concurrent retriers — each
    thread lands at a random point in the window rather than all at ``delay``.
    Used for connection errors and for retryable responses with no numeric
    ``Retry-After``. The caller still doubles ``delay`` per attempt, so this
    jitters a ceiling that grows 0.25 → 0.5 → 1.0s.
    """
    # S311: backoff jitter is a non-cryptographic use; a PRNG is the right tool.
    return random.uniform(0.0, delay)  # noqa: S311  # nosec B311


def _retry_delay_seconds(response: httpx.Response, default_delay: float) -> float:
    """Return a jittered retry delay, respecting numeric ``Retry-After``.

    With a numeric ``Retry-After`` we honor it (capped at
    ``_MAX_RETRY_AFTER_SECONDS``) and add a small *upward* jitter, so workers
    handed the identical value still desynchronize — we never sleep *less* than
    the server asked. Without one, the exponential ``default_delay`` is
    full-jittered via :func:`_jittered_backoff`.
    """
    retry_after = response.headers.get("Retry-After", "").strip()
    # ``isdecimal``, not ``isdigit``: the latter also accepts characters such
    # as superscript digits, which ``float()`` rejects.
    if retry_after.isdecimal():
        capped = min(float(retry_after), _MAX_RETRY_AFTER_SECONDS)
        # S311: jitter, not crypto — see _jittered_backoff.
        return capped + random.uniform(0.0, _INITIAL_BACKOFF_SECONDS)  # noqa: S311  # nosec B311
    return _jittered_backoff(default_delay)


def _read_capped_bytes(response: httpx.Response) -> bytes | None:
    """Stream a response body to bytes, or ``None`` once it exceeds the ceiling.

    ``iter_bytes`` yields the *decompressed* body, so a gzip/deflate/br bomb is
    caught as it expands rather than after it has already ballooned memory.
    Equivalent to ``response.read()`` for a well-behaved (in-bounds) body — so
    ``json.loads(_read_capped_bytes(r))`` matches ``r.json()``.
    """
    total = 0
    parts: list[bytes] = []
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            return None
        parts.append(chunk)
    return b"".join(parts)


def _read_capped_text(response: httpx.Response) -> str | None:
    """Read a response body as text, or ``None`` if it is too large or undecodable.

    The capped bytes are decoded with the response's charset (UTF-8 when the
    ``Content-Type`` names none, or one Python doesn't know), malformed
    sequences replaced: the same text ``response.text`` gives for an in-bounds
    body. A ``Content-Type`` whose charset names a codec that can't decode text
    yields ``None`` rather than an error from the codec.
    """
    raw = _read_capped_bytes(response)
    if raw is None:
        return None
    try:
        return raw.decode(response.encoding or "utf-8", errors="replace")
    except (LookupError, ValueError):
        # LookupError: a registered codec that is not a text encoding.
        # ValueError: a codec that does not support replacing malformed input.
        return None


def _decode_json_object(raw: bytes) -> dict | None:
    """Parse a response body as a JSON object, or ``None`` if it isn't one.

    Every JSON endpoint licenseal reads answers with an object. A body that is
    not JSON, is JSON of another type (a list, a string, a number, ``null``),
    or is nested past the parser's recursion limit is a failed lookup, so no
    cache trim, resolver, or walker has to check the top-level shape itself.
    """
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def object_field(data: dict, key: str) -> dict:
    """Return ``data[key]`` when it is a JSON object, else an empty ``dict``.

    Registry metadata nests the fields licenseal reads one object down
    (``info``, ``crate``, ``version``). A response carrying another type there
    reads as "no such fields", the same as a response without the key.
    """
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def has_utf8_encoding(value: str) -> bool:
    """Whether ``value`` can be written into a request URL or body.

    False for a string holding a lone surrogate: half of a UTF-16 pair, which
    is what an unpaired ``\\uD800``-style escape in a JSON manifest or registry
    response decodes to. No request can carry it.
    """
    try:
        value.encode()
    except UnicodeEncodeError:
        return False
    return True


def quote_coordinate(value: str, *, safe: str = "") -> str:
    """Percent-encode a dependency name or version for a registry URL.

    A value with no UTF-8 encoding (see :func:`has_utf8_encoding`) cannot be
    percent-encoded. It is returned as it is, not stripped or replaced, so the
    URL built from it has no UTF-8 encoding either: the fetch helpers report a
    failed lookup for it and send nothing.
    """
    return quote(value, safe=safe) if has_utf8_encoding(value) else value


def fetch_registry_json(
    url: str, client: httpx.Client, *, rate_limits: RateLimitReport | None = None
) -> dict | None:
    """Fetch a JSON object with brief retries for transient registry failures.

    Returns ``None`` for every failed lookup: an error status, an exhausted
    retry budget, an oversized body, or a body that is not a JSON object (see
    :func:`_decode_json_object`).

    A URL that cannot be sent is a failed lookup too, here and in the other
    GET fetchers below. One with no UTF-8 encoding (a lone surrogate in a name
    or version, see :func:`has_utf8_encoding`) is never handed to the client.
    One the client refuses to build raises ``httpx.InvalidURL`` before anything
    is sent, which is not a ``RequestError``; it is what a dependency name or
    version carrying a character no URL may hold (an ASCII control character,
    for example) produces. Neither is retried: the same URL fails the same way.

    A rate-limited response from a host with a rate-limit window (see
    :class:`_HostRateLimitWindow`) is retried once the window reopens without
    spending one of the ``_MAX_ATTEMPTS``; the window bounds its own waiting.
    ``rate_limits`` is told when such a pause starts, and counts the lookup
    when it is still rate limited after all of the waiting.
    """
    if not has_utf8_encoding(url):
        return None
    delay = _INITIAL_BACKOFF_SECONDS
    attempt = 0
    while attempt < _MAX_ATTEMPTS:
        try:
            _respect_host_rate_limit(url)
            with client.stream("GET", url) as response:
                if _defer_to_rate_limit_window(url, response, rate_limits):
                    continue
                if response.status_code in _RETRYABLE_STATUS_CODES:
                    if attempt == _MAX_ATTEMPTS - 1:
                        _note_rate_limited_out(url, response, rate_limits)
                        return None
                    time.sleep(_retry_delay_seconds(response, delay))
                    delay *= 2
                    attempt += 1
                    continue

                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError:
                    return None

                raw = _read_capped_bytes(response)
                if raw is None:
                    return None
                return _decode_json_object(raw)
        except httpx.InvalidURL:
            return None
        except httpx.RequestError:
            if attempt == _MAX_ATTEMPTS - 1:
                return None
            time.sleep(_jittered_backoff(delay))
            delay *= 2
            attempt += 1
            continue

    return None


def fetch_registry_json_post(url: str, body: dict, client: httpx.Client) -> dict | None:
    """Fetch JSON via POST with the same retry semantics as :func:`fetch_registry_json`.

    Used by deps.dev's batch endpoint (``POST /v3alpha/versionbatch``). POST
    responses are not routed through :class:`RegistryCache` (which is GET +
    URL-keyed), because batches are inherently scan-shaped: each scan's
    request list is unique, so cache hits don't apply.
    """
    delay = _INITIAL_BACKOFF_SECONDS
    for attempt in range(_MAX_ATTEMPTS):
        try:
            _respect_host_rate_limit(url)
            with client.stream("POST", url, json=body) as response:
                if response.status_code in _RETRYABLE_STATUS_CODES:
                    if attempt == _MAX_ATTEMPTS - 1:
                        return None
                    time.sleep(_retry_delay_seconds(response, delay))
                    delay *= 2
                    continue

                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError:
                    return None

                raw = _read_capped_bytes(response)
                if raw is None:
                    return None
                return _decode_json_object(raw)
        except httpx.RequestError:
            if attempt == _MAX_ATTEMPTS - 1:
                return None
            time.sleep(_jittered_backoff(delay))
            delay *= 2
            continue

    return None


# PEP 658 sidecar: ``{wheel_url}.metadata`` returns the wheel's METADATA file
# (RFC 5322-style headers). The wheel's METADATA is the canonical PEP 643
# source for a package's license declaration. PyPI's JSON API does
# generally surface that data (PEP 639 ``License-Expression``, the legacy
# ``license`` field, and classifiers all flow through), and ~97% of Python
# deps in measured corpora resolve cleanly from JSON alone. The pypi
# resolver falls back to this sidecar fetch only for the minority of
# packages (~3%) where all of those JSON fields come back null even though
# the wheel METADATA carries clean license data — an indexer-side gap on
# PyPI's end, not a deliberate PyPA design choice. The sidecar lives on
# ``files.pythonhosted.org`` (PSF-operated artifact host, same trust
# posture as ``pypi.org``) and serves plain text — so it routes outside
# the JSON ``RegistryCache``. Volume is low (only the long tail of
# UNKNOWN-from-JSON packages), so per-scan in-memory caching adds little.
_PEP658_HEADER_LINES_MAX = 200


def fetch_pep658_metadata(url: str, client: httpx.Client) -> dict[str, str] | None:
    """Fetch a wheel's PEP 658 .metadata sidecar; return parsed headers.

    Headers stop at the first empty line. RFC 5322 continuation lines (lines
    starting with whitespace) are folded into the header they continue, each
    one marked by a newline in the returned value (see
    :func:`_parse_pep658_headers`). The caller needs the whole value to decide:
    a folded ``License-Expression`` is unfolded and validated complete, while a
    legacy ``License:`` value with any continuation is a license-text body and
    is refused whole — per the no-prose-extraction rule, the first line of a
    body must never become the identifier.
    """
    if not has_utf8_encoding(url):
        return None
    delay = _INITIAL_BACKOFF_SECONDS
    # Override the client default ``Accept: application/json`` — the sidecar
    # is served as plain text.
    headers = {"Accept": "*/*"}
    for attempt in range(_MAX_ATTEMPTS):
        try:
            _respect_host_rate_limit(url)
            with client.stream("GET", url, headers=headers) as response:
                if response.status_code in _RETRYABLE_STATUS_CODES:
                    if attempt == _MAX_ATTEMPTS - 1:
                        return None
                    time.sleep(_retry_delay_seconds(response, delay))
                    delay *= 2
                    continue

                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError:
                    return None

                text = _read_capped_text(response)
                if text is None:
                    return None
                return _parse_pep658_headers(text)
        except httpx.InvalidURL:
            return None
        except httpx.RequestError:
            if attempt == _MAX_ATTEMPTS - 1:
                return None
            time.sleep(_jittered_backoff(delay))
            delay *= 2
            continue

    return None


def _parse_pep658_headers(text: str) -> dict[str, str]:
    """Parse RFC 5322-style PEP 658 metadata headers into ``{name: value}``.

    Stops at the first empty line (end of headers / start of description body).
    A line starting with a space or tab continues the preceding header, even
    when it is otherwise blank: multi-line values are written with indented
    blank lines between paragraphs, so such a line is part of the value, not
    the end of the headers. Each continuation line is appended as ``"\\n"`` plus
    its stripped text, so a value contains a newline exactly when it was
    folded. Callers must look at the whole value — never just its first line.

    The first occurrence of a repeated header wins; later occurrences are
    dropped together with their continuation lines. Hard-caps the iteration so
    adversarial inputs can't balloon memory; a value the cap cuts short is
    dropped rather than returned incomplete.
    """
    out: dict[str, str] = {}
    # Header that continuation lines extend; ``None`` after a dropped duplicate.
    current: str | None = None
    for i, line in enumerate(text.splitlines()):
        is_continuation = line.startswith((" ", "\t"))
        if i >= _PEP658_HEADER_LINES_MAX:
            if is_continuation and current is not None:
                del out[current]
            break
        if is_continuation:
            if current is not None:
                out[current] += "\n" + line.strip()
            continue
        if not line.strip():
            break
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key in out:
            current = None
            continue
        out[key] = value.strip()
        current = key
    return out


# Go module proxy (``proxy.golang.org``) serves the raw ``go.mod`` text for
# each (module, version) pair. The transitive walker fetches these to build
# the dep edge graph — go.sum carries no edges, and deps.dev's
# ``GetDependencies`` endpoint is documented as available only for npm,
# Cargo, Maven, and PyPI (not Go). proxy.golang.org is the canonical source
# the ``go`` toolchain itself consults.
# Path encoding (per the Go modules reference): uppercase letters in the
# module path are replaced with ``!<lowercase>`` to avoid case-insensitive
# filesystem collisions on the proxy side.


def encode_module_proxy_path(module_path: str) -> str:
    """Case-encode a Go module path for use in proxy.golang.org URLs.

    ``github.com/MyOrg/MyMod`` → ``github.com/!my!org/!my!mod``.
    """
    out: list[str] = []
    for ch in module_path:
        if "A" <= ch <= "Z":
            out.append("!" + ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def fetch_go_mod_text(url: str, client: httpx.Client) -> dict[str, str] | None:
    """Fetch raw text from a URL and wrap it for ``RegistryCache`` compatibility.

    Used for the Go module proxy's ``/<module>/@v/<version>.mod`` endpoint.
    The cache's ``dict | None`` shape doesn't natively carry text, so we
    return a one-key dict ``{"text": "<go.mod source>"}``. Callers extract
    the ``"text"`` key.

    Same retry/backoff semantics as :func:`fetch_registry_json`. The default
    client ``Accept: application/json`` is overridden to ``*/*`` since the
    proxy serves plain text.
    """
    return fetch_registry_text(url, client)


def fetch_registry_text(url: str, client: httpx.Client) -> dict[str, str] | None:
    """Fetch raw text from a URL and wrap it for ``RegistryCache`` compatibility.

    Generic text-mode fetcher: returns ``{"text": "<body>"}`` on success,
    ``None`` on failure. Same retry/backoff curve as
    :func:`fetch_registry_json`; overrides the client's default
    ``Accept: application/json`` to ``*/*`` so registries that serve XML
    or plain text don't 406. Used for raw POM XML from Maven Central and
    raw go.mod text from the Go module proxy.
    """
    if not has_utf8_encoding(url):
        return None
    delay = _INITIAL_BACKOFF_SECONDS
    headers = {"Accept": "*/*"}
    for attempt in range(_MAX_ATTEMPTS):
        try:
            _respect_host_rate_limit(url)
            with client.stream("GET", url, headers=headers) as response:
                if response.status_code in _RETRYABLE_STATUS_CODES:
                    if attempt == _MAX_ATTEMPTS - 1:
                        return None
                    time.sleep(_retry_delay_seconds(response, delay))
                    delay *= 2
                    continue

                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError:
                    return None

                text = _read_capped_text(response)
                if text is None:
                    return None
                return {"text": text}
        except httpx.InvalidURL:
            return None
        except httpx.RequestError:
            if attempt == _MAX_ATTEMPTS - 1:
                return None
            time.sleep(_jittered_backoff(delay))
            delay *= 2
            continue

    return None


# --- Per-scan URL cache --------------------------------------------------
#
# The transitive walker often re-fetches the same registry URL: a common
# transitive gets hit once per dep that depends on it,
# which on large Python projects means the same URL is requested many times
# in a single scan. With a per-scan URL cache, the second through Nth fetch
# are served in-memory. The cache also dedupes in-flight requests: if two
# worker threads start fetching the same URL simultaneously, the second one
# blocks on the first's response rather than racing the same call to the
# network.


_PYPI_INFO_KEEP = frozenset(
    {
        "name",
        "version",
        "license",
        "license_expression",
        "classifiers",
        "project_urls",
        "home_page",
        "requires_dist",
    }
)
_NPM_VERSION_KEEP = frozenset(
    {
        "version",
        "license",
        # Pre-modern npm convention: `licenses` array / dict. Old-but-still-
        # popular packages only ship the legacy field; dropping it here would
        # silently force them all to UNKNOWN through the cached path.
        "licenses",
        "dependencies",
        "peerDependencies",
        "optionalDependencies",
        "repository",
        # Author-supplied homepage. Surfaced as the dep's actionability link
        # (never fetched). Omitting it here silently empties `homepage_url`
        # on the cached production path while resolver unit tests — which use
        # the direct fetcher and bypass `_trim_for_cache` — still pass.
        "homepage",
    }
)


def _trim_pypi(data: dict) -> dict:
    # An ``info`` that is not an object is cached as ``None``, not as an empty
    # object: the dependency fetcher tells "declares nothing" from "not the
    # documented shape" by it.
    info = data.get("info")
    trimmed_info = (
        {k: v for k, v in info.items() if k in _PYPI_INFO_KEEP} if isinstance(info, dict) else None
    )
    # `_resolve_version` and `resolve_python_license` only read the release
    # *version strings* to pick a matching version. Store them as a list,
    # not a `{ver: []}` dict — drops the per-entry dict slot + empty-list
    # overhead, which matters because nightly-build packages can carry
    # thousands of historical versions and would otherwise dominate the
    # cache. Both call sites already iterate `for k in releases`, which
    # works the same on a list as on a dict's keys.
    releases = data.get("releases", {})
    if isinstance(releases, dict):
        trimmed_releases: list[str] = [k for k in releases if isinstance(k, str)]
    elif isinstance(releases, list):
        trimmed_releases = [k for k in releases if isinstance(k, str)]
    else:
        trimmed_releases = []
    # PEP 658 fallback: keep this version's wheel URL so the pypi resolver can
    # fetch the ``.metadata`` sidecar when the JSON-side license fields all
    # come back null despite the wheel having clean PEP 643 metadata (the
    # ~3%-of-Python-deps indexer gap — see ``fetch_pep658_metadata`` above
    # for the full rationale). Stored as a single string, not the full
    # ``urls`` list — the resolver only needs the first bdist_wheel URL.
    wheel_url = ""
    urls = data.get("urls", [])
    if isinstance(urls, list):
        for entry in urls:
            if not isinstance(entry, dict):
                continue
            if entry.get("packagetype") != "bdist_wheel":
                continue
            candidate = entry.get("url", "")
            if isinstance(candidate, str) and candidate:
                wheel_url = candidate
                break
    return {"info": trimmed_info, "releases": trimmed_releases, "wheel_url": wheel_url}


def _trim_npm_project(data: dict) -> dict:
    # `/registry/{name}` returns the full `versions` dict with each version's
    # complete metadata + tarball URLs + readme. resolve_npm_license picks a
    # version and reads its license/deps fields *inline* (no second fetch),
    # so we must preserve those fields per version — just not the megabyte
    # of tarball-url metadata each version also ships.
    versions = data.get("versions", {})
    if not isinstance(versions, dict):
        return {"versions": {}, "dist-tags": data.get("dist-tags", {})}
    trimmed: dict[str, dict] = {}
    for key, value in versions.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, dict):
            trimmed[key] = {k: v for k, v in value.items() if k in _NPM_VERSION_KEEP}
        else:
            trimmed[key] = {}
    # ``dist-tags`` is a tiny `{tag: version}` mapping that the spec resolver
    # consults to handle ``"latest"`` / ``"next"`` / custom-tag deps.
    return {"versions": trimmed, "dist-tags": data.get("dist-tags", {})}


def _trim_npm_version(data: dict) -> dict:
    return {k: v for k, v in data.items() if k in _NPM_VERSION_KEEP}


# deps.dev ``/v3/systems/GO/packages/{name}/versions/{version}`` returns a
# ``version`` object with ``licenses`` (SPDX-shape string array), ``links``
# (carries ``SOURCE_REPO`` to populate ``repository_url``), and a long tail
# of unrelated metadata (security advisories, SLSA provenance, attestation
# bundles, related projects, registries, …) that we don't read. The trim
# keeps just what the resolver consumes; everything else would otherwise
# multiply the cache footprint for popular transitive Go modules.
_DEPS_DEV_LINK_KEEP = frozenset({"label", "url"})


# deps.dev's ``…:dependencies`` endpoint returns the resolved Maven
# dependency subgraph as ``{nodes: [...], edges: [...], error: "..."}``.
# The transitive walker reads only:
#
# * ``nodes[i].versionKey`` — (system, name, version) for each node
# * ``nodes[i].relation`` — SELF / DIRECT / INDIRECT
# * ``edges[i].fromNode`` / ``toNode`` — node indices for the parent/child link
# * ``error`` — set when deps.dev could not resolve the whole graph; the
#   walker records the graph as incomplete
#
# Everything else (``requirement`` strings, ``bundled``, optional flag
# metadata that some node entries carry) is dropped. Maven dependency
# graphs can be large — popular framework starters' transitive closures
# run into hundreds of nodes per direct dep — so the trim materially
# shrinks the per-scan cache footprint when many direct deps share
# popular transitives.
_DEPS_DEV_DEPS_NODE_KEEP = frozenset({"versionKey", "relation"})
_DEPS_DEV_DEPS_EDGE_KEEP = frozenset({"fromNode", "toNode"})


def _trim_deps_dev_dependencies(data: dict) -> dict:
    """Strip a deps.dev ``:dependencies`` response to walker-read fields.

    A node that is not an object is kept as an empty one: the edges refer to
    nodes by position, and the walker reads an empty node as a graph it could
    not read in full. A ``nodes`` that is not a list is cached as it is, for
    the same reason.
    """
    raw_nodes = data.get("nodes")
    trimmed_nodes = raw_nodes
    if isinstance(raw_nodes, list):
        trimmed_nodes = [
            {k: v for k, v in entry.items() if k in _DEPS_DEV_DEPS_NODE_KEEP}
            if isinstance(entry, dict)
            else {}
            for entry in raw_nodes
        ]
    raw_edges = data.get("edges", [])
    trimmed_edges: list[dict] = []
    if isinstance(raw_edges, list):
        for entry in raw_edges:
            if isinstance(entry, dict):
                trimmed_edges.append(
                    {k: v for k, v in entry.items() if k in _DEPS_DEV_DEPS_EDGE_KEEP}
                )
    return {"nodes": trimmed_nodes, "edges": trimmed_edges, "error": data.get("error")}


# Maven Central serves raw POM XML at ``repo.maven.apache.org/maven2/...``
# (and equivalent aliases ``repo1.maven.apache.org`` / ``repo1.maven.org``).
# The resolver / transitive walker reads project coordinates, ``<parent>``
# (for parent-chain license + DM inheritance), ``<licenses>`` (for the
# SPDX-extractable fields), ``<properties>`` (for ``${…}`` expansion across
# the inheritance chain), and ``<dependencyManagement>`` (for managed-
# version lookup when a child POM omits ``<version>`` — BOMs carry their
# entire payload in this block, so dropping it breaks BOM-of-BOM resolution
# end-to-end). Everything else — ``<dependencies>``, ``<build>``,
# ``<profiles>``, ``<reporting>``, ``<distributionManagement>``,
# ``<repositories>``, ``<pluginRepositories>``, ``<modules>``,
# ``<contributors>``, ``<developers>``, ``<mailingLists>``, ``<scm>``,
# ``<ciManagement>``, ``<issueManagement>``, ``<organization>``,
# ``<description>`` — is dropped before caching. Heavy enterprise POMs can
# run into the megabytes; for large multi-module reactor scans we'd
# otherwise hold hundreds of those in memory per worker.
# ``profiles`` is kept because ``_parse_pom`` collects profile-conditional
# ``<dependencyManagement>`` entries (a managed version supplied only inside a
# ``<profile>`` block). Dropping it here loses those managed versions on the
# cached path — a BOM consumer whose version comes from profile-DM degrades to
# UNKNOWN — while parser unit tests that feed raw POM text still pass.
_POM_KEEP_TAGS = frozenset(
    {
        "groupId",
        "artifactId",
        "version",
        "parent",
        "licenses",
        "properties",
        "dependencyManagement",
        "profiles",
    }
)

# ``maven-metadata.xml`` keep sets. The Maven registries list an artifact's
# published versions in this file, beside the per-version directories its POMs
# are in. Only ``<versioning><versions>`` is read, to pick the latest release
# of a Gradle coordinate declared with no version; ``<latest>``, ``<release>``
# and ``<lastUpdated>`` are dropped.
_MAVEN_METADATA_KEEP_TAGS = frozenset({"versioning"})
_MAVEN_VERSIONING_KEEP_TAGS = frozenset({"versions"})

# NuGet ``.nuspec`` XML keep set. The flatcontainer endpoint serves the
# raw nuspec at ``api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.nuspec``;
# the resolver reads only ``<id>``, ``<version>``, ``<license>``,
# ``<licenseUrl>``, ``<projectUrl>``, ``<repository>``, ``<dependencies>``
# (the last for the lockfile-less transitive walker). Everything else
# (``<icon>``, ``<description>``, ``<releaseNotes>``, ``<owners>``,
# ``<tags>``, ``<readme>``, ``<authors>``, ``<copyright>``, ``<title>``,
# ``<summary>``, ``<language>``, ``<contentFiles>``, ``<frameworkAssemblies>``,
# ``<references>``) is heavy and unused — release notes and descriptions
# can run kilobytes per package.
_NUSPEC_KEEP_TAGS = frozenset(
    {"id", "version", "license", "licenseUrl", "projectUrl", "repository", "dependencies"}
)

# Packagist v2 metadata responses (``repo.packagist.org/p2/{vendor}/{package}.json``)
# carry the full version history of a package — every release with its
# README, autoloader config, suggested deps, conflict map, and a long tail
# of fields the resolver doesn't read. The walker and the per-version
# resolver only need ``version`` / ``version_normalized`` (to match the
# requested pin), ``license`` (the structured SPDX array we extract),
# ``source`` (for repository URL), ``homepage`` (for homepage URL), and
# ``require`` (for the manifest-only transitive walker's per-version
# dependency edges). Trimming matters here because popular Composer
# packages ship hundreds of historical versions and the per-version
# dict is the bulky one. The top-level ``minified`` marker is kept too:
# it tells the resolver that each entry lists only what changed from the
# entry before it, and the trimmed entries are still in that form.
_PACKAGIST_VERSION_KEEP = frozenset(
    {"version", "version_normalized", "license", "source", "homepage", "require"}
)

# RubyGems v2 per-version endpoint
# (``rubygems.org/api/v2/rubygems/{name}/versions/{version}.json``) returns
# the structured-license array, source / homepage URIs, and a dependencies
# map split into runtime / development sub-arrays (only ``runtime`` is kept at
# trim time — see ``_trim_rubygems_deps``). Everything else (info / summary /
# description / sha / built_at / metadata / authors / yanked / …) is heavy and
# unused. ``number`` is RubyGems' field name for the resolved version — we
# extract it for the report's resolved_version slot.
_RUBYGEMS_VERSION_KEEP = frozenset(
    {"name", "number", "licenses", "homepage_uri", "source_code_uri", "dependencies"}
)

# RubyGems v1 latest-version endpoint (``rubygems.org/api/v1/gems/{name}.json``)
# returns the same fields as the v2 per-version response except the version
# is exposed as ``version`` (not ``number``). Used only for unpinned
# fallbacks (manifest-only scans without a Gemfile.lock).
_RUBYGEMS_GEM_KEEP = frozenset(
    {"name", "version", "licenses", "homepage_uri", "source_code_uri", "dependencies"}
)

# RubyGems version-list endpoint (``rubygems.org/api/v1/versions/{name}.json``)
# answers with a JSON array: one entry per published version and platform,
# each with the gem's summary, description, authors, and metadata. A declared
# requirement is resolved against the ``number`` of each entry and nothing
# else. Requested only for a gem whose latest release is outside the
# requirement.
_RUBYGEMS_VERSIONS_KEEP = frozenset({"number"})

# hex.pm package endpoint (``hex.pm/api/packages/{name}``) returns the
# package-level ``meta`` (with ``licenses`` / ``links``), the latest version,
# and the ``releases`` a declared requirement is resolved against. Everything
# else (``owners``, ``downloads``, ``security_advisories``, timestamps, …) is
# heavy and unused.
_HEX_PACKAGE_KEEP = frozenset({"meta", "latest_stable_version", "latest_version", "releases"})
# Within ``meta`` only the license array and the repo/homepage link map matter.
_HEX_META_KEEP = frozenset({"licenses", "links"})
# Of a ``releases`` entry only the version number is read.
_HEX_PACKAGE_RELEASE_KEEP = frozenset({"version"})

# hex.pm release endpoint (``hex.pm/api/packages/{name}/releases/{version}``)
# carries no license — only the ``requirements`` edge map for the manifest-only
# transitive walker.
_HEX_RELEASE_KEEP = frozenset({"version", "requirements"})
_HEX_REQUIREMENT_KEEP = frozenset({"requirement", "optional", "app"})


def _trim_maven_central_pom(data: dict) -> dict:
    """Strip a Maven Central POM XML body to the resolver-read fields.

    Accepts the ``{"text": "<full POM XML>"}`` shape produced by
    :func:`fetch_registry_text`. Parses the XML defensively (defusedxml
    blocks XXE / billion-laughs), drops every direct child of ``<project>``
    that isn't in the keep set, and re-serializes with stdlib ElementTree.

    On any parse failure the data is returned unchanged — the resolver
    will hit the same error path on its own ``defusedxml`` call and emit
    UNKNOWN, which is the right outcome for a malformed registry response.
    """
    text = data.get("text", "")
    if not isinstance(text, str) or not text:
        return data
    try:
        root = DefusedET.fromstring(text)
    except DefusedET.ParseError:
        # Malformed XML — keep the broken text as-is so the resolver hits
        # the same parse failure and routes to UNKNOWN; caching the failure
        # avoids re-fetching on subsequent siblings that reference the same
        # bad parent.
        return data
    except DefusedET.EntitiesForbidden:
        # Entity bomb — never cache the raw body (an attacker-controlled POM
        # could otherwise consume per-scan memory at full size). Cache a
        # small sentinel; the resolver's own defusedxml parse rejects it
        # independently and emits UNKNOWN.
        return {"text": ""}

    # Walk direct children of <project> only. Heavy blocks are always
    # top-level in the POM schema; recursing into <licenses> or
    # <properties> would also strip their meaningful content.
    for child in list(root):
        local = child.tag.rsplit("}", 1)[-1]
        if local not in _POM_KEEP_TAGS:
            root.remove(child)

    # The output carries an ``ns0:`` prefix when the source declared a default
    # namespace — functionally equivalent for the resolver, which strips any
    # prefix.
    return _serialize_trimmed_xml(root)


def _serialize_trimmed_xml(root: Element) -> dict:
    """Wrap a pruned XML tree back into the ``{"text": ...}`` cache shape.

    ``tostring`` is serialization, not a parse surface, so defusedxml
    re-exports the stdlib function unchanged (the parse-side bombs are
    handled by ``DefusedET.fromstring``). Unlike the parser it recurses once
    per level of element nesting, so a document nested past the recursion
    limit inside a kept element parses and then can't be written back. That
    is cached as the same empty sentinel as an entity bomb: the resolver
    reads it as a response with no metadata.
    """
    try:
        return {"text": DefusedET.tostring(root, encoding="unicode")}
    except RecursionError:
        return {"text": ""}


def _trim_maven_metadata(data: dict) -> dict:
    """Strip a ``maven-metadata.xml`` body to its list of published versions.

    Same shape and failure handling as :func:`_trim_maven_central_pom`:
    malformed XML is cached as it is, an entity bomb as an empty sentinel.
    Keeps ``<versioning>`` under the root and ``<versions>`` under that.
    """
    text = data.get("text", "")
    if not isinstance(text, str) or not text:
        return data
    try:
        root = DefusedET.fromstring(text)
    except DefusedET.ParseError:
        return data
    except DefusedET.EntitiesForbidden:
        return {"text": ""}

    for child in list(root):
        if child.tag.rsplit("}", 1)[-1] not in _MAVEN_METADATA_KEEP_TAGS:
            root.remove(child)
            continue
        for sub in list(child):
            if sub.tag.rsplit("}", 1)[-1] not in _MAVEN_VERSIONING_KEEP_TAGS:
                child.remove(sub)

    return _serialize_trimmed_xml(root)


def _trim_nuspec(data: dict) -> dict:
    """Strip a NuGet ``.nuspec`` XML body to the resolver-read fields.

    Same shape as :func:`_trim_maven_central_pom`: accepts the
    ``{"text": "<full nuspec XML>"}`` produced by
    :func:`fetch_registry_text`. The nuspec schema nests the metadata
    we care about inside a ``<metadata>`` element under the ``<package>``
    root; we walk into ``<metadata>`` (the only ``<package>`` child we
    keep) and prune its children to the keep set. Other ``<package>``
    children (``<files>``, signing metadata) are dropped entirely.

    On parse failure the data is returned unchanged. On entity-bomb
    detection we cache an empty sentinel ``{"text": ""}`` so an
    attacker-controlled nuspec can't fill the per-scan cache with the
    raw expanded body.
    """
    text = data.get("text", "")
    if not isinstance(text, str) or not text:
        return data
    try:
        root = DefusedET.fromstring(text)
    except DefusedET.ParseError:
        return data
    except DefusedET.EntitiesForbidden:
        return {"text": ""}

    # Some nuspec schemas declare a namespace
    # (``http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd`` or its
    # earlier 2010/2011/2012 variants); strip the prefix for matching.
    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    for child in list(root):
        if _local(child.tag) != "metadata":
            root.remove(child)
            continue
        for sub in list(child):
            if _local(sub.tag) not in _NUSPEC_KEEP_TAGS:
                child.remove(sub)

    return _serialize_trimmed_xml(root)


def _trim_rubygems_deps(data: dict) -> dict[str, list[dict]]:
    """Return the trimmed ``runtime`` deps map for a RubyGems response body.

    Reads ``data['dependencies'].runtime`` and reduces each entry to the
    ``name`` / ``requirements`` fields the registry-walk transitive fetcher
    reads. Development dependencies aren't followed transitively (same posture
    as the other ecosystems), so that sub-array is dropped rather than cached.

    Only well-formed values are reduced. A ``runtime`` that is not a list, and
    an entry of it that is not an object, are cached as they are: the fetcher
    tells a gem that declares nothing from a response it could not read by
    them. ``data['dependencies']`` is an object here; the callers check.
    """
    deps = data["dependencies"]
    if "runtime" not in deps:
        return {}
    runtime = deps["runtime"]
    if not isinstance(runtime, list):
        return {"runtime": runtime}
    return {
        "runtime": [
            {k: v for k, v in entry.items() if k in {"name", "requirements"}}
            if isinstance(entry, dict)
            else entry
            for entry in runtime
        ]
    }


def _trim_rubygems_version(data: dict) -> dict:
    """Strip a RubyGems v2 per-version response to the resolver-read fields.

    The endpoint returns a flat dict (one version). Top-level keys outside
    ``_RUBYGEMS_VERSION_KEEP`` are dropped; ``dependencies`` is reduced to its
    trimmed ``runtime`` array via :func:`_trim_rubygems_deps`.
    """
    out = {k: v for k, v in data.items() if k in _RUBYGEMS_VERSION_KEEP}
    if isinstance(out.get("dependencies"), dict):
        out["dependencies"] = _trim_rubygems_deps(data)
    return out


def _trim_rubygems_gem(data: dict) -> dict:
    """Strip a RubyGems v1 ``/gems/{name}.json`` response to the kept fields."""
    out = {k: v for k, v in data.items() if k in _RUBYGEMS_GEM_KEEP}
    if isinstance(out.get("dependencies"), dict):
        out["dependencies"] = _trim_rubygems_deps(data)
    return out


def _trim_rubygems_versions(data: dict) -> dict:
    """Strip a RubyGems version-list body to the version numbers.

    Takes and returns the ``{"text": "<JSON array>"}`` shape of
    :func:`fetch_registry_text`: the endpoint answers with an array, which
    the JSON fetcher does not take. A body that is not a JSON array is cached
    as it is, and the resolver reads it as a gem with no version list.
    """
    try:
        entries = json.loads(data.get("text", ""))
    except (TypeError, ValueError, RecursionError):
        return data
    if not isinstance(entries, list):
        return data
    kept = [
        {k: v for k, v in entry.items() if k in _RUBYGEMS_VERSIONS_KEEP}
        for entry in entries
        if isinstance(entry, dict)
    ]
    return {"text": json.dumps(kept)}


def _trim_hex_package(data: dict) -> dict:
    """Strip a hex.pm package response to the license + links + version fields.

    Drops the heavy ``owners`` / ``downloads`` blocks; reduces the nested
    ``meta`` to just ``licenses`` and ``links``, and each ``releases`` entry
    to its ``version``.
    """
    out = {k: v for k, v in data.items() if k in _HEX_PACKAGE_KEEP}
    meta = out.get("meta")
    if isinstance(meta, dict):
        out["meta"] = {k: v for k, v in meta.items() if k in _HEX_META_KEEP}
    releases = out.get("releases")
    if isinstance(releases, list):
        out["releases"] = [
            {k: v for k, v in release.items() if k in _HEX_PACKAGE_RELEASE_KEEP}
            for release in releases
            if isinstance(release, dict)
        ]
    return out


def _trim_hex_release(data: dict) -> dict:
    """Strip a hex.pm release response to the ``requirements`` edge map.

    Each requirement entry is reduced to the ``requirement`` / ``optional`` /
    ``app`` fields the transitive walker reads. An entry that is not an
    object is cached as it is, so the walker sees the same requirement names
    with and without the cache.
    """
    out = {k: v for k, v in data.items() if k in _HEX_RELEASE_KEEP}
    requirements = out.get("requirements")
    if isinstance(requirements, dict):
        out["requirements"] = {
            name: (
                {k: v for k, v in entry.items() if k in _HEX_REQUIREMENT_KEEP}
                if isinstance(entry, dict)
                else entry
            )
            for name, entry in requirements.items()
        }
    return out


def _trim_packagist(data: dict) -> dict:
    """Strip a Packagist v2 metadata response to the resolver-read fields.

    Response shape: ``{"packages": {"<vendor/package>": [<version-entry>, ...]}}``
    where the version-entry list is in descending version order. Trim each
    entry to ``_PACKAGIST_VERSION_KEEP``; preserve the outer envelope so
    callers can look up by package name.

    A minified response is cached minified, with its ``minified`` marker.
    Trimming removes whole keys and keeps the entries in order, so the
    resolver's expansion gives the same result on the cached response as
    on the original.
    """
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        return {"packages": {}}
    trimmed_packages: dict[str, list[dict]] = {}
    for name, entries in packages.items():
        if not isinstance(name, str) or not isinstance(entries, list):
            continue
        trimmed_entries: list[dict] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            trimmed_entries.append({k: v for k, v in entry.items() if k in _PACKAGIST_VERSION_KEEP})
        trimmed_packages[name] = trimmed_entries
    trimmed: dict = {"packages": trimmed_packages}
    minified = data.get("minified")
    if isinstance(minified, str):
        trimmed["minified"] = minified
    return trimmed


def _trim_deps_dev_v3(data: dict) -> dict:
    links = data.get("links")
    trimmed_links: list[dict] = []
    if isinstance(links, list):
        for entry in links:
            if isinstance(entry, dict):
                trimmed_links.append({k: v for k, v in entry.items() if k in _DEPS_DEV_LINK_KEEP})
    return {
        "versionKey": data.get("versionKey", {}),
        "licenses": data.get("licenses", []),
        "links": trimmed_links,
    }


def _trim_for_cache(url: str, data: dict | None) -> dict | None:
    if data is None:
        return None
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path
    if host == "pypi.org" and path.startswith("/pypi/"):
        return _trim_pypi(data)
    if host == "registry.npmjs.org":
        # /registry/{name} has a 'versions' dict; /registry/{name}/{version}
        # doesn't. Discriminate on shape.
        if "versions" in data and isinstance(data["versions"], dict):
            return _trim_npm_project(data)
        return _trim_npm_version(data)
    if host == "api.deps.dev" and path.startswith("/v3/systems/"):
        # ``:dependencies`` sub-resource has a different shape than the
        # plain version endpoint; route it to its own trim. Match by the
        # ``:dependencies`` suffix (URLs are e.g. ``…/versions/1.0.0:dependencies``).
        if path.endswith(":dependencies"):
            return _trim_deps_dev_dependencies(data)
        return _trim_deps_dev_v3(data)
    is_maven_central = host in {
        "repo.maven.apache.org",
        "repo1.maven.apache.org",
        "repo1.maven.org",
    } and path.startswith("/maven2/")
    is_google_maven = host == "dl.google.com" and path.startswith("/dl/android/maven2/")
    is_jenkins_maven = host == "repo.jenkins-ci.org" and path.startswith("/public/")
    if is_maven_central or is_google_maven or is_jenkins_maven:
        # Match any Maven-style registry licenseal queries — Maven Central
        # (``repo.maven.apache.org`` plus its historical ``repo1`` aliases),
        # Google Android Maven, and the Jenkins public repository. All
        # serve POM XML at the canonical layout, so the same trim handles
        # every response shape. An artifact's version list is the one other
        # file read from them; the POM trim would drop what it holds.
        if path.endswith("/maven-metadata.xml"):
            return _trim_maven_metadata(data)
        return _trim_maven_central_pom(data)
    if (
        host == "api.nuget.org"
        and path.startswith("/v3-flatcontainer/")
        and path.endswith(".nuspec")
    ):
        # The flatcontainer service serves raw ``.nuspec`` XML at
        # ``api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.nuspec``.
        # The package's version list (``{id}/index.json``) is a bare array
        # of version numbers with nothing to strip, so the ``.nuspec``
        # suffix check leaves it alone.
        return _trim_nuspec(data)
    if host == "repo.packagist.org" and path.startswith("/p2/"):
        # Packagist v2 metadata — full version history per package, kept
        # entries trimmed to the SPDX / repository / require fields the
        # resolver and the manifest-only transitive walker consume.
        return _trim_packagist(data)
    if host == "rubygems.org" and path.startswith("/api/v2/rubygems/"):
        # RubyGems v2 per-version endpoint — single-version response with
        # the licenses array plus a dependencies.runtime sub-array for the
        # manifest-only transitive walker.
        return _trim_rubygems_version(data)
    if host == "rubygems.org" and path.startswith("/api/v1/gems/"):
        # RubyGems v1 latest-version fallback for unpinned deps; same kept
        # fields modulo ``number`` vs ``version`` for the resolved version.
        return _trim_rubygems_gem(data)
    if host == "rubygems.org" and path.startswith("/api/v1/versions/"):
        # RubyGems version list, fetched as text: reduced to version numbers.
        return _trim_rubygems_versions(data)
    if host == "hex.pm" and path.startswith("/api/packages/"):
        # Two hex.pm endpoints share this prefix: the per-version release
        # (``.../releases/{version}``) carries the transitive requirements;
        # the package endpoint carries the package-level license + links.
        if "/releases/" in path:
            return _trim_hex_release(data)
        return _trim_hex_package(data)
    # crates.io responses are small and varied; not worth trimming.
    # proxy.golang.org go.mod text fits in the ``{"text": "..."}`` shape from
    # fetch_go_mod_text; it's already minimal — no further trim needed.
    # deps.dev's batch endpoint (POST /v3alpha/versionbatch) doesn't go
    # through RegistryCache (POST, scan-unique body) so no trim entry needed.
    return data


class RegistryCache:
    """Per-scan URL response cache with in-flight request dedup.

    Hand `.fetch` to anything that would otherwise call
    :func:`fetch_registry_json` directly — same signature, same return
    semantics, but repeat URLs are served from memory and concurrent
    requests for the same URL collapse into one.

    ``on_rate_limit_pause(host, seconds)`` is called each time the scan's
    requests to a host start waiting for its rate limit to reset (see
    :class:`RateLimitReport`); ``rate_limits.abandoned`` counts the lookups
    that waiting did not save.
    """

    def __init__(self, on_rate_limit_pause: Callable[[str, float], None] | None = None) -> None:
        self._results: dict[str, dict | None] = {}
        self._done: set[str] = set()
        self._events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        # Registry-reachability tallies, counted once per *owned* fetch (waiters
        # served from the cache don't re-count). ``fetches_attempted`` is every
        # request that ran the retry loop to completion; ``fetches_succeeded``
        # is the subset that returned a usable body (a 404 / 5xx / connection
        # failure leaves them equal-but-for-one). The CLI reads these after
        # resolution to tell a wholesale connectivity failure (requests issued,
        # none succeeded) from a scan that simply had nothing registry-
        # resolvable to look up (no requests issued at all). Repeat URLs and
        # short-circuited deps (git/path specs, batch/lockfile hits) never reach
        # here, so they can't skew the ratio.
        self.fetches_attempted = 0
        self.fetches_succeeded = 0
        # Per-host breakdown of ``fetches_attempted``, for the end-of-scan
        # traffic summary: a slow scan should explain itself (a large
        # crates.io count means the 1 req/s fallback tail dominated; a large
        # pypi.org count means a no-lockfile transitive walk). deps.dev batch
        # POSTs bypass the per-URL cache and are not counted here — they are
        # bounded at ~⌈deps/100⌉ per ecosystem and never dominate wall-clock.
        self.fetches_by_host: Counter[str] = Counter()
        # Rate-limit waiting during this scan's fetches. The CLI reads
        # ``rate_limits.abandoned`` after resolution to explain the lookups
        # that came back empty because a host was still rate limiting.
        self.rate_limits = RateLimitReport(on_rate_limit_pause)

    def fetch(self, url: str, client: httpx.Client) -> dict | None:
        """Return cached body for ``url`` or fetch it (deduping in-flight calls).

        JSON-endpoint variant. First caller per URL becomes the owner and
        performs the actual HTTP fetch; concurrent callers for the same
        URL wait on a shared Event and serve from cache once the owner
        finishes. Failed fetches are cached as ``None`` so the scan
        doesn't hammer a dead endpoint.
        """
        return self._fetch(url, client, partial(fetch_registry_json, rate_limits=self.rate_limits))

    def fetch_text(self, url: str, client: httpx.Client) -> dict | None:
        """Cached text-endpoint variant of :meth:`fetch`.

        Used for registries that serve XML or plain text (Maven Central's
        raw POM URLs; the Go module proxy's ``go.mod`` files). The body
        is wrapped as ``{"text": "<body>"}`` for shape uniformity with
        the JSON path. Shares the same cache dict as :meth:`fetch` so
        a URL is at most one cache entry regardless of which method
        fetched it.
        """
        return self._fetch(url, client, fetch_registry_text)

    def _fetch(
        self,
        url: str,
        client: httpx.Client,
        inner_fetcher: Callable[[str, httpx.Client], dict | None],
    ) -> dict | None:
        """Shared in-flight dedup + cache machinery.

        Owner / waiter coordination is identical to the original single-
        fetcher implementation; ``inner_fetcher`` is what changes between
        the JSON and text variants.
        """
        while True:
            with self._lock:
                if url in self._done:
                    return self._results.get(url)
                event = self._events.get(url)
                if event is None:
                    event = threading.Event()
                    self._events[url] = event
                    is_owner = True
                else:
                    is_owner = False
            if is_owner:
                break
            # Another thread is already fetching this URL; wait for it to
            # finish, then loop back to check the cache. If the owner errored
            # before caching, `_done` won't contain `url` — re-enter the
            # owner role on the next iteration.
            event.wait()
        try:
            data = _trim_for_cache(url, inner_fetcher(url, client))
        except BaseException:
            # The fetch raised (e.g. tethered.EgressBlocked propagating past
            # the inner fetcher's httpx.RequestError catch). Don't cache an
            # entry — let the next caller try fresh. Drop the event slot so a
            # retry won't reuse this stale Event, then release waiters.
            with self._lock:
                self._events.pop(url, None)
            event.set()
            raise
        with self._lock:
            self.fetches_attempted += 1
            self.fetches_by_host[urlsplit(url).hostname or "?"] += 1
            if data is not None:
                self.fetches_succeeded += 1
            self._results[url] = data
            self._done.add(url)
        event.set()
        return data
