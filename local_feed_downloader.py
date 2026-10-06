# ==================================================
# STEP 24B.2D: GENERIC SECURE FEED DOWNLOADER + UPDATE ORCHESTRATOR
# ==================================================
#
# download(generic, secure) -> transport validation -> size limits ->
# decompression limits -> format validation -> provider parser
# (feed_providers/*.py, injected as `parse_fn`) -> records ->
# local_feed_store.ingest_snapshot() (UNCHANGED - see that module's own
# header for why the versioned-snapshot + atomic-pointer architecture is
# never touched here).
#
# NOT hard-coded to PhishTank or any provider: every provider-specific
# fact (URL, allowed redirect hosts, compression, expected content
# types, User-Agent) comes from local_feed_providers.LOCAL_FEED_
# PROVIDER_REGISTRY[provider]["download"] - this module only knows
# `provider` as a string and a `parse_fn` callable. A second provider
# needs a new feed_providers/<name>.py module + one more registry
# entry - zero changes here.
#
# SECURITY (Step 24B.2D instructions, all enforced below):
#   - HTTPS verification is NEVER disabled. No TLS-bypass parameter
#     (the "verify" keyword set to a falsy value, an unverified SSL
#     context, disabling hostname checking) appears anywhere in this
#     file - the default `requests` behaviour (certifi-backed
#     verification) is always used for every request this module ever
#     issues, with no parameter that could turn it off.
#   - Redirects are NEVER followed automatically (allow_redirects=False
#     on every request) - each hop's Location is validated explicitly:
#     HTTPS only (no downgrade - an http:// redirect TARGET is refused
#     unconditionally, even though the INITIAL url may itself be http://
#     per a provider's documented endpoint), hostname must be in that
#     provider's own allowlist, never a private/loopback/link-local IP
#     literal, bounded hop count, and an explicit loop check (a URL
#     repeated in the chain aborts immediately rather than silently
#     spinning to the hop limit).
#   - Network size is enforced by STREAMING byte-counting, never by
#     trusting Content-Length alone (a missing, wrong, or deliberately
#     understated Content-Length cannot bypass the limit).
#   - Decompressed size is enforced INCREMENTALLY during decompression
#     itself (zip-bomb protection) - the limit is checked before the
#     next chunk is even requested, never after a full decompress.
#   - Content-Type is validated against the provider's declared
#     expectation before any parsing is attempted (catches, e.g., an
#     HTML error page served with HTTP 200).
#
# CONCURRENCY: a per-provider, file-based exclusive lock
# (download.lock, colocated via local_feed_store.get_provider_dir())
# ensures two concurrent update attempts for the SAME provider can
# never both proceed - the second one fails FAST (ConcurrentUpdateError,
# recorded as an ordinary FAILED attempt) rather than queuing or
# blocking.
#
# Step 24B.2D.1 (ownership-aware lock hardening): recovering an
# abandoned lock is no longer purely age-based - a lock older than any
# threshold is NEVER reclaimed while its recorded owner (pid + the
# OS's own process-creation timestamp for that pid, read via psutil -
# already an approved, pinned dependency in requirements.txt, already
# used identically in endpoint_agent_stable.py - no new dependency)
# is still verifiably alive. Only a CONFIRMED-dead pid, or a pid whose
# current creation time no longer matches what the lock recorded (pid
# reuse), is ever treated as orphaned. Whenever liveness cannot be
# determined reliably (malformed/partial lock content, a psutil access
# error, anything unexpected), the lock is fail-safe treated exactly
# like "still alive" - this module always prefers blocking a new
# download over any chance of two concurrent ones. Reclaiming an
# orphan is itself race-safe: the suspected-orphan file is atomically
# renamed aside first and its content re-verified (by a unique per-
# lock-instance id) before being discarded, so a second recoverer can
# never delete a brand-new lock a third process created in the
# meantime - see _ProviderDownloadLock._reclaim_orphan()'s own comment
# for the exact sequence. release() is likewise ownership-aware: it
# only ever removes a lock file that still contains ITS OWN lock id.
# ==================================================

import json
import os
import uuid
import zlib
from datetime import datetime
from urllib.parse import urljoin, urlsplit
import ipaddress

import psutil
import requests

import local_feed_attempt_store
import local_feed_normalize
import local_feed_providers
import local_feed_store

DEFAULT_CONNECT_TIMEOUT_SECONDS = 10
DEFAULT_READ_TIMEOUT_SECONDS = 120
DEFAULT_MAX_NETWORK_BYTES = 50 * 1024 * 1024          # 50 MB, raw (possibly compressed) bytes over the wire
DEFAULT_MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024    # 200 MB, after decompression
DEFAULT_MAX_REDIRECTS = 3

# Step 24B.2D.1: no longer used to GATE lock reclaim decisions (see the
# module header) - ownership (pid + pid_start_time, via psutil) is the
# only thing that ever decides that now. Kept only as a tolerance for
# comparing a recorded process-creation timestamp against the OS's
# current answer for that same pid (clock/serialization slack), which
# is a completely different, much smaller number - see
# _START_TIME_TOLERANCE_SECONDS.
_START_TIME_TOLERANCE_SECONDS = 2.0

_STREAM_CHUNK_BYTES = 65536


class DownloadError(Exception):
    """Base class for every failure this module can raise. Each
    subclass's own name is used verbatim as the attempt's
    failure_category, so these class names ARE the category vocabulary
    - renaming one is an observability-affecting change."""


class TransportError(DownloadError):
    """DNS/connection/TLS/timeout/unexpected-HTTP-status."""


class RedirectPolicyError(DownloadError):
    """A redirect hop violated policy (non-HTTPS target, host not in
    the provider's allowlist, private/loopback target, too many hops,
    or a repeated URL in the chain)."""


class SizeLimitError(DownloadError):
    """Network or decompressed byte limit exceeded."""


class ContentTypeError(DownloadError):
    """Response Content-Type was not one of the provider's expected
    values (catches, among other things, an HTML error page served
    with HTTP 200)."""


class DecompressionError(DownloadError):
    """Missing magic bytes, corrupt/malformed compressed data, or a
    truncated compressed stream."""


class ParseError(DownloadError):
    """The provider's own parse_fn raised on the (decompressed) body."""


class ConcurrentUpdateError(DownloadError):
    """Another update attempt for this provider is already in
    progress, OR a previous attempt's lock exists and this process
    could not SAFELY prove its recorded owner is dead (see
    _owner_liveness) - fail-safe always raises this rather than ever
    risking two concurrent downloads for the same provider."""


class ConfigurationError(DownloadError):
    """The provider has no registered download configuration."""


# --------------------------------------------------
# REDIRECT / TARGET POLICY (pure functions - no network)
# --------------------------------------------------

def _is_private_target_ip(hostname):

    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        return False  # not an IP literal at all - judged by the allowlist instead

    return (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified
    )


class InsecureInitialUrlError(DownloadError):
    """The INITIAL url (before any redirect) was not https:// and no
    explicit, hostname-scoped test exception was given for it. Step
    24B.2D (verification round): production download configuration
    must always start at an https:// URL - an http:// starting point is
    no longer accepted just because a later redirect might upgrade it.
    The ONLY exception is `allow_insecure_test_hosts`, an explicit,
    hostname-matched allowlist that callers pass themselves; the
    provider registry format has no field for this and
    download_and_ingest() never forwards one from a provider's
    `download` config, so a real provider's configuration cannot ever
    enable it, accidentally or otherwise."""


def validate_initial_url(url, allow_insecure_test_hosts=()):
    """
    Raises InsecureInitialUrlError unless `url` is https://, UNLESS its
    hostname is explicitly listed in `allow_insecure_test_hosts` (empty
    by default - i.e. nothing is allowed by default). Called BEFORE any
    network activity, so a rejected initial URL never causes an outbound
    request of any kind.
    """

    parsed = urlsplit(url)

    if parsed.scheme == "https":
        return

    if parsed.hostname in allow_insecure_test_hosts:
        return

    raise InsecureInitialUrlError(
        f"initial URL {url!r} is not https:// and its host is not in the explicit "
        f"test-only allowlist {allow_insecure_test_hosts!r} - refusing before any network request"
    )


def validate_redirect_target(url, allowed_hosts):
    """
    Raises RedirectPolicyError, or returns None if the target is
    acceptable. HTTPS is required UNCONDITIONALLY for every redirect
    TARGET (this is what makes an HTTPS->HTTP downgrade impossible). As
    of this verification round, the INITIAL url given to secure_fetch()
    is ALSO required to be https:// (see validate_initial_url) except
    for an explicit, hostname-scoped test exception - so http:// is now
    never reachable in a real production call at all, not even as a
    starting point.
    """

    parsed = urlsplit(url)

    if parsed.scheme != "https":
        raise RedirectPolicyError(f"redirect target is not https: {url!r}")

    host = parsed.hostname

    if not host:
        raise RedirectPolicyError(f"redirect target has no hostname: {url!r}")

    if _is_private_target_ip(host):
        raise RedirectPolicyError(
            f"redirect target resolves to a private/loopback/link-local/reserved address: {host!r}"
        )

    if host not in allowed_hosts:
        raise RedirectPolicyError(
            f"redirect target host {host!r} is not in this provider's allowlist {allowed_hosts!r}"
        )


# --------------------------------------------------
# SECURE FETCH (transport + redirects + size + content-type)
# --------------------------------------------------

def _default_http_get(url, **kwargs):
    # The ONLY place this module calls `requests` - a single, auditable
    # call site. The "verify" keyword is never passed at all, which
    # means requests' own default (certifi-backed verification) always
    # applies; there is no parameter path anywhere in this module that
    # could disable it.
    return requests.get(url, **kwargs)


def secure_fetch(url, allowed_redirect_hosts, expected_content_types, user_agent,
                  connect_timeout=DEFAULT_CONNECT_TIMEOUT_SECONDS,
                  read_timeout=DEFAULT_READ_TIMEOUT_SECONDS,
                  max_network_bytes=DEFAULT_MAX_NETWORK_BYTES,
                  max_redirects=DEFAULT_MAX_REDIRECTS,
                  http_get=None,
                  allow_insecure_test_hosts=()):
    """
    Returns raw (possibly still-compressed) bytes. Every failure mode
    raises one of this module's DownloadError subclasses - never a bare
    requests exception, so callers have one vocabulary to handle.
    """

    validate_initial_url(url, allow_insecure_test_hosts=allow_insecure_test_hosts)

    http_get = http_get or _default_http_get
    current_url = url
    visited = []

    for _hop in range(max_redirects + 1):

        if current_url in visited:
            raise RedirectPolicyError(f"redirect loop detected: {current_url!r} repeats in the chain")

        visited.append(current_url)

        try:
            response = http_get(
                current_url,
                headers={"User-Agent": user_agent},
                timeout=(connect_timeout, read_timeout),
                allow_redirects=False,
                stream=True,
            )
        except requests.exceptions.SSLError as exc:
            raise TransportError(f"TLS verification failed: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            raise TransportError(f"timeout: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            raise TransportError(f"connection error (DNS/network): {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise TransportError(f"request error: {exc}") from exc

        if response.status_code in (301, 302, 303, 307, 308):

            location = response.headers.get("Location")
            response.close()

            if not location:
                raise RedirectPolicyError("redirect response carried no Location header")

            next_url = urljoin(current_url, location)
            validate_redirect_target(next_url, allowed_redirect_hosts)
            current_url = next_url
            continue

        if response.status_code != 200:
            response.close()
            raise TransportError(f"unexpected HTTP status {response.status_code}")

        content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()

        if expected_content_types and content_type not in expected_content_types:
            response.close()
            raise ContentTypeError(
                f"unexpected Content-Type {content_type!r} (expected one of {expected_content_types!r}) "
                "- a misconfigured/compromised server returning an error page with HTTP 200 looks exactly "
                "like this"
            )

        # Content-Length is a HINT only (fast-fail when clearly over the
        # limit) - the authoritative enforcement is the streaming loop
        # below, which is immune to a missing, wrong, or deliberately
        # understated header.
        content_length = response.headers.get("Content-Length")

        if content_length is not None:
            try:
                if int(content_length) > max_network_bytes:
                    response.close()
                    raise SizeLimitError(
                        f"advertised Content-Length {content_length} exceeds max_network_bytes={max_network_bytes}"
                    )
            except ValueError:
                pass

        chunks = []
        total = 0

        try:
            for chunk in response.iter_content(chunk_size=_STREAM_CHUNK_BYTES):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_network_bytes:
                    raise SizeLimitError(f"response exceeded max_network_bytes={max_network_bytes}")
                chunks.append(chunk)
        except SizeLimitError:
            raise
        except requests.exceptions.RequestException as exc:
            # A connection drop mid-stream (truncated download) - the
            # partial chunks collected so far are discarded entirely,
            # never partially parsed.
            raise TransportError(f"connection error during download: {exc}") from exc
        finally:
            response.close()

        return b"".join(chunks)

    raise RedirectPolicyError(f"exceeded max_redirects={max_redirects}")


# --------------------------------------------------
# DECOMPRESSION (incremental size enforcement - zip-bomb protection)
# --------------------------------------------------

_GZIP_MAGIC = b"\x1f\x8b"


def decompress(raw_bytes, compression, max_decompressed_bytes):

    if not compression:
        if len(raw_bytes) > max_decompressed_bytes:
            raise SizeLimitError(f"uncompressed body exceeds max_decompressed_bytes={max_decompressed_bytes}")
        return raw_bytes

    if compression != "gzip":
        raise DecompressionError(f"unsupported compression declared: {compression!r}")

    if raw_bytes[:2] != _GZIP_MAGIC:
        raise DecompressionError("missing gzip magic bytes (0x1f8b) - not a valid gzip stream")

    decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)  # | 16 = expect a gzip header/trailer
    out = bytearray()
    pending_input = raw_bytes

    try:
        while True:

            piece = decompressor.decompress(pending_input, _STREAM_CHUNK_BYTES)
            pending_input = decompressor.unconsumed_tail

            if piece:
                out.extend(piece)
                if len(out) > max_decompressed_bytes:
                    raise SizeLimitError(
                        f"decompressed size exceeded max_decompressed_bytes={max_decompressed_bytes}"
                    )

            if not piece and not pending_input:
                break

        tail = decompressor.flush()

        if tail:
            out.extend(tail)
            if len(out) > max_decompressed_bytes:
                raise SizeLimitError(
                    f"decompressed size exceeded max_decompressed_bytes={max_decompressed_bytes}"
                )

    except SizeLimitError:
        raise
    except zlib.error as exc:
        raise DecompressionError(f"malformed/corrupt gzip stream: {exc}") from exc

    if not decompressor.eof:
        raise DecompressionError("truncated gzip stream (ended before the expected gzip trailer)")

    return bytes(out)


# --------------------------------------------------
# PER-PROVIDER CONCURRENCY LOCK (Step 24B.2D.1: ownership-aware)
# --------------------------------------------------

def _read_lock_data(path):
    """Returns the lock file's parsed content as a dict, or None if it
    is missing, unreadable, or not valid JSON - callers treat None
    exactly like "cannot determine ownership" (fail-safe)."""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _owner_liveness(lock_data):
    """
    Three-valued: True (confirmed alive - this IS still the original
    owner), False (confirmed dead/orphan - safe to reclaim), or None
    (cannot be determined reliably). EVERY caller in this module
    treats None exactly like True - fail-safe always prefers blocking
    a new download over any chance of running two concurrently; the
    only way a lock is EVER reclaimed is a proven-dead or proven-
    reused pid, never merely "we could not check".
    """

    if not isinstance(lock_data, dict):
        return None  # malformed/unreadable lock content

    pid = lock_data.get("pid")
    recorded_start_time = lock_data.get("pid_start_time")

    if not isinstance(pid, int) or not isinstance(recorded_start_time, (int, float)):
        return None  # missing/partial metadata - an older or malformed lock file

    try:
        actual_start_time = psutil.Process(pid).create_time()
    except psutil.NoSuchProcess:
        return False  # confirmed dead - no process with this pid exists at all
    except Exception:
        # psutil.AccessDenied, psutil.ZombieProcess, or anything else
        # unexpected - cannot determine reliably. Deliberately broad:
        # the fail-safe answer (None) is correct regardless of WHY the
        # check failed.
        return None

    if abs(actual_start_time - recorded_start_time) > _START_TIME_TOLERANCE_SECONDS:
        # Same pid number, but the OS says THIS process started at a
        # different time than the lock recorded - the original holder
        # exited and the OS has already reused its pid for an unrelated
        # process. Confirmed orphan, same as a dead pid.
        return False

    return True  # same pid, same creation time - genuinely still the original owner


class _ProviderDownloadLock:

    def __init__(self, provider, base_dir=None):
        self._provider = provider
        self._dir = local_feed_store.get_provider_dir(provider, base_dir)
        self._path = os.path.join(self._dir, "download.lock")
        self._lock_id = None
        self._acquired = False

    def _lock_payload(self, lock_id):
        return {
            "pid": os.getpid(),
            "pid_start_time": psutil.Process(os.getpid()).create_time(),
            "acquired_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "provider": self._provider,
            "lock_id": lock_id,
        }

    def _try_create(self, payload):
        """Atomic exclusive-create - the actual mutex. Returns True if
        this call created the file (and wrote `payload` into it),
        False if something was already there (untouched)."""

        try:
            fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
        except Exception:
            try:
                os.remove(self._path)
            except OSError:
                pass
            raise

        return True

    def _reclaim_orphan(self, expected_lock_id):
        """
        Race-safe reclaim of a lock already independently confirmed
        orphaned (by _owner_liveness returning False for its content,
        read a moment ago by the caller).

        THE RACE THIS GUARDS AGAINST: between that read and this call,
        a THIRD process could have already reclaimed the same orphan
        and created its OWN brand-new, legitimate lock at this exact
        path. A naive `os.remove(self._path)` here would delete that
        new, live lock, having nothing to do with the orphan this
        process actually decided to reclaim.

        THE FIX: atomically RENAME the file aside first (os.rename on
        an existing path is atomic on both Windows and POSIX - exactly
        one concurrent reclaimer can ever win this rename; a loser's
        rename simply fails with the source no longer existing). Only
        after winning the rename does this re-read the now-relocated
        file's own lock_id and confirm it is STILL the exact orphaned
        instance this process originally inspected (`expected_lock_id`)
        - if a different, newer lock got swept up by the rename instead
        (because the ORIGINAL orphan had, in the meantime, already been
        reclaimed-and-replaced by someone else between this process's
        read and its rename), it is put back EXACTLY where it was found
        and this call reports failure rather than discarding it.

        Returns True only if the exact expected orphan was captured and
        safely discarded (the path is now free for _try_create). Never
        raises on a losing race - returns False, and the caller treats
        that as "someone else is already handling this", never as an
        error worth crashing over.
        """

        trash_path = f"{self._path}.orphan-{uuid.uuid4().hex}"

        try:
            os.rename(self._path, trash_path)
        except OSError:
            return False  # lost the race to rename it away at all

        captured = _read_lock_data(trash_path)
        captured_lock_id = captured.get("lock_id") if isinstance(captured, dict) else None

        if expected_lock_id is None or captured_lock_id != expected_lock_id:
            # Captured something other than the exact orphan expected -
            # a newer lock materialized at this path in the meantime.
            # Put it back untouched and report failure; never discard
            # content this process cannot prove is the orphan it
            # decided to reclaim.
            try:
                os.rename(trash_path, self._path)
            except OSError:
                pass  # a third party already holds the path again - nothing left to restore
            return False

        try:
            os.remove(trash_path)
        except OSError:
            pass

        return True

    def acquire(self):

        os.makedirs(self._dir, exist_ok=True)

        my_lock_id = str(uuid.uuid4())
        payload = self._lock_payload(my_lock_id)

        if self._try_create(payload):
            self._lock_id = my_lock_id
            self._acquired = True
            return

        existing = _read_lock_data(self._path)
        liveness = _owner_liveness(existing)

        if liveness is not False:
            # True (confirmed alive) or None (cannot determine) - never
            # reclaim either case. A lock held by a genuinely slow but
            # alive attempt is valid REGARDLESS OF AGE (no time-based
            # override exists anymore - see the module header).
            raise ConcurrentUpdateError(
                f"another update attempt for provider {self._provider!r} is already in progress, or "
                f"its lock's ownership could not be safely verified as dead (owner_alive={liveness!r})"
            )

        expected_lock_id = existing.get("lock_id") if isinstance(existing, dict) else None

        if not self._reclaim_orphan(expected_lock_id):
            raise ConcurrentUpdateError(
                f"provider {self._provider!r}'s lock looked orphaned but changed before it could be "
                f"safely reclaimed - another process is already handling it"
            )

        if not self._try_create(payload):
            raise ConcurrentUpdateError(
                f"provider {self._provider!r}'s orphaned lock was reclaimed but another process "
                f"created a new one first"
            )

        self._lock_id = my_lock_id
        self._acquired = True

    def release(self):

        if not self._acquired:
            return

        # Ownership-aware: only remove the file if it still contains
        # THIS instance's own lock_id. If it does not (e.g. this lock
        # was, somehow, independently reclaimed as an orphan by another
        # process while this one was still actually running - not
        # expected in normal operation, but checked anyway), a newer,
        # legitimate lock is never deleted out from under its real
        # owner.
        current = _read_lock_data(self._path)

        if isinstance(current, dict) and current.get("lock_id") == self._lock_id:
            try:
                os.remove(self._path)
            except OSError:
                pass

        self._acquired = False
        self._lock_id = None


def get_lock(name, base_dir=None):
    """
    Step 24B.2E: public factory over _ProviderDownloadLock, so OTHER
    modules (local_feed_scheduler.py) can reuse the exact same proven
    ownership-aware lock/crash-recovery mechanism (pid + pid_start_time
    + unique lock_id + race-safe orphan reclaim - see the class's own
    docstrings) for a DIFFERENT purpose - single-scheduler-instance
    ownership - without importing a leading-underscore "private" name
    and without any refactor of the lock itself. `name` need not be a
    real provider id; the scheduler uses a reserved pseudo-name
    ("__scheduler__") that can never collide with an actual provider,
    getting its own directory under the same local_threat_feed tree.
    """
    return _ProviderDownloadLock(name, base_dir=base_dir)


# --------------------------------------------------
# ORCHESTRATOR
# --------------------------------------------------

def download_and_ingest(provider, parse_fn, feed_name, base_dir=None,
                         attempt_store=None, http_get=None, now=None,
                         download_config=None, allow_insecure_test_hosts=()):
    """
    One full update attempt for one provider:
      acquire per-provider lock -> secure_fetch -> decompress ->
      parse_fn(bytes) -> records -> local_feed_store.ingest_snapshot()
      -> record SUCCESS (only after a real activation) or FAILED (with
      reason+category) via attempt_store.

    parse_fn: a provider's own parser, e.g.
      feed_providers.phishtank_feed.parse_online_valid_json - injected,
      never imported by name here, so this module stays provider-
      agnostic (Step 24B.2D requirement).

    allow_insecure_test_hosts: test-only escape hatch for
    validate_initial_url() - empty by default. The provider registry's
    `download` dict has no field for this, so the normal, registry-
    driven production call (download_config=None, reading from
    LOCAL_FEED_PROVIDER_REGISTRY) can NEVER populate it; a caller must
    explicitly pass it as its own keyword argument to this function
    to use it at all, which a production code path simply never does.

    Raises the same DownloadError subclass it recorded as the failure
    (callers that only care about the recorded state may ignore the
    exception and read attempt_store.get_state(provider) instead).
    """

    attempt_store = attempt_store or local_feed_attempt_store.LocalFeedAttemptStore(base_dir=base_dir)
    now = now or datetime.now()

    meta = download_config
    if meta is None:
        provider_meta = local_feed_providers.get_provider_meta(provider) or {}
        meta = provider_meta.get("download")

    if not meta:
        exc = ConfigurationError(f"no download configuration registered for provider {provider!r}")
        attempt_store.record_attempt_failure(provider, str(exc), type(exc).__name__, now=now)
        raise exc

    lock = _ProviderDownloadLock(provider, base_dir=base_dir)

    try:
        lock.acquire()
    except ConcurrentUpdateError as exc:
        attempt_store.record_attempt_failure(provider, str(exc), type(exc).__name__, now=now)
        raise

    try:

        try:
            raw_bytes = secure_fetch(
                meta["url"],
                allowed_redirect_hosts=meta.get("allowed_redirect_hosts", ()),
                expected_content_types=meta.get("expected_content_types", ()),
                user_agent=meta.get("user_agent", "LocalFeedDownloader/1.0"),
                connect_timeout=meta.get("connect_timeout_seconds", DEFAULT_CONNECT_TIMEOUT_SECONDS),
                read_timeout=meta.get("read_timeout_seconds", DEFAULT_READ_TIMEOUT_SECONDS),
                max_network_bytes=meta.get("max_network_bytes", DEFAULT_MAX_NETWORK_BYTES),
                max_redirects=meta.get("max_redirects", DEFAULT_MAX_REDIRECTS),
                http_get=http_get,
                allow_insecure_test_hosts=allow_insecure_test_hosts,
            )

            decompressed = decompress(
                raw_bytes, meta.get("compression"),
                meta.get("max_decompressed_bytes", DEFAULT_MAX_DECOMPRESSED_BYTES),
            )

            try:
                records = parse_fn(decompressed)
            except DownloadError:
                raise
            except Exception as exc:
                raise ParseError(f"provider parser raised: {exc}") from exc

            result = local_feed_store.ingest_snapshot(
                provider, feed_name, records, local_feed_normalize.classify_and_normalize,
                base_dir=base_dir, now=now,
            )

            if not result.activated:
                raise DownloadError(f"ingest_snapshot rejected the downloaded feed: {result.reason}")

        except DownloadError as exc:
            attempt_store.record_attempt_failure(provider, str(exc), type(exc).__name__, now=now)
            raise

        # Reached ONLY after a real, successful activation - never
        # written before local_feed_store.ingest_snapshot() has
        # actually returned activated=True (Step 24B.2D requirement 8).
        attempt_store.record_attempt_success(provider, now=now)
        return result

    finally:
        lock.release()
