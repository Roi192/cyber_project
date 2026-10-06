# ==================================================
# PHASE 12B.6C.1: CENTRAL SQLITE CONNECTION POLICY
# ==================================================
#
# Reliability hardening only - no detection semantics live here.
#
# WHY THIS EXISTS (12B.6C live-verification incident, reproduced on scratch
# DBs by repro_lock_12b6c1.py):
#   In rollback-journal mode a writer whose COMMIT fails with "database is
#   locked" (an unfinished reader holds SHARED) STAYS inside its transaction
#   and keeps a PENDING lock, which blocks every other reader AND writer,
#   even after the original reader finished, until that writer is rolled
#   back and closed. If its traceback is kept alive (Flask's debug-mode
#   debugger retains frames), the connection is never released. Workers that
#   exited on the first "database is locked" then made things worse.
#
# THE POLICY (one place, used by every module's get_db_connection()):
#   * WAL journal mode (persistent in the DB file; readers never block the
#     writer and the writer never blocks readers) - set once by ensure_wal().
#   * synchronous=FULL, explicitly: the same durability as before. NEVER OFF.
#   * a deliberate, bounded busy timeout (default 15 s) on EVERY connection,
#     replacing the accidental mix of 5 s / 30 s defaults. It tolerates short
#     contention; it is deliberately not long enough to mask a multi-minute
#     stuck transaction.
#   * bounded, explicit retry for transient lock errors (retry_on_lock) and
#     a single classification of "transient lock" (is_transient_lock_error).
#     Non-lock errors are never classified as transient and are never hidden.
#   * connection tracking so a request / a worker iteration can always
#     roll back and close connections that an exception left behind
#     (release_since / release_thread_connections).

import os
import sqlite3
import sys
import threading
import time

# --------------------------------------------------
# CONFIGURATION (module constants; env overrides are for tests/operators)
# --------------------------------------------------

DEFAULT_BUSY_TIMEOUT_MS = 15000
DEFAULT_LOCK_RETRY_ATTEMPTS = 5
DEFAULT_LOCK_RETRY_BASE_DELAY_SECONDS = 0.5
LOCK_RETRY_MAX_DELAY_SECONDS = 8.0

# synchronous=FULL is SQLite's default; it is set explicitly so it can never
# drift, and OFF/NORMAL are deliberately not offered.
SYNCHRONOUS_MODE = "FULL"

# Keeps the -wal file from staying large after a checkpoint.
WAL_JOURNAL_SIZE_LIMIT_BYTES = 64 * 1024 * 1024


def _env_int(name, default, minimum):

    try:
        value = int(os.getenv(name, "").strip())
    except ValueError:
        return default

    return value if value >= minimum else default


def busy_timeout_ms():
    return _env_int("SOC_DB_BUSY_TIMEOUT_MS", DEFAULT_BUSY_TIMEOUT_MS, 100)


def lock_retry_attempts():
    return _env_int("SOC_DB_LOCK_RETRY_ATTEMPTS", DEFAULT_LOCK_RETRY_ATTEMPTS, 1)


def lock_retry_base_delay():

    try:
        value = float(os.getenv("SOC_DB_LOCK_RETRY_BASE_DELAY", "").strip())
    except ValueError:
        return DEFAULT_LOCK_RETRY_BASE_DELAY_SECONDS

    return value if value >= 0 else DEFAULT_LOCK_RETRY_BASE_DELAY_SECONDS


def desired_journal_mode():

    mode = os.getenv("SOC_DB_JOURNAL_MODE", "WAL").strip().upper()

    return mode if mode in ("WAL", "DELETE") else "WAL"


# --------------------------------------------------
# ERROR CLASSIFICATION
# --------------------------------------------------

_TRANSIENT_MARKERS = (
    "database is locked",
    "database table is locked",
    "database schema is locked",
)


class LockRetryExhausted(sqlite3.OperationalError):

    # Raised by retry_on_lock when every bounded attempt hit a transient
    # lock. Still an OperationalError (and still classified transient) so
    # callers can defer the item; carries the last underlying error.
    pass


def is_transient_lock_error(exc):

    # ONLY lock/busy contention is transient. Every other OperationalError
    # (disk I/O, disk full, malformed, no such table ...) returns False and
    # must stay visible to the caller.
    if not isinstance(exc, sqlite3.OperationalError):
        return False

    text = str(exc).lower()

    return any(marker in text for marker in _TRANSIENT_MARKERS)


# --------------------------------------------------
# CONNECTION TRACKING
# --------------------------------------------------
# Connections are tracked by WEAK reference (the factory returns a tiny
# sqlite3.Connection subclass, which - unlike the C type - supports weak
# references), so tracking never extends a connection's lifetime: an
# unreferenced connection is still closed/rolled back by garbage collection
# exactly as before. Entries carry a monotonically increasing sequence
# number, so a position marker stays valid however the list is pruned.

import itertools
import weakref


class TrackedConnection(sqlite3.Connection):

    pass


_local = threading.local()
_sequence = itertools.count(1)


def _entries():

    entries = getattr(_local, "entries", None)

    if entries is None:
        entries = []
        _local.entries = entries

    return entries


def _is_open(conn):

    try:
        conn.in_transaction
        return True
    except sqlite3.ProgrammingError:
        return False


def _prune(entries):

    entries[:] = [
        (seq, ref) for seq, ref in entries
        if ref() is not None and _is_open(ref())
    ]


def tracked_connections():

    # Live, still-open connections opened by this thread (diagnostics/tests).
    return [c for _, ref in _entries() for c in [ref()] if c is not None and _is_open(c)]


def mark():

    # Position marker: release_since(mark) only touches connections opened
    # AFTER it (a Flask request never closes connections a caller opened
    # before the request started).
    return next(_sequence)


def _release(conn):

    try:
        if conn.in_transaction:
            conn.rollback()
    except sqlite3.Error:
        pass

    try:
        conn.close()
    except sqlite3.Error:
        pass


def release_since(position):

    # Roll back (if a transaction is open) and close every tracked
    # connection opened after `position`. Idempotent; never raises. This is
    # the safety net that makes a leaked write transaction impossible to
    # outlive its request, even if a debugger retains the traceback.
    if position is None:
        return 0

    entries = _entries()
    released = 0
    kept = []

    for seq, ref in entries:

        conn = ref()

        if conn is None:
            continue

        if seq > position and _is_open(conn):
            _release(conn)
            released += 1
        elif _is_open(conn):
            kept.append((seq, ref))

    entries[:] = kept

    return released


def release_thread_connections():

    # Worker-loop variant: release everything this thread still has open.
    return release_since(0)


# --------------------------------------------------
# CONNECTION FACTORY
# --------------------------------------------------

def configure_connection(conn):

    conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms()}")
    conn.execute(f"PRAGMA synchronous = {SYNCHRONOUS_MODE}")

    return conn


def open_connection(db_name):

    conn = sqlite3.connect(
        db_name,
        timeout=busy_timeout_ms() / 1000.0,
        factory=TrackedConnection
    )
    conn.row_factory = sqlite3.Row

    configure_connection(conn)

    entries = _entries()

    if len(entries) >= 64:
        _prune(entries)

    entries.append((next(_sequence), weakref.ref(conn)))

    return conn


# --------------------------------------------------
# WAL INITIALIZATION (controlled, idempotent, never fatal)
# --------------------------------------------------

def ensure_journal_mode(db_name, log=None):

    # Returns the journal mode actually in effect. Called from the
    # application / worker start-up paths. Switching the mode needs a brief
    # exclusive moment, so it is retried within the same bounded policy and,
    # if it still cannot be done, start-up continues in the current mode
    # (a warning is logged) rather than failing.
    log = log or (lambda message: print(message, flush=True))
    wanted = desired_journal_mode()

    conn = sqlite3.connect(db_name, timeout=busy_timeout_ms() / 1000.0)

    try:

        current = conn.execute("PRAGMA journal_mode").fetchone()[0].upper()

        if current == wanted:
            conn.execute(f"PRAGMA journal_size_limit = {WAL_JOURNAL_SIZE_LIMIT_BYTES}")
            return current

        def switch():
            return conn.execute(f"PRAGMA journal_mode = {wanted}").fetchone()[0].upper()

        try:
            result = retry_on_lock(switch, label="journal_mode", log=log)
        except sqlite3.OperationalError as exc:
            log(f"[db-config] WARNING: could not switch journal_mode to {wanted} "
                f"(staying in {current}): {exc}")
            return current

        log(f"[db-config] journal_mode {current} -> {result}")

        return result

    finally:
        conn.close()


# --------------------------------------------------
# BOUNDED RETRY FOR TRANSIENT LOCKS
# --------------------------------------------------

def retry_on_lock(operation, *, attempts=None, base_delay=None, label="db",
                  cleanup=None, sleep=time.sleep, log=None):

    # Runs operation() and retries ONLY on a transient lock error, with a
    # short exponential back-off (base, 2*base, 4*base ... capped). Between
    # attempts `cleanup(exc)` (typically conn.rollback()) restores a usable
    # connection. After the bounded attempts it raises LockRetryExhausted;
    # any other exception propagates untouched on the first occurrence.
    # `operation` must be safe to re-run (idempotent or fully rolled back).
    attempts = attempts or lock_retry_attempts()
    base = lock_retry_base_delay() if base_delay is None else base_delay
    log = log or (lambda message: print(message, flush=True))

    last = None

    for attempt in range(1, attempts + 1):

        try:
            return operation()

        except sqlite3.OperationalError as exc:

            if not is_transient_lock_error(exc):
                raise

            last = exc

            if cleanup is not None:
                try:
                    cleanup(exc)
                except sqlite3.Error:
                    pass

            if attempt >= attempts:
                break

            delay = min(base * (2 ** (attempt - 1)), LOCK_RETRY_MAX_DELAY_SECONDS)

            log(f"[db-config] {label}: transient lock (attempt {attempt}/{attempts}), "
                f"retrying in {delay:.1f}s: {exc}")

            sleep(delay)

    raise LockRetryExhausted(
        f"{label}: gave up after {attempts} attempts: {last}"
    ) from last
