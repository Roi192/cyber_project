# ==================================================
# STEP 24B.2A: LOCAL THREAT INTELLIGENCE FEED - STORAGE ENGINE
# ==================================================
#
# Storage for a bulk, locally-held threat-intel feed (e.g. a PhishTank
# bulk download), kept in a SEPARATE SQLite file per provider - NEVER in
# cybersec.db and NEVER in threat_indicators (see the Step 24B.2 planning
# report: threat_indicators is already live-wired into Legacy TI risk
# scoring/alerting, has no URL support, and is not indexed for bulk
# volume - reusing it would silently turn every feed match into a
# risk-score/alert event, which this feed must never do in Phase 1).
#
# ARCHITECTURE (revised after a real Windows go/no-go test - see the
# Step 24B.2A report): os.replace() of a live SQLite file while a reader
# holds ANY open connection to it fails on this Windows machine with
# PermissionError, in every journal mode tested (rollback AND WAL),
# whether or not the reader had executed a query. SQLite's Windows VFS
# does not set FILE_SHARE_DELETE, so this is not a fluke - it is
# standard Windows file-locking behaviour. Overwriting an "active" DB
# file in place is therefore NOT a safe design on this platform.
#
# Instead, every snapshot is an IMMUTABLE, uniquely-named file that is
# only ever created once, fully built and validated BEFORE it is ever
# exposed under its final name, and NEVER written to or replaced again:
#
#   data/local_threat_feed/<provider>/snapshot_000001.db   (immutable)
#   data/local_threat_feed/<provider>/snapshot_000002.db   (immutable)
#   data/local_threat_feed/<provider>/active_pointer.json  (the ONLY
#                                                            thing ever
#                                                            replaced)
#
# Activation = atomically replacing the tiny JSON pointer file to name a
# new (already fully built+validated+immutable) snapshot version as
# active. The multi-megabyte indicator data itself is never touched
# again once written - only the pointer, a few dozen bytes, changes.
# A snapshot file is renamed into its FINAL name (os.replace of a
# brand-new filename nothing could possibly have open yet) only after
# every validation gate below has passed; building happens under a
# throwaway ".building" filename that is deleted on any failure.
#
# Readers never hold a long-lived connection: every lookup opens the
# pointer file, reads it, closes it; opens the snapshot file it names,
# queries, closes it. This is what makes concurrent activation safe -
# see the explicit concurrent-reader test in test_local_feed_*.py.
#
# Retry is used ONLY for the tiny pointer file's atomic write, to
# absorb a transient I/O error on that few-dozen-byte operation - it is
# NOT used as a substitute for replacing an open SQLite database file
# (that approach was tested, found unreliable on Windows, and
# deliberately abandoned - see above).
# ==================================================

import json
import os
import re
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta

SCHEMA_VERSION = 1

# How long after local_imported_at a feed is considered STALE rather
# than CURRENT, when the caller does not specify its own threshold.
# Generic default (not PhishTank-specific): PhishTank's own feed updates
# hourly, so a provider-aware caller may pass a tighter threshold: this
# default is deliberately more conservative for providers with unknown
# update cadence.
DEFAULT_STALE_AFTER_HOURS = 6

# A rebuilt feed with far fewer rows than the currently-active one is
# treated as suspiciously truncated and rejected (the previous snapshot
# stays active) rather than silently accepted - guards against a
# truncated/partial download being mistaken for a real update.
TRUNCATION_REJECT_RATIO = 0.5

_SNAPSHOT_NAME_RE = re.compile(r"^snapshot_(\d{6})\.db$")


class LocalFeedError(Exception):
    pass


# --------------------------------------------------
# PATHS
# --------------------------------------------------

def default_feed_base_dir():

    override = os.getenv("LOCAL_THREAT_FEED_DIR", "").strip()

    if override:
        return override if os.path.isabs(override) else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), override
        )

    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "local_threat_feed"
    )


def _provider_dir(provider, base_dir=None):

    base = base_dir or default_feed_base_dir()
    return os.path.join(base, provider)


def get_provider_dir(provider, base_dir=None):
    """
    Step 24B.2D: public accessor for a provider's storage directory, so
    a SEPARATE module (local_feed_attempt_store.py, local_feed_
    downloader.py) can colocate its own files there (attempt_state.json,
    download.lock) WITHOUT re-implementing this path resolution itself
    and risking the two modules ever disagreeing about where a given
    provider's files live. Pure passthrough - no change to activation/
    snapshot/pointer behavior.
    """
    return _provider_dir(provider, base_dir)


def _pointer_path(provider, base_dir=None):

    return os.path.join(_provider_dir(provider, base_dir), "active_pointer.json")


def _snapshot_filename(version):

    return f"snapshot_{version:06d}.db"


def _snapshot_path(provider, version, base_dir=None):

    return os.path.join(_provider_dir(provider, base_dir), _snapshot_filename(version))


def _existing_versions(provider, base_dir=None):

    directory = _provider_dir(provider, base_dir)

    if not os.path.isdir(directory):
        return []

    versions = []

    for name in os.listdir(directory):

        match = _SNAPSHOT_NAME_RE.match(name)

        if match and os.path.isfile(os.path.join(directory, name)):
            versions.append(int(match.group(1)))

    return sorted(versions)


# --------------------------------------------------
# SCHEMA (inside each immutable snapshot file)
# --------------------------------------------------

def _create_snapshot_schema(conn):

    conn.execute("""
        CREATE TABLE snapshot_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            provider TEXT NOT NULL,
            feed_name TEXT NOT NULL,
            version INTEGER NOT NULL,
            feed_updated_at TEXT,
            local_imported_at TEXT NOT NULL,
            row_count INTEGER NOT NULL,
            schema_version INTEGER NOT NULL,
            source_metadata_json TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE feed_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            raw_value TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            provider_metadata_json TEXT,
            UNIQUE(indicator_type, normalized_value)
        )
    """)


# --------------------------------------------------
# BUILD + VALIDATE + ACTIVATE (the only writer-side entry point)
# --------------------------------------------------

class IngestResult:

    def __init__(self, activated, version=None, row_count=0, skipped_count=0,
                 reason=None):
        self.activated = activated
        self.version = version
        self.row_count = row_count
        self.skipped_count = skipped_count
        self.reason = reason

    def __repr__(self):
        return (
            f"IngestResult(activated={self.activated}, version={self.version}, "
            f"row_count={self.row_count}, skipped_count={self.skipped_count}, "
            f"reason={self.reason!r})"
        )


def ingest_snapshot(provider, feed_name, records, normalize_fn, feed_updated_at=None,
                     source_metadata=None, base_dir=None, now=None,
                     truncation_reject_ratio=TRUNCATION_REJECT_RATIO):
    """
    records: iterable of dicts with at least "indicator_type" and
        "raw_value" (feed-format parsing already done by the caller's own
        feed_providers/*.py module - this function is format-agnostic).
        Optional: "first_seen", "last_seen", "provider_metadata" (dict).
    normalize_fn: callable(indicator_type, raw_value) -> (indicator_type,
        normalized_value) or (None, None) if the record is not usable -
        see local_feed_normalize.classify_and_normalize. Injected rather
        than imported directly so this module stays independent of any
        one normalization policy.

    Builds a brand-new, immutable snapshot file under a throwaway name,
    validates it, and ONLY on success renames it into its permanent name
    and atomically repoints the provider's pointer file at it. On ANY
    failure the throwaway file is deleted and the previously-active
    snapshot (if any) is left completely untouched - this function never
    writes to an existing snapshot file or to the pointer except on a
    fully-validated success.
    """

    now = now or datetime.now()
    provider_dir = _provider_dir(provider, base_dir)
    os.makedirs(provider_dir, exist_ok=True)

    existing = _existing_versions(provider, base_dir)
    next_version = (existing[-1] + 1) if existing else 1

    building_path = os.path.join(provider_dir, f"snapshot_{next_version:06d}.db.building")

    # A stray leftover from a previous crashed/interrupted build at the
    # same version number must never be silently reused.
    if os.path.exists(building_path):
        os.remove(building_path)

    row_count = 0
    skipped_count = 0

    try:
        conn = sqlite3.connect(building_path)
        try:
            _create_snapshot_schema(conn)

            for record in records:

                indicator_type = record.get("indicator_type")
                raw_value = record.get("raw_value")

                normalized_type, normalized_value = normalize_fn(indicator_type, raw_value)

                if normalized_type is None or normalized_value is None:
                    skipped_count += 1
                    continue

                provider_metadata = record.get("provider_metadata")

                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO feed_indicators (
                            indicator_type, normalized_value, raw_value,
                            first_seen, last_seen, provider_metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        normalized_type,
                        normalized_value,
                        str(raw_value),
                        record.get("first_seen"),
                        record.get("last_seen"),
                        json.dumps(provider_metadata) if provider_metadata else None,
                    ))

                except sqlite3.Error:
                    skipped_count += 1
                    continue

            conn.commit()

            row_count = conn.execute("SELECT COUNT(*) FROM feed_indicators").fetchone()[0]

            # Gate 1: zero usable records -> reject (previous snapshot,
            # if any, stays active).
            if row_count == 0:
                conn.close()
                os.remove(building_path)
                return IngestResult(
                    activated=False, row_count=0, skipped_count=skipped_count,
                    reason="EMPTY_FEED"
                )

            # Gate 2: suspiciously truncated vs the currently-active
            # snapshot (if one exists).
            active_before = get_feed_status(provider, base_dir=base_dir)

            if active_before["status"] != "NEVER_LOADED":

                previous_row_count = active_before.get("row_count") or 0

                if previous_row_count > 0 and row_count < previous_row_count * truncation_reject_ratio:
                    conn.close()
                    os.remove(building_path)
                    return IngestResult(
                        activated=False, row_count=row_count, skipped_count=skipped_count,
                        reason=(
                            "SUSPICIOUSLY_TRUNCATED: new row_count "
                            f"{row_count} < {truncation_reject_ratio:.0%} of previous "
                            f"{previous_row_count}"
                        )
                    )

            local_imported_at = now.strftime("%Y-%m-%d %H:%M:%S")

            conn.execute("""
                INSERT INTO snapshot_meta (
                    id, provider, feed_name, version, feed_updated_at,
                    local_imported_at, row_count, schema_version,
                    source_metadata_json
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                provider, feed_name, next_version, feed_updated_at,
                local_imported_at, row_count, SCHEMA_VERSION,
                json.dumps(source_metadata) if source_metadata else None,
            ))
            conn.commit()

        finally:
            conn.close()

        # Gate 3: integrity_check on a fresh connection (closed write
        # connection first - integrity_check wants exclusive access).
        check_conn = sqlite3.connect(building_path)
        try:
            result = check_conn.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            check_conn.close()

        if result != "ok":
            os.remove(building_path)
            return IngestResult(
                activated=False, row_count=row_count, skipped_count=skipped_count,
                reason=f"INTEGRITY_CHECK_FAILED: {result}"
            )

        # All gates passed. Rename into its permanent, immutable name -
        # this is a brand-new filename nothing could ever have had open,
        # so this particular os.replace() is unconditionally safe
        # regardless of the open-handle issue documented above.
        final_path = _snapshot_path(provider, next_version, base_dir)
        os.replace(building_path, final_path)

    except Exception:
        # Any unexpected failure during build: never leave a partial
        # file behind under either name.
        if os.path.exists(building_path):
            try:
                os.remove(building_path)
            except OSError:
                pass
        raise

    _activate_pointer(provider, next_version, base_dir=base_dir)

    return IngestResult(
        activated=True, version=next_version, row_count=row_count,
        skipped_count=skipped_count, reason=None
    )


# --------------------------------------------------
# POINTER (the ONLY thing ever atomically replaced)
# --------------------------------------------------

def _activate_pointer(provider, version, base_dir=None, retries=3, retry_delay_seconds=0.05):

    # Retry here is explicitly scoped to absorbing a transient I/O
    # error on this few-dozen-byte file only (see module header) - it
    # is never used as a substitute for the versioned-snapshot design.
    provider_dir = _provider_dir(provider, base_dir)
    os.makedirs(provider_dir, exist_ok=True)

    pointer_path = _pointer_path(provider, base_dir)

    payload = json.dumps({
        "active_version": version,
        "activated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "schema_version": SCHEMA_VERSION,
    })

    fd, tmp_path = tempfile.mkstemp(
        prefix="active_pointer_", suffix=".json.tmp", dir=provider_dir
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)

        last_error = None

        for attempt in range(retries):
            try:
                os.replace(tmp_path, pointer_path)
                return
            except OSError as exc:
                last_error = exc
                if attempt < retries - 1:
                    time.sleep(retry_delay_seconds)

        raise LocalFeedError(
            f"Failed to activate pointer for provider={provider!r} after "
            f"{retries} attempts: {last_error!r}"
        )

    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def deactivate_provider(provider, base_dir=None):
    """
    Removes the provider's pointer file entirely, returning
    get_feed_status() to NEVER_LOADED. Used when there is no PREVIOUS
    valid snapshot to roll back to (e.g. the very first activation for
    a provider turns out to need undoing) - rollback_to_version()
    requires an existing target version; this does not. Snapshot files
    themselves are left on disk (immutable, untouched) - only the
    pointer is removed, via the same atomic-replace-of-a-tiny-file
    mechanism as _activate_pointer(), just targeting a "points at
    nothing" end state instead of a new version.
    """

    pointer_path = _pointer_path(provider, base_dir)

    try:
        os.remove(pointer_path)
    except OSError:
        pass  # already absent - already NEVER_LOADED, nothing to do


def rollback_to_version(provider, version, base_dir=None):
    """
    Points the provider back at an older, still-existing snapshot
    version (e.g. after discovering a newly-activated snapshot is bad
    for a reason the automated gates did not catch). Re-verifies the
    target file's integrity before switching - never points at a file
    that is missing or corrupt.
    """

    path = _snapshot_path(provider, version, base_dir)

    if not os.path.isfile(path):
        raise LocalFeedError(f"Cannot roll back: snapshot version {version} does not exist")

    conn = sqlite3.connect(path)
    try:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()

    if result != "ok":
        raise LocalFeedError(f"Cannot roll back: snapshot version {version} failed integrity_check")

    _activate_pointer(provider, version, base_dir=base_dir)


# --------------------------------------------------
# READ SIDE (always short-lived connections - see module header)
# --------------------------------------------------

def get_active_pointer(provider, base_dir=None):
    """Returns {"active_version": int, "activated_at": str} or None if
    no feed was ever activated for this provider (NEVER_LOADED)."""

    pointer_path = _pointer_path(provider, base_dir)

    if not os.path.isfile(pointer_path):
        return None

    try:
        with open(pointer_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None

    if not isinstance(data, dict) or "active_version" not in data:
        return None

    return data


def get_feed_status(provider, base_dir=None, stale_after_hours=DEFAULT_STALE_AFTER_HOURS, now=None):
    """
    Returns a dict: {"status": "CURRENT"|"STALE"|"NEVER_LOADED",
    "version", "feed_name", "feed_updated_at", "local_imported_at",
    "row_count", "schema_version"} - version/feed_name/etc. are None
    when status is NEVER_LOADED.
    """

    now = now or datetime.now()
    pointer = get_active_pointer(provider, base_dir)

    if pointer is None:
        return {
            "status": "NEVER_LOADED", "version": None, "feed_name": None,
            "feed_updated_at": None, "local_imported_at": None,
            "row_count": None, "schema_version": None,
        }

    version = pointer["active_version"]
    snap_path = _snapshot_path(provider, version, base_dir)

    if not os.path.isfile(snap_path):
        # Pointer references a version that no longer exists on disk -
        # should never happen given the retention policy in
        # cleanup_old_snapshots(), but fails safe rather than crashing.
        return {
            "status": "NEVER_LOADED", "version": None, "feed_name": None,
            "feed_updated_at": None, "local_imported_at": None,
            "row_count": None, "schema_version": None,
        }

    conn = sqlite3.connect(snap_path)
    try:
        conn.execute("PRAGMA query_only = ON")
        row = conn.execute("""
            SELECT feed_name, feed_updated_at, local_imported_at, row_count,
                   schema_version
            FROM snapshot_meta WHERE id = 1
        """).fetchone()
    finally:
        conn.close()

    if row is None:
        return {
            "status": "NEVER_LOADED", "version": None, "feed_name": None,
            "feed_updated_at": None, "local_imported_at": None,
            "row_count": None, "schema_version": None,
        }

    feed_name, feed_updated_at, local_imported_at, row_count, schema_version = row

    try:
        imported_dt = datetime.strptime(local_imported_at, "%Y-%m-%d %H:%M:%S")
        is_stale = (now - imported_dt) > timedelta(hours=stale_after_hours)
    except (ValueError, TypeError):
        is_stale = True  # unparsable timestamp - fail safe toward STALE, never CURRENT

    return {
        "status": "STALE" if is_stale else "CURRENT",
        "version": version,
        "feed_name": feed_name,
        "feed_updated_at": feed_updated_at,
        "local_imported_at": local_imported_at,
        "row_count": row_count,
        "schema_version": schema_version,
    }


def lookup_indicator(provider, indicator_type, normalized_value, base_dir=None):
    """
    Exact, indexed lookup only - (indicator_type, normalized_value) is
    the snapshot's UNIQUE constraint, so this is always a single-row
    index seek, never a table scan (verified via EXPLAIN QUERY PLAN in
    the test suite). Returns (row_dict_or_None, feed_status_dict).
    A short-lived connection is opened and closed within this call only
    - nothing is held open across calls.
    """

    status = get_feed_status(provider, base_dir=base_dir)

    if status["status"] == "NEVER_LOADED":
        return None, status

    snap_path = _snapshot_path(provider, status["version"], base_dir)

    if not os.path.isfile(snap_path):
        return None, status

    conn = sqlite3.connect(snap_path)
    try:
        conn.execute("PRAGMA query_only = ON")
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT indicator_type, normalized_value, raw_value, first_seen,
                   last_seen, provider_metadata_json
            FROM feed_indicators
            WHERE indicator_type = ? AND normalized_value = ?
        """, (indicator_type, normalized_value)).fetchone()
    finally:
        conn.close()

    return (dict(row) if row is not None else None), status


# --------------------------------------------------
# CLEANUP (separate from activation; never deletes the active version
# or the retained previous version(s); skips - never forces - a file it
# cannot delete)
# --------------------------------------------------

def cleanup_old_snapshots(provider, keep_count=2, base_dir=None):
    """
    Deletes snapshot files older than the `keep_count` most recent
    versions (which always includes the currently-active one, if any).
    keep_count=2 (the default) retains the active snapshot PLUS exactly
    one prior valid snapshot for rollback, per the approved design.
    Never attempts to delete the active version or a retained version.
    A file that cannot be deleted (e.g. still held open by something on
    Windows) is skipped, logged in the returned list, and left for a
    later cleanup attempt - never forced.
    """

    pointer = get_active_pointer(provider, base_dir)
    active_version = pointer["active_version"] if pointer else None

    versions = _existing_versions(provider, base_dir)

    if active_version is not None and active_version not in versions:
        versions.append(active_version)
        versions.sort()

    keep = set(versions[-keep_count:]) if keep_count > 0 else set()

    if active_version is not None:
        keep.add(active_version)

    deleted = []
    skipped = []

    for version in versions:

        if version in keep:
            continue

        path = _snapshot_path(provider, version, base_dir)

        try:
            os.remove(path)
            deleted.append(version)
        except OSError:
            skipped.append(version)

    return {"deleted": deleted, "skipped": skipped, "kept": sorted(keep)}
