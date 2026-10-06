# ==================================================
# PHASE 13B: SEPARATE, BOUNDED TELEMETRY STORE (OBSERVATIONS)
# ==================================================
#
# High-volume normalized OBSERVATIONS never go into cybersec.db. They live in
# one SQLite file per UTC day:  <telemetry dir>/telemetry_YYYYMMDD.db
#
# FILE POLICY - the file is chosen by the UTC DAY OF observed_at:
#   * the same source event always maps to the same file, so
#     UNIQUE(sensor_id, source_event_id) gives EXACT idempotency (no lookback,
#     no midnight race);
#   * an event observed at 23:59:59.9 and ingested at 00:00:01 lands in the
#     EARLIER day file - nothing is lost at midnight;
#   * a day file is writable only while it can still receive on-time or late
#     events (observed_at within SECURITY_MAX_PAST_DAYS); older files are
#     SEALED: ingestion never opens them for writing.
#
# Connections are opened per batch and closed in `finally` (never pooled):
# app.py's teardown_request closes every db_config connection opened during a
# request, and short-lived connections keep lock scope tiny (12B.6C.1 policy:
# WAL, synchronous=FULL, bounded busy timeout, retry_on_lock).
#
# RETENTION is foundation-only: OFF by default, never run automatically, only
# ever removes files named telemetry_YYYYMMDD.db inside the telemetry
# directory (judged by the filename day, never mtime), never any other file,
# never the main database.

import ipaddress
import os
import re
import sqlite3

from datetime import timedelta

import db_config
import endpoint_identity
import security_contract as sc
import security_detections as sd

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

SCHEMA_VERSION = "1"

_DAY_FILE_RE = re.compile(r"^telemetry_(\d{8})\.db\Z")
_DAY_RE = re.compile(r"^\d{8}\Z")

OBSERVATIONS_DDL = """
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY,
        sensor_id TEXT NOT NULL,
        source_engine TEXT NOT NULL,
        source_type TEXT NOT NULL,
        source_event_id TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        ingested_at TEXT NOT NULL,
        endpoint_uid TEXT,
        endpoint_resolution TEXT NOT NULL,
        src_ip TEXT,
        src_port INTEGER,
        dst_ip TEXT,
        dst_port INTEGER,
        protocol TEXT,
        community_id TEXT,
        raw_ref TEXT,
        metadata_json TEXT,
        UNIQUE (sensor_id, source_event_id)
    )
"""

META_DDL = """
    CREATE TABLE IF NOT EXISTS telemetry_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
"""

# Index set for one day file. Every index is justified by a bounded query
# helper below and by the Phase 13B benchmark (see the report).
INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_obs_observed ON observations(observed_at)",
    "CREATE INDEX IF NOT EXISTS idx_obs_sensor ON observations(sensor_id, observed_at)",
    """
    CREATE INDEX IF NOT EXISTS idx_obs_endpoint
    ON observations(endpoint_uid, observed_at)
    WHERE endpoint_uid IS NOT NULL
    """,
    "CREATE INDEX IF NOT EXISTS idx_obs_src ON observations(src_ip, observed_at)",
    "CREATE INDEX IF NOT EXISTS idx_obs_dst ON observations(dst_ip, observed_at)",
    """
    CREATE INDEX IF NOT EXISTS idx_obs_community
    ON observations(community_id)
    WHERE community_id IS NOT NULL
    """,
)


class TelemetryStoreError(Exception):

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# --------------------------------------------------
# PATHS
# --------------------------------------------------

def telemetry_dir():

    override = os.getenv("SECURITY_TELEMETRY_DIR", "").strip()

    if override:
        base = override if os.path.isabs(override) else os.path.join(_PROJECT_DIR, override)
    else:
        base = os.path.join(_PROJECT_DIR, "data", "telemetry")

    return os.path.abspath(base)


def _same_path(a, b):
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _assert_safe_dir(directory):

    # The telemetry directory can never be, or contain, the main database
    # file - telemetry is physically separate from control data.
    main = os.path.realpath(sd.main_db_path())
    target = os.path.realpath(directory)

    if os.path.normcase(main) == os.path.normcase(target):
        raise TelemetryStoreError("TELEMETRY_DIR_IS_MAIN_DB")

    try:
        common = os.path.commonpath([os.path.normcase(main), os.path.normcase(target)])
    except ValueError:
        common = None

    if common is not None and common == os.path.normcase(target):
        raise TelemetryStoreError("TELEMETRY_DIR_CONTAINS_MAIN_DB")


def day_file_path(day, directory=None):

    if not isinstance(day, str) or not _DAY_RE.match(day):
        raise TelemetryStoreError("BAD_DAY")

    directory = directory or telemetry_dir()

    return os.path.join(directory, f"telemetry_{day}.db")


def is_sealed(day, now):

    # A day is sealed once it can no longer receive any acceptable record:
    # strictly older than the late-arrival window.
    oldest_writable = (now - timedelta(days=sc.max_past_days())).strftime("%Y%m%d")

    return day < oldest_writable


# --------------------------------------------------
# WRITE PATH
# --------------------------------------------------

def _open_day_connection(day, now):

    directory = telemetry_dir()

    _assert_safe_dir(directory)

    if is_sealed(day, now):
        raise TelemetryStoreError("DAY_SEALED")

    os.makedirs(directory, exist_ok=True)

    path = day_file_path(day, directory)

    if not os.path.exists(path):
        # Creation: WAL is persistent in the file header; set it once through
        # the controlled, idempotent path (safe if two writers race here).
        db_config.ensure_journal_mode(path, log=lambda message: None)

    conn = db_config.open_connection(path)

    has_schema = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'observations'"
    ).fetchone()

    if has_schema is None:

        def create():

            conn.execute("BEGIN IMMEDIATE")

            try:
                conn.execute(OBSERVATIONS_DDL)
                conn.execute(META_DDL)

                for statement in INDEX_DDL:
                    conn.execute(statement)

                conn.execute(
                    "INSERT INTO telemetry_meta (key, value) VALUES ('schema_version', ?) "
                    "ON CONFLICT (key) DO NOTHING", (SCHEMA_VERSION,)
                )
                conn.execute(
                    "INSERT INTO telemetry_meta (key, value) VALUES ('utc_day', ?) "
                    "ON CONFLICT (key) DO NOTHING", (day,)
                )

                conn.commit()

            except BaseException:
                conn.rollback()
                raise

        try:
            db_config.retry_on_lock(create, label="telemetry_schema", cleanup=lambda exc: conn.rollback())
        except BaseException:
            conn.close()
            raise

    return conn


_INSERT_SQL = """
    INSERT INTO observations (
        sensor_id, source_engine, source_type, source_event_id,
        observed_at, ingested_at, endpoint_uid, endpoint_resolution,
        src_ip, src_port, dst_ip, dst_port, protocol, community_id,
        raw_ref, metadata_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (sensor_id, source_event_id) DO NOTHING
"""


def insert_observations(day, records, now):

    # All `records` must belong to `day` (the UTC day of observed_at). One
    # short write transaction; returns "ACCEPTED"/"DUPLICATE" per record. The
    # transaction is all-or-nothing, so a retry after a transient lock is safe.
    if not records:
        return []

    for r in records:

        if r.record_type != sc.RECORD_OBSERVATION:
            raise TelemetryStoreError("NOT_AN_OBSERVATION")

        if r.observed_day() != day:
            raise TelemetryStoreError("WRONG_DAY_FILE")

    conn = _open_day_connection(day, now)

    def write():

        statuses = []

        conn.execute("BEGIN IMMEDIATE")

        try:

            for r in records:

                cursor = conn.execute(_INSERT_SQL, (
                    r.sensor_id, r.source_engine, r.source_type, r.source_event_id,
                    r.observed_at, r.ingested_at, r.endpoint_uid, r.endpoint_resolution,
                    r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.protocol, r.community_id,
                    r.raw_ref, r.metadata_json,
                ))

                statuses.append("ACCEPTED" if cursor.rowcount == 1 else "DUPLICATE")

            conn.commit()

            return statuses

        except BaseException:

            try:
                conn.rollback()
            except Exception:
                pass

            raise

    try:
        return db_config.retry_on_lock(write, label="telemetry_insert")
    finally:
        conn.close()


# --------------------------------------------------
# BOUNDED QUERY HELPERS
# --------------------------------------------------

_OBS_COLUMNS = (
    "id, sensor_id, source_engine, source_type, source_event_id, "
    "observed_at, ingested_at, endpoint_uid, endpoint_resolution, "
    "src_ip, src_port, dst_ip, dst_port, protocol, community_id, "
    "raw_ref, metadata_json"
)


def list_day_files(directory=None):

    # (day, path) for regular files that EXACTLY match telemetry_YYYYMMDD.db.
    # Symlinks/junctions and anything else are ignored.
    directory = directory or telemetry_dir()

    if not os.path.isdir(directory):
        return []

    found = []

    with os.scandir(directory) as entries:

        for entry in entries:

            match = _DAY_FILE_RE.match(entry.name)

            if match is None:
                continue

            try:
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue

            found.append((match.group(1), entry.path))

    return sorted(found)


def query_max_span_days():

    return sc.retention_days()


def query_observations(start, end, endpoint_uid=None, ip=None, community_id=None,
                       sensor_id=None, limit=None, source_engine=None):

    # Time bounds are REQUIRED; the range is capped; explicit columns only;
    # `limit` is clamped to 1000. Only the day files overlapping the range are
    # opened (read-only, query_only), so a query costs at most a few bounded
    # index lookups.
    start_s, end_s = sd.parse_range(start, end, query_max_span_days())
    limit = sd.clamp_limit(limit)

    clauses = []
    params = []

    if endpoint_uid is not None:

        uid = endpoint_identity.normalize_endpoint_uid(endpoint_uid)

        if uid is None:
            raise sd.QueryError("invalid endpoint_uid")

        clauses.append("endpoint_uid = ?")
        params.append(uid)

    if community_id is not None:

        if not isinstance(community_id, str) or not sc.COMMUNITY_ID_RE.match(community_id):
            raise sd.QueryError("invalid community_id")

        clauses.append("community_id = ?")
        params.append(community_id)

    if sensor_id is not None:

        if not isinstance(sensor_id, str) or not sc.SENSOR_ID_RE.match(sensor_id):
            raise sd.QueryError("invalid sensor_id")

        clauses.append("sensor_id = ?")
        params.append(sensor_id)

    clean = None

    if source_engine is not None:

        if not isinstance(source_engine, str) or not sd.ENGINE_NAME_RE.match(source_engine):
            raise sd.QueryError("invalid source_engine")

        clauses.append("source_engine = ?")
        params.append(source_engine)

    if ip is not None:

        try:
            clean = str(ipaddress.ip_address(ip)) if isinstance(ip, str) and "%" not in ip else None
        except ValueError:
            clean = None

        if clean is None:
            raise sd.QueryError("invalid ip")

    first_day = sc.day_key(sc.parse_utc(start_s))
    last_day = sc.day_key(sc.parse_utc(end_s))

    rows = []

    for day, path in list_day_files():

        if day < first_day or day > last_day:
            continue

        conn = db_config.open_connection(path)

        try:

            conn.execute("PRAGMA query_only = ON")

            time_clause = "observed_at >= ? AND observed_at <= ?"
            time_params = [start_s, end_s]
            base = " AND ".join([time_clause] + clauses)

            if clean is not None:

                sql = (
                    f"SELECT {_OBS_COLUMNS} FROM observations WHERE {base} AND src_ip = ? "
                    f"UNION "
                    f"SELECT {_OBS_COLUMNS} FROM observations WHERE {base} AND dst_ip = ? "
                    "ORDER BY observed_at DESC, id DESC LIMIT ?"
                )
                args = time_params + params + [clean] + time_params + params + [clean, limit]

            else:

                sql = (
                    f"SELECT {_OBS_COLUMNS} FROM observations WHERE {base} "
                    "ORDER BY observed_at DESC, id DESC LIMIT ?"
                )
                args = time_params + params + [limit]

            try:
                fetched = conn.execute(sql, args).fetchall()
            except sqlite3.OperationalError as exc:
                # A writer has just created this day file but not yet committed
                # its schema: the day is simply empty right now. Any other
                # error (a real lock, corruption ...) is NOT swallowed.
                if "no such table" in str(exc).lower():
                    continue
                raise

            for row in fetched:
                item = dict(row)
                item["day_file"] = day
                rows.append(item)

        finally:
            conn.close()

    rows.sort(key=lambda r: (r["observed_at"], r["day_file"], r["id"]), reverse=True)

    return rows[:limit]


# --------------------------------------------------
# RETENTION FOUNDATION (destructive; OFF by default; never automatic)
# --------------------------------------------------

def apply_retention(directory=None, now=None, days=None, enabled=None,
                    protected_days=(), dry_run=False):

    # Returns a report dict. Deletes ONLY when enabled and not dry_run.
    # Candidates are regular files named exactly telemetry_YYYYMMDD.db inside
    # `directory`, whose FILENAME day is older than `days` (never mtime), and
    # not in `protected_days` (hook for future incident links). The main
    # database and every other file are never candidates.
    directory = os.path.abspath(directory or telemetry_dir())
    now = now or sc.utc_now()
    enabled = sc.retention_enabled() if enabled is None else bool(enabled)

    effective_days = max(days if days is not None else sc.retention_days(),
                         sc.max_past_days() + 1)

    report = {
        "directory": directory,
        "enabled": enabled,
        "dry_run": bool(dry_run),
        "effective_days": effective_days,
        "candidates": [],
        "deleted": [],
        "skipped_protected": [],
        "errors": [],
        "note": None,
    }

    _assert_safe_dir(directory)

    cutoff_day = (now - timedelta(days=effective_days)).strftime("%Y%m%d")
    protected = {d for d in protected_days if isinstance(d, str)}
    main_db = os.path.realpath(sd.main_db_path())

    candidates = []

    for day, path in list_day_files(directory):

        if day >= cutoff_day:
            continue

        real = os.path.realpath(path)

        # Belt and braces: must be directly inside the directory, must not be
        # the main database, must not have escaped through a link.
        if (os.path.dirname(real) != os.path.realpath(directory)
                or os.path.normcase(real) == os.path.normcase(main_db)
                or os.path.islink(path)):
            report["errors"].append(f"{day}: refused (path safety)")
            continue

        if day in protected:
            report["skipped_protected"].append(day)
            continue

        candidates.append((day, path))

    report["candidates"] = [d for d, _ in candidates]

    if dry_run:
        report["note"] = "DRY_RUN"
        return report

    if not enabled:
        report["note"] = "RETENTION_DISABLED"
        return report

    for day, path in candidates:

        try:
            os.remove(path)
        except OSError as exc:
            report["errors"].append(f"{day}: {type(exc).__name__}")
            continue

        report["deleted"].append(day)

        for suffix in ("-wal", "-shm"):

            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    return report
