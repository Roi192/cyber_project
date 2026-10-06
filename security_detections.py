# ==================================================
# PHASE 13B: GENERIC DETECTION STORAGE (main database)
# ==================================================
#
# A DETECTION is an engine/rule judgment. It is NOT an alert: nothing in this
# module creates, updates or reads alerts, incidents, alert_events or
# response commands, and nothing here ever will (promotion to an alert is a
# separate, explicit, later policy decision).
#
# Idempotency key: UNIQUE(sensor_id, source_event_id, rule_id). One source
# event can legitimately produce several detections (for example several
# rules matching one log line), so rule_id is the bounded discriminator.
# First write wins; a re-sent detection is a DUPLICATE, never an update.
#
# Portable SQL on purpose (ON CONFLICT DO NOTHING, ISO text timestamps): the
# same statements work on SQLite >= 3.24 and PostgreSQL.

import os
import re

import db_config
import endpoint_identity
import security_contract as sc

# SOC_DB_PATH (optional) - identical override to app.py / web_monitoring.py.
_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


def main_db_path():

    override = os.getenv("SOC_DB_PATH", "").strip()

    if override:
        return override if os.path.isabs(override) else os.path.join(_PROJECT_DIR, override)

    return os.path.join(_PROJECT_DIR, "cybersec.db")


def get_db_connection():

    return db_config.open_connection(main_db_path())


DETECTIONS_DDL = (
    """
    CREATE TABLE IF NOT EXISTS security_detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_type TEXT NOT NULL,
        source_engine TEXT NOT NULL,
        sensor_id TEXT NOT NULL REFERENCES security_sensors(sensor_id),
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
        rule_id TEXT NOT NULL,
        rule_name TEXT,
        rule_category TEXT,
        source_severity TEXT,
        source_action TEXT,
        independence_group TEXT NOT NULL,
        raw_ref TEXT,
        metadata_json TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (sensor_id, source_event_id, rule_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_secdet_observed ON security_detections(observed_at)",
    "CREATE INDEX IF NOT EXISTS idx_secdet_sensor ON security_detections(sensor_id, observed_at)",
    """
    CREATE INDEX IF NOT EXISTS idx_secdet_endpoint
    ON security_detections(endpoint_uid, observed_at)
    WHERE endpoint_uid IS NOT NULL
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_secdet_community
    ON security_detections(community_id)
    WHERE community_id IS NOT NULL
    """,
)

_INSERT_SQL = """
    INSERT INTO security_detections (
        source_type, source_engine, sensor_id, source_event_id,
        observed_at, ingested_at, endpoint_uid, endpoint_resolution,
        src_ip, src_port, dst_ip, dst_port, protocol, community_id,
        rule_id, rule_name, rule_category, source_severity, source_action,
        independence_group, raw_ref, metadata_json, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (sensor_id, source_event_id, rule_id) DO NOTHING
"""


def insert_detections(conn, records):

    # Inserts DETECTION records in ONE short write transaction. Returns a list
    # of "ACCEPTED" / "DUPLICATE" aligned with `records`. On any error the
    # whole transaction is rolled back (so a retry is safe and idempotent).
    statuses = []

    if not records:
        return statuses

    conn.execute("BEGIN IMMEDIATE")

    try:

        for r in records:

            if r.record_type != sc.RECORD_DETECTION:
                raise ValueError("insert_detections accepts DETECTION records only")

            cursor = conn.execute(_INSERT_SQL, (
                r.source_type, r.source_engine, r.sensor_id, r.source_event_id,
                r.observed_at, r.ingested_at, r.endpoint_uid, r.endpoint_resolution,
                r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.protocol, r.community_id,
                r.rule_id, r.rule_name, r.rule_category, r.source_severity, r.source_action,
                r.independence_group, r.raw_ref, r.metadata_json, r.ingested_at,
            ))

            statuses.append("ACCEPTED" if cursor.rowcount == 1 else "DUPLICATE")

        conn.commit()

    except BaseException:

        try:
            conn.rollback()
        except Exception:
            pass

        raise

    return statuses


# --------------------------------------------------
# BOUNDED QUERY HELPERS
# --------------------------------------------------

MAX_QUERY_LIMIT = 1000
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_SPAN_DAYS = 366


class QueryError(ValueError):
    pass


_DETECTION_COLUMNS = (
    "id, source_type, source_engine, sensor_id, source_event_id, "
    "observed_at, ingested_at, endpoint_uid, endpoint_resolution, "
    "src_ip, src_port, dst_ip, dst_port, protocol, community_id, "
    "rule_id, rule_name, rule_category, source_severity, source_action, "
    "independence_group, raw_ref, metadata_json, created_at"
)


def clamp_limit(limit):

    if limit is None:
        return DEFAULT_QUERY_LIMIT

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise QueryError("limit must be an integer")

    return max(1, min(limit, MAX_QUERY_LIMIT))


def parse_range(start, end, max_span_days):

    # Time bounds are REQUIRED on every query helper: no unbounded scans.
    s = sc.parse_utc(start) if isinstance(start, str) else None
    e = sc.parse_utc(end) if isinstance(end, str) else None

    if s is None or e is None:
        raise QueryError("start and end are required UTC timestamps")

    if e < s:
        raise QueryError("end must not precede start")

    if (e - s).total_seconds() > max_span_days * 86400:
        raise QueryError("time range too wide")

    return sc.format_utc(s), sc.format_utc(e)


ENGINE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}\Z")


def get_detection(detection_id, conn=None):

    # One detection by primary key (read-only). None for an invalid or unknown id.
    if isinstance(detection_id, bool) or not isinstance(detection_id, int) or not 0 < detection_id < 2 ** 53:
        return None

    own = conn is None

    if own:
        conn = get_db_connection()

    try:
        row = conn.execute(
            f"SELECT {_DETECTION_COLUMNS} FROM security_detections WHERE id = ?", (detection_id,)
        ).fetchone()

        return dict(row) if row else None
    finally:
        if own:
            conn.close()


def query_detections(start, end, endpoint_uid=None, sensor_id=None,
                     community_id=None, limit=None, conn=None, source_engine=None):

    start_s, end_s = parse_range(start, end, MAX_QUERY_SPAN_DAYS)
    limit = clamp_limit(limit)

    clauses = ["observed_at >= ?", "observed_at <= ?"]
    params = [start_s, end_s]

    if endpoint_uid is not None:

        uid = endpoint_identity.normalize_endpoint_uid(endpoint_uid)

        if uid is None:
            raise QueryError("invalid endpoint_uid")

        clauses.append("endpoint_uid = ?")
        params.append(uid)

    if sensor_id is not None:

        if not isinstance(sensor_id, str) or not sc.SENSOR_ID_RE.match(sensor_id):
            raise QueryError("invalid sensor_id")

        clauses.append("sensor_id = ?")
        params.append(sensor_id)

    if community_id is not None:

        if not isinstance(community_id, str) or not sc.COMMUNITY_ID_RE.match(community_id):
            raise QueryError("invalid community_id")

        clauses.append("community_id = ?")
        params.append(community_id)

    if source_engine is not None:

        if not isinstance(source_engine, str) or not ENGINE_NAME_RE.match(source_engine):
            raise QueryError("invalid source_engine")

        clauses.append("source_engine = ?")
        params.append(source_engine)

    sql = (
        f"SELECT {_DETECTION_COLUMNS} FROM security_detections "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY observed_at DESC, id DESC LIMIT ?"
    )
    params.append(limit)

    own = conn is None

    if own:
        conn = get_db_connection()

    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        if own:
            conn.close()
