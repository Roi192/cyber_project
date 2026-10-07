"""SQLite access: schema, small query helpers and the retention policy."""
import os
import sqlite3
from datetime import datetime, timedelta

import config

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# A computer is ONLINE while its last heartbeat/visit is at most this old.
# The extension sends a heartbeat every 60 s, so 180 s tolerates two missed beats
# (brief network drops, a busy browser) without flapping, and a closed browser
# shows OFFLINE after at most 3 minutes.
ONLINE_WINDOW_SECONDS = 180

SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_uid TEXT NOT NULL UNIQUE,
    computer_name TEXT NOT NULL,
    username TEXT,
    browser TEXT,
    last_seen TEXT NOT NULL,
    archived_at TEXT
);
CREATE TABLE IF NOT EXISTS web_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    domain TEXT NOT NULL,
    sanitized_url TEXT,
    browser TEXT,
    visited_at TEXT NOT NULL,
    reputation_status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visits_time ON web_visits(visited_at);
CREATE INDEX IF NOT EXISTS idx_visits_endpoint ON web_visits(endpoint_id, visited_at);
CREATE INDEX IF NOT EXISTS idx_visits_domain ON web_visits(domain);
CREATE TABLE IF NOT EXISTS domain_reputation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reputation_expires ON domain_reputation(expires_at);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    web_visit_id INTEGER REFERENCES web_visits(id),
    domain TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN'
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_endpoint_domain ON alerts(endpoint_id, domain, created_at);
"""


def now_str():
    return datetime.now().strftime(TIME_FORMAT)


def get_connection(path=None):
    path = path or config.DATABASE_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path=None):
    conn = get_connection(path)
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


def _migrate(conn):
    """Small, additive, idempotent migrations for databases created by older phases."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(endpoints)")}
    if "browser" not in columns:                       # added in Phase 3
        conn.execute("ALTER TABLE endpoints ADD COLUMN browser TEXT")
    if "archived_at" not in columns:                   # added in Phase 3.5
        conn.execute("ALTER TABLE endpoints ADD COLUMN archived_at TEXT")


def apply_retention(conn, days=None):
    """Delete web visits older than `days` (alerts keep their own row)."""
    days = config.RETENTION_DAYS if days is None else days
    if not days or days <= 0:
        return 0
    cutoff = (datetime.now() - timedelta(days=days)).strftime(TIME_FORMAT)
    conn.execute(
        "UPDATE alerts SET web_visit_id = NULL WHERE web_visit_id IN "
        "(SELECT id FROM web_visits WHERE visited_at < ?)",
        (cutoff,),
    )
    deleted = conn.execute("DELETE FROM web_visits WHERE visited_at < ?", (cutoff,)).rowcount
    conn.commit()
    return deleted


def upsert_endpoint(conn, endpoint_uid, computer_name, username, browser=None, username_provided=False):
    """Create or update the endpoint identified by endpoint_uid (never a second row).
    Registration, heartbeat and web events all go through here, so each of them
    refreshes last_seen. A changed computer_name just updates the existing row.
    username_provided=True makes `username` authoritative (it may clear the label);
    otherwise an absent username keeps the stored one.
    An archived computer that connects again is restored (archived_at cleared): a
    computer that is alive must never stay hidden from the owner."""
    now = now_str()
    username_sql = "excluded.username" if username_provided else "COALESCE(excluded.username, endpoints.username)"
    conn.execute(
        "INSERT INTO endpoints (endpoint_uid, computer_name, username, browser, last_seen) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(endpoint_uid) DO UPDATE SET computer_name = excluded.computer_name, "
        "username = " + username_sql + ", browser = COALESCE(excluded.browser, endpoints.browser), "
        "last_seen = excluded.last_seen, archived_at = NULL",
        (endpoint_uid, computer_name, username, browser, now),
    )
    conn.commit()
    return conn.execute("SELECT * FROM endpoints WHERE endpoint_uid = ?", (endpoint_uid,)).fetchone()


DEDUPE_WINDOW_SECONDS = 10


def find_recent_visit(conn, endpoint_id, domain, sanitized_url, visited_at, window_seconds=DEDUPE_WINDOW_SECONDS):
    """Server-side dedupe: id of an identical visit (same computer, same page)
    recorded within +/- window_seconds of visited_at, else None.
    Catches reload / redirect bursts the browser extension did not suppress."""
    try:
        ts = datetime.strptime(visited_at, TIME_FORMAT)
    except (TypeError, ValueError):
        return None
    lo = (ts - timedelta(seconds=window_seconds)).strftime(TIME_FORMAT)
    hi = (ts + timedelta(seconds=window_seconds)).strftime(TIME_FORMAT)
    row = conn.execute(
        "SELECT id FROM web_visits WHERE endpoint_id = ? AND domain = ? "
        "AND IFNULL(sanitized_url, '') = IFNULL(?, '') AND visited_at BETWEEN ? AND ? "
        "ORDER BY id DESC LIMIT 1",
        (endpoint_id, domain, sanitized_url, lo, hi),
    ).fetchone()
    return row["id"] if row else None


def insert_visit(conn, endpoint_id, domain, sanitized_url, browser, visited_at, status):
    cur = conn.execute(
        "INSERT INTO web_visits (endpoint_id, domain, sanitized_url, browser, visited_at, reputation_status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (endpoint_id, domain, sanitized_url, browser, visited_at, status),
    )
    conn.commit()
    return cur.lastrowid


def create_alert_if_new(conn, endpoint_id, web_visit_id, domain, severity, reason):
    """At most one OPEN alert per computer + domain per 24 hours."""
    since = (datetime.now() - timedelta(hours=24)).strftime(TIME_FORMAT)
    existing = conn.execute(
        "SELECT id FROM alerts WHERE endpoint_id = ? AND domain = ? AND status = 'OPEN' AND created_at >= ?",
        (endpoint_id, domain, since),
    ).fetchone()
    if existing:
        return existing["id"], False
    cur = conn.execute(
        "INSERT INTO alerts (endpoint_id, web_visit_id, domain, severity, reason, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (endpoint_id, web_visit_id, domain, severity, reason, now_str()),
    )
    conn.commit()
    return cur.lastrowid, True


def close_alert(conn, alert_id):
    changed = conn.execute(
        "UPDATE alerts SET status = 'CLOSED' WHERE id = ? AND status = 'OPEN'", (alert_id,)
    ).rowcount
    conn.commit()
    return changed == 1


def online_cutoff(now=None):
    return ((now or datetime.now()) - timedelta(seconds=ONLINE_WINDOW_SECONDS)).strftime(TIME_FORMAT)


def endpoint_status(last_seen, now=None):
    """ONLINE when last_seen is within ONLINE_WINDOW_SECONDS, otherwise OFFLINE."""
    try:
        seen = datetime.strptime(last_seen, TIME_FORMAT)
    except (TypeError, ValueError):
        return "OFFLINE"
    return "ONLINE" if ((now or datetime.now()) - seen).total_seconds() <= ONLINE_WINDOW_SECONDS else "OFFLINE"


def last_seen_label(last_seen, now=None):
    """'21:43' for today, '06 Oct 18:22' for earlier days."""
    try:
        seen = datetime.strptime(last_seen, TIME_FORMAT)
    except (TypeError, ValueError):
        return "-"
    now = now or datetime.now()
    return seen.strftime("%H:%M") if seen.date() == now.date() else seen.strftime("%d %b %H:%M")


def relative_time(timestamp, now=None):
    """Human-friendly age: Now, 1 min ago, 14 min ago, 2 h ago, 3 d ago."""
    try:
        seen = datetime.strptime(timestamp, TIME_FORMAT)
    except (TypeError, ValueError):
        return "-"
    seconds = max(0, int(((now or datetime.now()) - seen).total_seconds()))
    if seconds < 60:
        return "Now"
    if seconds < 3600:
        return "%d min ago" % (seconds // 60)
    if seconds < 86400:
        return "%d h ago" % (seconds // 3600)
    return "%d d ago" % (seconds // 86400)


def time_label(timestamp, now=None):
    """'22:07' for today, '06 Oct 22:07' for earlier days (same rule as last_seen_label)."""
    return last_seen_label(timestamp, now)


def start_of_today(now=None):
    return (now or datetime.now()).strftime("%Y-%m-%d") + " 00:00:00"


# Dashboard counts only look at ACTIVE computers (archived_at IS NULL):
#   monitored computers, online now, websites today, threats today, reputation
#   coverage and the recent-activity list. Open ALERTS are always counted, even
#   for an archived computer, so archiving can never hide an unresolved threat.
#   Historical visits and alerts of archived computers stay in the Browsing and
#   Alerts pages.
_EVALUATED = "('SAFE', 'SUSPICIOUS', 'MALICIOUS')"


def dashboard_summary(conn, now=None):
    now = now or datetime.now()
    start = start_of_today(now)
    row = conn.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM endpoints WHERE archived_at IS NULL) AS computers, "
        "(SELECT COUNT(*) FROM endpoints WHERE archived_at IS NULL AND last_seen >= ?) AS online_now, "
        "(SELECT COUNT(*) FROM web_visits v JOIN endpoints e ON e.id = v.endpoint_id "
        " WHERE e.archived_at IS NULL AND v.visited_at >= ?) AS visits_today, "
        "(SELECT COUNT(*) FROM web_visits v JOIN endpoints e ON e.id = v.endpoint_id "
        " WHERE e.archived_at IS NULL AND v.visited_at >= ? AND v.reputation_status IN " + _EVALUATED + ") AS evaluated_today, "
        "(SELECT COUNT(*) FROM web_visits v JOIN endpoints e ON e.id = v.endpoint_id "
        " WHERE e.archived_at IS NULL AND v.visited_at >= ? "
        " AND v.reputation_status IN ('MALICIOUS', 'SUSPICIOUS')) AS threats_today, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN') AS open_alerts, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN' AND severity = 'HIGH') AS open_high, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN' AND severity = 'MEDIUM') AS open_medium",
        (online_cutoff(now), start, start, start),
    ).fetchone()
    summary = dict(row)
    summary["unchecked_today"] = summary["visits_today"] - summary["evaluated_today"]
    # Alert-only level. app.py replaces this with the full, truthful verdict
    # (overview.py) that also considers reputation coverage and provider state.
    if summary["open_high"] > 0:
        summary["security_status"] = "ALERT"
    elif summary["open_alerts"] > 0:
        summary["security_status"] = "WARNING"
    else:
        summary["security_status"] = "OK"
    return summary


def open_alert_items(conn, limit=5):
    """Open alerts for the Needs-attention list: dangerous first, then newest."""
    return [dict(r) for r in conn.execute(
        "SELECT a.id, a.severity, a.domain, a.created_at, e.computer_name, e.username "
        "FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id WHERE a.status = 'OPEN' "
        "ORDER BY CASE a.severity WHEN 'HIGH' THEN 0 ELSE 1 END, a.created_at DESC, a.id DESC LIMIT ?",
        (limit,),
    )]


def long_offline_computers(conn, seconds, now=None):
    """Active computers silent for more than `seconds` (operational information only)."""
    cutoff = ((now or datetime.now()) - timedelta(seconds=seconds)).strftime(TIME_FORMAT)
    return [r["computer_name"] for r in conn.execute(
        "SELECT computer_name FROM endpoints WHERE archived_at IS NULL AND last_seen < ? "
        "ORDER BY last_seen DESC", (cutoff,))]


_VISIT_SELECT = (
    "SELECT v.id, v.visited_at, v.domain, v.sanitized_url, v.browser, v.reputation_status, "
    "e.computer_name, e.username FROM web_visits v JOIN endpoints e ON e.id = v.endpoint_id "
)


def _like(value):
    """LIKE pattern for a plain search term (wildcards typed by the user are literal)."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def _visit_filters(status, query, active_only):
    clauses, params = [], []
    if status:
        clauses.append("v.reputation_status = ?")
        params.append(status)
    if query:
        clauses.append("(v.domain LIKE ? ESCAPE '\\' OR e.computer_name LIKE ? ESCAPE '\\' "
                       "OR IFNULL(e.username, '') LIKE ? ESCAPE '\\')")
        params.extend([_like(query)] * 3)
    if active_only:
        clauses.append("e.archived_at IS NULL")
    return clauses, params


def recent_visits(conn, limit=50, status=None, query=None, active_only=False):
    clauses, params = _visit_filters(status, query, active_only)
    sql = _VISIT_SELECT + ("WHERE " + " AND ".join(clauses) + " " if clauses else "")
    sql += "ORDER BY v.visited_at DESC, v.id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def visits_after(conn, after_id, limit=50, status=None, query=None, active_only=False):
    """Visits with id > after_id, newest first - used by the page polling."""
    clauses, params = _visit_filters(status, query, active_only)
    clauses.insert(0, "v.id > ?")
    params.insert(0, after_id)
    sql = _VISIT_SELECT + "WHERE " + " AND ".join(clauses) + " ORDER BY v.id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def max_visit_id(conn):
    """Highest visit id: the polling cursor. It is NOT the id of the newest row by time -
    computers with skewed clocks insert rows whose time order differs from id order."""
    return conn.execute("SELECT IFNULL(MAX(id), 0) FROM web_visits").fetchone()[0]


def list_alerts(conn, limit=100):
    return conn.execute(
        "SELECT a.*, e.computer_name, e.username FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id "
        "ORDER BY CASE a.status WHEN 'OPEN' THEN 0 ELSE 1 END, a.created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


def list_endpoints(conn, now=None, archived=False):
    """One dict per computer (active ones by default, archived ones with archived=True),
    ONLINE first. No heartbeat history exists: status is derived from the single
    last_seen value."""
    now = now or datetime.now()
    start = start_of_today(now)
    rows = conn.execute(
        "SELECT e.id, e.endpoint_uid, e.computer_name, e.username, e.browser, e.last_seen, e.archived_at, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.endpoint_id = e.id AND v.visited_at >= ?) AS websites_today, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.endpoint_id = e.id AND v.visited_at >= ? "
        " AND v.reputation_status IN ('MALICIOUS', 'SUSPICIOUS')) AS threats_today, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.endpoint_id = e.id AND a.status = 'OPEN') AS open_alerts "
        "FROM endpoints e WHERE e.archived_at IS " + ("NOT NULL" if archived else "NULL"),
        (start, start),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["status"] = endpoint_status(item["last_seen"], now)
        item["last_seen_label"] = last_seen_label(item["last_seen"], now)
        item["last_seen_relative"] = relative_time(item["last_seen"], now)
        result.append(item)
    result.sort(key=lambda e: (e["status"] != "ONLINE", e["computer_name"].lower()))
    return result


def count_archived(conn):
    return conn.execute("SELECT COUNT(*) FROM endpoints WHERE archived_at IS NOT NULL").fetchone()[0]


def set_archived(conn, endpoint_id, archived):
    """Archive (hide from the Computers page and the dashboard counts) or restore a
    computer. Nothing is deleted: its visits and alerts stay. Returns False if the
    id does not exist."""
    stamp = now_str() if archived else None
    changed = conn.execute("UPDATE endpoints SET archived_at = ? WHERE id = ?", (stamp, endpoint_id)).rowcount
    conn.commit()
    return changed == 1
