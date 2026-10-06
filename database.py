"""SQLite access: schema, small query helpers and the retention policy."""
import os
import sqlite3
from datetime import datetime, timedelta

import config

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_uid TEXT NOT NULL UNIQUE,
    computer_name TEXT NOT NULL,
    username TEXT,
    last_seen TEXT NOT NULL
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
        conn.commit()
    finally:
        conn.close()


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


def upsert_endpoint(conn, endpoint_uid, computer_name, username):
    now = now_str()
    conn.execute(
        "INSERT INTO endpoints (endpoint_uid, computer_name, username, last_seen) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(endpoint_uid) DO UPDATE SET computer_name = excluded.computer_name, "
        "username = COALESCE(excluded.username, endpoints.username), last_seen = excluded.last_seen",
        (endpoint_uid, computer_name, username, now),
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


def dashboard_summary(conn):
    start_of_day = datetime.now().strftime("%Y-%m-%d") + " 00:00:00"
    row = conn.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM endpoints) AS computers, "
        "(SELECT COUNT(*) FROM web_visits WHERE visited_at >= ?) AS visits_today, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN') AS open_alerts, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN' AND severity = 'HIGH') AS open_high, "
        "(SELECT COUNT(*) FROM web_visits WHERE visited_at >= ? "
        " AND reputation_status IN ('MALICIOUS', 'SUSPICIOUS')) AS threats_today",
        (start_of_day, start_of_day),
    ).fetchone()
    if row["open_high"] > 0:
        status = "ALERT"
    elif row["open_alerts"] > 0:
        status = "WARNING"
    else:
        status = "OK"
    summary = dict(row)
    summary["security_status"] = status
    return summary


_VISIT_SELECT = (
    "SELECT v.id, v.visited_at, v.domain, v.sanitized_url, v.browser, v.reputation_status, "
    "e.computer_name, e.username FROM web_visits v JOIN endpoints e ON e.id = v.endpoint_id "
)


def recent_visits(conn, limit=50, status=None):
    sql = _VISIT_SELECT
    params = []
    if status:
        sql += "WHERE v.reputation_status = ? "
        params.append(status)
    sql += "ORDER BY v.visited_at DESC, v.id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def visits_after(conn, after_id, limit=50, status=None):
    """Visits with id > after_id, newest first - used by the dashboard polling."""
    sql = _VISIT_SELECT + "WHERE v.id > ? "
    params = [after_id]
    if status:
        sql += "AND v.reputation_status = ? "
        params.append(status)
    sql += "ORDER BY v.id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def list_alerts(conn, limit=100):
    return conn.execute(
        "SELECT a.*, e.computer_name, e.username FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id "
        "ORDER BY CASE a.status WHEN 'OPEN' THEN 0 ELSE 1 END, a.created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


def list_endpoints(conn):
    return conn.execute(
        "SELECT e.*, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.endpoint_id = e.id) AS visit_count, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.endpoint_id = e.id AND a.status = 'OPEN') AS open_alerts "
        "FROM endpoints e ORDER BY e.last_seen DESC"
    ).fetchall()
