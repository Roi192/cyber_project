"""SQLite access: schema, small query helpers and the retention policy."""
import os
import pathlib
import random
import sqlite3
import time
from datetime import datetime, timedelta

import config

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# A computer is ONLINE while its last heartbeat/visit is at most this old.
# The extension sends a heartbeat every 60 s, so 180 s tolerates two missed beats
# (brief network drops, a busy browser) without flapping, and a closed browser
# shows OFFLINE after at most 3 minutes.
ONLINE_WINDOW_SECONDS = 180

# Alert grouping window (see the Alerts section further down) and the text of the database's refusal of a duplicate open alert.
# They sit here because the schema migration builds a trigger from them.
ALERT_GROUP_WINDOW_HOURS = 24
ALERT_DUPLICATE_MESSAGE = "alert already open for this computer and domain"

# Where an observation came from. They are different kinds of fact and are never merged:
#   BROWSER  the browser extension saw a page load      -> "Visited website"
#   BROWSER_HISTORY  the agent saw a new local visit in the browser's history -> "Visited website (browser history)"
#   AGENT    the Windows network agent saw a DNS lookup -> "Contacted domain"
#            or a program's connection to a public IP   -> "Contacted IP address"
#            (dest_ip is set, process_name / process_kind / pid describe the program)
# (a program on that computer looked the name up or connected; it does NOT prove a person opened a website)
SOURCE_BROWSER = "BROWSER"
SOURCE_AGENT = "AGENT"
# the agent found a new LOCAL visit in Chrome's or Edge's own history (host only): a website visit with lower confidence than
# the extension, used when the extension is missing or silent
SOURCE_BROWSER_HISTORY = "BROWSER_HISTORY"
SOURCES = (SOURCE_BROWSER, SOURCE_BROWSER_HISTORY, SOURCE_AGENT)

# Duplicate policy (see find_recent_visit): browser = same computer + page within 10 s;
# agent = same computer + domain within 5 minutes (DNS caches re-add names constantly).
AGENT_DEDUPE_WINDOW_SECONDS = 300
# An agent observation is "covered" when the SAME computer also reported a browser visit to
# that domain within this many seconds: the visit already explains the lookup, so the agent
# row is not counted again in the dashboard numbers or the recent-activity list.
COVERED_WINDOW_SECONDS = 120

SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_uid TEXT NOT NULL UNIQUE,
    computer_name TEXT NOT NULL,
    username TEXT,
    browser TEXT,
    last_seen TEXT NOT NULL,
    archived_at TEXT,
    agent_version TEXT,
    history_browsers TEXT,
    agent_seen_at TEXT
);
CREATE TABLE IF NOT EXISTS web_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    domain TEXT NOT NULL,
    sanitized_url TEXT,
    browser TEXT,
    visited_at TEXT NOT NULL,
    reputation_status TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'BROWSER',
    dest_ip TEXT,
    process_name TEXT,
    process_kind TEXT,
    pid INTEGER
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
    expires_at TEXT NOT NULL,
    level TEXT,                              -- Phase F2: the evidence assessment (UNKNOWN/CLEAN/WEAK/CREDIBLE/CONFIRMED); NULL = decided by the legacy policy
    alert_severity TEXT                      -- Phase F2: HIGH / MEDIUM when the assessment calls for an alert; only read when level is not NULL
);
CREATE INDEX IF NOT EXISTS idx_reputation_expires ON domain_reputation(expires_at);
-- What each reputation provider found for a domain (Phase 5.4). One row per domain and provider, replaced on every new
-- check; evidence_json holds only the whitelisted integer counts (never a raw provider response). The OVERALL verdict stays
-- in domain_reputation, so evidence (what was found) and decision (what the system concluded) are separate.
CREATE TABLE IF NOT EXISTS reputation_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    provider TEXT NOT NULL,
    state TEXT NOT NULL,
    provider_verdict TEXT,
    reason TEXT,
    evidence_json TEXT,
    error TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    details_json TEXT,                       -- Phase F2: provider-neutral details (services/evidence.py): detections with engine names, classification, strength
    UNIQUE (domain, provider)
);
-- Phase F3.9: ADDRESS-level (URL-scoped) provider answers. Two tables, two jobs, neither ever holds an address, a path, a query or a credential:
--  * url_lookup_cache  the REUSABLE answer of a provider about one sanitized address, found by the SHA-256 of the exact expression set the provider is asked about
--    (url_key). It is shared by every computer and every visit, valid only until expires_at, and holds nothing about who looked.
--  * visit_url_evidence  what ONE visit's address check found (or why it was not checked): the visit-specific record the analysis page and the alert read. A cache hit is
--    copied here (reused = 1), so two computers visiting the same address each keep their own evidence. NOT_CHECKED rows (a sensitive path, the request budget, the host already
--    listed) carry no url_key and no detail about the path.
-- Domain-level tables above are never written with address-level results: a finding about one page is never a verdict about a whole host.
CREATE TABLE IF NOT EXISTS url_lookup_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'url' CHECK (scope = 'url'),
    state TEXT NOT NULL CHECK (state = 'CHECKED'),
    provider_verdict TEXT NOT NULL,
    level TEXT,
    alert_severity TEXT,
    reason TEXT,
    details_json TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE (url_key, provider)
);
CREATE INDEX IF NOT EXISTS idx_url_cache_expires ON url_lookup_cache(expires_at);
CREATE TABLE IF NOT EXISTS visit_url_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    web_visit_id INTEGER NOT NULL REFERENCES web_visits(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'url' CHECK (scope = 'url'),
    url_key TEXT,
    state TEXT NOT NULL CHECK (state IN ('CHECKED', 'UNAVAILABLE', 'ERROR', 'NOT_CHECKED')),
    provider_verdict TEXT,
    level TEXT,
    alert_severity TEXT,
    reason TEXT,
    skip_reason TEXT,
    details_json TEXT,
    error TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT,
    reused INTEGER NOT NULL DEFAULT 0,
    UNIQUE (web_visit_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_visit_url_evidence_key ON visit_url_evidence(url_key);
CREATE TABLE IF NOT EXISTS alert_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    web_visit_id INTEGER NOT NULL UNIQUE REFERENCES web_visits(id) ON DELETE CASCADE,
    alert_id INTEGER,                        -- informational link, no foreign key: this table never constrains alerts
    domain TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    legacy_policy TEXT NOT NULL,
    legacy_severity TEXT,
    shadow_severity TEXT,
    shadow_tier TEXT NOT NULL,
    agree INTEGER,                           -- NULL = insufficient evidence (never "clean")
    summary TEXT,
    groups_json TEXT,
    coverage_json TEXT,
    reasons_json TEXT,
    risk_score INTEGER,
    pending INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alert_decisions_agree ON alert_decisions(agree);
CREATE TABLE IF NOT EXISTS network_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL,          -- no foreign key on purpose: counters only, joined to endpoints when read
    day TEXT NOT NULL,
    process_name TEXT NOT NULL,
    process_kind TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    connections INTEGER NOT NULL DEFAULT 0,
    device_id INTEGER REFERENCES devices(id),   -- Phase D2.3: the device the sensor belonged to when the counter was counted
    attribution TEXT,
    UNIQUE (endpoint_id, device_id, day, process_name, process_kind)
);
CREATE INDEX IF NOT EXISTS idx_netactivity_day ON network_activity(day);
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
-- Phase A1. One row per exposure that an alert absorbed (or created / escalated it): the alert itself stays ONE row per computer +
-- domain + grouping window, while every distinct visit and its verdict stays on record here. The visit columns are a snapshot, so the
-- evidence survives the retention purge of web_visits (web_visit_id then becomes NULL).
CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                      -- CREATED | EXPOSURE | ESCALATED
    severity TEXT NOT NULL,                  -- the alert's severity after this event
    previous_severity TEXT,                  -- ESCALATED only
    verdict TEXT,                            -- the reputation verdict of this exposure (SUSPICIOUS / MALICIOUS)
    web_visit_id INTEGER REFERENCES web_visits(id) ON DELETE SET NULL,
    endpoint_id INTEGER,                     -- the sensor that reported it
    domain TEXT NOT NULL,
    browser TEXT,
    source TEXT,
    observed_at TEXT,
    recorded_at TEXT NOT NULL,
    detail TEXT,
    corroborates_event_id INTEGER            -- Phase F2: this record is the SAME real visit as that earlier event (reported by a second sensor); it is not counted again
);
CREATE INDEX IF NOT EXISTS idx_alert_events_alert ON alert_events(alert_id, id);
-- Phase B. Dashboard administrators and the record of sign-in attempts (the rate limit reads it). No default account exists: the first
-- administrator is created from a shell on the server with manage_admin.py.
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    password_changed_at TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip TEXT,
    attempted_at TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip, success, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username, success, attempted_at);
-- the same visit is never recorded twice for one alert
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_events_visit ON alert_events(alert_id, web_visit_id) WHERE web_visit_id IS NOT NULL;
-- Phase 5.5. A DEVICE is one physical computer; the rows of `endpoints` are its SENSORS (a Windows agent, a Chrome or an Edge
-- extension...). identity: VERIFIED = created by an authenticated Windows agent enrollment; PROVISIONAL = a browser-only install
-- that nobody has paired yet; LEGACY = an installation that existed before devices did (never merged, never assumed).
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_uid TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    identity TEXT NOT NULL DEFAULT 'PROVISIONAL',
    created_at TEXT NOT NULL,
    last_seen TEXT,
    archived_at TEXT
);
-- Phase D2.3. WHEN a sensor belonged to which device. Append-only: a row is only ever CLOSED (valid_to set, once); it is never edited or deleted while its sensor
-- exists, and two associations of one sensor never overlap (triggers in _migrate_attribution). Intervals are half-open [valid_from, valid_to): an event exactly on a
-- boundary belongs to the LATER association. basis: RECORDED = the change was seen by the server; MIGRATED_CURRENT = inferred when the table was introduced
-- (the sensor's device at that time, assumed for its whole earlier life - never presented as independently verified history).
CREATE TABLE IF NOT EXISTS sensor_device_associations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    basis TEXT NOT NULL CHECK (basis IN ('RECORDED', 'MIGRATED_CURRENT')),
    source TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_assoc_open ON sensor_device_associations(sensor_id) WHERE valid_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_assoc_lookup ON sensor_device_associations(sensor_id, valid_from);
CREATE INDEX IF NOT EXISTS idx_assoc_device ON sensor_device_associations(device_id);
-- Short-lived, single-use permission for ONE named sensor to join ONE device. Only the SHA-256 of the token is kept.
CREATE TABLE IF NOT EXISTS pairing_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_hash TEXT NOT NULL UNIQUE,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    sensor_uid TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
-- Who enrolled, paired, was refused or revoked. Never contains a secret, a grant or a pairing code.
CREATE TABLE IF NOT EXISTS device_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    event TEXT NOT NULL,
    device_id INTEGER,
    sensor_id INTEGER,
    detail TEXT
);
"""

SENSOR_TYPES = ("WINDOWS_AGENT", "CHROME_EXTENSION", "EDGE_EXTENSION", "BROWSER_EXTENSION", "LEGACY_COMBINED", "UNKNOWN")
IDENTITY_VERIFIED, IDENTITY_PROVISIONAL, IDENTITY_LEGACY = "VERIFIED", "PROVISIONAL", "LEGACY"


def now_str():
    return datetime.now().strftime(TIME_FORMAT)


def get_connection(path=None):
    path = path or config.DATABASE_PATH
    config.assert_database_allowed(path)           # production: nothing; test mode: only a temporary database (see config.py)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# Every table this version needs. Used by is_initialized(); keep it in step with SCHEMA.
REQUIRED_TABLES = ("endpoints", "web_visits", "domain_reputation", "reputation_evidence", "network_activity", "alerts", "alert_events", "admins", "login_attempts",
                   "devices", "sensor_device_associations", "pairing_grants", "device_audit", "url_lookup_cache", "visit_url_evidence")


def is_initialized(path=None):
    """True when the database file exists and has every table this version needs. Phase F3.11: it opens the file READ-ONLY and never creates a file, a folder or a table, so a
    server (or a script) can ask 'is it ready?' without any risk to the data."""
    path = path or config.DATABASE_PATH
    config.assert_database_allowed(path)
    if not os.path.isfile(path):
        return False
    try:
        conn = sqlite3.connect(pathlib.Path(os.path.abspath(path)).as_uri() + "?mode=ro", uri=True, timeout=10)
        try:
            names = set(row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'"))
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return all(table in names for table in REQUIRED_TABLES)


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
    if "agent_version" not in columns:                 # added in Phase 5.1 (Windows network agent)
        conn.execute("ALTER TABLE endpoints ADD COLUMN agent_version TEXT")
    # Phase 5.3: what the agent's browser-history watcher can read right now ("Chrome,Edge", "" = nothing, NULL = never said)
    # and when the agent last reported; both NULL for every older row
    for column in ("history_browsers", "agent_seen_at"):
        if column not in columns:
            conn.execute("ALTER TABLE endpoints ADD COLUMN %s TEXT" % column)
    visit_columns = {row["name"] for row in conn.execute("PRAGMA table_info(web_visits)")}
    if "source" not in visit_columns:                  # added in Phase 5.1: every old row is, truthfully, a browser visit
        conn.execute("ALTER TABLE web_visits ADD COLUMN source TEXT NOT NULL DEFAULT 'BROWSER'")
    # Phase 5.2 (native collector): all four are NULL for every older row. dest_ip is set only when the
    # agent saw a connection to an IP address and no domain is known (then `domain` holds the same
    # address, so listing and dedupe keep working). pid is transient diagnostic information.
    # Phase F2.1: the assessment level the verdict had WHEN THE VISIT HAPPENED (WEAK / CREDIBLE / CONFIRMED / ...), NULL for every older visit and while the legacy
    # policy decides. A WEAK finding stays visible but is not a threat: no alert, no risk points, no "compromised" count.
    for column, ddl in (("dest_ip", "TEXT"), ("process_name", "TEXT"), ("process_kind", "TEXT"), ("pid", "INTEGER"), ("level", "TEXT")):
        if column not in visit_columns:
            conn.execute("ALTER TABLE web_visits ADD COLUMN %s %s" % (column, ddl))
    _migrate_devices(conn, columns)
    # Phase 5.7: when a browser EXTENSION last reported (heartbeat or visit). last_seen is shared by every sensor that reports
    # through one row, so it cannot say whether the extension is alive. NULL for every older row = unknown = not verified.
    if "extension_seen_at" not in {row["name"] for row in conn.execute("PRAGMA table_info(endpoints)")}:
        conn.execute("ALTER TABLE endpoints ADD COLUMN extension_seen_at TEXT")
    # Phase F2: additive columns only (every one nullable, so code from before this phase still reads and writes these tables).
    for table, column, ddl in (("domain_reputation", "level", "TEXT"), ("domain_reputation", "alert_severity", "TEXT"),
                               ("reputation_evidence", "details_json", "TEXT"), ("alert_events", "corroborates_event_id", "INTEGER")):
        if column not in {row["name"] for row in conn.execute("PRAGMA table_info(%s)" % table)}:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, ddl))
    # Phase A1: an alert belongs to a COMPUTER (device), not to one of its sensors. All columns are nullable or defaulted, so code from
    # before this phase can still read and write the table (rollback safety); such rows have device_id NULL and are matched through
    # their endpoint's device (see _open_alert_for).
    alert_columns = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
    for column, ddl in (("device_id", "INTEGER REFERENCES devices(id)"), ("previous_severity", "TEXT"), ("escalated_at", "TEXT"),
                        ("last_exposure_at", "TEXT"), ("exposure_count", "INTEGER NOT NULL DEFAULT 1")):
        if column not in alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN %s %s" % (column, ddl))
    conn.execute("UPDATE alerts SET device_id = (SELECT device_id FROM endpoints WHERE endpoints.id = alerts.endpoint_id) "
                 "WHERE device_id IS NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_device_domain ON alerts(device_id, domain, status, created_at)")
    # Phase A1.1: the invariant "one OPEN alert per computer + domain within the grouping window" enforced by the database itself. It is
    # a trigger and not a unique index on purpose: a unique index cannot express a time window and would also forbid the legitimate new
    # alert after the window or after an alert was handled. A handled (non-OPEN) alert, another domain, another computer or an older
    # alert never matches. The window text comes from ALERT_GROUP_WINDOW_HOURS, so the trigger and the code cannot drift apart.
    # A row inserted by older code has device_id NULL: it is then checked by sensor only, exactly as that code groups.
    conn.execute("DROP TRIGGER IF EXISTS trg_alert_one_open_per_group")
    conn.execute(
        "CREATE TRIGGER trg_alert_one_open_per_group BEFORE INSERT ON alerts WHEN NEW.status = 'OPEN' BEGIN "
        "SELECT RAISE(ABORT, '" + ALERT_DUPLICATE_MESSAGE + "') WHERE EXISTS ("
        "SELECT 1 FROM alerts a WHERE a.status = 'OPEN' AND a.domain = NEW.domain "
        "AND a.created_at >= strftime('%Y-%m-%d %H:%M:%S', NEW.created_at, '-" + str(int(ALERT_GROUP_WINDOW_HOURS)) + " hours') "
        "AND ((NEW.device_id IS NOT NULL AND (a.device_id = NEW.device_id OR "
        "(a.device_id IS NULL AND a.endpoint_id IN (SELECT id FROM endpoints WHERE device_id = NEW.device_id)))) "
        "OR (NEW.device_id IS NULL AND a.endpoint_id = NEW.endpoint_id))); END")
    conn.commit()
    _migrate_attribution(conn)                  # Phase D2.3 (needs everything above); one transaction of its own


# ---- Phase D2.3: historical attribution ------------------------------------------------------------------------------------------------------
# Before this phase a visit or a network counter had no device of its own: its device was read through endpoints.device_id AT READ TIME, so pairing a sensor to
# another device silently moved the sensor's whole past. Now every event stores the device its sensor belonged to WHEN THE EVENT HAPPENED, found in
# sensor_device_associations, and says how sure that is (attribution). endpoints.device_id stays as the sensor's CURRENT device (live status, pairing); history
# never reads it.
#   RECORDED                              the event time fell inside an association the server recorded
#   MIGRATED_CURRENT                      inferred when this table was introduced (or for an event inside such an inferred association): the device the sensor was
#                                         on at that time, assumed for its whole earlier life. NOT independently verified history.
#   UNCERTAIN_NEAR_BOUNDARY               within ATTRIBUTION_SKEW_SECONDS of a change between two different devices (clock skew can put the event on either side);
#                                         it is attributed by the fixed rule below and flagged (events stored just BEFORE a change are flagged by the change itself,
#                                         which only ever edits this label, never the device)
#   UNCERTAIN_LATE_ACROSS_CHANGE          the event claims a time before a later change of device but reached the server after more than ATTRIBUTION_SKEW_SECONDS: a late
#                                         delivery, or a sensor clock that is behind. It is attributed to the device of the CLAIMED time and says it relies on that clock
#   UNCERTAIN_CLOCK_AHEAD                 the sensor's clock claims a time in the future; the event is attributed to the association current NOW
#   UNCERTAIN_BEFORE_FIRST_ASSOCIATION    older than the sensor's first association by more than the skew; attributed to that first device
#   UNKNOWN                               no association exists (cannot happen after the migration; kept for honesty)
# Boundary rule (deterministic): intervals are half-open [valid_from, valid_to); an event exactly on a boundary belongs to the LATER association.
ATTRIBUTION_SKEW_SECONDS = 60                    # same tolerance as the sensor freshness checks (SENSOR_CLOCK_SKEW_SECONDS, defined further down)
ATTRIBUTION_START_OF_TIME = "1970-01-01 00:00:00"
ATTRIBUTION_END_OF_TIME = "9999-12-31 23:59:59"
ATTR_RECORDED, ATTR_MIGRATED = "RECORDED", "MIGRATED_CURRENT"
ATTR_BOUNDARY, ATTR_CLOCK_AHEAD = "UNCERTAIN_NEAR_BOUNDARY", "UNCERTAIN_CLOCK_AHEAD"
ATTR_BEFORE_FIRST, ATTR_UNKNOWN = "UNCERTAIN_BEFORE_FIRST_ASSOCIATION", "UNKNOWN"
ATTR_LATE = "UNCERTAIN_LATE_ACROSS_CHANGE"
ATTRIBUTION_UNCERTAIN = (ATTR_BOUNDARY, ATTR_CLOCK_AHEAD, ATTR_LATE, ATTR_BEFORE_FIRST, ATTR_UNKNOWN)
_NOW_SQL = "strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')"
# A change of device takes effect from the NEXT WHOLE SECOND. Events carry whole-second times, so every event the server has already stored (its time is at most this
# second) is on the old side of the boundary, and one that arrives later with the same second is attributed to the old device and flagged as near the boundary.
_NEXT_SECOND_SQL = "strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime', '+1 second')"


def _parse_time(text):
    try:
        return datetime.strptime(text, TIME_FORMAT)
    except (TypeError, ValueError):
        return None


def attribute_event(conn, endpoint_id, event_time, now=None):
    """The device the sensor belonged to WHEN THE EVENT HAPPENED (not when it arrived), and how sure that is: (device_id, attribution). Read-only."""
    now = now or datetime.now()
    skew = timedelta(seconds=ATTRIBUTION_SKEW_SECONDS)
    event = _parse_time(event_time) or now
    label = None
    if event > now + skew:
        event, label = now, ATTR_CLOCK_AHEAD                  # a clock ahead of the server cannot reach into an association that has not started
    elif event > now:
        event = now
    rows = conn.execute("SELECT device_id, valid_from, valid_to, basis, recorded_at FROM sensor_device_associations WHERE sensor_id = ? ORDER BY valid_from, id",
                        (endpoint_id,)).fetchall()
    if not rows:
        current = conn.execute("SELECT device_id FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
        return (current["device_id"] if current else None), ATTR_UNKNOWN
    stamp = event.strftime(TIME_FORMAT)
    cover = None
    for index, row in enumerate(rows):
        if row["valid_from"] <= stamp and (row["valid_to"] is None or stamp < row["valid_to"]):
            cover = index                                    # half-open: a stamp equal to valid_to falls into the NEXT row
    if cover is None:
        if stamp < rows[0]["valid_from"]:
            first = _parse_time(rows[0]["valid_from"])
            gap = (first - event).total_seconds() if first else 0
            return rows[0]["device_id"], (label or (ATTR_RECORDED if gap <= ATTRIBUTION_SKEW_SECONDS else ATTR_BEFORE_FIRST))
        return rows[-1]["device_id"], (label or ATTR_UNKNOWN)
    row = rows[cover]
    if label is None:
        # ambiguous only where two DIFFERENT devices meet: a change of association within the skew window on either side of the event
        if cover > 0 and rows[cover - 1]["device_id"] != row["device_id"]:
            start = _parse_time(row["valid_from"])
            if start and (event - start).total_seconds() < ATTRIBUTION_SKEW_SECONDS:
                label = ATTR_BOUNDARY
        if label is None and cover + 1 < len(rows) and rows[cover + 1]["device_id"] != row["device_id"] and row["valid_to"]:
            end = _parse_time(row["valid_to"])
            if end and (end - event).total_seconds() <= ATTRIBUTION_SKEW_SECONDS:
                label = ATTR_BOUNDARY
    if label is None and (now - event).total_seconds() > ATTRIBUTION_SKEW_SECONDS and any(later["device_id"] != row["device_id"] for later in rows[cover + 1:]):
        label = ATTR_LATE                  # the sensor changed device AFTER the claimed time and the event only arrived now: its clock (or its delivery) decides the device
    if label is None:
        label = ATTR_RECORDED if (row["basis"] == "RECORDED" or stamp >= row["recorded_at"]) else ATTR_MIGRATED
    return row["device_id"], label


def _rebuild_network_activity(conn):
    """One counter row per sensor + DEVICE + day + program: a sensor that moves in the middle of a day gets a second row, so one counter never mixes two devices.
    SQLite cannot change a UNIQUE constraint in place, so the (small, counters-only) table is rebuilt; ids and every value are kept."""
    sequence = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'network_activity'").fetchone()
    old_sequence = sequence[0] if sequence else None                 # the next id must still be above every id that was EVER handed out, not only above the live rows
    conn.execute("CREATE TABLE network_activity_rebuilt (id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id INTEGER NOT NULL, day TEXT NOT NULL, process_name TEXT NOT NULL, "
                 "process_kind TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, connections INTEGER NOT NULL DEFAULT 0, "
                 "device_id INTEGER REFERENCES devices(id), attribution TEXT, UNIQUE (endpoint_id, device_id, day, process_name, process_kind))")
    conn.execute("INSERT INTO network_activity_rebuilt (id, endpoint_id, day, process_name, process_kind, first_seen, last_seen, connections, device_id, attribution) "
                 "SELECT n.id, n.endpoint_id, n.day, n.process_name, n.process_kind, n.first_seen, n.last_seen, n.connections, "
                 "(SELECT e.device_id FROM endpoints e WHERE e.id = n.endpoint_id), '" + ATTR_MIGRATED + "' FROM network_activity n ORDER BY n.id")
    conn.execute("DROP TABLE network_activity")
    conn.execute("ALTER TABLE network_activity_rebuilt RENAME TO network_activity")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_netactivity_day ON network_activity(day)")
    if old_sequence is not None:
        if conn.execute("UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = 'network_activity'", (old_sequence,)).rowcount == 0:
            conn.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('network_activity', ?)", (old_sequence,))


def _migrate_attribution(conn):
    """Phase D2.3, additive and idempotent, one transaction (all or nothing). Every existing row keeps its id and content; it only gains an event-time device and an
    honest label (MIGRATED_CURRENT: inferred from the sensor's device at migration time, which is exactly what every number showed before)."""
    _begin_write(conn)
    try:
        if "archived_at" not in {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}:
            conn.execute("ALTER TABLE devices ADD COLUMN archived_at TEXT")                # a former device is archived on its own (it has no sensor to archive)
        visit_cols = {r["name"] for r in conn.execute("PRAGMA table_info(web_visits)")}
        for column, ddl in (("device_id", "INTEGER REFERENCES devices(id)"), ("attribution", "TEXT")):
            if column not in visit_cols:
                conn.execute("ALTER TABLE web_visits ADD COLUMN %s %s" % (column, ddl))
        if "attribution" not in {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}:
            conn.execute("ALTER TABLE alerts ADD COLUMN attribution TEXT")
        if "device_id" not in {r["name"] for r in conn.execute("PRAGMA table_info(network_activity)")}:
            _rebuild_network_activity(conn)
        # the first association of every sensor that has none: its current device, from the start of time (the real start is unknown)
        conn.execute("INSERT INTO sensor_device_associations (sensor_id, device_id, valid_from, valid_to, basis, source, recorded_at) "
                     "SELECT e.id, e.device_id, '" + ATTRIBUTION_START_OF_TIME + "', NULL, 'MIGRATED_CURRENT', 'MIGRATION', " + _NOW_SQL + " FROM endpoints e "
                     "WHERE e.device_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sensor_device_associations a WHERE a.sensor_id = e.id)")
        # the backfill: the device the join gave until now, so no number changes - labelled as inferred, never as recorded
        conn.execute("UPDATE web_visits SET device_id = (SELECT device_id FROM endpoints WHERE endpoints.id = web_visits.endpoint_id), attribution = '" + ATTR_MIGRATED + "' "
                     "WHERE device_id IS NULL")
        conn.execute("UPDATE network_activity SET device_id = (SELECT device_id FROM endpoints WHERE endpoints.id = network_activity.endpoint_id), "
                     "attribution = '" + ATTR_MIGRATED + "' WHERE device_id IS NULL")
        conn.execute("UPDATE alerts SET attribution = '" + ATTR_MIGRATED + "' WHERE attribution IS NULL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_visits_device ON web_visits(device_id, visited_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_netactivity_device ON network_activity(device_id, day)")
        _create_attribution_guards(conn)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def _create_attribution_guards(conn):
    """Triggers and the view of this phase. They are DROPped and created again each time, so a changed definition always takes effect."""
    end = "'" + ATTRIBUTION_END_OF_TIME + "'"
    for name in ("trg_assoc_overlap", "trg_assoc_append_only", "trg_assoc_no_delete", "trg_assoc_new_sensor", "trg_assoc_device_changed",
                 "trg_visit_attribution", "trg_network_attribution"):
        conn.execute("DROP TRIGGER IF EXISTS " + name)
    conn.execute("DROP VIEW IF EXISTS active_devices")
    # two associations of one sensor never overlap (the unique index on open rows already allows one open row at most)
    conn.execute("CREATE TRIGGER trg_assoc_overlap BEFORE INSERT ON sensor_device_associations BEGIN "
                 "SELECT RAISE(ABORT, 'a sensor cannot belong to two devices at the same time') WHERE EXISTS (SELECT 1 FROM sensor_device_associations a "
                 "WHERE a.sensor_id = NEW.sensor_id AND a.valid_from < COALESCE(NEW.valid_to, " + end + ") AND NEW.valid_from < COALESCE(a.valid_to, " + end + ")); END")
    # append-only: the only change a row ever gets is being closed, once, at or after its start
    conn.execute("CREATE TRIGGER trg_assoc_append_only BEFORE UPDATE ON sensor_device_associations "
                 "WHEN NEW.sensor_id != OLD.sensor_id OR NEW.device_id != OLD.device_id OR NEW.valid_from != OLD.valid_from OR NEW.basis != OLD.basis "
                 "OR NEW.source != OLD.source OR NEW.recorded_at != OLD.recorded_at OR OLD.valid_to IS NOT NULL OR NEW.valid_to IS NULL OR NEW.valid_to < OLD.valid_from "
                 "BEGIN SELECT RAISE(ABORT, 'an association is append-only: it can only be closed once'); END")
    # never deleted while its sensor exists (deleting the sensor row itself removes them with it)
    conn.execute("CREATE TRIGGER trg_assoc_no_delete BEFORE DELETE ON sensor_device_associations "
                 "WHEN EXISTS (SELECT 1 FROM endpoints WHERE id = OLD.sensor_id) BEGIN SELECT RAISE(ABORT, 'associations are never deleted'); END")
    # a sensor is created WITH a device (an agent enrollment, a pairing): its first association starts now
    conn.execute("CREATE TRIGGER trg_assoc_new_sensor AFTER INSERT ON endpoints WHEN NEW.device_id IS NOT NULL BEGIN "
                 "INSERT INTO sensor_device_associations (sensor_id, device_id, valid_from, basis, source, recorded_at) "
                 "VALUES (NEW.id, NEW.device_id, " + _NOW_SQL + ", 'RECORDED', 'FIRST_SEEN', " + _NOW_SQL + "); END")
    # THE ONE PLACE a sensor changes device: the same statement that updates the current-device cache closes the open association and opens the next one at the
    # same instant (atomic: they succeed or fail together). A sensor whose device is set for the first time (the new-sensor trigger of Phase 5.5) gets its first one.
    boundary = "MAX(" + _NEXT_SECOND_SQL + ", COALESCE((SELECT MAX(valid_to) FROM sensor_device_associations WHERE sensor_id = NEW.id), " + _NEXT_SECOND_SQL + "))"
    window = "datetime(" + boundary + ", '-%d seconds')" % ATTRIBUTION_SKEW_SECONDS
    conn.execute("CREATE TRIGGER trg_assoc_device_changed AFTER UPDATE OF device_id ON endpoints "
                 "WHEN NEW.device_id IS NOT NULL AND NEW.device_id IS NOT OLD.device_id BEGIN "
                 "UPDATE sensor_device_associations SET valid_to = MAX(valid_from, " + _NEXT_SECOND_SQL + ") WHERE sensor_id = NEW.id AND valid_to IS NULL; "
                 "INSERT INTO sensor_device_associations (sensor_id, device_id, valid_from, basis, source, recorded_at) "
                 "VALUES (NEW.id, NEW.device_id, " + boundary + ", "
                 "'RECORDED', CASE WHEN OLD.device_id IS NULL THEN 'FIRST_SEEN' ELSE 'DEVICE_CHANGED' END, " + _NOW_SQL + "); "
                 # what was stored just before the change may belong to either side if the sensor's clock is off: say so. ONLY the label changes, never the device.
                 "UPDATE web_visits SET attribution = '" + ATTR_BOUNDARY + "' WHERE OLD.device_id IS NOT NULL AND endpoint_id = NEW.id AND device_id = OLD.device_id "
                 "AND attribution = '" + ATTR_RECORDED + "' AND visited_at >= " + window + "; "
                 "UPDATE network_activity SET attribution = '" + ATTR_BOUNDARY + "' WHERE OLD.device_id IS NOT NULL AND endpoint_id = NEW.id AND device_id = OLD.device_id "
                 "AND attribution = '" + ATTR_RECORDED + "' AND last_seen >= " + window + "; "
                 "UPDATE alerts SET attribution = '" + ATTR_BOUNDARY + "' WHERE OLD.device_id IS NOT NULL AND endpoint_id = NEW.id AND device_id = OLD.device_id "
                 "AND attribution = '" + ATTR_RECORDED + "' AND created_at >= " + window + "; END")
    # any writer that does not know about attribution (older code, a hand-written INSERT) still gets an event-time device, from the same table
    for table, name, event_time in (("web_visits", "trg_visit_attribution", "NEW.visited_at"), ("network_activity", "trg_network_attribution", "NEW.first_seen")):
        stamp = "MIN(" + event_time + ", " + _NOW_SQL + ")"
        cover = ("a.sensor_id = NEW.endpoint_id AND a.valid_from <= " + stamp + " AND (a.valid_to IS NULL OR " + stamp + " < a.valid_to)")
        conn.execute(
            "CREATE TRIGGER " + name + " AFTER INSERT ON " + table + " WHEN NEW.device_id IS NULL BEGIN "
            "UPDATE " + table + " SET device_id = COALESCE((SELECT a.device_id FROM sensor_device_associations a WHERE a.sensor_id = NEW.endpoint_id "
            "ORDER BY CASE WHEN " + cover + " THEN 0 ELSE 1 END, a.valid_from LIMIT 1), (SELECT device_id FROM endpoints WHERE id = NEW.endpoint_id)), "
            "attribution = CASE WHEN EXISTS (SELECT 1 FROM sensor_device_associations a WHERE " + cover + ") THEN '" + ATTR_RECORDED + "' ELSE '" + ATTR_BEFORE_FIRST + "' END "
            "WHERE id = NEW.id; END")
    # a computer is "active" until an administrator archives it: it has an unarchived sensor, or it lost its last sensor (a FORMER device, kept with its evidence:
    # it has association history but no sensor now). A device row that never had a sensor is not a computer.
    conn.execute("CREATE VIEW active_devices AS SELECT d.id AS device_id FROM devices d WHERE d.archived_at IS NULL AND ("
                 "EXISTS (SELECT 1 FROM endpoints s WHERE s.device_id = d.id AND s.archived_at IS NULL) "
                 "OR (NOT EXISTS (SELECT 1 FROM endpoints s WHERE s.device_id = d.id) "
                 "AND EXISTS (SELECT 1 FROM sensor_device_associations a WHERE a.device_id = d.id)))")


def sensor_type_for(browser, agent_version):
    """The kind of sensor an installation is, from what it has reported."""
    if browser and agent_version:
        return "LEGACY_COMBINED"          # one row that both an extension and an agent report through (linked by hand)
    if agent_version:
        return "WINDOWS_AGENT"
    if browser == "Chrome":
        return "CHROME_EXTENSION"
    if browser == "Edge":
        return "EDGE_EXTENSION"
    return "BROWSER_EXTENSION" if browser else "UNKNOWN"


def _migrate_devices(conn, endpoint_columns):
    """Phase 5.5, additive and idempotent: every existing installation keeps its row, its id and all its visits; it only gains a
    device. Each old installation becomes its OWN device (identity LEGACY): nothing is merged, by name or by anything else."""
    for column, ddl in (("device_id", "INTEGER REFERENCES devices(id)"), ("sensor_type", "TEXT"), ("sensor_label", "TEXT"),
                        ("sensor_version", "TEXT"), ("first_seen", "TEXT"), ("secret_hash", "TEXT"), ("paired_at", "TEXT"),
                        ("revoked_at", "TEXT")):
        if column not in endpoint_columns:
            conn.execute("ALTER TABLE endpoints ADD COLUMN %s %s" % (column, ddl))
    for row in conn.execute("SELECT id, computer_name, browser, agent_version, last_seen, sensor_type FROM endpoints "
                            "WHERE device_id IS NULL").fetchall():
        cur = conn.execute("INSERT INTO devices (device_uid, display_name, identity, created_at, last_seen) "
                           "VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?)",
                           (row["computer_name"], IDENTITY_LEGACY, now_str(), row["last_seen"]))
        conn.execute("UPDATE endpoints SET device_id = ?, sensor_type = COALESCE(sensor_type, ?), "
                     "first_seen = COALESCE(first_seen, (SELECT MIN(visited_at) FROM web_visits WHERE endpoint_id = endpoints.id), last_seen) "
                     "WHERE id = ?", (cur.lastrowid, sensor_type_for(row["browser"], row["agent_version"]), row["id"]))
    conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_device ON endpoints(device_id)")
    # From now on a new installation gets its own PROVISIONAL device, whatever code (or hand-written SQL) inserted it.
    # Since Phase D2.3 a visit stores the device its sensor belonged to WHEN IT HAPPENED (web_visits.device_id, found in sensor_device_associations), so pairing
    # a sensor to another device never moves its past: only events from then on belong to the new device (devices.py).
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS trg_endpoint_device AFTER INSERT ON endpoints WHEN NEW.device_id IS NULL BEGIN "
        "INSERT INTO devices (device_uid, display_name, identity, created_at, last_seen) "
        "VALUES (lower(hex(randomblob(16))), NEW.computer_name, 'PROVISIONAL', strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime'), NEW.last_seen); "
        "UPDATE endpoints SET device_id = last_insert_rowid(), first_seen = COALESCE(first_seen, NEW.last_seen), "
        "sensor_type = COALESCE(sensor_type, 'UNKNOWN') WHERE id = NEW.id; END")



def apply_retention(conn, days=None):
    """Delete web visits older than `days` (alerts keep their own row). Raw network activity (a per-program daily
    count) is pruned separately and always: it is kept a fixed 30 days, whatever the history setting."""
    conn.execute("DELETE FROM network_activity WHERE day < ?",
                 ((datetime.now() - timedelta(days=NETWORK_ACTIVITY_KEEP_DAYS)).strftime("%Y-%m-%d"),))
    conn.execute("DELETE FROM url_lookup_cache WHERE expires_at < ?", (now_str(),))          # Phase F3.9: an expired address answer is never reused, so it is not kept
    conn.commit()
    days = config.RETENTION_DAYS if days is None else days
    if not days or days <= 0:
        return 0
    cutoff = (datetime.now() - timedelta(days=days)).strftime(TIME_FORMAT)
    conn.execute(
        "UPDATE alerts SET web_visit_id = NULL WHERE web_visit_id IN "
        "(SELECT id FROM web_visits WHERE visited_at < ?)",
        (cutoff,),
    )
    conn.execute("UPDATE alert_events SET web_visit_id = NULL WHERE web_visit_id IN (SELECT id FROM web_visits WHERE visited_at < ?)",
                 (cutoff,))
    deleted = conn.execute("DELETE FROM web_visits WHERE visited_at < ?", (cutoff,)).rowcount
    conn.commit()
    return deleted


NETWORK_ACTIVITY_KEEP_DAYS = 30
UNKNOWN_PROGRAM = "(unidentified program)"


def record_network_activity(conn, endpoint_id, process_name, process_kind, observed_at):
    """Level 1, raw network telemetry: count that this program made a connection today. One row per computer,
    program and day - the connection's address, port and process id are deliberately NOT stored, so the table
    can never grow with traffic noise and is never mistaken for website history."""
    day = (observed_at or now_str())[:10]
    # the counter belongs to the device the sensor had when the connection was made; the key contains the device, so a sensor that moves in the middle of a day
    # gets a second row for the same day instead of one row that mixes two devices. A row that is uncertain stays uncertain when more events join it.
    device_id, attribution = attribute_event(conn, endpoint_id, observed_at or now_str())
    conn.execute(
        "INSERT INTO network_activity (endpoint_id, device_id, day, process_name, process_kind, first_seen, last_seen, connections, attribution) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?) "
        "ON CONFLICT(endpoint_id, device_id, day, process_name, process_kind) DO UPDATE SET connections = connections + 1, "
        "first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen), "
        "attribution = CASE WHEN attribution = '" + ATTR_RECORDED + "' THEN excluded.attribution ELSE attribution END",
        (endpoint_id, device_id, day, process_name or UNKNOWN_PROGRAM, process_kind or "UNKNOWN", observed_at, observed_at, attribution),
    )
    conn.commit()


def network_activity_today(conn, limit=8, now=None):
    """Most active programs today on active computers (raw activity, not website history)."""
    day = start_of_today(now)[:10]
    return [dict(r) for r in conn.execute(
        "SELECT " + DEVICE_NAME + " AS computer_name, n.process_name, n.process_kind, n.connections, n.last_seen "
        "FROM network_activity n JOIN active_devices ad ON ad.device_id = n.device_id JOIN endpoints e ON e.id = n.endpoint_id "
        "LEFT JOIN devices d ON d.id = n.device_id "
        "WHERE n.day = ? ORDER BY n.connections DESC, n.last_seen DESC LIMIT ?", (day, limit))]


def upsert_endpoint(conn, endpoint_uid, computer_name, username, browser=None, username_provided=False,
                    agent_version=None, history_browsers=None, sensor_version=None):
    """Create or update the endpoint identified by endpoint_uid (never a second row).
    Registration, heartbeat and web events all go through here, so each of them
    refreshes last_seen. A changed computer_name just updates the existing row.
    username_provided=True makes `username` authoritative (it may clear the label);
    otherwise an absent username keeps the stored one.
    `browser` is only set by the browser extension and `agent_version` only by the Windows
    agent; an absent value keeps what is stored, so one logical computer that reports
    through both (same endpoint_uid, linked on purpose) shows both.
    An archived computer that connects again is restored (archived_at cleared): a
    computer that is alive must never stay hidden from the owner."""
    now = now_str()
    agent_seen = now if agent_version is not None else None        # the agent always identifies itself with its version
    # Only the extension sends `browser`, and it never sends an agent version; the agent sends a version and never `browser`.
    # So a request that carries a browser and no agent version IS extension activity, and an agent beat can never refresh it.
    extension_seen = now if (browser is not None and agent_version is None) else None
    username_sql = "excluded.username" if username_provided else "COALESCE(excluded.username, endpoints.username)"
    conn.execute(
        "INSERT INTO endpoints (endpoint_uid, computer_name, username, browser, agent_version, history_browsers, agent_seen_at, "
        "last_seen, sensor_version, extension_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(endpoint_uid) DO UPDATE SET computer_name = excluded.computer_name, "
        "username = " + username_sql + ", browser = COALESCE(excluded.browser, endpoints.browser), "
        "agent_version = COALESCE(excluded.agent_version, endpoints.agent_version), "
        "history_browsers = COALESCE(excluded.history_browsers, endpoints.history_browsers), "
        "agent_seen_at = COALESCE(excluded.agent_seen_at, endpoints.agent_seen_at), "
        "sensor_version = COALESCE(excluded.sensor_version, endpoints.sensor_version), "
        "extension_seen_at = COALESCE(excluded.extension_seen_at, endpoints.extension_seen_at), "
        "last_seen = excluded.last_seen, archived_at = NULL",
        (endpoint_uid, computer_name, username, browser, agent_version, history_browsers, agent_seen, now,
         sensor_version or agent_version, extension_seen),
    )
    row = conn.execute("SELECT * FROM endpoints WHERE endpoint_uid = ?", (endpoint_uid,)).fetchone()
    # what this installation is, from everything it has ever reported (an agent that is linked by hand to an extension row
    # makes that row LEGACY_COMBINED; a paired sensor keeps the type it was paired with)
    kind = sensor_type_for(row["browser"], row["agent_version"])
    if row["secret_hash"] is None and kind != row["sensor_type"]:
        conn.execute("UPDATE endpoints SET sensor_type = ? WHERE id = ?", (kind, row["id"]))
    _sync_device(conn, row["device_id"], now)
    conn.commit()
    return conn.execute("SELECT * FROM endpoints WHERE endpoint_uid = ?", (endpoint_uid,)).fetchone()


def _sync_device(conn, device_id, now):
    """A sensor reported: its device is alive, and an UNVERIFIED device is named after its first sensor (a verified device keeps
    the name its Windows agent gave it, so a browser label such as BROWSER-8DC9A045 never renames a real computer)."""
    if device_id is None:
        return
    conn.execute("UPDATE devices SET last_seen = ?, archived_at = NULL WHERE id = ?", (now, device_id))
    conn.execute(
        "UPDATE devices SET display_name = (SELECT computer_name FROM endpoints WHERE device_id = devices.id "
        "ORDER BY id LIMIT 1) WHERE id = ? AND identity != 'VERIFIED' AND "
        "EXISTS (SELECT 1 FROM endpoints WHERE device_id = devices.id)", (device_id,))
    # a verified device is named by its Windows agent (the one sensor that can read the real computer name)
    conn.execute(
        "UPDATE devices SET display_name = (SELECT computer_name FROM endpoints WHERE device_id = devices.id "
        "AND sensor_type = 'WINDOWS_AGENT' ORDER BY id LIMIT 1) WHERE id = ? AND identity = 'VERIFIED' AND "
        "EXISTS (SELECT 1 FROM endpoints WHERE device_id = devices.id AND sensor_type = 'WINDOWS_AGENT')", (device_id,))


DEDUPE_WINDOW_SECONDS = 10


_VERDICT_RANK = {"UNKNOWN": 0, "SAFE": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}


def raise_visit_verdict(conn, visit_id, status, level):
    """Phase F3.9: an ADDRESS-level finding makes THIS visit's own verdict worse (never better), so the visit is listed as what its page was. Nothing else is touched: not the
    domain's cached verdict, not any other visit of the same host. Returns True when the row changed."""
    row = conn.execute("SELECT reputation_status FROM web_visits WHERE id = ?", (visit_id,)).fetchone()
    if row is None or _VERDICT_RANK.get(status, 0) <= _VERDICT_RANK.get(row["reputation_status"], 0):
        return False
    conn.execute("UPDATE web_visits SET reputation_status = ?, level = ? WHERE id = ?", (status, level, visit_id))
    conn.commit()
    return True


def url_evidence_for_visits(conn, visit_ids):
    """{visit id: [evidence rows]} of the address-level checks of these visits (two queries at most, never one per row)."""
    ids = sorted(set(int(i) for i in visit_ids if i is not None))
    grouped = {}
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        for row in conn.execute("SELECT * FROM visit_url_evidence WHERE web_visit_id IN (%s) ORDER BY provider" % ",".join("?" * len(chunk)), chunk):
            grouped.setdefault(row["web_visit_id"], []).append(dict(row))
    return grouped


def find_recent_visit(conn, endpoint_id, domain, sanitized_url, visited_at, window_seconds=DEDUPE_WINDOW_SECONDS,
                      source=SOURCE_BROWSER, process_name=None, browser=None):
    """Server-side dedupe: id of an identical observation (same computer, same page, SAME
    SOURCE) recorded within +/- window_seconds of visited_at, else None.
    Browser: catches reload / redirect bursts the extension did not suppress (10 s).
    Agent: same computer + domain (agent rows have no URL) within AGENT_DEDUPE_WINDOW_SECONDS.
    The source is part of the match, so a browser visit and an agent observation can never
    be mistaken for each other.
    process_name: given for the native collector, where two different programs reaching the same
    address are two observations (Edge and Teams to one Microsoft address); None (DNS-cache
    observations and browser visits) leaves the match exactly as it was."""
    try:
        ts = datetime.strptime(visited_at, TIME_FORMAT)
    except (TypeError, ValueError):
        return None
    lo = (ts - timedelta(seconds=window_seconds)).strftime(TIME_FORMAT)
    hi = (ts + timedelta(seconds=window_seconds)).strftime(TIME_FORMAT)
    sql = ("SELECT id FROM web_visits WHERE endpoint_id = ? AND domain = ? AND source = ? "
           "AND IFNULL(sanitized_url, '') = IFNULL(?, '') AND visited_at BETWEEN ? AND ? ")
    params = [endpoint_id, domain, source, sanitized_url, lo, hi]
    if process_name is not None:
        sql += "AND IFNULL(process_name, '') = ? "
        params.append(process_name)
    if browser is not None:       # browser-history visits: the same site in Chrome and in Edge are two visits
        sql += "AND IFNULL(browser, '') = ? "
        params.append(browser)
    row = conn.execute(sql + "ORDER BY id DESC LIMIT 1", params).fetchone()
    return row["id"] if row else None


def insert_visit(conn, endpoint_id, domain, sanitized_url, browser, visited_at, status, source=SOURCE_BROWSER,
                 dest_ip=None, process_name=None, process_kind=None, pid=None, level=None):
    # the visit belongs to the device its sensor had when it HAPPENED (visited_at), not when it arrived: a delayed event keeps its time's device
    device_id, attribution = attribute_event(conn, endpoint_id, visited_at)
    cur = conn.execute(
        "INSERT INTO web_visits (endpoint_id, domain, sanitized_url, browser, visited_at, reputation_status, source, "
        "dest_ip, process_name, process_kind, pid, device_id, attribution, level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (endpoint_id, domain, sanitized_url, browser, visited_at, status, source, dest_ip, process_name, process_kind, pid, device_id, attribution, level),
    )
    conn.commit()
    return cur.lastrowid


# ---- Alerts (Phase A1) ---------------------------------------------------------------------------------------------
# One OPEN alert per COMPUTER + DOMAIN per grouping window. The computer is the device (endpoints.device_id), so the extension and
# the agent's browser history reporting one exposure through two sensor rows of the same device share one alert. A legacy or
# unverified installation has a device of its own: it is never joined with another computer, whatever its name or address.
# The window is fixed from the alert's creation (not sliding), so a domain that is visited all day cannot be hidden by one old alert:
# after ALERT_GROUP_WINDOW_HOURS a new exposure opens a new alert. A handled (CLOSED) alert never absorbs anything: the next exposure
# opens a new alert at once.
ALERT_SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2}
ALERT_EVENT_CREATED, ALERT_EVENT_EXPOSURE, ALERT_EVENT_ESCALATED = "CREATED", "EXPOSURE", "ESCALATED"

# Concurrency (Phase A1.1). Several Flask request threads, each with its own connection, can report the same exposure at the same
# moment (the extension and the agent, or a burst). Checking for an open alert and then inserting one is a read followed by a write; the
# sqlite3 driver takes no lock for a plain SELECT, so without more every thread saw "no alert" and all of them created one. The fix:
#   1. the whole decision runs inside BEGIN IMMEDIATE, which takes SQLite's single write lock FIRST, so the check and the insert / update /
#      escalation are one atomic step across all connections and threads;
#   2. a trigger (trg_alert_one_open_per_group, created in _migrate) makes the database itself refuse a second OPEN alert for the same
#      computer + domain inside the window, whoever writes it; the code catches that refusal and looks again (it then joins the alert);
#   3. the escalation is a conditional UPDATE, and an evidence row is unique per alert + visit.
# Getting the write lock waits up to the connection timeout (10 s); beyond that the attempt is retried after the delays below and then
# fails with sqlite3.OperationalError. A failed attempt is rolled back completely: it never leaves half an alert and never a duplicate.
ALERT_LOCK_RETRY_DELAYS = (0.05, 0.15, 0.4, 1.0)         # seconds to wait before each further attempt to get the write lock
ALERT_RACE_ATTEMPTS = 3                                  # how often the decision is repeated after the database refused a duplicate


def _open_alert_for(conn, endpoint_id, device_id, domain, since):
    """The OPEN alert that absorbs an exposure of `domain` on this computer, or None. Alerts written before Phase A1 (device_id NULL,
    for example by older code after a rollback) are matched through the device of the sensor that raised them."""
    if device_id is None:                  # a sensor without a device: only itself
        return conn.execute(
            "SELECT * FROM alerts WHERE endpoint_id = ? AND domain = ? AND status = 'OPEN' AND created_at >= ? "
            "ORDER BY created_at DESC, id DESC LIMIT 1", (endpoint_id, domain, since)).fetchone()
    return conn.execute(
        "SELECT * FROM alerts WHERE domain = ? AND status = 'OPEN' AND created_at >= ? AND "
        "(device_id = ? OR (device_id IS NULL AND endpoint_id IN (SELECT id FROM endpoints WHERE device_id = ?))) "
        "ORDER BY created_at DESC, id DESC LIMIT 1", (domain, since, device_id, device_id)).fetchone()


def _begin_write(conn):
    """Take SQLite's write lock now (BEGIN IMMEDIATE), so what is read next cannot be changed by another connection before this
    transaction ends. Waits for a busy database (the connection timeout), then retries after ALERT_LOCK_RETRY_DELAYS; raises the last
    sqlite3.OperationalError when the database stays locked. Anything the caller left uncommitted is committed first: a transaction
    cannot be started inside another."""
    if conn.in_transaction:
        conn.commit()
    delays = iter(ALERT_LOCK_RETRY_DELAYS)
    while True:
        try:
            conn.execute("BEGIN IMMEDIATE")
            return
        except sqlite3.OperationalError as error:
            text = str(error).lower()
            if "locked" not in text and "busy" not in text:
                raise
            delay = next(delays, None)
            if delay is None:
                raise
            time.sleep(delay * (1 + random.random() * 0.5))          # up to 50% longer, never shorter: several writers must not retry in lock-step (seen on Linux with 8 at once)


def record_alert_exposure(conn, endpoint_id, web_visit_id, domain, severity, reason, verdict=None, browser=None, source=None,
                          observed_at=None, now=None, detail=None):
    """A visit to a SUSPICIOUS (MEDIUM) or MALICIOUS (HIGH) domain was seen. Creates the alert, or adds the exposure to the open one and
    escalates MEDIUM to HIGH when the new evidence is worse. Never lowers a severity, never deletes or edits a visit, never creates
    anything for UNKNOWN (callers only pass severities of SUSPICIOUS / MALICIOUS verdicts). Safe to call from many threads at once: the
    whole decision is one write transaction (see "Concurrency" above). Returns {"alert_id", "created", "escalated", "severity"}."""
    if severity not in ALERT_SEVERITY_RANK:
        raise ValueError("an alert severity is HIGH or MEDIUM, not %r" % (severity,))
    now = now or datetime.now()
    domain = (domain or "").lower().rstrip(".")
    for attempt in range(ALERT_RACE_ATTEMPTS):
        _begin_write(conn)
        try:
            result = _record_alert_exposure_locked(conn, endpoint_id, web_visit_id, domain, severity, reason, verdict, browser, source,
                                                   observed_at, now, detail)
            conn.commit()
            return result
        except sqlite3.IntegrityError as error:
            conn.rollback()
            # the database refused a second open alert: another writer's alert is now visible, so decide again (it will join it)
            if ALERT_DUPLICATE_MESSAGE not in str(error) or attempt == ALERT_RACE_ATTEMPTS - 1:
                raise
        except BaseException:
            conn.rollback()
            raise


# Phase F2.1: how close in time two reports from different sensors must be to be ONE visit. Measured on the real database: of the extension/history pairs on the same
# computer, domain and browser, 16 of 20 had identical timestamps and 18 of 20 were within 15 seconds; the stragglers (30 s, 110 s, 10 min) are as likely to be separate
# visits as the same one. A browser stamps both records from the same navigation, so a short window is right and a long one only risks merging two real visits. The
# dashboard's own display rule (COVERED_WINDOW_SECONDS, 120 s) is deliberately wider: showing two records as one row is harmless, counting two visits as one exposure is not.
ALERT_TWIN_WINDOW_SECONDS = 15
# If the second-best candidate is almost as close as the best one, the evidence cannot tell which record is the twin: nothing is merged.
ALERT_TWIN_AMBIGUITY_SECONDS = 2


def _same_visit_event(conn, web_visit_id, device_id, domain):
    """The alert event that already counts THIS visit, when it is the same real visit reported by the other browser sensor, else None.
    One record from the extension (BROWSER) and one from the agent's browser-history collector (BROWSER_HISTORY), the SAME device (the device each event was stored
    with), domain and browser, with event times at most ALERT_TWIN_WINDOW_SECONDS apart. Event TIMES are compared, never arrival times, so a history record that
    arrives late still matches. It is deterministic and conservative:
      * a different device never matches, a different browser never matches, two records of the same kind never match (two extension visits stay two exposures);
      * when BOTH records carry a page address (sanitized URL) the addresses must be equal; the history collector sends only the host, so today that is not checked;
      * the match is one-to-one: an event that already has a twin cannot be the twin of a third record, so two genuine visits seconds apart stay two exposures;
      * of several candidates the nearest in time wins (then the lowest event id) - unless the runner-up is within ALERT_TWIN_AMBIGUITY_SECONDS of it, in which case the
        evidence cannot tell them apart and nothing is merged;
      * a record without a stored device or time is never matched (insufficient evidence).
    Nothing is rewritten: only the NEW event is marked."""
    visit = conn.execute("SELECT source, browser, visited_at, sanitized_url FROM web_visits WHERE id = ?", (web_visit_id,)).fetchone()
    if visit is None or device_id is None or visit["source"] not in (SOURCE_BROWSER, SOURCE_BROWSER_HISTORY) or not visit["visited_at"]:
        return None
    other = SOURCE_BROWSER_HISTORY if visit["source"] == SOURCE_BROWSER else SOURCE_BROWSER
    candidates = conn.execute(
        "SELECT e.id, e.alert_id, e.web_visit_id, e.source, ABS(strftime('%s', w.visited_at) - strftime('%s', ?)) AS gap "
        "FROM alert_events e JOIN web_visits w ON w.id = e.web_visit_id "
        "WHERE w.source = ? AND w.device_id = ? AND w.domain = ? AND IFNULL(w.browser, '') = IFNULL(?, '') "
        "AND ABS(strftime('%s', w.visited_at) - strftime('%s', ?)) <= ? AND e.corroborates_event_id IS NULL "
        "AND (w.sanitized_url IS NULL OR ? IS NULL OR w.sanitized_url = ?) "
        "AND NOT EXISTS (SELECT 1 FROM alert_events t WHERE t.corroborates_event_id = e.id) "
        "ORDER BY gap, e.id LIMIT 2",
        (visit["visited_at"], other, device_id, domain, visit["browser"], visit["visited_at"], ALERT_TWIN_WINDOW_SECONDS,
         visit["sanitized_url"], visit["sanitized_url"])).fetchall()
    if not candidates:
        return None
    if len(candidates) == 2 and candidates[1]["gap"] - candidates[0]["gap"] < ALERT_TWIN_AMBIGUITY_SECONDS:
        return None
    return candidates[0]


def _record_alert_exposure_locked(conn, endpoint_id, web_visit_id, domain, severity, reason, verdict, browser, source, observed_at, now, extra_detail=None):
    """The decision itself; the caller holds the write lock and commits."""
    stamp = now.strftime(TIME_FORMAT)
    sensor = conn.execute("SELECT id, device_id FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
    if sensor is None:
        raise ValueError("unknown endpoint %r" % (endpoint_id,))
    device_id, attribution = None, None
    if web_visit_id is not None:                                   # the alert belongs to the device of the visit that raised it
        visit = conn.execute("SELECT device_id, attribution FROM web_visits WHERE id = ?", (web_visit_id,)).fetchone()
        if visit is not None and visit["device_id"] is not None:
            device_id, attribution = visit["device_id"], visit["attribution"]
    if device_id is None:                                          # no visit row (older callers): the device of the event's time
        device_id, attribution = attribute_event(conn, endpoint_id, observed_at or stamp, now)
    verdict = verdict or ("MALICIOUS" if severity == "HIGH" else "SUSPICIOUS")
    since = (now - timedelta(hours=ALERT_GROUP_WINDOW_HOURS)).strftime(TIME_FORMAT)

    def event(alert_id, kind, after, previous=None, detail=None):
        # one row per distinct visit and alert: the same visit reported twice (a retry, a duplicate burst) is not counted twice. Only
        # that one conflict is skipped; any other violation (a NULL where a value is required, a missing parent) raises and rolls the
        # whole decision back, so an alert can never be stored without its evidence.
        return conn.execute(
            "INSERT INTO alert_events (alert_id, kind, severity, previous_severity, verdict, web_visit_id, endpoint_id, domain, "
            "browser, source, observed_at, recorded_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (alert_id, web_visit_id) WHERE web_visit_id IS NOT NULL DO NOTHING",
            (alert_id, kind, after, previous, verdict, web_visit_id, endpoint_id, domain, browser, source, observed_at, stamp, detail)).rowcount

    twin = _same_visit_event(conn, web_visit_id, device_id, domain) if web_visit_id is not None else None
    if twin is not None:
        # The extension and the agent's browser-history collector reported ONE real visit. It is already counted (in an open or in a handled alert): this
        # report is kept as supporting evidence, linked to the event it corroborates, and is not counted as another exposure.
        current = conn.execute("SELECT severity, status FROM alerts WHERE id = ?", (twin["alert_id"],)).fetchone()
        worse = ALERT_SEVERITY_RANK[severity] > ALERT_SEVERITY_RANK[current["severity"]]
        if worse and current["status"] != "OPEN":
            twin = None                  # worse evidence than a HANDLED alert recorded must not be hidden behind it: decide as for a new report
    if twin is not None:
        kind, previous, after, escalated = ALERT_EVENT_EXPOSURE, None, current["severity"], False
        if worse:                        # the second sensor brought a worse verdict for the same visit: the alert is escalated (still one exposure)
            changed = conn.execute("UPDATE alerts SET severity = ?, previous_severity = ?, escalated_at = ?, reason = ? WHERE id = ? AND severity = ?",
                                   (severity, current["severity"], stamp, reason, twin["alert_id"], current["severity"])).rowcount
            if changed == 1:
                kind, previous, after, escalated = ALERT_EVENT_ESCALATED, current["severity"], severity, True
        conn.execute(
            "INSERT INTO alert_events (alert_id, kind, severity, previous_severity, verdict, web_visit_id, endpoint_id, domain, browser, source, observed_at, "
            "recorded_at, detail, corroborates_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (alert_id, web_visit_id) WHERE web_visit_id IS NOT NULL DO NOTHING",
            (twin["alert_id"], kind, after, previous, verdict, web_visit_id, endpoint_id, domain, browser, source, observed_at, stamp,
             "Same visit as event #%d (visit #%d, %s): supporting evidence, not counted again" % (twin["id"], twin["web_visit_id"], twin["source"]), twin["id"]))
        return {"alert_id": twin["alert_id"], "created": False, "escalated": escalated, "severity": after, "duplicate_of_event": twin["id"]}
    existing = _open_alert_for(conn, endpoint_id, device_id, domain, since)
    if existing is None:
        cur = conn.execute(
            "INSERT INTO alerts (endpoint_id, web_visit_id, domain, severity, reason, created_at, device_id, last_exposure_at, exposure_count, attribution) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)", (endpoint_id, web_visit_id, domain, severity, reason, stamp, device_id, stamp, attribution))
        event(cur.lastrowid, ALERT_EVENT_CREATED, severity, detail=extra_detail)
        return {"alert_id": cur.lastrowid, "created": True, "escalated": False, "severity": severity}

    alert_id = existing["id"]
    escalate = ALERT_SEVERITY_RANK[severity] > ALERT_SEVERITY_RANK[existing["severity"]]
    if escalate:
        # the creation time and the first visit stay as they were; the escalation is recorded beside them. The condition on the old
        # severity makes the step safe even if it were ever reached without the write lock.
        changed = conn.execute("UPDATE alerts SET severity = ?, previous_severity = ?, escalated_at = ?, reason = ? "
                               "WHERE id = ? AND severity = ?", (severity, existing["severity"], stamp, reason, alert_id, existing["severity"])).rowcount
        escalate = changed == 1
    if escalate:
        added = event(alert_id, ALERT_EVENT_ESCALATED, severity, existing["severity"],
                      "%s evidence replaced %s" % (verdict, existing["severity"]) + ("; " + extra_detail if extra_detail else ""))
    else:
        added = event(alert_id, ALERT_EVENT_EXPOSURE, existing["severity"], detail=extra_detail)
    if added:
        conn.execute("UPDATE alerts SET last_exposure_at = ?, exposure_count = exposure_count + 1 WHERE id = ?", (stamp, alert_id))
    return {"alert_id": alert_id, "created": False, "escalated": escalate, "severity": severity if escalate else existing["severity"]}


def create_alert_if_new(conn, endpoint_id, web_visit_id, domain, severity, reason):
    """Kept for callers of earlier phases: (alert id, created). The grouping and escalation rules are those of record_alert_exposure."""
    result = record_alert_exposure(conn, endpoint_id, web_visit_id, domain, severity, reason)
    return result["alert_id"], result["created"]


def alert_events(conn, alert_ids):
    """The recorded exposures of the given alerts, oldest first: {alert_id: [row, ...]}."""
    ids = [int(i) for i in alert_ids]
    if not ids:
        return {}
    grouped = {}
    for row in conn.execute("SELECT * FROM alert_events WHERE alert_id IN (%s) ORDER BY id" % ",".join("?" * len(ids)), ids):
        grouped.setdefault(row["alert_id"], []).append(dict(row))
    return grouped


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


# Sensor freshness (Phase 5.7). A sensor counts as REPORTING only while its own timestamp (extension_seen_at for the browser
# extension, agent_seen_at for the Windows agent) is at most SENSOR_FRESH_SECONDS old. Both send a beat every 60 s, so 180 s
# tolerates two missed beats (a busy browser, a short network drop) and a silent sensor is shown within 3 minutes. A timestamp
# that is missing, unreadable, or more than SENSOR_CLOCK_SKEW_SECONDS in the future is never trusted: it is "not verified",
# which is treated as not reporting, not as healthy.
SENSOR_FRESH_SECONDS = ONLINE_WINDOW_SECONDS
SENSOR_CLOCK_SKEW_SECONDS = 60


def sensor_fresh(seen_at, now=None):
    """True only for a readable timestamp that is recent (see SENSOR_FRESH_SECONDS). None / garbage / far future -> False."""
    try:
        seen = datetime.strptime(seen_at, TIME_FORMAT)
    except (TypeError, ValueError):
        return False
    age = ((now or datetime.now()) - seen).total_seconds()
    return -SENSOR_CLOCK_SKEW_SECONDS <= age <= SENSOR_FRESH_SECONDS


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
#   monitored computers, online now, websites today, domains contacted today, threats
#   today, reputation coverage and the recent-activity list. Open ALERTS are always
#   counted, even for an archived computer, so archiving can never hide an unresolved
#   threat. Historical visits and alerts of archived computers stay in the Browsing and
#   Alerts pages.
#
# Two kinds of observation, counted separately and never merged (Phase 5.1):
#   websites visited today    = BROWSER rows (exactly the numbers before the agent existed)
#   domains contacted today   = distinct AGENT (computer, domain) pairs that the same
#                               computer did NOT also visit in a monitored browser within
#                               COVERED_WINDOW_SECONDS ("covered" lookups are not counted twice)
#   threats today             = browser threat rows + uncovered agent threat domains
#   reputation coverage       = verified / (browser visits + uncovered agent domains)
_EVALUATED = "('SAFE', 'SUSPICIOUS', 'MALICIOUS')"
_THREATS = "('MALICIOUS', 'SUSPICIOUS')"
# A visit is a THREAT when its verdict is SUSPICIOUS / MALICIOUS and the evidence policy did not call it a WEAK finding (level is NULL for every historical visit).
_IS_THREAT = "(v.reputation_status IN " + _THREATS + " AND IFNULL(v.level, '') <> 'WEAK')"
def same_device(a, b):
    """SQL: sensors of visit rows a and b belong to the same device."""
    return "%s.device_id = %s.device_id" % (a, b)                 # the devices the two EVENTS belong to (stored), not where their sensors are now


_COVERED = ("EXISTS (SELECT 1 FROM web_visits b WHERE b.source = 'BROWSER' AND " + same_device("b", "v") + " "
            "AND b.domain = v.domain AND ABS(strftime('%%s', b.visited_at) - strftime('%%s', v.visited_at)) <= %d)"
            % COVERED_WINDOW_SECONDS)
_PAIR = "v.device_id || '|' || v.domain"
# A browser-history visit is explained by an extension visit of the SAME computer (explicit link), the SAME browser and the
# SAME domain within COVERED_WINDOW_SECONDS. It is evaluated when read, so it works whichever arrived first, and nothing is
# deleted or rewritten: the covered row stays in the Browsing page, only the dashboard figures and list count it once.
_COVERED_H = ("EXISTS (SELECT 1 FROM web_visits b WHERE b.source = 'BROWSER' AND " + same_device("b", "v") + " "
              "AND b.domain = v.domain AND IFNULL(b.browser, '') = IFNULL(v.browser, '') "
              "AND ABS(strftime('%%s', b.visited_at) - strftime('%%s', v.visited_at)) <= %d)" % COVERED_WINDOW_SECONDS)
# a website visit as the dashboard counts it: an extension visit, or a history visit the extension did not already report
_WEBSITE = "(v.source = 'BROWSER' OR (v.source = 'BROWSER_HISTORY' AND NOT " + _COVERED_H + "))"


def dashboard_summary(conn, now=None):
    now = now or datetime.now()
    row = conn.execute(
        "SELECT "
        # a COMPUTER is an ACTIVE device (see the active_devices view: it has an unarchived sensor, or it is a former device kept until archived); it is
        # online while ANY of its sensors is
        "(SELECT COUNT(*) FROM active_devices) AS computers, "
        "(SELECT COUNT(DISTINCT device_id) FROM endpoints WHERE archived_at IS NULL AND last_seen >= :cutoff) AS online_now, "
        "(SELECT COUNT(DISTINCT device_id) FROM endpoints WHERE archived_at IS NULL AND agent_version IS NOT NULL) AS agents_enrolled, "
        "(SELECT COUNT(*) FROM endpoints WHERE archived_at IS NULL) AS sensors, "
        "(SELECT COUNT(*) FROM endpoints WHERE archived_at IS NULL AND last_seen >= :cutoff) AS sensors_online, "
        "(SELECT COUNT(*) FROM active_devices ad JOIN devices d ON d.id = ad.device_id WHERE d.identity != 'VERIFIED') AS unverified_computers, "
        "(SELECT COUNT(*) FROM active_devices ad JOIN devices d ON d.id = ad.device_id WHERE d.identity = 'VERIFIED') AS self_enrolled_computers, "
        "(SELECT COUNT(*) FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        " WHERE " + _WEBSITE + " AND v.visited_at >= :start) AS visits_today, "
        "(SELECT COUNT(*) FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        " WHERE " + _WEBSITE + " AND v.visited_at >= :start "
        " AND v.reputation_status IN " + _EVALUATED + ") AS evaluated_today, "
        "(SELECT COUNT(*) FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        " WHERE " + _WEBSITE + " AND v.visited_at >= :start "
        " AND " + _IS_THREAT + ") AS browser_threats_today, "
        "(SELECT COUNT(DISTINCT " + _PAIR + ") FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        " WHERE v.source = 'AGENT' AND v.dest_ip IS NULL AND v.visited_at >= :start AND NOT " + _COVERED + ") AS contacted_today, "
        "(SELECT COUNT(DISTINCT CASE WHEN v.reputation_status IN " + _EVALUATED + " THEN " + _PAIR + " END) "
        " FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        " WHERE v.source = 'AGENT' AND v.dest_ip IS NULL AND v.visited_at >= :start AND NOT " + _COVERED + ") AS contacted_evaluated_today, "
        "(SELECT COUNT(DISTINCT CASE WHEN " + _IS_THREAT + " THEN " + _PAIR + " END) "
        " FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        " WHERE v.source = 'AGENT' AND v.dest_ip IS NULL AND v.visited_at >= :start AND NOT " + _COVERED + ") AS contacted_threats_today, "
        # raw network activity of programs (native collector), counted apart from every website figure
        "(SELECT IFNULL(SUM(n.connections), 0) FROM network_activity n JOIN active_devices e ON e.device_id = n.device_id "
        " WHERE n.day = :day) AS network_connections_today, "
        "(SELECT COUNT(*) FROM network_activity n JOIN active_devices e ON e.device_id = n.device_id "
        " WHERE n.day = :day) AS network_programs_today, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN') AS open_alerts, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN' AND severity = 'HIGH') AS open_high, "
        "(SELECT COUNT(*) FROM alerts WHERE status = 'OPEN' AND severity = 'MEDIUM') AS open_medium",
        {"cutoff": online_cutoff(now), "start": start_of_today(now), "day": start_of_today(now)[:10]},
    ).fetchone()
    summary = dict(row)
    summary["threats_today"] = summary.pop("browser_threats_today") + summary["contacted_threats_today"]
    summary["coverage_total"] = summary["visits_today"] + summary["contacted_today"]
    summary["coverage_evaluated"] = summary["evaluated_today"] + summary["contacted_evaluated_today"]
    summary["unchecked_today"] = summary["coverage_total"] - summary["coverage_evaluated"]
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
    """Open alerts for the Needs-attention list: dangerous first, then newest.
    visit_source tells whether the alert came from a browser visit or an agent lookup."""
    return [dict(r) for r in conn.execute(
        "SELECT a.id, a.severity, a.domain, a.created_at, " + DEVICE_NAME + " AS computer_name, e.username, v.source AS visit_source "
        "FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id LEFT JOIN devices d ON d.id = COALESCE(a.device_id, e.device_id) "
        "LEFT JOIN web_visits v ON v.id = a.web_visit_id "
        "WHERE a.status = 'OPEN' "
        "ORDER BY CASE a.severity WHEN 'HIGH' THEN 0 ELSE 1 END, a.created_at DESC, a.id DESC LIMIT ?",
        (limit,),
    )]


def long_offline_computers(conn, seconds, now=None):
    """Active computers silent for more than `seconds` (operational information only)."""
    cutoff = ((now or datetime.now()) - timedelta(seconds=seconds)).strftime(TIME_FORMAT)
    # a computer is silent only when ALL of its active sensors are
    names = [r["computer_name"] for r in conn.execute(
        "SELECT " + DEVICE_NAME + " AS computer_name FROM endpoints e LEFT JOIN devices d ON d.id = e.device_id "
        "WHERE e.archived_at IS NULL GROUP BY e.device_id HAVING MAX(e.last_seen) < ? "
        "ORDER BY MAX(e.last_seen) DESC", (cutoff,))]
    # a FORMER device (it lost its last sensor) is not reporting, whatever its last_seen says; it stays listed until an administrator archives it
    names += [r["display_name"] for r in conn.execute(
        "SELECT d.display_name FROM devices d JOIN active_devices ad ON ad.device_id = d.id "
        "WHERE NOT EXISTS (SELECT 1 FROM endpoints s WHERE s.device_id = d.id) ORDER BY d.last_seen DESC, d.id")]
    return names


# The name shown for the computer a sensor belongs to: a verified device keeps the name its Windows agent gave it; an
# unverified one is named after its installation (the old behaviour, so nothing changes until a sensor is paired).
DEVICE_NAME = ("CASE WHEN d.id IS NOT NULL AND (d.identity = 'VERIFIED' OR e.device_id IS NOT d.id) THEN d.display_name ELSE e.computer_name END")
# How many browser-history records back an extension visit up (same computer, browser and domain within the covered window):
# the visit is ONE logical visit, shown once, with the history record as supporting evidence.
_SUPPORT_MATCH = ("v.source = 'BROWSER' AND h.source = 'BROWSER_HISTORY' "
                  "AND " + same_device("h", "v") + " AND h.domain = v.domain AND IFNULL(h.browser, '') = IFNULL(v.browser, '') "
                  "AND ABS(strftime('%%s', h.visited_at) - strftime('%%s', v.visited_at)) <= %d" % COVERED_WINDOW_SECONDS)
# The STABLE identity of a logical visit, for pages that update themselves: the lowest physical id among the primary record and
# the records that back it up. A history record always has a lower id than the extension record that arrives after it, and an
# extension record that arrives first is already the lowest, so this number does not change when the primary switches from
# the history record to the extension record (or when supporting evidence arrives later). Everything that is not an extension
# visit with supporting evidence is its own logical visit (its own id).
# A history record that backs several extension visits gives its identity to the OLDEST of them only, so no two rows share a key.
_LOGICAL_ID = ("MIN(v.id, IFNULL((SELECT MIN(h.id) FROM web_visits h WHERE " + _SUPPORT_MATCH +
               " AND NOT EXISTS (SELECT 1 FROM web_visits o WHERE o.id < v.id AND o.source = 'BROWSER' "
               "AND " + same_device("o", "h") + " AND o.domain = h.domain AND IFNULL(o.browser, '') = IFNULL(h.browser, '') "
               "AND ABS(strftime('%%s', h.visited_at) - strftime('%%s', o.visited_at)) <= %d)), v.id)) AS logical_id, "
               % COVERED_WINDOW_SECONDS)
_SUPPORTING_HISTORY = ("(SELECT COUNT(*) FROM web_visits h WHERE " + _SUPPORT_MATCH + ") AS supporting_history, ")
_VISIT_SELECT = (
    "SELECT v.id, v.visited_at, v.domain, v.sanitized_url, v.browser, v.reputation_status, v.source, "
    "v.dest_ip, v.process_name, v.process_kind, v.pid, v.endpoint_id, v.device_id, v.attribution, v.level, " + _LOGICAL_ID + _SUPPORTING_HISTORY +
    "e.sensor_type, " + DEVICE_NAME + " AS computer_name, e.username FROM web_visits v JOIN endpoints e ON e.id = v.endpoint_id "
    "LEFT JOIN devices d ON d.id = v.device_id "
)


def _like(value):
    """LIKE pattern for a plain search term (wildcards typed by the user are literal)."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def _visit_filters(status, query, active_only, source=None, hide_covered=False, include_raw=False, physical=False):
    clauses, params = [], []
    if not physical:       # LOGICAL visits: a history record the extension already reported is supporting evidence, not a second visit
        clauses.append("NOT (v.source = 'BROWSER_HISTORY' AND " + _COVERED_H + ")")
    if not include_raw:    # older rows that only record 'a program connected to an address' are not website history
        clauses.append("v.dest_ip IS NULL")
    if status:
        clauses.append("v.reputation_status = ?")
        params.append(status)
    if source in SOURCES:
        clauses.append("v.source = ?")
        params.append(source)
    if query:
        clauses.append("(v.domain LIKE ? ESCAPE '\\' OR (" + DEVICE_NAME + ") LIKE ? ESCAPE '\\' "
                       "OR IFNULL(e.username, '') LIKE ? ESCAPE '\\' OR IFNULL(v.process_name, '') LIKE ? ESCAPE '\\')")
        params.extend([_like(query)] * 4)
    if active_only:
        clauses.append("v.device_id IN (SELECT device_id FROM active_devices)")
    if hide_covered:       # the dashboard shows each real event once: a lookup explained by a browser visit is hidden there
        clauses.append("NOT (v.source = 'AGENT' AND " + _COVERED + ")")
    return clauses, params


def recent_visits(conn, limit=50, status=None, query=None, active_only=False, source=None, hide_covered=False, include_raw=False,
                  physical=False):
    clauses, params = _visit_filters(status, query, active_only, source, hide_covered, include_raw, physical)
    sql = _VISIT_SELECT + ("WHERE " + " AND ".join(clauses) + " " if clauses else "")
    sql += "ORDER BY v.visited_at DESC, v.id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def visits_after(conn, after_id, limit=50, status=None, query=None, active_only=False, source=None, hide_covered=False,
                 include_raw=False, physical=False):
    """Visits with id > after_id, newest first - used by the page polling."""
    clauses, params = _visit_filters(status, query, active_only, source, hide_covered, include_raw, physical)
    clauses.insert(0, "v.id > ?")
    params.insert(0, after_id)
    sql = _VISIT_SELECT + "WHERE " + " AND ".join(clauses) + " ORDER BY v.id DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def get_visit(conn, visit_id):
    """One physical visit record (with its computer), or None."""
    return conn.execute(_VISIT_SELECT + "WHERE v.id = ?", (visit_id,)).fetchone()


def _gap_seconds(a, b):
    try:
        return abs((datetime.strptime(a, TIME_FORMAT) - datetime.strptime(b, TIME_FORMAT)).total_seconds())
    except (TypeError, ValueError):
        return None


def supporting_records(conn, visit):
    """The browser-history records that back up an extension visit (same computer, browser, domain, within the covered window),
    nearest first. Empty for anything else."""
    if visit["source"] != SOURCE_BROWSER:
        return []
    rows = conn.execute("SELECT id, visited_at, reputation_status FROM web_visits WHERE source = 'BROWSER_HISTORY' "
                        "AND device_id = ? AND domain = ? AND IFNULL(browser, '') = IFNULL(?, '')", (visit["device_id"], visit["domain"], visit["browser"])).fetchall()
    near = [(r, _gap_seconds(r["visited_at"], visit["visited_at"])) for r in rows]
    near = [(r, g) for r, g in near if g is not None and g <= COVERED_WINDOW_SECONDS]
    return [r for r, _g in sorted(near, key=lambda item: item[1])]


def primary_record(conn, visit):
    """For a browser-history record the extension already reported: that extension visit (the primary record of the logical
    visit). None when this record is itself the primary one."""
    if visit["source"] != SOURCE_BROWSER_HISTORY:
        return None
    rows = conn.execute("SELECT id, visited_at FROM web_visits WHERE source = 'BROWSER' "
                        "AND device_id = ? AND domain = ? "
                        "AND IFNULL(browser, '') = IFNULL(?, '')", (visit["device_id"], visit["domain"], visit["browser"])).fetchall()
    near = [(r, _gap_seconds(r["visited_at"], visit["visited_at"])) for r in rows]
    near = [(r, g) for r, g in near if g is not None and g <= COVERED_WINDOW_SECONDS]
    return sorted(near, key=lambda item: item[1])[0][0] if near else None


def max_visit_id(conn):
    """Highest visit id: the polling cursor. It is NOT the id of the newest row by time -
    computers with skewed clocks insert rows whose time order differs from id order."""
    return conn.execute("SELECT IFNULL(MAX(id), 0) FROM web_visits").fetchone()[0]


def list_alerts(conn, limit=100):
    return conn.execute(
        "SELECT a.*, " + DEVICE_NAME + " AS computer_name, e.username, v.source AS visit_source FROM alerts a "
        "JOIN endpoints e ON e.id = a.endpoint_id LEFT JOIN devices d ON d.id = COALESCE(a.device_id, e.device_id) "
        "LEFT JOIN web_visits v ON v.id = a.web_visit_id "
        "ORDER BY CASE a.status WHEN 'OPEN' THEN 0 ELSE 1 END, a.created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


# What can be seen of each monitored computer RIGHT NOW (Phase 5.7: derived from each SENSOR'S OWN freshness, never from the
# sensor type or from last_seen, which a linked extension + agent share):
#   FULL          the browser extension AND the Windows agent are both reporting: website visits come from the extension and
#                 programs / connections from the agent
#   BROWSER       only the browser extension is reporting: website visits are visible, network activity is not
#   HISTORY       the agent is reporting and its history watcher can read Chrome / Edge history, but no extension is reporting:
#                 website visits come from the browser's own history (lower confidence: no private windows, nothing after the
#                 history is cleared, only Chrome and Edge)
#   NETWORK_ONLY  only the agent is reporting and it cannot read browser history: programs and connections, no website visits
#   NONE          no sensor of the computer is reporting (offline), or its timestamps are missing / unreadable (not verified)
# A sensor is "reporting" only while its own timestamp is fresh (sensor_fresh). Missing means not verified, never healthy.
# `extension_silent` is separate: the computer has an extension that has reported before (or produced a visit) but is not
# reporting now. That is a missing required sensor, so the overview says LIMITED COVERAGE instead of a clean result.
VIS_FULL, VIS_BROWSER, VIS_HISTORY, VIS_NETWORK_ONLY, VIS_NONE = "FULL", "BROWSER", "HISTORY", "NETWORK_ONLY", "NONE"


def visibility_state(extension_fresh, agent_fresh, history_watching):
    """The visibility code for what is reporting right now."""
    if extension_fresh and agent_fresh:
        return VIS_FULL
    if extension_fresh:
        return VIS_BROWSER
    if agent_fresh:
        return VIS_HISTORY if history_watching else VIS_NETWORK_ONLY
    return VIS_NONE


def sensor_signals(item, now=None):
    """What one sensor row says right now: {extension_fresh, agent_fresh, history_watching, extension_known}.
    extension_known = this installation has an extension (it registered with a browser name, reported before, or produced a
    browser visit), whether or not it is alive; used to tell a silent extension from a computer that never had one."""
    now = now or datetime.now()
    # every report refreshes last_seen too, so a sensor timestamp that is fresh while its row's last_seen is not is inconsistent
    # data: it is not verified, never healthy
    alive = sensor_fresh(item.get("last_seen"), now)
    agent_fresh = alive and item.get("agent_version") is not None and sensor_fresh(item.get("agent_seen_at"), now)
    return {
        "extension_fresh": alive and sensor_fresh(item.get("extension_seen_at"), now),
        "agent_fresh": agent_fresh,
        "history_watching": agent_fresh and bool(item.get("history_browsers")),
        "extension_known": bool(item.get("browser")) or item.get("extension_seen_at") is not None
                           or item.get("browser_visits_total", 0) > 0,
    }


def endpoint_visibility(item, now=None):
    """item: one dict from list_endpoints (before visibility is added). One sensor row only."""
    signal = sensor_signals(item, now)
    return visibility_state(signal["extension_fresh"], signal["agent_fresh"], signal["history_watching"])


def visibility_summary(endpoints):
    """What the overview needs from list_devices(): who is online without full website visibility, and how many computers
    produced website visits today. Only ONLINE computers can have incomplete visibility; computers that are simply
    offline are handled by the existing offline rules."""
    online = [e for e in endpoints if e["status"] == "ONLINE"]
    return {
        "full_visibility_names": sorted(e["computer_name"] for e in online if e["visibility"] == VIS_FULL),
        "browser_only_names": sorted(e["computer_name"] for e in online if e["visibility"] == VIS_BROWSER),
        "history_names": sorted(e["computer_name"] for e in online if e["visibility"] == VIS_HISTORY),
        "network_only_names": sorted(e["computer_name"] for e in online if e["visibility"] == VIS_NETWORK_ONLY),
        "no_visibility_names": sorted(e["computer_name"] for e in online if e["visibility"] == VIS_NONE),
        "extension_silent_names": sorted(e["computer_name"] for e in online if e.get("extension_silent")),
        "visiting_computers_today": sum(1 for e in endpoints if e["websites_today"] > 0),
    }


def list_endpoints(conn, now=None, archived=False):
    """One dict per computer (active ones by default, archived ones with archived=True),
    ONLINE first. No heartbeat history exists: status is derived from the single
    last_seen value. websites_today counts browser visits, contacted_today counts the
    distinct domains the network agent saw that the browser did not already explain."""
    now = now or datetime.now()
    rows = conn.execute(
        "SELECT e.id, e.endpoint_uid, " + DEVICE_NAME + " AS computer_name, e.computer_name AS sensor_name, e.username, e.browser, "
        "e.last_seen, e.archived_at, e.agent_version, e.history_browsers, e.agent_seen_at, e.extension_seen_at, e.device_id, e.sensor_type, e.sensor_label, "
        "e.sensor_version, e.first_seen, e.paired_at, e.revoked_at, (e.secret_hash IS NOT NULL) AS has_credential, "
        "d.identity AS device_identity, d.device_uid, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.endpoint_id = e.id AND v.device_id = e.device_id AND " + _WEBSITE + " "
        " AND v.visited_at >= :start) AS websites_today, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.endpoint_id = e.id AND v.device_id = e.device_id AND " + _WEBSITE + " "
        " AND v.visited_at >= :start AND " + _IS_THREAT + ") AS browser_threats_today, "
        "(SELECT COUNT(DISTINCT v.domain) FROM web_visits v WHERE v.endpoint_id = e.id AND v.device_id = e.device_id AND v.source = 'AGENT' AND v.dest_ip IS NULL "
        " AND v.visited_at >= :start AND NOT " + _COVERED + ") AS contacted_today, "
        "(SELECT COUNT(DISTINCT CASE WHEN " + _IS_THREAT + " THEN v.domain END) FROM web_visits v "
        " WHERE v.endpoint_id = e.id AND v.device_id = e.device_id AND v.source = 'AGENT' AND v.dest_ip IS NULL AND v.visited_at >= :start AND NOT " + _COVERED + ") AS contacted_threats_today, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.endpoint_id = e.id AND v.source = 'BROWSER') AS browser_visits_total, "     # the sensor's own history, wherever it was
        "(SELECT IFNULL(SUM(n.connections), 0) FROM network_activity n WHERE n.endpoint_id = e.id AND n.device_id = e.device_id AND n.day = :day) AS network_connections_today, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.endpoint_id = e.id AND COALESCE(a.device_id, e.device_id) = e.device_id AND a.status = 'OPEN') AS open_alerts "
        "FROM endpoints e LEFT JOIN devices d ON d.id = e.device_id WHERE e.archived_at IS " + ("NOT NULL" if archived else "NULL"),
        {"start": start_of_today(now), "day": start_of_today(now)[:10]},
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["threats_today"] = item.pop("browser_threats_today") + item.pop("contacted_threats_today")
        item["has_agent"] = item["agent_version"] is not None
        item["status"] = endpoint_status(item["last_seen"], now)
        item["visibility"] = endpoint_visibility(item, now)
        item["last_seen_label"] = last_seen_label(item["last_seen"], now)
        item["last_seen_relative"] = relative_time(item["last_seen"], now)
        result.append(item)
    result.sort(key=lambda e: (e["status"] != "ONLINE", e["computer_name"].lower()))
    return result


SENSOR_LABELS = {
    "WINDOWS_AGENT": "Windows Agent", "CHROME_EXTENSION": "Chrome Extension", "EDGE_EXTENSION": "Edge Extension",
    "BROWSER_EXTENSION": "Browser Extension", "LEGACY_COMBINED": "Browser extension + agent (linked by hand)",
    "UNKNOWN": "Unidentified sensor",
}
# Phase D2.1: what a stored identity value really means, in plain words. The stored values (VERIFIED / PROVISIONAL / LEGACY) are NOT changed: VERIFIED has
# only ever meant "a Windows Agent enrolled itself with a secret of its own". No administrator approval exists in the product yet, so no stored value
# maps to ADMIN_APPROVED; it is listed so that the day an approval is added the wording is already defined. `tone` picks the badge colour.
IDENTITY_LEVEL_ADMIN_APPROVED, IDENTITY_LEVEL_SELF_ENROLLED = "ADMIN_APPROVED", "SELF_ENROLLED"
IDENTITY_LEVEL_UNVERIFIED, IDENTITY_LEVEL_LEGACY, IDENTITY_LEVEL_UNKNOWN = "UNVERIFIED", "LEGACY", "UNKNOWN"
IDENTITY_LEVELS = (IDENTITY_LEVEL_ADMIN_APPROVED, IDENTITY_LEVEL_SELF_ENROLLED, IDENTITY_LEVEL_UNVERIFIED, IDENTITY_LEVEL_LEGACY, IDENTITY_LEVEL_UNKNOWN)
_IDENTITY_TEXT = {
    IDENTITY_LEVEL_ADMIN_APPROVED: (
        "Administrator-approved", "Administrator-approved computer",
        "An administrator confirmed that this is the computer it claims to be.", "ok"),
    IDENTITY_LEVEL_SELF_ENROLLED: (
        "Self-enrolled", "Self-enrolled computer (its Windows Agent registered itself; no administrator has approved it)",
        "A Windows Agent on this computer registered itself with a secret key of its own, so the system recognises the same installation each time. "
        "No administrator has confirmed which physical computer it is.", "info"),
    IDENTITY_LEVEL_UNVERIFIED: (
        "Unverified device", "Unverified computer (a browser installation not paired with a Windows Agent; it may not be a whole computer)",
        "This is a browser installation that has not been paired with a Windows Agent. Its name is only a label and it may not be a whole computer.", "warn"),
    IDENTITY_LEVEL_LEGACY: (
        "Unverified (legacy)", "Unverified computer (recorded before devices existed; identity not confirmed)",
        "This installation was recorded before computers were tracked as devices. Nothing has confirmed which physical computer it is, "
        "and it has not been merged with any other record.", "warn"),
    IDENTITY_LEVEL_UNKNOWN: (
        "Unknown identity", "Unknown identity (no identity information is recorded for this computer)",
        "The system holds no usable identity information for this computer.", "warn"),
}
_IDENTITY_LEVEL_OF = {IDENTITY_VERIFIED: IDENTITY_LEVEL_SELF_ENROLLED, IDENTITY_PROVISIONAL: IDENTITY_LEVEL_UNVERIFIED, IDENTITY_LEGACY: IDENTITY_LEVEL_LEGACY}


def identity_presentation(identity, admin_approved=False):
    """The wording for a stored device identity. Additive presentation only: it never decides identity, matching or access. `admin_approved` is for the
    future approval feature; nothing passes True today, so no computer is ever shown as administrator-approved."""
    level = IDENTITY_LEVEL_ADMIN_APPROVED if admin_approved else _IDENTITY_LEVEL_OF.get(identity, IDENTITY_LEVEL_UNKNOWN)
    short, label, explanation, tone = _IDENTITY_TEXT[level]
    return {"level": level, "short": short, "label": label, "explanation": explanation, "tone": tone,
            "admin_approved": level == IDENTITY_LEVEL_ADMIN_APPROVED}


IDENTITY_LABELS = dict((value, identity_presentation(value)["label"]) for value in (IDENTITY_VERIFIED, IDENTITY_PROVISIONAL, IDENTITY_LEGACY))


def device_name(conn, endpoint_id):
    """The name of the computer a sensor belongs to (see DEVICE_NAME)."""
    row = conn.execute("SELECT " + DEVICE_NAME + " AS n FROM endpoints e LEFT JOIN devices d ON d.id = e.device_id WHERE e.id = ?",
                       (endpoint_id,)).fetchone()
    return row["n"] if row else ""


def visit_device_name(conn, visit_id):
    """The name of the computer a VISIT belongs to (the device of the time it happened, see DEVICE_NAME): what an alert's text must say, even when the visit
    reaches the server after its sensor moved to another computer."""
    row = conn.execute("SELECT " + DEVICE_NAME + " AS n FROM web_visits v JOIN endpoints e ON e.id = v.endpoint_id LEFT JOIN devices d ON d.id = v.device_id WHERE v.id = ?",
                       (visit_id,)).fetchone()
    return row["n"] if row else ""


def _sensor_view(item, now):
    """One sensor of a computer for the Computers page. Its status is its OWN heartbeat, never its device's."""
    collectors = []
    signal = sensor_signals(item, now)
    if item["sensor_type"] in ("WINDOWS_AGENT", "LEGACY_COMBINED") or item["agent_version"] is not None:
        # the agent's OWN timestamp decides, not the row's shared last_seen (an extension beat must not make the agent look alive)
        online = signal["agent_fresh"]
        watching = signal["history_watching"]
        collectors.append({"name": "Browser history", "state": "Active collector" if watching else ("Not available" if online else "Agent not reporting")})
        collectors.append({"name": "Network monitoring",
                           "state": ("Active - %d connections today" % item["network_connections_today"]) if item["network_connections_today"] and online
                           else ("No activity seen today" if online else "Agent not reporting")})
    if signal["extension_known"] or item["sensor_type"] in ("LEGACY_COMBINED", "CHROME_EXTENSION", "EDGE_EXTENSION", "BROWSER_EXTENSION"):
        if signal["extension_fresh"]:
            state = "Reporting"
        elif item.get("extension_seen_at"):
            state = "Not reporting since %s" % last_seen_label(item["extension_seen_at"], now)
        else:
            state = "Not verified (no extension report recorded)"
        collectors.append({"name": "Browser extension", "state": state})
    return {
        "id": item["id"], "type": item["sensor_type"], "type_label": SENSOR_LABELS.get(item["sensor_type"], SENSOR_LABELS["UNKNOWN"]),
        "browser": item["browser"], "name": item["sensor_name"], "label": item["sensor_label"] or "", "status": item["status"],
        "last_seen_label": item["last_seen_label"], "last_seen_relative": item["last_seen_relative"],
        "version": item["sensor_version"] or item["agent_version"] or "", "paired": bool(item["has_credential"]) and not item["revoked_at"],
        "revoked": bool(item["revoked_at"]), "collectors": collectors,
        "collectors_text": "; ".join("%s: %s" % (c["name"], c["state"]) for c in collectors),
    }


def _visibility_note(visibility, extension_silent, uncovered, history_watching, sensors, now):
    """The sentence under a computer's visibility label that names what is missing."""
    notes = []
    if extension_silent:
        seen = max((s["extension_seen_at"] for s in sensors if s.get("extension_seen_at")), default=None)
        notes.append("The browser extension is not reporting%s." % ((" (last report %s)" % last_seen_label(seen, now)) if seen else
                                                                    " (no report recorded, so it is not verified)"))
        if visibility == VIS_HISTORY:
            notes.append("Website visits are seen only through the agent's browser history.")
        elif visibility == VIS_NETWORK_ONLY:
            notes.append("Website visits cannot be seen.")
    elif uncovered:
        notes.append("%s only through browser history (no extension confirmed for it)." % " and ".join(uncovered))
    return " ".join(notes)


def _device_item(sensors, now):
    """One computer from the sensors that belong to it (rows of list_endpoints)."""
    sensors = sorted(sensors, key=lambda s: s["id"])
    first = sensors[0]
    online = [s for s in sensors if s["status"] == "ONLINE"]
    agent = next((s for s in sensors if s["agent_version"] is not None), None)
    # The computer's visibility comes from what its sensors are doing NOW, combined: an extension on one row and an agent on
    # another (or both on one linked row) make FULL; neither the sensor type nor last_seen can create it.
    signals = [sensor_signals(s, now) for s in sensors]
    extension_fresh = any(g["extension_fresh"] for g in signals)
    agent_fresh = any(g["agent_fresh"] for g in signals)
    history_watching = any(g["history_watching"] for g in signals)
    best = visibility_state(extension_fresh, agent_fresh, history_watching)
    # an extension that has reported before (or produced a visit) but is silent now is a MISSING sensor
    extension_silent = any(g["extension_known"] for g in signals) and not extension_fresh
    # browsers the agent can read but no reporting extension is known to cover are seen through their history only. A linked row
    # records only the browser that last reported, so any other history browser is conservatively listed as history only.
    covered = set(s["browser"] for s, g in zip(sensors, signals) if s["browser"] and g["extension_fresh"])
    history = [b for b in (agent["history_browsers"] or "").split(",") if b] if (agent is not None and agent_fresh) else []
    uncovered = [b for b in history if b not in covered] if (agent_fresh and not extension_silent) else []
    last_seen = max(s["last_seen"] for s in sensors)
    item = {
        "id": first["id"], "device_id": first["device_id"], "endpoint_uid": first["endpoint_uid"],
        "computer_name": first["computer_name"], "username": next((s["username"] for s in sensors if s["username"]), None),
        "browser": ", ".join(sorted(set(s["browser"] for s in sensors if s["browser"]))) or None,
        "last_seen": last_seen, "archived_at": min(s["archived_at"] or "" for s in sensors) or None,
        "status": "ONLINE" if online else "OFFLINE", "visibility": best,
        "last_seen_label": last_seen_label(last_seen, now), "last_seen_relative": relative_time(last_seen, now),
        "identity": first["device_identity"] or IDENTITY_PROVISIONAL,
        "has_agent": agent is not None, "agent_version": agent["agent_version"] if agent is not None else None,
        "history_browsers": agent["history_browsers"] if agent is not None else None,
        "agent_seen_at": agent["agent_seen_at"] if agent is not None else None,
        "websites_today": sum(s["websites_today"] for s in sensors), "contacted_today": sum(s["contacted_today"] for s in sensors),
        "threats_today": sum(s["threats_today"] for s in sensors), "open_alerts": sum(s["open_alerts"] for s in sensors),
        "browser_visits_total": sum(s["browser_visits_total"] for s in sensors),
        "extension_silent": extension_silent,
        "extension_seen_at": max((s["extension_seen_at"] for s in sensors if s.get("extension_seen_at")), default=None),
        "agent_fresh": agent_fresh, "extension_fresh": extension_fresh,
        "visibility_note": _visibility_note(best, extension_silent, uncovered, history_watching, sensors, now),
        "sensors": [_sensor_view(s, now) for s in sensors],
    }
    shown = identity_presentation(first["device_identity"])
    item["identity_label"] = shown["label"]
    item["verified"] = item["identity"] == IDENTITY_VERIFIED        # contract kept: it has only ever meant "enrolled by a Windows Agent", NOT administrator approval
    item["identity_level"], item["identity_short"] = shown["level"], shown["short"]
    item["identity_explanation"], item["identity_tone"] = shown["explanation"], shown["tone"]
    item["identity_admin_approved"] = shown["admin_approved"]
    item["sensor_count"] = len(sensors)
    item["online_sensor_count"] = len(online)
    item["former_device"] = False
    return item


FORMER_DEVICE_NOTE = ("This computer has no sensor any more: its last sensor now belongs to another computer. Its earlier records are kept here, "
                      "and it stays listed as not reporting until an administrator archives it.")


def _former_device_item(conn, device, now):
    """A computer that LOST ITS LAST SENSOR (the sensor was paired to another device). Its history stays attributed to it, it is shown as not reporting,
    and it stays listed until an administrator archives it (nothing is hidden because a sensor moved)."""
    params = {"d": device["id"], "start": start_of_today(now), "day": start_of_today(now)[:10]}
    counts = conn.execute(
        "SELECT (SELECT COUNT(*) FROM web_visits v WHERE v.device_id = :d AND " + _WEBSITE + " AND v.visited_at >= :start) AS websites_today, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.device_id = :d AND " + _WEBSITE + " AND v.visited_at >= :start AND " + _IS_THREAT + ") AS browser_threats, "
        "(SELECT COUNT(DISTINCT v.domain) FROM web_visits v WHERE v.device_id = :d AND v.source = 'AGENT' AND v.dest_ip IS NULL AND v.visited_at >= :start AND NOT " + _COVERED + ") AS contacted_today, "
        "(SELECT COUNT(DISTINCT CASE WHEN " + _IS_THREAT + " THEN v.domain END) FROM web_visits v WHERE v.device_id = :d AND v.source = 'AGENT' "
        " AND v.dest_ip IS NULL AND v.visited_at >= :start AND NOT " + _COVERED + ") AS contacted_threats, "
        "(SELECT COUNT(*) FROM web_visits v WHERE v.device_id = :d AND v.source = 'BROWSER') AS browser_visits_total, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.device_id = :d AND a.status = 'OPEN') AS open_alerts", params).fetchone()
    last_seen = device["last_seen"] or device["created_at"]
    shown = identity_presentation(device["identity"])
    return {
        "id": "d%d" % device["id"], "device_id": device["id"], "endpoint_uid": None, "computer_name": device["display_name"], "username": None, "browser": None,
        "last_seen": last_seen, "archived_at": device["archived_at"], "status": "OFFLINE", "visibility": VIS_NONE,
        "last_seen_label": last_seen_label(last_seen, now), "last_seen_relative": relative_time(last_seen, now),
        "identity": device["identity"] or IDENTITY_PROVISIONAL, "has_agent": False, "agent_version": None, "history_browsers": None, "agent_seen_at": None,
        "websites_today": counts["websites_today"], "contacted_today": counts["contacted_today"],
        "threats_today": counts["browser_threats"] + counts["contacted_threats"], "open_alerts": counts["open_alerts"],
        "browser_visits_total": counts["browser_visits_total"], "extension_silent": False, "extension_seen_at": None, "agent_fresh": False, "extension_fresh": False,
        "visibility_note": FORMER_DEVICE_NOTE, "sensors": [], "identity_label": shown["label"], "verified": device["identity"] == IDENTITY_VERIFIED,
        "identity_level": shown["level"], "identity_short": shown["short"], "identity_explanation": shown["explanation"], "identity_tone": shown["tone"],
        "identity_admin_approved": shown["admin_approved"], "sensor_count": 0, "online_sensor_count": 0, "former_device": True,
    }


def list_devices(conn, now=None, archived=False):
    """One dict per COMPUTER (a device with at least one active sensor; with archived=True, one whose sensors are all archived),
    ONLINE first. A computer is online while ANY of its sensors is; each sensor keeps its own status."""
    now = now or datetime.now()
    active = list_endpoints(conn, now, archived=False)
    by_device = {}
    for sensor in active:
        by_device.setdefault(sensor["device_id"], []).append(sensor)
    if archived:
        by_device = {}
        active_ids = set(s["device_id"] for s in active)
        for sensor in list_endpoints(conn, now, archived=True):
            if sensor["device_id"] not in active_ids:
                by_device.setdefault(sensor["device_id"], []).append(sensor)
    result = [_device_item(group, now) for group in by_device.values()]
    # FORMER devices: no sensor at all. Active ones are listed (not reporting) until archived; archived ones appear in the archived list.
    for device in conn.execute("SELECT * FROM devices d WHERE NOT EXISTS (SELECT 1 FROM endpoints s WHERE s.device_id = d.id) "
                               "AND EXISTS (SELECT 1 FROM sensor_device_associations a WHERE a.device_id = d.id) AND d.archived_at IS " +
                               ("NOT NULL" if archived else "NULL") + " ORDER BY d.id").fetchall():
        result.append(_former_device_item(conn, device, now))
    result.sort(key=lambda e: (e["status"] != "ONLINE", e["computer_name"].lower(), str(e["id"])))
    return result


def count_archived(conn):
    """Computers whose every sensor is archived, plus archived former devices (computers that lost their last sensor)."""
    sensors = conn.execute("SELECT COUNT(*) FROM (SELECT device_id FROM endpoints GROUP BY device_id HAVING SUM(archived_at IS NULL) = 0)").fetchone()[0]
    former = conn.execute("SELECT COUNT(*) FROM devices d WHERE d.archived_at IS NOT NULL AND NOT EXISTS (SELECT 1 FROM endpoints s WHERE s.device_id = d.id) "
                          "AND EXISTS (SELECT 1 FROM sensor_device_associations a WHERE a.device_id = d.id)").fetchone()[0]
    return sensors + former


def set_archived(conn, endpoint_id, archived):
    """Archive (hide from the Computers page and the dashboard counts) or restore a computer: every sensor of the device the given
    sensor belongs to. Nothing is deleted: its visits and alerts stay. Returns False if the id does not exist."""
    stamp = now_str() if archived else None
    row = conn.execute("SELECT device_id FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
    if row is None:
        return False
    conn.execute("UPDATE endpoints SET archived_at = ? WHERE device_id = ?", (stamp, row["device_id"]))
    conn.commit()
    return True


def set_former_device_archived(conn, device_id, archived):
    """Archive (or restore) a FORMER device - a computer that has no sensor any more - so an administrator decides when it leaves the lists. A device that
    still has sensors is archived through its sensors (set_archived). Nothing is deleted: its visits, alerts and counters stay attributed to it.
    Returns False when there is no such former device."""
    device = conn.execute("SELECT id FROM devices WHERE id = ? AND EXISTS (SELECT 1 FROM sensor_device_associations WHERE device_id = ?)", (device_id, device_id)).fetchone()
    if device is None or conn.execute("SELECT 1 FROM endpoints WHERE device_id = ? LIMIT 1", (device_id,)).fetchone() is not None:
        return False
    conn.execute("UPDATE devices SET archived_at = ? WHERE id = ?", (now_str() if archived else None, device_id))
    conn.commit()
    return True
