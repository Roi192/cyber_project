# ==================================================
# PHASE 11C: BEHAVIORAL BASELINE & EXPLAINABLE ANOMALY DETECTION
# ==================================================
#
# This module is the single shared source of truth for behavioral
# baseline schema, configuration, novelty checks, and scoring -
# used by BOTH behavioral_worker.py (bootstrap + live processing)
# and any future historical-replay tool, so the no-future-leakage
# rule can never drift between two copies of similar logic.
#
# This is NOT malware classification, NOT proof of compromise, NOT
# an AI verdict, and NEVER creates a Security Alert/Incident/
# Response Command on its own. "Unusual" means "unusual compared
# with previously observed telemetry for THIS endpoint" - nothing
# more. It is explicitly independent from the existing Threat Risk
# (web_events.risk_score/severity) engine - never reads it, never
# writes it, never modifies it.
#
# BOOTSTRAP CUTOFF: the single moment this engine first runs. Every
# trusted/analyzed Agent event with event_time <= the cutoff is
# TRAINING HISTORY ONLY (used to populate the aggregate "seen"
# tables and initial maturity state) and NEVER receives an anomaly
# score - scoring events that predate the engine's own existence
# would misrepresent the platform as having detected something it
# did not detect at the time. Every event with event_time > the
# cutoff is scored LIVE, using only baseline state that existed
# strictly BEFORE that event (see evaluate_live_event()).
# ==================================================

import json
import os
import db_config
import sqlite3
from datetime import datetime, timedelta


# --------------------------------------------------
# DB (same SOC_DB_PATH override convention as every other module)
# --------------------------------------------------

_soc_db_path_override = os.getenv("SOC_DB_PATH", "").strip()

if _soc_db_path_override:
    if os.path.isabs(_soc_db_path_override):
        DB_NAME = _soc_db_path_override
    else:
        DB_NAME = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            _soc_db_path_override
        )
else:
    DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersec.db")


def get_db_connection():

    # Phase 12B.6C.1: central policy (WAL, busy timeout, synchronous=FULL,
    # tracked so a request/iteration can always release it).
    return db_config.open_connection(DB_NAME)


# --------------------------------------------------
# CONFIGURATION CONSTANTS (centralized, not scattered)
# --------------------------------------------------

# Maturity thresholds - derived from the Phase 11C audit's real
# observed data (the two real trusted endpoints have thousands of
# events and 4-5 active days, and were expected to land in
# ESTABLISHING, not LEARNING or READY, once bootstrapped).
LEARNING_MAX_ACTIVE_DAYS = 3          # < this many active days...
LEARNING_MAX_EVENTS = 200             # ...OR fewer than this many analyzed events => LEARNING
READY_MIN_ACTIVE_DAYS = 7
READY_MIN_EVENTS = 1000
READY_MIN_CALENDAR_COVERAGE_DAYS = 7  # span from first to last active day

# Confidence sub-banding inside ESTABLISHING.
ESTABLISHING_MEDIUM_MIN_EVENTS = 500
ESTABLISHING_MEDIUM_MIN_ACTIVE_DAYS = 5

# Anomaly score contributions - approved as initial configurable
# constants. Every non-zero contribution must produce a factual
# reason string (see evaluate_live_event()). is_script_related
# NEVER contributes (display-only context, per the approved design).
NEW_PROCESS_POINTS = 25
NEW_DESTINATION_POINTS = 15
NEW_PAIR_POINTS = 20
TEMPORAL_DEVIATION_POINTS = 10   # READY maturity only
NEW_USER_PROCESS_POINTS = 15     # only when a real os_username exists
NEW_HASH_POINTS = 15             # only when a real sha256 exists (SHA-256 only, never MD5)
SCORE_CAP = 100

# Centralized TYPICAL vs UNUSUAL threshold - one shared function
# (behavioral_label()) below decides this; templates/routes must
# never reinterpret the number themselves. Chosen so that a single
# common, weak signal alone (e.g. one first-time destination, +15 -
# the audit measured a 24-44% destination singleton rate) never by
# itself crosses into UNUSUAL; a genuinely combined signal (e.g.
# new process +25 + new destination +15 = 40, or new process +25 +
# new pair is not possible together per the combination rules, but
# new process + new user-process +25+15=40) does.
UNUSUAL_THRESHOLD = 40

# Reason strings - fixed, factual, never "malicious"/"infected"/
# "compromised".
REASON_NEW_PROCESS = "Process not previously observed on this endpoint."
REASON_NEW_DESTINATION = "Destination not previously observed on this endpoint."
REASON_NEW_PAIR = "Process/destination pair not previously observed on this endpoint."
REASON_TEMPORAL = "Activity outside this endpoint's established active hours."
REASON_NEW_USER_PROCESS = "OS user not previously associated with this process on this endpoint."
REASON_NEW_HASH = "Executable SHA-256 not previously observed on this endpoint."
REASON_LATE_EVENT = (
    "Event arrived after newer endpoint activity had already been "
    "incorporated into the behavioral baseline."
)

UNKNOWN_PROCESS_SENTINEL = "unknown"


# --------------------------------------------------
# SCHEMA (additive only - new tables, zero changes to any existing
# evidentiary table: web_events, endpoints, security_alerts,
# security_events, response_commands, threat_indicators)
# --------------------------------------------------

def init_behavioral_db():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_engine_config (
            config_key TEXT PRIMARY KEY,
            config_value TEXT NOT NULL,
            set_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_baseline_state (
            endpoint_ip TEXT PRIMARY KEY,
            maturity_state TEXT NOT NULL DEFAULT 'LEARNING',
            active_days INTEGER NOT NULL DEFAULT 0,
            calendar_coverage_days INTEGER NOT NULL DEFAULT 0,
            analyzed_event_count INTEGER NOT NULL DEFAULT 0,
            first_event_time TEXT,
            latest_event_time_incorporated TEXT,
            bootstrap_completed INTEGER NOT NULL DEFAULT 0,
            bootstrap_last_event_id INTEGER,
            last_recomputed_at TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_active_days (
            endpoint_ip TEXT NOT NULL,
            activity_date TEXT NOT NULL,
            PRIMARY KEY (endpoint_ip, activity_date)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_seen_processes (
            endpoint_ip TEXT NOT NULL,
            process_name TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (endpoint_ip, process_name)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_seen_destinations (
            endpoint_ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (endpoint_ip, domain)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_seen_process_destination (
            endpoint_ip TEXT NOT NULL,
            process_name TEXT NOT NULL,
            domain TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (endpoint_ip, process_name, domain)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_seen_user_process (
            endpoint_ip TEXT NOT NULL,
            os_username TEXT NOT NULL,
            process_name TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (endpoint_ip, os_username, process_name)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_seen_hashes (
            endpoint_ip TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (endpoint_ip, sha256)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_hourly_activity (
            endpoint_ip TEXT NOT NULL,
            hour_of_day INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (endpoint_ip, hour_of_day)
        )
    """)

    # One row per LIVE (post-cutoff) event only - bootstrap/training
    # events never get a row here (see module docstring). The
    # UNIQUE constraint on web_event_id is a defense-in-depth
    # crash-safety guarantee alongside the worker's own "claim via
    # LEFT JOIN" query - an event can never be scored twice.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_event_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            web_event_id INTEGER NOT NULL UNIQUE,
            endpoint_ip TEXT NOT NULL,
            event_time TEXT NOT NULL,
            evaluation_status TEXT NOT NULL,
            anomaly_score INTEGER,
            maturity_state_at_evaluation TEXT,
            confidence TEXT,
            behavioral_reasons TEXT,
            temporal_status TEXT,
            computed_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_behavioral_event_results_endpoint
        ON behavioral_event_results(endpoint_ip)
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------
# BOOTSTRAP CUTOFF (persistent, set once, never recomputed)
# --------------------------------------------------

def get_or_create_bootstrap_cutoff(conn):

    row = conn.execute("""
        SELECT config_value FROM behavioral_engine_config
        WHERE config_key = 'bootstrap_cutoff'
    """).fetchone()

    if row is not None:
        return row["config_value"]

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        INSERT OR IGNORE INTO behavioral_engine_config (config_key, config_value, set_at)
        VALUES ('bootstrap_cutoff', ?, ?)
    """, (now, now))

    conn.commit()

    row = conn.execute("""
        SELECT config_value FROM behavioral_engine_config
        WHERE config_key = 'bootstrap_cutoff'
    """).fetchone()

    return row["config_value"]


# --------------------------------------------------
# MATURITY / CONFIDENCE
# --------------------------------------------------

def compute_maturity_state(active_days, calendar_coverage_days, analyzed_event_count):

    if active_days < LEARNING_MAX_ACTIVE_DAYS or analyzed_event_count < LEARNING_MAX_EVENTS:
        return "LEARNING"

    if (
        active_days >= READY_MIN_ACTIVE_DAYS
        and analyzed_event_count >= READY_MIN_EVENTS
        and calendar_coverage_days >= READY_MIN_CALENDAR_COVERAGE_DAYS
    ):
        return "READY"

    return "ESTABLISHING"


def compute_confidence(maturity_state, active_days, analyzed_event_count):

    if maturity_state == "LEARNING":
        return None

    if maturity_state == "READY":
        return "HIGH"

    # ESTABLISHING
    if (
        analyzed_event_count >= ESTABLISHING_MEDIUM_MIN_EVENTS
        and active_days >= ESTABLISHING_MEDIUM_MIN_ACTIVE_DAYS
    ):
        return "MEDIUM"

    return "LOW"


def behavioral_label(evaluation_status, anomaly_score):

    # Single shared function - the ONLY place that turns a stored
    # (evaluation_status, anomaly_score) pair into a display label.
    # Never reimplemented in a template or route.

    if evaluation_status == "LEARNING":
        return "LEARNING"

    if evaluation_status in ("LATE_EVENT", "ERROR"):
        return "NOT SCORED"

    if evaluation_status == "SCORED":

        if anomaly_score is not None and anomaly_score >= UNUSUAL_THRESHOLD:
            return "UNUSUAL"

        return "TYPICAL"

    return "NOT SCORED"


# --------------------------------------------------
# BASELINE STATE HELPERS
# --------------------------------------------------

def get_or_init_baseline_state(conn, endpoint_ip):

    row = conn.execute("""
        SELECT * FROM behavioral_baseline_state WHERE endpoint_ip = ?
    """, (endpoint_ip,)).fetchone()

    if row is not None:
        return dict(row)

    conn.execute("""
        INSERT INTO behavioral_baseline_state (
            endpoint_ip, maturity_state, active_days, calendar_coverage_days,
            analyzed_event_count, first_event_time, latest_event_time_incorporated,
            bootstrap_completed, bootstrap_last_event_id, last_recomputed_at
        ) VALUES (?, 'LEARNING', 0, 0, 0, NULL, NULL, 0, NULL, NULL)
    """, (endpoint_ip,))

    row = conn.execute("""
        SELECT * FROM behavioral_baseline_state WHERE endpoint_ip = ?
    """, (endpoint_ip,)).fetchone()

    return dict(row)


def _recompute_active_days(conn, endpoint_ip):

    row = conn.execute("""
        SELECT COUNT(*) AS active_days, MIN(activity_date) AS first_day, MAX(activity_date) AS last_day
        FROM behavioral_active_days WHERE endpoint_ip = ?
    """, (endpoint_ip,)).fetchone()

    active_days = row["active_days"] or 0

    calendar_coverage_days = 0

    if row["first_day"] and row["last_day"]:

        first = datetime.strptime(row["first_day"], "%Y-%m-%d")
        last = datetime.strptime(row["last_day"], "%Y-%m-%d")

        calendar_coverage_days = (last - first).days + 1

    return active_days, calendar_coverage_days


def _is_usable_process(process_name):

    return bool(
        process_name
        and process_name.strip().lower() != UNKNOWN_PROCESS_SENTINEL
    )


def _incorporate_into_aggregates(conn, endpoint_ip, event):

    # Upserts the "seen" aggregate tables and advances the
    # per-endpoint watermark/day/count state. Shared by BOTH the
    # bootstrap path and the live path (called only AFTER scoring
    # on the live path, per the required ordering) - this is what
    # keeps novelty checks O(distinct history) instead of O(total
    # web_events rows) as the table grows, and what makes
    # first-seen/occurrence facts consistent regardless of which
    # path incorporated them.

    event_time = event["event_time"]
    process_name = event["process_name"]
    domain = event["domain"]
    os_username = event["os_username"]
    sha256 = event["sha256"]

    activity_date = event_time[:10]

    conn.execute("""
        INSERT OR IGNORE INTO behavioral_active_days (endpoint_ip, activity_date)
        VALUES (?, ?)
    """, (endpoint_ip, activity_date))

    process_usable = _is_usable_process(process_name)

    if process_usable:

        conn.execute("""
            INSERT INTO behavioral_seen_processes (endpoint_ip, process_name, first_seen_at, last_seen_at, occurrence_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(endpoint_ip, process_name) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                occurrence_count = occurrence_count + 1
        """, (endpoint_ip, process_name, event_time, event_time))

    if domain:

        conn.execute("""
            INSERT INTO behavioral_seen_destinations (endpoint_ip, domain, first_seen_at, last_seen_at, occurrence_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(endpoint_ip, domain) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                occurrence_count = occurrence_count + 1
        """, (endpoint_ip, domain, event_time, event_time))

    if process_usable and domain:

        conn.execute("""
            INSERT INTO behavioral_seen_process_destination (endpoint_ip, process_name, domain, first_seen_at, last_seen_at, occurrence_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(endpoint_ip, process_name, domain) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                occurrence_count = occurrence_count + 1
        """, (endpoint_ip, process_name, domain, event_time, event_time))

    if process_usable and os_username:

        conn.execute("""
            INSERT INTO behavioral_seen_user_process (endpoint_ip, os_username, process_name, first_seen_at, last_seen_at, occurrence_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(endpoint_ip, os_username, process_name) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                occurrence_count = occurrence_count + 1
        """, (endpoint_ip, os_username, process_name, event_time, event_time))

    if sha256:

        conn.execute("""
            INSERT INTO behavioral_seen_hashes (endpoint_ip, sha256, first_seen_at, last_seen_at, occurrence_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(endpoint_ip, sha256) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                occurrence_count = occurrence_count + 1
        """, (endpoint_ip, sha256, event_time, event_time))

    hour_of_day = int(event_time[11:13])

    conn.execute("""
        INSERT INTO behavioral_hourly_activity (endpoint_ip, hour_of_day, occurrence_count)
        VALUES (?, ?, 1)
        ON CONFLICT(endpoint_ip, hour_of_day) DO UPDATE SET
            occurrence_count = occurrence_count + 1
    """, (endpoint_ip, hour_of_day))

    active_days, calendar_coverage_days = _recompute_active_days(conn, endpoint_ip)

    state = get_or_init_baseline_state(conn, endpoint_ip)

    new_count = state["analyzed_event_count"] + 1

    new_maturity = compute_maturity_state(active_days, calendar_coverage_days, new_count)

    first_event_time = state["first_event_time"] or event_time

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        UPDATE behavioral_baseline_state
        SET
            maturity_state = ?,
            active_days = ?,
            calendar_coverage_days = ?,
            analyzed_event_count = ?,
            first_event_time = ?,
            latest_event_time_incorporated = ?,
            last_recomputed_at = ?
        WHERE endpoint_ip = ?
    """, (
        new_maturity, active_days, calendar_coverage_days, new_count,
        first_event_time, event_time, now_str, endpoint_ip
    ))


def incorporate_bootstrap_event(conn, endpoint_ip, event):

    # Training only - populates aggregates/maturity, never scores,
    # never writes behavioral_event_results.
    _incorporate_into_aggregates(conn, endpoint_ip, event)

    conn.execute("""
        UPDATE behavioral_baseline_state
        SET bootstrap_last_event_id = ?
        WHERE endpoint_ip = ?
    """, (event["id"], endpoint_ip))


def mark_bootstrap_complete(conn, endpoint_ip):

    conn.execute("""
        UPDATE behavioral_baseline_state
        SET bootstrap_completed = 1
        WHERE endpoint_ip = ?
    """, (endpoint_ip,))


# --------------------------------------------------
# LIVE SCORING
# --------------------------------------------------

def evaluate_live_event(conn, endpoint_ip, event):

    # Strict required order: READ PRIOR BASELINE -> SCORE CURRENT
    # EVENT -> STORE RESULT -> UPDATE BASELINE WITH CURRENT EVENT.
    # Caller (behavioral_worker.py) wraps this whole function in one
    # transaction and commits/rolls back atomically - an event can
    # never be partially incorporated.

    event_time = event["event_time"]
    process_name = event["process_name"]
    domain = event["domain"]
    os_username = event["os_username"]
    sha256 = event["sha256"]
    is_script_related = event["is_script_related"]

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- READ PRIOR BASELINE ---
    state = get_or_init_baseline_state(conn, endpoint_ip)

    watermark = state["latest_event_time_incorporated"]

    if watermark and event_time < watermark:

        # LATE / OUT-OF-ORDER EVENT: never scored against baseline
        # state that was actually built from events AFTER this one
        # in time. Not incorporated into aggregates either (safest
        # MVP choice - avoids any risk of corrupting first-seen
        # semantics for a timestamp that is behind the watermark).
        conn.execute("""
            INSERT INTO behavioral_event_results (
                web_event_id, endpoint_ip, event_time, evaluation_status,
                anomaly_score, maturity_state_at_evaluation, confidence,
                behavioral_reasons, temporal_status, computed_at
            ) VALUES (?, ?, ?, 'LATE_EVENT', NULL, ?, NULL, ?, NULL, ?)
        """, (
            event["id"], endpoint_ip, event_time, state["maturity_state"],
            json.dumps([REASON_LATE_EVENT]), now_str
        ))

        return

    prior_maturity = state["maturity_state"]

    if prior_maturity == "LEARNING":

        # Still collect history (aggregates), but no score - avoids
        # both flooding analysts during cold start and falsely
        # claiming "typical" before there is any real baseline.
        conn.execute("""
            INSERT INTO behavioral_event_results (
                web_event_id, endpoint_ip, event_time, evaluation_status,
                anomaly_score, maturity_state_at_evaluation, confidence,
                behavioral_reasons, temporal_status, computed_at
            ) VALUES (?, ?, ?, 'LEARNING', NULL, 'LEARNING', NULL, '[]', 'INSUFFICIENT_HISTORY', ?)
        """, (event["id"], endpoint_ip, event_time, now_str))

        _incorporate_into_aggregates(conn, endpoint_ip, event)

        return

    # --- SCORE CURRENT EVENT (ESTABLISHING or READY) ---
    process_usable = _is_usable_process(process_name)

    score = 0
    reasons = []

    process_known = False
    dest_known = False
    pair_known = False

    if process_usable:
        process_known = conn.execute("""
            SELECT 1 FROM behavioral_seen_processes WHERE endpoint_ip=? AND process_name=?
        """, (endpoint_ip, process_name)).fetchone() is not None

    if domain:
        dest_known = conn.execute("""
            SELECT 1 FROM behavioral_seen_destinations WHERE endpoint_ip=? AND domain=?
        """, (endpoint_ip, domain)).fetchone() is not None

    if process_usable and domain:
        pair_known = conn.execute("""
            SELECT 1 FROM behavioral_seen_process_destination
            WHERE endpoint_ip=? AND process_name=? AND domain=?
        """, (endpoint_ip, process_name, domain)).fetchone() is not None

    # --- Combination rules (approved, no double counting) ---
    if process_usable and domain:

        if not process_known and not dest_known:
            score += NEW_PROCESS_POINTS
            reasons.append(REASON_NEW_PROCESS)
            score += NEW_DESTINATION_POINTS
            reasons.append(REASON_NEW_DESTINATION)
            # New process AND new destination together - pair is
            # necessarily new too, but is NOT separately scored.

        elif not process_known and dest_known:
            score += NEW_PROCESS_POINTS
            reasons.append(REASON_NEW_PROCESS)

        elif process_known and not dest_known:
            score += NEW_DESTINATION_POINTS
            reasons.append(REASON_NEW_DESTINATION)

        elif process_known and dest_known and not pair_known:
            score += NEW_PAIR_POINTS
            reasons.append(REASON_NEW_PAIR)

        # else: process known, destination known, pair known -> no
        # process/destination/pair contribution at all.

    elif domain and not process_usable:

        # No reliable process identity - only destination novelty
        # can be honestly assessed.
        if not dest_known:
            score += NEW_DESTINATION_POINTS
            reasons.append(REASON_NEW_DESTINATION)

    # --- Temporal (READY only) ---
    temporal_status = "INSUFFICIENT_HISTORY"

    if prior_maturity == "READY":

        temporal_status = "ACTIVE"

        hour_of_day = int(event_time[11:13])

        hour_known = conn.execute("""
            SELECT 1 FROM behavioral_hourly_activity WHERE endpoint_ip=? AND hour_of_day=?
        """, (endpoint_ip, hour_of_day)).fetchone() is not None

        if not hour_known:
            score += TEMPORAL_DEVIATION_POINTS
            reasons.append(REASON_TEMPORAL)

    # --- User -> process novelty (only when real os_username exists) ---
    if process_usable and os_username:

        user_process_known = conn.execute("""
            SELECT 1 FROM behavioral_seen_user_process
            WHERE endpoint_ip=? AND os_username=? AND process_name=?
        """, (endpoint_ip, os_username, process_name)).fetchone() is not None

        if not user_process_known:
            score += NEW_USER_PROCESS_POINTS
            reasons.append(REASON_NEW_USER_PROCESS)

    # --- Executable hash novelty (SHA-256 only, only when it exists) ---
    if sha256:

        hash_known = conn.execute("""
            SELECT 1 FROM behavioral_seen_hashes WHERE endpoint_ip=? AND sha256=?
        """, (endpoint_ip, sha256)).fetchone() is not None

        if not hash_known:
            score += NEW_HASH_POINTS
            reasons.append(REASON_NEW_HASH)

    # is_script_related: display-only, deliberately zero contribution.
    _ = is_script_related

    score = min(score, SCORE_CAP)

    confidence = compute_confidence(
        prior_maturity, state["active_days"], state["analyzed_event_count"]
    )

    # --- STORE RESULT ---
    conn.execute("""
        INSERT INTO behavioral_event_results (
            web_event_id, endpoint_ip, event_time, evaluation_status,
            anomaly_score, maturity_state_at_evaluation, confidence,
            behavioral_reasons, temporal_status, computed_at
        ) VALUES (?, ?, ?, 'SCORED', ?, ?, ?, ?, ?, ?)
    """, (
        event["id"], endpoint_ip, event_time, score, prior_maturity,
        confidence, json.dumps(reasons), temporal_status, now_str
    ))

    # --- UPDATE BASELINE WITH CURRENT EVENT (strictly after scoring) ---
    _incorporate_into_aggregates(conn, endpoint_ip, event)
