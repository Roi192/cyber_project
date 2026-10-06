import hmac
import ipaddress
import json
import os
import re
import socket
import db_config
import endpoint_identity
import endpoint_network
import process_correlation
import sqlite3
import time

from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    has_request_context
)

from threat_intelligence import (
    analyze_ip_reputation
)

from reputation_routes import (
    local_ioc_exists
)

from behavioral_analysis import (
    behavioral_label
)

from threat_intel_providers import (
    get_stored_evidence_for_event
)

import threat_intel_framework as threat_intel_fw
import threat_intel_display
import cloudflare_provider
import local_feed_evidence

from investigation_priority import (
    compute_investigation_priority,
    detect_local_ioc_matched
)


web_monitoring_bp = Blueprint(
    "web_monitoring",
    __name__
)

# Phase 11B: hash format validation, shared by ingestion
# (below) and HASH IOC matching (reputation_routes.py). Exact
# length/charset only - never used as a "looks hash-like"
# fuzzy check.
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
MD5_PATTERN = re.compile(r"^[a-f0-9]{32}$")

# SOC_DB_PATH (optional): see app.py's identical override for the
# full rationale - web_event_worker.py inherits this automatically
# via get_db_connection() below, no separate worker change needed.
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

# ==================================================
# PHASE 5: AGENT API AUTHENTICATION
# ==================================================
# python-dotenv's load_dotenv() has already populated
# os.environ by the time this module is imported (it runs at
# import time in threat_intelligence.py, which this module
# already imports above) - no second load_dotenv() call needed
# here. Read once at import time, same pattern as
# VT_API_KEY/ABUSEIPDB_API_KEY in threat_intelligence.py.
#
# Future improvement (not built in this phase): a single
# shared key is acceptable for one college-project agent. Per-
# agent tokens (e.g. an agent_keys table mapping a key hash to
# an agent identity) could replace this single constant later
# without changing the request flow or the header name.
AGENT_API_KEY = os.getenv(
    "AGENT_API_KEY",
    ""
).strip()

_AGENT_AUTH_FAIL_LOG_COOLDOWN_SECONDS = 60
_last_agent_auth_fail_log = {}


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db_connection():

    # Phase 12B.6C.1: central policy (WAL, busy timeout, synchronous=FULL,
    # tracked so a request/iteration can always release it).
    return db_config.open_connection(DB_NAME)


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

def init_web_monitoring_db():

    conn = get_db_connection()

    # --------------------------------------------------
    # ENDPOINTS
    # --------------------------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            hostname TEXT,
            status TEXT NOT NULL DEFAULT 'CONNECTED',
            last_seen TEXT,
            isolated_by TEXT,
            isolated_at TEXT
        )
    """)

    # Endpoint provenance ('source' column) is added and backfilled
    # further below, AFTER the WEB EVENTS section - the backfill
    # query reads web_events, which must already exist (fresh-DB
    # initialization ordering fix: this block used to sit here,
    # before web_events was created, which crashed
    # init_web_monitoring_db() on a genuinely empty database with
    # "no such table: web_events". Same trust model, same SQL,
    # only the position moved.

    # --------------------------------------------------
    # BLOCKED DOMAINS
    # --------------------------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            reason TEXT,
            severity TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)

    # Phase 7: distinguish policy-level blocking (this table,
    # unchanged, still drives the worker's internal ALLOWED/
    # BLOCKED decision) from REAL firewall enforcement.
    # enforcement_status is NULL until a BLOCK_DESTINATION
    # response_command reports SUCCESS; last_command_id points
    # at that command for traceability/rollback.

    blocked_domains_columns = conn.execute(
        "PRAGMA table_info(blocked_domains)"
    ).fetchall()

    blocked_domains_column_names = [
        column["name"]
        for column in blocked_domains_columns
    ]

    if "enforcement_status" not in blocked_domains_column_names:
        conn.execute("""
            ALTER TABLE blocked_domains
            ADD COLUMN enforcement_status TEXT
        """)

    if "last_command_id" not in blocked_domains_column_names:
        conn.execute("""
            ALTER TABLE blocked_domains
            ADD COLUMN last_command_id INTEGER
        """)

    # --------------------------------------------------
    # WEB EVENTS
    # --------------------------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS web_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            endpoint_ip TEXT NOT NULL,
            process_name TEXT,
            destination TEXT NOT NULL,
            domain TEXT,
            resolved_ip TEXT,
            risk_score INTEGER DEFAULT 0,
            severity TEXT DEFAULT 'INFO',
            decision TEXT NOT NULL,
            username TEXT,
            details TEXT
        )
    """)

    web_event_columns = conn.execute(
        "PRAGMA table_info(web_events)"
    ).fetchall()

    web_event_column_names = [
        column["name"]
        for column in web_event_columns
    ]

    if "process_name" not in web_event_column_names:
        conn.execute("""
            ALTER TABLE web_events
            ADD COLUMN process_name TEXT
        """)

    # --------------------------------------------------
    # PHASE 2: SAVE-FIRST / BACKGROUND ANALYSIS COLUMNS
    # --------------------------------------------------
    # Additive only (ALTER TABLE ADD COLUMN) - no existing
    # rows or columns are removed or recreated.

    web_event_columns = conn.execute(
        "PRAGMA table_info(web_events)"
    ).fetchall()

    web_event_column_names = [
        column["name"]
        for column in web_event_columns
    ]

    phase2_new_columns = {
        "analysis_status": "TEXT DEFAULT 'PENDING'",
        "analysis_started_at": "TEXT",
        "analysis_completed_at": "TEXT",
        "analysis_error": "TEXT",
        "source": "TEXT",
        "observed_ip": "TEXT",
        # Phase 3: was this event's reputation data pulled from
        # the threat_reputation cache, or fetched live from
        # VirusTotal/AbuseIPDB? NULL when no external reputation
        # lookup happened at all (private/local destination).
        "reputation_source": "TEXT",
        # How the agent attributed `destination` to this IP:
        # "dns" (forward OS DNS cache - preferred), "rdns"
        # (reverse-DNS/PTR fallback - not a confirmed forward
        # hostname), "ip" (no attribution, raw IP), or NULL for
        # rows written before this column existed, or by the
        # manual "Analyze Destination" form (no agent involved).
        # `destination` itself is always a clean hostname/IP
        # regardless of this value - this column is metadata
        # only, never mixed into the value used for DNS
        # resolution or IOC matching.
        "attribution_type": "TEXT"
    }

    for column_name, column_type in phase2_new_columns.items():

        if column_name not in web_event_column_names:

            conn.execute(f"""
                ALTER TABLE web_events
                ADD COLUMN {column_name} {column_type}
            """)

    # Backfill: rows that were analyzed synchronously under
    # the pre-Phase-2 code path already have a REAL final
    # decision (ALLOWED/BLOCKED). They must not appear as
    # PENDING to the new worker. Idempotent - safe to run on
    # every startup.
    #
    # IMPORTANT: must NOT match decision = 'PENDING' - that is
    # the placeholder value the fast /api/web-events path
    # inserts for brand-new, not-yet-analyzed rows (needed
    # because `decision` is NOT NULL). Matching it here would
    # falsely mark freshly-inserted rows as ANALYZED before the
    # worker ever processes them.

    conn.execute("""
        UPDATE web_events
        SET
            analysis_status = 'ANALYZED',
            analysis_completed_at = event_time
        WHERE
            analysis_status = 'PENDING'
            AND decision IN ('ALLOWED', 'BLOCKED')
    """)

    # --------------------------------------------------
    # PHASE 11B: ENDPOINT IDENTITY / FILE & SCRIPT TELEMETRY
    # --------------------------------------------------
    # Additive only - all nullable/optional. Old Agent payloads
    # that omit every one of these fields keep working exactly
    # as before (see receive_web_event()). `os_username` is
    # intentionally a SEPARATE column from the pre-existing
    # `username` column above, which already means something
    # unrelated (it is populated from `source`, e.g.
    # "endpoint-agent" - never a real OS user) - the two must
    # never be conflated.
    #
    # `is_script_related` has NO DEFAULT and stays nullable on
    # purpose: NULL means "telemetry unavailable / not
    # collected" (every historical row, and any row from an
    # Agent that doesn't send this field), while 0/1 mean the
    # Agent actually evaluated the process and found it
    # not-interpreter-related / interpreter-related. Collapsing
    # "unknown" into "known false" would misrepresent old data
    # as having been checked.

    web_event_columns = conn.execute(
        "PRAGMA table_info(web_events)"
    ).fetchall()

    web_event_column_names = [
        column["name"]
        for column in web_event_columns
    ]

    phase11b_new_columns = {
        "os_username": "TEXT",
        "process_pid": "INTEGER",
        "process_path": "TEXT",
        "file_name": "TEXT",
        "file_extension": "TEXT",
        "sha256": "TEXT",
        "md5": "TEXT",
        "is_script_related": "INTEGER"
    }

    for column_name, column_type in phase11b_new_columns.items():

        if column_name not in web_event_column_names:

            conn.execute(f"""
                ALTER TABLE web_events
                ADD COLUMN {column_name} {column_type}
            """)

    # --------------------------------------------------
    # ENDPOINTS - PROVENANCE BACKFILL
    # --------------------------------------------------
    # Moved here (fresh-DB initialization ordering fix) so the
    # backfill query below can safely reference web_events, which
    # is guaranteed to exist by this point - distinguishes a row
    # genuinely written by authenticated Endpoint Agent telemetry
    # ('endpoint-agent') from one written by the manual "Analyze
    # Destination" form ('manual') or from before this column
    # existed (NULL, no claim made either way). Additive only -
    # existing rows are never guessed at beyond the one-time,
    # evidence-based backfill immediately below.

    endpoint_columns = conn.execute(
        "PRAGMA table_info(endpoints)"
    ).fetchall()

    endpoint_column_names = [
        column["name"]
        for column in endpoint_columns
    ]

    if "source" not in endpoint_column_names:

        conn.execute("""
            ALTER TABLE endpoints
            ADD COLUMN source TEXT
        """)

        # One-time, conservative backfill: only mark a row
        # 'endpoint-agent' if real corroborating evidence already
        # exists in web_events for that exact IP - never inferred
        # from IP range, hostname, row count, or reverse-DNS.
        # Idempotent (guarded by the "IF NOT EXISTS"-style check
        # above; also harmless to re-run since it only ever sets
        # source where it is currently NULL and evidence exists).
        # On a fresh database, web_events is empty, so this
        # matches zero rows and is a correct no-op.

        conn.execute("""
            UPDATE endpoints
            SET source = 'endpoint-agent'
            WHERE source IS NULL
            AND ip_address IN (
                SELECT DISTINCT endpoint_ip
                FROM web_events
                WHERE source = 'endpoint-agent'
            )
        """)

    # --------------------------------------------------
    # PHASE 11B: LATEST KNOWN OS USERNAME PER ENDPOINT
    # --------------------------------------------------
    # Additive, nullable, "latest known" display attribute -
    # exactly analogous to `hostname` above. Never used for
    # endpoint identity/merge decisions: IP remains the sole
    # prototype endpoint identity, and the same-username implies
    # same-endpoint assumption is never made anywhere.

    if "last_known_os_username" not in endpoint_column_names:

        conn.execute("""
            ALTER TABLE endpoints
            ADD COLUMN last_known_os_username TEXT
        """)

    # --------------------------------------------------
    # PHASE 6: SECURITY ALERTS
    # --------------------------------------------------
    # New table, additive only (CREATE TABLE IF NOT EXISTS).
    # This is the new layer between raw detections
    # (web_events, and in future scanner findings) and
    # Incidents (security_events, unchanged table/model).
    # A future recommended_response field change doesn't
    # affect historical rows - it is stored per-alert at
    # creation time (see create_security_alert() docstring).

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            alert_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'NEW',
            endpoint_ip TEXT,
            hostname TEXT,
            process_name TEXT,
            domain TEXT,
            destination_ip TEXT,
            source TEXT,
            source_event_id INTEGER,
            detection_reasons TEXT,
            recommended_response TEXT,
            incident_id INTEGER,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            correlation_key TEXT
        )
    """)

    # Stage 25F Phase 2/4: guarded upgrade for a database created
    # BEFORE correlation_key existed in the CREATE TABLE above (same
    # pattern as every other additive column check in this function;
    # the live cybersec.db was migrated once, directly, by the Phase 2
    # one-off script - this closes the same gap for any OTHER existing
    # database).
    security_alert_columns = [
        column["name"]
        for column in conn.execute("PRAGMA table_info(security_alerts)").fetchall()
    ]

    if "correlation_key" not in security_alert_columns:
        conn.execute("ALTER TABLE security_alerts ADD COLUMN correlation_key TEXT")

    # --------------------------------------------------
    # PHASE 7: RESPONSE COMMANDS
    # --------------------------------------------------
    # New table, additive only. A command is a REQUEST for the
    # Endpoint Agent to take one of a fixed set of allowlisted
    # actions (see COMMAND_TYPES below) - the server never
    # executes OS-level actions itself (that stays in the Agent,
    # see endpoint_agent_stable.py, so the SOC server can run on
    # Linux while the Agent targets Windows).
    #
    # `mode` ('SIMULATED' or 'ENFORCED') is reported back BY THE
    # AGENT when it posts a result - the server never sets this
    # itself, so the UI can honestly show whether a real OS
    # action occurred or not (Phase 7 safety requirement).
    #
    # `reference_command_id` is used only by UNBLOCK_DESTINATION
    # to point back at the BLOCK_DESTINATION command whose
    # firewall rules must be removed (the rules are named
    # CyberProject_Block_<that command's id>, so this is how the
    # Agent finds exactly what to roll back - see Phase 7 report
    # for the exact naming rule).

    conn.execute("""
        CREATE TABLE IF NOT EXISTS response_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            endpoint_id INTEGER,
            endpoint_ip TEXT,
            hostname TEXT,
            command_type TEXT NOT NULL,
            target TEXT,
            reason TEXT,
            requested_by TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            mode TEXT,
            executed_at TEXT,
            result_message TEXT,
            alert_id INTEGER,
            incident_id INTEGER,
            reference_command_id INTEGER
        )
    """)

    # --------------------------------------------------
    # ORGANIZATION-WIDE RESPONSE / GLOBAL BLOCKLIST
    # --------------------------------------------------
    # Additive policy layer on top of response_commands - the
    # policy tables never execute PowerShell themselves and never
    # duplicate response_commands' status; every endpoint's real
    # deployment state is always computed live by joining
    # block_command_id/unblock_command_id back to response_commands
    # (see get_latest_block_command()/policy status helpers below).
    # blocked_domains is intentionally left untouched - it already
    # cannot hold more than one command reference (last_command_id
    # is a single column), so it is not a safe fit for multi-
    # endpoint fan-out ownership; that job belongs entirely to
    # global_block_policy_endpoints.block_command_id/
    # unblock_command_id, one row per (policy, endpoint).

    conn.execute("""
        CREATE TABLE IF NOT EXISTS global_block_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            scope TEXT NOT NULL,
            requested_mode TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            reason TEXT,
            source_type TEXT,
            source_id TEXT,
            requested_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            disabled_at TEXT,
            disabled_by TEXT
        )
    """)

    # Partial unique index: at most one ACTIVE policy per canonical
    # target at the DB level (belt-and-suspenders alongside the
    # application-level find_active_global_policy() check).
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
            idx_global_block_policies_active_target
        ON global_block_policies(target_type, target_value)
        WHERE active = 1
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS global_block_policy_endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER NOT NULL,
            endpoint_ip TEXT NOT NULL,
            block_command_id INTEGER,
            unblock_command_id INTEGER,
            created_at TEXT NOT NULL,
            UNIQUE(policy_id, endpoint_ip)
        )
    """)

    # --------------------------------------------------
    # PHASE 12B.6C: QUERY INDEXES FOR THE INVESTIGATION VIEW
    # --------------------------------------------------
    # Idempotent, additive, NO data change. Each index serves an exact
    # Investigation (investigation.py) query that was measured to full-scan
    # web_events (20-45 ms each at ~67k rows; ~0.03-5 ms with the index):
    #   endpoint_ip + event_time : same-endpoint window, same-process and
    #                              same-user (endpoint-scoped) queries
    #   domain + event_time      : confirmed-DNS-domain window
    #   resolved_ip + event_time : destination-IP window
    #   sha256 + event_time      : file (SHA-256) window; partial, because
    #                              only ~16% of rows carry a hash
    # Deliberately NOT created: md5 (only queried when SHA-256 is absent,
    # which no live row hits), security_alerts / response_commands indexes
    # (16 and 0 rows; lookups measured at ~0.03 ms). These columns are added
    # by the ALTER TABLE steps above, so this must stay AFTER them.
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_events_endpoint_time
        ON web_events(endpoint_ip, event_time)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_events_domain_time
        ON web_events(domain, event_time)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_events_resolved_ip_time
        ON web_events(resolved_ip, event_time)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_events_sha256_time
        ON web_events(sha256, event_time)
        WHERE sha256 IS NOT NULL
    """)

    # --------------------------------------------------
    # PHASE 12B.6D: STABLE ENDPOINT UID (additive, nullable)
    # --------------------------------------------------
    # NOT unique: two IP-based endpoint records legitimately carry the same
    # UID after an address change, and endpoint rows are never merged.
    # Historical rows stay NULL - identity is never inferred.
    for table_name in ("endpoints", "web_events"):

        column_names = [
            column["name"]
            for column in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        ]

        if "endpoint_uid" not in column_names:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN endpoint_uid TEXT")

    conn.commit()

    # --------------------------------------------------
    # PHASE 13C: ENDPOINT NETWORK CONTEXT (additive, nullable)
    # --------------------------------------------------
    # OS-observed connection metadata sent by the endpoint agent. NULL when
    # unavailable; historical rows stay NULL and nothing is ever guessed
    # (no port from the URL/domain, no protocol from the port).
    #   source_ip          the connection's LOCAL address as observed by the OS
    #                      (NOT the HTTP client IP, NOT endpoint_ip)
    #   destination_port   observed remote port, 1-65535
    #   transport_protocol 'tcp' | 'udp' - never an application protocol
    web_event_column_names = [
        column["name"]
        for column in conn.execute("PRAGMA table_info(web_events)").fetchall()
    ]

    for column_name, column_type in (
        ("source_ip", "TEXT"),
        ("destination_port", "INTEGER"),
        ("transport_protocol", "TEXT"),
    ):
        if column_name not in web_event_column_names:
            conn.execute(f"ALTER TABLE web_events ADD COLUMN {column_name} {column_type}")

    conn.commit()

    # --------------------------------------------------
    # STEP 24A: BROWSER-REPORTED URL EVENTS (additive, nullable)
    # --------------------------------------------------
    # Entirely NULL for every pre-existing (TCP/domain-level) row and for
    # every future row NOT sourced from the browser extension - existing
    # IP/domain monitoring is completely unaffected by these columns.
    #   url            the full URL as redacted by the extension BEFORE
    #                  transmission (query string/fragment already
    #                  stripped there by default - see browser_events.py).
    #                  Never the raw, un-redacted URL.
    #   url_source     'browser_extension' for rows created by
    #                  POST /api/browser-events; NULL otherwise.
    #   url_redacted   1 if the extension stripped something from this
    #                  URL before sending it, 0 if the URL had no query/
    #                  fragment to strip, NULL for non-browser rows. Lets
    #                  the UI show "(reduced)" instead of silently
    #                  presenting a redacted URL as if it were complete.
    #   browser_name   'chrome' | 'edge', as self-reported by the
    #                  extension - identity metadata only, like
    #                  endpoint_uid; never used as an authentication fact.
    #   url_nav_type   the browser's webNavigation transitionType
    #                  (e.g. 'link', 'typed', 'reload') - context only.
    #   url_dedup_key  SHA-256 of endpoint_uid|browser_name|url|raw
    #                  millisecond navigation timestamp, set ONLY for
    #                  browser-sourced rows. A UNIQUE index on this
    #                  column is the server-side duplicate-prevention
    #                  backstop required by Step 24A section 5 - a
    #                  retried/duplicated extension delivery of the same
    #                  navigation is rejected at the database level, not
    #                  merely by the agent's in-memory dedup window.
    for column_name, column_type in (
        ("url", "TEXT"),
        ("url_source", "TEXT"),
        ("url_redacted", "INTEGER"),
        ("browser_name", "TEXT"),
        ("url_nav_type", "TEXT"),
        ("url_dedup_key", "TEXT"),
    ):
        if column_name not in web_event_column_names:
            conn.execute(f"ALTER TABLE web_events ADD COLUMN {column_name} {column_type}")

    conn.commit()

    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_web_events_url_dedup_key
        ON web_events(url_dedup_key)
        WHERE url_dedup_key IS NOT NULL
    """)

    conn.commit()

    # --------------------------------------------------
    # STEP 24B.2C: ASYNC LOCAL FEED PROCESSING FOR BROWSER EVENTS
    # --------------------------------------------------
    # Entirely NULL for every non-browser row and for every browser row
    # not yet processed - existing analysis_status semantics for BOTH
    # TCP/domain rows ('PENDING'/'ANALYZING'/'ANALYZED') and the
    # permanent browser-row value ('COLLECTED', set at insert time by
    # browser_events.py) are completely untouched by this column; it is
    # a deliberately SEPARATE claim/status field so this narrow,
    # Local-Feed-only async step can never collide with or alter the
    # existing analysis_status contract any other code already depends
    # on.
    #   local_feed_status      NULL (not yet processed) -> 'PROCESSING'
    #                          (claimed by web_event_worker.py's browser
    #                          loop) -> 'CHECKED' (lookup completed,
    #                          match or no-match - see
    #                          local_feed_evidence.py; a row stuck at
    #                          'PROCESSING' past
    #                          BROWSER_LOCAL_FEED_STALE_MINUTES is swept
    #                          back to NULL for retry, mirroring
    #                          requeue_stale_analyzing()'s existing
    #                          pattern exactly).
    #   local_feed_claimed_at  claim timestamp, used only by the stale
    #                          sweep above; NULL once back to NULL.
    web_event_columns = conn.execute("PRAGMA table_info(web_events)").fetchall()
    web_event_column_names = [column["name"] for column in web_event_columns]

    for column_name, column_type in (
        ("local_feed_status", "TEXT"),
        ("local_feed_claimed_at", "TEXT"),
    ):
        if column_name not in web_event_column_names:
            conn.execute(f"ALTER TABLE web_events ADD COLUMN {column_name} {column_type}")

    conn.commit()

    # Explicit Alert <-> Event relationships (created + backfilled ONCE,
    # atomically, on first creation).
    init_alert_events_table(conn)

    # Indexes for the new access paths (measured on a snapshot copy; see
    # the 12B.6D report). Deliberately NOT created: endpoints(endpoint_uid)
    # (6-row table, 0.01 ms either way) and alert_events(alert_id, ...) (the
    # UNIQUE(alert_id, web_event_id) index already serves it).
    #   web_events(endpoint_uid, event_time)  partial: same-stable-endpoint,
    #       same-process/user by UID and identity-quality grouping
    #       (30 ms scan -> 0.6 ms)
    #   alert_events(web_event_id): "which alerts relate to this event"
    #       (Investigation, every page; 8 ms at 200k rows -> 0.01 ms)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_events_uid_time
        ON web_events(endpoint_uid, event_time)
        WHERE endpoint_uid IS NOT NULL
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_events_event
        ON alert_events(web_event_id)
    """)

    conn.commit()

    # --------------------------------------------------
    # STEP 25B: PROCESS <-> NETWORK CORRELATION (additive, nullable)
    # --------------------------------------------------
    # Entirely NULL for every pre-25B row and for every row whose source
    # pipeline provides no process-instance evidence (browser-extension
    # rows, old Agents that don't send process_create_time yet). Never
    # guessed from PID alone - see process_correlation.py's module header
    # for the full identity/evidence rules.
    #   process_instance_id        the SAME sha256 identity computed by
    #                               process_identity.compute_process_instance_id()
    #                               (endpoint_uid|pid|create_time) - the
    #                               Agent computes it when it has enough
    #                               evidence (Step 25B's TCP-loop addition);
    #                               the server independently RECOMPUTES and
    #                               verifies it, exactly like
    #                               process_events.py - never trusted as-is.
    #   process_correlation_status CONFIRMED (the referenced process
    #                               instance is known and verified) |
    #                               PENDING (a process_instance_id was
    #                               asserted and passed verification, but
    #                               no matching endpoint_process_events row
    #                               exists YET - "network event arrived
    #                               before its process event"; resolved
    #                               later by web_event_worker.py's
    #                               reconciliation sweep, or aged out to
    #                               UNAVAILABLE) | UNAVAILABLE (no evidence
    #                               ever existed, or it failed
    #                               verification) | NULL (pre-25B row, or a
    #                               source that predates this feature).
    #                               NEVER a probabilistic guess reported as
    #                               CONFIRMED.
    for column_name, column_type in (
        ("process_instance_id", "TEXT"),
        ("process_correlation_status", "TEXT"),
    ):
        if column_name not in web_event_column_names:
            conn.execute(f"ALTER TABLE web_events ADD COLUMN {column_name} {column_type}")

    conn.commit()

    # Process Detail view's main access path: "every network event for
    # this process instance, newest first" - partial (most rows will
    # never have one). event_time included so ORDER BY event_time DESC
    # is served directly from the index (no extra temp-B-tree sort step
    # - confirmed via EXPLAIN QUERY PLAN, see the Step 25B report).
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_events_process_instance
        ON web_events(process_instance_id, event_time)
        WHERE process_instance_id IS NOT NULL
    """)

    # Reconciliation sweep's access path: "the bounded PENDING backlog",
    # never a scan of the full table. See process_correlation.py.
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_events_pending_correlation
        ON web_events(id)
        WHERE process_correlation_status = 'PENDING'
    """)

    conn.commit()
    conn.close()


# ==================================================
# PHASE 12B.6D: ALERT <-> EVENT RELATIONSHIP TABLE
# ==================================================

def init_alert_events_table(conn):

    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alert_events'"
    ).fetchone():
        return None

    conn.commit()

    conn.execute("BEGIN IMMEDIATE")

    try:

        # Re-check inside the write transaction: another process (app vs
        # worker start-up) may have won the race.
        if conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alert_events'"
        ).fetchone():
            conn.rollback()
            return None

        types = ", ".join(f"'{t}'" for t in endpoint_identity.RELATIONSHIP_TYPES)

        conn.execute(f"""
            CREATE TABLE alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                web_event_id INTEGER NOT NULL,
                relationship_type TEXT NOT NULL CHECK (relationship_type IN ({types})),
                created_at TEXT NOT NULL,
                UNIQUE (alert_id, web_event_id)
            )
        """)

        counts = backfill_alert_events(conn)

        conn.commit()

    except BaseException:

        conn.rollback()
        raise

    print(
        "[alert-events] created; historical backfill from explicit evidence only: "
        f"{counts}",
        flush=True
    )

    return counts


def backfill_alert_events(conn, now=None):
    """
    ONE-TIME, CONSERVATIVE historical backfill (runs in the transaction that
    creates alert_events). Only relationships DIRECTLY supported by stored
    evidence:
      A. security_alerts.source_event_id            -> LEGACY_LATEST_REFERENCE
      B. the worker's own exact alert sentences in
         web_events.details ("Security Alert #N created" / "existing
         Security Alert #N (dedup window)"), strict regex, the alert exists
         and belongs to the SAME endpoint record as the event
                                                    -> LEGACY_TEXT_ASSOCIATION
    NEVER inferred from same endpoint / domain / IP / time / process / risk.
    Idempotent (INSERT OR IGNORE). Returns exact counts per source.
    """

    now = now or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts = {
        "latest_reference": 0,
        "text_association": 0,
        "text_skipped_alert_missing": 0,
        "text_skipped_endpoint_mismatch": 0,
    }

    cursor = conn.execute("""
        INSERT OR IGNORE INTO alert_events (alert_id, web_event_id, relationship_type, created_at)
        SELECT a.id, a.source_event_id, 'LEGACY_LATEST_REFERENCE', ?
        FROM security_alerts a
        WHERE a.source_event_id IS NOT NULL
        AND EXISTS (SELECT 1 FROM web_events w WHERE w.id = a.source_event_id)
    """, (now,))

    counts["latest_reference"] = cursor.rowcount

    rows = conn.execute("""
        SELECT id, endpoint_ip, details
        FROM web_events
        WHERE details LIKE '%Security Alert #%'
        ORDER BY id
    """).fetchall()

    for row in rows:

        alert_ids = []

        for pattern in endpoint_identity.LEGACY_ALERT_TEXT_PATTERNS:
            for match in pattern.finditer(row["details"] or ""):
                alert_id = int(match.group(1))
                if alert_id not in alert_ids:
                    alert_ids.append(alert_id)

        for alert_id in alert_ids[:5]:

            alert = conn.execute(
                "SELECT id, endpoint_ip FROM security_alerts WHERE id = ?",
                (alert_id,)
            ).fetchone()

            if alert is None:
                counts["text_skipped_alert_missing"] += 1
                continue

            if alert["endpoint_ip"] != row["endpoint_ip"]:
                counts["text_skipped_endpoint_mismatch"] += 1
                continue

            inserted = conn.execute("""
                INSERT OR IGNORE INTO alert_events (alert_id, web_event_id, relationship_type, created_at)
                VALUES (?, ?, 'LEGACY_TEXT_ASSOCIATION', ?)
            """, (alert_id, row["id"], now))

            counts["text_association"] += inserted.rowcount

    return counts


# ==================================================
# AUTH HELPERS
# ==================================================

def login_required():

    return "user_id" in session


def admin_required():

    return (
        "user_id" in session
        and session.get("role") == "admin"
    )


# ==================================================
# SYSTEM LOGGING
# ==================================================

def write_log(
    event_type,
    message,
    target_ip=None,
    username=None
):

    conn = get_db_connection()

    log_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Background workers/scripts have no Flask request/session
    # (touching `session` outside a request context raises
    # RuntimeError). Callers running inside a real request keep
    # today's exact behavior; callers with no request context
    # (or that pass username explicitly) get a safe fallback.
    if username is None:

        if has_request_context():

            username = session.get(
                "username",
                "anonymous"
            )

        else:

            username = "system"

    conn.execute("""
        INSERT INTO system_logs (
            log_time,
            event_type,
            target_ip,
            username,
            message
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        log_time,
        event_type,
        target_ip,
        username,
        message
    ))

    conn.commit()
    conn.close()


# ==================================================
# DESTINATION PARSING
# ==================================================

def normalize_destination(
    destination
):

    destination = (
        destination or ""
    ).strip()

    if not destination:

        return (
            None,
            None,
            "Destination is required."
        )

    # --------------------------------------------------
    # DESTINATION IS A RAW IP LITERAL (IPv4 or IPv6)
    # --------------------------------------------------
    # Checked BEFORE any URL parsing. A bare IPv6 literal (e.g.
    # "2606:4700:3034::6815:46ac") is not valid URL syntax on its
    # own - urlparse()/hostname would split it on its first colon
    # as if it were a host:port separator and silently truncate
    # it (confirmed: urlparse("https://2606:...").hostname ==
    # "2606"). Recognizing a raw IP directly, from the untouched
    # input, avoids that corruption entirely. IPv4 literals were
    # already unambiguous either way - this changes no IPv4
    # behavior, only fixes IPv6.

    try:

        ipaddress.ip_address(
            destination.lower()
        )

        host = destination.lower()

        return (
            host,
            host,
            None
        )

    except ValueError:

        pass

    value = destination

    if "://" not in value:

        value = (
            "https://"
            + value
        )

    parsed = urlparse(
        value
    )

    host = parsed.hostname

    if not host:

        return (
            None,
            None,
            (
                "Could not identify "
                "the destination domain."
            )
        )

    host = (
        host
        .lower()
        .strip(".")
    )

    # --------------------------------------------------
    # DNS RESOLUTION (dual-stack)
    # --------------------------------------------------
    # No `family=` restriction - returns both A and AAAA results
    # when both exist, so a domain that only has an IPv6 address
    # (or where IPv6 is otherwise the right choice) is no longer
    # silently treated as unresolvable. result[4][0] is the IP
    # string in BOTH the AF_INET (ip, port) and AF_INET6
    # (ip, port, flowinfo, scopeid) sockaddr tuples - no special
    # casing needed to extract it for either family.

    try:

        results = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = []

        for result in results:

            ip_value = (
                result[4][0]
            )

            if ip_value not in addresses:

                addresses.append(
                    ip_value
                )

        if not addresses:

            return (
                host,
                None,
                (
                    "The domain did not resolve "
                    "to a usable IP address."
                )
            )

        # Prefer a public destination - IPv4 first, to keep
        # existing IPv4 behavior unchanged for any domain that
        # has both an A and an AAAA record (e.g. an existing IP
        # IOC tagged against a known IPv4 address must keep
        # matching exactly as it did before dual-stack support
        # was added). Only falls through to a global IPv6 address
        # when no global IPv4 address is available - the actual
        # gap this fix closes (IPv6-only destinations).
        global_addresses = []

        for ip_value in addresses:

            try:

                ip_object = ipaddress.ip_address(
                    ip_value
                )

            except ValueError:

                continue

            if ip_object.is_global:

                global_addresses.append(
                    (ip_object.version, ip_value)
                )

        for preferred_version in (4, 6):

            for version, ip_value in global_addresses:

                if version == preferred_version:

                    return (
                        host,
                        ip_value,
                        None
                    )

        # Only private/local destination
        return (
            host,
            addresses[0],
            None
        )

    except socket.gaierror:

        return (
            host,
            None,
            "DNS resolution failed."
        )


# ==================================================
# ENDPOINT MANAGEMENT
# ==================================================

def save_endpoint(
    endpoint_ip,
    source=None,
    os_username=None,
    endpoint_uid=None
):

    # `source` should be 'endpoint-agent' when called from
    # authenticated Endpoint Agent telemetry, or omitted/None
    # otherwise. An existing 'endpoint-agent' row is NEVER
    # downgraded by a later call with a different/missing source -
    # provenance can only be upgraded from unknown (NULL) to
    # 'endpoint-agent', never removed once established. Manual
    # Destination Analysis does not call this function at all
    # (see the manual POST handler) - this parameter exists so
    # save_endpoint() itself enforces the rule even if some other
    # future caller ever passed a non-agent source by mistake.

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    hostname = None

    try:

        hostname = (
            socket.gethostbyaddr(
                endpoint_ip
            )[0]
        )

    except Exception:

        pass

    conn = get_db_connection()

    try:
        _save_endpoint_locked(conn, endpoint_ip, hostname, now, source, os_username, endpoint_uid)
    except BaseException:
        # Phase 12B.6C.1: never leave a write transaction open on failure.
        conn.rollback()
        raise
    finally:
        conn.close()


def _save_endpoint_locked(conn, endpoint_ip, hostname, now, source, os_username, endpoint_uid=None):

    # Phase 13C: take the write lock BEFORE the existence check. The
    # heartbeat and the first event of an agent can register the same new IP
    # at the same moment; a deferred SELECT-then-INSERT let both decide "no
    # row yet" and the loser failed with UNIQUE(endpoints.ip_address).
    # Serialized here, the second caller simply takes the UPDATE branch.
    conn.execute("BEGIN IMMEDIATE")

    endpoint = conn.execute("""
        SELECT *
        FROM endpoints
        WHERE ip_address = ?
    """, (
        endpoint_ip,
    )).fetchone()

    if endpoint is None:

        conn.execute("""
            INSERT INTO endpoints (
                ip_address,
                hostname,
                status,
                last_seen,
                source,
                last_known_os_username,
                endpoint_uid
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            endpoint_ip,
            hostname,
            "CONNECTED",
            now,
            source,
            os_username,
            endpoint_uid
        ))

    else:

        existing_source = endpoint["source"]

        if existing_source == "endpoint-agent":
            new_source = existing_source
        elif source == "endpoint-agent":
            new_source = "endpoint-agent"
        else:
            new_source = existing_source

        conn.execute("""
            UPDATE endpoints
            SET
                hostname = COALESCE(
                    ?,
                    hostname
                ),
                last_seen = ?,
                source = ?,
                last_known_os_username = COALESCE(
                    ?,
                    last_known_os_username
                ),
                endpoint_uid = COALESCE(
                    ?,
                    endpoint_uid
                )
            WHERE ip_address = ?
        """, (
            hostname,
            now,
            new_source,
            os_username,
            endpoint_uid,
            endpoint_ip
        ))

    conn.commit()


# ==================================================
# BLOCK LIST
# ==================================================

def domain_is_blocked(
    domain
):

    if not domain:

        return False

    conn = get_db_connection()

    result = conn.execute("""
        SELECT id
        FROM blocked_domains
        WHERE domain = ?
        AND active = 1
    """, (
        domain,
    )).fetchone()

    conn.close()

    return result is not None


def add_domain_to_blocklist(
    domain,
    severity,
    reason,
    username=None
):

    if not domain:

        return

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if username is None:

        if has_request_context():

            username = session.get(
                "username",
                "system"
            )

        else:

            username = "system"

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO blocked_domains (
            domain,
            reason,
            severity,
            created_by,
            created_at,
            active
        )
        VALUES (?, ?, ?, ?, ?, 1)

        ON CONFLICT(domain)

        DO UPDATE SET
            reason = excluded.reason,
            severity = excluded.severity,
            created_by = excluded.created_by,
            created_at = excluded.created_at,
            active = 1
    """, (
        domain,
        reason,
        severity,
        username,
        now
    ))

    conn.commit()
    conn.close()


# ==================================================
# CREATE SECURITY INCIDENT
# ==================================================

def create_web_incident(
    endpoint_ip,
    domain,
    resolved_ip,
    severity,
    risk_score,
    reasons,
    username=None
):

    conn = get_db_connection()

    existing = conn.execute("""
        SELECT id
        FROM security_events
        WHERE
            event_type = 'MALICIOUS_WEB_DESTINATION'
            AND target_ip = ?
            AND status != 'RESOLVED'
            AND description LIKE ?
        ORDER BY id DESC
        LIMIT 1
    """, (
        endpoint_ip,
        f"%{domain}%"
    )).fetchone()

    if existing:

        conn.close()

        return existing["id"]

    event_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if username is None:

        if has_request_context():

            username = session.get(
                "username"
            )

        else:

            username = "web-event-worker"

    reason_text = "; ".join(
        reasons or []
    )

    description = (
        f"Endpoint {endpoint_ip} attempted "
        f"to access {domain}. "
        f"Resolved IP: {resolved_ip}. "
        f"Risk Score: {risk_score}/100. "
        f"Threat Intelligence: {reason_text}"
    )

    cursor = conn.execute("""
        INSERT INTO security_events (
            event_time,
            event_type,
            severity,
            username,
            target_ip,
            title,
            description,
            status,
            updated_by,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_time,
        "MALICIOUS_WEB_DESTINATION",
        severity,
        username,
        endpoint_ip,
        "High-Risk Web Destination Detected",
        description,
        "OPEN",
        None,
        None
    ))

    incident_id = (
        cursor.lastrowid
    )

    conn.commit()
    conn.close()

    return incident_id


# ==================================================
# PHASE 6: SECURITY ALERTS
# ==================================================
# Detection -> Alert -> (optional) Incident.
#
# security_events (Incident) is unchanged and still created by
# create_web_incident() above, for the manual Web Monitoring page's
# own "analyze this destination now" POST feature only (the
# synchronous analyze_web_event() this comment used to reference was
# retired in Stage 25F Phase 6 - zero live callers, confirmed before
# removal; create_web_incident() itself is kept, still used by that
# live manual feature).
#
# The worker-driven pipeline (web_event_worker.py) now goes
# through this Alert layer instead of calling
# create_web_incident() directly - see create_incident_from_alert()
# below, which is a SEPARATE function from create_web_incident()
# on purpose: it builds the Incident description FROM the
# Alert's already-computed title/reasons/recommended response
# (single source of truth), rather than recomputing anything.

DEDUP_ALERT_WINDOW_MINUTES = 30


def get_endpoint_info(endpoint_ip):
    """
    Returns the endpoints row for endpoint_ip (hostname, status,
    etc.) or None if the endpoint has never been seen. Used to
    enrich Alerts with hostname and to check whether the
    endpoint is already isolated (for Recommended Response
    context - see threat_intelligence.build_recommended_response).
    """

    conn = get_db_connection()

    row = conn.execute("""
        SELECT *
        FROM endpoints
        WHERE ip_address = ?
    """, (
        endpoint_ip,
    )).fetchone()

    conn.close()

    return row


def _find_recent_matching_alert(
    alert_type,
    endpoint_ip,
    destination_ip,
    domain,
    minutes=DEDUP_ALERT_WINDOW_MINUTES
):
    """
    Simple, explainable Alert deduplication rule: an alert is
    considered a duplicate of a still-relevant existing one if
    all of the following match, within the last `minutes`:
      - same alert_type
      - same endpoint_ip
      - same destination (destination_ip OR domain match)
      - existing alert's status is NEW, ACKNOWLEDGED, or
        ESCALATED (i.e. not CLOSED - a closed alert doesn't
        suppress a fresh detection of the same thing)

    This is intentionally simple (no correlation engine): one
    SQL query, one time window, documented here.
    """

    conn = get_db_connection()

    cutoff = (
        datetime.now() - timedelta(minutes=minutes)
    ).strftime("%Y-%m-%d %H:%M:%S")

    row = conn.execute("""
        SELECT *
        FROM security_alerts
        WHERE alert_type = ?
          AND endpoint_ip = ?
          AND (
                (destination_ip IS NOT NULL AND destination_ip = ?)
                OR (domain IS NOT NULL AND domain = ?)
              )
          AND status IN ('NEW', 'ACKNOWLEDGED', 'ESCALATED')
          AND created_at >= ?
        ORDER BY id DESC
        LIMIT 1
    """, (
        alert_type,
        endpoint_ip,
        destination_ip,
        domain,
        cutoff
    )).fetchone()

    conn.close()

    return row


def add_alert_event(conn, alert_id, web_event_id, relationship_type, created_at):
    """
    Records an explicit Alert <-> Web Event relationship on the CALLER's
    connection/transaction (the caller commits). Bounded vocabulary only;
    INSERT OR IGNORE on UNIQUE(alert_id, web_event_id) so reprocessing an
    event can never create a duplicate pair. No-op without an event id.
    """

    if not web_event_id:
        return 0

    if relationship_type not in endpoint_identity.RELATIONSHIP_TYPES:
        raise ValueError(f"Unknown alert-event relationship type: {relationship_type}")

    cursor = conn.execute("""
        INSERT OR IGNORE INTO alert_events (
            alert_id, web_event_id, relationship_type, created_at
        ) VALUES (?, ?, ?, ?)
    """, (alert_id, web_event_id, relationship_type, created_at))

    return cursor.rowcount


def create_security_alert(
    alert_type,
    title,
    description,
    severity,
    risk_score,
    endpoint_ip=None,
    hostname=None,
    process_name=None,
    domain=None,
    destination_ip=None,
    source="web-event-worker",
    source_event_id=None,
    detection_reasons=None,
    recommended_response=None,
    username=None
):
    """
    Finds a recent matching Alert (see _find_recent_matching_alert)
    and reuses it if found - no new row, no flood. Otherwise
    creates a new Alert row (status='NEW') and returns it.

    IMPORTANT: when an existing Alert is reused, its detection
    data (severity, risk_score, description, detection_reasons,
    recommended_response) is REFRESHED to the latest occurrence
    before being returned. Without this, a later, more severe
    detection of the same thing (e.g. MEDIUM -> HIGH) would
    escalate to an Incident that still shows the original,
    stale MEDIUM data - discovered and fixed during Phase 6
    testing. Workflow fields (status, created_at, incident_id,
    acknowledged_by/at) are left untouched here; status/
    incident_id are updated separately by the escalation step
    in the caller (web_event_worker.py / app.py's manual
    escalation route).

    Recommended Response is stored as JSON AT CREATION TIME
    (Phase 6 requirement): if the playbook rules change later,
    historical alerts keep showing what was recommended when
    they were created - this refresh-on-reuse is the one
    deliberate exception, since it reflects a genuinely new
    detection of the same underlying threat, not a rule change.

    Returns (alert_row, reused: bool).
    """

    existing = _find_recent_matching_alert(
        alert_type,
        endpoint_ip,
        destination_ip,
        domain
    )

    if existing is not None:

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()

        try:

            conn.execute("""
                UPDATE security_alerts
                SET
                    title = ?,
                    description = ?,
                    severity = ?,
                    risk_score = ?,
                    hostname = COALESCE(?, hostname),
                    process_name = COALESCE(?, process_name),
                    source_event_id = ?,
                    detection_reasons = ?,
                    recommended_response = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                title,
                description,
                severity,
                risk_score,
                hostname,
                process_name,
                source_event_id,
                json.dumps(detection_reasons or []),
                json.dumps(recommended_response or []),
                now,
                existing["id"]
            ))

            # Phase 12B.6D: the refreshing event is RETAINED as an explicit
            # relationship (source_event_id above only keeps the latest).
            # Same short transaction: both happen or neither does.
            # INSERT OR IGNORE: reprocessing the same event never duplicates.
            add_alert_event(
                conn,
                existing["id"],
                source_event_id,
                endpoint_identity.REL_DEDUP_REFRESH,
                now
            )

            conn.commit()

            refreshed = conn.execute(
                "SELECT * FROM security_alerts WHERE id = ?",
                (existing["id"],)
            ).fetchone()

        except BaseException:

            conn.rollback()
            raise

        finally:

            conn.close()

        return refreshed, True

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    try:

        cursor = conn.execute("""
            INSERT INTO security_alerts (
                created_at, updated_at, alert_type, title, description,
                severity, risk_score, status, endpoint_ip, hostname,
                process_name, domain, destination_ip, source,
                source_event_id, detection_reasons, recommended_response
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, 'NEW', ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            now, now, alert_type, title, description,
            severity, risk_score, endpoint_ip, hostname,
            process_name, domain, destination_ip, source,
            source_event_id,
            json.dumps(detection_reasons or []),
            json.dumps(recommended_response or [])
        ))

        alert_id = cursor.lastrowid

        # Phase 12B.6D: the alert and its CREATED_FROM relationship are one
        # logical operation in ONE short transaction - the relationship can
        # never be lost while the alert survives (or vice versa).
        add_alert_event(
            conn,
            alert_id,
            source_event_id,
            endpoint_identity.REL_CREATED_FROM,
            now
        )

        conn.commit()

        row = conn.execute(
            "SELECT * FROM security_alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()

    except BaseException:

        conn.rollback()
        raise

    finally:

        conn.close()

    write_log(
        "ALERT_CREATED",
        f"Alert #{alert_id} ({severity}): {title}",
        target_ip=endpoint_ip,
        username=username or source
    )

    return row, False


def create_incident_from_alert(alert, username=None):
    """
    Escalates a Security Alert to an Incident (security_events
    row) - used both automatically (HIGH/CRITICAL, from the
    worker) and manually (Analyst/Admin escalating a MEDIUM
    alert from the Alert Details page).

    The Incident description is built FROM the alert's own
    title/description/detection_reasons/recommended_response -
    a single source of truth, not a second independent
    description. Preserves the existing Incident dedup
    behavior indirectly: if this alert was itself reused via
    _find_recent_matching_alert() and already has an
    incident_id, the caller should not call this function again
    (see web_event_worker.py and app.py's manual escalation
    route, both check alert['status'] != 'ESCALATED' first).

    `alert` may be a sqlite3.Row or a plain dict (the manual
    escalation route in app.py passes dict(row)).
    """

    try:
        reasons = json.loads(alert["detection_reasons"] or "[]")
    except (json.JSONDecodeError, TypeError):
        reasons = []

    try:
        response = json.loads(alert["recommended_response"] or "[]")
    except (json.JSONDecodeError, TypeError):
        response = []

    reason_text = "; ".join(reasons) if reasons else "No additional detection reasons recorded."

    response_text = "\n".join(
        f"{index}. {step}"
        for index, step in enumerate(response, start=1)
    ) if response else "No recommended response recorded."

    description = (
        f"{alert['description']}\n\n"
        f"Detection reasons: {reason_text}\n\n"
        f"Recommended response:\n{response_text}\n\n"
        f"(Escalated from Security Alert #{alert['id']}.)"
    )

    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    cursor = conn.execute("""
        INSERT INTO security_events (
            event_time, event_type, severity, username, target_ip,
            title, description, status, updated_by, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)
    """, (
        event_time,
        alert["alert_type"],
        alert["severity"],
        username,
        alert["endpoint_ip"],
        alert["title"],
        description,
        username,
        event_time
    ))

    incident_id = cursor.lastrowid

    conn.execute("""
        UPDATE security_alerts
        SET status = 'ESCALATED', incident_id = ?, updated_at = ?
        WHERE id = ?
    """, (
        incident_id,
        event_time,
        alert["id"]
    ))

    conn.commit()
    conn.close()

    write_log(
        "INCIDENT_CREATED_FROM_ALERT",
        (
            f"Alert #{alert['id']} escalated to Incident "
            f"#{incident_id}."
        ),
        target_ip=alert["endpoint_ip"],
        username=username
    )

    return incident_id


# ==================================================
# PHASE 7: RESPONSE COMMANDS
# ==================================================
# Allowlisted command types ONLY - the Agent never executes an
# arbitrary string. This tuple is the single source of truth
# for what a command_type is allowed to be, both here (command
# creation) and in the Agent (execution dispatch).

COMMAND_TYPES = (
    "BLOCK_DESTINATION",
    "UNBLOCK_DESTINATION",
    "ISOLATE_ENDPOINT",
    "RESTORE_ENDPOINT"
)

# A command is still "in flight" (not yet finished) in these
# statuses - used both for dedup and for the Agent's polling
# query.
ACTIVE_COMMAND_STATUSES = ("PENDING", "ACKNOWLEDGED", "EXECUTING")


def _find_active_command(endpoint_ip, command_type, target):
    """
    Dedup rule (Phase 7, section 19): a command is a duplicate
    of an already in-flight one if it targets the same
    endpoint, the same command_type, and the same target
    (destination for BLOCK/UNBLOCK, or NULL for ISOLATE/
    RESTORE which have no separate target), and that existing
    command is still PENDING/ACKNOWLEDGED/EXECUTING. Repeated
    admin clicks reuse the same in-flight command instead of
    creating a flood of identical ones.
    """

    conn = get_db_connection()

    placeholders = ",".join("?" for _ in ACTIVE_COMMAND_STATUSES)

    row = conn.execute(f"""
        SELECT *
        FROM response_commands
        WHERE endpoint_ip = ?
          AND command_type = ?
          AND (
                (target IS NULL AND ? IS NULL)
                OR target = ?
              )
          AND status IN ({placeholders})
        ORDER BY id DESC
        LIMIT 1
    """, (
        endpoint_ip,
        command_type,
        target,
        target,
        *ACTIVE_COMMAND_STATUSES
    )).fetchone()

    conn.close()

    return row


def create_response_command(
    command_type,
    endpoint_ip,
    target=None,
    reason=None,
    requested_by=None,
    alert_id=None,
    incident_id=None,
    reference_command_id=None,
    force_new=False,
    *,
    origin="manual",
    gate_result=None
):
    """
    STAGE 25G PHASE 2 - THE ONE authoritative command-creation boundary.
    This function owns the project's only insert statement for the
    response_commands table (verified by call-site audit). Two origins:
      origin="manual"    (default, every existing caller - admin UI
                          actions and the admin-driven Global Block
                          Policy orchestration) - behavior unchanged;
                          the Agent's own ENABLE_RESPONSE_ACTIONS gate
                          keeps these SIMULATED while the flag is false.
      origin="automated" (future policy-driven dispatch, Phase 3+) -
                          REQUIRES a passing gate_result from
                          response_gate.server_response_execution_
                          allowed() for this exact command/endpoint/
                          target; anything else raises PermissionError
                          BEFORE any row is written (fail closed). No
                          automated caller exists in Phase 2.

    Creates a response_commands row (status='PENDING') for the
    Agent to pick up, or reuses an existing in-flight duplicate
    (see _find_active_command). Looks up endpoint_id/hostname
    from the endpoints table if known. For UNBLOCK_DESTINATION,
    looks up the original BLOCK_DESTINATION command id from
    blocked_domains.last_command_id so the Agent knows exactly
    which firewall rules to remove.

    reference_command_id: optional explicit override (Global
    Blocklist, Global Response Response/Blocklist section 9) -
    when the caller already knows exactly which BLOCK command a
    given endpoint's UNBLOCK must reference (e.g. a Global Block
    Policy's own per-endpoint block_command_id), pass it directly
    here and the blocked_domains.last_command_id lookup below is
    skipped entirely. blocked_domains only ever holds ONE
    reference id globally, so it is not a safe source of truth
    once more than one endpoint/source can independently block the
    same target - existing callers never pass this, so their
    behavior is unchanged.

    force_new: optional, default False (Global Policy ownership
    fix). _find_active_command()'s dedup has no concept of WHO
    created the existing in-flight command - it will happily hand
    back an unrelated Alert/Incident's own active command just
    because it happens to match (endpoint_ip, command_type,
    target). That is correct/desired for a caller re-clicking its
    OWN action, but wrong for the Global Block Policy orchestrator,
    which must never claim an unrelated command as its own. When
    force_new=True, the _find_active_command() lookup below is
    skipped entirely and a brand-new row is always created. Only
    the Global Policy orchestration functions ever pass this -
    every existing caller omits it and keeps today's exact dedup
    behavior unchanged.

    Returns (command_row, reused: bool). Raises ValueError if
    command_type is not in COMMAND_TYPES - this function is the
    only way a row is created, so this is the enforcement point
    for "no arbitrary command types" (Phase 7, section 4).
    """

    if command_type not in COMMAND_TYPES:
        raise ValueError(f"Unsupported command_type: {command_type}")

    # Stage 25G Phase 2: automated origin must present a passing,
    # matching server-side gate result - checked before any lookup or
    # write. Manual origin is unchanged.
    if origin not in ("manual", "automated"):
        raise ValueError(f"Unsupported origin: {origin}")

    if origin == "automated":

        if (
            not isinstance(gate_result, dict)
            or gate_result.get("allowed") is not True
            or gate_result.get("command_type") != command_type
            or gate_result.get("endpoint_ip") != endpoint_ip
            or (gate_result.get("target") or None) != (target or None)
        ):
            raise PermissionError(
                "automated response command creation denied: no passing "
                "server-side gate result for this exact command/endpoint/target"
            )

    if not force_new:

        existing = _find_active_command(endpoint_ip, command_type, target)

        if existing is not None:
            return existing, True

    endpoint_info = get_endpoint_info(endpoint_ip)

    endpoint_id = endpoint_info["id"] if endpoint_info else None
    hostname = endpoint_info["hostname"] if endpoint_info else None

    if reference_command_id is not None:

        pass

    elif command_type == "UNBLOCK_DESTINATION" and target:

        conn = get_db_connection()

        blocked_row = conn.execute("""
            SELECT last_command_id
            FROM blocked_domains
            WHERE domain = ?
        """, (
            target,
        )).fetchone()

        conn.close()

        if blocked_row is not None:
            reference_command_id = blocked_row["last_command_id"]

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    cursor = conn.execute("""
        INSERT INTO response_commands (
            created_at, updated_at, endpoint_id, endpoint_ip, hostname,
            command_type, target, reason, requested_by, status,
            alert_id, incident_id, reference_command_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
    """, (
        now, now, endpoint_id, endpoint_ip, hostname,
        command_type, target, reason, requested_by,
        alert_id, incident_id, reference_command_id
    ))

    command_id = cursor.lastrowid

    conn.commit()

    row = conn.execute(
        "SELECT * FROM response_commands WHERE id = ?",
        (command_id,)
    ).fetchone()

    conn.close()

    write_log(
        "RESPONSE_COMMAND_CREATED",
        (
            f"Command #{command_id} ({command_type}) requested "
            f"for endpoint {endpoint_ip}"
            + (f" target {target}" if target else "")
            + "."
        ),
        target_ip=endpoint_ip,
        username=requested_by
    )

    return row, False


# ==================================================
# ORGANIZATION-WIDE RESPONSE / GLOBAL BLOCKLIST
# ==================================================
# This layer never talks to the Agent or to blocked_domains
# directly - it only orchestrates create_response_command() (the
# existing, unchanged execution ledger) once per eligible
# endpoint, and reads deployment status live from
# response_commands every time it's displayed. See the approved
# design/plan for the full rationale.

GLOBAL_BLOCK_TARGET_TYPES = ("IPV4", "IPV6")
GLOBAL_BLOCK_SCOPES = ("ALL_MANAGED_ENDPOINTS", "SELECTED_ENDPOINTS")
GLOBAL_BLOCK_MODES = ("SIMULATED", "ENFORCED")


def validate_global_block_target(raw_target):
    """
    Server-side-only target validation/normalization for the
    Global Blocklist MVP (IPv4/IPv6 only - no DOMAIN, no HASH).
    Never trusts a browser-supplied target_type; always derives it
    from the parsed address. Returns (target_type, target_value)
    or (None, None) if invalid.
    """

    if not raw_target:
        return None, None

    try:
        parsed = ipaddress.ip_address(raw_target.strip())
    except ValueError:
        return None, None

    target_type = "IPV4" if parsed.version == 4 else "IPV6"

    return target_type, str(parsed)


def compute_endpoint_presence(last_seen):
    """
    Same presence derivation already used for the Web Monitoring
    Managed Endpoints table (ONLINE <=2min, STALE <=24h, OFFLINE
    otherwise, UNKNOWN if missing/unparseable) - factored out here
    so the Global Blocklist preview/details pages can reuse it
    identically without duplicating the thresholds.
    """

    if not last_seen:
        return "UNKNOWN"

    try:

        last_seen_dt = datetime.strptime(
            last_seen,
            "%Y-%m-%d %H:%M:%S"
        )

        age = datetime.now() - last_seen_dt

        if age <= timedelta(minutes=2):
            return "ONLINE"
        elif age <= timedelta(hours=24):
            return "STALE"
        else:
            return "OFFLINE"

    except ValueError:

        return "UNKNOWN"


def get_eligible_endpoints(scope, selected_ips=None):
    """
    Managed-endpoint eligibility for Global Blocklist fan-out:
    source='endpoint-agent' (the established trust rule) AND not
    currently ISOLATED. Presence is NOT part of eligibility - an
    OFFLINE/STALE endpoint is still eligible and simply gets a
    PENDING command. For SELECTED_ENDPOINTS, the browser-supplied
    IP list is only ever used to INTERSECT this trusted query -
    an IP that isn't already a real managed endpoint can never be
    smuggled in this way.
    """

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT *
        FROM endpoints
        WHERE source = 'endpoint-agent'
        AND status != 'ISOLATED'
        ORDER BY ip_address
    """).fetchall()

    conn.close()

    eligible = [dict(row) for row in rows]

    if scope == "SELECTED_ENDPOINTS":

        selected_set = set(selected_ips or [])

        eligible = [
            endpoint for endpoint in eligible
            if endpoint["ip_address"] in selected_set
        ]

    return eligible


def find_active_global_policy(target_type, target_value):

    conn = get_db_connection()

    row = conn.execute("""
        SELECT *
        FROM global_block_policies
        WHERE target_type = ?
        AND target_value = ?
        AND active = 1
        ORDER BY id DESC
        LIMIT 1
    """, (
        target_type,
        target_value
    )).fetchone()

    conn.close()

    return row


def get_command_by_id(command_id):

    if not command_id:
        return None

    conn = get_db_connection()

    row = conn.execute("""
        SELECT * FROM response_commands WHERE id = ?
    """, (
        command_id,
    )).fetchone()

    conn.close()

    return row


def get_latest_block_command(endpoint_ip, target_value):
    """
    The single shared "what's the current coverage" query, reused
    identically by both the preview (read-only) and the actual
    fan-out (write) paths - deployment status is always computed
    live from response_commands, never a duplicated stored value.
    """

    conn = get_db_connection()

    row = conn.execute("""
        SELECT *
        FROM response_commands
        WHERE endpoint_ip = ?
        AND command_type = 'BLOCK_DESTINATION'
        AND target = ?
        ORDER BY id DESC
        LIMIT 1
    """, (
        endpoint_ip,
        target_value
    )).fetchone()

    conn.close()

    return row


def _classify_policy_membership_coverage(policy_command):
    """
    Maps a Global Policy's OWN block command for one of its member
    endpoints (or None, meaning the endpoint isn't a member yet)
    onto the action create_or_sync_global_block_policy() would
    take. Only ever fed a policy-owned command (never an unrelated
    Alert/Incident/manual one) - ownership is guaranteed by
    force_new=True at creation time (see create_response_command()).
    Shared by preview and by create_or_sync_global_block_policy()
    so the two can never silently disagree.
    """

    if policy_command is None:
        return "NEW", "New BLOCK command (policy-owned)"

    status = policy_command["status"]

    if status == "SUCCESS":
        return "ALREADY_COVERED_SUCCESS", "None (already blocked by this policy)"

    if status in ("PENDING", "ACKNOWLEDGED", "EXECUTING"):
        return "ALREADY_COVERED_PENDING", "None (already in progress for this policy)"

    if status == "FAILED":
        return "FAILED_NEEDS_RETRY", "None (use Retry)"

    return "NEW", "New BLOCK command (policy-owned)"


def compute_global_block_preview(target_type, target_value, scope, selected_ips=None):
    """
    READ-ONLY. Computes everything the mandatory Preview step
    shows: existing active policy (if any), the eligible-endpoint
    list annotated with presence + current coverage + the action
    that would be taken, and aggregate counts. Never writes
    anything - no policy, no response_commands, no blocked_domains,
    no system_logs.

    Ownership-hardening fix: "coverage"/"action_label" here reflect
    ONLY this specific policy's own membership - i.e. exactly what
    create_or_sync_global_block_policy() would actually do, which
    (as of the ownership fix) always creates its own independent,
    policy-owned command for any endpoint that isn't already one of
    THIS policy's members, regardless of whether some unrelated
    Alert/Incident/manual command already covers the same
    endpoint+target. That unrelated coverage is still surfaced
    separately, as "unrelated_existing_command", purely as
    informational context - it must never be read as "no command
    will be created here".
    """

    existing_policy = find_active_global_policy(target_type, target_value)

    policy_members_by_ip = {}

    if existing_policy:

        for member in get_policy_endpoints(existing_policy["id"]):
            policy_members_by_ip[member["endpoint_ip"]] = member

    eligible = get_eligible_endpoints(scope, selected_ips)

    presence_counts = {
        "ONLINE": 0,
        "STALE": 0,
        "OFFLINE": 0,
        "UNKNOWN": 0
    }

    already_covered = 0
    new_commands = 0

    endpoint_rows = []

    for endpoint in eligible:

        presence = compute_endpoint_presence(endpoint["last_seen"])
        presence_counts[presence] += 1

        ip = endpoint["ip_address"]

        membership = policy_members_by_ip.get(ip)

        policy_command = (
            get_command_by_id(membership["block_command_id"])
            if membership else None
        )

        action, action_label = _classify_policy_membership_coverage(
            policy_command
        )

        if action == "NEW":
            new_commands += 1
        else:
            already_covered += 1

        # Informational only, never gates the action above: does
        # some OTHER, unrelated source already have an active/
        # success BLOCK_DESTINATION for this exact endpoint+target?
        # Only relevant to show when this policy does NOT already
        # own a command here (membership is None) - once it's a
        # member, its own command is the only thing that matters.
        unrelated_command = None

        if membership is None:

            candidate = get_latest_block_command(ip, target_value)

            if candidate is not None:
                unrelated_command = dict(candidate)

        endpoint_rows.append({
            "hostname": endpoint["hostname"],
            "ip_address": ip,
            "presence": presence,
            "coverage": action,
            "action_label": action_label,
            "existing_command": dict(policy_command) if policy_command else None,
            "unrelated_existing_command": unrelated_command
        })

    return {
        "existing_policy": dict(existing_policy) if existing_policy else None,
        "eligible_count": len(eligible),
        "presence_counts": presence_counts,
        "already_covered": already_covered,
        "new_commands": new_commands,
        "endpoints": endpoint_rows
    }


def create_or_sync_global_block_policy(
    target_type,
    target_value,
    scope,
    selected_ips,
    requested_mode,
    reason,
    source_type,
    source_id,
    requested_by
):
    """
    The only writer for Global Block Policies. Either creates a
    brand-new policy header (if none is active for this target) or
    reuses/syncs the existing active one - in both cases, fans out
    a BLOCK_DESTINATION command to every currently-eligible
    endpoint that doesn't already have a membership row.

    Step A (one transaction): policy header (if new) + bare
    membership rows for newly-eligible endpoints. Any exception
    here rolls back completely - never leaves a policy header with
    silently-missing membership rows.

    Step B (after Step A commits): for each newly-inserted
    membership row, create the actual response_commands BLOCK
    command and store its id. This step is per-endpoint and
    inherently asynchronous from the Agent's point of view -
    a partially-deployed policy (some endpoints still PENDING or
    even FAILED) is an expected, legitimate state, not an error.

    Returns (policy_row, newly_deployed_endpoint_ips: list).
    """

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    eligible = get_eligible_endpoints(scope, selected_ips)

    conn = get_db_connection()

    is_new_policy = False

    try:

        policy_row = conn.execute("""
            SELECT * FROM global_block_policies
            WHERE target_type = ? AND target_value = ? AND active = 1
            ORDER BY id DESC LIMIT 1
        """, (
            target_type, target_value
        )).fetchone()

        if policy_row is None:

            is_new_policy = True

            cursor = conn.execute("""
                INSERT INTO global_block_policies (
                    target_type, target_value, scope, requested_mode,
                    active, reason, source_type, source_id,
                    requested_by, created_at
                ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
            """, (
                target_type, target_value, scope, requested_mode,
                reason, source_type, source_id, requested_by, now
            ))

            policy_id = cursor.lastrowid

        else:

            policy_id = policy_row["id"]

        existing_members = conn.execute("""
            SELECT endpoint_ip FROM global_block_policy_endpoints
            WHERE policy_id = ?
        """, (
            policy_id,
        )).fetchall()

        existing_ips = {row["endpoint_ip"] for row in existing_members}

        newly_added_ips = []

        for endpoint in eligible:

            ip = endpoint["ip_address"]

            if ip in existing_ips:
                continue

            conn.execute("""
                INSERT INTO global_block_policy_endpoints (
                    policy_id, endpoint_ip, created_at
                ) VALUES (?, ?, ?)
            """, (
                policy_id, ip, now
            ))

            newly_added_ips.append(ip)

        conn.commit()

    except Exception:

        conn.rollback()
        conn.close()
        raise

    conn.close()

    policy = conn_fetch_policy(policy_id)

    # Step B - one response_command per newly-added membership row.
    # A failure creating one endpoint's command never blocks the
    # others (async/per-endpoint by nature - see docstring).
    for ip in newly_added_ips:

        try:

            command, _reused = create_response_command(
                "BLOCK_DESTINATION",
                ip,
                target=target_value,
                reason=reason or f"Global Block Policy #{policy_id}.",
                requested_by=requested_by,
                force_new=True
            )

            update_conn = get_db_connection()

            update_conn.execute("""
                UPDATE global_block_policy_endpoints
                SET block_command_id = ?
                WHERE policy_id = ? AND endpoint_ip = ?
            """, (
                command["id"], policy_id, ip
            ))

            update_conn.commit()
            update_conn.close()

        except Exception as exc:

            write_log(
                "GLOBAL_BLOCK_DEPLOY_ERROR",
                (
                    f"Global Block Policy #{policy_id}: failed to "
                    f"create BLOCK command for endpoint {ip}: {exc}"
                ),
                target_ip=ip,
                username=requested_by
            )

    if is_new_policy:

        write_log(
            "GLOBAL_BLOCK_POLICY_CREATED",
            (
                f"Global Block Policy #{policy_id} created for "
                f"{target_value} ({target_type}), scope={scope}, "
                f"requested_mode={requested_mode}, by {requested_by}."
            ),
            target_ip=target_value,
            username=requested_by
        )

    write_log(
        "GLOBAL_BLOCK_DEPLOYED",
        (
            f"Global Block Policy #{policy_id} deployed to "
            f"{len(newly_added_ips)} endpoint(s) "
            f"(target={target_value}, scope={scope}, requested by "
            f"{requested_by})."
        ),
        target_ip=target_value,
        username=requested_by
    )

    return policy, newly_added_ips


def conn_fetch_policy(policy_id):

    conn = get_db_connection()

    row = conn.execute("""
        SELECT * FROM global_block_policies WHERE id = ?
    """, (
        policy_id,
    )).fetchone()

    conn.close()

    return row


def get_policy_endpoints(policy_id):

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT * FROM global_block_policy_endpoints
        WHERE policy_id = ?
        ORDER BY endpoint_ip
    """, (
        policy_id,
    )).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_policy_coverage(policy_id):
    """
    Live rollup over global_block_policy_endpoints joined back to
    response_commands - never a stored/cached status. Used by both
    the Organization Blocklist list page (KPIs/table) and the
    Policy Details page (coverage summary).
    """

    members = get_policy_endpoints(policy_id)

    total = len(members)
    success = 0
    pending = 0
    failed = 0

    for member in members:

        block_command = get_command_by_id(member["block_command_id"])

        if block_command is None:
            pending += 1
            continue

        status = block_command["status"]

        if status == "SUCCESS":
            success += 1
        elif status == "FAILED":
            failed += 1
        else:
            pending += 1

    return {
        "total": total,
        "success": success,
        "pending": pending,
        "failed": failed
    }


def disable_global_block_policy(policy_id, disabled_by):
    """
    Admin-only at the route level. For every membership row whose
    current block command is SUCCESS or still in flight (PENDING/
    ACKNOWLEDGED/EXECUTING) and that doesn't already have an
    unblock_command_id, creates an UNBLOCK_DESTINATION command
    whose reference_command_id is THAT membership's own
    block_command_id - never blocked_domains.last_command_id, and
    never any other source's command id, so this can only ever
    remove firewall rules this policy's own BLOCK commands created
    (see the Agent's rule-naming/removal convention).

    Does not delete the policy or any membership row - historical
    evidence stays visible. Returns (success: bool, unblocked_count
    or error message).
    """

    policy = conn_fetch_policy(policy_id)

    if policy is None or policy["active"] != 1:
        return False, "Policy not found or already disabled."

    members = get_policy_endpoints(policy_id)

    unblocked_count = 0

    for member in members:

        if not member["block_command_id"]:
            continue

        if member["unblock_command_id"]:
            continue

        block_command = get_command_by_id(member["block_command_id"])

        if block_command is None:
            continue

        if block_command["status"] not in (
            "SUCCESS", "PENDING", "ACKNOWLEDGED", "EXECUTING"
        ):
            # FAILED (or otherwise never-enforced) - nothing to
            # remove for this endpoint.
            continue

        command, _reused = create_response_command(
            "UNBLOCK_DESTINATION",
            member["endpoint_ip"],
            target=policy["target_value"],
            reason=f"Global Block Policy #{policy_id} disabled.",
            requested_by=disabled_by,
            reference_command_id=member["block_command_id"],
            force_new=True
        )

        update_conn = get_db_connection()

        update_conn.execute("""
            UPDATE global_block_policy_endpoints
            SET unblock_command_id = ?
            WHERE id = ?
        """, (
            command["id"], member["id"]
        ))

        update_conn.commit()
        update_conn.close()

        unblocked_count += 1

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    conn.execute("""
        UPDATE global_block_policies
        SET active = 0, disabled_at = ?, disabled_by = ?
        WHERE id = ?
    """, (
        now, disabled_by, policy_id
    ))

    conn.commit()
    conn.close()

    write_log(
        "GLOBAL_BLOCK_POLICY_DISABLED",
        (
            f"Global Block Policy #{policy_id} "
            f"({policy['target_value']}) disabled by {disabled_by}."
        ),
        target_ip=policy["target_value"],
        username=disabled_by
    )

    write_log(
        "GLOBAL_UNBLOCK_DEPLOYED",
        (
            f"Global Block Policy #{policy_id}: {unblocked_count} "
            f"UNBLOCK command(s) deployed, referencing only this "
            f"policy's own BLOCK command ids."
        ),
        target_ip=policy["target_value"],
        username=disabled_by
    )

    return True, unblocked_count


def retry_global_block_endpoint(policy_id, endpoint_ip, requested_by):
    """
    Admin-only at the route level. Re-validates the endpoint is
    still a real, eligible managed endpoint and that its current
    block command actually FAILED before creating a brand-new
    BLOCK_DESTINATION command - the old FAILED command row is never
    touched/deleted, only the membership's block_command_id pointer
    moves to the new command, preserving full retry history.
    """

    policy = conn_fetch_policy(policy_id)

    if policy is None or policy["active"] != 1:
        return None, "Policy not found or not active."

    conn = get_db_connection()

    member = conn.execute("""
        SELECT * FROM global_block_policy_endpoints
        WHERE policy_id = ? AND endpoint_ip = ?
    """, (
        policy_id, endpoint_ip
    )).fetchone()

    conn.close()

    if member is None:
        return None, "This endpoint is not a member of this policy."

    endpoint_info = get_endpoint_info(endpoint_ip)

    if (
        endpoint_info is None
        or endpoint_info["source"] != "endpoint-agent"
        or endpoint_info["status"] == "ISOLATED"
    ):
        return None, "This endpoint is no longer a recognized, eligible managed endpoint."

    current_command = get_command_by_id(member["block_command_id"])

    if current_command is None or current_command["status"] != "FAILED":
        return None, "This endpoint's deployment is not in a FAILED state - nothing to retry."

    new_command, _reused = create_response_command(
        "BLOCK_DESTINATION",
        endpoint_ip,
        target=policy["target_value"],
        reason=f"Retry for Global Block Policy #{policy_id}.",
        requested_by=requested_by,
        force_new=True
    )

    update_conn = get_db_connection()

    update_conn.execute("""
        UPDATE global_block_policy_endpoints
        SET block_command_id = ?
        WHERE id = ?
    """, (
        new_command["id"], member["id"]
    ))

    update_conn.commit()
    update_conn.close()

    write_log(
        "GLOBAL_BLOCK_RETRY",
        (
            f"Global Block Policy #{policy_id}: retry for endpoint "
            f"{endpoint_ip} - new command #{new_command['id']} "
            f"(previous command #{member['block_command_id']} "
            f"preserved as history), requested by {requested_by}."
        ),
        target_ip=endpoint_ip,
        username=requested_by
    )

    return new_command, None


def get_pending_commands_for_endpoint(endpoint_ip):
    """
    Used by the Agent's GET /api/agent/commands. Returns only
    PENDING commands for the CALLING agent's own endpoint_ip
    (never all devices - Phase 7, section 5), and immediately
    marks them ACKNOWLEDGED so a repeated poll before the result
    is posted does not hand out the same command twice.
    """

    conn = get_db_connection()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = conn.execute("""
        SELECT *
        FROM response_commands
        WHERE endpoint_ip = ?
          AND status = 'PENDING'
        ORDER BY id ASC
    """, (
        endpoint_ip,
    )).fetchall()

    commands = [dict(row) for row in rows]

    for command in commands:

        conn.execute("""
            UPDATE response_commands
            SET status = 'ACKNOWLEDGED', updated_at = ?
            WHERE id = ? AND status = 'PENDING'
        """, (
            now,
            command["id"]
        ))

        command["status"] = "ACKNOWLEDGED"

    conn.commit()
    conn.close()

    return commands


def apply_command_result(command_id, status, result_message=None, mode=None):
    """
    Applies an Agent-reported result to a response_commands row,
    and to whatever it controls (endpoints.status for ISOLATE/
    RESTORE, blocked_domains for BLOCK/UNBLOCK) - but ONLY when
    status == 'SUCCESS'. A FAILED result never flips endpoint/
    blocklist state (Phase 7, section 27: internal state must
    reflect the ACTUAL execution result, never an attempted one).

    `mode` ('SIMULATED' or 'ENFORCED') is whatever the Agent
    itself reports - this function does not decide it.

    The Agent may only influence status/result_message/mode/
    executed_at here - command_type, endpoint_ip, target,
    requested_by etc. are never touched by this function
    (Phase 7, section 24).
    """

    conn = get_db_connection()

    command = conn.execute(
        "SELECT * FROM response_commands WHERE id = ?",
        (command_id,)
    ).fetchone()

    if command is None:
        conn.close()
        return None

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        UPDATE response_commands
        SET
            status = ?,
            result_message = ?,
            mode = ?,
            executed_at = ?,
            updated_at = ?
        WHERE id = ?
    """, (
        status,
        (result_message or "")[:500],
        mode,
        now,
        now,
        command_id
    ))

    # Commit and close BEFORE calling out to any function that
    # opens its own connection (add_domain_to_blocklist below) -
    # holding this transaction open while another connection
    # tries to write the same SQLite file causes "database is
    # locked" (found and fixed during Phase 7 testing).
    conn.commit()
    conn.close()

    if status == "SUCCESS":

        command_type = command["command_type"]

        if command_type == "ISOLATE_ENDPOINT" and command["endpoint_id"]:

            conn = get_db_connection()

            conn.execute("""
                UPDATE endpoints
                SET status = 'ISOLATED', isolated_by = ?, isolated_at = ?
                WHERE id = ?
            """, (
                command["requested_by"],
                now,
                command["endpoint_id"]
            ))

            conn.commit()
            conn.close()

        elif command_type == "RESTORE_ENDPOINT" and command["endpoint_id"]:

            conn = get_db_connection()

            conn.execute("""
                UPDATE endpoints
                SET status = 'CONNECTED', isolated_by = NULL, isolated_at = NULL
                WHERE id = ?
            """, (
                command["endpoint_id"],
            ))

            conn.commit()
            conn.close()

        elif command_type == "BLOCK_DESTINATION" and command["target"]:

            add_domain_to_blocklist(
                command["target"],
                "HIGH",
                f"Enforced via response command #{command_id}.",
                username=command["requested_by"]
            )

            conn = get_db_connection()

            conn.execute("""
                UPDATE blocked_domains
                SET enforcement_status = 'ENFORCED', last_command_id = ?
                WHERE domain = ?
            """, (
                command_id,
                command["target"]
            ))

            conn.commit()
            conn.close()

        elif command_type == "UNBLOCK_DESTINATION" and command["target"]:

            conn = get_db_connection()

            conn.execute("""
                UPDATE blocked_domains
                SET active = 0, enforcement_status = NULL
                WHERE domain = ?
            """, (
                command["target"],
            ))

            conn.commit()
            conn.close()

    write_log(
        f"RESPONSE_COMMAND_{status}",
        (
            f"Command #{command_id} ({command['command_type']}) "
            f"for endpoint {command['endpoint_ip']} "
            f"reported {status} ({mode or 'mode unknown'})."
        ),
        target_ip=command["endpoint_ip"],
        username="agent"
    )

    return True


# ==================================================
# PHASE 2: FAST INGESTION (SAVE-FIRST, ANALYZE LATER)
# ==================================================
# Used only by the agent-facing /api/web-events endpoint.
# Does NOT call normalize_destination() (DNS lookup) or
# analyze_ip_reputation() (VirusTotal/AbuseIPDB HTTP calls) -
# those are deferred to web_event_worker.py so the HTTP
# request returns almost immediately.
#
# STAGE 25F PHASE 6: the original synchronous analyze_web_event()
# (Phase 1/2 era) was retired here - confirmed zero live callers both
# before and after removal (see the Phase 6 closure report's call-site
# search). It was NOT what powers the manual Web Monitoring page's own
# "analyze this destination now" feature - that is a separate, live,
# still-present inline block inside the web_monitoring() view function
# below (POST branch), which calls the SAME shared create_web_incident()
# helper this dead function also called - that helper is kept, unchanged,
# because it is still used by that live manual path.

def _identity_logger(event_type, message):

    # Bounded system_logs entry for the endpoint identity guard (validated
    # UUIDs + canonical IP only; never a secret or a payload).
    write_log(event_type, message, username="system")


def _record_event_ip_history(endpoint_uid, endpoint_ip, source_ip):

    # Phase 13C: record that this STABLE agent installation was observed using
    # its reported IP and the connection's local address (both must pass the
    # history eligibility policy). Short transaction, bounded retry; every
    # failure is swallowed - IP history must never break event ingestion.
    conn = None

    try:

        conn = get_db_connection()

        addresses = [endpoint_ip]

        if source_ip:
            addresses.append(source_ip)

        db_config.retry_on_lock(
            lambda: endpoint_network.record_observations(
                conn,
                endpoint_uid,
                addresses,
                endpoint_network.sc.utc_now(),
                endpoint_network.SOURCE_EVENT,
                logger=_identity_logger,
                route="event"
            ),
            label="endpoint_ip_history_event",
            cleanup=lambda exc: conn.rollback(),
            log=lambda message: None
        )

    except Exception:

        pass

    finally:

        if conn is not None:
            conn.close()


def _identity_logger(event_type, message):

    # Bounded system_logs entry for the endpoint identity guard (validated
    # UUIDs + canonical IP only; never a secret or a payload).
    write_log(event_type, message, username="system")


def _record_event_ip_history(endpoint_uid, endpoint_ip, source_ip):

    # Phase 13C: record that this STABLE agent installation was observed using
    # its reported IP and the connection's local address (both must pass the
    # history eligibility policy). Short transaction, bounded retry; every
    # failure is swallowed - IP history must never break event ingestion.
    conn = None

    try:

        conn = get_db_connection()

        addresses = [endpoint_ip]

        if source_ip:
            addresses.append(source_ip)

        db_config.retry_on_lock(
            lambda: endpoint_network.record_observations(
                conn,
                endpoint_uid,
                addresses,
                endpoint_network.sc.utc_now(),
                endpoint_network.SOURCE_EVENT,
                logger=_identity_logger,
                route="event"
            ),
            label="endpoint_ip_history_event",
            cleanup=lambda exc: conn.rollback(),
            log=lambda message: None
        )

    except Exception:

        pass

    finally:

        if conn is not None:
            conn.close()


def _identity_logger(event_type, message):

    # Bounded system_logs entry for the endpoint identity guard (validated
    # UUIDs + canonical IP only; never a secret or a payload).
    write_log(event_type, message, username="system")


def _record_event_ip_history(endpoint_uid, endpoint_ip, source_ip):

    # Phase 13C: record that this STABLE agent installation was observed using
    # its reported IP and the connection's local address (both must pass the
    # history eligibility policy). Short transaction, bounded retry; every
    # failure is swallowed - IP history must never break event ingestion.
    conn = None

    try:

        conn = get_db_connection()

        addresses = [endpoint_ip]

        if source_ip:
            addresses.append(source_ip)

        db_config.retry_on_lock(
            lambda: endpoint_network.record_observations(
                conn,
                endpoint_uid,
                addresses,
                endpoint_network.sc.utc_now(),
                endpoint_network.SOURCE_EVENT,
                logger=_identity_logger,
                route="event"
            ),
            label="endpoint_ip_history_event",
            cleanup=lambda exc: conn.rollback(),
            log=lambda message: None
        )

    except Exception:

        pass

    finally:

        if conn is not None:
            conn.close()


def _identity_logger(event_type, message):

    # Bounded system_logs entry for the endpoint identity guard (validated
    # UUIDs + canonical IP only; never a secret or a payload).
    write_log(event_type, message, username="system")


def _record_event_ip_history(endpoint_uid, endpoint_ip, source_ip):

    # Phase 13C: record that this STABLE agent installation was observed using
    # its reported IP and the connection's local address (both must pass the
    # history eligibility policy). Short transaction, bounded retry; every
    # failure is swallowed - IP history must never break event ingestion.
    conn = None

    try:

        conn = get_db_connection()

        addresses = [endpoint_ip]

        if source_ip:
            addresses.append(source_ip)

        db_config.retry_on_lock(
            lambda: endpoint_network.record_observations(
                conn,
                endpoint_uid,
                addresses,
                endpoint_network.sc.utc_now(),
                endpoint_network.SOURCE_EVENT,
                logger=_identity_logger,
                route="event"
            ),
            label="endpoint_ip_history_event",
            cleanup=lambda exc: conn.rollback(),
            log=lambda message: None
        )

    except Exception:

        pass

    finally:

        if conn is not None:
            conn.close()


def analyze_web_event_fast(
    endpoint_ip,
    destination,
    process_name=None,
    observed_ip=None,
    source="endpoint-agent",
    attribution_type=None,
    os_username=None,
    process_pid=None,
    process_path=None,
    file_name=None,
    file_extension=None,
    sha256=None,
    md5=None,
    is_script_related=None,
    endpoint_uid=None,
    source_ip=None,
    destination_port=None,
    transport_protocol=None,
    process_create_time=None,
    process_instance_id=None
):

    try:
        ipaddress.ip_address(endpoint_ip)
    except ValueError:
        return None, "Invalid endpoint IP address."

    # Phase 12B.6D: only a well-formed UUIDv4 ever becomes a stable
    # identity; anything else is stored as NULL (never guessed).
    endpoint_uid = endpoint_identity.normalize_endpoint_uid(endpoint_uid)

    # Phase 13C: OS-observed connection metadata. A bad optional value becomes
    # NULL - it never rejects the event and is never guessed.
    source_ip = endpoint_network.sanitize_source_ip(source_ip)
    destination_port = endpoint_network.sanitize_port(destination_port)
    transport_protocol = endpoint_network.sanitize_protocol(transport_protocol)

    if not destination:
        return None, "destination is required"

    # Phase 13C: ENDPOINT UID CONSISTENCY GUARD. The shared X-Agent-Key stays
    # the only authentication; this only prevents a SILENT conflicting
    # identity assertion. If a DIFFERENT UID is currently bound to this IP the
    # event is still stored and analyzed (telemetry is never dropped) but the
    # unverified UID is NOT attached to the event or to the endpoints row.
    # A lapsed binding (DHCP-style reuse) is allowed. If the guard cannot be
    # evaluated (e.g. sustained lock) the UID is likewise not attached.
    event_uid = endpoint_uid
    endpoint_os_username = os_username

    if endpoint_uid:

        try:
            identity_decision = endpoint_network.evaluate_identity_standalone(
                endpoint_uid,
                endpoint_ip
            )
        except Exception:
            identity_decision = None
            event_uid = None
            endpoint_os_username = None

        if (
            identity_decision is not None
            and identity_decision.outcome == endpoint_network.IDENTITY_CONFLICT
        ):

            event_uid = None
            endpoint_os_username = None

            endpoint_network.log_event_conflict(
                _identity_logger,
                endpoint_network.canonical_ip(endpoint_ip),
                identity_decision.bound_uid,
                endpoint_uid
            )

    # Local/bounded reverse-DNS only (wrapped in try/except
    # inside save_endpoint itself) - not an external API call.
    save_endpoint(
        endpoint_ip,
        source="endpoint-agent",
        os_username=endpoint_os_username,
        endpoint_uid=event_uid
    )

    event_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_db_connection()

    try:

        # Step 25B: evidence-only process<->network correlation. Uses the
        # FINAL, identity-guard-resolved event_uid (never the raw,
        # possibly-conflicting one) - same read connection the INSERT
        # below uses. See process_correlation.py's module header for the
        # full identity/evidence rules; this NEVER changes risk_score,
        # severity, decision or triggers any alert/response.
        resolved_process_instance_id, correlation_status = process_correlation.resolve_correlation(
            conn,
            event_uid,
            process_pid,
            process_create_time,
            process_instance_id,
            event_time,
            logger=_identity_logger
        )

        cursor = conn.execute("""
            INSERT INTO web_events (
                event_time,
                endpoint_ip,
                process_name,
                destination,
                domain,
                resolved_ip,
                risk_score,
                severity,
                decision,
                username,
                details,
                analysis_status,
                source,
                observed_ip,
                attribution_type,
                os_username,
                process_pid,
                process_path,
                file_name,
                file_extension,
                sha256,
                md5,
                is_script_related,
                endpoint_uid,
                source_ip,
                destination_port,
                transport_protocol,
                process_instance_id,
                process_correlation_status
            )
            VALUES (
                ?, ?, ?, ?, NULL, NULL, 0, 'PENDING', 'PENDING',
                ?, NULL, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            event_time,
            endpoint_ip,
            process_name,
            destination,
            source,
            source,
            observed_ip,
            attribution_type,
            os_username,
            process_pid,
            process_path,
            file_name,
            file_extension,
            sha256,
            md5,
            is_script_related,
            event_uid,
            source_ip,
            destination_port,
            transport_protocol,
            resolved_process_instance_id,
            correlation_status
        ))

        event_id = cursor.lastrowid

        conn.commit()

    except BaseException:
        # Phase 12B.6C.1: deterministic rollback on any failure.
        conn.rollback()
        raise

    finally:
        conn.close()

    # Phase 13C: endpoint IP history (UID events only). A recording failure
    # must NEVER fail or delay event ingestion.
    if event_uid:
        _record_event_ip_history(event_uid, endpoint_ip, source_ip)

    return event_id, None


# ==================================================
# ENDPOINT AGENT API
# ==================================================

def _log_agent_auth_failure():

    # Transport-layer source (who actually connected), kept
    # separate from any endpoint_ip the client claims in its
    # JSON body - the JSON value is unverified telemetry, not
    # proof of network origin.
    source_ip = request.remote_addr or "unknown"

    now = time.time()

    if (
        now - _last_agent_auth_fail_log.get(source_ip, 0)
        < _AGENT_AUTH_FAIL_LOG_COOLDOWN_SECONDS
    ):
        # Avoid flooding system_logs with repeated identical
        # entries during a retry storm from the same source.
        return

    _last_agent_auth_fail_log[source_ip] = now

    data = request.get_json(silent=True) or {}

    reported_endpoint_ip = str(
        data.get("endpoint_ip", "")
    ).strip()[:100]

    message = f"Rejected /api/web-events request from {source_ip}"

    if reported_endpoint_ip:
        message += f" (reported endpoint_ip: {reported_endpoint_ip})"

    # Never log the supplied or expected key here.
    write_log(
        "AGENT_AUTH_FAILED",
        message,
        target_ip=source_ip,
        username="system"
    )


def _agent_auth_error():
    """
    Shared Phase 5/7 Agent authentication check (fail closed),
    reused by every agent-facing route (/api/web-events and the
    Phase 7 /api/agent/commands* routes) so there is exactly
    ONE place that decides what counts as an authenticated
    agent request. Returns a Flask response tuple to return
    immediately if auth fails, or None if the request is
    authenticated and the caller should proceed.
    """

    if not AGENT_API_KEY:

        # Misconfiguration, not an authentication failure - the
        # server must never silently accept unauthenticated
        # requests just because no key was configured.
        write_log(
            "AGENT_CONFIG_ERROR",
            (
                "AGENT_API_KEY is not configured on the server "
                "- rejecting all agent requests."
            ),
            username="system"
        )

        return jsonify({
            "status": "error",
            "message": (
                "Agent authentication is not configured "
                "on this server."
            )
        }), 503

    supplied_key = request.headers.get("X-Agent-Key", "")

    if not hmac.compare_digest(
        supplied_key.encode("utf-8"),
        AGENT_API_KEY.encode("utf-8")
    ):

        _log_agent_auth_failure()

        return jsonify({
            "status": "error",
            "message": "Unauthorized agent"
        }), 401

    return None


@web_monitoring_bp.route(
    "/api/web-events",
    methods=["POST"]
)
def receive_web_event():

    # --------------------------------------------------
    # PHASE 5: AGENT AUTHENTICATION (fail closed)
    # --------------------------------------------------

    auth_error = _agent_auth_error()

    if auth_error is not None:
        return auth_error

    data = request.get_json(
        silent=True
    ) or {}

    endpoint_ip = str(
        data.get(
            "endpoint_ip",
            request.remote_addr or ""
        )
    ).strip()

    destination = str(
        data.get(
            "destination",
            ""
        )
    ).strip()

    process_name = str(
        data.get(
            "process_name",
            ""
        )
    ).strip() or None

    observed_ip = str(
        data.get(
            "observed_ip",
            ""
        )
    ).strip() or None

    source = str(
        data.get(
            "source",
            "endpoint-agent"
        )
    ).strip() or "endpoint-agent"

    # Attribution provenance metadata only - never mixed into
    # `destination` itself. Anything other than these three known
    # values (including a missing field, e.g. an older agent that
    # predates this metadata) is stored as NULL/"unknown" rather
    # than rejecting the request - this field is not
    # security/analysis-critical.
    attribution_type = str(
        data.get(
            "attribution_type",
            ""
        )
    ).strip().lower() or None

    if attribution_type not in ("dns", "rdns", "ip"):

        attribution_type = None

    # --------------------------------------------------
    # PHASE 11B: OPTIONAL ENDPOINT IDENTITY / FILE-SCRIPT
    # TELEMETRY FIELDS
    # --------------------------------------------------
    # All fields below are optional. A missing field (old Agent
    # payload) must never fail ingestion - it simply stores as
    # NULL. A malformed VALUE (e.g. a bad hash string, a
    # non-numeric pid) is silently nulled out per-field too,
    # never a 400 - only an oversized string (checked in
    # field_limits below, same as the existing fields) is
    # rejected.

    os_username = str(
        data.get(
            "os_username",
            ""
        )
    ).strip() or None

    raw_process_pid = data.get("process_pid")

    process_pid = None

    if raw_process_pid is not None:

        try:
            candidate_pid = int(raw_process_pid)
            if 0 < candidate_pid <= 4294967295:
                process_pid = candidate_pid
        except (TypeError, ValueError):
            process_pid = None

    # Step 25B: optional - only a Step-25B-updated Agent sends these. An
    # old Agent (or a request that omits them) simply gets no
    # correlation attempt (process_correlation.resolve_correlation()
    # returns (None, None) for missing input) - never guessed.
    raw_process_create_time = data.get("process_create_time")

    process_create_time = None

    if raw_process_create_time is not None:

        try:
            process_create_time = float(raw_process_create_time)
        except (TypeError, ValueError):
            process_create_time = None

    raw_process_instance_id = data.get("process_instance_id")

    process_instance_id = (
        raw_process_instance_id
        if isinstance(raw_process_instance_id, str) and len(raw_process_instance_id) == 64
        else None
    )

    process_path = str(
        data.get(
            "process_path",
            ""
        )
    ).strip() or None

    file_name = str(
        data.get(
            "file_name",
            ""
        )
    ).strip() or None

    file_extension = str(
        data.get(
            "file_extension",
            ""
        )
    ).strip() or None

    raw_sha256 = str(
        data.get("sha256", "")
    ).strip().lower()

    sha256 = raw_sha256 if SHA256_PATTERN.match(raw_sha256) else None

    raw_md5 = str(
        data.get("md5", "")
    ).strip().lower()

    md5 = raw_md5 if MD5_PATTERN.match(raw_md5) else None

    # Nullable tri-state, not a boolean default: the key must be
    # PRESENT for a value to be stored at all. An old Agent that
    # never sends this key leaves is_script_related as NULL
    # ("telemetry unavailable"), never as 0 ("evaluated as
    # false") - the two are not the same claim.
    is_script_related = None

    if "is_script_related" in data:

        is_script_related = (
            1
            if data.get("is_script_related") in (
                True, 1, "1", "true", "True"
            )
            else 0
        )

    if not destination:

        return jsonify({
            "ok": False,
            "error": "destination is required"
        }), 400

    # Defense-in-depth against exactly the bug class that caused
    # the PTR-fallback regression: `destination` must always be a
    # plain hostname or IP - never decorated with a presentation
    # label - since it is fed straight into DNS resolution
    # (normalize_destination) and domain-IOC matching downstream.
    # Reject rather than silently strip, consistent with the
    # field-length validation below.
    if any(
        character in destination
        for character in (" ", "\t", "(", ")")
    ):

        return jsonify({
            "ok": False,
            "error": (
                "destination must be a plain hostname or IP "
                "address (no spaces or parentheses)."
            )
        }), 400

    # Phase 9: reject (not silently truncate) obviously
    # oversized/malformed fields before they ever reach the
    # database. Agent telemetry values are always short in
    # practice - an IP is at most 45 chars (IPv6), everything
    # else is a hostname/process/domain-length string.
    field_limits = {
        "endpoint_ip": (endpoint_ip, 45),
        "destination": (destination, 255),
        "process_name": (process_name or "", 255),
        "observed_ip": (observed_ip or "", 45),
        "source": (source, 100),
        "os_username": (os_username or "", 100),
        "process_path": (process_path or "", 500),
        "file_name": (file_name or "", 255),
        "file_extension": (file_extension or "", 20),
    }

    for field_name, (value, max_length) in field_limits.items():

        if len(value) > max_length:

            return jsonify({
                "ok": False,
                "error": (
                    f"{field_name} exceeds the maximum "
                    f"allowed length ({max_length})."
                )
            }), 400

    # Phase 12B.6D: stable agent identifier. IDENTITY METADATA ONLY - the
    # request was already authenticated by X-Agent-Key above and the UID
    # never substitutes for it. Malformed/missing -> NULL (old agents keep
    # working; nothing is ever fabricated from the IP or hostname).
    endpoint_uid = endpoint_identity.normalize_endpoint_uid(
        data.get("endpoint_uid")
    )

    event_id, error = analyze_web_event_fast(
        endpoint_ip,
        destination,
        process_name=process_name,
        observed_ip=observed_ip,
        source=source,
        attribution_type=attribution_type,
        os_username=os_username,
        process_pid=process_pid,
        process_path=process_path,
        file_name=file_name,
        file_extension=file_extension,
        sha256=sha256,
        md5=md5,
        is_script_related=is_script_related,
        endpoint_uid=endpoint_uid,
        source_ip=data.get("source_ip"),
        destination_port=data.get("destination_port"),
        transport_protocol=data.get("transport_protocol"),
        process_create_time=process_create_time,
        process_instance_id=process_instance_id
    )

    if error:

        return jsonify({
            "ok": False,
            "error": error
        }), 400

    return jsonify({
        "status": "accepted",
        "event_id": event_id,
        "analysis_status": "PENDING"
    }), 202


# ==================================================
# PHASE 7: AGENT COMMAND API
# ==================================================
# Same X-Agent-Key authentication as /api/web-events. The
# Agent only ever receives commands for the endpoint_ip IT
# ITSELF supplies (its own local IP, exactly like the existing
# /api/web-events payload) - never a list of all devices. This
# is the same trust boundary already accepted project-wide
# since Phase 2/5: X-Agent-Key proves "this is a legitimate
# agent"; endpoint_ip is self-declared telemetry, not something
# the server independently verifies against the TCP source.
# Documented explicitly here rather than treated as a new gap.

@web_monitoring_bp.route(
    "/api/agent/commands",
    methods=["GET"]
)
def get_agent_commands():

    auth_error = _agent_auth_error()

    if auth_error is not None:
        return auth_error

    endpoint_ip = str(
        request.args.get("endpoint_ip", "")
    ).strip()

    if not endpoint_ip:

        return jsonify({
            "status": "error",
            "message": "endpoint_ip is required"
        }), 400

    commands = get_pending_commands_for_endpoint(endpoint_ip)

    return jsonify({
        "status": "ok",
        "commands": [
            {
                "id": command["id"],
                "command_type": command["command_type"],
                "target": command["target"],
                "reason": command["reason"],
                "reference_command_id": command["reference_command_id"]
            }
            for command in commands
        ]
    }), 200


@web_monitoring_bp.route(
    "/api/agent/commands/<int:command_id>/result",
    methods=["POST"]
)
def post_agent_command_result(command_id):

    auth_error = _agent_auth_error()

    if auth_error is not None:
        return auth_error

    data = request.get_json(silent=True) or {}

    status = str(data.get("status", "")).strip().upper()

    allowed_statuses = (
        "ACKNOWLEDGED", "EXECUTING", "SUCCESS", "FAILED"
    )

    if status not in allowed_statuses:

        return jsonify({
            "status": "error",
            "message": "Invalid result status"
        }), 400

    result_message = str(data.get("result_message", ""))[:500]
    mode = str(data.get("mode", "")).strip().upper() or None

    if mode not in ("SIMULATED", "ENFORCED", None):
        mode = None

    updated = apply_command_result(
        command_id,
        status,
        result_message=result_message,
        mode=mode
    )

    if updated is None:

        return jsonify({
            "status": "error",
            "message": "Command not found"
        }), 404

    return jsonify({
        "status": "ok"
    }), 200


# ==================================================
# MAIN WEB MONITORING PAGE
# ==================================================

# ==================================================
# SERVICE/PROVIDER LABEL (presentation only)
# ==================================================
# Small, conservative, centralized hostname -> provider-name
# mapping for the Web Monitoring table only. Purely cosmetic -
# never touches the stored destination/domain value, never used
# for IOC matching, scoring, or any security decision. Suffix
# matching only (exact match or a "." boundary), same principle
# already used by domain_matches_ioc() in threat_intelligence.py
# - kept as a separate function since this is presentation, not
# threat-intel logic. No confident match -> None -> the UI simply
# omits the badge rather than guessing.

PROVIDER_LABELS = [
    (
        (
            "googleusercontent.com",
            "1e100.net",
            "google.com",
            "gstatic.com",
            "googleapis.com"
        ),
        "Google"
    ),
    (
        (
            "amazonaws.com",
            "compute.amazonaws.com"
        ),
        "AWS"
    ),
    (
        ("cloudfront.net",),
        "CloudFront"
    ),
    (
        (
            "akamaitechnologies.com",
            "akamaiedge.net",
            "akamai.net"
        ),
        "Akamai"
    ),
    (
        ("avcdn.net",),
        "Avast"
    ),
    (
        (
            "microsoft.com",
            "windows.net",
            "office.com",
            "office365.com",
            "sharepoint.com",
            "live.com"
        ),
        "Microsoft"
    ),
]


def guess_provider_label(hostname):

    if not hostname:
        return None

    hostname = hostname.lower().strip(".")

    for suffixes, label in PROVIDER_LABELS:

        for suffix in suffixes:

            if hostname == suffix or hostname.endswith("." + suffix):
                return label

    return None


# Step 24A.3: maximum allowed span for the Web Monitoring date-range
# filter. Generous for interactive investigation while still bounding
# worst-case query cost on a 100k+ row table with no index on
# event_time alone (the existing composite indexes - endpoint_ip+time,
# domain+time, resolved_ip+time, uid+time - all still apply when their
# leading column is also filtered; a date-only filter with no other
# column narrows by table scan either way, so bounding the span is the
# real protection here).
MAX_DATE_RANGE_DAYS = 90

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _clamp_date_range(raw_from, raw_to):
    """
    Validates and bounds the Web Monitoring date-range filter.
    Malformed input on either side is treated as "no filter on that
    side" (never raises, never reaches SQL unvalidated) - consistent
    with how every other filter on this page silently ignores an
    unrecognized value rather than erroring the whole page. Returns
    (date_from_or_None, date_to_or_None, note_or_None) where note is a
    short, user-visible explanation ONLY when the requested range was
    clamped down to MAX_DATE_RANGE_DAYS.
    """

    date_from = raw_from if _DATE_RE.match(raw_from or "") else None
    date_to = raw_to if _DATE_RE.match(raw_to or "") else None

    if date_from and date_to and date_from > date_to:
        # Backwards range - safer to drop both than guess which end
        # the user actually meant.
        return None, None, None

    if date_from and date_to:

        try:
            start = datetime.strptime(date_from, "%Y-%m-%d")
            end = datetime.strptime(date_to, "%Y-%m-%d")
        except ValueError:
            return None, None, None

        if (end - start).days > MAX_DATE_RANGE_DAYS:
            start = end - timedelta(days=MAX_DATE_RANGE_DAYS)
            date_from = start.strftime("%Y-%m-%d")
            return date_from, date_to, (
                f"Date range was limited to the most recent {MAX_DATE_RANGE_DAYS} days."
            )

    return date_from, date_to, None


@web_monitoring_bp.route(
    "/web-monitoring",
    methods=[
        "GET",
        "POST"
    ]
)
def web_monitoring():

    if not login_required():

        return redirect(
            url_for(
                "login"
            )
        )

    error = None
    success = None
    analysis = None

    # ==================================================
    # ANALYZE DESTINATION
    # ==================================================

    if request.method == "POST":

        endpoint_ip = request.form.get(
            "endpoint_ip",
            ""
        ).strip()

        destination = request.form.get(
            "destination",
            ""
        ).strip()

        # --------------------------------------------------
        # VALIDATE ENDPOINT IP
        # --------------------------------------------------

        try:

            ipaddress.ip_address(
                endpoint_ip
            )

        except ValueError:

            error = (
                "Invalid endpoint IP address."
            )

        # --------------------------------------------------
        # ENDPOINT MUST BE A REAL MANAGED (AGENT-SOURCED)
        # ENDPOINT - re-verified server-side regardless of what
        # the form's dropdown shows, so a forged/arbitrary POST
        # value can never be accepted just because it looks like
        # a valid IP address.
        # --------------------------------------------------

        if error is None:

            managed_check_conn = get_db_connection()

            managed_endpoint = managed_check_conn.execute("""
                SELECT id
                FROM endpoints
                WHERE ip_address = ?
                AND source = 'endpoint-agent'
            """, (
                endpoint_ip,
            )).fetchone()

            managed_check_conn.close()

            if managed_endpoint is None:

                error = (
                    "Selected endpoint is not a recognized "
                    "managed endpoint."
                )

        # --------------------------------------------------
        # RESOLVE DESTINATION
        # --------------------------------------------------

        if error is None:

            (
                domain,
                resolved_ip,
                resolve_error
            ) = normalize_destination(
                destination
            )

            if resolve_error:

                error = resolve_error

        # --------------------------------------------------
        # ANALYSIS
        # --------------------------------------------------

        if error is None:

            # No save_endpoint() call here - Manual Destination
            # Analysis must never create or promote an endpoints
            # row. It only ever operates against an endpoint that
            # was already validated above as a real, existing
            # source='endpoint-agent' row - last_seen/hostname for
            # that row are refreshed exclusively by real agent
            # telemetry, never by this analyst-initiated action.

            already_blocked = (
                domain_is_blocked(
                    domain
                )
            )

            reputation = None

            risk_score = 0
            severity = "INFO"
            reasons = []

            if resolved_ip:

                try:

                    resolved_object = (
                        ipaddress.ip_address(
                            resolved_ip
                        )
                    )

                except ValueError:

                    resolved_object = None

                # --------------------------------------------------
                # PUBLIC DESTINATION IP
                # --------------------------------------------------

                if (
                    resolved_object
                    and resolved_object.is_global
                ):

                    local_ioc = (
                        local_ioc_exists(
                            resolved_ip
                        )
                    )

                    reputation = (
                        analyze_ip_reputation(
                            resolved_ip,
                            local_ioc
                        )
                    )

                    if not reputation.get(
                        "error"
                    ):

                        risk_score = int(
                            reputation.get(
                                "risk_score",
                                0
                            ) or 0
                        )

                        severity = (
                            reputation.get(
                                "severity",
                                "INFO"
                            )
                        )

                        reasons = list(
                            reputation.get(
                                "reasons",
                                []
                            )
                        )

                    else:

                        reasons.append(
                            reputation.get(
                                "error"
                            )
                        )

                else:

                    reasons.append(
                        (
                            "Destination resolved "
                            "to a private/local IP. "
                            "External reputation "
                            "was not performed."
                        )
                    )

            # --------------------------------------------------
            # DECISION
            # --------------------------------------------------

            decision = "ALLOWED"

            if already_blocked:

                decision = "BLOCKED"

                reasons.append(
                    (
                        "Domain already exists "
                        "in the active block list."
                    )
                )

            elif severity in [
                "HIGH",
                "CRITICAL"
            ]:

                decision = "BLOCKED"

                add_domain_to_blocklist(
                    domain,
                    severity,
                    (
                        "Automatically added after "
                        f"risk score {risk_score}/100."
                    )
                )

                incident_id = (
                    create_web_incident(
                        endpoint_ip,
                        domain,
                        resolved_ip,
                        severity,
                        risk_score,
                        reasons
                    )
                )

                reasons.append(
                    (
                        f"Security Incident "
                        f"#{incident_id} created."
                    )
                )

            # --------------------------------------------------
            # SAVE EVENT
            # --------------------------------------------------

            event_time = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            conn = get_db_connection()

            conn.execute("""
                INSERT INTO web_events (
                    event_time,
                    endpoint_ip,
                    destination,
                    domain,
                    resolved_ip,
                    risk_score,
                    severity,
                    decision,
                    username,
                    details,
                    source,
                    analysis_status,
                    analysis_completed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_time,
                endpoint_ip,
                destination,
                domain,
                resolved_ip,
                risk_score,
                severity,
                decision,
                session.get(
                    "username"
                ),
                "; ".join(
                    reasons
                ),
                "manual",
                "ANALYZED",
                event_time
            ))

            conn.commit()
            conn.close()

            # --------------------------------------------------
            # LOG EVENT
            # --------------------------------------------------

            write_log(
                "WEB_DESTINATION_ANALYZED",
                (
                    f"{endpoint_ip} -> "
                    f"{domain} "
                    f"({resolved_ip}) | "
                    f"Risk {risk_score}/100 | "
                    f"{severity} | "
                    f"{decision}"
                ),
                target_ip=endpoint_ip
            )

            analysis = {

                "endpoint_ip":
                    endpoint_ip,

                "destination":
                    destination,

                "domain":
                    domain,

                "resolved_ip":
                    resolved_ip,

                "risk_score":
                    risk_score,

                "severity":
                    severity,

                "decision":
                    decision,

                "reasons":
                    reasons,

                "reputation":
                    reputation
            }

            success = (
                "Web destination analyzed successfully."
            )

    # ==================================================
    # LOAD PAGE DATA
    # ==================================================

    severity_filter = request.args.get("severity", "").strip()
    decision_filter = request.args.get("decision", "").strip()
    attribution_filter = request.args.get("attribution", "").strip()
    process_filter = request.args.get("process", "").strip()
    source_filter = request.args.get("source", "").strip()
    analysis_status_filter = request.args.get("analysis_status", "").strip()
    search_filter = request.args.get("q", "").strip()

    # Step 24A.3: computer filter, by the STABLE identity (endpoint_uid),
    # not by IP - a single physical machine can legitimately have
    # several historical endpoint_ip values (address changes), which
    # filtering by IP would miss. Malformed/unrecognized values are
    # silently ignored (same convention as attribution_filter above),
    # never raise, never reach SQL unvalidated.
    endpoint_uid_filter = endpoint_identity.normalize_endpoint_uid(
        request.args.get("endpoint_uid", "")
    )

    # Step 24A.3: date-range filter. event_time is stored project-wide
    # as a NAIVE LOCAL timestamp string ("%Y-%m-%d %H:%M:%S" - see
    # write_log/create_security_alert/etc.), never UTC - so a calendar
    # date here is interpreted the same way: a local calendar day,
    # consistent with every other timestamp already on this page, not
    # a new UTC-conversion layer that would silently disagree with the
    # rest of the system.
    date_from_filter, date_to_filter, date_range_note = _clamp_date_range(
        request.args.get("date_from", "").strip(),
        request.args.get("date_to", "").strip()
    )

    # Step 24A.4 Task 2: KEYSET pagination by web_events.id (replaces the
    # earlier OFFSET-based paging). id is the table's own monotonic,
    # unique primary key - an unambiguous, stable sort anchor that never
    # needs a secondary tiebreaker. Two independent cursors:
    #   before_id=<id>  "Next" - rows older than this (id < before_id)
    #   after_id=<id>   "Previous" - rows newer than this (id > after_id),
    #                   fetched ascending then reversed for display
    # Malformed/non-numeric/non-positive values, or BOTH cursors present
    # at once (ambiguous), are ignored entirely - falls back to the
    # first page rather than guessing or raising. Critically: unlike
    # OFFSET, a cursor is an ANCHOR to one specific row's id, not a
    # "skip N rows" instruction - new rows arriving between requests
    # (any id, higher or lower) can never shift where an existing
    # cursor points, which is exactly what eliminates the duplicate-
    # across-pages drift the previous OFFSET design had (demonstrated
    # directly in test_web_monitoring_perf_step24a3.py's concurrency
    # test, and re-verified for this design in
    # test_web_monitoring_keyset_step24a4.py).
    PAGE_SIZE = 50

    def _parse_cursor(raw):
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            return None
        return value if value > 0 else None

    before_id = _parse_cursor(request.args.get("before_id", ""))
    after_id = _parse_cursor(request.args.get("after_id", ""))

    if before_id is not None and after_id is not None:
        # Ambiguous (a hand-edited or stale URL claiming both directions
        # at once) - never guess which one the caller meant.
        before_id = None
        after_id = None

    paging_direction = "prev" if after_id is not None else "next"

    events_query = """
        SELECT
            web_events.*,
            endpoints.hostname AS endpoint_hostname
        FROM web_events
        LEFT JOIN endpoints
            ON endpoints.ip_address = web_events.endpoint_ip
        WHERE 1=1
    """
    events_params = []

    if severity_filter:
        events_query += " AND web_events.severity = ?"
        events_params.append(severity_filter)

    if decision_filter:
        events_query += " AND web_events.decision = ?"
        events_params.append(decision_filter)

    if attribution_filter == "unknown":
        events_query += " AND web_events.attribution_type IS NULL"
    elif attribution_filter in ("dns", "rdns", "ip"):
        events_query += " AND web_events.attribution_type = ?"
        events_params.append(attribution_filter)

    if process_filter:
        events_query += " AND web_events.process_name = ?"
        events_params.append(process_filter)

    if source_filter == "manual":
        events_query += " AND web_events.source IS NULL"
    elif source_filter:
        events_query += " AND web_events.source = ?"
        events_params.append(source_filter)

    if analysis_status_filter:
        events_query += " AND web_events.analysis_status = ?"
        events_params.append(analysis_status_filter)

    if endpoint_uid_filter:
        events_query += " AND web_events.endpoint_uid = ?"
        events_params.append(endpoint_uid_filter)

    if date_from_filter:
        events_query += " AND web_events.event_time >= ?"
        events_params.append(date_from_filter + " 00:00:00")

    if date_to_filter:
        events_query += " AND web_events.event_time <= ?"
        events_params.append(date_to_filter + " 23:59:59")

    if search_filter:
        events_query += """ AND (
            web_events.destination LIKE ?
            OR web_events.domain LIKE ?
            OR web_events.resolved_ip LIKE ?
            OR web_events.observed_ip LIKE ?
            OR web_events.process_name LIKE ?
            OR web_events.endpoint_ip LIKE ?
            OR endpoints.hostname LIKE ?
            OR web_events.url LIKE ?
        )"""
        like_value = f"%{search_filter}%"
        events_params.extend([like_value] * 8)

    # Cursor boundary + direction. "prev" fetches ASCENDING (closest to
    # after_id first) so the +1 overflow row is the FARTHEST one (the
    # correct side to detect "is there even more above this"); it is
    # reversed back to the usual DESC display order below, after the
    # overflow row has been trimmed off.
    base_query = events_query
    base_params = list(events_params)

    if paging_direction == "prev":
        cursor_query = base_query + " AND web_events.id > ? ORDER BY web_events.id ASC LIMIT ?"
        cursor_params = base_params + [after_id, PAGE_SIZE + 1]
    elif before_id is not None:
        cursor_query = base_query + " AND web_events.id < ? ORDER BY web_events.id DESC LIMIT ?"
        cursor_params = base_params + [before_id, PAGE_SIZE + 1]
    else:
        cursor_query = base_query + " ORDER BY web_events.id DESC LIMIT ?"
        cursor_params = base_params + [PAGE_SIZE + 1]

    conn = get_db_connection()

    raw_events = conn.execute(cursor_query, cursor_params).fetchall()

    if paging_direction == "prev" and not raw_events:
        # Stale/invalid after_id (e.g. that row no longer exists and
        # nothing newer does either) - degrade to the first page rather
        # than render a dead end with no way back.
        before_id = None
        after_id = None
        paging_direction = "next"
        raw_events = conn.execute(
            base_query + " ORDER BY web_events.id DESC LIMIT ?",
            base_params + [PAGE_SIZE + 1]
        ).fetchall()

    if paging_direction == "prev":
        has_more_in_this_direction = len(raw_events) > PAGE_SIZE
        raw_events = raw_events[:PAGE_SIZE]
        raw_events = list(reversed(raw_events))  # back to newest-first display order
        has_previous = has_more_in_this_direction
        has_next = True  # there is always a "forward" back toward where we came from
    else:
        has_more_in_this_direction = len(raw_events) > PAGE_SIZE
        raw_events = raw_events[:PAGE_SIZE]
        has_next = has_more_in_this_direction
        has_previous = before_id is not None

    if not raw_events:
        # before_id pointed past the end (e.g. a concurrent delete) -
        # nothing to show, but still offer a way back rather than a
        # dead end.
        has_next = False
        has_previous = before_id is not None

    next_cursor = raw_events[-1]["id"] if (raw_events and has_next) else None
    prev_cursor = raw_events[0]["id"] if (raw_events and has_previous) else before_id

    event_ids = [row["id"] for row in raw_events]

    alert_by_event_id = {}

    if event_ids:

        placeholders = ",".join("?" * len(event_ids))

        alert_rows = conn.execute(
            f"""
                SELECT id, source_event_id
                FROM security_alerts
                WHERE source_event_id IN ({placeholders})
            """,
            event_ids
        ).fetchall()

        for alert_row in alert_rows:
            alert_by_event_id[alert_row["source_event_id"]] = alert_row["id"]

    # Phase 11C: behavioral results, one-to-one with web_events.id
    # via UNIQUE(web_event_id). A missing entry means the event
    # predates the behavioral engine's bootstrap cutoff (or hasn't
    # been picked up by behavioral_worker.py yet) - rendered
    # honestly as "no behavioral result", never a fabricated label.
    behavioral_by_event_id = {}

    if event_ids:

        placeholders = ",".join("?" * len(event_ids))

        behavioral_rows = conn.execute(
            f"""
                SELECT *
                FROM behavioral_event_results
                WHERE web_event_id IN ({placeholders})
            """,
            event_ids
        ).fetchall()

        for behavioral_row in behavioral_rows:
            behavioral_by_event_id[behavioral_row["web_event_id"]] = dict(behavioral_row)

    # Phase 12B.5B: Cloudflare MANUAL action state. Budget is read once;
    # per-event state is pure DB reads. Rendering NEVER performs a
    # Cloudflare request (only POST /cloudflare-investigate can).
    try:
        cf_budget = cloudflare_provider.get_budget_state(conn)
    except Exception:
        cf_budget = None

    cf_message = cloudflare_provider.OUTCOME_MESSAGES.get(
        (request.args.get("cf") or "").strip().upper()
    )
    cf_event_id = request.args.get("cf_event", "")

    # Step 24B.1: feedback for the "Investigate URL" button's redirect
    # (mirrors cf_message/cf_event_id above exactly). "blocked" means
    # the server-side privacy policy refused to send the URL
    # externally; "in_progress" means a concurrent request for the
    # same (provider, url) was already in flight.
    url_intel_message = (request.args.get("url_intel") or "").strip()
    url_intel_event_id = request.args.get("url_intel_event", "")

    # Step 24A.4 Task 1: computed ONCE per page load (one query) and
    # reused for every displayed event below - see
    # threat_intel_framework.build_enrichment_window_snapshot()'s own
    # docstring for why (previously: ~2 identical COUNT(*) JOIN queries
    # PER DISPLAYED EVENT, confirmed via profiling to dominate page
    # render time at real data volume). Same exact per-event answer,
    # verified by test_enrichment_window_equivalence_step24a4.py.
    enrichment_snapshot = threat_intel_fw.build_enrichment_window_snapshot(conn)

    events = []

    for row in raw_events:

        event = dict(row)

        event["provider_label"] = guess_provider_label(
            event["domain"] or event["destination"]
        )

        event["destination_ip_display"] = (
            event["resolved_ip"]
            or event["observed_ip"]
            or None
        )

        event["alert_id"] = alert_by_event_id.get(event["id"])

        behavioral_result = behavioral_by_event_id.get(event["id"])

        event["behavioral_result"] = behavioral_result

        if behavioral_result:

            event["behavioral_display_label"] = behavioral_label(
                behavioral_result["evaluation_status"],
                behavioral_result["anomaly_score"]
            )

            try:
                event["behavioral_reasons_list"] = json.loads(
                    behavioral_result["behavioral_reasons"] or "[]"
                )
            except (json.JSONDecodeError, TypeError):
                event["behavioral_reasons_list"] = []

        else:

            event["behavioral_display_label"] = None
            event["behavioral_reasons_list"] = []

        # Phase 11D.1: read-only ThreatFox evidence lookup (never
        # performs a live lookup here - only reads whatever
        # threat_intel_evidence rows already exist) + Investigation
        # Priority, computed fresh at render time from already-
        # stored Threat Risk / Behavioral / local-IOC / ThreatFox
        # evidence. Never writes anything.
        event["threatfox_evidence"] = get_stored_evidence_for_event(
            event["resolved_ip"], event["domain"], event["sha256"]
        )

        # Phase 12B.2: DISPLAY-ONLY, multi-provider evidence (ThreatFox +
        # URLhaus, now including MD5 candidates). Deliberately NOT used
        # as compute_investigation_priority()'s input above/below - that
        # keeps reading event["threatfox_evidence"] exactly as before,
        # unchanged, per the explicit instruction not to let URLhaus
        # affect Investigation Priority in this phase.
        event["ti_evidence_multi"] = threat_intel_fw.get_all_provider_evidence_for_event_with_conn(
            conn, event["resolved_ip"], event["domain"], event["sha256"], event["md5"]
        )

        # Oct 2026 Step 5: live, DISPLAY-ONLY Legacy-vs-multi-source
        # comparison (read-only against already-cached evidence; never
        # writes anywhere; does NOT activate the Step 4 Shadow Mode
        # pipeline - see threat_intel_display.compute_display_only_comparison).
        event["ti_comparison"] = threat_intel_display.compute_display_only_comparison(
            event["resolved_ip"], event["domain"], event["sha256"], event["md5"],
            event["risk_score"], event["severity"]
        )

        # Oct 2026 Step 18: the PERSISTED shadow_comparisons record for
        # this specific event (None if Shadow Mode hasn't evaluated it -
        # e.g. Shadow Mode disabled, or the event predates it). Purely
        # read-only, no computation triggered here. This is what lets the
        # panel show "first computed at X / updated N times since" - the
        # initial-vs-updated distinction - alongside the always-fresh
        # ti_comparison above, which already reflects current evidence on
        # every render regardless of this record's own freshness.
        event["ti_shadow_record"] = threat_intel_display.shadow_comparison_for_event(event["id"])

        # Oct 2026 Step 13: per-event provider status (selected/completed/
        # queued/processing/not configured/rate limited/failed/manual
        # only/not applicable) - read-only, never triggers a live lookup.
        event["ti_provider_status"] = threat_intel_display.per_event_provider_status(
            event["resolved_ip"], event["domain"], event["sha256"], event["md5"],
            event_analysis_status=event.get("analysis_status"),
            event_time=event.get("event_time"),
            enrichment_snapshot=enrichment_snapshot
        )

        event["investigation_priority_level"], event["investigation_priority_reasons"] = (
            compute_investigation_priority(
                event["severity"],
                event["behavioral_display_label"],
                behavioral_result["confidence"] if behavioral_result else None,
                detect_local_ioc_matched(event["details"]),
                event["threatfox_evidence"]
            )
        )

        event["cf_actions"] = []

        if cf_budget is not None:

            try:
                for cf_type, cf_raw in (("IP", event["resolved_ip"]), ("DOMAIN", event["domain"])):

                    cf_value = (
                        threat_intel_fw.normalize_ip_candidate(cf_raw)
                        if cf_type == "IP"
                        else threat_intel_fw.normalize_domain_candidate(cf_raw)
                    )

                    if cf_value:
                        event["cf_actions"].append({
                            "type": cf_type,
                            "value": cf_value,
                            "state": cloudflare_provider.get_action_state(
                                conn, cf_type, cf_value, cf_budget
                            )
                        })
            except Exception:
                event["cf_actions"] = []

        # Step 24B.1: URL threat-intel status (Google Safe Browsing /
        # PhishTank) - read-only, never performs a live lookup; only
        # POST /api/url-intel/investigate can. Only populated for
        # browser-sourced events that actually carry a url.
        try:
            event["url_intel_actions"] = threat_intel_display.url_intel_status_for_event(
                conn, event.get("url")
            )
        except Exception:
            event["url_intel_actions"] = []

        # Step 24B.2A: Local Threat Intelligence Feed - read-only
        # display. local_feed_evidence.get_display_rows_for_event()
        # performs ONLY local SQLite index lookups (no external HTTP
        # call of any kind - see local_feed_store.py), so calling it on
        # every page render is not "automatic external checking" in the
        # sense that instruction forbids; it never sends anything
        # off-box. NEVER presents NO_MATCH as "safe" (see
        # local_feed_evidence.py's module header).
        try:
            event["local_feed_actions"] = local_feed_evidence.get_display_rows_for_event(
                resolved_ip=event["resolved_ip"], domain=event["domain"],
                url=event.get("url")
            )
        except Exception:
            event["local_feed_actions"] = []

        events.append(event)

    distinct_processes = conn.execute("""
        SELECT DISTINCT process_name
        FROM web_events
        WHERE process_name IS NOT NULL
        ORDER BY process_name
    """).fetchall()

    # Step 24A.3: one dropdown entry per COMPUTER (endpoint_uid), not per
    # historical (endpoint_uid, ip_address) record - the same physical
    # machine can have several `endpoints` rows over time (address
    # changes; confirmed in the Step 24A pilot itself: one machine had 3
    # historical ip_address rows for the same endpoint_uid). The join
    # below picks each endpoint_uid's MOST RECENTLY SEEN hostname as its
    # single representative label; the Python loop below is a second,
    # unconditional safety net that guarantees exactly one entry per
    # endpoint_uid even in the (currently impossible, but not provably
    # unreachable) case of two rows sharing an identical last_seen.
    raw_distinct_computers = conn.execute("""
        SELECT e.endpoint_uid, e.hostname, e.ip_address
        FROM endpoints e
        JOIN (
            SELECT endpoint_uid, MAX(last_seen) AS max_seen
            FROM endpoints
            WHERE endpoint_uid IS NOT NULL
            GROUP BY endpoint_uid
        ) latest
            ON latest.endpoint_uid = e.endpoint_uid
            AND latest.max_seen = e.last_seen
        ORDER BY e.hostname
    """).fetchall()

    distinct_computers = []
    _seen_endpoint_uids = set()

    for row in raw_distinct_computers:

        if row["endpoint_uid"] in _seen_endpoint_uids:
            continue

        _seen_endpoint_uids.add(row["endpoint_uid"])
        distinct_computers.append(row)

    # Managed Endpoints: only rows genuinely observed through
    # authenticated Endpoint Agent telemetry (source='endpoint-
    # agent') are shown/selectable here. Manual-analysis and
    # historical/ambiguous (NULL-source) rows are deliberately
    # excluded - they still exist in the database, just not as
    # "managed endpoints" in this UI.
    raw_endpoints = conn.execute("""
        SELECT *
        FROM endpoints
        WHERE source = 'endpoint-agent'
        ORDER BY
            CASE status
                WHEN 'ISOLATED'
                THEN 1
                ELSE 2
            END,
            id DESC
    """).fetchall()

    endpoints = []

    for endpoint_row in raw_endpoints:

        endpoint = dict(endpoint_row)

        # Presence is derived from last_seen, never taken from
        # the static `status` column (that column only reflects
        # ISOLATED/CONNECTED admin-driven state, not liveness).
        # last_seen is refreshed by web-event telemetry only,
        # not a guaranteed heartbeat - an agent can be alive and
        # simply not have generated qualifying traffic recently,
        # so STALE is not proof of a dead/uninstalled agent.
        presence = "UNKNOWN"

        if endpoint["last_seen"]:

            try:

                last_seen_dt = datetime.strptime(
                    endpoint["last_seen"],
                    "%Y-%m-%d %H:%M:%S"
                )

                age = datetime.now() - last_seen_dt

                if age <= timedelta(minutes=2):
                    presence = "ONLINE"
                elif age <= timedelta(hours=24):
                    presence = "STALE"
                else:
                    presence = "OFFLINE"

            except ValueError:

                presence = "UNKNOWN"

        endpoint["presence"] = presence

        endpoints.append(endpoint)

    blocked_domains = conn.execute("""
        SELECT *
        FROM blocked_domains
        ORDER BY
            active DESC,
            id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "web_monitoring.html",
        error=error,
        success=success,
        analysis=analysis,
        events=events,
        endpoints=endpoints,
        blocked_domains=blocked_domains,
        distinct_processes=distinct_processes,
        distinct_computers=distinct_computers,
        severity_filter=severity_filter,
        decision_filter=decision_filter,
        attribution_filter=attribution_filter,
        process_filter=process_filter,
        source_filter=source_filter,
        analysis_status_filter=analysis_status_filter,
        search_filter=search_filter,
        endpoint_uid_filter=endpoint_uid_filter,
        date_from_filter=date_from_filter,
        date_to_filter=date_to_filter,
        date_range_note=date_range_note,
        has_next=has_next,
        has_previous=has_previous,
        next_cursor=next_cursor,
        prev_cursor=prev_cursor,
        cf_budget=cf_budget,
        cf_message=cf_message,
        cf_event_id=cf_event_id,
        url_intel_message=url_intel_message,
        url_intel_event_id=url_intel_event_id
    )


# ==================================================
# ISOLATE ENDPOINT
# ==================================================

@web_monitoring_bp.route(
    "/endpoints/<int:endpoint_id>/isolate",
    methods=[
        "POST"
    ]
)
def isolate_endpoint(
    endpoint_id
):

    if not login_required():

        return redirect(
            url_for(
                "login"
            )
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    username = session.get(
        "username"
    )

    conn = get_db_connection()

    endpoint = conn.execute("""
        SELECT *
        FROM endpoints
        WHERE id = ?
    """, (
        endpoint_id,
    )).fetchone()

    if endpoint is None:

        conn.close()

        return (
            "Endpoint not found",
            404
        )

    conn.close()

    # Defense in depth: never queue a containment command
    # against a row that isn't a real, agent-observed managed
    # endpoint - regardless of whether any UI still offers this
    # action. Rejects safely, no stack trace/internal detail.
    if endpoint["source"] != "endpoint-agent":

        return (
            "This endpoint is not a recognized managed "
            "endpoint and cannot be isolated.",
            400
        )

    # --------------------------------------------------
    # PHASE 7: REQUEST, DO NOT IMMEDIATELY APPLY
    # --------------------------------------------------
    # Isolation now goes through the same response_commands
    # pipeline as the Alert Details page - endpoints.status only
    # becomes 'ISOLATED' once the Agent reports SUCCESS (see
    # apply_command_result()). This route no longer flips the
    # status itself.

    command, reused = create_response_command(
        "ISOLATE_ENDPOINT",
        endpoint["ip_address"],
        reason="Requested from Web Monitoring endpoint list.",
        requested_by=username
    )

    write_log(
        "ENDPOINT_ISOLATION_REQUESTED",
        (
            f"Isolation requested for endpoint "
            f"{endpoint['ip_address']} by {username} "
            f"(command #{command['id']}"
            + (", reused existing" if reused else "")
            + ")."
        ),
        target_ip=endpoint["ip_address"]
    )

    return redirect(
        url_for(
            "web_monitoring.web_monitoring"
        )
    )


# ==================================================
# RESTORE ENDPOINT
# ==================================================

@web_monitoring_bp.route(
    "/endpoints/<int:endpoint_id>/restore",
    methods=[
        "POST"
    ]
)
def restore_endpoint(
    endpoint_id
):

    if not login_required():

        return redirect(
            url_for(
                "login"
            )
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    username = session.get(
        "username"
    )

    conn = get_db_connection()

    endpoint = conn.execute("""
        SELECT *
        FROM endpoints
        WHERE id = ?
    """, (
        endpoint_id,
    )).fetchone()

    if endpoint is None:

        conn.close()

        return (
            "Endpoint not found",
            404
        )

    conn.close()

    # Defense in depth: same managed-endpoint check as isolate -
    # never queue a containment command against a non-agent row.
    if endpoint["source"] != "endpoint-agent":

        return (
            "This endpoint is not a recognized managed "
            "endpoint and cannot be restored.",
            400
        )

    # Phase 7: request restore via response_commands - status
    # only flips back to 'CONNECTED' once the Agent reports
    # SUCCESS (see apply_command_result()).

    command, reused = create_response_command(
        "RESTORE_ENDPOINT",
        endpoint["ip_address"],
        reason="Requested from Web Monitoring endpoint list.",
        requested_by=username
    )

    write_log(
        "ENDPOINT_RESTORE_REQUESTED",
        (
            f"Restore requested for endpoint "
            f"{endpoint['ip_address']} by {username} "
            f"(command #{command['id']}"
            + (", reused existing" if reused else "")
            + ")."
        ),
        target_ip=endpoint["ip_address"]
    )

    return redirect(
        url_for(
            "web_monitoring.web_monitoring"
        )
    )


# ==================================================
# ENABLE / DISABLE DOMAIN BLOCK
# ==================================================

@web_monitoring_bp.route(
    "/blocked-domains/<int:block_id>/toggle",
    methods=[
        "POST"
    ]
)
def toggle_blocked_domain(
    block_id
):

    if not login_required():

        return redirect(
            url_for(
                "login"
            )
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    conn = get_db_connection()

    block = conn.execute("""
        SELECT *
        FROM blocked_domains
        WHERE id = ?
    """, (
        block_id,
    )).fetchone()

    if block is None:

        conn.close()

        return (
            "Block rule not found",
            404
        )

    new_active = (
        0
        if block["active"] == 1
        else 1
    )

    conn.execute("""
        UPDATE blocked_domains
        SET active = ?
        WHERE id = ?
    """, (
        new_active,
        block_id
    ))

    conn.commit()
    conn.close()

    state = (
        "enabled"
        if new_active == 1
        else "disabled"
    )

    write_log(
        "DOMAIN_BLOCK_STATUS_CHANGED",
        (
            f"Block rule for "
            f"{block['domain']} "
            f"was {state}."
        )
    )

    return redirect(
        url_for(
            "web_monitoring.web_monitoring"
        )
    )