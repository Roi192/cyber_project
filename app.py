from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    g
)

import json
import os
import re
import secrets
import socket
import ipaddress
import threading
import db_config
import sqlite3

from datetime import datetime, timedelta
from io import BytesIO

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reputation_routes import (
    reputation_bp,
    init_reputation_db
)
from flask_wtf import CSRFProtect

from threat_intelligence import (
    normalize_domain,
    score_ioc_severity,
    severity_from_score
)
from browser_events import (
    browser_events_bp,
    receive_browser_event
)
from process_events import (
    process_events_bp,
    init_process_events_db,
    receive_process_event
)
import process_correlation
import detection_engine
import provider_health
from web_monitoring import (
    web_monitoring_bp,
    init_web_monitoring_db,
    create_incident_from_alert,
    create_response_command,
    receive_web_event,
    post_agent_command_result,
    get_endpoint_info,
    validate_global_block_target,
    compute_endpoint_presence,
    get_eligible_endpoints,
    find_active_global_policy,
    get_latest_block_command,
    compute_global_block_preview,
    create_or_sync_global_block_policy,
    conn_fetch_policy,
    get_policy_endpoints,
    get_policy_coverage,
    get_command_by_id,
    disable_global_block_policy,
    retry_global_block_endpoint,
    GLOBAL_BLOCK_SCOPES,
    GLOBAL_BLOCK_MODES
)
from network_events import (
    network_events_bp,
    init_network_events_db
)

# Phase 13B: generic security-data foundation (sensor registry, normalized
# ingestion). No engine-specific code; detections never create alerts.
from security_ingest_routes import (
    security_ingest_bp,
    security_ingest as receive_security_ingest
)
from security_sensors import init_security_data_db

# Phase 13C: endpoint network context - IP history, heartbeat, resolver.
# No detection/alert/response logic; history is presence + network identity.
from endpoint_heartbeat_routes import (
    endpoint_heartbeat_bp,
    endpoint_heartbeat as receive_endpoint_heartbeat
)
from endpoint_network import init_endpoint_network_db

from behavioral_analysis import (
    init_behavioral_db,
    behavioral_label
)

from threat_intel_providers import (
    init_threat_intel_db,
    get_stored_evidence_for_event
)

import threat_intel_framework as threat_intel_fw

import threat_intel_display

import url_send_policy

import local_feed_health

import cloudflare_provider

import investigation

from executive_dashboard import executive_dashboard_bp

from i18n import init_babel, i18n_bp
from flask_babel import gettext as _
import plain_language

from urllib.parse import urlparse, parse_qsl, urlencode

from investigation_priority import (
    compute_investigation_priority,
    detect_local_ioc_matched
)

import report_data
from report_data import (
    init_security_reports_db,
    build_security_report_data,
    get_closed_weekly_periods,
    get_closed_monthly_periods,
    validate_custom_period,
    to_bound_str
)
from report_pdf import build_security_report_pdf

app = Flask(__name__)

init_babel(app)

app.register_blueprint(
    i18n_bp
)
app.register_blueprint(
    reputation_bp
)
app.register_blueprint(
    web_monitoring_bp
)
app.register_blueprint(
    network_events_bp
)
app.register_blueprint(
    security_ingest_bp
)
app.register_blueprint(
    endpoint_heartbeat_bp
)
app.register_blueprint(
    executive_dashboard_bp
)
app.register_blueprint(
    browser_events_bp
)
app.register_blueprint(
    process_events_bp
)

# ==================================================
# PHASE 9: ENVIRONMENT / SECURITY CONFIGURATION
# ==================================================
# python-dotenv has already loaded .env by this point (it runs
# at import time inside threat_intelligence.py, imported above
# via reputation_routes -> threat_intelligence, before this
# line executes) - same established pattern as AGENT_API_KEY.

FLASK_DEBUG = os.getenv(
    "FLASK_DEBUG", "false"
).strip().lower() == "true"

FLASK_HOST = os.getenv(
    "FLASK_HOST", "127.0.0.1"
).strip() or "127.0.0.1"

FLASK_PORT = int(
    os.getenv("FLASK_PORT", "5000").strip() or "5000"
)

FLASK_SECURE_COOKIES = os.getenv(
    "FLASK_SECURE_COOKIES", "false"
).strip().lower() == "true"

FLASK_SECRET_KEY = os.getenv(
    "FLASK_SECRET_KEY", ""
).strip()

if not FLASK_SECRET_KEY:

    if FLASK_DEBUG:

        # Development convenience only - regenerated every
        # process start, so existing sessions/CSRF tokens do
        # not survive a restart. Never appropriate outside
        # debug mode.
        FLASK_SECRET_KEY = secrets.token_urlsafe(32)

        print(
            "[CONFIG WARNING] FLASK_SECRET_KEY is not set - "
            "using a TEMPORARY random development key. Set "
            "FLASK_SECRET_KEY in .env for a real deployment."
        )

    else:

        # Fail closed: never silently run non-debug sessions
        # on a hard-coded or blank secret.
        raise RuntimeError(
            "FLASK_SECRET_KEY is not configured. Set it in "
            ".env before starting outside debug mode. "
            "Generate one with: "
            'python -c "import secrets; '
            'print(secrets.token_urlsafe(32))"'
        )

app.secret_key = FLASK_SECRET_KEY

# --------------------------------------------------
# SESSION COOKIE SECURITY
# --------------------------------------------------

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# True only when FLASK_SECURE_COOKIES=true in .env - intended
# for production/lab deployment behind HTTPS. Left False by
# default so local http://127.0.0.1:5000 development keeps
# working (a Secure cookie is never sent back over plain HTTP).
app.config["SESSION_COOKIE_SECURE"] = FLASK_SECURE_COOKIES

# Session expires after 45 minutes of inactivity. See login()
# for where session.permanent = True is set so this actually
# applies (Flask ignores PERMANENT_SESSION_LIFETIME for non-
# permanent sessions).
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=45)

# --------------------------------------------------
# REQUEST SIZE LIMIT
# --------------------------------------------------
# Agent telemetry events are tiny (a handful of short fields) -
# 1 MB is generous headroom while still blocking abusive/
# oversized request bodies. A 413 handler is registered below.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# --------------------------------------------------
# CSRF PROTECTION
# --------------------------------------------------
# Protects every browser-facing state-changing POST site-wide
# by default. The machine-authenticated endpoints below are
# explicitly exempted (Agent: X-Agent-Key; sensors: X-Sensor-Id/
# X-Sensor-Key) - a machine client cannot obtain a CSRF token from
# an HTML form. Step 24A's receive_browser_event is included here
# because it is also Agent-authenticated (X-Agent-Key) - see
# browser_events.py's module docstring: the browser extension and
# native host never call it directly, only the Agent does, over
# the same channel as receive_web_event. Everything else (login,
# scanner, threat intel, users, alerts, incidents, response
# actions, web monitoring, network events) requires a valid
# csrf_token in each form.
csrf = CSRFProtect(app)

csrf.exempt(receive_web_event)
csrf.exempt(receive_browser_event)
csrf.exempt(post_agent_command_result)
# Phase 13B: machine-authenticated by a per-sensor secret (X-Sensor-Id +
# X-Sensor-Key), never by a session cookie - so no CSRF token applies.
csrf.exempt(receive_security_ingest)
# Phase 13C: machine-authenticated by X-Agent-Key (the existing agent
# model), never by a session cookie - so no CSRF token applies.
csrf.exempt(receive_endpoint_heartbeat)
# Step 25A: same X-Agent-Key machine-authentication model as every other
# agent-facing route above - no CSRF token applies. Found missing live
# during this Step 25A restart (every process event was being rejected
# with a generic CSRF 400 before ever reaching receive_process_event()'s
# own validation) - see the Step 25A report.
csrf.exempt(receive_process_event)


# --------------------------------------------------
# SECURITY HEADERS / CACHE CONTROL
# --------------------------------------------------

# --------------------------------------------------
# PHASE 12B.6C.1: REQUEST-SCOPED DB CONNECTION SAFETY NET
# --------------------------------------------------
# Every connection opened through db_config during a request is rolled back
# (if a transaction is open) and closed when the request ends - on success
# AND on any exception, even if a debugger retains the traceback. This makes
# a leaked write transaction impossible to outlive its request, whichever
# code path leaked it. Connections opened BEFORE the request (position
# mark) are never touched. Does not depend on the reloader/debug mode.

@app.before_request
def mark_request_db_connections():

    g.db_mark = db_config.mark()


@app.teardown_request
def release_request_db_connections(exc):

    db_config.release_since(getattr(g, "db_mark", None))


@app.after_request
def apply_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    # Practical CSP for this project: blocks any externally
    # injected script/resource (default-src 'self'), but still
    # allows the existing inline <script>/<style> blocks
    # (dashboard Chart.js config, web_monitoring.html's page
    # CSS) without a UI rewrite. 'unsafe-inline' is a
    # documented, accepted limitation of this phase - see the
    # Phase 9 report.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )

    # Authenticated SOC pages should not be cached by the
    # browser/any intermediary proxy. Static assets (style.css,
    # chart.min.js, etc.) are untouched.
    if "user_id" in session and not request.path.startswith(
        "/static/"
    ):
        response.headers["Cache-Control"] = "no-store"

    return response


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------
# Generic messages only - never a Python traceback, DB path,
# SQL text, or secret value reaches the browser.

@app.errorhandler(400)
def handle_bad_request(error):
    return render_template(
        "error.html",
        code=400,
        message="The request could not be understood."
    ), 400


@app.errorhandler(401)
def handle_unauthorized(error):
    return render_template(
        "error.html",
        code=401,
        message="Authentication is required."
    ), 401


@app.errorhandler(403)
def handle_forbidden(error):
    return render_template(
        "error.html",
        code=403,
        message="Access denied."
    ), 403


@app.errorhandler(404)
def handle_not_found(error):
    return render_template(
        "error.html",
        code=404,
        message="The requested page was not found."
    ), 404


@app.errorhandler(413)
def handle_payload_too_large(error):
    return render_template(
        "error.html",
        code=413,
        message="The request was too large."
    ), 413


@app.errorhandler(500)
def handle_server_error(error):
    return render_template(
        "error.html",
        code=500,
        message="An unexpected error occurred."
    ), 500


# SOC_DB_PATH (optional): selects an alternate database file, e.g. the
# classroom demo DB - see prepare_demo_db.py / README "Classroom Demo
# Database". Unset = unchanged default behavior. A relative value
# resolves against this file's own directory (same base the default
# already uses); an absolute value is used as-is. Never sourced from
# a browser/user request - environment only, and not a secret.
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

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db_connection():

    # Phase 12B.6C.1: central policy (WAL, busy timeout, synchronous=FULL,
    # tracked so a request/iteration can always release it).
    return db_config.open_connection(DB_NAME)


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def init_db():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            security_score INTEGER DEFAULT 100,
            username TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            service TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (scan_id)
            REFERENCES scans (id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            score_penalty INTEGER NOT NULL,
            FOREIGN KEY (scan_id)
            REFERENCES scans (id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            target_ip TEXT,
            username TEXT,
            message TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            username TEXT,
            target_ip TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            updated_by TEXT,
            updated_at TEXT,
            correlation_key TEXT
        )
    """)

    # Stage 25F Phase 2/4: guarded upgrade for a database created
    # BEFORE correlation_key existed in the CREATE TABLE above - same
    # pattern web_monitoring.py already uses for its own additive
    # columns; the live cybersec.db was migrated once, directly, by
    # the Phase 2 one-off script.
    security_events_columns = [
        column["name"]
        for column in conn.execute("PRAGMA table_info(security_events)").fetchall()
    ]

    if "correlation_key" not in security_events_columns:
        conn.execute("ALTER TABLE security_events ADD COLUMN correlation_key TEXT")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL UNIQUE,
            severity TEXT NOT NULL,
            description TEXT,
            source TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)

    # --------------------------------------------------
    # Upgrade scans
    # --------------------------------------------------

    scan_columns = conn.execute(
        "PRAGMA table_info(scans)"
    ).fetchall()

    scan_column_names = [
        column["name"]
        for column in scan_columns
    ]

    if "security_score" not in scan_column_names:

        conn.execute("""
            ALTER TABLE scans
            ADD COLUMN security_score
            INTEGER DEFAULT 100
        """)

    if "username" not in scan_column_names:

        conn.execute("""
            ALTER TABLE scans
            ADD COLUMN username TEXT
        """)

    # --------------------------------------------------
    # Upgrade users
    # --------------------------------------------------

    user_columns = conn.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    user_column_names = [
        column["name"]
        for column in user_columns
    ]

    if "failed_attempts" not in user_column_names:

        conn.execute("""
            ALTER TABLE users
            ADD COLUMN failed_attempts
            INTEGER DEFAULT 0
        """)

    if "locked_until" not in user_column_names:

        conn.execute("""
            ALTER TABLE users
            ADD COLUMN locked_until TEXT
        """)

    # --------------------------------------------------
    # Upgrade logs
    # --------------------------------------------------

    log_columns = conn.execute(
        "PRAGMA table_info(system_logs)"
    ).fetchall()

    log_column_names = [
        column["name"]
        for column in log_columns
    ]

    if "username" not in log_column_names:

        conn.execute("""
            ALTER TABLE system_logs
            ADD COLUMN username TEXT
        """)

    # --------------------------------------------------
    # Upgrade security events
    # --------------------------------------------------

    event_columns = conn.execute(
        "PRAGMA table_info(security_events)"
    ).fetchall()

    event_column_names = [
        column["name"]
        for column in event_columns
    ]

    if "updated_by" not in event_column_names:

        conn.execute("""
            ALTER TABLE security_events
            ADD COLUMN updated_by TEXT
        """)

    if "updated_at" not in event_column_names:

        conn.execute("""
            ALTER TABLE security_events
            ADD COLUMN updated_at TEXT
        """)

    # --------------------------------------------------
    # PHASE 9: INITIAL ADMIN BOOTSTRAP
    # --------------------------------------------------
    # Only ever runs when the users table is completely empty
    # (a genuinely fresh install) - if any user already exists,
    # this is skipped entirely and no password is ever reset.
    # No hard-coded default password: the initial admin is only
    # created if INITIAL_ADMIN_USERNAME/INITIAL_ADMIN_PASSWORD
    # are set in .env. If the table is empty and these are
    # missing, the app starts with zero users and prints a
    # clear instruction instead of silently using a predictable
    # default credential.

    user_count = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    if user_count == 0:

        initial_username = os.getenv(
            "INITIAL_ADMIN_USERNAME", ""
        ).strip()

        initial_password = os.getenv(
            "INITIAL_ADMIN_PASSWORD", ""
        ).strip()

        if initial_username and initial_password:

            password_hash = generate_password_hash(
                initial_password
            )

            conn.execute("""
                INSERT INTO users (
                    username,
                    password_hash,
                    role,
                    failed_attempts,
                    locked_until
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                initial_username,
                password_hash,
                "admin",
                0,
                None
            ))

            # Never log the password itself.
            print(
                f"[SETUP] Initial admin account "
                f"'{initial_username}' created from "
                f".env configuration."
            )

        else:

            print(
                "[SETUP WARNING] No users exist yet and "
                "INITIAL_ADMIN_USERNAME/INITIAL_ADMIN_PASSWORD "
                "are not set in .env - no admin account was "
                "created. Set both variables and restart to "
                "bootstrap the first admin."
            )

    conn.commit()

    conn.close()


# --------------------------------------------------
# APPLICATION INITIALIZATION (WSGI-SAFE)
# --------------------------------------------------
# Runs at MODULE level (see the call immediately below), not
# inside `if __name__ == "__main__":` - a WSGI server such as
# `gunicorn app:app` only ever imports this module and reads the
# `app` object; it never executes that guard. Previously, all
# four init_*_db() calls lived only inside that guard, so
# `gunicorn app:app` alone would start successfully (Flask/CSRF/
# session config are all already module-level) while leaving
# every table missing on a fresh database - every DB-touching
# route would then fail. initialize_application() fixes this by
# being the single place all schema initialization happens,
# called unconditionally at import time.
#
# Each init_*_db() function is independently idempotent
# (CREATE TABLE IF NOT EXISTS / PRAGMA table_info()-guarded
# ALTER TABLE ADD COLUMN) - safe to call on every startup,
# including repeatedly in the same process (e.g. re-import during
# testing). Order matters only in that init_db() creates the
# core `users`/`system_logs`/scanner tables first; the three
# feature-module initializers do not depend on each other.
#
# Failures are never swallowed: if initialization raises, this
# re-raises after printing a sanitized (no secret values) error,
# so Gunicorn/Flask fails loudly at startup instead of serving
# traffic against a half-initialized database.

def initialize_application():

    try:

        # Phase 12B.6C.1: journal mode (WAL) is set here, once, through the
        # controlled idempotent path (never fatal: stays in the current
        # mode with a warning if the switch cannot be made).
        db_config.ensure_journal_mode(DB_NAME)

        init_db()
        init_reputation_db()
        init_web_monitoring_db()
        init_network_events_db()
        init_behavioral_db()
        init_threat_intel_db()
        init_security_reports_db()
        init_security_data_db()
        init_endpoint_network_db()
        init_process_events_db()
        detection_engine.init_detection_engine_db()

        # Stage 25G Phase 3A: durable response plans - guarded, additive,
        # idempotent (CREATE TABLE IF NOT EXISTS + IF NOT EXISTS indexes),
        # so the table exists whichever process starts first. The app only
        # ever READS plans; generation lives in web_event_worker.py and no
        # code path creates a response_command from a plan.
        import response_plans
        response_plans.init_response_plans_db()
        provider_health.init_provider_health_db()

    except Exception as exc:

        print(
            "[STARTUP ERROR] Application database initialization "
            f"failed ({type(exc).__name__}: {exc}). The "
            "application will not start with an incomplete "
            "database schema."
        )

        raise


initialize_application()


# --------------------------------------------------
# AUTH HELPERS
# --------------------------------------------------

def login_required():

    return "user_id" in session


def admin_required():

    return (
        "user_id" in session
        and session.get("role") == "admin"
    )


# --------------------------------------------------
# SYSTEM LOGGING
# --------------------------------------------------

def create_log(
    event_type,
    message,
    target_ip=None,
    username_override=None
):

    conn = get_db_connection()

    log_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    username = (
        username_override
        if username_override
        else session.get(
            "username",
            "anonymous"
        )
    )

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


# --------------------------------------------------
# SECURITY EVENTS
# --------------------------------------------------

def create_security_event(
    event_type,
    severity,
    title,
    description,
    username=None,
    target_ip=None
):

    conn = get_db_connection()

    event_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn.execute("""
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
        event_type,
        severity,
        username,
        target_ip,
        title,
        description,
        "OPEN",
        None,
        None
    ))

    conn.commit()

    conn.close()


# --------------------------------------------------
# THREAT INTELLIGENCE
# --------------------------------------------------

def check_ip_against_threat_intelligence(ip):

    conn = get_db_connection()

    indicator = conn.execute("""
        SELECT *
        FROM threat_indicators
        WHERE indicator_type = 'IP'
        AND indicator_value = ?
        AND active = 1
    """, (
        ip,
    )).fetchone()

    conn.close()

    return indicator


# --------------------------------------------------
# PORT SECURITY ANALYSIS
# --------------------------------------------------

def analyze_open_port(
    port,
    service
):

    findings = []

    if port == 22:

        findings.append({
            "port": port,
            "title": "SSH Service Exposed",
            "severity": "MEDIUM",
            "description":
                "SSH is accessible on the target host. "
                "Verify that access is restricted and securely configured.",
            "penalty": 10
        })

    elif port == 3306:

        findings.append({
            "port": port,
            "title": "Database Service Exposed",
            "severity": "HIGH",
            "description":
                "MySQL is accessible on the target host. "
                "Database services should normally be restricted.",
            "penalty": 25
        })

    elif port == 5000:

        findings.append({
            "port": port,
            "title": "Flask Web Service Detected",
            "severity": "INFO",
            "description":
                "A Flask development web service was detected.",
            "penalty": 0
        })

    elif port == 8080:

        findings.append({
            "port": port,
            "title": "Alternate HTTP Service Detected",
            "severity": "LOW",
            "description":
                "An HTTP service is accessible on alternate port 8080.",
            "penalty": 5
        })

    elif port == 80:

        findings.append({
            "port": port,
            "title": "HTTP Service Detected",
            "severity": "LOW",
            "description":
                "Unencrypted HTTP service is accessible.",
            "penalty": 5
        })

    elif port == 443:

        findings.append({
            "port": port,
            "title": "HTTPS Service Detected",
            "severity": "INFO",
            "description":
                "HTTPS service is accessible.",
            "penalty": 0
        })

    return findings


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db_connection()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (
            username,
        )).fetchone()

        if user is None:

            conn.close()

            create_log(
                "LOGIN_FAILED",
                "Failed login attempt for unknown username.",
                username_override=(
                    username
                    if username
                    else "unknown"
                )
            )

            return render_template(
                "login.html",
                error=_("Invalid username or password")
            )

        if user["locked_until"]:

            try:

                locked_until = datetime.strptime(
                    user["locked_until"],
                    "%Y-%m-%d %H:%M:%S"
                )

                if datetime.now() < locked_until:

                    remaining_seconds = int(
                        (
                            locked_until
                            - datetime.now()
                        ).total_seconds()
                    )

                    remaining_minutes = max(
                        1,
                        (
                            remaining_seconds + 59
                        ) // 60
                    )

                    conn.close()

                    create_log(
                        "LOGIN_BLOCKED",
                        "Login blocked because account is locked.",
                        username_override=username
                    )

                    return render_template(
                        "login.html",
                        error=_(
                            "Account temporarily locked. "
                            "Try again in approximately "
                            "%(minutes)s minute(s).",
                            minutes=remaining_minutes
                        )
                    )

                conn.execute("""
                    UPDATE users
                    SET
                        failed_attempts = 0,
                        locked_until = NULL
                    WHERE id = ?
                """, (
                    user["id"],
                ))

                conn.commit()

                user = conn.execute("""
                    SELECT *
                    FROM users
                    WHERE id = ?
                """, (
                    user["id"],
                )).fetchone()

            except ValueError:

                conn.execute("""
                    UPDATE users
                    SET
                        failed_attempts = 0,
                        locked_until = NULL
                    WHERE id = ?
                """, (
                    user["id"],
                ))

                conn.commit()

        if check_password_hash(
            user["password_hash"],
            password
        ):

            conn.execute("""
                UPDATE users
                SET
                    failed_attempts = 0,
                    locked_until = NULL
                WHERE id = ?
            """, (
                user["id"],
            ))

            conn.commit()

            conn.close()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            # Phase 9: makes PERMANENT_SESSION_LIFETIME (45 min
            # of inactivity) actually apply - a non-permanent
            # Flask session has no expiry of its own.
            session.permanent = True

            create_log(
                "LOGIN_SUCCESS",
                "User logged in successfully."
            )

            return redirect(
                url_for("dashboard")
            )

        failed_attempts = (
            user["failed_attempts"] or 0
        ) + 1

        if failed_attempts >= MAX_LOGIN_ATTEMPTS:

            locked_until = (
                datetime.now()
                + timedelta(
                    minutes=LOCKOUT_MINUTES
                )
            )

            locked_until_string = (
                locked_until.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            conn.execute("""
                UPDATE users
                SET
                    failed_attempts = ?,
                    locked_until = ?
                WHERE id = ?
            """, (
                failed_attempts,
                locked_until_string,
                user["id"]
            ))

            conn.commit()
            conn.close()

            create_log(
                "ACCOUNT_LOCKED",
                (
                    f"Account locked after "
                    f"{MAX_LOGIN_ATTEMPTS} "
                    f"failed login attempts."
                ),
                username_override=username
            )

            create_security_event(
                event_type="BRUTE_FORCE_DETECTED",
                severity="HIGH",
                title="Possible Brute Force Attack",
                description=(
                    f"Account '{username}' was locked "
                    f"after {MAX_LOGIN_ATTEMPTS} "
                    f"consecutive failed login attempts."
                ),
                username=username
            )

            error = _(
                "Too many failed login attempts. "
                "Account locked for "
                "%(minutes)s minutes.",
                minutes=LOCKOUT_MINUTES
            )

        else:

            conn.execute("""
                UPDATE users
                SET failed_attempts = ?
                WHERE id = ?
            """, (
                failed_attempts,
                user["id"]
            ))

            conn.commit()
            conn.close()

            attempts_left = (
                MAX_LOGIN_ATTEMPTS
                - failed_attempts
            )

            create_log(
                "LOGIN_FAILED",
                (
                    "Incorrect password. "
                    f"{attempts_left} attempt(s) remaining."
                ),
                username_override=username
            )

            error = _(
                "Invalid username or password. "
                "%(attempts_left)s attempt(s) remaining.",
                attempts_left=attempts_left
            )

    return render_template(
        "login.html",
        error=error
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    if "user_id" in session:

        create_log(
            "LOGOUT",
            "User logged out."
        )

    session.clear()

    return redirect(
        url_for("login")
    )


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def dashboard():

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    total_scans = conn.execute("""
        SELECT COUNT(*)
        FROM scans
    """).fetchone()[0]

    hosts_scanned = conn.execute("""
        SELECT COUNT(DISTINCT target_ip)
        FROM scans
    """).fetchone()[0]

    total_findings = conn.execute("""
        SELECT COUNT(*)
        FROM findings
    """).fetchone()[0]

    # --------------------------------------------------
    # PHASE 8: DASHBOARD METRICS
    # --------------------------------------------------
    # Exact definitions (documented in the Phase 8 report):
    #   Active Alerts       = security_alerts.status IN ('NEW','ACKNOWLEDGED')
    #   Open Incidents      = security_events.status != 'RESOLVED'
    #   Critical Incidents  = Open Incidents AND severity = 'CRITICAL'
    #   Monitored Endpoints = COUNT(endpoints)
    #   Isolated Endpoints  = endpoints.status = 'ISOLATED'
    #   Blocked Destinations= blocked_domains.active = 1 (policy-level;
    #                         enforcement_status shown separately, not
    #                         folded into this count - a destination is
    #                         "blocked" by policy regardless of whether
    #                         real enforcement also succeeded)
    #   Active IOCs         = threat_indicators.active = 1

    active_alerts = conn.execute("""
        SELECT COUNT(*)
        FROM security_alerts
        WHERE status IN ('NEW', 'ACKNOWLEDGED')
    """).fetchone()[0]

    open_incidents = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE status != 'RESOLVED'
    """).fetchone()[0]

    # Kept for backward compatibility with any code still
    # reading this exact variable name.
    active_security_events = open_incidents

    critical_incidents = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE status != 'RESOLVED' AND severity = 'CRITICAL'
    """).fetchone()[0]

    monitored_endpoints = conn.execute("""
        SELECT COUNT(*)
        FROM endpoints
    """).fetchone()[0]

    isolated_endpoints = conn.execute("""
        SELECT COUNT(*)
        FROM endpoints
        WHERE status = 'ISOLATED'
    """).fetchone()[0]

    blocked_destinations = conn.execute("""
        SELECT COUNT(*)
        FROM blocked_domains
        WHERE active = 1
    """).fetchone()[0]

    active_iocs = conn.execute("""
        SELECT COUNT(*)
        FROM threat_indicators
        WHERE active = 1
    """).fetchone()[0]

    latest_scan = conn.execute("""
        SELECT security_score
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    # This is a project-specific metric derived from the most
    # recent Scanner run only (open-port findings) - it is NOT
    # CVSS, and it is NOT a holistic enterprise risk score. See
    # Phase 8 report for why it is labeled this way.
    security_score = (
        latest_scan["security_score"]
        if latest_scan
        else 100
    )

    # --------------------------------------------------
    # PHASE 8: DASHBOARD SECTIONS
    # --------------------------------------------------

    recent_alerts = conn.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY id DESC
        LIMIT 8
    """).fetchall()

    recent_incidents = conn.execute("""
        SELECT *
        FROM security_events
        WHERE status != 'RESOLVED'
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    endpoint_rows = conn.execute("""
        SELECT *
        FROM endpoints
        ORDER BY
            CASE status WHEN 'ISOLATED' THEN 1 ELSE 2 END,
            id DESC
        LIMIT 10
    """).fetchall()

    # Simple, documented staleness rule: an endpoint that has
    # not been seen in the last 15 minutes is shown as STALE.
    # This is only a display hint (last_seen comparison), not a
    # new DB column/state - no endpoint status is changed by it.
    ENDPOINT_STALE_MINUTES = 15

    endpoint_activity = []

    for endpoint in endpoint_rows:

        is_stale = False

        if endpoint["last_seen"]:

            try:

                last_seen_dt = datetime.strptime(
                    endpoint["last_seen"], "%Y-%m-%d %H:%M:%S"
                )

                is_stale = (
                    datetime.now() - last_seen_dt
                ) > timedelta(minutes=ENDPOINT_STALE_MINUTES)

            except ValueError:
                is_stale = False

        endpoint_activity.append({
            "row": endpoint,
            "is_stale": is_stale
        })

    top_risky_destinations = conn.execute("""
        SELECT
            COALESCE(domain, resolved_ip, destination) AS destination,
            MAX(risk_score) AS max_risk,
            MAX(severity) AS worst_severity,
            COUNT(*) AS hits
        FROM web_events
        WHERE destination IS NOT NULL
        GROUP BY destination
        HAVING max_risk > 0
        ORDER BY max_risk DESC, hits DESC
        LIMIT 5
    """).fetchall()

    recent_response_actions = conn.execute("""
        SELECT *
        FROM response_commands
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    recent_scans = conn.execute("""
        SELECT
            id,
            target_ip,
            scan_time,
            security_score,
            username
        FROM scans
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    recent_findings = conn.execute("""
        SELECT
            findings.title,
            findings.severity,
            findings.port,
            scans.target_ip
        FROM findings
        JOIN scans
        ON findings.scan_id = scans.id
        ORDER BY findings.id DESC
        LIMIT 5
    """).fetchall()

    recent_security_events = conn.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    # Severity Distribution chart: driven by Security Alerts
    # (the current architecture's real severity signal, Phase 6)
    # plus open Incidents - scanner findings are intentionally
    # NOT folded in here anymore, since they are a different
    # model shown separately (Recent Findings / Scanner
    # Findings section) rather than mixed into Alert severity.
    severity_data = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    alert_severity_rows = conn.execute("""
        SELECT severity, COUNT(*) AS total
        FROM security_alerts
        GROUP BY severity
    """).fetchall()

    for row in alert_severity_rows:

        if row["severity"] in severity_data:

            severity_data[
                row["severity"]
            ] = row["total"]

    security_severity_rows = conn.execute("""
        SELECT
            severity,
            COUNT(*) AS total
        FROM security_events
        WHERE status != 'RESOLVED'
        GROUP BY severity
    """).fetchall()

    for row in security_severity_rows:

        if row["severity"] in severity_data:

            severity_data[
                row["severity"]
            ] += row["total"]

    score_rows = conn.execute("""
        SELECT
            id,
            security_score
        FROM scans
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    score_rows = list(
        reversed(score_rows)
    )

    score_labels = [
        f"Scan #{row['id']}"
        for row in score_rows
    ]

    score_values = [
        row["security_score"]
        for row in score_rows
    ]

    open_port_rows = conn.execute("""
        SELECT
            port,
            service,
            COUNT(*) AS total
        FROM scan_results
        WHERE status = 'OPEN'
        GROUP BY port, service
        ORDER BY total DESC
        LIMIT 5
    """).fetchall()

    open_port_labels = [
        f"{row['port']} / {row['service']}"
        for row in open_port_rows
    ]

    open_port_values = [
        row["total"]
        for row in open_port_rows
    ]

    conn.close()

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        hosts_scanned=hosts_scanned,
        total_findings=total_findings,
        active_security_events=active_security_events,
        active_alerts=active_alerts,
        open_incidents=open_incidents,
        critical_incidents=critical_incidents,
        monitored_endpoints=monitored_endpoints,
        isolated_endpoints=isolated_endpoints,
        blocked_destinations=blocked_destinations,
        active_iocs=active_iocs,
        security_score=security_score,
        recent_scans=recent_scans,
        recent_findings=recent_findings,
        recent_security_events=recent_security_events,
        recent_alerts=recent_alerts,
        recent_incidents=recent_incidents,
        endpoint_activity=endpoint_activity,
        endpoint_stale_minutes=ENDPOINT_STALE_MINUTES,
        top_risky_destinations=top_risky_destinations,
        recent_response_actions=recent_response_actions,
        severity_data=severity_data,
        score_labels=score_labels,
        score_values=score_values,
        open_port_labels=open_port_labels,
        open_port_values=open_port_values
    )


# --------------------------------------------------
# THREAT INTELLIGENCE PAGE
# --------------------------------------------------

@app.route(
    "/threat-intel",
    methods=["GET", "POST"]
)
def threat_intel():

    if not login_required():

        return redirect(
            url_for("login")
        )

    error = None
    success = None

    if request.method == "POST":

        if not admin_required():

            return (
                "Access denied - Administrator only",
                403
            )

        indicator_type = request.form.get(
            "indicator_type",
            "IP"
        ).strip().upper()

        indicator_value = request.form.get(
            "indicator_value",
            ""
        ).strip()

        severity = request.form.get(
            "severity",
            "MEDIUM"
        ).strip().upper()

        description = request.form.get(
            "description",
            ""
        ).strip()

        source = request.form.get(
            "source",
            ""
        ).strip()

        allowed_types = [
            "IP",
            "DOMAIN",
            "HASH"
        ]

        allowed_severities = [
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"
        ]

        if indicator_type not in allowed_types:

            error = "Invalid indicator type."

        elif severity not in allowed_severities:

            error = "Invalid severity."

        elif not indicator_value:

            error = "Indicator value is required."

        elif indicator_type == "IP":

            try:

                ipaddress.ip_address(
                    indicator_value
                )

            except ValueError:

                error = "Invalid IP address."

        elif indicator_type == "DOMAIN":

            # Phase 4: normalize before storing (lowercase, no
            # scheme/path/port, no trailing dot) so newly added
            # DOMAIN IOCs compare and dedupe cleanly. Existing
            # rows already in the table are NEVER rewritten -
            # check_domain_ioc() normalizes both sides at
            # comparison time regardless.
            indicator_value = normalize_domain(
                indicator_value
            )

            if not indicator_value:

                error = (
                    "Could not extract a valid domain "
                    "from the indicator value."
                )

        elif indicator_type == "HASH":

            # Phase 11B: normalize to lowercase and require
            # exactly 32 hex chars (MD5) or 64 hex chars
            # (SHA-256) - no other length/format is accepted.
            # No separate "algorithm" column is added - it is
            # inferred from the validated value's length
            # wherever it needs to be displayed. Existing
            # IP/DOMAIN creation-path behavior above is
            # unchanged, and no historical row is ever rewritten
            # by this validation.
            indicator_value = indicator_value.strip().lower()

            if not (
                re.match(r"^[a-f0-9]{32}$", indicator_value)
                or re.match(r"^[a-f0-9]{64}$", indicator_value)
            ):

                error = (
                    "Invalid hash value - must be exactly 32 "
                    "hexadecimal characters (MD5) or 64 "
                    "hexadecimal characters (SHA-256)."
                )

        if error is None:

            conn = get_db_connection()

            existing = conn.execute("""
                SELECT id
                FROM threat_indicators
                WHERE indicator_value = ?
            """, (
                indicator_value,
            )).fetchone()

            if existing:

                error = (
                    "This indicator already exists."
                )

                conn.close()

            else:

                created_at = (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                conn.execute("""
                    INSERT INTO threat_indicators (
                        indicator_type,
                        indicator_value,
                        severity,
                        description,
                        source,
                        created_by,
                        created_at,
                        active
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    indicator_type,
                    indicator_value,
                    severity,
                    description,
                    source,
                    session.get("username"),
                    created_at,
                    1
                ))

                conn.commit()
                conn.close()

                create_log(
                    "IOC_CREATED",
                    (
                        f"Threat indicator "
                        f"'{indicator_value}' "
                        f"was added."
                    )
                )

                success = (
                    "Threat indicator added successfully."
                )

    conn = get_db_connection()

    indicators = conn.execute("""
        SELECT *
        FROM threat_indicators
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    # Oct 2026 Step 5: read-only multi-source provider connection status
    # (configured/not-configured, automatic/manual, evidence counts, last
    # check). Never performs a live lookup - see threat_intel_display.py.
    provider_status = threat_intel_display.provider_status_table()

    # Stage 25D section 11: Provider Health dashboard data - requests
    # today / cache hits today / last success / last failure /
    # consecutive failures / status enum / quota (only where a provider
    # genuinely exposes one). Purely computed from existing data + the
    # new provider_daily_counters table - never a live lookup, never an
    # API key value (provider_health.py never reads/returns one).
    provider_health_rows = provider_health.all_providers_health()

    return render_template(
        "threat_intel.html",
        indicators=indicators,
        error=error,
        success=success,
        provider_status=provider_status,
        provider_health_rows=provider_health_rows
    )


# --------------------------------------------------
# STEP 24B.2E: LOCAL THREAT INTELLIGENCE FEED HEALTH (manager-facing)
# --------------------------------------------------
# Read-only. Never performs a live lookup, never starts a download,
# never touches a snapshot/lock/attempt-state file - purely renders
# what local_feed_health.py already assembles from existing, unchanged
# sources (local_feed_store/local_feed_attempt_store/local_feed_
# providers). No admin_required() gate: any logged-in user may view
# this page, matching the read-only convention of /reputation and
# similar pages - there is no POST/mutation here at all.

@app.route(
    "/threat-intel-health",
    methods=["GET"]
)
def threat_intel_health():

    if not login_required():

        return redirect(
            url_for("login")
        )

    provider_records = local_feed_health.get_all_provider_health()
    system_health = local_feed_health.aggregate_system_health(provider_records)

    return render_template(
        "threat_intel_health.html",
        provider_records=provider_records,
        system_health=system_health
    )


# --------------------------------------------------
# STEP 25A: PROCESS TELEMETRY - MINIMAL READ-ONLY VERIFICATION PAGE
# --------------------------------------------------
# Deliberately NOT a Manager EDR Dashboard (that belongs to a later
# stage - see the Step 25A report). Read-only, no POST, no detection/
# risk/alert logic of any kind - purely lists what
# endpoint_process_events already contains.

@app.route(
    "/process-events",
    methods=["GET"]
)
def process_events_view():

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    try:
        rows = conn.execute("""
            SELECT *
            FROM endpoint_process_events
            ORDER BY id DESC
            LIMIT 200
        """).fetchall()
    finally:
        conn.close()

    return render_template(
        "process_events.html",
        events=rows
    )


# --------------------------------------------------
# STEP 25B: PROCESS DETAIL - read-only, process<->network correlation
# --------------------------------------------------
# Deliberately NOT a Manager EDR Dashboard either. Shows ONE process
# instance's own stored fields (unchanged from Step 25A) plus the
# network events process_correlation.py has linked to it so far -
# reads web_events' EXISTING risk_score/severity/decision/
# reputation_source columns (already computed by the unmodified Threat
# Intel pipeline); triggers no new lookup, no alert, no response.

@app.route(
    "/process-events/<process_instance_id>",
    methods=["GET"]
)
def process_event_detail_view(process_instance_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    try:

        process_row = conn.execute("""
            SELECT *
            FROM endpoint_process_events
            WHERE process_instance_id = ?
        """, (process_instance_id,)).fetchone()

        network_events = process_correlation.get_network_events_for_process(
            conn, process_instance_id
        )

    finally:
        conn.close()

    if process_row is None:

        return render_template(
            "process_event_detail.html",
            process=None,
            network_events=[],
            process_instance_id=process_instance_id
        ), 404

    return render_template(
        "process_event_detail.html",
        process=process_row,
        network_events=network_events,
        process_instance_id=process_instance_id
    )


# --------------------------------------------------
# OCT 2026 STEP 5: MANUAL THREAT-INTEL RE-CHECK (admin-only)
# --------------------------------------------------
# Forces ONE fresh lookup for a single (provider, indicator) pair, bounded
# by that provider's own manual_eligible/configuration/quota/backoff rules
# (see threat_intel_display.force_recheck - nothing here bypasses them).
# Never creates/touches security_alerts, response_commands,
# blocked_domains, or any block/isolate action, and never changes any
# web_event's risk_score/severity/decision.

@app.route(
    "/api/threat-intel/recheck",
    methods=["POST"]
)
def threat_intel_recheck():

    # Plain form POST + redirect-back, matching this app's existing
    # pattern everywhere else (Delete/Toggle buttons etc.) - no JSON/AJAX
    # is introduced here, consistent with the rest of the project.
    return_to = request.form.get("return_to") or request.referrer or url_for("threat_intel")

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not admin_required():
        return "Access denied - Administrator only", 403

    provider = (request.form.get("provider") or "").strip()
    indicator_type = (request.form.get("indicator_type") or "").strip().upper()
    indicator_value = (request.form.get("indicator_value") or "").strip()

    if not provider or not indicator_type or not indicator_value:
        return redirect(return_to)

    result = threat_intel_display.force_recheck(provider, indicator_type, indicator_value)

    if "error" in result:
        create_log(
            "THREAT_INTEL_RECHECK_REJECTED",
            f"Manual re-check rejected for {provider}/{indicator_type}: {result['error']}"
        )
    else:
        create_log(
            "THREAT_INTEL_RECHECK",
            f"Manual re-check performed: {provider} / {indicator_type} -> {result.get('lookup_status')}"
        )

    separator = "&" if "?" in return_to else "?"
    return redirect(f"{return_to}{separator}ti_recheck={provider}")


# --------------------------------------------------
# TOGGLE IOC
# --------------------------------------------------

@app.route(
    "/threat-intel/<int:indicator_id>/toggle",
    methods=["POST"]
)
def toggle_indicator(indicator_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    conn = get_db_connection()

    indicator = conn.execute("""
        SELECT *
        FROM threat_indicators
        WHERE id = ?
    """, (
        indicator_id,
    )).fetchone()

    if indicator is None:

        conn.close()

        return (
            "Indicator not found",
            404
        )

    new_active = (
        0
        if indicator["active"] == 1
        else 1
    )

    conn.execute("""
        UPDATE threat_indicators
        SET active = ?
        WHERE id = ?
    """, (
        new_active,
        indicator_id
    ))

    conn.commit()
    conn.close()

    state = (
        "enabled"
        if new_active == 1
        else "disabled"
    )

    create_log(
        "IOC_STATUS_CHANGED",
        (
            f"Threat indicator "
            f"'{indicator['indicator_value']}' "
            f"was {state}."
        )
    )

    return redirect(
        url_for("threat_intel")
    )


# --------------------------------------------------
# DELETE IOC
# --------------------------------------------------

@app.route(
    "/threat-intel/<int:indicator_id>/delete",
    methods=["POST"]
)
def delete_indicator(indicator_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    conn = get_db_connection()

    indicator = conn.execute("""
        SELECT *
        FROM threat_indicators
        WHERE id = ?
    """, (
        indicator_id,
    )).fetchone()

    if indicator is None:

        conn.close()

        return (
            "Indicator not found",
            404
        )

    indicator_value = (
        indicator["indicator_value"]
    )

    conn.execute("""
        DELETE FROM threat_indicators
        WHERE id = ?
    """, (
        indicator_id,
    ))

    conn.commit()
    conn.close()

    create_log(
        "IOC_DELETED",
        (
            f"Threat indicator "
            f"'{indicator_value}' "
            f"was deleted."
        )
    )

    return redirect(
        url_for("threat_intel")
    )


# --------------------------------------------------
# SCANNER
# --------------------------------------------------

@app.route(
    "/scanner",
    methods=["GET", "POST"]
)
def scanner():

    if not login_required():

        return redirect(
            url_for("login")
        )

    result = None

    if request.method == "POST":

        ip = request.form.get(
            "ip",
            ""
        ).strip()

        try:

            target = ipaddress.ip_address(
                ip
            )

            if not (
                target.is_private
                or target.is_loopback
            ):

                create_log(
                    "SCAN_BLOCKED",
                    (
                        "Scan blocked because "
                        "target is not local/private."
                    ),
                    ip
                )

                result = {
                    "ip": ip,
                    "error":
                        "Only local/private lab targets are allowed",
                    "ports": [],
                    "findings": [],
                    "security_score": None
                }

            else:

                target_string = str(
                    target
                )

                # ------------------------------------------
                # Threat Intelligence Check
                # ------------------------------------------

                threat_match = (
                    check_ip_against_threat_intelligence(
                        target_string
                    )
                )

                if threat_match:

                    create_security_event(
                        event_type=(
                            "THREAT_INTELLIGENCE_MATCH"
                        ),
                        severity=(
                            threat_match["severity"]
                        ),
                        title=(
                            "Threat Intelligence IOC Match"
                        ),
                        description=(
                            f"Target IP {target_string} "
                            f"matched an active threat "
                            f"intelligence indicator. "
                            f"Source: "
                            f"{threat_match['source'] or 'Internal IOC database'}. "
                            f"Description: "
                            f"{threat_match['description'] or 'No additional description.'}"
                        ),
                        username=session.get(
                            "username"
                        ),
                        target_ip=target_string
                    )

                    create_log(
                        "IOC_MATCH",
                        (
                            f"Scan target "
                            f"{target_string} matched "
                            f"active IOC "
                            f"#{threat_match['id']}."
                        ),
                        target_string
                    )

                create_log(
                    "SCAN_STARTED",
                    "Security scan started.",
                    target_string
                )

                ports_to_scan = {
                    22: "SSH",
                    80: "HTTP",
                    443: "HTTPS",
                    3306: "MySQL",
                    5000: "Flask",
                    8080: "HTTP-ALT"
                }

                scan_results = []
                findings = []
                security_score = 100

                for (
                    port,
                    service
                ) in ports_to_scan.items():

                    sock = socket.socket(
                        socket.AF_INET,
                        socket.SOCK_STREAM
                    )

                    sock.settimeout(
                        0.5
                    )

                    connection = sock.connect_ex(
                        (
                            target_string,
                            port
                        )
                    )

                    sock.close()

                    if connection == 0:

                        status = "OPEN"

                        port_findings = (
                            analyze_open_port(
                                port,
                                service
                            )
                        )

                        for finding in (
                            port_findings
                        ):

                            findings.append(
                                finding
                            )

                            security_score -= (
                                finding["penalty"]
                            )

                    else:

                        status = "CLOSED"

                    scan_results.append({
                        "port": port,
                        "service": service,
                        "status": status
                    })

                security_score = max(
                    0,
                    security_score
                )

                scan_time = (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                conn = get_db_connection()

                cursor = conn.execute("""
                    INSERT INTO scans (
                        target_ip,
                        scan_time,
                        security_score,
                        username
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    target_string,
                    scan_time,
                    security_score,
                    session.get("username")
                ))

                scan_id = cursor.lastrowid

                for item in scan_results:

                    conn.execute("""
                        INSERT INTO scan_results (
                            scan_id,
                            port,
                            service,
                            status
                        )
                        VALUES (?, ?, ?, ?)
                    """, (
                        scan_id,
                        item["port"],
                        item["service"],
                        item["status"]
                    ))

                for finding in findings:

                    conn.execute("""
                        INSERT INTO findings (
                            scan_id,
                            port,
                            title,
                            severity,
                            description,
                            score_penalty
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        finding["port"],
                        finding["title"],
                        finding["severity"],
                        finding["description"],
                        finding["penalty"]
                    ))

                conn.commit()
                conn.close()

                open_count = sum(
                    1
                    for item in scan_results
                    if item["status"] == "OPEN"
                )

                create_log(
                    "SCAN_COMPLETED",
                    (
                        f"Scan completed. "
                        f"{open_count} open ports detected. "
                        f"Security score: "
                        f"{security_score}/100."
                    ),
                    target_string
                )

                result = {
                    "ip": target_string,
                    "error": None,
                    "ports": scan_results,
                    "findings": findings,
                    "security_score":
                        security_score
                }

        except ValueError:

            create_log(
                "INVALID_TARGET",
                "Invalid IP address entered.",
                ip
            )

            result = {
                "ip": ip,
                "error":
                    "Invalid IP address",
                "ports": [],
                "findings": [],
                "security_score": None
            }

    return render_template(
        "scanner.html",
        result=result
    )


# --------------------------------------------------
# HISTORY
# --------------------------------------------------

@app.route("/history")
def history():

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    scans = conn.execute("""
        SELECT
            scans.id,
            scans.target_ip,
            scans.scan_time,
            scans.security_score,
            scans.username,
            SUM(
                CASE
                    WHEN scan_results.status = 'OPEN'
                    THEN 1
                    ELSE 0
                END
            ) AS open_ports
        FROM scans
        LEFT JOIN scan_results
        ON scans.id = scan_results.scan_id
        GROUP BY scans.id
        ORDER BY scans.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "history.html",
        scans=scans
    )


# --------------------------------------------------
# SCAN DETAILS
# --------------------------------------------------

@app.route("/scan/<int:scan_id>")
def scan_details(scan_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    scan = conn.execute("""
        SELECT *
        FROM scans
        WHERE id = ?
    """, (
        scan_id,
    )).fetchone()

    results = conn.execute("""
        SELECT
            port,
            service,
            status
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY port
    """, (
        scan_id,
    )).fetchall()

    findings = conn.execute("""
        SELECT
            port,
            title,
            severity,
            description,
            score_penalty
        FROM findings
        WHERE scan_id = ?
        ORDER BY id
    """, (
        scan_id,
    )).fetchall()

    conn.close()

    if scan is None:

        return (
            "Scan not found",
            404
        )

    return render_template(
        "scan_details.html",
        scan=scan,
        results=results,
        findings=findings
    )


# --------------------------------------------------
# ALERTS
# --------------------------------------------------

# Presentation-only label for security_events.event_type - never
# changes the stored value, purely a display convenience. New/
# unrecognized event types fall back to the raw value unchanged.
INCIDENT_TYPE_LABELS = {
    "BRUTE_FORCE_DETECTED": "Brute Force Detection",
    "MALICIOUS_IP_REPUTATION": "Malicious IP Reputation",
    "MALICIOUS_WEB_DESTINATION": "Malicious Web Destination",
    "THREAT_INTELLIGENCE_MATCH": "Threat Intelligence Match"
}


def format_incident_type(event_type):

    return INCIDENT_TYPE_LABELS.get(
        event_type,
        event_type
    )


# Same purpose as INCIDENT_TYPE_LABELS/format_incident_type above,
# but for security_alerts.alert_type - kept as a separate mapping
# since the two tables' type vocabularies are independent. Unknown/
# future alert_type values fall back to a generic, safe formatting
# (underscores -> spaces, title case) rather than the raw
# ALL_CAPS_WITH_UNDERSCORES identifier, so a new alert_type added
# later never surfaces as an unformatted internal value.
ALERT_TYPE_LABELS = {
    "MALICIOUS_WEB_DESTINATION": "Malicious Web Destination"
}


def format_alert_type(alert_type):

    if alert_type in ALERT_TYPE_LABELS:

        return ALERT_TYPE_LABELS[alert_type]

    return alert_type.replace(
        "_",
        " "
    ).title()


# ==================================================
# PHASE 12B.5B: CLOUDFLARE MANUAL THREAT INTELLIGENCE
# ==================================================
# ONLY this POST can cause a live Cloudflare request. Never GET, never
# page load, never a background job. The browser sends ONLY a record id
# and an indicator TYPE - the indicator itself is always derived
# server-side from the stored event/alert, so this route cannot be used to
# look up arbitrary or internal values. CSRF is enforced site-wide by
# CSRFProtect (the form carries csrf_token). Analyst and Admin may use it
# (read-only intelligence; no configuration or enforcement side effects).
# Cloudflare evidence is context only: no Threat Risk, severity,
# Investigation Priority, Alert, Incident or Response effect, and (unlike
# the manual /reputation route) it can NEVER create an Incident.

def build_cloudflare_context(resolved_ip, domain):

    ip_value = threat_intel_fw.normalize_ip_candidate(resolved_ip)
    domain_value = threat_intel_fw.normalize_domain_candidate(domain)

    conn = get_db_connection()

    try:

        budget = cloudflare_provider.get_budget_state(conn)

        actions = []

        for indicator_type, value in (("IP", ip_value), ("DOMAIN", domain_value)):

            if value:
                actions.append({
                    "type": indicator_type,
                    "value": value,
                    "state": cloudflare_provider.get_action_state(conn, indicator_type, value, budget)
                })

        return {
            "actions": actions,
            "budget": budget,
            "configured": cloudflare_provider.is_configured()
        }

    finally:
        conn.close()


def _cloudflare_return_target(source, record_id, outcome, event_id):

    params = {"cf": outcome.lower()}

    if source == "alert":
        return url_for("alert_details", alert_id=record_id, **params)

    # Phase 12B.6B: when the POST came from THIS event's Investigation page
    # (same host, exact path match), return there. Nothing else about the
    # route changed; anything else keeps the previous behavior below.
    try:
        ref_inv = urlparse(request.referrer or "")
        if ref_inv.netloc == request.host and ref_inv.path == f"/investigation/event/{event_id}":
            return url_for("investigation_event", event_id=event_id, **params)
    except ValueError:
        pass

    # Back to Web Monitoring, preserving the analyst's filters when the
    # referrer is that same page on this host; anything else falls back to
    # the plain page (no open redirect).
    default_path = "/web-monitoring"
    query = []

    try:
        ref = urlparse(request.referrer or "")
        if ref.netloc == request.host and ref.path == default_path:
            query = [(k, v) for k, v in parse_qsl(ref.query) if k not in ("cf", "cf_event")]
    except ValueError:
        query = []

    query += [("cf", outcome.lower()), ("cf_event", str(event_id))]

    return default_path + "?" + urlencode(query)


@app.route("/cloudflare-investigate", methods=["POST"])
def cloudflare_investigate():

    if not login_required():

        return redirect(url_for("login"))

    if session.get("role") not in ("admin", "analyst"):

        return ("Access denied", 403)

    source = request.form.get("source", "")
    indicator_type = request.form.get("indicator_type", "")

    try:
        record_id = int(request.form.get("record_id", ""))
    except ValueError:
        return ("Bad request", 400)

    if source not in ("event", "alert") or indicator_type not in ("IP", "DOMAIN"):

        return ("Bad request", 400)

    # ---- derive the candidate SERVER-SIDE from the stored record ----
    conn = get_db_connection()

    resolved_ip = None
    domain = None
    event_id = record_id

    if source == "event":

        row = conn.execute(
            "SELECT resolved_ip, domain FROM web_events WHERE id = ?",
            (record_id,)
        ).fetchone()

        if row is None:
            conn.close()
            return ("Not found", 404)

        resolved_ip, domain = row["resolved_ip"], row["domain"]

    else:

        alert = conn.execute(
            "SELECT source_event_id, destination_ip, domain FROM security_alerts WHERE id = ?",
            (record_id,)
        ).fetchone()

        if alert is None:
            conn.close()
            return ("Not found", 404)

        event_row = None

        if alert["source_event_id"]:
            event_row = conn.execute(
                "SELECT resolved_ip, domain FROM web_events WHERE id = ?",
                (alert["source_event_id"],)
            ).fetchone()
            event_id = alert["source_event_id"]

        resolved_ip = (event_row["resolved_ip"] if event_row else None) or alert["destination_ip"]
        domain = (event_row["domain"] if event_row else None) or alert["domain"]

    conn.close()

    if indicator_type == "IP":
        value = threat_intel_fw.normalize_ip_candidate(resolved_ip)
    else:
        value = threat_intel_fw.normalize_domain_candidate(domain)

    if value is None:

        outcome = cloudflare_provider.OUTCOME_NOT_ELIGIBLE

    else:

        outcome = cloudflare_provider.manual_lookup(indicator_type, value)["outcome"]

    create_log(
        "CLOUDFLARE_INVESTIGATE",
        (
            f"Cloudflare {indicator_type} Intelligence lookup "
            f"requested from {source} #{record_id} for "
            f"{value or '(no eligible indicator)'}: {outcome}."
        ),
        value if indicator_type == "IP" and value else None
    )

    return redirect(_cloudflare_return_target(source, record_id, outcome, event_id))


# ==================================================
# STEP 24B.1: MANUAL URL THREAT-INTEL INVESTIGATION (display-only)
# ==================================================
# POST only, mirrors /cloudflare-investigate's exact pattern: same
# login_required()+role check, same "derive the candidate SERVER-SIDE
# from the stored record, never trust a client-submitted indicator
# value" design (record_id -> web_events.url, never a raw url= form
# field - an analyst cannot submit an arbitrary URL unrelated to a real
# event). Never creates/touches security_alerts, response_commands,
# blocked_domains, or any block/isolate action, and never changes any
# web_event's risk_score/severity/decision - threat_intel_display.
# force_recheck() (the only function that can cause a live external
# call here) already guarantees that, unchanged, exactly as it does for
# every other provider.

# Step 24B.1: in-process lock preventing two near-simultaneous manual
# clicks for the SAME (provider, url) from both reaching the external
# service - force_recheck() itself has no such guard (verified by
# reading it: it deletes the cache row, then calls the provider
# unconditionally). A single Flask dev-server process is this
# project's actual deployment model throughout (see e.g. Cloudflare's
# own budget-state reads, which assume single-process too) - this lock
# is scoped narrowly to the NEW route only, never touching the shared,
# provider-agnostic force_recheck()/manual_lookup() functions other
# providers (Cloudflare, the generic /api/threat-intel/recheck route)
# already rely on.
_url_intel_lock = threading.Lock()
_url_intel_in_progress = set()


@app.route("/api/url-intel/investigate", methods=["POST"])
def url_intel_investigate():

    if not login_required():
        return redirect(url_for("login"))

    if session.get("role") not in ("admin", "analyst"):
        return ("Access denied", 403)

    provider = (request.form.get("provider") or "").strip()

    if provider not in threat_intel_display.URL_INTEL_PROVIDERS:
        return ("Bad request", 400)

    try:
        event_id = int(request.form.get("event_id", ""))
    except ValueError:
        return ("Bad request", 400)

    return_to = request.form.get("return_to") or request.referrer or url_for("web_monitoring.web_monitoring")
    separator = "&" if "?" in return_to else "?"

    # ---- derive the URL SERVER-SIDE from the stored record only ----
    conn = get_db_connection()
    row = conn.execute(
        "SELECT url FROM web_events WHERE id = ?",
        (event_id,)
    ).fetchone()
    conn.close()

    if row is None or not row["url"]:
        return ("Not found", 404)

    url = row["url"]

    # ---- server-side privacy policy, independent of the extension's own ----
    allowed, reason = url_send_policy.url_is_safe_to_send_externally(url)

    if not allowed:
        create_log(
            "URL_INTEL_BLOCKED_BY_POLICY",
            f"URL intel investigation blocked for event #{event_id} ({provider}): {reason}"
        )
        return redirect(f"{return_to}{separator}url_intel=blocked")

    lock_key = (provider, url)

    with _url_intel_lock:
        if lock_key in _url_intel_in_progress:
            # A concurrent request for the identical (provider, url) is
            # already in flight - never fire a second external call for
            # the same pair; the first request's result will populate
            # the cache for this one to read on the next page view.
            return redirect(f"{return_to}{separator}url_intel=in_progress")
        _url_intel_in_progress.add(lock_key)

    try:
        result = threat_intel_display.force_recheck(provider, "URL", url)
    finally:
        with _url_intel_lock:
            _url_intel_in_progress.discard(lock_key)

    if "error" in result:
        create_log(
            "URL_INTEL_RECHECK_REJECTED",
            f"URL intel re-check rejected for event #{event_id} ({provider}): {result['error']}"
        )
    else:
        create_log(
            "URL_INTEL_RECHECK",
            f"URL intel re-check performed for event #{event_id}: {provider} -> {result.get('lookup_status')}"
        )

    return redirect(f"{return_to}{separator}url_intel={provider}&url_intel_event={event_id}")


# ==================================================
# PHASE 12B.6B: UNIFIED INVESTIGATION VIEW (READ-ONLY)
# ==================================================
# GET only. Loads exactly one web_events row by primary key, never accepts
# an indicator value, never performs an external lookup, never writes
# (no audit row for merely viewing). All assembly lives in
# investigation.py; the Cloudflare button (if shown) posts to the existing
# /cloudflare-investigate route with a server-derived indicator.

@app.route("/investigation/event/<int:event_id>", methods=["GET"])
def investigation_event(event_id):

    if not login_required():

        return redirect(url_for("login"))

    conn = get_db_connection()

    try:

        inv = investigation.build_investigation(conn, event_id)

    finally:

        conn.close()

    if inv is None:

        return ("Event not found", 404)

    cf_message = cloudflare_provider.OUTCOME_MESSAGES.get(
        (request.args.get("cf") or "").strip().upper()
    )

    return render_template(
        "investigation.html",
        inv=inv,
        cf_message=cf_message
    )


@app.route("/alerts")
def alerts():

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    # KPI summary - computed here, server-side, every request (no
    # cache). Definitions match the approved Security Operations
    # redesign exactly.
    today = datetime.now().strftime("%Y-%m-%d")

    active_alerts_count = conn.execute("""
        SELECT COUNT(*)
        FROM security_alerts
        WHERE status IN ('NEW', 'ACKNOWLEDGED')
    """).fetchone()[0]

    open_incidents_count = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE status IN ('OPEN', 'INVESTIGATING')
    """).fetchone()[0]

    high_critical_incidents_count = conn.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE status IN ('OPEN', 'INVESTIGATING')
        AND severity IN ('HIGH', 'CRITICAL')
    """).fetchone()[0]

    new_alerts_today_count = conn.execute("""
        SELECT COUNT(*)
        FROM security_alerts
        WHERE created_at LIKE ?
    """, (
        today + "%",
    )).fetchone()[0]

    raw_security_events = conn.execute("""
        SELECT *
        FROM security_events
        ORDER BY
            CASE status
                WHEN 'OPEN' THEN 1
                WHEN 'INVESTIGATING' THEN 2
                WHEN 'RESOLVED' THEN 3
                ELSE 4
            END,
            id DESC
    """).fetchall()

    # Enrich each Incident with a display-only type label and an
    # honest "is this target_ip a real managed endpoint" check -
    # never assumed, only shown true when a live join proves it
    # (endpoints.source='endpoint-agent'). Does not alter any
    # stored security_events value.
    security_events = []

    for event_row in raw_security_events:

        event = dict(event_row)

        event["type_label"] = format_incident_type(
            event["event_type"]
        )

        event["is_managed_endpoint"] = False

        if event["target_ip"]:

            managed_endpoint = conn.execute("""
                SELECT id
                FROM endpoints
                WHERE ip_address = ?
                AND source = 'endpoint-agent'
            """, (
                event["target_ip"],
            )).fetchone()

            event["is_managed_endpoint"] = (
                managed_endpoint is not None
            )

        security_events.append(event)

    # Phase 8: filters for the Security Alerts panel - Severity,
    # Status, Endpoint, free-text Search (title/domain/endpoint),
    # and whether the alert is linked to an Incident.
    severity_filter = request.args.get("severity", "").strip()
    status_filter = request.args.get("status", "").strip()
    endpoint_filter = request.args.get("endpoint_ip", "").strip()
    search_filter = request.args.get("q", "").strip()
    linked_filter = request.args.get("linked", "").strip()

    alert_query = "SELECT * FROM security_alerts WHERE 1=1"
    alert_params = []

    if severity_filter:
        alert_query += " AND severity = ?"
        alert_params.append(severity_filter)

    if status_filter:
        alert_query += " AND status = ?"
        alert_params.append(status_filter)

    if endpoint_filter:
        alert_query += " AND endpoint_ip = ?"
        alert_params.append(endpoint_filter)

    if search_filter:
        alert_query += (
            " AND (title LIKE ? OR domain LIKE ? "
            "OR destination_ip LIKE ? OR endpoint_ip LIKE ?)"
        )
        like_value = f"%{search_filter}%"
        alert_params.extend([like_value, like_value, like_value, like_value])

    if linked_filter == "linked":
        alert_query += " AND incident_id IS NOT NULL"
    elif linked_filter == "unlinked":
        alert_query += " AND incident_id IS NULL"

    alert_query += """
        ORDER BY
            CASE status
                WHEN 'NEW' THEN 1
                WHEN 'ACKNOWLEDGED' THEN 2
                WHEN 'ESCALATED' THEN 3
                WHEN 'CLOSED' THEN 4
                ELSE 5
            END,
            id DESC
        LIMIT 100
    """

    raw_security_alerts = conn.execute(alert_query, alert_params).fetchall()

    # Display-only human-readable alert_type label, same pattern
    # as type_label on Incidents above - never alters the stored
    # alert_type value.
    security_alerts = []

    for alert_row in raw_security_alerts:

        alert = dict(alert_row)

        alert["type_label"] = format_alert_type(
            alert["alert_type"]
        )

        security_alerts.append(alert)

    distinct_endpoints = conn.execute("""
        SELECT DISTINCT endpoint_ip
        FROM security_alerts
        WHERE endpoint_ip IS NOT NULL
        ORDER BY endpoint_ip
    """).fetchall()

    conn.close()

    return render_template(
        "alerts.html",
        security_events=security_events,
        security_alerts=security_alerts,
        distinct_endpoints=distinct_endpoints,
        severity_filter=severity_filter,
        status_filter=status_filter,
        endpoint_filter=endpoint_filter,
        search_filter=search_filter,
        linked_filter=linked_filter,
        active_alerts_count=active_alerts_count,
        open_incidents_count=open_incidents_count,
        high_critical_incidents_count=high_critical_incidents_count,
        new_alerts_today_count=new_alerts_today_count
    )


# --------------------------------------------------
# ALERT DETAILS (Phase 6)
# --------------------------------------------------
# Analyst/Admin workflow (documented in the Phase 6 report):
#   - Acknowledge and Close are allowed for any logged-in user
#     (Analyst or Admin) - normal SOC alert-triage work.
#   - Manual escalation (MEDIUM -> Incident) is also allowed for
#     Analyst/Admin - it is a triage decision, not a containment
#     action (no blocking/isolation happens here).
#   - Real containment actions (Block/Isolate) do not exist yet
#     - that is Phase 7, and will be Admin-only.

@app.route(
    "/alert/<int:alert_id>",
    methods=["GET", "POST"]
)
def alert_details(alert_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    error = None
    success = None

    if request.method == "POST":

        action = request.form.get("action", "")

        conn = get_db_connection()

        alert = conn.execute("""
            SELECT *
            FROM security_alerts
            WHERE id = ?
        """, (
            alert_id,
        )).fetchone()

        if alert is None:

            conn.close()

            return (
                "Alert not found",
                404
            )

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        username = session.get("username")

        if action == "acknowledge":

            if alert["status"] != "NEW":

                error = _(
                    "Only a NEW alert can be acknowledged."
                )

            else:

                conn.execute("""
                    UPDATE security_alerts
                    SET
                        status = 'ACKNOWLEDGED',
                        acknowledged_by = ?,
                        acknowledged_at = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    username,
                    now,
                    now,
                    alert_id
                ))

                conn.commit()

                create_log(
                    "ALERT_ACKNOWLEDGED",
                    f"Alert #{alert_id} acknowledged by {username}.",
                    target_ip=alert["endpoint_ip"]
                )

                success = _("Alert acknowledged.")

        elif action == "close":

            if alert["status"] not in ("NEW", "ACKNOWLEDGED"):

                error = _(
                    "This alert cannot be closed from its "
                    "current status."
                )

            else:

                conn.execute("""
                    UPDATE security_alerts
                    SET status = 'CLOSED', updated_at = ?
                    WHERE id = ?
                """, (
                    now,
                    alert_id
                ))

                conn.commit()

                create_log(
                    "ALERT_CLOSED",
                    f"Alert #{alert_id} closed by {username}.",
                    target_ip=alert["endpoint_ip"]
                )

                success = _("Alert closed.")

        elif action == "escalate":

            if alert["status"] == "ESCALATED":

                error = _(
                    "This alert is already escalated to an "
                    "incident."
                )

            elif alert["status"] == "CLOSED":

                error = _(
                    "A closed alert cannot be escalated in "
                    "this phase."
                )

            else:

                incident_id = create_incident_from_alert(
                    dict(alert),
                    username=username
                )

                create_log(
                    "INCIDENT_CREATED_FROM_ALERT",
                    (
                        f"Alert #{alert_id} manually escalated "
                        f"to Incident #{incident_id} by "
                        f"{username}."
                    ),
                    target_ip=alert["endpoint_ip"]
                )

                success = _(
                    "Alert escalated to Incident #%(id)s.",
                    id=incident_id
                )

        elif action in (
            "block_destination",
            "unblock_destination",
            "isolate_endpoint",
            "restore_endpoint"
        ):

            # Phase 7, section 7: containment actions are
            # Admin-only, enforced here server-side - NOT just
            # by hiding buttons in the template.
            if not admin_required():

                conn.close()

                return (
                    "Access denied - Administrator only",
                    403
                )

            target_map = {
                "block_destination": (
                    "BLOCK_DESTINATION",
                    alert["domain"] or alert["destination_ip"]
                ),
                "unblock_destination": (
                    "UNBLOCK_DESTINATION",
                    alert["domain"] or alert["destination_ip"]
                ),
                "isolate_endpoint": (
                    "ISOLATE_ENDPOINT",
                    None
                ),
                "restore_endpoint": (
                    "RESTORE_ENDPOINT",
                    None
                )
            }

            command_type, target = target_map[action]

            if command_type in (
                "BLOCK_DESTINATION", "UNBLOCK_DESTINATION"
            ) and not target:

                error = _(
                    "This alert has no destination to "
                    "block/unblock."
                )

            elif not alert["endpoint_ip"]:

                error = _(
                    "This alert has no associated endpoint."
                )

            elif command_type in (
                "ISOLATE_ENDPOINT", "RESTORE_ENDPOINT"
            ) and conn.execute("""
                SELECT id
                FROM endpoints
                WHERE ip_address = ?
                AND source = 'endpoint-agent'
            """, (
                alert["endpoint_ip"],
            )).fetchone() is None:

                # Defense in depth: never queue an endpoint
                # containment command unless the target is a
                # real, agent-observed managed endpoint - not
                # just a UI hide.
                error = _(
                    "This endpoint is not a recognized managed "
                    "endpoint and cannot be isolated/restored."
                )

            else:

                command, reused = create_response_command(
                    command_type,
                    alert["endpoint_ip"],
                    target=target,
                    reason=f"Requested from Alert #{alert_id}.",
                    requested_by=username,
                    alert_id=alert_id,
                    incident_id=alert["incident_id"]
                )

                create_log(
                    "RESPONSE_COMMAND_CREATED",
                    (
                        f"{command_type} requested for endpoint "
                        f"{alert['endpoint_ip']} from Alert "
                        f"#{alert_id} by {username} "
                        f"(command #{command['id']}"
                        + (", reused existing" if reused else "")
                        + ")."
                    ),
                    target_ip=alert["endpoint_ip"]
                )

                # Literal, translatable labels for the 4 known command
                # types - command_type.replace('_',' ').title() would
                # build a string dynamically, which gettext extraction
                # cannot discover statically.
                command_type_label = {
                    "BLOCK_DESTINATION": _("Block Destination"),
                    "UNBLOCK_DESTINATION": _("Unblock Destination"),
                    "ISOLATE_ENDPOINT": _("Isolate Endpoint"),
                    "RESTORE_ENDPOINT": _("Restore Endpoint"),
                }.get(command_type, command_type)

                success = _(
                    "%(command_label)s requested (command #%(command_id)s). "
                    "The Endpoint Agent will pick this up on its next poll.",
                    command_label=command_type_label,
                    command_id=command["id"]
                )

        else:

            error = _("Unknown action.")

        conn.close()

    conn = get_db_connection()

    alert = conn.execute("""
        SELECT *
        FROM security_alerts
        WHERE id = ?
    """, (
        alert_id,
    )).fetchone()

    conn.close()

    if alert is None:

        return (
            "Alert not found",
            404
        )

    try:
        detection_reasons = json.loads(
            alert["detection_reasons"] or "[]"
        )
    except (json.JSONDecodeError, TypeError):
        detection_reasons = []

    try:
        recommended_response = json.loads(
            alert["recommended_response"] or "[]"
        )
    except (json.JSONDecodeError, TypeError):
        recommended_response = []

    alert_type_label = format_alert_type(alert["alert_type"])

    # Detection Evidence enrichment (display-only, SOC investigation
    # workspace redesign): for detection_reasons strings the worker
    # is known to generate for a genuine local IOC hit, look up the
    # matching threat_indicators row so the analyst sees the
    # indicator's own severity/description/source instead of just
    # the frozen reason sentence. Any reason text that doesn't match
    # one of these known prefixes is shown as plain stored text with
    # no added detail - this never guesses/fabricates evidence for
    # a pattern that hasn't been audited.
    conn = get_db_connection()

    # Phase 11B: HASH evidence lookup. security_alerts has no
    # sha256/md5 columns of its own, so the hash values are
    # fetched by joining back to the originating web_events row
    # via source_event_id, rather than duplicating hash storage
    # onto security_alerts.
    #
    # KNOWN LIMITATION: source_event_id is refreshed on every
    # Alert dedup/reuse (see _find_recent_matching_alert /
    # create_security_alert), so it points at the CURRENTLY
    # REFERENCED / most recent correlated web_events row, not a
    # guaranteed-immutable original-detection event. HASH
    # evidence surfaced this way must never be described as
    # "immutable original-event evidence" - it is the best
    # currently-available correlation, exactly like the existing
    # IP/DOMAIN evidence below already behaves with the same
    # field. Redesigning source_event_id into a separate
    # immutable origin_event_id is out of scope for this phase.
    event_hashes_row = None

    if alert["source_event_id"]:

        event_hashes_row = conn.execute("""
            SELECT sha256, md5, resolved_ip, domain, details
            FROM web_events
            WHERE id = ?
        """, (
            alert["source_event_id"],
        )).fetchone()

    detection_evidence = []

    for reason_text in detection_reasons:

        ioc_row = None

        if reason_text.startswith(
            "IP matches an active local IOC"
        ) and alert["destination_ip"]:

            ioc_row = conn.execute("""
                SELECT *
                FROM threat_indicators
                WHERE indicator_type = 'IP'
                AND indicator_value = ?
                AND active = 1
            """, (
                alert["destination_ip"],
            )).fetchone()

        elif reason_text.startswith(
            "Domain matched active local IOC"
        ) and alert["domain"]:

            ioc_row = conn.execute("""
                SELECT *
                FROM threat_indicators
                WHERE indicator_type = 'DOMAIN'
                AND indicator_value = ?
                AND active = 1
            """, (
                alert["domain"],
            )).fetchone()

        elif reason_text.startswith(
            "SHA-256 matches an active local HASH IOC"
        ) and event_hashes_row and event_hashes_row["sha256"]:

            ioc_row = conn.execute("""
                SELECT *
                FROM threat_indicators
                WHERE indicator_type = 'HASH'
                AND indicator_value = ?
                AND active = 1
            """, (
                event_hashes_row["sha256"],
            )).fetchone()

        elif reason_text.startswith(
            "MD5 matches an active local HASH IOC"
        ) and event_hashes_row and event_hashes_row["md5"]:

            ioc_row = conn.execute("""
                SELECT *
                FROM threat_indicators
                WHERE indicator_type = 'HASH'
                AND indicator_value = ?
                AND active = 1
            """, (
                event_hashes_row["md5"],
            )).fetchone()

        detection_evidence.append({
            "text": reason_text,
            "ioc": dict(ioc_row) if ioc_row else None
        })

    conn.close()

    # Risk Assessment enrichment (display-only): reconstruct the
    # verified local-IOC point contribution using the same
    # IOC_SEVERITY_SCORE table / severity_from_score() thresholds
    # the real scoring engine uses (threat_intelligence.py) - this
    # never recomputes or alters the stored risk_score/severity, it
    # only explains them, and it self-checks against the stored
    # values every time the page renders rather than asserting a
    # breakdown that hasn't been verified.
    risk_contributions = []

    matched_local_ioc_severity = None

    for evidence in detection_evidence:

        if evidence["ioc"]:

            matched_local_ioc_severity = evidence["ioc"]["severity"]

            risk_contributions.append({
                "label": (
                    "Local IOC Match (indicator severity: "
                    f"{evidence['ioc']['severity']})"
                ),
                "points": score_ioc_severity(
                    evidence["ioc"]["severity"]
                )
            })

    if risk_contributions:

        contribution_total = sum(
            c["points"] for c in risk_contributions
        )

        # Only claim this is the COMPLETE reconstruction when the
        # verified contribution(s) alone already account for the
        # entire stored risk_score AND the resulting severity label
        # matches - otherwise some other factor (external
        # reputation, an unrecognized reason string) contributed
        # too, and that is disclosed rather than silently
        # under-reported.
        risk_breakdown_complete = (
            contribution_total == alert["risk_score"]
            and severity_from_score(contribution_total)
            == alert["severity"]
        )

    else:

        contribution_total = 0
        risk_breakdown_complete = False

    # --------------------------------------------------
    # PHASE 11D.1: EXTERNAL INTELLIGENCE (ThreatFox) + INVESTIGATION
    # PRIORITY - read-only, additive. Never re-scores risk_score/
    # severity, never re-derives Behavioral Anomaly. A ThreatFox
    # lookup failure or missing evidence never breaks this page.
    # --------------------------------------------------
    threatfox_evidence = get_stored_evidence_for_event(
        (event_hashes_row["resolved_ip"] if event_hashes_row else None) or alert["destination_ip"],
        (event_hashes_row["domain"] if event_hashes_row else None) or alert["domain"],
        event_hashes_row["sha256"] if event_hashes_row else None
    )

    # Phase 12B.2: DISPLAY-ONLY, multi-provider evidence (ThreatFox +
    # URLhaus, now including MD5). Deliberately NOT passed to
    # compute_investigation_priority() below - that keeps using
    # threatfox_evidence exactly as before, unchanged.
    ti_evidence_multi = threat_intel_fw.get_all_provider_evidence_for_event(
        (event_hashes_row["resolved_ip"] if event_hashes_row else None) or alert["destination_ip"],
        (event_hashes_row["domain"] if event_hashes_row else None) or alert["domain"],
        event_hashes_row["sha256"] if event_hashes_row else None,
        event_hashes_row["md5"] if event_hashes_row else None
    )

    # Phase 12B.5B: Cloudflare MANUAL action state. Pure DB reads - opening
    # this page NEVER causes a Cloudflare request. Any failure here must
    # never break the page.
    try:
        cf_ctx = build_cloudflare_context(
            (event_hashes_row["resolved_ip"] if event_hashes_row else None) or alert["destination_ip"],
            (event_hashes_row["domain"] if event_hashes_row else None) or alert["domain"]
        )
    except Exception:
        cf_ctx = None

    cf_message = cloudflare_provider.OUTCOME_MESSAGES.get(
        (request.args.get("cf") or "").strip().upper()
    )

    # Phase 12B.6D: every web event explicitly associated with this alert
    # (alert_events). Pure reads; a failure never breaks the page.
    associated_conn = get_db_connection()

    try:
        associated_events = investigation.alert_associated_events(associated_conn, alert_id)
    except Exception:
        associated_events = None
    finally:
        associated_conn.close()

    behavioral_row_for_alert = None

    if alert["source_event_id"]:

        # `conn` was already closed above (after the Detection
        # Evidence loop) - use a fresh connection for this read.
        behavioral_conn = get_db_connection()

        behavioral_row_for_alert = behavioral_conn.execute("""
            SELECT evaluation_status, anomaly_score, confidence
            FROM behavioral_event_results
            WHERE web_event_id = ?
        """, (alert["source_event_id"],)).fetchone()

        behavioral_conn.close()

    alert_behavioral_label = None
    alert_behavioral_confidence = None

    if behavioral_row_for_alert:
        alert_behavioral_label = behavioral_label(
            behavioral_row_for_alert["evaluation_status"],
            behavioral_row_for_alert["anomaly_score"]
        )
        alert_behavioral_confidence = behavioral_row_for_alert["confidence"]

    alert_local_ioc_matched = detect_local_ioc_matched(
        event_hashes_row["details"] if event_hashes_row else None
    )

    investigation_priority_level, investigation_priority_reasons = compute_investigation_priority(
        alert["severity"],
        alert_behavioral_label,
        alert_behavioral_confidence,
        alert_local_ioc_matched,
        threatfox_evidence
    )

    # Phase 7: current enforcement state, so the template can
    # show Block vs Unblock and Isolate vs Restore correctly,
    # and Actions Taken (never confused with Recommended
    # Response - section 11/26).
    conn = get_db_connection()

    destination = alert["domain"] or alert["destination_ip"]

    already_blocked = False

    if destination:

        blocked_row = conn.execute("""
            SELECT active
            FROM blocked_domains
            WHERE domain = ?
        """, (
            destination,
        )).fetchone()

        already_blocked = bool(
            blocked_row and blocked_row["active"] == 1
        )

    already_isolated = False

    if alert["endpoint_ip"]:

        endpoint_row = conn.execute("""
            SELECT status
            FROM endpoints
            WHERE ip_address = ?
        """, (
            alert["endpoint_ip"],
        )).fetchone()

        already_isolated = bool(
            endpoint_row and endpoint_row["status"] == "ISOLATED"
        )

    actions_taken = conn.execute("""
        SELECT *
        FROM response_commands
        WHERE alert_id = ?
        ORDER BY id DESC
    """, (
        alert_id,
    )).fetchall()

    conn.close()

    # Organization Blocklist entry point (display-only): only
    # offered when destination_ip is itself a validated IPv4/IPv6
    # literal - never derived from a domain string, per the Global
    # Blocklist MVP's IP-only scope.
    _global_block_target_type, global_block_target = validate_global_block_target(
        alert["destination_ip"] or ""
    )

    # Step 23.1: plain-language explanation layer (presentation only -
    # built from the same `alert` row already fetched above, never a
    # second query, never a rewrite of any stored field).
    plain_explanation = plain_language.explain_alert(alert)

    return render_template(
        "alert_details.html",
        alert=alert,
        plain_explanation=plain_explanation,
        alert_type_label=alert_type_label,
        detection_reasons=detection_reasons,
        detection_evidence=detection_evidence,
        recommended_response=recommended_response,
        risk_contributions=risk_contributions,
        contribution_total=contribution_total,
        risk_breakdown_complete=risk_breakdown_complete,
        matched_local_ioc_severity=matched_local_ioc_severity,
        already_blocked=already_blocked,
        already_isolated=already_isolated,
        actions_taken=actions_taken,
        global_block_target=global_block_target,
        error=error,
        success=success,
        threatfox_evidence=threatfox_evidence,
        ti_evidence_multi=ti_evidence_multi,
        cf_ctx=cf_ctx,
        cf_message=cf_message,
        associated_events=associated_events,
        investigation_priority_level=investigation_priority_level,
        investigation_priority_reasons=investigation_priority_reasons
    )


# --------------------------------------------------
# INCIDENT DETAILS
# --------------------------------------------------

@app.route(
    "/incident/<int:event_id>",
    methods=["GET", "POST"]
)
def incident_details(event_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    error = None
    success = None

    if request.method == "POST":

        if not admin_required():

            return (
                "Access denied - Administrator only",
                403
            )

        action = request.form.get("action", "")

        if action in (
            "block_destination",
            "unblock_destination",
            "isolate_endpoint",
            "restore_endpoint"
        ):

            conn = get_db_connection()

            event = conn.execute("""
                SELECT * FROM security_events WHERE id = ?
            """, (event_id,)).fetchone()

            if event is None:

                conn.close()

                return ("Incident not found", 404)

            # Phase 7, section 18: reuse the linked Alert's
            # structured domain/destination_ip for Block/Unblock
            # if one exists (security_events has no dedicated
            # destination column of its own - avoids fragile
            # text-parsing of the freeform description).
            linked_alert = conn.execute("""
                SELECT * FROM security_alerts WHERE incident_id = ?
                ORDER BY id DESC LIMIT 1
            """, (event_id,)).fetchone()

            conn.close()

            username = session.get("username")

            command_type_map = {
                "block_destination": "BLOCK_DESTINATION",
                "unblock_destination": "UNBLOCK_DESTINATION",
                "isolate_endpoint": "ISOLATE_ENDPOINT",
                "restore_endpoint": "RESTORE_ENDPOINT"
            }

            command_type = command_type_map[action]

            # Approved fix (Incident Investigation Workspace, section
            # 7): derive the block/unblock destination independently
            # of any endpoint concept. "block_target" is WHAT would be
            # blocked; "block_execution_endpoint" is WHICH managed
            # endpoint's Agent would enforce it - these are never the
            # same variable, and a destination existing does not by
            # itself mean an execution endpoint is known.
            #   A. A structurally linked Alert exists -> its own
            #      domain/destination_ip is the destination, and its
            #      endpoint_ip (already agent-observed, same trust
            #      model as alert_details()) is the execution target.
            #   B. No linked Alert, but this is a manual
            #      MALICIOUS_IP_REPUTATION incident -> target_ip IS
            #      the suspicious destination itself, but this
            #      incident type has no endpoint concept anywhere in
            #      its schema, so there is never a known execution
            #      endpoint for it.
            #   C. Otherwise -> no destination is known at all.
            if linked_alert:

                block_target = (
                    linked_alert["domain"]
                    or linked_alert["destination_ip"]
                )
                block_execution_endpoint = event["target_ip"]

            elif (
                event["event_type"] == "MALICIOUS_IP_REPUTATION"
                and event["target_ip"]
            ):

                block_target = event["target_ip"]
                block_execution_endpoint = None

            else:

                block_target = None
                block_execution_endpoint = None

            # ISOLATE_ENDPOINT/RESTORE_ENDPOINT never carry a
            # "target" - that column is BLOCK/UNBLOCK's destination
            # only, matching the pre-existing behavior this refactor
            # must not regress.
            target = (
                block_target
                if command_type in (
                    "BLOCK_DESTINATION", "UNBLOCK_DESTINATION"
                )
                else None
            )

            if command_type in (
                "BLOCK_DESTINATION", "UNBLOCK_DESTINATION"
            ) and not block_target:

                error = _(
                    "No destination is available for this "
                    "incident (no linked Alert with a recorded "
                    "domain/IP, and this is not a manual IP "
                    "reputation incident with a recorded IP)."
                )

            elif (
                command_type in (
                    "BLOCK_DESTINATION", "UNBLOCK_DESTINATION"
                )
                and not block_execution_endpoint
            ):

                # This is the case the approved fix explicitly
                # anticipated: a real suspicious destination is
                # known, but no managed endpoint exists on which
                # the Agent could enforce a block - never fabricate
                # one, and never queue a command with no Agent that
                # will ever poll for it.
                error = _(
                    "Blocking is not currently available because "
                    "this Incident is not associated with a "
                    "managed endpoint."
                )

            elif (
                command_type in (
                    "ISOLATE_ENDPOINT", "RESTORE_ENDPOINT"
                )
                and not event["target_ip"]
            ):

                error = _("This incident has no associated endpoint.")

            else:

                # Defense in depth: never queue an endpoint
                # containment command unless the target is a
                # real, agent-observed managed endpoint - not
                # just a UI hide.
                managed_endpoint = None

                if command_type in (
                    "ISOLATE_ENDPOINT", "RESTORE_ENDPOINT"
                ):

                    managed_check_conn = get_db_connection()

                    managed_endpoint = managed_check_conn.execute("""
                        SELECT id FROM endpoints
                        WHERE ip_address = ?
                        AND source = 'endpoint-agent'
                    """, (
                        event["target_ip"],
                    )).fetchone()

                    managed_check_conn.close()

                if (
                    command_type in (
                        "ISOLATE_ENDPOINT", "RESTORE_ENDPOINT"
                    )
                    and managed_endpoint is None
                ):

                    error = _(
                        "This endpoint is not a recognized "
                        "managed endpoint and cannot be "
                        "isolated/restored."
                    )

                else:

                    command_endpoint_ip = (
                        block_execution_endpoint
                        if command_type in (
                            "BLOCK_DESTINATION", "UNBLOCK_DESTINATION"
                        )
                        else event["target_ip"]
                    )

                    command, reused = create_response_command(
                        command_type,
                        command_endpoint_ip,
                        target=target,
                        reason=f"Requested from Incident #{event_id}.",
                        requested_by=username,
                        alert_id=linked_alert["id"] if linked_alert else None,
                        incident_id=event_id
                    )

                    create_log(
                        "RESPONSE_COMMAND_CREATED",
                        (
                            f"{command_type} requested for endpoint "
                            f"{command_endpoint_ip} from Incident "
                            f"#{event_id} by {username} "
                            f"(command #{command['id']}"
                            + (", reused existing" if reused else "")
                            + ")."
                        ),
                        target_ip=command_endpoint_ip
                    )

                    command_type_label = {
                        "BLOCK_DESTINATION": _("Block Destination"),
                        "UNBLOCK_DESTINATION": _("Unblock Destination"),
                        "ISOLATE_ENDPOINT": _("Isolate Endpoint"),
                        "RESTORE_ENDPOINT": _("Restore Endpoint"),
                    }.get(command_type, command_type)

                    success = _(
                        "%(command_label)s requested (command #%(command_id)s).",
                        command_label=command_type_label,
                        command_id=command["id"]
                    )

            new_status = None
            allowed_statuses = []

        else:

            new_status = request.form.get(
                "status",
                ""
            )

            allowed_statuses = [
                "OPEN",
                "INVESTIGATING",
                "RESOLVED"
            ]

        if new_status is None:

            pass

        elif new_status not in allowed_statuses:

            error = _("Invalid incident status.")

        else:

            conn = get_db_connection()

            event = conn.execute("""
                SELECT *
                FROM security_events
                WHERE id = ?
            """, (
                event_id,
            )).fetchone()

            if event is None:

                conn.close()

                return (
                    "Incident not found",
                    404
                )

            old_status = event["status"]

            updated_at = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            updated_by = session.get(
                "username"
            )

            conn.execute("""
                UPDATE security_events
                SET
                    status = ?,
                    updated_by = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                new_status,
                updated_by,
                updated_at,
                event_id
            ))

            conn.commit()
            conn.close()

            create_log(
                "INCIDENT_STATUS_CHANGED",
                (
                    f"Incident #{event_id} changed "
                    f"from {old_status} "
                    f"to {new_status}."
                ),
                target_ip=event["target_ip"]
            )

            # Literal, translatable labels for the 3 known incident
            # statuses - matches the badges already translated on
            # incident_details.html/alerts.html.
            status_display_label = {
                "OPEN": _("Open"),
                "INVESTIGATING": _("Investigating"),
                "RESOLVED": _("Resolved"),
            }

            success = _(
                "Incident status changed from %(old)s to %(new)s.",
                old=status_display_label.get(old_status, old_status),
                new=status_display_label.get(new_status, new_status)
            )

    conn = get_db_connection()

    event = conn.execute("""
        SELECT *
        FROM security_events
        WHERE id = ?
    """, (
        event_id,
    )).fetchone()

    if event is None:

        conn.close()

        return (
            "Incident not found",
            404
        )

    type_label = format_incident_type(event["event_type"])

    linked_alert = conn.execute("""
        SELECT * FROM security_alerts WHERE incident_id = ?
        ORDER BY id DESC LIMIT 1
    """, (event_id,)).fetchone()

    # Context/Origin - independent concepts, never collapsed into one
    # "target" variable (SOC Incident Investigation Workspace,
    # section 13). affected_managed_endpoint is proven ONLY via a
    # live join requiring source='endpoint-agent' - never inferred
    # from event_type or from the mere presence of target_ip.
    affected_managed_endpoint = None

    if event["target_ip"]:

        affected_managed_endpoint = conn.execute("""
            SELECT * FROM endpoints
            WHERE ip_address = ?
            AND source = 'endpoint-agent'
        """, (event["target_ip"],)).fetchone()

    # suspicious_destination is ONLY meaningful for a manual IP
    # reputation incident, where target_ip IS the analyzed IP itself
    # - never presented as an endpoint.
    suspicious_destination = None

    if (
        event["event_type"] == "MALICIOUS_IP_REPUTATION"
        and event["target_ip"]
    ):
        suspicious_destination = event["target_ip"]

    # block_target/block_execution_endpoint mirror the POST-path
    # derivation (approved fix, section 7) so the GET-rendered page
    # shows the same decision the POST handler will independently
    # re-derive and enforce - the template never gets to decide this
    # on its own.
    if linked_alert:

        block_target = (
            linked_alert["domain"] or linked_alert["destination_ip"]
        )
        block_execution_endpoint = event["target_ip"]

    elif suspicious_destination:

        block_target = suspicious_destination
        block_execution_endpoint = None

    else:

        block_target = None
        block_execution_endpoint = None

    already_blocked = False

    if block_target:

        blocked_row = conn.execute("""
            SELECT active FROM blocked_domains WHERE domain = ?
        """, (block_target,)).fetchone()

        already_blocked = bool(
            blocked_row and blocked_row["active"] == 1
        )

    already_isolated = bool(
        affected_managed_endpoint
        and affected_managed_endpoint["status"] == "ISOLATED"
    )

    # Threat Intelligence enrichment (display-only, live lookup) -
    # only attempted for manual IP reputation incidents. Presented as
    # "the supporting stored result" only when its risk_score matches
    # the score already embedded in this incident's own stored
    # description text (parsed, not guessed) - otherwise shown as
    # current/unconfirmed data, never as a guaranteed historical
    # snapshot (audit section 4/5).
    threat_reputation_row = None
    reputation_confirmed = False
    local_ioc_row = None

    if suspicious_destination:

        reputation_candidates = conn.execute("""
            SELECT * FROM threat_reputation
            WHERE ip_address = ?
            ORDER BY checked_at DESC
        """, (suspicious_destination,)).fetchall()

        parsed_score = None

        score_match = re.search(
            r"risk score (\d+)/100",
            event["description"] or "",
            re.IGNORECASE
        )

        if score_match:
            parsed_score = int(score_match.group(1))

        for candidate in reputation_candidates:

            if (
                parsed_score is not None
                and candidate["risk_score"] == parsed_score
            ):
                threat_reputation_row = candidate
                reputation_confirmed = True
                break

        if threat_reputation_row is None and reputation_candidates:
            threat_reputation_row = reputation_candidates[0]
            reputation_confirmed = False

        local_ioc_row = conn.execute("""
            SELECT * FROM threat_indicators
            WHERE indicator_value = ?
            AND active = 1
        """, (suspicious_destination,)).fetchone()

    # Related, exactly-matched system_logs only - never attached by
    # approximate timestamp (audit section 10/12).
    related_logs = [
        dict(row) for row in conn.execute("""
            SELECT * FROM system_logs
            WHERE event_type = 'INCIDENT_STATUS_CHANGED'
            AND message LIKE ?
            ORDER BY log_time ASC
        """, (f"Incident #{event_id} %",)).fetchall()
    ]

    if (
        event["event_type"] == "BRUTE_FORCE_DETECTED"
        and event["username"]
    ):

        lockout_log = conn.execute("""
            SELECT * FROM system_logs
            WHERE event_type = 'ACCOUNT_LOCKED'
            AND username = ?
            AND log_time = ?
        """, (
            event["username"],
            event["event_time"]
        )).fetchone()

        if lockout_log:
            related_logs.insert(0, dict(lockout_log))

    elif suspicious_destination:

        creation_logs = conn.execute("""
            SELECT * FROM system_logs
            WHERE target_ip = ?
            AND log_time = ?
            AND event_type IN (
                'THREAT_INCIDENT_CREATED', 'IP_REPUTATION_CHECK'
            )
            ORDER BY id ASC
        """, (
            suspicious_destination,
            event["event_time"]
        )).fetchall()

        related_logs = [dict(r) for r in creation_logs] + related_logs

    # Recommended Response - only ever inherited verbatim from a
    # linked Alert's own stored recommendation; never generated for
    # incidents that don't have one (security_events has no
    # structured recommendation column - audit section 9/11).
    alert_recommended_response = []

    if linked_alert:

        try:
            alert_recommended_response = json.loads(
                linked_alert["recommended_response"] or "[]"
            )
        except (json.JSONDecodeError, TypeError):
            alert_recommended_response = []

    actions_taken = conn.execute("""
        SELECT * FROM response_commands
        WHERE incident_id = ?
        ORDER BY id DESC
    """, (event_id,)).fetchall()

    conn.close()

    # Organization Blocklist entry point (display-only): reuses the
    # same block_target already derived above (linked Alert's
    # destination, or the suspicious IP for a reputation incident -
    # never shown at all for brute-force, since block_target is
    # already None there), re-validated as an IPv4/IPv6 literal
    # since Global Blocklist never accepts a domain.
    _global_block_target_type, global_block_target = validate_global_block_target(
        block_target or ""
    )

    # Step 23.1: plain-language explanation layer (presentation only -
    # built from the same `event` row and the already-computed
    # alert_recommended_response above, never a second query, never a
    # rewrite of any stored field).
    plain_explanation = plain_language.explain_incident(
        event, linked_alert_recommended_response=alert_recommended_response
    )

    return render_template(
        "incident_details.html",
        event=event,
        plain_explanation=plain_explanation,
        type_label=type_label,
        linked_alert=linked_alert,
        affected_managed_endpoint=affected_managed_endpoint,
        suspicious_destination=suspicious_destination,
        block_target=block_target,
        block_execution_endpoint=block_execution_endpoint,
        global_block_target=global_block_target,
        threat_reputation_row=threat_reputation_row,
        reputation_confirmed=reputation_confirmed,
        local_ioc_row=local_ioc_row,
        related_logs=related_logs,
        alert_recommended_response=alert_recommended_response,
        already_blocked=already_blocked,
        already_isolated=already_isolated,
        actions_taken=actions_taken,
        error=error,
        success=success
    )


# --------------------------------------------------
# RESPONSE ACTIONS (Phase 8)
# --------------------------------------------------
# Operational visibility / audit page over response_commands
# (Phase 7). No execution buttons here on purpose - commands
# are only ever created from an Alert/Incident with a specific
# target, matching Phase 7's design.

@app.route("/response-actions")
def response_actions():

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    status_filter = request.args.get("status", "").strip()
    command_type_filter = request.args.get("command_type", "").strip()
    endpoint_filter = request.args.get("endpoint_ip", "").strip()

    query = "SELECT * FROM response_commands WHERE 1=1"
    params = []

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)

    if command_type_filter:
        query += " AND command_type = ?"
        params.append(command_type_filter)

    if endpoint_filter:
        query += " AND endpoint_ip = ?"
        params.append(endpoint_filter)

    query += " ORDER BY id DESC LIMIT 200"

    commands = conn.execute(query, params).fetchall()

    distinct_endpoints = conn.execute("""
        SELECT DISTINCT endpoint_ip
        FROM response_commands
        WHERE endpoint_ip IS NOT NULL
        ORDER BY endpoint_ip
    """).fetchall()

    conn.close()

    return render_template(
        "response_actions.html",
        commands=commands,
        distinct_endpoints=distinct_endpoints,
        status_filter=status_filter,
        command_type_filter=command_type_filter,
        endpoint_filter=endpoint_filter
    )


# --------------------------------------------------
# PHASE 11A: SECURITY ANALYTICS & HISTORICAL RISK REPORTING
# --------------------------------------------------
# Strictly read-only historical aggregation over data the platform
# already collects (web_events, security_alerts, security_events,
# response_commands). No new detection/scoring/IOC/Alert/Incident/
# response-command/Agent logic - every query here is an additive
# SQL aggregation over already-stored columns. The one "risky"
# threshold used throughout (risk_score > 0) is not new - it is
# the exact same precedent already shipped on the Dashboard's Top
# Risky Destinations widget (see dashboard() above).
#
# Terminology note (explicit product decision): this page never
# claims the platform calculates a persistent per-endpoint risk
# score. "Highest Observed Event Risk" is the highest single
# stored web_events.risk_score value seen in the period - a
# historical fact about one event, not a standing endpoint score.

def _analytics_parse_range():
    """
    Reads range/start_date/end_date from the query string and
    returns (start_dt, end_dt, range_label, error). On any invalid/
    missing custom input, falls back to the 7-day default rather
    than crashing or silently misrendering - matching the existing
    codebase's datetime.strptime()+try/except ValueError idiom
    (e.g. app.py's endpoint staleness check).
    """

    range_param = request.args.get("range", "7d").strip()

    now = datetime.now()

    error = None

    if range_param == "30d":

        start_dt = now - timedelta(days=30)
        end_dt = now

    elif range_param == "custom":

        start_raw = request.args.get("start_date", "").strip()
        end_raw = request.args.get("end_date", "").strip()

        try:

            start_dt = datetime.strptime(
                start_raw, "%Y-%m-%d"
            )

            end_dt = datetime.strptime(
                end_raw, "%Y-%m-%d"
            ).replace(
                hour=23, minute=59, second=59
            )

            if start_dt > end_dt:
                raise ValueError(
                    "start_date is after end_date"
                )

        except ValueError:

            error = (
                "Invalid custom date range - showing "
                "Last 7 Days instead."
            )

            range_param = "7d"
            start_dt = now - timedelta(days=7)
            end_dt = now

    else:

        range_param = "7d"
        start_dt = now - timedelta(days=7)
        end_dt = now

    return start_dt, end_dt, range_param, error


def _analytics_fill_day_buckets(rows, start_dt, end_dt, key_col, value_col):
    """
    Turns a GROUP BY strftime('%Y-%m-%d', ...) SQL result into a
    complete, gap-free (labels, values) pair for Chart.js - any day
    in the range with no stored rows is filled with 0 (an honest
    absence-of-data fact, never a fabricated value), so the chart's
    x-axis never silently skips a day.
    """

    counts_by_day = {
        row[key_col]: row[value_col]
        for row in rows
    }

    labels = []
    values = []

    current_date = start_dt.date()
    last_date = end_dt.date()

    while current_date <= last_date:

        day_label = current_date.strftime("%Y-%m-%d")

        labels.append(day_label)
        values.append(counts_by_day.get(day_label, 0))

        current_date += timedelta(days=1)

    return labels, values


def _analytics_percent_change(current, previous):
    """
    Honest period-over-period comparison. Never divides by zero.
    """

    if previous == 0:

        if current > 0:
            return "New"

        return "No change"

    pct = round(
        ((current - previous) / previous) * 100
    )

    if pct == 0:
        return "No change"

    sign = "+" if pct > 0 else ""

    return f"{sign}{pct}%"


@app.route("/security-analytics")
def security_analytics():

    if not login_required():

        return redirect(
            url_for("login")
        )

    start_dt, end_dt, range_param, date_error = _analytics_parse_range()

    start_bound = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_bound = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    # Previous equivalent period - immediately preceding, same
    # length, no overlap. Used only for the Period Comparison
    # section (Section 10 of the approved plan).
    period_length = end_dt - start_dt

    previous_end_dt = start_dt - timedelta(seconds=1)
    previous_start_dt = previous_end_dt - period_length

    previous_start_bound = previous_start_dt.strftime("%Y-%m-%d %H:%M:%S")
    previous_end_bound = previous_end_dt.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    # --------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------
    # Endpoints Observed = distinct trusted (endpoints.source=
    # 'endpoint-agent') endpoints with ANY telemetry in the period.
    endpoints_observed = conn.execute("""
        SELECT COUNT(DISTINCT w.endpoint_ip)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    # Risky Destination = a destination with analyzed telemetry
    # that crossed the ALREADY-EXISTING risk_score > 0 threshold
    # (same precedent as the Dashboard's Top Risky Destinations
    # widget) - not a new/invented cutoff.
    risky_destinations = conn.execute("""
        SELECT COUNT(DISTINCT COALESCE(w.domain, w.resolved_ip, w.destination))
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
    """, (start_bound, end_bound)).fetchone()[0]

    # Endpoints Exposed to Risk = distinct trusted endpoints with
    # at least one risky (risk_score > 0) event in the period.
    endpoints_exposed = conn.execute("""
        SELECT COUNT(DISTINCT w.endpoint_ip)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
    """, (start_bound, end_bound)).fetchone()[0]

    security_alerts_count = conn.execute("""
        SELECT COUNT(*) FROM security_alerts
        WHERE created_at BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    security_incidents_count = conn.execute("""
        SELECT COUNT(*) FROM security_events
        WHERE event_time BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    response_actions_count = conn.execute("""
        SELECT COUNT(*) FROM response_commands
        WHERE created_at BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    block_actions_count = conn.execute("""
        SELECT COUNT(*) FROM response_commands
        WHERE created_at BETWEEN ? AND ?
        AND command_type = 'BLOCK_DESTINATION'
    """, (start_bound, end_bound)).fetchone()[0]

    isolation_actions_count = conn.execute("""
        SELECT COUNT(*) FROM response_commands
        WHERE created_at BETWEEN ? AND ?
        AND command_type = 'ISOLATE_ENDPOINT'
    """, (start_bound, end_bound)).fetchone()[0]

    # Users Observed (Phase 11B): web_events.username still holds
    # the legacy source-label/analyst-name value (never a real OS
    # user) and is NEVER read here. Real attribution now comes
    # exclusively from web_events.os_username, populated only by
    # Agents that report it. Distinct count from trusted
    # (endpoints.source='endpoint-agent') telemetry in the period,
    # excluding NULL/empty.
    users_observed = conn.execute("""
        SELECT COUNT(DISTINCT w.os_username)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.os_username IS NOT NULL
        AND w.os_username != ''
    """, (start_bound, end_bound)).fetchone()[0]

    users_observed_available = users_observed > 0

    # --------------------------------------------------
    # RISK ACTIVITY OVER TIME (day-bucketed, both 7d/30d/custom)
    # --------------------------------------------------

    risky_events_by_day = conn.execute("""
        SELECT strftime('%Y-%m-%d', w.event_time) AS day, COUNT(*) AS c
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
        GROUP BY day
    """, (start_bound, end_bound)).fetchall()

    alerts_by_day = conn.execute("""
        SELECT strftime('%Y-%m-%d', created_at) AS day, COUNT(*) AS c
        FROM security_alerts
        WHERE created_at BETWEEN ? AND ?
        GROUP BY day
    """, (start_bound, end_bound)).fetchall()

    incidents_by_day = conn.execute("""
        SELECT strftime('%Y-%m-%d', event_time) AS day, COUNT(*) AS c
        FROM security_events
        WHERE event_time BETWEEN ? AND ?
        GROUP BY day
    """, (start_bound, end_bound)).fetchall()

    trend_labels, trend_risky_events = _analytics_fill_day_buckets(
        risky_events_by_day, start_dt, end_dt, "day", "c"
    )
    _, trend_alerts = _analytics_fill_day_buckets(
        alerts_by_day, start_dt, end_dt, "day", "c"
    )
    _, trend_incidents = _analytics_fill_day_buckets(
        incidents_by_day, start_dt, end_dt, "day", "c"
    )

    # --------------------------------------------------
    # TOP ENDPOINTS BY RISK ACTIVITY
    # --------------------------------------------------
    # Three separate queries merged in Python by endpoint_ip -
    # deliberately NOT one multi-join query, which would fan-out/
    # inflate counts across the three one-to-many relationships
    # (one endpoint -> many web_events, many alerts, many incidents).

    endpoint_risk_rows = conn.execute("""
        SELECT
            w.endpoint_ip AS endpoint_ip,
            e.hostname AS hostname,
            COUNT(*) AS risk_events,
            MAX(w.risk_score) AS highest_risk,
            MAX(w.event_time) AS last_activity
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
        GROUP BY w.endpoint_ip, e.hostname
        ORDER BY highest_risk DESC, risk_events DESC
        LIMIT 10
    """, (start_bound, end_bound)).fetchall()

    endpoint_alert_counts = {
        row["endpoint_ip"]: row["c"]
        for row in conn.execute("""
            SELECT endpoint_ip, COUNT(*) AS c
            FROM security_alerts
            WHERE created_at BETWEEN ? AND ?
            GROUP BY endpoint_ip
        """, (start_bound, end_bound)).fetchall()
    }

    # Incidents trust-joined on target_ip - this is what correctly
    # excludes BRUTE_FORCE_DETECTED (target_ip NULL) and
    # MALICIOUS_IP_REPUTATION (target_ip is an external suspicious
    # IP, not an endpoint) from ever being miscounted against an
    # endpoint - only rows where target_ip genuinely resolves to a
    # trusted managed endpoint are counted here.
    endpoint_incident_counts = {
        row["target_ip"]: row["c"]
        for row in conn.execute("""
            SELECT se.target_ip AS target_ip, COUNT(*) AS c
            FROM security_events se
            JOIN endpoints e ON se.target_ip = e.ip_address
            WHERE e.source = 'endpoint-agent'
            AND se.event_time BETWEEN ? AND ?
            GROUP BY se.target_ip
        """, (start_bound, end_bound)).fetchall()
    }

    top_endpoints = []

    for row in endpoint_risk_rows:

        highest_risk = row["highest_risk"]

        top_endpoints.append({
            "endpoint_ip": row["endpoint_ip"],
            "hostname": row["hostname"],
            "risk_events": row["risk_events"],
            "alerts": endpoint_alert_counts.get(row["endpoint_ip"], 0),
            "incidents": endpoint_incident_counts.get(row["endpoint_ip"], 0),
            "highest_observed_event_risk": highest_risk,
            "highest_observed_event_severity": severity_from_score(highest_risk),
            "last_activity": row["last_activity"]
        })

    # --------------------------------------------------
    # USERS ASSOCIATED WITH RISK ACTIVITY (Phase 11B)
    # --------------------------------------------------
    # Activity association only - NOT proof the human user
    # intentionally visited a destination or caused the event.
    # Same separate-queries-merged-in-Python pattern as Top
    # Endpoints above, to avoid alert-count join fan-out.

    user_risk_rows = conn.execute("""
        SELECT
            w.os_username AS os_username,
            COUNT(DISTINCT w.endpoint_ip) AS endpoints,
            COUNT(*) AS risk_events,
            MAX(w.risk_score) AS highest_risk
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
        AND w.os_username IS NOT NULL
        AND w.os_username != ''
        GROUP BY w.os_username
        ORDER BY highest_risk DESC, risk_events DESC
        LIMIT 10
    """, (start_bound, end_bound)).fetchall()

    user_alert_counts = {
        row["os_username"]: row["c"]
        for row in conn.execute("""
            SELECT w.os_username AS os_username, COUNT(DISTINCT sa.id) AS c
            FROM security_alerts sa
            JOIN web_events w ON sa.source_event_id = w.id
            WHERE sa.created_at BETWEEN ? AND ?
            AND w.os_username IS NOT NULL
            AND w.os_username != ''
            GROUP BY w.os_username
        """, (start_bound, end_bound)).fetchall()
    }

    users_at_risk = []

    for row in user_risk_rows:

        highest_risk = row["highest_risk"]

        users_at_risk.append({
            "os_username": row["os_username"],
            "endpoints": row["endpoints"],
            "risk_events": row["risk_events"],
            "alerts": user_alert_counts.get(row["os_username"], 0),
            "highest_observed_event_risk": highest_risk,
            "highest_observed_event_severity": severity_from_score(highest_risk)
        })

    # --------------------------------------------------
    # OPTIONAL HASH / SCRIPT TELEMETRY COUNTS (Phase 11B)
    # --------------------------------------------------
    # Minimal, read-only - no new charts/panels, per the explicit
    # "don't overload the page" instruction.

    observed_hashes_count = conn.execute("""
        SELECT COUNT(DISTINCT w.sha256)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.sha256 IS NOT NULL
    """, (start_bound, end_bound)).fetchone()[0]

    hash_ioc_matches_count = conn.execute("""
        SELECT COUNT(*)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.details LIKE '%matches an active local HASH IOC%'
    """, (start_bound, end_bound)).fetchone()[0]

    script_related_events_count = conn.execute("""
        SELECT COUNT(*)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.is_script_related = 1
    """, (start_bound, end_bound)).fetchone()[0]

    # --------------------------------------------------
    # TOP RISKY DESTINATIONS
    # --------------------------------------------------

    destination_rows = conn.execute("""
        SELECT
            w.domain AS domain,
            w.resolved_ip AS resolved_ip,
            w.destination AS destination,
            COALESCE(w.domain, w.resolved_ip, w.destination) AS destination_label,
            COUNT(DISTINCT w.endpoint_ip) AS endpoints_affected,
            COUNT(*) AS event_count,
            MAX(w.risk_score) AS highest_risk,
            MAX(w.event_time) AS last_seen
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
        GROUP BY destination_label
        ORDER BY highest_risk DESC, event_count DESC
        LIMIT 10
    """, (start_bound, end_bound)).fetchall()

    top_destinations = []

    for row in destination_rows:

        has_hostname = (
            row["domain"] and row["domain"] != row["resolved_ip"]
            and row["domain"] != row["destination"]
        )

        # Local IOC evidence - only reported when a real, currently-
        # active threat_indicators row actually matches this
        # destination's stored domain/IP - never inferred/guessed.
        ioc_match = conn.execute("""
            SELECT indicator_type, severity
            FROM threat_indicators
            WHERE active = 1
            AND indicator_value IN (?, ?, ?)
            LIMIT 1
        """, (
            row["domain"], row["resolved_ip"], row["destination"]
        )).fetchone()

        highest_risk = row["highest_risk"]

        top_destinations.append({
            "destination_label": row["destination_label"],
            "has_hostname": bool(has_hostname),
            "domain": row["domain"],
            "resolved_ip": row["resolved_ip"],
            "destination": row["destination"],
            "endpoints_affected": row["endpoints_affected"],
            "event_count": row["event_count"],
            "highest_risk": highest_risk,
            "highest_severity": severity_from_score(highest_risk),
            "local_ioc": dict(ioc_match) if ioc_match else None,
            "last_seen": row["last_seen"]
        })

    # --------------------------------------------------
    # SEVERITY DISTRIBUTION - two SEPARATE, clearly labeled
    # datasets. Never mixed/merged - they represent different
    # things (raw analyzed telemetry vs. actual raised Alerts).
    # --------------------------------------------------

    severity_bands = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # Analyzed Web Events by Severity - analysis_status='ANALYZED'
    # only, so the 'PENDING' placeholder value (not-yet-analyzed
    # rows) is never conflated with a real INFO-severity result.
    web_event_severity_rows = conn.execute("""
        SELECT w.severity AS severity, COUNT(*) AS c
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.analysis_status = 'ANALYZED'
        AND w.event_time BETWEEN ? AND ?
        GROUP BY w.severity
    """, (start_bound, end_bound)).fetchall()

    web_event_severity_counts = {
        row["severity"]: row["c"] for row in web_event_severity_rows
    }

    web_event_severity_values = [
        web_event_severity_counts.get(band, 0) for band in severity_bands
    ]

    alert_severity_rows = conn.execute("""
        SELECT severity, COUNT(*) AS c
        FROM security_alerts
        WHERE created_at BETWEEN ? AND ?
        GROUP BY severity
    """, (start_bound, end_bound)).fetchall()

    alert_severity_counts = {
        row["severity"]: row["c"] for row in alert_severity_rows
    }

    alert_severity_values = [
        alert_severity_counts.get(band, 0) for band in severity_bands
    ]

    # --------------------------------------------------
    # RESPONSE ACTION STATISTICS
    # --------------------------------------------------

    response_by_command_type = conn.execute("""
        SELECT command_type, COUNT(*) AS c
        FROM response_commands
        WHERE created_at BETWEEN ? AND ?
        GROUP BY command_type
    """, (start_bound, end_bound)).fetchall()

    response_by_status = conn.execute("""
        SELECT status, COUNT(*) AS c
        FROM response_commands
        WHERE created_at BETWEEN ? AND ?
        GROUP BY status
    """, (start_bound, end_bound)).fetchall()

    # mode is ALWAYS whatever the Agent itself reported - never
    # inferred from requested intent. A command with no Agent-
    # reported mode yet (mode IS NULL) is excluded here, not
    # guessed as Simulated or Enforced.
    response_by_mode = conn.execute("""
        SELECT mode, COUNT(*) AS c
        FROM response_commands
        WHERE created_at BETWEEN ? AND ?
        AND mode IS NOT NULL
        GROUP BY mode
    """, (start_bound, end_bound)).fetchall()

    # --------------------------------------------------
    # PERIOD COMPARISON (current vs. immediately-preceding,
    # same-length period)
    # --------------------------------------------------

    previous_alerts_count = conn.execute("""
        SELECT COUNT(*) FROM security_alerts
        WHERE created_at BETWEEN ? AND ?
    """, (previous_start_bound, previous_end_bound)).fetchone()[0]

    previous_incidents_count = conn.execute("""
        SELECT COUNT(*) FROM security_events
        WHERE event_time BETWEEN ? AND ?
    """, (previous_start_bound, previous_end_bound)).fetchone()[0]

    previous_risky_events_count = conn.execute("""
        SELECT COUNT(*)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
    """, (previous_start_bound, previous_end_bound)).fetchone()[0]

    previous_response_actions_count = conn.execute("""
        SELECT COUNT(*) FROM response_commands
        WHERE created_at BETWEEN ? AND ?
    """, (previous_start_bound, previous_end_bound)).fetchone()[0]

    current_risky_events_count = conn.execute("""
        SELECT COUNT(*)
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.event_time BETWEEN ? AND ?
        AND w.risk_score > 0
    """, (start_bound, end_bound)).fetchone()[0]

    period_comparison = {
        "alerts": {
            "current": security_alerts_count,
            "previous": previous_alerts_count,
            "change": _analytics_percent_change(
                security_alerts_count, previous_alerts_count
            )
        },
        "incidents": {
            "current": security_incidents_count,
            "previous": previous_incidents_count,
            "change": _analytics_percent_change(
                security_incidents_count, previous_incidents_count
            )
        },
        "risky_events": {
            "current": current_risky_events_count,
            "previous": previous_risky_events_count,
            "change": _analytics_percent_change(
                current_risky_events_count, previous_risky_events_count
            )
        },
        "response_actions": {
            "current": response_actions_count,
            "previous": previous_response_actions_count,
            "change": _analytics_percent_change(
                response_actions_count, previous_response_actions_count
            )
        }
    }

    # --------------------------------------------------
    # WEEKLY / PERIOD SECURITY SUMMARY - rule-based/statistical
    # only, generated purely from the KPI numbers already computed
    # above. NOT AI-generated, and explicitly labeled as such in
    # the template. Never claims a persistent per-endpoint risk
    # score - only describes one observed historical event value.
    # --------------------------------------------------

    response_success_count = conn.execute("""
        SELECT COUNT(*) FROM response_commands
        WHERE created_at BETWEEN ? AND ?
        AND status = 'SUCCESS'
    """, (start_bound, end_bound)).fetchone()[0]

    response_failed_count = conn.execute("""
        SELECT COUNT(*) FROM response_commands
        WHERE created_at BETWEEN ? AND ?
        AND status = 'FAILED'
    """, (start_bound, end_bound)).fetchone()[0]

    top_endpoint_summary_line = None

    if top_endpoints:

        top = top_endpoints[0]

        top_endpoint_summary_line = (
            f"Endpoint {top['hostname'] or top['endpoint_ip']} "
            f"recorded the highest observed event risk during "
            f"the selected period: {top['highest_observed_event_risk']}/100."
        )

    # --------------------------------------------------
    # BEHAVIORAL ANALYTICS (Phase 11C) - fully independent from the
    # Threat Risk sections above. "Unusual" means unusual compared
    # with this endpoint's own previously observed telemetry - it
    # is never a threat verdict, and behavioral_event_results is
    # never joined into risk_score/severity computations anywhere.
    # --------------------------------------------------

    from behavioral_analysis import UNUSUAL_THRESHOLD

    behaviorally_unusual_events_count = conn.execute("""
        SELECT COUNT(*) FROM behavioral_event_results
        WHERE evaluation_status = 'SCORED'
        AND anomaly_score >= ?
        AND event_time BETWEEN ? AND ?
    """, (UNUSUAL_THRESHOLD, start_bound, end_bound)).fetchone()[0]

    endpoints_with_unusual_activity_count = conn.execute("""
        SELECT COUNT(DISTINCT endpoint_ip) FROM behavioral_event_results
        WHERE evaluation_status = 'SCORED'
        AND anomaly_score >= ?
        AND event_time BETWEEN ? AND ?
    """, (UNUSUAL_THRESHOLD, start_bound, end_bound)).fetchone()[0]

    new_processes_observed_count = conn.execute("""
        SELECT COUNT(*) FROM behavioral_seen_processes
        WHERE first_seen_at BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    new_destinations_observed_count = conn.execute("""
        SELECT COUNT(*) FROM behavioral_seen_destinations
        WHERE first_seen_at BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    new_process_destination_relationships_count = conn.execute("""
        SELECT COUNT(*) FROM behavioral_seen_process_destination
        WHERE first_seen_at BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    unusual_endpoint_rows = conn.execute("""
        SELECT
            r.endpoint_ip AS endpoint_ip,
            e.hostname AS hostname,
            e.last_known_os_username AS os_username,
            COUNT(*) AS unusual_events,
            MAX(r.anomaly_score) AS highest_anomaly_score,
            MAX(r.event_time) AS last_unusual_activity,
            s.maturity_state AS maturity_state,
            s.active_days AS active_days,
            s.analyzed_event_count AS analyzed_event_count
        FROM behavioral_event_results r
        JOIN endpoints e ON r.endpoint_ip = e.ip_address
        LEFT JOIN behavioral_baseline_state s ON s.endpoint_ip = r.endpoint_ip
        WHERE r.evaluation_status = 'SCORED'
        AND r.anomaly_score >= ?
        AND r.event_time BETWEEN ? AND ?
        GROUP BY r.endpoint_ip
        ORDER BY highest_anomaly_score DESC, unusual_events DESC
        LIMIT 10
    """, (UNUSUAL_THRESHOLD, start_bound, end_bound)).fetchall()

    from behavioral_analysis import compute_confidence

    endpoints_with_unusual_activity = []

    for row in unusual_endpoint_rows:

        confidence = None

        if row["maturity_state"]:
            confidence = compute_confidence(
                row["maturity_state"], row["active_days"] or 0, row["analyzed_event_count"] or 0
            )

        endpoints_with_unusual_activity.append({
            "endpoint_ip": row["endpoint_ip"],
            "hostname": row["hostname"],
            "os_username": row["os_username"],
            "unusual_events": row["unusual_events"],
            "highest_anomaly_score": row["highest_anomaly_score"],
            "baseline_confidence": confidence or "N/A",
            "last_unusual_activity": row["last_unusual_activity"]
        })

    # --------------------------------------------------
    # PHASE 11D.1: THREAT INTELLIGENCE & PRIORITIZATION
    # --------------------------------------------------
    # KPI DEFINITIONS (exact, since threat_intel_evidence is
    # INDICATOR-centric, not event-centric):
    #   "ThreatFox Matches"     = distinct (indicator_type,
    #       indicator_value) pairs whose MOST RECENT ThreatFox
    #       lookup was a MATCH, first/last retrieved within the
    #       selected period (retrieved_at BETWEEN start/end) - this
    #       counts INDICATORS looked up in this period, not events.
    #   "Indicators Enriched"   = distinct indicators with ANY
    #       ThreatFox lookup (MATCH or NO_MATCH) retrieved in this
    #       period - never implies every referencing event happened
    #       in this same period.
    #   "Investigation Priority distribution" = computed from the
    #       ACTUAL analyzed EVENTS in this period (trusted, agent-
    #       sourced, ANALYZED, event_time in range) - genuinely
    #       event-centric, unlike the two KPIs above.
    from threat_intel_providers import candidate_indicators_for_event

    threatfox_matches_count = conn.execute("""
        SELECT COUNT(DISTINCT indicator_type || '|' || indicator_value) c
        FROM threat_intel_evidence
        WHERE provider = 'threatfox' AND lookup_status = 'MATCH'
        AND retrieved_at BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    indicators_enriched_count = conn.execute("""
        SELECT COUNT(DISTINCT indicator_type || '|' || indicator_value) c
        FROM threat_intel_evidence
        WHERE provider = 'threatfox'
        AND retrieved_at BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchone()[0]

    recent_threatfox_matches = conn.execute("""
        SELECT * FROM threat_intel_evidence
        WHERE provider = 'threatfox' AND lookup_status = 'MATCH'
        AND retrieved_at BETWEEN ? AND ?
        ORDER BY retrieved_at DESC
        LIMIT 10
    """, (start_bound, end_bound)).fetchall()

    # Investigation Priority distribution - batch-computed (one
    # events query, one behavioral query, one full small
    # threat_intel_evidence table read) rather than one DB round
    # trip per event, to stay performant at real event volume.
    priority_event_rows = conn.execute("""
        SELECT w.id, w.severity, w.domain, w.resolved_ip, w.sha256, w.details
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.source = 'endpoint-agent'
        AND w.analysis_status = 'ANALYZED'
        AND w.event_time BETWEEN ? AND ?
    """, (start_bound, end_bound)).fetchall()

    behavioral_by_event_id_for_priority = {
        row["web_event_id"]: dict(row)
        for row in conn.execute("""
            SELECT web_event_id, evaluation_status, anomaly_score, confidence
            FROM behavioral_event_results
            WHERE event_time BETWEEN ? AND ?
        """, (start_bound, end_bound)).fetchall()
    }

    threatfox_lookup_table = {}
    for row in conn.execute("SELECT * FROM threat_intel_evidence WHERE provider = 'threatfox'").fetchall():
        threatfox_lookup_table[(row["indicator_type"], row["indicator_value"])] = dict(row)

    priority_distribution = {"ROUTINE": 0, "REVIEW": 0, "ELEVATED": 0, "URGENT": 0}

    for row in priority_event_rows:

        behavioral_row = behavioral_by_event_id_for_priority.get(row["id"])

        b_label = (
            behavioral_label(behavioral_row["evaluation_status"], behavioral_row["anomaly_score"])
            if behavioral_row else None
        )
        b_confidence = behavioral_row["confidence"] if behavioral_row else None

        local_ioc = detect_local_ioc_matched(row["details"])

        candidates = candidate_indicators_for_event(row["resolved_ip"], row["domain"], row["sha256"])

        tf_evidence = [
            threatfox_lookup_table[c] for c in candidates if c in threatfox_lookup_table
        ]

        level, _ = compute_investigation_priority(
            row["severity"], b_label, b_confidence, local_ioc, tf_evidence
        )

        priority_distribution[level] += 1

    conn.close()

    return render_template(
        "security_analytics.html",
        range_param=range_param,
        start_date=start_dt.strftime("%Y-%m-%d"),
        end_date=end_dt.strftime("%Y-%m-%d"),
        date_error=date_error,
        endpoints_observed=endpoints_observed,
        users_observed=users_observed,
        users_observed_available=users_observed_available,
        users_at_risk=users_at_risk,
        observed_hashes_count=observed_hashes_count,
        hash_ioc_matches_count=hash_ioc_matches_count,
        script_related_events_count=script_related_events_count,
        risky_destinations=risky_destinations,
        endpoints_exposed=endpoints_exposed,
        security_alerts_count=security_alerts_count,
        security_incidents_count=security_incidents_count,
        response_actions_count=response_actions_count,
        block_actions_count=block_actions_count,
        isolation_actions_count=isolation_actions_count,
        trend_labels=trend_labels,
        trend_risky_events=trend_risky_events,
        trend_alerts=trend_alerts,
        trend_incidents=trend_incidents,
        top_endpoints=top_endpoints,
        top_destinations=top_destinations,
        severity_bands=severity_bands,
        web_event_severity_values=web_event_severity_values,
        alert_severity_values=alert_severity_values,
        response_by_command_type=response_by_command_type,
        response_by_status=response_by_status,
        response_by_mode=response_by_mode,
        period_comparison=period_comparison,
        response_success_count=response_success_count,
        response_failed_count=response_failed_count,
        top_endpoint_summary_line=top_endpoint_summary_line,
        behaviorally_unusual_events_count=behaviorally_unusual_events_count,
        endpoints_with_unusual_activity_count=endpoints_with_unusual_activity_count,
        new_processes_observed_count=new_processes_observed_count,
        new_destinations_observed_count=new_destinations_observed_count,
        new_process_destination_relationships_count=new_process_destination_relationships_count,
        endpoints_with_unusual_activity=endpoints_with_unusual_activity,
        threatfox_matches_count=threatfox_matches_count,
        indicators_enriched_count=indicators_enriched_count,
        recent_threatfox_matches=recent_threatfox_matches,
        priority_distribution=priority_distribution
    )


# --------------------------------------------------
# PHASE 11C: BASELINE STATUS (read-only)
# --------------------------------------------------
# Shows per-endpoint behavioral baseline maturity/progress. No
# reset/relearn functionality in this phase (per the approved
# design) - purely informational, same both-roles read access as
# Security Analytics.

@app.route("/baseline-status")
def baseline_status():

    if not login_required():

        return redirect(
            url_for("login")
        )

    from behavioral_analysis import (
        LEARNING_MAX_ACTIVE_DAYS,
        LEARNING_MAX_EVENTS,
        READY_MIN_ACTIVE_DAYS,
        READY_MIN_EVENTS,
        READY_MIN_CALENDAR_COVERAGE_DAYS,
        compute_confidence
    )

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT
            s.*,
            e.hostname AS hostname
        FROM behavioral_baseline_state s
        JOIN endpoints e ON s.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        ORDER BY s.endpoint_ip
    """).fetchall()

    conn.close()

    endpoints = []

    for row in rows:

        maturity = row["maturity_state"]

        confidence = compute_confidence(
            maturity, row["active_days"] or 0, row["analyzed_event_count"] or 0
        )

        if maturity == "READY":
            progress_note = "Full scoring active (including temporal)."
        elif maturity == "ESTABLISHING":
            progress_note = (
                f"{row['active_days'] or 0}/{READY_MIN_ACTIVE_DAYS} active days, "
                f"{row['analyzed_event_count'] or 0}/{READY_MIN_EVENTS} events, "
                f"{row['calendar_coverage_days'] or 0}/{READY_MIN_CALENDAR_COVERAGE_DAYS} calendar days "
                "toward READY."
            )
        else:
            progress_note = (
                f"{row['active_days'] or 0}/{LEARNING_MAX_ACTIVE_DAYS} active days, "
                f"{row['analyzed_event_count'] or 0}/{LEARNING_MAX_EVENTS} events "
                "toward ESTABLISHING."
            )

        endpoints.append({
            "endpoint_ip": row["endpoint_ip"],
            "hostname": row["hostname"],
            "maturity_state": maturity,
            "active_days": row["active_days"],
            "analyzed_event_count": row["analyzed_event_count"],
            "confidence": confidence or "N/A",
            "latest_event_time_incorporated": row["latest_event_time_incorporated"],
            "bootstrap_completed": bool(row["bootstrap_completed"]),
            "progress_note": progress_note
        })

    return render_template(
        "baseline_status.html",
        endpoints=endpoints
    )


# --------------------------------------------------
# ORGANIZATION-WIDE RESPONSE / GLOBAL BLOCKLIST
# --------------------------------------------------
# Fans out to the existing response_commands/Agent architecture
# unchanged (BLOCK_DESTINATION/UNBLOCK_DESTINATION only, no new
# command types). See web_monitoring.py's global_block_policies/
# global_block_policy_endpoints functions for the actual writes -
# every route here only validates input and delegates to those.

@app.route("/response/organization-blocklist")
def organization_blocklist():

    if not login_required():
        return redirect(url_for("login"))

    conn = get_db_connection()

    policies = conn.execute("""
        SELECT * FROM global_block_policies
        ORDER BY active DESC, id DESC
    """).fetchall()

    conn.close()

    policy_rows = []

    active_policy_count = 0
    total_endpoints_covered = 0
    total_pending = 0
    total_failed = 0

    for policy in policies:

        coverage = get_policy_coverage(policy["id"])

        if policy["active"] == 1:
            active_policy_count += 1
            total_endpoints_covered += coverage["success"]
            total_pending += coverage["pending"]
            total_failed += coverage["failed"]

        policy_rows.append({
            "policy": dict(policy),
            "coverage": coverage
        })

    return render_template(
        "organization_blocklist.html",
        policy_rows=policy_rows,
        active_policy_count=active_policy_count,
        total_endpoints_covered=total_endpoints_covered,
        total_pending=total_pending,
        total_failed=total_failed
    )


@app.route("/response/organization-blocklist/new")
def organization_blocklist_new():

    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return ("Access denied - Administrator only", 403)

    eligible_endpoints = get_eligible_endpoints("ALL_MANAGED_ENDPOINTS")

    prefill = {
        "target": request.args.get("target", "").strip(),
        "reason": request.args.get("reason", "").strip(),
        "source_type": request.args.get("source_type", "").strip(),
        "source_id": request.args.get("source_id", "").strip()
    }

    return render_template(
        "organization_blocklist_new.html",
        eligible_endpoints=eligible_endpoints,
        prefill=prefill
    )


def _parse_global_block_form(form):
    """
    Shared, server-side-only validation for the Step 1 -> Preview
    -> Create flow. Never trusts target_type/scope/endpoint list
    from the browser beyond what this function re-derives/re-
    validates. Returns (parsed_dict, error_message_or_None).
    """

    raw_target = form.get("target", "").strip()

    target_type, target_value = validate_global_block_target(raw_target)

    if target_type is None:
        return None, "Invalid target - only IPv4 or IPv6 addresses are supported."

    scope = form.get("scope", "").strip()

    if scope not in GLOBAL_BLOCK_SCOPES:
        return None, "Invalid scope."

    selected_ips = form.getlist("selected_endpoints")

    if scope == "SELECTED_ENDPOINTS":

        eligible_selected = get_eligible_endpoints(
            "SELECTED_ENDPOINTS", selected_ips=selected_ips
        )

        if not eligible_selected:
            return None, "Select at least one valid, eligible managed endpoint."

        selected_ips = [e["ip_address"] for e in eligible_selected]

    else:

        selected_ips = None

    requested_mode = form.get("requested_mode", "").strip()

    if requested_mode not in GLOBAL_BLOCK_MODES:
        return None, "Invalid requested mode."

    reason = form.get("reason", "").strip() or None
    source_type = form.get("source_type", "").strip() or "MANUAL"
    source_id = form.get("source_id", "").strip() or None

    return {
        "target_type": target_type,
        "target_value": target_value,
        "scope": scope,
        "selected_ips": selected_ips,
        "requested_mode": requested_mode,
        "reason": reason,
        "source_type": source_type,
        "source_id": source_id
    }, None


@app.route(
    "/response/organization-blocklist/preview",
    methods=["POST"]
)
def organization_blocklist_preview():

    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return ("Access denied - Administrator only", 403)

    parsed, error = _parse_global_block_form(request.form)

    if error:

        eligible_endpoints = get_eligible_endpoints("ALL_MANAGED_ENDPOINTS")

        return render_template(
            "organization_blocklist_new.html",
            eligible_endpoints=eligible_endpoints,
            prefill={
                "target": request.form.get("target", ""),
                "reason": request.form.get("reason", ""),
                "source_type": request.form.get("source_type", ""),
                "source_id": request.form.get("source_id", "")
            },
            error=error
        ), 400

    # Read-only. No policy, no response_commands, no
    # blocked_domains, no system_logs are written by this step.
    preview = compute_global_block_preview(
        parsed["target_type"],
        parsed["target_value"],
        parsed["scope"],
        parsed["selected_ips"]
    )

    return render_template(
        "organization_blocklist_preview.html",
        parsed=parsed,
        preview=preview
    )


@app.route(
    "/response/organization-blocklist/create",
    methods=["POST"]
)
def organization_blocklist_create():

    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return ("Access denied - Administrator only", 403)

    # Never trust the preview page's hidden fields at face value -
    # re-run the exact same validation from scratch.
    parsed, error = _parse_global_block_form(request.form)

    if error:
        return (error, 400)

    username = session.get("username")

    policy, newly_added_ips = create_or_sync_global_block_policy(
        parsed["target_type"],
        parsed["target_value"],
        parsed["scope"],
        parsed["selected_ips"],
        parsed["requested_mode"],
        parsed["reason"],
        parsed["source_type"],
        parsed["source_id"],
        username
    )

    return redirect(
        url_for("organization_blocklist_details", policy_id=policy["id"])
    )


@app.route("/response/organization-blocklist/<int:policy_id>")
def organization_blocklist_details(policy_id):

    if not login_required():
        return redirect(url_for("login"))

    policy = conn_fetch_policy(policy_id)

    if policy is None:
        return ("Global Block Policy not found", 404)

    members = get_policy_endpoints(policy_id)

    endpoint_rows = []

    for member in members:

        endpoint_info = get_endpoint_info(member["endpoint_ip"])

        block_command = get_command_by_id(member["block_command_id"])
        unblock_command = get_command_by_id(member["unblock_command_id"])

        endpoint_rows.append({
            "membership": member,
            "hostname": endpoint_info["hostname"] if endpoint_info else None,
            "endpoint_ip": member["endpoint_ip"],
            "presence": compute_endpoint_presence(
                endpoint_info["last_seen"]
            ) if endpoint_info else "UNKNOWN",
            "block_command": dict(block_command) if block_command else None,
            "unblock_command": dict(unblock_command) if unblock_command else None
        })

    coverage = get_policy_coverage(policy_id)

    return render_template(
        "policy_details.html",
        policy=policy,
        endpoint_rows=endpoint_rows,
        coverage=coverage,
        error=request.args.get("error"),
        success=request.args.get("success")
    )


@app.route(
    "/response/organization-blocklist/<int:policy_id>/disable",
    methods=["POST"]
)
def organization_blocklist_disable(policy_id):

    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return ("Access denied - Administrator only", 403)

    username = session.get("username")

    ok, result = disable_global_block_policy(policy_id, username)

    if ok:
        return redirect(url_for(
            "organization_blocklist_details",
            policy_id=policy_id,
            success=f"Policy disabled. {result} UNBLOCK command(s) deployed."
        ))

    return redirect(url_for(
        "organization_blocklist_details",
        policy_id=policy_id,
        error=result
    ))


@app.route(
    "/response/organization-blocklist/<int:policy_id>/sync",
    methods=["POST"]
)
def organization_blocklist_sync(policy_id):

    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return ("Access denied - Administrator only", 403)

    policy = conn_fetch_policy(policy_id)

    if policy is None or policy["active"] != 1:
        return redirect(url_for(
            "organization_blocklist_details",
            policy_id=policy_id,
            error="Policy not found or not active."
        ))

    username = session.get("username")

    selected_ips = None

    if policy["scope"] == "SELECTED_ENDPOINTS":
        selected_ips = [
            member["endpoint_ip"]
            for member in get_policy_endpoints(policy_id)
        ]

    _policy, newly_added_ips = create_or_sync_global_block_policy(
        policy["target_type"],
        policy["target_value"],
        policy["scope"],
        selected_ips,
        policy["requested_mode"],
        policy["reason"],
        policy["source_type"],
        policy["source_id"],
        username
    )

    return redirect(url_for(
        "organization_blocklist_details",
        policy_id=policy_id,
        success=f"Sync complete. {len(newly_added_ips)} new endpoint(s) deployed."
    ))


@app.route(
    "/response/organization-blocklist/<int:policy_id>/retry",
    methods=["POST"]
)
def organization_blocklist_retry(policy_id):

    if not login_required():
        return redirect(url_for("login"))

    if not admin_required():
        return ("Access denied - Administrator only", 403)

    endpoint_ip = request.form.get("endpoint_ip", "").strip()

    username = session.get("username")

    command, error = retry_global_block_endpoint(
        policy_id, endpoint_ip, username
    )

    if error:
        return redirect(url_for(
            "organization_blocklist_details",
            policy_id=policy_id,
            error=error
        ))

    return redirect(url_for(
        "organization_blocklist_details",
        policy_id=policy_id,
        success=f"Retry requested (command #{command['id']})."
    ))


# --------------------------------------------------
# REPORTS
# --------------------------------------------------

@app.route("/reports")
def reports():

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    scans = conn.execute("""
        SELECT
            id,
            target_ip,
            scan_time,
            security_score,
            username
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "reports.html",
        scans=scans
    )


# --------------------------------------------------
# REPORT DETAILS
# --------------------------------------------------

@app.route("/report/<int:scan_id>")
def report_details(scan_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    scan = conn.execute("""
        SELECT *
        FROM scans
        WHERE id = ?
    """, (
        scan_id,
    )).fetchone()

    results = conn.execute("""
        SELECT
            port,
            service,
            status
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY port
    """, (
        scan_id,
    )).fetchall()

    findings = conn.execute("""
        SELECT
            port,
            title,
            severity,
            description,
            score_penalty
        FROM findings
        WHERE scan_id = ?
        ORDER BY id
    """, (
        scan_id,
    )).fetchall()

    conn.close()

    if scan is None:

        return (
            "Report not found",
            404
        )

    open_ports = [
        item
        for item in results
        if item["status"] == "OPEN"
    ]

    high_count = sum(
        1
        for finding in findings
        if finding["severity"] == "HIGH"
    )

    medium_count = sum(
        1
        for finding in findings
        if finding["severity"] == "MEDIUM"
    )

    low_count = sum(
        1
        for finding in findings
        if finding["severity"] == "LOW"
    )

    info_count = sum(
        1
        for finding in findings
        if finding["severity"] == "INFO"
    )

    return render_template(
        "report_details.html",
        scan=scan,
        results=results,
        open_ports=open_ports,
        findings=findings,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count
    )


# --------------------------------------------------
# PDF REPORT
# --------------------------------------------------

@app.route(
    "/report/<int:scan_id>/pdf"
)
def download_report_pdf(scan_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    scan = conn.execute("""
        SELECT *
        FROM scans
        WHERE id = ?
    """, (
        scan_id,
    )).fetchone()

    results = conn.execute("""
        SELECT
            port,
            service,
            status
        FROM scan_results
        WHERE scan_id = ?
        ORDER BY port
    """, (
        scan_id,
    )).fetchall()

    findings = conn.execute("""
        SELECT
            port,
            title,
            severity,
            description,
            score_penalty
        FROM findings
        WHERE scan_id = ?
        ORDER BY id
    """, (
        scan_id,
    )).fetchall()

    conn.close()

    if scan is None:

        return (
            "Report not found",
            404
        )

    pdf_buffer = BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "Cyber Security Assessment Report",
            styles["Title"]
        )
    )

    story.append(
        Spacer(
            1,
            15
        )
    )

    story.append(
        Paragraph(
            f"Report #{scan['id']}",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(
            1,
            20
        )
    )

    assessment_data = [
        [
            "Target IP",
            scan["target_ip"]
        ],
        [
            "Scan Date",
            scan["scan_time"]
        ],
        [
            "Performed By",
            (
                scan["username"]
                if scan["username"]
                else "Unknown"
            )
        ],
        [
            "Security Score",
            f"{scan['security_score']}/100"
        ]
    ]

    assessment_table = Table(
        assessment_data,
        colWidths=[
            5 * cm,
            10 * cm
        ]
    )

    assessment_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(
        assessment_table
    )

    story.append(
        Spacer(
            1,
            25
        )
    )

    story.append(
        Paragraph(
            "Open Ports",
            styles["Heading2"]
        )
    )

    open_ports = [
        item
        for item in results
        if item["status"] == "OPEN"
    ]

    if open_ports:

        port_data = [
            [
                "Port",
                "Service",
                "Status"
            ]
        ]

        for item in open_ports:

            port_data.append([
                str(item["port"]),
                item["service"],
                item["status"]
            ])

        port_table = Table(
            port_data,
            colWidths=[
                4 * cm,
                7 * cm,
                4 * cm
            ]
        )

        port_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#1e293b"
                    )
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    7
                )
            ])
        )

        story.append(
            port_table
        )

    else:

        story.append(
            Paragraph(
                "No open ports were detected.",
                styles["Normal"]
            )
        )

    story.append(
        Spacer(
            1,
            25
        )
    )

    story.append(
        Paragraph(
            "Security Findings",
            styles["Heading2"]
        )
    )

    if findings:

        finding_data = [
            [
                "Severity",
                "Port",
                "Finding",
                "Penalty"
            ]
        ]

        for finding in findings:

            finding_data.append([
                finding["severity"],
                str(finding["port"]),
                Paragraph(
                    finding["title"],
                    styles["Normal"]
                ),
                f"-{finding['score_penalty']}"
            ])

        findings_table = Table(
            finding_data,
            colWidths=[
                2.5 * cm,
                2 * cm,
                8 * cm,
                2.5 * cm
            ]
        )

        findings_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#1e293b"
                    )
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )
            ])
        )

        story.append(
            findings_table
        )

    else:

        story.append(
            Paragraph(
                "No security findings detected.",
                styles["Normal"]
            )
        )

    story.append(
        Spacer(
            1,
            25
        )
    )

    score = scan["security_score"]

    if score >= 90:

        summary = (
            "The target currently demonstrates "
            "a strong security posture."
        )

    elif score >= 70:

        summary = (
            "The target demonstrates a moderate "
            "security posture."
        )

    else:

        summary = (
            "The target demonstrates an elevated "
            "security risk."
        )

    story.append(
        Paragraph(
            "Assessment Summary",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            summary,
            styles["Normal"]
        )
    )

    generated_time = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    story.append(
        Spacer(
            1,
            25
        )
    )

    story.append(
        Paragraph(
            (
                "Generated by CyberSec Security "
                "Monitoring & Assessment System"
            ),
            styles["Italic"]
        )
    )

    story.append(
        Paragraph(
            f"Generated: {generated_time}",
            styles["Italic"]
        )
    )

    document.build(
        story
    )

    pdf_buffer.seek(0)

    create_log(
        "REPORT_DOWNLOADED",
        (
            f"PDF report for scan "
            f"#{scan_id} was downloaded."
        ),
        scan["target_ip"]
    )

    filename = (
        f"security_report_"
        f"{scan_id}_"
        f"{scan['target_ip'].replace('.', '_')}"
        f".pdf"
    )

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )


# --------------------------------------------------
# PHASE 11E: SCHEDULED SECURITY REPORTS (manual generation only)
# --------------------------------------------------
# Immutable, persisted report snapshots - separate from the
# scanner "Assessment Reports" above (scans/scan_results/findings
# are never touched by anything below). Once a security_reports
# row is inserted, snapshot_json never changes - both the HTML
# detail view and the PDF route read that same stored JSON, never
# recalculating against live telemetry.

@app.route("/security-reports")
def security_reports():

    if not login_required():

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    reports = conn.execute("""
        SELECT id, report_type, period_start, period_end, generated_at, generated_by
        FROM security_reports
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    # display_period is not persisted as its own column - the
    # list view only needs a cheap, honest date-range label,
    # derived directly from the stored [period_start, period_end)
    # bounds. The exact human-readable display_period used at
    # generation time lives inside snapshot_json and is shown on
    # the report detail page itself.
    reports_with_display = []

    for r in reports:

        row = dict(r)
        row["display_period"] = row["period_start"][:10] + " to " + row["period_end"][:10]
        reports_with_display.append(row)

    is_admin = admin_required()

    weekly_periods = get_closed_weekly_periods(count=8) if is_admin else []
    monthly_periods = get_closed_monthly_periods(count=6) if is_admin else []

    return render_template(
        "security_reports.html",
        reports=reports_with_display,
        is_admin=is_admin,
        weekly_periods=weekly_periods,
        monthly_periods=monthly_periods,
        error=request.args.get("error")
    )


@app.route("/security-report/generate", methods=["POST"])
def security_report_generate():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    report_type = request.form.get("report_type", "").strip().upper()

    error = None
    period_start_dt = None
    period_end_dt = None

    if report_type == "WEEKLY":

        try:
            selected_start = request.form.get("weekly_period", "").strip()
            candidate = next(
                (p for p in get_closed_weekly_periods(count=8)
                 if to_bound_str(p["start"]) == selected_start),
                None
            )
            if candidate is None:
                error = "Invalid or non-closed weekly period selected."
            else:
                period_start_dt = candidate["start"]
                period_end_dt = candidate["end"]
        except Exception:
            error = "Invalid weekly period selection."

    elif report_type == "MONTHLY":

        try:
            selected_start = request.form.get("monthly_period", "").strip()
            candidate = next(
                (p for p in get_closed_monthly_periods(count=6)
                 if to_bound_str(p["start"]) == selected_start),
                None
            )
            if candidate is None:
                error = "Invalid or non-closed monthly period selected."
            else:
                period_start_dt = candidate["start"]
                period_end_dt = candidate["end"]
        except Exception:
            error = "Invalid monthly period selection."

    elif report_type == "CUSTOM":

        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()

        period_start_dt, period_end_dt, error = validate_custom_period(start_date, end_date)

    else:

        error = "Invalid report type."

    if error:

        return redirect(url_for(
            "security_reports",
            error=error
        ))

    generated_by = session.get("username", "unknown")
    generated_at_dt = datetime.now()

    snapshot = build_security_report_data(
        report_type, period_start_dt, period_end_dt, generated_by, generated_at_dt
    )

    conn = get_db_connection()

    cursor = conn.execute("""
        INSERT INTO security_reports (
            report_type, period_start, period_end, generated_at,
            generated_by, schema_version, timezone_basis, snapshot_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report_type,
        snapshot["period_start"],
        snapshot["period_end"],
        snapshot["generated_at"],
        generated_by,
        snapshot["schema_version"],
        snapshot["timezone_basis"],
        json.dumps(snapshot)
    ))

    report_id = cursor.lastrowid

    conn.commit()
    conn.close()

    create_log(
        "SECURITY_REPORT_GENERATED",
        f"Security Report #{report_id} generated ({report_type}, {snapshot['display_period']})."
    )

    return redirect(url_for("security_report_detail", report_id=report_id))


def _load_security_report(report_id):

    conn = get_db_connection()

    row = conn.execute("""
        SELECT * FROM security_reports WHERE id = ?
    """, (report_id,)).fetchone()

    conn.close()

    if row is None:
        return None, None

    try:
        snapshot = json.loads(row["snapshot_json"])
    except (json.JSONDecodeError, TypeError):
        return dict(row), None

    return dict(row), snapshot


@app.route("/security-report/<int:report_id>")
def security_report_detail(report_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    report_row, snapshot = _load_security_report(report_id)

    if report_row is None:

        return (
            "Security Report not found",
            404
        )

    if snapshot is None or report_row["schema_version"] != report_data.SCHEMA_VERSION:

        return (
            "This report uses an unsupported schema version and cannot be rendered.",
            409
        )

    return render_template(
        "security_report_detail.html",
        report=report_row,
        snapshot=snapshot
    )


@app.route("/security-report/<int:report_id>/pdf")
def security_report_pdf(report_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    report_row, snapshot = _load_security_report(report_id)

    if report_row is None:

        return (
            "Security Report not found",
            404
        )

    if snapshot is None or report_row["schema_version"] != report_data.SCHEMA_VERSION:

        return (
            "This report uses an unsupported schema version and cannot be rendered.",
            409
        )

    pdf_buffer = build_security_report_pdf(snapshot)

    create_log(
        "SECURITY_REPORT_PDF_DOWNLOADED",
        f"PDF for Security Report #{report_id} was downloaded."
    )

    filename = f"security_report_{report_id}_{report_row['report_type'].lower()}.pdf"

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )


# --------------------------------------------------
# SYSTEM LOGS
# --------------------------------------------------

@app.route("/logs")
def logs():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    conn = get_db_connection()

    logs = conn.execute("""
        SELECT *
        FROM system_logs
        ORDER BY id DESC
        LIMIT 200
    """).fetchall()

    conn.close()

    return render_template(
        "logs.html",
        logs=logs
    )


# --------------------------------------------------
# USER MANAGEMENT
# --------------------------------------------------

@app.route(
    "/users",
    methods=["GET", "POST"]
)
def users():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    error = None
    success = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        role = request.form.get(
            "role",
            "analyst"
        )

        if not username:

            error = "Username is required."

        elif len(username) < 3:

            error = (
                "Username must contain "
                "at least 3 characters."
            )

        elif len(password) < 10:

            error = (
                "Password must contain "
                "at least 10 characters."
            )

        elif (
            not any(c.isalpha() for c in password)
            or not any(c.isdigit() for c in password)
        ):

            error = (
                "Password must contain at least one "
                "letter and one digit."
            )

        elif role not in [
            "admin",
            "analyst"
        ]:

            error = "Invalid role."

        else:

            conn = get_db_connection()

            existing_user = conn.execute("""
                SELECT id
                FROM users
                WHERE username = ?
            """, (
                username,
            )).fetchone()

            if existing_user:

                error = (
                    "Username already exists."
                )

                conn.close()

            else:

                password_hash = (
                    generate_password_hash(
                        password
                    )
                )

                conn.execute("""
                    INSERT INTO users (
                        username,
                        password_hash,
                        role,
                        failed_attempts,
                        locked_until
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    username,
                    password_hash,
                    role,
                    0,
                    None
                ))

                conn.commit()
                conn.close()

                create_log(
                    "USER_CREATED",
                    (
                        f"User '{username}' "
                        f"created with role "
                        f"'{role}'."
                    )
                )

                success = (
                    f"User '{username}' "
                    f"created successfully."
                )

    conn = get_db_connection()

    user_list = conn.execute("""
        SELECT
            id,
            username,
            role,
            failed_attempts,
            locked_until
        FROM users
        ORDER BY id
    """).fetchall()

    conn.close()

    return render_template(
        "users.html",
        users=user_list,
        error=error,
        success=success
    )


@app.route(
    "/users/<int:user_id>/delete",
    methods=["POST"]
)
def delete_user(user_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return (
            "Access denied - Administrator only",
            403
        )

    if user_id == session.get("user_id"):

        return redirect(
            url_for("users")
        )

    conn = get_db_connection()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        user_id,
    )).fetchone()

    if user:

        # Phase 9: never allow the last remaining admin account
        # to be deleted - server-side, not just a UI omission.
        if user["role"] == "admin":

            admin_count = conn.execute("""
                SELECT COUNT(*) FROM users WHERE role = 'admin'
            """).fetchone()[0]

            if admin_count <= 1:

                conn.close()

                create_log(
                    "USER_DELETE_BLOCKED",
                    (
                        f"Attempt to delete the last "
                        f"remaining admin account "
                        f"'{user['username']}' was blocked."
                    )
                )

                return redirect(
                    url_for("users")
                )

        username = user["username"]

        conn.execute("""
            DELETE FROM users
            WHERE id = ?
        """, (
            user_id,
        ))

        conn.commit()
        conn.close()

        create_log(
            "USER_DELETED",
            (
                f"User '{username}' "
                f"was deleted."
            )
        )

    else:

        conn.close()

    return redirect(
        url_for("users")
    )


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == "__main__":

    # Database initialization already happened at module import
    # time (initialize_application(), above) - safe under both
    # `python app.py` and a WSGI import (`gunicorn app:app`).
    # Nothing left to do here except actually run the dev server.

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG
    )