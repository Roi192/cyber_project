# ==================================================
# OCT 2026 STEP 22: EXECUTIVE / OWNER-FACING SECURITY SUMMARY
# ==================================================
#
# A SEPARATE, read-only view alongside the existing technical Dashboard
# (dashboard.html / app.py's dashboard() route, both completely
# unchanged). Built for a non-technical SMB owner/manager per the Step 21
# gap-analysis report's finding that no plain-language view exists today.
#
# HARD GUARANTEES:
#   - Read-only: every function here does SELECT-only queries against
#     ALREADY-EXISTING tables (endpoints, security_alerts,
#     security_events). No new table is created, no row is ever written,
#     and no detection/scoring/response function is called. This module
#     cannot affect Legacy, Shadow, alert creation, or response actions -
#     it has no import of, or call into, any of that code.
#   - No invented metric: there is NO overall "security score" anywhere
#     on this page. Organizational status is one of 4 named, documented
#     states, each derived by an explicit, auditable rule over real,
#     already-verified counts - see _compute_organization_status() below.
#     "No active threats" is never shown when there is no monitoring
#     coverage at all (STATUS_NO_COVERAGE is its own, separate state,
#     checked first, specifically to prevent that misleading reading).
#   - Monitoring-coverage ("partial coverage") is independent of, and
#     always shown ALONGSIDE, the primary organizational status - it
#     never substitutes for or hides an urgent/needs-review state, and an
#     urgent state never hides a coverage gap either.
#   - Technical jargon (IOC, SHA-256/hash, Risk Score, Shadow, Legacy,
#     provider names) never appears on this page - only on the existing
#     technical pages this page links out to (/alert/<id>,
#     /web-monitoring, etc.), which are completely unchanged.
#   - i18n-ready: every user-facing string lives either in
#     templates/executive_dashboard.html (server-rendered Jinja, directly
#     wrappable in {{ _('...') }} later) or as one of the small, named
#     STATUS_* constants below - never hardcoded inside a <script> block,
#     and never stored in the database.
# ==================================================

import os
import db_config

from datetime import datetime, timedelta

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from web_monitoring import compute_endpoint_presence
import plain_language

# SOC_DB_PATH (optional): same override convention as every other module.
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


executive_dashboard_bp = Blueprint(
    "executive_dashboard",
    __name__
)


def get_db_connection():

    # Phase 12B.6C.1 central policy (WAL, busy timeout, tracked) - same
    # connection policy as every other module; this module only ever
    # reads through it.
    return db_config.open_connection(DB_NAME)


def login_required():

    return "user_id" in session


# --------------------------------------------------
# Organizational status: 4 named states (the user's own exact wording),
# each a plain Python string constant - the one place this module's own
# Python-side vocabulary lives, so a future i18n pass has a single,
# small, named set of keys to map, rather than scattered literals.
# --------------------------------------------------
STATUS_URGENT = "urgent_security_event"
STATUS_NEEDS_REVIEW = "needs_review"
STATUS_NO_ACTIVE_THREATS = "no_active_threats"
STATUS_NO_COVERAGE = "no_monitoring_coverage"

# Alert/incident lifecycle states that count as "still open" - exactly
# the same vocabulary already enforced server-side in app.py's alert/
# incident status-transition handlers (acknowledge/close/escalate) -
# never re-derived or guessed here.
OPEN_ALERT_STATUSES = ("NEW", "ACKNOWLEDGED", "ESCALATED")
OPEN_INCIDENT_STATUSES = ("OPEN", "INVESTIGATING")

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

PERIOD_DAYS = {"today": 1, "week": 7, "month": 30}
PERIOD_LABELS = {"today": "Today", "week": "This week", "month": "This month"}

# How many days of history the trend chart covers - a real, bounded
# window, not a user-controlled/unbounded query.
TREND_WINDOW_DAYS = 14

# How many rows to show in the "computers needing inspection" /
# "non-reporting computers" / "recommended actions" lists before telling
# the user there are more (bounded display, never an unbounded table).
LIST_DISPLAY_LIMIT = 20


def _compute_organization_status(conn, monitored_total):

    # Documented, auditable rule, checked in this exact priority order -
    # every branch reads ONLY already-existing, already-tested columns.
    #
    # 1. No monitored computers at all -> we cannot make any claim about
    #    threats one way or the other. This is checked FIRST and
    #    unconditionally, specifically so "no active threats" can never
    #    be shown when there is, in fact, no visibility at all.
    if monitored_total == 0:
        return STATUS_NO_COVERAGE

    # 2. Any currently-open HIGH/CRITICAL alert, or any currently-open
    #    incident -> urgent.
    urgent_alert_count = conn.execute(f"""
        SELECT COUNT(*) FROM security_alerts
        WHERE status IN ({",".join("?" * len(OPEN_ALERT_STATUSES))})
          AND severity IN ('HIGH', 'CRITICAL')
    """, OPEN_ALERT_STATUSES).fetchone()[0]

    open_incident_count = conn.execute(f"""
        SELECT COUNT(*) FROM security_events
        WHERE status IN ({",".join("?" * len(OPEN_INCIDENT_STATUSES))})
    """, OPEN_INCIDENT_STATUSES).fetchone()[0]

    if urgent_alert_count > 0 or open_incident_count > 0:
        return STATUS_URGENT

    # 3. Any currently-open LOW/MEDIUM (or INFO, a local-IOC-match-only
    #    alert can carry INFO severity) alert -> needs review.
    review_alert_count = conn.execute(f"""
        SELECT COUNT(*) FROM security_alerts
        WHERE status IN ({",".join("?" * len(OPEN_ALERT_STATUSES))})
          AND severity NOT IN ('HIGH', 'CRITICAL')
    """, OPEN_ALERT_STATUSES).fetchone()[0]

    if review_alert_count > 0:
        return STATUS_NEEDS_REVIEW

    # 4. Nothing open at all, and real monitoring coverage exists.
    return STATUS_NO_ACTIVE_THREATS


def build_executive_summary(period="week"):

    # The single read-only aggregator this page's route calls. Returns a
    # plain dict of real counts/rows - nothing here is computed from an
    # invented formula, and nothing here writes anything.
    period = period if period in PERIOD_DAYS else "week"
    period_start = (datetime.now() - timedelta(days=PERIOD_DAYS[period])).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    try:

        # --------------------------------------------------
        # Monitored computers - the SAME source='endpoint-agent' trust
        # rule already used everywhere else in this project that counts
        # "real" monitored machines (Managed Endpoints table, Global
        # Blocklist eligibility) - never re-derived or guessed here.
        # --------------------------------------------------
        endpoint_rows = conn.execute("""
            SELECT ip_address, hostname, status, last_seen
            FROM endpoints
            WHERE source = 'endpoint-agent'
            ORDER BY hostname, ip_address
        """).fetchall()

        monitored_total = len(endpoint_rows)
        presence_counts = {"ONLINE": 0, "STALE": 0, "OFFLINE": 0, "UNKNOWN": 0}
        non_reporting_endpoints = []

        for row in endpoint_rows:
            # compute_endpoint_presence() is the SAME, already-verified
            # function already used by Web Monitoring's Managed Endpoints
            # table and the Global Blocklist preview - not a new
            # threshold invented for this page.
            presence = compute_endpoint_presence(row["last_seen"])
            presence_counts[presence] = presence_counts.get(presence, 0) + 1
            if presence != "ONLINE":
                non_reporting_endpoints.append({
                    "ip_address": row["ip_address"],
                    "hostname": row["hostname"],
                    "last_seen": row["last_seen"],
                    "presence": presence,
                })

        non_reporting_count = len(non_reporting_endpoints)

        # --------------------------------------------------
        # Open alerts, by severity - real counts only.
        # --------------------------------------------------
        open_by_severity = {sev: 0 for sev in SEVERITY_ORDER}
        severity_rows = conn.execute(f"""
            SELECT severity, COUNT(*) as n
            FROM security_alerts
            WHERE status IN ({",".join("?" * len(OPEN_ALERT_STATUSES))})
            GROUP BY severity
        """, OPEN_ALERT_STATUSES).fetchall()
        for row in severity_rows:
            if row["severity"] in open_by_severity:
                open_by_severity[row["severity"]] = row["n"]
        total_open_alerts = sum(open_by_severity.values())

        open_incident_count = conn.execute(f"""
            SELECT COUNT(*) FROM security_events
            WHERE status IN ({",".join("?" * len(OPEN_INCIDENT_STATUSES))})
        """, OPEN_INCIDENT_STATUSES).fetchone()[0]

        # --------------------------------------------------
        # New alerts discovered within the selected period.
        # --------------------------------------------------
        new_in_period = conn.execute("""
            SELECT COUNT(*) FROM security_alerts WHERE created_at >= ?
        """, (period_start,)).fetchone()[0]

        # --------------------------------------------------
        # Computers requiring inspection: distinct endpoints tied to a
        # CURRENTLY-open alert (real join on already-written data).
        # --------------------------------------------------
        computers_needing_inspection = conn.execute(f"""
            SELECT DISTINCT endpoint_ip, hostname
            FROM security_alerts
            WHERE status IN ({",".join("?" * len(OPEN_ALERT_STATUSES))})
              AND endpoint_ip IS NOT NULL
            ORDER BY endpoint_ip
            LIMIT ?
        """, OPEN_ALERT_STATUSES + (LIST_DISPLAY_LIMIT + 1,)).fetchall()

        # --------------------------------------------------
        # Recommended actions: the ALREADY-STORED recommended_response
        # text on each currently-open alert - never invented/generated
        # here, only surfaced and ordered by severity.
        # --------------------------------------------------
        recommended_actions = conn.execute(f"""
            SELECT id, alert_type, severity, status, hostname, endpoint_ip, recommended_response, created_at
            FROM security_alerts
            WHERE status IN ({",".join("?" * len(OPEN_ALERT_STATUSES))})
              AND recommended_response IS NOT NULL AND recommended_response != ''
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4
                END,
                created_at DESC
            LIMIT ?
        """, OPEN_ALERT_STATUSES + (LIST_DISPLAY_LIMIT,)).fetchall()

        # Step 23.1: attach the plain-language explanation (what
        # happened / business meaning) to each recommended action row -
        # pure presentation, built from the already-fetched columns
        # above, never a second query and never a rewrite of the stored
        # alert.
        recommended_actions = [
            dict(row, explanation=plain_language.explain_alert(row))
            for row in recommended_actions
        ]

        # --------------------------------------------------
        # Simple trend: real daily alert counts for the last
        # TREND_WINDOW_DAYS days - a bounded, server-computed series (no
        # client-side text, only numbers, for the chart).
        # --------------------------------------------------
        trend_start = (datetime.now() - timedelta(days=TREND_WINDOW_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        trend_rows = conn.execute("""
            SELECT substr(created_at, 1, 10) as day, COUNT(*) as n
            FROM security_alerts
            WHERE created_at >= ?
            GROUP BY day
        """, (trend_start,)).fetchall()
        trend_map = {row["day"]: row["n"] for row in trend_rows}
        trend_labels = []
        trend_values = []
        for i in range(TREND_WINDOW_DAYS - 1, -1, -1):
            day = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            trend_labels.append(day[5:])  # MM-DD only - locale-neutral, no month/weekday NAME baked in
            trend_values.append(trend_map.get(day, 0))

        # --------------------------------------------------
        # Weekly / monthly summary counts (real aggregates, no new
        # snapshot machinery - kept intentionally decoupled from
        # report_data.py's heavier period-report engine).
        # --------------------------------------------------
        week_start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        month_start = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

        alerts_this_week = conn.execute(
            "SELECT COUNT(*) FROM security_alerts WHERE created_at >= ?", (week_start,)
        ).fetchone()[0]
        alerts_this_month = conn.execute(
            "SELECT COUNT(*) FROM security_alerts WHERE created_at >= ?", (month_start,)
        ).fetchone()[0]
        incidents_this_week = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_time >= ?", (week_start,)
        ).fetchone()[0]
        incidents_this_month = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_time >= ?", (month_start,)
        ).fetchone()[0]

        organization_status = _compute_organization_status(conn, monitored_total)
        # Partial coverage is independent of, and always shown ALONGSIDE,
        # organization_status - it is never allowed to override it (an
        # urgent event stays urgent even if coverage is also partial),
        # and it is never hidden by an otherwise-clean status either.
        partial_coverage = monitored_total > 0 and non_reporting_count > 0

        return {
            "period": period,
            "period_label": PERIOD_LABELS[period],
            "organization_status": organization_status,
            "partial_coverage": partial_coverage,
            "monitored_total": monitored_total,
            "presence_counts": presence_counts,
            "non_reporting_count": non_reporting_count,
            "non_reporting_endpoints": non_reporting_endpoints[:LIST_DISPLAY_LIMIT],
            "non_reporting_truncated": non_reporting_count > LIST_DISPLAY_LIMIT,
            "open_by_severity": open_by_severity,
            "total_open_alerts": total_open_alerts,
            "open_incident_count": open_incident_count,
            "new_in_period": new_in_period,
            "computers_needing_inspection": computers_needing_inspection[:LIST_DISPLAY_LIMIT],
            "computers_needing_inspection_truncated": len(computers_needing_inspection) > LIST_DISPLAY_LIMIT,
            "recommended_actions": recommended_actions,
            "trend_labels": trend_labels,
            "trend_values": trend_values,
            "alerts_this_week": alerts_this_week,
            "alerts_this_month": alerts_this_month,
            "incidents_this_week": incidents_this_week,
            "incidents_this_month": incidents_this_month,
        }

    finally:
        conn.close()


@executive_dashboard_bp.route("/executive-summary")
def executive_summary():

    if not login_required():
        return redirect(url_for("login"))

    period = request.args.get("period", "week")

    data = build_executive_summary(period=period)

    return render_template("executive_dashboard.html", **data)
