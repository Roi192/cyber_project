# ==================================================
# PHASE 11E: SCHEDULED SECURITY REPORTS - SHARED DATA BUILDER
# ==================================================
#
# ONE function, build_security_report_data(), produces the complete,
# immutable snapshot dict consumed by BOTH the HTML report view and
# the PDF renderer (report_pdf.py) - they must never calculate
# anything independently (see app.py's report routes: both simply
# read the same stored security_reports.snapshot_json).
#
# This module never writes to the database - report_data.py only
# reads. The INSERT into security_reports happens in app.py, once,
# immediately after build_security_report_data() returns.
#
# All timestamps in this project are naive local wall-clock strings
# ("%Y-%m-%d %H:%M:%S", no timezone info) - confirmed by a full
# codebase audit (Phase 11E design). This module follows the exact
# same convention: TIMEZONE_BASIS below documents that fact, it does
# not change it. Every period boundary uses [start, end) - inclusive
# start, exclusive end - via plain string comparison, since the
# stored format is lexicographically sortable.
# ==================================================

import json
import os
import db_config
import sqlite3
from datetime import datetime, timedelta

from behavioral_analysis import (
    UNUSUAL_THRESHOLD,
    behavioral_label,
    compute_confidence
)
from threat_intel_providers import candidate_indicators_for_event
from investigation_priority import (
    compute_investigation_priority,
    detect_local_ioc_matched
)
from threat_intelligence import severity_from_score, score_ioc_severity


SCHEMA_VERSION = 1
TIMEZONE_BASIS = "SERVER_LOCAL_NAIVE"

SEVERITY_BANDS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

TOP_ENDPOINTS_LIMIT = 10
TOP_DESTINATIONS_LIMIT = 10
ALERTS_LIMIT = 20
INCIDENTS_LIMIT = 20
ANALYST_REVIEW_LIMIT = 20


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


def init_security_reports_db():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type TEXT NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            generated_by TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1,
            timezone_basis TEXT NOT NULL,
            snapshot_json TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_security_reports_period
        ON security_reports(report_type, period_start)
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------
# PERIOD HELPERS
# --------------------------------------------------

def to_bound_str(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _most_recent_monday(dt):
    return (dt - timedelta(days=dt.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )


def _first_of_month(dt):
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _add_months(dt, n):
    month_index = dt.month - 1 + n
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    return dt.replace(year=year, month=month)


def format_display_period(report_type, start_dt, end_dt):
    # end_dt is EXCLUSIVE - the last real day in the period is
    # end_dt minus one day, for human-readable display only. The
    # exact [start, end) values are always retained separately in
    # the snapshot (period_start/period_end).
    last_day = end_dt - timedelta(days=1)

    if report_type == "WEEKLY":
        if start_dt.month == last_day.month:
            return f"{start_dt.day}–{last_day.day} {start_dt.strftime('%B %Y')}"
        return f"{start_dt.strftime('%d %b')} – {last_day.strftime('%d %b %Y')}"

    if report_type == "MONTHLY":
        return start_dt.strftime("%B %Y")

    return f"{start_dt.strftime('%d %B %Y')} – {last_day.strftime('%d %B %Y')}"


def get_closed_weekly_periods(count=8):
    # Most recent CLOSED (fully elapsed) calendar weeks first -
    # never includes the current, still-open week.
    now = datetime.now()
    end = _most_recent_monday(now)

    periods = []

    for _ in range(count):
        start = end - timedelta(days=7)
        periods.append({
            "start": start,
            "end": end,
            "display_period": format_display_period("WEEKLY", start, end)
        })
        end = start

    return periods


def get_closed_monthly_periods(count=6):
    now = datetime.now()
    end = _first_of_month(now)

    periods = []

    for _ in range(count):
        start = _add_months(end, -1)
        periods.append({
            "start": start,
            "end": end,
            "display_period": format_display_period("MONTHLY", start, end)
        })
        end = start

    return periods


def validate_custom_period(start_date_str, end_date_str):
    # Returns (start_dt, end_dt, error). end_dt is the EXCLUSIVE
    # boundary (end_date + 1 day, midnight). Only CLOSED periods are
    # allowed - the exclusive end must not be in the future.

    now = datetime.now()

    try:
        start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
        end_date_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        return None, None, "Invalid date format. Use YYYY-MM-DD."

    if start_dt.date() > end_date_dt.date():
        return None, None, "Start date must be on or before end date."

    end_dt = end_date_dt + timedelta(days=1)

    if end_dt > now:
        return None, None, (
            "The selected period is not yet complete. Custom reports "
            "may only cover closed/completed periods."
        )

    return start_dt, end_dt, None


def _percent_change(current, previous):
    # Same safe-divide semantics as app.py's _analytics_percent_change().
    if previous == 0:
        return "New" if current > 0 else "No change"

    pct = round(((current - previous) / previous) * 100)

    if pct == 0:
        return "No change"

    sign = "+" if pct > 0 else ""
    return f"{sign}{pct}%"


# --------------------------------------------------
# MAIN BUILDER
# --------------------------------------------------

def build_security_report_data(
    report_type,
    period_start_dt,
    period_end_dt,
    generated_by,
    generated_at_dt
):

    start_bound = to_bound_str(period_start_dt)
    end_bound = to_bound_str(period_end_dt)

    period_length = period_end_dt - period_start_dt
    previous_start_dt = period_start_dt - period_length
    previous_end_dt = period_start_dt
    previous_start_bound = to_bound_str(previous_start_dt)
    previous_end_bound = to_bound_str(previous_end_dt)

    display_period = format_display_period(report_type, period_start_dt, period_end_dt)
    generated_at = to_bound_str(generated_at_dt)

    conn = get_db_connection()

    # --------------------------------------------------
    # ONE READ TRANSACTION - a coherent, single point-in-time view
    # for the entire data-collection phase. Released immediately
    # after collection; never held open during HTML/PDF rendering.
    # --------------------------------------------------
    conn.execute("BEGIN")

    try:

        snapshot = _collect_snapshot(
            conn, report_type, start_bound, end_bound,
            previous_start_bound, previous_end_bound,
            period_start_dt, period_end_dt, display_period
        )

    finally:

        conn.execute("COMMIT")
        conn.close()

    snapshot.update({
        "schema_version": SCHEMA_VERSION,
        "report_type": report_type,
        "period_start": start_bound,
        "period_end": end_bound,
        "display_period": display_period,
        "generated_at": generated_at,
        "generated_by": generated_by,
        "timezone_basis": TIMEZONE_BASIS
    })

    return snapshot


def _collect_snapshot(
    conn, report_type, start_bound, end_bound,
    previous_start_bound, previous_end_bound,
    period_start_dt, period_end_dt, display_period
):

    # ==================================================
    # CORE EVENT SET (trusted, agent-sourced, ANALYZED, in period)
    # ==================================================
    event_rows = conn.execute("""
        SELECT
            w.id, w.event_time, w.endpoint_ip, w.process_name,
            w.domain, w.resolved_ip, w.destination, w.risk_score,
            w.severity, w.decision, w.details, w.os_username,
            w.sha256, w.is_script_related, e.hostname AS endpoint_hostname
        FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
        AND w.source = 'endpoint-agent'
        AND w.analysis_status = 'ANALYZED'
        AND w.event_time >= ? AND w.event_time < ?
    """, (start_bound, end_bound)).fetchall()

    analyzed_trusted_events = len(event_rows)

    # ==================================================
    # BEHAVIORAL RESULTS FOR THESE EVENTS (own event_time column,
    # no join needed - batch, not per-event).
    # ==================================================
    # behavioral_event_results carries its OWN event_time column
    # (Phase 11C), so this is queried by the same period bound
    # directly - never via a per-event IN(...) list, which would
    # both be slower and risk exceeding SQLite's default bound
    # SQL-variable limit at real event volumes (tens of thousands
    # of ids per period).
    behavioral_by_event_id = {
        row["web_event_id"]: dict(row)
        for row in conn.execute("""
            SELECT web_event_id, evaluation_status, anomaly_score, confidence
            FROM behavioral_event_results
            WHERE event_time >= ? AND event_time < ?
        """, (start_bound, end_bound)).fetchall()
    }

    # ==================================================
    # THREATFOX EVIDENCE - full current table read ONCE, then
    # looked up per event in Python (batch pattern, no N+1 queries -
    # same pattern proven in Phase 11D.1 Security Analytics).
    # ==================================================
    threatfox_lookup = {}

    for row in conn.execute(
        "SELECT * FROM threat_intel_evidence WHERE provider = 'threatfox'"
    ).fetchall():
        threatfox_lookup[(row["indicator_type"], row["indicator_value"])] = dict(row)

    def threatfox_evidence_for(resolved_ip, domain, sha256):
        candidates = candidate_indicators_for_event(resolved_ip, domain, sha256)
        return [threatfox_lookup[c] for c in candidates if c in threatfox_lookup]

    # ==================================================
    # PER-EVENT: behavioral label/confidence, local IOC, ThreatFox
    # evidence, Investigation Priority - computed ONCE here, at
    # generation time, using only what is verifiably frozen
    # (Threat Risk, Behavioral result, details text) or explicitly
    # labeled as generation-time-only (ThreatFox).
    # ==================================================
    priority_distribution = {"ROUTINE": 0, "REVIEW": 0, "ELEVATED": 0, "URGENT": 0}
    evaluation_status_distribution = {"TYPICAL": 0, "UNUSUAL": 0, "LEARNING": 0, "NOT_SCORED": 0}
    review_candidates = []

    endpoint_stats = {}
    destination_stats = {}

    threatfox_correlation = {"MATCH": 0, "NO_MATCH": 0, "ERROR": 0, "RATE_LIMITED": 0, "NOT_QUERIED": 0}

    for row in event_rows:

        behavioral_row = behavioral_by_event_id.get(row["id"])

        b_label = None
        b_confidence = None

        if behavioral_row:
            b_label = behavioral_label(behavioral_row["evaluation_status"], behavioral_row["anomaly_score"])
            b_confidence = behavioral_row["confidence"]

            if b_label == "TYPICAL":
                evaluation_status_distribution["TYPICAL"] += 1
            elif b_label == "UNUSUAL":
                evaluation_status_distribution["UNUSUAL"] += 1
            elif b_label == "LEARNING":
                evaluation_status_distribution["LEARNING"] += 1
            else:
                evaluation_status_distribution["NOT_SCORED"] += 1
        else:
            evaluation_status_distribution["NOT_SCORED"] += 1

        local_ioc_matched = detect_local_ioc_matched(row["details"])

        tf_evidence = threatfox_evidence_for(row["resolved_ip"], row["domain"], row["sha256"])

        if tf_evidence:
            for ev in tf_evidence:
                status = ev.get("lookup_status", "ERROR")
                threatfox_correlation[status] = threatfox_correlation.get(status, 0) + 1
        else:
            candidates = candidate_indicators_for_event(row["resolved_ip"], row["domain"], row["sha256"])
            if not candidates:
                threatfox_correlation["NOT_QUERIED"] += 1
            else:
                threatfox_correlation["NOT_QUERIED"] += len(candidates)

        priority_level, priority_reasons = compute_investigation_priority(
            row["severity"], b_label, b_confidence, local_ioc_matched, tf_evidence
        )

        priority_distribution[priority_level] += 1

        endpoint_ip = row["endpoint_ip"]
        endpoint_entry = endpoint_stats.setdefault(endpoint_ip, {
            "endpoint_ip": endpoint_ip,
            "hostname": row["endpoint_hostname"],
            "analyzed_events": 0,
            "risky_events": 0,
            "highest_observed_event_risk": 0,
            "unusual_events": 0
        })
        endpoint_entry["analyzed_events"] += 1
        if row["risk_score"] and row["risk_score"] > 0:
            endpoint_entry["risky_events"] += 1
        endpoint_entry["highest_observed_event_risk"] = max(
            endpoint_entry["highest_observed_event_risk"], row["risk_score"] or 0
        )
        if b_label == "UNUSUAL":
            endpoint_entry["unusual_events"] += 1

        destination_key = row["domain"] or row["resolved_ip"] or row["destination"]

        if row["risk_score"] and row["risk_score"] > 0 and destination_key:
            dest_entry = destination_stats.setdefault(destination_key, {
                "destination": destination_key,
                "observed_events": 0,
                "highest_observed_event_risk": 0,
                "endpoints": set(),
                "threatfox_match": False
            })
            dest_entry["observed_events"] += 1
            dest_entry["highest_observed_event_risk"] = max(
                dest_entry["highest_observed_event_risk"], row["risk_score"]
            )
            dest_entry["endpoints"].add(endpoint_ip)
            if any(e.get("lookup_status") == "MATCH" for e in tf_evidence):
                dest_entry["threatfox_match"] = True

        if priority_level in ("REVIEW", "ELEVATED", "URGENT"):
            review_candidates.append({
                "kind": "EVENT_PRIORITY",
                "priority": priority_level,
                "timestamp": row["event_time"],
                "reference": f"web_events#{row['id']}",
                "summary": (
                    f"Endpoint {row['endpoint_hostname'] or endpoint_ip} - "
                    f"{row['process_name'] or 'unknown process'} - "
                    f"{destination_key or 'unknown destination'}"
                ),
                "reasons": priority_reasons
            })

    # ==================================================
    # ALERTS COUNTING PER ENDPOINT (for Top Endpoints table)
    # ==================================================
    alert_counts_by_endpoint = {
        row["endpoint_ip"]: row["c"]
        for row in conn.execute("""
            SELECT endpoint_ip, COUNT(*) c FROM security_alerts
            WHERE created_at >= ? AND created_at < ?
            GROUP BY endpoint_ip
        """, (start_bound, end_bound)).fetchall()
    }
    for ip, entry in endpoint_stats.items():
        entry["alerts"] = alert_counts_by_endpoint.get(ip, 0)

    # ==================================================
    # THREAT RISK OVERVIEW
    # ==================================================
    events_with_risk_gt_0 = sum(1 for r in event_rows if (r["risk_score"] or 0) > 0)
    highest_observed_event_risk = max((r["risk_score"] or 0 for r in event_rows), default=0)
    highest_observed_event_severity = severity_from_score(highest_observed_event_risk)

    severity_distribution = {band: 0 for band in SEVERITY_BANDS}
    for r in event_rows:
        if r["severity"] in severity_distribution:
            severity_distribution[r["severity"]] += 1

    events_with_local_ioc_evidence = sum(
        1 for r in event_rows if detect_local_ioc_matched(r["details"])
    )

    distinct_risky_destinations = len({
        (r["domain"] or r["resolved_ip"] or r["destination"])
        for r in event_rows if (r["risk_score"] or 0) > 0
    })

    threat_risk = {
        "analyzed_events": analyzed_trusted_events,
        "events_with_risk_gt_0": events_with_risk_gt_0,
        "highest_observed_event_risk": highest_observed_event_risk,
        "highest_observed_event_severity": highest_observed_event_severity,
        "severity_distribution": severity_distribution,
        "events_with_local_ioc_evidence": events_with_local_ioc_evidence,
        "distinct_risky_destinations": distinct_risky_destinations
    }

    # ==================================================
    # BEHAVIORAL ANALYTICS
    # ==================================================
    behaviorally_unusual_events = evaluation_status_distribution["UNUSUAL"]
    endpoints_with_unusual_activity = sum(
        1 for e in endpoint_stats.values() if e["unusual_events"] > 0
    )
    behavioral_evaluation_coverage_pct = (
        round(100 * (analyzed_trusted_events - evaluation_status_distribution["NOT_SCORED"]) / analyzed_trusted_events, 1)
        if analyzed_trusted_events else 0.0
    )

    baseline_rows = conn.execute("""
        SELECT s.endpoint_ip, e.hostname, s.maturity_state, s.active_days, s.analyzed_event_count
        FROM behavioral_baseline_state s
        JOIN endpoints e ON s.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent'
    """).fetchall()

    baseline_maturity_as_of_generation = [
        {
            "endpoint_ip": r["endpoint_ip"],
            "hostname": r["hostname"],
            "maturity_state": r["maturity_state"],
            "confidence": compute_confidence(r["maturity_state"], r["active_days"] or 0, r["analyzed_event_count"] or 0) or "N/A"
        }
        for r in baseline_rows
    ]

    baseline_inventory = {
        "distinct_processes_in_baseline": conn.execute(
            "SELECT COUNT(*) c FROM behavioral_seen_processes"
        ).fetchone()["c"],
        "distinct_destinations_in_baseline": conn.execute(
            "SELECT COUNT(*) c FROM behavioral_seen_destinations"
        ).fetchone()["c"],
        "distinct_process_destination_in_baseline": conn.execute(
            "SELECT COUNT(*) c FROM behavioral_seen_process_destination"
        ).fetchone()["c"]
    }

    behavioral = {
        "behaviorally_unusual_events": behaviorally_unusual_events,
        "endpoints_with_unusual_activity": endpoints_with_unusual_activity,
        "behavioral_evaluation_coverage_pct": behavioral_evaluation_coverage_pct,
        "evaluation_status_distribution": evaluation_status_distribution,
        "baseline_maturity_as_of_generation": baseline_maturity_as_of_generation,
        "baseline_inventory_as_of_generation": baseline_inventory
    }

    # ==================================================
    # THREAT INTELLIGENCE
    # ==================================================
    indicators_enriched_during_period = conn.execute("""
        SELECT COUNT(DISTINCT indicator_type || '|' || indicator_value) c
        FROM threat_intel_evidence
        WHERE provider = 'threatfox'
        AND retrieved_at >= ? AND retrieved_at < ?
    """, (start_bound, end_bound)).fetchone()["c"]

    threat_intelligence = {
        "event_correlation": threatfox_correlation,
        "indicators_enriched_during_period": indicators_enriched_during_period,
        "disclosure": (
            "Threat Intelligence evidence reflects the state stored by the "
            "system at report generation time and may not represent the "
            "provider state at the original event time."
        )
    }

    # ==================================================
    # ALERTS & INCIDENTS
    # ==================================================
    alert_rows = conn.execute("""
        SELECT * FROM security_alerts
        WHERE created_at >= ? AND created_at < ?
        ORDER BY created_at DESC
    """, (start_bound, end_bound)).fetchall()

    alerts_total = len(alert_rows)

    alert_severity_dist = {band: 0 for band in SEVERITY_BANDS}
    alert_status_dist = {}
    alert_type_dist = {}

    for r in alert_rows:
        if r["severity"] in alert_severity_dist:
            alert_severity_dist[r["severity"]] += 1
        alert_status_dist[r["status"]] = alert_status_dist.get(r["status"], 0) + 1
        alert_type_dist[r["alert_type"]] = alert_type_dist.get(r["alert_type"], 0) + 1

    alerts_bounded = [dict(r) for r in alert_rows[:ALERTS_LIMIT]]
    alerts_truncated_count = max(0, alerts_total - ALERTS_LIMIT)

    incident_rows = conn.execute("""
        SELECT * FROM security_events
        WHERE event_time >= ? AND event_time < ?
        ORDER BY event_time DESC
    """, (start_bound, end_bound)).fetchall()

    incidents_total = len(incident_rows)
    incident_status_dist = {}
    for r in incident_rows:
        status = r["status"] if "status" in r.keys() else "UNKNOWN"
        incident_status_dist[status] = incident_status_dist.get(status, 0) + 1

    incidents_bounded = [dict(r) for r in incident_rows[:INCIDENTS_LIMIT]]
    incidents_truncated_count = max(0, incidents_total - INCIDENTS_LIMIT)

    alerts_incidents = {
        "alerts_total": alerts_total,
        "alert_severity_distribution": alert_severity_dist,
        "alert_status_distribution": alert_status_dist,
        "alert_type_distribution": alert_type_dist,
        "alerts": alerts_bounded,
        "alerts_truncated_count": alerts_truncated_count,
        "incidents_total": incidents_total,
        "incident_status_distribution": incident_status_dist,
        "incidents": incidents_bounded,
        "incidents_truncated_count": incidents_truncated_count
    }

    # ==================================================
    # ITEMS FOR ANALYST REVIEW (dedup + bounded + supplemented by
    # unresolved alerts/incidents/failed responses/ThreatFox matches
    # not already surfaced via event priority)
    # ==================================================
    rank = {"URGENT": 0, "ELEVATED": 1, "REVIEW": 2}

    review_items = list(review_candidates)

    for r in alert_rows:
        if r["severity"] in ("HIGH", "CRITICAL") and r["status"] not in ("CLOSED",):
            review_items.append({
                "kind": "UNRESOLVED_ALERT",
                "priority": "URGENT" if r["severity"] == "CRITICAL" else "ELEVATED",
                "timestamp": r["created_at"],
                "reference": f"security_alerts#{r['id']}",
                "summary": f"Unresolved {r['severity']} Alert: {r['title']}",
                "reasons": [f"Alert status: {r['status']}"]
            })

    for r in incident_rows:
        status = r["status"] if "status" in r.keys() else None
        if status in ("OPEN", "INVESTIGATING"):
            review_items.append({
                "kind": "OPEN_INCIDENT",
                "priority": "URGENT",
                "timestamp": r["event_time"],
                "reference": f"security_events#{r['id']}",
                "summary": f"Open Incident: {r['event_type']}",
                "reasons": [f"Incident status: {status}"]
            })

    failed_responses = conn.execute("""
        SELECT * FROM response_commands
        WHERE created_at >= ? AND created_at < ?
        AND status = 'FAILED'
        ORDER BY created_at DESC
    """, (start_bound, end_bound)).fetchall()

    for r in failed_responses:
        review_items.append({
            "kind": "FAILED_RESPONSE",
            "priority": "REVIEW",
            "timestamp": r["created_at"],
            "reference": f"response_commands#{r['id']}",
            "summary": f"Failed response action: {r['command_type']} on {r['endpoint_ip']}",
            "reasons": [r["result_message"] or "No result message recorded."]
        })

    # Deduplicate by (kind, reference); merge reasons for exact dups.
    deduped = {}
    for item in review_items:
        key = (item["kind"], item["reference"])
        if key in deduped:
            deduped[key]["reasons"] = list(dict.fromkeys(deduped[key]["reasons"] + item["reasons"]))
        else:
            deduped[key] = item

    ordered_review_items = sorted(
        deduped.values(),
        key=lambda it: (rank.get(it["priority"], 3), it["timestamp"]),
        reverse=False
    )
    # Within a priority tier, newest first: sort ascending by rank,
    # then descending by timestamp - do it in two passes for clarity.
    ordered_review_items.sort(key=lambda it: it["timestamp"], reverse=True)
    ordered_review_items.sort(key=lambda it: rank.get(it["priority"], 3))

    analyst_review_truncated_count = max(0, len(ordered_review_items) - ANALYST_REVIEW_LIMIT)
    analyst_review_items = ordered_review_items[:ANALYST_REVIEW_LIMIT]

    # ==================================================
    # RESPONSE ACTIONS
    # ==================================================
    response_rows = conn.execute("""
        SELECT * FROM response_commands
        WHERE created_at >= ? AND created_at < ?
    """, (start_bound, end_bound)).fetchall()

    response_total = len(response_rows)
    response_by_type = {}
    response_by_status = {}
    response_by_mode = {}

    for r in response_rows:
        response_by_type[r["command_type"]] = response_by_type.get(r["command_type"], 0) + 1
        response_by_status[r["status"]] = response_by_status.get(r["status"], 0) + 1
        if r["mode"]:
            response_by_mode[r["mode"]] = response_by_mode.get(r["mode"], 0) + 1

    response_actions = {
        "total": response_total,
        "by_command_type": response_by_type,
        "by_status": response_by_status,
        "by_mode": response_by_mode
    }

    # ==================================================
    # TOP ENDPOINTS / TOP DESTINATIONS
    # ==================================================
    top_endpoints = sorted(
        endpoint_stats.values(),
        key=lambda e: (e["highest_observed_event_risk"], e["risky_events"]),
        reverse=True
    )[:TOP_ENDPOINTS_LIMIT]
    for e in top_endpoints:
        e["highest_observed_event_severity"] = severity_from_score(e["highest_observed_event_risk"])

    top_destinations_raw = sorted(
        destination_stats.values(),
        key=lambda d: (d["highest_observed_event_risk"], d["observed_events"]),
        reverse=True
    )[:TOP_DESTINATIONS_LIMIT]

    top_destinations = []
    for d in top_destinations_raw:
        top_destinations.append({
            "destination": d["destination"],
            "observed_events": d["observed_events"],
            "highest_observed_event_risk": d["highest_observed_event_risk"],
            "highest_observed_event_severity": severity_from_score(d["highest_observed_event_risk"]),
            "endpoints_observed": len(d["endpoints"]),
            "threatfox_match": d["threatfox_match"]
        })

    # ==================================================
    # PERIOD-OVER-PERIOD COMPARISON
    # ==================================================
    previous_analyzed_events = conn.execute("""
        SELECT COUNT(*) c FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent' AND w.source = 'endpoint-agent'
        AND w.analysis_status = 'ANALYZED'
        AND w.event_time >= ? AND w.event_time < ?
    """, (previous_start_bound, previous_end_bound)).fetchone()["c"]

    previous_risky_events = conn.execute("""
        SELECT COUNT(*) c FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        WHERE e.source = 'endpoint-agent' AND w.source = 'endpoint-agent'
        AND w.analysis_status = 'ANALYZED' AND w.risk_score > 0
        AND w.event_time >= ? AND w.event_time < ?
    """, (previous_start_bound, previous_end_bound)).fetchone()["c"]

    previous_alerts = conn.execute("""
        SELECT COUNT(*) c FROM security_alerts
        WHERE created_at >= ? AND created_at < ?
    """, (previous_start_bound, previous_end_bound)).fetchone()["c"]

    previous_incidents = conn.execute("""
        SELECT COUNT(*) c FROM security_events
        WHERE event_time >= ? AND event_time < ?
    """, (previous_start_bound, previous_end_bound)).fetchone()["c"]

    previous_unusual = conn.execute("""
        SELECT COUNT(*) c FROM behavioral_event_results
        WHERE evaluation_status = 'SCORED' AND anomaly_score >= ?
        AND event_time >= ? AND event_time < ?
    """, (UNUSUAL_THRESHOLD, previous_start_bound, previous_end_bound)).fetchone()["c"]

    previous_response = conn.execute("""
        SELECT COUNT(*) c FROM response_commands
        WHERE created_at >= ? AND created_at < ?
    """, (previous_start_bound, previous_end_bound)).fetchone()["c"]

    bootstrap_cutoff_row = conn.execute("""
        SELECT config_value FROM behavioral_engine_config WHERE config_key = 'bootstrap_cutoff'
    """).fetchone()
    bootstrap_cutoff = bootstrap_cutoff_row["config_value"] if bootstrap_cutoff_row else None

    behavioral_limited_comparability = bool(
        bootstrap_cutoff and previous_end_bound <= bootstrap_cutoff
    )

    def comparison_entry(current, previous, limited=False):
        return {
            "current": current,
            "previous": previous,
            "absolute_change": current - previous,
            "change_label": "LIMITED COMPARABILITY" if limited else _percent_change(current, previous)
        }

    period_comparison = {
        "analyzed_events": comparison_entry(analyzed_trusted_events, previous_analyzed_events),
        "risky_events": comparison_entry(events_with_risk_gt_0, previous_risky_events),
        "security_alerts": comparison_entry(alerts_total, previous_alerts),
        "incidents": comparison_entry(incidents_total, previous_incidents),
        "behaviorally_unusual_events": comparison_entry(
            behaviorally_unusual_events, previous_unusual, limited=behavioral_limited_comparability
        ),
        "response_actions": comparison_entry(response_total, previous_response)
    }

    # ==================================================
    # COVERAGE
    # ==================================================
    active_observation_days = len({
        r["event_time"][:10] for r in event_rows
    })

    os_user_covered = sum(1 for r in event_rows if r["os_username"])
    sha256_covered = sum(1 for r in event_rows if r["sha256"])

    coverage = {
        "trusted_endpoint_identities_observed": len(endpoint_stats),
        "analyzed_trusted_events": analyzed_trusted_events,
        "active_observation_days": active_observation_days,
        "behavioral_evaluation_coverage_pct": behavioral_evaluation_coverage_pct,
        "os_user_telemetry_coverage_pct": (
            round(100 * os_user_covered / analyzed_trusted_events, 1) if analyzed_trusted_events else 0.0
        ),
        "sha256_telemetry_coverage_pct": (
            round(100 * sha256_covered / analyzed_trusted_events, 1) if analyzed_trusted_events else 0.0
        ),
        "baseline_maturity_as_of_generation": baseline_maturity_as_of_generation,
        "identity_caveat": (
            "Endpoint identity is currently based on observed IP address. "
            "Distinct endpoint identities do not necessarily represent "
            "distinct physical computers."
        )
    }

    # ==================================================
    # EXECUTIVE SUMMARY (deterministic, rule-based)
    # ==================================================
    summary_sentences = [
        f"During the selected period ({display_period}), "
        f"{coverage['trusted_endpoint_identities_observed']} trusted endpoint "
        f"identit{'y' if coverage['trusted_endpoint_identities_observed'] == 1 else 'ies'} "
        f"generated {analyzed_trusted_events} analyzed event"
        f"{'s' if analyzed_trusted_events != 1 else ''}.",

        f"{alerts_total} Security Alert{'s' if alerts_total != 1 else ''} and "
        f"{incidents_total} Security Incident{'s' if incidents_total != 1 else ''} "
        f"were recorded.",

        (
            f"The highest observed event risk was {highest_observed_event_risk}/100 "
            f"({highest_observed_event_severity})."
            if analyzed_trusted_events else
            "No trusted endpoint telemetry was analyzed during this period."
        ),

        f"{behaviorally_unusual_events} event"
        f"{'s were' if behaviorally_unusual_events != 1 else ' was'} "
        f"flagged as behaviorally unusual.",

        f"{response_total} response action{'s were' if response_total != 1 else ' was'} recorded."
    ]

    executive_summary = {
        "label": "Rule-based summary — not AI-generated.",
        "sentences": summary_sentences
    }

    # ==================================================
    # SCOPE & LIMITATIONS
    # ==================================================
    scope_and_limitations = [
        "Visibility is limited to telemetry collected by connected endpoint agents and explicitly ingested events.",
        "This is not full packet capture.",
        "This is not a complete network-wide SIEM.",
        "Endpoint identity is primarily IP-based.",
        "HTTPS visibility generally provides domain/IP context, not full URL paths.",
        "Behavioral conclusions depend on baseline maturity/history.",
        "Threat Intelligence depends on external provider coverage and availability.",
        "A ThreatFox NO_MATCH result is not proof of safety.",
        "Absence of Alerts does not prove absence of compromise.",
        "Timestamps use SERVER_LOCAL_NAIVE semantics in the current prototype."
    ]

    return {
        "report_information": {
            "trusted_endpoints_observed": coverage["trusted_endpoint_identities_observed"],
            "events_analyzed": analyzed_trusted_events
        },
        "executive_summary": executive_summary,
        "coverage": coverage,
        "threat_risk": threat_risk,
        "behavioral": behavioral,
        "threat_intelligence": threat_intelligence,
        "alerts_incidents": alerts_incidents,
        "investigation_priority": {
            "priority_distribution": priority_distribution,
            "disclosure": (
                "Investigation Priority is a generation-time snapshot. Threat "
                "Intelligence evidence may change after this report is generated."
            )
        },
        "response_actions": response_actions,
        "top_endpoints": top_endpoints,
        "top_destinations": top_destinations,
        "destination_caveat": (
            "Shared CDN/cloud edge infrastructure may serve multiple unrelated "
            "sites/services; an IP-only observation does not uniquely attribute "
            "traffic to one site."
        ),
        "period_comparison": period_comparison,
        "analyst_review_items": analyst_review_items,
        "analyst_review_truncated_count": analyst_review_truncated_count,
        "analyst_review_label": (
            "Queue of stored evidence for analyst attention — not an "
            "AI-ranked recommendation."
        ),
        "scope_and_limitations": scope_and_limitations
    }
