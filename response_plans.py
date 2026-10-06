# ==================================================
# STAGE 25G PHASE 2: DECISION ADAPTER + DURABLE RESPONSE PLANS
# ==================================================
#
#   Unified Stage-25F decision (security_alerts row + its rule-level
#   detections/evidence) -> build_policy_input() [read-only adapter]
#   -> response_policy.evaluate_policy() [pure] -> response_plans rows
#
# PHASE 2 INVARIANTS:
#   * creates ZERO response_commands - no dispatch exists here at all
#     (there is no code path from a plan to the command-creation
#     boundary in web_monitoring.py);
#   * AUTO_EXECUTE on a persisted plan means "policy says eligible",
#     never "executed";
#   * identity is never inferred: conflicting linked evidence resolves
#     to the conservative tier (UNAVAILABLE / no uid), exactly as the
#     Stage 25F correlation design requires;
#   * NOT WIRED into the live worker/app - generation is called only by
#     tests in Phase 2.
# ==================================================

import json
from datetime import datetime, timedelta

import detection_engine
import response_policy
from endpoint_identity import normalize_endpoint_uid
from web_monitoring import SHA256_PATTERN, ACTIVE_COMMAND_STATUSES, get_db_connection

STATUS_PROPOSED = "PROPOSED"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"
# Designed for future dispatch, deliberately unused in Phase 2.
STATUS_DISPATCHED = "DISPATCHED"
STATUS_FAILED = "FAILED"

ALLOWED_TRANSITIONS = {
    STATUS_PROPOSED: {STATUS_APPROVED, STATUS_REJECTED, STATUS_EXPIRED},
    STATUS_APPROVED: {STATUS_EXPIRED},
    STATUS_REJECTED: set(),
    STATUS_EXPIRED: set(),
}

# A plan's own absolute lifetime - reuses the existing 24h "decision
# has gone quiet" horizon (detection_engine.DETECTION_RESOLVE_AFTER_
# HOURS) rather than inventing a new number.
PLAN_TTL_HOURS = detection_engine.DETECTION_RESOLVE_AFTER_HOURS
# A plan is dispatchable only while its decision is still ACTIVE -
# the same 30-minute window Stage 25F uses for reuse/reopen.
ACTIVE_DECISION_WINDOW_MINUTES = detection_engine.DETECTION_DEDUP_WINDOW_MINUTES

_TS = "%Y-%m-%d %H:%M:%S"


# --------------------------------------------------
# SCHEMA (additive, guarded - project convention)
# --------------------------------------------------
def init_response_plans_db(conn=None):
    own = conn is None
    conn = conn or get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS response_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL UNIQUE,
                security_alert_id INTEGER NOT NULL,
                correlation_key TEXT,
                incident_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target TEXT,
                policy_outcome TEXT NOT NULL,
                baseline_outcome TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PROPOSED',
                reason_text TEXT NOT NULL,
                prerequisites_json TEXT NOT NULL,
                guards_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                reversible INTEGER NOT NULL,
                reverse_action TEXT,
                approval_required INTEGER NOT NULL,
                policy_version TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_by TEXT,
                decided_at TEXT,
                decision_note TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_response_plans_alert ON response_plans(security_alert_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_response_plans_status ON response_plans(status, expires_at)")
        conn.commit()
    finally:
        if own:
            conn.close()


# --------------------------------------------------
# DECISION ADAPTER (read-only; conservative on conflict)
# --------------------------------------------------
def build_policy_input(security_alert_id, conn=None):
    """
    Derives the response_policy input from EXISTING rows only. Returns
    None if the alert does not exist. Never infers identity:
      * endpoint_uid: taken only if every linked detection agrees;
      * process identity: CONFIRMED only if every linked web_event is
        CONFIRMED on the SAME process_instance_id (and that process row
        exists); any browser-extension source makes it NOT_APPLICABLE;
        anything else -> UNAVAILABLE;
      * file identity: sha256/path only from the confirmed process row.
    """
    own = conn is None
    conn = conn or get_db_connection()
    try:
        alert = conn.execute("SELECT * FROM security_alerts WHERE id = ?", (security_alert_id,)).fetchone()
        if alert is None:
            return None

        detections = conn.execute(
            "SELECT * FROM detections WHERE security_alert_id = ? ORDER BY id", (security_alert_id,)
        ).fetchall()
        det_ids = [d["id"] for d in detections]

        evidence_sources = []
        if det_ids:
            marks = ",".join("?" for _ in det_ids)
            evidence_sources = [r["evidence_source"] for r in conn.execute(
                f"SELECT DISTINCT evidence_source FROM detection_evidence WHERE detection_id IN ({marks})", det_ids
            ).fetchall()]

        confidences = [d["confidence"] for d in detections if d["confidence"] is not None]
        min_confidence = min(confidences) if confidences else None

        uids = {normalize_endpoint_uid(d["endpoint_uid"]) for d in detections}
        endpoint_uid = uids.pop() if len(uids) == 1 and None not in uids else None

        web_event_ids = sorted({d["web_event_id"] for d in detections if d["web_event_id"] is not None})
        web_events = []
        if web_event_ids:
            marks = ",".join("?" for _ in web_event_ids)
            web_events = conn.execute(f"SELECT * FROM web_events WHERE id IN ({marks})", web_event_ids).fetchall()

        sources = {w["source"] for w in web_events}
        event_source = "browser-extension" if "browser-extension" in sources else (sources.pop() if len(sources) == 1 else "endpoint-agent")

        process_status = "UNAVAILABLE"
        process_instance_id = None
        pids = {w["process_instance_id"] for w in web_events}
        statuses = {w["process_correlation_status"] for w in web_events}
        if (
            event_source != "browser-extension"
            and web_events
            and statuses == {"CONFIRMED"}
            and len(pids) == 1
            and next(iter(pids))
        ):
            candidate = next(iter(pids))
            if conn.execute("SELECT 1 FROM endpoint_process_events WHERE process_instance_id = ?", (candidate,)).fetchone():
                process_status, process_instance_id = "CONFIRMED", candidate
            # CONFIRMED web_event but no process row -> UNAVAILABLE (fail closed)
        elif web_events and statuses == {"PENDING"}:
            process_status = "PENDING"

        process_name = process_path = sha256 = None
        if process_instance_id:
            proc = conn.execute(
                "SELECT process_name, process_path, sha256 FROM endpoint_process_events WHERE process_instance_id = ?",
                (process_instance_id,)
            ).fetchone()
            process_name, process_path = proc["process_name"], proc["process_path"]
            sha = (proc["sha256"] or "").lower()
            sha256 = sha if SHA256_PATTERN.match(sha) else None
        elif alert["process_name"]:
            process_name = alert["process_name"]  # display only - never authorizes a process action

        marks = ",".join("?" for _ in ACTIVE_COMMAND_STATUSES)
        active = conn.execute(
            f"SELECT command_type, target FROM response_commands WHERE endpoint_ip = ? AND status IN ({marks})",
            (alert["endpoint_ip"], *ACTIVE_COMMAND_STATUSES)
        ).fetchall()

        return {
            "security_alert_id": alert["id"],
            "alert_status": alert["status"],
            "alert_updated_at": alert["updated_at"] or alert["created_at"],
            "correlation_key": alert["correlation_key"],
            "incident_id": alert["incident_id"],
            "severity": alert["severity"],
            "risk_score": alert["risk_score"],
            "endpoint_uid": endpoint_uid,
            "endpoint_ip": alert["endpoint_ip"],
            "hostname": alert["hostname"],
            "contributing_rules": [d["rule_id"] for d in detections],
            "contributing_categories": sorted({d["category"] for d in detections}),
            "detection_ids": det_ids,
            "evidence_sources": sorted(set(evidence_sources)),
            "min_confidence": min_confidence,
            "process_correlation_status": process_status,
            "process_instance_id": process_instance_id,
            "process_name": process_name,
            "process_path": process_path,
            "sha256": sha256,
            "domain": alert["domain"],
            "resolved_ip": alert["destination_ip"],
            "event_source": event_source,
            "previous_response_state": {"active_commands": [dict(r) for r in active]},
        }
    finally:
        if own:
            conn.close()


# --------------------------------------------------
# PLAN GENERATION (idempotent upsert, one evaluation per alert)
# --------------------------------------------------
def _should_persist(plan):
    # Meaningful = a non-NO_ACTION outcome, OR a destructive action a
    # guard explicitly prevented (audit reason: "which guard stopped
    # stronger action"). A plain LOW-baseline NO_ACTION is not stored.
    if plan["policy_outcome"] != response_policy.NO_ACTION:
        return True
    return plan["destructive"] and any(g["from"] != g["to"] for g in plan["guards_applied"])


def generate_plans_for_alert(security_alert_id, conn=None, now=None, protection_policy=None):
    """Returns {"created": [...ids], "updated": [...ids], "skipped": n, "policy_input": {...}}.
    Never creates a response_commands row."""
    own = conn is None
    conn = conn or get_db_connection()
    now = now or datetime.now()
    try:
        policy_input = build_policy_input(security_alert_id, conn)
        if policy_input is None:
            return {"created": [], "updated": [], "skipped": 0, "policy_input": None}

        result = response_policy.evaluate_policy(policy_input, protection_policy)
        created, updated, skipped = [], [], 0
        now_s = now.strftime(_TS)
        expires = (now + timedelta(hours=PLAN_TTL_HOURS)).strftime(_TS)

        for plan in result["plans"]:
            if not _should_persist(plan):
                skipped += 1
                continue
            explanation = response_policy.explain_plan(plan)
            reason_text = " | ".join(plan["reasons"] + [g["reason"] for g in plan["guards_applied"] if g["from"] != g["to"]])
            existing = conn.execute("SELECT id FROM response_plans WHERE idempotency_key = ?", (plan["idempotency_key"],)).fetchone()
            if existing:
                conn.execute("""
                    UPDATE response_plans SET policy_outcome=?, baseline_outcome=?, reason_text=?, prerequisites_json=?,
                        guards_json=?, evidence_json=?, approval_required=?, updated_at=?
                    WHERE id=?
                """, (plan["policy_outcome"], plan["baseline_outcome"], reason_text, json.dumps(plan["prerequisites"]),
                      json.dumps(plan["guards_applied"]), json.dumps(explanation["evidence"]),
                      int(plan["approval_required"]), now_s, existing["id"]))
                updated.append(existing["id"])
            else:
                cur = conn.execute("""
                    INSERT INTO response_plans (idempotency_key, security_alert_id, correlation_key, incident_id, action,
                        target_type, target, policy_outcome, baseline_outcome, status, reason_text, prerequisites_json,
                        guards_json, evidence_json, reversible, reverse_action, approval_required, policy_version,
                        created_at, updated_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (plan["idempotency_key"], security_alert_id, plan["correlation_key"], plan["incident_id"],
                      plan["proposed_action"], plan["target_type"], plan["target"], plan["policy_outcome"],
                      plan["baseline_outcome"], reason_text, json.dumps(plan["prerequisites"]),
                      json.dumps(plan["guards_applied"]), json.dumps(explanation["evidence"]), int(plan["reversible"]),
                      plan["reverse_action"], int(plan["approval_required"]), plan["policy_version"], now_s, now_s, expires))
                created.append(cur.lastrowid)
        conn.commit()
        return {"created": created, "updated": updated, "skipped": skipped, "policy_input": policy_input}
    finally:
        if own:
            conn.close()


# --------------------------------------------------
# LIFECYCLE (persistence only - no dispatch exists in Phase 2)
# --------------------------------------------------
def transition_plan(plan_id, new_status, actor, note=None, conn=None, now=None):
    own = conn is None
    conn = conn or get_db_connection()
    now = now or datetime.now()
    try:
        row = conn.execute("SELECT * FROM response_plans WHERE id = ?", (plan_id,)).fetchone()
        if row is None:
            raise ValueError(f"response_plan {plan_id} does not exist")
        if new_status not in ALLOWED_TRANSITIONS.get(row["status"], set()):
            raise ValueError(f"invalid transition {row['status']} -> {new_status} for plan {plan_id}")
        if not actor:
            raise ValueError("actor is required for an audited transition")
        conn.execute("""
            UPDATE response_plans SET status=?, decided_by=?, decided_at=?, decision_note=?, updated_at=? WHERE id=?
        """, (new_status, actor, now.strftime(_TS), note, now.strftime(_TS), plan_id))
        conn.commit()
        return conn.execute("SELECT * FROM response_plans WHERE id = ?", (plan_id,)).fetchone()
    finally:
        if own:
            conn.close()


def is_plan_dispatchable(plan_id, conn=None, now=None):
    """
    Predicate only (no dispatch exists in Phase 2). Returns (bool,
    reasons). True requires: APPROVED, or PROPOSED with AUTO_EXECUTE
    eligibility; not past expires_at; its alert still exists, is not
    CLOSED, and its decision is still ACTIVE (updated within the
    Stage-25F window). An approval never carries over to a different
    decision occurrence because the plan is bound to one alert id.
    """
    own = conn is None
    conn = conn or get_db_connection()
    now = now or datetime.now()
    try:
        plan = conn.execute("SELECT * FROM response_plans WHERE id = ?", (plan_id,)).fetchone()
        reasons = []
        if plan is None:
            return False, ["plan does not exist"]
        if plan["status"] == STATUS_APPROVED:
            pass
        elif plan["status"] == STATUS_PROPOSED and plan["policy_outcome"] == response_policy.AUTO_EXECUTE:
            pass
        else:
            reasons.append(f"status {plan['status']} / outcome {plan['policy_outcome']} is not dispatchable")
        if plan["expires_at"] < now.strftime(_TS):
            reasons.append("plan has expired")
        alert = conn.execute("SELECT status, updated_at, created_at FROM security_alerts WHERE id = ?", (plan["security_alert_id"],)).fetchone()
        if alert is None:
            reasons.append("originating alert no longer exists")
        else:
            if alert["status"] == "CLOSED":
                reasons.append("originating alert is CLOSED")
            last = alert["updated_at"] or alert["created_at"]
            cutoff = (now - timedelta(minutes=ACTIVE_DECISION_WINDOW_MINUTES)).strftime(_TS)
            if last < cutoff:
                reasons.append("originating decision is no longer active (outside the Stage-25F window) - revalidation required")
        return (not reasons), reasons
    finally:
        if own:
            conn.close()


def expire_stale_plans(conn=None, now=None):
    """Sweep: PROPOSED/APPROVED plans past expires_at or whose alert is
    CLOSED/missing -> EXPIRED. Returns the number expired."""
    own = conn is None
    conn = conn or get_db_connection()
    now = now or datetime.now()
    try:
        rows = conn.execute(
            "SELECT p.id, p.expires_at, a.status AS alert_status FROM response_plans p "
            "LEFT JOIN security_alerts a ON a.id = p.security_alert_id WHERE p.status IN ('PROPOSED','APPROVED')"
        ).fetchall()
        count = 0
        for r in rows:
            if r["expires_at"] < now.strftime(_TS) or r["alert_status"] in (None, "CLOSED"):
                conn.execute("UPDATE response_plans SET status='EXPIRED', updated_at=?, decided_by=COALESCE(decided_by,'system-expiry'), "
                             "decided_at=COALESCE(decided_at,?), decision_note=COALESCE(decision_note,'expired by staleness sweep') WHERE id=?",
                             (now.strftime(_TS), now.strftime(_TS), r["id"]))
                count += 1
        conn.commit()
        return count
    finally:
        if own:
            conn.close()
