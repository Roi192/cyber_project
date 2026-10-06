# ==================================================
# STAGE 25G PHASE 1: RESPONSE POLICY ENGINE (policy / safety only)
# ==================================================
#
# The central policy authority that receives a unified Stage-25F
# decision and classifies each CANDIDATE response action as one of:
#   NO_ACTION | RECOMMEND_ONLY | REQUIRE_APPROVAL | AUTO_EXECUTE
#
#   Unified Decision -> Response Policy Engine -> Response Plan
#                    -> (Approval/Execution layer - DISABLED in Phase 1)
#
# PHASE 1 BOUNDARIES (all deliberate):
#   * PURE: no database writes, no response_commands row, no Agent
#     command, no OS action. evaluate_policy() returns plain dicts.
#   * NOT WIRED: nothing in the live pipeline (web_event_worker.py /
#     detection_engine.py / app.py) imports this module yet. Wiring,
#     approval UI and execution are later phases, each separately
#     approved. ENABLE_RESPONSE_ACTIONS stays false regardless.
#   * Every plan carries execution_enabled=False - an AUTO_EXECUTE
#     outcome is a POLICY CLASSIFICATION ("would be eligible"), never
#     an execution.
#
# FAIL-CLOSED PRINCIPLES (instruction "Mandatory safety principles"):
#   * destructive actions default to the SAFER outcome whenever any
#     prerequisite cannot be proven from existing trusted data;
#   * ISOLATE_ENDPOINT requires a well-formed endpoint_uid
#     (endpoint_identity.normalize_endpoint_uid) - an IP is NOT an
#     identity (Phase 12B.6D's own rule);
#   * TERMINATE_PROCESS requires CONFIRMED process correlation with a
#     valid process_instance_id - gated through the same
#     correlation_key.tier_allows_process_identity_claim() the alert
#     layer already uses, so PENDING/UNAVAILABLE/NOT_APPLICABLE and
#     unresolved Suricata evidence can never authorize it;
#   * QUARANTINE_FILE requires a confirmed file identity: a valid
#     SHA-256 (web_monitoring.SHA256_PATTERN) AND a file path, both from
#     the CONFIRMED process row - hash_status is free text from the
#     Agent and is deliberately NOT treated as proof on its own;
#   * BLOCK_DESTINATION requires a real domain or a public IP target -
#     an IP is never treated as a domain (same ipaddress check the
#     advisory blocklist uses), never a private/loopback address;
#   * protected endpoints/processes/destinations (see PROTECTION
#     MODEL) prevent or downgrade destructive actions;
#   * the same unified decision occurrence always yields the same
#     idempotency key per action/target, so reprocessing can never
#     produce a second executable action.
#
# CONFIDENCE: never invented. The only confidence this project
# has today is per-detection (detections.confidence, Stage 25C) plus
# the number of DISTINCT evidence sources (the same corroboration
# notion Rule A uses). Both are consumed as-is.
# ==================================================

import hashlib
import ipaddress
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import correlation_key
from endpoint_identity import normalize_endpoint_uid
from web_monitoring import SHA256_PATTERN

# --------------------------------------------------
# OUTCOMES (ordered least -> most permissive)
# --------------------------------------------------
NO_ACTION = "NO_ACTION"
RECOMMEND_ONLY = "RECOMMEND_ONLY"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
AUTO_EXECUTE = "AUTO_EXECUTE"

_OUTCOME_RANK = {NO_ACTION: 0, RECOMMEND_ONLY: 1, REQUIRE_APPROVAL: 2, AUTO_EXECUTE: 3}

# --------------------------------------------------
# ACTION VOCABULARY
# --------------------------------------------------
COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
BLOCK_DESTINATION = "BLOCK_DESTINATION"
TERMINATE_PROCESS = "TERMINATE_PROCESS"
QUARANTINE_FILE = "QUARANTINE_FILE"
ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
RESTORE_ENDPOINT = "RESTORE_ENDPOINT"
UNBLOCK_DESTINATION = "UNBLOCK_DESTINATION"
RESTORE_QUARANTINED_FILE = "RESTORE_QUARANTINED_FILE"

TARGET_ENDPOINT = "ENDPOINT"
TARGET_PROCESS = "PROCESS"
TARGET_FILE = "FILE"
TARGET_DESTINATION = "DESTINATION"

# destructive: changes endpoint/network/process/file state.
# reverse_action: None = not directly reversible (TERMINATE_PROCESS).
# existing_command_type: the response_commands/Agent command this maps
# to TODAY (Phase 7 vocabulary) - None means the Agent has no such
# command yet (TERMINATE/QUARANTINE/COLLECT are design-only here).
ACTIONS = {
    COLLECT_EVIDENCE: {"target_type": TARGET_ENDPOINT, "destructive": False, "reversible": True, "reverse_action": None, "existing_command_type": None},
    BLOCK_DESTINATION: {"target_type": TARGET_DESTINATION, "destructive": True, "reversible": True, "reverse_action": UNBLOCK_DESTINATION, "existing_command_type": "BLOCK_DESTINATION"},
    UNBLOCK_DESTINATION: {"target_type": TARGET_DESTINATION, "destructive": False, "reversible": True, "reverse_action": BLOCK_DESTINATION, "existing_command_type": "UNBLOCK_DESTINATION"},
    ISOLATE_ENDPOINT: {"target_type": TARGET_ENDPOINT, "destructive": True, "reversible": True, "reverse_action": RESTORE_ENDPOINT, "existing_command_type": "ISOLATE_ENDPOINT"},
    RESTORE_ENDPOINT: {"target_type": TARGET_ENDPOINT, "destructive": False, "reversible": True, "reverse_action": ISOLATE_ENDPOINT, "existing_command_type": "RESTORE_ENDPOINT"},
    QUARANTINE_FILE: {"target_type": TARGET_FILE, "destructive": True, "reversible": True, "reverse_action": RESTORE_QUARANTINED_FILE, "existing_command_type": None},
    RESTORE_QUARANTINED_FILE: {"target_type": TARGET_FILE, "destructive": False, "reversible": True, "reverse_action": QUARANTINE_FILE, "existing_command_type": None},
    TERMINATE_PROCESS: {"target_type": TARGET_PROCESS, "destructive": True, "reversible": False, "reverse_action": None, "existing_command_type": None},
}

# Rollback pairs (instruction "Rollback model") - derived, single source.
ROLLBACK_PAIRS = {name: meta["reverse_action"] for name, meta in ACTIONS.items() if meta["reverse_action"]}

# Candidate actions the policy considers for a FORWARD (containment)
# decision. Reverse actions are never proposed from a detection - they
# only ever follow a previously executed forward action (Phase 2+).
FORWARD_CANDIDATES = (COLLECT_EVIDENCE, BLOCK_DESTINATION, ISOLATE_ENDPOINT, TERMINATE_PROCESS, QUARANTINE_FILE)

# Severity vocabulary = threat_intelligence.severity_from_score()'s own
# bands (INFO <15, LOW <35, MEDIUM <60, HIGH <80, CRITICAL >=80).
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Corroboration: distinct evidence SOURCES (THREATFOX, LOCAL_FEED,
# LEGACY_IOC, SURICATA, VIRUSTOTAL, ABUSEIPDB, ...) - the same notion
# Rule A already uses ("TWO independent sources corroborating").
AUTO_EXECUTE_MIN_DISTINCT_SOURCES = 2
# Per-detection confidence floor for any AUTO_EXECUTE eligibility -
# every contributing rule's own confidence (Stage 25C values are 60-90).
AUTO_EXECUTE_MIN_CONFIDENCE = 70

# --------------------------------------------------
# PROTECTION MODEL (allowlist / protected targets)
# --------------------------------------------------
# Env-driven comma lists (same convention as MONITORED_NETWORKS and
# url_send_policy's exclusion list), plus a SMALL, justified default
# set - deliberately not a sweeping Windows process list.
PROTECTED_ENDPOINT_UIDS_ENV = "RESPONSE_PROTECTED_ENDPOINT_UIDS"
PROTECTED_PROCESSES_ENV = "RESPONSE_PROTECTED_PROCESSES"
PROTECTED_PATH_FRAGMENTS_ENV = "RESPONSE_PROTECTED_PATH_FRAGMENTS"
ALLOWED_DESTINATIONS_ENV = "RESPONSE_ALLOWED_DESTINATIONS"

# Justification per entry (instruction: no arbitrary giant list):
#   smss/csrss/wininit/winlogon/services/lsass - session/security
#   subsystem; killing any of them crashes or locks the host (and
#   lsass holds credentials - an attacker-grade action, never ours).
#   svchost - hosts dozens of unrelated services per instance; name
#   alone cannot identify the culprit. explorer - the user shell.
DEFAULT_PROTECTED_PROCESSES = frozenset({
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe",
})
# The SOC itself: every Agent/worker/server process of this project runs
# from the project directory under python.exe. Protecting by path
# fragment (not by "python.exe", which would also shield an attacker's
# own interpreter) keeps the SOC's management plane un-terminable.
DEFAULT_PROTECTED_PATH_FRAGMENTS = frozenset({"cyber_project"})


def _env_list(name):
    raw = os.getenv(name, "") or ""
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def load_protection_policy(env=None):
    """
    Returns the effective protection policy as a plain dict. Pure
    (reads env only). The SOC server host from SOC_SERVER_URL is ALWAYS
    an allowed (never-blocked) destination - management connectivity.
    """
    getenv = (env or os.environ).get

    def _list(name):
        raw = getenv(name, "") or ""
        return [item.strip().lower() for item in raw.split(",") if item.strip()]

    soc_host = None
    soc_url = getenv("SOC_SERVER_URL", "") or ""
    if soc_url:
        try:
            soc_host = (urlparse(soc_url).hostname or "").lower() or None
        except ValueError:
            soc_host = None

    return {
        "protected_endpoint_uids": frozenset(u for u in (normalize_endpoint_uid(x) for x in _list(PROTECTED_ENDPOINT_UIDS_ENV)) if u),
        "protected_processes": DEFAULT_PROTECTED_PROCESSES | frozenset(_list(PROTECTED_PROCESSES_ENV)),
        "protected_path_fragments": DEFAULT_PROTECTED_PATH_FRAGMENTS | frozenset(_list(PROTECTED_PATH_FRAGMENTS_ENV)),
        "allowed_destinations": frozenset(_list(ALLOWED_DESTINATIONS_ENV)) | (frozenset({soc_host}) if soc_host else frozenset()),
        "soc_server_host": soc_host,
    }


# --------------------------------------------------
# TARGET VALIDATION HELPERS (fail closed)
# --------------------------------------------------
def _as_ip(value):
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def _destination_kind(domain, resolved_ip):
    """('DOMAIN', host) | ('IP', ip_str) | (None, None). An IP literal
    in `domain` is NEVER reported as a domain."""
    if domain and _as_ip(domain) is None:
        host = domain.strip().lower().strip(".")
        if host:
            return "DOMAIN", host
    ip = _as_ip(resolved_ip) or _as_ip(domain)
    if ip is not None:
        return "IP", str(ip)
    return None, None


def _destination_is_allowed(host, policy):
    host = (host or "").lower()
    if not host:
        return False
    for allowed in policy["allowed_destinations"]:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def _process_is_protected(process_name, process_path, policy):
    name = (process_name or "").strip().lower()
    path = (process_path or "").strip().lower()
    if name and name in policy["protected_processes"]:
        return True, f"process name '{name}' is on the protected-process list"
    for fragment in policy["protected_path_fragments"]:
        if fragment and fragment in path:
            return True, f"process path matches protected fragment '{fragment}' (SOC/agent process)"
    return False, None


def _file_identity_confirmed(decision):
    """Confirmed file identity = CONFIRMED process correlation AND a
    valid SHA-256 AND a file path, all from the same trusted process
    row. hash_status (free text from the Agent) is not sufficient."""
    if not _process_identity_confirmed(decision):
        return False, "process correlation is not CONFIRMED, so no file identity can be trusted"
    sha256 = (decision.get("sha256") or "").strip().lower()
    path = (decision.get("process_path") or "").strip()
    if not SHA256_PATTERN.match(sha256):
        return False, "no valid SHA-256 for the file"
    if not path:
        return False, "no file path for the file"
    return True, None


def _process_identity_confirmed(decision):
    return correlation_key.tier_allows_process_identity_claim(
        decision.get("process_correlation_status"),
        decision.get("process_instance_id"),
        event_source=decision.get("event_source"),
    )


# --------------------------------------------------
# IDEMPOTENCY
# --------------------------------------------------
def idempotency_key(correlation_key_value, security_alert_id, action, target_type, target):
    """
    One key per (decision occurrence, action, target). The decision
    occurrence is the unified alert id (Stage 25F: a lapsed-window
    re-occurrence is a NEW alert id), so the same decision reprocessed
    inside its window always maps to the SAME key, and a distinct
    occurrence maps to a distinct key - never invented, never random.
    """
    raw = "|".join([
        correlation_key_value or "", str(security_alert_id or ""), action or "",
        target_type or "", (target or "").lower(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------
# SEVERITY BASELINE (before prerequisites/protections)
# --------------------------------------------------
def _baseline_outcome(action, severity):
    """
    Conservative mapping against the project's own bands:
      INFO/LOW   -> NO_ACTION (COLLECT_EVIDENCE: RECOMMEND_ONLY)
      MEDIUM     -> RECOMMEND_ONLY
      HIGH       -> reversible destructive: REQUIRE_APPROVAL;
                    irreversible (TERMINATE): RECOMMEND_ONLY;
                    COLLECT_EVIDENCE: REQUIRE_APPROVAL
      CRITICAL   -> reversible destructive: AUTO_EXECUTE-eligible
                    (subject to every guard below); irreversible
                    (TERMINATE): REQUIRE_APPROVAL at most - an
                    irreversible action is never automatic in Phase 1;
                    COLLECT_EVIDENCE: AUTO_EXECUTE-eligible
                    (non-destructive).
    """
    rank = SEVERITY_RANK.get(severity or "INFO", 0)
    meta = ACTIONS[action]

    if rank <= SEVERITY_RANK["LOW"]:
        return RECOMMEND_ONLY if action == COLLECT_EVIDENCE else NO_ACTION
    if rank == SEVERITY_RANK["MEDIUM"]:
        return RECOMMEND_ONLY
    if rank == SEVERITY_RANK["HIGH"]:
        if action == COLLECT_EVIDENCE:
            return REQUIRE_APPROVAL
        return REQUIRE_APPROVAL if meta["reversible"] else RECOMMEND_ONLY
    # CRITICAL
    if not meta["reversible"]:
        return REQUIRE_APPROVAL
    return AUTO_EXECUTE


def _downgrade(plan, to_outcome, guard, reason):
    """Lower (never raise) the outcome and record which guard did it."""
    if _OUTCOME_RANK[to_outcome] < _OUTCOME_RANK[plan["policy_outcome"]]:
        plan["guards_applied"].append({"guard": guard, "from": plan["policy_outcome"], "to": to_outcome, "reason": reason})
        plan["policy_outcome"] = to_outcome
    else:
        plan["guards_applied"].append({"guard": guard, "from": plan["policy_outcome"], "to": plan["policy_outcome"], "reason": reason})


# --------------------------------------------------
# PLAN CONSTRUCTION
# --------------------------------------------------
def _new_plan(decision, action, target_type, target, now):
    meta = ACTIONS[action]
    return {
        "correlation_key": decision.get("correlation_key"),
        "security_alert_id": decision.get("security_alert_id"),
        "incident_id": decision.get("incident_id"),
        "proposed_action": action,
        "target_type": target_type,
        "target": target,
        "policy_outcome": None,
        "baseline_outcome": None,
        "reasons": [],              # why this action was proposed
        "evidence": list(decision.get("evidence_sources") or []),
        "contributing_rules": list(decision.get("contributing_rules") or []),
        "prerequisites": [],        # {"name", "satisfied", "detail"}
        "guards_applied": [],       # {"guard", "from", "to", "reason"}
        "destructive": meta["destructive"],
        "reversible": meta["reversible"],
        "reverse_action": meta["reverse_action"],
        "existing_command_type": meta["existing_command_type"],
        "approval_required": None,
        "idempotency_key": idempotency_key(decision.get("correlation_key"), decision.get("security_alert_id"), action, target_type, target),
        "execution_enabled": False,  # Phase 1 invariant - never executes
        "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy_version": "25G.1",
    }


def _prereq(plan, name, satisfied, detail=None):
    plan["prerequisites"].append({"name": name, "satisfied": bool(satisfied), "detail": detail})
    return bool(satisfied)


def evaluate_policy(decision, policy=None, now=None):
    """
    decision: a plain dict built from EXISTING trusted data -
      severity, risk_score, correlation_key, security_alert_id,
      incident_id, contributing_rules (rule_ids), evidence_sources
      (distinct detection_evidence.evidence_source values),
      min_confidence (min of contributing detections.confidence),
      endpoint_uid, endpoint_ip, process_correlation_status,
      process_instance_id, process_name, process_path, sha256,
      domain, resolved_ip, event_source, previous_response_state
      (optional: {"active_commands": [...]}).
    Returns {"plans": [...], "summary": {...}} - plain data, no side
    effects. Never raises on missing fields (fail closed instead).
    """
    policy = policy or load_protection_policy()
    now = now or datetime.now(timezone.utc)
    severity = (decision.get("severity") or "INFO").upper()
    plans = []

    endpoint_uid = normalize_endpoint_uid(decision.get("endpoint_uid"))
    dest_kind, dest_target = _destination_kind(decision.get("domain"), decision.get("resolved_ip"))
    process_confirmed = _process_identity_confirmed(decision)
    distinct_sources = len(set(decision.get("evidence_sources") or []))
    min_confidence = decision.get("min_confidence")
    endpoint_protected = bool(endpoint_uid and endpoint_uid in policy["protected_endpoint_uids"])
    proc_protected, proc_protected_reason = _process_is_protected(decision.get("process_name"), decision.get("process_path"), policy)
    active_cmds = {(c.get("command_type"), (c.get("target") or "").lower()) for c in (decision.get("previous_response_state") or {}).get("active_commands", [])}

    for action in FORWARD_CANDIDATES:
        meta = ACTIONS[action]

        # ---- target identity (fail closed: no target -> NO_ACTION) ----
        if meta["target_type"] == TARGET_DESTINATION:
            target = dest_target
        elif meta["target_type"] == TARGET_PROCESS:
            target = decision.get("process_instance_id") if process_confirmed else None
        elif meta["target_type"] == TARGET_FILE:
            target = (decision.get("sha256") or "").lower() or None
        else:
            target = endpoint_uid

        plan = _new_plan(decision, action, meta["target_type"], target, now)
        plan["baseline_outcome"] = _baseline_outcome(action, severity)
        plan["policy_outcome"] = plan["baseline_outcome"]
        plan["reasons"].append(f"unified decision severity {severity} (risk {decision.get('risk_score')}) -> baseline {plan['baseline_outcome']} for {action}")

        # ---- universal prerequisites ----
        if not _prereq(plan, "target_identity_present", target is not None, f"{meta['target_type']} target could not be established from trusted data"):
            _downgrade(plan, NO_ACTION, "MISSING_TARGET_IDENTITY", "no trustworthy target identity - fail closed")

        if action == ISOLATE_ENDPOINT:
            if not _prereq(plan, "endpoint_uid_well_formed", endpoint_uid is not None, "endpoint_uid missing/malformed - an IP is not an endpoint identity"):
                _downgrade(plan, NO_ACTION, "ENDPOINT_UID_REQUIRED", "isolation denied: no well-formed endpoint_uid")
            if endpoint_protected:
                _downgrade(plan, RECOMMEND_ONLY, "PROTECTED_ENDPOINT", "endpoint is on the protected-endpoint list - isolation denied automatically")
            if not _prereq(plan, "soc_management_path_known", bool(policy["soc_server_host"]), "SOC_SERVER_URL host unknown - cannot guarantee a management path during isolation"):
                _downgrade(plan, REQUIRE_APPROVAL, "SOC_PATH_UNKNOWN", "isolation needs a known SOC management host")

        if action == TERMINATE_PROCESS:
            if not _prereq(plan, "process_identity_confirmed", process_confirmed, f"process correlation status '{decision.get('process_correlation_status')}' / event_source '{decision.get('event_source')}' does not confirm a specific process"):
                _downgrade(plan, NO_ACTION, "PROCESS_NOT_CONFIRMED", "termination denied: process identity not CONFIRMED")
            if proc_protected:
                _downgrade(plan, NO_ACTION, "PROTECTED_PROCESS", f"termination denied: {proc_protected_reason}")
            _prereq(plan, "irreversible_action_acknowledged", True, "TERMINATE_PROCESS cannot be undone - never automatic in Phase 1")

        if action == QUARANTINE_FILE:
            ok, why = _file_identity_confirmed(decision)
            if not _prereq(plan, "file_identity_confirmed", ok, why):
                _downgrade(plan, NO_ACTION, "FILE_IDENTITY_REQUIRED", f"quarantine denied: {why}")
            if proc_protected:
                _downgrade(plan, NO_ACTION, "PROTECTED_PROCESS", f"quarantine denied: {proc_protected_reason}")

        if action == BLOCK_DESTINATION:
            if not _prereq(plan, "destination_is_domain_or_public_ip", dest_kind is not None and (dest_kind == "DOMAIN" or _as_ip(dest_target).is_global), "destination is missing, private/loopback, or otherwise not blockable"):
                _downgrade(plan, NO_ACTION, "DESTINATION_NOT_BLOCKABLE", "blocking denied: no blockable public destination")
            if dest_kind == "IP":
                plan["reasons"].append("destination target is an IP literal - treated strictly as an IP, never as a domain")
            if _destination_is_allowed(dest_target, policy):
                _downgrade(plan, NO_ACTION, "ALLOWED_DESTINATION", "blocking denied: destination is allowlisted (or is the SOC management host)")

        if action == COLLECT_EVIDENCE:
            if endpoint_protected:
                plan["reasons"].append("protected endpoint - evidence collection is non-destructive and remains allowed")

        # ---- AUTO_EXECUTE needs corroboration + confidence (never invented) ----
        if plan["policy_outcome"] == AUTO_EXECUTE:
            if not _prereq(plan, "corroborated_by_independent_sources", distinct_sources >= AUTO_EXECUTE_MIN_DISTINCT_SOURCES, f"{distinct_sources} distinct evidence source(s); {AUTO_EXECUTE_MIN_DISTINCT_SOURCES} required"):
                _downgrade(plan, REQUIRE_APPROVAL, "INSUFFICIENT_CORROBORATION", "automatic execution requires at least two independent evidence sources")
            if not _prereq(plan, "contributing_confidence_known_and_sufficient", isinstance(min_confidence, (int, float)) and min_confidence >= AUTO_EXECUTE_MIN_CONFIDENCE, f"min contributing detection confidence = {min_confidence}; {AUTO_EXECUTE_MIN_CONFIDENCE} required (never assumed when absent)"):
                _downgrade(plan, REQUIRE_APPROVAL, "INSUFFICIENT_CONFIDENCE", "automatic execution requires known, sufficient detection confidence")

        # ---- idempotency / previous state ----
        if meta["existing_command_type"] and (meta["existing_command_type"], (target or "").lower()) in active_cmds:
            _downgrade(plan, NO_ACTION, "ALREADY_IN_FLIGHT", "an equivalent response command is already active for this target - no duplicate")

        plan["approval_required"] = plan["policy_outcome"] == REQUIRE_APPROVAL
        plans.append(plan)

    return {
        "plans": plans,
        "summary": {
            "severity": severity,
            "distinct_evidence_sources": distinct_sources,
            "min_confidence": min_confidence,
            "endpoint_uid_well_formed": endpoint_uid is not None,
            "process_identity_confirmed": process_confirmed,
            "execution_enabled": False,
            "auto_execute_eligible": [p["proposed_action"] for p in plans if p["policy_outcome"] == AUTO_EXECUTE],
            "approval_required": [p["proposed_action"] for p in plans if p["policy_outcome"] == REQUIRE_APPROVAL],
        },
    }


def explain_plan(plan):
    """Structured 'why' answers (CEO wording is a later concern)."""
    return {
        "why_proposed": plan["reasons"],
        "why_execution_allowed_or_denied": [g["reason"] for g in plan["guards_applied"]] or ["no guard changed the baseline outcome"],
        "evidence": {"sources": plan["evidence"], "rules": plan["contributing_rules"]},
        "guards_that_changed_outcome": [g for g in plan["guards_applied"] if g["from"] != g["to"]],
        "final_outcome": plan["policy_outcome"],
        "execution_enabled": plan["execution_enabled"],
    }
