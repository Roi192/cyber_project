# ==================================================
# STAGE 25G PHASE 2: SERVER-SIDE RESPONSE EXECUTION GATE
# ==================================================
#
# ONE reusable, fail-closed gate for every FUTURE automated response
# command. Until now the only enforcement of ENABLE_RESPONSE_ACTIONS
# lived on the Agent (execution side) - the Stage 25F audit flagged
# that as a mandatory precondition for autonomous response. This is
# that server-side precondition.
#
# TWO SEPARATE FLAGS, never equated:
#   ENABLE_RESPONSE_ACTIONS     - may ANY response command be created
#                                 by automated code at all (false today)
#   ENABLE_AUTONOMOUS_RESPONSE  - may a command be created WITHOUT an
#                                 analyst approval (false today). An
#                                 autonomous dispatch needs BOTH.
#
# The gate only CLASSIFIES. It never creates a row, never calls the
# Agent, never touches the OS. web_monitoring.create_response_command(
# origin="automated") refuses anything but a passing result from here,
# so the gate cannot be bypassed by calling the low-level insert - that
# insert lives only inside create_response_command() (call-site audit,
# Phase 2 report).
# ==================================================

import ipaddress
import os
from datetime import datetime, timezone

import response_policy
import web_monitoring
from endpoint_identity import normalize_endpoint_uid

RESPONSE_ACTIONS_ENV = "ENABLE_RESPONSE_ACTIONS"
AUTONOMOUS_RESPONSE_ENV = "ENABLE_AUTONOMOUS_RESPONSE"

# response_commands vocabulary -> policy action it realizes.
COMMAND_TO_ACTION = {
    "BLOCK_DESTINATION": response_policy.BLOCK_DESTINATION,
    "UNBLOCK_DESTINATION": response_policy.UNBLOCK_DESTINATION,
    "ISOLATE_ENDPOINT": response_policy.ISOLATE_ENDPOINT,
    "RESTORE_ENDPOINT": response_policy.RESTORE_ENDPOINT,
}


def _flag(env, name):
    return (env.get(name, "false") or "false").strip().lower() == "true"


def server_response_execution_allowed(
    command_type,
    endpoint_ip,
    target=None,
    endpoint_uid=None,
    autonomous=False,
    policy_input=None,
    protection_policy=None,
    env=None,
    now=None,
):
    """
    Returns a plain dict:
      {allowed: bool, reasons: [...], checks: [{name, passed, detail}],
       command_type, endpoint_ip, target, autonomous, evaluated_at}
    Every check runs (never short-circuits) so the result explains
    EVERY failing condition, and `allowed` is True only if all passed.
    env defaults to os.environ; tests pass an isolated dict - the live
    .env is never modified to exercise the TRUE cases.
    """
    env = os.environ if env is None else env
    now = now or datetime.now(timezone.utc)
    protection_policy = protection_policy or response_policy.load_protection_policy(env)
    checks = []

    def check(name, passed, detail):
        checks.append({"name": name, "passed": bool(passed), "detail": detail})
        return bool(passed)

    check("response_actions_enabled", _flag(env, RESPONSE_ACTIONS_ENV),
          f"{RESPONSE_ACTIONS_ENV} must be true for ANY automated command")

    if autonomous:
        check("autonomous_response_enabled", _flag(env, AUTONOMOUS_RESPONSE_ENV),
              f"{AUTONOMOUS_RESPONSE_ENV} must be true for a command created without analyst approval")

    supported = command_type in web_monitoring.COMMAND_TYPES
    check("supported_command_type", supported, f"command_type {command_type!r} must be one of {web_monitoring.COMMAND_TYPES}")

    try:
        ip_ok = ipaddress.ip_address((endpoint_ip or "").strip()) is not None
    except ValueError:
        ip_ok = False
    check("valid_endpoint_ip", ip_ok, "endpoint_ip must be a valid IP address")

    uid = normalize_endpoint_uid(endpoint_uid)

    if command_type in ("ISOLATE_ENDPOINT", "RESTORE_ENDPOINT"):
        check("endpoint_uid_well_formed", uid is not None,
              "endpoint isolation/restore requires a well-formed endpoint_uid - an IP is not an identity")
        check("soc_management_path_known", bool(protection_policy.get("soc_server_host")),
              "SOC_SERVER_URL host must be known so isolation keeps a management path")
        if command_type == "ISOLATE_ENDPOINT":
            check("endpoint_not_protected", uid is None or uid not in protection_policy["protected_endpoint_uids"],
                  "endpoint is on the protected-endpoint list")

    if command_type in ("BLOCK_DESTINATION", "UNBLOCK_DESTINATION"):
        kind, host = response_policy._destination_kind(target, target)
        blockable = kind == "DOMAIN" or (kind == "IP" and ipaddress.ip_address(host).is_global)
        check("destination_target_present_and_blockable", blockable,
              "target must be a domain or a public IP (an IP is never treated as a domain; private/loopback never blockable)")
        if command_type == "BLOCK_DESTINATION":
            check("destination_not_allowlisted", not response_policy._destination_is_allowed(host, protection_policy),
                  "destination is allowlisted or is the SOC management host")

    if supported:
        duplicate = web_monitoring._find_active_command(endpoint_ip, command_type, target)
        check("no_duplicate_active_command", duplicate is None,
              f"an equivalent command is already active (id={duplicate['id']})" if duplicate else "no active duplicate")

    if policy_input is not None and supported:
        action = COMMAND_TO_ACTION[command_type]
        plans = response_policy.evaluate_policy(policy_input, protection_policy, now)["plans"]
        plan = next((p for p in plans if p["proposed_action"] == action), None)
        if plan is None:
            # reverse actions (UNBLOCK/RESTORE) are never produced from a
            # detection; they are only ever reversals of a prior command.
            check("policy_prerequisites_satisfied", action in (response_policy.UNBLOCK_DESTINATION, response_policy.RESTORE_ENDPOINT),
                  "forward action not proposed by policy for this decision")
        else:
            required = response_policy.AUTO_EXECUTE if autonomous else response_policy.REQUIRE_APPROVAL
            ok = response_policy._OUTCOME_RANK[plan["policy_outcome"]] >= response_policy._OUTCOME_RANK[required]
            check("policy_prerequisites_satisfied", ok,
                  f"policy outcome {plan['policy_outcome']} does not reach {required}; guards: "
                  + "; ".join(g["reason"] for g in plan["guards_applied"] if g["from"] != g["to"]))

    allowed = all(c["passed"] for c in checks)

    return {
        "allowed": allowed,
        "reasons": [c["detail"] for c in checks if not c["passed"]],
        "checks": checks,
        "command_type": command_type,
        "endpoint_ip": endpoint_ip,
        "target": target or None,
        "autonomous": bool(autonomous),
        "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
