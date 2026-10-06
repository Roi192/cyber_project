# ==================================================
# PHASE 13C: ENDPOINT HEARTBEAT
# ==================================================
#
# POST /api/endpoint-heartbeat
#   A lightweight presence + network-identity signal from an endpoint agent so
#   endpoint_ip_history stays accurate while the agent has no qualifying web
#   event. It carries ONLY: endpoint_uid, the agent's primary IP and its
#   eligible local addresses (and an optional interval). No processes, files,
#   browsing data or documents - this is presence + network identity, not
#   surveillance.
#
#   Authentication is the EXISTING agent model (X-Agent-Key, fail closed, via
#   web_monitoring._agent_auth_error). The endpoint_uid is identity metadata,
#   not authentication. Sensor credentials do NOT authenticate this route and
#   the agent key does not authenticate /api/security-ingest.
#
#   Consistency guard (endpoint_network.evaluate_identity): a heartbeat that
#   asserts a UID for an IP that a DIFFERENT UID is currently bound to is a
#   CONFLICT for that address only - nothing is recorded for it, the stored UID
#   is not overwritten and a bounded ENDPOINT_IDENTITY_CONFLICT log entry is
#   written. Other addresses in the same heartbeat are still recorded and the
#   response is a deterministic 409 listing the conflicting addresses.
#
#   202 ok   409 conflict (partial)   400 malformed   401 unauthorized
#   413 too large   415 not JSON   503 not configured / storage busy   500 generic

import json

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

import db_config
import endpoint_identity
import endpoint_network as en
import security_contract as sc
import security_detections as sd
import web_monitoring

endpoint_heartbeat_bp = Blueprint("endpoint_heartbeat", __name__)

MAX_BODY_BYTES = 8 * 1024
_ALLOWED_KEYS = {"endpoint_uid", "endpoint_ip", "addresses", "interval_seconds"}


def _reply(payload, status, retry_after=None):

    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"

    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)

    return response


def _error(status, message, retry_after=None):
    return _reply({"status": "error", "message": message}, status, retry_after)


def _reject_constant(name):
    raise ValueError("non-finite JSON constant")


def _system_logger(event_type, message):

    # Bounded system_logs entry (validated UUIDs + canonical IP only).
    web_monitoring.write_log(event_type, message, username="system")


@endpoint_heartbeat_bp.route("/api/endpoint-heartbeat", methods=["POST"])
def endpoint_heartbeat():

    auth_error = web_monitoring._agent_auth_error()

    if auth_error is not None:
        return auth_error

    declared = request.content_length

    if declared is not None and declared > MAX_BODY_BYTES:
        return _error(413, "Request too large.")

    if request.mimetype != "application/json":
        return _error(415, "Content-Type must be application/json.")

    try:
        body = request.get_data(cache=False)
    except RequestEntityTooLarge:
        return _error(413, "Request too large.")

    if len(body) > MAX_BODY_BYTES:
        return _error(413, "Request too large.")

    try:
        payload = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return _error(400, "Invalid JSON.")

    if not isinstance(payload, dict):
        return _error(400, "Body must be a JSON object.")

    if set(payload) - _ALLOWED_KEYS:
        return _error(400, "Unknown field.")

    uid = endpoint_identity.normalize_endpoint_uid(payload.get("endpoint_uid"))

    if uid is None:
        return _error(400, "Invalid endpoint_uid.")

    primary = en.canonical_ip(payload.get("endpoint_ip"))

    if primary is None:
        return _error(400, "Invalid endpoint_ip.")

    addresses = payload.get("addresses", [])

    if not isinstance(addresses, list) or len(addresses) > en.MAX_ADDRESSES_PER_HEARTBEAT:
        return _error(400, "Invalid addresses.")

    cleaned = []

    for item in addresses:

        ip = en.canonical_ip(item)

        if ip is None:
            return _error(400, "Invalid address in addresses.")

        cleaned.append(ip)

    interval = payload.get("interval_seconds")

    if interval is not None and (isinstance(interval, bool) or not isinstance(interval, int)
                                 or not 15 <= interval <= 600):
        return _error(400, "Invalid interval_seconds.")

    now = sc.utc_now()
    ordered = []

    for ip in [primary] + cleaned:
        if ip not in ordered:
            ordered.append(ip)

    conn = None

    try:

        conn = sd.get_db_connection()

        outcome = db_config.retry_on_lock(
            lambda: en.record_observations(
                conn, uid, ordered, now, en.SOURCE_HEARTBEAT,
                logger=_system_logger, route="heartbeat"
            ),
            label="endpoint_heartbeat_history",
            cleanup=lambda exc: conn.rollback(),
            log=lambda message: None,
        )

        # Presence for the primary IP's endpoints row (cheap, throttled).
        eligible_primary = en.history_eligible_ip(primary)
        decision = outcome["decisions"].get(eligible_primary) if eligible_primary else None

        if eligible_primary is None:
            # e.g. a link-local/virtual primary: presence is still meaningful
            # for the endpoints row, but never for identity history.
            presence_ip, presence_decision = primary, None
        else:
            presence_ip, presence_decision = eligible_primary, decision

        if outcome["results"].get(presence_ip) != en.REC_CONFLICT:

            state = db_config.retry_on_lock(
                lambda: en.touch_endpoint_presence(conn, uid, presence_ip, presence_decision, now),
                label="endpoint_heartbeat_presence",
                cleanup=lambda exc: conn.rollback(),
                log=lambda message: None,
            )

            if state == "MISSING":
                # First time this IP is seen: the normal endpoint registration
                # (reverse-DNS hostname etc.) - once, never per heartbeat.
                conn.close()
                conn = None
                web_monitoring.save_endpoint(presence_ip, source="endpoint-agent", endpoint_uid=uid)

    except db_config.LockRetryExhausted:
        return _error(503, "Storage busy; retry.", retry_after=2)

    except Exception as exc:
        # Class name only: exception text could carry request data.
        try:
            _system_logger("ENDPOINT_HEARTBEAT_ERROR", f"error={type(exc).__name__}")
        except Exception:
            pass
        return _error(500, "Internal error.")

    finally:
        if conn is not None:
            conn.close()

    if outcome["conflicts"]:

        return _reply({
            "status": "conflict",
            "code": "ENDPOINT_IDENTITY_CONFLICT",
            "recorded": outcome["recorded"],
            "conflicting_addresses": outcome["conflicts"][:en.MAX_ADDRESSES_PER_HEARTBEAT],
        }, 409)

    return _reply({"status": "ok", "recorded": outcome["recorded"]}, 202)
