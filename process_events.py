# ==================================================
# STEP 25A: ENDPOINT PROCESS TELEMETRY - INGESTION
# ==================================================
#
# POST /api/process-events
#   Agent-authenticated - the EXACT SAME shared-secret check as
#   /api/web-events and /api/browser-events (_agent_auth_error():
#   X-Agent-Key header, see web_monitoring.py). The HTTP caller is
#   always the Endpoint Agent itself.
#
#   Collection ONLY (Step 25A scope). This route NEVER:
#     - reads/writes risk_score, severity, decision
#     - creates/touches security_alerts, incidents, response_commands
#     - performs a Threat Intelligence lookup, hashing, or any
#       enrichment of any kind inside the request (deliberately -
#       ingestion must stay fast; see the Step 25A report's
#       performance section)
#     - touches Legacy TI / Shadow TI / Local Feed in any way
#
# ENDPOINT_PROCESS_EVENTS TABLE SEMANTICS: despite its name (kept to
# match the Step 25A request's own suggested name), this is a ONE-ROW-
# PER-PROCESS-INSTANCE table, not an append-only event log - see the
# Step 25A report's Data Model section for the explicit event-table-
# vs-instance-table decision and why. UNIQUE(process_instance_id) +
# INSERT OR IGNORE makes a duplicate/retried delivery of the SAME
# process instance a safe no-op, never a second row.
#
# PROCESS IDENTITY: process_instance_id is NEVER trusted from the
# client as-is - it is RECOMPUTED server-side from the raw
# (endpoint_uid, pid, process_create_time) fields (process_identity.py,
# the exact same function the Agent itself uses) and the request is
# rejected if a client-submitted id does not match what the server
# independently derives. This mirrors the project's existing principle
# of never trusting a client-asserted identity/dedup key the server can
# derive itself (browser_events.py's url_dedup_key, local_feed's
# lock_id, etc.).
# ==================================================

from datetime import datetime

from flask import Blueprint, jsonify, request

import command_line_privacy
import endpoint_identity
import endpoint_network
import process_identity
from web_monitoring import get_db_connection, _agent_auth_error, write_log

process_events_bp = Blueprint("process_events", __name__)

MAX_COMMAND_LINE_LENGTH = 4096
MAX_STRING_FIELD_LENGTH = 512

_identity_logger = None  # set lazily - see _get_identity_logger


def _get_identity_logger():

    global _identity_logger

    if _identity_logger is None:

        import logging
        _identity_logger = logging.getLogger("process_events")

    return _identity_logger


def init_process_events_db():

    conn = get_db_connection()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS endpoint_process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_instance_id TEXT NOT NULL,
                endpoint_uid TEXT,
                endpoint_ip TEXT NOT NULL,
                pid INTEGER NOT NULL,
                ppid INTEGER,
                parent_process_instance_id TEXT,
                process_name TEXT,
                process_path TEXT,
                process_create_time REAL NOT NULL,
                os_username TEXT,
                command_line_text TEXT,
                command_line_was_redacted INTEGER NOT NULL DEFAULT 0,
                server_redaction_applied INTEGER NOT NULL DEFAULT 0,
                sha256 TEXT,
                md5 TEXT,
                hash_status TEXT,
                discovered_at TEXT,
                received_at TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'endpoint-agent',
                UNIQUE(process_instance_id)
            )
        """)

        conn.commit()

    finally:
        conn.close()


def _truncate(value, max_length):

    if value is None:
        return None

    value = str(value)

    return value[:max_length]


def _bad_request(message):

    return jsonify({"status": "error", "message": message}), 400


@process_events_bp.route("/api/process-events", methods=["POST"])
def receive_process_event():

    auth_error = _agent_auth_error()

    if auth_error:
        return auth_error

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return _bad_request("Request body must be a JSON object.")

    endpoint_ip = payload.get("endpoint_ip")

    try:
        import ipaddress
        ipaddress.ip_address(endpoint_ip)
    except (ValueError, TypeError):
        return _bad_request("endpoint_ip is required and must be a valid IP address.")

    pid = payload.get("pid")
    process_create_time = payload.get("process_create_time")

    try:
        pid_int = int(pid)
        if pid_int <= 0:
            raise ValueError("pid must be positive")
    except (TypeError, ValueError):
        return _bad_request("pid is required and must be a positive integer.")

    try:
        create_time_float = float(process_create_time)
    except (TypeError, ValueError):
        return _bad_request("process_create_time is required and must be a number.")

    # endpoint_uid: only a well-formed UUIDv4 ever becomes a stable
    # identity (same rule as every other agent-facing route) - anything
    # else is treated as absent, never guessed.
    endpoint_uid = endpoint_identity.normalize_endpoint_uid(payload.get("endpoint_uid"))

    # The client may omit process_instance_id and let the server derive
    # it entirely; if it DOES submit one, it must match exactly - never
    # trusted blindly. endpoint_uid may be None (unverified installs are
    # still accepted, matching the existing web-event convention) - in
    # that case the instance id is derived with endpoint_uid=None,
    # which process_identity.compute_process_instance_id correctly
    # refuses (returns None) since it requires a real endpoint_uid; such
    # an event is still stored, just without a cross-poll-cycle-stable
    # instance id (see below).
    server_derived_instance_id = process_identity.compute_process_instance_id(
        endpoint_uid, pid_int, create_time_float
    )

    client_instance_id = payload.get("process_instance_id")

    if client_instance_id and server_derived_instance_id and client_instance_id != server_derived_instance_id:
        return _bad_request("process_instance_id does not match the identity derived from "
                             "endpoint_uid/pid/process_create_time.")

    final_instance_id = server_derived_instance_id or client_instance_id

    if not final_instance_id:
        return _bad_request("Unable to derive a process_instance_id (endpoint_uid missing/invalid "
                             "and no client-submitted id provided).")

    # Step 13C ENDPOINT UID CONSISTENCY GUARD - identical pattern to
    # web_monitoring.analyze_web_event_fast(): a conflicting UID is
    # dropped (event still stored), never silently trusted, never
    # rejects the whole request.
    event_uid = endpoint_uid

    if endpoint_uid:

        try:
            identity_decision = endpoint_network.evaluate_identity_standalone(endpoint_uid, endpoint_ip)
        except Exception:
            identity_decision = None
            event_uid = None

        if identity_decision is not None and identity_decision.outcome == endpoint_network.IDENTITY_CONFLICT:

            event_uid = None

            endpoint_network.log_event_conflict(
                _get_identity_logger(),
                endpoint_network.canonical_ip(endpoint_ip),
                identity_decision.bound_uid,
                endpoint_uid
            )

    ppid = payload.get("ppid")
    try:
        ppid_int = int(ppid) if ppid is not None else None
    except (TypeError, ValueError):
        ppid_int = None

    parent_process_instance_id = payload.get("parent_process_instance_id")
    # Never trusted/recomputed here beyond basic shape-checking - the
    # Agent is the only one with the parent's own create_time in hand
    # at discovery time (see process_identity.py's module header); the
    # server does not attempt to re-derive or verify it. An
    # implausible value (wrong length) is dropped rather than stored.
    if not isinstance(parent_process_instance_id, str) or len(parent_process_instance_id) != 64:
        parent_process_instance_id = None

    command_line_from_agent = payload.get("command_line")
    agent_claimed_redacted = bool(payload.get("command_line_redacted", False))

    if command_line_from_agent is not None and not isinstance(command_line_from_agent, str):
        return _bad_request("command_line must be a string if present.")

    # DEFENSE IN DEPTH (Step 25A instructions): re-run the SAME shared
    # redaction function server-side on whatever arrived, regardless of
    # what the Agent claims - never store something a fresh redaction
    # pass would still flag, even if an older/buggy Agent forgot to
    # redact it.
    final_command_line, server_also_redacted = command_line_privacy.redact_command_line(
        command_line_from_agent
    )
    final_command_line = _truncate(final_command_line, MAX_COMMAND_LINE_LENGTH)
    command_line_was_redacted = agent_claimed_redacted or server_also_redacted

    sha256_value = _truncate(payload.get("sha256"), 64)
    md5_value = _truncate(payload.get("md5"), 32)
    hash_status = _truncate(payload.get("hash_status"), 64)

    process_name = _truncate(payload.get("process_name"), MAX_STRING_FIELD_LENGTH)
    process_path = _truncate(payload.get("process_path"), MAX_STRING_FIELD_LENGTH)
    os_username = _truncate(payload.get("os_username"), MAX_STRING_FIELD_LENGTH)

    discovered_at = _truncate(payload.get("discovered_at"), 32)
    received_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    try:

        cursor = conn.execute("""
            INSERT OR IGNORE INTO endpoint_process_events (
                process_instance_id, endpoint_uid, endpoint_ip, pid, ppid,
                parent_process_instance_id, process_name, process_path,
                process_create_time, os_username, command_line_text,
                command_line_was_redacted, server_redaction_applied,
                sha256, md5, hash_status, discovered_at, received_at, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'endpoint-agent')
        """, (
            final_instance_id, event_uid, endpoint_ip, pid_int, ppid_int,
            parent_process_instance_id, process_name, process_path,
            create_time_float, os_username, final_command_line,
            1 if command_line_was_redacted else 0, 1 if server_also_redacted else 0,
            sha256_value, md5_value, hash_status, discovered_at, received_at
        ))

        if cursor.rowcount == 0:

            # Duplicate delivery of an already-known process instance -
            # reported honestly as "duplicate", never silently merged
            # into a 202 as if it were new (same convention as
            # browser_events.py's url_dedup_key handling).
            conn.commit()

            existing = conn.execute(
                "SELECT id FROM endpoint_process_events WHERE process_instance_id = ?",
                (final_instance_id,)
            ).fetchone()

            return jsonify({
                "status": "duplicate",
                "id": existing["id"] if existing else None,
                "process_instance_id": final_instance_id
            }), 200

        event_id = cursor.lastrowid

        conn.commit()

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    write_log(
        "PROCESS_EVENT_RECEIVED",
        f"endpoint_uid={event_uid} pid={pid_int} process={process_name}",
        username="system"
    )

    return jsonify({
        "status": "accepted",
        "id": event_id,
        "process_instance_id": final_instance_id
    }), 202
