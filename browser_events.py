# ==================================================
# STEP 24A: BROWSER-EXTENSION URL EVENT INGESTION
# ==================================================
#
# POST /api/browser-events
#   Agent-authenticated - the EXACT SAME shared-secret check as
#   /api/web-events (web_monitoring._agent_auth_error(): X-Agent-Key
#   header compared against AGENT_API_KEY via hmac.compare_digest).
#   The HTTP caller of this route is always the Endpoint Agent itself
#   (endpoint_agent_stable.py's new local listener - see
#   browser_agent_bridge.py) forwarding an event it already received,
#   over a SEPARATE local-only channel, from browser_native_host.py.
#   Neither the browser extension nor the native host ever sees or
#   holds AGENT_API_KEY, and neither ever calls this route directly.
#
#   Stores one new row per browser navigation in the EXISTING
#   web_events table, using only additive/nullable columns (see
#   init_web_monitoring_db() in web_monitoring.py). source is always
#   'browser-extension' and analysis_status is always 'COLLECTED' -
#   a value that web_event_worker.py's and threat_intel_worker.py's
#   claim queries never match (both require
#   analysis_status='PENDING' AND source='endpoint-agent'). This is a
#   structural, not conventional, guarantee that Step 24A cannot
#   change Legacy/Shadow/risk-scoring/alert-creation behavior: these
#   rows are simply invisible to every one of those query paths until
#   a separately-approved later step explicitly wires them in.
#
#   Response codes:
#     202 accepted            new row stored
#     200 duplicate           dedup key already existed - not an error
#     400 malformed/missing/invalid field
#     401 bad X-Agent-Key     503 agent authentication not configured
#     429 rate limited (per endpoint_uid, in-memory, process-local)

import hashlib
import time

from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request

import endpoint_identity

from web_monitoring import (
    get_db_connection,
    _agent_auth_error,
    write_log
)

browser_events_bp = Blueprint("browser_events", __name__)

MAX_URL_LENGTH = 2048

ALLOWED_BROWSERS = ("chrome", "edge")

# The browser's own webNavigation transitionType vocabulary (Chrome/Edge
# extension API docs) plus "unknown" as a safe fallback for anything this
# server has not been told about yet - never rejected, just normalized.
ALLOWED_NAV_TYPES = (
    "link", "typed", "auto_bookmark", "auto_subframe", "manual_subframe",
    "generated", "start_page", "form_submit", "reload", "keyword",
    "keyword_generated", "unknown"
)

RATE_LIMIT_WINDOW_SECONDS = 60

# Generous headroom for rapid tab navigation (Step 24A test scenario
# "rapid navigation between pages") while still bounding a misbehaving
# or compromised installation from flooding the server.
RATE_LIMIT_MAX_EVENTS_PER_WINDOW = 120

# endpoint_uid -> list[float monotonic timestamps within the window].
# Process-local, in-memory, intentionally not persisted - a restart
# simply resets everyone's budget, which is acceptable for a rate
# limit (unlike the dedup key, which IS persisted, in the database).
_rate_limit_buckets = {}

# Defensive cap so a very large number of distinct endpoint_uids could
# never grow this dict unboundedly in a long-running process.
_RATE_LIMIT_MAX_TRACKED_ENDPOINTS = 1000


def _rate_limited(endpoint_uid):

    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    bucket = _rate_limit_buckets.setdefault(endpoint_uid, [])

    while bucket and bucket[0] < cutoff:
        bucket.pop(0)

    if len(bucket) >= RATE_LIMIT_MAX_EVENTS_PER_WINDOW:
        return True

    bucket.append(now)

    if len(_rate_limit_buckets) > _RATE_LIMIT_MAX_TRACKED_ENDPOINTS:
        _rate_limit_buckets.pop(next(iter(_rate_limit_buckets)))

    return False


def _extract_hostname(url):
    """
    Pure, local hostname extraction - deliberately NOT
    web_monitoring.normalize_destination(), which performs a REAL,
    SYNCHRONOUS socket.getaddrinfo() DNS resolution as part of
    normalizing a TCP-path destination. A browser-reported URL event
    must never trigger a live DNS lookup from inside this request
    handler (slow, network-dependent, and out of scope - Step 24A
    explicitly defers any Threat-Intelligence/resolution integration
    for URL events to a separately approved later step). Returns the
    lowercase hostname, or None if the URL has no parseable host.
    """

    try:
        parsed = urlparse(url)
    except ValueError:
        return None

    host = parsed.hostname

    if not host:
        return None

    return host.lower().strip(".")


def _resolve_endpoint_ip(conn, endpoint_uid):
    """
    Best-effort, honest lookup of the last IP address seen for this
    stable endpoint identifier - never fabricated. Checked against the
    endpoints table first (populated by heartbeats/TCP events), then
    against web_events itself (a machine that has only ever sent
    browser events but no heartbeat yet). '0.0.0.0' - clearly a
    placeholder, never a real routable address - is the last resort.
    """

    row = conn.execute(
        """
            SELECT ip_address
            FROM endpoints
            WHERE endpoint_uid = ?
            ORDER BY last_seen DESC
            LIMIT 1
        """,
        (endpoint_uid,)
    ).fetchone()

    if row and row["ip_address"]:
        return row["ip_address"]

    row = conn.execute(
        """
            SELECT endpoint_ip
            FROM web_events
            WHERE endpoint_uid = ? AND endpoint_ip IS NOT NULL AND endpoint_ip != '0.0.0.0'
            ORDER BY id DESC
            LIMIT 1
        """,
        (endpoint_uid,)
    ).fetchone()

    if row and row["endpoint_ip"]:
        return row["endpoint_ip"]

    return "0.0.0.0"


@browser_events_bp.route("/api/browser-events", methods=["POST"])
def receive_browser_event():

    auth_error = _agent_auth_error()

    if auth_error:
        return auth_error

    if not request.is_json:
        return jsonify({
            "status": "error",
            "message": "Request body must be JSON."
        }), 400

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "status": "error",
            "message": "Request body must be a JSON object."
        }), 400

    endpoint_uid = endpoint_identity.normalize_endpoint_uid(
        data.get("endpoint_uid")
    )

    if not endpoint_uid:
        return jsonify({
            "status": "error",
            "message": "endpoint_uid is required and must be a valid UUIDv4."
        }), 400

    browser_name = str(data.get("browser_name") or "").strip().lower()

    if browser_name not in ALLOWED_BROWSERS:
        return jsonify({
            "status": "error",
            "message": "browser_name must be one of: " + ", ".join(ALLOWED_BROWSERS)
        }), 400

    raw_url = data.get("url")

    if not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({
            "status": "error",
            "message": "url is required."
        }), 400

    raw_url = raw_url.strip()

    if len(raw_url) > MAX_URL_LENGTH:
        return jsonify({
            "status": "error",
            "message": f"url exceeds the maximum allowed length ({MAX_URL_LENGTH})."
        }), 400

    # Step 24A section 3: only http(s) is ever collected - the extension
    # already filters chrome://, edge://, file://, etc. before sending,
    # but the server independently refuses anything else too (defense in
    # depth - never trust a single layer for a privacy boundary).
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        return jsonify({
            "status": "error",
            "message": "Only http:// and https:// URLs are accepted."
        }), 400

    # Step 24A section 3: enforced server-side, independently of what the
    # extension claims via url_redacted below. Once the query string/
    # fragment are stripped (origin + pathname only), a '?' or '#' can
    # never legitimately appear in what is left - their presence means
    # redaction did NOT happen as expected, and the event is refused
    # rather than stored with an unverified privacy claim.
    if "?" in raw_url or "#" in raw_url:
        return jsonify({
            "status": "error",
            "message": "url must not contain a query string or fragment - strip it before sending."
        }), 400

    host = _extract_hostname(raw_url)

    if not host:
        return jsonify({
            "status": "error",
            "message": "Could not identify the destination host in the URL."
        }), 400

    nav_type = str(data.get("nav_type") or "unknown").strip().lower()

    if nav_type not in ALLOWED_NAV_TYPES:
        nav_type = "unknown"

    raw_redacted = data.get("url_redacted")

    if not isinstance(raw_redacted, bool):
        return jsonify({
            "status": "error",
            "message": "url_redacted is required and must be a boolean."
        }), 400

    url_redacted = 1 if raw_redacted else 0

    timestamp_ms = data.get("timestamp_ms")

    if (
        not isinstance(timestamp_ms, int)
        or isinstance(timestamp_ms, bool)
        or timestamp_ms <= 0
    ):
        return jsonify({
            "status": "error",
            "message": "timestamp_ms is required and must be a positive integer."
        }), 400

    if _rate_limited(endpoint_uid):
        return jsonify({
            "status": "error",
            "message": "Rate limit exceeded for this endpoint."
        }), 429

    # Identifies ONE specific navigation: the same endpoint, the same
    # browser, the same (already-redacted) URL, reported at the same
    # client-side millisecond timestamp. A genuine duplicate delivery
    # (retry after a dropped reply, a restarted native host re-sending
    # a queued item) repeats this exact tuple; two distinct navigations
    # to the same URL seconds apart do not.
    dedup_key = hashlib.sha256(
        f"{endpoint_uid}|{browser_name}|{raw_url}|{timestamp_ms}".encode("utf-8")
    ).hexdigest()

    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    try:

        endpoint_ip = _resolve_endpoint_ip(conn, endpoint_uid)

        cursor = conn.execute("""
            INSERT OR IGNORE INTO web_events (
                event_time, endpoint_ip, process_name, destination, domain,
                resolved_ip, risk_score, severity, decision, username, details,
                analysis_status, source, endpoint_uid,
                url, url_source, url_redacted, browser_name, url_nav_type,
                url_dedup_key
            )
            VALUES (
                ?, ?, NULL, ?, ?,
                NULL, 0, 'INFO', 'COLLECTED', NULL, NULL,
                'COLLECTED', 'browser-extension', ?,
                ?, 'browser_extension', ?, ?, ?,
                ?
            )
        """, (
            event_time, endpoint_ip, host, host,
            endpoint_uid,
            raw_url, url_redacted, browser_name, nav_type,
            dedup_key
        ))

        if cursor.rowcount == 0:

            # The UNIQUE index on url_dedup_key rejected this insert -
            # a duplicate delivery of a navigation already stored.
            # Reported honestly as "duplicate", never silently merged
            # into a 202 as if it were new.
            existing = conn.execute(
                "SELECT id FROM web_events WHERE url_dedup_key = ?",
                (dedup_key,)
            ).fetchone()

            conn.close()

            return jsonify({
                "status": "duplicate",
                "event_id": existing["id"] if existing else None
            }), 200

        event_id = cursor.lastrowid

        conn.commit()
        conn.close()

    except Exception:

        conn.close()
        raise

    write_log(
        "BROWSER_URL_EVENT",
        f"endpoint_uid={endpoint_uid} browser={browser_name} host={host}",
        username="system"
    )

    return jsonify({
        "status": "accepted",
        "event_id": event_id,
        "analysis_status": "COLLECTED"
    }), 202
