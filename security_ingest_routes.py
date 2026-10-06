# ==================================================
# PHASE 13B: SECURITY INGEST ROUTE + READ-ONLY DATA PAGE
# ==================================================
#
# POST /api/security-ingest
#   Machine-authenticated (X-Sensor-Id + X-Sensor-Key). No browser session, no
#   cookies, no CSRF token (csrf.exempt is applied in app.py ONLY because the
#   route is authenticated by a per-sensor secret, not by ambient credentials).
#   JSON only; single record or {"records": [...]}; <= 512 KB; <= 100 records.
#
#   202 all ACCEPTED/DUPLICATE   207 mixed   422 all REJECTED
#   400 malformed envelope   401 uniform authentication failure
#   413 too large   415 not JSON   429 rate limited (Retry-After)
#   503 storage busy (Retry-After) OR sensor authentication not configured
#   500 generic - never a stack trace, never an echo of the input.
#
# GET /security-data
#   Administrator-only, read-only, bounded, not linked from navigation. Shows
#   sensors ("Last data received" - never "healthy") and the latest normalized
#   records with explicit UTC labels. Everything is autoescaped.

import ipaddress
import json
import os

from datetime import timedelta

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge

import security_contract as sc
import security_detections as sd
import security_ingest as si
import security_resolution
import security_sensors
import telemetry_store

security_ingest_bp = Blueprint("security_ingest", __name__)

MAX_BODY_BYTES = 512 * 1024

_sensor_limiter = si.make_sensor_limiter()
_failure_throttle = si.FailureThrottle()


MAX_TRUSTED_PROXY_HOPS = 5


def trusted_proxy_hops():

    # SECURITY_TRUSTED_PROXY_HOPS = number of reverse proxies in FRONT of this application that
    # append to X-Forwarded-For. DEFAULT 0 (unset/invalid/negative): X-Forwarded-For is IGNORED
    # and the client address is the TCP peer, exactly as before. Read per request.
    try:
        hops = int(os.getenv("SECURITY_TRUSTED_PROXY_HOPS", "").strip() or "0")
    except ValueError:
        return 0

    return hops if 0 < hops <= MAX_TRUSTED_PROXY_HOPS else 0


def client_addr():

    # The address used for failed-authentication throttling and the ingest log. With hops = N the
    # client is the N-th entry counted from the RIGHT of X-Forwarded-For (the entries a client
    # itself supplies are on the left and are never trusted). Anything malformed, too short or not
    # an IP falls back to the TCP peer - a spoofed header can never choose its own address.
    remote = request.remote_addr or "unknown"
    hops = trusted_proxy_hops()

    if hops == 0:
        return remote

    parts = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]

    if len(parts) < hops:
        return remote

    candidate = parts[-hops]

    if "%" in candidate or len(candidate) > 45:
        return remote

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return remote


def _reply(payload, status, retry_after=None):

    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"

    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)

    return response


def _error(status, message, retry_after=None):
    return _reply({"status": "error", "message": message}, status, retry_after)


def _reject_json_constant(name):
    raise ValueError("non-finite JSON constant")


@security_ingest_bp.route("/api/security-ingest", methods=["POST"])
def security_ingest():

    remote = client_addr()

    # ---- fail closed if credential verification is unavailable ----
    config_code = security_sensors.config_error_code()

    if config_code is not None:

        si.security_log("config_error", code=config_code)

        return _error(503, "Sensor authentication is not configured on this server.")

    if _failure_throttle.blocked(remote):
        return _error(429, "Too many failed attempts.", retry_after=60)

    # ---- authentication (uniform failure; the secret is never logged) ----
    sensor_id = request.headers.get("X-Sensor-Id", "")
    secret = request.headers.get("X-Sensor-Key", "")

    try:
        sensor = security_sensors.authenticate(sensor_id, secret)
    except security_sensors.CredentialConfigError:
        return _error(503, "Sensor authentication is not configured on this server.")

    if sensor is None:

        _failure_throttle.record_failure(remote)
        # The claimed id is logged only if it is a well-formed identifier;
        # anything else is attacker text and is omitted entirely.
        claimed = sensor_id if sc.SENSOR_ID_RE.match(sensor_id or "") else None
        si.security_log("auth_failure", sensor_id=claimed, remote_addr=remote)

        return _error(401, "Unauthorized")

    if not _sensor_limiter.allow(sensor.sensor_id):
        return _error(429, "Rate limit exceeded.", retry_after=1)

    # ---- envelope ----
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
        payload = json.loads(body.decode("utf-8"), parse_constant=_reject_json_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return _error(400, "Invalid JSON.")

    if not isinstance(payload, dict):
        return _error(400, "Body must be a JSON object.")

    if "records" in payload:

        if set(payload) != {"records"} or not isinstance(payload["records"], list):
            return _error(400, "Invalid batch envelope.")

        records = payload["records"]

    else:
        records = [payload]

    if not records or len(records) > si.MAX_BATCH_RECORDS:
        return _error(400, f"A request must carry 1 to {si.MAX_BATCH_RECORDS} records.")

    # ---- ingestion ----
    try:
        result = si.ingest_batch(sensor, records)

    except si.StorageBusy:
        return _error(503, "Storage busy; retry.", retry_after=2)

    except si.BatchTooLarge:
        return _error(400, "Invalid batch.")

    except Exception as exc:
        # Class name only: exception text could contain record data.
        si.security_log("internal_error", sensor_id=sensor.sensor_id, code=type(exc).__name__)
        return _error(500, "Internal error.")

    status = result.http_status()

    return _reply({
        "status": "ok" if status == 202 else ("partial" if status == 207 else "rejected"),
        "accepted": result.accepted,
        "duplicates": result.duplicates,
        "rejected": result.rejected,
        "resolution": result.resolution_counts,
        "results": result.results,
    }, status)


@security_ingest_bp.route("/security-data")
def security_data():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access denied - Administrator only", 403

    now = sc.utc_now()

    filters, notes = _parse_filters(request.args)

    start = sc.format_utc(now - timedelta(hours=filters["hours"]))
    end = sc.format_utc(now + timedelta(seconds=sc.max_future_seconds()))

    sensors = security_sensors.list_sensors()

    detections = sd.query_detections(start, end, sensor_id=filters["sensor"],
                                     source_engine=filters["engine"], limit=filters["limit"])
    observations = telemetry_store.query_observations(start, end, sensor_id=filters["sensor"],
                                                      source_engine=filters["engine"], limit=filters["limit"])

    for row in detections:
        _decorate(row)

    for row in observations:
        _decorate(row)
        row["summary"] = _observation_summary(row["_meta"])

    # Factual count of the rows SHOWN below (bounded by the row limit) - not a total.
    type_counts = {}

    for row in observations:
        kind = row["_meta"].get("eve_type") or "other"
        type_counts[kind] = type_counts.get(kind, 0) + 1

    network_config = security_resolution.config_status()

    if network_config["error"]:
        notes.append("Monitored-network setting is INVALID and was rejected: endpoint resolution for network "
                     "sensors is disabled until it is corrected.")

    detail = None

    if filters["detail"] is not None:

        detail = sd.get_detection(filters["detail"])

        if detail is None:
            notes.append("Detection not found.")
        else:
            _decorate(detail)

    return render_template(
        "security_data.html",
        sensors=sensors,
        engines=sorted({s["source_engine"] for s in sensors}),
        detections=detections,
        observations=observations,
        detail=detail,
        type_counts=sorted(type_counts.items()),
        network_config=network_config,
        filters=filters,
        notes=notes,
        window_start=start,
        window_end=end,
        credentials_configured=security_sensors.credentials_available(),
    )


# --------------------------------------------------
# /security-data VIEW HELPERS (read-only; everything rendered is autoescaped)
# --------------------------------------------------

_HOURS_CHOICES = (1, 6, 24, 72, 168)
_PAGE_LIMIT_DEFAULT = 50
_PAGE_LIMIT_MAX = 200


def _parse_filters(args):

    # Bounded, whitelisted query parameters. An invalid value is IGNORED (and
    # reported on the page) - it never reaches SQL and never causes a 500.
    filters = {"engine": None, "sensor": None, "hours": 24, "limit": _PAGE_LIMIT_DEFAULT, "detail": None}
    notes = []

    engine = args.get("engine", "").strip()

    if engine:
        if sd.ENGINE_NAME_RE.match(engine):
            filters["engine"] = engine
        else:
            notes.append("Invalid engine filter ignored.")

    sensor = args.get("sensor", "").strip()

    if sensor:
        if sc.SENSOR_ID_RE.match(sensor):
            filters["sensor"] = sensor
        else:
            notes.append("Invalid sensor filter ignored.")

    hours = args.get("hours", "").strip()

    if hours:
        if hours.isdigit() and int(hours) in _HOURS_CHOICES:
            filters["hours"] = int(hours)
        else:
            notes.append("Invalid time window ignored (allowed hours: 1, 6, 24, 72, 168).")

    limit = args.get("limit", "").strip()

    if limit:
        if limit.isdigit() and 1 <= int(limit) <= _PAGE_LIMIT_MAX:
            filters["limit"] = int(limit)
        else:
            notes.append(f"Invalid limit ignored (1-{_PAGE_LIMIT_MAX}).")

    detail = args.get("detail", "").strip()

    if detail:
        if detail.isdigit() and len(detail) <= 15 and int(detail) > 0:
            filters["detail"] = int(detail)
        else:
            notes.append("Invalid detection id ignored.")

    return filters, notes


def _flatten(value, prefix="", depth=0, out=None):

    out = [] if out is None else out

    if len(out) >= 48:
        return out

    if isinstance(value, dict):
        for key in sorted(value):
            _flatten(value[key], f"{prefix}{key}." if depth < 3 else f"{prefix}{key}.", depth + 1, out)
    elif isinstance(value, list):
        out.append((prefix.rstrip("."), ", ".join(str(v)[:120] for v in value[:16])))
    else:
        out.append((prefix.rstrip("."), str(value)[:300]))

    return out


def _decorate(row):

    # Adds view-only keys: parsed metadata (sensor-supplied, shown as inert text),
    # the platform-owned resolution provenance, and flat key/value pairs.
    try:
        meta = json.loads(row.get("metadata_json") or "{}")
        if not isinstance(meta, dict):
            meta = {}
    except ValueError:
        meta = {}

    platform = meta.pop("platform", None)
    context = platform.get("endpoint_context") if isinstance(platform, dict) else None

    row["_meta"] = meta
    row["meta_pairs"] = _flatten(meta) if meta else []
    row["resolution_context"] = _context_lines(context) if isinstance(context, dict) else []


def _context_lines(context):

    lines = []

    side = context.get("side")

    if side == "both":
        for label in ("src", "dst"):
            part = context.get(label)
            if isinstance(part, dict):
                text = str(part.get("status", "?"))
                if part.get("uid"):
                    text += f" ({part['uid']})"
                lines.append(f"{label}: {text}")
    else:
        lines.append(f"{side}: {context.get('status', '?')}" + (f" ({context['uid']})" if context.get("uid") else ""))

    lines.append(f"policy: {context.get('policy', '?')}")

    return lines


def _observation_summary(meta):

    # A short factual line per EVE-derived observation (names, sizes - no scores).
    kind = meta.get("eve_type")

    if kind == "dns":
        queries = "; ".join(str(q) for q in (meta.get("dns_queries") or [])[:2])
        answers = "; ".join(str(a) for a in (meta.get("dns_answers") or [])[:3])
        return f"DNS {meta.get('dns_rcode', '')} {queries} -> {answers}".strip()

    if kind == "tls":
        return f"TLS {meta.get('tls_version', '')} SNI {meta.get('tls_sni', '-')}".strip()

    if kind == "flow":
        return (f"Flow {meta.get('bytes_toserver', 0)}/{meta.get('bytes_toclient', 0)} bytes "
                f"(to server/to client), age {meta.get('age', '-')} s"
                + (", alerted" if meta.get("alerted") else ""))

    if kind == "http":
        return (f"HTTP {meta.get('http_method', '')} {meta.get('http_hostname', '-')}"
                f"{meta.get('http_path', '')} -> {meta.get('http_status', '-')}"
                + (" (path redacted)" if meta.get("http_path_redacted") else ""))

    if kind == "fileinfo":
        return (f"File {meta.get('file_name', '-')} ({meta.get('file_size', '-')} bytes) "
                f"sha256={meta.get('file_sha256') or 'unavailable'}")

    if kind == "anomaly":
        return f"Anomaly {meta.get('anomaly_type', '')}: {meta.get('anomaly_event', '-')}"

    if kind == "ssh":
        return (f"SSH client={meta.get('ssh_client_software', '-')} "
                f"server={meta.get('ssh_server_software', '-')}")

    return ""
