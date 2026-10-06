import ipaddress
import os
import db_config
import sqlite3

from datetime import datetime, timedelta

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from threat_intelligence import (
    analyze_ip_reputation
)

from reputation_routes import (
    get_cached_result,
    save_reputation_result,
    create_reputation_incident,
    local_ioc_exists
)

# Phase 14C Workstream B3: read-only Suricata network-telemetry view, reusing the
# proven /security-data query/decorate pattern (security_ingest_routes.py). This
# adds NO new table and writes NOTHING; it only reads security_detections and the
# telemetry_store observations via their existing bounded query helpers.
import security_contract as sc
import security_detections as sd
import security_sensors
import telemetry_store
from security_ingest_routes import _decorate, _observation_summary


# SOC_DB_PATH (optional): see app.py's identical override for the
# full rationale.
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


network_events_bp = Blueprint(
    "network_events",
    __name__
)


# ==================================================
# DATABASE
# ==================================================

def get_db_connection():

    # Phase 12B.6C.1: central policy (WAL, busy timeout, synchronous=FULL,
    # tracked so a request/iteration can always release it).
    return db_config.open_connection(DB_NAME)


def init_network_events_db():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            description TEXT,
            username TEXT
        )
    """)

    conn.commit()

    conn.close()


# ==================================================
# HELPERS
# ==================================================

def login_required():

    return "user_id" in session


def is_valid_ip(ip_address):

    try:

        ipaddress.ip_address(
            ip_address
        )

        return True

    except ValueError:

        return False


def is_public_ip(ip_address):

    try:

        ip = ipaddress.ip_address(
            ip_address
        )

        return ip.is_global

    except ValueError:

        return False


def write_log(
    event_type,
    message,
    target_ip=None
):

    conn = get_db_connection()

    log_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
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
        session.get(
            "username",
            "anonymous"
        ),
        message
    ))

    conn.commit()

    conn.close()


# ==================================================
# AUTOMATIC THREAT ENRICHMENT
# ==================================================

def enrich_ip(ip_address):

    cached = get_cached_result(
        ip_address
    )

    if cached:

        cached["automatic"] = True

        incident_created = (
            create_reputation_incident(
                cached
            )
        )

        return (
            cached,
            incident_created
        )

    local_ioc = local_ioc_exists(
        ip_address
    )

    result = analyze_ip_reputation(
        ip_address,
        local_ioc
    )

    if result.get(
        "error"
    ):

        return (
            result,
            False
        )

    result["cached"] = False
    result["automatic"] = True

    result = save_reputation_result(
        result
    )

    incident_created = (
        create_reputation_incident(
            result
        )
    )

    return (
        result,
        incident_created
    )


# ==================================================
# SURICATA NETWORK TELEMETRY (Phase 14C Workstream B3)
# ==================================================
#
# Read-only presentation-layer merge of two EXISTING, already-tested sources:
#   security_detections  (Suricata "alert" records - DETECTION)
#   telemetry_store       (Suricata dns/tls/bounded-flow records - OBSERVATION)
# No new table is created and no schema changes. Both sources are queried with
# their existing bounded/indexed helpers (mandatory time window, capped limit);
# nothing here can load unbounded history into memory. Only an explicit
# allow-list of metadata_json fields is ever rendered - never the raw blob,
# never payload/packet/HTTP-body/header/certificate content (the adapter never
# forwards those; this is defense in depth on top of that contract).

SURICATA_ENGINE = "suricata"

_NE_KIND_CHOICES = ("all", "alerts", "telemetry")
_NE_HOURS_CHOICES = (1, 6, 24, 72, 168)
_NE_LIMIT_DEFAULT = 50
_NE_LIMIT_MAX = 200

# Explicit per-event-type allow-list for the OPTIONAL metadata disclosure.
# Nothing outside this list is ever shown, regardless of what a future
# adapter version might add to metadata_json.
_NE_META_ALLOW = {
    "alert": ("app_proto", "in_iface", "gid", "rev", "tx_id", "flow_id", "rule_metadata"),
    "dns": ("dns_type", "dns_rcode", "dns_queries", "dns_answers", "app_proto", "flow_id"),
    "tls": ("tls_sni", "tls_version", "tls_subject", "tls_issuer", "tls_ja3", "tls_ja4",
            "tls_client_alpn", "tls_server_alpn", "app_proto", "flow_id"),
    "flow": ("app_proto", "age", "pkts_toserver", "pkts_toclient", "bytes_toserver",
             "bytes_toclient", "state", "reason", "alerted", "flow_id"),
}

# Defense in depth: even an allow-listed key is dropped if its name looks
# sensitive (the adapter never produces these under the current contract).
_NE_META_FORBIDDEN = ("payload", "packet", "http_body", "header", "certificate",
                      "chain", "cookie", "credential", "secret", "token", "password", "auth")


def _ne_allowed_meta_pairs(meta, event_key):

    pairs = []

    for key in _NE_META_ALLOW.get(event_key, ()):

        if key not in meta or any(bad in key.lower() for bad in _NE_META_FORBIDDEN):
            continue

        value = meta[key]

        if isinstance(value, list):
            text = ", ".join(str(v)[:120] for v in value[:8])
        else:
            text = str(value)[:300]

        pairs.append((key, text))

    return pairs


def _ne_parse_filters(args):

    # Whitelisted, bounded query-string filters - same discipline as
    # security_ingest_routes._parse_filters: an invalid value is IGNORED (and
    # reported on the page), never reaches SQL, never causes a 500.
    filters = {"sensor": None, "hours": 24, "limit": _NE_LIMIT_DEFAULT, "kind": "all", "ip": None}
    notes = []

    sensor = args.get("sensor", "").strip()

    if sensor:
        if sc.SENSOR_ID_RE.match(sensor):
            filters["sensor"] = sensor
        else:
            notes.append("Invalid sensor filter ignored.")

    kind = args.get("kind", "").strip()

    if kind:
        if kind in _NE_KIND_CHOICES:
            filters["kind"] = kind
        else:
            notes.append("Invalid kind filter ignored.")

    hours = args.get("hours", "").strip()

    if hours:
        if hours.isdigit() and int(hours) in _NE_HOURS_CHOICES:
            filters["hours"] = int(hours)
        else:
            notes.append("Invalid time window ignored (allowed hours: 1, 6, 24, 72, 168).")

    limit = args.get("limit", "").strip()

    if limit:
        if limit.isdigit() and 1 <= int(limit) <= _NE_LIMIT_MAX:
            filters["limit"] = int(limit)
        else:
            notes.append(f"Invalid limit ignored (1-{_NE_LIMIT_MAX}).")

    ip = args.get("ip", "").strip()

    if ip:
        try:
            filters["ip"] = str(ipaddress.ip_address(ip))
        except ValueError:
            notes.append("Invalid IP filter ignored.")

    return filters, notes


def _ne_format_time(observed_at):

    # STEP B3.3 (UI polish only): splits the existing stored UTC timestamp into
    # a compact two-line "22 Sep 2026" / "00:31:21 UTC" display for the
    # template. Purely presentational - observed_at itself is returned
    # unchanged by the caller and is what the template puts in the tooltip;
    # nothing stored, queried or compared uses this. Never raises: falls back
    # to the raw string (unsplit) if it cannot be parsed as a UTC timestamp.
    moment = sc.parse_utc(observed_at) if isinstance(observed_at, str) else None

    if moment is None:
        return observed_at or "", ""

    return moment.strftime("%d %b %Y"), moment.strftime("%H:%M:%S UTC")


def _ne_alert_summary(row):

    parts = []

    if row.get("rule_category"):
        parts.append(row["rule_category"])

    if row.get("source_action"):
        parts.append("action=" + row["source_action"])

    if row.get("independence_group"):
        parts.append(row["independence_group"])

    return " | ".join(parts)


def _ne_normalize(row, kind):

    # _decorate (imported from security_ingest_routes, the proven /security-data
    # helper) defensively parses metadata_json and separates the platform-owned
    # resolution context; it never raises on malformed metadata.
    _decorate(row)

    meta = row.get("_meta") or {}

    if kind == "alert":
        event_key = "alert"
        event_type = "Alert"
        summary = _ne_alert_summary(row)
        rule_id = row.get("rule_id")
        rule_name = row.get("rule_name")
        severity = row.get("source_severity")
    else:
        event_key = meta.get("eve_type") or "telemetry"
        event_type = event_key.upper()
        summary = _observation_summary(meta)
        rule_id = None
        rule_name = None
        severity = None

    observed_date, observed_time = _ne_format_time(row.get("observed_at"))

    return {
        "kind": kind,
        "event_type": event_type,
        "observed_at": row.get("observed_at"),
        "observed_date": observed_date,
        "observed_time": observed_time,
        "ingested_at": row.get("ingested_at"),
        "sensor_id": row.get("sensor_id"),
        "src_ip": row.get("src_ip"),
        "src_port": row.get("src_port"),
        "dst_ip": row.get("dst_ip"),
        "dst_port": row.get("dst_port"),
        "protocol": row.get("protocol"),
        "endpoint_uid": row.get("endpoint_uid"),
        "endpoint_resolution": row.get("endpoint_resolution"),
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "summary": summary,
        "meta_pairs": _ne_allowed_meta_pairs(meta, event_key),
    }


def query_suricata_network_events(filters, now=None):

    # Read-only. Merges security_detections + telemetry_store ONLY in this
    # presentation layer - nothing is written, nothing new is stored. Both
    # sources are queried through their existing bounded/indexed helpers
    # (mandatory time window, capped limit): no unbounded scan is possible.
    notes = []
    now = now or sc.utc_now()

    start = sc.format_utc(now - timedelta(hours=filters["hours"]))
    end = sc.format_utc(now + timedelta(seconds=sc.max_future_seconds()))

    limit = filters["limit"]
    ip = filters["ip"]
    kind = filters["kind"]

    want_alerts = kind in ("all", "alerts")
    want_telemetry = kind in ("all", "telemetry")

    if ip is not None and want_alerts:
        # security_detections.query_detections() has no IP parameter. Filtering
        # it after a bounded fetch would be a misleading partial filter over an
        # already-truncated result set, so alert rows are OMITTED (not silently
        # unfiltered) while an IP filter is active, and this is stated on the page.
        want_alerts = False
        notes.append("IP filtering is supported for telemetry (DNS/TLS/flow) records only; "
                     "alert results are omitted while an IP filter is active.")

    rows = []

    if want_alerts:

        try:
            detections = sd.query_detections(start, end, sensor_id=filters["sensor"],
                                             source_engine=SURICATA_ENGINE, limit=limit)
        except sd.QueryError as exc:
            detections = []
            notes.append(f"Detection query rejected: {exc}")

        rows.extend(_ne_normalize(row, "alert") for row in detections)

    if want_telemetry:

        try:
            observations = telemetry_store.query_observations(
                start, end, sensor_id=filters["sensor"], source_engine=SURICATA_ENGINE,
                ip=ip, limit=limit)
        except sd.QueryError as exc:
            observations = []
            notes.append(f"Telemetry query rejected: {exc}")

        rows.extend(_ne_normalize(row, "telemetry") for row in observations)

    rows.sort(key=lambda r: (r["observed_at"] or "", r["kind"]), reverse=True)

    return rows[:limit], notes, start, end


def suricata_sensor_choices():

    # Public columns only (security_sensors.list_sensors never returns the
    # verifier); restricted to the Suricata engine for this view's dropdown.
    return [s for s in security_sensors.list_sensors() if s.get("source_engine") == SURICATA_ENGINE]


# ==================================================
# NETWORK EVENTS PAGE
# ==================================================

@network_events_bp.route(
    "/network-events",
    methods=["GET", "POST"]
)
def network_events():

    if not login_required():

        return redirect(
            url_for("login")
        )

    error = None
    success = None
    enrichment_results = []

    if request.method == "POST":

        event_type = request.form.get(
            "event_type",
            "NETWORK_CONNECTION"
        ).strip()

        source_ip = request.form.get(
            "source_ip",
            ""
        ).strip()

        destination_ip = request.form.get(
            "destination_ip",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        if not source_ip:

            error = (
                "Source IP is required."
            )

        elif not destination_ip:

            error = (
                "Destination IP is required."
            )

        elif not is_valid_ip(
            source_ip
        ):

            error = (
                "Source IP is invalid."
            )

        elif not is_valid_ip(
            destination_ip
        ):

            error = (
                "Destination IP is invalid."
            )

        else:

            event_time = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            conn = get_db_connection()

            conn.execute("""
                INSERT INTO network_events (
                    event_time,
                    event_type,
                    source_ip,
                    destination_ip,
                    description,
                    username
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event_time,
                event_type,
                source_ip,
                destination_ip,
                description,
                session.get(
                    "username"
                )
            ))

            conn.commit()

            conn.close()

            write_log(
                "NETWORK_EVENT_RECEIVED",
                (
                    f"Network event received: "
                    f"{source_ip} -> "
                    f"{destination_ip}."
                ),
                destination_ip
            )

            public_ips = []

            for ip_address in [
                source_ip,
                destination_ip
            ]:

                if (
                    is_public_ip(
                        ip_address
                    )
                    and ip_address
                    not in public_ips
                ):

                    public_ips.append(
                        ip_address
                    )

            for ip_address in public_ips:

                result, incident_created = (
                    enrich_ip(
                        ip_address
                    )
                )

                enrichment_results.append({
                    "ip": ip_address,
                    "result": result,
                    "incident_created":
                        incident_created
                })

                if not result.get(
                    "error"
                ):

                    write_log(
                        "AUTOMATIC_IP_ENRICHMENT",
                        (
                            f"Automatic reputation "
                            f"analysis completed for "
                            f"{ip_address}. "
                            f"Risk: "
                            f"{result['risk_score']}/100. "
                            f"Severity: "
                            f"{result['severity']}."
                        ),
                        ip_address
                    )

            if public_ips:

                success = (
                    "Network event recorded and "
                    "public IP reputation analysis "
                    "completed automatically."
                )

            else:

                success = (
                    "Network event recorded. "
                    "No public IP addresses required "
                    "external reputation analysis."
                )

    conn = get_db_connection()

    events = conn.execute("""
        SELECT *
        FROM network_events
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    # Phase 14C Workstream B3: the primary, real-sensor-data view. Read-only;
    # writes nothing; the legacy manual-submission table/behavior above is
    # unchanged.
    suricata_filters, suricata_notes = _ne_parse_filters(request.args)
    suricata_events, query_notes, suricata_window_start, suricata_window_end = \
        query_suricata_network_events(suricata_filters)
    suricata_notes = suricata_notes + query_notes
    suricata_sensors = suricata_sensor_choices()

    return render_template(
        "network_events.html",
        events=events,
        error=error,
        success=success,
        enrichment_results=
            enrichment_results,
        suricata_events=suricata_events,
        suricata_filters=suricata_filters,
        suricata_notes=suricata_notes,
        suricata_sensors=suricata_sensors,
        suricata_window_start=suricata_window_start,
        suricata_window_end=suricata_window_end
    )