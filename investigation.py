# ==================================================
# PHASE 12B.6B: UNIFIED SECURITY INVESTIGATION (ADAPTER)
# ==================================================
#
# READ-ONLY (12B.6D adds stable-identity and explicit alert-relationship reads).
# Assembles an in-memory investigation object for ONE existing
# web_events row from CURRENT tables only. Nothing here is persisted.
#
#  * Every statement is a SELECT. No INSERT/UPDATE/DELETE/DDL, no index,
#    no schema change, no audit write, no cache write.
#  * No network access of any kind (no provider client is imported or
#    called). Cloudflare is represented only by its already-stored
#    evidence and by its pure-DB button state.
#  * No score is computed here. Threat Risk, severity, decision, Behavioral
#    label and Investigation Priority are all taken from the existing
#    backend functions/stored values, unchanged.
#  * Relationships are reported honestly and never guessed:
#      - alert.source_event_id is the LATEST/REFERENCE event (Phase 12B.6A):
#        relation code REFERENCED_EVENT, never "origin";
#      - an alert mentioned only in this event's historical text is
#        DERIVED_FROM_EVENT_TEXT (verified to exist on the same endpoint
#        record);
#      - an incident is shown only through alert.incident_id;
#      - response commands only through explicit alert_id / incident_id.
#  * Human-readable sentences live in the template; this module returns
#    structured data and technical codes.
#
# FUTURE SOURCES: every detection / timeline / related item carries a
# `source` code from SOURCE_LABELS so later phases can add SURICATA, ZEEK
# or SIGMA items without rewriting the page. None of those exist yet, and
# nothing here assumes every detection comes from web_events.

import json
import re
from datetime import datetime, timedelta

import behavioral_analysis
import cloudflare_provider
import endpoint_identity
import endpoint_network
import investigation_priority
import threat_intel_framework as framework
import threat_intel_providers

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# Source taxonomy (design only for the not-yet-implemented ones).
SOURCE_ENDPOINT = "ENDPOINT"
SOURCE_NETWORK = "NETWORK"
SOURCE_SURICATA = "SURICATA"
SOURCE_ZEEK = "ZEEK"
SOURCE_SIGMA = "SIGMA"
SOURCE_THREAT_INTEL = "THREAT_INTEL"
SOURCE_BEHAVIORAL = "BEHAVIORAL"
SOURCE_LOCAL_IOC = "LOCAL_IOC"
SOURCE_SYSTEM = "SYSTEM"

SOURCE_LABELS = {
    SOURCE_ENDPOINT: "Endpoint",
    SOURCE_NETWORK: "Network",
    SOURCE_SURICATA: "Suricata",
    SOURCE_ZEEK: "Zeek",
    SOURCE_SIGMA: "Sigma",
    SOURCE_THREAT_INTEL: "Threat Intelligence",
    SOURCE_BEHAVIORAL: "Behavioral",
    SOURCE_LOCAL_IOC: "Local IOC",
    SOURCE_SYSTEM: "System",
}

# Bounded Related Activity (12B.6B only; 12B.6C owns the indexed,
# cross-endpoint, blast-radius version).
RELATED_WINDOW_MINUTES = 30
RELATED_LIMIT = 50

MAX_DETAIL_ITEMS = 40
MAX_TEXT = 400

# Alert relationship codes: since 12B.6D these are the explicit alert_events
# relationship types (CREATED_FROM, DEDUP_REFRESH, LEGACY_LATEST_REFERENCE,
# LEGACY_TEXT_ASSOCIATION). Nothing is parsed from event text at request
# time any more - the one-time historical backfill did that, strictly.
REL_CREATED_FROM = endpoint_identity.REL_CREATED_FROM
REL_DEDUP_REFRESH = endpoint_identity.REL_DEDUP_REFRESH
REL_LEGACY_LATEST_REFERENCE = endpoint_identity.REL_LEGACY_LATEST_REFERENCE
REL_LEGACY_TEXT_ASSOCIATION = endpoint_identity.REL_LEGACY_TEXT_ASSOCIATION

# Attribution codes
ATTR_DNS = "DNS"
ATTR_RDNS = "RDNS"
ATTR_IP = "IP"
ATTR_UNKNOWN = "UNKNOWN"

# Behavioral display states
BEH_SCORED = "SCORED"
BEH_NOT_SCORED = "NOT_SCORED"
BEH_LEARNING = "LEARNING"
BEH_HISTORICAL = "HISTORICAL_TRAINING"

_TIMELINE_KIND_ORDER = {
    "EVENT": 0,
    "ANALYSIS": 1,
    "BEHAVIORAL": 2,
    "THREAT_INTEL": 3,
    "ALERT": 4,
    "INCIDENT": 5,
    "RESPONSE": 6,
}


def _parse_ts(value):

    if not value or not isinstance(value, str):
        return None

    try:
        return datetime.strptime(value, TS_FORMAT)
    except ValueError:
        return None


def _clip(value, limit=MAX_TEXT):

    if value is None:
        return None

    text = str(value)

    return text if len(text) <= limit else text[:limit] + "..."


def _rows(cursor):

    return [dict(row) for row in cursor.fetchall()]


# --------------------------------------------------
# SECTIONS
# --------------------------------------------------

def _attribution_code(attribution_type):

    return {
        "dns": ATTR_DNS,
        "rdns": ATTR_RDNS,
        "ip": ATTR_IP,
    }.get((attribution_type or "").strip().lower(), ATTR_UNKNOWN)


def _build_endpoint(conn, event):

    # Phase 12B.6D: stable identity is reported SEPARATELY from the
    # IP-based endpoint record. A UID on the event is identity metadata
    # ("stable agent identifier", not an authenticated device ID); its
    # absence is stated, never papered over from the IP or hostname.
    event_uid = event.get("endpoint_uid")

    stable = {
        "available": bool(event_uid),
        "uid": event_uid,
        "latest_ip": None,
        "latest_seen": None,
        "ip_records": 0,
    }

    if event_uid:

        rows = conn.execute(
            """
            SELECT ip_address, last_seen FROM endpoints
            WHERE endpoint_uid = ?
            ORDER BY last_seen DESC, id DESC
            LIMIT 20
            """,
            (event_uid,)
        ).fetchall()

        stable["ip_records"] = len(rows)

        if rows:
            stable["latest_ip"] = rows[0]["ip_address"]
            stable["latest_seen"] = rows[0]["last_seen"]

    row = conn.execute(
        "SELECT * FROM endpoints WHERE ip_address = ?",
        (event["endpoint_ip"],)
    ).fetchone()

    if row is None:
        return {"record_found": False, "ip_address": event["endpoint_ip"], "stable": stable}

    endpoint = dict(row)
    endpoint["record_found"] = True
    endpoint["stable"] = stable

    # Presence uses the SAME shared derivation as the Web Monitoring
    # Managed Endpoints table (imported lazily: web_monitoring is a heavy
    # module the app has already loaded).
    try:
        from web_monitoring import compute_endpoint_presence
        endpoint["presence"] = compute_endpoint_presence(endpoint.get("last_seen"))
    except Exception:
        endpoint["presence"] = "UNKNOWN"

    endpoint["is_managed_agent"] = endpoint.get("source") == "endpoint-agent"

    return endpoint


def _build_network_identity(conn, event):

    # Phase 13C: bounded IP history of the event's STABLE agent identifier.
    # Each row means "this agent installation was observed using this IP
    # during [first_seen_at, last_seen_at]" (UTC) - never permanent ownership.
    # Events without a stable identifier show nothing here (no guessing from
    # the IP or hostname).
    uid = event.get("endpoint_uid")

    if not uid:
        return {"available": False, "uid": None, "rows": [], "latest": None, "truncated": False}

    limit = endpoint_network.MAX_HISTORY_PANEL_ROWS

    try:
        rows = endpoint_network.endpoint_history_for_uid(conn, uid, limit + 1)
    except Exception:
        rows = []

    return {
        "available": True,
        "uid": uid,
        "rows": rows[:limit],
        "latest": rows[0] if rows else None,
        "truncated": len(rows) > limit,
    }


def _build_behavioral(conn, event):

    row = conn.execute(
        "SELECT * FROM behavioral_event_results WHERE web_event_id = ?",
        (event["id"],)
    ).fetchone()

    if row is None:
        return {"state": BEH_HISTORICAL, "row": None, "reasons": [], "label": None}

    result = dict(row)

    try:
        reasons = json.loads(result.get("behavioral_reasons") or "[]")
        if not isinstance(reasons, list):
            reasons = []
    except (ValueError, TypeError):
        reasons = []

    label = behavioral_analysis.behavioral_label(
        result.get("evaluation_status"), result.get("anomaly_score")
    )

    status = result.get("evaluation_status")

    if status == "SCORED" and result.get("anomaly_score") is not None:
        state = BEH_SCORED
    elif status == "LEARNING":
        state = BEH_LEARNING
    else:
        # LATE_EVENT / ERROR / anything else: never show a score.
        state = BEH_NOT_SCORED
        result["anomaly_score"] = None

    return {
        "state": state,
        "row": result,
        "reasons": [_clip(r, 300) for r in reasons[:20]],
        "label": label,
    }


def _build_detections(event):

    items = []

    details = event.get("details") or ""

    for index, text in enumerate(t.strip() for t in details.split(";") if t.strip()):

        if index >= MAX_DETAIL_ITEMS:
            break

        # ONLY the existing trusted helper decides that a line is a local
        # IOC statement; everything else is a neutral analysis note.
        source = (
            SOURCE_LOCAL_IOC
            if investigation_priority.detect_local_ioc_matched(text)
            else SOURCE_SYSTEM
        )

        items.append({"source": source, "text": _clip(text)})

    return {
        "risk_score": event.get("risk_score"),
        "severity": event.get("severity"),
        "decision": event.get("decision"),
        "items": items,
        "has_local_ioc": any(i["source"] == SOURCE_LOCAL_IOC for i in items),
    }


def _build_threat_intel(conn, event):

    rows = framework.get_all_provider_evidence_for_event_with_conn(
        conn,
        event.get("resolved_ip"),
        event.get("domain"),
        event.get("sha256"),
        event.get("md5"),
    )

    stored = []
    pending = []

    for row in rows:

        row = dict(row)
        row["source"] = SOURCE_THREAT_INTEL
        row["summary"] = _clip(row.get("summary"), 600)
        row["is_stored"] = row.get("lookup_status") in framework.PERSISTABLE_LOOKUP_STATUSES

        (stored if row["is_stored"] else pending).append(row)

    counts = framework.summarize_provider_evidence(rows)

    return {"stored": stored, "pending": pending, "counts": counts}


def _build_cloudflare(conn, event):

    # Pure DB reads. Opening the page NEVER performs a Cloudflare request.
    actions = []

    try:
        budget = cloudflare_provider.get_budget_state(conn)
    except Exception:
        return {"available": False, "actions": [], "budget": None, "configured": False}

    for indicator_type, value in (
        ("IP", framework.normalize_ip_candidate(event.get("resolved_ip"))),
        ("DOMAIN", framework.normalize_domain_candidate(event.get("domain"))),
    ):
        if not value:
            continue

        actions.append({
            "type": indicator_type,
            "value": value,
            "state": cloudflare_provider.get_action_state(conn, indicator_type, value, budget),
        })

    return {
        "available": True,
        "actions": actions,
        "budget": budget,
        "configured": cloudflare_provider.is_configured(),
    }


def _build_alerts(conn, event):

    # Phase 12B.6D: explicit relationships only (alert_events). No event-text
    # parsing and no guessing at request time. `relation` is the stored
    # relationship_type; `is_latest_reference` separately flags that this
    # event is currently the alert's source_event_id (the LATEST/REFERENCE
    # event - never an origin).
    rows = conn.execute(
        """
        SELECT a.id, a.alert_type, a.title, a.severity, a.status, a.created_at,
               a.updated_at, a.source_event_id, a.incident_id, a.endpoint_ip,
               ae.relationship_type
        FROM alert_events ae
        JOIN security_alerts a ON a.id = ae.alert_id
        WHERE ae.web_event_id = ?
        ORDER BY a.id
        """,
        (event["id"],)
    ).fetchall()

    alerts = []

    for row in rows:
        alert = dict(row)
        alert["relation"] = alert.pop("relationship_type")
        alert["is_latest_reference"] = alert.get("source_event_id") == event["id"]
        alerts.append(alert)

    return alerts


def _build_incident(conn, alerts):

    # Only through a listed alert's incident_id. Never inferred from
    # matching endpoint/domain values.
    for alert in alerts:

        if not alert.get("incident_id"):
            continue

        row = conn.execute(
            """
            SELECT id, event_type, severity, status, event_time, updated_at, title
            FROM security_events WHERE id = ?
            """,
            (alert["incident_id"],)
        ).fetchone()

        if row is not None:
            incident = dict(row)
            incident["via_alert_id"] = alert["id"]
            return incident

    return None


def _build_response(conn, alerts, incident):

    alert_ids = [a["id"] for a in alerts]
    incident_id = incident["id"] if incident else None

    if not alert_ids and incident_id is None:
        return []

    clauses = []
    params = []

    if alert_ids:
        clauses.append("alert_id IN ({})".format(",".join("?" * len(alert_ids))))
        params.extend(alert_ids)

    if incident_id is not None:
        clauses.append("incident_id = ?")
        params.append(incident_id)

    rows = _rows(conn.execute(
        f"""
        SELECT id, created_at, executed_at, command_type, target, status, mode,
               requested_by, alert_id, incident_id, endpoint_ip
        FROM response_commands
        WHERE {' OR '.join(clauses)}
        ORDER BY id DESC
        LIMIT 20
        """,
        params
    ))

    for row in rows:
        row["target"] = _clip(row.get("target"), 200)

    return rows


# --------------------------------------------------
# RELATED ACTIVITY / OBSERVED ELSEWHERE (Phase 12B.6C, identity-aware 12B.6D)
# --------------------------------------------------
# Investigation CONTEXT, never correlation: nothing here says two events are
# "the same attack", nothing is persisted, and nothing triggers a provider
# lookup, a behavioral evaluation, an alert, an incident or a response.
#
# Every query is: parameterized, time-windowed, LIMITed, and returns every
# field the page needs in ONE statement (no per-row follow-up queries; no TI
# or behavioral lookups for related events). Column names come from the fixed
# _CATEGORIES table below - never from a request parameter.
#
# ENDPOINT IDENTITY (12B.6D). Two qualities of identity exist and are NEVER
# silently mixed:
#   * STABLE  - events carrying a validated endpoint_uid (a per-installation
#     agent identifier that survives restarts and IP changes);
#   * HISTORICAL / IP-ONLY - older events (endpoint_uid NULL) known only by
#     the IP-based endpoint record, which may be the same physical device
#     under another address. These are never guessed into a UID.
# Same-endpoint / same-process / same-user context for an event WITH a UID
# matches on the UID; for an event WITHOUT one it falls back to the
# IP-based record and is labelled as such. Cross-endpoint counts report
# stable identifiers and historical/IP-only records separately and never
# claim a physical-device count.

ENDPOINT_RECORD_CAVEAT = "endpoint_records_are_ip_based"

SAMPLE_LIMIT = 10             # rows shown per cross-endpoint / supporting category
ENDPOINT_SAMPLE_LIMIT = RELATED_LIMIT
BREAKDOWN_LIMIT = 100         # identity groups enumerated per category (GROUP BY cap)
BREAKDOWN_SHOWN = 10

WINDOW_ENDPOINT_MINUTES = 30
WINDOW_FILE_MINUTES = 24 * 60
WINDOW_DOMAIN_MINUTES = 60
WINDOW_IP_MINUTES = 60
WINDOW_PROCESS_MINUTES = 60
WINDOW_USER_MINUTES = 60

STRENGTH_STRONG = "STRONG"
STRENGTH_SUPPORTING = "SUPPORTING"
STRENGTH_WEAKER_FILE_ID = "WEAKER_FILE_IDENTIFIER"
STRENGTH_CONTEXT = "CONTEXT"

IDENTITY_STABLE = "STABLE_UID"
IDENTITY_IP_RECORD = "IP_RECORD"

_SAMPLE_COLUMNS = (
    "id, event_time, endpoint_ip, endpoint_uid, process_name, domain, "
    "resolved_ip, destination, severity, source, attribution_type"
)

# Fixed statement templates. The only interpolated pieces are constants from
# this module (column names / fixed extra predicates), never user input.
SQL_ENDPOINT_SAMPLE = (
    f"SELECT {_SAMPLE_COLUMNS} FROM web_events "
    "WHERE endpoint_ip = ? AND id != ? AND event_time BETWEEN ? AND ? "
    "ORDER BY ABS(julianday(event_time) - julianday(?)), id LIMIT ?"
)

SQL_ENDPOINT_SAMPLE_UID = (
    f"SELECT {_SAMPLE_COLUMNS} FROM web_events "
    "WHERE endpoint_uid = ? AND id != ? AND event_time BETWEEN ? AND ? "
    "ORDER BY ABS(julianday(event_time) - julianday(?)), id LIMIT ?"
)


def _sql_aggregate(column, extra):
    return (
        "SELECT endpoint_uid, endpoint_ip, COUNT(*) AS n, MIN(event_time) AS first_seen, "
        "MAX(event_time) AS last_seen FROM web_events "
        f"WHERE {column} = ? {extra} AND event_time BETWEEN ? AND ? "
        "GROUP BY endpoint_uid, endpoint_ip "
        f"ORDER BY n DESC, endpoint_uid, endpoint_ip LIMIT {BREAKDOWN_LIMIT + 1}"
    )


def _sql_sample(column, extra):
    return (
        f"SELECT {_SAMPLE_COLUMNS} FROM web_events "
        f"WHERE {column} = ? {extra} AND event_time BETWEEN ? AND ? AND id != ? "
        "ORDER BY ABS(julianday(event_time) - julianday(?)), id LIMIT ?"
    )


# key -> (column, fixed extra predicate, window minutes, strength, cross_endpoint)
_CATEGORIES = {
    "same_sha256": ("sha256", "", WINDOW_FILE_MINUTES, STRENGTH_STRONG, True),
    "same_md5": ("md5", "", WINDOW_FILE_MINUTES, STRENGTH_WEAKER_FILE_ID, True),
    "same_domain": ("domain", "AND attribution_type = 'dns'", WINDOW_DOMAIN_MINUTES, STRENGTH_STRONG, True),
    "same_destination_ip": ("resolved_ip", "", WINDOW_IP_MINUTES, STRENGTH_SUPPORTING, True),
    "same_process": ("process_name", "AND endpoint_ip = ?", WINDOW_PROCESS_MINUTES, STRENGTH_SUPPORTING, False),
    "same_user": ("os_username", "AND endpoint_ip = ?", WINDOW_USER_MINUTES, STRENGTH_SUPPORTING, False),
}

# Endpoint-scoped categories switch to the stable UID when the event has one.
_UID_SCOPED_EXTRA = "AND endpoint_uid = ?"
_ENDPOINT_SCOPED_KEYS = ("same_process", "same_user")

CATEGORY_SQL = {
    key: (_sql_aggregate(spec[0], spec[1]), _sql_sample(spec[0], spec[1]))
    for key, spec in _CATEGORIES.items()
}

CATEGORY_SQL_UID = {
    key: (
        _sql_aggregate(_CATEGORIES[key][0], _UID_SCOPED_EXTRA),
        _sql_sample(_CATEGORIES[key][0], _UID_SCOPED_EXTRA),
    )
    for key in _ENDPOINT_SCOPED_KEYS
}


def _window(event_time, minutes):

    low = (event_time - timedelta(minutes=minutes)).strftime(TS_FORMAT)
    high = (event_time + timedelta(minutes=minutes)).strftime(TS_FORMAT)

    return low, high


def _not_applicable(reason, strength):

    return {
        "applicable": False,
        "reason": reason,
        "strength": strength,
        "total_events": 0,
        "endpoint_records": 0,
        "other_endpoint_records": 0,
        "stable_endpoints": 0,
        "other_stable_endpoints": 0,
        "historical_records": 0,
        "sample": [],
    }


def _decorate_sample(rows):

    for item in rows:
        item["source_code"] = SOURCE_ENDPOINT
        item["attribution_code"] = _attribution_code(item.get("attribution_type"))

    rows.sort(key=lambda i: (i["event_time"] or "", i["id"]))

    return rows


def _category_result(conn, key, identifier, event, event_time, sample_limit=SAMPLE_LIMIT):

    column, extra, minutes, strength, cross_endpoint = _CATEGORIES[key]

    event_uid = event.get("endpoint_uid")
    use_uid = bool(event_uid) and key in _ENDPOINT_SCOPED_KEYS

    aggregate_sql, sample_sql = (CATEGORY_SQL_UID if use_uid else CATEGORY_SQL)[key]

    low, high = _window(event_time, minutes)

    params = [identifier]

    if key in _ENDPOINT_SCOPED_KEYS:
        params.append(event_uid if use_uid else event["endpoint_ip"])

    params.extend([low, high])

    groups = conn.execute(aggregate_sql, params).fetchall()

    capped = len(groups) > BREAKDOWN_LIMIT
    groups = groups[:BREAKDOWN_LIMIT]

    total = sum(g["n"] for g in groups)
    firsts = [g["first_seen"] for g in groups if g["first_seen"]]
    lasts = [g["last_seen"] for g in groups if g["last_seen"]]

    sample_params = list(params) + [event["id"], event_time.strftime(TS_FORMAT), sample_limit]
    sample = _decorate_sample(_rows(conn.execute(sample_sql, sample_params)))

    ip_records = {g["endpoint_ip"] for g in groups}
    stable_ids = {g["endpoint_uid"] for g in groups if g["endpoint_uid"]}
    historical_ips = {g["endpoint_ip"] for g in groups if not g["endpoint_uid"]}

    other_stable = stable_ids - ({event_uid} if event_uid else set())

    def is_this_record(group):
        if event_uid:
            return group["endpoint_uid"] == event_uid
        return not group["endpoint_uid"] and group["endpoint_ip"] == event["endpoint_ip"]

    return {
        "applicable": True,
        "reason": None,
        "strength": strength,
        "identifier": identifier,
        "window_minutes": minutes,
        "cross_endpoint": cross_endpoint,
        "identity_basis": IDENTITY_STABLE if use_uid else IDENTITY_IP_RECORD,
        # counts INCLUDE the investigated event (it matches its own identifier)
        "total_events": total,
        # distinct IP-based endpoint records (unchanged 12B.6C meaning)
        "endpoint_records": len(ip_records),
        "other_endpoint_records": sum(1 for ip in ip_records if ip != event["endpoint_ip"]),
        # 12B.6D: identity quality is reported SEPARATELY, never summed into
        # a device count.
        "stable_endpoints": len(stable_ids),
        "other_stable_endpoints": len(other_stable),
        "historical_records": len(historical_ips),
        "endpoint_records_capped": capped,
        "first_observed": min(firsts) if firsts else None,
        "last_observed": max(lasts) if lasts else None,
        "endpoint_breakdown": [
            {
                "endpoint_ip": g["endpoint_ip"],
                "endpoint_uid": g["endpoint_uid"],
                "events": g["n"],
                "is_this_record": is_this_record(g),
            }
            for g in groups[:BREAKDOWN_SHOWN]
        ],
        "breakdown_more": max(0, len(groups) - BREAKDOWN_SHOWN),
        "sample": sample,
        "sample_limit": sample_limit,
        "sample_truncated": max(0, total - 1) > len(sample),
        "caveat": ENDPOINT_RECORD_CAVEAT if cross_endpoint else None,
    }


def _build_related_activity(conn, event):

    event_time = _parse_ts(event.get("event_time"))
    event_uid = event.get("endpoint_uid")

    empty = {
        "available": False,
        "same_endpoint": {"items": [], "truncated": False, "window_minutes": WINDOW_ENDPOINT_MINUTES, "unavailable": True,
                          "identity_basis": IDENTITY_STABLE if event_uid else IDENTITY_IP_RECORD},
        "same_sha256": _not_applicable("TIME_UNAVAILABLE", STRENGTH_STRONG),
        "same_md5": _not_applicable("TIME_UNAVAILABLE", STRENGTH_WEAKER_FILE_ID),
        "same_domain": _not_applicable("TIME_UNAVAILABLE", STRENGTH_STRONG),
        "same_destination_ip": _not_applicable("TIME_UNAVAILABLE", STRENGTH_SUPPORTING),
        "same_process": _not_applicable("TIME_UNAVAILABLE", STRENGTH_SUPPORTING),
        "same_user": _not_applicable("TIME_UNAVAILABLE", STRENGTH_SUPPORTING),
        "observed_elsewhere": [],
        "caveat": ENDPOINT_RECORD_CAVEAT,
    }

    if event_time is None:
        return empty

    # ---- same endpoint, +-30 min (context only): stable UID when the event
    #      has one, otherwise the IP-based endpoint record (labelled) ----
    low, high = _window(event_time, WINDOW_ENDPOINT_MINUTES)

    rows = conn.execute(
        SQL_ENDPOINT_SAMPLE_UID if event_uid else SQL_ENDPOINT_SAMPLE,
        (event_uid if event_uid else event["endpoint_ip"], event["id"], low, high,
         event_time.strftime(TS_FORMAT), ENDPOINT_SAMPLE_LIMIT + 1)
    ).fetchall()

    truncated = len(rows) > ENDPOINT_SAMPLE_LIMIT

    same_endpoint = {
        "items": _decorate_sample([dict(r) for r in rows[:ENDPOINT_SAMPLE_LIMIT]]),
        "truncated": truncated,
        "window_minutes": WINDOW_ENDPOINT_MINUTES,
        "unavailable": False,
        "strength": STRENGTH_CONTEXT,
        "identity_basis": IDENTITY_STABLE if event_uid else IDENTITY_IP_RECORD,
    }

    result = {"available": True, "same_endpoint": same_endpoint, "caveat": ENDPOINT_RECORD_CAVEAT}

    # ---- file identity: SHA-256 preferred; MD5 only when SHA-256 is absent ----
    sha256 = framework.normalize_sha256_candidate(event.get("sha256"))
    md5 = framework.normalize_md5_candidate(event.get("md5"))

    if sha256:
        result["same_sha256"] = _category_result(conn, "same_sha256", sha256, event, event_time)
        result["same_md5"] = _not_applicable("SHA256_PRESENT", STRENGTH_WEAKER_FILE_ID)
    else:
        result["same_sha256"] = _not_applicable("NO_SHA256", STRENGTH_STRONG)
        result["same_md5"] = (
            _category_result(conn, "same_md5", md5, event, event_time)
            if md5 else _not_applicable("NO_MD5", STRENGTH_WEAKER_FILE_ID)
        )

    # ---- domain: ONLY a confirmed DNS-attributed, normalized domain ----
    attribution = _attribution_code(event.get("attribution_type"))
    domain = framework.normalize_domain_candidate(event.get("domain"))

    if not event.get("domain"):
        result["same_domain"] = _not_applicable("NO_DOMAIN", STRENGTH_STRONG)
    elif attribution != ATTR_DNS:
        result["same_domain"] = _not_applicable(
            "RDNS_INFERRED" if attribution == ATTR_RDNS else ("IP_ONLY" if attribution == ATTR_IP else "ATTRIBUTION_UNKNOWN"),
            STRENGTH_STRONG
        )
    elif not domain or domain != event.get("domain"):
        result["same_domain"] = _not_applicable("DOMAIN_NOT_ELIGIBLE", STRENGTH_STRONG)
    else:
        result["same_domain"] = _category_result(conn, "same_domain", domain, event, event_time)

    # ---- destination IP: public, exact ----
    ip_value = framework.normalize_ip_candidate(event.get("resolved_ip"))

    if not event.get("resolved_ip"):
        result["same_destination_ip"] = _not_applicable("NO_IP", STRENGTH_SUPPORTING)
    elif not ip_value or ip_value != event.get("resolved_ip"):
        result["same_destination_ip"] = _not_applicable("IP_NOT_PUBLIC_OR_NOT_CANONICAL", STRENGTH_SUPPORTING)
    else:
        result["same_destination_ip"] = _category_result(conn, "same_destination_ip", ip_value, event, event_time)

    # ---- process: same endpoint (UID if present, else IP record); never PID ----
    process_name = (event.get("process_name") or "").strip()

    if not process_name or process_name.lower() == "unknown":
        result["same_process"] = _not_applicable("NO_PROCESS", STRENGTH_SUPPORTING)
    else:
        result["same_process"] = _category_result(conn, "same_process", process_name, event, event_time)

    # ---- user: the EVENT-observed username only, same endpoint ----
    os_username = (event.get("os_username") or "").strip()

    if not os_username:
        result["same_user"] = _not_applicable("NO_EVENT_USER", STRENGTH_SUPPORTING)
    else:
        result["same_user"] = _category_result(conn, "same_user", os_username, event, event_time)

    # ---- Observed Elsewhere: file / domain / destination IP only ----
    elsewhere = []

    for key, kind in (("same_sha256", "FILE_SHA256"), ("same_md5", "FILE_MD5"), ("same_domain", "DOMAIN"), ("same_destination_ip", "DESTINATION_IP")):
        item = result[key]
        if item["applicable"]:
            elsewhere.append({
                "kind": kind,
                "category": key,
                "strength": item["strength"],
                "identifier": item["identifier"],
                "window_minutes": item["window_minutes"],
                "total_events": item["total_events"],
                "endpoint_records": item["endpoint_records"],
                "other_endpoint_records": item["other_endpoint_records"],
                "stable_endpoints": item["stable_endpoints"],
                "other_stable_endpoints": item["other_stable_endpoints"],
                "historical_records": item["historical_records"],
                "endpoint_records_capped": item["endpoint_records_capped"],
                "first_observed": item["first_observed"],
                "last_observed": item["last_observed"],
            })

    result["observed_elsewhere"] = elsewhere

    return result


# --------------------------------------------------
# ALERT -> ASSOCIATED EVENTS (Alert Details, 12B.6D)
# --------------------------------------------------

ASSOCIATED_EVENTS_LIMIT = 25


def alert_associated_events(conn, alert_id, limit=ASSOCIATED_EVENTS_LIMIT):

    # Every web event explicitly associated with the alert via alert_events.
    # "Earliest/latest associated event" mean the earliest/latest EXPLICIT
    # relationship by event time - never an inferred origin. An event is
    # only ever described as "created from" when its relationship_type is
    # CREATED_FROM (new alerts recorded after 12B.6D).
    summary = conn.execute(
        """
        SELECT COUNT(*) AS total, MIN(w.event_time) AS first_time, MAX(w.event_time) AS last_time
        FROM alert_events ae JOIN web_events w ON w.id = ae.web_event_id
        WHERE ae.alert_id = ?
        """,
        (alert_id,)
    ).fetchone()

    columns = (
        "w.id, w.event_time, w.endpoint_ip, w.endpoint_uid, w.process_name, w.domain, "
        "w.resolved_ip, w.destination, w.severity, ae.relationship_type"
    )

    first = conn.execute(
        f"SELECT {columns} FROM alert_events ae JOIN web_events w ON w.id = ae.web_event_id "
        "WHERE ae.alert_id = ? ORDER BY w.event_time ASC, w.id ASC LIMIT 1",
        (alert_id,)
    ).fetchone()

    latest = conn.execute(
        f"SELECT {columns} FROM alert_events ae JOIN web_events w ON w.id = ae.web_event_id "
        "WHERE ae.alert_id = ? ORDER BY w.event_time DESC, w.id DESC LIMIT 1",
        (alert_id,)
    ).fetchone()

    items = _rows(conn.execute(
        f"SELECT {columns} FROM alert_events ae JOIN web_events w ON w.id = ae.web_event_id "
        "WHERE ae.alert_id = ? ORDER BY w.event_time DESC, w.id DESC LIMIT ?",
        (alert_id, limit)
    ))

    counts = {
        row["relationship_type"]: row["n"]
        for row in conn.execute(
            "SELECT relationship_type, COUNT(*) AS n FROM alert_events WHERE alert_id = ? GROUP BY relationship_type",
            (alert_id,)
        ).fetchall()
    }

    return {
        "total": summary["total"],
        "first_time": summary["first_time"],
        "last_time": summary["last_time"],
        "first": dict(first) if first else None,
        "latest": dict(latest) if latest else None,
        "items": items,
        "truncated": summary["total"] > len(items),
        "relationship_counts": counts,
        "first_is_created_from": bool(first) and first["relationship_type"] == endpoint_identity.REL_CREATED_FROM,
    }


# --------------------------------------------------
# TIMELINE
# --------------------------------------------------

def _build_timeline(event, behavioral, threat_intel, alerts, incident, response):

    items = {}

    def add(ts, kind, source, source_type, source_id, title, note=None):

        key = (source_type, str(source_id), kind)

        if key in items:
            return

        items[key] = {
            "timestamp": ts,
            "kind": kind,
            "source": source,
            "source_type": source_type,
            "source_id": source_id,
            "title": title,
            "note": note,
            "_sort": _parse_ts(ts),
        }

    add(event.get("event_time"), "EVENT", SOURCE_ENDPOINT, "web_event", event["id"], "web_event_observed", "server_receipt_time")

    if event.get("analysis_completed_at"):
        add(event["analysis_completed_at"], "ANALYSIS", SOURCE_SYSTEM, "web_event", event["id"], "analysis_completed")

    if behavioral["row"] and behavioral["row"].get("computed_at"):
        add(behavioral["row"]["computed_at"], "BEHAVIORAL", SOURCE_BEHAVIORAL, "behavioral_result", behavioral["row"]["id"], "behavioral_evaluated", behavioral["state"])

    for row in threat_intel["stored"]:
        if row.get("retrieved_at"):
            add(
                row["retrieved_at"], "THREAT_INTEL", SOURCE_THREAT_INTEL, "ti_evidence",
                f"{row.get('provider')}:{row.get('indicator_type')}:{row.get('indicator_value')}",
                "provider_evidence_retrieved", row.get("provider")
            )

    for alert in alerts:
        add(alert["created_at"], "ALERT", SOURCE_SYSTEM, "alert", alert["id"], "alert_created", alert["relation"])
        if alert.get("updated_at") and alert["updated_at"] != alert["created_at"]:
            add(alert["updated_at"], "ALERT", SOURCE_SYSTEM, "alert_update", alert["id"], "alert_updated", alert["relation"])

    if incident:
        add(incident["event_time"], "INCIDENT", SOURCE_SYSTEM, "incident", incident["id"], "incident_created")

    for command in response:
        add(command["created_at"], "RESPONSE", SOURCE_SYSTEM, "response_command", command["id"], "response_requested", command["command_type"])
        if command.get("executed_at"):
            add(command["executed_at"], "RESPONSE", SOURCE_SYSTEM, "response_command_exec", command["id"], "response_executed", command["command_type"])

    ordered = sorted(
        items.values(),
        key=lambda i: (
            i["_sort"] is None,
            i["_sort"] or datetime.max,
            _TIMELINE_KIND_ORDER.get(i["kind"], 99),
            str(i["source_id"]),
        )
    )

    for item in ordered:
        item.pop("_sort", None)

    return ordered


# --------------------------------------------------
# PUBLIC ENTRY POINT
# --------------------------------------------------

def build_investigation(conn, event_id):

    row = conn.execute("SELECT * FROM web_events WHERE id = ?", (event_id,)).fetchone()

    if row is None:
        return None

    event = dict(row)

    endpoint = _build_endpoint(conn, event)
    network_identity = _build_network_identity(conn, event)
    behavioral = _build_behavioral(conn, event)
    detections = _build_detections(event)
    threat_intel = _build_threat_intel(conn, event)
    cloudflare = _build_cloudflare(conn, event)
    alerts = _build_alerts(conn, event)
    incident = _build_incident(conn, alerts)
    response = _build_response(conn, alerts, incident)
    related_activity = _build_related_activity(conn, event)
    related = related_activity["same_endpoint"]

    # Investigation Priority: the EXISTING function with the EXACT inputs
    # Web Monitoring passes (see web_monitoring.py). ThreatFox evidence via
    # the existing read-only helper. Never recomputed in the template.
    threatfox_evidence = threat_intel_providers.get_stored_evidence_for_event(
        event.get("resolved_ip"), event.get("domain"), event.get("sha256")
    )

    behavioral_row = behavioral["row"]

    priority_level, priority_reasons = investigation_priority.compute_investigation_priority(
        event.get("severity"),
        behavioral["label"],
        behavioral_row["confidence"] if behavioral_row else None,
        investigation_priority.detect_local_ioc_matched(event.get("details")),
        threatfox_evidence,
    )

    header = {
        "event_id": event["id"],
        "event_time": event.get("event_time"),
        "endpoint_ip": event.get("endpoint_ip"),
        "process_name": event.get("process_name"),
        "destination": event.get("domain") or event.get("resolved_ip") or event.get("destination"),
        "risk_score": event.get("risk_score"),
        "severity": event.get("severity"),
        "decision": event.get("decision"),
        "priority_level": priority_level,
        "priority_reasons": list(priority_reasons or []),
        "behavioral_label": behavioral["label"],
        "behavioral_state": behavioral["state"],
    }

    process = {
        key: event.get(key)
        for key in (
            "process_name", "process_pid", "process_path", "file_name",
            "file_extension", "sha256", "md5", "is_script_related",
        )
    }

    destination = {
        "destination": event.get("destination"),
        "domain": event.get("domain"),
        "resolved_ip": event.get("resolved_ip"),
        "observed_ip": event.get("observed_ip"),
        "attribution_code": _attribution_code(event.get("attribution_type")),
        "source": event.get("source"),
        # Phase 13C: OS-observed connection metadata (NULL = not observed /
        # not collected for this event; nothing is ever inferred).
        "port": event.get("destination_port"),
        "protocol": event.get("transport_protocol"),
        "source_ip": event.get("source_ip"),
    }

    limitations = [
        "server_receipt_time",
        "endpoint_record_not_device",
        "latest_reference_fields",
        "current_ti_not_point_in_time",
        "alert_reference_is_latest_event",
        "no_process_tree",
        "behavioral_partial_coverage",
        "related_activity_is_time_window_context",
        "endpoint_records_are_ip_based",
    ]

    if event.get("destination_port") is None and event.get("transport_protocol") is None:
        limitations.insert(5, "port_protocol_not_collected")

    return {
        "event": event,
        "header": header,
        "endpoint": endpoint,
        "network_identity": network_identity,
        "process": process,
        "destination": destination,
        "detections": detections,
        "threat_intelligence": threat_intel,
        "cloudflare": cloudflare,
        "behavioral": behavioral,
        "alerts": alerts,
        "incident": incident,
        "response": response,
        "timeline": _build_timeline(event, behavioral, threat_intel, alerts, incident, response),
        "related_events": related,
        "related_activity": related_activity,
        "limitations": limitations,
        "source_labels": SOURCE_LABELS,
    }
