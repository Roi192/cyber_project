"""Website-visit monitoring for small businesses - Flask application.

Many computers (browser extensions) POST the websites they visit to this one
central server. The server validates and sanitizes everything it receives,
checks the domain's reputation (cached), records the visit, raises an alert for
dangerous destinations and shows it all on a simple dashboard.
"""
import sys

if __name__ == "__main__":          # `python app.py`: check Python and packages, prepare .env (secrets) and the database folder BEFORE the configuration is read; never run when imported
    import bootstrap
    if bootstrap.preflight():
        sys.exit(1)

import hmac
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

import analytics
import auth
import config
import database
import devices
import overview
from services import panels, reputation, risk, shadow, urlcheck
from validation import (ValidationError, is_browser_noise, is_non_public_domain, is_public_address, validate_enrollment,
                        validate_grant_request, validate_network_event, validate_pairing, validate_registration,
                        validate_web_event)

app = Flask(__name__)
def proxy_aware(wsgi_app, hops):
    """The WSGI app behind `hops` reverse proxies that set X-Forwarded-For / -Proto / -Prefix (see config.TRUSTED_PROXY_HOPS). Host is not forwarded: Apache keeps it
    with ProxyPreserveHost On."""
    from werkzeug.middleware.proxy_fix import ProxyFix
    return ProxyFix(wsgi_app, x_for=hops, x_proto=hops, x_host=0, x_prefix=hops)


if config.TRUSTED_PROXY_HOPS:
    app.wsgi_app = proxy_aware(app.wsgi_app, config.TRUSTED_PROXY_HOPS)
_database_ready = False


@app.before_request
def _refuse_until_the_database_is_initialised():
    """Phase F3.11: the server never creates or migrates the database by itself when it is merely imported (a Gunicorn worker, a shell one-liner). It is prepared by
    `python manage_db.py init` (deploy/service.sh does that before Gunicorn starts) or by `python app.py`. A worker that finds it missing answers 503 and says how to fix it,
    instead of racing other workers to create it. Registered BEFORE auth.init_app so it runs before the sign-in guard, which reads the database. Once ready, the check is a flag."""
    global _database_ready
    if _database_ready:
        return None
    if database.is_initialized():
        _database_ready = True
        return None
    return jsonify({"ok": False, "error": "The database is not initialised. Run: python manage_db.py init (then start the server)."}), 503


auth.init_app(app)          # secret-key and API-key policy, sessions, CSRF, the deny-by-default guard, /login and /logout
app.register_blueprint(analytics.bp)      # /api/analytics/*: read-only; not marked as sensor API, so the guard demands an administrator
app.config["JSON_SORT_KEYS"] = False

# Internal reputation statuses (SAFE / SUSPICIOUS / MALICIOUS / UNKNOWN) never change;
# these are the words shown to the business owner (see overview.REPUTATION_UI).
STATUS_LABELS = {code: ui[0] for code, ui in overview.REPUTATION_UI.items()}
STATUS_HINTS = {code: ui[1] for code, ui in overview.REPUTATION_UI.items()}
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_SEARCH_LENGTH = 100


# --------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------
def require_api_key(view):
    """Every endpoint-facing route uses this. When API_KEY is configured the
    request must carry it in X-Api-Key (constant-time comparison); when it is
    empty the server is in DEV MODE and the check is skipped. The key is never
    logged, stored or returned."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if config.API_KEY:
            supplied = request.headers.get("X-Api-Key", "")
            if not hmac.compare_digest(supplied.encode("utf-8"), config.API_KEY.encode("utf-8")):
                return jsonify({"ok": False, "error": "invalid or missing API key"}), 401
        elif not auth.is_loopback(request.remote_addr):
            # no key is configured (development mode): that is only acceptable for a sensor on this very computer. A request that
            # comes from the network is refused, however the server was started (python app.py, gunicorn, a proxy on another host).
            return jsonify({"ok": False, "error": "API authentication is required for clients other than this computer; set API_KEY"}), 403
        return view(*args, **kwargs)

    return wrapper


def json_body():
    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("request body must be JSON")
    return data


@app.errorhandler(ValidationError)
def handle_validation_error(error):
    return jsonify({"ok": False, "error": str(error)}), 400


def dev_mode():
    """DEV MODE = no API_KEY configured, so endpoint POSTs are not authenticated."""
    return not config.API_KEY


def lan_exposed_without_key():
    """DEV MODE while listening beyond localhost: anyone on the network could submit data."""
    return dev_mode() and config.HOST not in LOOPBACK_HOSTS


def threat_intel_view(conn):
    ti = reputation.provider_status(conn)
    return dict(ti, label=overview.TI_LABELS.get(ti["status"], ti["status"]))


@app.context_processor
def inject_globals():
    conn = database.get_connection()
    try:
        ti = threat_intel_view(conn)
    finally:
        conn.close()
    return {
        "score_tooltip": risk.SCORE_TOOLTIP,
        "status_labels": STATUS_LABELS,
        "status_hints": STATUS_HINTS,
        "threat_intel": ti,
        "demo_banner": app.config.get("DEMO_BANNER", ""),
        "dev_mode": dev_mode(),
        "lan_exposed_without_key": lan_exposed_without_key(),
    }


def _prefix_links(verdict):
    """The overview's links are written as site paths ("/alerts"); under a proxy sub-path they need the prefix (request.script_root, empty otherwise)."""
    root = request.script_root
    if not root:
        return
    for item in [verdict.get("action") or {}] + list(verdict.get("attention") or []):
        if isinstance(item.get("url"), str) and item["url"].startswith("/"):
            item["url"] = root + item["url"]


def build_state(conn):
    """Dashboard numbers plus the truthful verdict. summary["security_status"] is the
    full verdict (ALERT / WARNING / LIMITED / OK), not just the alert level."""
    summary = database.dashboard_summary(conn)
    summary.update(database.visibility_summary(database.list_devices(conn)))     # who is online without website visibility
    ti = reputation.provider_status(conn)
    alerts = database.open_alert_items(conn, limit=3)
    offline = database.long_offline_computers(conn, overview.OFFLINE_ATTENTION_SECONDS)
    verdict = overview.build_overview(summary, ti, alerts, offline)
    _prefix_links(verdict)
    summary["security_status"] = verdict["status"]
    summary["coverage_percent"] = verdict["coverage"]["percent"]
    return summary, verdict


def visit_view(row, now=None, analysis=None):
    """A visit as a dict with the business-readable fields the pages need. `analysis` (reputation.analysis_bulk) adds the
    one-line summary of who checked the domain and what they found."""
    item = dict(row)
    item["supporting_sources"] = [overview.source_label(database.SOURCE_BROWSER_HISTORY)] if item.get("supporting_history") else []
    item["logical_id"] = item.get("logical_id") or item["id"]       # the stable identity of the logical visit (see database._LOGICAL_ID)
    item["analysis_summary"] = reputation.summarize(analysis) if analysis is not None else ""
    item["time_label"] = database.time_label(item["visited_at"], now)
    item["status_label"] = STATUS_LABELS.get(item["reputation_status"], STATUS_LABELS["UNKNOWN"])
    item["status_hint"] = STATUS_HINTS.get(item["reputation_status"], STATUS_HINTS["UNKNOWN"])
    if item.get("level") == "WEAK":              # Phase F2.1: kept visible for investigation, but not an alert and not a threat
        item["status_label"] = "Weak finding"
        item["status_hint"] = reputation.weak_hint(analysis)
    item["source_label"] = overview.source_label(item.get("source"))
    item["observation_label"] = overview.observation_label(item.get("source"), item.get("dest_ip"))
    item["observation_hint"] = overview.observation_hint(item.get("source"), item.get("dest_ip"))
    item["is_ip_only"] = bool(item.get("dest_ip"))
    if item["is_ip_only"]:       # nothing to look up for a bare address: say so instead of the generic "could not determine"
        item["status_hint"] = overview.IP_REPUTATION_HINT
    # which program made the connection (native collector only; empty for browser visits and DNS lookups)
    item["has_process"] = bool(item.get("process_kind"))
    if item["has_process"]:
        item["process_label"] = overview.process_label(item.get("process_name"), item["process_kind"])
        item["process_kind_label"] = overview.process_kind_label(item["process_kind"])
        item["process_kind_hint"] = overview.process_kind_hint(item["process_kind"])
    return item


def raw_filter():
    """?raw=1 also lists the older rows that only record 'a program connected to an address'."""
    return request.args.get("raw") == "1"


def configured_sources():
    """Names of the sources that are switched on (and have what they need): a source in this set that left no evidence was SKIPPED, one outside it is not configured."""
    return set(r["name"] for r in reputation.provider_states() if r["state"] not in ("DISABLED", "NOT_CONFIGURED", "RETIRED"))


def risk_fields(analysis, url_rows, is_ip_only=False, configured=None):
    """The short risk fields every list row carries (the full explanation is on the analysis page). None when there is nothing to assess (a bare address)."""
    empty = {"risk_score": None, "risk_band": None, "risk_label": None, "risk_coverage": None}
    if is_ip_only or not analysis:
        return empty
    assessment = risk.assess(analysis.get("providers") or [], url_rows or [], configured)
    return {"risk_score": assessment["score"], "risk_band": assessment["band"], "risk_label": assessment["label"], "risk_coverage": assessment["coverage_text"]}


def visit_views(conn, rows):
    """visit_view for a list of rows, with every row's analysis summary from two queries (not one per row).
    In the audit view (?physical=1) every record is its own row, so its identity is its own id."""
    rows = list(rows)
    analyses = reputation.analysis_bulk(conn, [r["domain"] for r in rows if not r["dest_ip"]])
    views = [visit_view(r, analysis=analyses.get(r["domain"])) for r in rows]
    address_evidence = database.url_evidence_for_visits(conn, [v["id"] for v in views])
    configured = configured_sources()
    for view in views:                       # Phase F3.9: what the address-level check found for THIS page, in its own words, next to the site-level summary
        note = reputation.address_summary(address_evidence.get(view["id"]))
        if note:
            view["analysis_summary"] = (view["analysis_summary"] + "; " if view["analysis_summary"] else "") + note
        view.update(risk_fields(analyses.get(view["domain"]), address_evidence.get(view["id"]), view["is_ip_only"], configured))          # Phase F3.12
    if physical_filter():
        for view in views:
            view["logical_id"] = view["id"]
    return views


def physical_filter():
    """?physical=1 lists every stored record, including a browser-history record the extension already reported (audit view).
    The normal views list LOGICAL visits: one row per navigation."""
    return request.args.get("physical") == "1"


def source_filter():
    source = request.args.get("source", "").upper() or None
    return source if source in database.SOURCES else None


def endpoint_view(row):
    """A computer with its visibility in words for the owner."""
    item = dict(row)
    item["visibility_label"] = overview.visibility_label(item["visibility"])
    item["visibility_hint"] = overview.visibility_hint(item["visibility"])
    if item.get("visibility_note"):
        item["visibility_hint"] = (item["visibility_hint"] + " " + item["visibility_note"]).strip()
    return item


def network_activity_view(row):
    """One program's raw activity today, in words for the owner (never a website)."""
    item = dict(row)
    name = None if item["process_name"] == database.UNKNOWN_PROGRAM else item["process_name"]
    item["process_label"] = overview.process_label(name, item["process_kind"])
    item["process_kind_label"] = overview.process_kind_label(item["process_kind"])
    item["process_kind_hint"] = overview.process_kind_hint(item["process_kind"])
    item["last_seen_label"] = database.time_label(item["last_seen"])
    return item


def search_term():
    return request.args.get("q", "").strip()[:MAX_SEARCH_LENGTH] or None


def status_filter():
    status = request.args.get("status", "").upper() or None
    return status if status in STATUS_LABELS else None


def _register(conn, data):
    return database.upsert_endpoint(
        conn, data["endpoint_uid"], data["computer_name"], data["username"],
        browser=data["browser"], username_provided=data["username_provided"],
        agent_version=data["agent_version"], history_browsers=data.get("history_browsers"),
        sensor_version=data.get("sensor_version"))


def credential_gate(conn, endpoint_uid):
    """None when the request may act as this sensor, else the refusal. A sensor that was paired or enrolled has a secret and every
    request in its name must present it (X-Sensor-Secret): knowing its UID, its computer name or the organisation API key is not
    enough to speak for it. A sensor without a secret (installed before Phase 5.5, or not paired yet) works as it always did."""
    problem = devices.credential_problem(conn, endpoint_uid, request.headers.get(devices.CREDENTIAL_HEADER, ""))
    if problem is None:
        return None
    return jsonify({"ok": False, "error": problem[1]}), problem[0]


# --------------------------------------------------------------------
# Endpoint-facing API (all protected by the same X-Api-Key logic)
# --------------------------------------------------------------------
@app.route("/api/ping", methods=["GET"])
@auth.sensor_api
@require_api_key
def api_ping():
    """Connection test used by the extension Options page. Read-only: it
    changes nothing, but it is authenticated, so a wrong key gives 401."""
    return jsonify({"ok": True, "service": "website-monitor", "auth_required": bool(config.API_KEY),
                    "server_time": database.now_str()})


@app.route("/api/endpoints/register", methods=["POST"])
@auth.sensor_api
@require_api_key
def api_register_endpoint():
    data = validate_registration(json_body())
    conn = database.get_connection()
    try:
        refused = credential_gate(conn, data["endpoint_uid"])
        if refused:
            return refused
        row = _register(conn, data)
    finally:
        conn.close()
    return jsonify({"ok": True, "endpoint_id": row["id"], "endpoint_uid": row["endpoint_uid"]}), 201


@app.route("/api/devices/enroll", methods=["POST"])
@auth.sensor_api
@require_api_key
def api_enroll_device():
    """The Windows agent announces its device (a random UID it generated) and its own sensor. The reply carries the sensor secret
    ONCE; every later request of that agent must present it. Re-announcing an existing device needs that secret."""
    data = validate_enrollment(json_body())
    conn = database.get_connection()
    try:
        try:
            result = devices.enroll_agent(conn, data["device_uid"], data["sensor_uid"], data["computer_name"], data["agent_version"],
                                          request.headers.get(devices.CREDENTIAL_HEADER, ""))
        except devices.DeviceError as error:
            return jsonify({"ok": False, "error": error.message}), error.status
    finally:
        conn.close()
    result["ok"] = True
    return jsonify(result), 201 if result["created"] else 200


@app.route("/api/sensors/grants", methods=["POST"])
@auth.sensor_api
@require_api_key
def api_pairing_grant():
    """An enrolled agent (proved by its sensor secret) asks permission for one named extension installation to join its device."""
    data = validate_grant_request(json_body())
    conn = database.get_connection()
    try:
        refused = credential_gate(conn, data["endpoint_uid"])
        if refused:
            return refused
        try:
            token, ttl = devices.issue_grant(conn, data["endpoint_uid"], data["sensor_uid"])
        except devices.DeviceError as error:
            return jsonify({"ok": False, "error": error.message}), error.status
    finally:
        conn.close()
    return jsonify({"ok": True, "grant": token, "expires_in": ttl}), 201


@app.route("/api/sensors/pair", methods=["POST"])
@auth.sensor_api
@require_api_key
def api_pair_sensor():
    """An extension installation presents a pairing grant and joins that device. Returns the sensor secret ONCE."""
    data = validate_pairing(json_body())
    conn = database.get_connection()
    try:
        try:
            result = devices.pair_sensor(conn, data["grant"], data["endpoint_uid"], data["computer_name"], data["browser"],
                                         data["username"], data["sensor_version"], request.headers.get(devices.CREDENTIAL_HEADER, ""))
        except devices.DeviceError as error:
            return jsonify({"ok": False, "error": error.message}), error.status
    finally:
        conn.close()
    result["ok"] = True
    return jsonify(result), 201


@app.route("/api/sensors/<int:sensor_id>/revoke", methods=["POST"])
@auth.admin_or_api_key
def api_revoke_sensor(sensor_id):
    """Block one paired sensor until it is paired again (administrator action: it needs the API key)."""
    conn = database.get_connection()
    try:
        done = devices.revoke_sensor(conn, sensor_id)
    finally:
        conn.close()
    if not done:
        return jsonify({"ok": False, "error": "no such paired sensor"}), 404
    return jsonify({"ok": True})


@app.route("/api/heartbeat", methods=["POST"])
@auth.sensor_api
@require_api_key
def api_heartbeat():
    """Answers one question: is this browser online? It updates the single
    last_seen value of the endpoint. No row is inserted per heartbeat and no
    history is kept."""
    data = validate_registration(json_body())
    conn = database.get_connection()
    try:
        refused = credential_gate(conn, data["endpoint_uid"])
        if refused:
            return refused
        row = _register(conn, data)
    finally:
        conn.close()
    return jsonify({"ok": True, "endpoint_id": row["id"], "status": database.endpoint_status(row["last_seen"])})


@app.route("/api/web-events", methods=["POST"])
@auth.sensor_api
@require_api_key
def api_web_event():
    deadline = reputation.Deadline()          # Phase F3.11: the extension gives up after 5 s, so this request is answered within reputation.REQUEST_BUDGET_SECONDS
    event = validate_web_event(json_body())
    conn = database.get_connection()
    try:
        refused = credential_gate(conn, event["endpoint_uid"])
        if refused:
            return refused
        endpoint = database.upsert_endpoint(
            conn, event["endpoint_uid"], event["computer_name"], event["username"],
            browser=event["endpoint_browser"], username_provided=event["username_provided"])
        if is_browser_noise(event["domain"], event["sanitized_url"]):
            # browser-generated page (e.g. the Edge New Tab): the endpoint is alive, but this is not a visit
            return jsonify({"ok": True, "ignored": "browser_internal_page"}), 200
        verdict = reputation.check_domain(conn, event["domain"], source="browser", deadline=deadline)
        # Server-side dedupe of reload/redirect bursts: the same SENSOR reporting the same page in the same BROWSER within a few
        # seconds. The browser is part of the match, so Chrome and Edge opening one site together are two visits, never one.
        visit_id = database.find_recent_visit(
            conn, endpoint["id"], event["domain"], event["sanitized_url"], event["visited_at"], browser=event["browser"])
        duplicate = visit_id is not None
        if not duplicate:
            visit_id = database.insert_visit(
                conn, endpoint["id"], event["domain"], event["sanitized_url"],
                event["browser"], event["visited_at"], verdict["status"], level=verdict.get("level"),
            )
        # Phase F3.9: the page ADDRESS (sanitized: no query, fragment or credentials) is checked on its own when Google Safe Browsing is on. The answer belongs to THIS visit
        # (visit_url_evidence); it never changes the domain's cached verdict and never marks another page of the host.
        address = reputation.check_visit_url(conn, visit_id, event["domain"], event["sanitized_url"], source="browser", deadline=deadline)
        page_severity = address["severity"] if address else None
        if page_severity:
            database.raise_visit_verdict(conn, visit_id, address["status"], address["level"])
        alert = None
        host_severity = reputation.alert_severity_for(verdict)       # only SUSPICIOUS / MALICIOUS: UNKNOWN never alerts
        severity = max((s for s in (host_severity, page_severity) if s), key=lambda s: database.ALERT_SEVERITY_RANK[s], default=None)
        if severity:
            device = database.visit_device_name(conn, visit_id)
            page_drives = bool(page_severity) and (not host_severity or database.ALERT_SEVERITY_RANK[page_severity] > database.ALERT_SEVERITY_RANK[host_severity])
            detail = None
            if page_severity:
                detail = "%s on %s (Google Safe Browsing: %s)" % (reputation.URL_FINDING, urlcheck.display_path(event["sanitized_url"]), ", ".join(address["categories"]) or address["status"])
            if page_drives:
                reason = "%s opened a page of %s that Google Safe Browsing identified as %s (%s). This finding is about that page only; other pages of the site were not flagged." % (
                    device, event["domain"], address["status"].lower(), ", ".join(address["categories"]) or "address-level listing")
                shown_verdict = address["status"]
            else:
                reason = "%s visited a website identified as %s (%s). %s" % (device, verdict["status"].lower(), event["domain"], verdict["reason"])
                shown_verdict = verdict["status"]
            alert = database.record_alert_exposure(
                conn, endpoint["id"], visit_id, event["domain"], severity, reason, verdict=shown_verdict, browser=event["browser"],
                source=database.SOURCE_BROWSER, observed_at=event["visited_at"], detail=detail)
        _shadow(conn, visit_id, event["domain"], severity, alert)
    finally:
        conn.close()
    answer = {
        "ok": True,
        "visit_id": visit_id,
        "domain": event["domain"],
        "reputation": verdict,
        "alert_id": alert["alert_id"] if alert else None,
        "duplicate": duplicate,
    }
    if address:
        answer["address_check"] = {"state": address["state"], "verdict": address["status"], "alert_severity": page_severity, "reused": address["reused"]}
    return jsonify(answer), 201


def _shadow(conn, visit_id, domain, legacy_severity, alert):
    """Phase F3.17 SHADOW MODE: record what the proposed corroborated policy would have decided next to the decision just taken. Information only: it runs after the alert
    decision, receives it as a value, writes only its own table and can never raise (shadow.record swallows every error)."""
    shadow.record(conn, visit_id, domain, legacy_severity, alert["alert_id"] if alert else None)


def _history_visit(conn, endpoint, event):
    """A new LOCAL visit the agent found in Chrome's or Edge's own history (host only). It is a website visit, so it takes the
    same road as an extension visit: normalised domain -> cached reputation (the provider only when the cache has no valid
    answer) -> stored -> alert if dangerous. Differences: it is stored with its own source so it is never mistaken for an
    extension visit, its repeats collapse over the agent window (5 minutes, per computer + browser + domain, decided before any
    lookup), and the extension wins when both reported (read-time coverage in database.py, either arrival order)."""
    domain, browser = event["domain"], event["browser"]
    duplicate_id = database.find_recent_visit(
        conn, endpoint["id"], domain, None, event["observed_at"],
        window_seconds=database.AGENT_DEDUPE_WINDOW_SECONDS, source=database.SOURCE_BROWSER_HISTORY, browser=browser)
    if duplicate_id is not None:
        return jsonify({"ok": True, "visit_id": duplicate_id, "domain": domain, "source": database.SOURCE_BROWSER_HISTORY,
                        "duplicate": True, "alert_id": None}), 201
    verdict = reputation.check_domain(conn, domain, source="agent", deadline=reputation.Deadline())
    visit_id = database.insert_visit(conn, endpoint["id"], domain, None, browser, event["observed_at"], verdict["status"],
                                     source=database.SOURCE_BROWSER_HISTORY, level=verdict.get("level"))
    alert = None
    severity = reputation.alert_severity_for(verdict)
    if severity:
        reason = "%s visited a website identified as %s (%s). %s" % (
            database.visit_device_name(conn, visit_id), verdict["status"].lower(), domain, verdict["reason"])
        alert = database.record_alert_exposure(
            conn, endpoint["id"], visit_id, domain, severity, reason, verdict=verdict["status"], browser=browser,
            source=database.SOURCE_BROWSER_HISTORY, observed_at=event["observed_at"])
    _shadow(conn, visit_id, domain, severity, alert)
    return jsonify({"ok": True, "visit_id": visit_id, "domain": domain, "source": database.SOURCE_BROWSER_HISTORY,
                    "reputation": verdict, "alert_id": alert["alert_id"] if alert else None,
                    "duplicate": False}), 201


@app.route("/api/network-events", methods=["POST"])
@auth.sensor_api
@require_api_key
def api_network_event():
    """One observation from the Windows network agent: this computer looked up <domain> (DNS-cache
    collector) or a program on it connected to <destination_ip> (native collector).

    Two levels, never mixed:
      * a DOMAIN is a meaningful destination: same pipeline as browser visits (validation, endpoint upsert,
        5-minute duplicate rule, cached reputation check limited by AGENT_BUDGET, alert), stored as source AGENT
        and shown as "Contacted domain", never as a visit;
      * a connection known only by IP address is raw network telemetry: it is NOT website history. It has no
        domain to look up, so it only increments a per computer + program + day counter (the address, port and
        process id are not stored), and it never reaches the reputation service.
    The agent never talks to VirusTotal."""
    event = validate_network_event(json_body())
    ip_only = event["destination_ip"] is not None
    # the label shown and used for dedupe: the domain, or - when only an address is known - that address
    label = event["destination_ip"] if ip_only else event["domain"]
    conn = database.get_connection()
    try:
        refused = credential_gate(conn, event["endpoint_uid"])
        if refused:
            return refused
        endpoint = database.upsert_endpoint(
            conn, event["endpoint_uid"], event["computer_name"], event["username"],
            username_provided=event["username_provided"], agent_version=event["agent_version"])
        if ip_only and not is_public_address(label):
            return jsonify({"ok": True, "ignored": "not_a_public_address"}), 200
        if not ip_only and is_non_public_domain(label):
            return jsonify({"ok": True, "ignored": "not_a_public_domain"}), 200
        if event["via"] == "BROWSER_HISTORY":
            return _history_visit(conn, endpoint, event)
        if ip_only:
            # Level 1, raw network telemetry: a program connected to an address. There is no domain to look up and no
            # second reputation system, and it is NOT website history, so it is only counted per computer, program and day.
            database.record_network_activity(conn, endpoint["id"], event["process_name"], event["process_kind"], event["observed_at"])
            return jsonify({"ok": True, "aggregated": True, "destination_ip": event["destination_ip"], "source": database.SOURCE_AGENT,
                            "duplicate": False, "alert_id": None}), 201
        duplicate_id = database.find_recent_visit(
            conn, endpoint["id"], label, None, event["observed_at"],
            window_seconds=database.AGENT_DEDUPE_WINDOW_SECONDS, source=database.SOURCE_AGENT)
        if duplicate_id is not None:           # decided before any reputation lookup: a repeat costs nothing
            return jsonify({"ok": True, "visit_id": duplicate_id, "domain": event["domain"],
                            "destination_ip": event["destination_ip"], "source": database.SOURCE_AGENT,
                            "duplicate": True, "alert_id": None}), 201
        verdict = reputation.check_domain(conn, label, budget=reputation.AGENT_BUDGET, source="agent", deadline=reputation.Deadline())
        visit_id = database.insert_visit(
            conn, endpoint["id"], label, None, None, event["observed_at"], verdict["status"], source=database.SOURCE_AGENT,
            level=verdict.get("level"))
        alert = None
        severity = reputation.alert_severity_for(verdict)
        if severity:
            reason = "%s contacted a domain identified as %s (%s). %s" % (
                database.visit_device_name(conn, visit_id), verdict["status"].lower(), label, verdict["reason"])
            alert = database.record_alert_exposure(
                conn, endpoint["id"], visit_id, label, severity, reason, verdict=verdict["status"], browser=None,
                source=database.SOURCE_AGENT, observed_at=event["observed_at"])
        _shadow(conn, visit_id, label, severity, alert)
    finally:
        conn.close()
    return jsonify({"ok": True, "visit_id": visit_id, "domain": event["domain"], "destination_ip": event["destination_ip"],
                    "source": database.SOURCE_AGENT, "reputation": verdict, "alert_id": alert["alert_id"] if alert else None,
                    "duplicate": False}), 201


# --------------------------------------------------------------------
# Dashboard data (read-only GETs used by the pages; no endpoint secrets)
# --------------------------------------------------------------------
@app.route("/api/status", methods=["GET"])
def api_status():
    conn = database.get_connection()
    try:
        summary, verdict = build_state(conn)
        ti = threat_intel_view(conn)
        sources = reputation.source_overview(conn)
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "sources": [dict((k, s[k]) for k in ("name", "configured", "enabled", "status", "last_success_at")) for s in sources],
        "source_counts": reputation.source_counts(sources),
        "summary": summary,
        "overview": verdict,
        "provider_configured": bool(config.VT_API_KEY),
        "threat_intel": ti,
        "dev_mode": dev_mode(),
        "server_time": database.now_str(),
    })


@app.route("/api/visits", methods=["GET"])
def api_visits():
    """Visits newer than ?after_id= (newest first) - or, with window=1, the newest `limit` LOGICAL visits whatever their id
    (the same list the page was rendered from). The pages poll with window=1 and reconcile what they show with it, so a visit
    whose supporting evidence arrives later, or whose primary record changes, is updated in place instead of duplicated.
    Optional: status, source (BROWSER, BROWSER_HISTORY or AGENT), q (search), active=1 (the dashboard view: hides archived
    computers and agent lookups already explained by a browser visit), physical=1 (audit view)."""
    after_id = request.args.get("after_id", default=0, type=int) or 0
    limit = min(max(request.args.get("limit", default=50, type=int) or 50, 1), 200)
    active_only = request.args.get("active") == "1"
    conn = database.get_connection()
    try:
        if request.args.get("window") == "1":
            rows = database.recent_visits(conn, limit=limit, status=status_filter(), query=search_term(), active_only=active_only,
                                          source=source_filter(), hide_covered=active_only, include_raw=raw_filter(),
                                          physical=physical_filter())
        else:
            rows = database.visits_after(conn, after_id, limit=limit, status=status_filter(),
                                         query=search_term(), active_only=active_only, source=source_filter(),
                                         hide_covered=active_only, include_raw=raw_filter(), physical=physical_filter())
        visits = visit_views(conn, rows)
        newest = database.max_visit_id(conn)
    finally:
        conn.close()
    if request.args.get("window") == "1":
        return jsonify({"ok": True, "visits": visits, "last_id": newest, "window": True})
    return jsonify({"ok": True, "visits": visits, "last_id": visits[0]["id"] if visits else after_id})


@app.route("/api/endpoints", methods=["GET"])
def api_endpoints():
    """Computers (devices, each with its sensors) with live status, for the Computers page polling (?archived=1 for the archived
    list). `id` is the id of the computer's first sensor, kept so older links and the archive buttons keep working. No UID and no
    credential is ever included."""
    conn = database.get_connection()
    try:
        rows = [endpoint_view(r) for r in database.list_devices(conn, archived=request.args.get("archived") == "1")]
    finally:
        conn.close()
    fields = ("id", "computer_name", "username", "browser", "status", "last_seen_label", "last_seen_relative",
              "websites_today", "contacted_today", "has_agent", "threats_today", "visibility", "visibility_label",
              "visibility_hint", "extension_silent", "device_id", "identity", "identity_label", "verified", "sensor_count", "online_sensor_count",
              "identity_level", "identity_short", "identity_explanation", "identity_tone", "identity_admin_approved", "former_device", "sensors")
    return jsonify({"ok": True, "endpoints": [{k: r[k] for k in fields} for r in rows]})


# --------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------
@app.route("/")
def dashboard():
    conn = database.get_connection()
    try:
        database.apply_retention(conn)
        summary, verdict = build_state(conn)
        cursor = database.max_visit_id(conn)       # read before the rows: a racing insert is re-fetched, never missed
        visits = visit_views(conn, database.recent_visits(conn, limit=8, active_only=True, hide_covered=True))
        activity = [network_activity_view(r) for r in database.network_activity_today(conn, limit=8)]
        pool = visit_views(conn, database.recent_visits(conn, limit=60, active_only=True, hide_covered=True))
        alert_rows = database.list_alerts(conn, limit=200)
        sources = reputation.source_overview(conn)
    finally:
        conn.close()
    # Phase F3.12: the most recent visits the risk score finds suspicious or worse, and the open alerts per computer
    risky = sorted([v for v in pool if (v.get("risk_score") or 0) >= 40], key=lambda v: v["visited_at"], reverse=True)[:6]
    by_computer = {}
    for a in alert_rows:
        if a["status"] != "OPEN":
            continue
        entry = by_computer.setdefault(a["computer_name"], {"computer": a["computer_name"], "open": 0, "high": 0})
        entry["open"] += 1
        entry["high"] += 1 if a["severity"] == "HIGH" else 0
    alerts_by_computer = sorted(by_computer.values(), key=lambda e: (-e["high"], -e["open"], e["computer"]))
    return render_template("dashboard.html", summary=summary, overview=verdict, visits=visits, last_id=cursor,
                           network_activity=activity, days=requested_days(), risky=risky, alerts_by_computer=alerts_by_computer, sources=sources, source_counts=reputation.source_counts(sources),
                           score_tooltip=risk.SCORE_TOOLTIP)


def requested_days():
    """The reporting period asked for in the address (?days=): 7, 14 or 30; anything else is the default of 7."""
    try:
        days = int(request.args.get("days", "7"))
    except (TypeError, ValueError):
        return 7
    return days if days in analytics.PERIODS else 7


@app.route("/computers/<int:device_id>")
def computer_detail(device_id):
    """One computer: its observed web exposure, monitoring coverage and evidence. The page only holds the computer's name and identity; every number
    is fetched by the page from the read-only analytics API, so the page and the API cannot disagree."""
    conn = database.get_connection()
    try:
        computer = next((c for c in database.list_devices(conn) if c["device_id"] == device_id), None)
    finally:
        conn.close()
    if computer is None:
        abort(404)
    return render_template("computer_detail.html", computer=computer, days=requested_days())


@app.route("/browsing")
def browsing():
    status, query, source = status_filter(), search_term(), source_filter()
    conn = database.get_connection()
    try:
        cursor = database.max_visit_id(conn)
        visits = visit_views(conn, database.recent_visits(conn, limit=200, status=status, query=query, source=source,
                                                          include_raw=raw_filter(), physical=physical_filter()))
        has_agent_data = conn.execute("SELECT 1 FROM web_visits WHERE source != 'BROWSER' LIMIT 1").fetchone() is not None
    finally:
        conn.close()
    return render_template("browsing.html", visits=visits, active_status=status, query=query or "", last_id=cursor,
                           active_source=source, show_sources=has_agent_data or source is not None, physical=physical_filter(),
                           source_labels=overview.SOURCE_LABELS)


@app.route("/visits/<int:visit_id>")
def visit_detail(visit_id):
    """'View analysis': why the system decided what it did about one website visit - the overall verdict, which telemetry
    sources saw the visit, and what each reputation provider found (or why it did not check)."""
    conn = database.get_connection()
    try:
        row = database.get_visit(conn, visit_id)
        if row is None:
            abort(404)
        analysis = reputation.analysis_bulk(conn, [row["domain"]]).get(row["domain"])
        supporting = database.supporting_records(conn, row)
        primary = database.primary_record(conn, row)
    finally:
        conn.close()
    visit = visit_view(row, analysis=analysis)
    latest = (analysis or {}).get("overall")
    conn = database.get_connection()
    try:
        ids = [row["id"]] + ([primary["id"]] if primary else [])
        address_rows = database.url_evidence_for_visits(conn, ids)
        alert_row = conn.execute("SELECT a.severity FROM alert_events e JOIN alerts a ON a.id = e.alert_id WHERE e.web_visit_id IN (%s) ORDER BY a.id DESC LIMIT 1" % ",".join("?" * len(ids)),
                                 ids).fetchone()
    finally:
        conn.close()
    address_checks = reputation.address_cards([e for rows_ in address_rows.values() for e in rows_])
    page_raised = any(c["raised_verdict"] for c in address_checks)
    url_rows = [e for rows_ in address_rows.values() for e in rows_]
    assessment = None if row["dest_ip"] or not analysis else risk.assess(analysis.get("providers") or [], url_rows, configured_sources())
    sources = [] if assessment is None else ([risk.normalized(c) for c in analysis["providers"]] + [risk.normalized(None, u) for u in url_rows])
    alert_severity = alert_row["severity"] if alert_row else None
    provider_panels = [] if row["dest_ip"] or not analysis else panels.build_all(analysis.get("providers") or [], url_rows, configured_sources(), page_path=reputation.page_path_of(row))          # Phases F3.19 / F3.20
    discrepancy = risk.compare_with_alert(assessment["score"], alert_severity, assessment["weak_only"]) if assessment else None
    return render_template(
        "visit_detail.html", v=visit, analysis=analysis, ip_only=bool(row["dest_ip"]), address_checks=address_checks, page_path=reputation.page_path_of(row), assessment=assessment, sources=sources, panels=provider_panels, alert_severity=alert_severity, discrepancy=discrepancy,
        score_tooltip=risk.SCORE_TOOLTIP,
        supporting=[{"id": r["id"], "label": overview.source_label(database.SOURCE_BROWSER_HISTORY), "time": r["visited_at"]} for r in supporting],
        primary=({"id": primary["id"], "label": overview.source_label(database.SOURCE_BROWSER), "time": primary["visited_at"]} if primary else None),
        differs=bool(latest and latest["status"] != row["reputation_status"] and row["reputation_status"] != "UNKNOWN" and not page_raised),
        latest_status=latest["status"] if latest else None)


def alert_evidence(card, analysis, url_evidence, visit_urls, configured=None):
    """Risk assessment of the most serious visit of an alert (each event keeps its own visit), the five sources' verdicts for it, and the page address when it is safe to show."""
    out = {"risk": None, "sources": [], "page_label": None, "discrepancy": None}
    if not analysis:
        return out
    best, best_visit = None, None
    for event in card["events"]:
        visit_id = event.get("web_visit_id")
        if not visit_id:
            continue
        assessment = risk.assess(analysis.get("providers") or [], url_evidence.get(visit_id) or [], configured)
        if best is None or assessment["score"] > best["score"]:
            best, best_visit = assessment, visit_id
    if best is None:
        return out
    address = visit_urls.get(best_visit)
    label = None
    if address:
        label = urlcheck.display_path(address) if urlcheck.assess(address)["eligible"] else ("the site's front page" if urlcheck.assess(address)["skip"] == "no-path" else "(address hidden: it looks like a private link)")
    out.update(risk=best, page_label=label, discrepancy=risk.compare_with_alert(best["score"], card["severity"], best["weak_only"]),
               sources=[risk.normalized(c) for c in analysis["providers"]] + [risk.normalized(None, u) for u in (url_evidence.get(best_visit) or [])])
    return out


@app.route("/alerts")
def alerts():
    conn = database.get_connection()
    try:
        rows = database.list_alerts(conn)
    finally:
        conn.close()
    conn = database.get_connection()
    try:
        history = database.alert_events(conn, [r["id"] for r in rows])
        analyses = reputation.analysis_bulk(conn, [r["domain"] for r in rows])
        event_visits = sorted(set(e["web_visit_id"] for events in history.values() for e in events if e.get("web_visit_id")))[-300:]
        url_evidence = database.url_evidence_for_visits(conn, event_visits)
        decisions = shadow.decisions_for_visits(conn, event_visits)          # Phase F3.17: read-only shadow snapshots (alerts raised before shadow recording have none = historical)
        visit_urls = {}
        for start in range(0, len(event_visits), 400):
            chunk = event_visits[start:start + 400]
            for v in conn.execute("SELECT id, sanitized_url FROM web_visits WHERE id IN (%s)" % ",".join("?" * len(chunk)), chunk):
                visit_urls[v["id"]] = v["sanitized_url"]
    finally:
        conn.close()
    cards = []
    configured = configured_sources()
    for row in rows:
        card = dict(row)
        card["events"] = history.get(card["id"], [])
        card["exposures"] = card.get("exposure_count") or 1
        card["last_exposure_label"] = database.time_label(card["last_exposure_at"]) if card.get("last_exposure_at") else card.get("created_at")
        card["escalated_label"] = database.time_label(card["escalated_at"]) if card.get("escalated_at") else None
        card["previous_title"] = {"HIGH": "Dangerous", "MEDIUM": "Needs review"}.get(card.get("previous_severity") or "", "")
        from_agent = card.get("visit_source") == database.SOURCE_AGENT
        card["detected_label"] = database.time_label(card["created_at"])
        if from_agent:       # a DNS lookup seen by the network agent, not a page the browser opened
            card["title"] = overview.ALERT_TITLES_AGENT.get(card["severity"], "Alert")
            card["target_label"] = "Domain contacted"
            card["why"] = reputation.WHY_IT_MATTERS_AGENT.get(card["severity"], "")
            card["action"] = reputation.RECOMMENDED_ACTION_AGENT.get(card["severity"], "")
        else:
            card["title"] = overview.ALERT_TITLES.get(card["severity"], "Alert")
            card["target_label"] = "Website"
            card["why"] = reputation.WHY_IT_MATTERS.get(card["severity"], "")
            card["action"] = reputation.RECOMMENDED_ACTION.get(card["severity"], "")
        card["source_label"] = overview.source_label(database.SOURCE_AGENT if from_agent else (card.get("visit_source") or database.SOURCE_BROWSER))
        page_events = [e for e in card["events"] if reputation.URL_FINDING in (e.get("detail") or "")]
        other_events = [e for e in card["events"] if reputation.URL_FINDING not in (e.get("detail") or "") and not e.get("corroborates_event_id") and e.get("kind") != "ESCALATED"]
        card["url_findings"] = [e["detail"].split("; ")[-1] for e in page_events]
        if page_events:
            card["scope_label"] = "Specific page(s) only - other pages of this site were not flagged" if not other_events else "The whole site and specific page(s)"
            if not other_events:
                card["why"] = reputation.WHY_IT_MATTERS_PAGE.get(card["severity"], card["why"])
        else:
            card["scope_label"] = None
        card.update(alert_evidence(card, analyses.get(card["domain"]), url_evidence, visit_urls, configured))          # Phase F3.12: risk score, coverage, per-source verdicts, page
        first_visit = next((e["web_visit_id"] for e in card["events"] if e.get("web_visit_id")), None)
        card["explain"] = shadow.explain_alert(card, card["events"], (analyses.get(card["domain"]) or {}).get("providers") or [], decisions.get(first_visit))          # Phase F3.17
        cards.append(card)
    return render_template("alerts.html", alerts=cards, actions=reputation.RECOMMENDED_ACTION)


@app.route("/shadow")
def shadow_review():
    """Phase F3.17: READ-ONLY comparison of the running (legacy) alert decisions with the proposed corroborated policy. Nothing on this page changes an alert or a decision."""
    conn = database.get_connection()
    try:
        counts = shadow.summary(conn)
        recent = shadow.recent(conn, 100, only_differences=request.args.get("differences") == "1")
        history = shadow.reconstruct(conn)
    finally:
        conn.close()
    return render_template("shadow.html", counts=counts, recent=recent, history=history, only_differences=request.args.get("differences") == "1")


@app.route("/alerts/<int:alert_id>/close", methods=["POST"])
def close_alert(alert_id):
    conn = database.get_connection()
    try:
        if not database.close_alert(conn, alert_id):
            abort(404)
    finally:
        conn.close()
    return redirect(url_for("alerts"))


@app.route("/endpoints")
def endpoints():
    show_archived = request.args.get("archived") == "1"
    conn = database.get_connection()
    try:
        rows = [endpoint_view(r) for r in database.list_devices(conn, archived=show_archived)]
        archived_count = database.count_archived(conn)
    finally:
        conn.close()
    show_contacted = any(row["has_agent"] for row in rows)       # the extra column only appears once an agent exists
    return render_template("endpoints.html", endpoints=rows, show_archived=show_archived, archived_count=archived_count,
                           show_contacted=show_contacted)


def _set_archived(endpoint_id, archived):
    conn = database.get_connection()
    try:
        if not database.set_archived(conn, endpoint_id, archived):
            abort(404)
    finally:
        conn.close()
    return redirect(url_for("endpoints", archived="1") if request.form.get("view") == "archived" else url_for("endpoints"))


@app.route("/endpoints/<int:endpoint_id>/archive", methods=["POST"])
def archive_endpoint(endpoint_id):
    """Hide a computer (for example a dead test installation) from the Computers page
    and the dashboard counts. Nothing is deleted: its visits and alerts stay."""
    return _set_archived(endpoint_id, True)


@app.route("/endpoints/<int:endpoint_id>/restore", methods=["POST"])
def restore_endpoint(endpoint_id):
    return _set_archived(endpoint_id, False)


def _set_device_archived(device_id, archived):
    conn = database.get_connection()
    try:
        if not database.set_former_device_archived(conn, device_id, archived):
            abort(404)
    finally:
        conn.close()
    return redirect(url_for("endpoints", archived="1") if request.form.get("view") == "archived" else url_for("endpoints"))


@app.route("/devices/<int:device_id>/archive", methods=["POST"])
def archive_device(device_id):
    """Archive a FORMER computer (it lost its last sensor): it stays listed as not reporting, with its evidence, until an administrator does this.
    Nothing is deleted. A computer that still has sensors is archived through them (/endpoints/<id>/archive)."""
    return _set_device_archived(device_id, True)


@app.route("/devices/<int:device_id>/restore", methods=["POST"])
def restore_device(device_id):
    return _set_device_archived(device_id, False)


if config.TEST_MODE:          # a test run: the database is a throw-away temporary file (config refuses anything else), prepared at once as before
    database.init_db()

def _provider_lines():
    """One line per source for the start-up report: the state AS CONFIGURED (nothing is asked of any provider here)."""
    words = {"ACTIVE": "ready", "DISABLED": "off", "NOT_CONFIGURED": "no key", "UNAVAILABLE": "unavailable", "ERROR": "error"}
    return ["%s: %s" % (row["name"], words.get(row["state"], str(row["state"]).lower())) for row in reputation.provider_states()]


def _port_in_use(host, port):
    import socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        return probe.connect_ex((LOOPBACK_HOSTS[0] if host in ("0.0.0.0", "", LOOPBACK_HOSTS[1]) else host, port)) == 0
    except OSError:
        return False
    finally:
        probe.close()


def main():
    """`python app.py`: everything needed to run, in one process and one command (no Gunicorn, no worker, no manage_db/manage_admin step)."""
    import os
    import platform
    import signal

    if _port_in_use(config.HOST, config.PORT):
        sys.stderr.write("Port %d is already in use on %s: another copy of the monitor (or another program) is running. Stop it first, or set PORT in .env.\n" % (config.PORT, config.HOST))
        return 1
    existed = os.path.isfile(config.DATABASE_PATH)
    try:
        database.init_db()      # idempotent: creates a new database, or only adds what an older one is missing; never touches a row
    except Exception as error:
        sys.stderr.write("[cannot start] The database %s could not be prepared (%s: %s). Check that the folder is writable by this user and the disk is not full; if the file is damaged, "
                         "move it away (it is never deleted for you) and start again to get a new one.\n" % (config.DATABASE_PATH, type(error).__name__, error))
        return 1
    shown_host = LOOPBACK_HOSTS[0] if config.HOST in ("0.0.0.0", "") else config.HOST
    print("=" * 72)
    print(" Website Monitor  |  Python %s on %s" % (platform.python_version(), platform.system()))
    print(" Address       : http://%s:%d/%s" % (shown_host, config.PORT, "   (listening on ALL interfaces; the API key protects the sensor routes)" if config.HOST == "0.0.0.0" else "   (this computer only; set HOST=0.0.0.0 in .env to allow other computers)"))
    print(" Database      : %s (%s)" % (config.DATABASE_PATH, "existing, kept as it is" if existed else "NEW, created now"))
    print(" Alert policy  : %s   |  API key for sensors: %s" % (config.SEVERITY_POLICY, "set in .env" if config.API_KEY else "NOT set (development mode)"))
    for line in _provider_lines():
        print("   source %s" % line)
    code = auth.setup_code()
    if code:
        print("-" * 72)
        print(" FIRST-TIME SETUP: no administrator exists yet.")
        print("   Open  http://%s:%d/setup  and type this one-time setup code: %s" % (shown_host, config.PORT, code))
        print("   (the code is shown only here and changes at every start; the page disappears once the administrator exists)")
    else:
        print(" Sign in at http://%s:%d/login" % (shown_host, config.PORT))
    print(" Stop with Ctrl+C (or SIGTERM). Starting a second copy is refused while this one runs.")
    print("=" * 72, flush=True)
    if lan_exposed_without_key():
        sys.stderr.write(
            "\n*** WARNING: API_KEY is empty (DEV MODE) and the server listens on %s. "
            "Anyone who can reach port %d can submit data. Set API_KEY in .env for LAN use. ***\n\n"
            % (config.HOST, config.PORT))

    def _terminate(signum, frame):
        raise KeyboardInterrupt()

    for name in ("SIGTERM", "SIGBREAK"):                   # a polite kill (and Ctrl+Break on Windows) ends the server as cleanly as Ctrl+C
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _terminate)
            except (ValueError, OSError):
                pass
    try:
        app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    print("Website Monitor stopped cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
