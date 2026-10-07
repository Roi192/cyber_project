"""Website-visit monitoring for small businesses - Flask application.

Many computers (browser extensions) POST the websites they visit to this one
central server. The server validates and sanitizes everything it receives,
checks the domain's reputation (cached), records the visit, raises an alert for
dangerous destinations and shows it all on a simple dashboard.
"""
import hmac
import sys
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

import config
import database
import overview
from services import reputation
from validation import ValidationError, is_browser_noise, validate_registration, validate_web_event

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
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
        "status_labels": STATUS_LABELS,
        "status_hints": STATUS_HINTS,
        "threat_intel": ti,
        "dev_mode": dev_mode(),
        "lan_exposed_without_key": lan_exposed_without_key(),
    }


def build_state(conn):
    """Dashboard numbers plus the truthful verdict. summary["security_status"] is the
    full verdict (ALERT / WARNING / LIMITED / OK), not just the alert level."""
    summary = database.dashboard_summary(conn)
    ti = reputation.provider_status(conn)
    alerts = database.open_alert_items(conn, limit=3)
    offline = database.long_offline_computers(conn, overview.OFFLINE_ATTENTION_SECONDS)
    verdict = overview.build_overview(summary, ti, alerts, offline)
    summary["security_status"] = verdict["status"]
    summary["coverage_percent"] = verdict["coverage"]["percent"]
    return summary, verdict


def visit_view(row, now=None):
    """A visit as a dict with the business-readable fields the pages need."""
    item = dict(row)
    item["time_label"] = database.time_label(item["visited_at"], now)
    item["status_label"] = STATUS_LABELS.get(item["reputation_status"], STATUS_LABELS["UNKNOWN"])
    item["status_hint"] = STATUS_HINTS.get(item["reputation_status"], STATUS_HINTS["UNKNOWN"])
    return item


def search_term():
    return request.args.get("q", "").strip()[:MAX_SEARCH_LENGTH] or None


def status_filter():
    status = request.args.get("status", "").upper() or None
    return status if status in STATUS_LABELS else None


def _register(conn, data):
    return database.upsert_endpoint(
        conn, data["endpoint_uid"], data["computer_name"], data["username"],
        browser=data["browser"], username_provided=data["username_provided"])


# --------------------------------------------------------------------
# Endpoint-facing API (all protected by the same X-Api-Key logic)
# --------------------------------------------------------------------
@app.route("/api/ping", methods=["GET"])
@require_api_key
def api_ping():
    """Connection test used by the extension Options page. Read-only: it
    changes nothing, but it is authenticated, so a wrong key gives 401."""
    return jsonify({"ok": True, "service": "website-monitor", "auth_required": bool(config.API_KEY),
                    "server_time": database.now_str()})


@app.route("/api/endpoints/register", methods=["POST"])
@require_api_key
def api_register_endpoint():
    data = validate_registration(json_body())
    conn = database.get_connection()
    try:
        row = _register(conn, data)
    finally:
        conn.close()
    return jsonify({"ok": True, "endpoint_id": row["id"], "endpoint_uid": row["endpoint_uid"]}), 201


@app.route("/api/heartbeat", methods=["POST"])
@require_api_key
def api_heartbeat():
    """Answers one question: is this browser online? It updates the single
    last_seen value of the endpoint. No row is inserted per heartbeat and no
    history is kept."""
    data = validate_registration(json_body())
    conn = database.get_connection()
    try:
        row = _register(conn, data)
    finally:
        conn.close()
    return jsonify({"ok": True, "endpoint_id": row["id"], "status": database.endpoint_status(row["last_seen"])})


@app.route("/api/web-events", methods=["POST"])
@require_api_key
def api_web_event():
    event = validate_web_event(json_body())
    conn = database.get_connection()
    try:
        endpoint = database.upsert_endpoint(
            conn, event["endpoint_uid"], event["computer_name"], event["username"],
            browser=event["endpoint_browser"], username_provided=event["username_provided"])
        if is_browser_noise(event["domain"], event["sanitized_url"]):
            # browser-generated page (e.g. the Edge New Tab): the endpoint is alive, but this is not a visit
            return jsonify({"ok": True, "ignored": "browser_internal_page"}), 200
        verdict = reputation.check_domain(conn, event["domain"])
        # Server-side dedupe of reload/redirect bursts (same computer + same page within a few seconds).
        visit_id = database.find_recent_visit(
            conn, endpoint["id"], event["domain"], event["sanitized_url"], event["visited_at"])
        duplicate = visit_id is not None
        if not duplicate:
            visit_id = database.insert_visit(
                conn, endpoint["id"], event["domain"], event["sanitized_url"],
                event["browser"], event["visited_at"], verdict["status"],
            )
        alert_id = None
        severity = reputation.ALERT_SEVERITY.get(verdict["status"])
        if severity:
            reason = "%s visited a website identified as %s (%s). %s" % (
                endpoint["computer_name"], verdict["status"].lower(), event["domain"], verdict["reason"])
            alert_id, _created = database.create_alert_if_new(
                conn, endpoint["id"], visit_id, event["domain"], severity, reason)
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "visit_id": visit_id,
        "domain": event["domain"],
        "reputation": verdict,
        "alert_id": alert_id,
        "duplicate": duplicate,
    }), 201


# --------------------------------------------------------------------
# Dashboard data (read-only GETs used by the pages; no endpoint secrets)
# --------------------------------------------------------------------
@app.route("/api/status", methods=["GET"])
def api_status():
    conn = database.get_connection()
    try:
        summary, verdict = build_state(conn)
        ti = threat_intel_view(conn)
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "summary": summary,
        "overview": verdict,
        "provider_configured": bool(config.VT_API_KEY),
        "threat_intel": ti,
        "dev_mode": dev_mode(),
        "server_time": database.now_str(),
    })


@app.route("/api/visits", methods=["GET"])
def api_visits():
    """Visits newer than ?after_id= (newest first) - polled by the pages every few seconds.
    Optional: status, q (search), active=1 (hide archived computers, used by the dashboard)."""
    after_id = request.args.get("after_id", default=0, type=int) or 0
    limit = min(max(request.args.get("limit", default=50, type=int) or 50, 1), 200)
    active_only = request.args.get("active") == "1"
    conn = database.get_connection()
    try:
        rows = database.visits_after(conn, after_id, limit=limit, status=status_filter(),
                                     query=search_term(), active_only=active_only)
    finally:
        conn.close()
    visits = [visit_view(r) for r in rows]
    return jsonify({"ok": True, "visits": visits, "last_id": visits[0]["id"] if visits else after_id})


@app.route("/api/endpoints", methods=["GET"])
def api_endpoints():
    """Computers with live status, for the Computers page polling (?archived=1 for the
    archived list). The internal endpoint_uid is deliberately not included."""
    conn = database.get_connection()
    try:
        rows = database.list_endpoints(conn, archived=request.args.get("archived") == "1")
    finally:
        conn.close()
    fields = ("id", "computer_name", "username", "browser", "status", "last_seen_label", "last_seen_relative",
              "websites_today", "threats_today")
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
        visits = [visit_view(r) for r in database.recent_visits(conn, limit=8, active_only=True)]
    finally:
        conn.close()
    return render_template("dashboard.html", summary=summary, overview=verdict, visits=visits, last_id=cursor)


@app.route("/browsing")
def browsing():
    status, query = status_filter(), search_term()
    conn = database.get_connection()
    try:
        cursor = database.max_visit_id(conn)
        visits = [visit_view(r) for r in database.recent_visits(conn, limit=200, status=status, query=query)]
    finally:
        conn.close()
    return render_template("browsing.html", visits=visits, active_status=status, query=query or "", last_id=cursor)


@app.route("/alerts")
def alerts():
    conn = database.get_connection()
    try:
        rows = database.list_alerts(conn)
    finally:
        conn.close()
    cards = []
    for row in rows:
        card = dict(row)
        card["title"] = overview.ALERT_TITLES.get(card["severity"], "Alert")
        card["detected_label"] = database.time_label(card["created_at"])
        card["why"] = reputation.WHY_IT_MATTERS.get(card["severity"], "")
        card["action"] = reputation.RECOMMENDED_ACTION.get(card["severity"], "")
        cards.append(card)
    return render_template("alerts.html", alerts=cards, actions=reputation.RECOMMENDED_ACTION)


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
        rows = database.list_endpoints(conn, archived=show_archived)
        archived_count = database.count_archived(conn)
    finally:
        conn.close()
    return render_template("endpoints.html", endpoints=rows, show_archived=show_archived, archived_count=archived_count)


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


database.init_db()

if __name__ == "__main__":
    if lan_exposed_without_key():
        sys.stderr.write(
            "\n*** WARNING: API_KEY is empty (DEV MODE) and the server listens on %s. "
            "Anyone who can reach port %d can submit data. Set API_KEY in .env for LAN use. ***\n\n"
            % (config.HOST, config.PORT))
    app.run(host=config.HOST, port=config.PORT, debug=False)
