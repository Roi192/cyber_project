"""Website-visit monitoring for small businesses - Flask application.

Endpoints POST the websites their computers visit; the server records
them, checks the domain's reputation (cached), raises an alert for
dangerous destinations and shows everything on a simple dashboard.
"""
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

import config
import database
from services import reputation
from validation import ValidationError, validate_registration, validate_web_event

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["JSON_SORT_KEYS"] = False

STATUS_LABELS = {
    "SAFE": "Safe",
    "SUSPICIOUS": "Suspicious",
    "MALICIOUS": "Malicious",
    "UNKNOWN": "Unknown",
}


# --------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------
def require_api_key(view):
    """When API_KEY is configured, endpoint POSTs must carry it."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if config.API_KEY and request.headers.get("X-Api-Key", "") != config.API_KEY:
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


TI_LABELS = {
    reputation.STATUS_ACTIVE: "Active",
    reputation.STATUS_NOT_CONFIGURED: "Not configured",
    reputation.STATUS_UNAVAILABLE: "Temporarily unavailable",
}


def dev_mode():
    """DEV MODE = no API_KEY configured, so endpoint POSTs are not authenticated."""
    return not config.API_KEY


@app.context_processor
def inject_globals():
    return {
        "status_labels": STATUS_LABELS,
        "ti_labels": TI_LABELS,
        "threat_intel": reputation.provider_status(),
        "dev_mode": dev_mode(),
    }


# --------------------------------------------------------------------
# API
# --------------------------------------------------------------------
@app.route("/api/endpoints/register", methods=["POST"])
@require_api_key
def api_register_endpoint():
    data = validate_registration(json_body())
    conn = database.get_connection()
    try:
        row = database.upsert_endpoint(conn, data["endpoint_uid"], data["computer_name"], data["username"])
    finally:
        conn.close()
    return jsonify({"ok": True, "endpoint_id": row["id"], "endpoint_uid": row["endpoint_uid"]}), 201


@app.route("/api/web-events", methods=["POST"])
@require_api_key
def api_web_event():
    event = validate_web_event(json_body())
    conn = database.get_connection()
    try:
        endpoint = database.upsert_endpoint(conn, event["endpoint_uid"], event["computer_name"], event["username"])
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


@app.route("/api/status", methods=["GET"])
def api_status():
    conn = database.get_connection()
    try:
        summary = database.dashboard_summary(conn)
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "summary": summary,
        "provider_configured": bool(config.VT_API_KEY),
        "threat_intel": reputation.provider_status(),
        "dev_mode": dev_mode(),
        "server_time": database.now_str(),
    })


@app.route("/api/visits", methods=["GET"])
def api_visits():
    """Visits newer than ?after_id= (newest first) - polled by the pages every few seconds."""
    after_id = request.args.get("after_id", default=0, type=int) or 0
    limit = min(max(request.args.get("limit", default=50, type=int) or 50, 1), 200)
    status = request.args.get("status", "").upper() or None
    if status and status not in STATUS_LABELS:
        status = None
    conn = database.get_connection()
    try:
        rows = database.visits_after(conn, after_id, limit=limit, status=status)
    finally:
        conn.close()
    visits = [dict(r) for r in rows]
    return jsonify({"ok": True, "visits": visits, "last_id": visits[0]["id"] if visits else after_id})


# --------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------
@app.route("/")
def dashboard():
    conn = database.get_connection()
    try:
        database.apply_retention(conn)
        summary = database.dashboard_summary(conn)
        visits = database.recent_visits(conn, limit=25)
    finally:
        conn.close()
    return render_template("dashboard.html", summary=summary, visits=visits)


@app.route("/browsing")
def browsing():
    status = request.args.get("status", "").upper() or None
    if status and status not in STATUS_LABELS:
        status = None
    conn = database.get_connection()
    try:
        visits = database.recent_visits(conn, limit=200, status=status)
    finally:
        conn.close()
    return render_template("browsing.html", visits=visits, active_status=status)


@app.route("/alerts")
def alerts():
    conn = database.get_connection()
    try:
        rows = database.list_alerts(conn)
    finally:
        conn.close()
    return render_template("alerts.html", alerts=rows, actions=reputation.RECOMMENDED_ACTION)


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
    conn = database.get_connection()
    try:
        rows = database.list_endpoints(conn)
    finally:
        conn.close()
    return render_template("endpoints.html", endpoints=rows)


database.init_db()

if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=False)
