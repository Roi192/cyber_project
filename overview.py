"""Truthful, derived dashboard state.

Pure presentation logic: it stores nothing, calls nothing and changes no
security decision (reputation thresholds, cache, alerts and sanitization live
elsewhere). Inputs are plain dicts built from existing data, so every rule
here can be tested without a database.

Core rule: UNKNOWN is not SAFE. "All clear" is only shown when there are no open
alerts AND the reputation service works AND enough of today's browsing was
actually evaluated.
"""

# --- documented thresholds -------------------------------------------------
# Share of today's website visits that must have a real verdict (SAFE,
# SUSPICIOUS or MALICIOUS; UNKNOWN does not count) before "All clear" is allowed.
COVERAGE_OK_PERCENT = 80
# An active computer silent for longer than this is listed under "Needs attention"
# as operational information (it never raises an alert and never changes the status).
OFFLINE_ATTENTION_SECONDS = 3600

# Internal status codes are kept (ALERT / WARNING / LIMITED / OK); these are the
# words the business owner sees.
STATUS_TITLES = {
    "ALERT": "Threat detected",
    "WARNING": "Attention required",
    "LIMITED": "Limited visibility",
    "OK": "All clear",
}
STATUS_CSS = {"ALERT": "threat", "WARNING": "attention", "LIMITED": "limited", "OK": "clear"}

# Internal reputation status -> (label, explanation) for business users.
REPUTATION_UI = {
    "SAFE": ("Safe", "No known threat was detected by the reputation service."),
    "SUSPICIOUS": ("Needs review", "This website received suspicious reputation signals and should be reviewed."),
    "MALICIOUS": ("Dangerous", "This website was identified as potentially malicious."),
    "UNKNOWN": ("Not checked", "The system could not currently determine this website's reputation."),
}

# Threat-intelligence state shown to users (internal code -> label).
TI_LABELS = {
    "ACTIVE": "Active",
    "NOT_CONFIGURED": "Not configured",
    "TEMPORARILY_UNAVAILABLE": "Limited",
}

ALERT_TITLES = {"HIGH": "Dangerous website detected", "MEDIUM": "Suspicious website - needs review"}


def reputation_label(status):
    return REPUTATION_UI.get(status, REPUTATION_UI["UNKNOWN"])[0]


def reputation_hint(status):
    return REPUTATION_UI.get(status, REPUTATION_UI["UNKNOWN"])[1]


def coverage(summary):
    """Reputation coverage of today's visits (active computers).
    evaluated = SAFE + SUSPICIOUS + MALICIOUS; UNKNOWN is not evaluated.
    percent is None when there were no visits (0/0 is never 100%) and is rounded
    DOWN, so a single unchecked visit can never show as 100%."""
    total = summary["visits_today"]
    evaluated = summary["evaluated_today"]
    percent = None if total <= 0 else (evaluated * 100) // total
    return {"total": total, "evaluated": evaluated, "unchecked": total - evaluated, "percent": percent}


def _plural(count, singular, plural):
    return singular if count == 1 else plural


def _names(names, limit=3):
    shown = ", ".join(names[:limit])
    return shown + (" and %d more" % (len(names) - limit) if len(names) > limit else "")


def build_overview(summary, ti, alerts, offline_names):
    """summary: database.dashboard_summary(); ti: reputation.provider_status();
    alerts: database.open_alert_items(); offline_names: computers silent for a long time."""
    cov = coverage(summary)
    ti_status = ti["status"]
    low_coverage = cov["percent"] is not None and cov["percent"] < COVERAGE_OK_PERCENT
    no_computers = summary["computers"] == 0
    # computers are enrolled but none of them is online right now: nothing is being observed
    # (operational information, never an alert; heartbeat behaviour is unchanged)
    none_online = summary["computers"] > 0 and summary["online_now"] == 0
    provider_ok = ti_status == "ACTIVE"

    # ---- decision hierarchy ------------------------------------------------
    # 1 open dangerous alert, 2 open suspicious alert, 3 any visibility limitation, 4 all clear.
    # Visibility limitations: reputation service Limited / Not configured, no computer enrolled,
    # enrolled computers but none online, or too little of today's browsing verified.
    if summary["open_high"] > 0:
        status = "ALERT"
    elif summary["open_alerts"] > 0:
        status = "WARNING"
    elif not provider_ok or no_computers or none_online or low_coverage:
        status = "LIMITED"
    else:
        status = "OK"

    affected = ""
    if status in ("ALERT", "WARNING") and alerts:
        wanted = "HIGH" if status == "ALERT" else "MEDIUM"
        matching = [a for a in alerts if a["severity"] == wanted] or alerts
        first = matching[0]
        count = summary["open_high"] if status == "ALERT" else summary["open_alerts"]
        affected = "%s visited %s." % (first["computer_name"], first["domain"])
        if count > 1:
            affected = affected[:-1] + " and %d more open %s." % (count - 1, _plural(count - 1, "alert", "alerts"))

    # ---- hero text ---------------------------------------------------------
    if status == "ALERT":
        message = "A dangerous website was detected on one of your monitored computers. Review the alert immediately."
    elif status == "WARNING":
        message = "A suspicious website visit requires review."
    elif status == "LIMITED":
        if no_computers:
            message = "No computers are being monitored yet. Install the browser extension on a computer to start."
        elif none_online:
            message = ("No monitored computers are currently online. "
                       "No confirmed threats were detected in the available data.")
        elif ti_status == "NOT_CONFIGURED":
            message = ("No confirmed threats were detected, but website reputation checking is not set up, "
                       "so websites cannot be verified.")
        else:
            message = "No confirmed threats were detected, but some website visits could not currently be verified."
    else:
        message = "No suspicious or dangerous websites were detected."

    if cov["total"] == 0:
        coverage_line = "No browsing activity yet today."
    elif cov["unchecked"] > 0:
        coverage_line = "%d of %d website %s today could not be verified." % (
            cov["unchecked"], cov["total"], _plural(cov["total"], "visit", "visits"))
    elif cov["total"] == 1:
        coverage_line = "The website visit today was checked."
    else:
        coverage_line = "All %d website visits today were checked." % cov["total"]

    if status in ("ALERT", "WARNING"):
        action = {"label": "Review alerts", "url": "/alerts"}
    elif status == "LIMITED" and none_online:
        action = {"label": "View computers", "url": "/endpoints"}
    elif cov["unchecked"] > 0:
        action = {"label": "View browsing activity", "url": "/browsing?status=UNKNOWN"}
    else:
        action = {"label": "View browsing activity", "url": "/browsing"}

    # ---- needs attention (derived UI list, not an alert engine) -------------
    items = []
    for a in alerts:
        if a["severity"] == "HIGH":
            items.append({"level": "danger", "text": "Dangerous website: %s visited %s." % (a["computer_name"], a["domain"]),
                          "url": "/alerts"})
        else:
            items.append({"level": "warning", "text": "Needs review: %s visited %s." % (a["computer_name"], a["domain"]),
                          "url": "/alerts"})
    hidden = summary["open_alerts"] - len(alerts)
    if hidden > 0:
        items.append({"level": "warning", "text": "%d more open %s." % (hidden, _plural(hidden, "alert", "alerts")),
                      "url": "/alerts"})
    if ti_status == "NOT_CONFIGURED":
        items.append({"level": "warning", "text": "Website reputation checking is not set up. Websites are shown as Not checked.",
                      "url": None})
    elif ti_status == "TEMPORARILY_UNAVAILABLE":
        items.append({"level": "warning", "text": "The reputation service is temporarily unavailable. "
                                                  "New websites are shown as Not checked.", "url": None})
    elif low_coverage:
        items.append({"level": "warning", "text": "%d of %d website visits today could not be verified." % (
            cov["unchecked"], cov["total"]), "url": "/browsing?status=UNKNOWN"})
    if no_computers:
        items.append({"level": "info", "text": "No computers are being monitored yet. Install the browser extension to start.",
                      "url": "/endpoints"})
    elif none_online:
        items.append({"level": "warning", "text": "No monitored computers are currently online.", "url": "/endpoints"})
    if offline_names:
        items.append({"level": "info", "text": "%d %s offline for more than 1 hour: %s." % (
            len(offline_names), _plural(len(offline_names), "computer has been", "computers have been"), _names(offline_names)),
            "url": "/endpoints"})

    return {
        "status": status,
        "css": STATUS_CSS[status],
        "title": STATUS_TITLES[status],
        "message": message,
        "affected": affected,
        "coverage": cov,
        "coverage_line": coverage_line,
        "action": action,
        "attention": items,
        "ti": dict(ti, label=TI_LABELS.get(ti_status, ti_status)),
    }
