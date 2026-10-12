"""Truthful, derived dashboard state.

Pure presentation logic: it stores nothing, calls nothing and changes no
security decision (reputation thresholds, cache, alerts and sanitization live
elsewhere). Inputs are plain dicts built from existing data, so every rule
here can be tested without a database.

Core rule: UNKNOWN is not SAFE. "All clear" is only shown when there are no open
alerts AND the reputation service works AND enough of today's browsing was
actually evaluated.
"""
import os

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
    "LIMITED": "Limited coverage",
    "OK": "No threats detected",
}
STATUS_CSS = {"ALERT": "threat", "WARNING": "attention", "LIMITED": "limited", "OK": "clear"}

# Internal reputation status -> (label, explanation) for business users.
REPUTATION_UI = {
    "SAFE": ("No threat detected", "No reputation source reported a threat for this website. That is not proof that it is safe: it only means nothing was found."),
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
ALERT_TITLES_AGENT = {"HIGH": "Dangerous domain contacted", "MEDIUM": "Suspicious domain contacted - needs review"}


def reputation_label(status):
    return REPUTATION_UI.get(status, REPUTATION_UI["UNKNOWN"])[0]


def reputation_hint(status):
    return REPUTATION_UI.get(status, REPUTATION_UI["UNKNOWN"])[1]


def coverage(summary):
    """Reputation coverage of today's visits (active computers).
    evaluated = SAFE + SUSPICIOUS + MALICIOUS; UNKNOWN is not evaluated.
    percent is None when there were no visits (0/0 is never 100%) and is rounded
    DOWN, so a single unchecked visit can never show as 100%."""
    # With a network agent the denominator also holds the domains it contacted that no browser
    # visit already explains (database.dashboard_summary builds coverage_total / coverage_evaluated);
    # without one these equal the browser figures, so nothing changes for browser-only installs.
    total = summary.get("coverage_total", summary["visits_today"])
    evaluated = summary.get("coverage_evaluated", summary["evaluated_today"])
    percent = None if total <= 0 else (evaluated * 100) // total
    return {"total": total, "evaluated": evaluated, "unchecked": total - evaluated, "percent": percent}


def _plural(count, singular, plural):
    return singular if count == 1 else plural


def _names(names, limit=3):
    shown = ", ".join(names[:limit])
    return shown + (" and %d more" % (len(names) - limit) if len(names) > limit else "")


# Shown under the status so that no status is read as a statement about all network traffic.
SCOPE_NOTE = ("Based on website visits reported by browser extensions or, where marked, found by the agent in Chrome and Edge "
              "history (private windows are not covered). Network activity seen by the agent is shown separately and is not judged.")

# What can be seen of a computer right now (database.endpoint_visibility)
VISIBILITY_LABELS = {"FULL": "Extension + agent reporting", "BROWSER": "Browser extension only", "HISTORY": "Agent: browser history only",
                     "NETWORK_ONLY": "Agent: network only", "NONE": "No sensor reporting"}
VISIBILITY_HINTS = {
    "FULL": "The browser extension and the Windows agent are both reporting right now: website visits come from the extension, "
            "programs and connections from the agent.",
    "BROWSER": "Only the browser extension is reporting: website visits are visible, network activity is not.",
    "HISTORY": "No browser extension is reporting. Website visits are read from the browser's own history by the network agent "
               "(Chrome and Edge only). Lower confidence than the extension: private windows and cleared history are not covered.",
    "NETWORK_ONLY": "Only the network agent reports for this computer: programs and connections are visible, website visits are not.",
    "NONE": "No sensor is reporting right now (the computer is offline, or the sensors' last reports are missing or too old).",
}


def visibility_label(code):
    return VISIBILITY_LABELS.get(code, VISIBILITY_LABELS["NONE"])


def visibility_hint(code):
    return VISIBILITY_HINTS.get(code, VISIBILITY_HINTS["NONE"])


def build_overview(summary, ti, alerts, offline_names):
    """summary: database.dashboard_summary(); ti: reputation.provider_status();
    alerts: database.open_alert_items(); offline_names: computers silent for a long time."""
    cov = coverage(summary)
    ti_status = ti["status"]
    low_coverage = cov["percent"] is not None and cov["percent"] < COVERAGE_OK_PERCENT
    # Per-computer visibility (database.endpoint_visibility): an ONLINE computer that only the network agent reports for
    # shows programs and connections, not website visits, and one with no usable telemetry shows nothing. Either way
    # a clean result about the OTHER computers must never be presented as "all clear".
    network_only = list(summary.get("network_only_names", []))
    no_visibility = list(summary.get("no_visibility_names", []))
    # an extension that has reported before is not reporting now: a required sensor is missing, so a clean result is only a
    # statement about the part that IS being monitored (Phase 5.7)
    extension_silent = list(summary.get("extension_silent_names", []))
    incomplete_visibility = bool(network_only or no_visibility or extension_silent)
    history_only = list(summary.get("history_names", []))      # website visits visible, but only through the browser history
    no_computers = summary["computers"] == 0
    # computers are enrolled but none of them is online right now: nothing is being observed
    # (operational information, never an alert; heartbeat behaviour is unchanged)
    none_online = summary["computers"] > 0 and summary["online_now"] == 0
    provider_ok = ti_status == "ACTIVE"

    # ---- decision hierarchy ------------------------------------------------
    # 1 open dangerous alert (Threat detected), 2 open suspicious alert (Attention required),
    # 3 any visibility limitation (Limited coverage), 4 no threats detected in the monitored activity.
    # Visibility limitations: reputation service Limited / Not configured, no computer enrolled, enrolled computers but
    # none online, an online computer without website visibility (network agent only, or nothing), or too little of
    # today's browsing verified. A clean result is therefore only said when every sensor that should report is reporting; it is always scoped to the monitored activity.
    if summary["open_high"] > 0:
        status = "ALERT"
    elif summary["open_alerts"] > 0:
        status = "WARNING"
    elif not provider_ok or no_computers or none_online or incomplete_visibility or low_coverage:
        status = "LIMITED"
    else:
        status = "OK"

    # Browser alerts say "visited"; agent alerts say "contacted": a DNS lookup does not prove
    # that a person opened a website.
    with_agent = summary.get("contacted_today", 0) > 0
    affected = ""
    from_agent = False
    if status in ("ALERT", "WARNING") and alerts:
        wanted = "HIGH" if status == "ALERT" else "MEDIUM"
        matching = [a for a in alerts if a["severity"] == wanted] or alerts
        first = matching[0]
        from_agent = first.get("visit_source") == "AGENT"
        count = summary["open_high"] if status == "ALERT" else summary["open_alerts"]
        affected = "%s %s %s." % (first["computer_name"], "contacted" if from_agent else "visited", first["domain"])
        if count > 1:
            affected = affected[:-1] + " and %d more open %s." % (count - 1, _plural(count - 1, "alert", "alerts"))

    # ---- hero text ---------------------------------------------------------
    if status == "ALERT" and from_agent:
        message = "A dangerous domain was contacted from one of your monitored computers. Review the alert immediately."
    elif status == "ALERT":
        message = "A dangerous website was detected on one of your monitored computers. Review the alert immediately."
    elif status == "WARNING" and from_agent:
        message = "A suspicious domain contact requires review."
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
        elif incomplete_visibility:
            parts = []
            if network_only:
                parts.append("%s %s network activity only, so %s website visits cannot be seen." % (
                    _names(network_only), "shows" if len(network_only) == 1 else "show", "its" if len(network_only) == 1 else "their"))
            if no_visibility:
                parts.append("%s %s no browser or network telemetry." % (_names(no_visibility), "reports" if len(no_visibility) == 1 else "report"))
            if extension_silent:
                parts.append("The browser extension on %s is not reporting, so its website visits are %s." % (
                    _names(extension_silent), "seen only through browser history" if set(extension_silent) <= set(history_only)
                    else "not fully covered"))
            message = ("No threats were detected in the monitored activity, but coverage is limited: " + " ".join(parts))
        elif with_agent:
            message = "No confirmed threats were detected, but some websites and domains could not currently be verified."
        else:
            message = "No confirmed threats were detected, but some website visits could not currently be verified."
    else:
        # Scoped, factual: what was actually seen, not "everything is fine".
        visits = summary.get("visits_today", 0)
        computers_seen = summary.get("visiting_computers_today")
        if visits > 0:
            scope = "%d %s visited today" % (visits, _plural(visits, "website", "websites"))
            if computers_seen:
                scope += " on %d monitored %s" % (computers_seen, _plural(computers_seen, "computer", "computers"))
            message = "No threats detected in the monitored activity (%s)." % scope
        else:
            message = "No threats detected in the monitored activity. No websites have been visited yet today."

    if with_agent:   # websites visited in a monitored browser AND domains the network agent saw
        noun_one, noun_many = "website or domain", "websites and domains"
    else:
        noun_one, noun_many = "website visit", "website visits"
    if cov["total"] == 0:
        coverage_line = "No browsing activity yet today."
    elif cov["unchecked"] > 0:
        coverage_line = "%d of %d %s today could not be verified." % (
            cov["unchecked"], cov["total"], _plural(cov["total"], noun_one, noun_many))
    elif cov["total"] == 1:
        coverage_line = "The %s today was checked." % noun_one
    else:
        coverage_line = "All %d %s today were checked." % (cov["total"], noun_many)

    if status in ("ALERT", "WARNING"):
        action = {"label": "Review alerts", "url": "/alerts"}
    elif status == "LIMITED" and (none_online or incomplete_visibility):
        action = {"label": "View computers", "url": "/endpoints"}
    elif cov["unchecked"] > 0:
        action = {"label": "View browsing activity", "url": "/browsing?status=UNKNOWN"}
    else:
        action = {"label": "View browsing activity", "url": "/browsing"}

    # ---- needs attention (derived UI list, not an alert engine) -------------
    items = []
    for a in alerts:
        agent_alert = a.get("visit_source") == "AGENT"
        verb, thing = ("contacted", "domain") if agent_alert else ("visited", "website")
        if a["severity"] == "HIGH":
            items.append({"level": "danger", "text": "Dangerous %s: %s %s %s." % (thing, a["computer_name"], verb, a["domain"]),
                          "url": "/alerts"})
        else:
            items.append({"level": "warning", "text": "Needs review: %s %s %s." % (a["computer_name"], verb, a["domain"]),
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
        text = "%d of %d %s today could not be verified." % (cov["unchecked"], cov["total"], noun_many)
        if with_agent:       # explain the usual reason: the network agent sees many background domains
            text += " Domains seen by the network agent are checked a few at a time."
        items.append({"level": "warning", "text": text, "url": "/browsing?status=UNKNOWN"})
    if network_only:
        items.append({"level": "warning", "text": "%s: network activity only. Website visits are not visible because no browser "
                                                  "extension is reporting (see Network activity below)." % _names(network_only),
                      "url": "/endpoints"})
    if no_visibility:
        items.append({"level": "warning", "text": "%s is online but reports no browser or network telemetry." % _names(no_visibility),
                      "url": "/endpoints"})
    if extension_silent:
        items.append({"level": "warning", "text": "%s: the browser extension is not reporting. Website visits are %s." % (
            _names(extension_silent), "seen only through the agent's browser history (private windows and cleared history are not covered)"
            if set(extension_silent) <= set(history_only) else "not fully covered"), "url": "/endpoints"})
    if history_only and not set(history_only) <= set(extension_silent):
        items.append({"level": "info", "text": "%s: website visits come from the agent's browser history only (no extension). "
                                               "Private windows and cleared history are not covered." %
                                               _names([n for n in history_only if n not in extension_silent]),
                      "url": "/endpoints"})
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
        "scope_note": SCOPE_NOTE,
        "action": action,
        "attention": items,
        "ti": dict(ti, label=TI_LABELS.get(ti_status, ti_status)),
    }


# ---- where an observation came from (Phase 5.1) -----------------------------------------
# Never call a DNS lookup a "visit": the browser extension SAW a page open, the network agent
# only knows a program on the computer looked a name up.
SOURCE_LABELS = {"BROWSER": "Browser extension", "BROWSER_HISTORY": "Browser history (agent)", "AGENT": "Network agent"}
OBSERVATION_LABELS = {"BROWSER": "Visited website", "BROWSER_HISTORY": "Visited website (browser history)",
                      "AGENT": "Contacted domain"}
OBSERVATION_HINTS = {
    "BROWSER": "The browser extension saw this page open in the browser.",
    "BROWSER_HISTORY": "The network agent found this visit in the browser's own history (used when the extension is not "
                       "reporting). Only the website name is kept. It does not cover private windows or cleared history.",
    "AGENT": "A program on this computer looked up this domain name (seen by the network agent). "
             "This does not show that a person opened a website.",
}


def source_label(source):
    return SOURCE_LABELS.get(source, SOURCE_LABELS["BROWSER"])


# The native collector (Phase 5.2) sees a connection to an IP address, not a name. It is shown as
# exactly that: no domain is invented, and nothing says a person opened a website.
IP_OBSERVATION_LABEL = "Contacted IP address"
IP_OBSERVATION_HINT = ("A program on this computer opened a network connection to this IP address (seen by the network agent). "
                       "The system cannot tell which website, if any, this is, and it does not show that a person opened a website.")
IP_REPUTATION_HINT = "Only an IP address was observed, so no website reputation check was done."


def observation_label(source, dest_ip=None):
    if source == "AGENT" and dest_ip:
        return IP_OBSERVATION_LABEL
    return OBSERVATION_LABELS.get(source, OBSERVATION_LABELS["BROWSER"])


def observation_hint(source, dest_ip=None):
    if source == "AGENT" and dest_ip:
        return IP_OBSERVATION_HINT
    return OBSERVATION_HINTS.get(source, OBSERVATION_HINTS["BROWSER"])


# What kind of program made a connection. The agent classifies by where the program file lives
# (never by name alone) and sends only the file name. A browser process also makes background
# connections of its own (updates, sync), so "Browser process" does not mean "a person browsing".
PROCESS_KIND_LABELS = {
    "BROWSER": "Browser process",
    "SYSTEM": "Windows system process",
    "APPLICATION": "Application",
    "UNKNOWN": "Unknown application",
}
PROCESS_KIND_HINTS = {
    "BROWSER": "A web browser made this connection. Browsers also connect on their own (updates, sync), "
               "so this does not show that a person opened a website.",
    "SYSTEM": "A program from the Windows folder made this connection (operating-system background activity).",
    "APPLICATION": "An installed or user program made this connection.",
    "UNKNOWN": "Windows did not allow the agent to identify the program (usually a protected or administrator program).",
}
BROWSER_NAMES = {"msedge": "Microsoft Edge", "chrome": "Google Chrome", "firefox": "Firefox",
                 "brave": "Brave", "opera": "Opera", "vivaldi": "Vivaldi"}     # keyed by file name without extension


def process_kind_label(kind):
    return PROCESS_KIND_LABELS.get(kind, PROCESS_KIND_LABELS["UNKNOWN"])


def process_kind_hint(kind):
    return PROCESS_KIND_HINTS.get(kind, PROCESS_KIND_HINTS["UNKNOWN"])


def process_label(name, kind):
    """The program as the owner should read it. A friendly browser name is only used when the agent
    verified the location of the file; any other program is shown by its file name as reported."""
    if not name:
        return "Unknown application"
    if kind == "BROWSER":
        return BROWSER_NAMES.get(os.path.splitext(name)[0].lower(), name)
    return name
