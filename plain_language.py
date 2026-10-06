# ==================================================
# OCT 2026 STEP 23.1: PLAIN-LANGUAGE EXPLANATION LAYER
# ==================================================
#
# A presentation-only layer that turns a KNOWN alert_type/event_type into
# a short, plain-language, non-technical explanation (what happened /
# who's involved / possible business meaning / recommended action /
# open-or-handled), in whichever language is currently active.
#
# HARD GUARANTEES:
#   - Pure read/presentation: this module never queries a database, never
#     writes anywhere, and never calls any detection/scoring/alert-
#     creation function. It takes an already-fetched alert/incident row
#     (a dict or sqlite3.Row) and returns a plain dict of display
#     strings - nothing else.
#   - Never rewrites stored data: alert.title/description/
#     detection_reasons/recommended_response and incident.description
#     are read AS-IS and never modified in the database. The sentences
#     below are NEW, separate, hand-written summaries shown ALONGSIDE the
#     original technical record, never a replacement for it, and the
#     original technical text remains fully visible on the same page.
#   - No automatic ("machine") translation of free text: every sentence
#     here is a hand-written, reviewed, translatable template
#     (_("...")), keyed by the SMALL, FINITE set of alert_type/event_type
#     values this system actually produces today - confirmed by a direct
#     code audit of every INSERT/create_security_alert/
#     create_security_event call site (see KNOWN_ALERT_TYPES/
#     KNOWN_EVENT_TYPES below). An alert_type/event_type NOT in that set
#     (e.g. a type added by future work) NEVER gets a fabricated
#     explanation - it always falls back to an honest, generic message
#     that explicitly points at the technical details page instead.
#   - Never invents information: "recommended action" surfaces the
#     EXISTING, already-stored recommended_response list verbatim (only
#     the surrounding framing text is translated, never the content
#     itself); "who/what is involved" is read directly from
#     hostname/endpoint_ip/target_ip/username - never guessed or derived.
#     When a field genuinely has no data, the explanation says so plainly
#     rather than omitting it silently or filling in a placeholder.
# ==================================================

import json

from flask_babel import gettext as _

# The REAL, finite vocabulary this system produces today - verified by
# direct code audit (grep for every create_security_alert/
# create_security_event call site), not assumed:
#   - security_alerts.alert_type: exactly one value exists anywhere in
#     the code (web_event_worker.py's single automatic alert-creation
#     call site).
#   - security_events.event_type: BRUTE_FORCE_DETECTED (app.py login
#     lockout), MALICIOUS_IP_REPUTATION (reputation_routes.py manual
#     lookup), MALICIOUS_WEB_DESTINATION (escalated from an Alert -
#     create_incident_from_alert() copies alert_type verbatim),
#     THREAT_INTELLIGENCE_MATCH (app.py's scanner IOC check).
#
# Stage 25C adds six new alert_type values, one per Detection Engine
# rule category (detection_engine._ALERT_TYPE_BY_CATEGORY) - each gets
# its own hand-written, reviewed explanation below, same discipline as
# every existing type (never a machine translation, never invented).
KNOWN_ALERT_TYPES = frozenset({
    "MALICIOUS_WEB_DESTINATION",
    "CONFIRMED_MALICIOUS_DESTINATION_DETECTION",
    "LOCAL_IOC_MATCH_DETECTION",
    "SUSPICIOUS_PROCESS_DESTINATION_DETECTION",
    "SUSPICIOUS_COMMAND_LINE_DETECTION",
    "UNUSUAL_EXECUTABLE_LOCATION_DETECTION",
    "BEHAVIORAL_ANOMALY_DETECTION",
})
KNOWN_EVENT_TYPES = frozenset({
    "MALICIOUS_WEB_DESTINATION",
    "BRUTE_FORCE_DETECTED",
    "MALICIOUS_IP_REPUTATION",
    "THREAT_INTELLIGENCE_MATCH",
})

# Open/handled vocabulary - matches exactly the status values already
# enforced server-side elsewhere (app.py's alert/incident workflow
# handlers); never re-derived or guessed here.
_OPEN_ALERT_STATUSES = ("NEW", "ACKNOWLEDGED", "ESCALATED")
_OPEN_INCIDENT_STATUSES = ("OPEN", "INVESTIGATING")


def _type_explanation(type_code):
    # One hand-written, reviewed pair of sentences per KNOWN type. Each
    # _("...") call is a literal, statically-extractable string - safe
    # for pybabel - even though it is wrapped in a dict built at import
    # time; it is evaluated fresh on every call (never cached across
    # requests), so it always reflects the CURRENTLY active language.
    if type_code == "MALICIOUS_WEB_DESTINATION":
        return (
            _("A computer on your network attempted to connect to a website or server that is considered risky or potentially malicious."),
            _("This could expose your business to malware, data theft, or further compromise if the connection succeeded or is repeated."),
        )
    if type_code == "CONFIRMED_MALICIOUS_DESTINATION_DETECTION":
        return (
            _("A computer on your network communicated with a destination that independent threat-intelligence sources have confirmed as malicious."),
            _("This is a confirmed match, not a guess - the connection may have exposed your business to malware or data theft."),
        )
    if type_code == "LOCAL_IOC_MATCH_DETECTION":
        return (
            _("A computer on your network communicated with a destination, or ran a file, that exactly matches an indicator your organization specifically flagged as malicious."),
            _("This is a direct match against a known threat your organization is already tracking."),
        )
    if type_code == "SUSPICIOUS_PROCESS_DESTINATION_DETECTION":
        return (
            _("A program behaving unusually on a computer also communicated with a destination carrying threat-intelligence evidence."),
            _("The combination of an unusual program and a risky destination together is more concerning than either alone."),
        )
    if type_code == "SUSPICIOUS_COMMAND_LINE_DETECTION":
        return (
            _("A program was started with command-line options that match a technique sometimes used to hide malicious activity."),
            _("This does not by itself confirm malicious intent, but it is a pattern worth a person reviewing."),
        )
    if type_code == "UNUSUAL_EXECUTABLE_LOCATION_DETECTION":
        return (
            _("A program ran from a temporary or unusual folder, together with at least one other suspicious sign."),
            _("Legitimate software rarely runs from these locations - this combination is worth reviewing."),
        )
    if type_code == "BEHAVIORAL_ANOMALY_DETECTION":
        return (
            _("Activity on a computer deviated from that computer's own established normal behavior, together with at least one other suspicious sign."),
            _("This is a behavioral signal, not proof on its own - it is reported because it was corroborated by other evidence."),
        )
    if type_code == "BRUTE_FORCE_DETECTED":
        return (
            _("Multiple failed login attempts were detected on a user account, and the account was temporarily locked for protection."),
            _("This may indicate someone is trying to guess a password to gain unauthorized access to your systems."),
        )
    if type_code == "MALICIOUS_IP_REPUTATION":
        return (
            _("An IP address that was checked was found to have a poor security reputation, as reported by external threat intelligence services."),
            _("Communication with this address could be linked to malicious activity such as scanning, attacks, or malware distribution."),
        )
    if type_code == "THREAT_INTELLIGENCE_MATCH":
        return (
            _("A scanned target matched a known indicator of compromise from threat intelligence sources."),
            _("This target has previously been associated with malicious activity and may pose a risk if connected to."),
        )
    # Unreachable for a KNOWN type (every member of KNOWN_ALERT_TYPES/
    # KNOWN_EVENT_TYPES is handled above) - kept only as a defensive
    # fallback, never actually hit by _explain()'s own gating.
    return (
        _("A security event was recorded by the system."),
        _("The specific business impact could not be summarized automatically - please review the technical details."),
    )


_GENERIC_WHAT_HAPPENED = lambda: _(  # noqa: E731
    "A security event of an unrecognized type was recorded. Please see the technical details below for the full information."
)
_GENERIC_BUSINESS_MEANING = lambda: _(  # noqa: E731
    "The specific business impact could not be summarized automatically for this type of event - please review the technical details."
)
_NO_SPECIFIC_RECOMMENDATION = lambda: _(  # noqa: E731
    "No specific recommended action is recorded for this type of event. Please review the technical details and consider a manual investigation."
)


def _parse_response_list(raw):
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw or "[]")
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _status_label(status, open_set, open_label, handled_label):
    is_open = status in open_set
    return is_open, (open_label if is_open else handled_label)


def explain_alert(alert_row):
    """
    alert_row: a dict/sqlite3.Row with at least alert_type, hostname,
    endpoint_ip, status, recommended_response (raw JSON string, already-
    parsed list, or None). Returns a plain dict of display strings/
    values - never writes anything, never queries anything.
    """
    alert_type = alert_row["alert_type"] if "alert_type" in alert_row.keys() else alert_row.get("alert_type")
    is_known = alert_type in KNOWN_ALERT_TYPES

    if is_known:
        what_happened, business_meaning = _type_explanation(alert_type)
    else:
        what_happened, business_meaning = _GENERIC_WHAT_HAPPENED(), _GENERIC_BUSINESS_MEANING()

    hostname = alert_row["hostname"] if "hostname" in alert_row.keys() else alert_row.get("hostname")
    endpoint_ip = alert_row["endpoint_ip"] if "endpoint_ip" in alert_row.keys() else alert_row.get("endpoint_ip")
    subject_value = hostname or endpoint_ip or None

    recommended = _parse_response_list(
        alert_row["recommended_response"] if "recommended_response" in alert_row.keys() else alert_row.get("recommended_response")
    )
    has_specific_recommendation = bool(recommended)
    if not has_specific_recommendation:
        recommended = [_NO_SPECIFIC_RECOMMENDATION()]

    status = alert_row["status"] if "status" in alert_row.keys() else alert_row.get("status")
    is_open, status_label = _status_label(status, _OPEN_ALERT_STATUSES, _("Still open"), _("Already handled"))

    return {
        "is_known_type": is_known,
        "what_happened": what_happened,
        "subject_label": _("Computer:"),
        "subject_value": subject_value,
        "business_meaning": business_meaning,
        "recommended_action": recommended,
        "has_specific_recommendation": has_specific_recommendation,
        "is_open": is_open,
        "status_label": status_label,
    }


def explain_incident(event_row, linked_alert_recommended_response=None):
    """
    event_row: a dict/sqlite3.Row with at least event_type, username,
    target_ip, status. linked_alert_recommended_response: an OPTIONAL
    pre-parsed list (or raw JSON string) the CALLER already fetched from
    a structurally-linked Alert (e.g. incident_details()'s existing
    `alert_recommended_response`) - this module never queries the DB
    itself to find one. Returns a plain dict of display strings/values.
    """
    event_type = event_row["event_type"] if "event_type" in event_row.keys() else event_row.get("event_type")
    is_known = event_type in KNOWN_EVENT_TYPES

    if is_known:
        what_happened, business_meaning = _type_explanation(event_type)
    else:
        what_happened, business_meaning = _GENERIC_WHAT_HAPPENED(), _GENERIC_BUSINESS_MEANING()

    # BRUTE_FORCE_DETECTED has no computer/IP concept in its schema (see
    # Step 21's finding: "the source IP ... was not captured by the
    # incident model") - showing a computer field for it would be
    # fabricating data that was never recorded. Every other known type
    # has a target_ip.
    if event_type == "BRUTE_FORCE_DETECTED":
        subject_label = _("Account:")
        subject_value = (event_row["username"] if "username" in event_row.keys() else event_row.get("username")) or None
    else:
        subject_label = _("Computer / IP:")
        subject_value = (event_row["target_ip"] if "target_ip" in event_row.keys() else event_row.get("target_ip")) or None

    recommended = _parse_response_list(linked_alert_recommended_response)
    has_specific_recommendation = bool(recommended)
    if not has_specific_recommendation:
        recommended = [_NO_SPECIFIC_RECOMMENDATION()]

    status = event_row["status"] if "status" in event_row.keys() else event_row.get("status")
    is_open, status_label = _status_label(status, _OPEN_INCIDENT_STATUSES, _("Still open"), _("Already handled"))

    return {
        "is_known_type": is_known,
        "what_happened": what_happened,
        "subject_label": subject_label,
        "subject_value": subject_value,
        "business_meaning": business_meaning,
        "recommended_action": recommended,
        "has_specific_recommendation": has_specific_recommendation,
        "is_open": is_open,
        "status_label": status_label,
    }
