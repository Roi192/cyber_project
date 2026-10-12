"""Web threat analytics and explainable computer risk scoring (Phase C1).  READ-ONLY.

Nothing here writes to the database, changes a verdict, creates or closes an alert, or triggers any action. Every function opens its
connection with PRAGMA query_only = ON, so even a bug could not change data.

SOURCES OF TRUTH
  physical visit       a row of web_visits. Three sources: BROWSER (the extension), BROWSER_HISTORY (the agent read the browser's own history) and
                       AGENT (a DNS lookup seen by the agent: NOT a website visit and never counted here).
  logical website visit  what a person did once. database._WEBSITE: an extension row, or a history row that no extension row of the SAME
                       computer + browser + domain explains within COVERED_WINDOW_SECONDS (120 s). The extension and the agent reporting
                       one visit are therefore ONE logical visit. This module reuses that exact SQL so the dashboard and the analytics can never disagree.
  computer             a row of devices (endpoints are its SENSORS). Legacy / unverified installations are separate devices and are never merged on a name
                       or an address.
  verdict of a visit   web_visits.reputation_status: the verdict the visit got WHEN IT HAPPENED. It is never rewritten, and a later change of
                       the domain's reputation does not change past visits (retroactive re-evaluation is a later phase).
  security alert       alerts (one open alert per computer + domain + 24 h) with its evidence in alert_events.
  sensor health        endpoints.extension_seen_at / agent_seen_at, as in Phase 5.7.

TIME. Timestamps are stored as LOCAL naive text ("2026-10-08 14:05:09", the server's clock when the event was recorded, no offset).
A reporting period is N CALENDAR days in that local time: from 00:00:00 of the day N-1 days before today up to now (today is included, so
the current period ends with a partial day), and the previous period is the N calendar days right before it. Daily buckets are the local
calendar date written in the timestamp, so a day with 23 or 25 hours (daylight-saving change) is still one bucket. Only the repeated hour of the
autumn change is ambiguous in the stored text (the same wall-clock time occurs twice); it affects neither the day a visit belongs to nor its count.

REPEATED VISITS. Every logical visit counts: opening the same site again later is a new visit. The collection layer already merges the
extension's reloads of one page within 10 seconds, and the agent's history records of one computer + browser + domain within 5 minutes, so
a genuine second visit made inside those windows is not stored twice. A visit seen by the extension and by the agent is one logical visit.
"""
import math
import time
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

import config
import database
import overview

PERIODS = (7, 14, 30)
TIME_FORMAT = database.TIME_FORMAT
THREATS = ("MALICIOUS", "SUSPICIOUS")
DEFAULT_LIMIT = 50
MAX_LIMIT = 200

# ---- the risk score: every number of the formula, in one place (see docs/SEVERITY_POLICY.md) ----------------------------------------
SEVERITY_POINTS = {"MALICIOUS": 40.0, "SUSPICIOUS": 12.0}      # points for the FIRST logical visit to a risky domain in the period
REPEAT_MAX_BONUS = 0.5                                         # repeat factor = 1 + 0.5 * (1 - 1/n): 1, 1.25, 1.33 ... never above 1.5
RECENCY_HALF_LIFE_DAYS = 7.0                                   # recency weight = 0.25 + 0.75 * 0.5 ** (age_days / 7): 1.0 today, 0.25 at the floor
RECENCY_FLOOR = 0.25
SUSPICIOUS_RAW_CAP = 36.0                                      # suspicious domains alone can add at most this many points (3 domains' worth)
SATURATION = 60.0                                              # score = 100 * (1 - exp(-raw / 60))
CATEGORY_BOUNDS = ((75, "SEVERE"), (50, "HIGH"), (25, "MODERATE"), (1, "LOW"))
CATEGORY_LABELS = {
    "NONE_OBSERVED": "No risky websites observed", "LOW": "Low web exposure", "MODERATE": "Moderate web exposure",
    "HIGH": "High web exposure", "SEVERE": "Severe web exposure",
}
# ---- coverage thresholds -----------------------------------------------------------------------------------------------------------------
MIN_HISTORY_FRACTION = 0.5       # the computer must have been known for at least half of the period ...
MIN_OBSERVED_RATIO = 0.25        # ... and have left a trace (a website visit or agent network record) on at least a quarter of the days it was known
MAX_DOMAINS_IN_RANKING = 5
MAX_DOMAINS_IN_DETAIL = 25
MAX_VISIT_IDS_PER_DOMAIN = 5

DISCLAIMER = ("The score describes the websites a computer opened, as judged by a reputation service. It is not proof that the computer "
              "is infected or that anything was harmed.")
LIMITATIONS = [
    "Only websites seen by the browser extension or read from Chrome/Edge history are counted; private windows and other browsers are not covered.",
    "A visit keeps the verdict it received when it happened. Later changes in a website's reputation do not change past visits.",
    "Visits whose reputation could not be checked (unknown) are not counted as safe; they make a score a lower bound.",
    "The server records no sensor heartbeat history, only the last report of each sensor, so past monitoring is inferred from the days on which "
    "records exist; a quiet day and a monitoring gap look the same.",
    "Visits older than the retention period (RETENTION_DAYS, 30 by default) are deleted, so long periods and previous-period comparisons can be incomplete.",
    "Repeat visits to one page within seconds (extension) or one domain within 5 minutes (agent history) are stored once.",
]


# ---- time ------------------------------------------------------------------------------------------------------------------------------------
def _fmt(moment):
    return moment.strftime(TIME_FORMAT)


def _midnight(moment):
    return datetime(moment.year, moment.month, moment.day)


def period_bounds(days, now=None):
    """The current period and the equivalent previous one, in local calendar days (see the module text)."""
    if days not in PERIODS:
        raise ValueError("days must be one of %s" % ", ".join(str(p) for p in PERIODS))
    now = now or datetime.now()
    today = _midnight(now)
    start = today - timedelta(days=days - 1)
    prev_start = start - timedelta(days=days)
    return {
        "days": days,
        "now": _fmt(now),
        "current": {"start": _fmt(start), "end": _fmt(now), "first_date": start.date().isoformat(), "last_date": today.date().isoformat(),
                    "dates": [(start + timedelta(days=i)).date().isoformat() for i in range(days)], "includes_partial_day": True},
        "previous": {"start": _fmt(prev_start), "end": _fmt(start - timedelta(seconds=1)), "first_date": prev_start.date().isoformat(),
                     "last_date": (start - timedelta(days=1)).date().isoformat(),
                     "dates": [(prev_start + timedelta(days=i)).date().isoformat() for i in range(days)], "includes_partial_day": False},
    }


def read_only_connection():
    conn = database.get_connection()
    conn.execute("PRAGMA query_only = ON")                  # this module can read, never write
    return conn


# Phase F2.1: a visit whose verdict the evidence policy called a WEAK finding (web_visits.level = 'WEAK') is neither a threat nor "no threat detected": it has its own bucket,
# contributes no risk points and never makes a computer look compromised. level is NULL for every historical visit, so those are read exactly as before.
_STATUS = "CASE WHEN IFNULL(v.level, '') = 'WEAK' THEN 'WEAK' ELSE v.reputation_status END"


def _verdict(status):
    return status if status in ("MALICIOUS", "SUSPICIOUS", "SAFE", "WEAK") else "UNKNOWN"


# ---- logical visits ------------------------------------------------------------------------------------------------------------------
# the dashboard's own definition of a website visit, restricted to ACTIVE computers (archived ones are hidden from every dashboard figure)
# Phase D2.3: `e` is the ACTIVE DEVICE the visit belongs to (active_devices; e.device_id is the visit's own, event-time device - never the device its sensor is on now)
_LOGICAL = ("FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id WHERE " + database._WEBSITE +
            " AND v.visited_at >= :lo AND v.visited_at <= :hi")


def _period_metrics(conn, window):
    params = {"lo": window["start"], "hi": window["end"]}
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "SAFE": 0, "UNKNOWN": 0, "WEAK": 0}
    for row in conn.execute("SELECT " + _STATUS + " AS s, COUNT(*) AS n " + _LOGICAL + " GROUP BY s", params):
        counts[_verdict(row["s"])] += row["n"]
    distinct = conn.execute("SELECT COUNT(DISTINCT v.domain) AS d, COUNT(DISTINCT CASE WHEN " + _STATUS + " IN ('MALICIOUS', 'SUSPICIOUS') THEN v.domain END) AS r, "
                            "COUNT(DISTINCT CASE WHEN " + _STATUS + " IN ('MALICIOUS', 'SUSPICIOUS') THEN e.device_id END) AS c " + _LOGICAL, params).fetchone()
    alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE created_at >= :lo AND created_at <= :hi", params).fetchone()[0]
    return {
        "logical_visits": sum(counts.values()),
        "malicious_visits": counts["MALICIOUS"], "suspicious_visits": counts["SUSPICIOUS"],
        "no_threat_detected_visits": counts["SAFE"], "unknown_visits": counts["UNKNOWN"], "weak_finding_visits": counts["WEAK"],
        "distinct_domains": distinct["d"], "distinct_risky_domains": distinct["r"], "affected_computers": distinct["c"],
        "alerts_created": alerts,
    }


def open_alert_counts(conn):
    """Currently open alerts (a snapshot of now, not of the period). Archived computers' open alerts are included on purpose, as on the dashboard."""
    row = conn.execute("SELECT COUNT(*) AS total, SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high, "
                       "SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium FROM alerts WHERE status = 'OPEN'").fetchone()
    return {"total": row["total"] or 0, "high": row["high"] or 0, "medium": row["medium"] or 0}


def daily_trend(conn, window, first_data_date, device_id=None):
    """One entry per calendar day of the window. A day before the first record of the whole system has null counts (nothing existed to count);
    a day with records but no visits is a real zero; `records_present` says whether ANY sensor record exists for that day.
    With `device_id` the same series for one computer (the days are then judged against that computer's own first record)."""
    params = {"lo": window["start"], "hi": window["end"]}
    one = ""
    if device_id is not None:
        params["device"] = device_id
        one = " AND e.device_id = :device"
    by_day = {}
    for row in conn.execute("SELECT substr(v.visited_at, 1, 10) AS day, " + _STATUS + " AS s, COUNT(*) AS n " + _LOGICAL + one + " GROUP BY day, s", params):
        by_day.setdefault(row["day"], {"MALICIOUS": 0, "SUSPICIOUS": 0, "SAFE": 0, "UNKNOWN": 0, "WEAK": 0})[_verdict(row["s"])] += row["n"]
    record_days = _record_days(conn, window, device_id)
    series = []
    for date in window["dates"]:
        if first_data_date is None or date < first_data_date:
            series.append({"date": date, "records_present": False, "before_first_data": True, "malicious": None, "suspicious": None, "no_threat_detected": None,
                           "unknown": None, "weak_finding": None, "logical_visits": None})
            continue
        c = by_day.get(date, {"MALICIOUS": 0, "SUSPICIOUS": 0, "SAFE": 0, "UNKNOWN": 0, "WEAK": 0})
        series.append({"date": date, "records_present": date in record_days, "before_first_data": False, "malicious": c["MALICIOUS"],
                       "suspicious": c["SUSPICIOUS"], "no_threat_detected": c["SAFE"], "unknown": c["UNKNOWN"], "weak_finding": c["WEAK"],
                       "logical_visits": sum(c.values())})
    return series


def _record_days(conn, window, device_id=None):
    """Dates inside the window on which ANY record of an active computer exists (a visit of any source, or the agent's network counters)."""
    params = {"lo": window["start"], "hi": window["end"], "d1": window["first_date"], "d2": window["last_date"]}
    one = ""
    if device_id is not None:
        params["device"] = device_id
        one = " AND e.device_id = :device"
    rows = conn.execute(
        "SELECT substr(v.visited_at, 1, 10) AS d FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        "WHERE v.visited_at >= :lo AND v.visited_at <= :hi" + one +
        " UNION SELECT n.day FROM network_activity n JOIN active_devices e ON e.device_id = n.device_id WHERE n.day >= :d1 AND n.day <= :d2" + one, params)
    return {r[0] for r in rows}


def first_data_date(conn):
    """The earliest date on which the system holds any record of an active computer (None when it holds none)."""
    row = conn.execute(
        "SELECT MIN(d) FROM (SELECT MIN(substr(COALESCE(first_seen, last_seen), 1, 10)) AS d FROM endpoints WHERE archived_at IS NULL "
        "UNION ALL SELECT MIN(substr(v.visited_at, 1, 10)) FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
        "UNION ALL SELECT MIN(n.day) FROM network_activity n JOIN active_devices e ON e.device_id = n.device_id)").fetchone()
    return row[0]


def completeness(conn, window, first_date, now):
    """How much of the period the stored data can speak for. It never claims more than the records show."""
    today = _midnight(now).date()
    retention = config.RETENTION_DAYS
    limited_by_retention = False
    if retention and retention > 0:
        cutoff = (_midnight(now) - timedelta(days=retention)).date().isoformat()
        limited_by_retention = window["first_date"] < cutoff
    record_days = _record_days(conn, window)
    starts_before_data = first_date is None or first_date > window["first_date"]
    if first_date is None or first_date > window["last_date"]:
        status = "NO_DATA"
    elif starts_before_data or limited_by_retention:
        status = "PARTIAL"
    else:
        status = "COMPLETE"
    covered_from = window["first_date"] if not starts_before_data else (first_date if first_date and first_date <= window["last_date"] else None)
    days_in_scope = 0
    if covered_from:
        days_in_scope = (datetime.strptime(window["last_date"], "%Y-%m-%d") - datetime.strptime(covered_from, "%Y-%m-%d")).days + 1
    notes = []
    if status == "NO_DATA":
        notes.append("The system holds no records for this period.")
    if starts_before_data and status != "NO_DATA":
        notes.append("Monitoring data starts on %s, after the start of the period (%s)." % (first_date, window["first_date"]))
    if limited_by_retention:
        notes.append("Part of this period is older than the retention limit of %d days; those visits have been deleted." % retention)
    return {
        "status": status, "period_days": len(window["dates"]), "first_data_date": first_date, "days_after_first_data": days_in_scope,
        "days_with_records": len(record_days), "starts_before_first_data": bool(starts_before_data and status != "NO_DATA"),
        "limited_by_retention": limited_by_retention, "notes": notes,
    }


def _comparison(current, previous, reliable):
    out = {}
    for key in ("logical_visits", "malicious_visits", "suspicious_visits", "no_threat_detected_visits", "unknown_visits", "distinct_domains",
                "distinct_risky_domains", "affected_computers"):
        delta = current[key] - previous[key]
        out[key] = {"delta": delta, "percent": (round(100.0 * delta / previous[key], 1) if previous[key] else None), "reliable": reliable}
    return out


# ---- exposures and the score -------------------------------------------------------------------------------------------------------
def device_exposures(conn, lo, hi, with_visit_ids=False):
    """{device_id: {domain: exposure}} of the logical visits to SUSPICIOUS / MALICIOUS domains inside [lo, hi]. One exposure per computer + domain:
    its worst verdict, how many LOGICAL visits (never physical records), when first and last, and on how many days."""
    params = {"lo": lo, "hi": hi}
    out = {}
    for row in conn.execute(
            "SELECT e.device_id AS device_id, v.domain AS domain, " + _STATUS + " AS s, COUNT(*) AS n, MIN(v.visited_at) AS first_at, MAX(v.visited_at) AS last_at, "
            "COUNT(DISTINCT substr(v.visited_at, 1, 10)) AS days " + _LOGICAL + " AND " + _STATUS + " IN ('MALICIOUS', 'SUSPICIOUS') "
            "GROUP BY e.device_id, v.domain, s", params):
        domains = out.setdefault(row["device_id"], {})
        item = domains.setdefault(row["domain"], {"domain": row["domain"], "verdict": "SUSPICIOUS", "malicious_visits": 0, "suspicious_visits": 0, "visits": 0,
                                                  "first_at": row["first_at"], "last_at": row["last_at"], "days_with_visits": 0})
        item["visits"] += row["n"]
        item["malicious_visits" if row["s"] == "MALICIOUS" else "suspicious_visits"] += row["n"]
        if row["s"] == "MALICIOUS":
            item["verdict"] = "MALICIOUS"
        item["first_at"] = min(item["first_at"], row["first_at"])
        item["last_at"] = max(item["last_at"], row["last_at"])
        item["days_with_visits"] = max(item["days_with_visits"], row["days"])
    if with_visit_ids:
        for row in conn.execute(
                "SELECT e.device_id AS device_id, v.domain AS domain, v.id AS id, v.visited_at AS at " + _LOGICAL +
                " AND " + _STATUS + " IN ('MALICIOUS', 'SUSPICIOUS') ORDER BY v.visited_at DESC, v.id DESC", params):
            item = out.get(row["device_id"], {}).get(row["domain"])
            if item is not None:
                ids = item.setdefault("sample_visit_ids", [])
                if len(ids) < MAX_VISIT_IDS_PER_DOMAIN:
                    ids.append(row["id"])
    return out


def _recency(age_days):
    return RECENCY_FLOOR + (1.0 - RECENCY_FLOOR) * (0.5 ** (max(age_days, 0.0) / RECENCY_HALF_LIFE_DAYS))


def score_exposures(exposures, now):
    """The deterministic web exposure score (0-100) from a computer's risky domains in the period. A pure function: the same input always gives the
    same output, and it reads nothing else. Safe and unknown visits are not an input, so they can neither dilute nor hide a serious exposure.

        points(domain) = severity_points(worst verdict) * repeat_factor(n) * recency_weight(age of the last visit)
            severity_points : MALICIOUS 40, SUSPICIOUS 12
            repeat_factor   : 1 + 0.5 * (1 - 1/n)          n = LOGICAL visits to that domain (1 visit -> 1.0, 2 -> 1.25, many -> below 1.5)
            recency_weight  : 0.25 + 0.75 * 0.5 ** (age_days / 7)
        raw   = sum(points of dangerous domains) + min(sum(points of suspicious domains), 36)
        score = round(100 * (1 - exp(-raw / 60)));  0 when there is no risky exposure (a dangerous visit always scores at least 15).
    """
    malicious_raw = 0.0
    suspicious_raw = 0.0
    scored = []
    for item in exposures:
        last = datetime.strptime(item["last_at"], TIME_FORMAT)
        age_days = max((now - last).total_seconds(), 0.0) / 86400.0
        n = max(item["visits"], 1)
        repeat = 1.0 + REPEAT_MAX_BONUS * (1.0 - 1.0 / n)
        recency = _recency(age_days)
        points = SEVERITY_POINTS[item["verdict"]] * repeat * recency
        if item["verdict"] == "MALICIOUS":
            malicious_raw += points
        else:
            suspicious_raw += points
        scored.append(dict(item, age_days=round(age_days, 2), repeat_factor=round(repeat, 3), recency_weight=round(recency, 3), points=round(points, 2)))
    raw = malicious_raw + min(suspicious_raw, SUSPICIOUS_RAW_CAP)
    if not scored:
        score = 0
    else:
        # a dangerous visit is worth at least 40 * 0.25 = 10 points (the recency floor), so it always scores at least 15
        score = max(0, min(100, int(100.0 * (1.0 - math.exp(-raw / SATURATION)) + 0.5)))
    category = "NONE_OBSERVED"
    for bound, name in CATEGORY_BOUNDS:
        if score >= bound:
            category = name
            break
    scored.sort(key=lambda d: (-SEVERITY_POINTS[d["verdict"]], -d["points"], d["domain"]))
    return {"score": score, "category": category, "raw_points": round(raw, 2), "malicious_points": round(malicious_raw, 2),
            "suspicious_points": round(suspicious_raw, 2), "suspicious_points_counted": round(min(suspicious_raw, SUSPICIOUS_RAW_CAP), 2), "domains": scored}


def _ago(moment, now):
    seconds = (now - datetime.strptime(moment, TIME_FORMAT)).total_seconds()
    if seconds < 3600:
        return "less than an hour ago"
    if seconds < 86400:
        return "%d hour%s ago" % (seconds // 3600, "" if seconds // 3600 == 1 else "s")
    d = int(seconds // 86400)
    return "%d day%s ago" % (d, "" if d == 1 else "s")


def _plural(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


# ---- per-computer data -------------------------------------------------------------------------------------------------------------
def _per_device_facts(conn, window, now):
    """Everything needed per computer, fetched in a few grouped queries (no per-computer round trips)."""
    params = {"lo": window["start"], "hi": window["end"], "d1": window["first_date"], "d2": window["last_date"]}
    verdicts = {}
    website_days = {}
    for row in conn.execute("SELECT e.device_id AS device_id, " + _STATUS + " AS s, COUNT(*) AS n " + _LOGICAL + " GROUP BY e.device_id, s", params):
        verdicts.setdefault(row["device_id"], {"MALICIOUS": 0, "SUSPICIOUS": 0, "SAFE": 0, "UNKNOWN": 0, "WEAK": 0})[_verdict(row["s"])] += row["n"]
    for row in conn.execute("SELECT DISTINCT e.device_id AS device_id, substr(v.visited_at, 1, 10) AS d " + _LOGICAL, params):
        website_days.setdefault(row["device_id"], set()).add(row["d"])
    activity_days = {k: set(v) for k, v in website_days.items()}
    for row in conn.execute("SELECT DISTINCT e.device_id AS device_id, substr(v.visited_at, 1, 10) AS d FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id "
                            "WHERE v.visited_at >= :lo AND v.visited_at <= :hi", params):
        activity_days.setdefault(row["device_id"], set()).add(row["d"])
    for row in conn.execute("SELECT DISTINCT e.device_id AS device_id, n.day AS d FROM network_activity n JOIN active_devices e ON e.device_id = n.device_id "
                            "WHERE n.day >= :d1 AND n.day <= :d2", params):
        activity_days.setdefault(row["device_id"], set()).add(row["d"])
    first_seen = {}
    # when a computer was first known: its sensors' first reports, the day the device itself was created (a former device has no sensor left), the first association
    # the server RECORDED for it, and its earliest event
    for row in conn.execute("SELECT device_id, MIN(substr(COALESCE(first_seen, last_seen), 1, 10)) AS d FROM endpoints WHERE archived_at IS NULL GROUP BY device_id "
                            "UNION ALL SELECT d.id, substr(d.created_at, 1, 10) FROM devices d JOIN active_devices ad ON ad.device_id = d.id "
                            "UNION ALL SELECT a.device_id, MIN(substr(a.valid_from, 1, 10)) FROM sensor_device_associations a WHERE a.basis = 'RECORDED' GROUP BY a.device_id "
                            "UNION ALL SELECT v.device_id, MIN(substr(v.visited_at, 1, 10)) FROM web_visits v JOIN active_devices e ON e.device_id = v.device_id GROUP BY v.device_id"):
        if row[1] and (first_seen.get(row[0]) is None or row[1] < first_seen[row[0]]):
            first_seen[row[0]] = row[1]
    open_alerts = {}
    for row in conn.execute("SELECT COALESCE(a.device_id, e.device_id) AS device_id, COUNT(*) AS n FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id "
                            "WHERE a.status = 'OPEN' GROUP BY COALESCE(a.device_id, e.device_id)"):
        open_alerts[row["device_id"]] = row["n"]
    return {"verdicts": verdicts, "website_days": website_days, "activity_days": activity_days, "first_seen": first_seen, "open_alerts": open_alerts,
            "exposures": device_exposures(conn, window["start"], window["end"])}


def computer_coverage(item, facts, window):
    """MONITORING coverage of one computer, kept apart from its threat score. Combines what the sensors do NOW (Phase 5.7 freshness) with what the
    records show about the PAST; a sensor that is online today is never taken as proof that the whole period was monitored."""
    device_id = item["device_id"]
    extension = "REPORTING" if item.get("extension_fresh") else ("NOT_REPORTING" if item.get("extension_silent") else "NOT_PRESENT")
    agent = "REPORTING" if item.get("agent_fresh") else ("NOT_REPORTING" if item.get("has_agent") else "NOT_PRESENT")
    visibility = item.get("visibility")
    reasons = []
    if extension == "NOT_PRESENT" and agent == "NOT_PRESENT":
        current = "NOT_REPORTING"
    elif extension != "REPORTING" and agent != "REPORTING":
        current = "NOT_REPORTING"
    elif extension == "NOT_REPORTING" or agent == "NOT_REPORTING" or visibility == database.VIS_NETWORK_ONLY:
        current = "PARTIALLY_MONITORED"
    else:
        current = "REPORTING_NORMALLY"
    if current == "NOT_REPORTING":
        reasons.append("No sensor of this computer is reporting right now.")
    if extension == "NOT_REPORTING":
        reasons.append("The browser extension has reported before but is silent now.")
    if agent == "NOT_REPORTING":
        reasons.append("The Windows agent has reported before but is silent now.")
    if visibility == database.VIS_NETWORK_ONLY:
        reasons.append("Only network activity is visible; website visits cannot be seen.")
    elif visibility == database.VIS_HISTORY and current != "NOT_REPORTING":
        reasons.append("Website visits come from the browser's own history (lower confidence than the extension).")
    if item.get("former_device"):
        reasons.append("This computer has no sensor any more (its last sensor now belongs to another computer); its earlier records are kept.")
    verified = item.get("identity") == database.IDENTITY_VERIFIED
    if not verified:
        reasons.append("The identity of this computer is not verified (it is a browser installation or was recorded before devices existed).")

    first_seen = facts["first_seen"].get(device_id)
    first_date = window["first_date"]
    start_date = max(first_date, first_seen) if first_seen else None
    period_days = len(window["dates"])
    if start_date is None or start_date > window["last_date"]:
        days_in_scope = 0
    else:
        days_in_scope = (datetime.strptime(window["last_date"], "%Y-%m-%d") - datetime.strptime(start_date, "%Y-%m-%d")).days + 1
    observed = len([d for d in facts["activity_days"].get(device_id, set()) if window["first_date"] <= d <= window["last_date"]])
    history_fraction = days_in_scope / float(period_days)
    observed_ratio = (observed / float(days_in_scope)) if days_in_scope else 0.0
    insufficient = history_fraction < MIN_HISTORY_FRACTION or observed_ratio < MIN_OBSERVED_RATIO
    if insufficient:
        if history_fraction < MIN_HISTORY_FRACTION:
            reasons.append("This computer has been known for only %s of the %d-day period." % (_plural(days_in_scope, "day", "days"), period_days))
        else:
            reasons.append("Records exist for only %d of the %d days this computer has been known." % (observed, days_in_scope))
    if current == "NOT_REPORTING":
        summary = "NOT_REPORTING"
    elif current == "PARTIALLY_MONITORED":
        summary = "PARTIALLY_MONITORED"
    elif insufficient:
        summary = "INSUFFICIENT_HISTORICAL_COVERAGE"
    elif not verified:
        summary = "UNVERIFIED_IDENTITY"
    else:
        summary = "REPORTING_NORMALLY"
    return {
        "status": summary, "current_status": current, "identity_status": "VERIFIED" if verified else "UNVERIFIED",
        # Phase D2.1: identity_status above keeps its old meaning (VERIFIED = a Windows Agent enrolled itself) and must not be read as administrator approval;
        # these additive fields say what it really is
        "identity_level": item.get("identity_level"), "identity_short": item.get("identity_short"), "identity_label": item.get("identity_label"),
        "identity_explanation": item.get("identity_explanation"), "identity_admin_approved": bool(item.get("identity_admin_approved")),
        "history_status": "INSUFFICIENT" if insufficient else "SUFFICIENT",
        "sensors": {"extension": extension, "agent": agent, "website_visibility": visibility,
                    "website_visibility_label": overview.visibility_label(visibility)},
        "history": {"first_seen_date": first_seen, "period_days": period_days, "days_known_in_period": days_in_scope, "history_fraction": round(history_fraction, 2),
                    "days_with_records": observed, "records_ratio": round(observed_ratio, 2)},
        "reasons": reasons,
    }


def computer_risk(item, facts, coverage, window, now, detail=False):
    """The explainable web exposure risk of one computer, or an honest 'insufficient data'."""
    device_id = item["device_id"]
    exposures = list(facts["exposures"].get(device_id, {}).values())
    verdict_counts = facts["verdicts"].get(device_id, {"MALICIOUS": 0, "SUSPICIOUS": 0, "SAFE": 0, "UNKNOWN": 0, "WEAK": 0})
    total = sum(verdict_counts.values())
    unknown = verdict_counts["UNKNOWN"]
    days = len(window["dates"])
    scoring = score_exposures(exposures, now)
    quality = {"logical_visits": total, "checked_visits": total - unknown, "unchecked_visits": unknown,
               "unchecked_fraction": round(unknown / float(total), 2) if total else 0.0, "score_is_lower_bound": unknown > 0}

    website_capable = item.get("visibility") in (database.VIS_FULL, database.VIS_BROWSER, database.VIS_HISTORY)
    has_website_days = len(facts["website_days"].get(device_id, set())) >= 1
    sufficient = website_capable and coverage["history_status"] == "SUFFICIENT" and has_website_days
    insufficient_reasons = []
    if not website_capable:
        insufficient_reasons.append("Website visits cannot be seen on this computer right now (%s)." % overview.visibility_label(item.get("visibility")).lower())
    if coverage["history_status"] == "INSUFFICIENT":
        insufficient_reasons.append("There is not enough history for this period to say anything about low risk.")
    if not has_website_days:
        insufficient_reasons.append("No website visit from this computer was recorded in this period.")

    result = {"status": "SCORED", "score": scoring["score"], "category": scoring["category"], "category_label": CATEGORY_LABELS[scoring["category"]],
              "insufficient_reasons": [], "data_quality": quality}
    if not exposures and not sufficient:
        result.update(status="INSUFFICIENT_DATA", score=None, category=None, category_label="Not enough monitoring data to assess", insufficient_reasons=insufficient_reasons)

    reasons = []
    malicious_n = sum(e["malicious_visits"] for e in exposures)
    suspicious_n = sum(e["suspicious_visits"] for e in exposures)
    if exposures:
        parts = []
        if malicious_n:
            parts.append("%s to dangerous websites" % _plural(malicious_n, "visit", "visits"))
        if suspicious_n:
            parts.append("%s to websites that need review" % _plural(suspicious_n, "visit", "visits"))
        last = max(e["last_at"] for e in exposures)
        reasons.append("In the last %d days this computer made %s (%s), most recently %s." % (
            days, " and ".join(parts), _plural(len(exposures), "distinct website", "distinct websites"), _ago(last, now)))
        top = scoring["domains"][0]
        reasons.append("Most serious: %s (%s, %s)." % (top["domain"], "dangerous" if top["verdict"] == "MALICIOUS" else "needs review",
                                                        _plural(top["visits"], "visit", "visits")))
        if scoring["suspicious_points"] > SUSPICIOUS_RAW_CAP:
            reasons.append("Websites that only need review are capped in the score, so they cannot outweigh dangerous ones.")
        if any(e["age_days"] > RECENCY_HALF_LIFE_DAYS for e in scoring["domains"]):
            reasons.append("Older exposures count less than recent ones.")
        reasons.append(DISCLAIMER)
        if coverage["status"] in ("NOT_REPORTING", "PARTIALLY_MONITORED", "INSUFFICIENT_HISTORICAL_COVERAGE"):
            reasons.append("Monitoring of this computer is incomplete, so other exposure may not have been seen.")
    elif result["status"] == "SCORED":
        reasons.append("No dangerous or suspicious websites were observed in the last %d days. This does not prove the computer is safe." % days)
    else:
        reasons.extend(insufficient_reasons)
        reasons.append("A low score cannot be given without enough monitoring data.")
    if unknown:
        reasons.append("%s could not be checked by the reputation service and are not counted as safe, so the real exposure may be higher." % _plural(unknown, "visit", "visits"))

    cap = MAX_DOMAINS_IN_DETAIL if detail else MAX_DOMAINS_IN_RANKING
    evidence = []
    for e in scoring["domains"][:cap]:
        row = {"domain": e["domain"], "verdict": e["verdict"], "logical_visits": e["visits"], "malicious_visits": e["malicious_visits"],
               "suspicious_visits": e["suspicious_visits"], "first_visit": e["first_at"], "last_visit": e["last_at"], "days_with_visits": e["days_with_visits"],
               "age_days": e["age_days"], "points": e["points"]}
        if detail:
            row.update(repeat_factor=e["repeat_factor"], recency_weight=e["recency_weight"], sample_visit_ids=e.get("sample_visit_ids", []))
        evidence.append(row)
    result.update(
        reasons=reasons, evidence=evidence, evidence_domains_total=len(scoring["domains"]),
        inputs={"malicious_visits": malicious_n, "suspicious_visits": suspicious_n, "risky_domains": len(exposures), "raw_points": scoring["raw_points"],
                "malicious_points": scoring["malicious_points"], "suspicious_points": scoring["suspicious_points"],
                "suspicious_points_counted": scoring["suspicious_points_counted"], "period_days": days},
        last_risky_exposure=max([e["last_at"] for e in exposures]) if exposures else None, disclaimer=DISCLAIMER)
    return result


_COVERAGE_ORDER = ("NOT_REPORTING", "PARTIALLY_MONITORED", "INSUFFICIENT_HISTORICAL_COVERAGE", "UNVERIFIED_IDENTITY", "REPORTING_NORMALLY")


def assess_computers(conn, days, now=None, detail_device=None):
    """Risk + coverage of every ACTIVE computer for the last `days` days (or only `detail_device`), without ranking."""
    now = now or datetime.now()
    window = period_bounds(days, now)["current"]
    facts = _per_device_facts(conn, window, now)
    if detail_device is not None:
        facts["exposures"] = device_exposures(conn, window["start"], window["end"], with_visit_ids=True)
    out = []
    for item in database.list_devices(conn, now):
        if detail_device is not None and item["device_id"] != detail_device:
            continue
        coverage = computer_coverage(item, facts, window)
        risk = computer_risk(item, facts, coverage, window, now, detail=detail_device is not None)
        username = item.get("username")
        out.append({
            "device_id": item["device_id"], "display_name": item["computer_name"],
            "user": {"name": username, "verified": False, "note": "A label reported by the sensor; it is not authenticated."},
            "device_identity": item.get("identity"), "device_identity_verified": item.get("identity") == database.IDENTITY_VERIFIED,
            "identity": {"level": item.get("identity_level"), "short": item.get("identity_short"), "label": item.get("identity_label"),
                         "explanation": item.get("identity_explanation"), "admin_approved": bool(item.get("identity_admin_approved")),
                         "note": "device_identity / device_identity_verified keep their earlier meaning (a Windows Agent enrolled itself); they are not administrator approval"},
            "risk": risk, "coverage": coverage,
            "malicious_visits": risk["inputs"]["malicious_visits"], "suspicious_visits": risk["inputs"]["suspicious_visits"],
            "distinct_risky_domains": risk["inputs"]["risky_domains"], "last_risky_exposure": risk["last_risky_exposure"],
            "open_alerts": facts["open_alerts"].get(item["device_id"], 0),
        })
    return out


def _rank_key(entry):
    risk = entry["risk"]
    scored = risk["status"] == "SCORED"
    last = entry["last_risky_exposure"]
    last_epoch = time.mktime(datetime.strptime(last, TIME_FORMAT).timetuple()) if last else 0.0
    return (0 if scored else 1, -(risk["score"] or 0), -entry["malicious_visits"], -entry["distinct_risky_domains"], -last_epoch,
            (entry["display_name"] or "").lower(), entry["device_id"])


def ranking(conn, days, now=None, limit=DEFAULT_LIMIT):
    """Computers ordered by web exposure risk, most exposed first. Ties break on dangerous visits, risky domains, most recent exposure, name, id;
    computers without enough data come after the scored ones. Computers are never merged: each device id is its own row."""
    entries = sorted(assess_computers(conn, days, now), key=_rank_key)
    n = 0
    for entry in entries:
        if entry["risk"]["status"] == "SCORED":
            n += 1
            entry["rank"] = n
        else:
            entry["rank"] = None
        entry["explanation"] = " ".join(entry["risk"]["reasons"][:3])
    return entries[:limit], len(entries)


# ---- the organisation summary ---------------------------------------------------------------------------------------------------------
def organisation_summary(conn, days, now=None):
    now = now or datetime.now()
    bounds = period_bounds(days, now)
    first_date = first_data_date(conn)
    current = _period_metrics(conn, bounds["current"])
    previous = _period_metrics(conn, bounds["previous"])
    comp_current = completeness(conn, bounds["current"], first_date, now)
    comp_previous = completeness(conn, bounds["previous"], first_date, now)
    reliable = comp_previous["status"] == "COMPLETE"
    computers = assess_computers(conn, days, now)
    by_coverage = dict((name, 0) for name in _COVERAGE_ORDER)
    for c in computers:
        by_coverage[c["coverage"]["status"]] += 1
    by_identity = dict((level, 0) for level in database.IDENTITY_LEVELS)
    for c in computers:
        by_identity[c["identity"]["level"]] += 1
    categories = {}
    for c in computers:
        key = c["risk"]["category"] if c["risk"]["status"] == "SCORED" else "INSUFFICIENT_DATA"
        categories[key] = categories.get(key, 0) + 1
    return {
        "period": {"days": days, "current": bounds["current"]["first_date"] + " to " + bounds["current"]["last_date"],
                   "previous": bounds["previous"]["first_date"] + " to " + bounds["previous"]["last_date"]},
        "current": current, "previous": previous, "comparison": _comparison(current, previous, reliable),
        "open_alerts": open_alert_counts(conn),
        "completeness": {"current": comp_current, "previous": comp_previous, "comparison_reliable": reliable},
        "computers": {"total": len(computers), "by_coverage": by_coverage, "by_risk_category": categories, "by_identity_level": by_identity,
                      "scored": sum(1 for c in computers if c["risk"]["status"] == "SCORED"),
                      "insufficient_data": sum(1 for c in computers if c["risk"]["status"] != "SCORED"),
                      "with_risky_exposure": sum(1 for c in computers if c["distinct_risky_domains"])},
    }


MAX_ACTIVITY_VISITS = 100
DEFAULT_ACTIVITY_VISITS = 20


def computer_activity(conn, device_id, days, now=None, limit=DEFAULT_ACTIVITY_VISITS):
    """Read-only extras for one computer's detail page: its daily series, its most recent risky LOGICAL visits and its most recent visits of any verdict (each with the id of the visit page that shows
    the evidence) and its open alerts. Returns None when the computer is not an active one."""
    now = now or datetime.now()
    limit = max(1, min(int(limit), MAX_ACTIVITY_VISITS))
    if conn.execute("SELECT 1 FROM active_devices WHERE device_id = ?", (device_id,)).fetchone() is None:
        return None
    bounds = period_bounds(days, now)
    window = bounds["current"]
    first_seen = conn.execute(
        "SELECT MIN(d) FROM (SELECT MIN(substr(COALESCE(first_seen, last_seen), 1, 10)) AS d FROM endpoints WHERE device_id = :d AND archived_at IS NULL "
        "UNION ALL SELECT substr(created_at, 1, 10) FROM devices WHERE id = :d "
        "UNION ALL SELECT MIN(substr(valid_from, 1, 10)) FROM sensor_device_associations WHERE device_id = :d AND basis = 'RECORDED' "
        "UNION ALL SELECT MIN(substr(visited_at, 1, 10)) FROM web_visits WHERE device_id = :d)", {"d": device_id}).fetchone()[0]
    visits = []
    for row in conn.execute(
            "SELECT v.id AS id, v.visited_at AS at, v.domain AS domain, v.reputation_status AS verdict, v.browser AS browser, v.source AS source " + _LOGICAL +
            " AND e.device_id = :device AND " + _STATUS + " IN ('MALICIOUS', 'SUSPICIOUS') ORDER BY v.visited_at DESC, v.id DESC LIMIT :limit",
            {"lo": window["start"], "hi": window["end"], "device": device_id, "limit": limit}):
        visits.append({"visit_id": row["id"], "visited_at": row["at"], "domain": row["domain"], "verdict": row["verdict"], "browser": row["browser"],
                       "source": row["source"]})
    recent = []
    for row in conn.execute(
            "SELECT v.id AS id, v.visited_at AS at, v.domain AS domain, " + _STATUS + " AS verdict, v.browser AS browser, v.source AS source " + _LOGICAL +
            " AND e.device_id = :device ORDER BY v.visited_at DESC, v.id DESC LIMIT :limit",
            {"lo": window["start"], "hi": window["end"], "device": device_id, "limit": limit}):
        recent.append({"visit_id": row["id"], "visited_at": row["at"], "domain": row["domain"], "verdict": _verdict(row["verdict"]), "browser": row["browser"],
                       "source": row["source"]})
    alerts = []
    for row in conn.execute(
            "SELECT a.id AS id, a.severity AS severity, a.domain AS domain, a.created_at AS created_at, a.exposure_count AS exposures, a.escalated_at AS escalated_at "
            "FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id WHERE a.status = 'OPEN' AND COALESCE(a.device_id, e.device_id) = ? "
            "ORDER BY CASE a.severity WHEN 'HIGH' THEN 0 ELSE 1 END, a.created_at DESC, a.id DESC LIMIT 25", (device_id,)):
        alerts.append({"alert_id": row["id"], "severity": row["severity"], "domain": row["domain"], "created_at": row["created_at"],
                       "exposures": row["exposures"] or 1, "escalated": row["escalated_at"] is not None})
    return {"device_id": device_id, "period": {"first_date": window["first_date"], "last_date": window["last_date"]}, "daily": daily_trend(conn, window, first_seen, device_id),
            "recent_risky_visits": visits, "recent_risky_visits_limit": limit, "recent_visits": recent, "open_alerts": alerts}


def trends(conn, days, now=None):
    now = now or datetime.now()
    bounds = period_bounds(days, now)
    first_date = first_data_date(conn)
    return {"current": {"dates": bounds["current"], "daily": daily_trend(conn, bounds["current"], first_date)},
            "previous": {"dates": bounds["previous"], "daily": daily_trend(conn, bounds["previous"], first_date)},
            "completeness": {"current": completeness(conn, bounds["current"], first_date, now), "previous": completeness(conn, bounds["previous"], first_date, now)}}


# ---- the JSON interface --------------------------------------------------------------------------------------------------------------
# Every route below is protected by the default-deny guard of auth.py (it is not marked as a sensor API or public). They only read.
bp = Blueprint("analytics", __name__, url_prefix="/api/analytics")


def _meta(days, now):
    return {"generated_at": _fmt(now), "timezone": {"stored_as": "server local time, no offset", "utc_offset_now": time.strftime("%z"), "name": time.strftime("%Z")},
            "period_days": days, "scope": "active computers (archived computers are hidden, as on the dashboard)", "limitations": LIMITATIONS}


def _bad(message):
    response = jsonify({"ok": False, "error": message})
    response.status_code = 400
    return response


def _days():
    raw = request.args.get("days", "7")
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return None, _bad("days must be one of %s" % ", ".join(str(p) for p in PERIODS))
    if days not in PERIODS:
        return None, _bad("days must be one of %s" % ", ".join(str(p) for p in PERIODS))
    return days, None


def _respond(days, build):
    now = datetime.now()
    conn = read_only_connection()
    try:
        data = build(conn, now)
    finally:
        conn.close()
    return jsonify({"ok": True, "meta": _meta(days, now), "data": data})


@bp.route("/summary", methods=["GET"])
def api_summary():
    days, error = _days()
    if error:
        return error
    return _respond(days, lambda conn, now: organisation_summary(conn, days, now))


@bp.route("/trends", methods=["GET"])
def api_trends():
    days, error = _days()
    if error:
        return error
    return _respond(days, lambda conn, now: trends(conn, days, now))


@bp.route("/computers", methods=["GET"])
def api_computers():
    days, error = _days()
    if error:
        return error
    try:
        limit = int(request.args.get("limit", DEFAULT_LIMIT))
    except (TypeError, ValueError):
        return _bad("limit must be a whole number from 1 to %d" % MAX_LIMIT)
    if not 1 <= limit <= MAX_LIMIT:
        return _bad("limit must be a whole number from 1 to %d" % MAX_LIMIT)

    def build(conn, now):
        entries, total = ranking(conn, days, now, limit)
        return {"computers": entries, "returned": len(entries), "total": total, "ranked_by": "web exposure risk score, most exposed first"}

    return _respond(days, build)


@bp.route("/computers/<int:device_id>", methods=["GET"])
def api_computer(device_id):
    days, error = _days()
    if error:
        return error
    now = datetime.now()
    conn = read_only_connection()
    try:
        found = assess_computers(conn, days, now, detail_device=device_id)
    finally:
        conn.close()
    if not found:
        response = jsonify({"ok": False, "error": "computer not found"})
        response.status_code = 404
        return response
    entry = found[0]
    entry["rank"] = None
    return jsonify({"ok": True, "meta": _meta(days, now), "data": {"computer": entry}})


@bp.route("/computers/<int:device_id>/activity", methods=["GET"])
def api_computer_activity(device_id):
    days, error = _days()
    if error:
        return error
    try:
        limit = int(request.args.get("limit", DEFAULT_ACTIVITY_VISITS))
    except (TypeError, ValueError):
        return _bad("limit must be a whole number from 1 to %d" % MAX_ACTIVITY_VISITS)
    if not 1 <= limit <= MAX_ACTIVITY_VISITS:
        return _bad("limit must be a whole number from 1 to %d" % MAX_ACTIVITY_VISITS)
    now = datetime.now()
    conn = read_only_connection()
    try:
        data = computer_activity(conn, device_id, days, now, limit)
    finally:
        conn.close()
    if data is None:
        response = jsonify({"ok": False, "error": "computer not found"})
        response.status_code = 404
        return response
    return jsonify({"ok": True, "meta": _meta(days, now), "data": data})


@bp.route("/coverage", methods=["GET"])
def api_coverage():
    days, error = _days()
    if error:
        return error

    def build(conn, now):
        computers = assess_computers(conn, days, now)
        rows = [{"device_id": c["device_id"], "display_name": c["display_name"], "coverage": c["coverage"]} for c in computers]
        rows.sort(key=lambda r: (_COVERAGE_ORDER.index(r["coverage"]["status"]), (r["display_name"] or "").lower(), r["device_id"]))
        counts = dict((name, 0) for name in _COVERAGE_ORDER)
        for r in rows:
            counts[r["coverage"]["status"]] += 1
        return {"computers": rows, "by_status": counts, "note": "Coverage describes monitoring, not threats. It is deliberately separate from the risk score."}

    return _respond(days, build)
