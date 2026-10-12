"""SHADOW MODE for the corroborated alert policy (Phase F3.17).

For every newly analysed visit the application records, next to the decision it actually took (legacy), what the PROPOSED corroborated policy (services/alert_policy.py) would have
decided from the same evidence, whether they agree, the independent evidence groups with their strengths, and which sources had answered at that moment. The record lives in its own
table (alert_decisions). It is INFORMATION ONLY:
  * nothing in this module creates, closes, suppresses, downgrades or edits an alert, a visit or any evidence; the legacy decision is passed in, never recomputed or changed;
  * a failure here (record() swallows every error) can never stop an event from being stored or alerted;
  * missing evidence is never reported as "clean": a visit without a single successful lookup is INSUFFICIENT, not 'agrees: no alert'.
reconstruct() reviews HISTORY: alerts and visits from before shadow recording began are re-evaluated from the evidence stored NOW and labelled "reconstructed" (the evidence may have been
refreshed since, and the sources that existed then are not recorded), again never as a clean result.
Standard library plus the project's own modules; Python 3.8 compatible.
"""
import json
import re
from datetime import datetime, timedelta

from services import alert_policy, risk

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
RECONSTRUCTION_SLACK_SECONDS = 120


def _cards(conn, domain):
    from services import reputation          # imported late: reputation does not import this module
    analysis = reputation.analysis_bulk(conn, [domain]).get(domain)
    return (analysis or {}).get("providers") or [], analysis


def _configured_names():
    from services import reputation
    return set(r["name"] for r in reputation.provider_states() if r["state"] not in ("DISABLED", "NOT_CONFIGURED", "RETIRED"))


def judge(proposed, legacy_severity):
    """(agree, reason): True / False when the two decisions can BOTH be evaluated reliably, None (with the reason) when they cannot - a difference is then reported as
    "insufficient evidence", never as a disagreement.
      * the same decision                         -> agree;
      * the proposed policy says "no alert" only because sources could not be checked (`pending`) -> the proposed decision is provisional, not a decision;
      * the running policy alerted but no stored evidence shows why (nothing reports anything now: the source that raised it is gone or unavailable) -> the legacy decision cannot
        be reconstructed, so there is nothing reliable to compare."""
    if proposed["alert_severity"] == legacy_severity:
        return True, None
    if proposed["pending"]:
        return None, "%s could not be checked, so what the proposed policy would have decided cannot be determined reliably." % ", ".join(proposed["failed"])
    if legacy_severity and proposed["tier"] == "NONE":
        return None, ("No stored evidence shows why the running policy raised this alert (the source that raised it is not available now), so the two decisions cannot be compared "
                      "reliably. This is not a clean result.")
    return False, None


def snapshot(conn, domain, visit_id, legacy_severity, configured=None):
    """The shadow decision for one visit as a dict (nothing is written). `legacy_severity` is the alert severity the running policy decided for this visit: HIGH, MEDIUM or None."""
    cards, analysis = _cards(conn, domain)
    cards = risk.scoring_cards(cards)          # observation-only sources (Phase F3.22) are not part of the comparison
    url_rows = []
    if visit_id is not None:
        from database import url_evidence_for_visits
        url_rows = url_evidence_for_visits(conn, [visit_id]).get(visit_id, [])
    assessment = risk.assess(cards, url_rows, configured)
    answered = [c for c in cards if c.get("state") == "CHECKED"] + [r for r in url_rows if r.get("state") == "CHECKED"]
    if not answered:
        # no source has answered: the visit is neither clean nor risky as far as anyone knows
        return {"legacy_severity": legacy_severity, "shadow_severity": None, "tier": "INSUFFICIENT", "agree": None, "summary": "INSUFFICIENT EVIDENCE: no source has answered for this visit, so the "
                "proposed policy cannot decide (this is not a clean result).", "groups": {"confirmed": [], "credible": [], "weak": []}, "reasons": ["No source has answered."],
                "coverage": _coverage(assessment), "score": assessment["score"], "pending": False}
    proposed = alert_policy.evaluate(cards, url_rows)
    agree, why_not = judge(proposed, legacy_severity)
    names = alert_policy._Names()
    groups = {"confirmed": [names[g] for g in proposed["confirmed"]], "credible": [names[g] for g in proposed["credible"]], "weak": [names[g] for g in proposed["weak"]]}
    return {"legacy_severity": legacy_severity, "shadow_severity": proposed["alert_severity"], "tier": proposed["tier"], "agree": agree,
            "summary": ("INSUFFICIENT EVIDENCE: " + why_not) if agree is None else alert_policy.compare_with_legacy(None, None, legacy_severity, proposed), "groups": groups, "reasons": proposed["reasons"], "coverage": _coverage(assessment),
            "score": assessment["score"], "pending": proposed["pending"]}


def _coverage(assessment):
    out = {"answered": [], "failed": [], "skipped": [], "not_configured": []}
    for c in assessment["coverage"]:
        key = {"finding": "answered", "no_records": "answered", "coverage_gap": "answered", "failed": "failed", "skipped": "skipped", "not_configured": "not_configured"}.get(c["outcome"], "answered")
        out[key].append(c["provider"])
    return out


def record(conn, visit_id, domain, legacy_severity, alert_id=None, configured=None):
    """Store the shadow decision of a visit. NEVER raises and never touches anything but its own table."""
    try:
        if visit_id is None:
            return None
        snap = snapshot(conn, domain, visit_id, legacy_severity, configured if configured is not None else _configured_names())
        conn.execute(
            "INSERT OR IGNORE INTO alert_decisions (web_visit_id, alert_id, domain, decided_at, legacy_policy, legacy_severity, shadow_severity, shadow_tier, agree, summary, groups_json, "
            "coverage_json, reasons_json, risk_score, pending) VALUES (?, ?, ?, ?, 'legacy', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (visit_id, alert_id, domain, datetime.now().strftime(TIME_FORMAT), snap["legacy_severity"], snap["shadow_severity"], snap["tier"], None if snap["agree"] is None else int(snap["agree"]),
             snap["summary"], json.dumps(snap["groups"]), json.dumps(snap["coverage"]), json.dumps(snap["reasons"]), snap["score"], int(bool(snap["pending"]))))
        conn.commit()
        return snap
    except Exception:                       # shadow mode must never be able to break ingestion
        try:
            conn.rollback()
        except Exception:
            pass
        return None


def scrub(text):
    """Display text of a decision that was recorded while a source that has since been removed was still asked: that source's name is never shown (the stored row is untouched), the sentence
    keeps its meaning ("A retired source could not be checked ...")."""
    if not isinstance(text, str):
        return text
    text = re.sub(r"(^|[.:;]\s+)URLhaus\b", r"\1A retired source", text)
    return re.sub(r"URLhaus", "a retired source", text, flags=re.I)


def _row(r):
    d = dict(r)
    for key in ("groups_json", "coverage_json", "reasons_json"):
        try:
            d[key[:-5]] = json.loads(d.get(key) or "null")
        except ValueError:
            d[key[:-5]] = None
    d["summary"] = scrub(d.get("summary"))
    if isinstance(d.get("reasons"), list):
        d["reasons"] = [scrub(x) for x in d["reasons"]]
    if isinstance(d.get("coverage"), dict):
        d["coverage"] = dict((k, [n for n in v if isinstance(n, str) and "urlhaus" not in n.lower()] if isinstance(v, list) else v) for k, v in d["coverage"].items())
    return d


def decisions_for_visits(conn, visit_ids):
    ids = sorted(set(int(i) for i in visit_ids if i is not None))
    out = {}
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        for r in conn.execute("SELECT * FROM alert_decisions WHERE web_visit_id IN (%s)" % ",".join("?" * len(chunk)), chunk):
            out[r["web_visit_id"]] = _row(r)
    return out


def summary(conn):
    """Counts for the review page: decisions recorded, agreeing, differing (and how), insufficient."""
    rows = conn.execute("SELECT legacy_severity, shadow_severity, shadow_tier, agree FROM alert_decisions").fetchall()
    out = {"total": len(rows), "agree": 0, "differ": 0, "insufficient": 0, "legacy_only": 0, "shadow_only": 0, "severity_differs": 0}
    for r in rows:
        if r["agree"] is None:
            out["insufficient"] += 1
        elif r["agree"]:
            out["agree"] += 1
        else:
            out["differ"] += 1
            if r["legacy_severity"] and not r["shadow_severity"]:
                out["legacy_only"] += 1
            elif r["shadow_severity"] and not r["legacy_severity"]:
                out["shadow_only"] += 1
            else:
                out["severity_differs"] += 1
    return out


def recent(conn, limit=100, only_differences=False):
    sql = "SELECT d.*, v.visited_at, v.source, e.computer_name FROM alert_decisions d JOIN web_visits v ON v.id = d.web_visit_id JOIN endpoints e ON e.id = v.endpoint_id"
    if only_differences:
        sql += " WHERE d.agree = 0"
    sql += " ORDER BY d.id DESC LIMIT ?"
    return [_row(r) for r in conn.execute(sql, (int(limit),))]


def reconstruct(conn):
    """Review of HISTORY: every alert, re-evaluated with the evidence stored now. Each entry says what it is based on and never turns missing evidence into a clean result.
    {alert_id, domain, legacy_severity, shadow_severity, tier, agree, sufficient, basis, evidence_refreshed, coverage_then, vendors, note}"""
    out = []
    for a in conn.execute("SELECT * FROM alerts ORDER BY id").fetchall():
        cards, _ = _cards(conn, a["domain"])
        cards = risk.scoring_cards(cards)
        has_snapshot = conn.execute("SELECT COUNT(*) FROM alert_decisions WHERE alert_id = ?", (a["id"],)).fetchone()[0] > 0
        created = datetime.strptime(a["created_at"], TIME_FORMAT)
        then, later = [], []
        for c in cards:
            checked = c.get("checked_at")
            if checked and datetime.strptime(checked, TIME_FORMAT) <= created + timedelta(seconds=RECONSTRUCTION_SLACK_SECONDS):
                then.append(c["provider"])
            elif checked:
                later.append(c["provider"])
        answered = [c for c in cards if c.get("state") == "CHECKED"]
        entry = {"alert_id": a["id"], "domain": a["domain"], "legacy_severity": a["severity"], "exposure_count": a["exposure_count"], "created_at": a["created_at"], "has_snapshot": has_snapshot,
                 "coverage_then": sorted(then), "evidence_refreshed_later": sorted(later)}
        if not answered:
            entry.update(sufficient=False, shadow_severity=None, tier="INSUFFICIENT", agree=None, basis="reconstructed from stored evidence: none stored",
                         note="No successful lookup is stored for this domain, so nothing can be compared. This is not a clean result.")
        else:
            proposed = alert_policy.evaluate(cards)
            agree, why_not = judge(proposed, a["severity"])
            entry.update(sufficient=agree is not None, shadow_severity=proposed["alert_severity"] if agree is not None else None, tier=proposed["tier"] if agree is not None else "INSUFFICIENT",
                         agree=agree, basis="reconstructed from the evidence stored now" if agree is not None else "reconstructed from the evidence stored now: insufficient",
                         note=("Insufficient evidence: " + why_not) if agree is None else " ".join(proposed["reasons"]), pending=proposed["pending"])
            if later:
                entry["note"] += " Some evidence was refreshed after the alert was raised (%s), so this may not equal the original situation." % ", ".join(sorted(later))
        out.append(entry)
    return out


STRENGTH_TEXT = {
    "CONFIRMED": "Strong: an independent source confirmed it",
    "CORROBORATED": "Strong: two independent sources agree",
    "CREDIBLE": "Moderate: one source reported credible evidence, no second source confirms it",
    "WEAK_CORROBORATED": "Weak: several independent sources each report only weak evidence",
    "WEAK": "Weak: only weak evidence (for example a single vendor, or a historical or shared-host association)",
    "NONE": "No source that answered reported anything",
    "INSUFFICIENT": "Unknown: no stored lookup is available for this domain",
}
LEGACY_RULE = {"HIGH": "the running rule raises a Dangerous alert when any source's verdict is MALICIOUS",
               "MEDIUM": "the running rule raises a Needs review alert when any source's verdict is SUSPICIOUS, even if only one vendor says so"}


def detectors(cards):
    """Who reported what: one entry per source that has a finding, strongest first. `vendor` is the 'N of M security vendors (names)' text when VirusTotal recorded the engines,
    otherwise None (the page then says the vendor was not recorded - it never invents one)."""
    out = []
    for card in cards or []:
        f = risk.finding(card, "host")
        if f is None or alert_policy.RANK.get(f["level"], 0) == 0:          # a source that found nothing did not "report" anything
            continue
        vendor = alert_policy._vendor_text(card) if f["group"] == "virustotal" else None
        out.append({"provider": alert_policy._Names()[f["group"]], "level": f["level"], "vendor": vendor, "rank": alert_policy.RANK.get(f["level"], 0)})
    return sorted(out, key=lambda d: (-d["rank"], d["provider"]))


def explain_alert(alert, events, cards, decision=None):
    """Read-only explanation of an existing alert for the Alerts page. `alert`: the alerts row (dict); `events`: its alert_events; `cards`: the domain's current analysis cards;
    `decision`: the shadow snapshot of the alert's first visit when one was recorded. Nothing is stored or changed."""
    cards = risk.scoring_cards(cards)
    answered = [c for c in cards or [] if c.get("state") == "CHECKED"]
    proposed = alert_policy.evaluate(cards) if answered else None
    agree, why_not = judge(proposed, alert.get("severity")) if proposed else (None, None)
    tier = proposed["tier"] if proposed else "INSUFFICIENT"          # what the stored evidence says about strength, whether or not the comparison is reliable
    if proposed and agree is None:          # both decisions cannot be evaluated reliably: say so, do not call it a disagreement
        proposed = None
    logical = alert.get("exposure_count") or 1
    supporting = sum(1 for e in events or [] if e.get("corroborates_event_id"))
    created = alert.get("created_at")
    historical = decision is None
    if decision is not None:
        coverage = decision.get("coverage") or {}
        coverage_basis = "recorded when the alert was raised"
    else:
        then = []
        for c in cards or []:
            if c.get("checked_at") and created and c["checked_at"] <= (datetime.strptime(created, TIME_FORMAT) + timedelta(seconds=RECONSTRUCTION_SLACK_SECONDS)).strftime(TIME_FORMAT):
                then.append(c["provider"])
        coverage = {"answered": sorted(then), "failed": [], "skipped": [], "not_configured": []}
        coverage_basis = "reconstructed from the stored lookup times (the sources consulted at that moment were not recorded)"
    return {
        "historical": historical,
        "why": LEGACY_RULE.get(alert.get("severity"), ""),
        "strength": STRENGTH_TEXT[tier], "tier": tier,
        "detectors": detectors(cards),
        "logical_exposures": logical, "supporting_records": supporting, "total_records": len([e for e in events or [] if e.get("web_visit_id")]),
        "coverage": coverage, "coverage_basis": coverage_basis,
        "proposed": None if not proposed else proposed["alert_severity"], "proposed_known": proposed is not None,
        "agree": agree,
        "shadow_note": " ".join(proposed["reasons"]) if proposed else ("Insufficient evidence: " + why_not) if why_not else STRENGTH_TEXT["INSUFFICIENT"] + ". This is not a clean result.",
    }
