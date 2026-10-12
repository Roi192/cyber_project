"""PROPOSED alert policy ("corroborated") - Phase F3.16. NOT WIRED INTO THE APPLICATION: nothing imports this module except tests and comparison scripts, SEVERITY_POLICY stays
"legacy", and no alert, visit or stored row is touched. It exists so the proposal can be tested against the legacy rule and against stored history before anybody decides.

WHY. The legacy rule is "one malicious vendor => SUSPICIOUS => MEDIUM alert". Stored evidence shows what that does: two alerts for ordinary, well-known sites (a cloud console and a sign-in
service) were raised because ONE VirusTotal engine of about ninety-two called them malicious. The evidence layer already knows that is only WEAK (services/evidence.py).
The `evidence` policy that is built but switched off fixes this per provider; what it cannot do is combine sources. This module adds that.

THE RULES (inputs are the findings of services/risk.py: one strongest finding per independent source group; a source that failed, was skipped or is not configured has no finding):
    HIGH    some independent group is CONFIRMED                    (Google MALWARE/SOCIAL_ENGINEERING, VirusTotal >= 4 engines or 3 with an authoritative one)
    HIGH    two or more independent groups are CREDIBLE or better  (corroboration: two sources that do not repeat each other agree)
    MEDIUM  exactly one group is CREDIBLE and none is CONFIRMED    (3+ engines, a recent attributed OTX campaign, a fresh malicious urlscan.io scan, UNWANTED_SOFTWARE ...)
    none    only WEAK findings (one vendor, a historical or shared-host association, a community mention, a stale scan): the visit stays visible as a "weak finding" with its explanation,
            it raises no alert. Several independent WEAK findings are listed as `tier = WEAK_CORROBORATED`; they alert only if `weak_corroboration_alerts` is switched on (default off).
    Sources that did not answer NEVER make a visit look clean and never lower anything: a weak-only visit whose other sources were unavailable is flagged `pending` (to be looked at
    again when they answer) instead of being declared harmless. No domain is treated specially: a popular site gets the same treatment, only its evidence differs.
An alert that already exists is never closed or lowered by this module; it is advice for NEW decisions, and a human reviews what it would have changed (see compare_with_legacy).
Standard library plus services.risk; Python 3.8 compatible.
"""
from services import risk

RANK = {"CONFIRMED": 3, "CREDIBLE": 2, "WEAK": 1}
LEGACY_ALERT = {"MALICIOUS": "HIGH", "SUSPICIOUS": "MEDIUM"}


class _Names(object):
    """Display names of the source groups; a group without a known name (a source added later) is shown under its own key instead of breaking the page."""

    def __getitem__(self, group):
        return risk.GROUP_NAMES.get(group, group)


def _vendor_text(card):
    details = risk._details(card)
    names = [d.get("engine") for d in (details.get("detections") or []) if d.get("category") in ("malicious", "suspicious") and d.get("engine")]
    counts = card.get("counts") or {}
    total = sum(v for v in counts.values() if isinstance(v, int)) if counts else None
    if not names:
        return None
    shown = ", ".join(names[:3])
    return "%d of %s security vendors (%s)" % (len(names), total if total else "the", shown)


def evaluate(host_cards, url_rows=(), weak_corroboration_alerts=False):
    """The proposed alert decision for ONE visit. host_cards: the analysis cards of the visit's domain; url_rows: its visit_url_evidence rows (dicts)."""
    findings = []
    for card in risk.scoring_cards(host_cards):          # observation-only sources never take part (Phase F3.22)
        f = risk.finding(card, "host")
        if f is not None:
            findings.append((f, card))
    for row in url_rows or []:
        f = risk.finding(row, "url")
        if f is not None:
            findings.append((f, row))
    strongest = {}
    for f, source in findings:
        r = RANK.get(f["level"], 0)
        if r and (f["group"] not in strongest or r > RANK[strongest[f["group"]][0]["level"]]):
            strongest[f["group"]] = (f, source)
    confirmed = sorted(g for g, (f, _) in strongest.items() if f["level"] == "CONFIRMED")
    credible = sorted(g for g, (f, _) in strongest.items() if f["level"] == "CREDIBLE")
    weak = sorted(g for g, (f, _) in strongest.items() if f["level"] == "WEAK")
    names = _Names()
    states = dict((c.get("provider"), c.get("state")) for c in risk.scoring_cards(host_cards))
    failed = sorted(p for p, s in states.items() if s in ("UNAVAILABLE", "ERROR"))
    answered = sorted(p for p, s in states.items() if s == "CHECKED")
    reasons = []
    severity, tier = None, "NONE"
    if confirmed:
        severity, tier = "HIGH", "CONFIRMED"
        reasons.append("%s confirmed it (strong evidence)." % " and ".join(names[g] for g in confirmed))
    elif len(credible) >= 2:
        severity, tier = "HIGH", "CORROBORATED"
        reasons.append("%s independently reported credible evidence: two sources that do not repeat each other agree." % " and ".join(names[g] for g in credible))
    elif len(credible) == 1:
        severity, tier = "MEDIUM", "CREDIBLE"
        reasons.append("%s reported credible evidence; no other independent source confirms it yet." % names[credible[0]])
    elif weak:
        tier = "WEAK_CORROBORATED" if len(weak) >= 2 else "WEAK"
        if tier == "WEAK_CORROBORATED" and weak_corroboration_alerts:
            severity = "MEDIUM"
        for g in weak:
            f, source = strongest[g]
            text = _vendor_text(source) if g == "virustotal" else None
            reasons.append("%s: only weak evidence%s." % (names[g], (" - " + text + " flagged it") if text else ""))
        reasons.append("Weak evidence alone (a single vendor, a historical or shared-host association, a community mention) does not raise an alert; it stays visible for review.")
    else:
        reasons.append("No source that answered reported anything.")
    pending = bool(failed) and severity is None and tier != "NONE"
    if failed and severity is None:
        reasons.append("%s could not be checked, so this is NOT a clean result%s." % (", ".join(failed), "; the visit is flagged to be looked at again" if pending else ""))
    return {"alert_severity": severity, "tier": tier, "confirmed": confirmed, "credible": credible, "weak": weak, "pending": pending, "answered": answered, "failed": failed, "reasons": reasons}


def compare_with_legacy(legacy_status, legacy_level, legacy_alert, proposed):
    """A one-line comparison for a human reviewer. legacy_alert: the alert severity the running (legacy) policy gave, or None."""
    new = proposed["alert_severity"]
    if new == legacy_alert:
        return "same (%s)" % (new or "no alert")
    if legacy_alert and not new:
        return "legacy alert %s would NOT be raised (%s): REVIEW before accepting" % (legacy_alert, proposed["tier"])
    if new and not legacy_alert:
        return "proposed alert %s where legacy raised none (%s): more sensitive" % (new, proposed["tier"])
    return "severity differs: legacy %s, proposed %s (%s)" % (legacy_alert, new, proposed["tier"])
