"""A transparent 0-100 risk score for one website visit, built from the evidence the five threat-intelligence sources left in the database (Phase F3.12).

THE SCORE IS FOR HUMANS. It is DISPLAYED next to the alert; it does not decide alerts. Alerts follow SEVERITY_POLICY (legacy today). Where the two disagree the analysis page says so
(compare_with_alert) instead of quietly changing a rule.

HOW IT IS BUILT (every step is also printed, in words, next to the number):
 1. Each source that answered contributes at most ONE finding, with the assessment its own rules gave it (services/evidence.py): CONFIRMED, CREDIBLE, WEAK or nothing (CLEAN).
        confidence:  CONFIRMED 80 %   CREDIBLE 45 %   WEAK 25 %   CLEAN / no records 0 %
    It is scaled by how recent the source says the evidence is (newest pulse / scan): <= 30 days x1.0, <= 90 days x0.85, <= 365 days x0.6, older x0.4.
 2. INDEPENDENCE. Several sources can repeat one underlying list: a VirusTotal engine that only re-publishes Google Safe Browsing.
    Findings that share a source GROUP count once (the strongest one). Groups: virustotal, google, otx, urlscan.
 3. Independent groups are combined as probabilities of "this is really bad":  risk = 1 - (1 - p1) x (1 - p2) x ... . One confirmed source gives 80 (critical); two credible
    independent sources give 70 (high); a confirmed and a credible give 89.
 4. A visit with NO credible-or-better evidence is capped at 49: any number of weak, historical or ambiguous associations stay below "high risk".
 5. SCOPE. Site-level evidence (the whole host: VirusTotal, OTX, urlscan.io, Google host list) and page-level evidence (Google Safe Browsing's check of this exact address,
    attached to this exact visit) are scored separately (host_score, url_score) and together (score). A page-level finding never changes the site's own score.
 6. Sources that FAILED, were SKIPPED or are NOT CONFIGURED add nothing and subtract nothing: a failure never lowers the score. They are listed as coverage, because a low
    score from few sources is weaker than a low score from five.

BANDS (display only): 0-19 no known risk indicators | 20-39 low concern | 40-59 suspicious | 60-79 high risk | 80-100 critical risk.
A score below 20 is NEVER "safe": it means no source reported anything. Standard library only; Python 3.8 compatible.
"""
import json

PROVIDERS = ("VirusTotal", "Google Safe Browsing", "AlienVault OTX", "urlscan.io")          # the sources that can be part of a score
# APIVoid, MetaDefender Cloud and AbuseIPDB are OBSERVATION-ONLY: shown, never scored (see docs/PROVIDERS.md for the proposed mapping before any of them may count).
OBSERVED_PROVIDERS = ("APIVoid", "MetaDefender Cloud", "AbuseIPDB")


def scoring_cards(cards):
    """The analysis cards that may take part in a verdict, a score or a policy decision: everything except the observation-only sources."""
    return [c for c in cards or [] if c.get("provider") not in OBSERVED_PROVIDERS]
GROUP_OF = {"VirusTotal": "virustotal", "Google Safe Browsing": "google", "AlienVault OTX": "otx", "urlscan.io": "urlscan"}
GROUP_NAMES = {"virustotal": "VirusTotal", "google": "Google Safe Browsing", "otx": "AlienVault OTX", "urlscan": "urlscan.io"}
# VirusTotal engines that only republish another source we also ask (lower-case engine name -> group)
VT_DERIVED = {"google safebrowsing": "google"}

CONFIDENCE = {"CONFIRMED": 0.80, "CREDIBLE": 0.45, "WEAK": 0.25}
RECENCY = ((30, 1.0), (90, 0.85), (365, 0.6))
RECENCY_OLDER = 0.4
CAP_WITHOUT_CREDIBLE = 49
LEVEL_WORDS = {"CONFIRMED": "confirmed", "CREDIBLE": "credible", "WEAK": "weak", "CLEAN": "no records", "UNKNOWN": "no information"}
RANK = {"CONFIRMED": 3, "CREDIBLE": 2, "WEAK": 1}

BANDS = ((80, "critical", "Critical risk"), (60, "high", "High risk"), (40, "suspicious", "Suspicious"), (20, "low", "Low concern"), (0, "none", "No known risk indicators"))
SCORE_TOOLTIP = ("A 0-100 score that combines what the independent threat-intelligence sources reported about this visit. It explains the evidence; it is not the alert rule. "
                 "A low score is never a promise that a website is safe: it only means nothing was reported.")


def band(score):
    for floor, key, label in BANDS:
        if score >= floor:
            return key, label
    return "none", BANDS[-1][2]


def recency_factor(age_days):
    if age_days is None:
        return 1.0
    for limit, factor in RECENCY:
        if age_days <= limit:
            return factor
    return RECENCY_OLDER


def _details(source):
    details = source.get("details")
    if details is None and source.get("details_json"):
        details = source["details_json"]
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            details = None
    return details if isinstance(details, dict) else {}


def _group_of(provider, details):
    if provider == "VirusTotal":
        engines = [str(d.get("engine", "")).lower() for d in (details.get("detections") or []) if d.get("category") == "malicious"]
        groups = set(VT_DERIVED.get(e) for e in engines)
        if engines and None not in groups and len(groups) == 1:
            return groups.pop()
    return GROUP_OF.get(provider, provider)


def _level_from(source, details):
    level = details.get("classification")
    if level in CONFIDENCE or level in ("CLEAN", "UNKNOWN"):
        return level, False
    verdict = source.get("verdict") or source.get("provider_verdict")          # an older record without details: judge cautiously from the verdict alone
    return {"MALICIOUS": "CREDIBLE", "SUSPICIOUS": "WEAK", "SAFE": "CLEAN"}.get(verdict, "UNKNOWN"), True


def finding(source, scope):
    """A finding from a stored evidence row / card, or None when the source did not answer. `source`: an analysis card (host) or a visit_url_evidence row (url)."""
    if source.get("state") != "CHECKED":
        return None
    details = _details(source)
    level, guessed = _level_from(source, details)
    base = CONFIDENCE.get(level, 0.0)
    age = details.get("newest_age_days")
    factor = recency_factor(age) if isinstance(age, int) and not isinstance(age, bool) else 1.0
    provider = source["provider"]
    return {"provider": provider, "scope": scope, "level": level, "p": base * factor, "base": base, "factor": factor, "age_days": age, "group": _group_of(provider, details),
            "guessed": guessed, "categories": categories_of(details)}


def categories_of(details):
    found = set()
    for d in details.get("detections") or []:
        if isinstance(d, dict) and d.get("engine") != "OTX pulse" and d.get("result"):
            found.add(str(d["result"])[:30])
    for key in ("categories", "malware_families", "threat_types", "adversaries"):
        for value in details.get(key) or []:
            found.add(str(value)[:30])
    return sorted(found)[:6]


def combine(findings):
    """(score 0-100, kept) - the strongest finding of each independent group, combined as 1 - product(1 - p); capped without credible evidence."""
    best = {}
    for f in findings:                  # the strongest finding of a group represents it; on a tie the group's own provider (not a republisher) does
        if f["p"] <= 0:
            continue
        native = GROUP_OF.get(f["provider"]) == f["group"]
        if f["group"] not in best or (f["p"], native) > (best[f["group"]]["p"], GROUP_OF.get(best[f["group"]]["provider"]) == f["group"]):
            best[f["group"]] = f
    remaining = 1.0
    for f in best.values():
        remaining *= 1.0 - f["p"]
    score = int(round(100 * (1.0 - remaining)))
    capped = False
    if best and not any(RANK.get(f["level"], 0) >= RANK["CREDIBLE"] for f in best.values()) and score > CAP_WITHOUT_CREDIBLE:
        score, capped = CAP_WITHOUT_CREDIBLE, True
    return score, sorted(best.values(), key=lambda f: -f["p"]), capped


def _scope_word(scope, provider):
    return "this exact page" if scope == "url" else "the whole site"


def assess(host_cards, url_rows=(), configured_names=None):
    """The complete explained assessment of a visit.
    host_cards: the analysis cards of the visit's domain (reputation.analysis_bulk()[domain]["providers"]); url_rows: the visit's visit_url_evidence rows (dicts)."""
    host_findings, url_findings, coverage = [], [], []
    seen = {}
    for card in host_cards or []:
        seen[card["provider"]] = card
    url_by_provider = dict((r["provider"], r) for r in (url_rows or []))
    for name in PROVIDERS:
        card, url_row = seen.get(name), url_by_provider.get(name)
        parts = []
        # a source that is switched on but left no evidence row (its request budget was used up) was SKIPPED, not "unconfigured"
        outcome = "skipped" if (card is None and configured_names is not None and name in configured_names) else "not_configured"
        if card is not None:
            state = card.get("state")
            f = finding(card, "host")
            if f is not None:
                host_findings.append(f)
                outcome = "finding" if f["p"] > 0 else ("coverage_gap" if _details(card).get("coverage_gap") else "no_records")
                parts.append(("site: " + LEVEL_WORDS.get(f["level"], f["level"].lower())) if f["p"] > 0 else ("site: " + ("no information (nothing to look up)" if outcome == "coverage_gap" else "no records")))
            elif state in ("UNAVAILABLE", "ERROR"):
                outcome = "failed"
                parts.append("site: " + ("unavailable" if state == "UNAVAILABLE" else "error"))
            elif state in ("NOT_CHECKED",):
                outcome = "skipped"
                parts.append("site: not checked yet")
            elif state in ("NO_PROVIDER", "NO_EVIDENCE"):
                outcome = "not_configured" if state == "NO_PROVIDER" else "no_records"
        if url_row is not None:
            uf = finding(dict(url_row, provider=name), "url")
            if uf is not None:
                url_findings.append(uf)
                if outcome in ("not_configured", "skipped"):
                    outcome = "finding" if uf["p"] > 0 else "no_records"
                parts.append("this page: " + (LEVEL_WORDS.get(uf["level"], "") if uf["p"] > 0 else "no records"))
            elif url_row.get("state") in ("UNAVAILABLE", "ERROR"):
                parts.append("this page: unavailable")
                outcome = "failed" if outcome in ("not_configured",) else outcome
            elif url_row.get("state") == "NOT_CHECKED":
                parts.append("this page: not checked (%s)" % {"sensitive": "private-looking address", "budget": "request limit", "time": "no time left", "host-listed": "site already listed"}.get(url_row.get("skip_reason"), "skipped"))
        coverage.append({"provider": name, "outcome": outcome, "text": "; ".join(parts) if parts else {"not_configured": "not configured", "failed": "failed", "skipped": "skipped"}.get(outcome, outcome)})
    host_score, host_kept, host_capped = combine(host_findings)
    url_score, url_kept, url_capped = combine(url_findings)
    score, kept, capped = combine(host_findings + url_findings)
    key, label = band(score)
    answered = [c for c in coverage if c["outcome"] in ("finding", "no_records", "coverage_gap")]
    failed = [c["provider"] for c in coverage if c["outcome"] == "failed"]
    skipped = [c["provider"] for c in coverage if c["outcome"] == "skipped"]
    missing = [c["provider"] for c in coverage if c["outcome"] == "not_configured"]
    if not answered:
        label = "Not assessed"
    total = len(coverage)
    coverage_text = "%d of %d sources answered" % (len(answered), total)
    for word, names in (("failed", failed), ("skipped", skipped), ("not configured", missing)):
        if names:
            coverage_text += "; %s: %s" % (word, ", ".join(names))
    lines = explanation(kept, host_findings + url_findings, score, capped, failed, skipped, missing, bool(answered))
    return {"score": score, "band": key, "label": label, "host_score": host_score, "url_score": url_score, "capped": capped,
            "lines": lines,
            "coverage": coverage, "coverage_text": coverage_text, "answered": len(answered), "total": total,
            "weak_only": bool(kept) and not any(RANK.get(f["level"], 0) >= RANK["CREDIBLE"] for f in kept),
            "caveat": ("No source could be checked, so there is no evidence either way. This is not a clean result." if not answered else
                       ("Nothing was reported by the sources that answered. That is not proof that the website is safe." if score < 20 else None))}


def explanation(kept, all_findings, score, capped, failed, skipped, missing, answered_any=True):
    lines = []
    if not kept:
        lines.append("No source that answered reported anything about this visit, so the score is %d. That is not proof that the website is safe." % score if answered_any
                     else "No source could be checked for this visit, so there is no evidence either way. The score of 0 means 'not assessed', not 'safe'.")
    for f in kept:
        republishes = "" if GROUP_OF.get(f["provider"]) == f["group"] else " (only repeats %s)" % GROUP_NAMES.get(f["group"], f["group"])
        text = "%s%s, %s: %s evidence -> %d%% confidence" % (f["provider"], republishes, _scope_word(f["scope"], f["provider"]), LEVEL_WORDS.get(f["level"], f["level"].lower()),
                                                             round(100 * f["p"]))
        if f["factor"] < 1.0:
            text += " (reduced to x%.2f because the evidence is %s days old)" % (f["factor"], f["age_days"])
        if f["guessed"]:
            text += " (older record without details; judged from its verdict only)"
        if f["categories"]:
            text += " [%s]" % ", ".join(f["categories"][:4])
        lines.append(text)
    groups_kept = set(f["group"] for f in kept)
    for f in all_findings:
        if f["p"] > 0 and f["group"] in groups_kept and f not in kept and any(k["group"] == f["group"] for k in kept):
            main = [k for k in kept if k["group"] == f["group"]][0]
            if f["provider"] != main["provider"] or f["scope"] != main["scope"]:
                lines.append("%s (%s) reports the same underlying source (%s) as %s: counted once, not twice." % (f["provider"], _scope_word(f["scope"], f["provider"]), GROUP_NAMES.get(f["group"], f["group"]),
                                                                                                                  main["provider"]))
    if len(kept) > 1:
        lines.append("Independent sources are combined as 1 - (1 - a) x (1 - b) ...  = %d%%." % score)
    if capped:
        lines.append("Capped at %d: no source reported credible or confirmed evidence, only weak, historical or ambiguous associations." % CAP_WITHOUT_CREDIBLE)
    for word, names in (("failed", failed), ("were skipped", skipped), ("are not configured", missing)):
        if names:
            lines.append("%s %s: they add nothing to the score and do not lower it." % (", ".join(names), word if word != "failed" else "failed"))
    return lines


def compare_with_alert(score, alert_severity, weak_only=False):
    """A sentence when the score and the active alert policy tell different stories, else None. The alert rule is never changed by the score."""
    if alert_severity == "HIGH" and score < 60:
        return "The alert policy raised a HIGH alert, but the score is only %d: the policy reacts to a single strong listing, the score weighs all sources." % score
    if alert_severity == "MEDIUM" and score < 40:
        return "The alert policy raised a MEDIUM alert, but the score is only %d." % score
    if alert_severity is None and score >= 60:
        return "No alert was raised, but the score is %d (high or critical). The alert policy and the score disagree; the policy decides alerts." % score
    return None


def normalized(card, url_row=None):
    """One provider's result in one shape: provider, state, indicator type, verdict, strength, categories, facts, checked time, cache expiry, reason, attribution."""
    source = url_row if url_row is not None else card
    details = _details(source)
    state = source.get("state")
    level, _ = _level_from(source, details) if state == "CHECKED" else (None, False)
    if state == "CHECKED":
        verdict = source.get("verdict") or source.get("provider_verdict")
        if level in ("CONFIRMED", "CREDIBLE", "WEAK"):
            shown = "MALICIOUS" if verdict == "MALICIOUS" else "SUSPICIOUS"
        elif level == "CLEAN":
            shown = "CLEAN" if source["provider"] == "VirusTotal" else "NO_RECORDS"
        else:
            shown = "UNKNOWN"
    elif state in ("UNAVAILABLE", "ERROR"):
        shown = "ERROR"
    else:
        shown = "NOT_CHECKED"
    facts = dict((k, v) for k, v in details.items() if k in ("pulse_count", "recent_pulses", "recent_authors", "attributed_recent", "whitelisted", "newest_pulse_age_days", "total_scans",
                                                              "malicious_scans", "newest_malicious_age_days", "newest_scan_age_days", "online_urls", "offline_urls", "url_count",
                                                              "evidence_kind", "spamhaus_dbl", "surbl", "answer_format", "cache_duration_seconds", "search_authenticated"))
    return {"provider": source["provider"], "state": state, "indicator_type": "url" if url_row is not None else details.get("indicator_type", "domain"),
            "scope": "url" if url_row is not None else "host", "verdict": shown, "strength": details.get("strength") if state == "CHECKED" else None, "level": level,
            "categories": categories_of(details), "facts": facts, "checked_at": source.get("checked_at"), "expires_at": source.get("valid_until") or source.get("expires_at"),
            "reason": source.get("skip_reason") or source.get("error") or source.get("reason"), "attribution": GROUP_NAMES.get(_group_of(source["provider"], details), source["provider"])}
