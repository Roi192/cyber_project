"""Unified presentation of the five threat-intelligence providers (Phase F3.19).

PRESENTATION ONLY. This module reads what is ALREADY stored (the analysis cards of services/reputation.analysis_bulk and the visit_url_evidence rows) and arranges it into one
consistent shape per provider: a summary row and a detail panel. It makes no request, writes nothing, changes no verdict, level or alert, and never invents a field: a number
the adapter did not keep is shown as "not recorded", never as zero.

The five providers supply DIFFERENT KINDS of intelligence and are not equivalent malware scanners:
    VirusTotal            a vote of about ninety security engines about the domain
    Google Safe Browsing  membership of Google's curated lists of unsafe sites (hash-prefix lookup), for the host and, separately, for one exact page
    AlienVault OTX        community "pulses" (analyst reports) that mention the domain - context, not a scan
    urlscan.io            a catalogue of scans other people already ran; whether it can say anything about them depends on the access level of the key
Verdict words (the same five everywhere): MALICIOUS, SUSPICIOUS, NO_THREAT, UNKNOWN, UNAVAILABLE, NOT_CHECKED (plus NOT_CONFIGURED). An unavailable, skipped, unreadable or
not-yet-checked source is never NO_THREAT. Standard library plus services.risk; Python 3.8 compatible.
"""
from datetime import datetime

from services import risk

# The SEVEN sources in display order; the last three are observation-only (risk.OBSERVED_PROVIDERS).
ORDER = ("VirusTotal", "Google Safe Browsing", "AlienVault OTX", "urlscan.io", "APIVoid", "MetaDefender Cloud", "AbuseIPDB")
VERDICT_LABELS = {"MALICIOUS": "Malicious", "SUSPICIOUS": "Suspicious", "NO_THREAT": "No threat detected", "UNKNOWN": "Unknown", "UNAVAILABLE": "Unavailable",
                  "NOT_CHECKED": "Not checked", "NOT_CONFIGURED": "Not configured"}
STRENGTH_LABELS = {"none": "None", "weak": "Weak", "moderate": "Moderate", "strong": "Strong"}
KIND = {"VirusTotal": "Vote of about ninety security engines", "Google Safe Browsing": "Google's curated lists of unsafe sites",
        "AlienVault OTX": "Community reports (pulses) that mention the domain",
        "urlscan.io": "Scans other people already made", "APIVoid": "Blacklist aggregator (the service behind URLVoid)",
        "MetaDefender Cloud": "OPSWAT multi-source domain reputation", "AbuseIPDB": "IP reputation: abuse reports about an IP address"}
URLSCAN_SEARCH_CAP = 10000          # urlscan.io's search reports at most this many hits; a total equal to it is a lower bound
NOT_RECORDED = "not recorded"


def _number(value):
    return "{:,}".format(value) if isinstance(value, int) and not isinstance(value, bool) else NOT_RECORDED


def _age(days):
    if not isinstance(days, int) or isinstance(days, bool):
        return NOT_RECORDED
    if days <= 0:
        return "today"
    return "1 day ago" if days == 1 else "%d days ago" % days


def _duration(seconds):
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or seconds <= 0:
        return NOT_RECORDED
    seconds = int(seconds)
    if seconds < 120:
        return "%d seconds" % seconds
    if seconds < 7200:
        return "%d minutes" % round(seconds / 60.0)
    return "%d hours" % round(seconds / 3600.0)


def _yes_no(value):
    return "yes" if value is True else ("no" if value is False else NOT_RECORDED)


def verdict_of(source):
    """(verdict key, level or None, details dict) for a stored card / visit_url_evidence row. Never CLEAN for anything that did not answer."""
    state = source.get("state")
    details = risk._details(source)
    if state in ("UNAVAILABLE", "ERROR"):
        return "UNAVAILABLE", None, details
    if state == "NO_PROVIDER":
        return "NOT_CONFIGURED", None, details
    if state != "CHECKED":
        return "NOT_CHECKED", None, details
    level, _ = risk._level_from(source, details)
    if details.get("coverage_gap") or level == "UNKNOWN":
        return "UNKNOWN", level, details
    if level == "CLEAN":
        return "NO_THREAT", level, details
    said = source.get("verdict") or source.get("provider_verdict")
    if level == "CONFIRMED" or (said == "MALICIOUS" and level == "CREDIBLE"):
        return "MALICIOUS", level, details
    return "SUSPICIOUS", level, details


def _row(label, value, hint=None, lines=None, flag=None):
    return {"label": label, "value": value, "hint": hint, "lines": lines or [], "flag": flag}


METRICS_TITLE = {"VirusTotal": "Threat evidence", "Google Safe Browsing": "Threat evidence",
                 "AlienVault OTX": "Contextual intelligence: community reports", "urlscan.io": "Contextual intelligence: existing scans", "APIVoid": "Threat evidence (observation only)",
                 "MetaDefender Cloud": "Threat evidence (observation only)", "AbuseIPDB": "IP reputation (observation only)"}
SECTION_TITLES = (("threat", "Threat evidence"), ("context", "Contextual intelligence"), ("infra", "Infrastructure metadata"), ("limits", "Coverage limitations"))


def _moment(text):
    for form in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, form)
        except (ValueError, TypeError):
            continue
    return None


def _days_between(earlier, later):
    a, b = _moment(earlier), _moment(later)
    if a is None or b is None:
        return None
    return max(0, int((b - a).total_seconds() // 86400))


def _or_none(values, empty="none returned"):
    return ", ".join(values) if values else empty


def _panel_base(provider, source, scope):
    verdict, level, details = verdict_of(source)
    checked = source.get("state") == "CHECKED"
    strength = STRENGTH_LABELS.get(details.get("strength"), None) if checked else None
    if checked and strength is None:
        strength = "Not recorded (older record)"
    if verdict == "UNKNOWN":
        strength = "No information"
    elif verdict == "NO_THREAT":
        strength = "None"
    state_label = source.get("state_label") or {"CHECKED": "Answered", "UNAVAILABLE": "Provider unavailable", "ERROR": "Provider error", "NOT_CHECKED": "Not checked",
                                                "NO_EVIDENCE": "Older record", "NO_PROVIDER": "No provider configured"}.get(source.get("state"), source.get("state") or "-")
    return {"provider": provider, "kind": KIND.get(provider, ""), "state_label": state_label, "scope": scope, "scope_label": "Exact page" if scope == "url" else "Whole site (host)", "role": "observation only" if provider in risk.OBSERVED_PROVIDERS else "scoring", "retired": False, "state": source.get("state"),
            "verdict": verdict, "verdict_label": VERDICT_LABELS[verdict], "level": level, "weak": level == "WEAK", "strength": strength or "-", "headline": "", "plain": "",
            "metrics": [], "metrics_title": METRICS_TITLE.get(provider, ""), "categories": [], "flagged": [], "details_rows": [], "notes": [], "sections": {"threat": [], "context": [], "infra": [], "limits": []}, "checked_at": source.get("checked_at"),
            "valid_until": source.get("valid_until") or source.get("expires_at"), "reused": bool(source.get("reused")), "error": source.get("error"), "reason": source.get("reason"),
            "_details": details}


def _not_answered(panel, source):
    verdict = panel["verdict"]
    if verdict == "UNAVAILABLE":
        panel["headline"] = "No answer"
        panel["plain"] = ("The provider could not be reached or was busy, or it answered with an error, so %s checked nothing. This is NOT a safe result; it is tried again later." % panel["provider"])
    elif verdict == "NOT_CHECKED":
        skip = {"sensitive": "the address looks private, so it was not sent", "budget": "the request limit was used up", "time": "no time was left in this request",
                "host-listed": "the whole site is already listed"}.get(source.get("skip_reason"))
        panel["headline"] = "Not checked"
        panel["plain"] = ("%s did not check this%s. This is NOT a safe result." % (panel["provider"], " (%s)" % skip if skip else "")
                          if source.get("state") != "NO_EVIDENCE" else "This check was made before detailed results were kept, so only its verdict is known.")
    elif verdict == "NOT_CONFIGURED":
        panel["headline"] = "Not set up"
        panel["plain"] = "%s is not set up, so it was not asked. It adds nothing and does not lower anything." % panel["provider"]
    if panel["error"]:
        panel["details_rows"].append(_row("Technical detail", panel["error"]))


NOT_KEPT_YET = ("These fields were not recorded for this lookup (it was made before they were kept); they appear after the site is looked up again. Older records are never filled in "
                "retroactively.")


def _intel(panel):
    return panel["_details"].get("intel") if isinstance(panel["_details"].get("intel"), dict) else None


def _virustotal_sections(panel, card):
    intel = _intel(panel)
    s = panel["sections"]
    if intel is None:
        if card.get("counts"):
            s["limits"].append(NOT_KEPT_YET)
        return
    if "categories" in intel:
        s["context"].append(_row("Website categories", _or_none(intel["categories"]), "how VirusTotal's vendors categorise the site; context, not a verdict"))
    if "reputation" in intel:
        s["context"].append(_row("Community reputation", intel["reputation"], "a community score, not a detection; it can be negative for a safe site and zero for a harmful one"))
    if "last_analysis" in intel:
        days = _days_between(intel["last_analysis"], card.get("checked_at"))
        s["context"].append(_row("Last analysed by VirusTotal", intel["last_analysis"] + " UTC", ("%d day(s) before this lookup" % days) if days is not None else None))
    if "registrar" in intel:
        s["infra"].append(_row("Registrar", intel["registrar"], "who registered the domain; not evidence of malice"))
    if "created" in intel:
        days = _days_between(intel["created"], card.get("checked_at"))
        s["infra"].append(_row("Domain created", intel["created"], ("about %.1f year(s) old" % (days / 365.25)) if days is not None else None))
    if not any(k in intel for k in ("categories", "reputation", "last_analysis", "registrar", "created")):
        s["limits"].append("VirusTotal's answer carried none of the optional context fields for this site.")
    s["limits"].append("WHOIS contact records are never stored: only the registrar and the creation date are kept. Domain age and a registrar are not proof of anything on their own.")


def _otx_sections(panel, card):
    intel, d = _intel(panel), panel["_details"]
    s = panel["sections"]
    if d.get("malware_families"):
        s["context"].append(_row("Malware families named by pulses", ", ".join(d["malware_families"]), "only families a pulse explicitly names; a tag or title is never promoted to a family"))
    if intel is None:
        if d.get("pulse_count"):
            s["limits"].append(NOT_KEPT_YET)
        return
    pulses = intel.get("pulses") or []
    items = []
    for x in pulses:
        bits = [b for b in (x.get("author"), x.get("date"), ("TLP:" + x["tlp"]) if x.get("tlp") else None, ("family: " + ", ".join(x["families"])) if x.get("families") else None) if b]
        items.append("%s - %s" % (x.get("name"), ", ".join(bits) if bits else "no details"))
    if pulses or d.get("pulse_count") == 0:
        s["context"].append(_row("Newest pulses", "%d shown of %s" % (len(pulses), _number(d.get("pulse_count"))), lines=items or None))
    if intel.get("authors"):
        s["context"].append(_row("Distinct authors (pulses read)", ", ".join(intel["authors"])))
    if intel.get("newest"):
        s["context"].append(_row("Pulse dates", "%s to %s" % (intel.get("oldest"), intel["newest"])))
    if intel.get("tlp"):
        s["context"].append(_row("TLP mix", ", ".join("%s %d" % kv for kv in intel["tlp"].items()), "how widely the pulse authors say it may be shared; not a severity"))
    s["limits"].append("Only the five newest pulses are summarised, and only name, author, date, TLP and explicitly named families: descriptions, references and indicators are not kept.")


def _urlscan_sections(panel, card):
    intel, d = _intel(panel), panel["_details"]
    s = panel["sections"]
    if intel is None:
        if d.get("total_scans"):
            s["limits"].append(NOT_KEPT_YET)
        return
    s["context"].append(_row("Scans read for this summary", _number(intel.get("scans_read")), "the newest scans only"))
    if intel.get("newest_scan"):
        s["context"].append(_row("Newest scan", intel["newest_scan"] + " UTC"))
        s["context"].append(_row("Oldest of the scans read", intel.get("oldest_scan_read", NOT_RECORDED) + " UTC"))
    s["infra"].append(_row("Server IP addresses", _or_none(intel.get("ips"), "not provided"), "of the scanned pages"))
    s["infra"].append(_row("Countries", _or_none(intel.get("countries"), "not provided")))
    s["infra"].append(_row("ASNs", _or_none(intel.get("asns"), "not provided"), "the network that announces the address"))
    s["infra"].append(_row("Server software", _or_none(intel.get("servers"), "not provided")))
    s["limits"].append("This describes the servers of the pages that were scanned, not this visit. An address, a country, a network or a server product is never evidence of malicious "
                       "activity by itself.")


def _virustotal(panel, card):
    counts = card.get("counts") or {}
    details = panel["_details"]
    if not counts:
        panel["headline"] = "No engine results recorded"
        panel["plain"] = "VirusTotal has no analysis of this website yet, or the result was kept without its engine counts."
        return
    malicious, suspicious = counts.get("malicious", 0), counts.get("suspicious", 0)
    total = card.get("total") or sum(v for v in counts.values() if isinstance(v, int))
    panel["headline"] = "%d of %d engines flag it" % (malicious + suspicious, total) if total else "No engines"
    panel["metrics"] = [_row("Malicious", malicious), _row("Suspicious", suspicious), _row("Harmless", counts.get("harmless", 0)), _row("Undetected", counts.get("undetected", 0))]
    if counts.get("timeout"):
        panel["metrics"].append(_row("Timed out", counts.get("timeout")))
    panel["metrics"].append(_row("Total engines", total))
    flagged = [d for d in (details.get("detections") or []) if isinstance(d, dict)]
    panel["flagged"] = [{"engine": d.get("engine"), "category": d.get("category"), "result": d.get("result")} for d in flagged]
    panel["categories"] = sorted(set(d.get("result") for d in flagged if d.get("result")))[:6]
    if malicious + suspicious == 0:
        panel["plain"] = "None of the %d security engines flagged this website. That means nothing was reported, not that the website is proven safe." % total
    elif panel["flagged"]:
        names = ", ".join(d["engine"] for d in panel["flagged"][:3])
        panel["plain"] = "%d of %d security engines flagged this website (%s%s)." % (malicious + suspicious, total, names, " and others" if len(panel["flagged"]) > 3 else "")
        if panel["weak"]:
            panel["plain"] += " A single or lightly corroborated detection is weak evidence; it is kept for investigation."
    else:
        panel["plain"] = "%d of %d security engines flagged this website, but the engine names were not recorded for this older result." % (malicious + suspicious, total)
    panel["notes"].append("Engine counts are not independent: several products share a detection back end. VirusTotal's counts change over time.")


def _google(panel, source):
    details = panel["_details"]
    types = [d.get("result") for d in (details.get("detections") or []) if isinstance(d, dict) and d.get("result")]
    panel["categories"] = sorted(set(types))
    where = "this exact page" if panel["scope"] == "url" else "the site's address (host level)"
    if panel["verdict"] == "NO_THREAT":
        panel["headline"] = "Not on Google's lists"
        panel["plain"] = "Google Safe Browsing has no listing for %s. A missing listing is not proof that it is safe." % where
    elif panel["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
        panel["headline"] = "Listed: " + ", ".join(panel["categories"]) if panel["categories"] else "Listed"
        panel["plain"] = "Google Safe Browsing lists %s as unsafe (%s)." % (where, ", ".join(panel["categories"]) or "threat type not recorded")
    elif panel["verdict"] == "UNKNOWN":
        panel["headline"] = "Could not be interpreted"
        panel["plain"] = "Google returned something this client cannot interpret, so it is not treated as safe."
    panel["metrics"] = [_row("Threat types", ", ".join(panel["categories"]) or "none"), _row("Prefixes sent", _number(details.get("prefixes_sent"))),
                        _row("Address forms checked", _number(details.get("expressions_checked")))]
    panel["details_rows"] = [_row("Answer format", details.get("answer_format") or NOT_RECORDED), _row("Answer", details.get("answer_form") or NOT_RECORDED),
                             _row("Google's cache duration", _duration(details.get("cache_duration_seconds")),
                                  None if details.get("cache_duration_given") else "Google gave none; the conservative default was used")]
    panel["notes"].append("Only the first 4 bytes of each hashed address leave this computer; Google never sees the website name or address.")
    if panel["scope"] == "host":
        panel["notes"].append("This is the host-level answer. The exact page is checked separately (below) and a page finding never changes the site's verdict.")


def _otx(panel, card):
    d = panel["_details"]
    count = d.get("pulse_count")
    panel["categories"] = sorted(set((d.get("malware_families") or []) + (d.get("adversaries") or [])))[:6]
    if count == 0 or count is None and panel["verdict"] == "NO_THREAT":
        panel["headline"] = "No pulses mention it"
        panel["plain"] = "No AlienVault OTX pulse mentions this domain." + (" OTX also lists it as whitelisted." if d.get("whitelisted") else "") + " That is not proof that the website is safe."
    else:
        panel["headline"] = "%s pulse(s), %s recent" % (_number(count), _number(d.get("recent_pulses")))
        panel["plain"] = ("Community pulses mention this domain. A pulse is a community report that mentions the site, written by an analyst among other indicators; it may describe the domain as a victim, a "
                          "shared service or a mistake, so a mention is context, not proof that the website is malicious or that a computer is compromised.")
        if d.get("whitelisted"):
            panel["plain"] += " OTX itself lists this domain as whitelisted / a known false positive."
        elif panel["verdict"] == "SUSPICIOUS" and panel["level"] == "CREDIBLE":
            panel["plain"] += " Several recent pulses from different authors name a malware family or adversary, which is why this is rated moderate."
    pulses = [x.get("result") for x in (d.get("detections") or []) if isinstance(x, dict) and x.get("engine") == "OTX pulse"]
    panel["metrics"] = [_row("Pulses mentioning it", _number(count)), _row("Recent (90 days)", _number(d.get("recent_pulses"))), _row("Distinct recent authors", _number(d.get("recent_authors"))),
                        _row("Naming a family / adversary", _number(d.get("attributed_recent")))]
    panel["details_rows"] = [_row("Whitelisted / false positive", _yes_no(d.get("whitelisted"))), _row("Newest pulse", _age(d.get("newest_pulse_age_days")) if d.get("newest_pulse_age_days") is not None else "-"),
                             _row("Pulses read", _number(d.get("pulses_read"))), _row("Malware families named", ", ".join(d.get("malware_families") or []) or "none"),
                             _row("Adversaries named", ", ".join(d.get("adversaries") or []) or "none"), _row("Tags", ", ".join(d.get("tags") or []) or "none"),
                             _row("Pulses shown (names only)", "; ".join(pulses) if pulses else "none recorded")]
    if d.get("derived_from"):
        panel["notes"].append("These pulses repeat %s, so they are not counted as a second independent source." % ", ".join(d["derived_from"]))
    panel["notes"].append("Pulse details beyond these counts are not stored. OTX can be slow or unresponsive for very heavily referenced domains; that shows as Unavailable, not as clean.")


def _urlscan(panel, card):
    d = panel["_details"]
    total = d.get("total_scans")
    capped = isinstance(total, int) and total >= URLSCAN_SEARCH_CAP
    shown_total = ("at least " + _number(total)) if capped else _number(total)
    newest = d.get("newest_scan_age_days")
    readable = d.get("verdicts_readable")
    panel["metrics"] = [_row("Existing scans", shown_total), _row("Latest scan", _age(newest) if newest is not None else "-"),
                        _row("Verdicts readable", _yes_no(readable) if readable is not None else "n/a")]
    if readable is True:
        panel["metrics"].append(_row("Scans with a malicious verdict", _number(d.get("malicious_scans"))))
    panel["categories"] = sorted(set(d.get("categories") or []))[:5]
    if not total:
        panel["headline"] = "No scan exists"
        panel["plain"] = "No scan exists for this site: that is a gap in coverage, not a clean result. urlscan.io can say nothing about it."
    elif readable is False:
        panel["headline"] = "%s scans exist; verdicts not readable" % shown_total
        why = ("this API key's plan does not allow searching scan verdicts" if d.get("search_authenticated") else "no API key is set, and verdicts need a key on a plan that allows it")
        panel["plain"] = ("urlscan.io has %s scan(s) of this website, the latest %s. This setup cannot read their verdicts (%s), so it says nothing about whether they are malicious. "
                          "That is a gap in coverage, not a clean result and not a threat." % (shown_total, _age(newest), why))
    elif d.get("malicious_scans"):
        panel["headline"] = "%s malicious scan(s) of %s" % (_number(d.get("malicious_scans")), shown_total)
        panel["plain"] = "urlscan.io has malicious-verdict scans of pages on this website. A verdict belongs to the page that was scanned, not necessarily to the one you visited."
    else:
        panel["headline"] = "%s scans, none malicious" % shown_total
        panel["plain"] = "urlscan.io has existing scans of this website and none has a malicious verdict. That is not proof that the website is safe."
    panel["details_rows"] = [_row("Search authenticated", _yes_no(d.get("search_authenticated"))), _row("Scans submitted by this application", "none, ever")]
    if capped:
        panel["notes"].append("urlscan.io reports at most %s hits for a search, so the real number may be larger." % _number(URLSCAN_SEARCH_CAP))
    panel["notes"].append("This application never submits a scan: it only searches scans that already exist, so nothing you browse is published to urlscan.io. "
                          "Scan metadata (page IP, server, country, screenshots) is available from urlscan.io but is not read by this application.")


def _observation_note(panel):
    panel["notes"].append("Observation only: this result is stored and shown, but it does not change the verdict, the risk score or any alert (see docs/PROVIDERS.md for what would have to be true first).")


def _apivoid(panel, card):
    d = panel["_details"]
    detections, engines = d.get("blacklist_detections"), d.get("engines_count")
    shown = [x for x in (d.get("detections") or []) if isinstance(x, dict)]
    panel["flagged"] = [{"engine": x.get("engine"), "category": x.get("category"), "result": x.get("result")} for x in shown]
    panel["categories"] = list(d.get("categories") or [])
    if panel["verdict"] == "UNKNOWN":
        panel["headline"] = "No blacklist engines reported"
        panel["plain"] = "APIVoid reported no blacklist engines for this host, so it can say nothing. That is a gap in coverage, not a clean result."
    elif not detections:
        panel["headline"] = "0 of %s blacklists flag it" % (_number(engines) if engines is not None else "?")
        panel["plain"] = "None of the blacklist engines APIVoid checked flagged this host. That means nothing was reported, not that the website is proven safe."
    else:
        panel["headline"] = "%s of %s blacklists flag it" % (_number(detections), _number(engines) if engines is not None else "?")
        panel["plain"] = ("%s blacklist engine(s) flagged this host (%s). APIVoid aggregates many lists, several of which repeat sources that are asked separately, so this is "
                          "context to read, not an independent confirmation." % (_number(detections), ", ".join(x["engine"] for x in panel["flagged"][:3]) or "names not recorded"))
    panel["metrics"] = [_row("Blacklists flagging it", _number(detections)), _row("Engines checked", _number(engines)),
                        _row("APIVoid risk score", ("%d / 100" % d["risk_score"]) if isinstance(d.get("risk_score"), int) else NOT_RECORDED, "APIVoid's own number, not ours")]
    s, intel = panel["sections"], _intel(panel) or {}
    if d.get("derived_from"):
        s["context"].append(_row("Repeats sources asked separately", ", ".join({"google": "Google Safe Browsing", "virustotal": "VirusTotal"}.get(g, g) for g in d["derived_from"]),
                                 "counted once, never as an extra confirmation"))
    if d.get("categories"):
        s["context"].append(_row("Categories / flags", ", ".join(d["categories"]), "properties APIVoid reports about the domain; not verdicts"))
    if intel.get("created"):
        s["infra"].append(_row("Domain created", intel["created"], ("%s day(s) old" % intel["age_days"]) if "age_days" in intel else None))
    for key, label in (("ip", "Server IP address"), ("country", "Server country"), ("isp", "Hosting provider (ISP)")):
        if intel.get(key):
            s["infra"].append(_row(label, intel[key]))
    s["limits"].append("APIVoid aggregates many blacklists; engines that repeat Google Safe Browsing or VirusTotal are recorded as repeats and must not be counted twice.")
    s["limits"].append("The answer format follows APIVoid's published documentation and has not yet been confirmed against the live service.")
    _observation_note(panel)


def _metadefender(panel, card):
    d = panel["_details"]
    flagged, answered = d.get("detected_by"), d.get("sources_count")
    panel["flagged"] = [{"engine": x.get("engine"), "category": x.get("category"), "result": x.get("result")} for x in (d.get("detections") or []) if isinstance(x, dict)]
    panel["categories"] = list(d.get("categories") or [])
    if panel["verdict"] == "UNKNOWN":
        panel["headline"] = "No source assessments"
        panel["plain"] = "MetaDefender Cloud returned no source assessments for this domain, so it can say nothing. That is a gap in coverage, not a clean result."
    elif not flagged:
        panel["headline"] = "0 of %s sources flag it" % _number(answered)
        panel["plain"] = "None of the %s sources that assessed this domain flagged it. 'Trustworthy' is an assessment, not a guarantee." % _number(answered)
    else:
        panel["headline"] = "%s of %s sources flag it" % (_number(flagged), _number(answered))
        panel["plain"] = "%s source(s) flagged this domain (%s). MetaDefender Cloud lists what each source assessed; it does not always give one overall verdict." % (_number(flagged), ", ".join(panel["categories"]) or "assessment not recorded")
    panel["metrics"] = [_row("Sources flagging it", _number(flagged)), _row("Sources that assessed it", _number(answered))]
    if d.get("sources_failed"):
        panel["metrics"].append(_row("Sources that failed to scan", _number(d.get("sources_failed")), "no opinion, not a clean result"))
    s, intel = panel["sections"], _intel(panel) or {}
    if d.get("site_categories"):
        s["context"].append(_row("Website categories (vendors)", ", ".join(d["site_categories"]), "how the sources classify the site; context, never a verdict"))
    if intel.get("newest_detection"):
        s["context"].append(_row("Latest confirmed detection", intel["newest_detection"], "the newest date a flagging source confirmed malicious activity"))
    quota = d.get("quota") or {}
    if quota:
        parts = []
        if "used" in quota and "limit" in quota:
            parts.append("%d of %d used" % (quota["used"], quota["limit"]))
        elif "remaining" in quota:
            parts.append("%d remaining" % quota["remaining"])
        if "reset_in_seconds" in quota:
            parts.append("window resets in %d min" % max(1, quota["reset_in_seconds"] // 60))
        if parts:
            s["context"].append(_row("Quota reported by MetaDefender", ", ".join(parts), "for this API key"))
    if d.get("derived_from"):
        s["context"].append(_row("Repeats sources asked separately", ", ".join({"google": "Google Safe Browsing", "virustotal": "VirusTotal"}.get(g, g) for g in d["derived_from"]), "counted once"))
    if intel.get("newest_update"):
        s["context"].append(_row("Newest source update", intel["newest_update"]))
    if intel.get("scan_time"):
        s["context"].append(_row("Lookup time reported by MetaDefender", intel["scan_time"]))
    if intel.get("country"):
        s["infra"].append(_row("Country", intel["country"]))
    s["limits"].append("An answer need not contain any malicious verdict, and a domain without assessments is a coverage gap, never clean.")
    s["limits"].append("The answer format follows OPSWAT's published documentation and has not yet been confirmed against the live service.")
    _observation_note(panel)


def _abuseipdb(panel, card):
    d = panel["_details"]
    panel["scope"], panel["scope_label"] = "ip", "IP address (IP reputation)"
    ip, score = d.get("ip"), d.get("abuse_score")
    if panel["verdict"] == "UNKNOWN" or not ip:
        panel["headline"] = "No public IP address to check"
        panel["plain"] = ("The website name did not resolve to a public IP address, so there is nothing to ask AbuseIPDB about. That is a gap in coverage, not a clean result "
                          "(private and reserved addresses are never sent to a third party).")
    else:
        panel["headline"] = "IP %s: abuse score %s / 100" % (ip, score)
        shared = " It looks like shared infrastructure (a CDN or hosting address), so the reports may concern other tenants." if d.get("shared_infrastructure") else ""
        panel["plain"] = ("This is IP reputation, not website reputation. The address %s that this website resolves to has an abuse confidence score of %s / 100 (%s report(s)).%s "
                          "It never makes the website malicious on its own." % (ip, score, _number(d.get("total_reports")), shared))
    panel["metrics"] = [_row("Abuse confidence score", ("%d / 100" % score) if isinstance(score, int) else NOT_RECORDED), _row("Total reports (90 days)", _number(d.get("total_reports"))),
                        _row("Distinct reporters", _number(d.get("distinct_reporters"))), _row("Last reported", d.get("last_reported") or "never / not recorded")]
    s, intel = panel["sections"], _intel(panel) or {}
    s["context"].append(_row("Whitelisted by AbuseIPDB", _yes_no(d.get("whitelisted")) if "whitelisted" in d else NOT_RECORDED))
    s["context"].append(_row("Tor exit node", _yes_no(d.get("is_tor")) if "is_tor" in d else NOT_RECORDED))
    s["context"].append(_row("Shared infrastructure", _yes_no(d.get("shared_infrastructure")) if "shared_infrastructure" in d else NOT_RECORDED, "a CDN or hosting address carries reports about other tenants"))
    for key, label in (("ip", "IP address"), ("isp", "ISP"), ("usage_type", "Usage type"), ("country", "Country")):
        if intel.get(key):
            s["infra"].append(_row(label, intel[key]))
    s["limits"].append("AbuseIPDB describes an IP ADDRESS. Several websites can share one address, so a high score never proves that this website is malicious and is never used as a verdict about it.")
    s["limits"].append("Only a validated public address is ever sent. The website name is resolved on this computer's own resolver.")
    _observation_note(panel)


BUILDERS = {"VirusTotal": _virustotal, "Google Safe Browsing": _google, "AlienVault OTX": _otx, "urlscan.io": _urlscan, "APIVoid": _apivoid,
            "MetaDefender Cloud": _metadefender, "AbuseIPDB": _abuseipdb}


def build(provider, source, scope="host", page_path=None):
    """One provider's panel from a stored analysis card (scope host) or a visit_url_evidence row (scope url). `page_path`: the visited page's path when it is safe to show."""
    panel = _panel_base(provider, source, scope)
    if panel["state"] == "CHECKED":
        BUILDERS[provider](panel, source)
        if scope == "host":
            {"VirusTotal": lambda: _virustotal_sections(panel, source), "AlienVault OTX": lambda: _otx_sections(panel, source),
             "urlscan.io": lambda: _urlscan_sections(panel, source)}.get(provider, lambda: None)()
    else:
        _not_answered(panel, source)
    panel.pop("_details", None)
    return panel


def build_all(cards, url_rows=(), configured=None, page_path=None):
    """The five panels in a fixed order. `cards`: analysis["providers"]; `url_rows`: the visit's address-level rows (only Google writes them today).
    A provider with no card is NOT_CONFIGURED when it is not switched on, else NOT_CHECKED (skipped): never clean.
    """
    by_name = dict((c["provider"], c) for c in cards or [])
    url_by_name = dict((r["provider"], r) for r in (url_rows or []))
    out = []
    order = list(ORDER)
    for name in order:
        card = by_name.get(name)
        if card is None:
            state = "NOT_CHECKED" if configured is not None and name in configured else "NO_PROVIDER"
            card = {"provider": name, "state": state, "details": None}
        panel = build(name, card, page_path=page_path)
        if name in url_by_name:
            panel["page"] = build(name, url_by_name[name], "url")
        out.append(panel)
    return out
