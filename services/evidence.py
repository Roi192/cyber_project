"""Provider-neutral evidence (Phase F2): what a provider found, in one shape, and the evidence-based severity policy.

THE EVIDENCE RECORD. Every provider (today VirusTotal; later Google Safe Browsing, AlienVault OTX, urlscan.io) reports the same facts. Most of them already
have a column in reputation_evidence; the rest travel in `details_json` (this module builds and reads it):

    provider            reputation_evidence.provider          who answered
    checked_at          reputation_evidence.checked_at        lookup timestamp
    state / error       reputation_evidence.state / .error    CHECKED, UNAVAILABLE, ERROR ... and why (never the raw response, never a key)
    indicator_type      details_json["indicator_type"]        "domain" | "url" | "ip"
    classification      details_json["classification"]        UNKNOWN | CLEAN | WEAK | CREDIBLE | CONFIRMED  (the assessment, see below)
    strength            details_json["strength"]              "none" | "weak" | "moderate" | "strong"
    detections          details_json["detections"]            [{"engine", "category", "result"}] - only the sources that flagged the indicator
    counts              reputation_evidence.evidence_json     the integer counts, a fixed set (malicious, suspicious, harmless, undetected, timeout)
A provider that only gives context (for example AlienVault OTX pulses) reports classification "UNKNOWN" or "WEAK" with its context in `detections`; it can never
reach CREDIBLE on its own because the policy below only counts verdict-giving engines.

THE SEVERITY POLICY ("evidence", see assess_virustotal). It is DOCUMENTED HERE AND COMPUTED FOR EVERY LOOKUP, but it only decides alerts when SEVERITY_POLICY=evidence
is set in the environment; the default "legacy" policy (one malicious engine => SUSPICIOUS => MEDIUM alert) is unchanged until that is approved and switched on.

    Inputs: M = engines saying "malicious", S = engines saying "suspicious", E = engines that gave any answer,
            A = at least one MALICIOUS engine is on the AUTHORITATIVE list below (curated, list-based or long-established engines).
    UNKNOWN   E == 0                                                   no analysis exists / nobody analysed it          -> status UNKNOWN, no alert
    CLEAN     M == 0 and S == 0                                        no engine flagged it. NOT proof of safety         -> status SAFE,    no alert
    CONFIRMED M >= 4, or M >= 3 and A                                  several independent engines, or authoritative     -> status MALICIOUS, HIGH alert
    CREDIBLE  M >= 3, or M >= 2 and A, or M >= 1 and M+S >= 4,
              or M+S >= 5                                              corroborated by more than one engine              -> status SUSPICIOUS, MEDIUM alert
    WEAK      anything else with at least one flagged engine           a single engine, or two non-authoritative ones    -> status SUSPICIOUS, NO alert
                                                                       (kept visible with the engine names for investigation)
LIMITATIONS (also in the user documentation): engine counts are not independent (several products share a detection back end); the authoritative list is a judgement
about the current VirusTotal engine names and will need maintenance; a threshold is a trade-off, not a truth: 3 agreeing non-authoritative engines still raise a MEDIUM
alert for a legitimate site, and two non-authoritative engines alone do not; VirusTotal's counts change over time and are cached for hours; no domain is treated
specially - a popular site is judged by the same numbers as any other.
"""
import json
import re

SCHEMA_VERSION = 1
INDICATOR_DOMAIN = "domain"

UNKNOWN, CLEAN, WEAK, CREDIBLE, CONFIRMED = "UNKNOWN", "CLEAN", "WEAK", "CREDIBLE", "CONFIRMED"
LEVELS = (UNKNOWN, CLEAN, WEAK, CREDIBLE, CONFIRMED)
STRENGTH = {UNKNOWN: "none", CLEAN: "none", WEAK: "weak", CREDIBLE: "moderate", CONFIRMED: "strong"}

# thresholds of the evidence policy (see the module docstring)
CONFIRMED_MIN_MALICIOUS = 4
CONFIRMED_MIN_MALICIOUS_WITH_AUTHORITATIVE = 3
CREDIBLE_MIN_MALICIOUS = 3
CREDIBLE_MIN_MALICIOUS_WITH_AUTHORITATIVE = 2
CREDIBLE_MIN_FLAGGED_WITH_ONE_MALICIOUS = 4
CREDIBLE_MIN_FLAGGED = 5

# VirusTotal engine names that curate their own lists or are long-established (a judgement; lower-cased for the comparison)
AUTHORITATIVE_ENGINES = frozenset(name.lower() for name in (
    "Google Safebrowsing", "Kaspersky", "BitDefender", "ESET", "Sophos", "Fortinet", "Avira", "Forcepoint ThreatSeeker", "Spamhaus", "OpenPhish", "Phishtank"))

FLAGGED_CATEGORIES = ("malicious", "suspicious")
MAX_DETECTIONS = 30                  # an indicator flagged by more engines than this is already CONFIRMED; the counts keep the total
MAX_TEXT = 60
MAX_DETAILS_BYTES = 4096
_PRINTABLE = re.compile(r"[^\x20-\x7e]")


def clean_text(value, limit=MAX_TEXT):
    """A short, printable-ASCII label from provider data (never trusted: a provider's text is data, not markup)."""
    if not isinstance(value, str):
        return ""
    return _PRINTABLE.sub("?", value).strip()[:limit]


def vt_detections(last_analysis_results):
    """The engines that FLAGGED the domain, from VirusTotal's last_analysis_results: [{"engine", "category", "result"}], malicious first, then by engine name.
    Engines that found nothing are not listed (the counts say how many there were); nothing else of the response is kept."""
    found = []
    if not isinstance(last_analysis_results, dict):
        return found
    for key, entry in last_analysis_results.items():
        if not isinstance(entry, dict) or entry.get("category") not in FLAGGED_CATEGORIES:
            continue
        name = clean_text(entry.get("engine_name") or key)
        if not name:
            continue
        found.append({"engine": name, "category": entry["category"], "result": clean_text(entry.get("result"), 40)})
    found.sort(key=lambda d: (0 if d["category"] == "malicious" else 1, d["engine"].lower()))
    return found[:MAX_DETECTIONS]


def _count(counts, key):
    value = (counts or {}).get(key, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def assess_virustotal(counts, detections):
    """The evidence policy for one VirusTotal answer. Returns {"level", "strength", "status", "alert_severity", "reason", "authoritative"}.
    `status` is the display verdict (SAFE / SUSPICIOUS / MALICIOUS / UNKNOWN); `alert_severity` is "HIGH", "MEDIUM" or None."""
    malicious, suspicious = _count(counts, "malicious"), _count(counts, "suspicious")
    engines = sum(_count(counts, k) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout"))
    flagged = malicious + suspicious
    malicious_names = [d["engine"] for d in (detections or []) if d.get("category") == "malicious"]
    authoritative = any(name.lower() in AUTHORITATIVE_ENGINES for name in malicious_names)
    if engines <= 0:
        level, status, alert, reason = UNKNOWN, "UNKNOWN", None, "No security vendor has analysed this website yet."
    elif flagged == 0:
        level, status, alert = CLEAN, "SAFE", None
        reason = "No security vendor flagged this website (%d vendors checked). This is not proof that it is safe." % engines
    elif malicious >= CONFIRMED_MIN_MALICIOUS or (malicious >= CONFIRMED_MIN_MALICIOUS_WITH_AUTHORITATIVE and authoritative):
        level, status, alert = CONFIRMED, "MALICIOUS", "HIGH"
        reason = "%d of %d security vendors classified this website as malicious%s." % (malicious, engines, _names(malicious_names, authoritative))
    elif (malicious >= CREDIBLE_MIN_MALICIOUS or (malicious >= CREDIBLE_MIN_MALICIOUS_WITH_AUTHORITATIVE and authoritative)
          or (malicious >= 1 and flagged >= CREDIBLE_MIN_FLAGGED_WITH_ONE_MALICIOUS) or flagged >= CREDIBLE_MIN_FLAGGED):
        level, status, alert = CREDIBLE, "SUSPICIOUS", "MEDIUM"
        reason = "%d vendor(s) flagged this website as malicious and %d as suspicious (of %d)%s." % (malicious, suspicious, engines, _names(malicious_names, authoritative))
    else:
        level, status, alert = WEAK, "SUSPICIOUS", None
        reason = ("Weak finding, no alert: %d of %d security vendors flagged this website (%d malicious, %d suspicious)%s. A single or lightly corroborated "
                  "detection is kept for investigation." % (flagged, engines, malicious, suspicious, _names([d["engine"] for d in (detections or [])], authoritative)))
    return {"level": level, "strength": STRENGTH[level], "status": status, "alert_severity": alert, "reason": reason, "authoritative": authoritative}


def _names(names, authoritative):
    shown = ", ".join(names[:3])
    if not shown:
        return ""
    more = " and %d more" % (len(names) - 3) if len(names) > 3 else ""
    return " (%s%s%s)" % (shown, more, "; includes an authoritative engine" if authoritative else "")


# ---- list-based sources (Phase F3.1): a listing is a verdict of the list's curators, not a count of engines -------------------------------------------------------------
# Google Safe Browsing: a host on the MALWARE or SOCIAL_ENGINEERING list is a curated, high-confidence indicator -> CONFIRMED (status MALICIOUS, HIGH when the evidence policy
# decides); UNWANTED_SOFTWARE / POTENTIALLY_HARMFUL_APPLICATION -> CREDIBLE (SUSPICIOUS, MEDIUM). A match flagged CANARY (not for enforcement) or FRAME_ONLY is ignored.
GSB_THREAT_LEVELS = {"MALWARE": (CONFIRMED, "MALICIOUS", "HIGH"), "SOCIAL_ENGINEERING": (CONFIRMED, "MALICIOUS", "HIGH"),
                     "UNWANTED_SOFTWARE": (CREDIBLE, "SUSPICIOUS", "MEDIUM"), "POTENTIALLY_HARMFUL_APPLICATION": (CREDIBLE, "SUSPICIOUS", "MEDIUM")}
GSB_IGNORED_ATTRIBUTES = ("CANARY", "FRAME_ONLY")
_SEVERITY_RANK = {CLEAN: 0, UNKNOWN: 0, WEAK: 1, CREDIBLE: 2, CONFIRMED: 3}


def _assessment(level, status, alert, reason, authoritative=True):
    return {"level": level, "strength": STRENGTH[level], "status": status, "alert_severity": alert, "reason": reason, "authoritative": authoritative}


def assess_gsb(threat_types):
    """`threat_types`: the threat types of the matching, enforceable full hashes. Empty = the host is not on a list Google publishes through this API (NOT proof of safety)."""
    usable = [t for t in threat_types if t in GSB_THREAT_LEVELS]
    if not usable:
        return _assessment(CLEAN, "SAFE", None, "Not on the Google Safe Browsing lists (no match). This is not proof that the website is safe.")
    worst = max(usable, key=lambda t: _SEVERITY_RANK[GSB_THREAT_LEVELS[t][0]])
    level, status, alert = GSB_THREAT_LEVELS[worst]
    return _assessment(level, status, alert, "Google Safe Browsing lists this website (%s)." % ", ".join(sorted(set(usable))))


# ---- AlienVault OTX (Phase F3.12) -------------------------------------------------------------------------------------------------------------------------------------
# OTX is a community exchange: an analyst publishes a "pulse" (a named collection of indicators, with tags, an optional adversary / malware family and a date). A pulse that
# MENTIONS a domain is context - the domain may be the victim, a shared service, or a mistake - so OTX alone is never CONFIRMED and never raises a HIGH alert:
#   CLEAN     no pulse mentions the domain                                              NOT proof of safety
#   WEAK      pulses mention it, but only old ones, a single one, none attributing a malware family / adversary, or OTX itself lists the domain as whitelisted / a false positive
#   CREDIBLE  at least OTX_CREDIBLE_RECENT_PULSES pulses from the last OTX_RECENT_DAYS days, written by at least OTX_CREDIBLE_AUTHORS different authors, at least one of them
#             naming a malware family, an adversary or an ATT&CK technique, and the domain is not whitelisted     -> SUSPICIOUS, MEDIUM alert
OTX_RECENT_DAYS = 90
OTX_CREDIBLE_RECENT_PULSES = 3
OTX_CREDIBLE_AUTHORS = 2
OTX_MAX_PULSES_READ = 50


def assess_otx(pulse_count, recent, authors, attributed, whitelisted):
    """pulse_count: pulses OTX says mention the domain; recent: how many of those read are newer than OTX_RECENT_DAYS; authors: distinct authors among the recent ones;
    attributed: recent pulses that name a malware family / adversary / ATT&CK id; whitelisted: OTX's own validation says whitelisted or false positive."""
    if pulse_count <= 0:
        return _assessment(CLEAN, "SAFE", None, "No AlienVault OTX pulse mentions this domain. This is not proof that the website is safe.")
    if whitelisted:
        return _assessment(WEAK, "SUSPICIOUS", None, "%d OTX pulse(s) mention this domain, but OTX itself lists it as whitelisted or a known false positive; context only, not an alert." % pulse_count)
    if recent >= OTX_CREDIBLE_RECENT_PULSES and authors >= OTX_CREDIBLE_AUTHORS and attributed >= 1:
        return _assessment(CREDIBLE, "SUSPICIOUS", "MEDIUM", "%d recent OTX pulses from %d different authors mention this domain, and %d of them name a malware family or adversary."
                           % (recent, authors, attributed))
    return _assessment(WEAK, "SUSPICIOUS", None, "%d OTX pulse(s) mention this domain (%d recent). A pulse mention is community context, not proof of compromise; kept for investigation, "
                       "not an alert." % (pulse_count, recent))


# ---- urlscan.io (Phase F3.12) -----------------------------------------------------------------------------------------------------------------------------------------
# urlscan.io keeps public scans of web pages, each with a verdict. We only SEARCH existing scans whose page is on this host; we never submit one. A malicious verdict belongs to
# the page that was scanned (any page of the host), not necessarily to the one visited, so it is host-associated evidence, and it ages:
#   CLEAN     scans exist and none carries a malicious verdict                          NOT proof of safety
#   UNKNOWN   no scan exists at all (a coverage gap, not a clean result)
#   CREDIBLE  a malicious scan from the last URLSCAN_FRESH_DAYS days                    -> SUSPICIOUS, MEDIUM alert
#   WEAK      malicious scans that are all older than that (stale context)              -> SUSPICIOUS, no alert
URLSCAN_FRESH_DAYS = 30
URLSCAN_STALE_DAYS = 180


def assess_urlscan(total_scans, malicious_scans, newest_malicious_age_days):
    if total_scans <= 0:
        return dict(_assessment(UNKNOWN, "UNKNOWN", None, "urlscan.io has no scan of this website, so it could not say anything. That is a gap in coverage, not a clean result."), coverage_gap=True)
    if malicious_scans <= 0:
        return _assessment(CLEAN, "SAFE", None, "urlscan.io has %d scan(s) of this website and none has a malicious verdict. This is not proof that the website is safe." % total_scans)
    age = newest_malicious_age_days
    if age is not None and age <= URLSCAN_FRESH_DAYS:
        return _assessment(CREDIBLE, "SUSPICIOUS", "MEDIUM", "urlscan.io has %d malicious scan(s) of pages on this website, the newest %d day(s) old. The verdict belongs to the page that was scanned."
                           % (malicious_scans, age))
    stale = "old" if age is None or age > URLSCAN_STALE_DAYS else "not recent"
    return _assessment(WEAK, "SUSPICIOUS", None, "urlscan.io has %d malicious scan(s) of pages on this website, but the newest is %s (%s); stale context, kept for investigation, not an alert."
                       % (malicious_scans, "%d days old" % age if age is not None else "of unknown age", stale))


def assess_urlscan_unreadable(total_scans, newest_scan_age_days):
    """Scans exist, but this access level (no key, or a plan that may not search verdicts) cannot read their verdicts: UNKNOWN, a coverage gap - NOT clean, NOT malicious."""
    age = "newest %d day(s) old" % newest_scan_age_days if newest_scan_age_days is not None else "age unknown"
    return dict(_assessment(UNKNOWN, "UNKNOWN", None, "urlscan.io has %d scan(s) of this website (%s), but this access level cannot read their verdicts, so it says nothing about whether they "
                            "are malicious. That is a gap in coverage, not a clean result." % (total_scans, age)), coverage_gap=True)


# ---- bounded provider context (Phase F3.20) ----------------------------------------------------------------------------------------------------------------------------
# Extra facts that the providers ALREADY return in the answers this application asks for anyway (no extra request) are kept in a small `intel` section of details_json: short,
# sanitised, explicitly bounded summaries - never a raw response, never a credential, never a query string, never a personal WHOIS record. A key that is ABSENT means "not recorded"
# (a lookup made before this phase, or a field the provider did not send); an empty list or a 0 means the provider said so. Nothing here feeds a verdict, a score or an alert.
INTEL_KEY = "intel"
INTEL_LIST_LIMIT = 8


def stamp(moment, with_time=True):
    """A datetime -> 'YYYY-MM-DD HH:MM' (or just the date); None when it is not a datetime."""
    try:
        return moment.strftime("%Y-%m-%d %H:%M" if with_time else "%Y-%m-%d")
    except (AttributeError, ValueError):
        return None


def short_list(values, limit=INTEL_LIST_LIMIT, width=30):
    """Distinct, sanitised, non-empty strings in first-seen order, at most `limit` of them."""
    seen = []
    for value in values or []:
        text = clean_text(value if isinstance(value, str) else "", width)
        if text and text not in seen:
            seen.append(text)
        if len(seen) >= limit:
            break
    return seen


def _shrink_intel(document):
    """Make room: drop the tail of the longest list in `intel`; as a last resort drop `intel` itself (and say so)."""
    intel = document.get(INTEL_KEY)
    if not isinstance(intel, dict):
        return False
    lists = [(len(v), k) for k, v in intel.items() if isinstance(v, list) and v]
    if lists:
        intel[max(lists)[1]].pop()
        intel["trimmed"] = True
        return True
    del document[INTEL_KEY]
    document["intel_dropped"] = True
    return True


# ---- Phase F3.22: observation-only sources -------------------------------------------------------------------------------------------------------------------------------------
# APIVoid, MetaDefender Cloud and AbuseIPDB are STORED AND SHOWN, but their classification never decides a verdict, a score or an alert (the pipeline excludes them). The levels below
# are what each source's own answer supports, so that a human can judge them before any of them is allowed to count:
#   APIVoid        a blacklist aggregator: it repeats other lists (Google Safe Browsing, PhishTank, Spamhaus ...). CREDIBLE needs >= 3 detections AND at least 2 of them from engines that do
#                  not repeat a source we already ask; fewer is WEAK; none CLEAN.
#   MetaDefender   a multi-source reputation: assessments such as malware / phishing / malicious are detections, "trustworthy" is not proof; same thresholds. No usable sources = UNKNOWN.
#   AbuseIPDB      the reputation of an IP ADDRESS (community abuse reports), never of the website: at most WEAK, however high the score, because a shared CDN or hosting address carries
#                  reports for other tenants.
APIVOID_REPEATED_SOURCES = ("google safebrowsing", "googlesafebrowsing", "safe browsing", "virustotal")
SHARED_USAGE_TYPES = ("content delivery network", "data center/web hosting/transit", "hosting", "cdn")


def _flag_level(detections, independent):
    if detections <= 0:
        return CLEAN
    if detections >= 3 and independent >= 2:
        return CREDIBLE
    return WEAK


def assess_apivoid(detections, engines_count, detected_engines):
    """detections: how many blacklist engines flagged the host; detected_engines: their names. Returns the standard assessment (never an alert in this phase)."""
    names = [str(n).lower() for n in detected_engines or []]
    independent = sum(1 for n in names if not any(r in n for r in APIVOID_REPEATED_SOURCES))
    level = _flag_level(detections, independent)
    if engines_count is not None and engines_count <= 0:
        return dict(_assessment(UNKNOWN, "UNKNOWN", None, "APIVoid reported no blacklist engines for this host, so it could not say anything. That is a gap in coverage, not a clean result."), coverage_gap=True)
    if level == CLEAN:
        return _assessment(CLEAN, "SAFE", None, "APIVoid: no blacklist flagged this host (%s engines). This is not proof that the website is safe." % (engines_count if engines_count is not None else "?"))
    status = "SUSPICIOUS"
    return _assessment(level, status, None, "APIVoid: %d blacklist(s) flagged this host (%d independent of sources already asked); observation only, no alert." % (detections, independent))


def assess_metadefender(detected_by, sources_count, assessments):
    """detected_by: how many sources flagged the domain; sources_count: how many sources answered at all; assessments: their assessment words."""
    if not sources_count:
        return dict(_assessment(UNKNOWN, "UNKNOWN", None, "MetaDefender Cloud returned no source assessments for this domain, so it could not say anything. That is a gap in coverage, not a clean result."),
                    coverage_gap=True)
    names = [str(a).lower() for a in assessments or []]
    independent = sum(1 for n in names if n and n not in ("trustworthy", "unknown", "none", "") and not any(r in n for r in APIVOID_REPEATED_SOURCES))
    level = _flag_level(detected_by, independent if detected_by else 0)
    if level == CLEAN:
        return _assessment(CLEAN, "SAFE", None, "MetaDefender Cloud: no source flagged this domain (%d answered). This is not proof that the website is safe." % sources_count)
    return _assessment(level, "SUSPICIOUS", None, "MetaDefender Cloud: %d of %d sources flagged this domain; observation only, no alert." % (detected_by, sources_count))


def assess_abuseipdb(score, total_reports, exempt, usage_type):
    """The IP address's abuse confidence score (0-100). It describes the ADDRESS: at most WEAK, never an alert, never a verdict about the website."""
    if score is None:
        return dict(_assessment(UNKNOWN, "UNKNOWN", None, "AbuseIPDB gave no score for this address, so it could not say anything."), coverage_gap=True)
    shared = any(t in (usage_type or "").lower() for t in SHARED_USAGE_TYPES)
    if exempt or score < 25:
        return _assessment(CLEAN, "SAFE", None, "AbuseIPDB: the address has no meaningful abuse reports (score %d). This says nothing about the website itself." % score)
    return _assessment(WEAK, "SUSPICIOUS", None, "AbuseIPDB: the address has an abuse confidence score of %d (%s report(s))%s. It describes the IP address, not the website; observation only, no alert."
                       % (score, total_reports if total_reports is not None else "?", "; it looks like shared infrastructure, so the reports may concern other tenants" if shared else ""))


def build_details(indicator_type, assessment, detections, extra=None):
    """The details_json document of one evidence row (compact, bounded, no raw response). `extra`: small provider-specific facts (counts, lookup time, list-based marker)."""
    document = {"schema": SCHEMA_VERSION, "indicator_type": indicator_type, "classification": assessment["level"], "strength": assessment["strength"],
                "scope": "host", "detections": list(detections or [])}          # scope: what the answer is ABOUT - "host" (the whole domain) or "url" (one address only)
    for key, value in (extra or {}).items():
        document[key] = value
    while len(json.dumps(document)) > MAX_DETAILS_BYTES and (document["detections"] or INTEL_KEY in document):
        if INTEL_KEY in document and (not document["detections"] or len(json.dumps(document.get(INTEL_KEY))) > len(json.dumps(document["detections"]))):
            _shrink_intel(document)
        else:
            document["detections"].pop()
    return document


def read_details(text):
    """details_json back to a dict; None for a row stored before this phase (or a damaged one). Never raises."""
    if not text:
        return None
    try:
        document = json.loads(text)
    except ValueError:
        return None
    return document if isinstance(document, dict) and document.get("schema") == SCHEMA_VERSION else None
