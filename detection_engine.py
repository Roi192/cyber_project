# ==================================================
# STAGE 25C: AUTONOMOUS DETECTION & RISK ENGINE
# ==================================================
#
# Reads evidence that ALREADY EXISTS (Legacy IOC, VT/AbuseIPDB
# reputation, ThreatFox, Local Feed, Behavioral anomaly, 25A process
# telemetry, 25B process<->network correlation) and produces
# EXPLAINABLE Detection records: rule -> evidence -> risk contribution
# -> severity -> recommended action. It NEVER performs a new external
# lookup (see each rule function's docstring - every one is fed
# already-computed evidence by the caller), NEVER changes the
# Legacy risk_score/severity/decision formula (threat_intelligence.py
# is untouched), and NEVER performs isolate/block/response - only
# RECOMMENDS an action as text (ENABLE_RESPONSE_ACTIONS stays
# irrelevant to this module entirely; nothing here ever reads it or
# acts on it).
#
# EVIDENCE != VERDICT (Stage 25C instruction #4): a single weak signal
# (e.g. one VirusTotal engine, or a destination resolving to a
# temp-folder executable with no other evidence) never alone produces
# a HIGH/CRITICAL detection. Confidence and risk_contribution are
# always derived from how MANY INDEPENDENT evidence sources agree,
# never invented.
#
# NO DOUBLE COUNTING (instruction #5): every rule's contribution is
# tagged with an `evidence_key` - (evidence_source, indicator_value).
# When aggregating the detections fired for ONE event, a second rule
# citing the SAME evidence_key is still recorded (for explainability -
# it is genuinely a different rule's logic) but contributes ZERO
# additional points to the aggregate risk - see _aggregate_risk().
# ==================================================

import hashlib
import json
import re
from datetime import datetime, timedelta

import db_config
import threat_intelligence
import suricata_classification
import correlation_key
import endpoint_identity

from web_monitoring import (
    get_db_connection,
    create_security_alert,
    create_incident_from_alert,
    add_alert_event,
    write_log,
)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

# Same dedup philosophy as web_monitoring.DEDUP_ALERT_WINDOW_MINUTES
# (30 min) - a detection fingerprint repeating within this window
# updates the existing row (occurrence_count/last_seen_at) instead of
# inserting a new one. Deliberately the SAME number as the existing
# alert dedup window, not a new, unexplained constant.
DETECTION_DEDUP_WINDOW_MINUTES = 30

# A detection not re-observed for this long is considered over -
# background sweep (detection_reconciliation, called from
# web_event_worker.py) moves it ACTIVE -> RESOLVED. Mirrors the
# 25B correlation aging pattern (24h) - "gone quiet" is itself
# meaningful evidence that whatever was happening has stopped.
DETECTION_RESOLVE_AFTER_HOURS = 24

RULE_CATEGORY_MALICIOUS_DESTINATION = "MALICIOUS_DESTINATION"
RULE_CATEGORY_LOCAL_IOC = "LOCAL_IOC_MATCH"
RULE_CATEGORY_SUSPICIOUS_PROCESS_DESTINATION = "SUSPICIOUS_PROCESS_AND_DESTINATION"
RULE_CATEGORY_SUSPICIOUS_COMMAND_LINE = "SUSPICIOUS_COMMAND_LINE"
RULE_CATEGORY_UNUSUAL_EXECUTABLE_LOCATION = "UNUSUAL_EXECUTABLE_LOCATION"
RULE_CATEGORY_BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY_SIGNAL"
RULE_CATEGORY_SURICATA_QUALIFIED = "SURICATA_QUALIFIED_SECURITY_EVIDENCE"
# Stage 25F Phase 5 - Rule H's category (the ported Legacy-only signal
# - see rule_external_reputation_signal() below).
RULE_CATEGORY_EXTERNAL_REPUTATION = "EXTERNAL_REPUTATION_SIGNAL"

# Stage 25E: how far around this event's own time to look for a
# Suricata detection against the SAME destination - same bounded,
# fixed-window philosophy as every other correlation window in this
# project (25B's CORRELATION_CLOCK_SKEW_TOLERANCE_SECONDS, this
# module's own DETECTION_DEDUP_WINDOW_MINUTES).
SURICATA_EVIDENCE_WINDOW_SECONDS = 300

STATUS_NEW = "NEW"
STATUS_ACTIVE = "ACTIVE"
STATUS_RESOLVED = "RESOLVED"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"

ACTION_MONITOR = "MONITOR"
ACTION_BLOCK_DESTINATION = "BLOCK_DESTINATION"
ACTION_SCAN_ENDPOINT = "SCAN_ENDPOINT"
ACTION_ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
ACTION_REVIEW_PROCESS = "REVIEW_PROCESS"


# --------------------------------------------------
# SCHEMA (additive only - two new tables, nothing existing touched)
# --------------------------------------------------

def init_detection_engine_db():

    conn = get_db_connection()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                category TEXT NOT NULL,
                endpoint_uid TEXT,
                endpoint_ip TEXT,
                process_instance_id TEXT,
                web_event_id INTEGER,
                severity TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                risk_contribution INTEGER NOT NULL,
                detection_risk_score INTEGER NOT NULL,
                explanation TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                recommended_action_explanation TEXT NOT NULL,
                security_alert_id INTEGER,
                status TEXT NOT NULL DEFAULT 'NEW',
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                resolved_at TEXT,
                correlation_key TEXT,
                UNIQUE(fingerprint)
            )
        """)

        # Stage 25F Phase 2/4: guarded upgrade for a database created
        # BEFORE correlation_key existed in the CREATE TABLE above (the
        # live cybersec.db was migrated once, directly, by the Phase 2
        # one-off script - this closes the same gap for any OTHER
        # existing database, matching the exact column this project's
        # own web_events additive-migration pattern already uses
        # elsewhere in web_monitoring.py).
        existing_columns = [row["name"] for row in conn.execute("PRAGMA table_info(detections)").fetchall()]

        if "correlation_key" not in existing_columns:
            conn.execute("ALTER TABLE detections ADD COLUMN correlation_key TEXT")

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_detections_correlation_key
            ON detections(correlation_key, last_seen_at)
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER NOT NULL,
                evidence_source TEXT NOT NULL,
                evidence_type TEXT,
                indicator_value TEXT,
                status TEXT,
                detail_text TEXT,
                FOREIGN KEY (detection_id) REFERENCES detections(id)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_detections_status_lastseen
            ON detections(status, last_seen_at)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_detections_endpoint
            ON detections(endpoint_uid, created_at)
            WHERE endpoint_uid IS NOT NULL
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_detections_process_instance
            ON detections(process_instance_id)
            WHERE process_instance_id IS NOT NULL
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_detection_evidence_detection
            ON detection_evidence(detection_id)
        """)

        conn.commit()

    finally:
        conn.close()


# --------------------------------------------------
# FINGERPRINT (dedup identity - instruction #8)
# --------------------------------------------------

def compute_fingerprint(rule_id, endpoint_uid, process_instance_id, destination_key):

    raw = "|".join([
        rule_id or "",
        endpoint_uid or "",
        process_instance_id or "",
        destination_key or ""
    ])

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------
# SUSPICIOUS COMMAND-LINE PATTERNS (rule D) - a SMALL, fixed, EXPLAINABLE
# list, never "PowerShell = malicious". Each pattern names the SPECIFIC
# technique it is evidence of. Matched against the ALREADY-REDACTED
# command_line_text (25A) - a redacted secret can never be un-redacted
# or examined by these patterns, since they only ever see "***REDACTED***"
# in place of any real secret value.
# --------------------------------------------------

SUSPICIOUS_COMMAND_LINE_PATTERNS = (
    (
        re.compile(r"-enc(odedcommand)?\b", re.IGNORECASE),
        "PowerShell -EncodedCommand (base64-encoded script body, hides the actual command from casual inspection)"
    ),
    (
        re.compile(r"-(w|windowstyle)\s+hidden", re.IGNORECASE),
        "Hidden window (-WindowStyle Hidden) - process intentionally runs without a visible console"
    ),
    (
        re.compile(r"-(ep|executionpolicy)\s+bypass", re.IGNORECASE),
        "PowerShell execution policy explicitly bypassed (-ExecutionPolicy Bypass)"
    ),
    (
        re.compile(r"(invoke-expression|\biex\b)", re.IGNORECASE),
        "Invoke-Expression/IEX (executes a dynamically-built string as code)"
    ),
    (
        re.compile(r"downloadstring|downloadfile|net\.webclient", re.IGNORECASE),
        "Scripted download cmdlet (Net.WebClient/DownloadString/DownloadFile)"
    ),
    (
        re.compile(r"certutil.*-decode|certutil.*-urlcache", re.IGNORECASE),
        "certutil used for decoding/downloading (a well-known LOLBin technique, not its documented certificate purpose)"
    ),
    (
        re.compile(r"bitsadmin.*\/transfer", re.IGNORECASE),
        "bitsadmin /transfer (background download via the BITS LOLBin technique)"
    ),
    (
        re.compile(r"mshta\b", re.IGNORECASE),
        "mshta.exe invocation (can execute remote HTA/script content)"
    ),
    (
        re.compile(r"rundll32.*javascript:", re.IGNORECASE),
        "rundll32 with an inline javascript: payload"
    ),
)


def _match_suspicious_command_line(command_line_text):

    if not command_line_text:
        return []

    findings = []

    for pattern, explanation in SUSPICIOUS_COMMAND_LINE_PATTERNS:
        if pattern.search(command_line_text):
            findings.append(explanation)

    return findings


# --------------------------------------------------
# UNUSUAL EXECUTABLE LOCATION (rule E) - a SMALL, fixed list of
# user-writable/temporary path fragments. Case-insensitive substring
# match on the normalized path - never a guess about what the file
# IS, only about WHERE it is running from.
# --------------------------------------------------

UNUSUAL_LOCATION_FRAGMENTS = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\programdata\\",
)


def _is_unusual_location(process_path):

    if not process_path:
        return False

    normalized = process_path.lower()

    return any(fragment in normalized for fragment in UNUSUAL_LOCATION_FRAGMENTS)


# --------------------------------------------------
# RULE FUNCTIONS
# --------------------------------------------------
# Each takes the SAME `ctx` dict (built by the caller from evidence it
# ALREADY computed - see build_context_for_web_event() /
# build_context_for_browser_event() below) and returns a list of
# finding dicts:
#   {rule_id, rule_name, category, risk_points, confidence,
#    explanation, evidence:[{source, type, indicator, status, detail}]}
# An empty list means the rule did not fire. A rule NEVER raises -
# any internal error is the caller's problem to isolate (same
# try/except-per-rule discipline as every other evidence block in
# web_event_worker.py).

def rule_confirmed_malicious_destination(ctx):
    """
    A. Confirmed malicious destination - the process/network event's
    destination has a REAL MATCH from existing TI (ThreatFox and/or
    Local Feed) - not a numeric score, an actual confirmed indicator
    match. Each distinct matching source is its own evidence item;
    TWO independent sources corroborating the SAME destination raises
    confidence further (instruction #4's example) without inventing
    anything.
    """

    findings = []
    evidence = []

    for tf_entry in ctx.get("threatfox_evidence") or []:
        if tf_entry.get("lookup_status") == "MATCH":
            evidence.append({
                "source": "THREATFOX",
                "type": tf_entry.get("indicator_type"),
                "indicator": tf_entry.get("indicator_value"),
                "status": "MATCH",
                "detail": tf_entry.get("summary") or "ThreatFox confirmed match."
            })

    for lf_entry in ctx.get("local_feed_results") or []:
        for match_row in lf_entry.get("matches") or []:
            evidence.append({
                "source": "LOCAL_FEED",
                "type": match_row.get("indicator_type"),
                "indicator": match_row.get("normalized_value"),
                "status": "MATCH",
                "detail": f"Local Feed ({lf_entry.get('provider')}) confirmed match."
            })

    if not evidence:
        return findings

    independent_sources = {item["source"] for item in evidence}
    confidence = 70 if len(independent_sources) == 1 else 90

    # A CONFIRMED indicator match (ThreatFox/Local Feed are curated
    # malicious-indicator feeds, not a probabilistic reputation score)
    # is treated as CRITICAL-tier evidence even from a single source -
    # score_ioc_severity("CRITICAL")=40 clears the MEDIUM threshold
    # (35) on its own, matching how seriously an exact confirmed match
    # is already treated elsewhere (e.g. Legacy IOC). Two or more
    # INDEPENDENT corroborating sources add a further, bounded bonus
    # (instruction #4's explicit corroboration-raises-confidence
    # example) - capped by _aggregate_risk()'s overall min(100) either
    # way.
    risk_points = threat_intelligence.score_ioc_severity("CRITICAL")
    if len(independent_sources) > 1:
        risk_points += 15

    findings.append({
        "rule_id": "RULE_A_CONFIRMED_MALICIOUS_DESTINATION",
        "rule_name": "Confirmed malicious destination",
        "category": RULE_CATEGORY_MALICIOUS_DESTINATION,
        "risk_points": risk_points,
        "confidence": confidence,
        "explanation": (
            f"The destination ({ctx.get('destination_label')}) has a confirmed match in "
            f"{', '.join(sorted(independent_sources))} "
            f"({len(evidence)} indicator match(es))."
        ),
        "evidence": evidence,
    })

    return findings


def rule_local_ioc_match(ctx):
    """
    B. Local IOC match - an exact match against the admin-curated
    `threat_indicators` table (domain/hash/IP), reusing the SAME
    reliability gate web_event_worker.py already applies (a domain
    match is only used here if attribution_type == "dns" - an rDNS
    guess is never treated as proof, exactly like the Legacy pipeline).
    """

    findings = []
    evidence = []

    domain_ioc = ctx.get("domain_ioc_match")
    domain_ioc_reliable = ctx.get("domain_ioc_reliable")

    if domain_ioc and domain_ioc_reliable:
        evidence.append({
            "source": "LEGACY_IOC",
            "type": "DOMAIN",
            "indicator": domain_ioc.get("indicator_value"),
            "status": "MATCH",
            "detail": f"Local Legacy IOC, severity {domain_ioc.get('severity')}."
        })

    hash_ioc = ctx.get("hash_ioc_match")

    if hash_ioc:
        evidence.append({
            "source": "LEGACY_IOC",
            "type": "HASH",
            "indicator": hash_ioc.get("indicator_value"),
            "status": "MATCH",
            "detail": f"Local Legacy IOC, severity {hash_ioc.get('severity')}."
        })

    if ctx.get("ip_ioc_match"):
        evidence.append({
            "source": "LEGACY_IOC",
            "type": "IP",
            "indicator": ctx.get("resolved_ip"),
            "status": "MATCH",
            "detail": "Local Legacy IP IOC match."
        })

    if not evidence:
        return findings

    worst_severity = "CRITICAL" if any(
        (e.get("type") == "DOMAIN" and domain_ioc and str(domain_ioc.get("severity")).upper() == "CRITICAL")
        for e in evidence
    ) else "HIGH"

    findings.append({
        "rule_id": "RULE_B_LOCAL_IOC_MATCH",
        "rule_name": "Local IOC match",
        "category": RULE_CATEGORY_LOCAL_IOC,
        "risk_points": threat_intelligence.score_ioc_severity(worst_severity),
        "confidence": 85,
        "explanation": (
            f"Exact match against {len(evidence)} active local threat indicator(s) "
            f"for {ctx.get('destination_label')}."
        ),
        "evidence": evidence,
    })

    return findings


def rule_suspicious_process_and_destination(ctx):
    """
    C. Suspicious process + suspicious destination - fires ONLY when
    BOTH a process-side signal (unusual location OR suspicious
    command line OR behavioral anomaly) AND at least weak destination
    TI evidence (any ThreatFox/Local Feed/Legacy IOC signal, even a
    single one) are present TOGETHER. Neither alone is this rule -
    that is rules D/E/A/B's job; this rule exists specifically for the
    corroboration case instruction #4 describes.
    """

    findings = []

    process_row = ctx.get("process_row")

    if process_row is None:
        return findings  # no CONFIRMED process context - never guessed

    has_destination_signal = bool(
        ctx.get("domain_ioc_match") or ctx.get("hash_ioc_match") or ctx.get("ip_ioc_match")
        or (ctx.get("threatfox_evidence") and any(e.get("lookup_status") == "MATCH" for e in ctx["threatfox_evidence"]))
        or (ctx.get("local_feed_results") and any(entry.get("matches") for entry in ctx["local_feed_results"]))
    )

    if not has_destination_signal:
        return findings

    process_signals = []

    if _is_unusual_location(process_row["process_path"]):
        process_signals.append("executable runs from an unusual/temporary location")

    cmdline_findings = _match_suspicious_command_line(process_row["command_line_text"])
    if cmdline_findings:
        process_signals.append("suspicious command-line pattern(s) present")

    behavioral = ctx.get("behavioral_result")
    if behavioral and (behavioral.get("anomaly_score") or 0) >= 40:
        process_signals.append("behavioral anomaly on this endpoint")

    if not process_signals:
        return findings

    findings.append({
        "rule_id": "RULE_C_SUSPICIOUS_PROCESS_AND_DESTINATION",
        "rule_name": "Suspicious process with suspicious destination",
        "category": RULE_CATEGORY_SUSPICIOUS_PROCESS_DESTINATION,
        "risk_points": threat_intelligence.score_ioc_severity("HIGH"),
        "confidence": 75,
        "explanation": (
            f"Process {process_row['process_name']} ({'; '.join(process_signals)}) "
            f"communicated with a destination that also carries threat-intelligence evidence."
        ),
        "evidence": [{
            "source": "PROCESS_CONTEXT",
            "type": "PROCESS",
            "indicator": process_row["process_instance_id"],
            "status": "SUSPICIOUS",
            "detail": "; ".join(process_signals)
        }],
    })

    return findings


def rule_suspicious_command_line(ctx):
    """
    D. Suspicious command line - explainable pattern match only (see
    SUSPICIOUS_COMMAND_LINE_PATTERNS). Never fires on "PowerShell"
    alone - only on a specific, named technique pattern.
    """

    findings = []

    process_row = ctx.get("process_row")

    if process_row is None:
        return findings

    matched = _match_suspicious_command_line(process_row["command_line_text"])

    if not matched:
        return findings

    findings.append({
        "rule_id": "RULE_D_SUSPICIOUS_COMMAND_LINE",
        "rule_name": "Suspicious command-line pattern",
        "category": RULE_CATEGORY_SUSPICIOUS_COMMAND_LINE,
        "risk_points": threat_intelligence.score_ioc_severity("MEDIUM"),
        "confidence": 60,
        "explanation": (
            f"Process {process_row['process_name']}'s command line matches "
            f"{len(matched)} known-suspicious pattern(s): {'; '.join(matched)}."
        ),
        "evidence": [{
            "source": "PROCESS_CONTEXT",
            "type": "COMMAND_LINE",
            "indicator": process_row["process_instance_id"],
            "status": "PATTERN_MATCH",
            "detail": "; ".join(matched)
        }],
    })

    return findings


def rule_unusual_executable_location(ctx):
    """
    E. Unusual executable location - NEVER fires alone (instruction
    3E: "כאשר יש evidence נוסף"). Requires at least one additional
    corroborating signal: a destination TI signal, a command-line
    finding, or a behavioral anomaly.
    """

    findings = []

    process_row = ctx.get("process_row")

    if process_row is None or not _is_unusual_location(process_row["process_path"]):
        return findings

    corroboration = []

    if ctx.get("domain_ioc_match") or ctx.get("hash_ioc_match") or ctx.get("ip_ioc_match"):
        corroboration.append("local IOC match on the destination")

    if ctx.get("threatfox_evidence") and any(e.get("lookup_status") == "MATCH" for e in ctx["threatfox_evidence"]):
        corroboration.append("ThreatFox match on the destination")

    if ctx.get("local_feed_results") and any(entry.get("matches") for entry in ctx["local_feed_results"]):
        corroboration.append("Local Feed match on the destination")

    if _match_suspicious_command_line(process_row["command_line_text"]):
        corroboration.append("suspicious command-line pattern")

    behavioral = ctx.get("behavioral_result")
    if behavioral and (behavioral.get("anomaly_score") or 0) >= 40:
        corroboration.append("behavioral anomaly")

    if not corroboration:
        return findings  # location alone is never enough

    findings.append({
        "rule_id": "RULE_E_UNUSUAL_EXECUTABLE_LOCATION",
        "rule_name": "Unusual executable location with corroboration",
        "category": RULE_CATEGORY_UNUSUAL_EXECUTABLE_LOCATION,
        "risk_points": threat_intelligence.score_ioc_severity("MEDIUM"),
        "confidence": 55,
        "explanation": (
            f"Process {process_row['process_name']} runs from an unusual/temporary "
            f"location ({process_row['process_path']}), corroborated by: {'; '.join(corroboration)}."
        ),
        "evidence": [{
            "source": "PROCESS_CONTEXT",
            "type": "EXECUTABLE_PATH",
            "indicator": process_row["process_instance_id"],
            "status": "UNUSUAL_LOCATION",
            "detail": "; ".join(corroboration)
        }],
    })

    return findings


def rule_behavioral_anomaly_signal(ctx):
    """
    F. Behavioral anomaly as a SIGNAL only - never sole proof of
    malware (instruction 3F). Fires only when ALSO corroborated by at
    least one other evidence item, same spirit as rule E.
    """

    findings = []

    behavioral = ctx.get("behavioral_result")

    if not behavioral or (behavioral.get("anomaly_score") or 0) < 40:
        return findings

    corroboration = bool(
        ctx.get("domain_ioc_match") or ctx.get("hash_ioc_match") or ctx.get("ip_ioc_match")
        or (ctx.get("threatfox_evidence") and any(e.get("lookup_status") == "MATCH" for e in ctx["threatfox_evidence"]))
        or (ctx.get("local_feed_results") and any(entry.get("matches") for entry in ctx["local_feed_results"]))
    )

    if not corroboration:
        return findings

    findings.append({
        "rule_id": "RULE_F_BEHAVIORAL_ANOMALY_SIGNAL",
        "rule_name": "Behavioral anomaly, corroborated",
        "category": RULE_CATEGORY_BEHAVIORAL_ANOMALY,
        "risk_points": threat_intelligence.score_ioc_severity("LOW"),
        "confidence": 50,
        "explanation": (
            f"This endpoint's behavioral baseline flagged this activity as unusual "
            f"(anomaly score {behavioral.get('anomaly_score')}/100: "
            f"{'; '.join(behavioral.get('reasons') or [])}), corroborated by other threat evidence."
        ),
        "evidence": [{
            "source": "BEHAVIORAL",
            "type": "ANOMALY",
            "indicator": ctx.get("web_event_id"),
            "status": "UNUSUAL",
            "detail": "; ".join(behavioral.get("reasons") or [])
        }],
    })

    return findings


def rule_suricata_qualified_evidence(ctx):
    """
    G. Suricata qualified security evidence (Stage 25E) - fires ONLY
    for Suricata detections ALREADY classified SECURITY_ALERT by
    suricata_classification.py (never PROTOCOL_EVENT/ENGINE_DIAGNOSTIC/
    SENSOR_HEALTH - the classification happens in get_qualified_
    suricata_evidence_for_destination() below, BEFORE this rule ever
    sees the evidence, so an engine-noise checksum diagnostic or an
    ET INFO signature can never reach this rule at all, regardless of
    Suricata's own numeric "severity" field - instruction #9's explicit
    "don't use Suricata severity alone" requirement). Each qualified
    detection is its own evidence item (distinct rule_id per item), so
    multiple different qualified signatures against the same
    destination corroborate (instruction #10) without being treated as
    one blob.
    """

    findings = []
    suricata_evidence = ctx.get("suricata_evidence") or []

    if not suricata_evidence:
        return findings

    evidence = [{
        "source": "SURICATA",
        "type": "NETWORK_SIGNATURE",
        "indicator": entry.get("rule_id"),
        "status": "MATCH",
        "detail": (
            f"Suricata signature '{entry.get('rule_name')}' (category "
            f"{entry.get('rule_category')}) - classified SECURITY_ALERT, not an engine "
            f"diagnostic or informational event."
        ),
    } for entry in suricata_evidence]

    findings.append({
        "rule_id": "RULE_G_SURICATA_QUALIFIED_EVIDENCE",
        "rule_name": "Suricata qualified security signature",
        "category": RULE_CATEGORY_SURICATA_QUALIFIED,
        "risk_points": threat_intelligence.score_ioc_severity("HIGH"),
        "confidence": 70,
        "explanation": (
            f"The destination ({ctx.get('destination_label')}) triggered "
            f"{len(evidence)} Suricata network signature(s) independently classified as "
            f"genuine security alerts (never engine diagnostics or informational traffic)."
        ),
        "evidence": evidence,
    })

    return findings


def rule_external_reputation_signal(ctx):
    """
    H. External reputation signal (Stage 25F Phase 5) - the ONE Legacy-
    only signal audited and found that Rules A-G did not already
    consume: VirusTotal/AbuseIPDB's own probabilistic reputation score
    for the destination IP, INDEPENDENT of any curated IOC match
    (Rule B already owns the local_ioc/domain_ioc/hash_ioc portion via
    ctx["ip_ioc_match"]/["domain_ioc_match"]/["hash_ioc_match"] - this
    rule deliberately recomputes the risk using ONLY the raw
    virustotal/abuseipdb sub-dicts with local_ioc=None, so it can never
    double-count the same underlying local-IOC fact Rule B already
    scores under a different, genuinely distinct evidence_key).

    Ported into the Detection Engine BEFORE the Legacy block's own
    alert creation was retired (Phase 5 instruction #3) - this is what
    preserves detection coverage for a destination that external
    providers flag as malicious/suspicious but that has no curated
    local/ThreatFox/Local-Feed indicator at all.
    """

    findings = []

    reputation = ctx.get("reputation")

    if not reputation or reputation.get("error"):
        return findings

    external_only = threat_intelligence.calculate_threat_risk(
        reputation.get("virustotal") or {},
        reputation.get("abuseipdb") or {},
        local_ioc=None,
    )

    if external_only["severity"] not in ("MEDIUM", "HIGH", "CRITICAL"):
        return findings

    vt = reputation.get("virustotal") or {}
    abuse = reputation.get("abuseipdb") or {}

    vt_malicious = int(vt.get("malicious", 0) or 0)
    abuse_confidence = int(abuse.get("abuse_confidence", 0) or 0)

    evidence = []

    if vt.get("available") and vt_malicious > 0:
        evidence.append({
            "source": "VIRUSTOTAL",
            "type": "IP",
            "indicator": ctx.get("resolved_ip"),
            "status": "MATCH",
            "detail": f"VirusTotal: {vt_malicious} security vendor(s) classified the destination as malicious.",
        })

    if abuse.get("available") and abuse_confidence > 0:
        evidence.append({
            "source": "ABUSEIPDB",
            "type": "IP",
            "indicator": ctx.get("resolved_ip"),
            "status": "MATCH",
            "detail": f"AbuseIPDB: {abuse_confidence}% abuse confidence.",
        })

    if not evidence:
        return findings

    # Two independent external providers corroborating the same
    # destination raises confidence further - same "corroboration"
    # principle Rule A already uses, not a new/arbitrary number.
    independent_sources = {item["source"] for item in evidence}
    confidence = 60 if len(independent_sources) == 1 else 75

    findings.append({
        "rule_id": "RULE_H_EXTERNAL_REPUTATION_SIGNAL",
        "rule_name": "External reputation signal",
        "category": RULE_CATEGORY_EXTERNAL_REPUTATION,
        "risk_points": external_only["score"],
        "confidence": confidence,
        "explanation": (
            f"The destination ({ctx.get('destination_label')}) is flagged by "
            f"{len(independent_sources)} independent external reputation provider(s) "
            f"(VirusTotal/AbuseIPDB), independent of any curated local indicator match."
        ),
        "evidence": evidence,
    })

    return findings


ALL_RULES = (
    rule_confirmed_malicious_destination,
    rule_local_ioc_match,
    rule_suspicious_process_and_destination,
    rule_suspicious_command_line,
    rule_unusual_executable_location,
    rule_behavioral_anomaly_signal,
    rule_suricata_qualified_evidence,
    rule_external_reputation_signal,
)


# --------------------------------------------------
# RISK AGGREGATION (no double counting - instruction #5)
# --------------------------------------------------

def _aggregate_risk(findings):
    """
    Returns (detection_risk_score, counted_evidence_keys). Processes
    findings in the FIXED rule order above (deterministic) - the
    FIRST finding to cite a given evidence_key gets its points
    counted; any LATER finding citing the SAME evidence_key still
    exists as its own Detection row (different rule logic, kept for
    explainability) but contributes zero additional points here.
    """

    counted_keys = set()
    total = 0

    for finding in findings:

        evidence_keys_this_finding = {
            (item["source"], item.get("indicator"))
            for item in finding["evidence"]
        }

        already_fully_counted = evidence_keys_this_finding and evidence_keys_this_finding.issubset(counted_keys)

        if not already_fully_counted:
            total += finding["risk_points"]

        counted_keys |= evidence_keys_this_finding

    return min(total, 100), counted_keys


# --------------------------------------------------
# RECOMMENDED ACTION ENGINE (instruction #6 - recommendation only,
# never executed)
# --------------------------------------------------

def recommend_action(category, severity, ctx):

    if category == RULE_CATEGORY_MALICIOUS_DESTINATION or category == RULE_CATEGORY_LOCAL_IOC:

        if severity in ("HIGH", "CRITICAL"):
            return ACTION_BLOCK_DESTINATION, (
                f"Blocking the destination is recommended because it was identified by "
                f"confirmed threat-intelligence evidence and the endpoint communicated with it directly."
            )
        return ACTION_MONITOR, (
            "Continued monitoring is recommended; the evidence is confirmed but the "
            "overall risk does not yet warrant blocking."
        )

    if category == RULE_CATEGORY_SUSPICIOUS_PROCESS_DESTINATION:
        return ACTION_ISOLATE_ENDPOINT if severity == "CRITICAL" else ACTION_SCAN_ENDPOINT, (
            "Scanning the endpoint is recommended because a suspicious process communicated "
            "with a destination that also carries threat-intelligence evidence."
        )

    if category == RULE_CATEGORY_SUSPICIOUS_COMMAND_LINE:
        return ACTION_REVIEW_PROCESS, (
            "Reviewing the process is recommended because its command line matches a "
            "known-suspicious pattern; this alone does not confirm malicious intent."
        )

    if category == RULE_CATEGORY_UNUSUAL_EXECUTABLE_LOCATION:
        return ACTION_SCAN_ENDPOINT, (
            "Scanning the endpoint is recommended because the executable runs from an "
            "unusual location with additional corroborating evidence."
        )

    if category == RULE_CATEGORY_BEHAVIORAL_ANOMALY:
        return ACTION_REVIEW_PROCESS, (
            "Reviewing the process is recommended because it deviates from this endpoint's "
            "established behavioral baseline, corroborated by other evidence."
        )

    if category == RULE_CATEGORY_SURICATA_QUALIFIED:
        return ACTION_BLOCK_DESTINATION if severity in ("HIGH", "CRITICAL") else ACTION_MONITOR, (
            "Blocking the destination is recommended because the network sensor (Suricata) "
            "independently flagged traffic to it with a genuine security signature, not an "
            "engine diagnostic."
            if severity in ("HIGH", "CRITICAL") else
            "Continued monitoring is recommended; a network sensor signature fired but the "
            "overall risk does not yet warrant blocking."
        )

    if category == RULE_CATEGORY_EXTERNAL_REPUTATION:
        return ACTION_BLOCK_DESTINATION if severity in ("HIGH", "CRITICAL") else ACTION_MONITOR, (
            "Blocking the destination is recommended because independent external reputation "
            "providers (VirusTotal/AbuseIPDB) flag it as malicious with high confidence."
            if severity in ("HIGH", "CRITICAL") else
            "Continued monitoring is recommended; external reputation providers flag the "
            "destination but the overall risk does not yet warrant blocking."
        )

    return ACTION_MONITOR, "Continued monitoring is recommended."


# --------------------------------------------------
# PERSISTENCE (fingerprint-based upsert - instruction #8/#9)
# --------------------------------------------------

def _upsert_detection(conn, finding, ctx, detection_risk_score, severity, now_str):

    destination_key = ctx.get("destination_label") or ""

    fingerprint = compute_fingerprint(
        finding["rule_id"], ctx.get("endpoint_uid"), ctx.get("process_instance_id"), destination_key
    )

    existing = conn.execute(
        "SELECT * FROM detections WHERE fingerprint = ?", (fingerprint,)
    ).fetchone()

    action, action_explanation = recommend_action(finding["category"], severity, ctx)

    # Stash the computed recommendation back onto the finding dict so
    # _maybe_create_alert() (called by the same caller right after this
    # function returns) can carry it into the Security Alert's own
    # recommended_response field - without this, the Alert's
    # recommendation was silently always empty even though the right
    # sentence was computed and stored correctly in this very table
    # (found live, Stage 25C E2E #5).
    finding["recommended_action"] = action
    finding["recommended_action_explanation"] = action_explanation

    evidence_summary = json.dumps([item["detail"] for item in finding["evidence"]][:20])

    if existing is not None:

        cutoff = (datetime.now() - timedelta(minutes=DETECTION_DEDUP_WINDOW_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")

        if existing["last_seen_at"] >= cutoff and existing["status"] != STATUS_RESOLVED:

            # Same fingerprint, still within the dedup window and not
            # yet resolved - this is the SAME ongoing detection, not a
            # new one (instruction #8: "אותו אירוע שחוזר").
            conn.execute("""
                UPDATE detections
                SET occurrence_count = occurrence_count + 1,
                    last_seen_at = ?,
                    status = CASE WHEN status = 'NEW' THEN 'ACTIVE' ELSE status END,
                    web_event_id = ?
                WHERE id = ?
            """, (now_str, ctx.get("web_event_id"), existing["id"]))

            conn.commit()

            return existing["id"], False

        # Fingerprint seen before but the window lapsed (or it was
        # RESOLVED) - a genuinely NEW occurrence of the same rule;
        # re-open it rather than silently losing history under the
        # same fingerprint (instruction #8: distinguish "new real
        # event" from "same event repeating").
        conn.execute("""
            UPDATE detections
            SET status = 'NEW', occurrence_count = occurrence_count + 1,
                last_seen_at = ?, created_at = ?, resolved_at = NULL,
                severity = ?, confidence = ?, risk_contribution = ?,
                detection_risk_score = ?, explanation = ?, evidence_summary = ?,
                recommended_action = ?, recommended_action_explanation = ?,
                web_event_id = ?
            WHERE id = ?
        """, (
            now_str, now_str, severity, finding["confidence"], finding["risk_points"],
            detection_risk_score, finding["explanation"], evidence_summary,
            action, action_explanation, ctx.get("web_event_id"), existing["id"]
        ))

        conn.commit()

        # BUGFIX (found live during Stage 25F Phase 4 testing, pre-
        # existing since Stage 25C): this branch's own comment above
        # says "a genuinely NEW occurrence... re-open it", but the
        # code returned False here - meaning a reopened detection
        # (dedup window lapsed) was silently treated as NOT new, so it
        # never triggered the old per-finding alert path either. Fixed
        # to match the documented intent; see the Phase 4 report.
        return existing["id"], True

    cursor = conn.execute("""
        INSERT INTO detections (
            fingerprint, rule_id, rule_name, category, endpoint_uid, endpoint_ip,
            process_instance_id, web_event_id, severity, confidence,
            risk_contribution, detection_risk_score, explanation, evidence_summary,
            recommended_action, recommended_action_explanation, status,
            occurrence_count, created_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW', 1, ?, ?)
    """, (
        fingerprint, finding["rule_id"], finding["rule_name"], finding["category"],
        ctx.get("endpoint_uid"), ctx.get("endpoint_ip"), ctx.get("process_instance_id"),
        ctx.get("web_event_id"), severity, finding["confidence"], finding["risk_points"],
        detection_risk_score, finding["explanation"], evidence_summary,
        action, action_explanation, now_str, now_str
    ))

    detection_id = cursor.lastrowid

    for item in finding["evidence"]:
        conn.execute("""
            INSERT INTO detection_evidence (
                detection_id, evidence_source, evidence_type, indicator_value,
                status, detail_text
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            detection_id, item["source"], item.get("type"), item.get("indicator"),
            item.get("status"), item.get("detail")
        ))

    conn.commit()

    return detection_id, True


# --------------------------------------------------
# ALERT TYPE NAMING (distinct from Legacy's single "MALICIOUS_WEB_
# DESTINATION" alert_type - never collides with or suppresses it; see
# the Stage 25C report's explicit design-decision note on this)
# --------------------------------------------------

_ALERT_TYPE_BY_CATEGORY = {
    RULE_CATEGORY_MALICIOUS_DESTINATION: "CONFIRMED_MALICIOUS_DESTINATION_DETECTION",
    RULE_CATEGORY_LOCAL_IOC: "LOCAL_IOC_MATCH_DETECTION",
    RULE_CATEGORY_SUSPICIOUS_PROCESS_DESTINATION: "SUSPICIOUS_PROCESS_DESTINATION_DETECTION",
    RULE_CATEGORY_SUSPICIOUS_COMMAND_LINE: "SUSPICIOUS_COMMAND_LINE_DETECTION",
    RULE_CATEGORY_UNUSUAL_EXECUTABLE_LOCATION: "UNUSUAL_EXECUTABLE_LOCATION_DETECTION",
    RULE_CATEGORY_BEHAVIORAL_ANOMALY: "BEHAVIORAL_ANOMALY_DETECTION",
    RULE_CATEGORY_SURICATA_QUALIFIED: "SURICATA_QUALIFIED_EVIDENCE_DETECTION",
    RULE_CATEGORY_EXTERNAL_REPUTATION: "EXTERNAL_REPUTATION_DETECTION",
}


def _maybe_create_alert(conn, finding, ctx, detection_id, severity, detection_risk_score):
    """
    Stage 25F Phase 4: this per-FINDING alert path is no longer called
    from the normal evaluate_detections() flow (see _finalize_decision()
    below, the new single alert authority). It is kept, UNCHANGED, as
    the documented FALLBACK for the one case where a correlation_key
    cannot be deterministically formed (missing/malformed endpoint_uid,
    or no derivable destination) - "never invent a correlation key"
    means the Detection Engine falls back to its pre-Phase-4 per-rule
    alert behavior in that case rather than silently losing alerting
    capability. See the Phase 4 report for how often this path is
    expected to actually trigger (rare - the normal case always has
    a usable endpoint_uid/destination).
    """

    # Alert creation threshold mirrors Legacy's own should_alert
    # philosophy (MEDIUM+ or a confirmed IOC match) - never
    # duplicated with different numbers; same severity vocabulary.
    should_alert = severity in ("MEDIUM", "HIGH", "CRITICAL")

    if not should_alert:
        return None

    # STAGE 25G PHASE 3A - FALLBACK IDENTITY HARDENING.
    # Previously this delegated to create_security_alert(), whose dedup
    # keys on (alert_type, endpoint_ip, destination) and knows nothing
    # about endpoint IDENTITY: a fallback event (malformed/missing
    # endpoint_uid) on a shared IP could be merged into an alert that a
    # DIFFERENT, identified endpoint had legitimately created for the
    # same destination (found live in Stage 25G Phase 2 testing).
    # Now a fallback alert is isolated by the strongest trustworthy
    # identity that exists - the endpoint IP - AND may only ever reuse
    # another FALLBACK alert (correlation_key IS NULL): it never merges
    # into, and is never reused by, a canonical (identified) decision.
    # correlation_key stays NULL - uncertainty is never papered over
    # with a fabricated key - and the uncertainty is stated explicitly
    # on the alert itself.
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    existing = _find_fallback_alert(conn, finding, ctx, now_str)

    if existing is not None:
        alert = _update_unified_alert(conn, existing, ctx, [finding], severity, detection_risk_score, now_str)
    else:
        alert = _create_unified_alert(conn, None, ctx, [finding], severity, detection_risk_score, now_str)

    if FALLBACK_IDENTITY_NOTE not in (alert["description"] or ""):
        conn.execute(
            "UPDATE security_alerts SET description = ? WHERE id = ?",
            (((alert["description"] or "") + " | " + FALLBACK_IDENTITY_NOTE)[:2000], alert["id"])
        )

    conn.execute(
        "UPDATE detections SET security_alert_id = ? WHERE id = ?",
        (alert["id"], detection_id)
    )
    conn.commit()

    return alert["id"]


FALLBACK_IDENTITY_NOTE = (
    "ENDPOINT IDENTITY UNCERTAIN: no well-formed endpoint_uid was available, so this alert "
    "was isolated by endpoint IP only and carries no correlation_key; it was never merged "
    "with any identified endpoint's decision."
)


def _find_fallback_alert(conn, finding, ctx, now_str):
    """
    Fallback-only dedup (Stage 25G Phase 3A): same alert_type, same
    endpoint IP, same destination, still active, within
    DETECTION_DEDUP_WINDOW_MINUTES, AND correlation_key IS NULL - i.e.
    only another fallback alert for the same uncertain identity. A
    canonical alert (correlation_key set) is never a candidate, so two
    endpoints that merely share an IP/destination can never be merged
    through this path. Returns a row or None.
    """

    alert_type = _ALERT_TYPE_BY_CATEGORY.get(finding["category"], "DETECTION_ENGINE_FINDING")
    cutoff = (
        datetime.strptime(now_str, "%Y-%m-%d %H:%M:%S")
        - timedelta(minutes=DETECTION_DEDUP_WINDOW_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")
    placeholders = ",".join("?" for _ in _ACTIVE_ALERT_STATUSES)

    return conn.execute(f"""
        SELECT * FROM security_alerts
        WHERE correlation_key IS NULL
          AND alert_type = ?
          AND endpoint_ip = ?
          AND (
                (destination_ip IS NOT NULL AND destination_ip = ?)
                OR (domain IS NOT NULL AND domain = ?)
              )
          AND status IN ({placeholders})
          AND updated_at >= ?
        ORDER BY id DESC LIMIT 1
    """, (alert_type, ctx.get("endpoint_ip"), ctx.get("resolved_ip"), ctx.get("domain"),
          *_ACTIVE_ALERT_STATUSES, cutoff)).fetchone()


# --------------------------------------------------
# STAGE 25F PHASE 4: SINGLE DECISION AUTHORITY
# --------------------------------------------------
# One correlation_key -> at most one active security_alerts row, no
# matter how many of Rules A-G fired together. Individual rule findings
# still persist as their OWN detections rows (unchanged, rule-level,
# fully explainable via detection_evidence - see _upsert_detection()
# above, untouched) - only ALERT CREATION moves from "once per finding"
# to "once per evaluate_detections() call", via _finalize_decision()
# below, the ONE place now allowed to decide this. No individual rule
# function is an independent alert authority any more.
#
# The Legacy alert block in web_event_worker.py is explicitly NOT
# touched in this phase - it keeps creating its own MALICIOUS_WEB_
# DESTINATION alerts independently. The known Legacy-vs-Detection-Engine
# duplicate therefore still exists until Phase 5 - see the Phase 4
# report.
# --------------------------------------------------

# Same active-status vocabulary _find_recent_matching_alert() already
# uses (CLOSED alerts never suppress/get reused by a fresh occurrence).
_ACTIVE_ALERT_STATUSES = ("NEW", "ACKNOWLEDGED", "ESCALATED")


def _find_active_decision_alert(conn, corr_key, now_str):
    """
    Looks up a still-active unified decision alert for this EXACT
    correlation_key whose most recent update is within
    DETECTION_DEDUP_WINDOW_MINUTES of now - the SAME window
    _upsert_detection() already uses for its own reopen rule (not a
    new, unexplained number - instruction #4). A lapsed window
    deliberately returns None so the caller treats the next occurrence
    as a FRESH decision, never silently extending an old one's lifetime
    forever (instruction #4/#9 of the approved design).
    """

    cutoff = (
        datetime.strptime(now_str, "%Y-%m-%d %H:%M:%S")
        - timedelta(minutes=DETECTION_DEDUP_WINDOW_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")

    placeholders = ",".join("?" for _ in _ACTIVE_ALERT_STATUSES)

    return conn.execute(f"""
        SELECT * FROM security_alerts
        WHERE correlation_key = ?
          AND status IN ({placeholders})
          AND updated_at >= ?
        ORDER BY id DESC LIMIT 1
    """, (corr_key, *_ACTIVE_ALERT_STATUSES, cutoff)).fetchone()


def _unified_title(all_findings):

    distinct_rule_names = list(dict.fromkeys(f["rule_name"] for f in all_findings))

    if len(distinct_rule_names) == 1:
        return distinct_rule_names[0]

    extra = len(distinct_rule_names) - 1

    return f"{distinct_rule_names[0]} (corroborated by {extra} more detection{'s' if extra > 1 else ''})"


def _claimable_process_name(ctx):

    # Instruction #7: only CONFIRMED + a genuinely valid process_
    # instance_id may ever result in alert content asserting a
    # specific process. PENDING/UNAVAILABLE/NOT_APPLICABLE/unresolved
    # Suricata evidence all fall through to None here - the alert then
    # only ever makes an endpoint/destination-level statement.
    claim_allowed = correlation_key.tier_allows_process_identity_claim(
        ctx.get("process_correlation_status"),
        ctx.get("process_instance_id"),
        event_source=ctx.get("event_source"),
    )

    if not claim_allowed:
        return None

    return ctx["process_row"]["process_name"] if ctx.get("process_row") else ctx.get("process_name")


def _create_unified_alert(conn, corr_key, ctx, all_findings, severity, detection_risk_score, now_str):

    # Deterministic rule order (ALL_RULES A-G) already orders
    # all_findings - using the FIRST finding's own category for
    # alert_type preserves today's naming for the common case (one or
    # more rules led by A) instead of inventing a brand-new label;
    # every contributing rule is still named in the title/description/
    # detection_reasons below (instruction #5 - no unnecessary schema).
    alert_type = _ALERT_TYPE_BY_CATEGORY.get(all_findings[0]["category"], "DETECTION_ENGINE_FINDING")

    title = _unified_title(all_findings)
    description = " | ".join(dict.fromkeys(f["explanation"] for f in all_findings))[:2000]
    reasons = list(dict.fromkeys(item["detail"] for f in all_findings for item in f["evidence"]))
    recommendations = list(dict.fromkeys(
        f.get("recommended_action_explanation", "") for f in all_findings if f.get("recommended_action_explanation")
    ))

    process_name = _claimable_process_name(ctx)

    cursor = conn.execute("""
        INSERT INTO security_alerts (
            created_at, updated_at, alert_type, title, description, severity, risk_score,
            status, endpoint_ip, hostname, process_name, domain, destination_ip, source,
            source_event_id, detection_reasons, recommended_response, correlation_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'NEW', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_str, now_str, alert_type, title, description, severity, detection_risk_score,
        ctx.get("endpoint_ip"), ctx.get("hostname"), process_name, ctx.get("domain"), ctx.get("resolved_ip"),
        "detection-engine", ctx.get("web_event_id"), json.dumps(reasons), json.dumps(recommendations), corr_key
    ))

    alert_id = cursor.lastrowid

    add_alert_event(conn, alert_id, ctx.get("web_event_id"), endpoint_identity.REL_CREATED_FROM, now_str)

    conn.commit()

    write_log(
        "ALERT_CREATED",
        f"Alert #{alert_id} ({severity}): {title} [unified decision, correlation_key={(corr_key or 'NONE-fallback')[:16]}...]",
        target_ip=ctx.get("endpoint_ip"),
        username="detection-engine"
    )

    return conn.execute("SELECT * FROM security_alerts WHERE id = ?", (alert_id,)).fetchone()


def _update_unified_alert(conn, existing_alert, ctx, all_findings, severity, detection_risk_score, now_str):

    # MONOTONIC - instruction #6: independent corroborating evidence
    # may only RAISE an already-active decision's severity/risk, never
    # silently lower it just because one later re-evaluation happened
    # to see weaker evidence than before. Deliberately NOT the same as
    # create_security_alert()'s own Legacy "refresh to latest" reuse
    # semantics - that function is left untouched for Legacy's use;
    # this unified path needs different, monotonic semantics instead.
    combined_risk_score = max(existing_alert["risk_score"] or 0, detection_risk_score)
    combined_severity = threat_intelligence.severity_from_score(combined_risk_score)

    new_title = _unified_title(all_findings)

    try:
        existing_reasons = json.loads(existing_alert["detection_reasons"] or "[]")
    except (ValueError, TypeError):
        existing_reasons = []

    new_reasons = [item["detail"] for f in all_findings for item in f["evidence"]]
    combined_reasons = list(dict.fromkeys(existing_reasons + new_reasons))

    try:
        existing_recs = json.loads(existing_alert["recommended_response"] or "[]")
    except (ValueError, TypeError):
        existing_recs = []

    new_recs = [f.get("recommended_action_explanation", "") for f in all_findings if f.get("recommended_action_explanation")]
    combined_recs = list(dict.fromkeys(existing_recs + new_recs))

    # Appended, never overwritten - analysts can see the full
    # accumulated history of a still-active decision, not only its
    # latest snapshot.
    combined_description = existing_alert["description"] or ""
    new_description_piece = " | ".join(dict.fromkeys(f["explanation"] for f in all_findings))

    if new_description_piece and new_description_piece not in combined_description:
        combined_description = (combined_description + " | " + new_description_piece)[:2000]

    claimable_name = _claimable_process_name(ctx)
    process_name = claimable_name if claimable_name else existing_alert["process_name"]

    conn.execute("""
        UPDATE security_alerts
        SET severity = ?, risk_score = ?, title = ?, description = ?, detection_reasons = ?,
            recommended_response = ?, process_name = ?, updated_at = ?
        WHERE id = ?
    """, (
        combined_severity, combined_risk_score, new_title, combined_description,
        json.dumps(combined_reasons), json.dumps(combined_recs), process_name, now_str,
        existing_alert["id"]
    ))

    add_alert_event(conn, existing_alert["id"], ctx.get("web_event_id"), endpoint_identity.REL_DEDUP_REFRESH, now_str)

    conn.commit()

    return conn.execute("SELECT * FROM security_alerts WHERE id = ?", (existing_alert["id"],)).fetchone()


def _finalize_decision(conn, ctx, finding_records, severity, detection_risk_score, now_str):
    """
    Stage 25F Phase 4. Runs ONCE per evaluate_detections() call, after
    every rule finding has already been persisted as its own rule-level
    detections row. This is the ONLY place that decides whether the
    Detection Engine creates or reuses a security_alerts row.

    finding_records: list of (finding, detection_id, is_new) tuples -
    one per finding this call produced, in ALL_RULES order.

    Returns the list of alert ids touched - normally a single-element
    list (one unified alert), except in the documented FALLBACK case
    (see _maybe_create_alert()'s own docstring) where it may be several
    or none. Never raises - isolated by the caller like every other
    evidence block in this pipeline.
    """

    # Mirrors the OLD per-finding `if is_new:` gate exactly: a call
    # where every finding was a pure continuation (same fingerprint,
    # still within its own dedup window, nothing new) never touches
    # the alert at all - occurrence_count already advanced via
    # _upsert_detection(), nothing more to do here.
    if not any(is_new for _finding, _detection_id, is_new in finding_records):
        return []

    all_findings = [finding for finding, _detection_id, _is_new in finding_records]

    corr_key = correlation_key.compute_correlation_key(
        ctx.get("endpoint_uid"),
        ctx.get("process_correlation_status"),
        ctx.get("process_instance_id"),
        ctx.get("destination_label"),
        event_source=ctx.get("event_source"),
    )

    if corr_key is None:
        # FALLBACK - see _maybe_create_alert()'s docstring. "Never
        # invent a correlation key": when one cannot be formed, fall
        # back to the exact pre-Phase-4 per-finding alert behavior
        # rather than silently losing alerting capability.
        alert_ids = []

        for finding, detection_id, is_new in finding_records:

            if not is_new:
                continue

            alert_id = _maybe_create_alert(conn, finding, ctx, detection_id, severity, detection_risk_score)

            if alert_id:
                alert_ids.append(alert_id)

        return alert_ids

    existing_alert = _find_active_decision_alert(conn, corr_key, now_str)

    # BUGFIX (found live via the full regression run during Phase 4
    # testing - test_threat_intel_step12_e2e.py's LOW-severity single-
    # IOC scenario): the original per-finding _maybe_create_alert()
    # always gated on should_alert = severity in (MEDIUM, HIGH,
    # CRITICAL) - Stage 25C's own, never-duplicated-with-different-
    # numbers policy. That gate was dropped when alert creation moved
    # here. Restored: a call whose OWN aggregate severity does not
    # clear the threshold must NOT create a brand-new alert (matches
    # the original policy exactly). It MAY still update an ALREADY-
    # ACTIVE alert for this correlation_key, though - that decision
    # already cleared the threshold at some point, and a weaker new
    # occurrence must be recorded (never silently dropped), just never
    # used to downgrade it (see _update_unified_alert's own monotonic
    # max - instruction #6/#10).
    #
    # BUGFIX (found live via the Phase 5 test suite, "local IOC match
    # alone -> 0 alerts" regression): the RETIRED Legacy block's own
    # should_alert had an explicit extra OR-clause - "ANY severity + a
    # curated indicator match (domain/IP/hash IOC) -> alert regardless
    # of the numeric severity, because a watchlist hit is always worth
    # an analyst's attention even if the combined score is modest"
    # (Phase 6's own documented policy). Rule B's own risk_points can
    # score as low as LOW/INFO for a lightly-tagged IOC (e.g. a bare
    # HIGH-severity IP IOC alone scores 30 = LOW, below MEDIUM) - with
    # only the severity gate, that case silently stopped alerting the
    # moment Legacy's independent alert was retired, losing real
    # coverage. Restored at the unified-decision level instead of
    # inside any one rule, so it applies no matter which rule(s)
    # contributed a curated-match-category finding this call.
    any_curated_indicator_match = any(
        f["category"] in (RULE_CATEGORY_MALICIOUS_DESTINATION, RULE_CATEGORY_LOCAL_IOC)
        for f in all_findings
    )

    should_alert = severity in ("MEDIUM", "HIGH", "CRITICAL") or any_curated_indicator_match

    if existing_alert is None and not should_alert:
        return []

    if existing_alert is not None:
        alert = _update_unified_alert(conn, existing_alert, ctx, all_findings, severity, detection_risk_score, now_str)
    else:
        alert = _create_unified_alert(conn, corr_key, ctx, all_findings, severity, detection_risk_score, now_str)

    for _finding, detection_id, _is_new in finding_records:
        conn.execute(
            "UPDATE detections SET security_alert_id = ?, correlation_key = ? WHERE id = ?",
            (alert["id"], corr_key, detection_id)
        )

    conn.commit()

    # Incident escalation - instruction #9: at most once per decision
    # occurrence. create_security_alert()/create_incident_from_alert()'s
    # own ESCALATED/incident_id bookkeeping (unchanged) makes a second
    # escalation attempt for the SAME still-active alert a no-op check
    # here, exactly like Legacy's own escalation guard.
    if alert["severity"] in ("HIGH", "CRITICAL") and alert["status"] != "ESCALATED":

        incident_id = create_incident_from_alert(dict(alert), username="detection-engine")

        conn.execute(
            "UPDATE security_events SET correlation_key = ? WHERE id = ?",
            (corr_key, incident_id)
        )

        conn.commit()

    return [alert["id"]]


# --------------------------------------------------
# MAIN ENTRY POINT - called automatically from the worker pipeline
# (instruction #10) - never a manual "Analyze" action.
# --------------------------------------------------

def evaluate_detections(ctx):
    """
    Runs every rule against ctx, aggregates risk without double-
    counting, persists (or updates, if a dedup fingerprint matches)
    each firing rule as its own rule-level Detection row (unchanged -
    still fully explainable via detection_evidence), and then finalizes
    AT MOST ONE unified decision/Security Alert for the whole call via
    _finalize_decision() (Stage 25F Phase 4 - the single decision
    authority; no individual rule is its own alert authority any more).
    Returns a summary dict - never raises (every rule call and the
    whole pass is isolated so a Detection Engine problem can never
    break event ingestion/scoring).
    """

    # Stage 25F Phase 5: severity/risk_score start at None/0 rather than
    # absent keys, so a caller (e.g. the downstream advisory-blocklist
    # policy in web_event_worker.py) can always call .get() safely even
    # when no rule fired at all this call - "no detection activity"
    # must never be confused with "a LOW decision".
    summary = {"fired_rules": 0, "detection_ids": [], "alert_ids": [], "errors": [], "severity": None, "risk_score": 0}

    all_findings = []

    for rule_fn in ALL_RULES:

        try:
            findings = rule_fn(ctx)
        except Exception as exc:
            summary["errors"].append(f"{rule_fn.__name__}: {exc}")
            continue

        all_findings.extend(findings)

    if not all_findings:
        return summary

    detection_risk_score, _counted = _aggregate_risk(all_findings)
    severity = threat_intelligence.severity_from_score(detection_risk_score)

    summary["severity"] = severity
    summary["risk_score"] = detection_risk_score

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    try:

        finding_records = []

        for finding in all_findings:

            try:

                detection_id, is_new = _upsert_detection(
                    conn, finding, ctx, detection_risk_score, severity, now_str
                )

                summary["fired_rules"] += 1
                summary["detection_ids"].append(detection_id)
                finding_records.append((finding, detection_id, is_new))

            except Exception as exc:
                summary["errors"].append(f"persist[{finding.get('rule_id')}]: {exc}")

        try:

            alert_ids = _finalize_decision(
                conn, ctx, finding_records, severity, detection_risk_score, now_str
            )

            summary["alert_ids"].extend(alert_ids)

        except Exception as exc:
            summary["errors"].append(f"finalize_decision: {exc}")

    finally:
        conn.close()

    if summary["errors"]:
        write_log(
            "DETECTION_ENGINE_ERROR",
            f"web_event_id={ctx.get('web_event_id')} errors={summary['errors']}",
            username="system"
        )

    return summary


# --------------------------------------------------
# RECONCILIATION SWEEP (ACTIVE -> RESOLVED aging, instruction #9) -
# same periodic-sweep pattern as 25B's process-correlation sweep.
# --------------------------------------------------

def reconcile_detection_lifecycle(conn, max_age_hours=DETECTION_RESOLVE_AFTER_HOURS, now=None):

    now = now or datetime.now()
    cutoff = (now - timedelta(hours=max_age_hours)).strftime("%Y-%m-%d %H:%M:%S")

    cursor = conn.execute("""
        UPDATE detections
        SET status = 'RESOLVED', resolved_at = ?
        WHERE status IN ('NEW', 'ACTIVE')
        AND last_seen_at < ?
    """, (now.strftime("%Y-%m-%d %H:%M:%S"), cutoff))

    conn.commit()

    return {"resolved": cursor.rowcount}


# --------------------------------------------------
# CONTEXT BUILDERS - the ONLY place that decides what evidence a
# detection pass sees; both callers (web_event_worker.py's TCP/domain
# path and its browser-URL path) build ctx the same way so no rule
# ever needs to know which pipeline it came from.
# --------------------------------------------------

def get_confirmed_process_row(conn, process_instance_id):
    """
    Returns the endpoint_process_events row for process_instance_id,
    or None. Deliberately the caller's job to only call this when
    process_correlation_status == 'CONFIRMED' - this function itself
    does not re-check that (single responsibility; see build_context_*
    below, which IS where that check happens).
    """

    if not process_instance_id:
        return None

    return conn.execute(
        "SELECT * FROM endpoint_process_events WHERE process_instance_id = ?",
        (process_instance_id,)
    ).fetchone()


def get_behavioral_result(conn, web_event_id):

    if not web_event_id:
        return None

    row = conn.execute("""
        SELECT anomaly_score, behavioral_reasons FROM behavioral_event_results
        WHERE web_event_id = ? AND evaluation_status = 'SCORED'
    """, (web_event_id,)).fetchone()

    if row is None:
        return None

    try:
        reasons = json.loads(row["behavioral_reasons"] or "[]")
    except (ValueError, TypeError):
        reasons = []

    return {"anomaly_score": row["anomaly_score"], "reasons": reasons}


def get_qualified_suricata_evidence_for_destination(resolved_ip, event_time_str):
    """
    Stage 25E section 9. Looks up recent Suricata detections whose
    src_ip or dst_ip matches resolved_ip, within a bounded time window
    around this event, and returns only the ones suricata_
    classification.py classifies as SECURITY_ALERT - a PROTOCOL_EVENT/
    ENGINE_DIAGNOSTIC detection (e.g. sids 2200074/2200077) is filtered
    out HERE, before rule_suricata_qualified_evidence() ever sees it,
    so it structurally cannot become security evidence no matter what
    Suricata's own numeric severity field says. Returns [] (never
    raises) if resolved_ip is falsy, security_detections has nothing,
    or any lookup error occurs - a Suricata-evidence problem must never
    break event processing (same isolation discipline as every other
    evidence block in this project).
    """

    if not resolved_ip or not event_time_str:
        return []

    try:

        import security_detections as sd
        import security_contract as sc

        moment = datetime.strptime(event_time_str, "%Y-%m-%d %H:%M:%S")
        start = sc.format_utc(moment - timedelta(seconds=SURICATA_EVIDENCE_WINDOW_SECONDS))
        end = sc.format_utc(moment + timedelta(seconds=SURICATA_EVIDENCE_WINDOW_SECONDS))

        rows = sd.query_detections(start, end, limit=50)

        qualified = []

        for row in rows:

            if row.get("src_ip") != resolved_ip and row.get("dst_ip") != resolved_ip:
                continue

            classification, _explanation = suricata_classification.classify_detection_row(row)

            if classification == suricata_classification.CLASS_SECURITY_ALERT:
                qualified.append(row)

        return qualified

    except Exception:
        return []
