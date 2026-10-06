# ==================================================
# STAGE 25E: SURICATA DETECTION CLASSIFICATION
# ==================================================
#
# Separates "this is a security threat" from "this is engine noise" -
# WITHOUT a blind SID allowlist (section 2's explicit requirement).
# Classification is semantic: it reads `independence_group` (rule
# LINEAGE - already computed and stored by sensors/suricata_adapter.py,
# see its own independence_group() for the exact sid-range rules: a
# "suricata:" prefix means Suricata's OWN decoder/stream/app-layer
# engine rule, "et:" means genuine Emerging Threats lineage, "snort-gpl:"
# /"local:" are other known lineages) TOGETHER WITH the rule's own name/
# category TEXT - never the sid number alone, and never severity alone.
#
# Four buckets (section 2):
#   SECURITY_ALERT    - a real threat signature fired (malware/trojan/
#                        C2/exploit/phishing/botnet/ransomware/backdoor/
#                        webshell-class ET signature, or any local/
#                        custom rule - those are never "noise" by
#                        definition, an analyst wrote them on purpose).
#   PROTOCOL_EVENT     - informational/policy-class signature (ET INFO/
#                        ET POLICY, "Misc activity", "Potential
#                        Corporate Privacy Violation", etc.) - real
#                        signal, but not itself a threat verdict.
#   ENGINE_DIAGNOSTIC  - Suricata's own decoder/stream/protocol-parser
#                        complaining about packet-level anomalies
#                        (checksums, decode errors) - an engine health
#                        signal, never a security verdict. sids
#                        2200074/2200077 (TCPv4/v6 invalid checksum)
#                        land here, but via their NAME+LINEAGE match,
#                        not because they are hard-coded by number -
#                        any other "suricata:"-lineage decoder/stream
#                        complaint classifies the same way.
#   SENSOR_HEALTH      - not produced by this module (that is `stats`
#                        events, a different concept entirely - see
#                        suricata_sensor_health.py). Kept as a named
#                        constant here only so callers share one
#                        vocabulary.
#
# UNKNOWN rule names/categories (a signature this module has never
# seen) deliberately default to PROTOCOL_EVENT, never SECURITY_ALERT -
# evidence must be positively identified as a threat before it is
# treated as one (same "evidence != verdict" principle as Stage 25C).
# This module NEVER reads/writes risk_score/severity/decision/
# security_alerts/response_commands - it only labels existing
# security_detections rows for display and for Stage 25C's Detection
# Engine to decide what counts as real evidence.
# ==================================================

import re

CLASS_SECURITY_ALERT = "SECURITY_ALERT"
CLASS_PROTOCOL_EVENT = "PROTOCOL_EVENT"
CLASS_ENGINE_DIAGNOSTIC = "ENGINE_DIAGNOSTIC"
CLASS_SENSOR_HEALTH = "SENSOR_HEALTH"

ALL_CLASSIFICATIONS = (
    CLASS_SECURITY_ALERT, CLASS_PROTOCOL_EVENT, CLASS_ENGINE_DIAGNOSTIC, CLASS_SENSOR_HEALTH,
)

# Suricata's own decoder/stream/app-layer engine complaints (NOT attack
# signatures) - matched against the rule NAME text, only ever combined
# with a "suricata:" lineage prefix below. Small, fixed, explainable
# list (same "start small" philosophy as every rule list in this
# project) - a "suricata:"-lineage rule whose name does NOT match one
# of these is NOT assumed to be a diagnostic (see _classify_suricata_
# native below: falls through to PROTOCOL_EVENT, never silently
# swallowed as noise).
_ENGINE_DIAGNOSTIC_NAME_PATTERNS = (
    re.compile(r"invalid checksum", re.IGNORECASE),
    re.compile(r"\bdecode\b", re.IGNORECASE),
    re.compile(r"unable to match response to request", re.IGNORECASE),
    re.compile(r"excessive header repetition", re.IGNORECASE),
    re.compile(r"\bmalformed\b", re.IGNORECASE),
    re.compile(r"\btruncated\b", re.IGNORECASE),
    re.compile(r"\bfragment(ation)?\b", re.IGNORECASE),
    re.compile(r"gap in stream", re.IGNORECASE),
)

# Genuine threat-class keywords - matched against ET-lineage rule name/
# category TEXT. Deliberately a short, explainable list of established
# threat-family terms (never "any ET rule = threat" - see the
# informational-prefix check below, which is evaluated FIRST and wins).
_THREAT_KEYWORDS = (
    "malware", "trojan", "c2", "cnc", "c&c", "command and control", "exploit",
    "phishing", "botnet", "ransomware", "backdoor", "webshell", "shellcode",
    "worm", "rootkit", "keylogger", "spyware", "dropper", "rat ", "remote access trojan",
    "exfiltration", "credential", "cobalt strike", "metasploit", "mirai",
)

# Informational/policy-class prefixes and categories - checked BEFORE
# the threat-keyword match, so e.g. "ET INFO ... Credential ..." (an
# informational signature that happens to mention a threat-adjacent
# word) is correctly PROTOCOL_EVENT, not misclassified as SECURITY_ALERT
# purely from a keyword hit. This ordering is itself the "check
# semantics, not just a keyword/SID" requirement in practice.
_INFORMATIONAL_NAME_PREFIXES = ("et info", "et policy", "et scan")
_INFORMATIONAL_CATEGORIES = (
    "misc activity", "not suspicious traffic", "potential corporate privacy violation",
    "generic protocol command decode",
)


def _norm(text):
    return (text or "").strip().lower()


def classify_security_detection(rule_id, rule_name, rule_category, independence_group):
    """
    Returns (classification, explanation) - explanation is a short,
    human-readable sentence (never just a code), for the same
    "explainable, never a bare code" discipline as Stage 25C's
    detections. Inputs are exactly the columns already stored on a
    security_detections row - this is a pure function, no DB access,
    safe to call for display (bulk) or for feeding the Detection
    Engine (per-row).
    """

    name = _norm(rule_name)
    category = _norm(rule_category)
    lineage = _norm(independence_group)

    # 1. Suricata's OWN engine lineage - a decoder/stream/protocol-
    # parser complaint is a diagnostic ONLY if its name actually
    # matches a known diagnostic pattern; an unrecognized
    # "suricata:"-lineage rule is NOT assumed to be noise (falls
    # through to PROTOCOL_EVENT below, explainable and reviewable).
    if lineage.startswith("suricata:"):

        for pattern in _ENGINE_DIAGNOSTIC_NAME_PATTERNS:
            if pattern.search(name):
                return CLASS_ENGINE_DIAGNOSTIC, (
                    f"Suricata's own decoder/stream engine reported a packet-level anomaly "
                    f"('{rule_name}') - this is a sensor health signal, not a security verdict."
                )

        return CLASS_PROTOCOL_EVENT, (
            f"A Suricata-native engine rule ('{rule_name}') fired that this classifier does not "
            f"recognize as a known diagnostic pattern - treated conservatively as a protocol "
            f"event, not a confirmed threat, pending review."
        )

    # 2. Local/custom rules - an analyst wrote these on purpose; never
    # demoted to noise regardless of name text.
    if lineage.startswith("local:") or lineage.startswith("snort-gpl:"):
        return CLASS_SECURITY_ALERT, (
            f"A locally-curated/custom rule ('{rule_name}') fired - written deliberately by this "
            f"organization's own analysts, always treated as a real security signal."
        )

    # 3. Emerging Threats lineage - informational/policy prefix wins
    # FIRST (checked before any threat keyword), so an ET INFO/POLICY/
    # SCAN signature or an informational category is never promoted to
    # SECURITY_ALERT just because its text happens to mention a
    # threat-adjacent word.
    if lineage.startswith("et:") or category in _INFORMATIONAL_CATEGORIES:

        if any(name.startswith(prefix) for prefix in _INFORMATIONAL_NAME_PREFIXES) or (
            category in _INFORMATIONAL_CATEGORIES
        ):
            return CLASS_PROTOCOL_EVENT, (
                f"An informational/policy-class signature ('{rule_name}', category "
                f"'{rule_category}') fired - real signal, but not itself a threat verdict."
            )

        if any(keyword in name or keyword in category for keyword in _THREAT_KEYWORDS):
            return CLASS_SECURITY_ALERT, (
                f"An Emerging Threats signature matching a known threat family "
                f"('{rule_name}', category '{rule_category}') fired."
            )

        # ET-lineage but neither informational nor a recognized threat
        # keyword - conservative default, never silently promoted.
        return CLASS_PROTOCOL_EVENT, (
            f"An Emerging Threats signature ('{rule_name}', category '{rule_category}') fired "
            f"that this classifier does not recognize as a known threat-family pattern - "
            f"treated conservatively as a protocol event, pending review."
        )

    # 4. Unknown lineage entirely - conservative default.
    return CLASS_PROTOCOL_EVENT, (
        f"Rule '{rule_name}' (id {rule_id}, lineage '{independence_group}') has no recognized "
        f"lineage or category match - treated conservatively as a protocol event, never "
        f"silently promoted to a security verdict without positive identification."
    )


def classify_detection_row(row):
    """Convenience wrapper for a security_detections dict/sqlite3.Row."""

    return classify_security_detection(
        row["rule_id"], row["rule_name"], row["rule_category"], row["independence_group"]
    )
