# ==================================================
# PHASE 11D.1: INVESTIGATION PRIORITY
# ==================================================
#
# A pure, deterministic, analyst-facing prioritization layer. Does
# NOT replace and NEVER writes to: web_events.risk_score/severity,
# behavioral_event_results.anomaly_score/confidence. Never creates
# a Security Alert/Incident/Response Command on its own - it is
# read-only, computed at render time from already-stored evidence.
#
# Levels (categorical, never a numeric third score):
#   ROUTINE < REVIEW < ELEVATED < URGENT
#
# Every contributing rule produces an explicit, object-precise
# reason string - never a claim like "endpoint infected" or
# "malware confirmed" unless another existing evidence source
# (Threat Risk / local IOC) independently already supports that
# wording elsewhere in the platform.
# ==================================================

LEVELS = ["ROUTINE", "REVIEW", "ELEVATED", "URGENT"]
_LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}


def detect_local_ioc_matched(details_text):

    # Reuses the exact reason-string prefixes the worker already
    # writes for IP/DOMAIN/HASH IOC matches (web_event_worker.py) -
    # the same convention already relied on by Security Analytics'
    # hash_ioc_matches_count KPI and Alert Details' evidence
    # reconstruction. Never re-derives IOC matching independently.

    if not details_text:
        return False

    markers = (
        "matches an active local IOC",
        "matched active local IOC",
        "matches an active local HASH IOC"
    )

    return any(marker in details_text for marker in markers)


def _threatfox_reason(evidence_row):

    indicator_type = evidence_row.get("indicator_type")

    threat_type = evidence_row.get("threat_type") or "unknown threat type"

    malware_family = evidence_row.get("malware_family")

    family_suffix = (
        f" (malware family: {malware_family})" if malware_family else ""
    )

    if indicator_type == "DOMAIN":
        return f"ThreatFox matched destination domain as {threat_type}{family_suffix}."

    if indicator_type == "IP":
        return f"ThreatFox matched destination IP as {threat_type}{family_suffix}."

    if indicator_type == "SHA256":
        return f"ThreatFox matched observed executable SHA-256 as {threat_type}{family_suffix}."

    return f"ThreatFox matched indicator as {threat_type}{family_suffix}."


def compute_investigation_priority(
    threat_severity,
    behavioral_label,
    behavioral_confidence,
    local_ioc_matched,
    threatfox_evidence=None
):

    threatfox_evidence = threatfox_evidence or []

    applicable = []

    # Rule 1: HIGH/CRITICAL Threat Risk -> URGENT
    if threat_severity in ("HIGH", "CRITICAL"):
        applicable.append((
            "URGENT",
            f"Threat Risk severity {threat_severity}."
        ))

    # Rule 2: any active local IOC match -> at least ELEVATED
    if local_ioc_matched:
        applicable.append((
            "ELEVATED",
            "Active local IOC match on this event."
        ))

    # Rules 3/4: MEDIUM Threat Risk
    if threat_severity == "MEDIUM":

        if behavioral_label == "UNUSUAL" and behavioral_confidence in ("MEDIUM", "HIGH"):
            applicable.append((
                "ELEVATED",
                "Threat Risk MEDIUM combined with Unusual behavior "
                f"({behavioral_confidence} baseline confidence)."
            ))
        else:
            applicable.append((
                "REVIEW",
                "Threat Risk MEDIUM."
            ))

    # Rules 5/6: INFO/LOW Threat Risk + Unusual behavior
    if threat_severity in ("INFO", "LOW") and behavioral_label == "UNUSUAL":

        if behavioral_confidence == "HIGH":
            applicable.append((
                "REVIEW",
                "Unusual behavior with High baseline confidence, "
                "independent of Threat Risk."
            ))
        else:
            applicable.append((
                "ROUTINE",
                "Unusual behavior noted, but baseline confidence is "
                "still Low/Medium - endpoint history is still maturing."
            ))

    # Rule 7: ThreatFox MATCH(es) -> at least REVIEW, never alone
    # ELEVATED/URGENT. One reason line per matched indicator, so
    # the evidence stays object-precise even when several
    # candidate indicators on the same event match independently.
    threatfox_matches = [
        row for row in threatfox_evidence
        if row.get("lookup_status") == "MATCH"
    ]

    for match_row in threatfox_matches:
        applicable.append(("REVIEW", _threatfox_reason(match_row)))

    # Rule 8: fallback
    if not applicable:
        applicable.append((
            "ROUTINE",
            "No elevated threat or behavioral evidence for this event."
        ))

    best_level = max(
        applicable,
        key=lambda entry: _LEVEL_RANK[entry[0]]
    )[0]

    reasons = [reason for _, reason in applicable]

    return best_level, reasons
