# ==================================================
# PHASE 12B.4: ABUSEIPDB NORMALIZED EVIDENCE PROVIDER (DERIVE-ONLY)
# ==================================================
#
# CONTEXT / CORROBORATION ONLY. Nothing here reads or writes
# web_events.risk_score/severity/decision, security_alerts,
# security_events, response_commands, or any Behavioral Baseline table.
# Normalized AbuseIPDB evidence adds ZERO Threat Risk points and never
# creates an Alert, Incident or Response Command. The LEGACY AbuseIPDB
# integration (threat_intelligence.check_abuseipdb -> reputation cache ->
# calculate_threat_risk) remains the only AbuseIPDB influence on risk and
# is not modified by this module.
#
# --------------------------------------------------
# ZERO DUPLICATE HTTP - STRUCTURAL GUARANTEE
# --------------------------------------------------
# This module has NO HTTP client: it does not import `requests` and
# contains no network code of any kind. Evidence is DERIVED from the
# result the legacy path has ALREADY fetched (record_legacy_ip_result(),
# called from reputation_routes.save_reputation_result, which only runs
# after a live legacy lookup). The registry entry has an empty
# live_lookup_types, and the async worker never manages this provider, so
# no code path can request an IP from AbuseIPDB a second time.
#
# --------------------------------------------------
# NEVER FABRICATE "NO ABUSE" FROM A FAILURE
# --------------------------------------------------
# The legacy cache persists a failed lookup as zeros, which is
# indistinguishable from a real "score 0" answer. So evidence is only
# written when the live legacy result PROVES a real provider object was
# returned (see _proves_provider_object). Anything else writes nothing -
# in particular a failed/rate-limited/unauthorised lookup can never become
# classification "no_reported_abuse". Historical threat_reputation rows are
# never used or backfilled.
#
# --------------------------------------------------
# WHAT IS RETAINED / EXCLUDED
# --------------------------------------------------
# Retained (all already parsed by the legacy result; nothing new is
# requested or stored raw): abuse confidence score, total reports,
# distinct reporting users (a COUNT), last-reported date, and - as bounded
# prose in the summary only - ISP, country, usage type, domain.
# Excluded on purpose: reporter identities/comments/raw reports (never
# requested - the API's verbose mode is not used), the raw response body,
# hostnames and isTor (the legacy parser does not read them; adding them
# would mean changing legacy code, which this phase must not do), and the
# score as a "confidence_level" (that column is a different provider's
# semantic and would invite reading the score as a probability).
# ==================================================

import re

import threat_intel_framework as framework

PROVIDER_NAME = "abuseipdb"

_MAX_TEXT = 80
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean_text(value):

    # Bounded, control-character-free provider text for the summary.
    if not isinstance(value, str):
        return None

    cleaned = _CONTROL_CHARS.sub(" ", value).strip()

    return cleaned[:_MAX_TEXT] if cleaned else None


def _non_negative_int(value):

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None

    return value


def _proves_provider_object(legacy_abuse_result):

    # The legacy result sets available=True as soon as an HTTP 200 body
    # parses as JSON, and every field then defaults to 0/None - so a 200
    # with an unexpected body would look like a genuine "score 0" answer.
    # A real AbuseIPDB report for a public IP always carries descriptive
    # fields (ISP / country / usage type / domain). Require at least one,
    # or a non-zero score/report count (which cannot come from defaults).
    # If nothing proves it, the safe answer is NO evidence - a rare valid
    # report with every descriptive field empty is skipped rather than
    # risking false "no abuse" evidence.
    for key in ("country_code", "isp", "usage_type", "domain"):
        value = legacy_abuse_result.get(key)
        if isinstance(value, str) and value.strip():
            return True

    return (
        (_non_negative_int(legacy_abuse_result.get("abuse_confidence")) or 0) > 0
        or (_non_negative_int(legacy_abuse_result.get("total_reports")) or 0) > 0
    )


def build_summary(score, total_reports, isp=None, country=None, usage_type=None, domain=None):

    # Provider-attributed, never a probability or a verdict.
    if score > 0:
        headline = (
            f"AbuseIPDB reports an abuse confidence score of {score} "
            f"with {total_reports} report(s)."
        )
    elif total_reports > 0:
        headline = (
            f"AbuseIPDB reports an abuse confidence score of 0 for this IP, "
            f"with {total_reports} report(s) on record."
        )
    else:
        headline = "AbuseIPDB reports an abuse confidence score of 0 for this IP."

    context = []
    for label, value in (("ISP", isp), ("Country", country), ("Usage type", usage_type), ("Domain", domain)):
        if value:
            context.append(f"{label}: {value}.")

    return " ".join([headline] + context)


def record_legacy_ip_result(ip_address, legacy_abuse_result, conn=None):

    # legacy_abuse_result is the dict check_abuseipdb() already returned.
    # Only a live legacy result that PROVES a real provider answer becomes
    # evidence; everything else writes nothing. Never raises to a legacy
    # caller (they also wrap this in try/except). Returns the stored row or
    # None.
    if not isinstance(legacy_abuse_result, dict) or legacy_abuse_result.get("available") is not True:
        return None

    ip = framework.normalize_ip_candidate(ip_address)

    if not ip:
        return None

    score = _non_negative_int(legacy_abuse_result.get("abuse_confidence"))
    total_reports = _non_negative_int(legacy_abuse_result.get("total_reports"))
    distinct_users = _non_negative_int(legacy_abuse_result.get("distinct_users") or 0)

    if score is None or score > 100 or total_reports is None or distinct_users is None:
        return None

    if not _proves_provider_object(legacy_abuse_result):
        return None

    last_reported = _clean_text(legacy_abuse_result.get("last_reported_at"))

    result = {
        "lookup_status": "MATCH",
        "threat_type": None,
        "malware_family": None,
        "confidence_level": None,
        "tags": None,
        "first_seen": None,
        "last_seen": last_reported,
        "summary": build_summary(
            score, total_reports,
            isp=_clean_text(legacy_abuse_result.get("isp")),
            country=_clean_text(legacy_abuse_result.get("country_code")),
            usage_type=_clean_text(legacy_abuse_result.get("usage_type")),
            domain=_clean_text(legacy_abuse_result.get("domain")),
        ),
        "analysis_stats": {
            "abuse_confidence_score": score,
            "total_reports": total_reports,
            "distinct_users": distinct_users,
        },
    }

    owns_conn = conn is None
    conn = conn or framework.get_db_connection()

    try:
        return framework.store_evidence(conn, PROVIDER_NAME, "IP", ip, result)
    finally:
        if owns_conn:
            conn.close()


def get_abuseipdb_evidence(indicator_type, indicator_value, conn=None):

    # READ-ONLY, cache-only. Never performs (or can perform) an HTTP
    # request: returns the stored derived evidence if fresh, otherwise an
    # honest NO_STORED_EVIDENCE placeholder.
    if (
        indicator_type != "IP"
        or not framework.provider_supports_indicator(PROVIDER_NAME, indicator_type, indicator_value)
        or framework.normalize_ip_candidate(indicator_value) is None
    ):
        return {
            "provider": PROVIDER_NAME,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "lookup_status": "NOT_SUPPORTED",
            "source": "ROUTING"
        }

    owns_conn = conn is None
    conn = conn or framework.get_db_connection()

    try:

        framework.ensure_evidence_schema(conn)

        # AbuseIPDB has no independent live fetch of its own (see module
        # header) - this is a pure read of whatever the legacy reputation
        # path already derived, never an orchestration "avoid a live
        # call" decision, so it must not count toward cache_hits_today.
        cached = framework.get_cached_evidence(
            conn, PROVIDER_NAME, "IP", indicator_value, count_as_lookup=False
        )

        if cached is not None:
            return cached

        return {
            "provider": PROVIDER_NAME,
            "indicator_type": "IP",
            "indicator_value": indicator_value,
            "lookup_status": "NO_STORED_EVIDENCE",
            "source": "LEGACY_DERIVED_ONLY"
        }

    finally:
        if owns_conn:
            conn.close()
