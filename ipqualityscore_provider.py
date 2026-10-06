# ==================================================
# OCT 2026: IPQUALITYSCORE - EXTERNAL THREAT INTELLIGENCE
# ==================================================
#
# Contextual/corroboration evidence. A commercial fraud/risk score with
# proxy/VPN detection - useful corroboration, but proxy/VPN usage alone is
# common and legitimate, so this is NEVER decisive alone (see
# threat_intel_framework.PROVIDER_REGISTRY["ipqualityscore"]). Only
# recent_abuse=true or a high fraud_score is treated as a signal; a bare
# proxy/vpn/tor flag with no abuse history is NOT a signal on its own.
#
# API contract verified against the official documentation at
# https://www.ipqualityscore.com/documentation/proxy-detection/overview
# (fetched at implementation time - not guessed):
#   GET https://ipqualityscore.com/api/json/ip/<API_KEY>/<ip>?strictness=1
#   response: {"success": bool, "message": str, "fraud_score": 0-100,
#     "proxy": bool, "vpn": bool, "tor": bool, "recent_abuse": bool,
#     "bot_status": bool, ...}
# API KEY IS MANDATORY (embedded in the URL path) - no keyless mode is
# documented.
#
# strictness=1 is used (a light extra check beyond the default) - not the
# most aggressive setting, to keep the false-positive rate conservative
# given this evidence is corroboration-only, never decisive.
# ==================================================

import os
from datetime import datetime

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


IPQS_API_KEY = os.getenv("IPQS_API_KEY", "").strip()

IPQS_API_BASE = "https://ipqualityscore.com/api/json/ip/"

IPQS_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "ipqualityscore"

# --------------------------------------------------
# OCT 2026 STEP 13: SELF-IMPOSED MONTHLY QUOTA GUARD
# --------------------------------------------------
# Unlike OTX's keyless community ceiling (self-imposed, in-memory, resets
# on restart - acceptable there because its real documented limit is
# hourly), IPQualityScore's real free-tier quota is MONTHLY and typically
# small (commonly on the order of a few thousand lookups/month) - an
# in-memory-only counter would under-protect it across any worker
# restart within the same month. This guard is PERSISTED (its own tiny
# table in the same DB threat_intel_evidence lives in) so it survives a
# restart. Configurable via IPQS_MONTHLY_QUOTA_LIMIT (env); a
# conservative default is used if unset - deliberately well under a
# typical free-tier ceiling, never assumed to be the account's real
# limit (the account holder should set this explicitly once a real plan
# is chosen). This guard engages ONLY when IPQS_API_KEY is actually set -
# with no key, the provider is already fully inert (see
# query_ipqualityscore_live's own key check) and this table is never
# touched at all.
IPQS_MONTHLY_QUOTA_LIMIT = int(os.getenv("IPQS_MONTHLY_QUOTA_LIMIT", "").strip() or "500")

_QUOTA_SCHEMA = """
    CREATE TABLE IF NOT EXISTS ipqualityscore_quota_state (
        year_month TEXT PRIMARY KEY,
        call_count INTEGER NOT NULL DEFAULT 0
    )
"""


def _ensure_quota_schema(conn):
    conn.execute(_QUOTA_SCHEMA)
    conn.commit()


def _current_year_month(now=None):
    return (now or datetime.now()).strftime("%Y-%m")


def _ipqs_quota_used(conn, now=None):
    _ensure_quota_schema(conn)
    row = conn.execute(
        "SELECT call_count FROM ipqualityscore_quota_state WHERE year_month = ?",
        (_current_year_month(now),)
    ).fetchone()
    return row[0] if row else 0


def _ipqs_quota_increment(conn, now=None):
    _ensure_quota_schema(conn)
    ym = _current_year_month(now)
    conn.execute("""
        INSERT INTO ipqualityscore_quota_state (year_month, call_count) VALUES (?, 1)
        ON CONFLICT(year_month) DO UPDATE SET call_count = call_count + 1
    """, (ym,))
    conn.commit()


def get_ipqs_quota_status(conn=None, now=None):

    # Public, read-only status for the UI/diagnostics - never performs a
    # live call. "enabled" is false whenever no key is configured (the
    # provider is fully inert in that state, regardless of the quota
    # table's contents, which are never written to in that case).
    own = conn is None
    if own:
        conn = framework.get_db_connection()
    try:
        used = _ipqs_quota_used(conn, now)
        return {
            "enabled": bool(IPQS_API_KEY),
            "used": used,
            "limit": IPQS_MONTHLY_QUOTA_LIMIT,
            "remaining": max(0, IPQS_MONTHLY_QUOTA_LIMIT - used),
            "year_month": _current_year_month(now),
            "quota_exceeded": used >= IPQS_MONTHLY_QUOTA_LIMIT,
        }
    finally:
        if own:
            conn.close()

# High-confidence fraud_score threshold for treating the result as a
# signal even without a recorded recent_abuse flag (reasoned default,
# reviewable - IPQS documents fraud_score as 0-100, 85+ as high risk in
# its own scoring guidance).
_FRAUD_SCORE_SIGNAL_THRESHOLD = 85


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


def _parse_ipqs_response(response_json):

    if not response_json.get("success"):
        return {"lookup_status": "ERROR", "summary": response_json.get("message") or "IPQualityScore reported failure."}

    try:
        fraud_score = int(response_json.get("fraud_score") or 0)
    except (TypeError, ValueError):
        return {"lookup_status": "ERROR", "summary": "IPQualityScore returned a non-numeric fraud_score."}

    recent_abuse = bool(response_json.get("recent_abuse"))
    proxy = bool(response_json.get("proxy"))
    vpn = bool(response_json.get("vpn"))
    tor = bool(response_json.get("tor"))

    stats = {
        "fraud_score": max(0, min(fraud_score, 100)),
        "recent_abuse": int(recent_abuse),
        "proxy_or_vpn_or_tor": int(proxy or vpn or tor),
    }

    flags = []
    if proxy: flags.append("proxy")
    if vpn: flags.append("vpn")
    if tor: flags.append("tor")

    return {
        "lookup_status": "MATCH",
        "analysis_stats": stats,
        "summary": f"IPQualityScore: fraud_score={stats['fraud_score']}, recent_abuse={recent_abuse}"
                   + (f", flags: {'/'.join(flags)}" if flags else "") + ".",
    }


def classify_ipqs(stats):

    # Pure, mirrors the pattern of framework.classify_evidence()'s other
    # stats-based branches. "reported" requires recent_abuse OR a high
    # fraud_score - a bare proxy/vpn/tor flag alone is "flagged_anonymizer"
    # (NOT a signal: legitimate privacy-tool usage is extremely common).
    if stats is None:
        return "unknown"

    if stats.get("recent_abuse") or stats.get("fraud_score", 0) >= _FRAUD_SCORE_SIGNAL_THRESHOLD:
        return "reported"

    if stats.get("proxy_or_vpn_or_tor"):
        return "flagged_anonymizer"

    return "no_reported_abuse"


def query_ipqualityscore_live(indicator_type, indicator_value):

    if indicator_type != "IP":
        return {"lookup_status": "ERROR", "summary": "IPQualityScore (this integration) supports IP indicators only."}

    if not IPQS_API_KEY:
        return {"lookup_status": "ERROR", "summary": "IPQualityScore API key is not configured."}

    url = f"{IPQS_API_BASE}{IPQS_API_KEY}/{indicator_value}"

    try:

        response = requests.get(url, params={"strictness": 1}, timeout=IPQS_HTTP_TIMEOUT_SECONDS)

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "IPQualityScore authentication failed."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"IPQualityScore returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "IPQualityScore returned invalid JSON."}

        return _parse_ipqs_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "IPQualityScore request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "IPQualityScore connection error."}


def get_ipqualityscore_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        # Step 13 monthly quota guard - only ever engages when a real key
        # is configured (with no key, query_ipqualityscore_live's own
        # check below returns ERROR immediately, exactly as before this
        # change, and the quota table is never touched). Does not count
        # against the quota itself - this is a LOCAL gate, not a request.
        if IPQS_API_KEY and _ipqs_quota_used(conn) >= IPQS_MONTHLY_QUOTA_LIMIT:
            live_result = {
                "lookup_status": "RATE_LIMITED",
                "summary": f"Local monthly-quota guard engaged ({IPQS_MONTHLY_QUOTA_LIMIT}/month configured).",
            }
        else:
            try:
                live_result = query_ipqualityscore_live(indicator_type, indicator_value)
                if IPQS_API_KEY:
                    # A real network attempt was made (key present, quota
                    # not yet exhausted) - count it regardless of outcome
                    # (including a provider-side error/429), matching how
                    # a real account's own usage meter would count it.
                    _ipqs_quota_increment(conn)
            except Exception as exc:
                _log_lookup_error(indicator_type, exc)
                live_result = {"lookup_status": "ERROR", "summary": "Unexpected IPQualityScore integration error."}
                if IPQS_API_KEY:
                    _ipqs_quota_increment(conn)

        framework.ensure_evidence_schema(conn)

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
