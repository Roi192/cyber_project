# ==================================================
# OCT 2026: PHISHTANK - EXTERNAL THREAT INTELLIGENCE (URL ONLY)
# ==================================================
#
# Contextual/corroboration evidence. A VERIFIED PhishTank match is treated
# as decisive malicious_evidence (community-voted confirmation of an active
# phishing URL) - see threat_intel_risk.py. An UNVERIFIED submission
# (reported but not yet confirmed by PhishTank's community review) is
# explicitly NOT treated as a signal: an unverified report could be wrong,
# stale, or itself malicious spam - only a verified entry counts.
#
# API contract verified against the official documentation at
# https://phishtank.org/api_info.php (fetched at implementation time - not
# guessed):
#   POST http://checkurl.phishtank.com/checkurl/
#   body (form-encoded): url=<target>, format=json, app_key=<key>
#   app_key is DOC-CONFIRMED OPTIONAL ("Optional, but without it the rate
#   at which you can make requests will be much more limited.") - this is
#   a verified fact, not an assumption, so this module calls the API
#   without a key when none is configured. Because the exact keyless rate
#   limit is NOT numerically documented (only described as "much more
#   limited"), this provider is registered manual_eligible ONLY
#   (automatic_eligible=False) - never dispatched by the automatic worker,
#   only by an analyst's explicit on-demand lookup, so routine enrichment
#   can never silently exhaust an undocumented shared quota.
#   Response (json): {"meta": {...}, "results": {"url":..., "in_database":
#     bool, "phish_id":..., "phish_detail_page":..., "verified": "y"/"n",
#     "verified_at":..., "valid": "y"/"n"}}
#
# NOTE: PhishTank only supports plain HTTP for this endpoint per its own
# documentation (no HTTPS variant is published); requests already warns on
# any non-loopback http:// URL at the adapter layer elsewhere in this
# project, but that warning path is specific to the sensor adapter and does
# not apply to this server-side outbound call. No secret/credential is sent
# over this connection (app_key is a rate-limit identifier, not a bearer
# credential for sensitive data), so this mirrors how the project already
# tolerates plain HTTP for low-sensitivity outbound lookups elsewhere
# (see URLhaus/ThreatFox, which are HTTPS; PhishTank is the one provider
# whose official endpoint is HTTP-only - documented, not a workaround).
# ==================================================

import os

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


# --------------------------------------------------
# CONFIG
# --------------------------------------------------

PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()

PHISHTANK_API_URL = "http://checkurl.phishtank.com/checkurl/"

PHISHTANK_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "phishtank"


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


# --------------------------------------------------
# LIVE CLIENT
# --------------------------------------------------

def _truthy_flag(value):

    # PhishTank's JSON responses represent booleans as "y"/"n" strings in
    # some API versions and as real JSON booleans in others (observed
    # inconsistently across its history) - accept both defensively.
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in ("y", "yes", "true", "1")


def _parse_phishtank_response(response_json):

    results = response_json.get("results")

    if not isinstance(results, dict):
        return {"lookup_status": "ERROR", "summary": "PhishTank returned an unexpected response shape."}

    if not _truthy_flag(results.get("in_database")):
        return {"lookup_status": "NO_MATCH"}

    verified = _truthy_flag(results.get("verified"))

    detail_url = results.get("phish_detail_page")

    if verified:
        return {
            "lookup_status": "MATCH",
            "threat_type": "verified_phishing",
            "last_seen": results.get("verified_at"),
            "summary": "PhishTank: community-verified active phishing URL."
                       + (f" Detail: {detail_url}" if detail_url else ""),
        }

    return {
        "lookup_status": "MATCH",
        "threat_type": "unverified_report",
        "summary": "PhishTank: an unverified submission exists for this URL (not yet community-confirmed; "
                   "not used as a malicious-activity signal).",
    }


def query_phishtank_live(indicator_type, indicator_value):

    if indicator_type != "URL":
        return {"lookup_status": "ERROR", "summary": "PhishTank supports URL indicators only."}

    data = {"url": indicator_value, "format": "json"}

    if PHISHTANK_API_KEY:
        data["app_key"] = PHISHTANK_API_KEY

    try:

        response = requests.post(
            PHISHTANK_API_URL,
            data=data,
            timeout=PHISHTANK_HTTP_TIMEOUT_SECONDS,
            # Step 24B.1.1 Task 2 fix: requests follows redirects on POST
            # by default, re-sending the full body (the URL being
            # checked, plus app_key if configured) to WHATEVER host a
            # 3xx response names - a real concern specifically here
            # because this endpoint is plain HTTP (no TLS; see the
            # module header), so a network-path attacker could inject a
            # redirect and have our data/key resent to an attacker-
            # controlled host. The documented endpoint never redirects,
            # so refusing this costs nothing (same reasoning and
            # precedent already applied to the Suricata adapter's own
            # ingest client elsewhere in this project).
            allow_redirects=False
        )

        if response.status_code == 509 or response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "PhishTank authentication failed."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"PhishTank returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "PhishTank returned invalid JSON."}

        return _parse_phishtank_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "PhishTank request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "PhishTank connection error."}


# --------------------------------------------------
# CACHE
# --------------------------------------------------

def get_phishtank_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        try:
            live_result = query_phishtank_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {"lookup_status": "ERROR", "summary": "Unexpected PhishTank integration error."}

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
