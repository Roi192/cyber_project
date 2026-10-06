# ==================================================
# OCT 2026: GOOGLE SAFE BROWSING (Lookup API v4) - EXTERNAL THREAT INTEL
# ==================================================
#
# Contextual/corroboration evidence. A MATCH is treated as DECISIVE
# malicious_evidence (see threat_intel_framework.PROVIDER_REGISTRY
# ["google_safe_browsing"]) - Google's own maintained phishing/malware
# list is among the most authoritative, low-false-positive sources
# available; still never independently triggers block/isolate response
# actions (out of scope for this phase - see project decision).
#
# API contract verified against the official documentation at
# https://developers.google.com/safe-browsing/v4/lookup-api (fetched at
# implementation time - not guessed):
#   POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=<key>
#   body: {"client": {"clientId": str, "clientVersion": str},
#          "threatInfo": {"threatTypes": [...], "platformTypes": [...],
#                         "threatEntryTypes": ["URL"],
#                         "threatEntries": [{"url": <value>}]}}
#   response: {} (empty object) when no match; {"matches": [...]} when
#     at least one threatType/platformType combination matches.
# API KEY IS MANDATORY (passed as the "key" query parameter) - no keyless
# mode is documented. Numeric free-tier rate limits were not published on
# the fetched pages; this module therefore applies no optimistic
# assumption about quota beyond honoring HTTP 429/403 from Google.
# ==================================================

import os

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()

GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

GSB_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "google_safe_browsing"

_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION")


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


def _parse_gsb_response(response_json):

    matches = response_json.get("matches")

    if not matches:
        # The documented "no match" response is an empty JSON object - an
        # absent/empty "matches" key means the same thing.
        return {"lookup_status": "NO_MATCH"}

    if not isinstance(matches, list):
        return {"lookup_status": "ERROR", "summary": "Safe Browsing returned an unexpected response shape."}

    threat_types = sorted({m.get("threatType") for m in matches if isinstance(m, dict) and m.get("threatType")})

    return {
        "lookup_status": "MATCH",
        "threat_type": ",".join(threat_types) if threat_types else "UNKNOWN",
        "summary": "Google Safe Browsing: listed for " + (", ".join(threat_types) if threat_types else "an unspecified threat type") + ".",
    }


def query_google_safe_browsing_live(indicator_type, indicator_value):

    if indicator_type != "URL":
        return {"lookup_status": "ERROR", "summary": "Safe Browsing supports URL indicators only."}

    if not GSB_API_KEY:
        return {"lookup_status": "ERROR", "summary": "Google Safe Browsing API key is not configured."}

    body = {
        "client": {"clientId": "soc-platform", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": list(_THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": indicator_value}],
        },
    }

    try:

        response = requests.post(
            GSB_API_URL,
            params={"key": GSB_API_KEY},
            json=body,
            timeout=GSB_HTTP_TIMEOUT_SECONDS,
            # Step 24B.1.1 Task 2 fix: requests follows redirects on POST
            # by default, re-sending the full body (the URL being
            # checked, plus the API key as a query param) to WHATEVER
            # host a 3xx response names. The documented endpoint never
            # redirects, so refusing this costs nothing (same reasoning
            # and precedent already applied to the Suricata adapter's
            # own ingest client elsewhere in this project).
            allow_redirects=False
        )

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "Safe Browsing authentication failed."}

        if response.status_code == 400:
            return {"lookup_status": "ERROR", "summary": "Safe Browsing rejected the request (bad API key or malformed body)."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"Safe Browsing returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "Safe Browsing returned invalid JSON."}

        return _parse_gsb_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "Safe Browsing request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "Safe Browsing connection error."}


def get_google_safe_browsing_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        try:
            live_result = query_google_safe_browsing_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {"lookup_status": "ERROR", "summary": "Unexpected Safe Browsing integration error."}

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
