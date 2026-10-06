# ==================================================
# OCT 2026: CENSYS - CONTEXT-ONLY ENRICHMENT (never a risk signal)
# ==================================================
#
# context_only (see threat_intel_framework.PROVIDER_REGISTRY["censys"]),
# same rule as Shodan: exposed ports/services/certificates are NEVER
# independent evidence of malicious activity. Descriptive technical facts
# only - can never contribute to risk scoring regardless of what it
# reports (enforced in threat_intel_risk.py via evidence_class).
# manual_eligible only (automatic_eligible=False).
#
# LOWER CONFIDENCE THAN THE OTHER 7 ADAPTERS - DISCLOSED EXPLICITLY:
# Censys's own primary API documentation pages returned HTTP 403/522 when
# fetched directly at implementation time (blocked/unavailable), so this
# adapter is built from secondary, independently-corroborated sources
# (Censys community Q&A and third-party integration references) rather
# than a directly-read primary doc page, unlike every other adapter in
# this project. Verified facts used here: authentication is HTTP Basic
# with an API ID (username) and API Secret (password), obtained from the
# Censys account console; a v2 host-lookup endpoint exists at
# /v2/hosts/{ip}. THE EXACT BASE DOMAIN AND RESPONSE SHAPE BELOW SHOULD BE
# RE-VERIFIED AGAINST CENSYS'S CURRENT OWN DOCUMENTATION before this
# adapter is relied upon - Censys has changed its API surface over time
# (a newer unified "Censys Platform" API using Bearer tokens instead of
# Basic auth has been publicly discussed and may have superseded this
# endpoint). Until re-verified, this adapter will report ERROR on any
# unexpected response shape rather than guess.
# ==================================================

import os

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


CENSYS_API_ID = os.getenv("CENSYS_API_ID", "").strip()
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "").strip()

CENSYS_API_BASE = "https://search.censys.io/api/v2/hosts/"

CENSYS_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "censys"


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


def _parse_censys_response(response_json):

    result = response_json.get("result")

    if not isinstance(result, dict):
        return {"lookup_status": "ERROR", "summary": "Censys returned an unexpected response shape (adapter not fully doc-verified - see module header)."}

    services = result.get("services")
    port_count = len(services) if isinstance(services, list) else 0

    autonomous_system = result.get("autonomous_system") or {}
    org = autonomous_system.get("name") if isinstance(autonomous_system, dict) else None

    return {
        "lookup_status": "MATCH",
        "threat_type": "technical_enrichment",
        "summary": f"Censys: {port_count} service(s) observed" + (f", AS org: {org}" if org else "")
                   + ". Technical enrichment only - never independent evidence of malicious activity.",
    }


def query_censys_live(indicator_type, indicator_value):

    if indicator_type != "IP":
        return {"lookup_status": "ERROR", "summary": "Censys (this integration) supports IP indicators only."}

    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return {"lookup_status": "ERROR", "summary": "Censys API credentials are not configured."}

    try:

        response = requests.get(
            f"{CENSYS_API_BASE}{indicator_value}",
            auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            timeout=CENSYS_HTTP_TIMEOUT_SECONDS
        )

        if response.status_code == 404:
            return {"lookup_status": "NO_MATCH"}

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "Censys authentication failed."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"Censys returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "Censys returned invalid JSON."}

        return _parse_censys_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "Censys request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "Censys connection error."}


def get_censys_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        try:
            live_result = query_censys_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {"lookup_status": "ERROR", "summary": "Unexpected Censys integration error."}

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
