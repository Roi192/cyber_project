# ==================================================
# OCT 2026: SHODAN - CONTEXT-ONLY ENRICHMENT (never a risk signal)
# ==================================================
#
# context_only (see threat_intel_framework.PROVIDER_REGISTRY["shodan"]):
# per the original project instruction, an open port or exposed service is
# NEVER independent evidence that a server is malicious. This module only
# ever stores DESCRIPTIVE technical facts (open port count, product/
# service names) for analyst investigation - it can never contribute to
# risk scoring, regardless of what it reports (enforced in
# threat_intel_risk.py via evidence_class, not by this module).
# manual_eligible only (automatic_eligible=False): a technical enrichment
# lookup, not a verdict feed, so it is never dispatched automatically.
#
# API contract verified against the official documentation at
# https://developer.shodan.io/api (fetched at implementation time - not
# guessed):
#   GET https://api.shodan.io/shodan/host/<ip>?key=<API_KEY>
#   response: {"ports": [...], "data": [{"port":, "transport":,
#     "product":, ...}, ...], "org":, "hostnames": [...], ...}
# API KEY IS MANDATORY (query parameter "key") - no keyless mode is
# documented for this endpoint.
# ==================================================

import os

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()

SHODAN_API_BASE = "https://api.shodan.io/shodan/host/"

SHODAN_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "shodan"


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


def _parse_shodan_response(response_json):

    ports = response_json.get("ports")

    if not isinstance(ports, list):
        return {"lookup_status": "ERROR", "summary": "Shodan returned an unexpected response shape."}

    products = []
    for entry in (response_json.get("data") or [])[:5]:
        if isinstance(entry, dict) and entry.get("product"):
            products.append(str(entry["product"])[:40])

    org = response_json.get("org")

    return {
        "lookup_status": "MATCH",
        "threat_type": "technical_enrichment",
        "summary": f"Shodan: {len(ports)} open port(s) observed"
                   + (f", org: {org}" if org else "")
                   + (f", products: {', '.join(sorted(set(products)))}" if products else "") + ". "
                   "Technical enrichment only - never independent evidence of malicious activity.",
    }


def query_shodan_live(indicator_type, indicator_value):

    if indicator_type != "IP":
        return {"lookup_status": "ERROR", "summary": "Shodan supports IP indicators only."}

    if not SHODAN_API_KEY:
        return {"lookup_status": "ERROR", "summary": "Shodan API key is not configured."}

    try:

        response = requests.get(
            f"{SHODAN_API_BASE}{indicator_value}",
            params={"key": SHODAN_API_KEY},
            timeout=SHODAN_HTTP_TIMEOUT_SECONDS
        )

        if response.status_code == 404:
            # Documented Shodan behavior: no scan data on file for this host.
            return {"lookup_status": "NO_MATCH"}

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "Shodan authentication failed."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"Shodan returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "Shodan returned invalid JSON."}

        return _parse_shodan_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "Shodan request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "Shodan connection error."}


def get_shodan_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        try:
            live_result = query_shodan_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {"lookup_status": "ERROR", "summary": "Unexpected Shodan integration error."}

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
