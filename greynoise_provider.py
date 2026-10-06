# ==================================================
# OCT 2026: GREYNOISE COMMUNITY API - EXTERNAL THREAT INTELLIGENCE
# ==================================================
#
# Contextual evidence for the scanning-noise classification ONLY ("malicious"
# classification counts as a signal; "benign"/"unknown" never lower risk -
# see threat_intel_risk.py). Nothing here reads or writes
# web_events.risk_score/severity/decision, security_alerts, security_events,
# response_commands, or any Behavioral Baseline table on its own - this
# module only ever writes a normalized row into the existing
# threat_intel_evidence table, exactly like every other provider adapter.
#
# API contract verified against the official documentation at
# https://docs.greynoise.io/docs/using-the-greynoise-community-api
# (fetched at implementation time - not guessed):
#   GET https://api.greynoise.io/v3/community/<ip>
#   header: key: <api_key>   (OPTIONAL - see below)
#   response (200): {"ip":..., "noise": bool, "riot": bool,
#     "classification": "malicious"|"benign"|"unknown", "name": str,
#     "link": str, "last_seen": str, "message": str}
#
# AUTHENTICATION IS DOC-CONFIRMED OPTIONAL (not assumed): the Community
# endpoint is documented as "available to unauthenticated users with a
# limited number of lookups per day" (10 lookups/day unauthenticated vs 50
# searches/week for a free registered Community account). Per project
# decision (Oct 2026), this module WILL call the endpoint without a key,
# because the provider's own documentation confirms this is a supported,
# intended usage mode - it is a verified fact, not an assumption. BECAUSE
# the keyless/community quota is so tight, this provider is registered as
# manual_eligible ONLY (automatic_eligible=False in PROVIDER_REGISTRY) - it
# is never dispatched by the automatic worker, only by an analyst's
# explicit, on-demand lookup, so routine automatic enrichment can never
# silently exhaust the shared daily/weekly quota.
#
# Only IPv4 is supported (GreyNoise Community covers IPv4 scanning
# activity; registry ip_versions=(4,) already enforces this upstream).
# ==================================================

import os

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


# --------------------------------------------------
# CONFIG (never logged/rendered - only presence is ever checked)
# --------------------------------------------------

GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "").strip()

GREYNOISE_API_URL = "https://api.greynoise.io/v3/community/"

GREYNOISE_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "greynoise"


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


# --------------------------------------------------
# TTL (own, reasoned values - not copied from another provider): scanning
# activity classification can change day to day, so MATCH/NO_MATCH both
# refresh faster than the multi-day IOC-feed TTLs used elsewhere.
# --------------------------------------------------

def _ttl_for_status(lookup_status):

    return framework.get_ttl(PROVIDER_NAME, lookup_status)


# --------------------------------------------------
# LIVE CLIENT
# --------------------------------------------------

def _parse_greynoise_response(response_json):

    classification = response_json.get("classification")

    if classification not in ("malicious", "benign", "unknown"):
        # An unexpected/missing classification value is a provider-contract
        # surprise, not a usable answer.
        return {
            "lookup_status": "ERROR",
            "summary": f"Unexpected GreyNoise classification: {classification!r}"
        }

    name = response_json.get("name")
    noise = bool(response_json.get("noise"))
    riot = bool(response_json.get("riot"))

    summary = (
        f"GreyNoise classification: {classification}"
        + (f" ({name})" if name and name != "unknown" else "")
        + (" - internet scanning activity observed" if noise else "")
        + (" - known common business service (RIOT)" if riot else "")
    )

    return {
        "lookup_status": "MATCH",
        "threat_type": classification,
        "last_seen": response_json.get("last_seen"),
        "summary": summary,
    }


def query_greynoise_live(indicator_type, indicator_value):

    if indicator_type != "IP":
        return {"lookup_status": "ERROR", "summary": "GreyNoise supports IPv4 only."}

    headers = {}
    if GREYNOISE_API_KEY:
        headers["key"] = GREYNOISE_API_KEY

    try:

        response = requests.get(
            GREYNOISE_API_URL + indicator_value,
            headers=headers,
            timeout=GREYNOISE_HTTP_TIMEOUT_SECONDS
        )

        if response.status_code == 404:
            # Documented behavior: no data for this IP (never observed) -
            # absence of data, never evidence the IP is safe.
            return {"lookup_status": "NO_MATCH"}

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "GreyNoise authentication failed."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"GreyNoise returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "GreyNoise returned invalid JSON."}

        return _parse_greynoise_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "GreyNoise request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "GreyNoise connection error."}


# --------------------------------------------------
# CACHE (delegates to the shared framework cache layer, parameterized with
# provider="greynoise" - never reads threat_reputation/reputation_source)
# --------------------------------------------------

def get_greynoise_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        try:
            live_result = query_greynoise_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {"lookup_status": "ERROR", "summary": "Unexpected GreyNoise integration error."}

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
