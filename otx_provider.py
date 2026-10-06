# ==================================================
# OCT 2026: ALIENVAULT OTX (DirectConnect API) - EXTERNAL THREAT INTELLIGENCE
# ==================================================
#
# Contextual/corroboration evidence ONLY - a pulse match means "at least
# one community-authored OTX Pulse references this indicator", never
# "endpoint infected" or "confirmed malicious" on its own (same cautious
# wording discipline as every other provider here). Pulse authorship/
# curation quality varies widely, which is exactly why this provider is
# registered reliability_weight=0.6 and never decisive alone (see
# threat_intel_framework.PROVIDER_REGISTRY["alienvault_otx"]).
#
# API contract verified against the official documentation at
# https://otx.alienvault.com/assets/static/external_api.html and
# corroborated against the OTX DirectConnect API reference (fetched/
# searched at implementation time - not guessed):
#   GET https://otx.alienvault.com/api/v1/indicators/{IOC_TYPE}/{value}/general
#   IOC_TYPE: "IPv4" | "IPv6" | "domain" | "file" (file auto-detects the
#     hash type server-side - MD5/SHA1/SHA256 all use the "file" segment)
#   header: X-OTX-API-KEY: <key>   (DOC-CONFIRMED OPTIONAL for general
#     indicator info: 1,000 requests/hour unauthenticated vs 10,000/hour
#     authenticated - this is a verified fact, not an assumption)
#   response (200) includes "pulse_info": {"count": N, "pulses": [...]}
#
# Because keyless access is relatively generous (1,000/hour, a SHARED
# resource across all unauthenticated OTX callers everywhere - not specific
# to this deployment), this module calls the API without a key when none
# is configured, but applies its OWN conservative per-process rate guard
# (see _record_call/_recent_call_count below) well under the documented
# ceiling, so this single deployment can never be the reason that shared
# allowance is exhausted. automatic_eligible=True in the registry reflects
# this generosity (unlike GreyNoise/PhishTank's much tighter keyless
# limits, which are manual-only).
# ==================================================

import os
import time

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


# --------------------------------------------------
# CONFIG
# --------------------------------------------------

OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()

OTX_API_BASE = "https://otx.alienvault.com/api/v1/indicators/"

OTX_HTTP_TIMEOUT_SECONDS = 10

# --------------------------------------------------
# OCT 2026 STEP 16: OTX-SPECIFIC CA BUNDLE OVERRIDE (opt-in, OTX ONLY)
# --------------------------------------------------
# Root cause (diagnosed Step 15): on this development machine, a locally
# installed antivirus product's HTTPS-scanning feature transparently
# re-signs the TLS connection to otx.alienvault.com with a certificate
# rooted in a LOCALLY GENERATED CA that the Windows OS trust store
# already trusts (legitimately - it is how the AV product's own HTTPS
# scanning works) but requests/certifi's bundled PUBLIC-CA-only list
# does not. This is NOT disabling verification - verification stays
# fully ON; OTX_CA_BUNDLE only tells requests to also trust the
# certificate(s) in this ADDITIONAL, OPERATOR-PROVIDED file, in place of
# (not in addition to silently expanding) the default certifi list for
# THIS PROVIDER'S REQUEST ONLY. Every other provider (VirusTotal,
# AbuseIPDB, URLhaus, etc.) is completely unaffected - each has its own
# separate requests.get() call using requests' own default verify
# behavior, untouched by this variable.
#
# This file is NEVER generated automatically by this adapter and NEVER
# defaults to the full Windows certificate store - see threat_intel_
# diagnostics.py's "prepare-otx-ca-bundle" command, which shows the
# operator exactly what certificate chain otx.alienvault.com actually
# presents on THIS machine and requires explicit, informed confirmation
# before writing anything. OTX_CA_BUNDLE is unset by default (empty) -
# in that state this adapter behaves EXACTLY as before this change
# (requests' own default verify=True against certifi's public bundle).
OTX_CA_BUNDLE = os.getenv("OTX_CA_BUNDLE", "").strip()

PROVIDER_NAME = "alienvault_otx"

_IOC_TYPE_SEGMENT = {
    "IPv4": "IPv4",
    "IPv6": "IPv6",
    "DOMAIN": "domain",
    "SHA256": "file",
    "MD5": "file",
}

# Conservative self-imposed ceiling when running keyless (documented
# keyless ceiling is 1,000/hour, shared globally - this deployment never
# tries to use more than a fraction of that on its own).
_KEYLESS_MAX_CALLS_PER_HOUR = 200
_recent_call_times = []


def _record_call(now=None):
    _recent_call_times.append(now or time.time())


# --------------------------------------------------
# OCT 2026 STEP 17: OPTIONAL TOTAL-CALL CAP (for a controlled, bounded
# initial activation - separate from, and in addition to, the hourly
# keyless guard above and threat_intel_worker.py's per-cycle/gradual-
# rollout budgets). Unlike those, this is a LIFETIME total, not a
# rolling window, and PERSISTS across a worker restart (a plain
# in-memory counter would not survive the exact restart this is meant to
# bound). Default unset = no cap at all (completely unchanged existing
# behavior). Only ever read/written when OTX_MAX_TOTAL_CALLS is actually
# set to a number - the schema/table is not even created otherwise.
# --------------------------------------------------
_OTX_MAX_TOTAL_CALLS_RAW = os.getenv("OTX_MAX_TOTAL_CALLS", "").strip()
OTX_MAX_TOTAL_CALLS = int(_OTX_MAX_TOTAL_CALLS_RAW) if _OTX_MAX_TOTAL_CALLS_RAW.isdigit() else None

_TOTAL_CALLS_SCHEMA = """
    CREATE TABLE IF NOT EXISTS otx_total_call_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        call_count INTEGER NOT NULL DEFAULT 0
    )
"""


def _ensure_total_calls_schema(conn):
    conn.execute(_TOTAL_CALLS_SCHEMA)
    conn.execute("INSERT OR IGNORE INTO otx_total_call_state (id, call_count) VALUES (1, 0)")
    conn.commit()


def _otx_total_calls_used(conn):
    _ensure_total_calls_schema(conn)
    row = conn.execute("SELECT call_count FROM otx_total_call_state WHERE id = 1").fetchone()
    return row[0] if row else 0


def _otx_total_calls_increment(conn):
    _ensure_total_calls_schema(conn)
    conn.execute("UPDATE otx_total_call_state SET call_count = call_count + 1 WHERE id = 1")
    conn.commit()


def get_otx_total_call_status(conn=None):

    # Public, read-only status - never performs a live call.
    own = conn is None
    if own:
        conn = framework.get_db_connection()
    try:
        used = _otx_total_calls_used(conn)
        limit = OTX_MAX_TOTAL_CALLS
        return {
            "used": used,
            "limit": limit,
            "unlimited": limit is None,
            "remaining": (max(0, limit - used) if limit is not None else None),
            "cap_reached": (limit is not None and used >= limit),
        }
    finally:
        if own:
            conn.close()


def _recent_call_count(now=None, window_seconds=3600):
    now = now or time.time()
    cutoff = now - window_seconds
    while _recent_call_times and _recent_call_times[0] < cutoff:
        _recent_call_times.pop(0)
    return len(_recent_call_times)


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


# --------------------------------------------------
# LIVE CLIENT
# --------------------------------------------------

def _ioc_segment(indicator_type, indicator_value):

    if indicator_type == "IP":

        try:
            import ipaddress
            version = ipaddress.ip_address(indicator_value).version
        except ValueError:
            return None

        return "IPv4" if version == 4 else "IPv6"

    return _IOC_TYPE_SEGMENT.get(indicator_type)


def _parse_otx_response(response_json):

    pulse_info = response_json.get("pulse_info")

    if not isinstance(pulse_info, dict) or "count" not in pulse_info:
        return {"lookup_status": "ERROR", "summary": "OTX response missing usable pulse_info."}

    try:
        count = int(pulse_info.get("count") or 0)
    except (TypeError, ValueError):
        return {"lookup_status": "ERROR", "summary": "OTX pulse_info.count was not a number."}

    if count <= 0:
        return {"lookup_status": "NO_MATCH"}

    pulses = pulse_info.get("pulses")
    names = []

    if isinstance(pulses, list):
        for pulse in pulses[:3]:
            if isinstance(pulse, dict) and pulse.get("name"):
                names.append(str(pulse["name"])[:80])

    return {
        "lookup_status": "MATCH",
        "threat_type": "pulse_match",
        "confidence_level": None,
        "tags": None,
        "summary": f"AlienVault OTX: referenced by {count} Pulse(s)" + (f" ({'; '.join(names)})" if names else "") + ".",
    }


def query_otx_live(indicator_type, indicator_value):

    segment = _ioc_segment(indicator_type, indicator_value)

    if segment is None:
        return {"lookup_status": "ERROR", "summary": "Unsupported OTX indicator type."}

    if not OTX_API_KEY and _recent_call_count() >= _KEYLESS_MAX_CALLS_PER_HOUR:
        # Self-imposed guard, not a provider error: protects the shared
        # keyless quota. Treated as a transient backoff, not a hard error.
        return {"lookup_status": "RATE_LIMITED", "summary": "Local keyless-quota guard engaged (no OTX_API_KEY configured)."}

    headers = {}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY

    url = f"{OTX_API_BASE}{segment}/{indicator_value}/general"

    try:

        _record_call()

        # verify defaults to True (requests' own normal, portable,
        # certifi-based behavior) unless an operator has explicitly
        # configured OTX_CA_BUNDLE - never verify=False, never disabled.
        response = requests.get(
            url, headers=headers, timeout=OTX_HTTP_TIMEOUT_SECONDS,
            verify=(OTX_CA_BUNDLE or True)
        )

        if response.status_code == 404:
            return {"lookup_status": "NO_MATCH"}

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "OTX authentication failed."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"OTX returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "OTX returned invalid JSON."}

        return _parse_otx_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "OTX request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "OTX connection error."}


# --------------------------------------------------
# CACHE
# --------------------------------------------------

def get_otx_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        # Step 17 total-call cap - only engages when OTX_MAX_TOTAL_CALLS
        # is explicitly set (default: no effect at all, identical to
        # before this change). Checked BEFORE the network call; does not
        # itself count against the cap.
        if OTX_MAX_TOTAL_CALLS is not None and _otx_total_calls_used(conn) >= OTX_MAX_TOTAL_CALLS:
            live_result = {
                "lookup_status": "RATE_LIMITED",
                "summary": f"Local total-call cap engaged ({OTX_MAX_TOTAL_CALLS} total calls configured).",
            }
            return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

        try:
            live_result = query_otx_live(indicator_type, indicator_value)
            if OTX_MAX_TOTAL_CALLS is not None:
                # A real network attempt was made (cap not yet reached) -
                # count it regardless of outcome, same discipline as the
                # IPQualityScore monthly quota guard.
                _otx_total_calls_increment(conn)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {"lookup_status": "ERROR", "summary": "Unexpected OTX integration error."}
            if OTX_MAX_TOTAL_CALLS is not None:
                _otx_total_calls_increment(conn)

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
