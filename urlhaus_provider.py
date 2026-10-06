# ==================================================
# PHASE 12B.2: URLHAUS EXTERNAL THREAT INTELLIGENCE
# ==================================================
#
# Contextual evidence ONLY, exactly like the ThreatFox adapter this
# module mirrors (threat_intel_providers.py). Nothing here reads or
# writes web_events.risk_score/severity/decision, security_alerts,
# security_events, response_commands, or any Behavioral Baseline table.
# A URLhaus failure of any kind must never affect Threat Risk,
# Alert/Incident policy, or endpoint ingestion. A URLhaus MATCH means
# only "this host/payload is represented in URLhaus threat
# intelligence" - never "endpoint infected" or "computer compromised".
#
# API contract verified against the official documentation at
# https://urlhaus-api.abuse.ch/ (fetched at implementation time - not
# guessed):
#   Base URL: https://urlhaus-api.abuse.ch/v1/
#   Auth: header "Auth-Key: <key>" required on every endpoint used here
#     (same abuse.ch Auth-Key infrastructure as ThreatFox).
#
#   POST /host/   body: host=<IPv4 or domain>
#     query_status: ok | no_results | invalid_host | http_post_expected
#     on "ok": urlhaus_reference, host, firstseen, url_count,
#       blacklists, urls[] (each: id, url, url_status, date_added,
#       threat, tags, ...)
#
#   POST /payload/   body: sha256_hash=<hash>  OR  md5_hash=<hash>
#     query_status: ok | no_results | invalid_sha256 | invalid_md5 |
#       http_post_expected
#     on "ok": md5_hash, sha256_hash, file_type, file_size, signature,
#       firstseen, lastseen, url_count, ...
#
# ROUTING: IP and DOMAIN candidates use /host/ (host lookup). SHA256
# and MD5 candidates use /payload/ (payload lookup). URL lookup is
# deliberately NOT implemented - this project does not reliably collect
# full URLs, and a URL must never be fabricated from a domain.
#
# HTTP-level handling mirrors ThreatFox's own conventions (same
# abuse.ch Auth-Key auth backend, so the same status-code behavior is a
# reasonable, documented assumption - not guessed from nothing):
# 429 -> RATE_LIMITED, 401/403 -> ERROR ("authentication failed"),
# any other non-200 -> ERROR, timeout/connection error -> ERROR,
# malformed JSON -> ERROR.
#
# RECORD SELECTION RULE for /host/ (multiple urls[] entries possible):
# identical to ThreatFox's rule - sort by date_added descending, take
# the single most-recently-added URL entry. /payload/ has no such
# array to select from (one record per hash).
# ==================================================

import json
import os

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


# --------------------------------------------------
# CONFIG (never logged/rendered - only presence is ever checked)
# --------------------------------------------------

URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "").strip()

URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_PAYLOAD_URL = "https://urlhaus-api.abuse.ch/v1/payload/"

URLHAUS_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "urlhaus"


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


# --------------------------------------------------
# LIVE CLIENT
# --------------------------------------------------

def _select_best_host_url(urls):

    def sort_key(record):
        return record.get("date_added") or ""

    return sorted(urls, key=sort_key, reverse=True)[0]


def _parse_host_response(response_json):

    query_status = response_json.get("query_status")

    if query_status == "ok":

        url_count = response_json.get("url_count")
        urls = response_json.get("urls") or []

        best_url = _select_best_host_url(urls) if urls else None

        threat_type = best_url.get("threat") if best_url else None
        tags = best_url.get("tags") if best_url else None
        # URLhaus /host/ has no dedicated "last seen" field for the host
        # itself - the most recently added URL's own date_added is real
        # returned data, reused here as the best available "most recent
        # known activity" fact (never fabricated).
        last_seen = best_url.get("date_added") if best_url else None

        summary_parts = [f"URLhaus host listing: {url_count or 0} URL(s) on record"]
        if threat_type:
            summary_parts.append(f"most recent threat type: {threat_type}")

        return {
            "lookup_status": "MATCH",
            "threat_type": threat_type,
            "malware_family": None,
            "confidence_level": None,
            "tags": json.dumps(tags) if tags else None,
            "first_seen": response_json.get("firstseen"),
            "last_seen": last_seen,
            "summary": ", ".join(summary_parts)
        }

    if query_status in ("no_results",):
        return {"lookup_status": "NO_MATCH", "summary": "No URLhaus match found."}

    if query_status == "invalid_host":
        # Should not occur - our own normalization already validates
        # the value before sending. Treated as ERROR, never NO_MATCH.
        return {
            "lookup_status": "ERROR",
            "summary": "URLhaus rejected the host value as invalid."
        }

    return {
        "lookup_status": "ERROR",
        "summary": f"Unexpected URLhaus query_status: {query_status!r}"
    }


def _parse_payload_response(response_json):

    query_status = response_json.get("query_status")

    if query_status == "ok":

        signature = response_json.get("signature")
        file_type = response_json.get("file_type")
        url_count = response_json.get("url_count")

        return {
            "lookup_status": "MATCH",
            "threat_type": None,
            "malware_family": signature,
            "confidence_level": None,
            "tags": None,
            "first_seen": response_json.get("firstseen"),
            "last_seen": response_json.get("lastseen"),
            "summary": (
                f"URLhaus payload listing: signature={signature or 'unknown'}, "
                f"file_type={file_type or 'unknown'}, url_count={url_count or 0}"
            )
        }

    if query_status in ("no_results",):
        return {"lookup_status": "NO_MATCH", "summary": "No URLhaus match found."}

    if query_status in ("invalid_sha256", "invalid_md5"):
        return {
            "lookup_status": "ERROR",
            "summary": "URLhaus rejected the hash value as invalid."
        }

    return {
        "lookup_status": "ERROR",
        "summary": f"Unexpected URLhaus query_status: {query_status!r}"
    }


def query_urlhaus_live(indicator_type, indicator_value):

    # Capability first (Phase 12B.2B): e.g. IPv6 is not accepted by
    # URLhaus /host/ - decided from the provider registry, never from an
    # HTTP round-trip.
    if not framework.provider_supports_indicator(PROVIDER_NAME, indicator_type, indicator_value):
        return {"lookup_status": "NOT_SUPPORTED"}

    if not URLHAUS_API_KEY:

        return {
            "lookup_status": "NOT_CONFIGURED",
            "summary": "URLhaus API key is not configured."
        }

    if indicator_type in ("IP", "DOMAIN"):
        url = URLHAUS_HOST_URL
        body = {"host": indicator_value}
    elif indicator_type == "SHA256":
        url = URLHAUS_PAYLOAD_URL
        body = {"sha256_hash": indicator_value}
    elif indicator_type == "MD5":
        url = URLHAUS_PAYLOAD_URL
        body = {"md5_hash": indicator_value}
    else:
        return {"lookup_status": "NOT_SUPPORTED"}

    try:

        response = requests.post(
            url,
            data=body,
            headers={"Auth-Key": URLHAUS_API_KEY},
            timeout=URLHAUS_HTTP_TIMEOUT_SECONDS
        )

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {
                "lookup_status": "ERROR",
                "summary": "URLhaus authentication failed."
            }

        if response.status_code != 200:
            return {
                "lookup_status": "ERROR",
                "summary": f"URLhaus returned HTTP {response.status_code}."
            }

        try:
            response_json = response.json()
        except ValueError:
            return {
                "lookup_status": "ERROR",
                "summary": "URLhaus returned invalid JSON."
            }

        if indicator_type in ("IP", "DOMAIN"):
            return _parse_host_response(response_json)

        return _parse_payload_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "URLhaus request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "URLhaus connection error."}


# --------------------------------------------------
# CACHE (delegates to the generalized framework cache layer, parameterized
# with provider="urlhaus" - never reads threat_reputation / ThreatFox's
# own rows; storage/TTL/upsert behavior lives entirely in the framework)
# --------------------------------------------------

def get_urlhaus_evidence(indicator_type, indicator_value, conn=None):

    # Provider eligibility takes precedence over everything, including the
    # cache: a historical row for an indicator URLhaus can no longer be
    # asked about (e.g. the IPv6 ERROR rows written before Phase 12B.2B)
    # is neither served nor refreshed - zero HTTP, nothing persisted.
    if not framework.provider_supports_indicator(PROVIDER_NAME, indicator_type, indicator_value):
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

        cached = framework.get_cached_evidence(
            conn, PROVIDER_NAME, indicator_type, indicator_value
        )

        if cached is not None:
            return cached

        try:
            live_result = query_urlhaus_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {
                "lookup_status": "ERROR",
                "summary": "Unexpected URLhaus integration error."
            }

        # NOT_CONFIGURED / NOT_SUPPORTED are routing-level short-circuits,
        # not real provider responses - never cached/persisted (mirrors
        # the framework's PERSISTABLE_LOOKUP_STATUSES distinction).
        if live_result.get("lookup_status") not in framework.PERSISTABLE_LOOKUP_STATUSES:
            result = dict(live_result)
            result["provider"] = PROVIDER_NAME
            result["indicator_type"] = indicator_type
            result["indicator_value"] = indicator_value
            result["source"] = "ROUTING"
            return result

        return framework.store_evidence(
            conn, PROVIDER_NAME, indicator_type, indicator_value, live_result
        )

    finally:
        if owns_conn:
            conn.close()
