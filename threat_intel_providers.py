# ==================================================
# PHASE 11D.1: THREATFOX EXTERNAL THREAT INTELLIGENCE
# (PHASE 12B.1: refactored into a thin adapter on top of the
#  provider-neutral threat_intel_framework.py - observable behavior is
#  unchanged; this module now delegates its cache/TTL/normalization
#  plumbing to the shared framework instead of duplicating it.)
# ==================================================
#
# Contextual evidence ONLY. Nothing in this file reads or writes
# web_events.risk_score/severity/decision, security_alerts,
# security_events, response_commands, or any Behavioral Baseline
# table. A ThreatFox failure of any kind must never affect Threat
# Risk, Alert/Incident policy, or endpoint ingestion.
#
# API contract verified against the official documentation at
# https://threatfox.abuse.ch/api/ and the reference client at
# https://github.com/abusech/ThreatFox/blob/main/threatfox_search_ioc.py
# (fetched at implementation time - not guessed):
#   POST https://threatfox-api.abuse.ch/api/v1/
#   header: Auth-Key: <key>
#   body:   {"query": "search_ioc", "search_term": <value>,
#            "exact_match": true|false}
#   response: {"query_status": "ok", "data": [ {id, ioc, ioc_type,
#              threat_type, malware, malware_printable,
#              confidence_level, first_seen, last_seen, tags,
#              reporter}, ... ]}
#
# IMPORTANT VERIFIED NUANCE: ThreatFox indexes IP indicators as
# "ip:port" strings (ioc_type "ip:port"), never a bare IP. Our
# telemetry only ever has a bare resolved_ip (no port). An
# exact_match=true search on the bare IP would therefore under-
# match real ThreatFox IP entries. To avoid this false-negative
# without inventing a port, IP lookups use exact_match=false (the
# provider's own broader search) and then this module applies its
# OWN deterministic exact-match filter client-side: only records
# whose "ioc" field, split on ":", has the IP portion equal to the
# queried IP are accepted as a match. This preserves exact-match
# semantics (never a fuzzy/substring "looks similar" match) while
# correctly handling the documented ip:port storage format. DOMAIN
# and SHA256 lookups use the provider's own exact_match=true
# directly, since their ioc_type values ("domain", "sha256_hash")
# have no such ambiguity.
#
# RECORD SELECTION RULE (when multiple records match): sort by
# last_seen (nullable) descending, falling back to first_seen
# descending for records with no last_seen, and take the single
# most-recently-active record. This is deterministic and documented
# here exactly as required - never "data[0]" blindly.
# ==================================================

import json
import os
import db_config
import sqlite3

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework
import provider_health

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


# --------------------------------------------------
# DB (same SOC_DB_PATH override convention as every other module)
# --------------------------------------------------

_soc_db_path_override = os.getenv("SOC_DB_PATH", "").strip()

if _soc_db_path_override:
    if os.path.isabs(_soc_db_path_override):
        DB_NAME = _soc_db_path_override
    else:
        DB_NAME = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            _soc_db_path_override
        )
else:
    DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersec.db")


def get_db_connection():

    # Phase 12B.6C.1: central policy (WAL, busy timeout, synchronous=FULL,
    # tracked so a request/iteration can always release it).
    return db_config.open_connection(DB_NAME)


# --------------------------------------------------
# CONFIG (never logged/rendered - only presence is ever checked)
# --------------------------------------------------

THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", "").strip()

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

THREATFOX_HTTP_TIMEOUT_SECONDS = 10

# Centralized TTL constants - kept here byte-for-byte for backward
# compatibility (nothing external reads these directly today), but the
# ACTUAL TTL lookup now happens through framework.PROVIDER_TTL_CONFIG,
# which holds these same values under provider key "threatfox".
THREATFOX_MATCH_TTL_HOURS = 24
THREATFOX_NO_MATCH_TTL_HOURS = 12
THREATFOX_ERROR_RETRY_MINUTES = 15
THREATFOX_RATE_LIMITED_RETRY_MINUTES = 30

SHA256_PATTERN = framework.SHA256_PATTERN

PROVIDER_NAME = "threatfox"

# Thin re-exports of the shared logger/suppression state so existing
# code/tests referencing threat_intel_providers._logger keep working
# unchanged. The actual suppression bookkeeping now lives in the
# framework (generalized to be provider-keyed).
_logger = framework._logger
_LOG_SUPPRESS_SECONDS = framework._LOG_SUPPRESS_SECONDS
_last_logged_failure = framework._last_logged_failure


def _log_lookup_error(indicator_type, exc):

    # Preserves the exact original signature/behavior - delegates to the
    # generalized, provider-parameterized framework logger with
    # provider="threatfox" fixed. Sanitized, operational-context-only
    # logging: never logs the API key, request headers, or full response
    # body - only provider name, indicator type, and the exception's
    # class name.
    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


# --------------------------------------------------
# SCHEMA (additive only - unchanged from Phase 11D.1)
# --------------------------------------------------

def init_threat_intel_db():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            lookup_status TEXT NOT NULL,
            threat_type TEXT,
            malware_family TEXT,
            confidence_level INTEGER,
            tags TEXT,
            first_seen TEXT,
            last_seen TEXT,
            summary TEXT,
            retrieved_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            UNIQUE(provider, indicator_type, indicator_value)
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_threat_intel_evidence_lookup
        ON threat_intel_evidence(provider, indicator_type, indicator_value)
    """)

    # Phase 12B.3: additive nullable column used only by VirusTotal.
    framework.ensure_evidence_schema(conn)

    conn.commit()
    conn.close()


# --------------------------------------------------
# INDICATOR NORMALIZATION / VALIDATION
# Thin wrappers over the centralized framework implementations - kept as
# module-level functions here (same names) so no caller needs to change.
# --------------------------------------------------

def normalize_ip_candidate(resolved_ip):

    return framework.normalize_ip_candidate(resolved_ip)


def normalize_domain_candidate(domain):

    return framework.normalize_domain_candidate(domain)


def normalize_sha256_candidate(sha256):

    return framework.normalize_sha256_candidate(sha256)


# --------------------------------------------------
# TTL HELPERS
# --------------------------------------------------

def _ttl_for_status(lookup_status):

    # Delegates to the provider-keyed framework registry, which holds
    # ThreatFox's four values byte-equivalent to the original constants
    # above (MATCH 24h / NO_MATCH 12h / ERROR 15min / RATE_LIMITED 30min).
    return framework.get_ttl(PROVIDER_NAME, lookup_status)


# --------------------------------------------------
# LIVE CLIENT
# --------------------------------------------------

def _select_best_record(records):

    # Deterministic selection rule (documented at module top):
    # most-recently-active record wins - last_seen descending
    # (nulls last), tie/fallback broken by first_seen descending.
    def sort_key(record):

        last_seen = record.get("last_seen") or ""
        first_seen = record.get("first_seen") or ""

        return (last_seen, first_seen)

    return sorted(records, key=sort_key, reverse=True)[0]


def _parse_threatfox_response(response_json, indicator_type, queried_value):

    query_status = response_json.get("query_status")

    data = response_json.get("data")

    if query_status == "ok" and data:

        if indicator_type == "IP":

            # Client-side exact-match filter for the documented
            # ip:port storage format (see module docstring).
            matching = [
                record for record in data
                if str(record.get("ioc", "")).split(":")[0] == queried_value
            ]

            if not matching:
                return {"lookup_status": "NO_MATCH"}

            best = _select_best_record(matching)

        else:

            best = _select_best_record(data)

        return {
            "lookup_status": "MATCH",
            "threat_type": best.get("threat_type"),
            "malware_family": best.get("malware_printable") or best.get("malware"),
            "confidence_level": best.get("confidence_level"),
            "tags": json.dumps(best.get("tags")) if best.get("tags") else None,
            "first_seen": best.get("first_seen"),
            "last_seen": best.get("last_seen"),
            "summary": (
                f"{best.get('threat_type') or 'unknown threat type'} "
                f"({best.get('malware_printable') or best.get('malware') or 'unknown family'})"
            )
        }

    # "no_result" is the documented empty-result status for the
    # abuse.ch API family; treated generically alongside "ok" with
    # an empty data array, so a minor wording difference between
    # API versions can never be misread as an error.
    if query_status == "no_result" or (query_status == "ok" and not data):
        return {"lookup_status": "NO_MATCH"}

    # Any other/unrecognized query_status (e.g. "illegal_search_term")
    # is an unexpected provider response - ERROR, never NO_MATCH.
    return {
        "lookup_status": "ERROR",
        "summary": f"Unexpected ThreatFox query_status: {query_status!r}"
    }


def query_threatfox_live(indicator_type, indicator_value):

    if not THREATFOX_API_KEY:

        return {
            "lookup_status": "ERROR",
            "summary": "ThreatFox API key is not configured."
        }

    exact_match = indicator_type != "IP"

    try:

        response = requests.post(
            THREATFOX_API_URL,
            json={
                "query": "search_ioc",
                "search_term": indicator_value,
                "exact_match": exact_match
            },
            headers={"Auth-Key": THREATFOX_API_KEY},
            timeout=THREATFOX_HTTP_TIMEOUT_SECONDS
        )

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {
                "lookup_status": "ERROR",
                "summary": "ThreatFox authentication failed."
            }

        if response.status_code != 200:
            return {
                "lookup_status": "ERROR",
                "summary": f"ThreatFox returned HTTP {response.status_code}."
            }

        try:
            response_json = response.json()
        except ValueError:
            return {
                "lookup_status": "ERROR",
                "summary": "ThreatFox returned invalid JSON."
            }

        return _parse_threatfox_response(
            response_json, indicator_type, indicator_value
        )

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "ThreatFox request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "ThreatFox connection error."}


# --------------------------------------------------
# CACHE (delegates to the generalized framework cache layer, parameterized
# with provider="threatfox" - never reads threat_reputation /
# reputation_source; storage/TTL/upsert behavior is unchanged)
# --------------------------------------------------

def get_threatfox_evidence(indicator_type, indicator_value):

    conn = get_db_connection()

    try:

        cached = framework.get_cached_evidence(
            conn, PROVIDER_NAME, indicator_type, indicator_value
        )

        if cached is not None:
            return cached

        try:
            live_result = query_threatfox_live(indicator_type, indicator_value)
        except Exception as exc:
            # Unexpected programming exception - sanitized, non-
            # fatal logging (correction #7), never a silent
            # `except Exception: pass`.
            _log_lookup_error(indicator_type, exc)
            live_result = {
                "lookup_status": "ERROR",
                "summary": "Unexpected ThreatFox integration error."
            }

        return framework.store_evidence(
            conn, PROVIDER_NAME, indicator_type, indicator_value, live_result
        )

    finally:
        conn.close()


# --------------------------------------------------
# EVENT-LEVEL HELPERS (no per-event row - lookup by indicator only)
# --------------------------------------------------

def candidate_indicators_for_event(resolved_ip, domain, sha256):

    candidates = []

    normalized_ip = normalize_ip_candidate(resolved_ip)
    if normalized_ip:
        candidates.append(("IP", normalized_ip))

    normalized_domain = normalize_domain_candidate(domain)
    if normalized_domain:
        candidates.append(("DOMAIN", normalized_domain))

    normalized_sha256 = normalize_sha256_candidate(sha256)
    if normalized_sha256:
        candidates.append(("SHA256", normalized_sha256))

    return candidates


def lookup_threatfox_for_event(resolved_ip, domain, sha256):

    # Called by the worker (writes/refreshes cache) AND by
    # rendering code (reads only, via get_stored_evidence_for_event
    # below) - this function performs live lookups (subject to the
    # cache), so it belongs on the WRITE side only.
    #
    # Stage 25D section 13: ThreatFox is the one provider called
    # automatically from a THIRD separate OS process (web_event_worker.py
    # calls this function inline - see the module header's migration
    # decision), distinct from both threat_intel_worker.py and a manual
    # /threat-intel re-check. The single-flight lock is acquired here
    # (not inside get_threatfox_evidence() itself) because
    # threat_intel_display.force_recheck() already holds this exact
    # lock for the duration of ITS OWN call into get_threatfox_evidence()
    # - locking again inside that shared function would self-deadlock
    # the manual re-check path. A lock-layer failure must never block
    # real enrichment (fails open).
    results = {}

    for indicator_type, indicator_value in candidate_indicators_for_event(
        resolved_ip, domain, sha256
    ):
        try:
            got_lock = provider_health.acquire_lookup_lock(PROVIDER_NAME, indicator_type, indicator_value)
        except Exception:
            got_lock = True

        if not got_lock:
            continue

        try:
            results[(indicator_type, indicator_value)] = get_threatfox_evidence(
                indicator_type, indicator_value
            )
        finally:
            try:
                provider_health.release_lookup_lock(PROVIDER_NAME, indicator_type, indicator_value)
            except Exception:
                pass

    return results


def get_stored_evidence_for_event(resolved_ip, domain, sha256):

    # READ-ONLY: looks up whatever threat_intel_evidence rows
    # currently exist for this event's candidate indicators -
    # never performs a live lookup, never writes. Used by
    # Web Monitoring / Alert Details / Security Analytics
    # rendering code. A candidate with NO stored row is reported
    # as such (never fabricated as NO_MATCH) - see
    # candidate_indicators_for_event() callers.

    conn = get_db_connection()

    try:

        evidence = []

        for indicator_type, indicator_value in candidate_indicators_for_event(
            resolved_ip, domain, sha256
        ):

            row = conn.execute("""
                SELECT * FROM threat_intel_evidence
                WHERE provider = ? AND indicator_type = ? AND indicator_value = ?
            """, (PROVIDER_NAME, indicator_type, indicator_value)).fetchone()

            if row is not None:
                evidence.append(dict(row))
            else:
                evidence.append({
                    "provider": PROVIDER_NAME,
                    "indicator_type": indicator_type,
                    "indicator_value": indicator_value,
                    "lookup_status": "NO_STORED_EVIDENCE"
                })

        return evidence

    finally:
        conn.close()
