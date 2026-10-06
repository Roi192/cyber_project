# ==================================================
# PHASE 12B.3: VIRUSTOTAL NORMALIZED EVIDENCE PROVIDER
# ==================================================
#
# CONTEXT / CORROBORATION ONLY. Nothing here reads or writes
# web_events.risk_score/severity/decision, security_alerts,
# security_events, response_commands, or any Behavioral Baseline table.
# Normalized VirusTotal evidence adds ZERO Threat Risk points and never
# creates an Alert, Incident or Response Command.
#
# The LEGACY VirusTotal IP integration (threat_intelligence.
# check_virustotal -> reputation cache -> calculate_threat_risk) is
# authoritative for Threat Risk and is not modified by this module.
#
# API: VirusTotal API v3, header "x-apikey" (env var VT_API_KEY - the
# SAME variable the legacy path already uses). Report retrieval only:
#   GET /api/v3/domains/{domain}
#   GET /api/v3/files/{sha256-or-md5}     (report BY HASH - no file is
#                                          ever uploaded or downloaded)
# NEVER used: file upload, URL submission, rescan/analyse, download,
# generic search.
#
# --------------------------------------------------
# IP EVIDENCE: NO SECOND REQUEST (the key architecture rule)
# --------------------------------------------------
# Every public IP the platform sees is already looked up by the legacy
# cache-first reputation path. So this module NEVER makes an HTTP request
# for an IP indicator. Instead, record_legacy_ip_result() derives the
# normalized evidence from the result the legacy path has ALREADY
# fetched (called from reputation_routes.save_reputation_result, which
# only runs after a live legacy lookup). The legacy cache table itself is
# deliberately NOT used as a source: it has no "VT was actually
# available" flag, so a failed lookup is stored as all-zero counts that
# are indistinguishable from a genuine zero-detection report.
#
# --------------------------------------------------
# SHARED-QUOTA SAFETY
# --------------------------------------------------
# The legacy path uses the SAME API key and is unthrottled, so this
# module must never let normalized enrichment starve it (that would
# silently degrade legacy Threat Risk). Defaults are safe for the Public
# API (4 requests/min, 500/day):
#   VT_MAX_CALLS_PER_MINUTE = 3     (stays below 4)
#   VT_MAX_CALLS_PER_DAY    = 450   (stays below 500)
#   VT_COUNT_LEGACY_USAGE   = 1     (legacy lookups, read from
#                                    threat_reputation.checked_at: ALL of them
#                                    in the minute window, successful ones
#                                    in the daily window)
# A licensed higher quota is supported by raising those variables; this
# module never rotates keys or otherwise tries to defeat a limit.
# Non-secret quota state (a ledger of live calls + a 429 back-off
# timestamp) is persisted so a worker restart cannot reset the accounting.
# ==================================================

import json
import os
import sqlite3
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


# --------------------------------------------------
# CONFIG (key is never logged/rendered - only its presence is checked)
# --------------------------------------------------

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

VT_BASE_URL = "https://www.virustotal.com/api/v3/"

VT_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "virustotal"

DEFAULT_MAX_CALLS_PER_MINUTE = 3
DEFAULT_MAX_CALLS_PER_DAY = 450

# Back-off after an HTTP 429 when no sane Retry-After header is present.
DEFAULT_429_BACKOFF_SECONDS = 300
MAX_RETRY_AFTER_SECONDS = 3600

BACKOFF_STATE_KEY = "virustotal_backoff_until"

_TS_FORMAT = "%Y-%m-%d %H:%M:%S"

IP_DERIVED_NOTE = (
    "VirusTotal IP evidence is derived from the legacy reputation lookup; "
    "no separate request is made."
)


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


def _int_env(name, default):

    try:
        value = int(os.getenv(name, "").strip())
    except ValueError:
        return default

    return value if value >= 1 else default


def max_calls_per_minute():
    return _int_env("VT_MAX_CALLS_PER_MINUTE", DEFAULT_MAX_CALLS_PER_MINUTE)


def max_calls_per_day():
    return _int_env("VT_MAX_CALLS_PER_DAY", DEFAULT_MAX_CALLS_PER_DAY)


def count_legacy_usage():
    return os.getenv("VT_COUNT_LEGACY_USAGE", "1").strip() != "0"


# --------------------------------------------------
# QUOTA STATE (non-secret, additive)
# --------------------------------------------------

def ensure_quota_schema(conn):

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_call_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            called_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_threat_intel_call_log_lookup
        ON threat_intel_call_log(provider, called_at)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_worker_state (
            config_key TEXT PRIMARY KEY,
            config_value TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()


# In-memory record of every attempt made in the last minute, INCLUDING
# ones that failed before reaching VirusTotal (e.g. a TLS failure) - those
# consume no provider quota and are not in the persisted ledger, but the
# worker must still never hammer a failing endpoint.
_recent_attempts = deque()


def _note_attempt(now=None):

    now = now or time.time()
    _recent_attempts.append(now)
    _prune_attempts(now)


def _prune_attempts(now):

    while _recent_attempts and now - _recent_attempts[0] >= 60:
        _recent_attempts.popleft()


def record_live_call(now=None):

    # Persist one row for a request that actually reached VirusTotal (any
    # HTTP response, or a read timeout). Bounded: rows older than 2 days
    # of this module's OWN ledger are pruned. A ledger failure must never
    # break a lookup.
    now = now or datetime.now()

    try:
        conn = framework.get_db_connection()
        try:
            ensure_quota_schema(conn)
            conn.execute(
                "INSERT INTO threat_intel_call_log (provider, called_at) VALUES (?, ?)",
                (PROVIDER_NAME, now.strftime(_TS_FORMAT))
            )
            conn.execute(
                "DELETE FROM threat_intel_call_log WHERE provider = ? AND called_at < ?",
                (PROVIDER_NAME, (now - timedelta(days=2)).strftime(_TS_FORMAT))
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        _log_lookup_error("LEDGER", exc)


def _ledger_count(conn, since):

    try:
        return conn.execute(
            "SELECT COUNT(*) FROM threat_intel_call_log WHERE provider = ? AND called_at >= ?",
            (PROVIDER_NAME, since.strftime(_TS_FORMAT))
        ).fetchone()[0]
    except sqlite3.OperationalError:
        return 0


def _legacy_count(conn, since, successful_only):

    # LEGACY VirusTotal lookups (same key, same quota), read-only.
    #   successful_only=True : rows with a real VT count = genuine
    #       responses that certainly consumed quota (used for the DAILY
    #       budget - counting failed lookups there would wrongly starve
    #       normalized enrichment for a whole day after an outage ends).
    #   successful_only=False: EVERY legacy lookup row, any outcome (used
    #       for the short MINUTE window - the legacy path is unthrottled
    #       and bursts, so a recent failure may have been a rate-limited
    #       request that still counts against VirusTotal's per-minute cap;
    #       being conservative here is what protects the authoritative
    #       legacy Threat Risk path from being starved, and it costs at
    #       most 60 seconds of normalized throughput).
    # Any failure -> 0.
    if not count_legacy_usage():
        return 0

    query = "SELECT COUNT(*) FROM threat_reputation WHERE checked_at >= ?"

    if successful_only:
        query += """
              AND (vt_malicious > 0 OR vt_suspicious > 0
                   OR vt_harmless > 0 OR vt_undetected > 0)"""

    try:
        return conn.execute(query, (since.strftime(_TS_FORMAT),)).fetchone()[0]
    except sqlite3.OperationalError:
        return 0


def get_backoff_until(conn):

    try:
        row = conn.execute(
            "SELECT config_value FROM threat_intel_worker_state WHERE config_key = ?",
            (BACKOFF_STATE_KEY,)
        ).fetchone()
    except sqlite3.OperationalError:
        return None

    if row is None:
        return None

    try:
        return datetime.strptime(row[0], _TS_FORMAT)
    except (TypeError, ValueError):
        return None


def set_backoff(seconds, now=None):

    now = now or datetime.now()
    until = (now + timedelta(seconds=seconds)).strftime(_TS_FORMAT)

    try:
        conn = framework.get_db_connection()
        try:
            ensure_quota_schema(conn)
            conn.execute("""
                INSERT INTO threat_intel_worker_state (config_key, config_value, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value
            """, (BACKOFF_STATE_KEY, until, now.strftime(_TS_FORMAT)))
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        _log_lookup_error("BACKOFF", exc)


def get_quota_state(conn, now=None):

    # Pure accounting from persisted state (+ the in-memory attempt
    # window). "allowance" is how many more live calls may be started
    # right now; it is 0 while a 429 back-off is active.
    now = now or datetime.now()
    _prune_attempts(now.timestamp())

    minute_limit = max_calls_per_minute()
    day_limit = max_calls_per_day()

    ledger_minute = _ledger_count(conn, now - timedelta(seconds=60))
    ledger_day = _ledger_count(conn, now - timedelta(hours=24))

    legacy_minute = _legacy_count(conn, now - timedelta(seconds=60), successful_only=False)
    legacy_day = _legacy_count(conn, now - timedelta(hours=24), successful_only=True)

    # In-memory attempts and the ledger describe the same calls from two
    # angles; max() avoids double counting while still covering both
    # "attempt that never reached VT" and "restart wiped memory".
    minute_used = legacy_minute + max(len(_recent_attempts), ledger_minute)
    day_used = legacy_day + ledger_day

    backoff_until = get_backoff_until(conn)
    backing_off = backoff_until is not None and now < backoff_until

    allowance = 0 if backing_off else max(0, min(minute_limit - minute_used, day_limit - day_used))

    return {
        "minute_limit": minute_limit,
        "day_limit": day_limit,
        "minute_used": minute_used,
        "day_used": day_used,
        "legacy_minute": legacy_minute,
        "legacy_day": legacy_day,
        "backoff_until": backoff_until,
        "backing_off": backing_off,
        "allowance": allowance,
    }


# --------------------------------------------------
# RESPONSE NORMALIZATION
# --------------------------------------------------

def _epoch_to_text(value):

    # VirusTotal returns dates as Unix epoch seconds. Rendered UTC and
    # labelled as such (matches URLhaus's "... UTC" convention).
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None

    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime(_TS_FORMAT) + " UTC"
    except (OverflowError, OSError, ValueError):
        return None


def build_summary(stats):

    if stats["malicious"] > 0 or stats["suspicious"] > 0:
        headline = (
            f"VirusTotal analysis: {stats['malicious']} engine(s) malicious, "
            f"{stats['suspicious']} suspicious."
        )
    else:
        headline = (
            "VirusTotal analysis: 0 malicious, 0 suspicious detections in "
            "the latest available analysis."
        )

    return (
        f"{headline} Other engines: {stats['harmless']} harmless, "
        f"{stats['undetected']} undetected, {stats['timeout']} timeout."
    )


def _error(summary):
    return {"lookup_status": "ERROR", "summary": summary, "analysis_stats": None}


def _parse_report(response_json):

    # 200 response -> normalized fields. Anything that is not a report
    # object with usable last_analysis_stats is an ERROR, never a match.
    if not isinstance(response_json, dict):
        return _error("VirusTotal returned an unexpected response.")

    data = response_json.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    raw_stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None

    if not isinstance(raw_stats, dict) or not raw_stats:
        return _error("VirusTotal returned a report without analysis statistics.")

    stats = framework.parse_analysis_stats(raw_stats)

    if stats is None:
        return _error("VirusTotal returned an unexpected response.")

    tags = attributes.get("tags")
    tags_json = None
    if isinstance(tags, list):
        clean = [t[:64] for t in tags if isinstance(t, str)][:10]
        tags_json = json.dumps(clean) if clean else None

    # Provider-supplied classification fields only - null when absent.
    threat_type = None
    malware_family = None
    ptc = attributes.get("popular_threat_classification")
    if isinstance(ptc, dict):
        label = ptc.get("suggested_threat_label")
        threat_type = label[:120] if isinstance(label, str) and label else None
        names = ptc.get("popular_threat_name")
        if isinstance(names, list) and names and isinstance(names[0], dict):
            value = names[0].get("value")
            malware_family = value[:120] if isinstance(value, str) and value else None

    return {
        "lookup_status": "MATCH",
        "threat_type": threat_type,
        "malware_family": malware_family,
        "confidence_level": None,
        "tags": tags_json,
        "first_seen": _epoch_to_text(attributes.get("first_submission_date")),
        "last_seen": _epoch_to_text(attributes.get("last_analysis_date")),
        "summary": build_summary(stats),
        "analysis_stats": stats,
    }


def _valid_value(indicator_type, indicator_value):

    # The exact value must already be in canonical normalized form - a
    # malformed hash / non-routable or malformed domain is never sent.
    if not isinstance(indicator_value, str):
        return False

    if indicator_type == "DOMAIN":
        return framework.normalize_domain_candidate(indicator_value) == indicator_value

    if indicator_type == "SHA256":
        return framework.normalize_sha256_candidate(indicator_value) == indicator_value

    if indicator_type == "MD5":
        return framework.normalize_md5_candidate(indicator_value) == indicator_value

    return False


def _retry_after_seconds(response):

    headers = getattr(response, "headers", None) or {}

    try:
        value = int(str(headers.get("Retry-After", "")).strip())
    except ValueError:
        return DEFAULT_429_BACKOFF_SECONDS

    return value if 1 <= value <= MAX_RETRY_AFTER_SECONDS else DEFAULT_429_BACKOFF_SECONDS


# --------------------------------------------------
# LIVE CLIENT (DOMAIN / SHA256 / MD5 only)
# --------------------------------------------------

def query_virustotal_live(indicator_type, indicator_value):

    if not framework.provider_supports_indicator(PROVIDER_NAME, indicator_type, indicator_value):
        return {"lookup_status": "NOT_SUPPORTED"}

    # Structural no-duplicate guarantee: this client can never request an
    # IP report, no matter who calls it (see module docstring).
    if not framework.provider_live_lookup_allowed(PROVIDER_NAME, indicator_type):
        return {"lookup_status": "NOT_SUPPORTED", "summary": IP_DERIVED_NOTE}

    if not _valid_value(indicator_type, indicator_value):
        return {"lookup_status": "NOT_SUPPORTED"}

    if not VT_API_KEY:
        return {
            "lookup_status": "NOT_CONFIGURED",
            "summary": "VirusTotal API key is not configured."
        }

    # Defense in depth: honour the local budget even if a caller skipped
    # the worker's own pre-check. Not a provider response, so it is
    # reported as a non-persisted local throttle.
    conn = framework.get_db_connection()
    try:
        state = get_quota_state(conn)
    finally:
        conn.close()

    if state["allowance"] <= 0:
        return {
            "lookup_status": "RATE_LIMITED",
            "summary": "VirusTotal local request budget exhausted.",
            "local_quota_exhausted": True
        }

    if indicator_type == "DOMAIN":
        url = f"{VT_BASE_URL}domains/{indicator_value}"
    else:
        url = f"{VT_BASE_URL}files/{indicator_value}"

    _note_attempt()

    try:

        response = requests.get(
            url,
            headers={"x-apikey": VT_API_KEY},
            timeout=VT_HTTP_TIMEOUT_SECONDS
        )

    except requests.ConnectTimeout:
        # Never reached VirusTotal - no quota consumed, not ledgered.
        return _error("VirusTotal connection timed out.")

    except requests.Timeout:
        # Request was sent; count it.
        record_live_call()
        return _error("VirusTotal request timed out.")

    except requests.RequestException:
        # DNS/TLS/connection failure before any response - no quota used.
        return _error("VirusTotal connection error.")

    record_live_call()

    status = response.status_code

    if status == 404:
        return {
            "lookup_status": "NO_MATCH",
            "summary": "No VirusTotal report found for this indicator.",
            "analysis_stats": None
        }

    if status == 429:
        set_backoff(_retry_after_seconds(response))
        return {
            "lookup_status": "RATE_LIMITED",
            "summary": "VirusTotal rate limit reached.",
            "analysis_stats": None
        }

    if status in (401, 403):
        return _error("VirusTotal authentication failed.")

    if status != 200:
        return _error(f"VirusTotal returned HTTP {status}.")

    try:
        response_json = response.json()
    except ValueError:
        return _error("VirusTotal returned invalid JSON.")

    return _parse_report(response_json)


# --------------------------------------------------
# IP EVIDENCE DERIVED FROM THE LEGACY RESULT (zero additional HTTP)
# --------------------------------------------------

def record_legacy_ip_result(ip_address, legacy_vt_result, conn=None):

    # legacy_vt_result is the dict check_virustotal() already returned.
    # Only a genuinely available result (a real VT response was parsed) is
    # turned into evidence; an unavailable one (failure, missing key,
    # 429...) writes nothing. Never raises to a legacy caller (they wrap
    # this in try/except as well). Returns the stored row or None.
    if not isinstance(legacy_vt_result, dict) or legacy_vt_result.get("available") is not True:
        return None

    ip = framework.normalize_ip_candidate(ip_address)

    if not ip:
        return None

    stats = framework.parse_analysis_stats(legacy_vt_result)

    if stats is None:
        return None

    result = {
        "lookup_status": "MATCH",
        "threat_type": None,
        "malware_family": None,
        "confidence_level": None,
        "tags": None,
        "first_seen": None,
        "last_seen": None,
        "summary": build_summary(stats),
        "analysis_stats": stats,
    }

    owns_conn = conn is None
    conn = conn or framework.get_db_connection()

    try:
        return framework.store_evidence(conn, PROVIDER_NAME, "IP", ip, result)
    finally:
        if owns_conn:
            conn.close()


# --------------------------------------------------
# CACHE-AWARE ENTRY POINT
# --------------------------------------------------

def get_virustotal_evidence(indicator_type, indicator_value, conn=None):

    # Privacy first: a private/loopback/link-local/unspecified IP is never
    # an eligible indicator for this provider (even though IP evidence is
    # derived, not fetched).
    if (
        not framework.provider_supports_indicator(PROVIDER_NAME, indicator_type, indicator_value)
        or (indicator_type == "IP" and framework.normalize_ip_candidate(indicator_value) is None)
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

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        # IP: evidence exists only if the legacy path produced it. Never
        # an HTTP request here (see module docstring).
        if not framework.provider_live_lookup_allowed(PROVIDER_NAME, indicator_type):
            return {
                "provider": PROVIDER_NAME,
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "lookup_status": "NO_STORED_EVIDENCE",
                "source": "LEGACY_DERIVED_ONLY"
            }

        try:
            live_result = query_virustotal_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = _error("Unexpected VirusTotal integration error.")

        # Routing-level / local-throttle outcomes are not provider
        # responses: never cached or persisted.
        if (
            live_result.get("local_quota_exhausted")
            or live_result.get("lookup_status") not in framework.PERSISTABLE_LOOKUP_STATUSES
        ):
            result = dict(live_result)
            result["provider"] = PROVIDER_NAME
            result["indicator_type"] = indicator_type
            result["indicator_value"] = indicator_value
            result["source"] = "ROUTING"
            return result

        live_result.setdefault("analysis_stats", None)

        return framework.store_evidence(
            conn, PROVIDER_NAME, indicator_type, indicator_value, live_result
        )

    finally:
        if owns_conn:
            conn.close()
