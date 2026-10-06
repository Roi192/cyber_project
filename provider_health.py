# ==================================================
# STAGE 25D: PROVIDER HEALTH + SINGLE-FLIGHT LOCK
# ==================================================
#
# Central, read-mostly health model for every Threat Intelligence
# provider, built ENTIRELY on top of what already exists
# (threat_intel_framework.PROVIDER_REGISTRY, threat_intel_evidence,
# get_provider_configuration_state) plus two small additive tables:
#   - provider_daily_counters: our OWN request/cache-hit counts, reset
#     naturally per calendar day (no cron needed - the day is part of
#     the primary key).
#   - provider_lookup_locks: a tiny single-flight guard (section 13) -
#     prevents the automatic worker (threat_intel_worker.py, a separate
#     OS process) and a manual re-check (app.py's /threat-intel route,
#     also a separate OS process) from making a live call for the
#     EXACT same (provider, indicator_type, indicator_value) at the
#     same time. Stale locks (a crashed holder) self-heal after
#     LOCK_STALE_SECONDS - never a permanent deadlock.
#
# HARD GUARANTEES (same as every other module in this project):
#   - NEVER reads/writes risk_score/severity/decision/security_alerts/
#     response_commands/Behavioral tables.
#   - NEVER performs a live HTTP call itself - purely accounting/status.
#   - NEVER logs/displays an API key - only configured: bool (reuses
#     framework.get_provider_configuration_state(), which already never
#     returns the key value itself).
#   - "quota_used"/"quota_remaining"/"quota_reset_at" are populated ONLY
#     for a provider whose OWN adapter genuinely exposes that
#     information (currently: VirusTotal's documented day/minute ledger,
#     virustotal_provider.get_quota_state()). For every other provider
#     these three fields are None - never invented, never guessed
#     (section 5's explicit "no fabricated quota" requirement).
# ==================================================

import sqlite3
from datetime import datetime, timedelta

import threat_intel_framework as framework

STATUS_HEALTHY = "HEALTHY"
STATUS_DEGRADED = "DEGRADED"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
STATUS_MISSING_KEY = "MISSING_KEY"
STATUS_DISABLED = "DISABLED"
STATUS_UNAVAILABLE = "UNAVAILABLE"

# How many of the most recent evidence rows (any indicator) to inspect
# when deriving consecutive_failures/health - bounded, cheap, no
# full-table scan (same spirit as every other bounded query in this
# project).
RECENT_ROWS_WINDOW = 20

# A held lock older than this is assumed to belong to a crashed/killed
# holder (process kill, worker restart) and may be stolen by the next
# caller - prevents a permanent deadlock without needing a separate
# cleanup job.
LOCK_STALE_SECONDS = 30

# Degraded/unavailable thresholds, consecutive-failure-based - small,
# fixed, explainable numbers (same "start small" philosophy as Stage
# 25C's rule thresholds), not a tuned ML cutoff.
DEGRADED_AFTER_CONSECUTIVE_FAILURES = 2
UNAVAILABLE_AFTER_CONSECUTIVE_FAILURES = 5


def get_db_connection():
    return framework.get_db_connection()


# --------------------------------------------------
# SCHEMA (additive only)
# --------------------------------------------------

def init_provider_health_db():

    conn = get_db_connection()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS provider_daily_counters (
                provider TEXT NOT NULL,
                day TEXT NOT NULL,
                requests INTEGER NOT NULL DEFAULT 0,
                cache_hits INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (provider, day)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS provider_lookup_locks (
                lock_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                acquired_at TEXT NOT NULL
            )
        """)

        conn.commit()

    finally:
        conn.close()


def _today_str(now=None):
    return (now or datetime.now()).strftime("%Y-%m-%d")


# --------------------------------------------------
# COUNTERS (section 5 - requests_today / cache_hits_today)
# Called from exactly the two shared choke points every provider
# module already routes through (threat_intel_framework.
# get_cached_evidence/store_evidence) - see the hooks added there.
# A counter failure must never break a real lookup, so callers wrap
# these in try/except (defense in depth, matching every other
# evidence block in this project).
# --------------------------------------------------

def record_cache_hit(provider, now=None):

    conn = get_db_connection()

    try:
        day = _today_str(now)
        conn.execute("""
            INSERT INTO provider_daily_counters (provider, day, requests, cache_hits)
            VALUES (?, ?, 0, 1)
            ON CONFLICT(provider, day) DO UPDATE SET cache_hits = cache_hits + 1
        """, (provider, day))
        conn.commit()
    finally:
        conn.close()


def record_request(provider, now=None):

    conn = get_db_connection()

    try:
        day = _today_str(now)
        conn.execute("""
            INSERT INTO provider_daily_counters (provider, day, requests, cache_hits)
            VALUES (?, ?, 1, 0)
            ON CONFLICT(provider, day) DO UPDATE SET requests = requests + 1
        """, (provider, day))
        conn.commit()
    finally:
        conn.close()


def get_today_counters(provider, now=None):

    conn = get_db_connection()

    try:
        day = _today_str(now)
        row = conn.execute("""
            SELECT requests, cache_hits FROM provider_daily_counters
            WHERE provider = ? AND day = ?
        """, (provider, day)).fetchone()
    finally:
        conn.close()

    if row is None:
        return {"requests_today": 0, "cache_hits_today": 0}

    return {"requests_today": row["requests"], "cache_hits_today": row["cache_hits"]}


# --------------------------------------------------
# SINGLE-FLIGHT LOCK (section 13)
# --------------------------------------------------

def _lock_key(provider, indicator_type, indicator_value):
    return f"{provider}|{indicator_type}|{indicator_value}"


def acquire_lookup_lock(provider, indicator_type, indicator_value, now=None):
    """
    Returns True if the caller may proceed with a live lookup for this
    exact (provider, indicator_type, indicator_value), False if another
    caller already holds the lock (and it is not stale). Always paired
    with release_lookup_lock() in a try/finally by the caller.
    """

    key = _lock_key(provider, indicator_type, indicator_value)
    now = now or datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()

    try:

        cursor = conn.execute("""
            INSERT OR IGNORE INTO provider_lookup_locks (lock_key, provider, acquired_at)
            VALUES (?, ?, ?)
        """, (key, provider, now_str))
        conn.commit()

        if cursor.rowcount == 1:
            return True

        row = conn.execute(
            "SELECT acquired_at FROM provider_lookup_locks WHERE lock_key = ?", (key,)
        ).fetchone()

        if row is None:
            # Released between the failed INSERT and this SELECT - fail
            # closed (skip this cycle) rather than risk a double lookup;
            # the caller/next cycle will simply retry.
            return False

        try:
            acquired_at = datetime.strptime(row["acquired_at"], "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            acquired_at = now  # malformed timestamp - treat as fresh, do not steal

        if (now - acquired_at).total_seconds() <= LOCK_STALE_SECONDS:
            return False

        # Stale - a prior holder almost certainly crashed/was killed
        # without releasing. Steal it, guarded by the timestamp we just
        # read so two simultaneous stealers can't both succeed.
        steal = conn.execute("""
            UPDATE provider_lookup_locks SET acquired_at = ?
            WHERE lock_key = ? AND acquired_at = ?
        """, (now_str, key, row["acquired_at"]))
        conn.commit()

        return steal.rowcount == 1

    finally:
        conn.close()


def release_lookup_lock(provider, indicator_type, indicator_value):

    key = _lock_key(provider, indicator_type, indicator_value)

    conn = get_db_connection()

    try:
        conn.execute("DELETE FROM provider_lookup_locks WHERE lock_key = ?", (key,))
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------
# HEALTH STATUS (section 5/6) - computed, never persisted as a verdict.
# --------------------------------------------------

def _otx_automatic_gate_open():
    # Mirrors threat_intel_worker.py's own OTX_ENABLED read exactly -
    # same env var, same default, so this module's view of "is OTX
    # actually automatic today" can never disagree with the worker's.
    import os
    return os.getenv("OTX_ENABLED", "false").strip().lower() == "true"


def _virustotal_quota(now=None):

    try:
        import virustotal_provider
    except Exception:
        return None, None, None

    conn = get_db_connection()

    try:
        state = virustotal_provider.get_quota_state(conn, now=now)
    except Exception:
        return None, None, None
    finally:
        conn.close()

    quota_used = state.get("day_used")
    day_limit = state.get("day_limit")
    quota_remaining = (
        max(0, day_limit - quota_used) if quota_used is not None and day_limit is not None else None
    )
    quota_reset_at = state.get("backoff_until").strftime("%Y-%m-%d %H:%M:%S") if state.get("backing_off") else None

    return quota_used, quota_remaining, quota_reset_at


def compute_provider_health(provider, now=None):

    now = now or datetime.now()
    meta = framework.PROVIDER_REGISTRY.get(provider)

    base = {
        "provider": provider,
        "configured": False,
        "automatic_eligible": False,
        "manual_eligible": False,
        "supported_indicator_types": list((meta or {}).get("supported_indicator_types", ())),
        "requests_today": 0,
        "cache_hits_today": 0,
        "last_success_at": None,
        "last_failure_at": None,
        "last_error_category": None,
        "consecutive_failures": 0,
        "quota_used": None,
        "quota_remaining": None,
        "quota_reset_at": None,
    }

    if meta is None or not meta.get("implemented"):
        base["status"] = STATUS_UNAVAILABLE
        return base

    requires_key = bool(meta.get("requires_api_key", True))
    config_state = framework.get_provider_configuration_state(provider)
    configured = (config_state == framework.CONFIG_STATE_AVAILABLE) or not requires_key

    base["configured"] = configured
    base["automatic_eligible"] = bool(meta.get("automatic_eligible"))
    base["manual_eligible"] = bool(meta.get("manual_eligible"))

    counters = get_today_counters(provider, now)
    base["requests_today"] = counters["requests_today"]
    base["cache_hits_today"] = counters["cache_hits_today"]

    # OTX's own global automatic gate (separate from "configured") -
    # explicitly surfaced as DISABLED, not MISSING_KEY, when it is the
    # OTX_ENABLED flag (not a missing key) holding it back.
    if provider == "alienvault_otx" and not _otx_automatic_gate_open():
        base["status"] = STATUS_DISABLED
        return base

    if bool(meta.get("manual_only")):
        # Cloudflare: never evaluated as "automatic health" - its own
        # dedicated budget-aware flow (cloudflare_provider.py) already
        # tracks this; here it is simply configured-or-not.
        base["status"] = STATUS_HEALTHY if configured else STATUS_MISSING_KEY
        return base

    if requires_key and not configured:
        base["status"] = STATUS_MISSING_KEY
        return base

    conn = get_db_connection()

    try:

        recent_rows = conn.execute("""
            SELECT lookup_status, retrieved_at FROM threat_intel_evidence
            WHERE provider = ?
            ORDER BY retrieved_at DESC LIMIT ?
        """, (provider, RECENT_ROWS_WINDOW)).fetchall()

        last_success_row = conn.execute("""
            SELECT retrieved_at FROM threat_intel_evidence
            WHERE provider = ? AND lookup_status IN ('MATCH', 'NO_MATCH')
            ORDER BY retrieved_at DESC LIMIT 1
        """, (provider,)).fetchone()

        last_failure_row = conn.execute("""
            SELECT retrieved_at, lookup_status FROM threat_intel_evidence
            WHERE provider = ? AND lookup_status IN ('ERROR', 'RATE_LIMITED')
            ORDER BY retrieved_at DESC LIMIT 1
        """, (provider,)).fetchone()

    finally:
        conn.close()

    base["last_success_at"] = last_success_row["retrieved_at"] if last_success_row else None
    base["last_failure_at"] = last_failure_row["retrieved_at"] if last_failure_row else None
    base["last_error_category"] = last_failure_row["lookup_status"] if last_failure_row else None

    consecutive_failures = 0
    for row in recent_rows:
        if row["lookup_status"] in ("ERROR", "RATE_LIMITED"):
            consecutive_failures += 1
        else:
            break
    base["consecutive_failures"] = consecutive_failures

    if provider == "virustotal":
        quota_used, quota_remaining, quota_reset_at = _virustotal_quota(now)
        base["quota_used"] = quota_used
        base["quota_remaining"] = quota_remaining
        base["quota_reset_at"] = quota_reset_at
        if quota_remaining == 0:
            base["status"] = STATUS_QUOTA_EXHAUSTED
            return base

    if recent_rows and consecutive_failures >= 1 and all(
        r["lookup_status"] == "RATE_LIMITED" for r in recent_rows[:consecutive_failures]
    ):
        base["status"] = STATUS_RATE_LIMITED
        return base

    if consecutive_failures >= UNAVAILABLE_AFTER_CONSECUTIVE_FAILURES:
        base["status"] = STATUS_UNAVAILABLE
        return base

    if consecutive_failures >= DEGRADED_AFTER_CONSECUTIVE_FAILURES:
        base["status"] = STATUS_DEGRADED
        return base

    base["status"] = STATUS_HEALTHY
    return base


def all_providers_health(now=None):
    """Health for every implemented provider in PROVIDER_REGISTRY, sorted
    by name - the data source for the Threat Intelligence Providers
    dashboard (section 11)."""

    return [
        compute_provider_health(name, now=now)
        for name, meta in sorted(framework.PROVIDER_REGISTRY.items())
        if meta.get("implemented")
    ]
