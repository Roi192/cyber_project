# ==================================================
# PHASE 12B.2: ASYNC THREAT INTELLIGENCE WORKER
# ==================================================
#
# Standalone, long-running process - NOT a Flask dependency, does NOT
# replace web_event_worker.py or behavioral_worker.py.
#
# Conceptual architecture:
#   endpoint_agent -> web_event_worker -> Threat Risk / IOC / Alert
#   processing -> web_event stored ANALYZED -> threat_intel_worker ->
#   normalized external TI enrichment -> threat_intel_evidence
#
# --------------------------------------------------
# THREATFOX MIGRATION DECISION (Phase 12B.2 section 11 audit)
# --------------------------------------------------
# web_event_worker.py currently calls lookup_threatfox_for_event()
# SYNCHRONOUSLY, on the same request path that also computes Threat
# Risk and creates Alerts. ThreatFox already contributes ZERO Threat
# Risk points, so moving it here would not change Threat Risk/Alert/
# Incident math - but it WOULD change *timing*: Web Monitoring and
# Alert Details compute Investigation Priority at render time from
# whatever ThreatFox evidence is CURRENTLY stored
# (compute_investigation_priority() in investigation_priority.py, fed
# by threat_intel_providers.get_stored_evidence_for_event()). If
# ThreatFox's WRITE moved to this async worker, an analyst opening an
# alert seconds after it fires could see stale/absent ThreatFox
# evidence until this worker's next cycle catches up - a real,
# analyst-visible regression risk to Investigation Priority freshness
# that was extensively regression-tested in Phase 12B.1.
#
# DECISION: ThreatFox stays synchronous in web_event_worker.py,
# UNCHANGED, in this phase. This worker manages ONLY URLhaus
# (ASYNC_MANAGED_PROVIDERS below) and never calls any ThreatFox
# function - so there is no risk of a duplicate ThreatFox lookup.
# Revisiting this is deferred to a future phase, once multi-provider
# Investigation Priority semantics are reconsidered (explicitly out of
# scope for 12B.2 - see investigation_priority.py, untouched).
# ==================================================

import os
import signal
import db_config
import worker_status
import sqlite3
import sys
import time
from datetime import datetime

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

import threat_intel_framework as framework
import threat_intel_shadow
import urlhaus_provider
import virustotal_provider
import otx_provider
import ipqualityscore_provider
import provider_health


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
# CONFIG
# --------------------------------------------------

# Only providers this worker is responsible for enriching asynchronously.
# ThreatFox deliberately excluded - see migration decision above.
# Phase 12B.3: VirusTotal added. It is quota-governed (see
# virustotal_provider.get_quota_state) rather than using the generic
# per-cycle budget below, and never fetches IPs (IP evidence is
# derived from the legacy reputation result).
#
# Oct 2026 Step 10: AlienVault OTX activation switch. Default DISABLED -
# same read-once-at-import convention as every other flag in this project
# (FLASK_DEBUG, THREAT_INTEL_SHADOW_MODE_ENABLED). Gates ONLY whether
# "alienvault_otx" is in ASYNC_MANAGED_PROVIDERS at all - urlhaus/
# virustotal/ipqualityscore's position, order and behavior in this list
# are completely unaffected either way (list membership, not a per-item
# branch, so there is nothing for the existing providers to notice).
OTX_ENABLED = os.getenv("OTX_ENABLED", "false").strip().lower() == "true"

ASYNC_MANAGED_PROVIDERS = ["urlhaus", "virustotal", "ipqualityscore"]

if OTX_ENABLED:
    ASYNC_MANAGED_PROVIDERS.append("alienvault_otx")

# ipqualityscore (IP only; requires IPQS_API_KEY, reports NOT_CONFIGURED and
# generates no work until set - same as every other key-gated provider).
# GreyNoise/PhishTank/Google Safe Browsing/urlscan.io/Shodan/Censys are all
# manual_eligible only (automatic_eligible=False in the registry) and are
# deliberately NOT listed here - resolve_provider_lookup_eligibility()/
# provider_is_manual_only() would refuse them anyway (defense in depth),
# but they are kept out of this list entirely so that fact is visible here
# too, not just enforced deep in the routing layer.

# Oct 2026 Step 10: gradual-rollout budget for OTX's OWN first cycle only
# (a one-time, much smaller cap than MAX_CALLS_PER_PROVIDER_PER_CYCLE,
# specifically for controlled activation against a real historical
# backlog) - see OTX_FIRST_CYCLE_LIMIT / _otx_first_cycle_done below.
# Applies ONLY to "alienvault_otx"; every other provider's per-cycle
# budget is completely unaffected.
OTX_FIRST_CYCLE_LIMIT = 5

# How many recent trusted/analyzed events to consider per poll cycle.
# Bounded on purpose - never scans the full 58K+ event table.
BATCH_EVENT_LIMIT = 300

# Per-provider live HTTP call budget per cycle - prevents hammering a
# provider even under a burst of many new distinct indicators at once.
MAX_CALLS_PER_PROVIDER_PER_CYCLE = 20

# Small delay between individual live calls (pacing, not a real rate
# limiter - see section 18: "do not implement a complex distributed
# rate limiter").
INTER_CALL_DELAY_SECONDS = 0.5

# Provider-call scheduling priority ONLY (lower = sooner). Scarce VirusTotal
# quota goes to the most specific indicators first. This never touches
# Investigation Priority or any risk logic.
VT_TYPE_PRIORITY = {"SHA256": 0, "MD5": 0, "DOMAIN": 1}

# Poll cadence when there was work this cycle vs. when idle.
ACTIVE_CYCLE_SLEEP_SECONDS = 5
IDLE_CYCLE_SLEEP_SECONDS = 15

_running = True


def _handle_shutdown_signal(signum, frame):
    global _running
    _running = False


signal.signal(signal.SIGINT, _handle_shutdown_signal)
try:
    signal.signal(signal.SIGTERM, _handle_shutdown_signal)
except (AttributeError, ValueError):
    # SIGTERM not available on all platforms/threads - non-fatal.
    pass


# --------------------------------------------------
# STATE (additive, minimal - mirrors behavioral_engine_config's proven
# bootstrap-cutoff pattern from Phase 11C). Only the activation cutoff
# is stored; no "last processed event" watermark is needed because this
# worker always rescans a bounded RECENT window each cycle (see
# BATCH_EVENT_LIMIT) rather than advancing a cursor - freshness (via
# the existing threat_intel_evidence cache/TTL) is what prevents
# redundant work, not a watermark. This is deliberately the smallest
# state that safely solves the problem (section 17 audit).
# --------------------------------------------------

def init_worker_state_db(conn):

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_worker_state (
            config_key TEXT PRIMARY KEY,
            config_value TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()


def get_or_create_activation_cutoff(conn):

    # CRITICAL (section 16): on first-ever startup, do NOT enrich the
    # full historical event backlog - that would be an uncontrolled API-
    # call storm against URLhaus (58K+ historical web_events, each with
    # up to 4 candidate indicator types). Instead, the cutoff is set
    # ONCE to "now" the very first time this worker ever runs, and only
    # events at/after that moment are ever considered for automatic
    # enrichment. Historical events before the cutoff permanently show
    # "no stored URLhaus evidence" unless a future phase adds an
    # explicit, deliberately-throttled backfill tool - never automatic.
    row = conn.execute("""
        SELECT config_value FROM threat_intel_worker_state
        WHERE config_key = 'activation_cutoff'
    """).fetchone()

    if row is not None:
        return row["config_value"]

    cutoff_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        INSERT OR IGNORE INTO threat_intel_worker_state (config_key, config_value, created_at)
        VALUES ('activation_cutoff', ?, ?)
    """, (cutoff_str, cutoff_str))
    conn.commit()

    row2 = conn.execute("""
        SELECT config_value FROM threat_intel_worker_state
        WHERE config_key = 'activation_cutoff'
    """).fetchone()

    return row2["config_value"]


# --------------------------------------------------
# Oct 2026 Step 10: OTX gradual-rollout one-time marker. Same table/pattern
# as activation_cutoff above - the smallest state that solves the problem.
# Read/written only when OTX_ENABLED (otherwise never touched at all).
# --------------------------------------------------

def otx_first_cycle_done(conn):

    row = conn.execute("""
        SELECT config_value FROM threat_intel_worker_state
        WHERE config_key = 'otx_first_cycle_done'
    """).fetchone()

    return row is not None and row["config_value"] == "true"


def mark_otx_first_cycle_done(conn):

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        INSERT INTO threat_intel_worker_state (config_key, config_value, created_at)
        VALUES ('otx_first_cycle_done', 'true', ?)
        ON CONFLICT(config_key) DO UPDATE SET config_value = 'true'
    """, (now,))
    conn.commit()


# --------------------------------------------------
# WORK DISCOVERY (indicator-level, provider-aware claim model)
# --------------------------------------------------

def _recent_candidate_events(conn, activation_cutoff):

    # Same trusted/analyzed join pattern used by every other subsystem
    # (behavioral engine, Phase 11E reports) - only real endpoint-agent
    # telemetry, only fully analyzed rows, only at/after the activation
    # cutoff, bounded to the most recent BATCH_EVENT_LIMIT rows.
    return conn.execute("""
        SELECT web_events.resolved_ip, web_events.domain,
               web_events.sha256, web_events.md5
        FROM web_events
        JOIN endpoints ON endpoints.ip_address = web_events.endpoint_ip
        WHERE endpoints.source = 'endpoint-agent'
          AND web_events.source = 'endpoint-agent'
          AND web_events.analysis_status = 'ANALYZED'
          AND web_events.event_time >= ?
        ORDER BY web_events.event_time DESC
        LIMIT ?
    """, (activation_cutoff, BATCH_EVENT_LIMIT)).fetchall()


def _recent_browser_candidate_events(conn, activation_cutoff):

    # Stage 25D section 8: browser-sourced web_events rows
    # (source='browser-extension') were, until now, COMPLETELY
    # EXCLUDED from this worker's candidate gathering - the query
    # above explicitly filters source='endpoint-agent', and browser
    # rows never reach analysis_status='ANALYZED' at all (they use
    # their own local_feed_status column instead - see
    # web_event_worker.process_browser_event_for_local_feed()). This
    # is the real, audited gap: a browser URL/domain got Local Feed
    # matching only, never VirusTotal/URLhaus/ThreatFox domain
    # evidence. Only DOMAIN is extracted here (never the raw URL/
    # query/fragment - the existing browser-privacy redaction rules,
    # section 8's own "query/fragment privacy rules stay", are
    # untouched; this reads the ALREADY-derived `domain` column, never
    # the raw url). 'CHECKED' means Local Feed + Detection Engine have
    # already run for this row (same readiness bar as 'ANALYZED' for
    # TCP events) - never scans a row still mid-processing.
    return conn.execute("""
        SELECT domain
        FROM web_events
        WHERE source = 'browser-extension'
          AND local_feed_status = 'CHECKED'
          AND domain IS NOT NULL
          AND event_time >= ?
        ORDER BY event_time DESC
        LIMIT ?
    """, (activation_cutoff, BATCH_EVENT_LIMIT)).fetchall()


def _recent_process_hash_candidates(conn, activation_cutoff):

    # Stage 25D section 9: endpoint_process_events.sha256/md5 (Stage
    # 25A) was, until now, NEVER read by this worker - only
    # web_events.sha256/md5 (populated for a process that also made a
    # TCP connection) fed hash candidates. A process discovered with no
    # associated network connection got zero automatic hash
    # intelligence. hash_status='ok' means the Agent successfully
    # computed a real hash for this process's executable (never
    # 'no_path'/'unavailable'/'error') - and per the project's standing
    # rule, ONLY the hash is ever sent to a provider, never the
    # executable itself (no upload capability exists anywhere in this
    # pipeline; VirusTotal/URLhaus are called with a hash string only,
    # exactly as they already are for TCP-sourced hashes).
    return conn.execute("""
        SELECT sha256, md5
        FROM endpoint_process_events
        WHERE hash_status = 'ok'
          AND (sha256 IS NOT NULL OR md5 IS NOT NULL)
          AND received_at >= ?
        ORDER BY received_at DESC
        LIMIT ?
    """, (activation_cutoff, BATCH_EVENT_LIMIT)).fetchall()


def find_enrichment_work(conn, activation_cutoff):

    # Returns a de-duplicated list of (provider, indicator_type,
    # indicator_value) tuples that are NOT currently fresh in the cache
    # - i.e. genuinely need a live lookup. Operates at INDICATOR level:
    # 500 events sharing one public IP collapse to exactly one work
    # item for that (provider, "IP", value) pair (hard requirement,
    # section 13) - this happens naturally because a Python set() is
    # used for de-duplication before any freshness check or HTTP call.
    events = _recent_candidate_events(conn, activation_cutoff)
    browser_events = _recent_browser_candidate_events(conn, activation_cutoff)
    process_hash_rows = _recent_process_hash_candidates(conn, activation_cutoff)

    all_candidates = {}  # insertion-ordered set: most recent event first

    for row in events:
        for indicator_type, indicator_value in framework.all_candidate_indicators_for_event(
            row["resolved_ip"], row["domain"], row["sha256"], row["md5"]
        ):
            all_candidates[(indicator_type, indicator_value)] = None

    # Stage 25D section 8: browser DOMAIN candidates (no resolved_ip/
    # sha256/md5 - browser events never have them, by design).
    for row in browser_events:
        for indicator_type, indicator_value in framework.all_candidate_indicators_for_event(
            None, row["domain"], None, None
        ):
            all_candidates[(indicator_type, indicator_value)] = None

    # Stage 25D section 9: process-only hash candidates (no resolved_ip/
    # domain - these rows may belong to a process that never made a
    # network connection at all).
    for row in process_hash_rows:
        for indicator_type, indicator_value in framework.all_candidate_indicators_for_event(
            None, None, row["sha256"], row["md5"]
        ):
            all_candidates[(indicator_type, indicator_value)] = None

    work = []

    for indicator_type, indicator_value in all_candidates:

        for provider in ASYNC_MANAGED_PROVIDERS:

            # Phase 12B.5B STRUCTURAL GUARD: a manual_only provider
            # (Cloudflare - 100 calls/MONTH, shared with the dashboard) is
            # never scheduled automatically, even if it were accidentally
            # added to ASYNC_MANAGED_PROVIDERS.
            if framework.provider_is_manual_only(provider):
                continue

            meta = framework.PROVIDER_REGISTRY.get(provider, {})

            if indicator_type not in meta.get("supported_indicator_types", ()):
                continue

            # Types this worker may not FETCH (VirusTotal IP evidence is
            # derived from the legacy lookup) never become work.
            if not framework.provider_live_lookup_allowed(provider, indicator_type):
                continue

            # NOT_CONFIGURED / NOT_SUPPORTED providers never generate
            # HTTP work - skip without touching the cache at all.
            # Eligibility is value-aware (Phase 12B.2B: URLhaus does not
            # accept IPv6) and is evaluated BEFORE the cache check below,
            # so a pre-existing cached ERROR row for an unsupported
            # indicator can never cause a new dispatch or a retry.
            eligibility = framework.resolve_provider_lookup_eligibility(provider, indicator_type, indicator_value)
            if eligibility != "ELIGIBLE":
                continue

            # Fresh cached evidence (including a fresh negative/ERROR/
            # RATE_LIMITED row) means this pair does NOT need a live
            # call - this is what makes RATE_LIMITED cache suppress
            # retry (section 28) and what prevents duplicate calls for
            # already-enriched indicators (section 13/29) with zero
            # extra bookkeeping beyond the existing cache layer.
            cached = framework.get_cached_evidence(conn, provider, indicator_type, indicator_value)
            if cached is not None:
                continue

            work.append((provider, indicator_type, indicator_value))

    work.sort(key=lambda item: (
        VT_TYPE_PRIORITY.get(item[1], 9) if item[0] == "virustotal" else 0
    ))

    return work


# --------------------------------------------------
# LIVE LOOKUP DISPATCH (provider-isolated - one provider's exception or
# outage never blocks another provider's work, and never crashes the
# worker loop)
# --------------------------------------------------

def _perform_lookup(conn, provider, indicator_type, indicator_value):

    # Second, independent manual_only guard (defense in depth): dispatch
    # itself refuses, so no request can be made even by a direct call.
    if framework.provider_is_manual_only(provider):
        return False

    # Stage 25D section 13: single-flight guard against a manual
    # re-check (/threat-intel route, a SEPARATE OS process from this
    # worker) racing this exact (provider, indicator_type,
    # indicator_value) at the same moment. If the lock cannot be
    # acquired, someone else is already fetching this - skip it this
    # cycle (find_enrichment_work() will simply see it again next
    # cycle if it is still not fresh). A lock-layer failure must never
    # block real enrichment, so it fails OPEN (proceeds) rather than
    # silently starving the worker forever.
    try:
        got_lock = provider_health.acquire_lookup_lock(provider, indicator_type, indicator_value)
    except Exception:
        got_lock = True

    if not got_lock:
        return False

    try:

        if provider == "urlhaus":
            urlhaus_provider.get_urlhaus_evidence(indicator_type, indicator_value, conn=conn)
            return True

        if provider == "virustotal":
            result = virustotal_provider.get_virustotal_evidence(indicator_type, indicator_value, conn=conn)
            # Only a real live request counts as "performed" work.
            return result.get("source") == "LIVE"

        if provider == "alienvault_otx":
            result = otx_provider.get_otx_evidence(indicator_type, indicator_value, conn=conn)
            return result.get("source") == "LIVE"

        if provider == "ipqualityscore":
            result = ipqualityscore_provider.get_ipqualityscore_evidence(indicator_type, indicator_value, conn=conn)
            return result.get("source") == "LIVE"

        # ASYNC_MANAGED_PROVIDERS only ever contains implemented,
        # dispatchable providers - reaching here would be a programming
        # error, not a runtime condition, so it is only logged, never
        # raised further (failure isolation - section 19).
        framework.log_provider_lookup_error(
            provider, indicator_type, RuntimeError("no dispatch registered for provider")
        )
        return False

    except Exception as exc:
        # A single provider's exception must never crash the worker
        # loop or block the next work item (section 19/29).
        framework.log_provider_lookup_error(provider, indicator_type, exc)
        return False

    finally:
        try:
            provider_health.release_lookup_lock(provider, indicator_type, indicator_value)
        except Exception:
            pass


# --------------------------------------------------
# MAIN LOOP
# --------------------------------------------------

def run_cycle(conn, activation_cutoff):

    work = find_enrichment_work(conn, activation_cutoff)

    if not work:
        return 0

    # Oct 2026 Step 10: OTX gradual rollout - the very FIRST cycle in which
    # OTX has any work at all gets a much smaller budget (5, not the
    # normal 20) against the real historical backlog. Decided once, up
    # front, from this cycle's own work list - never re-evaluated mid-cycle
    # (so a cycle's cap cannot change while it is running). Every other
    # provider's budget (urlhaus/virustotal/ipqualityscore) is completely
    # untouched by this.
    otx_is_first_cycle = (
        OTX_ENABLED
        and not otx_first_cycle_done(conn)
        and any(p == "alienvault_otx" for p, _, _ in work)
    )

    calls_made_by_provider = {}
    performed = 0
    # Oct 2026 Step 18: indicators that got a genuinely NEW live result
    # this cycle (never cache hits/budget-skipped/rate-limited ones) -
    # fed to Shadow Mode's bounded recompute ONCE, after this cycle's
    # normal dispatch work is entirely done, so it can never delay or
    # reorder the worker's own provider calls above. A set, not a list:
    # the same indicator can legitimately appear for more than one
    # provider in one cycle (e.g. both urlhaus and virustotal return a
    # fresh result for the same domain) and must only trigger one
    # recompute pass per distinct indicator.
    changed_indicators = set()

    for provider, indicator_type, indicator_value in work:

        if provider == "virustotal":

            # Quota-governed (per-minute + per-day + legacy usage + 429
            # back-off), re-evaluated before EVERY call so a 429 that
            # arrives mid-cycle stops the rest immediately. Anything
            # skipped is simply picked up by a later cycle.
            if virustotal_provider.get_quota_state(conn)["allowance"] <= 0:
                continue

            if _perform_lookup(conn, provider, indicator_type, indicator_value):
                performed += 1
                changed_indicators.add((indicator_type, indicator_value))

            continue

        budget_cap = MAX_CALLS_PER_PROVIDER_PER_CYCLE

        if provider == "alienvault_otx" and otx_is_first_cycle:
            budget_cap = OTX_FIRST_CYCLE_LIMIT

        budget_used = calls_made_by_provider.get(provider, 0)

        if budget_used >= budget_cap:
            # Per-provider call budget reached for this cycle (section
            # 18) - remaining work is simply picked up next cycle, since
            # freshness state (or lack thereof) is entirely re-derived
            # from the cache each time, never lost.
            continue

        if _perform_lookup(conn, provider, indicator_type, indicator_value):
            changed_indicators.add((indicator_type, indicator_value))

        calls_made_by_provider[provider] = budget_used + 1
        performed += 1

        time.sleep(INTER_CALL_DELAY_SECONDS)

    if otx_is_first_cycle:
        # Marked AFTER the cycle, regardless of how many of the 5 slots
        # were actually used - "first cycle" means the first opportunity,
        # not "until 5 real calls happened". Every subsequent cycle uses
        # the normal MAX_CALLS_PER_PROVIDER_PER_CYCLE budget for OTX.
        mark_otx_first_cycle_done(conn)

    if changed_indicators:
        # Shadow-only (see threat_intel_shadow.py's own hard guarantees):
        # no-ops entirely when SHADOW_MODE_ENABLED is false (today's live
        # state), never raises, never touches Legacy risk_score/severity/
        # decision, alerts or response_commands - it only ever re-writes
        # rows in the separate shadow.db. Bounded by SHADOW_RECOMPUTE_MAX_
        # EVENTS_PER_CYCLE regardless of how many indicators changed.
        threat_intel_shadow.recompute_shadow_for_changed_evidence(changed_indicators, conn=conn)

    return performed


def main():

    db_config.ensure_journal_mode(DB_NAME)

    conn = get_db_connection()

    # Phase 12B.6C.1: start-up initialisation is retried (bounded) on a
    # transient lock instead of killing the worker before it starts.
    def initialize():

        # Reuses the existing threat_intel_evidence table (Phase 11D.1/
        # 12B.1) - additive CREATE TABLE IF NOT EXISTS, safe to call from
        # every process that touches it.
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
        conn.commit()

        framework.ensure_evidence_schema(conn)
        virustotal_provider.ensure_quota_schema(conn)

        init_worker_state_db(conn)
        provider_health.init_provider_health_db()
        return get_or_create_activation_cutoff(conn)

    activation_cutoff = db_config.retry_on_lock(
        initialize,
        cleanup=lambda exc: conn.rollback(),
        label="threat-intel worker initialization"
    )

    print(f"[threat-intel-worker] started - activation_cutoff={activation_cutoff} "
          f"managed_providers={ASYNC_MANAGED_PROVIDERS}", flush=True)

    global _running

    while _running:

        worker_status.heartbeat("threat_intel_worker")

        # Connections opened DURING the cycle (not the long-lived `conn`,
        # which predates this mark) are always released afterwards.
        cycle_mark = db_config.mark()

        try:
            performed = run_cycle(conn, activation_cutoff)
        except Exception as exc:
            # Phase 12B.6C.1: ALWAYS discard any transaction the failed
            # cycle left open on this long-lived connection (it would
            # otherwise hold a lock indefinitely), and reconnect if the
            # connection itself is unusable.
            try:
                conn.rollback()
            except sqlite3.Error:
                conn = get_db_connection()

            if db_config.is_transient_lock_error(exc):
                # SQLite lock contention with the other processes -
                # non-fatal, retried next cycle.
                print(f"[threat-intel-worker] DB busy, will retry: {exc}", flush=True)
            else:
                # Any other unexpected exception (including a NON-lock
                # OperationalError, which is no longer reported as "busy")
                # is logged visibly and must never permanently kill the
                # worker (section 19).
                framework.log_provider_lookup_error("worker", "CYCLE", exc)

            performed = 0

        finally:
            db_config.release_since(cycle_mark)

        if performed > 0:
            print(f"[threat-intel-worker] cycle complete: {performed} lookup(s) performed", flush=True)
            time.sleep(ACTIVE_CYCLE_SLEEP_SECONDS)
        else:
            time.sleep(IDLE_CYCLE_SLEEP_SECONDS)

    conn.close()
    print("[threat-intel-worker] shutdown complete", flush=True)


if __name__ == "__main__":
    worker_status.run_guarded("threat_intel_worker", main)
