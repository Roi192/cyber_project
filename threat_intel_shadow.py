# ==================================================
# OCT 2026 STEP 4: MULTI-SOURCE THREAT INTEL RISK ENGINE - SHADOW MODE
# ==================================================
#
# Computes what threat_intel_risk.py's corroboration-based engine WOULD
# contribute to risk_score/severity for an event, and records it alongside
# the EXISTING (legacy) engine's ACTUAL result for side-by-side comparison.
# This module NEVER changes the legacy result - it only ever READS the
# values the caller already finalized and WRITES a comparison row.
#
# HARD GUARANTEES (each is also covered by an automated test):
#   - READ-ONLY against threat_intel_evidence: this module never performs
#     a live HTTP request and never calls any provider adapter's query_*
#     function - it only reads whatever is ALREADY cached (written by the
#     async worker or a manual lookup elsewhere). Zero extra load on any
#     external TI provider; existing cache/TTL/rate-limit behavior for
#     every provider is completely unaffected by this module's existence.
#   - Writes ONLY to a dedicated, SEPARATE SQLite file
#     (data/threat_intel_shadow/shadow.db) - NEVER cybersec.db. No schema
#     change to any live table; the live database is untouched.
#   - Never creates/touches security_alerts, security_events,
#     response_commands, blocked_domains, or any endpoint
#     isolation/blocking action - it has no import of, or call into, any
#     of that code.
#   - A failure anywhere in evaluate_shadow() is caught internally and
#     logged (never raised) - it can never interrupt the caller's event
#     processing, matching the existing ThreatFox contextual-lookup
#     block's own isolation discipline in web_event_worker.py.
#   - context_only providers (shodan/censys/urlscan) can never affect
#     shadow_ti_points - enforced upstream by threat_intel_risk.py's
#     evidence_class gate (Step 1/2), re-verified here by this module's
#     own test suite rather than assumed.
# ==================================================

import json
import os
import sqlite3
from datetime import datetime

import threat_intel_framework as framework
import threat_intel_risk as risk
from threat_intelligence import severity_from_score

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# SOC_SHADOW_DIR: same override convention as every other module - lets an
# isolated test point this at a temp location without touching the real one.
#
# SAFETY FALLBACK (added after a real test-pollution incident found during
# Step 4 development): every existing test suite in this project isolates
# the MAIN database via SOC_DB_PATH, but none of them know about the new
# SOC_SHADOW_DIR variable (it didn't exist before this module). A suite
# that imports web_event_worker (which imports this module) - e.g.
# test_12b2_noninterference.py - would otherwise silently write a real
# shadow.db into the LIVE project's data/ directory even though its own
# main database was correctly redirected to a temp file. To prevent that:
# if SOC_DB_PATH is set but SOC_SHADOW_DIR is NOT, the shadow directory is
# derived as a sibling of the redirected main DB - NEVER the live project
# tree - with no change required to any existing test file. Only when
# NEITHER override is set (genuine live/production operation) does this
# default to the real data/threat_intel_shadow/ path.
_shadow_dir_override = os.getenv("SOC_SHADOW_DIR", "").strip()
_db_path_override = os.getenv("SOC_DB_PATH", "").strip()

if _shadow_dir_override:
    _SHADOW_DIR = _shadow_dir_override if os.path.isabs(_shadow_dir_override) else os.path.join(_PROJECT_DIR, _shadow_dir_override)
elif _db_path_override:
    _db_dir = os.path.dirname(os.path.abspath(_db_path_override)) or _PROJECT_DIR
    _SHADOW_DIR = os.path.join(_db_dir, "threat_intel_shadow_" + os.path.basename(_db_path_override).replace(".", "_"))
else:
    _SHADOW_DIR = os.path.join(_PROJECT_DIR, "data", "threat_intel_shadow")

_SHADOW_DB = os.path.join(_SHADOW_DIR, "shadow.db")

# Providers whose threat_intel_evidence rows are a DERIVED TRANSCRIPT of
# the exact same check the LEGACY engine already performed (see
# threat_intel_framework.PROVIDER_REGISTRY's "virustotal"/"abuseipdb"
# comments: their evidence is "derived from the result the legacy
# reputation path already fetched, so the same IP is never requested
# twice"). Counting their signal again here would double-count the SAME
# underlying evidence that is already fully inside legacy_risk_score -
# Step 5 pre-check #1 fix. They are still shown in detail/evidence VIEWS
# elsewhere (nothing here hides their existence) - they are excluded ONLY
# from the number that gets added on top of legacy_risk_score.
DOUBLE_COUNT_RISK_PROVIDERS = frozenset({"virustotal", "abuseipdb"})

# --------------------------------------------------
# OCT 2026 STEP 7: SHADOW MODE ACTIVATION SWITCH
# --------------------------------------------------
# Default DISABLED, same read-once-at-import convention as FLASK_DEBUG
# (app.py) and SOC_REQUIRE_HTTPS (sensors/suricata_adapter.py) - a value
# change takes effect on the next process start, never silently mid-run.
# When disabled (the default, and the state of every live process today -
# see module docstring), evaluate_shadow() below returns immediately, opens
# no connection, reads no evidence and writes no row: zero behavioural or
# performance difference from this module not existing at all. Enabling it
# does not, by itself, change risk_score/severity/decision/alerts/block/
# isolate anywhere - it only starts writing comparison rows to the separate
# shadow database (this was already true before this switch existed; see
# the hard guarantees above). A worker process picks up a change to this
# variable only when it is restarted - which, per this project's standing
# rule, happens only as an explicit, separately-approved action.
SHADOW_MODE_ENABLED = os.getenv("THREAT_INTEL_SHADOW_MODE_ENABLED", "false").strip().lower() == "true"

_SCHEMA = """
    CREATE TABLE IF NOT EXISTS shadow_comparisons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        web_event_id INTEGER,
        evaluated_at TEXT NOT NULL,
        resolved_ip TEXT,
        domain TEXT,
        sha256 TEXT,
        md5 TEXT,
        legacy_risk_score INTEGER NOT NULL,
        legacy_severity TEXT NOT NULL,
        shadow_ti_points INTEGER NOT NULL,
        shadow_combined_score INTEGER NOT NULL,
        shadow_combined_severity TEXT NOT NULL,
        severity_changed INTEGER NOT NULL,
        decisive INTEGER NOT NULL,
        signal_providers TEXT,
        legacy_reasons TEXT,
        shadow_reasons TEXT,
        excluded_double_count_providers TEXT
    )
"""


def _ensure_schema(conn):

    conn.execute(_SCHEMA)

    # Additive migration for a shadow DB created before this column existed
    # (this is this module's OWN, separate, not-yet-live database - never
    # cybersec.db - so this is a safe, local, backward-compatible add).
    columns = {row[1] for row in conn.execute("PRAGMA table_info(shadow_comparisons)")}
    if "excluded_double_count_providers" not in columns:
        conn.execute("ALTER TABLE shadow_comparisons ADD COLUMN excluded_double_count_providers TEXT")

    # Oct 2026 Step 18: asynchronous recompute support. first_evaluated_at
    # is set once (the original evaluation) and never touched again;
    # recompute_count/last_recompute_reason/last_recomputed_at let the UI
    # and reports distinguish an initial calculation from one that was
    # later updated by new async evidence - see recompute_shadow_for_
    # changed_evidence() below.
    if "first_evaluated_at" not in columns:
        conn.execute("ALTER TABLE shadow_comparisons ADD COLUMN first_evaluated_at TEXT")
        # Backfill existing rows (written before this column existed) -
        # their first (and so far only) evaluation IS their current
        # evaluated_at value.
        conn.execute("UPDATE shadow_comparisons SET first_evaluated_at = evaluated_at WHERE first_evaluated_at IS NULL")
    if "recompute_count" not in columns:
        conn.execute("ALTER TABLE shadow_comparisons ADD COLUMN recompute_count INTEGER NOT NULL DEFAULT 0")
    if "last_recompute_reason" not in columns:
        conn.execute("ALTER TABLE shadow_comparisons ADD COLUMN last_recompute_reason TEXT")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_shadow_evaluated_at ON shadow_comparisons(evaluated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_shadow_severity_changed ON shadow_comparisons(severity_changed)")
    # UNIQUE, not just a plain index: makes evaluate_shadow() an UPSERT
    # (one row per event, truly updated in place) rather than appending a
    # new row on every recompute - this is itself the primary defense
    # against "duplicate/redundant" rows for the same event (Step 18
    # item 2's explicit requirement), enforced at the schema level, not
    # just in application logic. Safe to add here: the live shadow DB has
    # zero duplicate/NULL web_event_id values today (verified before this
    # change shipped) - if that were ever not true on some other
    # deployment, this CREATE would simply fail loudly rather than
    # silently corrupt anything, which is the right failure mode.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_shadow_web_event_id ON shadow_comparisons(web_event_id)")

    # Oct 2026 Step 19 item 1 (bounding + continuation): when a cycle's
    # changed indicators would require recomputing MORE events than
    # SHADOW_RECOMPUTE_MAX_EVENTS_PER_CYCLE allows, the leftover
    # (indicator_type, indicator_value) pairs are persisted here instead
    # of being silently dropped - the NEXT call to recompute_shadow_for_
    # changed_evidence() picks them up automatically (FIFO, oldest first)
    # ahead of that cycle's own newly-changed indicators, guaranteeing
    # eventual progress without ever re-scanning unbounded history.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shadow_recompute_queue (
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            queued_at TEXT NOT NULL,
            last_processed_id INTEGER,
            PRIMARY KEY (indicator_type, indicator_value)
        )
    """)
    queue_columns = {row[1] for row in conn.execute("PRAGMA table_info(shadow_recompute_queue)")}
    if "last_processed_id" not in queue_columns:
        conn.execute("ALTER TABLE shadow_recompute_queue ADD COLUMN last_processed_id INTEGER")
    conn.commit()


def get_shadow_connection():

    # A brand-new, separate database file - never the live cybersec.db.
    os.makedirs(_SHADOW_DIR, exist_ok=True)
    conn = sqlite3.connect(_SHADOW_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def evaluate_shadow(web_event_id, resolved_ip, domain, sha256, md5,
                    legacy_risk_score, legacy_severity, legacy_reasons,
                    recompute_reason=None):

    # Read-only against threat_intel_evidence (no live HTTP call is ever
    # made here); writes (or, from Step 18 on, UPDATES in place - see the
    # upsert below) ONE row per event in the separate shadow DB; NEVER
    # raises; NEVER returns a value the caller is expected to act on (by
    # design - the caller's own risk_score/severity/reasons are untouched,
    # passed in only to be recorded for comparison).
    #
    # recompute_reason: None for the original, first-ever evaluation of an
    # event (the normal web_event_worker.py call site, unchanged from
    # before Step 18). A non-None string (e.g. "new_evidence:otx") marks a
    # Step 18 asynchronous recompute, triggered by recompute_shadow_for_
    # changed_evidence() below after new/updated evidence arrives for this
    # event's indicator(s) - purely a label for transparency/reporting,
    # never read back into the score itself.
    if not SHADOW_MODE_ENABLED:
        return None

    try:

        conn_main = framework.get_db_connection()

        try:
            evidence_rows = framework.get_all_provider_evidence_for_event_with_conn(
                conn_main, resolved_ip, domain, sha256, md5
            )
        finally:
            conn_main.close()

        # Step 5 pre-check #1 fix: VirusTotal/AbuseIPDB evidence is EXCLUDED
        # from the number added on top of legacy_risk_score, because it is
        # a transcript of the exact same check that already produced
        # legacy_risk_score - counting it again here would double-count
        # the same underlying evidence under a different provider name.
        result = risk.compute_threat_intel_contribution(
            evidence_rows, exclude_providers=DOUBLE_COUNT_RISK_PROVIDERS
        )

        # Transparency only (never affects the score): which excluded
        # providers actually HAD a real signal here, so the UI/report can
        # explain exactly why they were left out rather than silently
        # dropping them.
        excluded_with_signal = sorted({
            row.get("provider") for row in evidence_rows
            if row.get("provider") in DOUBLE_COUNT_RISK_PROVIDERS and risk.eligible_malicious_signal(row)
        })

        reasons = list(result["reasons"])
        if excluded_with_signal:
            reasons.append(
                "Excluded from this delta (already fully reflected in the legacy score above): "
                + ", ".join(excluded_with_signal) + "."
            )

        combined_score = max(0, min(100, int(legacy_risk_score or 0) + result["points"]))
        combined_severity = severity_from_score(combined_score)
        severity_changed = combined_severity != legacy_severity

        shadow_conn = get_shadow_connection()

        try:

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Oct 2026 Step 19 item 2: duplicate/no-op prevention. If an
            # identical evidence set is saved again (same provider, same
            # MATCH, TTL simply refreshed with no real change) - or any
            # other recompute trigger that happens to land on a result
            # that is byte-identical to what is ALREADY stored - writing
            # another row version would be a wasted DB write and, worse,
            # would make recompute_count/evaluated_at claim an "update"
            # that never actually happened. So: compare the freshly
            # computed result against the EXISTING row (if any) BEFORE
            # writing anything, and skip the write entirely when nothing
            # meaningful changed. "Meaningful" is every field that could
            # possibly be visible to an analyst or a report - comparing
            # fewer fields would risk silently hiding a real change.
            existing_row = shadow_conn.execute(
                "SELECT * FROM shadow_comparisons WHERE web_event_id = ?", (web_event_id,)
            ).fetchone()

            new_signal_providers_json = json.dumps(result["signal_providers"])
            new_legacy_reasons_json = json.dumps(list(legacy_reasons or []))
            new_shadow_reasons_json = json.dumps(reasons)
            new_excluded_json = json.dumps(excluded_with_signal)

            is_noop = existing_row is not None and (
                existing_row["shadow_ti_points"] == result["points"]
                and existing_row["shadow_combined_score"] == combined_score
                and existing_row["shadow_combined_severity"] == combined_severity
                and existing_row["severity_changed"] == int(severity_changed)
                and existing_row["decisive"] == int(result["decisive"])
                and existing_row["signal_providers"] == new_signal_providers_json
                and existing_row["legacy_risk_score"] == int(legacy_risk_score or 0)
                and existing_row["legacy_severity"] == legacy_severity
                and existing_row["legacy_reasons"] == new_legacy_reasons_json
                and existing_row["shadow_reasons"] == new_shadow_reasons_json
                and existing_row["excluded_double_count_providers"] == new_excluded_json
            )

            if is_noop:
                # Nothing written: evaluated_at, recompute_count and
                # last_recompute_reason are all left exactly as they were.
                # The caller still gets a valid, fully-populated result
                # (read from the existing row) - this is a successful,
                # cheap no-op, never an error/failure.
                return {
                    "shadow_ti_points": existing_row["shadow_ti_points"],
                    "shadow_combined_score": existing_row["shadow_combined_score"],
                    "shadow_combined_severity": existing_row["shadow_combined_severity"],
                    "severity_changed": bool(existing_row["severity_changed"]),
                    "decisive": bool(existing_row["decisive"]),
                    "signal_providers": result["signal_providers"],
                    "excluded_double_count_providers": excluded_with_signal,
                    "first_evaluated_at": existing_row["first_evaluated_at"],
                    "recompute_count": existing_row["recompute_count"],
                    "no_op": True,
                }

            # Upsert (Step 18): one authoritative row per web_event_id,
            # enforced by the UNIQUE index added in _ensure_schema(). On a
            # genuine first evaluation this INSERTs with recompute_count=0
            # and first_evaluated_at=now. On every later call for the SAME
            # event (i.e. a recompute triggered by new evidence) it UPDATEs
            # the existing row in place instead of appending a duplicate -
            # first_evaluated_at is deliberately left out of the UPDATE SET
            # list so it is never overwritten, and recompute_count is
            # incremented exactly once per such call.
            shadow_conn.execute("""
                INSERT INTO shadow_comparisons (
                    web_event_id, evaluated_at, first_evaluated_at, resolved_ip, domain, sha256, md5,
                    legacy_risk_score, legacy_severity, shadow_ti_points,
                    shadow_combined_score, shadow_combined_severity, severity_changed,
                    decisive, signal_providers, legacy_reasons, shadow_reasons,
                    excluded_double_count_providers, recompute_count, last_recompute_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(web_event_id) DO UPDATE SET
                    evaluated_at = excluded.evaluated_at,
                    resolved_ip = excluded.resolved_ip,
                    domain = excluded.domain,
                    sha256 = excluded.sha256,
                    md5 = excluded.md5,
                    legacy_risk_score = excluded.legacy_risk_score,
                    legacy_severity = excluded.legacy_severity,
                    shadow_ti_points = excluded.shadow_ti_points,
                    shadow_combined_score = excluded.shadow_combined_score,
                    shadow_combined_severity = excluded.shadow_combined_severity,
                    severity_changed = excluded.severity_changed,
                    decisive = excluded.decisive,
                    signal_providers = excluded.signal_providers,
                    legacy_reasons = excluded.legacy_reasons,
                    shadow_reasons = excluded.shadow_reasons,
                    excluded_double_count_providers = excluded.excluded_double_count_providers,
                    recompute_count = shadow_comparisons.recompute_count + 1,
                    last_recompute_reason = excluded.last_recompute_reason
            """, (
                web_event_id, now, now, resolved_ip, domain, sha256, md5,
                int(legacy_risk_score or 0), legacy_severity, result["points"],
                combined_score, combined_severity, int(severity_changed),
                int(result["decisive"]), json.dumps(result["signal_providers"]),
                json.dumps(list(legacy_reasons or [])), json.dumps(reasons),
                json.dumps(excluded_with_signal), recompute_reason
            ))
            shadow_conn.commit()

            updated_row = shadow_conn.execute(
                "SELECT first_evaluated_at, recompute_count FROM shadow_comparisons WHERE web_event_id = ?",
                (web_event_id,)
            ).fetchone()

        finally:
            shadow_conn.close()

        return {
            "shadow_ti_points": result["points"],
            "shadow_combined_score": combined_score,
            "shadow_combined_severity": combined_severity,
            "severity_changed": severity_changed,
            "decisive": result["decisive"],
            "signal_providers": result["signal_providers"],
            "excluded_double_count_providers": excluded_with_signal,
            "first_evaluated_at": updated_row["first_evaluated_at"] if updated_row else now,
            "recompute_count": updated_row["recompute_count"] if updated_row else 0,
            "no_op": False,
        }

    except Exception as exc:
        framework.log_provider_lookup_error("shadow_mode", "EVENT", exc)
        return None


# --------------------------------------------------
# READ-ONLY REPORTING HELPERS (for the comparison report / UI display -
# never called from the live ingest path, never trigger a live lookup or
# write anything)
# --------------------------------------------------

def get_shadow_comparison_for_event(web_event_id):

    # Read-only: the most recent shadow_comparisons row for this event, or
    # None if Shadow Mode has never evaluated it (true for every live event
    # today, since the live worker has not been restarted to pick up Step
    # 4's code - this is expected, not an error). Never raises: a missing
    # shadow DB file/table is treated the same as "no data yet".
    try:
        conn = get_shadow_connection()
    except Exception:
        return None

    try:
        row = conn.execute("""
            SELECT * FROM shadow_comparisons
            WHERE web_event_id = ?
            ORDER BY id DESC LIMIT 1
        """, (web_event_id,)).fetchone()
        return dict(row) if row else None
    except Exception:
        return None
    finally:
        conn.close()


# --------------------------------------------------
# OCT 2026 STEP 18: ASYNCHRONOUS RECOMPUTE ON NEW EVIDENCE
# --------------------------------------------------
# threat_intel_worker.py runs independently of web_event_worker.py: an
# event can be fully analyzed (legacy risk_score/severity finalized,
# Shadow's FIRST evaluation already recorded) BEFORE a slower async
# provider (e.g. a rate-limited or not-yet-cached indicator) has actually
# returned evidence for that same event's IP/domain/hash. When that
# evidence lands later, the persisted shadow_comparisons row for every
# affected event is stale until something re-runs evaluate_shadow() for
# it. This section is that "something" - entirely Shadow-side, entirely
# additive, called ONLY from threat_intel_worker.py's own cycle (never
# from web_event_worker.py's ingest path, so event ingestion latency is
# completely unaffected - see the hook in threat_intel_worker.py and its
# own test coverage for the performance claim).
#
# Bounding (explicit requirement - never scan unlimited history):
#   - find_events_for_changed_indicators() only looks at events that
#     match one of the indicators the CALLER says actually changed this
#     cycle (never a blind "all events" scan).
#   - A hard LIMIT per indicator query AND a hard cap on the total number
#     of distinct events recomputed in one call (SHADOW_RECOMPUTE_MAX_
#     EVENTS_PER_CYCLE), so a burst of newly-arrived evidence can never
#     turn into an unbounded recompute pass.
#   - Only events with a FINISHED legacy analysis are eligible (analysis_
#     status='ANALYZED') - recomputing against an in-progress/pending
#     legacy result would record a comparison against a result that is
#     about to change anyway, which is wasted and potentially misleading
#     work.
#   - Deduplication: an event matching more than one changed indicator in
#     the same cycle (e.g. both its IP and its domain had new evidence
#     arrive) is still recomputed exactly ONCE per call (set-based, same
#     discipline as threat_intel_worker.find_enrichment_work()'s own
#     indicator-level dedup).
SHADOW_RECOMPUTE_MAX_EVENTS_PER_CYCLE = int(os.getenv("SHADOW_RECOMPUTE_MAX_EVENTS_PER_CYCLE", "50"))

# --------------------------------------------------
# OCT 2026 STEP 20: FAIR (ROUND-ROBIN) WORK DISTRIBUTION
# --------------------------------------------------
# Root cause found live in Step 19's activation: a single indicator with
# far more matching ANALYZED events than SHADOW_RECOMPUTE_MAX_EVENTS_PER_
# CYCLE (confirmed live - a browser process hash shared by 5,029 events)
# would consume the ENTIRE per-cycle budget by itself, every cycle, for as
# long as it stayed oldest in the FIFO queue - starving every other queued
# indicator (62 of 63, in the live observation) of even a SINGLE attempt,
# indefinitely. Nothing was lost or corrupted (the queue is durable and
# exact), but fairness was not bounded - a real defect, fixed here.
#
# SHADOW_RECOMPUTE_PER_INDICATOR_MAX_EVENTS_PER_CYCLE: a hard ceiling on
# how many events ANY SINGLE indicator may consume in ONE call, even when
# it is the only indicator being processed and idle budget would
# otherwise allow more. This directly bounds the worst case (one giant
# indicator can never again swallow the whole cycle) and leaves headroom
# within the SAME cycle for new evidence that arrives while an older,
# large indicator is still mid-drain (explicit Step 20 requirement).
SHADOW_RECOMPUTE_PER_INDICATOR_MAX_EVENTS_PER_CYCLE = int(
    os.getenv("SHADOW_RECOMPUTE_PER_INDICATOR_MAX_EVENTS_PER_CYCLE", "10")
)

# Per-indicator column to match against on web_events - mirrors
# threat_intel_framework.all_candidate_indicators_for_event()'s own
# IP/DOMAIN/SHA256/MD5 vocabulary exactly, so a caller passing the same
# (indicator_type, indicator_value) pairs threat_intel_worker.py already
# produces needs no translation.
_INDICATOR_COLUMN = {
    "IP": "resolved_ip",
    "DOMAIN": "domain",
    "SHA256": "sha256",
    "MD5": "md5",
}


def find_events_for_changed_indicators(conn, changed_indicators, max_events=None, cursors=None,
                                        per_indicator_max_events=None):

    # Read-only lookup against the MAIN database (web_events) - never
    # writes anything. Returns an ordered list of dicts, each one distinct
    # web_event row plus the (indicator_type, indicator_value) that first
    # matched it, capped at max_events total. changed_indicators is an
    # iterable of (indicator_type, indicator_value) tuples, e.g. exactly
    # what threat_intel_worker.run_cycle() collects from its own
    # already-bounded, already-deduplicated dispatch loop this cycle.
    #
    # cursors (Step 19 item 1 - continuation): optional {(indicator_type,
    # indicator_value): last_processed_event_id} map. Each indicator's
    # events are returned newest-first (id DESC); once an indicator has
    # been partially drained in an earlier call, its cursor is the
    # smallest id already handled - passing it here resumes strictly
    # BELOW that id, so a later call for the same indicator can never
    # re-return rows an earlier call already consumed. Omitted/None for
    # an indicator means "start from the newest matching row".
    #
    # Fair distribution (Step 20): indicators are served in ROUNDS, in
    # the CALLER's given order (FIFO priority is the caller's
    # responsibility - see recompute_shadow_for_changed_evidence, which
    # puts previously-queued indicators first). Each round recomputes an
    # ADAPTIVE quantum = max(1, remaining_budget // still-active-indicator
    # -count), so:
    #   - under heavy contention (many waiting indicators), the quantum
    #     shrinks toward 1 - EVERY indicator that fits within the overall
    #     budget gets touched this call, none can hog it;
    #   - under light contention (few waiting indicators), the quantum
    #     grows - idle budget is still used efficiently, no artificial
    #     slowdown when there is no one to be unfair to;
    #   - per_indicator_max_events additionally hard-caps any ONE
    #     indicator's total take in this single call, independent of how
    #     much idle budget exists - so even the ONLY indicator in the
    #     queue can never again consume the entire cycle, leaving
    #     headroom for newly-arrived evidence in the SAME cycle.
    # This is a standard max-min fair-share scheduler, applied to a SQL
    # LIMIT/cursor pagination rather than an in-memory queue.
    if max_events is None:
        max_events = SHADOW_RECOMPUTE_MAX_EVENTS_PER_CYCLE
    if per_indicator_max_events is None:
        per_indicator_max_events = SHADOW_RECOMPUTE_PER_INDICATOR_MAX_EVENTS_PER_CYCLE

    if max_events <= 0 or not changed_indicators:
        return []

    # De-dup the indicator list itself up front, preserving the caller's
    # order (FIFO priority) - a repeated tuple must not get two separate
    # "lanes" in the round-robin.
    indicator_list = list(dict.fromkeys(tuple(x) for x in changed_indicators))

    cursors = dict(cursors or {})  # local working copy; advances as rows are consumed
    taken_per_indicator = {}       # this call's own running total, for the hard per-indicator cap
    exhausted = set()              # confirmed (this call) to have no more matching rows below their cursor
    seen_event_ids = set()
    matches = []

    while len(matches) < max_events:

        active = [key for key in indicator_list if key not in exhausted]
        if not active:
            break

        remaining_budget = max_events - len(matches)
        quantum = max(1, remaining_budget // len(active))

        made_progress_this_round = False

        for indicator_type, indicator_value in active:

            if len(matches) >= max_events:
                break

            key = (indicator_type, indicator_value)
            column = _INDICATOR_COLUMN.get(indicator_type)
            if not column or not indicator_value:
                exhausted.add(key)
                continue

            already_taken = taken_per_indicator.get(key, 0)
            per_indicator_headroom = per_indicator_max_events - already_taken
            if per_indicator_headroom <= 0:
                # This indicator hit its OWN hard ceiling for this call -
                # not "exhausted" (more rows may genuinely remain below
                # its cursor for a LATER call/cycle), just paused here.
                continue

            take = min(quantum, max_events - len(matches), per_indicator_headroom)
            cursor = cursors.get(key)

            if cursor is not None:
                rows = conn.execute(f"""
                    SELECT id, resolved_ip, domain, sha256, md5, risk_score, severity, details
                    FROM web_events
                    WHERE {column} = ? AND analysis_status = 'ANALYZED' AND id < ?
                    ORDER BY id DESC
                    LIMIT ?
                """, (indicator_value, cursor, take)).fetchall()
            else:
                rows = conn.execute(f"""
                    SELECT id, resolved_ip, domain, sha256, md5, risk_score, severity, details
                    FROM web_events
                    WHERE {column} = ? AND analysis_status = 'ANALYZED'
                    ORDER BY id DESC
                    LIMIT ?
                """, (indicator_value, take)).fetchall()

            if not rows:
                exhausted.add(key)
                continue

            min_id_this_batch = None
            for row in rows:
                if row["id"] not in seen_event_ids:
                    seen_event_ids.add(row["id"])
                    matches.append({
                        "event": dict(row),
                        "indicator_type": indicator_type,
                        "indicator_value": indicator_value,
                    })
                    made_progress_this_round = True
                    if min_id_this_batch is None or row["id"] < min_id_this_batch:
                        min_id_this_batch = row["id"]
                if len(matches) >= max_events:
                    break

            if min_id_this_batch is not None:
                cursors[key] = min_id_this_batch
                taken_per_indicator[key] = already_taken + len(rows)

            if len(rows) < take:
                # Fewer rows than requested were returned - genuinely
                # nothing left below this cursor for this indicator.
                exhausted.add(key)

        if not made_progress_this_round:
            # Every remaining active indicator is either paused at its
            # per-indicator ceiling or returned nothing new - stop rather
            # than spin (the per-indicator-ceiling case is picked up again
            # on the NEXT call/cycle, never lost).
            break

    return matches


def _dequeue_recompute_indicator(shadow_conn, indicator_type, indicator_value):
    shadow_conn.execute(
        "DELETE FROM shadow_recompute_queue WHERE indicator_type = ? AND indicator_value = ?",
        (indicator_type, indicator_value)
    )


def _enqueue_recompute_indicator(shadow_conn, indicator_type, indicator_value, cursor=None):
    # queued_at is set only on first insert (never touched again) so FIFO
    # ordering reflects how long an indicator has been waiting, not how
    # recently its cursor last advanced; last_processed_id DOES update on
    # conflict, since that is exactly the progress being recorded.
    shadow_conn.execute("""
        INSERT INTO shadow_recompute_queue (indicator_type, indicator_value, queued_at, last_processed_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET
            last_processed_id = excluded.last_processed_id
    """, (indicator_type, indicator_value, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), cursor))


def recompute_shadow_for_changed_evidence(changed_indicators, conn=None, max_events=None):

    # The single entry point threat_intel_worker.py calls, once per cycle,
    # with the list of (indicator_type, indicator_value) pairs that
    # actually received a REAL new lookup result this cycle (never called
    # for cache hits/no-op dispatches - the worker's own per-cycle budget
    # already bounds how many such indicators can exist). NEVER raises -
    # mirrors evaluate_shadow()'s own isolation discipline so a problem
    # here can never interrupt the worker's normal cycle.
    #
    # events_recomputed vs events_unchanged (Step 19 item 2): every
    # matched event is evaluated, but a result that is byte-identical to
    # what was ALREADY stored (evaluate_shadow()'s own no-op detection)
    # counts as "unchanged", not "recomputed" - no DB write, no
    # recompute_count bump. This is the explicit duplicate/redundant-
    # computation guard: an identical evidence row being re-saved (e.g. a
    # provider's TTL simply refreshing the same MATCH) does real, cheap,
    # in-memory work to CONFIRM nothing changed, but never touches disk or
    # claims an "update" that never happened.
    #
    # pending_indicators (Step 19 item 1): indicators that still have more
    # matching, already-analyzed events than this call's bound allowed are
    # persisted in shadow_recompute_queue (FIFO) so a LATER call continues
    # automatically - nothing is ever silently dropped, and no single call
    # is ever allowed to scan more than max_events events.
    summary = {
        "events_considered": 0,
        "events_recomputed": 0,
        "events_unchanged": 0,
        "events_failed": 0,
        "pending_indicators": 0,
    }

    if not SHADOW_MODE_ENABLED:
        return summary

    own_conn = conn is None
    shadow_conn = None

    try:
        conn = conn or framework.get_db_connection()
        shadow_conn = get_shadow_connection()

        queue_rows = shadow_conn.execute(
            "SELECT indicator_type, indicator_value, last_processed_id FROM shadow_recompute_queue ORDER BY queued_at ASC"
        ).fetchall()
        queued = [(row["indicator_type"], row["indicator_value"]) for row in queue_rows]
        existing_cursors = {
            (row["indicator_type"], row["indicator_value"]): row["last_processed_id"]
            for row in queue_rows if row["last_processed_id"] is not None
        }

        # FIFO priority: indicators already queued from a PRIOR cycle's
        # overflow are handled before this cycle's newly-changed ones, so
        # a persistent backlog makes guaranteed forward progress every
        # cycle rather than being starved by a steady stream of new work.
        combined = list(dict.fromkeys(queued + [tuple(x) for x in (changed_indicators or [])]))

        if not combined:
            return summary

        effective_max = max_events if max_events is not None else SHADOW_RECOMPUTE_MAX_EVENTS_PER_CYCLE

        # cursors ensure a continuation call can never re-return rows an
        # earlier call already consumed for the same indicator (see
        # find_events_for_changed_indicators's own docstring) - this is
        # what makes the queue a genuine continuation, not just a repeat.
        matches = find_events_for_changed_indicators(conn, combined, max_events=effective_max, cursors=existing_cursors)
        summary["events_considered"] = len(matches)

        min_id_consumed_this_call = {}
        for m in matches:
            key = (m["indicator_type"], m["indicator_value"])
            eid = m["event"]["id"]
            if key not in min_id_consumed_this_call or eid < min_id_consumed_this_call[key]:
                min_id_consumed_this_call[key] = eid

        # Step 20 item 3 (failure mid-cycle + safe continuation after a
        # restart): the queue's cursor is ONLY advanced/committed AFTER
        # the per-event evaluate_shadow() loop below has actually run for
        # every matched row - NEVER before. If the whole process were
        # killed/crashed partway through that loop, the queue would still
        # hold the PREVIOUS cursor (nothing committed yet), so the very
        # same batch is re-selected and retried in full on the next call -
        # never silently skipped. Re-processing an event that already
        # succeeded just before the crash is safe and cheap: evaluate_
        # shadow()'s own no-op detection (Step 19 item 2) recognizes the
        # already-current result and writes nothing a second time.
        for match in matches:
            event = match["event"]
            reason = f"new_evidence:{match['indicator_type']}={match['indicator_value']}"

            try:
                result = evaluate_shadow(
                    web_event_id=event["id"],
                    resolved_ip=event["resolved_ip"],
                    domain=event["domain"],
                    sha256=event["sha256"],
                    md5=event["md5"],
                    legacy_risk_score=event["risk_score"],
                    legacy_severity=event["severity"],
                    # web_events.details is a plain "; "-joined string
                    # (see web_event_worker.py), never JSON - wrapped as a
                    # single-item list rather than re-split, which would
                    # be fragile if any individual reason itself contains
                    # "; ".
                    legacy_reasons=[event["details"]] if event["details"] else [],
                    recompute_reason=reason,
                )
                if result is None:
                    summary["events_failed"] += 1
                elif result.get("no_op"):
                    summary["events_unchanged"] += 1
                else:
                    summary["events_recomputed"] += 1
            except Exception as exc:
                summary["events_failed"] += 1
                framework.log_provider_lookup_error("shadow_mode_recompute", "EVENT", exc)

        # ONLY NOW (after every matched row has actually been attempted)
        # commit the queue's progress: an indicator with more matching
        # ANALYZED events still below its (possibly just-advanced) cursor
        # stays queued for continuation; a fully-drained indicator is
        # removed. A cheap COUNT(*) per distinct indicator - never a
        # second unbounded scan of all events.
        for indicator_type, indicator_value in combined:

            column = _INDICATOR_COLUMN.get(indicator_type)
            if not column or not indicator_value:
                _dequeue_recompute_indicator(shadow_conn, indicator_type, indicator_value)
                continue

            key = (indicator_type, indicator_value)
            # If this call consumed anything for this indicator, its
            # cursor advances to the smallest id just processed. Otherwise
            # (budget ran out before reaching it, or its own per-indicator
            # ceiling paused it) keep whatever cursor it already had
            # (None if it never started).
            new_cursor = min_id_consumed_this_call.get(key, existing_cursors.get(key))

            if new_cursor is not None:
                remaining_count = conn.execute(
                    f"SELECT COUNT(*) FROM web_events WHERE {column} = ? AND analysis_status = 'ANALYZED' AND id < ?",
                    (indicator_value, new_cursor)
                ).fetchone()[0]
            else:
                remaining_count = conn.execute(
                    f"SELECT COUNT(*) FROM web_events WHERE {column} = ? AND analysis_status = 'ANALYZED'",
                    (indicator_value,)
                ).fetchone()[0]

            if remaining_count > 0:
                _enqueue_recompute_indicator(shadow_conn, indicator_type, indicator_value, cursor=new_cursor)
            else:
                _dequeue_recompute_indicator(shadow_conn, indicator_type, indicator_value)

        shadow_conn.commit()

        summary["pending_indicators"] = shadow_conn.execute(
            "SELECT COUNT(*) FROM shadow_recompute_queue"
        ).fetchone()[0]

        return summary

    except Exception as exc:
        framework.log_provider_lookup_error("shadow_mode_recompute", "CYCLE", exc)
        return summary

    finally:
        if shadow_conn is not None:
            shadow_conn.close()
        if own_conn and conn is not None:
            conn.close()


def summarize_shadow_results(conn=None):

    own = conn is None
    conn = conn or get_shadow_connection()

    try:
        total = conn.execute("SELECT COUNT(*) FROM shadow_comparisons").fetchone()[0]
        changed = conn.execute("SELECT COUNT(*) FROM shadow_comparisons WHERE severity_changed = 1").fetchone()[0]
        decisive = conn.execute("SELECT COUNT(*) FROM shadow_comparisons WHERE decisive = 1").fetchone()[0]
        nonzero = conn.execute("SELECT COUNT(*) FROM shadow_comparisons WHERE shadow_ti_points > 0").fetchone()[0]

        return {
            "total_evaluated": total,
            "nonzero_contribution": nonzero,
            "severity_would_change": changed,
            "decisive_matches": decisive,
        }
    finally:
        if own:
            conn.close()


def get_shadow_recompute_status(conn=None):

    # Read-only monitoring helper for Step 19 Part B's live observation
    # (and for any future dashboard) - never triggers a computation.
    # recomputed_events/unchanged_events aggregate the PERSISTED outcome
    # markers (recompute_count > 0, last_recompute_reason) rather than any
    # per-call summary, so this is meaningful even from a cold read (e.g.
    # right after a process restart) with no in-memory state required.
    own = conn is None
    conn = conn or get_shadow_connection()

    try:
        pending = conn.execute("SELECT COUNT(*) FROM shadow_recompute_queue").fetchone()[0]
        recomputed_events = conn.execute(
            "SELECT COUNT(*) FROM shadow_comparisons WHERE recompute_count > 0"
        ).fetchone()[0]
        total_recomputes = conn.execute(
            "SELECT COALESCE(SUM(recompute_count), 0) FROM shadow_comparisons"
        ).fetchone()[0]
        last_recompute_at = conn.execute(
            "SELECT MAX(evaluated_at) FROM shadow_comparisons WHERE recompute_count > 0"
        ).fetchone()[0]

        return {
            "pending_indicators": pending,
            "events_with_at_least_one_recompute": recomputed_events,
            "total_recompute_operations": total_recomputes,
            "last_recompute_at": last_recompute_at,
        }
    finally:
        if own:
            conn.close()
