# ==================================================
# STEP 24B.2A: LOCAL THREAT INTELLIGENCE FEED - EVENT-LEVEL EVIDENCE
# ==================================================
#
# This is the ONLY module that (a) builds an event's candidate
# indicators for Local Feed matching, (b) calls local_feed_store's
# exact-indexed lookup, and (c) persists a MATCH into storage. It is the
# single call site both web_event_worker.py (Phase 4, TCP events) and a
# future Web Monitoring display route (browser-URL events) are meant to
# use, so both pipelines share identical matching/evidence behaviour.
#
# EVIDENCE ISOLATION (see the Step 24B.2A report for the full
# investigation): a MATCH is persisted to a BRAND-NEW, dedicated table,
# `local_feed_match_evidence` - NOT threat_intel_framework's shared
# `threat_intel_evidence` table. Investigation found that
# threat_intel_shadow.evaluate_shadow() fetches ALL threat_intel_evidence
# rows for an event's (resolved_ip, domain) via
# get_all_provider_evidence_for_event_with_conn() with no provider
# whitelist at the SQL level, relying entirely on
# threat_intel_framework.PROVIDER_REGISTRY's evidence_class to exclude
# non-malicious_evidence providers from scoring. An unregistered
# provider name defaults to "context_only" there today (so a row would
# not currently change Shadow TI's score) - but writing into that same
# shared table would make Shadow TI's "zero effect" guarantee depend on
# nobody ever registering this provider name in PROVIDER_REGISTRY later,
# which is exactly the kind of structural risk Step 24B.2's standing
# instruction ("never change Legacy TI or Shadow TI") rules out. A
# wholly separate table makes the isolation structural, not incidental:
# neither Legacy TI nor Shadow TI's code reads a table that does not
# exist in their imports.
#
# NO_MATCH results are never persisted (see the Step 24B.2A report): a
# Local Feed lookup is a free, local index read with no rate limit and
# no external cost, so - unlike ThreatFox's cache, which exists to avoid
# repeating a throttled live HTTP call - there is nothing to cache.
# Writing a permanent row for every non-matching candidate on every
# event would only bloat storage for no benefit. "No row" is correctly
# read by get_display_rows_for_event() below as NO_MATCH, never as
# "safe" (see classify/status handling throughout).
# ==================================================

import os
from datetime import datetime

import db_config
import local_feed_normalize
import local_feed_providers
import local_feed_store

_soc_db_path_override = os.getenv("SOC_DB_PATH", "").strip()

if _soc_db_path_override:
    if os.path.isabs(_soc_db_path_override):
        _DB_NAME = _soc_db_path_override
    else:
        _DB_NAME = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), _soc_db_path_override
        )
else:
    _DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersec.db")


def _ensure_schema(conn):

    conn.execute("""
        CREATE TABLE IF NOT EXISTS local_feed_match_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            feed_name TEXT,
            indicator_type TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            raw_value TEXT,
            first_seen TEXT,
            last_seen TEXT,
            provider_metadata_json TEXT,
            feed_version INTEGER,
            feed_updated_at TEXT,
            feed_status_at_match TEXT,
            matched_at TEXT NOT NULL,
            UNIQUE(provider, indicator_type, normalized_value)
        )
    """)
    conn.commit()


def get_db_connection():

    conn = db_config.open_connection(_DB_NAME)
    _ensure_schema(conn)
    return conn


# --------------------------------------------------
# CANDIDATE BUILDING (uses local_feed_normalize on BOTH sides of every
# match - see that module's header for why this is deliberately not
# threat_intel_framework's candidate builder)
# --------------------------------------------------

def candidate_indicators_for_event(resolved_ip=None, domain=None, url=None):

    candidates = []

    for raw_type, raw_value in (("IP", resolved_ip), ("DOMAIN", domain), ("URL", url)):

        normalized_type, normalized_value = local_feed_normalize.classify_and_normalize(
            raw_type, raw_value
        )

        if normalized_value is not None:
            candidates.append((normalized_type, normalized_value))

    return candidates


# --------------------------------------------------
# LOOKUP (read-only, no persistence - safe to call from display code as
# often as needed, since it is a cheap local index read)
# --------------------------------------------------

def lookup_candidates_for_event(resolved_ip=None, domain=None, url=None,
                                 providers=None, base_dir=None):
    """
    Returns a list of per-provider dicts:
      {"provider": str, "feed_status": {...from local_feed_store...},
       "matches": [row, ...]}   (matches is [] when the feed is loaded
                                 but nothing matched; feed_status alone
                                 explains a NEVER_LOADED provider)
    """

    providers = providers or local_feed_providers.known_providers()
    candidates = candidate_indicators_for_event(resolved_ip, domain, url)

    results = []

    for provider in providers:

        feed_status = local_feed_store.get_feed_status(provider, base_dir=base_dir)
        matches = []

        if feed_status["status"] != "NEVER_LOADED":

            for indicator_type, normalized_value in candidates:

                if not local_feed_providers.provider_supports_indicator_type(
                    provider, indicator_type
                ):
                    continue

                row, _status = local_feed_store.lookup_indicator(
                    provider, indicator_type, normalized_value, base_dir=base_dir
                )

                if row is not None:
                    matches.append(row)

        results.append({
            "provider": provider,
            "feed_status": feed_status,
            "matches": matches,
        })

    return results


# --------------------------------------------------
# EVIDENCE WRITE (MATCH only - see module header)
# --------------------------------------------------

def _record_match(conn, provider, feed_status, match_row, now):

    matched_at = now.strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        INSERT INTO local_feed_match_evidence (
            provider, feed_name, indicator_type, normalized_value,
            raw_value, first_seen, last_seen, provider_metadata_json,
            feed_version, feed_updated_at, feed_status_at_match,
            matched_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider, indicator_type, normalized_value) DO UPDATE SET
            feed_name = excluded.feed_name,
            raw_value = excluded.raw_value,
            first_seen = excluded.first_seen,
            last_seen = excluded.last_seen,
            provider_metadata_json = excluded.provider_metadata_json,
            feed_version = excluded.feed_version,
            feed_updated_at = excluded.feed_updated_at,
            feed_status_at_match = excluded.feed_status_at_match,
            matched_at = excluded.matched_at
    """, (
        provider, feed_status.get("feed_name"),
        match_row["indicator_type"], match_row["normalized_value"],
        match_row.get("raw_value"), match_row.get("first_seen"),
        match_row.get("last_seen"), match_row.get("provider_metadata_json"),
        feed_status.get("version"), feed_status.get("feed_updated_at"),
        feed_status.get("status"), matched_at,
    ))


def lookup_and_record_for_event(resolved_ip=None, domain=None, url=None,
                                 providers=None, base_dir=None, now=None):
    """
    Full read+write entry point. Intended caller: web_event_worker.py's
    Phase 4 block (TCP events) and, for a URL-only call, any future
    browser-event pipeline - this function does not care which fields
    are populated, only that at least one normalizes to a usable
    candidate.

    EXPLICITLY DOES NOT: touch risk_score/severity/reasons/decision,
    create a Security Alert/Incident, touch response_commands, or raise
    on a lookup/storage problem that should not be allowed to interrupt
    the caller - callers must still wrap this in their own try/except
    (see web_event_worker.py), matching the existing ThreatFox call
    site's own convention, rather than this function silently
    swallowing errors itself.

    Returns the same list shape as lookup_candidates_for_event().
    """

    now = now or datetime.now()
    results = lookup_candidates_for_event(resolved_ip, domain, url, providers, base_dir)

    any_match = any(entry["matches"] for entry in results)

    if any_match:

        conn = get_db_connection()

        try:
            for entry in results:
                for match_row in entry["matches"]:
                    _record_match(conn, entry["provider"], entry["feed_status"], match_row, now)
            conn.commit()
        finally:
            conn.close()

    return results


# --------------------------------------------------
# DISPLAY (section 12 - minimal dashboard rows: Source / Indicator type
# / MATCH|NO_MATCH / feed freshness / detection time. NEVER_LOADED and
# STALE are feed-level facts kept on their own field - a STALE feed can
# still show a MATCH (a historical finding), but it is always shown
# alongside feed_status so a STALE match is never presented as an
# unqualified current finding - see the module header / Step 24B.2A
# instruction #10.
# --------------------------------------------------

def get_display_rows_for_event(resolved_ip=None, domain=None, url=None,
                                providers=None, base_dir=None):

    raw_results = lookup_candidates_for_event(resolved_ip, domain, url, providers, base_dir)

    rows = []

    for entry in raw_results:

        provider = entry["provider"]
        feed_status = entry["feed_status"]

        if feed_status["status"] == "NEVER_LOADED":
            rows.append({
                "provider": provider,
                "feed_status": "NEVER_LOADED",
                "match_status": None,
                "indicator_type": None,
                "feed_freshness": None,
                "detection_time": None,
            })
            continue

        freshness = {
            "feed_updated_at": feed_status.get("feed_updated_at"),
            "local_imported_at": feed_status.get("local_imported_at"),
        }

        if entry["matches"]:
            for match_row in entry["matches"]:
                rows.append({
                    "provider": provider,
                    "feed_status": feed_status["status"],  # CURRENT or STALE
                    "match_status": "MATCH",
                    "indicator_type": match_row["indicator_type"],
                    "feed_freshness": freshness,
                    "detection_time": None,  # filled from local_feed_match_evidence by the caller, if needed
                })
        else:
            rows.append({
                "provider": provider,
                "feed_status": feed_status["status"],
                "match_status": "NO_MATCH",
                "indicator_type": None,
                "feed_freshness": freshness,
                "detection_time": None,
            })

    return rows
