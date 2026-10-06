# ==================================================
# OCT 2026 STEP 5: SHARED READ-ONLY DISPLAY + MANUAL RE-CHECK HELPERS
# ==================================================
#
# Used by /threat-intel, /reputation and /web-monitoring so none of the
# three pages duplicates this logic. Two concerns, both read-mostly:
#   1. provider_status_table(): READ-ONLY connection-status/last-check
#      summary for every provider (never performs a live lookup).
#   2. force_recheck(): the ONLY place that performs a live lookup from a
#      UI action - admin-gated by the caller (route), respects each
#      provider's OWN existing manual_eligible/configuration/quota/backoff
#      rules exactly as the automatic path does (never bypasses them). It
#      only invalidates the cached row first so the next read is live
#      instead of a cache hit - the provider's own function still decides
#      whether that live call is actually allowed right now.
#
# NEVER creates/touches security_alerts, response_commands, blocked_domains
# or any block/isolate action. NEVER changes risk_score/severity/decision
# of any web_event. NEVER activates Shadow Mode - shadow_comparison_for()
# below is a pure READ against the (currently empty, on the live system)
# shadow database; it cannot cause Shadow Mode to evaluate anything.
# ==================================================

import os

import threat_intel_framework as framework
import threat_intel_risk as risk
import threat_intel_shadow as shadow
from threat_intelligence import severity_from_score

import threat_intel_providers
import urlhaus_provider
import virustotal_provider
import otx_provider
import greynoise_provider
import google_safe_browsing_provider
import phishtank_provider
import urlscan_provider
import ipqualityscore_provider
import shodan_provider
import censys_provider
import provider_health

# Providers with an independent, callable "fetch evidence" function this
# module can dispatch a manual re-check to. NOT included:
#   "abuseipdb" - has no independent live query; its threat_intel_evidence
#     row is DERIVED from the legacy reputation check and refreshes
#     automatically whenever that runs - there is nothing separate here to
#     re-check on demand.
#   "cloudflare" - already has its own dedicated, budget-aware, manual-
#     only "Investigate with Cloudflare" flow elsewhere in this app
#     (cloudflare_provider.get_action_state/query_cloudflare_live) - not
#     duplicated or second-guessed here.
RECHECKABLE_PROVIDERS = {
    "threatfox": threat_intel_providers.get_threatfox_evidence,
    "urlhaus": urlhaus_provider.get_urlhaus_evidence,
    "virustotal": virustotal_provider.get_virustotal_evidence,
    "alienvault_otx": otx_provider.get_otx_evidence,
    "greynoise": greynoise_provider.get_greynoise_evidence,
    "google_safe_browsing": google_safe_browsing_provider.get_google_safe_browsing_evidence,
    "phishtank": phishtank_provider.get_phishtank_evidence,
    "urlscan": urlscan_provider.get_urlscan_evidence,
    "ipqualityscore": ipqualityscore_provider.get_ipqualityscore_evidence,
    "shodan": shodan_provider.get_shodan_evidence,
    "censys": censys_provider.get_censys_evidence,
}


# --------------------------------------------------
# PROVIDER CONNECTION STATUS (read-only)
# --------------------------------------------------

def provider_status_table():

    # One row per provider in PROVIDER_REGISTRY: name, configured (bool),
    # automatic/manual eligibility, evidence_class, counts by
    # lookup_status, and the most recent retrieved_at. Entirely read-only
    # aggregate SQL against threat_intel_evidence - never a live lookup.
    conn = framework.get_db_connection()

    try:

        rows = conn.execute("""
            SELECT provider, lookup_status, COUNT(*) AS n, MAX(retrieved_at) AS last_at
            FROM threat_intel_evidence
            GROUP BY provider, lookup_status
        """).fetchall()

    finally:
        conn.close()

    by_provider = {}

    for row in rows:
        entry = by_provider.setdefault(row["provider"], {"counts": {}, "last_at": None})
        entry["counts"][row["lookup_status"]] = row["n"]
        if row["last_at"] and (entry["last_at"] is None or row["last_at"] > entry["last_at"]):
            entry["last_at"] = row["last_at"]

    table = []

    for name, meta in sorted(framework.PROVIDER_REGISTRY.items()):

        if not meta.get("implemented"):
            continue

        stats = by_provider.get(name, {"counts": {}, "last_at": None})
        configured = framework.get_provider_configuration_state(name) == framework.CONFIG_STATE_AVAILABLE

        table.append({
            "provider": name,
            "configured": configured,
            "requires_api_key": bool(meta.get("requires_api_key", True)),
            "signup_url": framework.PROVIDER_SIGNUP_URLS.get(name),
            "evidence_class": meta.get("evidence_class"),
            "automatic_eligible": bool(meta.get("automatic_eligible")),
            "manual_eligible": bool(meta.get("manual_eligible")),
            "recheckable": name in RECHECKABLE_PROVIDERS,
            "match_count": stats["counts"].get("MATCH", 0),
            "no_match_count": stats["counts"].get("NO_MATCH", 0),
            "error_count": stats["counts"].get("ERROR", 0),
            "rate_limited_count": stats["counts"].get("RATE_LIMITED", 0),
            "last_checked_at": stats["last_at"],
        })

    return table


# --------------------------------------------------
# MANUAL RE-CHECK (the only live-lookup trigger in this module)
# --------------------------------------------------

def force_recheck(provider, indicator_type, indicator_value):

    # Caller (the Flask route) is responsible for admin authentication -
    # this function assumes that has already happened. Returns
    # {"error": str} on any rejection/failure, or the fresh evidence dict
    # (with "classification" added) on success. Never raises to the
    # caller.
    func = RECHECKABLE_PROVIDERS.get(provider)

    if func is None:
        return {"error": "This provider does not support a manual re-check here."}

    meta = framework.PROVIDER_REGISTRY.get(provider) or {}

    if not meta.get("manual_eligible"):
        return {"error": "This provider is not manual-eligible."}

    if not framework.provider_supports_indicator(provider, indicator_type, indicator_value):
        return {"error": "This provider does not support this indicator type."}

    # A provider is eligible for a manual re-check if it has a configured
    # key, OR its registry entry says it is doc-verified to work keyless
    # (GreyNoise/PhishTank/urlscan.io - see their PROVIDER_REGISTRY
    # comments and provider modules). get_provider_configuration_state()
    # alone would incorrectly block these, since it only checks whether
    # an (optional, for these three) key env var is set.
    requires_key = bool(meta.get("requires_api_key", True))

    if requires_key and framework.get_provider_configuration_state(provider) != framework.CONFIG_STATE_AVAILABLE:
        return {"error": "This provider is not configured (missing API key)."}

    # Stage 25D section 13: single-flight guard against the automatic
    # worker (threat_intel_worker.py, a SEPARATE OS process) racing
    # this exact (provider, indicator_type, indicator_value) at the
    # same moment. If busy, tell the admin plainly rather than firing a
    # second simultaneous live call for the same indicator.
    try:
        got_lock = provider_health.acquire_lookup_lock(provider, indicator_type, indicator_value)
    except Exception:
        got_lock = True

    if not got_lock:
        return {"error": "A lookup for this indicator is already in progress - try again shortly."}

    try:

        conn = framework.get_db_connection()

        try:
            conn.execute("""
                DELETE FROM threat_intel_evidence
                WHERE provider = ? AND indicator_type = ? AND indicator_value = ?
            """, (provider, indicator_type, indicator_value))
            conn.commit()
        finally:
            conn.close()

        # The provider's OWN function still applies its own quota/backoff/
        # rate-limit rules (e.g. virustotal_provider's internal quota
        # state) - clearing the cache row above only means THIS call is
        # not served from cache; it does not bypass any provider's own
        # safeguards.
        result = func(indicator_type, indicator_value)

    except Exception as exc:
        framework.log_provider_lookup_error(provider, indicator_type, exc)
        return {"error": "Unexpected error during re-check."}

    finally:
        try:
            provider_health.release_lookup_lock(provider, indicator_type, indicator_value)
        except Exception:
            pass

    result = dict(result)
    result["classification"] = framework.classify_evidence(
        provider, result.get("lookup_status"), indicator_type,
        result.get("analysis_stats"), result.get("threat_type")
    )
    return result


# --------------------------------------------------
# SHADOW COMPARISON (read-only; never activates Shadow Mode)
# --------------------------------------------------

def shadow_comparison_for_event(web_event_id):

    return shadow.get_shadow_comparison_for_event(web_event_id)


# --------------------------------------------------
# LIVE, DISPLAY-ONLY COMPARISON (page-render time only - NEVER persisted,
# NEVER written anywhere, NEVER activates the Step 4 Shadow Mode pipeline)
# --------------------------------------------------
#
# Used by pages that have a specific indicator already in view (a Web
# Monitoring event row, an analyzed Reputation IP) but no web_event_id to
# look up a PERSISTED shadow_comparisons row against (e.g. the Reputation
# page analyzes a raw IP, not a specific stored event). This performs the
# EXACT SAME read-only computation as threat_intel_shadow.evaluate_shadow()
# (same exclude_providers double-counting fix, same severity_from_score
# thresholds) but returns the result directly to the caller for rendering
# instead of inserting a row into the shadow database - "Shadow Mode" as a
# persistent, continuously-running evaluation of live traffic remains
# exactly as inactive as it was before this page existed.

def compute_display_only_comparison(resolved_ip, domain, sha256, md5, legacy_risk_score, legacy_severity):

    conn = framework.get_db_connection()

    try:
        evidence_rows = framework.get_all_provider_evidence_for_event_with_conn(
            conn, resolved_ip, domain, sha256, md5
        )
    finally:
        conn.close()

    result = risk.compute_threat_intel_contribution(
        evidence_rows, exclude_providers=shadow.DOUBLE_COUNT_RISK_PROVIDERS
    )

    excluded_with_signal = sorted({
        row.get("provider") for row in evidence_rows
        if row.get("provider") in shadow.DOUBLE_COUNT_RISK_PROVIDERS and risk.eligible_malicious_signal(row)
    })

    reasons = list(result["reasons"])
    if excluded_with_signal:
        reasons.append(
            "Excluded from this delta (already fully reflected in the legacy score above): "
            + ", ".join(excluded_with_signal) + "."
        )

    combined_score = max(0, min(100, int(legacy_risk_score or 0) + result["points"]))
    combined_severity = severity_from_score(combined_score)

    return {
        "legacy_risk_score": int(legacy_risk_score or 0),
        "legacy_severity": legacy_severity,
        "shadow_ti_points": result["points"],
        "shadow_combined_score": combined_score,
        "shadow_combined_severity": combined_severity,
        "severity_changed": combined_severity != legacy_severity,
        "decisive": result["decisive"],
        "signal_providers": result["signal_providers"],
        "excluded_double_count_providers": excluded_with_signal,
        "reasons": reasons,
    }


# ==================================================
# OCT 2026 STEP 13: PER-EVENT PROVIDER STATUS (read-only; never performs
# a live lookup; never writes anything)
# ==================================================
#
# For one event's candidate indicators, reports every implemented
# provider's status using ONLY what can actually be verified right now -
# never a fabricated "Pending" just because no cached result exists yet.
# Eight possible statuses:
#   COMPLETED       - a real cached MATCH/NO_MATCH result exists
#   RATE_LIMITED    - a real cached RATE_LIMITED result exists
#   FAILED          - a real cached ERROR result exists
#   PROCESSING      - verified in-flight RIGHT NOW (today this is only
#                     ever true for ThreatFox, whose lookup is literally
#                     synchronous inside web_event_worker.py - so
#                     "this event's own analysis_status is ANALYZING" IS
#                     direct proof it is running - no other provider in
#                     this project exposes an equivalent, honestly
#                     verifiable in-flight signal without modifying
#                     threat_intel_worker.py's own dispatch loop, which
#                     is explicitly out of scope here)
#   QUEUED          - eligible for automatic dispatch, no cached result
#                     yet, AND VERIFIED (Step 15) to be within threat_
#                     intel_worker.py's own real recent-enrichment window
#                     (framework.is_event_within_enrichment_window) - a
#                     genuine, checked promise it will be picked up soon,
#                     not just an absence of a cached result
#   ELIGIBLE        - (Step 15) eligible for automatic dispatch by every
#                     static criterion (type/config/wiring), but NOT
#                     verified to be in the worker's actual current work
#                     window (e.g. the Threat Intel Worker has never
#                     started yet, or this event is older than/behind
#                     more than ENRICHMENT_BATCH_EVENT_LIMIT newer ones) -
#                     an honest "will run automatically eventually, once
#                     within range" that does NOT promise imminent pickup
#   NOT_CONFIGURED  - requires an API key that is not set
#   MANUAL_ONLY     - will NEVER be dispatched automatically for this
#                     exact (provider, indicator type) pair - either the
#                     provider is manual_eligible only, OR (VirusTotal/
#                     AbuseIPDB on an IP) this specific indicator type is
#                     structurally derived from a manual Reputation-page
#                     check, never auto-fetched (provider_live_lookup_
#                     allowed() says so) - a real result still appears
#                     here (as COMPLETED) once an analyst has checked it
#   NOT_APPLICABLE  - no candidate indicator of any type this provider
#                     supports exists for this event at all (e.g. every
#                     URL-only provider, for every event today - the
#                     Endpoint Agent has no URL-capture capability; see
#                     docs/ENDPOINT_AGENT_URL_HASH_EXTENSION_PLAN.md)

STATUS_COMPLETED = "COMPLETED"
STATUS_QUEUED = "QUEUED"
STATUS_ELIGIBLE = "ELIGIBLE"
STATUS_PROCESSING = "PROCESSING"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_FAILED = "FAILED"
STATUS_MANUAL_ONLY = "MANUAL_ONLY"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

# Mirrors threat_intel_worker.ASYNC_MANAGED_PROVIDERS's own definition
# exactly (base list + the same OTX_ENABLED gate) - NOT imported directly:
# importing threat_intel_worker.py from inside the live Flask process
# would also execute ITS OWN module-level side effects (it registers
# SIGINT/SIGTERM handlers at import time, meant for its own standalone
# process) - a real, avoidable risk for a read-only display helper to
# take on. Kept in sync by code review (both sides are tiny and rarely
# change) and cross-checked directly against the real worker module by
# test_threat_intel_step13_provider_status.py's "mirror" test.
_BASE_ASYNC_MANAGED_PROVIDERS = frozenset({"urlhaus", "virustotal", "ipqualityscore"})
_OTX_ENABLED = os.getenv("OTX_ENABLED", "false").strip().lower() == "true"
_INLINE_AUTOMATIC_PROVIDERS = frozenset({"threatfox"})  # web_event_worker.py's own synchronous call

# Oct 2026 Step 14: VirusTotal/AbuseIPDB on an IP indicator are automatic
# via a THIRD mechanism - neither threat_intel_worker.py's async cycle
# nor web_event_worker.py's inline ThreatFox call, but the pre-existing
# Legacy Reputation Engine (reputation_routes.get_reputation_with_cache),
# which runs for every event with a resolved public IP. See the detailed
# comment at its one call site below.
_LEGACY_AUTOMATIC_IP_PROVIDERS = frozenset({"virustotal", "abuseipdb"})


def _automatically_wired_providers():
    return _BASE_ASYNC_MANAGED_PROVIDERS | ({"alienvault_otx"} if _OTX_ENABLED else set()) | _INLINE_AUTOMATIC_PROVIDERS


def per_event_provider_status(resolved_ip, domain, sha256, md5, event_analysis_status=None, event_time=None,
                               enrichment_snapshot=None):

    conn = framework.get_db_connection()

    try:
        candidates = framework.all_candidate_indicators_for_event(resolved_ip, domain, sha256, md5)
        wired = _automatically_wired_providers()
        rows = []

        for provider in sorted(framework.PROVIDER_REGISTRY):

            meta = framework.PROVIDER_REGISTRY[provider]

            if not meta.get("implemented"):
                continue

            supported = meta.get("supported_indicator_types", ())
            matching = [(t, v) for t, v in candidates if t in supported]

            if not matching:
                rows.append({
                    "provider": provider, "status": STATUS_NOT_APPLICABLE,
                    "indicator_type": None, "indicator_value": None,
                    "reason": "No indicator of a type this provider supports exists for this event.",
                })
                continue

            # Check EVERY type this provider supports for this event (not
            # just the first, priority one) for a real cached result
            # first - a provider that supports both IP and DOMAIN (e.g.
            # VirusTotal) must not have a genuinely real DOMAIN result
            # hidden just because the event's IP (a different, separate
            # check) has no cache yet. Only once nothing real is found
            # anywhere does priority order (IP, DOMAIN, SHA256, MD5,
            # matching all_candidate_indicators_for_event's own order)
            # decide which type the "why not yet" explanation below talks
            # about - matching the existing provider_status/evidence
            # display's convention.
            cached = None
            indicator_type, indicator_value = matching[0]
            for cand_type, cand_value in matching:
                row = framework.get_cached_evidence(conn, provider, cand_type, cand_value, count_as_lookup=False)
                if row is not None:
                    cached, indicator_type, indicator_value = row, cand_type, cand_value
                    break

            if cached is not None:
                lookup_status = cached.get("lookup_status")
                if lookup_status == framework.LOOKUP_STATUS_RATE_LIMITED:
                    status = STATUS_RATE_LIMITED
                elif lookup_status == framework.LOOKUP_STATUS_ERROR:
                    status = STATUS_FAILED
                else:
                    # MATCH or NO_MATCH - a real, completed result either way.
                    status = STATUS_COMPLETED
                rows.append({
                    "provider": provider, "status": status,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "evidence": cached,
                    "classification": framework.classify_evidence(
                        provider, lookup_status, indicator_type,
                        cached.get("analysis_stats"), cached.get("threat_type")
                    ),
                })
                continue

            # Oct 2026 Step 14 fix: VirusTotal/AbuseIPDB on an IP indicator
            # ARE genuinely automatic for every event with a resolved
            # public IP, through the Legacy Reputation Engine
            # (web_event_worker.py -> reputation_routes.get_reputation_
            # with_cache -> threat_intelligence.check_virustotal/
            # check_abuseipdb, cache-first against the threat_reputation
            # table). CORRECTION (verified directly, Step 14): a FRESH
            # Legacy check - automatic or manual alike - already calls
            # save_reputation_result() -> {provider}_provider.record_
            # legacy_ip_result(), which also writes the normal threat_
            # intel_evidence row the cache-check above reads - so in the
            # common case that existing check already reports COMPLETED
            # correctly, with no special-casing needed. This fallback
            # branch exists for the one real remaining gap: a
            # threat_reputation row exists (Legacy definitely ran) but no
            # threat_intel_evidence row does - e.g. the adapter-side TTL
            # (framework.PROVIDER_TTL_CONFIG) expired sooner than
            # threat_reputation's own CACHE_MINUTES=60 window, or a
            # cache-HIT path reused an old threat_reputation row without
            # re-calling save_reputation_result this time. Either way, the
            # absence of a threat_intel_evidence row does NOT mean these
            # providers did not run automatically, and must never be
            # reported as "Manual Only" on that basis. Read-only; never
            # performs a live call; never double-counts (the data is
            # already fully inside the stored risk_score either way).
            if provider in _LEGACY_AUTOMATIC_IP_PROVIDERS and indicator_type == "IP":
                legacy_row = conn.execute(
                    "SELECT * FROM threat_reputation WHERE ip_address = ?", (indicator_value,)
                ).fetchone()
                if legacy_row is not None:
                    if provider == "virustotal":
                        detail = (f"VirusTotal (via Legacy Reputation Engine): "
                                   f"{legacy_row['vt_malicious']} malicious, {legacy_row['vt_suspicious']} suspicious "
                                   f"(checked {legacy_row['checked_at']}).")
                    else:
                        detail = (f"AbuseIPDB (via Legacy Reputation Engine): "
                                   f"abuse_confidence={legacy_row['abuse_confidence']}, "
                                   f"{legacy_row['abuse_reports']} report(s) (checked {legacy_row['checked_at']}).")
                    rows.append({
                        "provider": provider, "status": STATUS_COMPLETED,
                        "indicator_type": indicator_type, "indicator_value": indicator_value,
                        "reason": detail,
                        "source_component": "Legacy Reputation Engine",
                    })
                    continue
                else:
                    rows.append({
                        "provider": provider, "status": STATUS_NOT_APPLICABLE,
                        "indicator_type": indicator_type, "indicator_value": indicator_value,
                        "reason": "No Legacy reputation check has been performed for this IP yet "
                                  "(it runs automatically the next time this IP is analyzed by the Web Event Worker).",
                    })
                    continue

            # No cached result yet - explain why, honestly, instead of a
            # generic "Pending".
            if not meta.get("automatic_eligible"):
                rows.append({
                    "provider": provider, "status": STATUS_MANUAL_ONLY,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": "This provider is only ever run from a manual re-check, never automatically.",
                })
                continue

            if not framework.provider_live_lookup_allowed(provider, indicator_type):
                rows.append({
                    "provider": provider, "status": STATUS_MANUAL_ONLY,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": f"For a {indicator_type} indicator, this provider's evidence is only ever "
                              "produced by a manual Reputation-page check, never fetched automatically.",
                })
                continue

            requires_key = bool(meta.get("requires_api_key", True))
            if requires_key and framework.get_provider_configuration_state(provider) != framework.CONFIG_STATE_AVAILABLE:
                rows.append({
                    "provider": provider, "status": STATUS_NOT_CONFIGURED,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": "Requires an API key that is not currently set.",
                })
                continue

            if provider not in wired:
                # Registry says automatic_eligible and this type is
                # live-lookup-allowed, but nothing actually dispatches it
                # today (e.g. alienvault_otx while OTX_ENABLED=false).
                rows.append({
                    "provider": provider, "status": STATUS_MANUAL_ONLY,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": "Automatic activation for this provider is not currently enabled.",
                })
                continue

            if provider in _INLINE_AUTOMATIC_PROVIDERS and event_analysis_status == "ANALYZING":
                rows.append({
                    "provider": provider, "status": STATUS_PROCESSING,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": "This event is being analyzed right now.",
                })
                continue

            if provider in _INLINE_AUTOMATIC_PROVIDERS:
                # Synchronous, per-event (web_event_worker.py's own inline
                # call) - not part of threat_intel_worker.py's async
                # batch/window at all, so that window check does not
                # apply here. If this point is reached (not cached, not
                # PROCESSING), it genuinely runs the moment this event is
                # (re)processed.
                rows.append({
                    "provider": provider, "status": STATUS_QUEUED,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": "Runs inline during event processing (not part of the async Threat Intel Worker cycle).",
                })
                continue

            # Oct 2026 Step 15 fix: QUEUED must mean a VERIFIED real work
            # item, not just "no cached result yet". Cross-check against
            # threat_intel_worker.py's own real recent-enrichment window
            # (same activation_cutoff + ENRICHMENT_BATCH_EVENT_LIMIT
            # bounding its find_enrichment_work() already applies) before
            # promising imminent pickup.
            if event_time and framework.is_event_within_enrichment_window(conn, event_time, snapshot=enrichment_snapshot):
                rows.append({
                    "provider": provider, "status": STATUS_QUEUED,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": "Eligible for automatic enrichment and verified within the Threat Intel "
                              "Worker's current recent-event window.",
                })
            else:
                rows.append({
                    "provider": provider, "status": STATUS_ELIGIBLE,
                    "indicator_type": indicator_type, "indicator_value": indicator_value,
                    "reason": "Eligible for automatic enrichment, but not currently verified to be within "
                              "the Threat Intel Worker's recent-event window - pickup is not guaranteed imminent.",
                })

        return rows

    finally:
        conn.close()


# ==================================================
# STEP 24B.1: URL THREAT-INTEL STATUS (read-only; never performs a live
# lookup; never writes anything; never affects Legacy/Shadow scoring,
# alerts, or response actions)
# ==================================================
#
# Mirrors cloudflare_provider.get_action_state()'s precedent exactly,
# for the two URL-capable, manual-eligible providers (Google Safe
# Browsing, PhishTank) - a dedicated, ALWAYS-SHOWN status per provider
# for a given URL, regardless of get_all_provider_evidence_for_event_
# with_conn()'s own "hide a manual-only provider until it has been
# checked" convention (left completely untouched for Cloudflare and any
# other provider - this is a separate, additive function, not a change
# to that one). Exactly four possible states, matching Step 24B.1's
# explicit requirement to distinguish them clearly:
#   NOT_CHECKED       no evidence has ever been retrieved for this URL
#   NO_THREAT         checked; the provider found nothing - NEVER
#                     presented as proof the destination is safe, only
#                     as "nothing found by THIS provider as of THIS time"
#   THREAT_DETECTED   checked; the provider reports a real finding
#   CHECK_FAILED      the provider was queried and returned an error
#   UNAVAILABLE       rate-limited right now, or not configured (no API
#                     key) - distinguished from CHECK_FAILED because
#                     neither is "we tried and it broke"

URL_INTEL_PROVIDERS = ("google_safe_browsing", "phishtank")

URL_STATUS_NOT_CHECKED = "NOT_CHECKED"
URL_STATUS_NO_THREAT = "NO_THREAT"
URL_STATUS_THREAT_DETECTED = "THREAT_DETECTED"
URL_STATUS_POSSIBLE_THREAT_UNCONFIRMED = "POSSIBLE_THREAT_UNCONFIRMED"
URL_STATUS_CHECK_FAILED = "CHECK_FAILED"
URL_STATUS_UNAVAILABLE = "UNAVAILABLE"


def url_intel_status_for_event(conn, url):

    if not url:
        return []

    normalized_url = framework.normalize_url_candidate(url)

    if not normalized_url:
        return []

    results = []

    for provider in URL_INTEL_PROVIDERS:

        cached = framework.get_cached_evidence(conn, provider, "URL", normalized_url, count_as_lookup=False)

        if cached is None:

            # get_provider_configuration_state() only checks whether the
            # env var is literally SET - it does not know a provider can
            # be requires_api_key=False (phishtank: documented to work
            # keyless) - exactly the same gate force_recheck() itself
            # applies before deciding a provider is "not configured".
            # Checked here too, or phishtank would be wrongly reported
            # UNAVAILABLE even when it is fully able to run keyless.
            meta = framework.PROVIDER_REGISTRY.get(provider) or {}
            requires_key = bool(meta.get("requires_api_key", True))

            not_configured = (
                requires_key
                and framework.get_provider_configuration_state(provider) != framework.CONFIG_STATE_AVAILABLE
            )

            status = URL_STATUS_UNAVAILABLE if not_configured else URL_STATUS_NOT_CHECKED

            results.append({
                "provider": provider,
                "indicator_type": "URL",
                "indicator_value": normalized_url,
                "status": status,
                "checked_at": None,
                "reason": (
                    "This provider requires an API key that is not currently set."
                    if status == URL_STATUS_UNAVAILABLE
                    else "This URL has not been checked with this provider yet."
                ),
            })
            continue

        lookup_status = cached.get("lookup_status")

        classification = framework.classify_evidence(
            provider, lookup_status, "URL",
            cached.get("analysis_stats"), cached.get("threat_type")
        )

        if lookup_status == framework.LOOKUP_STATUS_MATCH:
            # Step 24B.1 false-positive safeguard: a raw MATCH is not
            # always a confirmed signal. classify_evidence() already
            # distinguishes this for phishtank specifically - an
            # "unverified_report" is an unconfirmed community
            # submission, explicitly documented there as "NOT a signal
            # on its own". Showing it as a flat "Threat detected" would
            # overstate confidence and manufacture a false positive;
            # URL_STATUS_POSSIBLE_THREAT_UNCONFIRMED keeps the real
            # finding visible without asserting it is confirmed.
            if classification == "unverified_report":
                status = URL_STATUS_POSSIBLE_THREAT_UNCONFIRMED
            else:
                status = URL_STATUS_THREAT_DETECTED
        elif lookup_status == framework.LOOKUP_STATUS_NO_MATCH:
            status = URL_STATUS_NO_THREAT
        elif lookup_status == framework.LOOKUP_STATUS_RATE_LIMITED:
            status = URL_STATUS_UNAVAILABLE
        elif lookup_status == framework.LOOKUP_STATUS_ERROR:
            status = URL_STATUS_CHECK_FAILED
        else:
            status = URL_STATUS_UNAVAILABLE

        results.append({
            "provider": provider,
            "indicator_type": "URL",
            "indicator_value": normalized_url,
            "status": status,
            "checked_at": cached.get("retrieved_at"),
            "classification": classification,
            "reason": cached.get("summary") or classification,
        })

    return results
