# ==================================================
# WEB EVENT WORKER (Phase 2 + Phase 3 + Phase 4 + Phase 6, Stage 25F)
# ==================================================
#
# STAGE 25F PHASE 5: Phase 6's own alert/incident creation
# (web_monitoring.create_security_alert/create_incident_from_alert,
# alert_type "MALICIOUS_WEB_DESTINATION") is RETIRED - it was a second,
# competing alert authority alongside the Detection Engine's own
# unified decision (Stage 25C + Stage 25F Phase 4). This worker still
# computes reputation/IOC evidence exactly as before (Phase 2-4's own
# logic, unchanged) and still persists risk_score/severity/decision
# onto web_events for display/audit - it just no longer independently
# alerts on it. That evidence (including the full VirusTotal/AbuseIPDB
# reputation dict) now feeds detection_engine.evaluate_detections()
# instead (see detection_engine.rule_external_reputation_signal(), the
# Phase 5 port of the one Legacy-only signal Rules A-G didn't already
# consume). create_web_incident() is likewise not called from this
# worker; it still exists, unchanged, for the manual Web Monitoring
# page. Standalone background-analysis process for web_events rows
# inserted by the fast /api/web-events path
# (web_monitoring.analyze_web_event_fast).
#
# Phase 3: reputation lookups go through
# reputation_routes.get_reputation_with_cache(), which reuses a
# fresh threat_reputation cache row (<= CACHE_MINUTES old) when
# one exists, instead of always calling VirusTotal/AbuseIPDB
# live. Local IOC status is always re-checked fresh regardless
# of cache age.
#
# Phase 4: the observed domain is also checked against active
# DOMAIN threat_indicators (reputation_routes.check_domain_ioc),
# always fresh (never cached). A match adds to the same
# risk_score/severity/reasons IP reputation already produced,
# capped at 100, and can trigger the existing HIGH/CRITICAL
# incident/blocklist logic below exactly like a high IP
# reputation score already does.
#
# This is intentionally a SEPARATE PROCESS, not a thread
# started from inside app.py. Flask's debug reloader can
# spawn extra copies of the main process, which would
# duplicate an in-Flask worker thread. Running this as its
# own script means there is exactly one worker, started and
# stopped explicitly by whoever runs this file.
#
# Run in its own terminal window:
#   python web_event_worker.py
#
# Safe to stop/restart at any time - in-flight claims use
# the analysis_status column, so a killed worker simply
# leaves rows in 'ANALYZING'. (Phase 2 does not implement
# automatic re-queue of stuck ANALYZING rows; this is a
# known, accepted limitation for this phase.)
# ==================================================

import sqlite3
import time
from datetime import datetime, timedelta

import db_config
import worker_status
import process_correlation
import detection_engine
import response_plans

import ipaddress

from web_monitoring import DB_NAME as DB_PATH
from web_monitoring import (
    get_db_connection,
    init_web_monitoring_db,
    normalize_destination,
    domain_is_blocked,
    add_domain_to_blocklist,
    write_log,
    get_endpoint_info
)
from reputation_routes import (
    init_reputation_db,
    get_reputation_with_cache,
    check_domain_ioc,
    check_hash_ioc
)
from threat_intel_providers import (
    init_threat_intel_db,
    lookup_threatfox_for_event,
    _log_lookup_error as log_threat_intel_lookup_error
)
import threat_intel_shadow
import threat_intel_framework
import local_feed_evidence
from threat_intelligence import (
    severity_from_score,
    score_ioc_severity
)


POLL_SECONDS = 2

# Phase 12B.6C.1: resilience constants.
WORKER_NAME = "web_event_worker"
# After the bounded per-operation retries (db_config) are exhausted, the
# loop pauses this long and KEEPS RUNNING (it never exits on a lock).
LOCK_LOOP_BACKOFF_SECONDS = 3
# A claimed event that has been ANALYZING this long is treated as orphaned
# by a crash/lock failure and returned to PENDING (agent events only).
STALE_ANALYZING_MINUTES = 15
STALE_SWEEP_INTERVAL_SECONDS = 300

# Step 24B.2C: same stale-claim-recovery pattern, scoped to the
# browser-event Local Feed async step only (see claim_next_browser_
# event_for_local_feed / requeue_stale_browser_local_feed_claims below).
BROWSER_LOCAL_FEED_STALE_MINUTES = 15

# Step 25B: same periodic-sweep pattern as the two above, scoped to
# resolving PENDING process<->network correlations (network event
# arrived before its process event) - see process_correlation.py.
PROCESS_CORRELATION_SWEEP_INTERVAL_SECONDS = 60

# Stage 25C: same periodic-sweep pattern again, scoped to aging a
# detection from ACTIVE to RESOLVED once it stops recurring - see
# detection_engine.reconcile_detection_lifecycle().
DETECTION_LIFECYCLE_SWEEP_INTERVAL_SECONDS = 300

WORKER_IDENTITY = "web-event-worker"


# ==================================================
# ATOMIC CLAIM
# ==================================================
# A single UPDATE statement, guarded by a WHERE clause that
# only matches rows still in PENDING. SQLite serializes
# writers at the file level, so if two worker processes race
# on the same row, only one UPDATE can actually match it -
# the other will see rowcount == 0 and move on. This does
# NOT rely on a separate SELECT-then-UPDATE pair.

def claim_next_pending_event():

    conn = get_db_connection()

    claim_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:

        # Defense in depth: only ever claim rows submitted through
        # authenticated Endpoint Agent telemetry, never a manually
        # analyzed row. Manual Destination Analysis always inserts
        # analysis_status='ANALYZED' directly (never 'PENDING'),
        # so this filter should be a no-op in normal operation -
        # it exists so the worker can never reprocess an
        # analyst-typed test destination even if a manual row
        # somehow ended up PENDING.
        cursor = conn.execute("""
            UPDATE web_events
            SET
                analysis_status = 'ANALYZING',
                analysis_started_at = ?
            WHERE id = (
                SELECT id
                FROM web_events
                WHERE analysis_status = 'PENDING'
                AND source = 'endpoint-agent'
                ORDER BY id ASC
                LIMIT 1
            )
            AND analysis_status = 'PENDING'
            AND source = 'endpoint-agent'
        """, (
            claim_time,
        ))

        conn.commit()

        if cursor.rowcount == 0:

            return None

        row = conn.execute("""
            SELECT *
            FROM web_events
            WHERE
                analysis_status = 'ANALYZING'
                AND analysis_started_at = ?
            ORDER BY id DESC
            LIMIT 1
        """, (
            claim_time,
        )).fetchone()

        return row

    finally:

        conn.close()


# ==================================================
# STAGE 25G PHASE 3A: RESPONSE PLANNING (DRY-RUN) - PLANS ONLY
# ==================================================
# The ONE live wiring point from the unified decision to response
# planning. Called strictly AFTER detection_engine.evaluate_detections()
# has run _finalize_decision() and produced/reused the authoritative
# unified alert - never from a rule, never per finding: summary
# ["alert_ids"] holds at most one unified alert per evaluation (the
# documented identity-fallback path may hold several), so planning
# happens once per unified decision. generate_plans_for_alert() writes
# response_plans rows ONLY - there is no code path from a plan to a
# response_command, the Agent, or the OS in Phase 3A.
def _generate_response_plans(detection_summary, label="EVENT"):

    results = []

    for alert_id in (detection_summary or {}).get("alert_ids") or []:

        try:
            results.append(response_plans.generate_plans_for_alert(alert_id))
        except Exception as plan_exc:
            # A planning failure must never affect detection/alert/
            # incident processing - same isolation as every evidence block.
            log_threat_intel_lookup_error(label, plan_exc)

    return results


# ==================================================
# STAGE 25F PHASE 5: ADVISORY BLOCKLIST POLICY
# ==================================================
# blocked_domains is passive, advisory state - NOT real endpoint/
# network enforcement (confirmed in the Phase 5 audit: the Agent never
# reads this table; it only affects a future web_events.decision
# display value via domain_is_blocked()). Triggered ONLY from the
# unified Detection Engine decision's own severity/risk_score - never
# from a second, independently-computed severity (Phase 5 instruction
# #5/#6). Never creates a response_command, never touches
# ENABLE_RESPONSE_ACTIONS, never enforces anything.
ADVISORY_BLOCKLIST_SEVERITIES = ("HIGH", "CRITICAL")


def _maybe_advisory_blocklist(domain, severity, risk_score):

    if not domain:
        return

    # "Do NOT treat an IP as a domain" (Phase 5 instruction #5/#13,
    # test #13) - a destination with no real hostname (normalize_
    # destination() returns the IP literal itself as `domain` in that
    # case) must never be inserted into blocked_domains under that
    # column's domain semantics.
    try:
        ipaddress.ip_address(domain)
        return
    except ValueError:
        pass

    if severity not in ADVISORY_BLOCKLIST_SEVERITIES:
        return

    if domain_is_blocked(domain):
        return

    add_domain_to_blocklist(
        domain,
        severity,
        f"Automatically added after unified Detection Engine risk score {risk_score}/100.",
        username=WORKER_IDENTITY
    )


# ==================================================
# ANALYZE ONE EVENT
# ==================================================
# Reuses web_monitoring's own evidence helpers rather than duplicating
# them (normalize_destination, domain_is_blocked, add_domain_to_
# blocklist, analyze_ip_reputation, all imported, not reimplemented).
#
# STAGE 25F PHASE 6: this comment previously compared this function to
# web_monitoring.analyze_web_event() - that function was dead code
# (zero live callers) and was retired in Phase 6; this file never
# actually imported/called its create_web_incident() dependency
# either (that helper is used only by web_monitoring.py's own live
# manual-analysis feature). This worker's alert/incident authority is
# now solely detection_engine._finalize_decision() (Stage 25F Phase
# 4/5) - see the module header above for the full history.

def process_event(event):

    # Phase 12B.6C.1: anything opened while processing this event (by any
    # helper module) is rolled back and closed when it ends, so a failed
    # commit under a lock can never leave a write transaction lingering
    # until the cyclic garbage collector happens to run.
    connection_mark = db_config.mark()

    conn = get_db_connection()

    try:

        domain, resolved_ip, resolve_error = normalize_destination(
            event["destination"]
        )

        if resolve_error:
            raise ValueError(resolve_error)

        # Phase 4: DOMAIN IOC correlation. Checked fresh here,
        # independent of whether the destination resolves to a
        # public or private IP - a domain match is about domain
        # identity, not IP class. Never cached (see
        # reputation_routes.check_domain_ioc).
        domain_ioc_match = check_domain_ioc(domain)

        # Prefer the endpoint-observed IP over a fresh DNS
        # resolution (same override logic web_monitoring.py's live
        # manual-analysis feature and the fast-ingestion path both
        # use, for the same CDN/load-balancer-rotation reason).
        observed_ip = event["observed_ip"]

        if observed_ip:

            try:

                # Any valid IP version - the agent-observed
                # address is authoritative regardless of family;
                # it was never version-restricted for a real
                # reason, only overlooked when IPv6 monitoring
                # was still disabled at capture time.
                ipaddress.ip_address(
                    observed_ip
                )

                resolved_ip = observed_ip

            except ValueError:
                pass

        already_blocked = domain_is_blocked(domain)

        reputation = None
        risk_score = 0
        severity = "INFO"
        reasons = []
        reputation_source = None

        if resolved_ip:

            try:
                resolved_object = ipaddress.ip_address(resolved_ip)
            except ValueError:
                resolved_object = None

            if resolved_object and resolved_object.is_global:

                # Phase 3: cache-first. Reuses a fresh
                # threat_reputation row when available (no VT/
                # AbuseIPDB call); otherwise performs a live
                # lookup and saves it to the cache. Local IOC
                # state is always re-checked fresh regardless
                # of cache age - see get_reputation_with_cache().
                reputation = get_reputation_with_cache(
                    resolved_ip,
                    checked_by=WORKER_IDENTITY
                )

                if not reputation.get("error"):

                    risk_score = int(
                        reputation.get("risk_score", 0) or 0
                    )

                    severity = reputation.get("severity", "INFO")

                    reasons = list(reputation.get("reasons", []))

                    reputation_source = reputation.get(
                        "reputation_source"
                    )

                else:
                    reasons.append(reputation.get("error"))

            else:
                reasons.append(
                    "Destination resolved to a private/local "
                    "IP. External reputation was not performed."
                )

        # Phase 4 (+ IPv6-phase correctness fix): fold the DOMAIN
        # IOC match into the same score/severity/reasons that IP
        # reputation already produced above (not a second,
        # separate risk engine - same severity_from_score()
        # thresholds used everywhere else). Capped at 100. Both
        # an IP-IOC match (already inside risk_score via
        # get_reputation_with_cache) and a DOMAIN-IOC match can
        # contribute at the same time.
        #
        # RELIABILITY GATE: `domain` here can come from three
        # different sources depending on event["attribution_type"]
        # - "dns" (the agent's own OS DNS cache - a real forward
        # query this machine made), "rdns" (a reverse-DNS GUESS on
        # the destination IP, which may or may not be the actual
        # hostname the process requested), or "ip"/None (no
        # hostname at all, or a legacy/manual row predating this
        # field). Only a "dns"-attributed domain is treated as
        # reliable enough to raise risk_score/severity or trigger
        # a Security Alert on its own - an rDNS-derived guess is
        # never proof the endpoint actually visited that hostname
        # (see the IPv6/rDNS root-cause report). A match on
        # unreliable evidence is still surfaced to the analyst as
        # an informational note (rDNS stays useful for display/
        # enrichment - it is just never fake certainty), but does
        # NOT touch risk_score, severity, or should_alert below.
        domain_ioc_reliable = (
            domain_ioc_match is not None
            and event["attribution_type"] == "dns"
        )

        if domain_ioc_match and domain_ioc_reliable:

            ioc_points = score_ioc_severity(
                domain_ioc_match["severity"]
            )

            risk_score = min(risk_score + ioc_points, 100)

            severity = severity_from_score(risk_score)

            match_description = (
                domain_ioc_match["description"]
                or "no description provided"
            )

            reasons.append(
                "Domain matched active local IOC: "
                f"{domain} (rule: "
                f"{domain_ioc_match['indicator_value']}, "
                f"IOC severity: {domain_ioc_match['severity']}, "
                f"source: "
                f"{domain_ioc_match['source'] or 'internal'}) - "
                f"{match_description}"
            )

        elif domain_ioc_match:

            match_description = (
                domain_ioc_match["description"]
                or "no description provided"
            )

            reasons.append(
                "Note: destination hostname resembles an active "
                f"local IOC ({domain}, rule: "
                f"{domain_ioc_match['indicator_value']}, IOC "
                f"severity: {domain_ioc_match['severity']}) but "
                "attribution is not a confirmed forward-DNS "
                "request (attribution: "
                f"{event['attribution_type'] or 'unknown'}) - "
                f"{match_description} - not used to raise risk "
                "score or trigger an alert on its own; verify "
                "manually."
            )

        # Phase 11B: fold a HASH IOC match into the same
        # score/severity/reasons as IP/DOMAIN above - a third,
        # fully independent additive contributor (not merged
        # into `reputation`), same score_ioc_severity()/
        # severity_from_score() everywhere-else logic, capped at
        # 100 again. check_hash_ioc() is already SHA-256-first
        # (MD5 only as a fallback when SHA-256 has no match), so
        # a single observed executable contributes at most one
        # HASH-IOC boost here even if both its hashes are
        # separately registered as IOCs.
        hash_ioc_match, hash_ioc_field = check_hash_ioc(
            event["sha256"],
            event["md5"]
        )

        if hash_ioc_match:

            ioc_points = score_ioc_severity(
                hash_ioc_match["severity"]
            )

            risk_score = min(risk_score + ioc_points, 100)

            severity = severity_from_score(risk_score)

            match_description = (
                hash_ioc_match["description"]
                or "no description provided"
            )

            hash_label = (
                "SHA-256" if hash_ioc_field == "sha256" else "MD5"
            )

            reasons.append(
                f"{hash_label} matches an active local HASH IOC "
                f"(severity: {hash_ioc_match['severity']}) - rule: "
                f"{hash_ioc_match['indicator_value']}, source: "
                f"{hash_ioc_match['source'] or 'internal'} - "
                f"{match_description}."
            )

        # --------------------------------------------------
        # PHASE 11D.1: THREATFOX CONTEXTUAL LOOKUP
        # --------------------------------------------------
        # Runs strictly AFTER risk_score/severity above are fully
        # finalized. Reads/writes ONLY the independent
        # threat_intel_evidence table (via threat_intel_providers.py)
        # - never touches risk_score, severity, decision, `reasons`,
        # should_alert, or any Alert/Incident/Response logic below.
        # A failure here can never interrupt event processing.
        threatfox_results = {}

        try:
            threatfox_results = lookup_threatfox_for_event(resolved_ip, domain, event["sha256"])
        except Exception as threat_intel_exc:
            log_threat_intel_lookup_error("EVENT", threat_intel_exc)

        # --------------------------------------------------
        # STEP 24B.2A: LOCAL THREAT INTELLIGENCE FEED
        # --------------------------------------------------
        # Runs strictly AFTER risk_score/severity/reasons/decision above
        # are already finalized - same placement and same isolation
        # contract as the ThreatFox block immediately above. Reads/writes
        # ONLY local_feed_evidence's own dedicated
        # local_feed_match_evidence table (a table neither Legacy TI nor
        # Shadow TI's code ever queries - see local_feed_evidence.py's
        # module header for why this is a SEPARATE table from
        # threat_intel_evidence, not a reuse of it). Never touches
        # risk_score, severity, reasons, decision, should_alert, or any
        # Alert/Incident/Response action below. A failure here can never
        # interrupt event processing (defense in depth, matching the
        # ThreatFox try/except immediately above - local_feed_evidence
        # itself does not swallow its own exceptions).
        local_feed_results = []

        try:
            local_feed_results = local_feed_evidence.lookup_and_record_for_event(resolved_ip, domain)
        except Exception as local_feed_exc:
            log_threat_intel_lookup_error("EVENT", local_feed_exc)

        # --------------------------------------------------
        # OCT 2026 STEP 4: MULTI-SOURCE THREAT INTEL - SHADOW MODE
        # --------------------------------------------------
        # Computes what the new corroboration-based engine (threat_intel_
        # risk.py, fed by whatever evidence is ALREADY cached - no live
        # HTTP call is made here) WOULD contribute, for side-by-side
        # comparison only (recorded in a separate database file, never
        # cybersec.db - see threat_intel_shadow.py). Runs strictly AFTER
        # risk_score/severity/reasons above are fully finalized and reads
        # them only to RECORD them - it never reassigns risk_score,
        # severity, reasons, decision, should_alert, or anything below,
        # and never creates an Alert/Incident/Response/block/isolate
        # action. A failure here can never interrupt event processing
        # (evaluate_shadow() already catches its own exceptions; this
        # try/except is defense in depth, matching the ThreatFox block
        # immediately above).
        try:
            threat_intel_shadow.evaluate_shadow(
                event["id"], resolved_ip, domain, event["sha256"], event["md5"],
                risk_score, severity, reasons
            )
        except Exception as shadow_exc:
            log_threat_intel_lookup_error("EVENT", shadow_exc)

        decision = "ALLOWED"

        if already_blocked:

            decision = "BLOCKED"

            reasons.append(
                "Domain already exists in the active block list."
            )

        # Stage 25F Phase 5: the Legacy severity-triggered blocklist
        # add (`elif severity in ["HIGH","CRITICAL"]: add_domain_to_
        # blocklist(...)`) is RETIRED here - advisory blocklist state
        # must now be driven by the UNIFIED Detection Engine decision
        # only, never by this block's own independently-computed
        # severity (instruction #5/#6). See _maybe_advisory_blocklist()
        # below, called downstream of detection_engine.evaluate_
        # detections() with the unified severity/risk_score instead.
        # `already_blocked` above is untouched - a domain already on
        # the list (from an EARLIER unified decision) still marks this
        # event BLOCKED for display, exactly as before.

        # --------------------------------------------------
        # STAGE 25F PHASE 5: LEGACY ALERT CREATION RETIRED
        # --------------------------------------------------
        # Previously (Phase 6 through Stage 25F Phase 4), this block
        # independently created a "MALICIOUS_WEB_DESTINATION" Security
        # Alert (+ Incident) whenever should_alert was true - a SECOND,
        # competing alert authority alongside the unified Detection
        # Engine decision below. Retired per the approved Phase 5
        # design: one evidence pipeline -> one decision authority -> one
        # alert decision.
        #
        # What was PRESERVED (evidence, not alerting):
        #   - hostname/endpoint_info lookup - still needed by
        #     detection_context below (ctx["hostname"]).
        #   - ip_ioc_match (reputation["local_ioc"]) - still needed by
        #     detection_context (ctx["ip_ioc_match"], feeds Rule B).
        #   - the full `reputation` dict itself - now passed into
        #     detection_context too (ctx["reputation"]) so the
        #     Detection Engine's own new Rule H (external reputation
        #     signal) can consume the VirusTotal/AbuseIPDB portion that
        #     Rules A-G did not previously consume on their own - see
        #     detection_engine.rule_external_reputation_signal() and the
        #     Phase 5 report's audit section for why this port was
        #     necessary (ported BEFORE retiring this block, so no
        #     detection coverage was lost).
        #
        # What was RETIRED (competing decision authority):
        #   - should_alert / alert_title / alert_description /
        #     build_recommended_response / create_security_alert(
        #     alert_type="MALICIOUS_WEB_DESTINATION") / the HIGH/
        #     CRITICAL incident-escalation call. already_isolated and
        #     process_unknown were computed ONLY for that alert's own
        #     recommended_response context and are retired with it.
        #   - the severity-triggered add_domain_to_blocklist() call
        #     (moved downstream of the unified decision - see
        #     _maybe_advisory_blocklist() below).

        endpoint_info = get_endpoint_info(event["endpoint_ip"])

        hostname = (
            endpoint_info["hostname"]
            if endpoint_info else None
        )

        ip_ioc_match = bool(reputation.get("local_ioc")) if reputation and not reputation.get("error") else False

        # --------------------------------------------------
        # STAGE 25C: DETECTION & RISK ENGINE
        # (STAGE 25F PHASE 4/5: now the SOLE automatic alert authority)
        # --------------------------------------------------
        # Runs strictly AFTER every existing evidence/scoring block
        # above is fully finalized - reads what they already computed
        # (reputation, domain/hash/IP IOC matches, ThreatFox, Local
        # Feed, 25B process correlation, Behavioral evidence) and NEVER
        # reassigns risk_score/severity/decision/reasons above. A
        # failure here can never interrupt event processing
        # (evaluate_detections() already isolates every rule
        # internally; this try/except is defense in depth, matching
        # every other evidence block above).
        detection_summary = {}

        try:

            process_row = None

            if (
                event["process_instance_id"]
                and event["process_correlation_status"] == "CONFIRMED"
            ):
                process_row = detection_engine.get_confirmed_process_row(
                    conn, event["process_instance_id"]
                )

            threatfox_evidence_list = [
                dict(value, indicator_type=key[0], indicator_value=key[1])
                for key, value in threatfox_results.items()
            ]

            # Stage 25E section 9: only Suricata detections ALREADY
            # classified SECURITY_ALERT (never PROTOCOL_EVENT/
            # ENGINE_DIAGNOSTIC) reach here - see detection_engine.
            # get_qualified_suricata_evidence_for_destination()'s own
            # filtering. A failure here must never break event
            # processing (the helper itself never raises, but kept
            # isolated anyway for defense in depth).
            try:
                suricata_evidence_list = detection_engine.get_qualified_suricata_evidence_for_destination(
                    resolved_ip, event["event_time"]
                )
            except Exception as suricata_exc:
                suricata_evidence_list = []
                log_threat_intel_lookup_error("EVENT", suricata_exc)

            detection_context = {
                "web_event_id": event["id"],
                "endpoint_uid": event["endpoint_uid"],
                "endpoint_ip": event["endpoint_ip"],
                "hostname": hostname,
                "process_name": event["process_name"],
                "process_instance_id": event["process_instance_id"] if process_row else None,
                "process_row": process_row,
                # Stage 25F Phase 4: passed through verbatim (CONFIRMED/
                # PENDING/UNAVAILABLE/NULL) so correlation_key.compute_
                # correlation_key() can distinguish PENDING from
                # UNAVAILABLE - the two collapsed to the same NULL
                # process_instance_id above and were otherwise
                # indistinguishable to the Detection Engine. Never used
                # for anything else (risk/severity/decision are
                # unaffected - same as every other evidence field here).
                "process_correlation_status": event["process_correlation_status"],
                "event_source": event["source"],
                "resolved_ip": resolved_ip,
                "domain": domain,
                "destination_label": domain or resolved_ip or event["destination"],
                "domain_ioc_match": domain_ioc_match if domain_ioc_reliable else None,
                "domain_ioc_reliable": domain_ioc_reliable,
                "hash_ioc_match": hash_ioc_match,
                "ip_ioc_match": ip_ioc_match,
                "threatfox_evidence": threatfox_evidence_list,
                "local_feed_results": local_feed_results,
                "behavioral_result": detection_engine.get_behavioral_result(conn, event["id"]),
                "suricata_evidence": suricata_evidence_list,
                # Stage 25F Phase 5: the raw reputation dict (VirusTotal/
                # AbuseIPDB/local_ioc), already computed above for
                # display/audit purposes - now also feeds Rule H (see
                # the retirement comment above this try block).
                "reputation": reputation,
            }

            detection_summary = detection_engine.evaluate_detections(detection_context)

        except Exception as detection_exc:
            log_threat_intel_lookup_error("EVENT", detection_exc)

        # Stage 25G Phase 3A: dry-run response planning, after the unified
        # decision only (see _generate_response_plans above). Plans only.
        _generate_response_plans(detection_summary, label="EVENT")

        # --------------------------------------------------
        # STAGE 25F PHASE 5: ADVISORY BLOCKLIST, DOWNSTREAM OF THE
        # UNIFIED DECISION ONLY
        # --------------------------------------------------
        # Isolated from the Detection Engine call above (its own
        # try/except) - a policy-application bug here must never affect
        # detection_summary or vice versa. Reads ONLY the unified
        # decision's own severity/risk_score (detection_summary -
        # populated by _finalize_decision() inside evaluate_detections()
        # itself), never this block's own Legacy severity (now retired).
        try:
            _maybe_advisory_blocklist(
                domain, detection_summary.get("severity"), detection_summary.get("risk_score")
            )
        except Exception as blocklist_exc:
            log_threat_intel_lookup_error("EVENT", blocklist_exc)

        completed_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        final_params = (
            domain,
            resolved_ip,
            risk_score,
            severity,
            decision,
            "; ".join(reasons),
            completed_time,
            reputation_source,
            event["id"]
        )

        def persist_final_result():

            conn.execute("""
                UPDATE web_events
                SET
                    domain = ?,
                    resolved_ip = ?,
                    risk_score = ?,
                    severity = ?,
                    decision = ?,
                    details = ?,
                    analysis_status = 'ANALYZED',
                    analysis_completed_at = ?,
                    analysis_error = NULL,
                    reputation_source = ?
                WHERE id = ?
            """, final_params)

            conn.commit()

        # Phase 12B.6C.1: this single idempotent statement is the last step
        # after the alert/incident work; a transient lock here is retried
        # (rollback between attempts) instead of re-running the analysis.
        db_config.retry_on_lock(
            persist_final_result,
            cleanup=lambda exc: conn.rollback(),
            label=f"event #{event['id']} final result"
        )

        write_log(
            "WEB_EVENT_ANALYZED",
            (
                f"Event #{event['id']} "
                f"{event['endpoint_ip']} -> {domain} "
                f"({resolved_ip}) | Risk {risk_score}/100 | "
                f"{severity} | {decision}"
                + (
                    f" | {reputation_source}"
                    if reputation_source
                    else ""
                )
            ),
            target_ip=event["endpoint_ip"],
            username=WORKER_IDENTITY
        )

        source_suffix = (
            f" | {reputation_source}"
            if reputation_source
            else ""
        )

        print(
            f"[{WORKER_IDENTITY}] #{event['id']} analyzed: "
            f"{decision} {severity} {risk_score}/100 "
            f"({domain or event['destination']})"
            f"{source_suffix}"
        )

    except Exception as exc:

        # Whatever failed, never keep a half-open transaction on this
        # connection while we decide what to do next.
        try:
            conn.rollback()
        except sqlite3.Error:
            pass

        # Phase 12B.6C.1: a transient database LOCK is not an analysis
        # failure. The event is returned to PENDING (deferred) so it is
        # analyzed later, instead of being permanently marked ERROR.
        if db_config.is_transient_lock_error(exc):

            _defer_event(event, exc)

            return

        error_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        def mark_error():

            conn.execute("""
                UPDATE web_events
                SET
                    analysis_status = 'ERROR',
                    analysis_error = ?,
                    analysis_completed_at = ?
                WHERE id = ?
            """, (
                str(exc)[:500],
                error_time,
                event["id"]
            ))

            conn.commit()

        # Never delete the event on failure - mark it ERROR
        # with a sanitized (truncated) message instead.
        db_config.retry_on_lock(
            mark_error,
            cleanup=lambda lock_exc: conn.rollback(),
            label=f"event #{event['id']} error mark"
        )

        write_log(
            "WEB_EVENT_ANALYSIS_ERROR",
            f"Event #{event['id']} failed: {exc}",
            target_ip=event["endpoint_ip"],
            username=WORKER_IDENTITY
        )

        print(
            f"[{WORKER_IDENTITY}] #{event['id']} ERROR: {exc}"
        )

    finally:

        conn.close()

        db_config.release_since(connection_mark)


# ==================================================
# PHASE 12B.6C.1: LOCK-SAFE HELPERS
# ==================================================

def _defer_event(event, exc):

    # Return a claimed event to PENDING after a transient lock error. The
    # guard (still ANALYZING, still an agent event) makes this a no-op if
    # the event actually completed, so it can never resurrect finished work.
    print(
        f"[{WORKER_IDENTITY}] #{event['id']} deferred (transient database "
        f"lock, will be retried later): {exc}",
        flush=True
    )

    def requeue():

        conn = get_db_connection()

        try:

            conn.execute("""
                UPDATE web_events
                SET analysis_status = 'PENDING', analysis_started_at = NULL
                WHERE id = ?
                AND analysis_status = 'ANALYZING'
                AND source = 'endpoint-agent'
            """, (event["id"],))

            conn.commit()

        except BaseException:

            conn.rollback()
            raise

        finally:

            conn.close()

    try:

        db_config.retry_on_lock(requeue, label=f"event #{event['id']} requeue")

    except db_config.LockRetryExhausted:

        print(
            f"[{WORKER_IDENTITY}] #{event['id']} could not be requeued "
            "(database still locked); it stays ANALYZING and the stale-event "
            "sweep will return it to PENDING.",
            flush=True
        )


def requeue_stale_analyzing(minutes=STALE_ANALYZING_MINUTES):

    # Returns claimed-but-never-finished agent events (orphaned by a crash or
    # an unrecoverable lock) to PENDING. Only agent events, only ones that
    # have been ANALYZING longer than `minutes`.
    cutoff = (
        datetime.now() - timedelta(minutes=minutes)
    ).strftime("%Y-%m-%d %H:%M:%S")

    def sweep():

        conn = get_db_connection()

        try:

            cursor = conn.execute("""
                UPDATE web_events
                SET analysis_status = 'PENDING', analysis_started_at = NULL
                WHERE analysis_status = 'ANALYZING'
                AND source = 'endpoint-agent'
                AND analysis_started_at < ?
            """, (cutoff,))

            conn.commit()

            return cursor.rowcount

        except BaseException:

            conn.rollback()
            raise

        finally:

            conn.close()

    return db_config.retry_on_lock(sweep, label="stale-event sweep")


# ==================================================
# STEP 24B.2C: ASYNC LOCAL FEED PROCESSING FOR BROWSER EVENTS
# ==================================================
# Deliberately NOT process_event(): browser-extension rows must never
# receive IP reputation, Legacy TI DOMAIN/HASH IOC matching, ThreatFox,
# Shadow Mode, or Alert/Incident/blocklist treatment - process_event()
# does all of that, and the existing claim_next_pending_event() query
# already structurally excludes browser rows for exactly this reason
# (see its own WHERE source = 'endpoint-agent'). This is a separate,
# narrow claim/process pair, reusing this SAME already-isolated,
# already-long-running process's polling loop/signal-handling/
# resilience conventions (db_config.retry_on_lock, WORKER_IDENTITY,
# worker_status.heartbeat) - never a new thread spawned inside a Flask
# request, never a merge into the TCP pipeline.
#
# The ONLY effect of this step, ever: a local_feed_evidence lookup is
# performed and, on a MATCH, a row is upserted into
# local_feed_match_evidence (local_feed_evidence.py's own module header
# explains why that table is isolated from threat_intel_evidence/
# Legacy TI/Shadow TI). risk_score/severity/decision for a browser row
# are fixed literal values set at INSERT time by browser_events.py and
# are never read or written here.

def claim_next_browser_event_for_local_feed():

    conn = get_db_connection()

    claim_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:

        # Same atomic single-UPDATE claim pattern as claim_next_pending_
        # event() above - a lock-race between two instances of this
        # process (or a future second process) can only ever let ONE
        # UPDATE actually match a given row.
        cursor = conn.execute("""
            UPDATE web_events
            SET local_feed_status = 'PROCESSING', local_feed_claimed_at = ?
            WHERE id = (
                SELECT id
                FROM web_events
                WHERE source = 'browser-extension'
                AND url IS NOT NULL
                AND local_feed_status IS NULL
                ORDER BY id ASC
                LIMIT 1
            )
            AND source = 'browser-extension'
            AND url IS NOT NULL
            AND local_feed_status IS NULL
        """, (claim_time,))

        conn.commit()

        if cursor.rowcount == 0:
            return None

        row = conn.execute("""
            SELECT *
            FROM web_events
            WHERE source = 'browser-extension'
            AND local_feed_status = 'PROCESSING'
            AND local_feed_claimed_at = ?
            ORDER BY id DESC
            LIMIT 1
        """, (claim_time,)).fetchone()

        return row

    finally:

        conn.close()


def process_browser_event_for_local_feed(event):

    try:

        local_feed_results = local_feed_evidence.lookup_and_record_for_event(url=event["url"])

        # Stage 25D section 8: ThreatFox DOMAIN check for the browser
        # event's own `domain` column - the exact same cache-aware,
        # single-flight-guarded function the TCP path already uses
        # (lookup_threatfox_for_event), called here with resolved_ip/
        # sha256 both None (a browser event never resolves an IP or
        # computes a hash - no DNS interception, by design; only the
        # DOMAIN candidate is ever built from this call for a browser
        # event). Until now this was a real gap: a browser-visited
        # malicious domain never got ThreatFox evidence at all, only
        # Local Feed. A failure here must never break browser-event
        # ingestion (same isolation discipline as the Local Feed call
        # directly above and every other evidence block in this file).
        threatfox_evidence_list = []

        try:
            threatfox_results = lookup_threatfox_for_event(None, event["domain"], None)
            threatfox_evidence_list = [
                dict(value, indicator_type=key[0], indicator_value=key[1])
                for key, value in threatfox_results.items()
            ]
        except Exception as threatfox_exc:
            log_threat_intel_lookup_error("BROWSER_EVENT", threatfox_exc)

        # Stage 25C: same Detection Engine, fed the Local Feed + (as of
        # Stage 25D) ThreatFox-domain evidence this call just computed
        # - a browser-extension event NEVER carries process telemetry
        # (no PID, no process_instance_id - see browser_events.py's own
        # INSERT, which never even has those columns in scope), so
        # process_row/process_instance_id/domain_ioc/hash_ioc/
        # behavioral are all deliberately omitted here rather than
        # guessed - rules C/D/E/F and the Legacy-IOC half of rule B
        # simply never fire for a browser event; only rule A (Local
        # Feed/ThreatFox confirmed match) can. Isolated the same way as
        # every other evidence block - never breaks browser-event
        # ingestion.
        browser_summary = {}

        try:

            browser_summary = detection_engine.evaluate_detections({
                "web_event_id": event["id"],
                "endpoint_uid": event["endpoint_uid"],
                "endpoint_ip": event["endpoint_ip"],
                "hostname": None,
                "process_name": None,
                "process_instance_id": None,
                "process_row": None,
                # Stage 25F Phase 4: a browser event never has a process
                # concept at all - event_source="browser-extension" makes
                # correlation_key.compute_correlation_key() use the
                # NOT_APPLICABLE tier regardless of process_correlation_
                # status (left None - never applicable, so never set).
                "process_correlation_status": None,
                "event_source": "browser-extension",
                "resolved_ip": None,
                "domain": event["domain"],
                "destination_label": event["domain"] or event["url"],
                "domain_ioc_match": None,
                "domain_ioc_reliable": False,
                "hash_ioc_match": None,
                "ip_ioc_match": False,
                "threatfox_evidence": threatfox_evidence_list,
                "local_feed_results": local_feed_results,
                "behavioral_result": None,
                # Stage 25E: a browser event never has a resolved_ip (no
                # server-side DNS resolution, by design - see the
                # module header above), so there is no IP to match a
                # Suricata detection against; always empty here, never
                # guessed from the domain alone.
                "suricata_evidence": [],
            })

        except Exception as detection_exc:
            threat_intel_framework.log_provider_lookup_error("detection_engine", "BROWSER_EVENT", detection_exc)

        # Stage 25G Phase 3A: dry-run response planning for the browser
        # path's unified decision too - plans only, never a command.
        _generate_response_plans(browser_summary, label="BROWSER_EVENT")

    except Exception as exc:

        # Never advance to 'CHECKED' on failure (corrupt/unavailable
        # feed, transient DB error, etc.) - the row stays 'PROCESSING'
        # and is recovered by the stale sweep below for a later retry.
        # Never raises further: a Local Feed problem must never break
        # browser-event ingestion/processing or take down this worker.
        # threat_intel_framework.log_provider_lookup_error() is called
        # DIRECTLY (not the log_threat_intel_lookup_error alias above,
        # which hardcodes provider="threatfox" regardless of caller -
        # using it here would mislabel every Local Feed error as a
        # ThreatFox one in the log).
        threat_intel_framework.log_provider_lookup_error("local_feed", "BROWSER_EVENT", exc)
        return False

    def mark_checked():

        conn = get_db_connection()

        try:
            conn.execute("""
                UPDATE web_events
                SET local_feed_status = 'CHECKED'
                WHERE id = ?
            """, (event["id"],))
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    db_config.retry_on_lock(mark_checked, label=f"browser event #{event['id']} local feed mark-checked")

    return True


def requeue_stale_browser_local_feed_claims(minutes=BROWSER_LOCAL_FEED_STALE_MINUTES):

    # Mirrors requeue_stale_analyzing() exactly, scoped to this
    # worker's own local_feed_status column only.
    cutoff = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

    def sweep():

        conn = get_db_connection()

        try:
            cursor = conn.execute("""
                UPDATE web_events
                SET local_feed_status = NULL, local_feed_claimed_at = NULL
                WHERE source = 'browser-extension'
                AND local_feed_status = 'PROCESSING'
                AND local_feed_claimed_at < ?
            """, (cutoff,))
            conn.commit()
            return cursor.rowcount
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    return db_config.retry_on_lock(sweep, label="stale browser-event local-feed sweep")


def run_process_correlation_sweep():

    # Step 25B: resolves (or ages out) the PENDING backlog - see
    # process_correlation.reconcile_pending_correlations(). Read+write on
    # its own bounded batch only - never a full-table scan (the partial
    # index on process_correlation_status='PENDING' keeps the SELECT
    # itself indexed regardless of total web_events size).

    def sweep():

        conn = get_db_connection()

        try:
            return process_correlation.reconcile_pending_correlations(conn)
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    return db_config.retry_on_lock(sweep, label="process correlation reconciliation sweep")


# ==================================================
# MAIN LOOP
# ==================================================

def main():

    # Idempotent - safe even if app.py hasn't started yet,
    # and safe to run alongside it (CREATE TABLE IF NOT
    # EXISTS / guarded ALTER TABLE only).
    db_config.ensure_journal_mode(DB_PATH)

    def initialize():

        init_web_monitoring_db()
        init_reputation_db()
        init_threat_intel_db()
        detection_engine.init_detection_engine_db()
        # Stage 25G Phase 3A: durable response plans (guarded, additive).
        response_plans.init_response_plans_db()

    db_config.retry_on_lock(
        initialize,
        cleanup=lambda exc: db_config.release_thread_connections(),
        label="worker initialization"
    )

    print(f"[{WORKER_IDENTITY}] started.")
    print(f"[{WORKER_IDENTITY}] polling every {POLL_SECONDS}s for PENDING web_events...")

    last_sweep = 0.0
    last_browser_local_feed_sweep = 0.0
    last_process_correlation_sweep = 0.0
    last_detection_lifecycle_sweep = 0.0

    while True:

        worker_status.heartbeat(WORKER_NAME)

        try:

            if time.time() - last_sweep >= STALE_SWEEP_INTERVAL_SECONDS:

                recovered = requeue_stale_analyzing()
                last_sweep = time.time()

                if recovered:
                    print(
                        f"[{WORKER_IDENTITY}] returned {recovered} orphaned "
                        "ANALYZING event(s) to PENDING.",
                        flush=True
                    )

            if time.time() - last_browser_local_feed_sweep >= STALE_SWEEP_INTERVAL_SECONDS:

                browser_recovered = requeue_stale_browser_local_feed_claims()
                last_browser_local_feed_sweep = time.time()

                if browser_recovered:
                    print(
                        f"[{WORKER_IDENTITY}] returned {browser_recovered} orphaned "
                        "browser-event local-feed claim(s) for retry.",
                        flush=True
                    )

            if time.time() - last_process_correlation_sweep >= PROCESS_CORRELATION_SWEEP_INTERVAL_SECONDS:

                correlation_result = run_process_correlation_sweep()
                last_process_correlation_sweep = time.time()

                if correlation_result["confirmed"] or correlation_result["expired"]:
                    print(
                        f"[{WORKER_IDENTITY}] process correlation sweep: "
                        f"{correlation_result['confirmed']} confirmed, "
                        f"{correlation_result['expired']} expired, "
                        f"{correlation_result['checked']} checked.",
                        flush=True
                    )

            if time.time() - last_detection_lifecycle_sweep >= DETECTION_LIFECYCLE_SWEEP_INTERVAL_SECONDS:

                def _run_detection_lifecycle_sweep():
                    conn = get_db_connection()
                    try:
                        return detection_engine.reconcile_detection_lifecycle(conn)
                    finally:
                        conn.close()

                lifecycle_result = db_config.retry_on_lock(
                    _run_detection_lifecycle_sweep, label="detection lifecycle sweep"
                )
                last_detection_lifecycle_sweep = time.time()

                # Stage 25G Phase 3A: response-plan staleness sweep, on the
                # same cadence as the detection lifecycle sweep. Expiry is
                # driven only by a plan's own expires_at or its alert being
                # CLOSED/missing - never by whether a dashboard was opened.
                def _run_response_plan_expiry_sweep():
                    conn = get_db_connection()
                    try:
                        return response_plans.expire_stale_plans(conn)
                    finally:
                        conn.close()

                expired_plans = db_config.retry_on_lock(
                    _run_response_plan_expiry_sweep, label="response plan expiry sweep"
                )

                if expired_plans:
                    print(
                        f"[{WORKER_IDENTITY}] response plan expiry sweep: "
                        f"{expired_plans} stale plan(s) expired.",
                        flush=True
                    )

                if lifecycle_result["resolved"]:
                    print(
                        f"[{WORKER_IDENTITY}] detection lifecycle sweep: "
                        f"{lifecycle_result['resolved']} detection(s) resolved (no longer recurring).",
                        flush=True
                    )

            # Step 24B.2C: runs every iteration regardless of TCP traffic
            # (placed BEFORE the TCP claim's `continue` below, so an idle
            # TCP queue never starves browser-event Local Feed checking).
            # One claim per loop iteration, same POLL_SECONDS cadence as
            # the TCP path - never a separate thread/process.
            browser_event = db_config.retry_on_lock(
                claim_next_browser_event_for_local_feed,
                label="claim next browser event for local feed"
            )

            if browser_event is not None:

                process_browser_event_for_local_feed(browser_event)

            # Bounded retry (db_config): claim is one atomic UPDATE, so
            # re-running it after a lock error cannot double-claim.
            event = db_config.retry_on_lock(
                claim_next_pending_event,
                label="claim next event"
            )

            if event is None:

                time.sleep(POLL_SECONDS)
                continue

            print(
                f"[{WORKER_IDENTITY}] claimed #{event['id']} "
                f"({event['destination']})"
            )

            process_event(event)

        except sqlite3.OperationalError as exc:

            # Only a lock that persisted past the bounded retries lands
            # here. The worker keeps running; anything else is re-raised so
            # it stays visible (run_guarded logs a FATAL EXIT).
            if not db_config.is_transient_lock_error(exc):
                raise

            print(
                f"[{WORKER_IDENTITY}] database lock persisted after bounded "
                f"retries - continuing to poll: {exc}",
                flush=True
            )

            db_config.release_thread_connections()

            time.sleep(LOCK_LOOP_BACKOFF_SECONDS)


if __name__ == "__main__":

    worker_status.run_guarded(WORKER_NAME, main)
