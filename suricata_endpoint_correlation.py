# ==================================================
# STAGE 25E: SURICATA ENDPOINT CORRELATION (section 11)
# ==================================================
#
# AUDIT CORRECTION (made during this stage's own implementation, kept
# here honestly rather than silently dropped): IP -> endpoint_uid
# correlation for Suricata detections is ALREADY FULLY IMPLEMENTED -
# security_resolution.py's apply_policy() already calls
# endpoint_network.resolve_endpoint() (Phase 13C) AT INGESTION TIME,
# for every network-sourced record, gated by the operator's own
# MONITORED_NETWORKS setting, and already writes the result straight
# onto security_detections.endpoint_uid/endpoint_resolution (EXACT/
# AMBIGUOUS/STALE/UNKNOWN/NOT_ATTEMPTED - never SENSOR_ASSERTED for a
# network sensor). Live-verified: 22,355 of 22,963 real historical
# detections already carry endpoint_resolution='EXACT' with a real
# endpoint_uid. This module does NOT re-implement that - callers
# (e.g. detection_engine.py's Suricata rule) read endpoint_uid/
# endpoint_resolution directly off the security_detections row they
# already have.
#
# The ONE genuinely new correlation this module adds - NOT covered by
# security_resolution.py, which only resolves an endpoint identity,
# never a SPECIFIC web_event/process - is:
#
#   Suricata flow (src_ip, dst_ip, dst_port, protocol, observed_at)
#   -> a specific web_events row (and therefore its process_
#   instance_id, if that row's OWN Stage 25B correlation is itself
#   CONFIRMED) - a bounded 5-tuple + time-window match. web_events has
#   NO source-port column (see its schema), so more than one candidate
#   match within the window is a REAL ambiguity, not a bug - this
#   returns UNRESOLVED rather than guessing, exactly per instruction
#   #11 ("UNRESOLVED עדיף על process שגוי"). NEVER invents a
#   process_instance_id from source/destination alone.
#
# Read-only. No live lookup, no write to security_detections, no
# risk/alert/response action.
# ==================================================

from datetime import timedelta

import security_contract as sc
import web_monitoring

# Suricata (network sensor) and the endpoint Agent's own TCP-loop
# observe the SAME connection from two different vantage points with
# independent clocks and independent polling cadences (Agent: 2s TCP
# loop; Suricata: whenever the flow record is emitted) - a wider
# tolerance than 25B's own 5s process-identity clock-skew check, but
# still small and bounded (fixed, explainable number, not tuned).
FLOW_CORRELATION_WINDOW_SECONDS = 60


def find_related_web_event(src_ip, dst_ip, dst_port, protocol, observed_at_utc, conn=None):
    """
    Bounded (src_ip, dst_ip, dst_port, protocol, time-window) match
    against web_events. Returns (web_event_row_dict_or_None, status)
    where status is one of:
        "CONFIRMED"   - exactly one web_events row matches
        "UNRESOLVED"  - zero or MORE THAN ONE candidate match (web_events
                        has no source-port column, so >1 is a real,
                        honest ambiguity - never arbitrarily picked)
    NEVER invents a process_instance_id - the caller reads it only off
    a CONFIRMED row, and only if that row's OWN
    process_correlation_status (Stage 25B) is itself CONFIRMED.
    observed_at_utc may be a UTC ISO string (security_detections.
    observed_at's own format) or an aware datetime.
    """

    own = conn is None

    if own:
        conn = web_monitoring.get_db_connection()

    try:

        moment = sc.parse_utc(observed_at_utc) if isinstance(observed_at_utc, str) else observed_at_utc

        if moment is None:
            return None, "UNRESOLVED"

        # web_events.event_time is naive LOCAL time (see web_event_worker.py's
        # own documented caveat from Stage 25B) - converted here via the
        # system's own local timezone, matching detection_engine.py's own
        # identical conversion for the same reason.
        local_moment = moment.astimezone().replace(tzinfo=None)

        window_start = (local_moment - timedelta(seconds=FLOW_CORRELATION_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
        window_end = (local_moment + timedelta(seconds=FLOW_CORRELATION_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")

        rows = conn.execute("""
            SELECT * FROM web_events
            WHERE source_ip = ? AND resolved_ip = ? AND destination_port = ? AND transport_protocol = ?
              AND event_time >= ? AND event_time <= ?
            ORDER BY event_time DESC
            LIMIT 5
        """, (src_ip, dst_ip, dst_port, protocol, window_start, window_end)).fetchall()

        if len(rows) != 1:
            return None, "UNRESOLVED"

        return dict(rows[0]), "CONFIRMED"

    finally:
        if own:
            conn.close()
