# ==================================================
# STEP 25B: PROCESS <-> NETWORK CORRELATION (evidence/query only)
# ==================================================
#
# Links a web_events row (a TCP/domain network event, OR a browser-
# extension navigation) to the SPECIFIC endpoint_process_events row
# (Step 25A) that produced it - never a new table, never a copy of the
# telemetry: web_events gains two nullable columns
# (process_instance_id, process_correlation_status - see
# web_monitoring.init_web_monitoring_db()'s STEP 25B migration block for
# the full column rationale).
#
# IDENTITY RULE (never relaxed): a correlation is only ever CONFIRMED
# when process_instance_id - the SAME sha256(endpoint_uid|pid|create_time)
# identity as process_identity.compute_process_instance_id() - is
# INDEPENDENTLY RECOMPUTED by the server from the raw (endpoint_uid, pid,
# process_create_time) triple and verified against a real, stored
# endpoint_process_events row. PID ALONE IS NEVER A CORRELATION KEY - a
# reused PID with a different create_time produces a completely
# different process_instance_id, so it can never collide with an
# unrelated process's events. If there is not enough evidence to prove a
# link, the result is UNKNOWN (None/"UNAVAILABLE") - never a probabilistic
# guess reported as CONFIRMED (this is the one invariant Step 25B must
# never violate).
#
# ARRIVAL ORDER: a network event can legitimately arrive BEFORE its own
# process event (the TCP loop polls every 2s; the process-discovery loop
# polls every 30s - see endpoint_agent_stable.py). resolve_correlation()
# handles this as PENDING; reconcile_pending_correlations() (called
# periodically by web_event_worker.py, the same "periodic sweep" pattern
# already used for stale-claim recovery) re-checks PENDING rows once the
# process event has had a chance to arrive, and ages a PENDING row out to
# UNAVAILABLE after CORRELATION_MAX_PENDING_AGE_HOURS rather than
# retrying forever.
# ==================================================

from datetime import datetime, timedelta

import process_identity

CORRELATION_CONFIRMED = "CONFIRMED"
CORRELATION_PENDING = "PENDING"
CORRELATION_UNAVAILABLE = "UNAVAILABLE"

# Second-precision event_time (web_events) vs sub-second
# process_create_time (endpoint_process_events, a float) are compared
# with this much slack - covers truncation to the second plus a small
# allowance for Agent/Server clock drift on a LAN. This is a sanity
# check only (a network event cannot predate the process that made it);
# it is never the SOLE basis for a match - the process_instance_id hash
# match already proves the identity; this only guards against an
# otherwise-impossible timeline (e.g. severe clock skew) being reported
# as CONFIRMED regardless.
CORRELATION_CLOCK_SKEW_TOLERANCE_SECONDS = 5

# A PENDING row older than this without its process event ever showing
# up is given up on (UNAVAILABLE) rather than checked forever - bounds
# the reconciliation backlog. 24h comfortably covers "SOC was offline
# for a while" without retrying indefinitely.
CORRELATION_MAX_PENDING_AGE_HOURS = 24

RECONCILIATION_BATCH_LIMIT = 200


def _parse_event_time(event_time_str):

    try:
        return datetime.strptime(event_time_str, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def resolve_correlation(
    conn,
    endpoint_uid,
    pid,
    process_create_time,
    client_process_instance_id,
    event_time_str,
    logger=None
):
    """
    Called at web_events INGESTION time (analyze_web_event_fast), on the
    SAME connection/transaction as the row's own INSERT - never a second
    round trip.

    endpoint_uid: the FINAL, already-identity-guard-resolved uid (the
    caller's own `event_uid`, never the raw unverified client value) -
    a conflicting/unverified identity must never be used for correlation
    either, for the exact same reason it is not attached to the row.

    Returns (process_instance_id_or_None, status_or_None). status is
    None (not even NULL-as-"UNAVAILABLE") when there simply was not
    enough input to attempt correlation at all (old Agent, browser
    event, missing create_time) - distinct from UNAVAILABLE, which
    means correlation WAS attempted and did not succeed/verify.
    """

    if not endpoint_uid or not pid or process_create_time is None:
        return None, None

    recomputed_id = process_identity.compute_process_instance_id(
        endpoint_uid, pid, process_create_time
    )

    if not recomputed_id:
        return None, None

    if (
        client_process_instance_id
        and isinstance(client_process_instance_id, str)
        and client_process_instance_id != recomputed_id
    ):

        # Never trust a client-submitted id that doesn't match what the
        # server independently derives from the same raw fields it also
        # sent - same principle as process_events.py. The base event is
        # still stored (by the caller) - only the correlation is denied.
        if logger is not None:
            logger(
                "PROCESS_CORRELATION_ID_MISMATCH",
                f"endpoint_uid={endpoint_uid} pid={pid} "
                f"client_id={client_process_instance_id} recomputed_id={recomputed_id}"
            )

        return None, CORRELATION_UNAVAILABLE

    existing = conn.execute(
        "SELECT endpoint_uid, pid, process_create_time FROM endpoint_process_events "
        "WHERE process_instance_id = ?",
        (recomputed_id,)
    ).fetchone()

    if existing is None:
        # Network-first case (Step 25B lifecycle B) - the process event
        # has not arrived yet. Stored as PENDING; reconcile_pending_
        # correlations() resolves it once (if) the process event shows up.
        return recomputed_id, CORRELATION_PENDING

    # Defense in depth: the hash construction already makes a mismatch
    # here extremely unlikely (it would require two different
    # (endpoint_uid, pid, create_time) triples to hash identically), but
    # a stored row's fields are re-checked explicitly rather than ever
    # assumed from the id alone.
    if existing["endpoint_uid"] != endpoint_uid or existing["pid"] != pid:

        if logger is not None:
            logger(
                "PROCESS_CORRELATION_ANOMALY",
                f"id={recomputed_id} stored_uid={existing['endpoint_uid']} "
                f"stored_pid={existing['pid']} event_uid={endpoint_uid} event_pid={pid}"
            )

        return None, CORRELATION_UNAVAILABLE

    event_dt = _parse_event_time(event_time_str)

    if event_dt is not None:

        event_epoch = event_dt.timestamp()

        if event_epoch < process_create_time - CORRELATION_CLOCK_SKEW_TOLERANCE_SECONDS:

            # A network event cannot predate the process that produced
            # it (beyond clock-skew tolerance) - an otherwise-matching
            # hash is not enough to call this CONFIRMED if the timeline
            # itself is impossible.
            if logger is not None:
                logger(
                    "PROCESS_CORRELATION_IMPOSSIBLE_TIMELINE",
                    f"id={recomputed_id} event_time={event_time_str} "
                    f"process_create_time={process_create_time}"
                )

            return None, CORRELATION_UNAVAILABLE

    return recomputed_id, CORRELATION_CONFIRMED


def reconcile_pending_correlations(
    conn,
    batch_limit=RECONCILIATION_BATCH_LIMIT,
    max_age_hours=CORRELATION_MAX_PENDING_AGE_HOURS,
    now=None
):
    """
    Periodic sweep (called from web_event_worker.py's main loop, the
    same cadence/pattern already used for requeue_stale_analyzing() /
    requeue_stale_browser_local_feed_claims()) - resolves web_events
    rows left PENDING by resolve_correlation() once their process event
    has (or definitively has not, within the age bound) arrived.

    Plain SELECT-then-UPDATE (no claim/lock state): every step here is a
    cheap, side-effect-free local lookup (no external I/O, unlike the
    Local Feed browser-event sweep), so a crash mid-batch is always
    safely idempotent - the next sweep simply re-evaluates the same
    still-PENDING rows with no duplicate work.

    Returns {"confirmed": n, "expired": n, "checked": n}.
    """

    now = now or datetime.now()
    cutoff_dt = now - timedelta(hours=max_age_hours)

    rows = conn.execute("""
        SELECT id, endpoint_uid, process_pid, process_instance_id, event_time
        FROM web_events
        WHERE process_correlation_status = 'PENDING'
        ORDER BY id ASC
        LIMIT ?
    """, (batch_limit,)).fetchall()

    confirmed = 0
    expired = 0

    for row in rows:

        process_instance_id = row["process_instance_id"]

        existing = conn.execute(
            "SELECT endpoint_uid, pid, process_create_time FROM endpoint_process_events "
            "WHERE process_instance_id = ?",
            (process_instance_id,)
        ).fetchone()

        if existing is not None:

            # Re-verify - never promote to CONFIRMED on the id string
            # alone, even here.
            consistent = (
                existing["endpoint_uid"] == row["endpoint_uid"]
                and existing["pid"] == row["process_pid"]
            )

            event_dt = _parse_event_time(row["event_time"])
            timeline_ok = (
                event_dt is not None
                and event_dt.timestamp() >= existing["process_create_time"]
                - CORRELATION_CLOCK_SKEW_TOLERANCE_SECONDS
            )

            if consistent and timeline_ok:

                conn.execute(
                    "UPDATE web_events SET process_correlation_status = ? "
                    "WHERE id = ? AND process_correlation_status = 'PENDING'",
                    (CORRELATION_CONFIRMED, row["id"])
                )
                confirmed += 1
                continue

            # Found a row but it doesn't check out - give up rather than
            # leave a permanently-retried bad match.
            conn.execute(
                "UPDATE web_events SET process_correlation_status = ?, process_instance_id = NULL "
                "WHERE id = ? AND process_correlation_status = 'PENDING'",
                (CORRELATION_UNAVAILABLE, row["id"])
            )
            expired += 1
            continue

        event_dt = _parse_event_time(row["event_time"])

        if event_dt is not None and event_dt < cutoff_dt:

            # Aged out - the process event never arrived within the
            # bound. Never retried again; the id is cleared so nothing
            # downstream mistakes it for a live reference.
            conn.execute(
                "UPDATE web_events SET process_correlation_status = ?, process_instance_id = NULL "
                "WHERE id = ? AND process_correlation_status = 'PENDING'",
                (CORRELATION_UNAVAILABLE, row["id"])
            )
            expired += 1

        # else: still within the retry window, left PENDING as-is.

    conn.commit()

    return {"confirmed": confirmed, "expired": expired, "checked": len(rows)}


def get_network_events_for_process(conn, process_instance_id, limit=200):
    """
    Read-only, for the Process Detail view (Step 25B section 9). Reuses
    web_events' EXISTING risk_score/severity/decision/reputation_source
    columns, already populated by the existing (unmodified) Threat
    Intelligence pipeline - no new TI lookup is ever triggered by this
    query.
    """

    limit = max(1, min(int(limit), 1000))

    return conn.execute("""
        SELECT id, event_time, destination, domain, resolved_ip,
               transport_protocol, destination_port, risk_score,
               severity, decision, reputation_source, source,
               process_correlation_status
        FROM web_events
        WHERE process_instance_id = ?
        ORDER BY event_time DESC
        LIMIT ?
    """, (process_instance_id, limit)).fetchall()
