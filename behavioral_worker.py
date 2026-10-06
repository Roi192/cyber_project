# ==================================================
# PHASE 11C: BEHAVIORAL BASELINE WORKER
# ==================================================
#
# Standalone process (same rationale as web_event_worker.py's own
# header comment: one job, one process - Flask's debug reloader can
# spawn extra copies of the main process, and this worker's job is
# architecturally independent of Threat Intelligence/IOC/Alert
# processing anyway). Zero changes to web_event_worker.py; a
# failure or slowdown in this worker can never delay or break
# Threat Intelligence, IOC correlation, Alerts, or Incidents.
#
# Two phases, both driven by behavioral_analysis.py's single shared
# logic:
#
#   BOOTSTRAP: every trusted (endpoints.source='endpoint-agent'),
#   Agent-sourced (web_events.source='endpoint-agent'), ANALYZED
#   event with event_time <= the bootstrap cutoff is training
#   history only - it populates the aggregate "seen" tables and
#   maturity state, but never receives an anomaly score. This is a
#   fixed, closed historical set (the cutoff never moves), so it is
#   processed once, in (event_time, id) order, and is safely
#   resumable via behavioral_baseline_state.bootstrap_last_event_id
#   if the process is interrupted.
#
#   LIVE: every such event with event_time > the cutoff is scored,
#   using only baseline state that existed strictly before it (see
#   evaluate_live_event()). Claimed by id (arrival order, NOT
#   event_time order - event_time is client-set and can arrive out
#   of order), and idempotent via the UNIQUE(web_event_id)
#   constraint on behavioral_event_results plus one transaction per
#   event (commit on success, rollback on any exception - an event
#   can never be partially incorporated).
#
# Run in its own terminal window:
#   python behavioral_worker.py
# ==================================================

import sqlite3
import time
from datetime import datetime

import behavioral_analysis as ba
import db_config
import worker_status

WORKER_IDENTITY = "behavioral-worker"
WORKER_NAME = "behavioral_worker"

# Phase 12B.6C.1: pause after a lock that outlasted the connection's busy
# timeout; the worker then keeps running (it never exits on a lock).
LOCK_LOOP_BACKOFF_SECONDS = 3

POLL_SECONDS = 5
LIVE_BATCH_SIZE = 200
BOOTSTRAP_BATCH_SIZE = 500


def get_trusted_agent_endpoints(conn):

    rows = conn.execute("""
        SELECT DISTINCT ip_address FROM endpoints WHERE source = 'endpoint-agent'
    """).fetchall()

    return [row["ip_address"] for row in rows]


def run_bootstrap_for_endpoint(conn, endpoint_ip, cutoff):

    # Batched commits (one transaction per BOOTSTRAP_BATCH_SIZE
    # events, not one per event) - safe because bootstrap only ever
    # processes a FIXED, closed historical set (event_time <=
    # cutoff, which never moves), in deterministic (event_time, id)
    # order. If the process crashes mid-batch, the whole in-progress
    # batch is rolled back and simply reprocessed from the last
    # committed bootstrap_last_event_id checkpoint on the next run -
    # no double-counting, since nothing from a rolled-back batch was
    # ever committed to the aggregate tables.

    state = ba.get_or_init_baseline_state(conn, endpoint_ip)

    if state["bootstrap_completed"]:
        return 0

    last_id = state["bootstrap_last_event_id"] or 0

    total_incorporated = 0

    while True:

        rows = conn.execute("""
            SELECT w.* FROM web_events w
            JOIN endpoints e ON w.endpoint_ip = e.ip_address
            WHERE e.source = 'endpoint-agent'
            AND w.source = 'endpoint-agent'
            AND w.analysis_status = 'ANALYZED'
            AND w.endpoint_ip = ?
            AND w.event_time <= ?
            AND w.id > ?
            ORDER BY w.event_time ASC, w.id ASC
            LIMIT ?
        """, (endpoint_ip, cutoff, last_id, BOOTSTRAP_BATCH_SIZE)).fetchall()

        if not rows:
            break

        try:

            batch_last_id = last_id

            for row in rows:

                event = dict(row)
                ba.incorporate_bootstrap_event(conn, endpoint_ip, event)
                batch_last_id = event["id"]
                total_incorporated += 1

            conn.commit()
            last_id = batch_last_id

        except Exception as e:

            conn.rollback()

            # Phase 12B.6C.1: a transient lock aborts this cycle (the whole
            # batch was rolled back and is resumed from the last committed
            # checkpoint next time) - it is not a bootstrap error.
            if db_config.is_transient_lock_error(e):
                raise

            print(
                f"[behavioral-worker] BOOTSTRAP ERROR endpoint={endpoint_ip} "
                f"near event_id={last_id}: {e}"
            )

            return total_incorporated

        if len(rows) < BOOTSTRAP_BATCH_SIZE:
            break

    ba.mark_bootstrap_complete(conn, endpoint_ip)
    conn.commit()

    return total_incorporated


def run_bootstrap(conn, cutoff):

    endpoints = get_trusted_agent_endpoints(conn)

    for endpoint_ip in endpoints:

        count = run_bootstrap_for_endpoint(conn, endpoint_ip, cutoff)

        if count:
            print(f"[behavioral-worker] Bootstrap incorporated {count} training events for {endpoint_ip}")


def claim_live_batch(conn, cutoff):

    rows = conn.execute("""
        SELECT w.* FROM web_events w
        JOIN endpoints e ON w.endpoint_ip = e.ip_address
        JOIN behavioral_baseline_state s ON s.endpoint_ip = w.endpoint_ip
        LEFT JOIN behavioral_event_results r ON r.web_event_id = w.id
        WHERE e.source = 'endpoint-agent'
        AND w.source = 'endpoint-agent'
        AND w.analysis_status = 'ANALYZED'
        AND w.event_time > ?
        AND s.bootstrap_completed = 1
        AND r.id IS NULL
        ORDER BY w.id ASC
        LIMIT ?
    """, (cutoff, LIVE_BATCH_SIZE)).fetchall()

    return [dict(row) for row in rows]


def run_live_cycle(conn, cutoff):

    events = claim_live_batch(conn, cutoff)

    for event in events:

        try:
            ba.evaluate_live_event(conn, event["endpoint_ip"], event)
            conn.commit()

        except Exception as e:

            conn.rollback()

            # Phase 12B.6C.1: a transient database lock is not a property
            # of the event. Do NOT record a permanent ERROR outcome for it;
            # abort the batch and let the loop retry the event later
            # (evaluation is one transaction per event, so nothing is
            # half-incorporated).
            if db_config.is_transient_lock_error(e):
                raise

            print(
                f"[behavioral-worker] LIVE EVAL ERROR event_id={event['id']}: {e}"
            )

            # Record an ERROR outcome so this event is never retried
            # forever on a permanently-failing input (still one
            # commit, still idempotent via UNIQUE(web_event_id)).
            try:
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                conn.execute("""
                    INSERT OR IGNORE INTO behavioral_event_results (
                        web_event_id, endpoint_ip, event_time, evaluation_status,
                        anomaly_score, maturity_state_at_evaluation, confidence,
                        behavioral_reasons, temporal_status, computed_at
                    ) VALUES (?, ?, ?, 'ERROR', NULL, NULL, NULL, '[]', NULL, ?)
                """, (event["id"], event["endpoint_ip"], event["event_time"], now_str))
                conn.commit()
            except Exception:
                conn.rollback()

    return len(events)


def main():

    db_config.ensure_journal_mode(ba.DB_NAME)

    db_config.retry_on_lock(
        ba.init_behavioral_db,
        cleanup=lambda exc: db_config.release_thread_connections(),
        label="behavioral initialization"
    )

    def read_cutoff():

        conn = ba.get_db_connection()

        try:

            return ba.get_or_create_bootstrap_cutoff(conn)

        except BaseException:

            conn.rollback()
            raise

        finally:

            conn.close()

    cutoff = db_config.retry_on_lock(read_cutoff, label="bootstrap cutoff")

    print("Behavioral Baseline Worker started")
    print("Bootstrap cutoff:", cutoff)

    while True:

        worker_status.heartbeat(WORKER_NAME)

        connection_mark = db_config.mark()

        conn = ba.get_db_connection()

        try:

            run_bootstrap(conn, cutoff)

            processed = run_live_cycle(conn, cutoff)

            if processed:
                print(f"[behavioral-worker] scored {processed} live event(s)")

        except sqlite3.OperationalError as exc:

            # Phase 12B.6C.1: only a transient lock is tolerated (logged,
            # transaction rolled back by the per-event handlers / close, and
            # the loop simply tries again). Any other database error is
            # re-raised so it stays visible (run_guarded logs FATAL EXIT).
            if not db_config.is_transient_lock_error(exc):
                raise

            print(
                f"[behavioral-worker] database lock - cycle abandoned, will "
                f"retry: {exc}",
                flush=True
            )

            time.sleep(LOCK_LOOP_BACKOFF_SECONDS)

        finally:

            try:
                conn.rollback()
            except sqlite3.Error:
                pass

            conn.close()

            # Phase 12B.6C.1: nothing opened during this iteration may
            # outlive it (rolled back + closed if a helper leaked one).
            db_config.release_since(connection_mark)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    worker_status.run_guarded(WORKER_NAME, main)
