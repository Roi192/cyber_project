# ==================================================
# PHASE 12B.6C.1: LIGHTWEIGHT WORKER HEALTH VISIBILITY
# ==================================================
#
# Deliberately tiny (no monitoring platform): each worker writes a small JSON
# status file, ONE FILE PER WORKER, atomically (write temp + replace):
#
#     worker_status/<worker>.json
#     {"worker", "pid", "state": "running"|"exited"|"failed",
#      "started_at", "heartbeat_at", "exited_at", "error"}
#
# It never touches the database (the database is exactly what may be
# unavailable when a worker fails). A worker announces start, refreshes a
# heartbeat at most every HEARTBEAT_INTERVAL_SECONDS, and run_guarded() logs
# and records a FATAL EXIT if main() ever leaves with an exception.
#
# Check health from a terminal:   python worker_status.py
# (exit code 1 if any required worker is not running or its heartbeat is
# stale, so it can also be used by a scheduled check).

import json
import os
import sys
import time
import traceback
from datetime import datetime

REQUIRED_WORKERS = ("web_event_worker", "behavioral_worker", "threat_intel_worker")
HEARTBEAT_INTERVAL_SECONDS = 30
STALE_AFTER_SECONDS = 180

_STATUS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.getenv("SOC_WORKER_STATUS_DIR", "worker_status")
)

_state = {}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _path(worker):
    return os.path.join(_STATUS_DIR, f"{worker}.json")


def _write(worker, payload):

    try:
        os.makedirs(_STATUS_DIR, exist_ok=True)
        tmp = _path(worker) + f".{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        os.replace(tmp, _path(worker))
    except OSError:
        # Health reporting must never take a worker down.
        pass


def announce_start(worker):

    now = _now()

    _state[worker] = {
        "worker": worker,
        "pid": os.getpid(),
        "state": "running",
        "started_at": now,
        "heartbeat_at": now,
        "exited_at": None,
        "error": None,
        "_last_write": time.time(),
    }

    _write(worker, {k: v for k, v in _state[worker].items() if not k.startswith("_")})

    print(f"[{worker}] STARTED pid={os.getpid()} at {now}", flush=True)


def heartbeat(worker):

    record = _state.get(worker)

    if record is None:
        return

    if time.time() - record["_last_write"] < HEARTBEAT_INTERVAL_SECONDS:
        return

    record["heartbeat_at"] = _now()
    record["_last_write"] = time.time()

    _write(worker, {k: v for k, v in record.items() if not k.startswith("_")})


def announce_exit(worker, error=None, clean=True):

    record = _state.get(worker) or {"worker": worker, "pid": os.getpid(), "started_at": None}

    record["state"] = "exited" if clean else "failed"
    record["exited_at"] = _now()
    record["heartbeat_at"] = record.get("heartbeat_at") or record["exited_at"]
    record["error"] = None if error is None else str(error)[:500]

    _write(worker, {k: v for k, v in record.items() if not k.startswith("_")})

    if clean:
        print(f"[{worker}] EXITED cleanly at {record['exited_at']}", flush=True)
    else:
        print(f"[{worker}] FATAL EXIT at {record['exited_at']}: {record['error']}", file=sys.stderr, flush=True)


def run_guarded(worker, main):

    # Wraps a worker's main(): logs the start, and records a clear FATAL
    # EXIT (message + traceback on stderr, status file) on any exception.
    announce_start(worker)

    try:
        main()
    except KeyboardInterrupt:
        announce_exit(worker, error="interrupted", clean=True)
        raise
    except SystemExit:
        announce_exit(worker, clean=True)
        raise
    except BaseException as exc:
        traceback.print_exc()
        announce_exit(worker, error=f"{type(exc).__name__}: {exc}", clean=False)
        raise
    else:
        announce_exit(worker, clean=True)


# --------------------------------------------------
# CLI CHECK
# --------------------------------------------------

def check(status_dir=None, now=None):

    # Returns (rows, ok). A worker is healthy only if its status file says
    # running, its process still exists, and its heartbeat is fresh.
    directory = status_dir or _STATUS_DIR
    now = now or time.time()
    rows = []
    ok = True

    try:
        import psutil
    except ImportError:
        psutil = None

    for worker in REQUIRED_WORKERS:

        path = os.path.join(directory, f"{worker}.json")
        row = {"worker": worker, "healthy": False, "detail": "no status file (never started under this version)"}

        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            data = None

        if data:
            alive = True if psutil is None else psutil.pid_exists(int(data.get("pid") or 0))
            try:
                age = now - datetime.strptime(data["heartbeat_at"], "%Y-%m-%d %H:%M:%S").timestamp()
            except (KeyError, ValueError):
                age = None

            if data.get("state") != "running":
                row["detail"] = f"{data.get('state')} at {data.get('exited_at')}: {data.get('error')}"
            elif not alive:
                row["detail"] = f"pid {data.get('pid')} is gone (no clean exit recorded)"
            elif age is None or age > STALE_AFTER_SECONDS:
                row["detail"] = f"heartbeat stale ({'unknown' if age is None else int(age)}s old)"
            else:
                row["healthy"] = True
                row["detail"] = f"running pid={data.get('pid')}, heartbeat {int(age)}s ago"

        ok = ok and row["healthy"]
        rows.append(row)

    return rows, ok


if __name__ == "__main__":

    result, healthy = check()

    for item in result:
        print(f"{'OK  ' if item['healthy'] else 'FAIL'} {item['worker']:<22} {item['detail']}")

    sys.exit(0 if healthy else 1)
