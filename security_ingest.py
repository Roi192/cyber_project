# ==================================================
# PHASE 13B: GENERIC SECURITY INGESTION SERVICE
# ==================================================
#
# The one reusable internal path every future adapter (Suricata, Zeek, Wazuh
# ...) goes through. It contains NO engine-specific code:
#
#   authenticated sensor (SensorIdentity - produced by security_sensors)
#        -> validate/normalize each record (security_contract)
#        -> idempotency (UNIQUE keys in each store)
#        -> OBSERVATION -> telemetry store (separate daily files)
#           DETECTION   -> main DB security_detections
#
# It never creates alerts, incidents, alert_events or response commands.
# Rejected records are REJECTED with a deterministic reason code (no
# quarantine database); the reason is written to a bounded rotating
# structured log - never the payload, never any secret.

import json
import logging
import logging.handlers
import os
import re
import threading
import time

from collections import OrderedDict, defaultdict

import db_config
import security_contract as sc
import security_detections as sd
import security_resolution
import security_sensors
import telemetry_store

MAX_BATCH_RECORDS = 100
MAX_LOGGED_REJECTIONS_PER_BATCH = 20

STATUS_ACCEPTED = "ACCEPTED"
STATUS_DUPLICATE = "DUPLICATE"
STATUS_REJECTED = "REJECTED"

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


class BatchTooLarge(Exception):
    pass


class StorageBusy(Exception):

    # A store stayed locked through the bounded retry policy. The request is
    # safe to retry: ingestion is idempotent.
    pass


# --------------------------------------------------
# STRUCTURED SECURITY LOG (bounded, no payloads, no secrets)
# --------------------------------------------------

_log_lock = threading.Lock()
_logger = None
_logger_path = None

_SAFE_TOKEN_RE = re.compile(r"[^A-Za-z0-9._:@/+=-]")


def log_dir():

    override = os.getenv("SECURITY_LOG_DIR", "").strip()

    if override:
        base = override if os.path.isabs(override) else os.path.join(_PROJECT_DIR, override)
    else:
        base = os.path.join(_PROJECT_DIR, "data", "logs")

    return os.path.abspath(base)


def _clean(value, limit=64):

    # Only a short, character-restricted token can ever reach the log. Any
    # attacker-controlled value is reduced to this form (or "?").
    if value is None:
        return None

    text = _SAFE_TOKEN_RE.sub("", str(value))[:limit]

    return text or "?"


def _get_logger():

    global _logger, _logger_path

    directory = log_dir()
    path = os.path.join(directory, "security_ingest.log")

    with _log_lock:

        if _logger is not None and _logger_path == path:
            return _logger

        logger = logging.getLogger(f"soc.security_ingest.{path}")
        logger.setLevel(logging.INFO)
        logger.propagate = False

        for old in list(logger.handlers):
            logger.removeHandler(old)
            try:
                old.close()
            except Exception:
                pass

        try:
            os.makedirs(directory, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                path, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8", delay=True
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
        except OSError:
            logger.addHandler(logging.NullHandler())

        _logger, _logger_path = logger, path

        return logger


def security_log(event, **fields):

    # Whitelisted, cleaned fields only. Never raises.
    allowed = ("sensor_id", "source_event_id", "reason", "remote_addr",
               "status", "count", "accepted", "duplicates", "rejected", "code")

    entry = {"ts": sc.utc_now_iso(), "event": _clean(event, 40)}

    for key in allowed:
        if key in fields and fields[key] is not None:
            value = fields[key]
            entry[key] = value if isinstance(value, int) and not isinstance(value, bool) else _clean(value)

    try:
        _get_logger().info(json.dumps(entry, separators=(",", ":")))
    except Exception:
        pass


# --------------------------------------------------
# RATE LIMITING (in-process, bounded memory)
# --------------------------------------------------

def _float_env(name, default):

    try:
        value = float(os.getenv(name, "").strip())
    except ValueError:
        return default

    return value if value > 0 else default


class TokenBucketLimiter:

    def __init__(self, rate_per_second, burst, max_keys=1024, clock=time.monotonic):
        self.rate = rate_per_second
        self.burst = burst
        self.max_keys = max_keys
        self.clock = clock
        self._buckets = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key):

        now = self.clock()

        with self._lock:

            tokens, stamp = self._buckets.get(key, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + (now - stamp) * self.rate)

            allowed = tokens >= 1.0

            if allowed:
                tokens -= 1.0

            self._buckets[key] = (tokens, now)
            self._buckets.move_to_end(key)

            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)

            return allowed


class FailureThrottle:

    # Bounded per-remote-address counter of recent authentication failures.
    def __init__(self, max_failures=20, window_seconds=60.0, max_keys=2048, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window_seconds
        self.max_keys = max_keys
        self.clock = clock
        self._events = OrderedDict()
        self._lock = threading.Lock()

    def blocked(self, key):

        now = self.clock()

        with self._lock:

            recent = [t for t in self._events.get(key, ()) if now - t < self.window]

            return len(recent) >= self.max_failures

    def record_failure(self, key):

        now = self.clock()

        with self._lock:

            recent = [t for t in self._events.get(key, ()) if now - t < self.window]
            recent.append(now)

            self._events[key] = recent
            self._events.move_to_end(key)

            while len(self._events) > self.max_keys:
                self._events.popitem(last=False)


def make_sensor_limiter():
    return TokenBucketLimiter(
        _float_env("SECURITY_INGEST_RATE_PER_SEC", 20.0),
        _float_env("SECURITY_INGEST_BURST", 40.0),
    )


# --------------------------------------------------
# INGESTION
# --------------------------------------------------

class BatchResult:

    def __init__(self, results):
        self.results = results
        # Phase 14B: counts per stored endpoint_resolution status (statuses only -
        # never a uid, so a sensor learns nothing about endpoint identity).
        self.resolution_counts = {}

    @property
    def accepted(self):
        return sum(1 for r in self.results if r["status"] == STATUS_ACCEPTED)

    @property
    def duplicates(self):
        return sum(1 for r in self.results if r["status"] == STATUS_DUPLICATE)

    @property
    def rejected(self):
        return sum(1 for r in self.results if r["status"] == STATUS_REJECTED)

    def http_status(self):

        # 202: everything accepted or already present; 422: nothing usable;
        # 207: a mix (the per-record results say which).
        if self.rejected == 0:
            return 202

        if self.rejected == len(self.results):
            return 422

        return 207


_config_error_logged = set()


def _log_network_config_error_once(code):

    # A rejected MONITORED_NETWORKS setting disables resolution (fail closed); the
    # operator is told once per process, never once per request.
    if code in _config_error_logged:
        return

    _config_error_logged.add(code)
    security_log("config_error", code=code)


def _apply_resolution_policy(pairs, networks, now):

    # One short-lived read connection for the whole batch. ANY failure leaves the
    # records exactly as normalized (resolution is best effort, never mandatory).
    conn = None

    try:

        conn = sd.get_db_connection()

        cache = {}

        return [
            (index, security_resolution.apply_policy(record, networks, now, conn, cache))
            for index, record in pairs
        ]

    except Exception:

        return pairs

    finally:

        if conn is not None:
            conn.close()


def _resolve_or_keep(record, ip_field, now):

    # Never lets a resolver problem reject or alter the record otherwise.
    try:
        import endpoint_network
        return endpoint_network.apply_resolution(record, ip_field, now=now)
    except Exception:
        return record


def ingest_batch(sensor, raw_records, now=None, resolve_ip_field=None, monitored_networks=None):

    # `sensor` MUST be a SensorIdentity returned by authentication. `now`
    # (aware UTC datetime) is injectable for tests; ingested_at is stamped
    # from it, never accepted from the sensor.
    # Phase 13C: `resolve_ip_field` ('src_ip' or 'dst_ip') OPTIONALLY applies
    # the timestamp-aware endpoint resolver to each record. Default None =
    # off (resolution is never mandatory and the HTTP route does not enable
    # it). A SENSOR_ASSERTED record is never upgraded; only EXACT attaches
    # an endpoint_uid; a resolver failure leaves the record unresolved.
    # Phase 14B: when MONITORED_NETWORKS (alias SECURITY_MONITORED_NETWORKS, or `monitored_networks`) is
    # configured, a PER-RECORD policy (security_resolution) picks the internal
    # side of each NETWORK record and resolves it; unset = no resolution at all.
    if not isinstance(raw_records, list):
        raise BatchTooLarge("records must be a list")

    if len(raw_records) > MAX_BATCH_RECORDS or not raw_records:
        raise BatchTooLarge("batch size out of range")

    now = now or sc.utc_now()

    if isinstance(monitored_networks, str):
        networks, config_error = security_resolution.load_config(monitored_networks)
    elif monitored_networks is not None:
        networks, config_error = tuple(monitored_networks), None
    else:
        networks, config_error = security_resolution.config_from_env()

    if config_error:
        _log_network_config_error_once(config_error)

    results = [None] * len(raw_records)
    observations_by_day = defaultdict(list)
    detections = []
    normalized = []
    resolution_counts = {}
    logged = 0

    for index, raw in enumerate(raw_records):

        record, reason = sc.try_normalize(raw, sensor, now)

        if record is None:

            results[index] = {"index": index, "status": STATUS_REJECTED, "reason": reason}

            if logged < MAX_LOGGED_REJECTIONS_PER_BATCH:

                logged += 1

                event_id = raw.get("source_event_id") if isinstance(raw, dict) else None
                safe_id = event_id if (isinstance(event_id, str)
                                       and sc._SOURCE_EVENT_ID_RE.match(event_id)) else None

                security_log("record_rejected", sensor_id=sensor.sensor_id,
                             source_event_id=safe_id, reason=reason)

            continue

        if resolve_ip_field:
            record = _resolve_or_keep(record, resolve_ip_field, now)

        normalized.append((index, record))

    # Phase 14B: per-record resolution policy (one connection + cache per batch).
    # An explicit resolve_ip_field (13C) takes precedence and disables the policy.
    if networks and normalized and not resolve_ip_field:
        normalized = _apply_resolution_policy(normalized, networks, now)

    for index, record in normalized:

        if record.record_type == sc.RECORD_OBSERVATION:
            observations_by_day[record.observed_day()].append((index, record))
        else:
            detections.append((index, record))

        resolution_counts[record.endpoint_resolution] = resolution_counts.get(record.endpoint_resolution, 0) + 1

    try:

        for day in sorted(observations_by_day):

            pairs = observations_by_day[day]

            try:
                statuses = telemetry_store.insert_observations(day, [r for _, r in pairs], now)
            except telemetry_store.TelemetryStoreError as exc:
                # e.g. a sealed day (defensive: record validation already
                # bounds observed_at). Rejected, not partially stored.
                for index, _ in pairs:
                    results[index] = {"index": index, "status": STATUS_REJECTED, "reason": exc.code}
                continue

            for (index, _), status in zip(pairs, statuses):
                results[index] = {"index": index, "status": status}

        if detections:

            conn = sd.get_db_connection()

            try:
                statuses = db_config.retry_on_lock(
                    lambda: sd.insert_detections(conn, [r for _, r in detections]),
                    label="security_detections_insert",
                    cleanup=lambda exc: conn.rollback(),
                )
            finally:
                conn.close()

            for (index, _), status in zip(detections, statuses):
                results[index] = {"index": index, "status": status}

    except db_config.LockRetryExhausted as exc:
        raise StorageBusy("storage busy") from exc

    result = BatchResult(results)
    result.resolution_counts = resolution_counts

    if result.accepted or result.duplicates:
        security_sensors.touch_last_seen(sensor.sensor_id)

    security_log("batch", sensor_id=sensor.sensor_id, count=len(results),
                 accepted=result.accepted, duplicates=result.duplicates,
                 rejected=result.rejected)

    return result
