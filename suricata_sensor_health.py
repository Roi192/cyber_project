# ==================================================
# STAGE 25E: SENSOR HEALTH (section 12)
# ==================================================
#
# "22,000 diagnostics must never be shown to an admin as 22,000 cyber
# attacks" - this module's whole purpose. Computes a sensor's health
# from data that ALREADY EXISTS (security_sensors.last_seen_at,
# security_detections, the telemetry store) - no new ingestion, no new
# table, no live Kali/Suricata command. Packets/drops/capture-errors
# are NOT available today (Suricata's own `stats` EVE lines are
# currently kept LOCAL to the adapter's status.json, never forwarded
# to the server - see sensors/suricata_adapter.py's module header);
# this is reported honestly as UNAVAILABLE, never a fabricated 0 or
# guessed number. Forwarding `stats` to the server is DESIGNED but not
# implemented in this stage (see the Stage 25E report).
# ==================================================

from datetime import timedelta

import security_contract as sc
import security_detections as sd
import security_sensors
import suricata_classification

STATUS_ONLINE = "ONLINE"
STATUS_OFFLINE = "OFFLINE"
STATUS_UNKNOWN = "UNKNOWN"

# A sensor posts in small batches, frequently, while running (Phase
# 14B); 180s with zero new data is treated as OFFLINE - generous
# enough to absorb normal batching/network jitter, same "small, fixed,
# explainable number" philosophy as every other threshold in this
# project.
ONLINE_THRESHOLD_SECONDS = 180

# Bounded lookback for the events/min and classification-bucket
# counts - never an unbounded scan.
HEALTH_WINDOW_MINUTES = 15


def _classification_counts(detections):

    counts = {
        suricata_classification.CLASS_SECURITY_ALERT: 0,
        suricata_classification.CLASS_PROTOCOL_EVENT: 0,
        suricata_classification.CLASS_ENGINE_DIAGNOSTIC: 0,
    }

    for row in detections:
        classification, _explanation = suricata_classification.classify_detection_row(row)
        counts[classification] = counts.get(classification, 0) + 1

    return counts


def compute_sensor_health(sensor_id, now=None, conn=None):
    """
    Returns a dict:
        sensor_id, status (ONLINE/OFFLINE/UNKNOWN), last_seen_at,
        last_event_at, last_security_alert_at, events_per_min,
        security_alerts_per_min, diagnostics_per_min,
        protocol_events_per_min, interface (from recent metadata, if
        present), packets/drops/capture_errors (always None/
        "UNAVAILABLE" today - see module header), window_minutes.
    Never raises - a health-computation problem must never break the
    page/worker calling it; returns UNKNOWN on any lookup failure.
    """

    now = now or sc.utc_now()

    try:

        sensors_by_id = {row["sensor_id"]: row for row in security_sensors.list_sensors()}
        sensor = sensors_by_id.get(sensor_id)

        if sensor is None:
            return {"sensor_id": sensor_id, "status": STATUS_UNKNOWN, "reason": "NOT_REGISTERED"}

        last_seen_at = sensor.get("last_seen_at")
        status = STATUS_UNKNOWN
        seconds_since_seen = None

        if last_seen_at:
            last_seen_dt = sc.parse_utc(last_seen_at)
            if last_seen_dt is not None:
                seconds_since_seen = (now - last_seen_dt).total_seconds()
                status = STATUS_ONLINE if seconds_since_seen <= ONLINE_THRESHOLD_SECONDS else STATUS_OFFLINE

        window_start = sc.format_utc(now - timedelta(minutes=HEALTH_WINDOW_MINUTES))
        window_end = sc.format_utc(now)

        recent = sd.query_detections(
            window_start, window_end, sensor_id=sensor_id, limit=sd.MAX_QUERY_LIMIT
        )

        counts = _classification_counts(recent)
        security_count = counts[suricata_classification.CLASS_SECURITY_ALERT]
        diagnostic_count = counts[suricata_classification.CLASS_ENGINE_DIAGNOSTIC]
        protocol_count = counts[suricata_classification.CLASS_PROTOCOL_EVENT]
        total_count = len(recent)

        last_security_alert_at = None
        for row in recent:
            classification, _explanation = suricata_classification.classify_detection_row(row)
            if classification == suricata_classification.CLASS_SECURITY_ALERT:
                last_security_alert_at = row["observed_at"]
                break  # recent is ORDER BY observed_at DESC - first match is latest

        return {
            "sensor_id": sensor_id,
            "status": status,
            "last_seen_at": last_seen_at,
            "seconds_since_last_seen": seconds_since_seen,
            "last_event_at": recent[0]["observed_at"] if recent else None,
            "last_security_alert_at": last_security_alert_at,
            "window_minutes": HEALTH_WINDOW_MINUTES,
            "events_per_min": round(total_count / HEALTH_WINDOW_MINUTES, 2),
            "security_alerts_per_min": round(security_count / HEALTH_WINDOW_MINUTES, 2),
            "protocol_events_per_min": round(protocol_count / HEALTH_WINDOW_MINUTES, 2),
            "diagnostics_per_min": round(diagnostic_count / HEALTH_WINDOW_MINUTES, 2),
            "security_alert_count": security_count,
            "protocol_event_count": protocol_count,
            "diagnostic_count": diagnostic_count,
            "total_count": total_count,
            # Not available today - see module header. Never fabricated.
            "kernel_packets": None,
            "kernel_drops": None,
            "capture_errors": None,
            "packets_note": "unavailable - requires the stats-forwarding extension (designed, not implemented in Stage 25E)",
        }

    except Exception as exc:
        return {"sensor_id": sensor_id, "status": STATUS_UNKNOWN, "reason": f"HEALTH_COMPUTATION_ERROR: {type(exc).__name__}"}


def all_sensor_health(now=None):
    """Health for every registered sensor whose source_engine is
    'suricata' - the data source for a future Sensor Health panel."""

    sensors = [s for s in security_sensors.list_sensors() if s.get("source_engine") == "suricata"]

    return [compute_sensor_health(s["sensor_id"], now=now) for s in sensors]
