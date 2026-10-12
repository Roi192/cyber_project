"""Device identity, sensor credentials and pairing (Phase 5.5).

A DEVICE is one physical computer. A SENSOR (a row of `endpoints`) is one monitoring installation on it: a Windows agent, a
Chrome extension, an Edge extension. This module is the only place that decides which sensors belong to which device.

Rules that keep it honest:
  * a device or sensor name (the Windows computer name, a browser label) is only a label; it is never used to decide identity
    and two sensors are never merged because their names, UIDs or API keys look alike;
  * a UID is a public identifier. Proof of identity is a per-sensor secret: random, shown once, stored only as a SHA-256 hash.
    Once a sensor has one, every request for that sensor must carry it (X-Sensor-Secret);
  * a browser extension joins an agent's device only with a PAIRING GRANT: random, valid for GRANT_TTL_SECONDS, single use, bound
    to one device and one named sensor, and issued only to an authenticated agent (which in turn asks for it only after the
    owner typed the one-time code the agent printed on that very PC);
  * a secured sensor can only be re-paired by presenting its own secret; a revoked sensor is refused until it is paired again;
  * pairing changes where a sensor's FUTURE events go, never where its past went: the change is recorded as a new association (database triggers close the
    old one and open the new one in the same statement as the current-device update), and every event keeps the device of the time it happened;
  * nothing here ever writes a secret, a grant or a code to the audit table or to a log line.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

import database

GRANT_TTL_SECONDS = 120
MAX_GRANTS_PER_MINUTE = 10
GENERIC_REFUSAL = "invalid or expired pairing grant"
CREDENTIAL_HEADER = "X-Sensor-Secret"


class DeviceError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status
        self.message = message


def new_secret():
    return secrets.token_urlsafe(32)


def hash_secret(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def secret_matches(stored_hash, supplied):
    """Constant-time check of a presented secret against the stored hash."""
    if not stored_hash or not supplied or not isinstance(supplied, str):
        return False
    return hmac.compare_digest(hash_secret(supplied), stored_hash)


def audit(conn, event, device_id=None, sensor_id=None, detail=None):
    """One line in the audit trail. `detail` is a short plain-text reason: callers never pass a secret, grant or code."""
    conn.execute("INSERT INTO device_audit (at, event, device_id, sensor_id, detail) VALUES (?, ?, ?, ?, ?)",
                 (database.now_str(), event, device_id, sensor_id, (detail or "")[:200]))


def _sensor(conn, endpoint_uid):
    return conn.execute("SELECT * FROM endpoints WHERE endpoint_uid = ?", (endpoint_uid,)).fetchone()


def credential_problem(conn, endpoint_uid, supplied):
    """None when this request may act as that sensor; otherwise (http status, message).
    An unpaired sensor (no secret yet) is accepted on the API key alone, exactly as before Phase 5.5."""
    row = _sensor(conn, endpoint_uid)
    if row is None:
        return None
    if row["revoked_at"]:
        return 403, "this sensor was revoked; pair it again"
    if row["secret_hash"] is None:
        return None
    if not secret_matches(row["secret_hash"], supplied):
        return 401, "sensor credential required"
    return None


def enroll_agent(conn, device_uid, sensor_uid, computer_name, agent_version, supplied_secret):
    """The Windows agent announces its device. Creates a VERIFIED device and the agent's own sensor, and returns the sensor secret
    ONCE. Calling it again with the same identifiers is accepted only with that secret (and returns no secret)."""
    device = conn.execute("SELECT * FROM devices WHERE device_uid = ?", (device_uid,)).fetchone()
    sensor = _sensor(conn, sensor_uid)
    now = database.now_str()
    if device is None and sensor is None:
        secret = new_secret()
        cur = conn.execute("INSERT INTO devices (device_uid, display_name, identity, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                           (device_uid, computer_name, database.IDENTITY_VERIFIED, now, now))
        device_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO endpoints (endpoint_uid, computer_name, last_seen, agent_version, agent_seen_at, device_id, sensor_type, "
            "sensor_version, first_seen, secret_hash, paired_at) VALUES (?, ?, ?, ?, ?, ?, 'WINDOWS_AGENT', ?, ?, ?, ?)",
            (sensor_uid, computer_name, now, agent_version, now, device_id, agent_version, now, hash_secret(secret), now))
        audit(conn, "DEVICE_ENROLLED", device_id, cur.lastrowid, "Windows agent %s" % (agent_version or ""))
        conn.commit()
        return {"created": True, "device_id": device_id, "sensor_id": cur.lastrowid, "sensor_secret": secret}
    if (device is not None and sensor is not None and sensor["device_id"] == device["id"] and sensor["sensor_type"] == "WINDOWS_AGENT"
            and device["identity"] == database.IDENTITY_VERIFIED and not sensor["revoked_at"]
            and secret_matches(sensor["secret_hash"], supplied_secret)):
        conn.execute("UPDATE devices SET display_name = ?, last_seen = ? WHERE id = ?", (computer_name, now, device["id"]))
        conn.commit()
        return {"created": False, "device_id": device["id"], "sensor_id": sensor["id"]}
    audit(conn, "ENROLL_REFUSED", device["id"] if device is not None else None, sensor["id"] if sensor is not None else None,
          "identifier already registered and credentials did not match")
    conn.commit()
    raise DeviceError(403, "this device or sensor is already registered")


def issue_grant(conn, agent_uid, target_sensor_uid):
    """An authenticated agent (credential already checked by the caller) asks for permission for ONE extension installation to join
    its device. Returns (token, ttl seconds). Only the hash of the token is stored."""
    agent = _sensor(conn, agent_uid)
    if agent is None or agent["sensor_type"] != "WINDOWS_AGENT" or agent["secret_hash"] is None or agent["revoked_at"]:
        raise DeviceError(403, "only an enrolled Windows agent can issue a pairing grant")
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (agent["device_id"],)).fetchone()
    if device is None or device["identity"] != database.IDENTITY_VERIFIED:
        raise DeviceError(403, "only an enrolled Windows agent can issue a pairing grant")
    since = (datetime.now() - timedelta(seconds=60)).strftime(database.TIME_FORMAT)
    recent = conn.execute("SELECT COUNT(*) FROM pairing_grants WHERE device_id = ? AND created_at >= ?", (device["id"], since)).fetchone()[0]
    if recent >= MAX_GRANTS_PER_MINUTE:
        raise DeviceError(429, "too many pairing requests; wait a minute")
    token = secrets.token_urlsafe(24)
    now = datetime.now()
    conn.execute("INSERT INTO pairing_grants (grant_hash, device_id, sensor_uid, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                 (hash_secret(token), device["id"], target_sensor_uid, now.strftime(database.TIME_FORMAT),
                  (now + timedelta(seconds=GRANT_TTL_SECONDS)).strftime(database.TIME_FORMAT)))
    audit(conn, "GRANT_ISSUED", device["id"], agent["id"], "for sensor %s..." % target_sensor_uid[:8])
    conn.commit()
    return token, GRANT_TTL_SECONDS


def _refuse(conn, reason, device_id=None, sensor_id=None, status=403, message=GENERIC_REFUSAL):
    audit(conn, "PAIR_REFUSED", device_id, sensor_id, reason)
    conn.commit()
    raise DeviceError(status, message)


def pair_sensor(conn, token, sensor_uid, computer_name, browser, username, sensor_version, supplied_secret):
    """An extension installation joins the device the grant was issued for. Returns the new sensor secret (once)."""
    if not isinstance(token, str) or not token:
        _refuse(conn, "no grant presented")
    grant = conn.execute("SELECT * FROM pairing_grants WHERE grant_hash = ?", (hash_secret(token),)).fetchone()
    now = database.now_str()
    if grant is None:
        _refuse(conn, "unknown grant")
    if grant["used_at"] is not None:
        _refuse(conn, "grant already used", grant["device_id"])
    if grant["expires_at"] < now:
        _refuse(conn, "grant expired", grant["device_id"])
    if grant["sensor_uid"] != sensor_uid:
        _refuse(conn, "grant was issued for a different sensor", grant["device_id"])
    sensor = _sensor(conn, sensor_uid)
    if sensor is not None:
        if sensor["secret_hash"] is not None and not sensor["revoked_at"] and not secret_matches(sensor["secret_hash"], supplied_secret):
            # a secured sensor never changes device on a grant alone: the sender must prove it IS that sensor
            _refuse(conn, "secured sensor, credential missing or wrong", grant["device_id"], sensor["id"])
        if sensor["agent_version"] is not None or sensor["sensor_type"] in ("WINDOWS_AGENT", "LEGACY_COMBINED"):
            _refuse(conn, "legacy combined or agent sensor cannot be paired as an extension", grant["device_id"], sensor["id"], 409,
                    "this installation also carries a Windows agent (an older manual link) and cannot be paired automatically")
    consumed = conn.execute("UPDATE pairing_grants SET used_at = ? WHERE id = ? AND used_at IS NULL", (now, grant["id"])).rowcount
    if consumed != 1:                                           # lost a race with another use of the same grant
        conn.rollback()
        _refuse(conn, "grant already used", grant["device_id"])
    secret = new_secret()
    kind = database.sensor_type_for(browser, None)
    previous_device = None
    conn.execute("UPDATE devices SET archived_at = NULL WHERE id = ?", (grant["device_id"],))      # a computer that is joined again is alive: never left hidden
    if sensor is not None:
        previous_device = sensor["device_id"]
        conn.execute("UPDATE endpoints SET device_id = ?, secret_hash = ?, paired_at = ?, revoked_at = NULL, sensor_type = ?, "
                     "computer_name = ?, browser = COALESCE(?, browser), sensor_version = COALESCE(?, sensor_version), "
                     "username = COALESCE(?, username), last_seen = ?, archived_at = NULL WHERE id = ?",
                     (grant["device_id"], hash_secret(secret), now, kind, computer_name, browser, sensor_version, username, now, sensor["id"]))
        sensor_id = sensor["id"]
    else:
        cur = conn.execute(
            "INSERT INTO endpoints (endpoint_uid, computer_name, username, browser, last_seen, device_id, sensor_type, sensor_version, "
            "first_seen, secret_hash, paired_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sensor_uid, computer_name, username, browser, now, grant["device_id"], kind, sensor_version, now, hash_secret(secret), now))
        sensor_id = cur.lastrowid
    audit(conn, "SENSOR_PAIRED", grant["device_id"], sensor_id,
          "%s joined%s" % (kind, "" if previous_device is None else " (moved from device %d)" % previous_device))
    conn.commit()
    device = conn.execute("SELECT display_name FROM devices WHERE id = ?", (grant["device_id"],)).fetchone()
    return {"sensor_secret": secret, "device_id": grant["device_id"], "sensor_id": sensor_id, "device_name": device["display_name"]}


def revoke_sensor(conn, sensor_id):
    """Block a sensor until it is paired again. Its device, visits and history stay exactly as they are."""
    row = conn.execute("SELECT id, device_id, secret_hash FROM endpoints WHERE id = ?", (sensor_id,)).fetchone()
    if row is None or row["secret_hash"] is None:
        return False
    conn.execute("UPDATE endpoints SET revoked_at = ? WHERE id = ?", (database.now_str(), sensor_id))
    audit(conn, "SENSOR_REVOKED", row["device_id"], sensor_id, "revoked by the administrator")
    conn.commit()
    return True
