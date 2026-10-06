# ==================================================
# PHASE 13B: SENSOR REGISTRY + PER-SENSOR CREDENTIALS
# ==================================================
#
# A SENSOR is an external telemetry/detection producer (a Suricata host, a
# Zeek host, a Wazuh connector ...). sensor_id is an IDENTITY, not a
# credential. Authentication is a separate, high-entropy secret:
#
#   secret    = "ssk_" + secrets.token_urlsafe(32)            (256-bit random)
#   verifier  = HMAC-SHA256(key = SENSOR_CREDENTIAL_PEPPER,
#                           msg = LABEL + sensor_id + NUL + secret)
#
# Only the verifier is stored (security_sensors.secret_hash). The PEPPER lives
# only in the environment (.env), never in cybersec.db, so a copy of the
# database alone can neither authenticate a sensor nor be used to test guessed
# secrets. The verifier is bound to the sensor id and a fixed domain-
# separation label, so a copied row cannot be replayed onto another sensor.
# No slow KDF: the secret is 256-bit random (the pepper, not a work factor,
# is what makes a DB-only leak useless) and a KDF would add ~50-100 ms to
# every machine request.
#
# FAIL CLOSED: if the pepper is missing, too short, a placeholder, low
# diversity, or equal to / containing / contained in any other application
# secret, credential creation, rotation and authentication all refuse.
#
# BACKUP / RECOVERY: the pepper is deliberately NOT in database backups.
# Losing (or changing) it makes every stored verifier unverifiable: restore
# the pepper from the operator's secret store, or rotate every sensor secret.
# Never put the pepper in the same backup as the database.

import hashlib
import hmac
import os
import re
import secrets
import threading
import time

import db_config
import security_contract as sc
import security_detections

CREDENTIAL_SCHEME = "hmac-sha256-v1"
PEPPER_ENV = "SENSOR_CREDENTIAL_PEPPER"
SECRET_PREFIX = "ssk_"

_LABEL = b"soc-sensor-credential-v1\x00"
_MIN_PEPPER_LENGTH = 32
_MIN_PEPPER_DISTINCT_CHARS = 12
_PLACEHOLDERS = ("change_me", "changeme", "replace_me", "your_secret_here", "example", "secret", "pepper")

# Other application secrets the pepper must never equal or derive from.
_OTHER_SECRET_ENV_NAMES = (
    "FLASK_SECRET_KEY",
    "AGENT_API_KEY",
    "VT_API_KEY",
    "ABUSEIPDB_API_KEY",
    "THREATFOX_API_KEY",
    "URLHAUS_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "UMBRELLA_INVESTIGATE_API_TOKEN",
    "INITIAL_ADMIN_PASSWORD",
)

# A verifier that can never match (revoked sensors) and a constant used to
# equalize timing for unknown sensor ids.
_REVOKED_MARKER = "REVOKED"
_DUMMY_VERIFIER = "0" * 64

_MAX_PRESENTED_SECRET = 200
_LAST_SEEN_MIN_INTERVAL_SECONDS = 30.0


class CredentialConfigError(Exception):

    # The pepper is unavailable/unsafe. Carries ONLY a fixed reason code -
    # never any secret or pepper material.
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SensorError(Exception):

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# --------------------------------------------------
# PEPPER
# --------------------------------------------------

def load_pepper():

    # Returns the pepper as bytes, or raises CredentialConfigError(code).
    # Read from the environment on every call (no caching): a value changed
    # in .env + restart takes effect, and tests can vary it. The value is
    # never logged, rendered or included in an exception message.
    value = os.environ.get(PEPPER_ENV, "")

    if not value or not value.strip():
        raise CredentialConfigError("PEPPER_NOT_CONFIGURED")

    value = value.strip()

    if len(value) < _MIN_PEPPER_LENGTH:
        raise CredentialConfigError("PEPPER_TOO_SHORT")

    lowered = value.lower()

    if any(p in lowered for p in _PLACEHOLDERS) or len(set(value)) < _MIN_PEPPER_DISTINCT_CHARS:
        raise CredentialConfigError("PEPPER_WEAK_OR_PLACEHOLDER")

    for name in _OTHER_SECRET_ENV_NAMES:

        other = os.environ.get(name, "").strip()

        if not other:
            continue

        if value == other or (len(other) >= 8 and (other in value or value in other)):
            raise CredentialConfigError("PEPPER_REUSES_OTHER_SECRET")

    return value.encode("utf-8")


def credentials_available():

    try:
        load_pepper()
        return True
    except CredentialConfigError:
        return False


def config_error_code():

    try:
        load_pepper()
        return None
    except CredentialConfigError as exc:
        return exc.code


def compute_verifier(sensor_id, secret, pepper=None):

    pepper = pepper if pepper is not None else load_pepper()

    message = _LABEL + sensor_id.encode("utf-8") + b"\x00" + secret.encode("utf-8")

    return hmac.new(pepper, message, hashlib.sha256).hexdigest()


def new_secret():

    return SECRET_PREFIX + secrets.token_urlsafe(32)


# --------------------------------------------------
# SCHEMA (main DB; additive, idempotent)
# --------------------------------------------------

_SENSORS_DDL = """
    CREATE TABLE IF NOT EXISTS security_sensors (
        sensor_id TEXT PRIMARY KEY,
        sensor_name TEXT NOT NULL,
        source_engine TEXT NOT NULL,
        description TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        secret_hash TEXT NOT NULL,
        credential_scheme TEXT NOT NULL DEFAULT 'hmac-sha256-v1',
        secret_created_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        created_by TEXT,
        last_seen_at TEXT,
        revoked_at TEXT
    )
"""


def init_security_data_db():

    # Additive only: CREATE ... IF NOT EXISTS. Touches no existing table.
    conn = security_detections.get_db_connection()

    def run():

        conn.execute("BEGIN IMMEDIATE")

        try:
            conn.execute(_SENSORS_DDL)

            for statement in security_detections.DETECTIONS_DDL:
                conn.execute(statement)

            conn.commit()

        except BaseException:
            conn.rollback()
            raise

    try:
        db_config.retry_on_lock(run, label="init_security_data_db")
    finally:
        conn.close()


# --------------------------------------------------
# REGISTRY OPERATIONS
# --------------------------------------------------

_PUBLIC_COLUMNS = (
    "sensor_id, sensor_name, source_engine, description, enabled, "
    "credential_scheme, secret_created_at, created_at, created_by, "
    "last_seen_at, revoked_at"
)


def _validate_name(sensor_name, description):

    if (not isinstance(sensor_name, str) or not sensor_name.strip()
            or len(sensor_name) > 80 or re.search(r"[\x00-\x1f\x7f]", sensor_name)):
        raise SensorError("BAD_SENSOR_NAME")

    if description is not None and (
            not isinstance(description, str) or len(description) > 500
            or re.search(r"[\x00-\x1f\x7f]", description)):
        raise SensorError("BAD_DESCRIPTION")


def create_sensor(sensor_id, sensor_name, source_engine, description=None,
                  created_by=None, now=None):

    # Returns (public_row_dict, plaintext_secret). The secret is returned ONCE
    # to the caller (the admin CLI) and is never retrievable afterwards.
    pepper = load_pepper()

    if not isinstance(sensor_id, str) or not sc.SENSOR_ID_RE.match(sensor_id):
        raise SensorError("BAD_SENSOR_ID")

    spec = sc.engine_spec(source_engine)

    if spec is None:
        raise SensorError("UNKNOWN_ENGINE")

    if not spec.ingestible_via_sensor:
        raise SensorError("ENGINE_NOT_INGESTIBLE")

    _validate_name(sensor_name, description)

    secret = new_secret()
    stamp = sc.utc_now_iso(now)

    conn = security_detections.get_db_connection()

    try:
        conn.execute("BEGIN IMMEDIATE")

        try:

            cursor = conn.execute("""
                INSERT INTO security_sensors (
                    sensor_id, sensor_name, source_engine, description, enabled,
                    secret_hash, credential_scheme, secret_created_at,
                    created_at, created_by
                )
                VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                ON CONFLICT (sensor_id) DO NOTHING
            """, (
                sensor_id, sensor_name.strip(), source_engine, description,
                compute_verifier(sensor_id, secret, pepper), CREDENTIAL_SCHEME,
                stamp, stamp, (created_by or None)
            ))

            if cursor.rowcount != 1:
                conn.rollback()
                raise SensorError("SENSOR_EXISTS")

            conn.commit()

        except BaseException:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

        row = conn.execute(
            f"SELECT {_PUBLIC_COLUMNS} FROM security_sensors WHERE sensor_id = ?",
            (sensor_id,)
        ).fetchone()

        return dict(row), secret

    finally:
        conn.close()


def _get_row(conn, sensor_id):

    if not isinstance(sensor_id, str) or not sc.SENSOR_ID_RE.match(sensor_id):
        return None

    return conn.execute(
        "SELECT sensor_id, sensor_name, source_engine, enabled, secret_hash, "
        "credential_scheme, revoked_at FROM security_sensors WHERE sensor_id = ?",
        (sensor_id,)
    ).fetchone()


def authenticate(sensor_id, presented_secret):

    # Returns SensorIdentity on success, None on ANY failure (unknown sensor,
    # disabled, revoked, wrong secret, malformed input): callers cannot tell
    # these apart, so a caller cannot enumerate sensors. Raises
    # CredentialConfigError when verification is unavailable (fail closed).
    pepper = load_pepper()

    if (not isinstance(sensor_id, str) or not isinstance(presented_secret, str)
            or not presented_secret or len(presented_secret) > _MAX_PRESENTED_SECRET
            or not presented_secret.isascii()):
        # Still spend one verification so timing does not reveal malformed input.
        compute_verifier("unknown", "x", pepper)
        return None

    conn = security_detections.get_db_connection()

    try:
        row = _get_row(conn, sensor_id)
    finally:
        conn.close()

    if row is None:
        candidate = compute_verifier("unknown", presented_secret, pepper)
        hmac.compare_digest(candidate, _DUMMY_VERIFIER)
        return None

    candidate = compute_verifier(row["sensor_id"], presented_secret, pepper)
    stored = row["secret_hash"] or ""

    matches = hmac.compare_digest(candidate.encode("ascii"), stored.encode("ascii", "replace"))

    if (not matches or not row["enabled"] or row["revoked_at"]
            or row["credential_scheme"] != CREDENTIAL_SCHEME):
        return None

    return sc.SensorIdentity(
        sensor_id=row["sensor_id"],
        source_engine=row["source_engine"],
        sensor_name=row["sensor_name"],
    )


def rotate_secret(sensor_id, now=None):

    # New secret replaces the verifier; the old secret stops working at once.
    # A revoked sensor can never be rotated back to life.
    pepper = load_pepper()

    conn = security_detections.get_db_connection()

    try:
        row = _get_row(conn, sensor_id)

        if row is None:
            raise SensorError("UNKNOWN_SENSOR")

        if row["revoked_at"]:
            raise SensorError("SENSOR_REVOKED")

        secret = new_secret()

        conn.execute("BEGIN IMMEDIATE")

        try:
            conn.execute("""
                UPDATE security_sensors
                SET secret_hash = ?, credential_scheme = ?, secret_created_at = ?
                WHERE sensor_id = ? AND revoked_at IS NULL
            """, (
                compute_verifier(sensor_id, secret, pepper), CREDENTIAL_SCHEME,
                sc.utc_now_iso(now), sensor_id
            ))
            conn.commit()

        except BaseException:
            conn.rollback()
            raise

        return secret

    finally:
        conn.close()


def set_enabled(sensor_id, enabled):

    conn = security_detections.get_db_connection()

    try:
        row = _get_row(conn, sensor_id)

        if row is None:
            raise SensorError("UNKNOWN_SENSOR")

        if row["revoked_at"]:
            raise SensorError("SENSOR_REVOKED")

        conn.execute("BEGIN IMMEDIATE")

        try:
            conn.execute(
                "UPDATE security_sensors SET enabled = ? WHERE sensor_id = ?",
                (1 if enabled else 0, sensor_id)
            )
            conn.commit()

        except BaseException:
            conn.rollback()
            raise

    finally:
        conn.close()


def revoke_sensor(sensor_id, now=None):

    # Permanent. The verifier is replaced by a marker that can never match.
    conn = security_detections.get_db_connection()

    try:
        row = _get_row(conn, sensor_id)

        if row is None:
            raise SensorError("UNKNOWN_SENSOR")

        conn.execute("BEGIN IMMEDIATE")

        try:
            conn.execute("""
                UPDATE security_sensors
                SET enabled = 0, secret_hash = ?, revoked_at = COALESCE(revoked_at, ?)
                WHERE sensor_id = ?
            """, (_REVOKED_MARKER, sc.utc_now_iso(now), sensor_id))
            conn.commit()

        except BaseException:
            conn.rollback()
            raise

    finally:
        conn.close()


def list_sensors(conn=None):

    # Public columns only - the verifier is never returned.
    own = conn is None

    if own:
        conn = security_detections.get_db_connection()

    try:
        return [dict(r) for r in conn.execute(
            f"SELECT {_PUBLIC_COLUMNS} FROM security_sensors ORDER BY sensor_id LIMIT 500"
        ).fetchall()]
    finally:
        if own:
            conn.close()


# --------------------------------------------------
# LAST DATA RECEIVED
# --------------------------------------------------

_last_touch = {}
_last_touch_lock = threading.Lock()


def touch_last_seen(sensor_id, now=None, min_interval=_LAST_SEEN_MIN_INTERVAL_SECONDS,
                    monotonic=time.monotonic):

    # Records "last data received" ONLY after successful authenticated
    # ingestion. It is informational (never proof of sensor health) and never
    # turns a successful ingestion into an error. Throttled per sensor to
    # keep a main-DB write off the hot path.
    with _last_touch_lock:

        previous = _last_touch.get(sensor_id)
        current = monotonic()

        if previous is not None and (current - previous) < min_interval:
            return False

        if len(_last_touch) > 1024:
            _last_touch.clear()

        _last_touch[sensor_id] = current

    conn = None

    try:
        conn = security_detections.get_db_connection()

        def run():
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "UPDATE security_sensors SET last_seen_at = ? WHERE sensor_id = ?",
                    (sc.utc_now_iso(now), sensor_id)
                )
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

        db_config.retry_on_lock(run, label="sensor_last_seen", attempts=2, base_delay=0.2)

        return True

    except Exception:

        with _last_touch_lock:
            _last_touch.pop(sensor_id, None)

        return False

    finally:
        if conn is not None:
            conn.close()
