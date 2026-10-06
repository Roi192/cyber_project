# ==================================================
# PHASE 12B.6D: STABLE ENDPOINT IDENTITY + ALERT-EVENT RELATIONSHIP DEFINITIONS
# ==================================================
#
# ENDPOINT UID
#   A random UUIDv4 generated ONCE by a managed endpoint agent installation
#   and persisted in the agent's local state file. It identifies an agent
#   INSTALLATION. It is:
#     * not derived from the IP address or the hostname,
#     * not a secret and not an authentication credential - requests are
#       still authenticated ONLY by X-Agent-Key (see web_monitoring
#       _agent_auth_error); a request carrying a valid UID but no/incorrect
#       key is rejected exactly as before,
#     * not cryptographically authenticated identity: anything holding the
#       shared agent key can claim any UID. It is a stable LABEL that lets
#       the platform stop treating an IP address as a device.
#   The server validates the format and treats it as identity metadata. A
#   malformed value is stored as NULL (same tolerant handling as the other
#   optional telemetry fields), never as an identity.
#
# ALERT <-> EVENT RELATIONSHIPS
#   alert_events records EVERY web event explicitly associated with an alert.
#   security_alerts.source_event_id is kept only as the LATEST/REFERENCE event
#   (12B.6A); it is never an origin.

import re

# Canonical UUIDv4 (lowercase, hyphenated). Version nibble 4, RFC 4122 variant.
_UID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def normalize_endpoint_uid(value):

    # Returns the canonical lowercase UUIDv4 string, or None if `value` is
    # not a well-formed UUIDv4. Never raises; never accepts non-strings.
    if not isinstance(value, str):
        return None

    candidate = value.strip().lower()

    return candidate if _UID_PATTERN.match(candidate) else None


# ---- bounded relationship vocabulary (no free text) ----
REL_CREATED_FROM = "CREATED_FROM"
REL_DEDUP_REFRESH = "DEDUP_REFRESH"
REL_LEGACY_LATEST_REFERENCE = "LEGACY_LATEST_REFERENCE"
REL_LEGACY_TEXT_ASSOCIATION = "LEGACY_TEXT_ASSOCIATION"

RELATIONSHIP_TYPES = (
    REL_CREATED_FROM,
    REL_DEDUP_REFRESH,
    REL_LEGACY_LATEST_REFERENCE,
    REL_LEGACY_TEXT_ASSOCIATION,
)

# Strict, anchored patterns for the text the worker itself wrote into
# web_events.details BEFORE alert_events existed (web_event_worker.py). Used
# ONLY by the one-time historical backfill; never at request time.
LEGACY_ALERT_TEXT_PATTERNS = (
    re.compile(r"Security Alert #(\d{1,12}) created"),
    re.compile(r"existing Security Alert #(\d{1,12}) \(dedup window\)"),
)
