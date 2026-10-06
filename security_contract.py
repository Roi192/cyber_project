# ==================================================
# PHASE 13B: SECURITY DATA CONTRACT
# ==================================================
#
# The common contract every future external security engine (through an
# adapter) must satisfy before its data enters the platform. This module is
# PURE: no database, no Flask, no network, no filesystem access.
#
# DATA TYPES (kept distinct on purpose - never collapse into one "event"):
#   RAW TELEMETRY  unprocessed source records; stay on the sensor, never stored here
#   OBSERVATION    factual, source-attributed, no judgment          -> telemetry store
#   EVIDENCE       context about an indicator                        -> threat_intel_evidence
#   DETECTION      an engine/rule JUDGMENT, with rule identity       -> security_detections
#   ALERT          a detection promoted to analyst attention by policy (security_alerts)
#   INCIDENT       a correlated security case (security_events)
#   ENRICHMENT     lookup context about an indicator; never a detection by itself
#   RESPONSE       an explicit, audited action (response_commands)
#
# TIME CONTRACT (new Phase-13 records only):
#   Canonical form is ISO-8601 UTC with millisecond precision and a literal Z,
#   e.g. 2026-09-19T14:32:10.123Z.
#     observed_at  - when the SOURCE says the activity occurred
#     ingested_at  - when THIS platform accepted the record (server-stamped)
#   A timestamp without an explicit offset is REJECTED: it is never guessed to
#   be local time or UTC. Legacy platform timestamps (web_events.event_time
#   etc.) are server-local naive text and are NOT rewritten or reinterpreted.

import math
import os
import re
import json
import ipaddress

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import endpoint_identity

# --------------------------------------------------
# DATA TYPE DEFINITIONS (documentation constants)
# --------------------------------------------------

DATA_TYPE_DEFINITIONS = {
    "RAW_TELEMETRY": "Unprocessed source records; remain on the sensor, never stored by the platform.",
    "OBSERVATION": "Factual, source-attributed record of something seen. Carries no judgment.",
    "EVIDENCE": "Context attached to an indicator (owned by threat_intel_evidence); supports a judgment.",
    "DETECTION": "A security engine or rule judged something suspicious; carries rule identity.",
    "ALERT": "A detection promoted to analyst attention by explicit policy.",
    "INCIDENT": "A deliberately correlated security case grouping related alerts, with the reason.",
    "ENRICHMENT": "Lookup output about an indicator; never a detection on its own.",
    "RESPONSE": "An explicit, allowlisted, audited action on a target.",
}

# --------------------------------------------------
# SOURCE TAXONOMY
# --------------------------------------------------

SOURCE_ENDPOINT = "ENDPOINT"
SOURCE_NETWORK = "NETWORK"
SOURCE_HOST_LOG = "HOST_LOG"
SOURCE_ASSET = "ASSET"
SOURCE_THREAT_INTEL = "THREAT_INTEL"
SOURCE_BEHAVIORAL = "BEHAVIORAL"
SOURCE_LOCAL_IOC = "LOCAL_IOC"
SOURCE_MANUAL = "MANUAL"
SOURCE_SYSTEM = "SYSTEM"

# Stable and strictly validated (no DB CHECK: validated here, in code).
SOURCE_TYPES = (
    SOURCE_ENDPOINT,
    SOURCE_NETWORK,
    SOURCE_HOST_LOG,
    SOURCE_ASSET,
    SOURCE_THREAT_INTEL,
    SOURCE_BEHAVIORAL,
    SOURCE_LOCAL_IOC,
    SOURCE_MANUAL,
    SOURCE_SYSTEM,
)

# The ONLY source types an external sensor may claim. Threat intelligence,
# behavioral, local IOC, manual and system data are produced by the platform
# itself and can never be asserted through the sensor endpoint.
SENSOR_SOURCE_TYPES = (
    SOURCE_ENDPOINT,
    SOURCE_NETWORK,
    SOURCE_HOST_LOG,
    SOURCE_ASSET,
)

RECORD_OBSERVATION = "OBSERVATION"
RECORD_DETECTION = "DETECTION"
RECORD_TYPES = (RECORD_OBSERVATION, RECORD_DETECTION)


@dataclass(frozen=True)
class EngineSpec:

    source_types: tuple
    record_types: tuple
    ingestible_via_sensor: bool


_BOTH = (RECORD_OBSERVATION, RECORD_DETECTION)

# source_engine is an EXTENSIBLE registry (see extra_engines()): adding an
# engine never needs a schema migration. Engines are only NAMES here - no
# engine-specific code exists anywhere in the platform yet.
ENGINES = {
    "our_agent": EngineSpec((SOURCE_ENDPOINT,), (RECORD_OBSERVATION,), False),
    "suricata": EngineSpec((SOURCE_NETWORK,), _BOTH, True),
    "zeek": EngineSpec((SOURCE_NETWORK,), _BOTH, True),
    "wazuh": EngineSpec((SOURCE_HOST_LOG, SOURCE_ENDPOINT, SOURCE_ASSET), _BOTH, True),
    "nmap": EngineSpec((SOURCE_ASSET, SOURCE_NETWORK), (RECORD_OBSERVATION,), True),
    "tshark": EngineSpec((SOURCE_NETWORK,), (RECORD_OBSERVATION,), True),
    # Sigma is a detection engine OVER other telemetry.
    "sigma": EngineSpec((SOURCE_HOST_LOG, SOURCE_ENDPOINT, SOURCE_NETWORK), (RECORD_DETECTION,), True),
    "snort": EngineSpec((SOURCE_NETWORK,), _BOTH, True),
    "ossec": EngineSpec((SOURCE_HOST_LOG, SOURCE_ENDPOINT), _BOTH, True),
    "security_onion": EngineSpec((SOURCE_NETWORK, SOURCE_HOST_LOG, SOURCE_ENDPOINT), _BOTH, True),
    # Existing threat-intelligence providers: recognized names, produced by
    # the platform's own workers, never ingestible through a sensor.
    "threatfox": EngineSpec((SOURCE_THREAT_INTEL,), (RECORD_DETECTION,), False),
    "urlhaus": EngineSpec((SOURCE_THREAT_INTEL,), (RECORD_DETECTION,), False),
    "virustotal": EngineSpec((SOURCE_THREAT_INTEL,), (RECORD_DETECTION,), False),
    "abuseipdb": EngineSpec((SOURCE_THREAT_INTEL,), (RECORD_DETECTION,), False),
    "cloudflare": EngineSpec((SOURCE_THREAT_INTEL,), (RECORD_DETECTION,), False),
}

_ENGINE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}\Z")

_EXTRA_ENGINE_SPEC = EngineSpec(
    (SOURCE_NETWORK, SOURCE_HOST_LOG, SOURCE_ENDPOINT, SOURCE_ASSET),
    _BOTH,
    True,
)


def extra_engines():

    # SECURITY_EXTRA_ENGINES="foo,bar": additional engine names an operator
    # can register without a code or schema change. Names are validated;
    # invalid entries are ignored (never raise at request time).
    raw = os.getenv("SECURITY_EXTRA_ENGINES", "")

    names = []

    for part in raw.split(","):
        name = part.strip()
        if name and _ENGINE_NAME_RE.match(name) and name not in ENGINES:
            names.append(name)

    return tuple(names)


def engine_spec(name):

    if not isinstance(name, str):
        return None

    spec = ENGINES.get(name)

    if spec is not None:
        return spec

    return _EXTRA_ENGINE_SPEC if name in extra_engines() else None


def is_known_engine(name):
    return engine_spec(name) is not None


# --------------------------------------------------
# POLICY CONFIGURATION (env, read at call time so tests/operators can vary it)
# --------------------------------------------------

def _env_int(name, default, minimum, maximum):

    try:
        value = int(os.getenv(name, "").strip())
    except ValueError:
        return default

    if value < minimum or value > maximum:
        return default

    return value


def max_past_days():

    # observed_at older than this is REJECTED. It is also the late-arrival
    # window: a telemetry day file is writable only inside it.
    return _env_int("SECURITY_MAX_PAST_DAYS", 7, 1, 90)


def max_future_seconds():

    # Tolerated clock skew for an observed_at slightly ahead of the server.
    return _env_int("SECURITY_MAX_FUTURE_SECONDS", 300, 0, 3600)


def retention_enabled():

    # DESTRUCTIVE retention is OFF unless explicitly enabled.
    return os.getenv("TELEMETRY_RETENTION_ENABLED", "false").strip().lower() in ("1", "true", "yes")


def retention_days():

    configured = _env_int("TELEMETRY_RETENTION_DAYS", 14, 1, 3650)

    # Never shorter than the late-arrival window: a file that can still be
    # written to must not be deletable.
    return max(configured, max_past_days() + 1)


# --------------------------------------------------
# UTC TIME HELPERS
# --------------------------------------------------

_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:\d{2})\Z"
)


def utc_now():
    return datetime.now(timezone.utc)


def format_utc(moment):

    # Canonical, millisecond precision, literal Z. Sub-millisecond digits are
    # truncated (never rounded up into the next second).
    moment = moment.astimezone(timezone.utc)

    return (
        moment.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{moment.microsecond // 1000:03d}Z"
    )


def utc_now_iso(now=None):
    return format_utc(now or utc_now())


def parse_utc(value):

    # Strict ISO-8601 with an EXPLICIT offset -> aware UTC datetime, or None.
    # A naive timestamp is never accepted or guessed.
    if not isinstance(value, str) or len(value) > 40:
        return None

    match = _TS_RE.match(value)

    if match is None:
        return None

    year, month, day, hour, minute, second, fraction, offset = match.groups()

    microsecond = int((fraction or "0").ljust(6, "0")[:6])

    if offset == "Z":
        tzinfo = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        off_h, off_m = int(offset[1:3]), int(offset[4:6])
        if off_h > 23 or off_m > 59:
            return None
        tzinfo = timezone(sign * timedelta(hours=off_h, minutes=off_m))

    try:
        moment = datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second),
            microsecond, tzinfo=tzinfo
        )
    except ValueError:
        return None

    return moment.astimezone(timezone.utc)


def day_key(moment):

    # UTC calendar day used for telemetry files (YYYYMMDD).
    return moment.astimezone(timezone.utc).strftime("%Y%m%d")


# --------------------------------------------------
# VOCABULARIES / PATTERNS
# --------------------------------------------------

PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "esp", "ah", "other")

RESOLUTION_NOT_ATTEMPTED = "NOT_ATTEMPTED"
RESOLUTION_SENSOR_ASSERTED = "SENSOR_ASSERTED"

# EXACT / STALE / AMBIGUOUS / UNKNOWN are reserved for the Phase 13C
# timestamp-aware endpoint resolver. A sensor can never assert them, and
# Phase 13B never resolves an IP address to an endpoint.
RESOLUTION_RESERVED = ("EXACT", "STALE", "AMBIGUOUS", "UNKNOWN")
ENDPOINT_RESOLUTIONS = (RESOLUTION_NOT_ATTEMPTED, RESOLUTION_SENSOR_ASSERTED) + RESOLUTION_RESERVED

SENSOR_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,47}\Z")
_SOURCE_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9._:@/+=-]{1,128}\Z")
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9._:@/+=-]{1,128}\Z")
# Community ID v1: "1:" + base64(SHA-1) = 28 base64 chars ending in "=".
COMMUNITY_ID_RE = re.compile(r"^1:[A-Za-z0-9+/]{27}=\Z")
_INDEPENDENCE_GROUP_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}\Z")
# A raw_ref is a REFERENCE (scheme:opaque), never a path. No slashes,
# backslashes, whitespace or control characters can match.
_RAW_REF_RE = re.compile(r"^[a-z][a-z0-9_]{1,23}:[A-Za-z0-9._:@#=+-]{1,192}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Metadata keys only the platform may write (see security_resolution.py).
RESERVED_METADATA_KEYS = ("platform",)

MAX_RULE_NAME = 256
MAX_RULE_CATEGORY = 64
MAX_SHORT_TEXT = 32
MAX_RAW_REF = 224
MAX_METADATA_BYTES = 4096
MAX_METADATA_DEPTH = 3
MAX_METADATA_KEYS = 32
MAX_METADATA_LIST = 16
MAX_METADATA_KEY_LEN = 64
MAX_METADATA_STRING = 512
MAX_METADATA_NODES = 200

_COMMON_FIELDS = frozenset({
    "record_type", "source_type", "source_engine", "sensor_id",
    "source_event_id", "observed_at", "endpoint_uid",
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "community_id", "raw_ref", "metadata",
})

_DETECTION_ONLY_FIELDS = frozenset({
    "rule_id", "rule_name", "rule_category",
    "source_severity", "source_action", "independence_group",
})

# ingested_at and endpoint_resolution are deliberately NOT accepted from a
# sensor: the platform stamps/derives them.
_ALLOWED_FIELDS = {
    RECORD_OBSERVATION: _COMMON_FIELDS,
    RECORD_DETECTION: _COMMON_FIELDS | _DETECTION_ONLY_FIELDS,
}


# --------------------------------------------------
# MODELS
# --------------------------------------------------

@dataclass(frozen=True)
class SensorIdentity:

    # Produced ONLY by successful sensor authentication. sensor_id is an
    # identity; authentication is the separate secret credential.
    sensor_id: str
    source_engine: str
    sensor_name: str = ""


@dataclass(frozen=True)
class NormalizedRecord:

    record_type: str
    source_type: str
    source_engine: str
    sensor_id: str
    source_event_id: str
    observed_at: str
    ingested_at: str
    endpoint_uid: str = None
    endpoint_resolution: str = RESOLUTION_NOT_ATTEMPTED
    src_ip: str = None
    src_port: int = None
    dst_ip: str = None
    dst_port: int = None
    protocol: str = None
    community_id: str = None
    rule_id: str = None
    rule_name: str = None
    rule_category: str = None
    source_severity: str = None
    source_action: str = None
    independence_group: str = None
    raw_ref: str = None
    metadata_json: str = None

    def observed_day(self):
        return self.observed_at[:10].replace("-", "")


class RecordRejected(Exception):

    # Raised inside normalization; carries ONLY a deterministic reason code
    # (never any part of the offending value).
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# --------------------------------------------------
# FIELD VALIDATORS
# --------------------------------------------------

def _text(value, code, max_length, required=False):

    if value is None:
        if required:
            raise RecordRejected(code)
        return None

    if isinstance(value, bool):
        raise RecordRejected(code)

    if isinstance(value, int):
        value = str(value)

    if not isinstance(value, str):
        raise RecordRejected(code)

    if not value.strip() and required:
        raise RecordRejected(code)

    if len(value) > max_length or _CONTROL_RE.search(value):
        raise RecordRejected(code)

    return value if value.strip() else None


def _ip(value, code):

    if value is None:
        return None

    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise RecordRejected(code)

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise RecordRejected(code)


def _port(value):

    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(value, int):
        raise RecordRejected("BAD_PORT")

    if value < 1 or value > 65535:
        raise RecordRejected("BAD_PORT")

    return value


def _validate_metadata(value):

    # Bounded structured metadata only: never an arbitrary source payload.
    if value is None:
        return None

    if not isinstance(value, dict):
        raise RecordRejected("BAD_METADATA")

    nodes = [0]

    def walk(node, depth):

        nodes[0] += 1

        if nodes[0] > MAX_METADATA_NODES:
            raise RecordRejected("METADATA_TOO_LARGE")

        if isinstance(node, dict):

            if depth > MAX_METADATA_DEPTH:
                raise RecordRejected("METADATA_TOO_DEEP")

            if len(node) > MAX_METADATA_KEYS:
                raise RecordRejected("METADATA_TOO_LARGE")

            for key, item in node.items():

                if (not isinstance(key, str) or not key
                        or len(key) > MAX_METADATA_KEY_LEN
                        or _CONTROL_RE.search(key)):
                    raise RecordRejected("BAD_METADATA")

                walk(item, depth + 1)

        elif isinstance(node, list):

            if depth > MAX_METADATA_DEPTH:
                raise RecordRejected("METADATA_TOO_DEEP")

            if len(node) > MAX_METADATA_LIST:
                raise RecordRejected("METADATA_TOO_LARGE")

            for item in node:
                walk(item, depth + 1)

        elif isinstance(node, str):

            if len(node) > MAX_METADATA_STRING or _CONTROL_RE.search(node):
                raise RecordRejected("BAD_METADATA")

        elif isinstance(node, bool) or node is None:
            pass

        elif isinstance(node, int):

            if abs(node) > 2 ** 53:
                raise RecordRejected("BAD_METADATA")

        elif isinstance(node, float):

            if not math.isfinite(node):
                raise RecordRejected("BAD_METADATA")

        else:
            raise RecordRejected("BAD_METADATA")

    walk(value, 1)

    try:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        raise RecordRejected("BAD_METADATA")

    if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
        raise RecordRejected("METADATA_TOO_LARGE")

    return encoded


def describe_raw_ref(raw_ref):

    # Display helper ONLY: splits "scheme:opaque". A raw_ref is never a
    # filesystem path and nothing in the platform opens it.
    if not isinstance(raw_ref, str) or ":" not in raw_ref:
        return None, None

    scheme, _, opaque = raw_ref.partition(":")

    return scheme, opaque


# --------------------------------------------------
# NORMALIZATION
# --------------------------------------------------

def normalize_record(raw, sensor, now=None):

    # raw: one decoded JSON object from an adapter/sensor.
    # sensor: SensorIdentity from AUTHENTICATION (never taken from the payload).
    # Returns a NormalizedRecord or raises RecordRejected(code). A record is
    # accepted in full or rejected in full - never partially accepted.
    now = now or utc_now()

    if not isinstance(raw, dict):
        raise RecordRejected("BAD_RECORD")

    record_type = raw.get("record_type")

    if not isinstance(record_type, str) or record_type not in RECORD_TYPES:
        raise RecordRejected("BAD_RECORD_TYPE")

    for key in raw:
        if not isinstance(key, str) or key not in _ALLOWED_FIELDS[record_type]:
            raise RecordRejected(
                "FIELD_NOT_ALLOWED_FOR_RECORD_TYPE"
                if key in _DETECTION_ONLY_FIELDS else "UNKNOWN_FIELD"
            )

    # ---- source taxonomy ----
    source_type = raw.get("source_type")

    if not isinstance(source_type, str) or source_type not in SOURCE_TYPES:
        raise RecordRejected("BAD_SOURCE_TYPE")

    if source_type not in SENSOR_SOURCE_TYPES:
        raise RecordRejected("SOURCE_TYPE_NOT_ALLOWED")

    source_engine = raw.get("source_engine")

    spec = engine_spec(source_engine)

    if spec is None:
        raise RecordRejected("UNKNOWN_ENGINE")

    if not spec.ingestible_via_sensor:
        raise RecordRejected("ENGINE_NOT_INGESTIBLE")

    if source_engine != sensor.source_engine:
        raise RecordRejected("ENGINE_MISMATCH")

    if source_type not in spec.source_types:
        raise RecordRejected("SOURCE_TYPE_NOT_ALLOWED")

    if record_type not in spec.record_types:
        raise RecordRejected("RECORD_TYPE_NOT_ALLOWED")

    # ---- sensor identity comes from authentication ----
    if "sensor_id" in raw and raw["sensor_id"] != sensor.sensor_id:
        raise RecordRejected("SENSOR_MISMATCH")

    # ---- identity of the source event ----
    source_event_id = raw.get("source_event_id")

    if (not isinstance(source_event_id, str)
            or not _SOURCE_EVENT_ID_RE.match(source_event_id)):
        raise RecordRejected("BAD_SOURCE_EVENT_ID")

    # ---- time ----
    observed = parse_utc(raw.get("observed_at"))

    if observed is None:
        raise RecordRejected("BAD_TIMESTAMP")

    if observed > now + timedelta(seconds=max_future_seconds()):
        raise RecordRejected("OBSERVED_AT_FUTURE")

    if observed < now - timedelta(days=max_past_days()):
        raise RecordRejected("OBSERVED_AT_TOO_OLD")

    # ---- endpoint identity (validated only; NEVER resolved in 13B) ----
    endpoint_uid = raw.get("endpoint_uid")

    if endpoint_uid is not None:

        endpoint_uid = endpoint_identity.normalize_endpoint_uid(endpoint_uid)

        if endpoint_uid is None:
            raise RecordRejected("BAD_ENDPOINT_UID")

    resolution = (
        RESOLUTION_SENSOR_ASSERTED if endpoint_uid else RESOLUTION_NOT_ATTEMPTED
    )

    # ---- addressing ----
    src_ip = _ip(raw.get("src_ip"), "BAD_IP")
    dst_ip = _ip(raw.get("dst_ip"), "BAD_IP")
    src_port = _port(raw.get("src_port"))
    dst_port = _port(raw.get("dst_port"))

    protocol = raw.get("protocol")

    if protocol is not None:

        if not isinstance(protocol, str) or protocol.strip().lower() not in PROTOCOLS:
            raise RecordRejected("BAD_PROTOCOL")

        protocol = protocol.strip().lower()

    community_id = raw.get("community_id")

    if community_id is not None:

        if not isinstance(community_id, str) or not COMMUNITY_ID_RE.match(community_id):
            raise RecordRejected("BAD_COMMUNITY_ID")

    # ---- provenance ----
    raw_ref = raw.get("raw_ref")

    if raw_ref is not None:

        if (not isinstance(raw_ref, str) or len(raw_ref) > MAX_RAW_REF
                or ".." in raw_ref or not _RAW_REF_RE.match(raw_ref)):
            raise RecordRejected("RAW_REF_INVALID")

    # Phase 14B: "platform" is a RESERVED, server-owned metadata key (endpoint
    # resolution context). A sensor can never supply it, so it can never spoof
    # what the platform concluded.
    if isinstance(raw.get("metadata"), dict) and any(
            key in RESERVED_METADATA_KEYS for key in raw["metadata"]):
        raise RecordRejected("RESERVED_METADATA_KEY")

    metadata_json = _validate_metadata(raw.get("metadata"))

    rule_id = rule_name = rule_category = None
    source_severity = source_action = independence_group = None

    if record_type == RECORD_DETECTION:

        rule_id = raw.get("rule_id")

        if isinstance(rule_id, int) and not isinstance(rule_id, bool) and rule_id >= 0:
            rule_id = str(rule_id)

        if not isinstance(rule_id, str) or not _RULE_ID_RE.match(rule_id):
            raise RecordRejected("BAD_RULE_ID")

        rule_name = _text(raw.get("rule_name"), "BAD_RULE_NAME", MAX_RULE_NAME)
        rule_category = _text(raw.get("rule_category"), "BAD_RULE_CATEGORY", MAX_RULE_CATEGORY)
        source_severity = _text(raw.get("source_severity"), "BAD_SOURCE_SEVERITY", MAX_SHORT_TEXT)
        source_action = _text(raw.get("source_action"), "BAD_SOURCE_ACTION", MAX_SHORT_TEXT)

        independence_group = raw.get("independence_group")

        if independence_group is None:
            # Conservative default: everything from one engine is ONE group;
            # independence is never presumed.
            independence_group = f"engine:{source_engine}"

        elif (not isinstance(independence_group, str)
                or not _INDEPENDENCE_GROUP_RE.match(independence_group)):
            raise RecordRejected("BAD_INDEPENDENCE_GROUP")

    return NormalizedRecord(
        record_type=record_type,
        source_type=source_type,
        source_engine=source_engine,
        sensor_id=sensor.sensor_id,
        source_event_id=source_event_id,
        observed_at=format_utc(observed),
        ingested_at=format_utc(now),
        endpoint_uid=endpoint_uid,
        endpoint_resolution=resolution,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        community_id=community_id,
        rule_id=rule_id,
        rule_name=rule_name,
        rule_category=rule_category,
        source_severity=source_severity,
        source_action=source_action,
        independence_group=independence_group,
        raw_ref=raw_ref,
        metadata_json=metadata_json,
    )


def try_normalize(raw, sensor, now=None):

    # (record, None) or (None, reason_code). Never raises for bad input.
    try:
        return normalize_record(raw, sensor, now), None
    except RecordRejected as exc:
        return None, exc.code
    except (RecursionError, TypeError, ValueError, AttributeError):
        return None, "BAD_RECORD"
