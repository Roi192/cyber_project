# ==================================================
# PHASE 14B: PER-RECORD ENDPOINT RESOLUTION POLICY (server side)
# ==================================================
#
# A network sensor (Suricata, later others) reports IP addresses and a time; it
# does not know which managed endpoint held an address. The Phase 13C resolver
# answers that from timestamped IP history. THIS module decides, per record,
# WHICH side of the flow may be an internal managed endpoint - using an explicit
# operator setting - and applies the resolver honestly:
#
#   MONITORED_NETWORKS (alias: SECURITY_MONITORED_NETWORKS) = comma-separated CIDRs
#   of the NETWORKS this platform monitors (not individual endpoint IPs).
#   UNSET / EMPTY = resolution DISABLED: every record stays NOT_ATTEMPTED.
#   ANY malformed entry (or a /0-style catch-all) rejects the WHOLE setting: resolution
#   stays disabled and an error is logged - never "all networks".
#
#   src internal, dst external  -> src is the endpoint candidate
#   src external, dst internal  -> dst is the endpoint candidate
#   src internal, dst internal  -> BOTH sides are resolved and reported
#                                  separately; the single endpoint_uid slot stays
#                                  EMPTY (never silently choose one side)
#   src external, dst external  -> no resolution
#
# Result handling (13C rules, unchanged):
#   EXACT                       -> endpoint_uid attached, endpoint_resolution=EXACT
#   AMBIGUOUS / STALE / UNKNOWN -> status stored, NO endpoint_uid
#   SENSOR_ASSERTED             -> never upgraded, never touched
# Resolution uses the record's OWN observed_at (a late replay honestly degrades
# to STALE/UNKNOWN). It never creates alerts, incidents, detections or responses.
#
# The outcome is also written to server-owned metadata under the RESERVED key
# "platform" (a sensor cannot send that key - security_contract rejects it):
#   platform.endpoint_context = {"policy": "...", "side"|"src"/"dst": {...}}
# Only status strings and (for EXACT) the stable UUID are stored - never a
# hostname, username or process.

import ipaddress
import json
import os

from dataclasses import replace

import security_contract as sc

POLICY_VERSION = "monitored-networks-v1"

# Server-added metadata may exceed the sensor limit by this much (bounded).
_SERVER_METADATA_ALLOWANCE = 1024


NETWORKS_ENV = "MONITORED_NETWORKS"
LEGACY_NETWORKS_ENV = "SECURITY_MONITORED_NETWORKS"

MAX_NETWORK_ENTRIES = 64
MIN_PREFIX_V4 = 8       # broader than this is refused: it would mean "monitor everything"
MIN_PREFIX_V6 = 16

ERR_INVALID = "MONITORED_NETWORKS_INVALID"


def load_config(raw):

    # Returns (networks, error_code). FAIL CLOSED: if ANY entry is malformed (or
    # absurdly broad such as 0.0.0.0/0) the WHOLE setting is rejected - resolution is
    # disabled - it is never widened to "all networks" and never silently narrowed
    # to the entries that happened to parse. Empty / unset is not an error: it
    # simply means resolution is disabled.
    if raw is None or not str(raw).strip():
        return (), None

    parts = [p.strip() for p in str(raw).split(",")]
    parts = [p for p in parts if p]

    if not parts or len(parts) > MAX_NETWORK_ENTRIES:
        return (), ERR_INVALID

    networks = []

    for part in parts:

        if len(part) > 64:
            return (), ERR_INVALID

        try:
            network = ipaddress.ip_network(part, strict=False)
        except ValueError:
            return (), ERR_INVALID

        minimum = MIN_PREFIX_V4 if network.version == 4 else MIN_PREFIX_V6

        if network.prefixlen < minimum:
            return (), ERR_INVALID

        networks.append(network)

    return tuple(networks), None


def parse_networks(raw):

    return load_config(raw)[0]


def _env_setting():

    # MONITORED_NETWORKS is the documented name; SECURITY_MONITORED_NETWORKS is
    # accepted as an alias. The documented name wins when both are set.
    for name in (NETWORKS_ENV, LEGACY_NETWORKS_ENV):

        value = os.getenv(name, "")

        if value.strip():
            return name, value

    return None, ""


def config_from_env():

    name, value = _env_setting()
    networks, error = load_config(value)

    return networks, error


def monitored_networks():

    return config_from_env()[0]


def config_status():

    # For the admin page / diagnostics: never raises.
    name, value = _env_setting()
    networks, error = load_config(value)

    return {
        "source": name,
        "configured": bool(networks),
        "error": error,
        "networks": [str(n) for n in networks],
    }


def classify(ip_text, networks):

    # "internal" | "external" | None (no/invalid address).
    if not ip_text:
        return None

    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return None

    return "internal" if any(ip in n for n in networks if n.version == ip.version) else "external"


def _resolve(ip, observed_at, conn, now, cache):

    import endpoint_network as en

    key = (ip, observed_at)

    if key in cache:
        return cache[key]

    try:
        result = en.resolve_endpoint(ip, observed_at, conn=conn, now=now)
        outcome = {"status": result["status"],
                   "uid": result["endpoint_uid"] if result["status"] == en.RES_EXACT else None}
    except Exception:
        # A resolver problem (bad time, DB error) never rejects or alters the record.
        outcome = None

    cache[key] = outcome

    return outcome


def _with_context(record, context):

    # Adds the server-owned "platform" metadata (bounded). Returns the record
    # unchanged if the result would exceed the bound.
    try:
        metadata = json.loads(record.metadata_json) if record.metadata_json else {}
    except ValueError:
        return record

    metadata["platform"] = {"endpoint_context": context}

    encoded = json.dumps(metadata, separators=(",", ":"), sort_keys=True, allow_nan=False)

    if len(encoded.encode("utf-8")) > sc.MAX_METADATA_BYTES + _SERVER_METADATA_ALLOWANCE:
        return record

    return replace(record, metadata_json=encoded)


def apply_policy(record, networks, now, conn, cache=None):

    # Returns the (possibly new) record. Pure apart from the read-only resolver.
    if not networks or record.source_type != sc.SOURCE_NETWORK:
        return record

    if record.endpoint_resolution == sc.RESOLUTION_SENSOR_ASSERTED:
        return record

    cache = cache if cache is not None else {}

    src_side = classify(record.src_ip, networks)
    dst_side = classify(record.dst_ip, networks)

    src_internal = src_side == "internal"
    dst_internal = dst_side == "internal"

    if not src_internal and not dst_internal:
        return record

    if src_internal and dst_internal:

        context = {"policy": POLICY_VERSION, "side": "both"}

        for label, ip in (("src", record.src_ip), ("dst", record.dst_ip)):

            outcome = _resolve(ip, record.observed_at, conn, now, cache)

            context[label] = ({"status": "NOT_ATTEMPTED"} if outcome is None
                              else ({"status": outcome["status"], "uid": outcome["uid"]}
                                    if outcome["uid"] else {"status": outcome["status"]}))

        # The single endpoint slot stays EMPTY and NOT_ATTEMPTED on purpose.
        return _with_context(record, context)

    side = "src" if src_internal else "dst"
    ip = record.src_ip if src_internal else record.dst_ip

    outcome = _resolve(ip, record.observed_at, conn, now, cache)

    if outcome is None:
        return record

    record = replace(
        record,
        endpoint_uid=outcome["uid"],
        endpoint_resolution=outcome["status"],
    )

    context = {"policy": POLICY_VERSION, "side": side, "status": outcome["status"]}

    if outcome["uid"]:
        context["uid"] = outcome["uid"]

    return _with_context(record, context)


def apply_policy_to_batch(records, networks, now, conn):

    # records: list of NormalizedRecord. One shared cache per batch.
    cache = {}

    return [apply_policy(r, networks, now, conn, cache) for r in records]
