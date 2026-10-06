#!/usr/bin/env python3
"""Suricata EVE JSON -> SOC adapter (Phase 14B).

Runs on the SENSOR host next to Suricata. It tails Suricata's local eve.json,
normalizes a deliberately small set of event types into the platform's Phase 13B
security contract and posts them to POST /api/security-ingest with a PER-SENSOR
credential. Suricata itself never talks to the SOC. Standard library only.

    python suricata_adapter.py run        # follow EVE forever (systemd service)
    python suricata_adapter.py run --once # process what is there, then exit
    python suricata_adapter.py status     # print the local status file
    python suricata_adapter.py check-config

Scope (14A design, extended Stage 25E): alert -> DETECTION; dns RESPONSES, tls,
bounded flow, http, fileinfo, anomaly, ssh -> OBSERVATION; stats -> local health
only. quic/everything else is still ignored (deferred - the current contract
cannot represent it without expansion). No payload, no packet, no PCAP. http's
URL is forwarded PATH ONLY (query string stripped, same privacy principle as the
browser extension's own redaction) - never headers/cookies/Authorization/Referer.
fileinfo forwards only sha256/md5/filename(basename)/size - never the file's own
bytes, and this adapter never reads an extracted file from disk even if Suricata
itself is configured to store one (file EXTRACTION to disk is out of scope - see
the Stage 25E report's design-only section). This adapter is NOT a correlation
engine and never decides that anything is an alert or an incident.

Secrets: the sensor secret is read from the environment / an env file only. It is
never accepted on the command line, never written to the checkpoint or status
file, and never logged.
"""

import argparse
import collections
import hashlib
import ipaddress
import json
import os
import random
import re
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from datetime import datetime, timedelta, timezone

ADAPTER_VERSION = "14c.1"
ENGINE = "suricata"

# --------------------------------------------------
# LIMITS (mirror the server contract; the server re-validates everything)
# --------------------------------------------------
MAX_LINE_BYTES = 64 * 1024
BATCH_MAX_LINES = 100
BATCH_MAX_BYTES = 256 * 1024
READ_CHUNK = 64 * 1024
MAX_REQUEST_BYTES = 480 * 1024
MAX_PAST_DAYS = 7
HEAD_BYTES = 256

FLOW_MIN_BYTES = 1_000_000          # bounded flow: >= 1 MB ...
FLOW_MIN_AGE_SECONDS = 300          # ... or >= 300 s ... or alerted
MAX_ALERTS_PER_MINUTE = 600

MIN_POST_INTERVAL = 0.06            # <= ~16 requests/s (server allows 20/s)
BACKOFF_BASE = 1.0
BACKOFF_CAP = 60.0
AUTH_BACKOFF = 60.0
POLL_SECONDS = 0.5
EVE_ERROR_POLL_SECONDS = 5.0        # slower polling while the EVE file cannot be opened (already visible in status/log)
HTTP_TIMEOUT = 30

ALLOWED_TYPES = ("alert", "dns", "tls", "flow", "stats", "http", "fileinfo", "anomaly", "ssh")

SENSOR_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,47}\Z")
COMMUNITY_ID_RE = re.compile(r"^1:[A-Za-z0-9+/]{27}=\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})\Z"
)
_SAFE_TOKEN_RE = re.compile(r"[^A-Za-z0-9._:@/+=-]")

PROTOCOLS = {
    "TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "IPV6-ICMP": "icmpv6", "ICMPV6": "icmpv6",
    "SCTP": "sctp", "GRE": "gre", "ESP": "esp", "AH": "ah",
}

RULE_METADATA_KEYS = (
    "signature_severity", "attack_target", "deployment", "mitre_tactic_id", "mitre_tactic_name",
    "mitre_technique_id", "mitre_technique_name", "affected_product", "created_at", "updated_at",
    "confidence", "performance_impact",
)


# ==================================================
# LOGGING (sanitized tokens only; never payloads, URLs or secrets)
# ==================================================

def _clean_token(value, limit=80):

    return _SAFE_TOKEN_RE.sub("", str(value))[:limit] or "?"


def log(event, **fields):

    entry = {"ts": utc_now_iso(), "event": _clean_token(event, 40)}

    for key, value in fields.items():

        if isinstance(value, bool) or value is None:
            entry[key] = value
        elif isinstance(value, (int, float)):
            entry[key] = value
        else:
            entry[key] = _clean_token(value)

    try:
        print(json.dumps(entry, separators=(",", ":")), flush=True)
    except Exception:
        pass


# ==================================================
# TIME / VALUE HELPERS
# ==================================================

def utc_now():
    return datetime.now(timezone.utc)


def fmt_ms(moment):
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def fmt_us(moment):
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def utc_now_iso():
    return fmt_ms(utc_now())


def parse_eve_timestamp(value):

    # EVE uses "2017-04-07T22:24:37.251547+0100" (offset WITHOUT a colon). Returns
    # an aware UTC datetime, or None. A timestamp with no offset is rejected -
    # it is never guessed to be local time or UTC.
    if not isinstance(value, str) or len(value) > 48:
        return None

    match = _TS_RE.match(value)

    if match is None:
        return None

    year, month, day, hour, minute, second, fraction, offset = match.groups()

    microsecond = int((fraction or "0").ljust(6, "0")[:6])

    if offset == "Z":
        tzinfo = timezone.utc
    else:
        digits = offset[1:].replace(":", "")
        off_h, off_m = int(digits[:2]), int(digits[2:])
        if off_h > 23 or off_m > 59:
            return None
        tzinfo = timezone((1 if offset[0] == "+" else -1) * timedelta(hours=off_h, minutes=off_m))

    try:
        moment = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second),
                          microsecond, tzinfo=tzinfo)
    except ValueError:
        return None

    return moment.astimezone(timezone.utc)


def clean_ip(value):

    if not isinstance(value, str) or not value or len(value) > 45 or "%" in value:
        return None

    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped

    return str(parsed)


def clean_port(value):

    if isinstance(value, bool) or not isinstance(value, int):
        return None

    return value if 1 <= value <= 65535 else None


def map_protocol(value):

    if not isinstance(value, str):
        return None

    return PROTOCOLS.get(value.strip().upper(), "other")


def clean_text(value, limit):

    # Attacker-influenced strings (signature names, DNS names, SNI): control
    # characters removed, length bounded with a visible truncation marker.
    if value is None:
        return None

    text = _CONTROL_RE.sub(" ", str(value)).strip()

    if not text:
        return None

    return text if len(text) <= limit else text[: limit - 3] + "..."


def small_int(value):

    if isinstance(value, bool) or not isinstance(value, int):
        return None

    return value if 0 <= value <= 2 ** 53 else None


def stringify_id(value):

    # flow_id / tx_id can be 64-bit integers: sent as strings.
    if isinstance(value, bool) or value is None:
        return None

    if isinstance(value, (int, str)):
        return clean_text(str(value), 40)

    return None


# ==================================================
# IDEMPOTENCY / PROVENANCE
# ==================================================

def source_event_id(sensor_id, kind, fields):

    # EVE has NO native event id (flow_id correlates a flow, tx_id a transaction,
    # neither is globally unique). The id is a deterministic hash over a FIXED,
    # per-type list of stable fields plus the sensor id and the UTC microsecond
    # timestamp: replaying a line gives the same id; distinct records differ.
    blob = json.dumps([sensor_id, kind] + list(fields), separators=(",", ":"),
                      ensure_ascii=True, default=str)

    return f"eve:{kind}:{hashlib.sha256(blob.encode('utf-8')).hexdigest()[:40]}"


def independence_group(gid, sid):

    # Rule LINEAGE (lower-case): not a score, not an engine count.
    try:
        sid = int(sid)
    except (TypeError, ValueError):
        return f"suricata:{_clean_token(gid, 8).lower()}-unknown"

    if 2100000 <= sid <= 2199999:
        return f"snort-gpl:{sid - 2100000}"      # ET-converted GPL/Snort rules

    if 2200000 <= sid <= 2299999:
        # Suricata's OWN decoder / stream / app-layer event rules (e.g. "SURICATA TCPv4 invalid
        # checksum"): engine-native, NOT Emerging Threats lineage.
        return f"suricata:{gid if isinstance(gid, int) else 1}-{sid}"

    if 2000000 <= sid <= 2799999:
        return f"et:{sid}"

    if 1000000 <= sid <= 1999999 or 9000000 <= sid <= 9999999:
        return f"local:{sid}"

    return f"suricata:{gid if isinstance(gid, int) else 1}-{sid}"


def make_raw_ref(sensor_id, file_id, offset):

    # Provenance only - never a path.
    return f"suricata:{sensor_id}:eve:{file_id}:{int(offset)}"


# ==================================================
# NORMALIZATION (EVE event -> contract record)
# ==================================================

class Context:

    def __init__(self, sensor_id, file_id="00000000", now=utc_now, flow_min_bytes=FLOW_MIN_BYTES,
                 flow_min_age=FLOW_MIN_AGE_SECONDS, include_dns_requests=False,
                 max_alerts_per_minute=MAX_ALERTS_PER_MINUTE):
        self.sensor_id = sensor_id
        self.file_id = file_id
        self.now = now
        self.flow_min_bytes = flow_min_bytes
        self.flow_min_age = flow_min_age
        self.include_dns_requests = include_dns_requests
        self._max_alerts = max_alerts_per_minute
        self._alert_buckets = collections.OrderedDict()

    def alert_allowed(self, event_moment):

        # Flood guard measured in EVENT time (the alert's own UTC timestamp), never in
        # wall-clock time: a catch-up read of a large backlog delivers hours of history in
        # seconds and must not be mistaken for a flood (that would silently discard real,
        # already-checkpointed alerts). At most `max_alerts_per_minute` alerts are admitted
        # per event-minute; the excess is skipped and counted. Deterministic: replaying the
        # same file admits and drops exactly the same alerts.
        bucket = int(event_moment.timestamp() // 60)
        used = self._alert_buckets.get(bucket, 0)

        if used >= self._max_alerts:
            return False

        self._alert_buckets[bucket] = used + 1

        while len(self._alert_buckets) > 240:            # bounded memory: keep the newest 240 event-minutes
            self._alert_buckets.popitem(last=False)

        return True


def _base(ev, ctx, offset, record_type, moment):

    record = {
        "record_type": record_type,
        "source_type": "NETWORK",
        "source_engine": ENGINE,
        "observed_at": fmt_ms(moment),
        "raw_ref": make_raw_ref(ctx.sensor_id, ctx.file_id, offset),
    }

    src, dst = clean_ip(ev.get("src_ip")), clean_ip(ev.get("dest_ip"))

    if src:
        record["src_ip"] = src
    if dst:
        record["dst_ip"] = dst

    src_port, dst_port = clean_port(ev.get("src_port")), clean_port(ev.get("dest_port"))

    if src_port:
        record["src_port"] = src_port
    if dst_port:
        record["dst_port"] = dst_port

    protocol = map_protocol(ev.get("proto"))

    if protocol:
        record["protocol"] = protocol

    community = ev.get("community_id")

    # Preserved EXACTLY when present and well-formed; never computed or guessed.
    if isinstance(community, str) and COMMUNITY_ID_RE.match(community):
        record["community_id"] = community

    return record


def _needs_addresses(record):

    return "src_ip" in record or "dst_ip" in record


def _put(metadata, key, value):

    if value is not None and value != "":
        metadata[key] = value


def normalize_alert(ev, ctx, offset):

    alert = ev.get("alert")
    moment = parse_eve_timestamp(ev.get("timestamp"))

    if moment is None:
        return None, "bad_timestamp"

    if not isinstance(alert, dict):
        return None, "bad_alert"

    sid = small_int(alert.get("signature_id"))

    if sid is None:
        return None, "bad_signature_id"

    record = _base(ev, ctx, offset, "DETECTION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    gid, rev = small_int(alert.get("gid")), small_int(alert.get("rev"))
    tx_id = ev.get("tx_id")

    record["source_event_id"] = source_event_id(ctx.sensor_id, "alert", [
        fmt_us(moment), ev.get("flow_id"), ev.get("src_ip"), ev.get("src_port"), ev.get("dest_ip"),
        ev.get("dest_port"), ev.get("proto"), gid, sid, rev, tx_id, ev.get("pcap_cnt"),
    ])

    record["rule_id"] = str(sid)

    name = clean_text(alert.get("signature"), 256)

    if name:
        record["rule_name"] = name

    category = clean_text(alert.get("category"), 64)

    if category:
        record["rule_category"] = category

    severity = small_int(alert.get("severity"))

    if severity is not None:
        record["source_severity"] = str(severity)      # Suricata's own 1-3 scale; never converted

    action = clean_text(alert.get("action"), 32)

    if action:
        record["source_action"] = action

    record["independence_group"] = independence_group(gid if gid is not None else 1, sid)

    metadata = {"eve_type": "alert"}
    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))
    _put(metadata, "tx_id", stringify_id(tx_id))
    _put(metadata, "app_proto", clean_text(ev.get("app_proto"), 32))
    _put(metadata, "in_iface", clean_text(ev.get("in_iface"), 32))
    _put(metadata, "gid", gid)
    _put(metadata, "rev", rev)

    rule_meta = alert.get("metadata")

    if isinstance(rule_meta, dict):

        kept = {}

        for key in RULE_METADATA_KEYS:

            values = rule_meta.get(key)

            if isinstance(values, list):
                cleaned = [clean_text(v, 64) for v in values[:4]]
                cleaned = [v for v in cleaned if v]
                if cleaned:
                    kept[key] = cleaned

        if kept:
            metadata["rule_metadata"] = kept

    # NOTHING else from the alert object is forwarded: no payload, no packet, no
    # http/dns/tls sub-objects (URLs, headers, names are not needed for a detection).
    record["metadata"] = metadata

    return record, None


def _dns_queries(dns):

    queries = []

    raw = dns.get("queries")

    if isinstance(raw, list):                         # v3 layout
        for item in raw[:3]:
            if isinstance(item, dict):
                name = clean_text(item.get("rrname"), 100)
                rtype = clean_text(item.get("rrtype"), 12)
                if name:
                    queries.append(f"{name} {rtype}" if rtype else name)
    else:                                             # v2 layout
        name = clean_text(dns.get("rrname"), 100)
        rtype = clean_text(dns.get("rrtype"), 12)
        if name:
            queries.append(f"{name} {rtype}" if rtype else name)

    return queries


def _dns_answers(dns):

    answers = []

    raw = dns.get("answers")

    if isinstance(raw, list):                         # v3 (and v2 detailed lists)
        for item in raw[:8]:
            if isinstance(item, dict):
                rtype = clean_text(item.get("rrtype"), 12)
                data = clean_text(item.get("rdata"), 100)
                if rtype or data:
                    answers.append(f"{rtype or '?'} {data or ''}".strip())
    elif dns.get("rdata") is not None:                # v2 detailed: one answer per event
        rtype = clean_text(dns.get("rrtype"), 12)
        data = clean_text(dns.get("rdata"), 100)
        if data:
            answers.append(f"{rtype or '?'} {data}")

    grouped = dns.get("grouped")

    if isinstance(grouped, dict):
        for rtype, values in list(grouped.items())[:4]:
            if isinstance(values, list):
                for value in values[:4]:
                    data = clean_text(value, 100)
                    if data and len(answers) < 8:
                        answers.append(f"{clean_text(rtype, 12) or '?'} {data}")

    return answers


def normalize_dns(ev, ctx, offset):

    dns = ev.get("dns")
    moment = parse_eve_timestamp(ev.get("timestamp"))

    if moment is None:
        return None, "bad_timestamp"

    if not isinstance(dns, dict):
        return None, "bad_dns"

    dns_type = dns.get("type")

    if dns_type in ("response", "answer"):
        pass
    elif dns_type in ("request", "query") and ctx.include_dns_requests:
        pass
    else:
        return None, "dns_request_out_of_scope"

    record = _base(ev, ctx, offset, "OBSERVATION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    # Suricata 8 (DNS v3) logs a RESPONSE with the RESPONDER as src_ip. Orientation
    # is normalized so src = the client, dst = the resolver (Community ID is
    # direction independent and is unaffected). v2 "answer" is already client-first.
    swapped = dns_type == "response"

    if swapped:

        for a, b in (("src_ip", "dst_ip"), ("src_port", "dst_port")):

            va, vb = record.pop(a, None), record.pop(b, None)

            if vb is not None:
                record[a] = vb
            if va is not None:
                record[b] = va

    queries = _dns_queries(dns)

    record["source_event_id"] = source_event_id(ctx.sensor_id, "dns", [
        fmt_us(moment), ev.get("flow_id"), ev.get("tx_id"), dns_type, dns.get("id"), queries,
    ])

    metadata = {"eve_type": "dns"}
    _put(metadata, "dns_type", clean_text(dns_type, 12))
    _put(metadata, "dns_id", small_int(dns.get("id")))
    _put(metadata, "dns_rcode", clean_text(dns.get("rcode"), 16))

    if queries:
        metadata["dns_queries"] = queries

    answers = _dns_answers(dns)

    if answers:
        metadata["dns_answers"] = answers

    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))
    _put(metadata, "app_proto", clean_text(ev.get("app_proto"), 32))

    if swapped:
        metadata["oriented"] = "swapped"

    record["metadata"] = metadata

    return record, None


def normalize_tls(ev, ctx, offset):

    tls = ev.get("tls")
    moment = parse_eve_timestamp(ev.get("timestamp"))

    if moment is None:
        return None, "bad_timestamp"

    if not isinstance(tls, dict):
        return None, "bad_tls"

    record = _base(ev, ctx, offset, "OBSERVATION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    sni = clean_text(tls.get("sni"), 253)
    version = clean_text(tls.get("version"), 32)

    record["source_event_id"] = source_event_id(ctx.sensor_id, "tls", [
        fmt_us(moment), ev.get("flow_id"), ev.get("tx_id"), sni, version,
    ])

    ja3 = tls.get("ja3")
    ja3_hash = ja3.get("hash") if isinstance(ja3, dict) else ja3

    metadata = {"eve_type": "tls"}
    _put(metadata, "tls_sni", sni)
    _put(metadata, "tls_version", version)
    _put(metadata, "tls_subject", clean_text(tls.get("subject"), 300))
    _put(metadata, "tls_issuer", clean_text(tls.get("issuerdn"), 300))
    _put(metadata, "tls_ja3", clean_text(ja3_hash, 64))
    _put(metadata, "tls_ja4", clean_text(tls.get("ja4"), 64))
    # Certificate fingerprint (a hash, never the certificate) and negotiated ALPN protocol names.
    _put(metadata, "tls_fingerprint", clean_text(tls.get("fingerprint"), 128))
    # Suricata 8 reports ALPN as tls.client_alpns / tls.server_alpns (lists); older layouts used tls.alpn.
    for key, target in (("client_alpns", "tls_client_alpn"), ("server_alpns", "tls_server_alpn"), ("alpn", "tls_alpn")):

        values = tls.get(key)

        if isinstance(values, str):
            values = [values]

        if isinstance(values, list):
            names = [clean_text(v, 16) for v in values[:4]]
            names = [v for v in names if v]
            if names:
                metadata[target] = names

    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))
    _put(metadata, "app_proto", clean_text(ev.get("app_proto"), 32))

    record["metadata"] = metadata

    return record, None


def normalize_flow(ev, ctx, offset):

    flow = ev.get("flow")
    end = parse_eve_timestamp(ev.get("timestamp"))

    if end is None:
        return None, "bad_timestamp"

    if not isinstance(flow, dict):
        return None, "bad_flow"

    to_server, to_client = small_int(flow.get("bytes_toserver")) or 0, small_int(flow.get("bytes_toclient")) or 0
    age = flow.get("age")
    alerted = flow.get("alerted") is True

    long_lived = isinstance(age, (int, float)) and not isinstance(age, bool) and age >= ctx.flow_min_age

    # BOUNDED flow: only flows that alerted, moved >= 1 MB, or lasted >= 300 s.
    if not (alerted or to_server + to_client >= ctx.flow_min_bytes or long_lived):
        return None, "flow_below_threshold"

    start = parse_eve_timestamp(flow.get("start"))
    horizon = ctx.now() - timedelta(days=MAX_PAST_DAYS) + timedelta(hours=1)

    if start is not None and start >= horizon:
        moment, basis = start, "flow_start"
    else:
        moment, basis = end, "flow_end"

    record = _base(ev, ctx, offset, "OBSERVATION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    record["source_event_id"] = source_event_id(ctx.sensor_id, "flow", [
        fmt_us(end), ev.get("flow_id"), flow.get("start"), ev.get("src_ip"), ev.get("src_port"),
        ev.get("dest_ip"), ev.get("dest_port"), ev.get("proto"),
    ])

    metadata = {"eve_type": "flow", "observed_at_basis": basis, "flow_end": fmt_ms(end)}
    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))
    _put(metadata, "app_proto", clean_text(ev.get("app_proto"), 32))
    _put(metadata, "age", small_int(int(age)) if isinstance(age, (int, float)) and not isinstance(age, bool) else None)
    _put(metadata, "pkts_toserver", small_int(flow.get("pkts_toserver")))
    _put(metadata, "pkts_toclient", small_int(flow.get("pkts_toclient")))
    _put(metadata, "bytes_toserver", to_server)
    _put(metadata, "bytes_toclient", to_client)
    _put(metadata, "state", clean_text(flow.get("state"), 16))
    _put(metadata, "reason", clean_text(flow.get("reason"), 16))
    metadata["alerted"] = alerted

    record["metadata"] = metadata

    return record, None


def _basename_only(value):

    # Defense in depth: fileinfo.filename should already be a bare name,
    # never a path - this strips any path separators that slip through
    # so a filesystem path is never forwarded.
    if not isinstance(value, str):
        return None

    return value.replace("\\", "/").rsplit("/", 1)[-1]


_SHA256_RE = re.compile(r"^[a-f0-9]{64}\Z")
_MD5_RE = re.compile(r"^[a-f0-9]{32}\Z")


def _redact_http_path(url_field):

    # Suricata's http.url field is PATH+QUERY only (no scheme/host,
    # those are in http.hostname separately) per the EVE schema. The
    # query string is stripped here, before anything leaves this
    # process - same privacy principle as the browser extension's own
    # redactUrl() (Stage 24A): path only, flagged when something was
    # actually removed.
    if not isinstance(url_field, str):
        return None, False

    had_query = "?" in url_field

    return url_field.split("?", 1)[0], had_query


def normalize_http(ev, ctx, offset):

    # Stage 25E section 4. Telemetry only (never itself a Detection) -
    # hostname/method/path(redacted)/status/user-agent/protocol/length.
    # NEVER forwarded, even if present in the raw EVE line: request/
    # response headers (could carry Cookie/Authorization), Referer
    # (itself a private URL), request/response body.
    http = ev.get("http")
    moment = parse_eve_timestamp(ev.get("timestamp"))

    if moment is None:
        return None, "bad_timestamp"

    if not isinstance(http, dict):
        return None, "bad_http"

    record = _base(ev, ctx, offset, "OBSERVATION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    hostname = clean_text(http.get("hostname"), 253)
    path_only, had_query = _redact_http_path(http.get("url"))
    path_only = clean_text(path_only, 512)
    method = clean_text(http.get("http_method"), 16)

    record["source_event_id"] = source_event_id(ctx.sensor_id, "http", [
        fmt_us(moment), ev.get("flow_id"), ev.get("tx_id"), hostname, path_only, method,
    ])

    metadata = {"eve_type": "http"}
    _put(metadata, "http_hostname", hostname)
    _put(metadata, "http_path", path_only)
    if path_only is not None:
        metadata["http_path_redacted"] = had_query
    _put(metadata, "http_method", method)
    _put(metadata, "http_status", small_int(http.get("status")))
    _put(metadata, "http_user_agent", clean_text(http.get("http_user_agent"), 256))
    _put(metadata, "http_protocol", clean_text(http.get("protocol"), 16))
    _put(metadata, "http_length", small_int(http.get("length")))
    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))
    _put(metadata, "app_proto", clean_text(ev.get("app_proto"), 32))

    record["metadata"] = metadata

    return record, None


def normalize_fileinfo(ev, ctx, offset):

    # Stage 25E section 7. Hash + bare filename + size ONLY - never the
    # file's own bytes. This adapter never reads an extracted file from
    # disk even if Suricata itself is configured to store one; "stored"
    # below only forwards Suricata's OWN boolean flag about its own
    # (out-of-scope-for-us) extraction config, as telemetry.
    fileinfo = ev.get("fileinfo")
    moment = parse_eve_timestamp(ev.get("timestamp"))

    if moment is None:
        return None, "bad_timestamp"

    if not isinstance(fileinfo, dict):
        return None, "bad_fileinfo"

    record = _base(ev, ctx, offset, "OBSERVATION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    sha256_raw = fileinfo.get("sha256")
    sha256 = sha256_raw.lower() if isinstance(sha256_raw, str) and _SHA256_RE.match(sha256_raw.lower()) else None
    md5_raw = fileinfo.get("md5")
    md5 = md5_raw.lower() if isinstance(md5_raw, str) and _MD5_RE.match(md5_raw.lower()) else None
    size = small_int(fileinfo.get("size"))

    record["source_event_id"] = source_event_id(ctx.sensor_id, "fileinfo", [
        fmt_us(moment), ev.get("flow_id"), ev.get("tx_id"), sha256, md5, size,
    ])

    http_obj = ev.get("http") if isinstance(ev.get("http"), dict) else {}

    metadata = {"eve_type": "fileinfo"}
    _put(metadata, "file_sha256", sha256)
    _put(metadata, "file_md5", md5)
    _put(metadata, "file_size", size)
    _put(metadata, "file_name", clean_text(_basename_only(fileinfo.get("filename")), 128))
    _put(metadata, "file_state", clean_text(fileinfo.get("state"), 16))
    metadata["file_stored"] = fileinfo.get("stored") is True
    _put(metadata, "http_hostname", clean_text(http_obj.get("hostname"), 253))
    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))

    record["metadata"] = metadata

    return record, None


def normalize_anomaly(ev, ctx, offset):

    # Stage 25E section 3. A protocol-layer anomaly Suricata's own
    # parsers noticed - telemetry, never itself a Detection (the
    # Detection Engine never reads anomaly observations as confirmed
    # malicious evidence - see detection_engine.py).
    anomaly = ev.get("anomaly")
    moment = parse_eve_timestamp(ev.get("timestamp"))

    if moment is None:
        return None, "bad_timestamp"

    if not isinstance(anomaly, dict):
        return None, "bad_anomaly"

    record = _base(ev, ctx, offset, "OBSERVATION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    anomaly_type = clean_text(anomaly.get("type"), 32)
    anomaly_event = clean_text(anomaly.get("event"), 64)

    record["source_event_id"] = source_event_id(ctx.sensor_id, "anomaly", [
        fmt_us(moment), ev.get("flow_id"), anomaly_type, anomaly_event,
    ])

    metadata = {"eve_type": "anomaly"}
    _put(metadata, "anomaly_type", anomaly_type)
    _put(metadata, "anomaly_event", anomaly_event)
    _put(metadata, "anomaly_layer", clean_text(anomaly.get("layer"), 32))
    _put(metadata, "app_proto", clean_text(ev.get("app_proto"), 32))
    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))

    record["metadata"] = metadata

    return record, None


def normalize_ssh(ev, ctx, offset):

    # Stage 25E section 3. Client/server software BANNER strings only
    # (e.g. "OpenSSH_9.2") - never session content, never credentials
    # (SSH session content is encrypted and never visible to Suricata
    # at all; nothing here could leak it regardless).
    ssh = ev.get("ssh")
    moment = parse_eve_timestamp(ev.get("timestamp"))

    if moment is None:
        return None, "bad_timestamp"

    if not isinstance(ssh, dict):
        return None, "bad_ssh"

    record = _base(ev, ctx, offset, "OBSERVATION", moment)

    if not _needs_addresses(record):
        return None, "no_addresses"

    client = ssh.get("client") if isinstance(ssh.get("client"), dict) else {}
    server = ssh.get("server") if isinstance(ssh.get("server"), dict) else {}
    client_sw = clean_text(client.get("software_version"), 128)
    server_sw = clean_text(server.get("software_version"), 128)

    record["source_event_id"] = source_event_id(ctx.sensor_id, "ssh", [
        fmt_us(moment), ev.get("flow_id"), client_sw, server_sw,
    ])

    metadata = {"eve_type": "ssh"}
    _put(metadata, "ssh_client_software", client_sw)
    _put(metadata, "ssh_server_software", server_sw)
    _put(metadata, "flow_id", stringify_id(ev.get("flow_id")))

    record["metadata"] = metadata

    return record, None


def parse_stats(ev):

    # Health data only (never an observation): capture counters.
    stats = ev.get("stats")

    if not isinstance(stats, dict):
        return None

    capture = stats.get("capture") if isinstance(stats.get("capture"), dict) else {}

    return {
        "kernel_packets": small_int(capture.get("kernel_packets")),
        "kernel_drops": small_int(capture.get("kernel_drops")),
        "uptime": small_int(stats.get("uptime")),
    }


def _reject_constant(name):
    raise ValueError("non-finite JSON constant")


def process_line(line, offset, ctx):

    # -> (kind, payload): ("record", dict) | ("stats", dict) | ("skipped", reason)
    #                     | ("ignored", type) | ("malformed", reason)
    try:
        event = json.loads(line.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return "malformed", "invalid_json"

    if not isinstance(event, dict):
        return "malformed", "not_an_object"

    event_type = event.get("event_type")

    if not isinstance(event_type, str) or event_type not in ALLOWED_TYPES:
        # Unsupported / deferred types (quic, http, fileinfo, anomaly, ...) are counted by
        # name (sanitized) and dropped; they are never forwarded.
        return "ignored", _clean_token(event_type if isinstance(event_type, str) else "none", 24)

    if event_type == "stats":

        stats = parse_stats(event)

        return ("stats", stats) if stats is not None else ("skipped", "bad_stats")

    if event_type == "alert":

        record, reason = normalize_alert(event, ctx, offset)

        if record is not None and not ctx.alert_allowed(parse_eve_timestamp(event.get("timestamp"))):
            return "skipped", "alert_rate_cap"

    elif event_type == "dns":
        record, reason = normalize_dns(event, ctx, offset)
    elif event_type == "tls":
        record, reason = normalize_tls(event, ctx, offset)
    elif event_type == "http":
        record, reason = normalize_http(event, ctx, offset)
    elif event_type == "fileinfo":
        record, reason = normalize_fileinfo(event, ctx, offset)
    elif event_type == "anomaly":
        record, reason = normalize_anomaly(event, ctx, offset)
    elif event_type == "ssh":
        record, reason = normalize_ssh(event, ctx, offset)
    else:
        record, reason = normalize_flow(event, ctx, offset)

    if record is None:
        return "skipped", reason

    return "record", record


# ==================================================
# CHECKPOINT + STATUS (no secrets; atomic; 0600 where supported)
# ==================================================

def _atomic_write(path, data):

    tmp = path + ".tmp"

    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, separators=(",", ":"))
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass

    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass

    os.replace(tmp, path)


class Checkpoint:

    def __init__(self, state_dir, sensor_id):

        self.dir = state_dir
        self.path = os.path.join(state_dir, "checkpoint.json")
        self.sensor_id = sensor_id
        self.data = self._fresh()

    def _fresh(self):

        return {"version": 1, "sensor_id": self.sensor_id, "identity": None, "file_id": None,
                "offset": 0, "last_source_event_id": None, "last_ingest_ok_at": None}

    def load(self):

        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as exc:
            raise ConfigError(f"the state directory cannot be created or accessed ({type(exc).__name__})")

        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

        if not os.path.exists(self.path):
            return False

        try:

            with open(self.path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)

            ident = loaded.get("identity")

            valid = (
                isinstance(loaded, dict) and loaded.get("version") == 1
                and loaded.get("sensor_id") == self.sensor_id
                and isinstance(loaded.get("offset"), int) and loaded["offset"] >= 0
                and (ident is None or (isinstance(ident, dict)
                                       and all(k in ident for k in ("dev", "ino", "head", "head_len"))))
            )

            if not valid:
                raise ValueError("invalid checkpoint")

            self.data = {**self._fresh(), **{k: loaded.get(k) for k in self._fresh()}}

            return True

        except (OSError, ValueError):

            # Set aside, start fresh: a replay is always safe (server idempotency).
            try:
                os.replace(self.path, self.path + f".corrupt-{int(time.time())}")
            except OSError:
                pass

            log("checkpoint_reset", reason="unreadable_or_mismatched")

            self.data = self._fresh()

            return False

    def probe_writable(self):

        # A start-up probe: the state directory must accept a file (checkpoint + status).
        probe = os.path.join(self.dir, ".write-probe")

        try:
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write("ok")
            os.remove(probe)
        except OSError as exc:
            raise ConfigError(f"the state directory is not writable ({type(exc).__name__})")

    def save(self):

        _atomic_write(self.path, self.data)


# ==================================================
# EVE READER (append-only follower: partial lines, rotation, truncation)
# ==================================================

class Batch:

    def __init__(self, lines, next_state, file_id):
        self.lines = lines              # [(start_offset, bytes)]
        self.next_state = next_state    # state to commit after a successful delivery (or None)
        self.file_id = file_id


class EveReader:

    def __init__(self, path, checkpoint, max_line=MAX_LINE_BYTES, start_at_end=False):

        self.path = path
        self.cp = checkpoint
        self.max_line = max_line
        self.start_at_end = start_at_end
        self.counters = collections.Counter()
        self.open_error = None            # class name of the last open failure, None while readable
        self.last_open_ok_at = None

    def _note_open(self, error):

        # Makes an unreadable EVE file VISIBLE (counter + one log line per state change +
        # status.json) instead of silently idling. `error` is an exception CLASS NAME only.
        if error:

            self.counters["eve_open_errors"] += 1

            if self.open_error != error:
                self.open_error = error
                log("eve_unreadable", error=error)

        else:

            if self.open_error:
                log("eve_readable_again", previous=self.open_error)
                self.open_error = None

            self.last_open_ok_at = fmt_ms(utc_now())

    def _probe(self):

        try:
            with open(self.path, "rb"):
                pass
        except OSError as exc:
            self._note_open(type(exc).__name__)
            return False

        self._note_open(None)

        return True

    # ---- file identity ----
    @staticmethod
    def _stat_identity(path):

        try:
            info = os.stat(path)
        except OSError:
            return None

        return {"dev": info.st_dev, "ino": info.st_ino, "size": info.st_size}

    @staticmethod
    def _head(path, length):

        try:
            with open(path, "rb") as handle:
                return hashlib.sha256(handle.read(length)).hexdigest()[:16]
        except OSError:
            return None

    def _adopt(self, path, size, at_end):

        head_len = min(size, HEAD_BYTES)
        info = self._stat_identity(path)
        head = self._head(path, head_len) if head_len else "empty"

        identity = {"dev": info["dev"], "ino": info["ino"], "head": head, "head_len": head_len}
        file_id = hashlib.sha256(f"{info['dev']}:{info['ino']}:{head}".encode()).hexdigest()[:8]

        return identity, file_id, (size if at_end else 0)

    def _same_file(self, identity, current):

        if identity["dev"] != current["dev"] or identity["ino"] != current["ino"]:
            return False, identity

        head_len = identity["head_len"]

        if current["size"] < head_len:
            return False, identity          # replaced / truncated

        if head_len and self._head(self.path, head_len) != identity["head"]:
            return False, identity          # different content under the same inode

        if head_len < HEAD_BYTES and current["size"] >= HEAD_BYTES:
            # the file has grown past the fingerprint: extend it (stable file_id is kept)
            upgraded = dict(identity)
            upgraded["head_len"] = HEAD_BYTES
            upgraded["head"] = self._head(self.path, HEAD_BYTES)
            return True, upgraded

        return True, identity

    def _find_rotated(self, identity):

        # The previous file after a rename-style rotation (eve.json -> eve.json.1):
        # located by inode identity, never by trusting a path from the data.
        directory = os.path.dirname(self.path) or "."
        base = os.path.basename(self.path)

        try:
            names = sorted(os.listdir(directory))
        except OSError:
            return None

        for name in names:

            if not name.startswith(base) or name == base or name.endswith(".gz"):
                continue

            candidate = os.path.join(directory, name)
            info = self._stat_identity(candidate)

            if info and info["dev"] == identity["dev"] and info["ino"] == identity["ino"]:
                return candidate

        return None

    # ---- reading ----
    def _read_lines(self, path, offset, max_lines, max_bytes, final):

        # Complete lines only. A partial final line is left for the next poll
        # (unless `final`, i.e. the file is closed for writing: it is dropped).
        lines = []
        consumed = offset
        total = 0

        try:
            handle = open(path, "rb")
        except OSError as exc:
            self._note_open(type(exc).__name__)
            return lines, consumed

        with handle:

            handle.seek(offset)
            buffer = b""
            position = offset

            while len(lines) < max_lines and total < max_bytes:

                chunk = handle.read(READ_CHUNK)

                if not chunk:
                    break

                buffer += chunk

                while True:

                    newline = buffer.find(b"\n")

                    if newline < 0:
                        break

                    raw = buffer[:newline]
                    line_start = position
                    position += newline + 1
                    buffer = buffer[newline + 1:]
                    consumed = position

                    if len(raw) > self.max_line:
                        self.counters["oversized"] += 1
                        continue

                    if not raw.strip():
                        continue

                    lines.append((line_start, raw))
                    total += len(raw)

                    if len(lines) >= max_lines or total >= max_bytes:
                        break

                if len(lines) >= max_lines or total >= max_bytes:
                    break

                if len(buffer) > self.max_line:
                    # an over-long line still in progress: drop what we hold and
                    # keep skipping to its newline (memory stays bounded)
                    self.counters["oversized"] += 1
                    position += len(buffer)
                    consumed = position
                    buffer = b""
                    self._skip_to_newline(handle)
                    position = handle.tell()
                    consumed = position
                    buffer = b""

            if final and buffer.strip():
                self.counters["partial_final_dropped"] += 1

        return lines, consumed

    @staticmethod
    def _skip_to_newline(handle):

        while True:

            chunk = handle.read(READ_CHUNK)

            if not chunk:
                return

            newline = chunk.find(b"\n")

            if newline >= 0:
                handle.seek(handle.tell() - (len(chunk) - newline - 1))
                return

    def next_batch(self, max_lines=BATCH_MAX_LINES, max_bytes=BATCH_MAX_BYTES):

        cur = self._stat_identity(self.path)
        state = self.cp.data
        identity, file_id, offset = state["identity"], state["file_id"], state["offset"]

        # A file that exists but cannot be opened must never be adopted or advanced past.
        if cur is not None and not self._probe():
            return Batch([], None, None)

        if identity is None:

            if cur is None:
                return Batch([], None, None)

            identity, file_id, offset = self._adopt(self.path, cur["size"], self.start_at_end)

            if self.start_at_end and offset >= cur["size"]:
                return Batch([], {"identity": identity, "file_id": file_id, "offset": offset}, file_id)

            return self._read_current(identity, file_id, offset, cur, max_lines, max_bytes, adopted=True)

        if cur is not None:

            same, identity = self._same_file(identity, cur)

            if same and cur["size"] >= offset:
                return self._read_current(identity, file_id, offset, cur, max_lines, max_bytes)

            if same and cur["size"] < offset:
                self.counters["truncations"] += 1          # copytruncate-style rotation
                identity, file_id, offset = self._adopt(self.path, cur["size"], False)
                return self._read_current(identity, file_id, 0, cur, max_lines, max_bytes, adopted=True)

        # The file we were following is no longer at `path`: rotated (or replaced).
        old = self._find_rotated(identity)

        if old is not None:

            info = self._stat_identity(old)

            if info and offset < info["size"]:

                lines, consumed = self._read_lines(old, offset, max_lines, max_bytes, final=True)

                drained = consumed >= info["size"] or not lines and consumed == offset

                next_state = {"identity": identity, "file_id": file_id, "offset": consumed}

                if drained or consumed >= info["size"]:

                    self.counters["rotations_followed"] += 1

                    if cur is not None:
                        n_identity, n_file_id, _ = self._adopt(self.path, cur["size"], False)
                        next_state = {"identity": n_identity, "file_id": n_file_id, "offset": 0}

                return Batch(lines, next_state, file_id)

            # old file fully consumed: continue with the new one from its start
            self.counters["rotations_followed"] += 1

        else:
            self.counters["rotated_file_missing"] += 1

        if cur is None:
            return Batch([], None, None)

        n_identity, n_file_id, _ = self._adopt(self.path, cur["size"], False)

        return self._read_current(n_identity, n_file_id, 0, cur, max_lines, max_bytes, adopted=True)

    def _read_current(self, identity, file_id, offset, cur, max_lines, max_bytes, adopted=False):

        lines, consumed = self._read_lines(self.path, offset, max_lines, max_bytes, final=False)

        changed = adopted or consumed != offset or identity != self.cp.data["identity"]

        next_state = ({"identity": identity, "file_id": file_id, "offset": consumed}
                      if changed else None)

        return Batch(lines, next_state, file_id)


# ==================================================
# SOC CLIENT + DELIVERY (backoff, no tight loops, poison-line bisect)
# ==================================================

class ConfigError(Exception):

    # A configuration problem that must stop the adapter with a sanitized message.
    # The message NEVER contains a credential value.
    pass


_CREDENTIAL_CHARS_RE = re.compile(r"^[A-Za-z0-9_-]+\Z")      # "ssk_" + token_urlsafe alphabet
CREDENTIAL_PREFIX = "ssk_"
MAX_CREDENTIAL_LENGTH = 200                                   # the server refuses anything longer
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_HEADER_VALUE = 512
QUOTE_CHARS = "'\"`" + chr(0x2018) + chr(0x2019) + chr(0x201c) + chr(0x201d)      # ASCII and typographic quotes


def credential_properties(value):

    # Properties ONLY (counts / booleans) - never the value or any fragment of it.
    text = value if isinstance(value, str) else ""
    non_ascii = [i for i, ch in enumerate(text) if ord(ch) > 127]

    return {
        "present": bool(text),
        "length": len(text),
        "ascii": not non_ascii,
        "non_ascii_count": len(non_ascii),
        "first_non_ascii_index": non_ascii[0] if non_ascii else None,
        "whitespace_count": sum(1 for ch in text if ch.isspace()),
        "control_count": len(_CONTROL_CHARS_RE.findall(text)),
        "quote_count": sum(1 for ch in text if ch in QUOTE_CHARS),
        "charset_ok": bool(text) and bool(_CREDENTIAL_CHARS_RE.match(text)),
        "prefix_ok": text.startswith(CREDENTIAL_PREFIX),
        "length_ok": 0 < len(text) <= MAX_CREDENTIAL_LENGTH,
    }


def credential_problems(value):

    # Human-readable, value-free reasons why a credential cannot be sent as an HTTP header.
    props = credential_properties(value)

    if not props["present"]:
        return ["SENSOR_KEY is not set (environment or --env-file)"]

    problems = []

    if not props["ascii"]:
        problems.append(
            f"SENSOR_KEY contains {props['non_ascii_count']} non-ASCII character(s) (first at position "
            f"{props['first_non_ascii_index']}); it was probably typed/pasted with a non-English keyboard "
            "layout or copied with surrounding formatting - switch to the English (US) layout and re-enter it")

    if props["whitespace_count"]:
        problems.append(f"SENSOR_KEY contains {props['whitespace_count']} whitespace character(s) (spaces/tabs are never removed automatically)")

    if props["control_count"]:
        problems.append(f"SENSOR_KEY contains {props['control_count']} control character(s)")

    if props["quote_count"]:
        problems.append(f"SENSOR_KEY contains {props['quote_count']} quote character(s) (do not wrap the value in quotes)")

    if not props["length_ok"] and props["length"] > MAX_CREDENTIAL_LENGTH:
        problems.append(f"SENSOR_KEY is longer than {MAX_CREDENTIAL_LENGTH} characters")

    if not problems and not props["charset_ok"]:
        problems.append("SENSOR_KEY contains characters outside letters, digits, '_' and '-'")

    return problems


def check_header_value(name, value):

    # Every outbound header value must be plain ASCII without control characters (this also
    # blocks header injection). Raises ConfigError naming the HEADER, never its value.
    if not isinstance(value, str) or not value or len(value) > MAX_HEADER_VALUE:
        raise ConfigError(f"HTTP header {name} is missing or too long")

    if not value.isascii():
        raise ConfigError(f"HTTP header {name} contains non-ASCII characters and cannot be sent")

    if _CONTROL_CHARS_RE.search(value):
        raise ConfigError(f"HTTP header {name} contains control characters and cannot be sent")


def check_url(url):

    if not isinstance(url, str) or not url.isascii() or _CONTROL_CHARS_RE.search(url) or any(ch.isspace() for ch in url):
        raise ConfigError("SOC_URL contains non-ASCII, whitespace or control characters")


class Response:

    def __init__(self, status, body=None, retry_after=None, error=None, server_date=None, tls=False):
        self.status = status
        self.body = body
        self.retry_after = retry_after
        self.error = error
        self.server_date = server_date
        self.tls = tls                    # True: a TLS trust/handshake failure (never retried in a tight loop)


class _NoRedirect(urllib.request.HTTPRedirectHandler):

    # The ingest endpoint never redirects. Following a redirect would replay custom request
    # headers (including the sensor credential header) to whatever host the Location names -
    # possibly over plain http - so redirects are NEVER followed.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SocClient:

    def __init__(self, base_url, sensor_id, secret, timeout=HTTP_TIMEOUT, ca_file=None, require_https=False):

        check_url(base_url)
        self.url = base_url.rstrip("/") + "/api/security-ingest"
        self.sensor_id = sensor_id
        self._secret = secret
        self.timeout = timeout
        self._headers()             # fail at construction, never mid-run, never with a traceback

        scheme = urllib.parse.urlsplit(self.url).scheme.lower()

        if scheme not in ("http", "https"):
            raise ConfigError("SOC_URL must start with http:// or https://")

        if require_https and scheme != "https":
            raise ConfigError("SOC_REQUIRE_HTTPS is set but SOC_URL is not https://")

        self.scheme = scheme
        self.ca_file = ca_file or None
        self._opener = self._build_opener(scheme, self.ca_file)

    @staticmethod
    def _build_opener(scheme, ca_file):

        # TLS: certificate chain AND hostname verification are always ON (ssl.create_default_context).
        # `ca_file` (a private CA bundle) REPLACES the system store for this connection; it is a
        # trust anchor, never a way to switch verification off. Environment proxies are ignored
        # (the credential header must only ever travel to SOC_URL). Redirects are never followed.
        context = None

        if scheme == "https":

            try:
                context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
            except (OSError, ssl.SSLError, ValueError):
                raise ConfigError("SOC_CA_FILE cannot be read or is not a valid PEM CA bundle")

            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ConfigError("TLS verification cannot be enabled")

        handlers = [urllib.request.ProxyHandler({}), _NoRedirect()]

        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))

        return urllib.request.build_opener(*handlers)

    def _headers(self):

        # EVERY custom outbound header is validated before a request is built.
        problems = credential_problems(self._secret)

        if problems:
            raise ConfigError(problems[0])

        headers = {
            "Content-Type": "application/json",
            "X-Sensor-Id": self.sensor_id,
            "X-Sensor-Key": self._secret,
            "User-Agent": f"soc-suricata-adapter/{ADAPTER_VERSION}",
        }

        for name, value in headers.items():
            check_header_value(name, value)

        return headers

    def post(self, records):

        payload = json.dumps({"records": records}, separators=(",", ":")).encode("utf-8")

        request = urllib.request.Request(self.url, data=payload, method="POST", headers=self._headers())

        try:

            with self._opener.open(request, timeout=self.timeout) as reply:
                return self._response(reply.status, reply.read(65536), reply.headers)

        except urllib.error.HTTPError as exc:

            if 300 <= exc.code < 400:
                return Response(exc.code, error="redirect_refused")      # Location is never followed or logged

            try:
                data = exc.read(65536)
            except Exception:
                data = b""

            return self._response(exc.code, data, exc.headers)

        except UnicodeError:

            raise ConfigError("a request header or the URL cannot be encoded for HTTP")

        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:

            inner = getattr(exc, "reason", exc)

            if isinstance(inner, ssl.SSLError) or isinstance(exc, ssl.SSLError):
                detail = getattr(inner, "verify_message", None) or type(inner).__name__
                return Response(0, error=_clean_token(detail, 60), tls=True)

            return Response(0, error=type(exc).__name__)

    @staticmethod
    def _response(status, data, headers):

        try:
            body = json.loads(data.decode("utf-8")) if data else None
        except (ValueError, UnicodeDecodeError):
            body = None

        retry_after = None

        try:
            value = headers.get("Retry-After") if headers is not None else None
            retry_after = float(value) if value is not None else None
        except (TypeError, ValueError):
            retry_after = None

        return Response(status, body if isinstance(body, dict) else None, retry_after,
                        server_date=headers.get("Date") if headers is not None else None)

    def __repr__(self):
        return f"SocClient({self.url!r}, sensor={self.sensor_id!r})"        # never shows the secret


class Backoff:

    def __init__(self, base=BACKOFF_BASE, cap=BACKOFF_CAP, rand=random.random):
        self.base, self.cap, self.rand = base, cap, rand
        self.attempt = 0

    def next(self):

        delay = min(self.cap, self.base * (2 ** self.attempt))
        self.attempt += 1

        return delay * (0.8 + 0.4 * self.rand())

    def reset(self):
        self.attempt = 0


class Delivery:

    ADVANCE = "advance"
    AUTH = "auth"
    LATER = "later"

    def __init__(self, client, counters, sleep=time.sleep, rand=random.random,
                 stop=lambda: False, max_attempts=None):
        self.client, self.counters, self.sleep = client, counters, sleep
        self.backoff = Backoff(rand=rand)
        self.stop, self.max_attempts = stop, max_attempts
        self._last_post = 0.0

    def _pace(self):

        gap = MIN_POST_INTERVAL - (time.monotonic() - self._last_post)

        if gap > 0:
            self.sleep(gap)

        self._last_post = time.monotonic()

    def _record_outcome(self, response):

        body = response.body or {}

        for key, counter in (("accepted", "accepted"), ("duplicates", "duplicates"), ("rejected", "rejected")):
            value = body.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                self.counters[counter] += value

        for item in (body.get("results") or [])[:200]:
            if isinstance(item, dict) and item.get("status") == "REJECTED":
                self.counters["reject_" + _clean_token(item.get("reason", "unknown"), 40)] += 1

        server_date = response.server_date

        if server_date:
            try:
                from email.utils import parsedate_to_datetime
                skew = abs((parsedate_to_datetime(server_date) - utc_now()).total_seconds())
                if skew > 120:
                    self.counters["clock_skew_warnings"] += 1
                    log("clock_skew", seconds=int(skew))
            except Exception:
                pass

    def deliver(self, records):

        attempts = 0

        while True:

            if self.stop():
                return self.LATER

            self._pace()
            response = self.client.post(records)
            status = response.status

            if 200 <= status < 300 or status == 422:
                self.backoff.reset()
                self._record_outcome(response)
                return self.ADVANCE                    # 202 / 207 / 422: rejects are permanent

            if getattr(response, "tls", False):
                self.counters["tls_failures"] += 1
                log("tls_verification_failed", reason=response.error or "")
                return self.AUTH                       # fail closed: nothing was sent, checkpoint never advances

            if 300 <= status < 400:
                self.counters["redirects_refused"] += 1
                log("redirect_refused", status=status)
                return self.AUTH                       # misconfigured SOC_URL/proxy; never followed

            if status in (401, 403):
                self.counters["auth_failures"] += 1
                log("auth_failed", status=status)
                return self.AUTH                       # never advance; operator must fix the credential

            if status in (400, 413):

                if len(records) > 1:

                    self.counters["bisected"] += 1
                    middle = len(records) // 2

                    for part in (records[:middle], records[middle:]):

                        outcome = self.deliver(part)

                        if outcome != self.ADVANCE:
                            return outcome

                    return self.ADVANCE

                self.counters["poison_records_skipped"] += 1
                log("poison_record_skipped", status=status)
                return self.ADVANCE

            # 429, 503, other 5xx, network errors: wait, retry, never a tight loop
            self.counters["retries"] += 1

            if status == 429:
                wait = min(BACKOFF_CAP, max(1.0, response.retry_after or 1.0))
            else:
                wait = max(self.backoff.next(), min(BACKOFF_CAP, response.retry_after or 0.0))

            log("retry", status=status, error=response.error or "", wait=round(wait, 2))

            attempts += 1

            if self.max_attempts is not None and attempts >= self.max_attempts:
                return self.LATER

            self.sleep(wait)


# ==================================================
# ADAPTER
# ==================================================

class Adapter:

    def __init__(self, eve_path, state_dir, sensor_id, client, start_at_end=False, sleep=time.sleep,
                 now=utc_now, rand=random.random, stop=lambda: False, max_attempts=None,
                 flow_min_bytes=FLOW_MIN_BYTES, flow_min_age=FLOW_MIN_AGE_SECONDS, include_dns_requests=False):

        if not SENSOR_ID_RE.match(sensor_id or ""):
            raise ValueError("invalid sensor id")

        self.sensor_id = sensor_id
        self.checkpoint = Checkpoint(state_dir, sensor_id)
        self.checkpoint.load()
        self.checkpoint.probe_writable()
        self.reader = EveReader(eve_path, self.checkpoint, start_at_end=start_at_end)
        self.counters = collections.Counter()
        self.delivery = Delivery(client, self.counters, sleep=sleep, rand=rand, stop=stop, max_attempts=max_attempts)
        self.now = now
        self.sleep = sleep
        self.stop = stop
        self.flow_min_bytes, self.flow_min_age = flow_min_bytes, flow_min_age
        self.include_dns_requests = include_dns_requests
        self.state_dir = state_dir
        self.status = {"adapter_version": ADAPTER_VERSION, "sensor_id": sensor_id, "started_at": fmt_ms(now()),
                       "last_eve_record_at": None, "last_ingest_ok_at": self.checkpoint.data.get("last_ingest_ok_at"),
                       "kernel_drops": None, "kernel_packets": None}
        self._status_written = 0.0
        self._ctx_cache = None

    def _ctx(self, file_id):

        if self._ctx_cache is None:
            self._ctx_cache = Context(self.sensor_id, file_id or "00000000", now=self.now,
                                      flow_min_bytes=self.flow_min_bytes, flow_min_age=self.flow_min_age,
                                      include_dns_requests=self.include_dns_requests)

        self._ctx_cache.file_id = file_id or "00000000"

        return self._ctx_cache

    def write_status(self, force=False):

        if not force and time.monotonic() - self._status_written < 5.0:
            return

        self._status_written = time.monotonic()

        data = dict(self.status)
        data["counters"] = {k: v for k, v in sorted({**self.counters, **self.reader.counters}.items())}
        data["written_at"] = fmt_ms(self.now())
        data["checkpoint_saved_at"] = self.status.get("checkpoint_saved_at")
        data["eve_open_error"] = self.reader.open_error            # exception class name, or null while readable
        data["eve_last_open_ok_at"] = self.reader.last_open_ok_at
        data["checkpoint_offset"] = self.checkpoint.data.get("offset")

        try:
            os.makedirs(self.state_dir, exist_ok=True)
            _atomic_write(os.path.join(self.state_dir, "status.json"), data)
        except OSError:
            pass

    def step(self):

        # One bounded unit of work: read <= 100 lines, normalize, deliver, then commit
        # the checkpoint ONLY after the SOC accepted (or permanently rejected) them.
        batch = self.reader.next_batch()

        if not batch.lines and batch.next_state is None:
            return "idle"

        ctx = self._ctx(batch.file_id or self.checkpoint.data.get("file_id"))
        records = []
        last_eve_ts = None

        for offset, line in batch.lines:

            self.counters["lines_read"] += 1

            ctx.file_id = batch.file_id or ctx.file_id
            kind, payload = process_line(line, offset, ctx)

            if kind == "record":
                records.append(payload)
                self.counters["records_parsed"] += 1
                last_eve_ts = payload["observed_at"]
            elif kind == "stats":
                self.counters["stats_seen"] += 1
                self.status["kernel_drops"] = payload.get("kernel_drops")
                self.status["kernel_packets"] = payload.get("kernel_packets")
            elif kind == "skipped":
                self.counters["skipped_" + _clean_token(payload, 30)] += 1
                if payload == "alert_rate_cap":
                    self.counters["alerts_dropped"] += 1
            elif kind == "ignored":
                self.counters["ignored_types"] += 1
                self.counters["unsupported_" + _clean_token(payload, 24)] += 1
            else:
                self.counters["malformed"] += 1

        if records:

            outcome = self.delivery.deliver(records)

            if outcome == Delivery.AUTH:
                self.write_status(force=True)
                return "auth"

            if outcome != Delivery.ADVANCE:
                return "later"

            self.counters["records_sent"] += len(records)
            self.checkpoint.data["last_source_event_id"] = records[-1]["source_event_id"]
            self.checkpoint.data["last_ingest_ok_at"] = fmt_ms(self.now())
            self.status["last_ingest_ok_at"] = self.checkpoint.data["last_ingest_ok_at"]

        if last_eve_ts:
            self.status["last_eve_record_at"] = last_eve_ts

        if batch.next_state is not None:
            self.checkpoint.data.update(batch.next_state)

        self.checkpoint.save()
        self.status["checkpoint_saved_at"] = fmt_ms(self.now())
        self.write_status()

        return "progress"

    def run(self):

        while not self.stop():

            try:
                result = self.step()
            except ConfigError:
                raise                                # unrecoverable configuration problem: stop cleanly (main reports it)
            except Exception as exc:                 # noqa - the adapter must never die on one bad batch
                self.counters["step_errors"] += 1
                log("step_error", error=type(exc).__name__)
                result = "error"

            if result == "auth":
                self.sleep(AUTH_BACKOFF)
            elif result == "later":
                self.sleep(BACKOFF_BASE)
            elif result == "error":
                self.sleep(5.0)
            elif result == "idle":
                self.write_status()
                self.sleep(EVE_ERROR_POLL_SECONDS if self.reader.open_error else POLL_SECONDS)

        self.write_status(force=True)


# ==================================================
# CONFIG / CLI
# ==================================================

def read_env_file(path):

    return read_env_file_checked(path)[0]


def read_env_file_checked(path):

    # Returns (values, error_class_name_or_None).

    # Values are returned VERBATIM: only the line ending (CR/LF) is removed. Nothing is
    # stripped, unquoted or otherwise mutated here; callers decide per key (see _plain).
    # A UTF-8 byte-order mark at the very start of the FILE is an encoding marker, not data.
    values = {}

    try:

        if os.name == "posix" and os.stat(path).st_mode & 0o077:
            log("env_file_permissions_too_open")

        with open(path, "r", encoding="utf-8-sig", newline="") as handle:
            text = handle.read()

    except OSError as exc:
        log("env_file_unreadable")
        return values, type(exc).__name__
    except UnicodeDecodeError:
        log("env_file_not_utf8")
        return values, "UnicodeDecodeError"

    for line in text.split(chr(10)):

        if line.endswith(chr(13)):
            line = line[:-1]

        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue

        key, _, value = line.partition("=")
        values[key.strip()] = value

    return values, None


def _plain(value):

    # NON-secret settings only (URL, ids, paths, flags): surrounding whitespace and one pair of
    # matching quotes are tolerated. The credential is never passed through this.
    value = (value or "").strip()

    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()

    return value


def load_settings(args, environ):

    values = dict(environ)

    env_problem = None

    if args.env_file:
        file_values, env_error = read_env_file_checked(args.env_file)
        values.update(file_values)

        if env_error:
            env_problem = f"the env file cannot be read ({env_error})"

    url = _plain(args.soc_url or values.get("SOC_URL", ""))
    sensor_id = _plain(args.sensor_id or values.get("SENSOR_ID", ""))
    secret = values.get("SENSOR_KEY", "")                  # environment / env file ONLY, VERBATIM

    problems = []

    if env_problem:
        problems.append(env_problem)

    if not (url.startswith("http://") or url.startswith("https://")):
        problems.append("SOC_URL must be http(s)")

    if not SENSOR_ID_RE.match(sensor_id):
        problems.append("SENSOR_ID is missing or malformed")

    if url:
        try:
            check_url(url)
        except ConfigError as exc:
            problems.append(str(exc))

    problems.extend(credential_problems(secret))

    ca_file = _plain(getattr(args, "ca_file", None) or values.get("SOC_CA_FILE", ""))
    require_https = bool(getattr(args, "require_https", False)) or _plain(values.get("SOC_REQUIRE_HTTPS", "")).lower() in ("1", "true", "yes")

    if ca_file and not os.path.isfile(ca_file):
        problems.append("SOC_CA_FILE does not point to a readable file")

    if require_https and not url.startswith("https://"):
        problems.append("SOC_REQUIRE_HTTPS is set but SOC_URL is not https://")

    return {
        "url": url, "sensor_id": sensor_id, "secret": secret, "problems": problems,
        "eve": args.eve_path or _plain(values.get("SURICATA_EVE_PATH", "")) or "/var/log/suricata/eve.json",
        "state_dir": args.state_dir or _plain(values.get("SOC_ADAPTER_STATE_DIR", "")) or "/var/lib/soc-suricata-adapter",
        "ca_file": ca_file, "require_https": require_https,
        "dns_requests": bool(getattr(args, "include_dns_requests", False))
                        or _plain(values.get("SURICATA_INCLUDE_DNS_REQUESTS", "")).lower() in ("1", "true", "yes"),
    }


def probe_eve(path):

    # -> ("readable", None) | ("missing", None) | ("cannot-open", ErrorClassName)
    try:
        os.stat(path)
    except FileNotFoundError:
        return "missing", None
    except OSError as exc:
        return "cannot-open", type(exc).__name__

    try:
        with open(path, "rb"):
            pass
    except OSError as exc:
        return "cannot-open", type(exc).__name__

    return "readable", None


def probe_state_dir(path):

    # Side-effect free for check-config: an existing directory must accept a file; a missing one
    # must be creatable (its nearest existing ancestor must be writable). Nothing is created here.
    # -> None when fine, else a sanitized reason.
    if os.path.isdir(path):

        probe = os.path.join(path, ".write-probe")

        try:
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write("ok")
            os.remove(probe)
        except OSError as exc:
            return f"the state directory is not writable ({type(exc).__name__})"

        return None

    ancestor = os.path.dirname(os.path.abspath(path))

    while ancestor and not os.path.isdir(ancestor):
        parent = os.path.dirname(ancestor)
        if parent == ancestor:
            break
        ancestor = parent

    if not (os.path.isdir(ancestor) and os.access(ancestor, os.W_OK | os.X_OK)):
        return "the state directory does not exist and cannot be created here (its parent is not writable)"

    return None


def check_config(settings):

    errors = []

    eve_state, eve_error = probe_eve(settings["eve"])
    state_error = probe_state_dir(settings["state_dir"])

    if eve_state == "cannot-open":
        errors.append(f"the EVE file cannot be opened by this user ({eve_error}) - check its owner/group/mode and the service group")

    if state_error:
        errors.append(state_error[0].upper() + state_error[1:])

    if settings["url"].startswith("https://"):
        transport = ("https (certificate chain and hostname verification ON; trust anchor: "
                     + ("the configured CA file" if settings["ca_file"] else "the system CA store") + ")")
    else:
        transport = "http (plain; acceptable only on a loopback / isolated host-local path)"

    for problem in errors:
        print(f"CONFIG ERROR: {problem}", file=sys.stderr)

    print(f"sensor {settings['sensor_id']} -> {settings['url']}")
    print(f"transport: {transport}; https required: {'yes' if settings['require_https'] else 'no'}")
    print("eve: " + {"readable": "readable", "missing": "not present yet (the adapter will wait for Suricata to create it)",
                     "cannot-open": "CANNOT OPEN"}[eve_state] + f" ({settings['eve']})")
    print("state-dir: " + ("NOT WRITABLE" if state_error else ("writable" if os.path.isdir(settings["state_dir"]) else "will be created")) + f" ({settings['state_dir']})")
    print(describe_credential(settings["secret"]))

    if not credential_properties(settings["secret"])["prefix_ok"]:
        print(f"WARNING: the credential does not start with the expected '{CREDENTIAL_PREFIX}' prefix "
              "(wrong value, or text copied around it?)")

    if errors:
        return 2

    print("OK")

    return 0


def describe_credential(secret):

    # One line of PROPERTIES (counts/booleans) - never the value or a fragment of it.
    p = credential_properties(secret)

    def yn(flag):
        return "yes" if flag else "no"

    return (f"credential: present={yn(p['present'])} length={p['length']} ascii={yn(p['ascii'])} "
            f"non_ascii_chars={p['non_ascii_count']} whitespace={p['whitespace_count']} quotes={p['quote_count']} "
            f"control_chars={p['control_count']} charset_ok={yn(p['charset_ok'])} prefix_{CREDENTIAL_PREFIX}={yn(p['prefix_ok'])}")


def main(argv=None):

    parser = argparse.ArgumentParser(description="Suricata EVE -> SOC adapter")
    parser.add_argument("command", choices=("run", "status", "check-config"))
    parser.add_argument("--eve-path")
    parser.add_argument("--state-dir")
    parser.add_argument("--env-file")
    parser.add_argument("--soc-url")
    parser.add_argument("--sensor-id")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--start-at-end", action="store_true")
    parser.add_argument("--include-dns-requests", action="store_true",
                        help="also forward DNS requests (default: responses only)")
    parser.add_argument("--ca-file", help="PEM CA bundle that signs the SOC's TLS certificate (private CA); verification stays ON")
    parser.add_argument("--require-https", action="store_true", help="refuse to start unless SOC_URL is https:// (default off)")
    args = parser.parse_args(argv)

    settings = load_settings(args, os.environ)

    if args.command == "status":

        path = os.path.join(settings["state_dir"], "status.json")

        try:
            with open(path, "r", encoding="utf-8") as handle:
                print(handle.read())
            return 0
        except OSError:
            print("no status file yet", file=sys.stderr)
            return 1

    if settings["problems"]:
        for problem in settings["problems"]:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        print(describe_credential(settings["secret"]), file=sys.stderr)
        return 2

    if args.command == "check-config":
        return check_config(settings)

    host = settings["url"].split("//", 1)[1].split("/", 1)[0].split(":")[0]

    # Sensor credentials travel in a header: plain HTTP is acceptable only on a loopback /
    # trusted single-host path. Anything else must use HTTPS (TLS verification is never disabled).
    if settings["url"].startswith("http://") and host not in ("127.0.0.1", "localhost", "[::1]", "::1"):
        log("plain_http_credentials_warning", host=host)

    stop_flag = {"stop": False}

    def _signal(_signum, _frame):
        stop_flag["stop"] = True

    for name in ("SIGTERM", "SIGINT"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _signal)
            except (ValueError, OSError):
                pass

    try:
        client = SocClient(settings["url"], settings["sensor_id"], settings["secret"],
                           ca_file=settings["ca_file"] or None, require_https=settings["require_https"])
        adapter = Adapter(settings["eve"], settings["state_dir"], settings["sensor_id"], client,
                          start_at_end=args.start_at_end, stop=lambda: stop_flag["stop"],
                          include_dns_requests=settings["dns_requests"])

        log("adapter_started", version=ADAPTER_VERSION, sensor=settings["sensor_id"])
        adapter.write_status(force=True)          # `status` works from the first moment

        if args.once:

            while True:
                result = adapter.step()
                if result in ("idle", "auth", "later"):
                    break

            adapter.write_status(force=True)
            return 0 if result != "auth" else 3

        adapter.run()

    except ConfigError as exc:

        # Sanitized: the message names the setting/header, never its value. No traceback.
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
