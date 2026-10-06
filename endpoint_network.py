# ==================================================
# PHASE 13C: ENDPOINT NETWORK CONTEXT, IP HISTORY & TIMESTAMP-AWARE RESOLUTION
# ==================================================
#
# Flask-free library. Three foundations:
#
#   A. Sanitizers for the OS-observed connection metadata an endpoint agent
#      may send (destination port, transport protocol, connection source IP).
#      Bad optional values become NULL - they never reject an event.
#
#   B. endpoint_ip_history: "this STABLE agent installation (endpoint_uid) was
#      observed using this IP during [first_seen_at, last_seen_at]". It is a
#      time-interval record, NOT ownership: it never means the IP belongs to
#      the endpoint permanently. An endpoint that leaves an IP and returns much
#      later gets a NEW interval, so it never claims the gap in between.
#
#   C. resolve_endpoint(ip, observed_at_utc): answers "which endpoint had this
#      IP at that time?" ONLY from history: EXACT / AMBIGUOUS / STALE / UNKNOWN.
#      The current endpoints.ip_address, hostname, username or process name are
#      never consulted: CURRENT IP MUST NEVER BE ASSUMED TO BE HISTORICAL IDENTITY.
#
# ENDPOINT UID CONSISTENCY GUARD (evaluate_identity)
#   The shared X-Agent-Key stays the only authentication (per-agent credentials
#   are a documented future hardening item). The guard protects against SILENT
#   conflicting identity assertions: if a DIFFERENT UID is currently bound to an
#   IP, an incoming assertion of another UID is a CONFLICT - the stored UID is
#   not overwritten, no history is created from it and a bounded log entry is
#   written. A binding is TEMPORAL, never permanent: once the bound UID stops
#   being observed for the binding window, the IP may legitimately be used by a
#   different UID (DHCP reuse -> REASSIGNED).
#
# TIME DOMAIN: every history timestamp is UTC ISO-8601 with ms and a literal Z
# (security_contract.format_utc), stamped from the server clock AT RECEIPT (the
# agent sends no timestamps). Legacy local-naive columns are never converted.
#
# PORTABLE SQL: ON CONFLICT DO NOTHING, ISO text timestamps, no strftime.

import ipaddress
import os
import threading
import time

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

import db_config
import endpoint_identity
import security_contract as sc
import security_detections as sd

SOURCE_HEARTBEAT = "agent-heartbeat"
SOURCE_EVENT = "agent-event"

# identity guard outcomes
IDENTITY_OK = "OK"
IDENTITY_REASSIGNED = "REASSIGNED"
IDENTITY_CONFLICT = "CONFLICT"

# record_observations per-address statuses
REC_NEW = "NEW_INTERVAL"
REC_EXTENDED = "EXTENDED"
REC_THROTTLED = "THROTTLED"
REC_CONFLICT = "CONFLICT"
REC_INELIGIBLE = "INELIGIBLE"

# resolver statuses (the reserved 13B vocabulary)
RES_EXACT = "EXACT"
RES_AMBIGUOUS = "AMBIGUOUS"
RES_STALE = "STALE"
RES_UNKNOWN = "UNKNOWN"

MAX_ADDRESSES_PER_HEARTBEAT = 16
MAX_HISTORY_PANEL_ROWS = 20
MAX_CANDIDATES = 5
_MAX_RESOLVER_ROWS = 200

_HISTORY_DDL = (
    """
    CREATE TABLE IF NOT EXISTS endpoint_ip_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_uid TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 1,
        source TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (endpoint_uid, ip_address, first_seen_at)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_eiph_ip ON endpoint_ip_history(ip_address, last_seen_at)",
    "CREATE INDEX IF NOT EXISTS idx_eiph_uid ON endpoint_ip_history(endpoint_uid, last_seen_at)",
)


# --------------------------------------------------
# CONFIGURATION (env, read at call time)
# --------------------------------------------------

def _env_int(name, default, minimum, maximum):

    try:
        value = int(os.getenv(name, "").strip())
    except ValueError:
        return default

    return value if minimum <= value <= maximum else default


def continuity_gap_seconds():
    # A new observation within this gap EXTENDS the latest interval; a longer
    # silence starts a new one. 300 s = five 60 s heartbeats.
    return _env_int("ENDPOINT_HISTORY_CONTINUITY_GAP_SECONDS", 300, 30, 86400)


def pre_grace_seconds():
    # An address is first reported at most one heartbeat after it appears.
    return _env_int("ENDPOINT_RESOLVE_PRE_GRACE_SECONDS", 60, 0, 3600)


def post_grace_seconds():
    # One missed heartbeat is tolerated after the last observation.
    return _env_int("ENDPOINT_RESOLVE_POST_GRACE_SECONDS", 120, 0, 3600)


def stale_horizon_days():
    return _env_int("ENDPOINT_STALE_HORIZON_DAYS", 30, 1, 3650)


def write_min_seconds():
    return _env_int("ENDPOINT_HISTORY_WRITE_MIN_SECONDS", 30, 0, 3600)


def binding_window_seconds():
    # How long after its LAST observation a UID is still "currently bound" to
    # an IP (it could still be extending that interval). Never shorter than the
    # two resolver grace windows together, so evidence recorded for two UIDs
    # cannot normally overlap.
    floor = pre_grace_seconds() + post_grace_seconds()
    configured = _env_int("ENDPOINT_IDENTITY_BINDING_SECONDS", 0, 0, 86400)
    base = configured if configured else continuity_gap_seconds()
    return max(base, floor)


# --------------------------------------------------
# SCHEMA
# --------------------------------------------------

def init_endpoint_network_db():

    # Additive only (CREATE ... IF NOT EXISTS). Touches no existing table.
    conn = sd.get_db_connection()

    def run():

        conn.execute("BEGIN IMMEDIATE")

        try:
            for statement in _HISTORY_DDL:
                conn.execute(statement)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    try:
        db_config.retry_on_lock(run, label="init_endpoint_network_db")
    finally:
        conn.close()


# --------------------------------------------------
# SANITIZERS FOR OS-OBSERVED CONNECTION METADATA
# --------------------------------------------------

def sanitize_port(value):

    # Observed remote port only: an int 1-65535. Never a bool, a string or a
    # guess (no "443 because HTTPS", no "80 because HTTP").
    if isinstance(value, bool) or not isinstance(value, int):
        return None

    return value if 1 <= value <= 65535 else None


def sanitize_protocol(value):

    # Transport protocol only ("tcp"/"udp"); never an application protocol.
    if not isinstance(value, str):
        return None

    value = value.strip().lower()

    return value if value in ("tcp", "udp") else None


def canonical_ip(value):

    # Canonical text of a valid IP, or None. IPv4-mapped IPv6 is folded to IPv4
    # so one address has one spelling; zone ids ("%eth0") are rejected.
    if not isinstance(value, str) or not value or len(value) > 45 or "%" in value:
        return None

    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return str(ip)


def sanitize_source_ip(value):

    # The connection's LOCAL address as observed by the OS. Any valid address
    # except the unspecified one is kept as an observed fact (loopback and
    # link-local included); whether it may enter IP HISTORY is a separate,
    # stricter policy (history_eligible_ip).
    ip = canonical_ip(value)

    if ip is None or ipaddress.ip_address(ip).is_unspecified:
        return None

    return ip


def history_eligible_ip(value):

    # The IP-history eligibility policy. Returns the canonical IP, or None.
    #   recorded : private, CGNAT (100.64/10), ULA, global IPv4/IPv6, VPN
    #   NOT recorded: unspecified, loopback, multicast, broadcast/reserved and
    #   link-local (169.254/16, fe80::/10) - per-link, non-unique and
    #   non-routable, they would manufacture ambiguity and false matches.
    ip = canonical_ip(value)

    if ip is None:
        return None

    parsed = ipaddress.ip_address(ip)

    if (parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast
            or parsed.is_link_local or parsed.is_reserved):
        return None

    return ip


# --------------------------------------------------
# LOGGING HELPERS (bounded; the logger callable is supplied by the caller)
# --------------------------------------------------

_log_lock = threading.Lock()
_log_times = {}
_LOG_THROTTLE_SECONDS = 300.0


def _emit(logger, event_type, message, key, monotonic=time.monotonic):

    # At most one entry per key per throttle window; never raises.
    if logger is None:
        return False

    with _log_lock:

        now = monotonic()
        previous = _log_times.get(key)

        if previous is not None and now - previous < _LOG_THROTTLE_SECONDS:
            return False

        if len(_log_times) > 1024:
            _log_times.clear()

        _log_times[key] = now

    try:
        logger(event_type, message)
    except Exception:
        return False

    return True


def _conflict_message(route, ip, bound_uid, asserted_uid):
    return f"route={route} ip={ip} bound_uid={bound_uid} asserted_uid={asserted_uid}"


# --------------------------------------------------
# IDENTITY GUARD
# --------------------------------------------------

@dataclass(frozen=True)
class IdentityDecision:

    outcome: str
    bound_uid: str = None


def _local_naive(moment):

    return moment.astimezone().replace(tzinfo=None)


def evaluate_identity(conn, uid, ip, now):

    # `uid` and `ip` must already be validated/canonical. Read-only.
    #
    # CONFLICT   another UID is CURRENTLY bound to `ip` (observed within the
    #            binding window) - by history, or (fallback for records that
    #            pre-date history) by the endpoints row.
    # REASSIGNED an older, no-longer-current binding to another UID exists:
    #            legitimate DHCP-style reuse.
    # OK         nothing conflicting.
    window = binding_window_seconds()
    cutoff = sc.format_utc(now - timedelta(seconds=window))

    row = conn.execute(
        "SELECT endpoint_uid FROM endpoint_ip_history "
        "WHERE ip_address = ? AND last_seen_at >= ? AND endpoint_uid != ? "
        "ORDER BY last_seen_at DESC LIMIT 1",
        (ip, cutoff, uid)
    ).fetchone()

    if row is not None:
        return IdentityDecision(IDENTITY_CONFLICT, row[0])

    endpoint = conn.execute(
        "SELECT endpoint_uid, last_seen FROM endpoints WHERE ip_address = ?",
        (ip,)
    ).fetchone()

    other = None

    if endpoint is not None and endpoint[0] and endpoint[0] != uid:

        other = endpoint[0]

        # Same server-local clock domain on both sides of this comparison.
        local_cutoff = (_local_naive(now) - timedelta(seconds=window)).strftime("%Y-%m-%d %H:%M:%S")

        if endpoint[1] and endpoint[1] >= local_cutoff:
            return IdentityDecision(IDENTITY_CONFLICT, other)

    if other is None:

        older = conn.execute(
            "SELECT endpoint_uid FROM endpoint_ip_history "
            "WHERE ip_address = ? AND endpoint_uid != ? LIMIT 1",
            (ip, uid)
        ).fetchone()

        if older is not None:
            other = older[0]

    if other is not None:
        return IdentityDecision(IDENTITY_REASSIGNED, other)

    return IdentityDecision(IDENTITY_OK)


def evaluate_identity_standalone(uid, ip, now=None):

    # Read-only check on its own short connection (used by the event path
    # BEFORE the event row is written). Returns an IdentityDecision.
    uid = endpoint_identity.normalize_endpoint_uid(uid)
    ip = canonical_ip(ip)

    if uid is None or ip is None:
        return IdentityDecision(IDENTITY_OK)

    # Steady state: this exact (uid, ip) pair passed the guard and was recorded
    # within the write-throttle window, so nothing has changed for IT (a
    # different UID asserting the same IP is a different pair and is always
    # evaluated). Saves a connection + 3 queries on every event of a bound agent.
    min_interval = write_min_seconds()

    if min_interval > 0 and _throttled(uid, ip, min_interval, time.monotonic):
        return IdentityDecision(IDENTITY_OK)

    conn = sd.get_db_connection()

    try:
        return evaluate_identity(conn, uid, ip, now or sc.utc_now())
    finally:
        conn.close()


# --------------------------------------------------
# RECORDING
# --------------------------------------------------

_write_lock = threading.Lock()
_last_write = {}


def _throttled(uid, ip, min_interval, monotonic):

    if min_interval <= 0:
        return False

    with _write_lock:

        previous = _last_write.get((uid, ip))

        return previous is not None and (monotonic() - previous) < min_interval


def _stamp(uid, ip, monotonic):

    with _write_lock:

        if len(_last_write) > 4096:
            _last_write.clear()

        _last_write[(uid, ip)] = monotonic()


def reset_write_throttle():
    # Test helper.
    with _write_lock:
        _last_write.clear()
    with _log_lock:
        _log_times.clear()


def record_observations(conn, uid, addresses, now, source, logger=None, route=None,
                        min_interval=None, monotonic=time.monotonic):

    # Records that stable agent `uid` was observed using each address at `now`
    # (aware UTC datetime). ONE short write transaction for all addresses that
    # need a write; nothing is written for throttled/ineligible/conflicting
    # addresses. Returns:
    #   {"results": {ip: status}, "recorded": n, "conflicts": [ip...],
    #    "decisions": {ip: IdentityDecision}}
    # The guard is re-evaluated INSIDE the transaction, so two simultaneous
    # conflicting assertions are serialized: the first to commit is bound.
    uid = endpoint_identity.normalize_endpoint_uid(uid)

    outcome = {"results": {}, "recorded": 0, "conflicts": [], "decisions": {}}

    if uid is None:
        return outcome

    min_interval = write_min_seconds() if min_interval is None else min_interval
    route = route or source

    todo = []

    for raw in list(addresses)[:MAX_ADDRESSES_PER_HEARTBEAT]:

        ip = history_eligible_ip(raw)

        if ip is None:
            outcome["results"][canonical_ip(raw) or str(raw)[:45]] = REC_INELIGIBLE
            continue

        if ip in outcome["results"]:
            continue

        if _throttled(uid, ip, min_interval, monotonic):
            outcome["results"][ip] = REC_THROTTLED
            continue

        todo.append(ip)
        outcome["results"][ip] = None

    if not todo:
        return outcome

    now_iso = sc.format_utc(now)
    gap_cutoff = sc.format_utc(now - timedelta(seconds=continuity_gap_seconds()))

    conn.execute("BEGIN IMMEDIATE")

    try:

        for ip in todo:

            decision = evaluate_identity(conn, uid, ip, now)
            outcome["decisions"][ip] = decision

            if decision.outcome == IDENTITY_CONFLICT:
                outcome["results"][ip] = REC_CONFLICT
                outcome["conflicts"].append(ip)
                continue

            latest = conn.execute(
                "SELECT id, last_seen_at FROM endpoint_ip_history "
                "WHERE endpoint_uid = ? AND ip_address = ? "
                "ORDER BY last_seen_at DESC, id DESC LIMIT 1",
                (uid, ip)
            ).fetchone()

            if latest is not None and latest[1] >= gap_cutoff:

                conn.execute(
                    "UPDATE endpoint_ip_history SET "
                    "last_seen_at = CASE WHEN last_seen_at < ? THEN ? ELSE last_seen_at END, "
                    "observation_count = observation_count + 1, updated_at = ? WHERE id = ?",
                    (now_iso, now_iso, now_iso, latest[0])
                )
                outcome["results"][ip] = REC_EXTENDED

            else:

                cursor = conn.execute(
                    "INSERT INTO endpoint_ip_history "
                    "(endpoint_uid, ip_address, first_seen_at, last_seen_at, observation_count, "
                    "source, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?) "
                    "ON CONFLICT (endpoint_uid, ip_address, first_seen_at) DO NOTHING",
                    (uid, ip, now_iso, now_iso, source, now_iso, now_iso)
                )
                outcome["results"][ip] = REC_NEW if cursor.rowcount == 1 else REC_EXTENDED

        conn.commit()

    except BaseException:

        try:
            conn.rollback()
        except Exception:
            pass

        raise

    for ip in todo:

        status = outcome["results"][ip]
        decision = outcome["decisions"].get(ip)

        if status == REC_CONFLICT:
            _emit(logger, "ENDPOINT_IDENTITY_CONFLICT",
                  _conflict_message(route, ip, decision.bound_uid, uid),
                  ("conflict", decision.bound_uid, uid, ip))
            continue

        _stamp(uid, ip, monotonic)
        outcome["recorded"] += 1

        if decision is not None and decision.outcome == IDENTITY_REASSIGNED:
            _emit(logger, "ENDPOINT_IDENTITY_REASSIGNED",
                  _conflict_message(route, ip, decision.bound_uid, uid),
                  ("reassigned", decision.bound_uid, uid, ip))

    return outcome


def log_event_conflict(logger, ip, bound_uid, asserted_uid, route="event"):

    # Used by the event path when its pre-check found a CONFLICT (the event is
    # stored with NULL uid; nothing is recorded).
    return _emit(logger, "ENDPOINT_IDENTITY_CONFLICT",
                 _conflict_message(route, ip, bound_uid, asserted_uid),
                 ("conflict", bound_uid, asserted_uid, ip))


def log_event_reassigned(logger, ip, previous_uid, asserted_uid, route="event"):

    return _emit(logger, "ENDPOINT_IDENTITY_REASSIGNED",
                 _conflict_message(route, ip, previous_uid, asserted_uid),
                 ("reassigned", previous_uid, asserted_uid, ip))


# --------------------------------------------------
# ENDPOINTS-ROW PRESENCE (heartbeat)
# --------------------------------------------------

_presence_lock = threading.Lock()
_last_presence = {}


def touch_endpoint_presence(conn, uid, ip, decision, now, min_interval=None, monotonic=time.monotonic):

    # Heartbeat presence for the endpoints row of the agent's PRIMARY ip:
    # a cheap throttled UPDATE of last_seen only (no reverse DNS, no hostname,
    # no username). Returns "MISSING" (no row: the caller creates it through the
    # normal save_endpoint), "SKIPPED" (conflict), "THROTTLED" or "UPDATED".
    # endpoints.endpoint_uid is set only when NULL - or replaced only for a
    # LAPSED binding (REASSIGNED) - never while another UID is bound.
    if decision is not None and decision.outcome == IDENTITY_CONFLICT:
        return "SKIPPED"

    min_interval = write_min_seconds() if min_interval is None else min_interval

    with _presence_lock:

        previous = _last_presence.get(ip)

        if previous is not None and min_interval > 0 and (monotonic() - previous) < min_interval:
            return "THROTTLED"

    row = conn.execute(
        "SELECT id, endpoint_uid FROM endpoints WHERE ip_address = ?", (ip,)
    ).fetchone()

    if row is None:
        return "MISSING"

    rebind = decision is not None and decision.outcome == IDENTITY_REASSIGNED
    local_now = _local_naive(now).strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("BEGIN IMMEDIATE")

    try:
        if rebind:
            conn.execute("UPDATE endpoints SET last_seen = ?, endpoint_uid = ? WHERE ip_address = ?",
                         (local_now, uid, ip))
        else:
            conn.execute("UPDATE endpoints SET last_seen = ?, endpoint_uid = COALESCE(endpoint_uid, ?) "
                         "WHERE ip_address = ?", (local_now, uid, ip))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise

    with _presence_lock:

        if len(_last_presence) > 4096:
            _last_presence.clear()

        _last_presence[ip] = monotonic()

    return "UPDATED"


# --------------------------------------------------
# HISTORY READ (Investigation)
# --------------------------------------------------

def endpoint_history_for_uid(conn, uid, limit=MAX_HISTORY_PANEL_ROWS):

    # Bounded, newest first. Returns [] for a malformed uid.
    uid = endpoint_identity.normalize_endpoint_uid(uid)

    if uid is None:
        return []

    limit = max(1, min(int(limit), 50))

    return [dict(r) for r in conn.execute(
        "SELECT id, endpoint_uid, ip_address, first_seen_at, last_seen_at, "
        "observation_count, source FROM endpoint_ip_history "
        "WHERE endpoint_uid = ? ORDER BY last_seen_at DESC, id DESC LIMIT ?",
        (uid, limit)
    ).fetchall()]


# --------------------------------------------------
# RESOLVER
# --------------------------------------------------

class ResolverInputError(ValueError):

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _seconds(delta):
    return round(delta.total_seconds(), 3)


def resolve_endpoint(ip_address, observed_at_utc, conn=None, now=None):

    # Which stable endpoint had `ip_address` at `observed_at_utc`?
    # Evidence = endpoint_ip_history ONLY. An interval is ACTIVE at t when
    #   first_seen_at - PRE_GRACE  <=  t  <=  last_seen_at + POST_GRACE
    #   EXACT      exactly one distinct UID is active
    #   AMBIGUOUS  two or more distinct UIDs are active (never picks one)
    #   STALE      the IP has history within the horizon but nothing is active
    #              at t (candidates only; NO uid is asserted)
    #   UNKNOWN    no history within the horizon
    # Raises ResolverInputError for an invalid IP, a naive / non-UTC-parseable
    # timestamp, or a timestamp too far in the future.
    ip = canonical_ip(ip_address)

    if ip is None:
        raise ResolverInputError("BAD_IP")

    if isinstance(observed_at_utc, datetime):

        if observed_at_utc.tzinfo is None:
            raise ResolverInputError("BAD_TIMESTAMP")

        t = sc.parse_utc(sc.format_utc(observed_at_utc))

    else:
        t = sc.parse_utc(observed_at_utc)

    if t is None:
        raise ResolverInputError("BAD_TIMESTAMP")

    now = now or sc.utc_now()

    if t > now + timedelta(seconds=sc.max_future_seconds()):
        raise ResolverInputError("OBSERVED_AT_FUTURE")

    pre = pre_grace_seconds()
    post = post_grace_seconds()
    horizon = timedelta(days=stale_horizon_days())

    query_from = sc.format_utc(t - horizon - timedelta(seconds=post))
    query_to = sc.format_utc(t + horizon + timedelta(seconds=pre))

    own = conn is None

    if own:
        conn = sd.get_db_connection()

    try:
        rows = conn.execute(
            "SELECT endpoint_uid, first_seen_at, last_seen_at, observation_count, source "
            "FROM endpoint_ip_history WHERE ip_address = ? AND last_seen_at >= ? AND first_seen_at <= ? "
            "ORDER BY last_seen_at DESC LIMIT ?",
            (ip, query_from, query_to, _MAX_RESOLVER_ROWS)
        ).fetchall()
    finally:
        if own:
            conn.close()

    candidates = []

    for uid, first, last, count, source in rows:

        first_dt, last_dt = sc.parse_utc(first), sc.parse_utc(last)

        w_start = first_dt - timedelta(seconds=pre)
        w_end = last_dt + timedelta(seconds=post)

        if t < w_start:
            distance = _seconds(w_start - t)
        elif t > w_end:
            distance = _seconds(t - w_end)
        else:
            distance = 0.0

        if first_dt <= t <= last_dt:
            position = "INSIDE_INTERVAL"
        elif distance == 0.0:
            position = "WITHIN_GRACE"
        else:
            position = "OUTSIDE"

        candidates.append({
            "endpoint_uid": uid, "first_seen_at": first, "last_seen_at": last,
            "observation_count": count, "source": source, "position": position,
            "seconds_from_window": distance,
            "_start": w_start, "_end": w_end,
        })

    active = [c for c in candidates if c["seconds_from_window"] == 0.0]
    active_uids = sorted({c["endpoint_uid"] for c in active})

    def clean(items):
        return [{k: v for k, v in c.items() if not k.startswith("_")} for c in items]

    config = {"pre_grace_s": pre, "post_grace_s": post, "horizon_days": stale_horizon_days()}

    if len(active_uids) == 1:

        status, uid, reason = RES_EXACT, active_uids[0], "SINGLE_ENDPOINT_ACTIVE"
        chosen = active
        window = {"start": sc.format_utc(min(c["_start"] for c in chosen)),
                  "end": sc.format_utc(max(c["_end"] for c in chosen)), **config}

    elif len(active_uids) >= 2:

        status, uid, reason = RES_AMBIGUOUS, None, "MULTIPLE_ENDPOINTS_ACTIVE"
        chosen = active
        window = {"start": sc.format_utc(min(c["_start"] for c in chosen)),
                  "end": sc.format_utc(max(c["_end"] for c in chosen)), **config}

    elif candidates:

        status, uid, reason = RES_STALE, None, "NO_ACTIVE_WINDOW"
        chosen = sorted(candidates, key=lambda c: c["seconds_from_window"])
        window = {"start": None, "end": None, **config}

    else:

        status, uid, reason = RES_UNKNOWN, None, "NO_HISTORY_WITHIN_HORIZON"
        chosen = []
        window = {"start": None, "end": None, **config}

    return {
        "status": status,
        "endpoint_uid": uid,
        "candidates": clean(chosen)[:MAX_CANDIDATES],
        "reason": reason,
        "evidence_window": window,
        "ip_address": ip,
        "observed_at": sc.format_utc(t),
    }


# --------------------------------------------------
# NORMALIZED-RECORD INTEGRATION (opt-in; never mandatory)
# --------------------------------------------------

_RESOLVABLE_FIELDS = ("src_ip", "dst_ip")


def apply_resolution(record, ip_field, conn=None, now=None):

    # Returns a NEW NormalizedRecord with the resolution status stored
    # honestly. The CALLER (future adapter / correlation logic) chooses whether
    # src_ip or dst_ip is the internal-endpoint candidate; 13C provides only
    # the primitive.
    #   EXACT                     -> endpoint_uid attached
    #   AMBIGUOUS / STALE / UNKNOWN -> NO uid; the status is recorded
    #   SENSOR_ASSERTED           -> returned UNCHANGED (never upgraded to EXACT)
    #   no address on the field   -> returned unchanged (NOT_ATTEMPTED)
    if ip_field not in _RESOLVABLE_FIELDS:
        raise ValueError("ip_field must be 'src_ip' or 'dst_ip'")

    if record.endpoint_resolution == sc.RESOLUTION_SENSOR_ASSERTED:
        return record

    ip = getattr(record, ip_field)

    if not ip:
        return record

    result = resolve_endpoint(ip, record.observed_at, conn=conn, now=now)

    return replace(
        record,
        endpoint_uid=result["endpoint_uid"] if result["status"] == RES_EXACT else None,
        endpoint_resolution=result["status"],
    )
