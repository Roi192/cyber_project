# ==================================================
# STAGE 25F PHASE 3: PURE CORRELATION-KEY FUNCTION
# ==================================================
#
# compute_correlation_key() is a PURE function: no database access, no
# network call, no side effect, deterministic (same inputs -> same
# output, every time, forever). It is NOT YET USED by any live code
# path - detection_engine.py / web_event_worker.py / app.py do not
# import this module. Wiring it into the live Detection Engine
# orchestration (so one correlation key anchors one decision across
# several rule findings) is Phase 4 - not approved yet, see the Stage
# 25F Phase 3 report.
#
# WHAT THE KEY IDENTIFIES (approved Stage 25F design refinement,
# section 2): a correlation SUBJECT - "this endpoint, this process-
# identity tier, this destination" - never a point in time. Two calls
# with the same inputs ALWAYS return the same key, no matter how much
# time has passed between them. Deciding whether a repeat occurrence
# continues an existing open decision or starts a fresh one is a
# SEPARATE concern, deliberately NOT implemented here - it reuses the
# existing detection_engine.DETECTION_DEDUP_WINDOW_MINUTES = 30 reopen
# rule, in Phase 4. See test_same_key_does_not_imply_same_open_decision
# in the test suite for why this distinction is tested even though the
# window logic itself does not live in this module.
#
# PROCESS TIER (approved design, reused verbatim - see each branch):
#   CONFIRMED + a valid (64-hex-char) process_instance_id -> proc:<id>
#   CONFIRMED but NO valid process_instance_id (a status/data mismatch)
#     -> conservative fallback to UNAVAILABLE. Defensive rule,
#     explicitly required: a claimed CONFIRMED status must never
#     produce a CONFIRMED-shaped key without a real id behind it.
#   PENDING                                    -> proc:PENDING
#   UNAVAILABLE / missing / unrecognized status -> proc:UNAVAILABLE
#   event_source in NOT_APPLICABLE_EVENT_SOURCES (browser events, which
#     never have a process concept at all) -> proc:NOT_APPLICABLE,
#     checked FIRST - wins even over a (mistaken) CONFIRMED status/id
#     passed alongside it.
#
# SURICATA EVIDENCE: this function has NO Suricata-specific branch -
# deliberately. Per the approved design, Suricata evidence must inherit
# its process tier ONLY from the web_event it was confidently
# (CONFIRMED) matched to by suricata_endpoint_correlation.
# find_related_web_event() - never invented from IP evidence alone. A
# future caller correlating Suricata evidence must therefore call this
# function with either:
#   - that MATCHED web_event's own process_correlation_status/
#     process_instance_id, when find_related_web_event() returned
#     "CONFIRMED" (a single unambiguous match), or
#   - process_correlation_status=process_correlation.CORRELATION_
#     UNAVAILABLE, when find_related_web_event() returned "UNRESOLVED"
#     (zero or multiple candidates - a genuine ambiguity, never guessed)
# This caller discipline belongs to Phase 4; this module only documents
# and unit-tests it (see the Suricata-labelled tests).
# ==================================================

import hashlib
import ipaddress

import process_correlation
from endpoint_identity import normalize_endpoint_uid
from web_monitoring import SHA256_PATTERN

TOKEN_PENDING = "proc:PENDING"
TOKEN_UNAVAILABLE = "proc:UNAVAILABLE"
TOKEN_NOT_APPLICABLE = "proc:NOT_APPLICABLE"

# event_source values - matching web_events.source's OWN existing
# vocabulary ("endpoint-agent" / "browser-extension"), never a second,
# parallel vocabulary - that mean "process correlation does not apply
# to this event type at all", regardless of whatever process_
# correlation_status/process_instance_id was also passed.
NOT_APPLICABLE_EVENT_SOURCES = frozenset({"browser-extension"})


def _valid_process_instance_id(process_instance_id):

    return (
        isinstance(process_instance_id, str)
        and bool(SHA256_PATTERN.match(process_instance_id))
    )


def _process_tier_token(process_correlation_status, process_instance_id, event_source):

    if event_source in NOT_APPLICABLE_EVENT_SOURCES:
        return TOKEN_NOT_APPLICABLE

    if process_correlation_status == process_correlation.CORRELATION_CONFIRMED:

        if _valid_process_instance_id(process_instance_id):
            return f"proc:{process_instance_id}"

        # Defensive rule (explicitly required): a status claiming
        # CONFIRMED without a valid process_instance_id must NEVER
        # produce a CONFIRMED-shaped key - fall back conservatively.
        return TOKEN_UNAVAILABLE

    if process_correlation_status == process_correlation.CORRELATION_PENDING:
        return TOKEN_PENDING

    # CORRELATION_UNAVAILABLE, None, or any unrecognized value - never
    # guessed, always the most conservative tier.
    return TOKEN_UNAVAILABLE


def _normalize_destination_key(destination_key):
    """
    destination_key is expected to already be RESOLVED by the caller
    (a domain or IP literal string) via the project's existing
    normalize_destination()/"destination_label" convention
    (web_event_worker.py: `domain or resolved_ip or destination`).

    This function performs NO DNS lookup - that would be a side effect
    and a source of non-determinism a pure function must not have. It
    only re-applies the same non-network-dependent normalization rules
    normalize_destination() (web_monitoring.py) itself already uses on
    its own `host` value, so equivalent representations of the same
    destination collide and different ones do not:
      - an IP literal is canonicalized via ipaddress.ip_address() ->
        str() (the same technique endpoint_network.py/security_
        resolution.py already standardize on elsewhere in this
        project) - this also collapses equivalent expanded/compressed
        IPv6 forms, not merely letter case.
      - a domain is lowercased and has trailing dots stripped - the
        exact same two rules normalize_destination() applies.
    """

    if not destination_key or not isinstance(destination_key, str):
        return None

    value = destination_key.strip()

    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    return value.lower().strip(".")


def compute_correlation_key(
    endpoint_uid,
    process_correlation_status,
    process_instance_id,
    destination_key,
    event_source=None
):
    """
    Pure, deterministic, side-effect-free - no DB access, no network
    call. Returns a 64-char hex SHA-256 string identifying the
    correlation SUBJECT (endpoint + process tier + destination) - never
    a point in time (see module header) - or None when a correlation
    identity cannot be deterministically formed (missing/malformed
    endpoint_uid, or no derivable destination). "Never invent a
    correlation key" - the same Stage 25F Phase 2 principle, carried
    into this pure function.

    NOT YET CALLED by any live code path - see the Phase 3 report.
    """

    normalized_uid = normalize_endpoint_uid(endpoint_uid)

    if not normalized_uid:
        return None

    normalized_destination = _normalize_destination_key(destination_key)

    if not normalized_destination:
        return None

    tier_token = _process_tier_token(process_correlation_status, process_instance_id, event_source)

    raw = "|".join([normalized_uid, tier_token, normalized_destination])

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def tier_allows_process_identity_claim(process_correlation_status, process_instance_id, event_source=None):
    """
    Returns True ONLY when the correlation tier is CONFIRMED with a
    genuinely valid process_instance_id - the single, sole condition
    under which any future explanation/evidence text (Phase 4+) is
    allowed to assert that a SPECIFIC process performed the activity.

    PENDING, UNAVAILABLE, NOT_APPLICABLE, and an unresolved/ambiguous
    Suricata-derived tier must never claim a specific process - this
    predicate is the single source of truth a future caller should
    check before writing such text, rather than re-deriving the same
    CONFIRMED-with-a-valid-id condition independently in several
    places (and risking the two drifting apart).

    Does not redesign or touch any UI text itself (Phase 3 scope).
    """

    if event_source in NOT_APPLICABLE_EVENT_SOURCES:
        return False

    return (
        process_correlation_status == process_correlation.CORRELATION_CONFIRMED
        and _valid_process_instance_id(process_instance_id)
    )
