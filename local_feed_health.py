# ==================================================
# STEP 24B.2E: LOCAL THREAT INTELLIGENCE FEED HEALTH
# ==================================================
#
# Pure, read-only AGGREGATION over three already-existing, independent
# sources - this module introduces no new state and no new storage:
#   - local_feed_store.get_feed_status()      -> DATA status
#     (NEVER_LOADED / CURRENT / STALE) - unchanged, Step 24B.2A.
#   - local_feed_attempt_store.LocalFeedAttemptStore.get_state()
#                                              -> UPDATE status
#     (NEVER_ATTEMPTED / SUCCESS / FAILED) + enabled - unchanged,
#     Step 24B.2D.
#   - local_feed_providers.LOCAL_FEED_PROVIDER_REGISTRY
#                                              -> static metadata
#     (automatic_eligible, update_frequency_hours, licensing fields).
#
# DATA status and UPDATE status and `enabled` are three DELIBERATELY
# SEPARATE fields, never merged into one value - a manager must be able
# to see "CURRENT data, but the last refresh attempt FAILED" without
# that being collapsed into either "it's fine" or "it's broken" on its
# own; see classify_health()'s own docstring for the exact, documented
# decision table built on top of these three facts.
#
# This module never performs a live lookup, a network request, or a
# write of any kind - it only reads what local_feed_store/local_feed_
# attempt_store/local_feed_providers already expose.
# ==================================================

from datetime import datetime

import local_feed_attempt_store
import local_feed_providers
import local_feed_scheduler
import local_feed_store

HEALTH_HEALTHY = "HEALTHY"
HEALTH_ATTENTION = "ATTENTION"
HEALTH_PROBLEM = "PROBLEM"

_ALL_HEALTH_VALUES = (HEALTH_HEALTHY, HEALTH_ATTENTION, HEALTH_PROBLEM)


def classify_health(enabled, data_status, update_status):
    """
    Deterministic, documented decision table (Step 24B.2E instructions)
    over exactly these three already-separate facts - never anything
    else (not indicator count, not snapshot age directly, not which
    provider it is):

        enabled | data_status   | update_status           | health
        --------+---------------+--------------------------+----------
        False   | *             | *                        | HEALTHY
          (deliberately inactive is not a problem - see the module
           header; the separate `enabled` field already shows this
           honestly next to the health label, nothing is hidden)
        True    | NEVER_LOADED  | *                        | PROBLEM
          (enabled but has never served any data at all)
        True    | CURRENT       | SUCCESS / NEVER_ATTEMPTED | HEALTHY
        True    | CURRENT       | FAILED                   | ATTENTION
          (still serving valid, current data - NOT broken - but the
           most recent refresh attempt did not succeed; worth a look,
           not urgent)
        True    | STALE         | SUCCESS / NEVER_ATTEMPTED | ATTENTION
          (data has aged past its freshness threshold, but there is no
           active failure on record - e.g. simply not refreshed yet)
        True    | STALE         | FAILED                   | PROBLEM
          (aged data AND the refresh is actively failing - compounding)

    Returns one of HEALTH_HEALTHY/HEALTH_ATTENTION/HEALTH_PROBLEM -
    always exactly one of these three; NEVER_LOADED+disabled and every
    other combination not listed above still resolves through this
    same table (disabled always short-circuits to HEALTHY first).
    """

    if not enabled:
        return HEALTH_HEALTHY

    if data_status == "NEVER_LOADED":
        return HEALTH_PROBLEM

    if data_status == "CURRENT":
        return HEALTH_ATTENTION if update_status == "FAILED" else HEALTH_HEALTHY

    if data_status == "STALE":
        return HEALTH_PROBLEM if update_status == "FAILED" else HEALTH_ATTENTION

    # Any future/unrecognized data_status value - fail toward visibility,
    # never silently HEALTHY.
    return HEALTH_ATTENTION


_FRIENDLY_FAILURE_LABELS = {
    "TransportError": "Network or connection problem",
    "RedirectPolicyError": "Feed source redirected somewhere unexpected and was blocked for safety",
    "SizeLimitError": "Feed data was larger than the configured safe limit",
    "ContentTypeError": "Feed source returned unexpected content",
    "DecompressionError": "Feed file could not be decompressed correctly",
    "ParseError": "Feed data could not be read in the expected format",
    "ConcurrentUpdateError": "An update was already in progress",
    "ConfigurationError": "This feed source is not fully configured",
    "InsecureInitialUrlError": "Feed source is not using a secure (HTTPS) connection",
}


def friendly_failure_label(failure_category):
    """
    Manager-facing wording for a failure_category - NEVER a raw
    exception class name or traceback. Unknown/future categories fall
    back to a generic, still-honest label rather than exposing
    internals.
    """

    if not failure_category:
        return None

    return _FRIENDLY_FAILURE_LABELS.get(failure_category, "Update failed (technical details available to analysts)")


def get_provider_health(provider, base_dir=None, now=None, stale_after_hours=None):
    """
    Assembles the full observability record for one provider, per the
    Step 24B.2E field list. Never raises on a missing/never-loaded/
    never-attempted provider - every field degrades to None/0/a
    documented default rather than an exception, since "nothing has
    ever happened for this provider" is an entirely normal, expected
    state (NEVER_LOADED + NEVER_ATTEMPTED), not an error condition.
    """

    now = now or datetime.now()
    meta = local_feed_providers.get_provider_meta(provider) or {}

    feed_status_kwargs = {}
    if stale_after_hours is not None:
        feed_status_kwargs["stale_after_hours"] = stale_after_hours

    data_status_info = local_feed_store.get_feed_status(provider, base_dir=base_dir, now=now, **feed_status_kwargs)

    attempt_store = local_feed_attempt_store.LocalFeedAttemptStore(base_dir=base_dir)
    attempt_state = attempt_store.get_state(provider)

    snapshot_age_seconds = None
    if data_status_info.get("local_imported_at"):
        try:
            imported_dt = datetime.strptime(data_status_info["local_imported_at"], "%Y-%m-%d %H:%M:%S")
            snapshot_age_seconds = (now - imported_dt).total_seconds()
        except ValueError:
            snapshot_age_seconds = None

    next_update_at = None
    try:
        next_update_at = local_feed_scheduler.compute_next_update_at(meta, attempt_state, now=now)
    except Exception:
        next_update_at = None

    health = classify_health(attempt_state.enabled, data_status_info["status"], attempt_state.attempt_status)

    return {
        "provider": provider,
        "feed_name": data_status_info.get("feed_name"),
        "enabled": attempt_state.enabled,
        "automatic_eligible": bool(meta.get("automatic_eligible")),
        "data_status": data_status_info["status"],
        "update_status": attempt_state.attempt_status,
        "health": health,
        "current_version": data_status_info.get("version"),
        "indicator_count": data_status_info.get("row_count"),
        "last_successful_update": attempt_state.last_success_at,
        "last_update_attempt": attempt_state.last_attempt_at,
        "next_scheduled_attempt": next_update_at.strftime("%Y-%m-%d %H:%M:%S") if next_update_at else None,
        "snapshot_age_seconds": snapshot_age_seconds,
        "freshness_threshold_hours": stale_after_hours
            if stale_after_hours is not None else local_feed_store.DEFAULT_STALE_AFTER_HOURS,
        "consecutive_failures": attempt_state.consecutive_failures,
        "failure_category": attempt_state.failure_category,
        "failure_category_friendly": friendly_failure_label(attempt_state.failure_category),
        "failure_reason": attempt_state.failure_reason,
        "commercial_use_ok": meta.get("commercial_use_ok"),
        "license_note": meta.get("license_note"),
        "requires_attribution": meta.get("requires_attribution"),
    }


def get_all_provider_health(base_dir=None, now=None):
    """Returns a list of get_provider_health() records, one per
    registered provider (known_providers() order)."""

    now = now or datetime.now()
    return [
        get_provider_health(provider, base_dir=base_dir, now=now)
        for provider in local_feed_providers.known_providers()
    ]


def aggregate_system_health(provider_health_records):
    """
    System-wide roll-up for the manager-facing headline. Disabled
    providers are EXCLUDED from this computation entirely (never drag
    the aggregate down, per the Step 24B.2E instructions) - not merely
    "treated as healthy", genuinely left out of consideration, which
    also makes the "nothing is enabled at all" case distinguishable.
    """

    enabled_records = [r for r in provider_health_records if r["enabled"]]

    if not enabled_records:
        return HEALTH_ATTENTION  # no active source at all - worth noting, not necessarily a hard failure

    if any(r["health"] == HEALTH_PROBLEM for r in enabled_records):
        return HEALTH_PROBLEM

    if any(r["health"] == HEALTH_ATTENTION for r in enabled_records):
        return HEALTH_ATTENTION

    return HEALTH_HEALTHY
