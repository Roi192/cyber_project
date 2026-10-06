# ==================================================
# STEP 24B.2E: LOCAL THREAT INTELLIGENCE SCHEDULER
# ==================================================
#
# A standalone, independent process (run as `python local_feed_
# scheduler.py`, exactly like web_event_worker.py/threat_intel_worker.py
# /behavioral_worker.py) - NEVER a thread inside Flask, NEVER a thread
# inside web_event_worker.py's own loop, NEVER part of handling an
# HTTP request, NEVER part of the Agent. A real network download can
# take an unknown amount of time; running it anywhere inside an
# already-latency-sensitive process would be exactly the mistake the
# Step 24B.2 planning report's scheduler section warned against.
#
# DISABLED BY DEFAULT: if LOCAL_FEED_SCHEDULER_ENABLED is not exactly
# "true" (case-insensitive) in the environment, main() prints a single
# line and returns immediately - merely having this file on disk, or
# even starting the process, does nothing by itself. Nothing in this
# step starts this process live - see the Step 24B.2E report's own
# "not yet activated" section.
#
# SINGLE-INSTANCE OWNERSHIP: reuses local_feed_downloader.get_lock()
# (the EXACT SAME ownership-aware, crash-recovering lock proven in Step
# 24B.2D.1 - pid + pid_start_time + unique lock_id + race-safe orphan
# reclaim) under the reserved pseudo-provider name "__scheduler__" -
# zero new lock code, zero refactor of local_feed_downloader.py's lock
# internals. A second scheduler process started while one is already
# running exits immediately rather than running a redundant, racing
# loop (which would otherwise pollute attempt-state with spurious
# ConcurrentUpdateError "failures" every time both loops happened to
# wake up for the same provider at once).
#
# PER-PROVIDER FAILURE ISOLATION: run_once() iterates providers in a
# simple for-loop with its own try/except around each one - a provider
# whose download/parse/ingest fails (or whose per-provider download
# lock is busy - see local_feed_downloader.py's OWN, separate,
# per-provider lock) never prevents any OTHER provider in the same pass
# from being checked/updated. A provider's own failure is recorded via
# local_feed_attempt_store.LocalFeedAttemptStore by download_and_ingest()
# itself (unchanged from Step 24B.2D) - this module adds NOTHING to
# that recording path, only decides WHEN to call it and computes
# backoff/next-update timing.
#
# BACKOFF: deterministic, no jitter (not needed yet - see
# compute_backoff_multiplier). A successful update always resets
# consecutive_failures to 0 (local_feed_attempt_store.record_attempt_
# success() already does this, unchanged) - exponential growth starts
# fresh after every success.
#
# RESTART DURABILITY: this module keeps NO in-memory state across loop
# iterations beyond the lock itself - every decision in run_once() is
# recomputed FRESH, each time, purely from local_feed_attempt_store's
# on-disk JSON (durable) and local_feed_providers' static registry.
# A restarted scheduler therefore can never "forget" last_attempt,
# never resets failures by accident, and never fires an update before
# its properly-computed next_update_at - because there is nothing else
# it COULD compute from.
# ==================================================

import importlib
import os
import time
from datetime import datetime, timedelta

import local_feed_attempt_store
import local_feed_downloader
import local_feed_providers
import local_feed_store
import worker_status

WORKER_NAME = "local_feed_scheduler"
SCHEDULER_LOCK_NAME = "__scheduler__"

# How often the loop wakes up to check "is anything due" - NOT how
# often a download actually happens (that is governed entirely by each
# provider's own next_update_at). Deliberately modest - this is a
# cheap, local-only check (reads a few small JSON files), never a
# network call, so there is no "aggressive polling" concern even at
# this cadence; kept well above sub-second regardless.
POLL_INTERVAL_SECONDS = 60

DEFAULT_BASE_INTERVAL_HOURS = 1

# Backoff schedule (Step 24B.2E instructions - deterministic, no
# jitter): consecutive_failures=1 -> 1x base interval, 2 -> 2x,
# 3 -> 4x, 4 -> 8x, 5+ -> capped at MAX_BACKOFF_MULTIPLIER.
BACKOFF_BASE = 2
MAX_BACKOFF_MULTIPLIER = 16


def compute_backoff_multiplier(consecutive_failures):

    if consecutive_failures <= 0:
        return 1

    return min(BACKOFF_BASE ** (consecutive_failures - 1), MAX_BACKOFF_MULTIPLIER)


def compute_next_update_at(provider_meta, attempt_state, now=None):
    """
    Pure, deterministic, side-effect-free: given a provider's static
    registry metadata and its current (already-loaded) attempt state,
    returns the datetime at or after which an update attempt is due.
    Never performs I/O itself - callers pass in whatever they already
    read, so this is trivially unit-testable with synthetic inputs.
    """

    now = now or datetime.now()
    base_interval_hours = provider_meta.get("update_frequency_hours", DEFAULT_BASE_INTERVAL_HOURS)
    base_interval = timedelta(hours=base_interval_hours)

    if attempt_state.attempt_status == local_feed_attempt_store.STATUS_NEVER_ATTEMPTED:
        return now  # due immediately - a freshly-enabled provider is not made to wait a full interval

    if not attempt_state.last_attempt_at:
        return now  # defensive - should not normally happen once attempt_status is SUCCESS/FAILED

    last_attempt_dt = datetime.strptime(attempt_state.last_attempt_at, "%Y-%m-%d %H:%M:%S")

    if attempt_state.attempt_status == local_feed_attempt_store.STATUS_SUCCESS:
        return last_attempt_dt + base_interval

    # FAILED
    multiplier = compute_backoff_multiplier(attempt_state.consecutive_failures)
    return last_attempt_dt + base_interval * multiplier


def _resolve_parser(parser_module_name):

    module = importlib.import_module(parser_module_name)
    return module.parse_feed_bytes


def run_once(providers=None, base_dir=None, attempt_store=None, now=None):
    """
    One pass over every candidate provider. Returns a dict {provider:
    outcome_string} for observability/testing - never raises for a
    single provider's own failure (see the module header's failure-
    isolation guarantee). `providers`/`base_dir`/`attempt_store`/`now`
    are all injectable for deterministic testing - production calls
    (main()) leave them at their defaults.
    """

    now = now or datetime.now()
    attempt_store = attempt_store or local_feed_attempt_store.LocalFeedAttemptStore(base_dir=base_dir)
    providers = providers if providers is not None else local_feed_providers.known_providers()

    outcomes = {}

    for provider in providers:

        try:
            meta = local_feed_providers.get_provider_meta(provider)

            if not meta or not meta.get("implemented"):
                outcomes[provider] = "skipped_not_implemented"
                continue

            state = attempt_store.get_state(provider)

            if not state.enabled:
                outcomes[provider] = "skipped_disabled"
                continue

            if not meta.get("automatic_eligible"):
                outcomes[provider] = "skipped_not_automatic_eligible"
                continue

            next_update_at = compute_next_update_at(meta, state, now=now)

            if next_update_at > now:
                outcomes[provider] = "not_due"
                continue

            download_config = meta.get("download")

            if not download_config:
                outcomes[provider] = "skipped_no_download_config"
                continue

            try:
                parse_fn = _resolve_parser(meta.get("parser_module", ""))
            except Exception as exc:
                outcomes[provider] = f"skipped_parser_resolution_error:{type(exc).__name__}"
                continue

            try:
                local_feed_downloader.download_and_ingest(
                    provider, parse_fn, f"{provider}_scheduled_feed",
                    base_dir=base_dir, attempt_store=attempt_store,
                )
                outcomes[provider] = "updated"

            except local_feed_downloader.DownloadError as exc:
                # Already recorded (attempt_status=FAILED, reason,
                # category) by download_and_ingest()/its own internal
                # attempt_store.record_attempt_failure() call - nothing
                # further to record here. This includes
                # ConcurrentUpdateError (this provider's OWN per-
                # provider download lock busy - e.g. a manual trigger
                # already running) - never escalated, never blocks the
                # providers that follow in this same pass.
                outcomes[provider] = f"failed:{type(exc).__name__}"

        except Exception as exc:
            # Deliberately broad, deliberately the last line of defense:
            # an unexpected (non-DownloadError) exception for ONE
            # provider must never abort the pass or take down the
            # scheduler process - every other provider must still be
            # considered. This is intentionally NOT recorded via
            # attempt_store (that store's contract is "download/parse/
            # ingest outcomes", not "scheduler-internal bugs") - it is
            # surfaced only via this function's return value / the
            # caller's own logging.
            outcomes[provider] = f"unexpected_error:{type(exc).__name__}:{exc}"

    return outcomes


def main():

    enabled = os.getenv("LOCAL_FEED_SCHEDULER_ENABLED", "").strip().lower() == "true"

    if not enabled:
        print(
            f"[{WORKER_NAME}] LOCAL_FEED_SCHEDULER_ENABLED is not 'true' - "
            "exiting without doing anything (this is the default)."
        )
        return

    lock = local_feed_downloader.get_lock(SCHEDULER_LOCK_NAME)

    try:
        lock.acquire()
    except local_feed_downloader.ConcurrentUpdateError:
        print(f"[{WORKER_NAME}] another scheduler instance is already running - exiting.")
        return

    try:

        print(f"[{WORKER_NAME}] started.")
        print(f"[{WORKER_NAME}] checking for due providers every {POLL_INTERVAL_SECONDS}s.")

        while True:

            worker_status.heartbeat(WORKER_NAME)

            try:
                outcomes = run_once()

                for provider, outcome in outcomes.items():
                    if outcome not in ("not_due", "skipped_disabled", "skipped_not_automatic_eligible"):
                        print(f"[{WORKER_NAME}] {provider}: {outcome}", flush=True)

            except Exception as exc:
                # Last-resort guard around the whole pass - must never
                # crash the scheduler process itself.
                print(f"[{WORKER_NAME}] unexpected error in run_once(): {exc!r}", flush=True)

            time.sleep(POLL_INTERVAL_SECONDS)

    finally:
        lock.release()


if __name__ == "__main__":
    worker_status.run_guarded(WORKER_NAME, main)
