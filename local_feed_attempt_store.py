# ==================================================
# STEP 24B.2D: LOCAL FEED UPDATE-ATTEMPT STATE
# ==================================================
#
# Tracks the OUTCOME OF UPDATE ATTEMPTS (download/parse/ingest cycles),
# a completely separate axis from local_feed_store.get_feed_status()'s
# DATA FRESHNESS (NEVER_LOADED/CURRENT/STALE). The two must never be
# conflated: a provider's last download can FAIL while its previously-
# activated snapshot remains perfectly valid and CURRENT/STALE - this
# store exists specifically to make that distinction observable without
# touching local_feed_store.py's activation logic at all.
#
# `enabled` is tracked SEPARATELY from `attempt_status` (corrected
# design, Step 24B.2D instructions): disabling a provider is an
# operator decision about whether it should be attempted at all, and
# must never erase the meaning of what the LAST attempt (before being
# disabled) actually was. attempt_status is only ever NEVER_ATTEMPTED /
# SUCCESS / FAILED - there is no DISABLED value mixed into it.
#
# This module is a narrow ABSTRACTION (LocalFeedAttemptStore) - callers
# (local_feed_downloader.py, and later a scheduler/dashboard) never read
# or write attempt_state.json directly. The JSON-file backend is an
# implementation detail that may change (e.g. to a DB table) without
# any caller needing to change, as long as the same API is kept. No DB
# schema is added in this step, per the explicit instruction.
# ==================================================

import json
import os
import tempfile
import time
from datetime import datetime

import local_feed_store

STATUS_NEVER_ATTEMPTED = "NEVER_ATTEMPTED"
STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"

_VALID_STATUSES = (STATUS_NEVER_ATTEMPTED, STATUS_SUCCESS, STATUS_FAILED)

_STATE_FILENAME = "attempt_state.json"


class AttemptState:

    def __init__(self, enabled=True, attempt_status=STATUS_NEVER_ATTEMPTED,
                 last_attempt_at=None, last_success_at=None,
                 failure_reason=None, failure_category=None,
                 consecutive_failures=0):

        self.enabled = bool(enabled)
        self.attempt_status = attempt_status if attempt_status in _VALID_STATUSES else STATUS_NEVER_ATTEMPTED
        self.last_attempt_at = last_attempt_at
        self.last_success_at = last_success_at
        self.failure_reason = failure_reason
        self.failure_category = failure_category
        self.consecutive_failures = int(consecutive_failures or 0)

    def to_dict(self):
        return {
            "enabled": self.enabled,
            "attempt_status": self.attempt_status,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "failure_reason": self.failure_reason,
            "failure_category": self.failure_category,
            "consecutive_failures": self.consecutive_failures,
        }

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            return cls()
        return cls(
            enabled=data.get("enabled", True),
            attempt_status=data.get("attempt_status", STATUS_NEVER_ATTEMPTED),
            last_attempt_at=data.get("last_attempt_at"),
            last_success_at=data.get("last_success_at"),
            failure_reason=data.get("failure_reason"),
            failure_category=data.get("failure_category"),
            consecutive_failures=data.get("consecutive_failures", 0),
        )

    def __repr__(self):
        return f"AttemptState({self.to_dict()!r})"


def _atomic_write_json(path, data, retries=3, retry_delay_seconds=0.05):

    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix="attempt_state_", suffix=".json.tmp", dir=directory)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        last_error = None

        for attempt in range(retries):
            try:
                os.replace(tmp_path, path)
                return
            except OSError as exc:
                last_error = exc
                if attempt < retries - 1:
                    time.sleep(retry_delay_seconds)

        raise OSError(f"Failed to write {path!r} after {retries} attempts: {last_error!r}")

    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


class LocalFeedAttemptStore:
    """
    The ONLY sanctioned way to read/write a provider's update-attempt
    state. Backend is an atomically-written JSON file (same temp-file +
    os.replace + bounded-retry convention as local_feed_store.py's
    pointer file) colocated in the provider's own directory via
    local_feed_store.get_provider_dir() - never a path this module
    computes independently.
    """

    def __init__(self, base_dir=None):
        self._base_dir = base_dir

    def _state_path(self, provider):
        return os.path.join(
            local_feed_store.get_provider_dir(provider, self._base_dir), _STATE_FILENAME
        )

    def get_state(self, provider):

        path = self._state_path(provider)

        if not os.path.isfile(path):
            return AttemptState()

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return AttemptState()

        return AttemptState.from_dict(data)

    def _write_state(self, provider, state):
        _atomic_write_json(self._state_path(provider), state.to_dict())

    def set_enabled(self, provider, enabled):

        state = self.get_state(provider)
        state.enabled = bool(enabled)
        self._write_state(provider, state)
        return state

    def record_attempt_failure(self, provider, reason, category, now=None):

        now = now or datetime.now()
        state = self.get_state(provider)

        state.attempt_status = STATUS_FAILED
        state.last_attempt_at = now.strftime("%Y-%m-%d %H:%M:%S")
        state.failure_reason = str(reason) if reason is not None else None
        state.failure_category = category
        state.consecutive_failures += 1

        self._write_state(provider, state)
        return state

    def record_attempt_success(self, provider, now=None):

        now = now or datetime.now()
        state = self.get_state(provider)

        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

        state.attempt_status = STATUS_SUCCESS
        state.last_attempt_at = timestamp
        state.last_success_at = timestamp
        state.failure_reason = None
        state.failure_category = None
        state.consecutive_failures = 0

        self._write_state(provider, state)
        return state
