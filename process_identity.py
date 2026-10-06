# ==================================================
# STEP 25A: PROCESS INSTANCE IDENTITY
# ==================================================
#
# A single pid is NOT a stable process identity - Windows reuses pids
# (the exact same lesson already learned and tested in Step 24B.2D.1
# for lock-file ownership). process_instance_id is derived from
# (endpoint_uid, pid, process_create_time) - process_create_time (from
# psutil.Process.create_time(), confirmed stable/identical across
# repeated reads of the SAME still-alive process - see the Step 25A
# report) is what makes two DIFFERENT processes that happen to reuse
# the same pid resolve to two DIFFERENT instance ids.
#
# Used identically on BOTH sides (Agent computes it when reporting;
# the server INDEPENDENTLY RECOMPUTES it from the same three raw
# fields and never trusts a client-submitted id blindly - see
# process_events.py) - the same "normalize/derive the same way on both
# sides" principle already used for local_feed_normalize.py and
# browser_events.py's url_dedup_key.
#
# SHA-256 (not a raw concatenation) so the stored identifier is a
# fixed-length, opaque token - it reveals nothing about the endpoint_uid/
# pid/create_time it was derived from, and is a clean primary-key-
# shaped value.
# ==================================================

import hashlib

# process_create_time is a float (seconds since epoch, machine-
# dependent sub-second precision) - rounded to a fixed precision before
# hashing so that two independent reads of the SAME live process (by
# the agent, possibly in different polling cycles) are GUARANTEED to
# produce byte-identical input to the hash, never drifting by floating-
# point representation noise.
_CREATE_TIME_PRECISION = 6


def compute_process_instance_id(endpoint_uid, pid, process_create_time):
    """
    Returns a 64-character hex SHA-256 string, or None if any input is
    missing/invalid - never fabricates an id from incomplete data.
    """

    if not endpoint_uid or not isinstance(endpoint_uid, str):
        return None

    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return None

    if pid_int <= 0:
        return None

    try:
        create_time_float = float(process_create_time)
    except (TypeError, ValueError):
        return None

    normalized_create_time = f"{create_time_float:.{_CREATE_TIME_PRECISION}f}"

    raw = f"{endpoint_uid}|{pid_int}|{normalized_create_time}"

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
