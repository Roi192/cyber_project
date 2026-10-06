# ==================================================
# STEP 24A: NATIVE MESSAGING HOST
# ==================================================
#
# Launched exclusively by Chrome/Edge via the native-messaging
# registration (see docs/STEP24A_PILOT_INSTALL.md). The browser itself
# enforces that ONLY the extension id(s) listed in this host's own
# manifest's "allowed_origins" may ever start this process or exchange
# messages with it - that is the authoritative "only the authorized
# extension may connect" guarantee asked for in Step 24A section 2 (the
# browser, not this script, owns that boundary). This script
# additionally, independently, validates every message's shape before
# forwarding anything - defense in depth, never a single layer of trust.
#
# This process is deliberately given NEITHER AGENT_API_KEY NOR the
# Agent's endpoint_uid/state file (Step 24A section 2's explicit
# instruction). It knows exactly one local-only secret, read from
# BROWSER_HOST_LOCAL_KEY_FILE (generated and owned by the Agent itself -
# see browser_agent_bridge.py), used only to authenticate itself to the
# Agent's loopback listener on 127.0.0.1. It holds no SOC credential and
# makes no direct network request to the SOC server.
#
# Protocol: standard Chrome/Edge native messaging framing on
# stdin/stdout - a 4-byte little-endian unsigned length prefix followed
# by that many bytes of UTF-8 JSON, in both directions. The process
# stays alive for the lifetime of the extension's connectNative() port
# and exits cleanly when that pipe closes.

import json
import os
import struct
import sys

import requests

MAX_INCOMING_MESSAGE_BYTES = 8 * 1024  # generous for one navigation event

LOCAL_HOST_KEY_FILE = os.getenv(
    "BROWSER_HOST_LOCAL_KEY_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_host_local.key")
).strip() or os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_host_local.key")

LOCAL_LISTENER_URL = os.getenv(
    "BROWSER_EVENT_LISTENER_URL",
    "http://127.0.0.1:56765/local/browser-event"
).strip() or "http://127.0.0.1:56765/local/browser-event"

LOCAL_REQUEST_TIMEOUT_SECONDS = 3

_REQUIRED_STRING_FIELDS = ("url", "browser_name", "nav_type")


def _read_local_host_key():

    try:
        with open(LOCAL_HOST_KEY_FILE, encoding="utf-8") as handle:
            key = handle.read().strip()
        return key or None
    except OSError:
        return None


def _read_message(stream):

    raw_length = stream.read(4)

    if len(raw_length) < 4:
        return None  # pipe closed - the extension disconnected

    (length,) = struct.unpack("<I", raw_length)

    if length == 0 or length > MAX_INCOMING_MESSAGE_BYTES:
        # Drain (bounded) rather than leave the pipe desynchronized,
        # then report a clean rejection instead of hanging.
        stream.read(min(length, MAX_INCOMING_MESSAGE_BYTES))
        return False

    raw_message = stream.read(length)

    try:
        return json.loads(raw_message.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False


def _write_message(stream, obj):

    encoded = json.dumps(obj).encode("utf-8")
    stream.write(struct.pack("<I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def _validate_message(data):

    if not isinstance(data, dict):
        return "payload must be a JSON object"

    for field in _REQUIRED_STRING_FIELDS:
        if not isinstance(data.get(field), str) or not data.get(field).strip():
            return f"{field} is required and must be a non-empty string"

    if len(data["url"]) > 2048:
        return "url exceeds the maximum allowed length"

    timestamp_ms = data.get("timestamp_ms")

    if (
        not isinstance(timestamp_ms, int)
        or isinstance(timestamp_ms, bool)
        or timestamp_ms <= 0
    ):
        return "timestamp_ms is required and must be a positive integer"

    if not isinstance(data.get("url_redacted"), bool):
        return "url_redacted is required and must be a boolean"

    return None


_UNSET = object()


def main(stdin=None, stdout=None, poster=None, local_key=_UNSET):

    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    poster = poster or requests.post

    # local_key is a 3-way parameter, not a 2-way one: omitted entirely
    # (the real, production call) reads the real key file; explicitly
    # None (tests only) simulates "no key available at all" without
    # touching the filesystem.
    local_key = _read_local_host_key() if local_key is _UNSET else local_key

    while True:

        message = _read_message(stdin)

        if message is None:
            return

        if message is False:
            _write_message(stdout, {"ok": False, "error": "malformed_message"})
            continue

        validation_error = _validate_message(message)

        if validation_error:
            _write_message(stdout, {"ok": False, "error": validation_error})
            continue

        if not local_key:
            _write_message(stdout, {"ok": False, "error": "agent_not_configured"})
            continue

        try:

            response = poster(
                LOCAL_LISTENER_URL,
                json=message,
                headers={"X-Local-Host-Key": local_key},
                timeout=LOCAL_REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code in (200, 202):
                _write_message(stdout, {"ok": True})
            else:
                _write_message(stdout, {"ok": False, "error": f"agent_rejected_{response.status_code}"})

        except requests.RequestException:
            # Agent not running / listener not up yet. Reported plainly
            # to the extension, which owns the bounded retry queue for
            # this case - see browser_extension/background.js.
            _write_message(stdout, {"ok": False, "error": "agent_unreachable"})


if __name__ == "__main__":
    main()
