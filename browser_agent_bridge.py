# ==================================================
# STEP 24A: AGENT <-> NATIVE-MESSAGING-HOST LOCAL BRIDGE
# ==================================================
#
# This module is imported ONLY by endpoint_agent_stable.py. It gives the
# browser_native_host.py process (launched by Chrome/Edge, holding NEITHER
# AGENT_API_KEY nor the Agent's endpoint_uid state file - see that file's
# module docstring) a narrow, purely-local way to hand a browser-reported
# URL event to the already-running Agent process, which then forwards it
# to the SOC server over the Agent's EXISTING authenticated channel.
#
# Trust model (Step 24A section 2's "define a secure local communication
# mechanism - do not assume one already exists"):
#   - A random, local-only secret (BROWSER_HOST_LOCAL_KEY) is generated
#     once per Agent installation and persisted next to the Agent, in a
#     file the native host is told to read (its OWN config, set up by the
#     installer script - see docs/STEP24A_PILOT_INSTALL.md). This secret
#     is NEVER AGENT_API_KEY and the native host is never given
#     AGENT_API_KEY or endpoint_agent_state.json.
#   - The Agent listens on 127.0.0.1 ONLY (never 0.0.0.0) on a fixed local
#     port. A request without the correct X-Local-Host-Key header
#     (checked with hmac.compare_digest) is rejected with 401 and never
#     reaches the send queue.
#   - The Agent is the ONLY thing that ever calls the SOC server's
#     /api/browser-events; the secret above never leaves this machine and
#     is unrelated to the SOC server's own credential.

import hmac
import json
import os
import re
import secrets
import time

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCAL_LISTENER_HOST = "127.0.0.1"

LOCAL_LISTENER_PORT = int(
    os.getenv("BROWSER_EVENT_LISTENER_PORT", "56765").strip() or "56765"
)

LOCAL_HOST_KEY_FILE = os.getenv(
    "BROWSER_HOST_LOCAL_KEY_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_host_local.key")
).strip() or os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_host_local.key")

# A single browser navigation event as JSON is a handful of short fields -
# generous headroom while still blocking an abusive/malformed body.
MAX_REQUEST_BODY_BYTES = 8 * 1024

_REQUIRED_STRING_FIELDS = ("url", "browser_name", "nav_type")


def load_or_create_local_host_key(path=None):
    """
    Returns the local-only shared secret used ONLY between this Agent
    process and browser_native_host.py on the same machine. Generated
    once (secrets.token_urlsafe, 32 bytes of entropy) and persisted;
    never derived from, and never written alongside, endpoint_uid or any
    SOC credential. A malformed file is set aside (never silently
    deleted) exactly like load_or_create_endpoint_uid's own convention.
    """

    key_path = path or LOCAL_HOST_KEY_FILE

    try:
        with open(key_path, encoding="utf-8") as handle:
            existing = handle.read().strip()
        if existing:
            return existing
    except FileNotFoundError:
        pass
    except OSError:
        pass

    new_key = secrets.token_urlsafe(32)

    tmp_path = key_path + ".tmp"

    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(new_key)

    os.replace(tmp_path, key_path)

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        # Best-effort on platforms/filesystems where POSIX chmod bits
        # are not meaningful (e.g. most Windows filesystems) - the
        # directory-level access control already protecting
        # endpoint_agent_state.json is the real boundary here, exactly
        # as already accepted project-wide for that file.
        pass

    return new_key


def _validate_event_payload(data):
    """
    Minimal, defense-in-depth shape check performed by the Agent before
    ever queuing an event for the SOC server - the SOC server
    (browser_events.py) independently re-validates everything in full;
    this only protects the local queue from obviously malformed input.
    Returns an error string, or None if the payload is acceptable.
    """

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


def _make_handler_class(local_key, browser_event_queue):

    class _Handler(BaseHTTPRequestHandler):

        # Silence the default per-request stderr access log - this is a
        # purely local, high-frequency channel; noisy logging here would
        # drown out the Agent's existing, meaningful console output.
        def log_message(self, format_str, *args):
            return

        def _reply(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):

            # The request body MUST be drained from the socket before
            # this handler returns, on EVERY path (even a 401/404/400
            # short-circuit) - BaseHTTPRequestHandler closes the
            # connection once the response is sent, and closing a
            # socket with unread, already-buffered inbound bytes still
            # pending causes the OS to send a TCP RST instead of a
            # clean FIN (reproduced on Windows: the client's NEXT
            # connection to this same server then fails with
            # ConnectionResetError, even though that next connection is
            # otherwise unrelated). Reading up front, before any other
            # check, avoids this entirely.
            try:
                declared_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                declared_length = 0

            if 0 < declared_length <= MAX_REQUEST_BODY_BYTES:
                raw_body = self.rfile.read(declared_length)
            else:
                # Still drain whatever is actually bounded-readable so
                # the connection can close cleanly, even though this
                # request will be rejected below.
                raw_body = self.rfile.read(min(max(declared_length, 0), MAX_REQUEST_BODY_BYTES))

            if self.path != "/local/browser-event":
                self._reply(404, {"ok": False, "error": "not_found"})
                return

            supplied_key = self.headers.get("X-Local-Host-Key", "")

            if not hmac.compare_digest(supplied_key, local_key):
                self._reply(401, {"ok": False, "error": "unauthorized"})
                return

            if declared_length <= 0 or declared_length > MAX_REQUEST_BODY_BYTES:
                self._reply(400, {"ok": False, "error": "body_too_large_or_empty"})
                return

            try:
                data = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._reply(400, {"ok": False, "error": "malformed_json"})
                return

            validation_error = _validate_event_payload(data)

            if validation_error:
                self._reply(400, {"ok": False, "error": validation_error})
                return

            try:
                browser_event_queue.put_nowait(data)
            except Exception:
                # Bounded queue is full (SOC/Agent-side backlog) - tell
                # the host plainly rather than blocking this request or
                # silently dropping without a signal the host can log.
                self._reply(503, {"ok": False, "error": "agent_busy"})
                return

            self._reply(202, {"ok": True})

    return _Handler


def start_browser_event_listener(browser_event_queue, local_key=None, port=None):
    """
    Starts the loopback-only HTTP listener in a background daemon thread
    and returns the server instance (callers do not need to keep it, but
    may use it to shut down cleanly in tests). Binds 127.0.0.1 ONLY -
    never 0.0.0.0 - matching this project's existing documented stance
    that the Flask server itself must never face a network it isn't
    explicitly configured for.
    """

    import threading

    # Step 24A.3 bugfix: `port or LOCAL_LISTENER_PORT` silently ignored an
    # explicit `port=0` (Python's `0 or x` evaluates `x`, since 0 is
    # falsy) - a caller asking for "let the OS assign an ephemeral port"
    # (0 is the standard socket-API meaning of that) would instead
    # always get the real production port 56765, which can collide with
    # an actually-running Agent. Caught by a real-system test run while
    # the live Agent held that port - a test using 0 to get an isolated
    # port silently bound 56765 instead. `is None` treats 0 as the
    # meaningful value it is.
    key = local_key or load_or_create_local_host_key()
    listen_port = LOCAL_LISTENER_PORT if port is None else port

    handler_class = _make_handler_class(key, browser_event_queue)

    # Step 24A.1 Part B finding: http.server's HTTPServer/ThreadingHTTPServer
    # default allow_reuse_address=True (SO_REUSEADDR). On Windows this does
    # NOT just mean "fast restart after a clean shutdown" - it allows a
    # SECOND, completely independent process to silently bind the SAME
    # port while a first instance is still actively listening on it,
    # which would let a second Agent instance (exactly the kind of
    # duplicate process flagged by the Step 24A.1 process audit) steal
    # this security-sensitive local control channel without any error
    # at all. Forced off here deliberately: a genuine port conflict must
    # fail loudly (OSError, caught in endpoint_agent_stable.py's
    # try/except) rather than silently produce two competing listeners.
    class _ReuseDisabledServer(ThreadingHTTPServer):
        allow_reuse_address = False

    server = _ReuseDisabledServer((LOCAL_LISTENER_HOST, listen_port), handler_class)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    return server


def browser_sender_worker(
    browser_event_queue,
    endpoint_uid,
    soc_server,
    agent_api_key,
    http_timeout_seconds,
    auth_error_backoff_seconds,
    send_delay_seconds,
    post=None
):
    """
    Pulls validated browser-navigation events off the local queue and
    forwards them to the SOC server's /api/browser-events, attaching this
    installation's endpoint_uid, using the SAME X-Agent-Key credential
    and the same timeout/backoff conventions as send_event_to_soc() for
    ordinary TCP events. Runs forever in its own daemon thread - intended
    to be started from endpoint_agent_stable.main() alongside the
    existing sender/command/heartbeat threads.
    """

    post = post or __import__("requests").post

    while True:

        event = browser_event_queue.get()

        try:

            payload = dict(event)
            payload["endpoint_uid"] = endpoint_uid

            try:

                response = post(
                    f"{soc_server}/api/browser-events",
                    json=payload,
                    headers={"X-Agent-Key": agent_api_key},
                    timeout=http_timeout_seconds
                )

                if response.status_code in (401, 403):

                    print(
                        "[BROWSER EVENT AUTH ERROR] SOC rejected Agent "
                        "authentication. Check AGENT_API_KEY in .env."
                    )

                    time.sleep(auth_error_backoff_seconds)
                    continue

                if response.ok:

                    data = response.json()

                    print(
                        "[BROWSER EVENT SENT]",
                        payload.get("browser_name"),
                        "|",
                        payload.get("url"),
                        "|",
                        data.get("status")
                    )

                else:

                    print(
                        "[BROWSER EVENT SOC ERROR]",
                        response.status_code,
                        response.text[:300]
                    )

            except Exception as exc:

                # Deliberately broad: a transient DNS failure, a refused
                # connection (SOC offline) or a timeout must never crash
                # this worker thread - the event is simply dropped for
                # this attempt (the extension-side retry queue, not this
                # one, is responsible for redelivery across an Agent/SOC
                # outage - see browser_extension/background.js). This is
                # a known, documented v1 limitation, not a silent one.
                print(
                    "[BROWSER EVENT CONNECTION ERROR]",
                    exc
                )

            time.sleep(send_delay_seconds)

        finally:
            browser_event_queue.task_done()
