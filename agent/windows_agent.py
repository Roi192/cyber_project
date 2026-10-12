#!/usr/bin/env python
"""Website Monitor - lightweight Windows network agent (Phase 5.2 prototype).

A second telemetry source next to the browser extension. It tells the central server what this
computer's programs contact. The server does the reputation check; the agent never talks to
VirusTotal and never holds its key. Two collectors, neither needs administrator rights, a
driver, packet capture or any interception of traffic:

  native (default)  the documented Windows TCP connection table (GetExtendedTcpTable), read
                    through ctypes about 4 times a second. It shows WHICH PROGRAM opened a
                    connection to WHICH PUBLIC IP ADDRESS - including default Chrome and Edge,
                    which bypass the Windows DNS cache. It shows no website name: an address is
                    reported as an address ("Contacted IP address"), never turned into a domain.
  dns               the Phase 5.1 collector: the Windows DNS client cache (Get-DnsClientCache)
                    through one persistent PowerShell. It shows domain names but not Chrome or
                    Edge browsing, and costs about 115 MB for the PowerShell process.
  auto              native, and the dns collector only if the native one cannot start.

WHAT IT KNOWS, AND DOES NOT
  * native: "program P opened a connection to public address A". Not the website, the URL, the
    page, the user's action, or any content. A connection that opens and closes between two
    polls can be missed, and QUIC/HTTP3 (UDP) traffic is not in the TCP table at all.
  * dns: "a program looked up <domain>" - reported as "Contacted domain", never as a visit.
  * It sends only: computer identity, the domain or the address, the program's FILE NAME (never
    its path or command line), a coarse program kind (browser / Windows / application /
    unknown) decided from where the program file lives, the transient process id, and the time.

Standard library only; Python 3.8 or newer; run it by hand for now:
    python agent\\windows_agent.py --config agent\\agent.env
    python agent\\windows_agent.py --dry-run --once                      # look, send nothing
"""
import argparse
import collections
import hashlib
import hmac
import http.server
import io
import ipaddress
import json
import ntpath
import os
import queue
import re
import secrets
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from urllib.parse import urlsplit
from urllib.request import pathname2url

AGENT_VERSION = "0.4.0"

DEFAULT_POLL_SECONDS = 10          # how often the Windows DNS cache is read
DEFAULT_HEARTBEAT_SECONDS = 60     # the server treats a computer as online for 3 minutes after the last beat
MIN_POLL_SECONDS, MAX_POLL_SECONDS = 5, 300
QUEUE_MAX = 500                    # observations waiting for the server; when full the OLDEST is dropped
SEND_TIMEOUT_SECONDS = 5           # one request never blocks longer than this
MAX_SENDS_PER_CYCLE = 25           # a burst of new domains is spread over several cycles
CLIENT_MIN_GAP_SECONDS = 60        # the same domain is not re-reported more often than this (the server also dedupes, 5 min)
BACKOFF_STEPS = (5, 10, 20, 40, 60)  # seconds to wait after consecutive server failures
FINAL_FLUSH_SECONDS = 3            # on a clean stop, try to deliver the queue for at most this long

# --- native collector (Phase 5.2) ---------------------------------------------------------
COLLECTORS = ("auto", "native", "dns")
DEFAULT_COLLECTOR = "auto"
DEFAULT_NATIVE_POLL_MS = 250       # measured: about 0.3% of one core and 16 MB at this rate (agent/README.md)
MIN_NATIVE_POLL_MS, MAX_NATIVE_POLL_MS = 100, 5000
NATIVE_MIN_GAP_SECONDS = 300       # one program is not re-reported to the same address more often than this (the server dedupes the same)
NATIVE_MEMORY_LIMIT = 5000         # remembered (program, address) pairs; the oldest half is dropped beyond this
# TCP states (MIB_TCP_STATE). Everything except these is a connection that exists or is being made.
TCP_STATES = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTAB", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
              8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}
NOT_A_CONNECTION = ("CLOSED", "TIME_WAIT", "DELETE_TCB", "LISTEN")      # TIME_WAIT rows have lost their owner (pid 0)
AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
BROWSER_STEMS = ("msedge", "chrome", "firefox", "brave", "opera", "vivaldi")   # file names without extension

# --- browser-history fallback (Phase 5.3) -----------------------------------------------------
DEFAULT_HISTORY_POLL_SECONDS = 12  # "approximately every 10-15 seconds": Chrome and Edge write a visit to History about 10 s after it
MIN_HISTORY_POLL_SECONDS, MAX_HISTORY_POLL_SECONDS = 5, 120
HISTORY_REDISCOVER_EVERY = 6       # polls between looks for new or vanished profiles
HISTORY_MIN_GAP_SECONDS = 60       # one browser is not re-reported for the same host more often than this (the server dedupes, 5 min)
HISTORY_MEMORY_LIMIT = 2000        # remembered (browser, host) pairs; the oldest half is dropped beyond this
HISTORY_BATCH = 200                # at most this many new visits are read from one profile per poll
HISTORY_BACKOFF_MAX_SECONDS = 300  # a profile that cannot be read is retried less and less often, never faster than this
CHROMIUM_EPOCH_US = 11644473600 * 1000000     # microseconds between 1601-01-01 (Chromium time) and 1970-01-01 (Unix time)

UID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
DEFAULT_PAIRING_PORT = 47619       # loopback only; browser extensions pair with this agent here (see PairingService)
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # no 0/O/1/I: a code is read from a screen and typed
CODE_LENGTH = 8
CODE_TTL_SECONDS = 300
MAX_CODE_ATTEMPTS = 5
PAIR_REQUESTS_PER_MINUTE = 20
MAX_PAIR_BODY = 2048
PAIR_CONNECTION_TIMEOUT = 10        # seconds a local client may hold a connection without finishing its request
CODE_REFUSALS = {"wrong": (403, "that code is not right"), "locked": (429, "too many wrong codes; run pair-code again"),
                 "expired": (410, "that code expired; run pair-code again"),
                 "missing": (410, "no code is waiting; run pair-code on this computer first")}
LABEL_PATTERN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# Same list as the server (validation.NON_PUBLIC_TOP_LABELS): internal / infrastructure names.
NON_PUBLIC_TOP_LABELS = ("arpa", "local", "localhost", "localdomain", "internal", "lan", "home", "corp", "invalid")
RECORD_A, RECORD_CNAME, RECORD_AAAA = 1, 5, 28


class AgentError(Exception):
    """A problem the operator must fix (bad configuration, unsupported system)."""


class ConfigError(AgentError):
    pass


# --------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------
def parse_env_file(path):
    """KEY=VALUE lines; # comments and blank lines ignored; one pair of quotes removed."""
    values = {}
    if not path or not os.path.isfile(path):
        return values
    with io.open(path, encoding="utf-8-sig") as handle:         # utf-8-sig: tolerate a Notepad BOM
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            values[key.strip()] = value
    return values


def normalize_server_url(text):
    """http:// or https:// only, no credentials; query, fragment and trailing slashes removed."""
    text = (text or "").strip()
    if not text:
        raise ConfigError("SERVER_URL is not set (for example http://192.168.1.50:5002)")
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        raise ConfigError("SERVER_URL is not a valid address")
    if parts.scheme not in ("http", "https"):
        raise ConfigError("SERVER_URL must start with http:// or https://")
    if not host:
        raise ConfigError("SERVER_URL has no server name")
    if parts.username or parts.password:
        raise ConfigError("SERVER_URL must not contain a user name or password")
    return "%s://%s%s" % (parts.scheme, parts.netloc, parts.path.rstrip("/"))


def _clean_label(value, field, max_len, required=False):
    value = (value or "").strip()
    if not value:
        if required:
            raise ConfigError("%s is not set" % field)
        return ""
    if len(value) > max_len or any(ord(ch) < 32 for ch in value):
        raise ConfigError("%s must be at most %d characters and contain no control characters" % (field, max_len))
    return value


def _number(value, default, low, high, field, unit="a whole number"):
    if value in (None, ""):
        return default
    try:
        number = int(value)
    except ValueError:
        raise ConfigError("%s must be %s" % (field, unit))
    if not low <= number <= high:
        raise ConfigError("%s must be between %d and %d" % (field, low, high))
    return number


def _seconds(value, default, low, high, field):
    return _number(value, default, low, high, field, "a whole number of seconds")


class Config(object):
    """Settings. Precedence: environment variable WMA_<NAME>, then the config file, then the default.
    The prefix keeps an unrelated API_KEY variable on the machine from being picked up by accident."""

    def __init__(self, server_url, api_key, computer_name, user_label, endpoint_uid, poll_seconds, heartbeat_seconds,
                 state_file, collector=DEFAULT_COLLECTOR, native_poll_ms=DEFAULT_NATIVE_POLL_MS, history_watch=True,
                 history_poll_seconds=DEFAULT_HISTORY_POLL_SECONDS, history_chrome_root="", history_edge_root="",
                 pairing_port=DEFAULT_PAIRING_PORT, pair_extension_ids=()):
        self.server_url = server_url
        self.api_key = api_key
        self.computer_name = computer_name
        self.user_label = user_label
        self.endpoint_uid = endpoint_uid              # optional: link to a browser extension installation on purpose
        self.poll_seconds = poll_seconds              # DNS-cache collector only
        self.heartbeat_seconds = heartbeat_seconds
        self.state_file = state_file
        self.collector = collector                    # auto | native | dns
        self.native_poll_ms = native_poll_ms          # native collector only
        self.history_watch = history_watch            # browser-history fallback on/off
        self.history_poll_seconds = history_poll_seconds
        self.history_chrome_root = history_chrome_root    # "" = the standard Chrome "User Data" folder of this Windows user
        self.history_edge_root = history_edge_root
        self.pairing_port = pairing_port              # loopback port the browser extensions pair on (0 = pairing off)
        self.pair_extension_ids = pair_extension_ids  # optional allow-list of extension ids (empty = any extension, the code decides)

    @property
    def server_host(self):
        return urlsplit(self.server_url).hostname or ""


def load_config(path, environ=None, hostname=None):
    environ = os.environ if environ is None else environ
    from_file = parse_env_file(path)

    def get(name, default=""):
        if "WMA_" + name in environ:
            return environ["WMA_" + name]
        return from_file.get(name, default)

    state_default = os.path.join(os.path.dirname(os.path.abspath(path)) if path else os.getcwd(), "agent_state.json")
    uid = get("ENDPOINT_UID").strip()
    if uid and not UID_PATTERN.match(uid):
        raise ConfigError("ENDPOINT_UID may only contain letters, digits, dash and underscore (64 characters at most)")
    collector = (get("COLLECTOR") or DEFAULT_COLLECTOR).strip().lower()
    if collector not in COLLECTORS:
        raise ConfigError("COLLECTOR must be one of: %s" % ", ".join(COLLECTORS))
    watch_text = (get("HISTORY_WATCH") or "on").strip().lower()
    if watch_text not in ("on", "off", "true", "false", "yes", "no", "1", "0"):
        raise ConfigError("HISTORY_WATCH must be on or off")
    native_poll_ms = _number(get("NATIVE_POLL_MS"), DEFAULT_NATIVE_POLL_MS, MIN_NATIVE_POLL_MS, MAX_NATIVE_POLL_MS, "NATIVE_POLL_MS")
    return Config(
        server_url=normalize_server_url(get("SERVER_URL")),
        api_key=get("API_KEY").strip(),
        computer_name=_clean_label(get("COMPUTER_NAME") or hostname or socket.gethostname(), "COMPUTER_NAME", 100, True),
        user_label=_clean_label(get("USER_LABEL"), "USER_LABEL", 100),
        endpoint_uid=uid,
        poll_seconds=_seconds(get("POLL_SECONDS"), DEFAULT_POLL_SECONDS, MIN_POLL_SECONDS, MAX_POLL_SECONDS, "POLL_SECONDS"),
        heartbeat_seconds=_seconds(get("HEARTBEAT_SECONDS"), DEFAULT_HEARTBEAT_SECONDS, 15, 300, "HEARTBEAT_SECONDS"),
        state_file=get("STATE_FILE") or state_default,
        collector=collector,
        native_poll_ms=native_poll_ms,
        history_watch=watch_text in ("on", "true", "yes", "1"),
        history_poll_seconds=_seconds(get("HISTORY_POLL_SECONDS"), DEFAULT_HISTORY_POLL_SECONDS, MIN_HISTORY_POLL_SECONDS,
                                      MAX_HISTORY_POLL_SECONDS, "HISTORY_POLL_SECONDS"),
        history_chrome_root=get("HISTORY_CHROME_ROOT").strip(),
        history_edge_root=get("HISTORY_EDGE_ROOT").strip(),
        pairing_port=int(_number(get("PAIRING_PORT"), DEFAULT_PAIRING_PORT, 0, 65535, "PAIRING_PORT")),
        pair_extension_ids=tuple(item.strip() for item in get("PAIRING_EXTENSION_IDS").split(",") if item.strip()),
    )


def load_or_create_uid(state_file, override=""):
    """The persistent endpoint identity: a random UUID created once and kept in a small state file.
    Nothing about the hardware is read. ENDPOINT_UID in the configuration overrides it, which is how
    the agent is linked on purpose to a browser-extension installation of the same computer."""
    if override:
        return override
    try:
        with io.open(state_file, encoding="utf-8") as handle:
            stored = json.load(handle).get("endpoint_uid", "")
        if UID_PATTERN.match(stored or ""):
            return stored
    except (OSError, ValueError, AttributeError):
        pass
    uid = str(uuid.uuid4())
    temporary = state_file + ".tmp"
    try:
        with io.open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"endpoint_uid": uid, "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, handle)
        os.replace(temporary, state_file)
    except OSError as error:
        raise ConfigError("cannot save the agent identity to %s (%s)" % (state_file, type(error).__name__))
    return uid


# --------------------------------------------------------------------
# what the Windows DNS cache means
# --------------------------------------------------------------------
class DeviceIdentity(object):
    """Who this agent is. In DEVICE mode (the default) it is a random device UID and a random sensor UID that this agent made and
    keeps, plus the sensor secret the server handed out at enrollment. In LEGACY mode (ENDPOINT_UID set by hand, as before) it
    is only the UID the owner chose, and nothing changes."""

    def __init__(self, sensor_uid, device_uid=None, secret=None):
        self.sensor_uid = sensor_uid
        self.device_uid = device_uid
        self.secret = secret

    @property
    def legacy(self):
        return self.device_uid is None


def _read_state(state_file):
    try:
        with io.open(state_file, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(state_file, data):
    temporary = state_file + ".tmp"
    try:
        with io.open(temporary, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.replace(temporary, state_file)
    except OSError as error:
        raise ConfigError("cannot save the agent identity to %s (%s)" % (state_file, type(error).__name__))


def load_device_identity(state_file, override=""):
    """The persistent identity. ENDPOINT_UID in the configuration keeps the old, hand-linked behaviour. Otherwise random device and
    sensor UIDs (uuid4: os.urandom) are created once and kept in the state file next to the configuration; a restart reuses them."""
    if override:
        return DeviceIdentity(override)
    state = _read_state(state_file)
    changed = False
    for key in ("device_uid", "sensor_uid"):
        if not UID_PATTERN.match(str(state.get(key, ""))):
            state[key] = str(uuid.uuid4())
            changed = True
    if "created" not in state:
        state["created"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        changed = True
    if changed:
        _write_state(state_file, state)
    secret = state.get("sensor_secret")
    return DeviceIdentity(state["sensor_uid"], state["device_uid"], secret if isinstance(secret, str) and secret else None)


def save_sensor_secret(state_file, secret):
    state = _read_state(state_file)
    state["sensor_secret"] = secret
    state["enrolled_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _write_state(state_file, state)


# --------------------------------------------------------------------
# pairing a browser extension with this agent (loopback only)
# --------------------------------------------------------------------
# The owner runs `windows_agent.py pair-code` on this computer, reads the one-time code and types it into the extension's options
# page. The extension sends it to 127.0.0.1 together with its own installation id; the agent checks the code and asks the SERVER
# for a short-lived grant naming exactly that installation. The agent never sends a device identifier, a credential or the server
# key to the extension: only that grant, which is useless to anyone else.
def pairing_code_path(state_file):
    return os.path.join(os.path.dirname(os.path.abspath(state_file)), "pairing_code.json")


def _hash_code(salt, code):
    return hashlib.sha256((salt + code).encode("utf-8")).hexdigest()


def normalize_code(text):
    return re.sub(r"[^A-Z0-9]", "", str(text).upper())


def create_pairing_code(path, now=time.time):
    """A fresh one-time code (the previous one, if any, stops working). Only a salted hash is kept on disk."""
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    salt = secrets.token_hex(8)
    _write_state(path, {"salt": salt, "hash": _hash_code(salt, code), "expires": now() + CODE_TTL_SECONDS, "attempts": 0})
    return code[:4] + "-" + code[4:]


def check_pairing_code(path, supplied, now=time.time):
    """'ok' (and the code is used up), 'wrong', 'locked' (too many wrong tries: the code is destroyed), 'expired' or 'missing'."""
    record = _read_state(path)
    if not record.get("hash"):
        return "missing"
    if now() > float(record.get("expires", 0)):
        _remove(path)
        return "expired"
    if hmac.compare_digest(_hash_code(record["salt"], normalize_code(supplied)), record["hash"]):
        _remove(path)
        return "ok"
    record["attempts"] = int(record.get("attempts", 0)) + 1
    if record["attempts"] >= MAX_CODE_ATTEMPTS:
        _remove(path)
        return "locked"
    _write_state(path, record)
    return "wrong"


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


class PairingService(object):
    """The loopback listener. It answers exactly one request, POST /pair, and only to an extension (an Origin of chrome-extension://)
    that addressed it as 127.0.0.1 or localhost, with a JSON body and a valid one-time code. A web page cannot reach it: its Origin
    is a web origin, a JSON POST from a page needs a preflight this server never approves, and a DNS-rebinding request carries a
    foreign Host header. Every refusal is a plain status and message; no code, grant or identifier is ever logged."""

    def __init__(self, config, server, code_path, log=None, clock=time.time):
        self.config = config
        self.server = server
        self.code_path = code_path
        self.log = log or (lambda message: None)
        self.clock = clock
        self.httpd = None
        self.thread = None
        self.lock = threading.Lock()
        self.recent = collections.deque()

    # -- the decision, separate from the socket so it can be tested without one --------------------
    def handle(self, method, path, headers, body):
        """Returns (http status, JSON-able dict)."""
        if method != "POST" or path != "/pair":
            return 404, {"ok": False, "error": "not found"}
        port = self.config.pairing_port
        if headers.get("Host", "") not in ("127.0.0.1:%d" % port, "localhost:%d" % port):
            return 403, {"ok": False, "error": "refused"}
        origin = headers.get("Origin", "")
        if not origin.startswith("chrome-extension://"):
            return 403, {"ok": False, "error": "only a browser extension may pair"}
        if self.config.pair_extension_ids and origin[len("chrome-extension://"):].rstrip("/") not in self.config.pair_extension_ids:
            return 403, {"ok": False, "error": "this extension is not allowed to pair"}
        if not headers.get("Content-Type", "").lower().startswith("application/json") or len(body) > MAX_PAIR_BODY:
            return 400, {"ok": False, "error": "a small JSON body is expected"}
        with self.lock:
            now = self.clock()
            while self.recent and now - self.recent[0] > 60:
                self.recent.popleft()
            if len(self.recent) >= PAIR_REQUESTS_PER_MINUTE:
                return 429, {"ok": False, "error": "too many requests"}
            self.recent.append(now)
            try:
                data = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return 400, {"ok": False, "error": "a JSON body is expected"}
            sensor_uid = data.get("sensor_uid") if isinstance(data, dict) else None
            code = data.get("code") if isinstance(data, dict) else None
            if not isinstance(sensor_uid, str) or not UID_PATTERN.match(sensor_uid) or not isinstance(code, str) or len(code) > 32:
                return 400, {"ok": False, "error": "code and sensor_uid are required"}
            verdict = check_pairing_code(self.code_path, code, self.clock)
            if verdict != "ok":
                self.log("a browser extension tried to pair: refused (%s)" % verdict)
                status, message = CODE_REFUSALS[verdict]
                return status, {"ok": False, "error": message}
        status, reply = self.server.request_grant(sensor_uid)
        if status != 201 or not reply or not reply.get("grant"):
            self.log("pairing: the server did not issue a grant (HTTP %s)" % status)
            return 502, {"ok": False, "error": "the server did not accept the pairing request"}
        self.log("a browser extension was authorised to pair with this computer")
        return 200, {"ok": True, "grant": reply["grant"], "expires_in": reply.get("expires_in"), "device_name": self.config.computer_name}

    # -- the socket ---------------------------------------------------------------------------------
    def start(self):
        service = self

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "WebsiteMonitorAgent"
            sys_version = ""
            timeout = PAIR_CONNECTION_TIMEOUT        # a client that connects and says nothing cannot hold a thread for ever

            def _respond(self, status, payload):
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()                                    # deliberately NO Access-Control-Allow-* header
                self.wfile.write(data)

            def _any(self, method):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = MAX_PAIR_BODY + 1
                body = self.rfile.read(length) if 0 < length <= MAX_PAIR_BODY else b""
                if length > MAX_PAIR_BODY:
                    body = b"x" * (MAX_PAIR_BODY + 1)
                status, payload = service.handle(method, self.path, self.headers, body)
                self._respond(status, payload)

            def do_POST(self):
                self._any("POST")

            def do_GET(self):
                self._any("GET")

            def do_OPTIONS(self):                                     # a preflight is never approved
                self._respond(403, {"ok": False, "error": "refused"})

            def log_message(self, *_args):                            # the default log would print the request line
                pass

        try:
            self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.config.pairing_port), Handler)
        except OSError as error:
            self.log("pairing is off: cannot listen on 127.0.0.1:%d (%s)" % (self.config.pairing_port, type(error).__name__))
            self.httpd = None
            return False
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.5}, name="pairing", daemon=True)
        self.thread.start()
        return True

    @property
    def port(self):
        return self.httpd.server_address[1] if self.httpd is not None else None

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


def normalize_name(value):
    if not isinstance(value, str):
        return ""
    return value.strip().lower().rstrip(".")


def is_reportable(name):
    """A real, public-looking domain name: at least two valid labels, not an IP literal, not an
    internal or infrastructure name (printer.local, 4.3.2.1.in-addr.arpa, _ldap._tcp...)."""
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    if len(labels) < 2 or not all(LABEL_PATTERN.match(label) for label in labels):
        return False
    if all(label.isdigit() for label in labels):
        return False
    return labels[-1] not in NON_PUBLIC_TOP_LABELS


def extract_domains(rows, ignore_hosts=()):
    """The names this computer asked for, from one snapshot of the DNS cache.

    rows: dicts with Entry, Type and Data (successful lookups only). A CNAME chain is cached as
    several entries (www.site.com -> edge.cdn.net -> addresses); only the name that STARTS the chain
    is what a program looked up, so the CNAME targets (CDN infrastructure) are left out."""
    entries, cname_targets = set(), set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            record_type = int(row.get("Type"))
        except (TypeError, ValueError):
            continue
        if record_type not in (RECORD_A, RECORD_AAAA, RECORD_CNAME):
            continue
        name = normalize_name(row.get("Entry"))
        if not name:
            continue
        entries.add(name)
        if record_type == RECORD_CNAME:
            target = normalize_name(row.get("Data"))
            if target:
                cname_targets.add(target)
    ignored = set(normalize_name(h) for h in ignore_hosts if h)
    return sorted(name for name in entries - cname_targets if is_reportable(name) and name not in ignored)


class Observer(object):
    """Turns successive DNS-cache snapshots into NEW observations.

    The first snapshot is only a baseline: it holds names looked up at unknown earlier times, and
    reporting them as activity would be false (unless include_existing is set for diagnostics).
    After that a name is new when it is in this snapshot but was not in the previous one. The same
    name is not re-reported more often than min_gap seconds, and the memory of reported names is pruned."""

    def __init__(self, include_existing=False, min_gap=CLIENT_MIN_GAP_SECONDS, clock=time.monotonic):
        self.include_existing = include_existing
        self.min_gap = min_gap
        self.clock = clock
        self.previous = None
        self.last_reported = {}

    def observe(self, domains):
        current = set(domains)
        now = self.clock()
        if self.previous is None:
            self.previous = current
            fresh = sorted(current) if self.include_existing else []
        else:
            fresh = sorted(current - self.previous)
            self.previous = current
        reported = []
        for domain in fresh:
            last = self.last_reported.get(domain)
            if last is not None and now - last < self.min_gap:
                continue
            self.last_reported[domain] = now
            reported.append(domain)
        if len(self.last_reported) > 1000:
            self.last_reported = {d: t for d, t in self.last_reported.items() if now - t < 3600}
        return reported


# --------------------------------------------------------------------
# native collector (Phase 5.2): the Windows TCP connection table, owner process included
# --------------------------------------------------------------------
# GetExtendedTcpTable is a documented user-mode API of iphlpapi.dll. It reads a table the system
# already keeps; it needs no administrator rights, installs nothing and changes nothing. Each row
# holds both endpoints, the state and the id of the owning process. One row is a connection - the
# table says nothing about direction, so inbound connections are recognised separately (below).
def _ipv4_text(raw4):
    return socket.inet_ntoa(raw4)


def _ipv6_text(raw16):
    address = ipaddress.IPv6Address(bytes(raw16))
    mapped = address.ipv4_mapped                  # ::ffff:a.b.c.d is really the IPv4 address a.b.c.d
    return str(mapped if mapped is not None else address)


def _port(value):
    """The table stores a port in network byte order inside a 32-bit field."""
    return socket.ntohs(value & 0xFFFF)


def parse_tcp4_table(raw):
    """MIB_TCPTABLE_OWNER_PID: a 32-bit row count, then 24-byte rows (state, local address, local port,
    remote address, remote port, pid). Returns tuples (state, remote_ip, remote_port, pid, local_port).
    A truncated buffer yields only the complete rows."""
    rows = []
    if not raw or len(raw) < 4:
        return rows
    count = struct.unpack_from("<I", raw, 0)[0]
    for index in range(min(count, (len(raw) - 4) // 24)):
        state, _local_addr, local_port, remote_addr, remote_port, pid = struct.unpack_from("<IIIIII", raw, 4 + index * 24)
        rows.append((TCP_STATES.get(state, "UNKNOWN"), _ipv4_text(struct.pack("<I", remote_addr)), _port(remote_port), pid, _port(local_port)))
    return rows


def parse_tcp6_table(raw):
    """MIB_TCP6TABLE_OWNER_PID: 56-byte rows (local address 16, scope id, local port, remote address 16,
    scope id, remote port, state, pid). Same output as parse_tcp4_table."""
    rows = []
    if not raw or len(raw) < 4:
        return rows
    count = struct.unpack_from("<I", raw, 0)[0]
    for index in range(min(count, (len(raw) - 4) // 56)):
        base = 4 + index * 56
        local_port = struct.unpack_from("<I", raw, base + 20)[0]
        remote = bytes(raw[base + 24:base + 40])
        remote_port = struct.unpack_from("<I", raw, base + 44)[0]
        state, pid = struct.unpack_from("<II", raw, base + 48)
        rows.append((TCP_STATES.get(state, "UNKNOWN"), _ipv6_text(remote), _port(remote_port), pid, _port(local_port)))
    return rows


class NativeTcpTable(object):
    """Reads both TCP tables (IPv4 and IPv6) through ctypes. `read_table` can be replaced in tests."""

    def __init__(self, read_table=None):
        self.read_table = read_table or self._windows_read
        self.last_error = ""

    @staticmethod
    def _windows_read(family):
        import ctypes
        from ctypes import wintypes
        function = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
        function.restype = wintypes.ULONG
        size = wintypes.DWORD(0)
        function(None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)      # asks for the size needed
        for _attempt in range(5):                  # the table can grow between the two calls
            buffer = ctypes.create_string_buffer(size.value + 4096)
            size = wintypes.DWORD(len(buffer))
            code = function(buffer, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)
            if code == 0:
                return buffer.raw[:size.value]
            if code != 122:                        # ERROR_INSUFFICIENT_BUFFER: try again with the new size
                raise OSError("GetExtendedTcpTable failed (error %d)" % code)
        raise OSError("GetExtendedTcpTable kept growing")

    def snapshot(self):
        """All TCP rows now, or None when the system call failed (the caller keeps going)."""
        try:
            rows = parse_tcp4_table(self.read_table(AF_INET)) + parse_tcp6_table(self.read_table(AF_INET6))
        except (OSError, ValueError, AttributeError, ImportError) as error:
            self.last_error = "cannot read the TCP table (%s)" % type(error).__name__
            return None
        self.last_error = ""
        return rows

    def check(self):
        """Raises AgentError when this system cannot provide the table (not Windows, or the call fails)."""
        if os.name != "nt" and self.read_table == self._windows_read:
            raise AgentError("the native collector reads the Windows TCP table and only runs on Windows")
        if self.snapshot() is None:
            raise AgentError(self.last_error or "the Windows TCP table cannot be read")


def _under(path, root):
    root = ntpath.normcase(ntpath.normpath(root)).rstrip("\\") + "\\"
    return ntpath.normcase(ntpath.normpath(path)).startswith(root)


def classify_process(path, environ=None):
    """(file name, kind) for the program at `path`. Only the FILE NAME ever leaves this function.

    The kind is decided from where the file lives, never from its name alone:
      SYSTEM       inside the Windows folder
      BROWSER      a known browser file name inside Program Files (a folder only an administrator
                   can write to), so a program merely NAMED chrome.exe in a user folder is not trusted
      APPLICATION  anything else
    A browser process also makes background connections of its own (updates, sync): the kind says
    what program it is, not that a person was browsing."""
    environ = os.environ if environ is None else environ
    name = ntpath.basename(path)
    system_root = environ.get("SystemRoot") or environ.get("windir") or "C:\\Windows"
    if _under(path, system_root):
        return name, "SYSTEM"
    if ntpath.splitext(name)[0].lower() in BROWSER_STEMS:
        for variable in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            root = environ.get(variable)
            if root and _under(path, root):
                return name, "BROWSER"
    return name, "APPLICATION"


class ProcessIdentifier(object):
    """Name and kind of the program that owns a process id. Asks Windows for the program's file path
    only (QueryFullProcessImageName with the limited-information right, which an ordinary user has for
    their own programs). No command line, no memory, no handles to other data. When Windows refuses (a
    protected or administrator process) the answer is (None, "UNKNOWN") - never a guess."""

    def __init__(self, query_path=None, environ=None):
        self.query_path = query_path or self._windows_path
        self.environ = environ

    @staticmethod
    def _windows_path(pid):
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x1000, False, pid)           # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            buffer = ctypes.create_unicode_buffer(1024)
            length = wintypes.DWORD(len(buffer))
            return buffer.value if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)) else None
        finally:
            kernel32.CloseHandle(handle)

    def identify(self, pid):
        try:
            path = self.query_path(pid)
        except (OSError, ValueError, ImportError):
            path = None
        if not path:
            return None, "UNKNOWN"
        return classify_process(path, self.environ)


def resolve_ignored_addresses(host):
    """Addresses of the agent's own server: contacting it is not activity worth reporting."""
    found = set()
    try:
        found.add(str(ipaddress.ip_address(host)))
    except ValueError:
        try:
            for item in socket.getaddrinfo(host, None):
                found.add(item[4][0])
        except (OSError, UnicodeError):
            pass
    return found


class ConnectionObserver(object):
    """Turns successive TCP-table snapshots into NEW outbound connections to public addresses.

    * The first snapshot is only a baseline (connections that already existed: their start time is
      unknown), unless include_existing is set for diagnostics.
    * A row is new when its key (process, remote address, remote port, local port) was not in the
      previous snapshot. The same program is not re-reported to the same address within min_gap seconds.
    * Not reported: loopback / private / link-local / shared-range addresses (they are not websites on the
      internet), this agent's own process and its server, connections without an owner, and inbound
      connections (the local port is one this same program is listening on).
    * Memory is bounded: the set of known connections is the size of the table, and the remembered
      (program, address) pairs are capped.
    """

    def __init__(self, identify, own_pid=None, ignore_ips=(), include_existing=False, min_gap=NATIVE_MIN_GAP_SECONDS,
                 clock=time.monotonic):
        self.identify = identify
        self.own_pid = os.getpid() if own_pid is None else own_pid
        self.ignore_ips = set(ignore_ips)
        self.include_existing = include_existing
        self.min_gap = min_gap
        self.clock = clock
        self.known = None
        self.last_reported = {}

    @staticmethod
    def _public(ip):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return address.is_global and not address.is_multicast      # Python calls some multicast ranges "global"

    def observe(self, rows):
        listening = set((pid, local_port) for state, _ip, _port_, pid, local_port in rows if state == "LISTEN")
        current = {}
        for state, ip, port, pid, local_port in rows:
            if state in NOT_A_CONNECTION or not pid or not port:
                continue
            if (pid, local_port) in listening:          # a program connected TO this computer, not from it
                continue
            current[(pid, ip, port, local_port)] = None
        if self.known is None:
            self.known = set(current)
            fresh = sorted(current) if self.include_existing else []
        else:
            fresh = sorted(key for key in current if key not in self.known)
            self.known = set(current)
        now = self.clock()
        events = []
        for pid, ip, _port_, _local in fresh:
            if pid == self.own_pid or ip in self.ignore_ips or not self._public(ip):
                continue
            name, kind = self.identify(pid)
            pair = (name or "", ip)
            last = self.last_reported.get(pair)
            if last is not None and now - last < self.min_gap:
                continue
            self.last_reported[pair] = now
            events.append({"destination_ip": ip, "process_name": name, "process_kind": kind, "pid": pid})
        if len(self.last_reported) > NATIVE_MEMORY_LIMIT:         # keep the newest half
            newest = sorted(self.last_reported.items(), key=lambda item: item[1], reverse=True)[:NATIVE_MEMORY_LIMIT // 2]
            self.last_reported = dict(newest)
        return events


# --------------------------------------------------------------------
# browser-history fallback (Phase 5.3): new LOCAL visits from Chrome and Edge history, host only
# --------------------------------------------------------------------
# When the browser extension is missing or silent, the browser's own history says which sites were opened. Chrome and Edge
# (Chromium) keep it in a SQLite file, "History", per profile. This watcher only READS that file - it never writes to it,
# never copies it, never opens anything but the "visits" and "urls" tables - and it hands over a bare host name, nothing else.
#
# Schema facts used (checked against real Chrome 154 and Edge 153 history files, see agent/README.md):
#   visits.id               grows with every visit: the cursor, so a visit is never read twice
#   visits.visit_time       microseconds since 1601-01-01 UTC
#   visits.transition       low byte = core type (0 link, 1 typed, 2 auto bookmark, 3 auto subframe, 4 manual subframe, 5 generated,
#                           6 start page, 7 form submit, 8 reload, 9 keyword, 10 keyword generated); high bits = qualifiers,
#                           0x20000000 = CHAIN_END (the last page of a navigation: redirect hops before it do not have it)
#   visits.originator_cache_guid   empty for a visit made on THIS computer, set for a visit synced from another device
# A visit is reported only when it is: local (empty originator), top level (not a subframe), not a reload, the end of its
# navigation chain, http(s), id above the cursor, and made at or after the moment the watcher started (never a backfill).
# The host is cut out INSIDE the SQL query (scheme, user:password@, path, query and fragment are removed there), so the
# Python code never holds a full URL, a title or a search term.
CHAIN_END_FLAG = 0x20000000
HISTORY_EXCLUDED_CORE_TYPES = (3, 4, 8)           # auto subframe, manual subframe, reload
HISTORY_SQL = """
WITH c AS (
  SELECT v.id AS id, v.visit_time AS visit_time, substr(u.url, instr(u.url, '://') + 3) AS rest
  FROM visits v JOIN urls u ON u.id = v.url
  WHERE v.id > :after AND v.id <= :upto AND v.visit_time >= :since
    AND (v.transition & 255) NOT IN (3, 4, 8)
    AND (v.transition & 536870912) != 0
    {local}
    AND (u.url LIKE 'http://%' OR u.url LIKE 'https://%')
), p AS (
  SELECT id, visit_time, rest,
         min(CASE WHEN instr(rest, '/') = 0 THEN 99999 ELSE instr(rest, '/') END,
             CASE WHEN instr(rest, '?') = 0 THEN 99999 ELSE instr(rest, '?') END,
             CASE WHEN instr(rest, '#') = 0 THEN 99999 ELSE instr(rest, '#') END) AS cut
  FROM c
), a AS (
  SELECT id, visit_time, substr(rest, 1, cut - 1) AS authority FROM p
)
SELECT id, visit_time, lower(substr(authority, instr(authority, '@') + 1)) AS host FROM a ORDER BY id LIMIT :limit
"""
LOCAL_ONLY_CLAUSE = "AND IFNULL(v.originator_cache_guid, '') = ''"


def history_roots(environ=None, chrome_root="", edge_root=""):
    """(browser, "User Data" folder) pairs of the CURRENT Windows user. The two settings override the standard places
    (for a portable or non-standard install, and for tests)."""
    environ = os.environ if environ is None else environ
    local = environ.get("LOCALAPPDATA", "")
    roots = []
    chrome = chrome_root or (os.path.join(local, "Google", "Chrome", "User Data") if local else "")
    edge = edge_root or (os.path.join(local, "Microsoft", "Edge", "User Data") if local else "")
    if chrome:
        roots.append(("Chrome", chrome))
    if edge:
        roots.append(("Edge", edge))
    return roots


PROFILE_FOLDER = re.compile(r"^(Default|Profile \d{1,3})$")      # Chromium profile folders; Guest and System profiles are not users' browsing


def discover_history_files(roots):
    """[(browser, path of the History file)] for every profile that has one. Looks at folder names only."""
    found = []
    for browser, root in roots:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            if PROFILE_FOLDER.match(name):
                path = os.path.join(root, name, "History")
                if os.path.isfile(path):
                    found.append((browser, path))
    return found


def host_from_authority(text):
    """The reportable host from what the query returned (host[:port], already lower case), or None."""
    if not isinstance(text, str):
        return None
    host = text.strip().lower()
    if host.startswith("["):                        # an IPv6 literal is not a website name
        return None
    if ":" in host:
        host = host.rsplit(":", 1)[0]
    host = host.rstrip(".")
    return host if is_reportable(host) else None


def chromium_us_to_local_iso(microseconds):
    seconds = (microseconds - CHROMIUM_EPOCH_US) / 1000000.0
    return datetime.fromtimestamp(seconds).strftime("%Y-%m-%dT%H:%M:%S")


class HistoryReadError(Exception):
    """This profile cannot be read right now (locked, half-written, gone). Always transient from the caller's view."""


class ChromiumHistorySource(object):
    """One Chrome or Edge profile. Reads new visits with a strictly read-only, immutable SQLite connection:
      * the file is opened with mode=ro and immutable=1, so SQLite takes no lock and ignores the browser's journal
        (a normal read-only open fails with 'database is locked' while the browser runs - verified);
      * nothing is copied, so no history ever exists outside the browser's own file;
      * an immutable read can meet a page the browser is writing at that moment ('malformed', 'locked', 'no such table'):
        that is caught, the cursor is NOT moved, and the same visits are read on the next poll."""

    def __init__(self, browser, path, since_us, clock=time.monotonic):
        self.browser = browser
        self.path = path
        self.since_us = since_us
        self.clock = clock
        self.cursor = None                # highest visit id already handled
        self.failures = 0
        self.next_try = 0.0
        self.healthy = False

    def _connect(self):
        conn = sqlite3.connect("file:" + pathname2url(self.path) + "?mode=ro&immutable=1", uri=True, timeout=2)
        conn.execute("PRAGMA query_only = ON")
        return conn

    def _read(self):
        conn = self._connect()
        try:
            columns = set(row[1] for row in conn.execute("PRAGMA table_info(visits)"))
            if not {"id", "url", "visit_time", "transition"} <= columns:
                raise HistoryReadError("unexpected history layout")
            upto = conn.execute("SELECT IFNULL(MAX(id), 0) FROM visits").fetchone()[0]
            if self.cursor is None:           # first read: visits already there are the baseline and are never reported
                self.cursor = conn.execute("SELECT IFNULL(MAX(id), 0) FROM visits WHERE visit_time < ?", (self.since_us,)).fetchone()[0]
            if upto <= self.cursor:
                return [], upto
            local = LOCAL_ONLY_CLAUSE if "originator_cache_guid" in columns else ""
            rows = conn.execute(HISTORY_SQL.replace("{local}", local),
                                {"after": self.cursor, "upto": upto, "since": self.since_us, "limit": HISTORY_BATCH}).fetchall()
            return rows, (rows[-1][0] if len(rows) >= HISTORY_BATCH else upto)
        finally:
            conn.close()

    def poll(self):
        """New visits as [(visit id, time, host)], or [] . Never raises."""
        now = self.clock()
        if now < self.next_try:
            return []
        try:
            rows, new_cursor = self._read()
        except (sqlite3.Error, OSError, ValueError, HistoryReadError):
            self.failures += 1
            self.healthy = False
            self.next_try = now + min(HISTORY_BACKOFF_MAX_SECONDS, 5 * (2 ** min(self.failures, 6)))
            return []
        self.failures = 0
        self.healthy = True
        self.cursor = max(self.cursor, new_cursor)
        out = []
        for visit_id, visit_time, host in rows:
            clean = host_from_authority(host)
            if clean:
                try:
                    out.append((visit_id, chromium_us_to_local_iso(visit_time), clean))
                except (OverflowError, OSError, ValueError):
                    continue
        return out


class HistoryWatcher(object):
    """Finds the Chrome and Edge profiles of this Windows user and turns their NEW local visits into domain events.
    Starts with a baseline (nothing already in a history is reported), polls every `interval` seconds, re-checks the profile
    list now and then, and survives any single browser or profile failing."""

    def __init__(self, roots, interval=DEFAULT_HISTORY_POLL_SECONDS, clock=time.monotonic, wall=time.time,
                 min_gap=HISTORY_MIN_GAP_SECONDS, source_factory=ChromiumHistorySource):
        self.roots = roots
        self.interval = interval
        self.clock = clock
        self.min_gap = min_gap
        self.source_factory = source_factory
        self.since_us = int(wall() * 1000000) + CHROMIUM_EPOCH_US       # the moment the watcher started
        self.sources = {}
        self.next_poll = 0.0
        self.polls = 0
        self.last_reported = {}

    def _refresh_sources(self):
        found = dict((path, browser) for browser, path in discover_history_files(self.roots))
        for path in list(self.sources):
            if path not in found:
                del self.sources[path]                    # the profile disappeared
        for path, browser in found.items():
            if path not in self.sources:
                self.sources[path] = self.source_factory(browser, path, self.since_us, self.clock)

    def poll(self):
        """Domain events for visits made since the last poll: [{"domain", "browser", "timestamp"}]. Never raises."""
        now = self.clock()
        if now < self.next_poll:
            return []
        self.next_poll = now + self.interval
        try:
            if self.polls % HISTORY_REDISCOVER_EVERY == 0:
                self._refresh_sources()
            self.polls += 1
            events = []
            for path in sorted(self.sources):
                source = self.sources[path]
                for _visit_id, when, host in source.poll():
                    pair = (source.browser, host)
                    last = self.last_reported.get(pair)
                    if last is not None and now - last < self.min_gap:
                        continue
                    self.last_reported[pair] = now
                    events.append({"domain": host, "browser": source.browser, "timestamp": when})
            if len(self.last_reported) > HISTORY_MEMORY_LIMIT:
                newest = sorted(self.last_reported.items(), key=lambda item: item[1], reverse=True)[:HISTORY_MEMORY_LIMIT // 2]
                self.last_reported = dict(newest)
            return events
        except Exception:                                  # a watcher problem must never stop the agent
            return []

    def watching(self):
        """Browsers whose history can be read right now (what the server may call 'browser-history visibility')."""
        return sorted(set(source.browser for source in self.sources.values() if source.healthy))


# --------------------------------------------------------------------
# the DNS-cache collector: one long-lived PowerShell that prints a snapshot every interval
# --------------------------------------------------------------------
POWERSHELL_LOOP = (
    "$ErrorActionPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$parent={parent};"
    "while($true){{"
    "if(-not (Get-Process -Id $parent -ErrorAction SilentlyContinue)){{exit}};"
    "$rows=@(Get-DnsClientCache | Where-Object {{ $_.Status -eq 0 }} | Select-Object Entry,Type,Data);"
    "[Console]::Out.WriteLine((ConvertTo-Json -InputObject $rows -Compress));"
    "[Console]::Out.Flush();"
    "Start-Sleep -Seconds {interval}"
    "}}"
)


class PowerShellDnsCollector(object):
    """Reads Get-DnsClientCache through ONE persistent powershell.exe (about 35 ms per read once it
    runs, against about 650 ms to start a fresh one every time). The script exits by itself when the
    agent process disappears, so a killed agent never leaves an orphan behind. Needs no elevation."""

    def __init__(self, interval, popen=subprocess.Popen):
        self.interval = interval
        self.popen = popen
        self.process = None
        self.snapshots = queue.Queue(maxsize=2)
        self.restarts = 0
        self.next_restart_at = 0.0
        self.last_error = ""

    def start(self):
        if os.name != "nt":
            raise AgentError("this collector reads the Windows DNS client cache and only runs on Windows")
        script = POWERSHELL_LOOP.format(parent=os.getpid(), interval=self.interval)
        flags = 0x08000000 if os.name == "nt" else 0           # CREATE_NO_WINDOW: no console flashing
        self.process = self.popen(
            ["powershell.exe", "-NoProfile", "-NoLogo", "-NonInteractive", "-Command", script],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, encoding="utf-8", errors="replace", creationflags=flags)
        self.reader = threading.Thread(target=self._read, args=(self.process,), daemon=True)
        self.reader.start()

    def _read(self, process):
        for line in iter(process.stdout.readline, ""):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except ValueError:
                continue
            rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
            try:
                self.snapshots.put_nowait(rows)
            except queue.Full:                                  # keep only the freshest snapshot
                try:
                    self.snapshots.get_nowait()
                except queue.Empty:
                    pass
                self.snapshots.put_nowait(rows)

    def next_snapshot(self, timeout=1.0):
        """The next snapshot, or None when nothing arrived within `timeout` seconds."""
        try:
            return self.snapshots.get(timeout=timeout)
        except queue.Empty:
            self._restart_if_dead()
            return None

    def _restart_if_dead(self):
        if self.process is not None and self.process.poll() is None:
            return
        now = time.monotonic()
        if now < self.next_restart_at:
            return
        self.restarts += 1
        self.next_restart_at = now + min(60, 5 * self.restarts)
        self.last_error = "the PowerShell reader stopped; restarting it (restart %d)" % self.restarts
        try:
            self.start()
        except (AgentError, OSError) as error:
            self.last_error = "cannot start PowerShell (%s)" % type(error).__name__

    def stop(self):
        process, self.process = self.process, None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except Exception:
                process.kill()
        reader = getattr(self, "reader", None)
        if reader is not None:
            reader.join(timeout=2)                  # the pipe reaches end-of-file once the process is gone
        try:
            process.stdout.close()                  # do not leave the pipe to the garbage collector
        except Exception:
            pass


# --------------------------------------------------------------------
# talking to the server (never raises; never logs the API key)
# --------------------------------------------------------------------
def describe_process(event):
    """'msedge.exe' or 'an unidentified program', for the agent's own log lines."""
    return event.get("process_name") or "an unidentified program"


class ServerClient(object):
    def __init__(self, config, uid, transport=None, device_uid=None, secret=None, on_secret=None):
        self.config = config
        self.uid = uid                                # this agent's SENSOR uid (the old endpoint_uid)
        self.device_uid = device_uid                  # None = legacy mode (hand-set ENDPOINT_UID): no enrollment
        self.secret = secret                          # the sensor secret the server issued at enrollment
        self.on_secret = on_secret or (lambda secret: None)
        self.transport = transport or self._http_post
        self.history_provider = None

    def needs_enrollment(self):
        return self.device_uid is not None and not self.secret

    def enroll(self):
        status, body = self.transport("/api/devices/enroll", {
            "device_uid": self.device_uid, "sensor_uid": self.uid, "computer_name": self.config.computer_name,
            "agent_version": AGENT_VERSION})
        if status in (200, 201) and body and isinstance(body.get("sensor_secret"), str):
            self.secret = body["sensor_secret"]
            self.on_secret(self.secret)
        return status, body

    def request_grant(self, extension_uid):
        return self.transport("/api/sensors/grants", {"endpoint_uid": self.uid, "sensor_uid": extension_uid})

    def _identity(self):
        data = {"endpoint_uid": self.uid, "computer_name": self.config.computer_name, "agent_version": AGENT_VERSION}
        if self.config.user_label:         # sent only when configured, so a linked browser label is never wiped
            data["username"] = self.config.user_label
        return data

    def _http_post(self, path, payload):
        """Returns (http status, parsed JSON or None). Status 0 means the server could not be reached."""
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["X-Api-Key"] = self.config.api_key
        if self.secret:
            headers["X-Sensor-Secret"] = self.secret
        request = urllib.request.Request(self.config.server_url + path, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=SEND_TIMEOUT_SECONDS) as response:
                return response.status, self._parse(response.read())
        except urllib.error.HTTPError as error:
            return error.code, self._parse(error.read())
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError, ValueError):
            return 0, None

    @staticmethod
    def _parse(raw):
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else None
        except (ValueError, AttributeError, UnicodeDecodeError):
            return None

    def _identity_with_history(self):
        data = self._identity()
        if self.history_provider is not None:        # always sent (even empty): the server treats it as the current truth
            data["history_browsers"] = list(self.history_provider())
        return data

    def register(self):
        return self.transport("/api/endpoints/register", self._identity_with_history())

    def heartbeat(self):
        return self.transport("/api/heartbeat", self._identity_with_history())

    def send_history_event(self, domain, browser, timestamp):
        """A new local visit found in the browser's history: a bare host, the browser and the time. Nothing else."""
        payload = self._identity()
        payload.update({"domain": domain, "browser": browser, "via": "browser_history", "timestamp": timestamp})
        return self.transport("/api/network-events", payload)

    def send_event(self, domain, timestamp):
        payload = self._identity()
        payload.update({"domain": domain, "timestamp": timestamp})
        return self.transport("/api/network-events", payload)

    def send_connection(self, event, timestamp):
        """A connection seen by the native collector: the address, and - when Windows allowed the agent to
        identify it - the program's file name and kind. Never a path, command line or port."""
        payload = self._identity()
        payload.update({"destination_ip": event["destination_ip"], "process_kind": event.get("process_kind") or "UNKNOWN",
                        "timestamp": timestamp})
        if event.get("process_name"):
            payload["process_name"] = event["process_name"]
        if event.get("pid"):
            payload["pid"] = event["pid"]
        return self.transport("/api/network-events", payload)


# --------------------------------------------------------------------
# the agent loop
# --------------------------------------------------------------------
class Agent(object):
    """Registers, heartbeats and delivers observations. Everything is bounded: the queue holds at most
    QUEUE_MAX observations (the oldest is dropped when full), one cycle sends at most MAX_SENDS_PER_CYCLE,
    and after failures it backs off (5, 10, 20, 40, 60 s). A server outage can therefore never crash
    the agent or grow its memory."""

    def __init__(self, config, server, observer, log=None, clock=time.monotonic, now=datetime.now, connection_observer=None, history=None):
        self.config = config
        self.server = server
        self.observer = observer                          # DNS-cache observations
        self.connection_observer = connection_observer    # native-collector observations (None when not used)
        self.history = history                            # browser-history watcher (None when switched off)
        if history is not None and hasattr(server, "history_provider"):
            server.history_provider = history.watching
        self.clock = clock
        self.now = now
        self.log = log or (lambda message: None)
        self.queue = collections.deque()
        self.registered = False
        self.failures = 0
        self.retry_at = 0.0
        self.next_heartbeat = 0.0
        self.ignore_hosts = (config.server_host,)          # the agent's own lookups of the server are not activity
        self.stats = {"polls": 0, "observed": 0, "sent": 0, "duplicates": 0, "ignored": 0, "rejected": 0,
                      "dropped": 0, "failures": 0, "heartbeats": 0}

    # -- bookkeeping -------------------------------------------------
    def _failed(self, reason):
        self.failures += 1
        self.stats["failures"] += 1
        self.retry_at = self.clock() + BACKOFF_STEPS[min(self.failures - 1, len(BACKOFF_STEPS) - 1)]
        if self.failures == 1 or self.failures % 10 == 0:
            self.log("%s - will keep trying (%d queued)" % (reason, len(self.queue)))

    def _succeeded(self):
        if self.failures:
            self.log("server reachable again")
        self.failures = 0
        self.retry_at = 0.0

    def _ready(self):
        return self.clock() >= self.retry_at

    def _put(self, item):
        if len(self.queue) >= QUEUE_MAX:
            self.queue.popleft()
            self.stats["dropped"] += 1
        item["timestamp"] = self.now().strftime("%Y-%m-%dT%H:%M:%S")
        self.queue.append(item)

    def enqueue(self, domain):
        self._put({"domain": domain})

    def enqueue_connection(self, event):
        self._put(dict(event))

    def enqueue_history(self, event):
        item = dict(event)
        item["via"] = "browser_history"
        self._put(item)
        item["timestamp"] = event["timestamp"]            # the time of the VISIT, not of the moment it was queued

    # -- one pass ----------------------------------------------------
    def cycle(self, snapshot=None, connections=None):
        """snapshot: DNS-cache rows (dns collector). connections: TCP-table rows (native collector)."""
        if snapshot is not None:
            self.stats["polls"] += 1
            for domain in self.observer.observe(extract_domains(snapshot, self.ignore_hosts)):
                self.stats["observed"] += 1
                self.enqueue(domain)
                self.log("observed domain: %s" % domain)
        if connections is not None and self.connection_observer is not None:
            self.stats["polls"] += 1
            for event in self.connection_observer.observe(connections):
                self.stats["observed"] += 1
                self.enqueue_connection(event)
                self.log("observed connection: %s -> %s" % (describe_process(event), event["destination_ip"]))
        if self.history is not None:
            for event in self.history.poll():
                self.stats["observed"] += 1
                self.enqueue_history(event)
                self.log("observed website visit in %s history: %s" % (event["browser"], event["domain"]))
        self._register_if_needed()
        self._flush(MAX_SENDS_PER_CYCLE)
        self._heartbeat_if_due()

    @staticmethod
    def _rejection(body):
        """401 means the API key, unless the server says it is this sensor's credential that it rejects."""
        text = str((body or {}).get("error", "")) if isinstance(body, dict) else ""
        return "the server rejected this agent's sensor credential" if "sensor" in text else "the server rejected the API key"

    def _enroll_if_needed(self):
        """Device mode: announce this computer once; the server answers with the sensor secret, which is kept for good."""
        needs = getattr(self.server, "needs_enrollment", None)
        if needs is None or not needs():
            return True
        status, body = self.server.enroll()
        if status in (200, 201) and getattr(self.server, "secret", None):
            self._succeeded()
            self.log("enrolled this computer as a device")
            return True
        if status == 403:
            self._failed("the server already knows this device but this agent has no credential for it - delete agent_state.json "
                         "next to agent.env to enroll again as a new computer")
        elif status == 401:
            self._failed(self._rejection(body))
        elif status == 400:
            self._failed("the server rejected this computer's details")
        else:
            self._failed("cannot reach the server")
        return False

    def _register_if_needed(self):
        if self.registered or not self._ready():
            return
        if not self._enroll_if_needed():
            return
        status, _body = self.server.register()
        if status in (200, 201):
            self.registered = True
            self._succeeded()
            self.log("registered with the server as %s" % self.config.computer_name)
        elif status == 401:
            self._failed(self._rejection(_body))
        elif status == 400:
            self._failed("the server rejected this computer's details")
        else:
            self._failed("cannot reach the server")

    def _flush(self, limit):
        if not self._ready():
            return
        sent = 0
        while self.queue and sent < limit:
            event = self.queue[0]
            if "destination_ip" in event:
                status, body = self.server.send_connection(event, event["timestamp"])
            elif event.get("via") == "browser_history":
                status, body = self.server.send_history_event(event["domain"], event["browser"], event["timestamp"])
            else:
                status, body = self.server.send_event(event["domain"], event["timestamp"])
            if status in (200, 201):
                self.queue.popleft()
                sent += 1
                self._succeeded()
                if body and body.get("duplicate"):
                    self.stats["duplicates"] += 1
                elif body and body.get("ignored"):
                    self.stats["ignored"] += 1
                else:
                    self.stats["sent"] += 1
            elif status == 400:                          # this observation can never be accepted: drop it, keep going
                self.queue.popleft()
                self.stats["rejected"] += 1
                self.log("the server rejected %s" % (event.get("domain") or event.get("destination_ip")))
            elif status == 401:
                self._failed(self._rejection(body))
                return
            else:
                self._failed("cannot reach the server" if status == 0 else "the server answered with an error (%d)" % status)
                return

    def _heartbeat_if_due(self):
        if not self.registered or self.clock() < self.next_heartbeat or not self._ready():
            return
        status, _body = self.server.heartbeat()
        if status in (200, 201):
            self.stats["heartbeats"] += 1
            self.next_heartbeat = self.clock() + self.config.heartbeat_seconds
            self._succeeded()
        elif status == 401:
            self._failed(self._rejection(_body))
        else:
            self._failed("cannot reach the server" if status == 0 else "the server answered with an error (%d)" % status)

    def finish(self):
        """Clean stop: one last short attempt to deliver what is queued."""
        deadline = self.clock() + FINAL_FLUSH_SECONDS
        while self.queue and self.clock() < deadline and self._ready():
            before = len(self.queue)
            self._flush(MAX_SENDS_PER_CYCLE)
            if len(self.queue) == before:
                break
        return dict(self.stats, undelivered=len(self.queue))


# --------------------------------------------------------------------
# command line
# --------------------------------------------------------------------
def restore_ctrl_c(kernel32=None):
    """Windows: a launcher or parent (for example a virtual-environment python.exe) can leave Ctrl+C
    'ignored' in the child process, so the agent could not be stopped with Ctrl+C. This clears that
    flag. Returns True when the call was made; it does nothing on other systems."""
    if os.name != "nt":
        return False
    try:
        if kernel32 is None:
            import ctypes
            kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCtrlHandler(None, False)
        return True
    except Exception:
        return False


def say(message):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), message))
    sys.stdout.flush()


def parse_args(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Website Monitor Windows network agent (prototype)")
    parser.add_argument("command", nargs="?", default="run", choices=("run", "pair-code"),
                        help="run (default) the agent, or pair-code: print a one-time code to pair a browser extension with this computer")
    parser.add_argument("--config", default=os.path.join(here, "agent.env"), help="configuration file (default: agent.env next to this script)")
    parser.add_argument("--once", action="store_true", help="read the DNS cache once and exit")
    parser.add_argument("--dry-run", action="store_true", help="print what would be reported; contact no server")
    parser.add_argument("--include-existing", action="store_true",
                        help="also report names already in the cache at start (diagnostics only: their lookup time is unknown)")
    parser.add_argument("--version", action="version", version="Website Monitor agent " + AGENT_VERSION)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "pair-code":
            return print_pairing_code(config)
        identity = load_device_identity(config.state_file, config.endpoint_uid)
        uid = identity.sensor_uid
    except AgentError as error:
        say("configuration problem: %s" % error)
        return 2
    say("Website Monitor network agent %s" % AGENT_VERSION)
    native_table = None
    if config.collector in ("auto", "native"):
        candidate = NativeTcpTable()
        try:
            candidate.check()
            native_table = candidate
        except AgentError as error:
            if config.collector == "native":
                say("cannot start the native collector: %s" % error)
                return 2
            say("the native collector is not available (%s); using the DNS-cache collector instead" % error)
    say("server %s | computer %s | user label %s | identity %s... | collector %s | API key %s" % (
        config.server_url, config.computer_name, config.user_label or "(none)", uid[:8],
        ("native, every %d ms" % config.native_poll_ms) if native_table else ("dns, every %d s" % config.poll_seconds),
        ("set (%d characters, not shown)" % len(config.api_key)) if config.api_key else "NOT SET"))
    if native_table:
        say("reports which program connects to which public IP address (Chrome and Edge included). It sees no website "
            "names and no QUIC traffic, and can miss a connection shorter than one poll. Ctrl+C stops.")
    else:
        say("reports domains looked up through the Windows resolver; Chrome/Edge built-in DNS is not visible. Ctrl+C stops.")

    observer = Observer(include_existing=args.include_existing)
    connection_observer = None
    if native_table:
        connection_observer = ConnectionObserver(
            ProcessIdentifier().identify, ignore_ips=resolve_ignored_addresses(config.server_host),
            include_existing=args.include_existing)
    history = None
    if config.history_watch and os.name == "nt":
        history = HistoryWatcher(history_roots(chrome_root=config.history_chrome_root, edge_root=config.history_edge_root),
                                 interval=config.history_poll_seconds)
        say("browser-history fallback on: new Chrome and Edge visits are reported by host name only (private windows are not "
            "recorded by browsers). Set HISTORY_WATCH=off to disable.")
    client = ServerClient(config, uid, device_uid=identity.device_uid, secret=identity.secret,
                          on_secret=lambda secret: save_sensor_secret(config.state_file, secret))
    agent = Agent(config, client, observer, log=say, connection_observer=connection_observer, history=history)
    pairing = None
    if identity.legacy:
        say("ENDPOINT_UID is set, so this agent keeps the old hand-linked identity (no device enrollment, no extension pairing).")
    elif config.pairing_port and not args.dry_run:
        pairing = PairingService(config, client, pairing_code_path(config.state_file), log=say)
        if pairing.start():
            say("extension pairing is available on 127.0.0.1:%d (run 'pair-code' to get a one-time code)" % pairing.port)
        else:
            pairing = None
    stop = threading.Event()

    def request_stop(_signum=None, _frame=None):
        stop.set()

    restore_ctrl_c()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), request_stop)

    if native_table:
        try:
            run_native_loop(args, config, agent, native_table, connection_observer, stop)
        finally:
            summary = agent.finish() if not args.dry_run else {}
    else:
        collector = PowerShellDnsCollector(config.poll_seconds)
        try:
            collector.start()
        except (AgentError, OSError) as error:
            say("cannot start the DNS collector: %s" % error)
            return 2
        try:
            while not stop.is_set():
                snapshot = collector.next_snapshot(timeout=1.0)
                if args.dry_run:
                    if snapshot is not None:
                        for domain in observer.observe(extract_domains(snapshot, agent.ignore_hosts)):
                            say("would report: %s" % domain)
                        if args.once:
                            break
                    if agent.history is not None:
                        for event in agent.history.poll():
                            say("would report: website visit in %s: %s (browser history)" % (event["browser"], event["domain"]))
                    continue
                agent.cycle(snapshot)
                if args.once and snapshot is not None:
                    break
        finally:
            collector.stop()
            summary = agent.finish() if not args.dry_run else {}
    if summary:
        say("stopped. polls %(polls)d, observed %(observed)d, sent %(sent)d, duplicates %(duplicates)d, ignored %(ignored)d, "
            "rejected %(rejected)d, dropped %(dropped)d, failures %(failures)d, undelivered %(undelivered)d" % summary)
    return 0


def print_pairing_code(config):
    """`windows_agent.py pair-code`: a one-time code the owner types into the browser extension's options page."""
    identity = load_device_identity(config.state_file, config.endpoint_uid)
    if identity.legacy:
        say("pairing needs a device identity, but ENDPOINT_UID is set in the configuration (the old hand-linked mode).")
        return 2
    code = create_pairing_code(pairing_code_path(config.state_file))
    say("Pairing code: %s" % code)
    say("Valid for %d minutes, one use. Type it in the extension's options page (Pair with this computer's agent)." % (CODE_TTL_SECONDS // 60))
    if not config.pairing_port:
        say("note: PAIRING_PORT is 0 in the configuration, so the agent is not listening for extensions.")
    return 0


def run_native_loop(args, config, agent, table, observer, stop):
    """Poll the TCP table until stopped. A failed read is skipped (and logged once per streak); the agent
    keeps heartbeating and delivering what it has. --once: a baseline poll, then one poll that reports."""
    interval = config.native_poll_ms / 1000.0
    needed = 1 if args.include_existing else 2
    polls, failing = 0, False
    while not stop.is_set():
        rows = table.snapshot()
        if rows is None and not failing:
            say("%s - will keep trying" % table.last_error)
        failing = rows is None
        if args.dry_run:
            if rows is not None:
                for event in observer.observe(rows):
                    say("would report: %s -> %s [%s]" % (describe_process(event), event["destination_ip"], event["process_kind"]))
            if agent.history is not None:
                for event in agent.history.poll():
                    say("would report: website visit in %s: %s (browser history)" % (event["browser"], event["domain"]))
        else:
            agent.cycle(connections=rows)
        polls += 1
        if args.once and polls >= needed:
            break
        stop.wait(interval)


if __name__ == "__main__":
    sys.exit(main())
