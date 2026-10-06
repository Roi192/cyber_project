# ==================================================
# RECOMMENDED AGENT
# ==================================================
# This is the recommended endpoint agent going forward
# (see project audit + implementation plan, Phase 1).
# It includes global-IP + established-connection filtering,
# a bounded send queue with a dedicated sender thread, and
# inter-request throttling. endpoint_agent.py and
# endpoint_agent_browser.py are kept for reference but are
# marked deprecated. Future phases will extend this file with
# hostname/port/protocol fields, retry/backoff, explicit
# timestamps, offline buffering, and the Agent API key header.
# ==================================================

import getpass
import hashlib
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse

import psutil
import requests

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# Step 24A: the browser-extension URL-event bridge (Native Messaging Host
# -> this Agent -> SOC). Self-contained, no circular import - see that
# module's docstring for the local trust model.
import browser_agent_bridge

# Step 25A: process telemetry foundation - command-line redaction and
# the shared process-instance-identity function (the EXACT same
# function the server independently recomputes - see process_events.py
# / process_identity.py).
import command_line_privacy
import process_identity


# ==================================================
# CONFIGURATION
# ==================================================

SOC_SERVER = os.getenv(
    "SOC_SERVER_URL",
    "http://127.0.0.1:5000"
).strip() or "http://127.0.0.1:5000"

POLL_SECONDS = 2

# The same process + destination + IP will not be
# sent again during this period.
DEDUP_SECONDS = 300

DNS_REFRESH_SECONDS = 5

# PTR (reverse-DNS) fallback - used only when the forward DNS
# cache above has no hostname for a destination IP (see the
# REVERSE DNS (PTR) FALLBACK section below for why this is
# needed and what it does NOT solve).
PTR_LOOKUP_TIMEOUT_SECONDS = 2
PTR_CACHE_TTL_SECONDS = 600  # 10 min - PTR records rarely change
PTR_NEGATIVE_CACHE_TTL_SECONDS = 300  # 5 min - avoid hammering IPs with no PTR record
PTR_LOOKUPS_PER_CYCLE_LIMIT = 5  # bounds worst-case stall in one poll cycle

# Prevent an unlimited backlog if the SOC is offline.
EVENT_QUEUE_MAX = 500

# Small delay between SOC submissions so that external
# reputation APIs are not hit in a burst.
SEND_DELAY_SECONDS = 1.0

HTTP_TIMEOUT_SECONDS = 30

# Phase 5: shared secret for the SOC to authenticate this
# agent. Never hard-coded - loaded from .env only. Never
# printed anywhere (startup check below only reports whether
# it is present, not its value).
AGENT_API_KEY = os.getenv(
    "AGENT_API_KEY",
    ""
).strip()

# If the SOC rejects our key (401/403), back off for a long
# cooldown instead of retrying every second - the key is wrong
# until a human fixes the .env file, retrying fast just floods
# the server with doomed requests.
AUTH_ERROR_BACKOFF_SECONDS = 60

# ==================================================
# PHASE 7: RESPONSE ACTIONS (safety-gated OS enforcement)
# ==================================================
# Default FALSE, matching the Phase 7 safety requirement: this
# Agent must never touch the Windows Firewall unless a human
# has explicitly opted in via .env on THIS machine. When False,
# every command still gets a result reported back (so the SOC
# workflow/demo works end-to-end), but result is always
# mode="SIMULATED" and no OS action is attempted.
ENABLE_RESPONSE_ACTIONS = os.getenv(
    "ENABLE_RESPONSE_ACTIONS",
    "false"
).strip().lower() == "true"

COMMAND_POLL_SECONDS = 7

# All firewall rules this Agent ever creates use this prefix -
# required for reliable, narrowly-scoped rollback (Restore/
# Unblock only ever touch rules starting with this exact
# string, never any other firewall rule on the machine).
FIREWALL_RULE_PREFIX = "CyberProject_"

# ==================================================
# PHASE 11B: FILE HASHING (executable hashing only - never
# recursive filesystem scanning)
# ==================================================
# 50 MB covers essentially all legitimate process executables
# (interpreters like python.exe/powershell.exe/pwsh.exe and
# typical .exe binaries are a few MB to low tens of MB); it
# bounds worst-case chunked-read time/memory so a single
# oversized file can never meaningfully stall the loop -
# anything larger is skipped (hash omitted, telemetry
# continues) rather than read.
MAX_HASH_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
HASH_CHUNK_SIZE_BYTES = 65536  # 64 KB
HASH_CACHE_MAX_ENTRIES = 500  # generous headroom for one endpoint's distinct executables

# --------------------------------------------------
# STEP 25A: PROCESS TELEMETRY (discovery-only - see process_identity.py
# / process_events.py / the Step 25A report for full scope). A
# SEPARATE, slower-cadence loop from the TCP-connection loop above:
# psutil.process_iter() enumerates EVERY process system-wide (not just
# ones with an active connection), which is a heavier operation than
# the targeted psutil.Process(pid) calls the TCP loop already does -
# it deserves its own, less frequent interval so it can never add
# meaningful load to this already-lightweight Agent on an SMB machine.
# (The actual bounded, env-overridable PROCESS_DISCOVERY_INTERVAL_SECONDS
# is defined further below, next to HEARTBEAT_SECONDS, since it needs
# the _bounded_env_int() helper which is not defined yet at this point
# in the file.)
# --------------------------------------------------
PROCESS_INSTANCE_CACHE_MAX_ENTRIES = 2000  # bounded - see discover_new_processes()

# Recognized script interpreter / process names only. Used to
# classify is_script_related - NEVER derived from file_extension
# (process_path/file_extension describe the EXECUTABLE itself,
# e.g. powershell.exe -> ".exe", never the script file a process
# happens to be executing - the Agent does not observe script
# file paths in this phase; that is a future capability).
SCRIPT_INTERPRETER_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "python.exe", "pythonw.exe"
}


# ==================================================
# PHASE 12B.6D: STABLE AGENT IDENTIFIER (endpoint_uid)
# ==================================================
# A random UUIDv4 generated ONCE for this agent INSTALLATION and persisted in
# a small local state file. It is NOT derived from the IP address or the
# hostname, so it survives restarts and IP changes. It is not a secret and
# NOT an authentication credential (the SOC still authenticates every
# request with X-Agent-Key); it is a stable label for "this installation".
#
# State file (documented path): endpoint_agent_state.json next to this
# script, or the path in the AGENT_STATE_FILE environment variable.
# Contents: {"endpoint_uid": "<uuid4>", "created_at": "<local time>"} - no
# secrets. Written atomically (temp file + os.replace). A missing file is
# created; a malformed file is set aside as <name>.corrupt-<timestamp> and a
# new UID is created (the old content is never silently deleted).

AGENT_STATE_FILE = os.getenv(
    "AGENT_STATE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoint_agent_state.json")
).strip() or os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoint_agent_state.json")

_ENDPOINT_UID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _valid_endpoint_uid(value):

    return isinstance(value, str) and bool(_ENDPOINT_UID_PATTERN.match(value.strip().lower()))


def _read_state(path):

    # Returns (state_dict_or_None, malformed: bool). Missing file -> (None, False).
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None, False
    except (OSError, ValueError):
        return None, True

    if not isinstance(data, dict):
        return None, True

    return data, False


def load_or_create_endpoint_uid(state_path=None):

    path = state_path or AGENT_STATE_FILE

    state, malformed = _read_state(path)

    if state is not None and _valid_endpoint_uid(state.get("endpoint_uid")):
        return state["endpoint_uid"].strip().lower()

    if malformed or (state is not None):

        # Present but unusable: keep it for inspection, then start fresh.
        backup = f"{path}.corrupt-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        try:
            os.replace(path, backup)
            print(f"[WARNING] Agent state file was malformed; kept as {backup}. A new stable agent identifier will be created.")
        except OSError:
            print("[WARNING] Agent state file was malformed and could not be set aside.")

    new_state = dict(state) if isinstance(state, dict) else {}
    new_state["endpoint_uid"] = str(uuid.uuid4())
    new_state["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    temp_path = f"{path}.{os.getpid()}.tmp"

    try:

        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(new_state, handle)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_path, path)

        # If two starts raced, whatever is on disk now wins for both.
        persisted, _ = _read_state(path)

        if persisted is not None and _valid_endpoint_uid(persisted.get("endpoint_uid")):
            return persisted["endpoint_uid"].strip().lower()

    except OSError as exc:

        print(
            "[WARNING] Could not persist the stable agent identifier "
            f"({type(exc).__name__}); using it for this run only."
        )

        try:
            os.remove(temp_path)
        except OSError:
            pass

    return new_state["endpoint_uid"]


# ==================================================
# LOCAL ENDPOINT
# ==================================================

def get_local_ip():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        sock.connect(
            ("8.8.8.8", 80)
        )

        return sock.getsockname()[0]

    finally:

        sock.close()


# ==================================================
# PHASE 13C: ENDPOINT NETWORK CONTEXT + HEARTBEAT
# ==================================================
# WHAT THIS AGENT OBSERVES: OS-visible connection metadata only - the local and
# remote address, the remote port and TCP/UDP of connections that EXIST while
# it polls (psutil.net_connections). It is NOT a packet sniffer: no packet
# capture, no payloads, no complete traffic or connection history, and no
# application-protocol identification (TCP/443 is not "HTTPS", UDP/443 is not
# "QUIC"; nothing is inferred from a URL, a domain or a well-known port).
#
# HEARTBEAT: every ENDPOINT_HEARTBEAT_SECONDS the agent re-evaluates its
# current primary IP and eligible local addresses (so an IP change never needs
# a restart) and sends them - with its stable endpoint_uid ONLY - to
# /api/endpoint-heartbeat (same X-Agent-Key). No process list, files, browsing
# history or documents are ever sent. Presence + network identity, not
# surveillance.

def _bounded_env_int(name, default, minimum, maximum):

    try:
        value = int(os.getenv(name, "").strip())
    except ValueError:
        return default

    return value if minimum <= value <= maximum else default


HEARTBEAT_SECONDS = _bounded_env_int("ENDPOINT_HEARTBEAT_SECONDS", 60, 15, 600)

# STEP 25A: process-discovery loop cadence - deliberately its own, much
# slower, bounded interval (default 30s, 10-300s) - see the comment near
# PROCESS_INSTANCE_CACHE_MAX_ENTRIES above for why this loop must never
# run as hot as the TCP-connection loop.
PROCESS_DISCOVERY_INTERVAL_SECONDS = _bounded_env_int(
    "ENDPOINT_PROCESS_DISCOVERY_INTERVAL_SECONDS", 30, 10, 300
)

MAX_HEARTBEAT_ADDRESSES = 16

# Adapters whose addresses are NOT reported: hypervisor / container / host-only
# / tunnel-pseudo adapters. Their subnets repeat across hosts, so a network
# sensor seeing such an address would be a DIFFERENT host - reporting them would
# yield false endpoint matches. VPN adapters are deliberately kept.
DEFAULT_EXCLUDED_ADAPTER_PATTERN = (
    r"vEthernet|VMware|VirtualBox|Hyper-V|docker|WSL|Loopback|Teredo|isatap|Bluetooth"
)

HEARTBEAT_WARNING_INTERVAL_SECONDS = 600


def adapter_exclusion_regex():

    pattern = os.getenv("AGENT_EXCLUDE_ADAPTER_PATTERNS", "").strip() or DEFAULT_EXCLUDED_ADAPTER_PATTERN

    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return re.compile(DEFAULT_EXCLUDED_ADAPTER_PATTERN, re.IGNORECASE)


def _clean_ip(value):

    # Canonical text of a valid IP (zone id stripped, IPv4-mapped IPv6 folded
    # to IPv4), or None.
    if not isinstance(value, str) or not value:
        return None

    value = value.split("%", 1)[0].strip()

    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None

    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped

    return str(parsed)


def eligible_local_address(value):

    # Mirrors the server's history eligibility policy (endpoint_network.
    # history_eligible_ip): private / CGNAT / ULA / global / VPN addresses are
    # kept; unspecified, loopback, multicast, reserved and link-local are not.
    cleaned = _clean_ip(value)

    if cleaned is None:
        return None

    parsed = ipaddress.ip_address(cleaned)

    if (parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast
            or parsed.is_link_local or parsed.is_reserved):
        return None

    return cleaned


def connection_network_fields(connection):

    # Destination port, transport protocol and connection SOURCE ip exactly as
    # the OS reports them for this connection; None whenever unavailable.
    # Nothing is guessed.
    destination_port = None
    transport_protocol = None
    source_ip = None

    raddr = getattr(connection, "raddr", None)

    if raddr:

        port = getattr(raddr, "port", None)

        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            destination_port = port

    connection_type = getattr(connection, "type", None)

    if connection_type == socket.SOCK_STREAM:
        transport_protocol = "tcp"
    elif connection_type == socket.SOCK_DGRAM:
        transport_protocol = "udp"

    laddr = getattr(connection, "laddr", None)

    if laddr:

        cleaned = _clean_ip(getattr(laddr, "ip", None))

        if cleaned is not None and not ipaddress.ip_address(cleaned).is_unspecified:
            source_ip = cleaned

    return {
        "destination_port": destination_port,
        "transport_protocol": transport_protocol,
        "source_ip": source_ip,
    }


_ADAPTER_DESCRIPTION_TTL_SECONDS = 600
_adapter_description_cache = {"at": 0.0, "value": {}}


def normalize_adapter_name(name):

    # Windows connection names can carry invisible direction marks
    # (U+200E/U+200F ...); strip them so names compare and match reliably.
    return re.sub(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]", "", str(name or "")).strip()


def adapter_descriptions(now=time.time):

    # Best effort (Windows): {normalized connection name: hardware description},
    # e.g. "Ethernet 2" -> "VirtualBox Host-Only Ethernet Adapter". A renamed
    # virtual adapter is only recognizable by its DESCRIPTION. Cached; any
    # failure returns what is known so far - never raises, never blocks long.
    cache = _adapter_description_cache

    if cache["value"] and now() - cache["at"] < _ADAPTER_DESCRIPTION_TTL_SECONDS:
        return cache["value"]

    found = {}

    try:

        completed = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                "Get-NetAdapter | ForEach-Object { $_.Name + [char]9 + $_.InterfaceDescription }"
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )

        for line in (completed.stdout or "").splitlines():

            name, _, description = line.partition("\t")

            if name.strip() and description.strip():
                found[normalize_adapter_name(name)] = description.strip()

    except Exception:

        found = cache["value"]

    cache["at"] = now()
    cache["value"] = found

    return found


def collect_local_addresses(exclude_regex=None, net_if_addrs=None, net_if_stats=None,
                            max_addresses=MAX_HEARTBEAT_ADDRESSES, descriptions=None):

    # Eligible local addresses of interfaces that are UP, minus virtual /
    # hypervisor / container adapters (matched on the adapter NAME and, where
    # Windows provides it, its hardware DESCRIPTION). Returns
    # (sorted_unique_addresses, excluded_address_count) - exclusions are
    # counted, never silent.
    exclude_regex = exclude_regex or adapter_exclusion_regex()
    net_if_addrs = net_if_addrs or psutil.net_if_addrs
    net_if_stats = net_if_stats or psutil.net_if_stats
    descriptions = (descriptions or adapter_descriptions)()

    try:
        stats = net_if_stats()
    except Exception:
        stats = {}

    found = set()
    excluded = 0

    for name, entries in net_if_addrs().items():

        interface = stats.get(name)

        if interface is not None and not getattr(interface, "isup", True):
            continue

        for entry in entries:

            if entry.family not in (socket.AF_INET, socket.AF_INET6):
                continue

            address = eligible_local_address(entry.address)

            if address is None:
                continue

            label = normalize_adapter_name(name)
            label = label + " " + descriptions.get(label, "")

            if exclude_regex.search(label):
                excluded += 1
                continue

            found.add(address)

    return sorted(found)[:max_addresses], excluded


class NetworkIdentity:

    # The agent's CURRENT network identity: primary IP + eligible addresses.
    # Refreshed periodically, so nothing depends on the IP seen at start-up.
    def __init__(self, get_ip=None, collect=None):

        self._get_ip = get_ip or get_local_ip
        self._collect = collect or collect_local_addresses
        self._lock = threading.Lock()
        self._primary = None
        self._addresses = []
        self._excluded = 0

    def refresh(self):

        # Keeps the last good value if a probe fails. Returns True if the
        # primary IP or the address set changed.
        try:
            new_primary = self._get_ip()
        except Exception:
            new_primary = None

        try:
            new_addresses, new_excluded = self._collect()
        except Exception:
            new_addresses, new_excluded = None, None

        with self._lock:

            before = (self._primary, tuple(self._addresses))

            if new_primary:
                self._primary = new_primary

            if new_addresses is not None:
                self._addresses = list(new_addresses)
                self._excluded = new_excluded or 0

            return before != (self._primary, tuple(self._addresses))

    def primary(self):

        with self._lock:
            return self._primary

    def addresses(self):

        with self._lock:
            return list(self._addresses)

    def excluded_count(self):

        with self._lock:
            return self._excluded


def build_heartbeat_payload(endpoint_uid, identity, interval_seconds=None):

    # Minimal by design: identity + current addresses. Nothing else.
    payload = {
        "endpoint_uid": endpoint_uid,
        "endpoint_ip": identity.primary(),
        "addresses": identity.addresses()[:MAX_HEARTBEAT_ADDRESSES],
    }

    if interval_seconds is not None:
        payload["interval_seconds"] = interval_seconds

    return payload


def send_heartbeat(payload, post=None):

    # 'ok' | 'conflict' | 'auth_error' | 'error'. Never raises and never
    # prints the key.
    post = post or requests.post

    try:

        response = post(
            f"{SOC_SERVER}/api/endpoint-heartbeat",
            json=payload,
            headers={"X-Agent-Key": AGENT_API_KEY},
            timeout=HTTP_TIMEOUT_SECONDS
        )

    except requests.RequestException:

        return "error"

    if response.status_code in (401, 403):
        return "auth_error"

    if response.status_code == 409:
        return "conflict"

    return "ok" if 200 <= response.status_code < 300 else "error"


def heartbeat_once(identity, endpoint_uid, state, post=None, now=time.time):

    # One heartbeat cycle: re-evaluate the network identity (no restart needed
    # for an IP change), report it, and surface a change / conflict once.
    changed = identity.refresh()

    if changed and state.get("announced"):

        print(
            "[NETWORK] address set changed | primary:",
            identity.primary(),
            "| eligible addresses:",
            len(identity.addresses()),
            "| virtual/adapters excluded:",
            identity.excluded_count()
        )

    state["announced"] = True

    if not identity.primary():
        return "no_ip"

    result = send_heartbeat(
        build_heartbeat_payload(endpoint_uid, identity, HEARTBEAT_SECONDS),
        post=post
    )

    if result == "conflict":

        last = state.get("last_conflict_warning", 0)

        if now() - last >= HEARTBEAT_WARNING_INTERVAL_SECONDS:

            state["last_conflict_warning"] = now()

            print(
                "[HEARTBEAT] SOC reported ENDPOINT_IDENTITY_CONFLICT: another "
                "endpoint identifier is currently bound to one of this agent's "
                "addresses. Nothing was overwritten."
            )

    elif result == "auth_error":

        print(
            "[AUTH ERROR] SOC rejected Agent authentication (heartbeat). "
            "Check AGENT_API_KEY in .env."
        )

    return result


def heartbeat_worker(identity, endpoint_uid, interval_seconds=None, stop_event=None, sleep=time.sleep):

    state = {}
    interval_seconds = interval_seconds or HEARTBEAT_SECONDS

    while not (stop_event is not None and stop_event.is_set()):

        try:
            result = heartbeat_once(identity, endpoint_uid, state)
        except Exception:
            # A heartbeat problem must never stop network monitoring.
            result = "error"

        sleep(AUTH_ERROR_BACKOFF_SECONDS if result == "auth_error" else interval_seconds)


# ==================================================
# PROCESS NAME
# ==================================================

def get_process_name(pid):

    if not pid:

        return "unknown"

    try:

        process = psutil.Process(
            pid
        )

        return process.name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess
    ):

        return "unknown"


def get_process_path(pid):

    # Sibling to get_process_name() above - kept fully separate
    # so the already-working process-name path is never touched.
    # Returns None (not fabricated) on any failure.

    if not pid:

        return None

    try:

        process = psutil.Process(
            pid
        )

        return process.exe()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess
    ):

        return None


# ==================================================
# PHASE 11B: OS USERNAME (real endpoint user attribution)
# ==================================================

def get_os_username():

    # Resolved ONCE at startup (see main()) - same precedent as
    # get_local_ip(). The OS username of a running session does
    # not change mid-session without a logoff that would restart
    # this agent process anyway, so re-resolving every poll cycle
    # would be pure waste. Never captures passwords/tokens/
    # credentials - just the bare local login name.

    try:

        return getpass.getuser()

    except Exception:

        return None


# ==================================================
# PHASE 11B: SCRIPT-RELATED CLASSIFICATION
# ==================================================

def classify_script_related(process_name):

    # Based ONLY on recognized interpreter/process names - never
    # on file_extension (see SCRIPT_INTERPRETER_PROCESS_NAMES
    # comment above for why). Pure classification/telemetry -
    # never triggers anything alert-related on the agent side.

    if process_name and process_name.lower() in SCRIPT_INTERPRETER_PROCESS_NAMES:

        return True

    return False


# ==================================================
# PHASE 11B: BOUNDED EXECUTABLE HASH CACHE
# ==================================================
# Executable hashing ONLY - there is no recursive filesystem
# scanning anywhere in this agent. Cache is keyed by the
# executable's own path, validated by (mtime, size) rather than
# a pure TTL, so a file replaced at the same path is correctly
# rehashed while an unchanged file is never rehashed. Hashing
# failure of any kind must never stop network monitoring - every
# I/O path below is wrapped in try/except returning (None, None),
# and the call site (main loop) wraps this function in an
# ADDITIONAL outer try/except as a second guard.

def compute_file_hashes(path, hash_cache):

    if not path:
        return None, None

    try:
        stat_result = os.stat(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None, None

    size = stat_result.st_size
    mtime = stat_result.st_mtime

    cached = hash_cache.get(path)

    if cached and cached[0] == mtime and cached[1] == size:
        return cached[2], cached[3]

    if size > MAX_HASH_FILE_SIZE_BYTES:
        return None, None

    if not os.path.isfile(path):
        return None, None  # not a regular file - skip

    try:

        sha256_hasher = hashlib.sha256()
        md5_hasher = hashlib.md5()

        with open(path, "rb") as file_handle:

            while True:

                chunk = file_handle.read(HASH_CHUNK_SIZE_BYTES)

                if not chunk:
                    break

                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)

        sha256_hex = sha256_hasher.hexdigest()
        md5_hex = md5_hasher.hexdigest()

    except (PermissionError, FileNotFoundError, OSError):
        return None, None

    if path not in hash_cache and len(hash_cache) >= HASH_CACHE_MAX_ENTRIES:
        oldest_key = next(iter(hash_cache), None)
        if oldest_key is not None:
            hash_cache.pop(oldest_key, None)

    hash_cache[path] = (mtime, size, sha256_hex, md5_hex)

    return sha256_hex, md5_hex


# ==================================================
# STEP 25A: PROCESS DISCOVERY (collection only - no detection, no
# risk/alert/incident/response effect anywhere below - see
# process_events.py's module header and the Step 25A report)
# ==================================================
#
# One bounded psutil.process_iter() pass per call. "New vs already-
# observed" is decided purely by process_instance_id membership in
# seen_instance_ids (supplied by the caller - see
# process_discovery_worker() below for why this function itself never
# mutates that cache): an instance already in it is skipped BEFORE any
# per-process work (exe/cmdline/username/hash) happens, so an already-
# reported, still-running process is never re-hashed or re-inspected
# every cycle - only touched once per process LIFETIME, not once per
# poll cycle.
#
# KNOWN LIMITATION (accepted, per the Step 25A instructions): a process
# that starts AND exits entirely between two discovery cycles is never
# observed - there is no independent process-creation event stream in
# this step (that would require ETW/WMI, explicitly out of scope).

def discover_new_processes(endpoint_uid, endpoint_ip, seen_instance_ids, hash_cache):

    # pid -> {ppid, create_time, instance_id, process_name}, THIS pass
    # only. Used purely for proof-based parent linking below: a parent
    # is only ever linked when it is ALSO present in this very same
    # snapshot (so its create_time is independently known this cycle,
    # never guessed from PPID alone - Step 25A instruction #10).
    snapshot = {}
    new_events = []

    try:
        process_iterator = psutil.process_iter(["pid", "ppid", "create_time", "name"])
    except Exception:
        return new_events  # psutil itself failed to start iterating - never crash the worker

    for proc in process_iterator:

        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            continue

        pid = info.get("pid")
        ppid = info.get("ppid")
        create_time = info.get("create_time")
        process_name = info.get("name")

        if pid is None or create_time is None:
            continue  # cannot derive a stable identity without both

        instance_id = process_identity.compute_process_instance_id(
            endpoint_uid, pid, create_time
        )

        snapshot[pid] = {
            "ppid": ppid,
            "create_time": create_time,
            "instance_id": instance_id,
        }

        if not instance_id:
            # endpoint_uid missing/invalid - never fabricate an id, and
            # never report a process we cannot stably identify.
            continue

        if instance_id in seen_instance_ids:
            continue  # already reported in a previous cycle - skip all further work below

        # ------------------------------------------------
        # NEW process instance - gather remaining detail now. Each
        # piece is independently try/except'd so one failure (e.g.
        # AccessDenied on cmdline) never drops process_name/pid/identity,
        # which are already known-good at this point.
        # ------------------------------------------------

        process_path = None
        os_username = None
        raw_cmdline_parts = None

        try:
            handle = psutil.Process(pid)
            process_path = handle.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            process_path = None

        try:
            handle = psutil.Process(pid)
            os_username = handle.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            os_username = None

        try:
            handle = psutil.Process(pid)
            raw_cmdline_parts = handle.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            raw_cmdline_parts = None

        # Privacy processing happens BEFORE this ever leaves the Agent
        # process (Step 25A instruction #4) - the server additionally
        # re-applies the same redaction as defense-in-depth, but the
        # raw value is never sent regardless.
        #
        # IMPORTANT: the raw argv LIST is passed directly, never pre-
        # joined into a single string first. redact_command_line()
        # preserves exact token boundaries only when given a list - a
        # single shell-quoted argument such as
        # "Authorization: Bearer <secret>" arrives from psutil.cmdline()
        # as ONE token, and the whole token (key + value together) is
        # replaced as a unit. Joining it into a string first and letting
        # redact_command_line() re-split on whitespace would tear that
        # one token into ["Authorization:", "Bearer", "<secret>"] -
        # "Authorization:" alone still matches the sensitive-key pattern
        # and gets redacted, but with an EMPTY value, while "Bearer" and
        # the real secret that follows survive as separate, unmatched
        # tokens and WOULD leak. This was caught by Step 25A's own
        # secret-redaction test - see the Step 25A report.
        redacted_cmdline, was_redacted = command_line_privacy.redact_command_line(raw_cmdline_parts)

        sha256_value = None
        md5_value = None

        if not process_path:
            hash_status = "no_path"
        else:
            try:
                sha256_value, md5_value = compute_file_hashes(process_path, hash_cache)
                hash_status = "ok" if sha256_value else "unavailable"
            except Exception:
                # Hash failure must never fail collection (instruction #9).
                sha256_value = None
                md5_value = None
                hash_status = "error"

        parent_instance_id = None

        if ppid is not None:

            parent_info = snapshot.get(ppid)

            if parent_info is not None and parent_info.get("instance_id"):
                parent_instance_id = parent_info["instance_id"]

            # else: the parent is not in THIS snapshot (already exited,
            # not visible, or simply not alive this cycle) - no proof of
            # its create_time, so left None. Never guessed from PPID alone.

        new_events.append({
            "endpoint_uid": endpoint_uid,
            "endpoint_ip": endpoint_ip,
            "pid": pid,
            "ppid": ppid,
            "process_create_time": create_time,
            "process_instance_id": instance_id,
            "parent_process_instance_id": parent_instance_id,
            "process_name": process_name,
            "process_path": process_path,
            "os_username": os_username,
            "command_line": redacted_cmdline,
            "command_line_redacted": was_redacted,
            "sha256": sha256_value,
            "md5": md5_value,
            "hash_status": hash_status,
            "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    return new_events


def send_process_event_to_soc(event):

    # Deliberately separate from send_event_to_soc() above (different
    # endpoint, different payload shape, no risk/decision in the
    # response to print) - same auth/timeout/error-handling shape.

    try:

        response = requests.post(
            f"{SOC_SERVER}/api/process-events",
            json=event,
            headers={
                "X-Agent-Key": AGENT_API_KEY
            },
            timeout=HTTP_TIMEOUT_SECONDS
        )

        if response.status_code in (401, 403):

            print(
                "[AUTH ERROR] SOC rejected Agent authentication "
                "for a process event. Check AGENT_API_KEY in .env."
            )

            return "auth_error"

        if response.ok:

            data = response.json()

            print(
                "[PROCESS]",
                event.get("process_name"),
                "| pid=" + str(event.get("pid")),
                "|",
                data.get("status", "accepted")
            )

            return True

        # 400 (validation) is a PERMANENT rejection of this exact payload -
        # unlike a timeout/connection error/5xx, retrying identical bytes
        # can never succeed. Classified separately from False so the
        # caller (process_discovery_worker) can stop retrying just this
        # one process instance forever, instead of re-attempting (and
        # re-failing) it every single discovery cycle indefinitely. This
        # was found and fixed during Step 25A's own restart verification -
        # see the Step 25A report.
        if 400 <= response.status_code < 500:

            print(
                "[SOC REJECTED - process event]",
                response.status_code,
                response.text[:300]
            )

            return "rejected"

        print(
            "[SOC ERROR - process event]",
            response.status_code,
            response.text[:300]
        )

        return False

    except requests.Timeout:

        print(
            "[SOC TIMEOUT - process event]",
            event.get("process_name"),
            "| pid=" + str(event.get("pid"))
        )

        return False

    except requests.RequestException as exc:

        print(
            "[CONNECTION ERROR - process event]",
            exc
        )

        return False


def process_discovery_worker(endpoint_uid, get_endpoint_ip, interval_seconds=None, stop_event=None, sleep=time.sleep):

    # Testable/injectable the same way heartbeat_worker() is
    # (interval_seconds/stop_event/sleep) - a dedicated test can drive
    # exactly one bounded pass without a real 30s wait.
    #
    # get_endpoint_ip: a callable (identity.primary, matching
    # command_worker()'s existing convention above) OR a plain string -
    # resolved fresh EVERY cycle so an IP change never needs an Agent
    # restart, exactly like the rest of this Agent.
    #
    # seen_instance_ids is only ever updated HERE (not inside
    # discover_new_processes()) and only after a send that actually
    # succeeded (True, meaning HTTP 2xx - "accepted" or "duplicate"
    # alike) OR was permanently rejected ("rejected", HTTP 4xx - retrying
    # byte-identical bytes can never succeed; found live during this
    # Step 25A restart when endpoint_ip was initially missing from every
    # event and the server's 400 was retried every cycle forever for
    # every process on the machine - see the Step 25A report). A
    # transient failure (auth_error, timeout, connection error)
    # intentionally leaves the instance id OUT of the cache so the very
    # next cycle retries it - safe because the server independently
    # recomputes process_instance_id and dedups via INSERT OR IGNORE
    # (Step 25A instruction #8: idempotent-by-design, no durable spool
    # needed for THIS guarantee). If the SOC stays unreachable for
    # longer than this Agent keeps retrying (e.g. it is stopped first),
    # that event is lost - an accepted Known Limitation of 25A.
    seen_instance_ids = {}
    hash_cache = {}

    interval_seconds = interval_seconds or PROCESS_DISCOVERY_INTERVAL_SECONDS

    while not (stop_event is not None and stop_event.is_set()):

        try:

            endpoint_ip = get_endpoint_ip() if callable(get_endpoint_ip) else get_endpoint_ip

            new_events = discover_new_processes(endpoint_uid, endpoint_ip, seen_instance_ids, hash_cache)

            for event in new_events:

                result = send_process_event_to_soc(event)

                if result is True or result == "rejected":

                    seen_instance_ids[event["process_instance_id"]] = True

                    if len(seen_instance_ids) > PROCESS_INSTANCE_CACHE_MAX_ENTRIES:
                        oldest_key = next(iter(seen_instance_ids), None)
                        if oldest_key is not None:
                            seen_instance_ids.pop(oldest_key, None)

                elif result == "auth_error":

                    # Wrong/missing key - every subsequent event in this
                    # same pass would fail identically; stop this pass
                    # and back off rather than hammering the server.
                    sleep(AUTH_ERROR_BACKOFF_SECONDS)
                    break

        except Exception as exc:

            # A process-discovery problem must never stop network
            # monitoring, the heartbeat, or command polling - same
            # failure-isolation principle as heartbeat_worker() above.
            print("[PROCESS DISCOVERY ERROR]", exc)

        sleep(interval_seconds)


# ==================================================
# WINDOWS DNS CACHE
# ==================================================

def get_windows_dns_cache():

    powershell_command = (
        "Get-DnsClientCache | "
        "Select-Object Entry,RecordName,Data | "
        "ConvertTo-Json -Compress"
    )

    try:

        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                powershell_command
            ],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            )
        )

        if completed.returncode != 0:

            return {}

        raw = completed.stdout.strip()

        if not raw:

            return {}

        data = json.loads(
            raw
        )

        if isinstance(
            data,
            dict
        ):

            data = [data]

        ip_to_domains = {}

        for item in data:

            if not isinstance(
                item,
                dict
            ):

                continue

            ip_value = str(
                item.get(
                    "Data",
                    ""
                )
            ).strip()

            domain = str(
                item.get(
                    "RecordName"
                )
                or item.get(
                    "Entry"
                )
                or ""
            ).strip().rstrip(".").lower()

            if not ip_value or not domain:

                continue

            try:

                # Validates the value is a real IP (IPv4 or
                # IPv6) before trusting it as a cache key - the
                # parsed object itself isn't needed beyond that,
                # both families are cached identically.
                ipaddress.ip_address(
                    ip_value
                )

            except ValueError:

                continue

            domains = ip_to_domains.setdefault(
                ip_value,
                []
            )

            if domain not in domains:

                domains.append(
                    domain
                )

        return ip_to_domains

    except (
        subprocess.SubprocessError,
        json.JSONDecodeError,
        OSError
    ):

        return {}


# ==================================================
# REVERSE DNS (PTR) FALLBACK
# ==================================================
# The forward DNS cache above (get_windows_dns_cache) only ever
# reflects queries the Windows OS resolver itself observed. Some
# traffic never goes through it at all - most notably browsers
# using DNS-over-HTTPS (e.g. Chrome's default "Secure DNS"),
# which resolve entirely inside the browser process over an
# encrypted connection the OS never sees. When that happens, no
# amount of polling or cache-timing fixes this file will ever
# recover the real requested hostname - the OS genuinely never
# knew it. This PTR fallback is a best-effort label for that
# case only: a reverse lookup on the destination IP, which often
# returns SOMETHING readable (e.g. a cloud/CDN provider's own
# reverse-DNS name) even when it is not the site the user typed.
# The returned hostname is NEVER decorated with a presentation
# label - it must stay a clean value the SOC server can pass
# straight into DNS resolution and IOC matching. Provenance
# ("this came from PTR, not a real forward query") travels
# separately as an `attribution_type` string ("dns"/"rdns"/"ip"),
# set by choose_destination() below and carried through the
# event payload as its own field, so the UI can label it without
# ever touching the value used for resolution/matching. (An
# earlier version of this fix embedded the label directly in the
# destination string - that broke the worker's DNS resolution
# and has been corrected.)
#
# Also out of scope here (unrelated to DNS entirely): QUIC/UDP
# connections (used by some browser traffic on port 443) are not
# visible to this agent at all - psutil does not expose a remote
# address for UDP sockets on this platform, so only TCP
# connections are ever monitored, regardless of DNS attribution.
# See README.md "Limitations" for both points.


def resolve_ptr_hostname(
    ip,
    ptr_cache
):

    now = time.time()

    cached = ptr_cache.get(
        ip
    )

    if cached and now < cached[1]:

        return cached[0]  # may be None - a cached negative result

    # socket.gethostbyaddr() delegates directly to the OS's
    # blocking resolver call and does NOT honor
    # socket.setdefaulttimeout() - confirmed empirically (an
    # unresolvable IP took ~5s against an attempted 2s timeout).
    # Run it in a daemon thread and bound how long WE wait for
    # it instead: if it hasn't finished by
    # PTR_LOOKUP_TIMEOUT_SECONDS, we give up and cache a
    # negative result, without blocking the poll loop further.
    # The abandoned thread finishes on its own in the background
    # and is discarded - harmless, since its result is never
    # read once we've stopped waiting on it.

    lookup_result = {}

    def _do_lookup():

        try:

            lookup_result["hostname"] = (
                socket.gethostbyaddr(
                    ip
                )[0].rstrip(".").lower()
            )

        except (
            socket.herror,
            socket.gaierror,
            socket.timeout,
            OSError
        ):

            lookup_result["hostname"] = None

    lookup_thread = threading.Thread(
        target=_do_lookup,
        daemon=True
    )

    lookup_thread.start()

    lookup_thread.join(
        PTR_LOOKUP_TIMEOUT_SECONDS
    )

    if lookup_thread.is_alive():

        # Still running after the timeout - treat as a (possibly
        # temporary) failure for now rather than waiting longer.
        hostname = None

    else:

        hostname = lookup_result.get(
            "hostname"
        )

    ttl = (
        PTR_CACHE_TTL_SECONDS
        if hostname
        else PTR_NEGATIVE_CACHE_TTL_SECONDS
    )

    ptr_cache[ip] = (
        hostname,
        now + ttl
    )

    return hostname


# ==================================================
# DESTINATION LABEL
# ==================================================

def choose_destination(
    remote_ip,
    dns_cache,
    ptr_cache,
    ptr_lookups_this_cycle
):

    # Returns (destination, attribution_type, ptr_lookups_this_cycle).
    # `destination` is ALWAYS a clean hostname or IP - suitable for
    # DNS resolution and IOC matching on the SOC server - never
    # decorated with a presentation label. Provenance travels
    # separately as `attribution_type` ("dns" / "rdns" / "ip") so
    # the UI can show a badge without ever touching the value used
    # for resolution/matching.

    # 1. Forward DNS cache - preferred, reflects a query this
    #    machine actually made for that hostname.
    domains = dns_cache.get(
        remote_ip,
        []
    )

    if domains:

        return domains[0], "dns", ptr_lookups_this_cycle

    # 2. PTR fallback - only on a forward-cache miss, and only
    #    up to PTR_LOOKUPS_PER_CYCLE_LIMIT NEW (cache-miss)
    #    lookups per poll cycle, so a burst of unfamiliar IPs
    #    cannot stall the loop. Cached PTR results (positive or
    #    negative) are free and do not count against this limit.
    already_cached = (
        remote_ip in ptr_cache
        and time.time() < ptr_cache[remote_ip][1]
    )

    if already_cached or ptr_lookups_this_cycle < PTR_LOOKUPS_PER_CYCLE_LIMIT:

        if not already_cached:

            ptr_lookups_this_cycle += 1

        ptr_hostname = resolve_ptr_hostname(
            remote_ip,
            ptr_cache
        )

        if ptr_hostname:

            return (
                ptr_hostname,
                "rdns",
                ptr_lookups_this_cycle
            )

    # 3. Raw IP - both the forward cache and PTR fallback missed
    #    (or the per-cycle PTR limit was reached this cycle).
    return remote_ip, "ip", ptr_lookups_this_cycle


# ==================================================
# FILTER CONNECTIONS
# ==================================================

def should_monitor_connection(
    connection,
    endpoint_ip
):

    if not connection.raddr:

        return False

    remote_ip = connection.raddr.ip

    try:

        remote_object = ipaddress.ip_address(
            remote_ip
        )

    except ValueError:

        return False

    # IPv4 and IPv6 are both monitored. Version-specific handling
    # (if ever needed) belongs below this point, not as a blanket
    # exclusion - .is_global (next check) is correctly implemented
    # for both address families in Python's ipaddress module.

    # Skip loopback/private/link-local/multicast traffic.
    # The Web Monitoring page is focused on external
    # Internet destinations.
    if not remote_object.is_global:

        return False

    if remote_ip == endpoint_ip:

        return False

    # For TCP, keep only active established connections.
    if (
        connection.type == socket.SOCK_STREAM
        and connection.status != psutil.CONN_ESTABLISHED
    ):

        return False

    return True


# ==================================================
# SEND ONE EVENT
# ==================================================

def send_event_to_soc(
    event
):

    try:

        response = requests.post(
            f"{SOC_SERVER}/api/web-events",
            json=event,
            headers={
                "X-Agent-Key": AGENT_API_KEY
            },
            timeout=HTTP_TIMEOUT_SECONDS
        )

        if response.status_code in (401, 403):

            print(
                "[AUTH ERROR] SOC rejected Agent "
                "authentication. Check AGENT_API_KEY in .env - "
                "it must match the server's value exactly."
            )

            return "auth_error"

        if response.ok:

            data = response.json()

            # Phase 2: the server now returns 202 Accepted
            # immediately (save-first, analyze later) instead
            # of waiting for the final risk score. Print the
            # new PENDING-style line for that shape; fall back
            # to the old decision/severity/risk_score line if
            # ever pointed at a pre-Phase-2 server.
            if data.get("status") == "accepted":

                print(
                    "[SENT]",
                    event["process_name"],
                    "|",
                    event["destination"],
                    "| event_id=" + str(
                        data.get("event_id")
                    ),
                    "|",
                    data.get(
                        "analysis_status",
                        "PENDING"
                    )
                )

                return True

            result = data.get(
                "result",
                {}
            )

            shown_destination = (
                result.get(
                    "domain"
                )
                or event["destination"]
            )

            print(
                datetime.now().strftime(
                    "%H:%M:%S"
                ),
                "|",
                event["process_name"],
                "|",
                shown_destination,
                "|",
                event["observed_ip"],
                "->",
                result.get(
                    "decision"
                ),
                result.get(
                    "severity"
                ),
                f"{result.get('risk_score', 0)}/100"
            )

            return True

        print(
            "[SOC ERROR]",
            response.status_code,
            response.text[:300]
        )

        return False

    except requests.Timeout:

        print(
            "[SOC TIMEOUT]",
            event["process_name"],
            "|",
            event["destination"],
            "|",
            event["observed_ip"]
        )

        return False

    except requests.RequestException as exc:

        print(
            "[CONNECTION ERROR]",
            exc
        )

        return False


# ==================================================
# BACKGROUND SENDER
# ==================================================

def sender_worker(
    event_queue
):

    while True:

        event = event_queue.get()

        try:

            result = send_event_to_soc(
                event
            )

            if result == "auth_error":

                # Wrong/missing key - retrying every second
                # would just flood the server with requests
                # that are guaranteed to fail until a human
                # fixes AGENT_API_KEY. Back off instead.
                time.sleep(
                    AUTH_ERROR_BACKOFF_SECONDS
                )

            else:

                time.sleep(
                    SEND_DELAY_SECONDS
                )

        finally:

            event_queue.task_done()


# ==================================================
# PHASE 7: RESPONSE COMMAND EXECUTION
# ==================================================
# Allowlist dispatch ONLY - command_type strings come from the
# SOC server, but the actual OS action always runs through one
# of exactly four functions below, each of which builds its own
# PowerShell script from validated Python values. No raw string
# from the server is ever concatenated into a shell command, and
# subprocess is never called with shell=True.

def is_admin():

    try:

        import ctypes

        return bool(
            ctypes.windll.shell32.IsUserAnAdmin()
        )

    except Exception:

        return False


def _validate_ip_or_domain(target):
    """
    Returns ("ip", value), ("domain", value), or (None, None).
    Domains are restricted to a conservative safe character set
    (letters/digits/dot/hyphen) - anything else is refused
    rather than risk building an unsafe PowerShell argument.
    """

    if not target:
        return None, None

    try:

        ipaddress.ip_address(target)

        return "ip", target

    except ValueError:
        pass

    if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", target):
        return "domain", target.lower()

    return None, None


def _ps_quote(value):
    # Single-quoted PowerShell literal; '' escapes an embedded
    # single quote. Values passed here are always pre-validated
    # (IP/domain/rule-name built from a command id), never raw
    # user text.
    return "'" + str(value).replace("'", "''") + "'"


def run_powershell(script, timeout=20):

    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0
        )
    )


def execute_block_destination(command_id, target):

    if not is_admin():
        return (
            "FAILED",
            "Administrator privileges are required for "
            "firewall enforcement.",
            None
        )

    if not ENABLE_RESPONSE_ACTIONS:
        return (
            "SUCCESS",
            "Simulated - real enforcement disabled "
            "(ENABLE_RESPONSE_ACTIONS is not true on this Agent).",
            "SIMULATED"
        )

    kind, value = _validate_ip_or_domain(target)

    if kind is None:
        return (
            "FAILED",
            "Invalid or unsafe target - refused to build a "
            "firewall rule.",
            None
        )

    if kind == "ip":

        ips = [value]

    else:

        try:

            addr_info = socket.getaddrinfo(
                value, None, family=socket.AF_INET
            )

            ips = sorted(set(entry[4][0] for entry in addr_info))

        except socket.gaierror as exc:

            return (
                "FAILED",
                f"Could not resolve domain to block: {exc}",
                None
            )

        if not ips:

            return (
                "FAILED",
                "Domain did not resolve to any IPv4 address.",
                None
            )

    created_rules = []

    for index, ip in enumerate(ips):

        rule_name = (
            f"{FIREWALL_RULE_PREFIX}Block_{command_id}_{index}"
        )

        script = (
            f"New-NetFirewallRule -DisplayName {_ps_quote(rule_name)} "
            f"-Direction Outbound -RemoteAddress {_ps_quote(ip)} "
            f"-Action Block -Profile Any | Out-Null"
        )

        result = run_powershell(script)

        if result.returncode != 0:

            return (
                "FAILED",
                (
                    "Firewall rule creation failed: "
                    f"{result.stderr.strip()[:300]}"
                ),
                None
            )

        created_rules.append(rule_name)

    limitation_note = ""

    if kind == "domain":

        limitation_note = (
            f" LIMITATION: blocked {len(ips)} currently-resolved "
            "IP(s) for this domain only - if the domain later "
            "resolves to different IPs (CDN rotation), those new "
            "IPs are NOT automatically blocked."
        )

    return (
        "SUCCESS",
        (
            "Created firewall rule(s): "
            f"{', '.join(created_rules)}.{limitation_note}"
        ),
        "ENFORCED"
    )


def execute_unblock_destination(command_id, reference_command_id):

    if not is_admin():
        return (
            "FAILED",
            "Administrator privileges are required for "
            "firewall enforcement.",
            None
        )

    if not ENABLE_RESPONSE_ACTIONS:
        return (
            "SUCCESS",
            "Simulated - real enforcement disabled "
            "(ENABLE_RESPONSE_ACTIONS is not true on this Agent).",
            "SIMULATED"
        )

    if not reference_command_id:
        return (
            "FAILED",
            "No original BLOCK_DESTINATION command reference - "
            "nothing to safely remove.",
            None
        )

    rule_prefix = (
        f"{FIREWALL_RULE_PREFIX}Block_{reference_command_id}_"
    )

    script = (
        f"Get-NetFirewallRule -DisplayName {_ps_quote(rule_prefix + '*')} "
        "-ErrorAction SilentlyContinue "
        "| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
    )

    result = run_powershell(script)

    if result.returncode != 0:

        return (
            "FAILED",
            f"Rule removal failed: {result.stderr.strip()[:300]}",
            None
        )

    return (
        "SUCCESS",
        f"Removed firewall rule(s) matching {rule_prefix}*.",
        "ENFORCED"
    )


def execute_isolate_endpoint(command_id):

    if not is_admin():
        return (
            "FAILED",
            "Administrator privileges are required for "
            "firewall enforcement.",
            None
        )

    if not ENABLE_RESPONSE_ACTIONS:
        return (
            "SUCCESS",
            "Simulated - real enforcement disabled "
            "(ENABLE_RESPONSE_ACTIONS is not true on this Agent).",
            "SIMULATED"
        )

    soc_host = urlparse(SOC_SERVER).hostname

    try:

        soc_ip = socket.gethostbyname(soc_host)

    except socket.gaierror:

        return (
            "FAILED",
            (
                "Could not resolve the SOC server address - "
                "refusing to isolate without a guaranteed "
                "management path back to the SOC."
            ),
            None
        )

    allow_rule = (
        f"{FIREWALL_RULE_PREFIX}Isolation_{command_id}_AllowSOC"
    )

    # Allow-SOC rule created FIRST, default policy flipped to
    # Block SECOND - this ordering means there is never a
    # moment where the SOC path is unreachable while isolation
    # is only partially applied.
    allow_script = (
        f"New-NetFirewallRule -DisplayName {_ps_quote(allow_rule)} "
        f"-Direction Outbound -RemoteAddress {_ps_quote(soc_ip)} "
        f"-Action Allow -Profile Any | Out-Null"
    )

    result_allow = run_powershell(allow_script)

    if result_allow.returncode != 0:

        return (
            "FAILED",
            (
                "Could not create the SOC-allow rule - isolation "
                f"aborted: {result_allow.stderr.strip()[:300]}"
            ),
            None
        )

    block_default_script = (
        "Set-NetFirewallProfile -All -DefaultOutboundAction Block"
    )

    result_block = run_powershell(block_default_script)

    if result_block.returncode != 0:

        # Roll back the allow rule so no partial state is left
        # behind if the default-policy change failed.
        run_powershell(
            f"Remove-NetFirewallRule -DisplayName {_ps_quote(allow_rule)} "
            "-ErrorAction SilentlyContinue"
        )

        return (
            "FAILED",
            (
                "Could not set the default outbound policy to "
                f"Block: {result_block.stderr.strip()[:300]}"
            ),
            None
        )

    return (
        "SUCCESS",
        (
            "Default outbound policy set to Block; outbound "
            f"traffic to the SOC server ({soc_ip}) explicitly "
            f"allowed via rule {allow_rule}. Inbound traffic and "
            "localhost are not affected by this rule set."
        ),
        "ENFORCED"
    )


def execute_restore_endpoint(command_id):

    if not is_admin():
        return (
            "FAILED",
            "Administrator privileges are required for "
            "firewall enforcement.",
            None
        )

    if not ENABLE_RESPONSE_ACTIONS:
        return (
            "SUCCESS",
            "Simulated - real enforcement disabled "
            "(ENABLE_RESPONSE_ACTIONS is not true on this Agent).",
            "SIMULATED"
        )

    restore_script = (
        "Set-NetFirewallProfile -All -DefaultOutboundAction Allow; "
        f"Get-NetFirewallRule -DisplayName {_ps_quote(FIREWALL_RULE_PREFIX + 'Isolation_*')} "
        "-ErrorAction SilentlyContinue "
        "| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
    )

    result = run_powershell(restore_script)

    if result.returncode != 0:

        return (
            "FAILED",
            f"Restore failed: {result.stderr.strip()[:300]}",
            None
        )

    return (
        "SUCCESS",
        (
            "Default outbound policy restored to Allow; all "
            f"{FIREWALL_RULE_PREFIX}Isolation_* rules removed."
        ),
        "ENFORCED"
    )


def poll_for_commands(endpoint_ip):

    try:

        response = requests.get(
            f"{SOC_SERVER}/api/agent/commands",
            params={"endpoint_ip": endpoint_ip},
            headers={"X-Agent-Key": AGENT_API_KEY},
            timeout=HTTP_TIMEOUT_SECONDS
        )

        if response.status_code in (401, 403):

            print(
                "[AUTH ERROR] SOC rejected Agent authentication "
                "(command poll). Check AGENT_API_KEY in .env."
            )

            return []

        if not response.ok:

            return []

        return response.json().get("commands", [])

    except requests.RequestException:

        # Command polling failure must never stop telemetry
        # collection (Phase 7, section 20).
        return []


def report_command_result(command_id, status, result_message, mode):

    try:

        requests.post(
            f"{SOC_SERVER}/api/agent/commands/{command_id}/result",
            json={
                "status": status,
                "result_message": result_message,
                "mode": mode
            },
            headers={
                "X-Agent-Key": AGENT_API_KEY
            },
            timeout=HTTP_TIMEOUT_SECONDS
        )

    except requests.RequestException as exc:

        print(
            "[COMMAND REPORT ERROR]",
            exc
        )


def command_worker(get_endpoint_ip):

    # Phase 13C: accepts a callable so command polling FOLLOWS the agent's
    # refreshed primary IP (a plain string is still accepted).
    while True:

        endpoint_ip = (
            get_endpoint_ip() if callable(get_endpoint_ip) else get_endpoint_ip
        )

        commands = poll_for_commands(endpoint_ip)

        for command in commands:

            command_id = command["id"]
            command_type = command["command_type"]
            target = command.get("target")
            reference_command_id = command.get(
                "reference_command_id"
            )

            print(
                f"[COMMAND] #{command_id} {command_type} "
                f"{target or ''}"
            )

            if command_type == "BLOCK_DESTINATION":

                status, message, mode = execute_block_destination(
                    command_id, target
                )

            elif command_type == "UNBLOCK_DESTINATION":

                status, message, mode = execute_unblock_destination(
                    command_id, reference_command_id
                )

            elif command_type == "ISOLATE_ENDPOINT":

                status, message, mode = execute_isolate_endpoint(
                    command_id
                )

            elif command_type == "RESTORE_ENDPOINT":

                status, message, mode = execute_restore_endpoint(
                    command_id
                )

            else:

                # Should never happen - the server only ever
                # creates allowlisted command_type values - but
                # fail safely instead of crashing if it does.
                status, message, mode = (
                    "FAILED",
                    f"Unsupported command_type: {command_type}",
                    None
                )

            print(
                f"[COMMAND] #{command_id} -> {status} "
                f"({mode}): {message}"
            )

            report_command_result(
                command_id, status, message, mode
            )

        time.sleep(COMMAND_POLL_SECONDS)


# ==================================================
# MAIN
# ==================================================

def main():

    # --------------------------------------------------
    # PHASE 5: REQUIRE AGENT_API_KEY BEFORE STARTING
    # --------------------------------------------------

    if not AGENT_API_KEY:

        print(
            "[CONFIG ERROR] AGENT_API_KEY is not configured."
        )

        print(
            "Set AGENT_API_KEY in this project's .env file "
            "before starting this agent."
        )

        return

    # Phase 13C: the network identity is re-evaluated periodically (see
    # heartbeat_worker) - the IP seen at start-up is not assumed to stay valid.
    identity = NetworkIdentity()

    identity.refresh()

    while not identity.primary():

        print("[NETWORK] No usable local IP yet; retrying in 5 seconds.")
        time.sleep(5)
        identity.refresh()

    endpoint_ip = identity.primary()

    # Phase 12B.6D: stable per-installation identifier (independent of the
    # IP address above). Sent as identity metadata only.
    endpoint_uid = load_or_create_endpoint_uid()

    # Phase 11B: resolved once at startup - see get_os_username()
    # for why this is not re-resolved every poll cycle.
    os_username = get_os_username()

    print(
        "Endpoint Agent started"
    )

    print(
        "Endpoint IP:",
        endpoint_ip
    )

    print(
        "Stable agent identifier:",
        endpoint_uid
    )

    print(
        f"Heartbeat: every {HEARTBEAT_SECONDS} seconds "
        f"(eligible addresses: {len(identity.addresses())}, "
        f"virtual adapters excluded: {identity.excluded_count()})"
    )

    print(
        "SOC Server:",
        SOC_SERVER
    )

    print(
        "Mode: external connections + process + DNS correlation"
    )

    print(
        f"Deduplication window: {DEDUP_SECONDS} seconds"
    )

    print(
        "Events are queued locally before SOC analysis."
    )

    event_queue = queue.Queue(
        maxsize=EVENT_QUEUE_MAX
    )

    sender = threading.Thread(
        target=sender_worker,
        args=(
            event_queue,
        ),
        daemon=True
    )

    sender.start()

    print(
        "Response actions:",
        "ENABLED (real enforcement)" if ENABLE_RESPONSE_ACTIONS
        else "SIMULATION MODE (no real firewall changes)"
    )

    if ENABLE_RESPONSE_ACTIONS and not is_admin():

        print(
            "[WARNING] ENABLE_RESPONSE_ACTIONS=true but this "
            "Agent is not running as Administrator - firewall "
            "commands will FAIL safely until restarted elevated."
        )

    command_thread = threading.Thread(
        target=command_worker,
        args=(
            identity.primary,
        ),
        daemon=True
    )

    command_thread.start()

    heartbeat_thread = threading.Thread(
        target=heartbeat_worker,
        args=(
            identity,
            endpoint_uid,
        ),
        daemon=True
    )

    heartbeat_thread.start()

    # --------------------------------------------------
    # STEP 25A: PROCESS TELEMETRY DISCOVERY (collection-only - see
    # process_discovery_worker()'s docstring and the Step 25A report).
    # A separate thread, its own slower interval, its own caches - never
    # shares state with the TCP-connection loop below. Thread-start
    # itself cannot realistically raise (no socket bind, unlike the
    # browser bridge below), but it is still wrapped defensively so a
    # future change here can never take down TCP/domain monitoring.
    # --------------------------------------------------
    try:

        process_discovery_thread = threading.Thread(
            target=process_discovery_worker,
            args=(
                endpoint_uid,
                identity.primary,
            ),
            daemon=True
        )

        process_discovery_thread.start()

        print(
            f"Process telemetry discovery: every {PROCESS_DISCOVERY_INTERVAL_SECONDS} "
            "seconds (collection only - no detection, no alerts, no response)"
        )

    except Exception as exc:

        print(
            "[PROCESS DISCOVERY DISABLED] Could not start the process "
            f"discovery thread ({exc}). TCP/domain monitoring below is "
            "UNAFFECTED and will start normally."
        )

    # --------------------------------------------------
    # STEP 24A: BROWSER-EXTENSION URL EVENT BRIDGE
    # --------------------------------------------------
    # Loopback-only local listener for browser_native_host.py, plus a
    # dedicated sender thread forwarding to /api/browser-events over the
    # same X-Agent-Key channel as every other event. Entirely additive -
    # if no extension/native host is ever installed on this machine,
    # this listener simply never receives a connection and the existing
    # TCP/domain monitoring above is completely unaffected.
    browser_event_queue = queue.Queue(
        maxsize=EVENT_QUEUE_MAX
    )

    # Step 24A.1 Part B finding: start_browser_event_listener() binds a
    # real socket SYNCHRONOUSLY, in THIS (main) thread, before the
    # existing TCP-monitoring loop below ever runs. If that bind fails
    # (port already in use by a leftover prior instance, permission
    # issue, etc.) an unguarded call would raise OSError here and crash
    # the entire Agent - including the pre-existing TCP/domain
    # monitoring that has nothing to do with the browser bridge. This
    # must degrade gracefully instead: log it plainly and continue
    # straight into TCP monitoring with the bridge simply disabled.
    try:

        browser_agent_bridge.start_browser_event_listener(
            browser_event_queue
        )

        print(
            "Browser URL event bridge: listening on 127.0.0.1:"
            f"{browser_agent_bridge.LOCAL_LISTENER_PORT} "
            "(for an optional, separately installed browser extension)"
        )

        browser_sender_thread = threading.Thread(
            target=browser_agent_bridge.browser_sender_worker,
            args=(
                browser_event_queue,
                endpoint_uid,
                SOC_SERVER,
                AGENT_API_KEY,
                HTTP_TIMEOUT_SECONDS,
                AUTH_ERROR_BACKOFF_SECONDS,
                SEND_DELAY_SECONDS,
            ),
            daemon=True
        )

        browser_sender_thread.start()

    except OSError as exc:

        print(
            "[BROWSER BRIDGE DISABLED] Could not start the local "
            f"listener on 127.0.0.1:{browser_agent_bridge.LOCAL_LISTENER_PORT} "
            f"({exc}). TCP/domain monitoring below is UNAFFECTED and "
            "will start normally; the browser extension bridge is "
            "simply not available this run."
        )

    last_sent = {}

    dns_cache = {}
    last_dns_refresh = 0

    ptr_cache = {}

    # Phase 11B: bounded executable hash cache - see
    # compute_file_hashes() for its shape/bounds.
    hash_cache = {}

    while True:

        now = time.time()

        # Phase 13C: always the CURRENT primary IP (refreshed by the
        # heartbeat thread) - never the address seen at start-up.
        endpoint_ip = identity.primary() or endpoint_ip

        # ----------------------------------------------
        # REFRESH DNS CACHE
        # ----------------------------------------------

        if (
            now - last_dns_refresh
            >= DNS_REFRESH_SECONDS
        ):

            dns_cache = get_windows_dns_cache()

            last_dns_refresh = now

        # New (cache-miss) PTR lookups are capped per poll
        # cycle - see PTR_LOOKUPS_PER_CYCLE_LIMIT.
        ptr_lookups_this_cycle = 0

        # ----------------------------------------------
        # READ CONNECTIONS
        # ----------------------------------------------

        try:

            connections = psutil.net_connections(
                kind="inet"
            )

        except psutil.AccessDenied:

            print(
                "Access denied while reading network connections."
            )

            print(
                "Run PowerShell/CMD as Administrator "
                "and restart endpoint_agent.py."
            )

            time.sleep(
                5
            )

            continue

        # Step 25B: process<->network correlation evidence. ONE bulk
        # psutil.process_iter() sweep per TCP-loop cycle (not a fresh
        # psutil.Process(pid).create_time() call per connection) -
        # measured during Step 25B's own design phase: a fresh
        # Process(pid).create_time() call cost ~2.6ms/pid on this
        # machine (opening a new process handle each time), while one
        # bulk process_iter(['pid','create_time']) sweep covering EVERY
        # process on the machine cost ~1.5-2.5ms TOTAL once warm - far
        # cheaper for the common case of multiple active connections per
        # cycle. Builds a plain pid->create_time dict; a pid with no
        # connection this cycle is harmless, unused lookup data.
        process_create_time_map = {}

        try:

            for proc in psutil.process_iter(["pid", "create_time"]):

                try:
                    info = proc.info
                    process_create_time_map[info["pid"]] = info["create_time"]
                except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                    continue

        except Exception:
            # Never let a correlation-evidence sweep failure affect the
            # TCP/domain monitoring loop itself - an empty map just means
            # no event this cycle gets a process_instance_id attached.
            process_create_time_map = {}

        for connection in connections:

            if not should_monitor_connection(
                connection,
                endpoint_ip
            ):

                continue

            remote_ip = (
                connection.raddr.ip
            )

            process_name = get_process_name(
                connection.pid
            )

            destination, attribution_type, ptr_lookups_this_cycle = choose_destination(
                remote_ip,
                dns_cache,
                ptr_cache,
                ptr_lookups_this_cycle
            )

            # Same process/destination/IP is sent only
            # once during the deduplication window.
            key = (
                process_name.lower(),
                destination.lower(),
                remote_ip
            )

            previous_time = last_sent.get(
                key,
                0
            )

            if (
                now - previous_time
                < DEDUP_SECONDS
            ):

                continue

            # Phase 11B: process/file/hash/script telemetry.
            # Deliberately gathered AFTER the dedup check above,
            # so hashing effort is only ever spent on events that
            # will actually be queued/sent - never wasted on a
            # deduped repeat within the DEDUP_SECONDS window.
            process_path = get_process_path(
                connection.pid
            )

            try:
                sha256_value, md5_value = compute_file_hashes(
                    process_path,
                    hash_cache
                )
            except Exception:
                # Guarantees a hashing failure of any kind can
                # never raise into this loop - network monitoring
                # must never stop because of a hashing error.
                sha256_value, md5_value = None, None

            file_name = (
                os.path.basename(process_path)
                if process_path else None
            )

            file_extension = (
                os.path.splitext(file_name)[1].lower()
                if file_name and "." in file_name
                else None
            )

            is_script_related = classify_script_related(
                process_name
            )

            # Step 25B: process<->network correlation evidence - looked
            # up from the bulk sweep above (never a fresh per-connection
            # psutil.Process(pid).create_time() call - see that sweep's
            # comment for why). A pid the sweep didn't see (process
            # already exited, or the sweep itself failed open) simply
            # gets no process_instance_id - the event is still sent
            # normally, same as before this step existed.
            connection_create_time = process_create_time_map.get(connection.pid)

            connection_process_instance_id = None

            if connection_create_time is not None and endpoint_uid:

                connection_process_instance_id = process_identity.compute_process_instance_id(
                    endpoint_uid, connection.pid, connection_create_time
                )

            event = {
                "endpoint_ip":
                    endpoint_ip,

                "endpoint_uid":
                    endpoint_uid,

                "destination":
                    destination,

                "observed_ip":
                    remote_ip,

                "process_name":
                    process_name,

                "attribution_type":
                    attribution_type,

                "os_username":
                    os_username,

                "process_pid":
                    connection.pid,

                "process_path":
                    process_path,

                "file_name":
                    file_name,

                "file_extension":
                    file_extension,

                "sha256":
                    sha256_value,

                "md5":
                    md5_value,

                "is_script_related":
                    is_script_related,

                "process_create_time":
                    connection_create_time,

                "process_instance_id":
                    connection_process_instance_id
            }

            # Phase 13C: OS-observed connection metadata, added only when
            # the OS actually reported it (never guessed).
            event.update({
                key: value
                for key, value in connection_network_fields(connection).items()
                if value is not None
            })

            try:

                event_queue.put_nowait(
                    event
                )

                last_sent[key] = now

                print(
                    "[QUEUED]",
                    process_name,
                    "|",
                    destination,
                    "|",
                    remote_ip,
                    "| queue:",
                    event_queue.qsize()
                )

            except queue.Full:

                print(
                    "[QUEUE FULL] Event skipped:",
                    process_name,
                    destination,
                    remote_ip
                )

        # ----------------------------------------------
        # CLEAN OLD DEDUP RECORDS
        # ----------------------------------------------

        stale_keys = [
            key
            for key, sent_time
            in last_sent.items()
            if (
                now - sent_time
                > DEDUP_SECONDS * 2
            )
        ]

        for key in stale_keys:

            last_sent.pop(
                key,
                None
            )

        time.sleep(
            POLL_SECONDS
        )


if __name__ == "__main__":

    main()
