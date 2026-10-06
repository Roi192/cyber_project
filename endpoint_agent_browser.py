# ==================================================
# DEPRECATED
# ==================================================
# This is a browser-focused experimental variant of the
# endpoint agent. It filters connections to known browser
# process names and requires a Windows DNS-cache hit to
# report a domain, which causes it to silently drop
# connections it cannot map to a domain.
# endpoint_agent_stable.py is the recommended agent going
# forward. Kept here for reference only — not deleted, not
# modified beyond this notice. Do not deploy this version to
# new endpoints; use endpoint_agent_stable.py instead.
# ==================================================

import ipaddress
import json
import queue
import socket
import subprocess
import threading
import time
from datetime import datetime

import psutil
import requests


# ==================================================
# CONFIGURATION
# ==================================================

SOC_SERVER = "http://127.0.0.1:5000"

POLL_SECONDS = 2

# Same browser + domain will not be sent again
# during this period.
DEDUP_SECONDS = 600

DNS_REFRESH_SECONDS = 4

EVENT_QUEUE_MAX = 100

SEND_DELAY_SECONDS = 1.5

HTTP_TIMEOUT_SECONDS = 30


# Only browser processes are relevant for this
# web-monitoring stage.
MONITORED_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "avastbrowser.exe",
}


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

                ip_object = ipaddress.ip_address(
                    ip_value
                )

            except ValueError:

                continue

            if ip_object.version != 4:

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
# FILTER
# ==================================================

def should_monitor_connection(
    connection,
    endpoint_ip,
    process_name
):

    if process_name.lower() not in MONITORED_PROCESSES:

        return False

    if not connection.raddr:

        return False

    remote_ip = connection.raddr.ip

    try:

        remote_object = ipaddress.ip_address(
            remote_ip
        )

    except ValueError:

        return False

    if remote_object.version != 4:

        return False

    if not remote_object.is_global:

        return False

    if remote_ip == endpoint_ip:

        return False

    if (
        connection.type == socket.SOCK_STREAM
        and connection.status != psutil.CONN_ESTABLISHED
    ):

        return False

    return True


# ==================================================
# SEND EVENT
# ==================================================

def send_event_to_soc(
    event
):

    try:

        response = requests.post(
            f"{SOC_SERVER}/api/web-events",
            json=event,
            timeout=HTTP_TIMEOUT_SECONDS
        )

        if response.ok:

            data = response.json()

            result = data.get(
                "result",
                {}
            )

            print(
                datetime.now().strftime(
                    "%H:%M:%S"
                ),
                "|",
                event["process_name"],
                "|",
                event["destination"],
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
            event["destination"]
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

            send_event_to_soc(
                event
            )

            time.sleep(
                SEND_DELAY_SECONDS
            )

        finally:

            event_queue.task_done()


# ==================================================
# MAIN
# ==================================================

def main():

    endpoint_ip = get_local_ip()

    print(
        "Browser Web Agent started"
    )

    print(
        "Endpoint IP:",
        endpoint_ip
    )

    print(
        "SOC Server:",
        SOC_SERVER
    )

    print(
        "Mode: browser-only + DNS domain correlation"
    )

    print(
        (
            "Raw IP-only connections are skipped "
            "to prevent SOC event flooding."
        )
    )

    print(
        f"Deduplication window: {DEDUP_SECONDS} seconds"
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

    last_sent = {}

    dns_cache = {}
    last_dns_refresh = 0

    while True:

        now = time.time()

        if (
            now - last_dns_refresh
            >= DNS_REFRESH_SECONDS
        ):

            dns_cache = get_windows_dns_cache()

            last_dns_refresh = now

        try:

            connections = psutil.net_connections(
                kind="inet"
            )

        except psutil.AccessDenied:

            print(
                (
                    "Access denied. Run PowerShell/CMD "
                    "as Administrator."
                )
            )

            time.sleep(
                5
            )

            continue

        for connection in connections:

            process_name = get_process_name(
                connection.pid
            )

            if not should_monitor_connection(
                connection,
                endpoint_ip,
                process_name
            ):

                continue

            remote_ip = connection.raddr.ip

            domains = dns_cache.get(
                remote_ip,
                []
            )

            # Important:
            # if Windows has no trustworthy domain mapping
            # for this IP, skip it. This prevents hundreds
            # of raw CDN/cloud IP events.
            if not domains:

                continue

            for domain in domains:

                key = (
                    process_name.lower(),
                    domain.lower()
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

                event = {
                    "endpoint_ip":
                        endpoint_ip,

                    "process_name":
                        process_name,

                    "destination":
                        domain,

                    "observed_ip":
                        remote_ip
                }

                try:

                    event_queue.put_nowait(
                        event
                    )

                    last_sent[key] = now

                    print(
                        "[QUEUED]",
                        process_name,
                        "|",
                        domain,
                        "|",
                        remote_ip,
                        "| queue:",
                        event_queue.qsize()
                    )

                except queue.Full:

                    print(
                        "[QUEUE FULL]",
                        process_name,
                        "|",
                        domain
                    )

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
