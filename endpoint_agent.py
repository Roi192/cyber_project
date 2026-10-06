# ==================================================
# DEPRECATED
# ==================================================
# This is an early draft of the endpoint agent.
# It has no send queue (blocking send) and no global-IP
# filtering, so it is superseded by endpoint_agent_stable.py,
# which is the recommended agent going forward.
# Kept here for reference only — not deleted, not modified
# beyond this notice. Do not deploy this version to new
# endpoints; use endpoint_agent_stable.py instead.
# ==================================================

import ipaddress
import json
import socket
import subprocess
import time
from datetime import datetime

import psutil
import requests


SOC_SERVER = "http://127.0.0.1:5000"
POLL_SECONDS = 2
DEDUP_SECONDS = 60
DNS_REFRESH_SECONDS = 5


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
    """
    Returns a mapping:
        remote_ip -> [domain1, domain2, ...]

    Uses the local Windows DNS client cache. This lets us
    correlate an active remote IP with a recently resolved
    domain without intercepting encrypted web traffic.
    """

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
# DESTINATION LABEL
# ==================================================

def choose_destination(
    remote_ip,
    dns_cache
):

    domains = dns_cache.get(
        remote_ip,
        []
    )

    if domains:

        return domains[0]

    return remote_ip


# ==================================================
# SEND EVENT TO SOC
# ==================================================

def send_destination(
    endpoint_ip,
    destination,
    remote_ip,
    process_name
):

    try:

        response = requests.post(
            f"{SOC_SERVER}/api/web-events",
            json={
                "endpoint_ip": endpoint_ip,
                "destination": destination,
                "observed_ip": remote_ip,
                "process_name": process_name
            },
            timeout=15
        )

        if response.ok:

            data = response.json()

            result = data.get(
                "result",
                {}
            )

            shown_destination = (
                result.get(
                    "domain"
                )
                or destination
            )

            print(
                datetime.now().strftime(
                    "%H:%M:%S"
                ),
                "|",
                process_name,
                "|",
                shown_destination,
                "|",
                remote_ip,
                "->",
                result.get(
                    "decision"
                ),
                result.get(
                    "severity"
                ),
                f"{result.get('risk_score', 0)}/100"
            )

        else:

            print(
                "[SOC ERROR]",
                response.status_code,
                response.text
            )

    except requests.RequestException as exc:

        print(
            "[CONNECTION ERROR]",
            exc
        )


# ==================================================
# MAIN
# ==================================================

def main():

    endpoint_ip = get_local_ip()

    print(
        "Endpoint Agent started"
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
        "Monitoring outbound IPv4 connections + Windows DNS cache..."
    )

    print(
        f"Deduplication window: {DEDUP_SECONDS} seconds"
    )

    last_sent = {}

    dns_cache = {}
    last_dns_refresh = 0

    while True:

        now = time.time()

        # ----------------------------------------------
        # Refresh DNS correlation cache
        # ----------------------------------------------

        if (
            now - last_dns_refresh
            >= DNS_REFRESH_SECONDS
        ):

            dns_cache = get_windows_dns_cache()
            last_dns_refresh = now

        # ----------------------------------------------
        # Get active connections
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
                "Run Command Prompt/PowerShell as Administrator "
                "and restart endpoint_agent.py."
            )

            time.sleep(
                5
            )

            continue

        for connection in connections:

            remote = connection.raddr

            if not remote:

                continue

            remote_ip = remote.ip

            try:

                remote_object = ipaddress.ip_address(
                    remote_ip
                )

            except ValueError:

                continue

            # IPv4 only at this stage
            if remote_object.version != 4:

                continue

            # Prevent the agent from reporting its own local/SOC traffic
            if remote_object.is_loopback:

                continue

            if remote_ip == endpoint_ip:

                continue

            process_name = get_process_name(
                connection.pid
            )

            destination = choose_destination(
                remote_ip,
                dns_cache
            )

            # Deduplicate by process + domain/IP + observed IP
            key = (
                process_name,
                destination,
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

            last_sent[key] = now

            send_destination(
                endpoint_ip,
                destination,
                remote_ip,
                process_name
            )

        # ----------------------------------------------
        # Remove stale dedup records
        # ----------------------------------------------

        stale_keys = [
            key
            for key, sent_time
            in last_sent.items()
            if (
                now - sent_time
                > DEDUP_SECONDS * 5
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
