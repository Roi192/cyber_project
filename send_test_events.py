"""Development helper: simulate one endpoint sending NORMAL browsing
events to the server. Only well-known, benign websites are used.

    python send_test_events.py                 # -> http://127.0.0.1:5002
    python send_test_events.py http://host:5002
"""
import os
import sys
from datetime import datetime

import requests

SERVER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5002"
HEADERS = {"Content-Type": "application/json"}
if os.getenv("API_KEY"):
    HEADERS["X-Api-Key"] = os.getenv("API_KEY")

ENDPOINT = {"endpoint_uid": "test-pc-001", "computer_name": "PC-ACCOUNTING-01", "username": "david"}

# Benign test traffic. Query strings/fragments are included on purpose so
# the server's sanitization can be observed (they must not be stored).
VISITS = [
    ("example.com", "https://example.com/page?id=123&token=abc#section", "Chrome"),
    ("wikipedia.org", "https://wikipedia.org/wiki/Main_Page", "Chrome"),
    ("python.org", "https://python.org/downloads/?os=windows", "Edge"),
    ("github.com", "https://github.com/", "Firefox"),
]


def main():
    r = requests.post(SERVER + "/api/endpoints/register", json=ENDPOINT, headers=HEADERS, timeout=10)
    print("register:", r.status_code, r.json())
    for domain, url, browser in VISITS:
        event = dict(ENDPOINT, domain=domain, url=url, browser=browser,
                     timestamp=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
        r = requests.post(SERVER + "/api/web-events", json=event, headers=HEADERS, timeout=10)
        body = r.json()
        print("event:", r.status_code, domain, "->", body.get("reputation", body))
    r = requests.get(SERVER + "/api/status", timeout=10)
    print("status:", r.status_code, r.json()["summary"])


if __name__ == "__main__":
    main()
