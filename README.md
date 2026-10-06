# Website Monitor

A small Flask application that answers one question for a small business:
**which websites are our computers visiting, and did any of them visit a
dangerous website?**

Endpoints post the websites they visit; the server records the domain,
checks its reputation (cached), raises a plain-language alert for
malicious/suspicious destinations and shows everything on a simple dashboard.

Privacy: only the website name and page path are stored. Query strings,
fragments, credentials, cookies, passwords, form data and page contents are
never collected, and there is no HTTPS interception.

## Run locally

    python -m venv venv
    venv\Scripts\activate          # Windows   (Linux: source venv/bin/activate)
    pip install -r requirements.txt
    copy .env.example .env         # Linux: cp .env.example .env
    python app.py                  # http://127.0.0.1:5002

Send some benign test traffic from a second terminal:

    python send_test_events.py

Run the tests:

    python -m unittest discover -s tests -v

## Run on the Linux server (Python 3.8, port 5002)

    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env            # HOST=0.0.0.0, PORT=5002 are the defaults
    gunicorn -b 0.0.0.0:5002 app:app

## Collect real browsing from Chrome / Edge (browser extension)

`browser_extension/` is a tiny Manifest V3 extension (no build step) that
reports every top-level `http`/`https` navigation as
`{domain, scheme://host/path}` to `http://127.0.0.1:5002/api/web-events`.
Query strings, fragments, credentials, cookies, headers, form data and page
contents never leave the browser. Install: `chrome://extensions` (or
`edge://extensions`) -> Developer mode -> Load unpacked -> choose the
`browser_extension` folder. Details, limitations (it cannot read the Windows
computer name - labels are configured on its Options page) and CORS notes
are in `browser_extension/README.md`.

Duplicate reload/redirect events are suppressed twice: in the extension
(same tab + URL within 5 s) and on the server (same computer + page within
10 s; the response carries `"duplicate": true` and no new row is written).

The Dashboard and Browsing pages poll `/api/status` and `/api/visits`
every 7 seconds, so new visits appear without a reload (no WebSockets).

## API

| Method | Route                     | Purpose                                            |
|--------|---------------------------|----------------------------------------------------|
| POST   | `/api/endpoints/register` | register / refresh a computer                      |
| POST   | `/api/web-events`         | submit one website visit                           |
| GET    | `/api/status`             | counters, `threat_intel` status, `dev_mode`        |
| GET    | `/api/visits?after_id=N`  | visits newer than N (newest first) for polling     |

Example web event:

    {"endpoint_uid": "pc-001", "computer_name": "PC-ACCOUNTING-01",
     "username": "david", "domain": "example.com",
     "url": "https://example.com/page", "browser": "Chrome",
     "timestamp": "2026-10-06T12:00:00"}

Set `API_KEY` in `.env` to require an `X-Api-Key` header on POST requests.

## Reputation

`services/reputation.py` exposes `check_domain(conn, domain)` which returns
`{"status": SAFE|SUSPICIOUS|MALICIOUS|UNKNOWN, "source", "reason"}`, using
the `domain_reputation` cache before any provider call. One optional
provider (VirusTotal v3) is included and is active only when `VT_API_KEY` is
set (environment only, never in code); without it every domain is `UNKNOWN`
and no detection is claimed.

VirusTotal verdict rules (`last_analysis_stats`):

| Condition                                   | Status     |
|---------------------------------------------|------------|
| no vendor has analysed the domain           | UNKNOWN    |
| `malicious >= 3`                            | MALICIOUS  |
| `malicious` 1-2, or `suspicious >= 2`       | SUSPICIOUS |
| otherwise                                   | SAFE       |
| HTTP 404 (domain not in VirusTotal)         | UNKNOWN    |
| 401/403/429/5xx, timeout, network, bad JSON | UNKNOWN    |

A failure is never reported as SAFE. After 429 the provider is paused for
15 minutes, after 401/403 for 60 minutes, after other errors for 5 minutes
(no rapid retries); meanwhile new domains are UNKNOWN and the dashboard
shows **Threat intel: Temporarily unavailable** (otherwise **Active** or
**Not configured**).

Cache TTL per status: SAFE 24 h (`REPUTATION_CACHE_HOURS`), SUSPICIOUS and
MALICIOUS 6 h, UNKNOWN 30 min. A valid cache entry never triggers an API call.
