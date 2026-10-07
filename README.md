# Website Monitor

A small Flask application that answers one question for a small business:
**which websites are our computers visiting, and did any of them visit a
dangerous website?**

    PC-01 ─┐
    PC-02 ─┤   browser extension on every computer
    PC-03 ─┼──► POST /api/web-events, /api/heartbeat ──► Central Flask server :5002
    PC-04 ─┤                                                   │
    PC-05 ─┘                                       SQLite ◄────┤
                                                   Reputation check (cached)
                                                   Alerts ──► Dashboard

Each computer runs a tiny Chrome/Edge extension that reports the websites its
browser opens. One central server stores them, checks each domain's
reputation (cached), raises a plain-language alert for malicious or suspicious
destinations and shows everything on a simple dashboard.

Privacy: only the website name and page path are stored. Query strings,
fragments, credentials, cookies, passwords, form data and page contents are
never collected, and there is no HTTPS interception.

## 1. Run the server

Windows (development):

    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    copy .env.example .env
    python app.py                  # http://127.0.0.1:5002 and http://<this-pc-ip>:5002

Linux (Python 3.8+, with uv):

    git clone https://github.com/Roi192/cyber_project.git ~/cyber_project
    cd ~/cyber_project
    uv venv --python 3.8
    uv pip install -r requirements.txt
    cp .env.example .env
    nano .env                      # set API_KEY (and VT_API_KEY if you have one)
    uv run python app.py

The server listens on `0.0.0.0:5002` by default (`HOST` / `PORT` in `.env`), so
other computers can reach it. Run the tests with
`python -m unittest discover -s tests -v`.

With gunicorn use threads, because a reputation lookup can take a few seconds
and every computer posts to the same server:

    gunicorn --workers 1 --threads 4 --bind 0.0.0.0:5002 app:app

(one worker on purpose: SQLite and the reputation back-off state live in the
process). `app:app` is the module `app.py` and its `app` object; importing it
creates the database. Step-by-step Linux instructions, the environment variable
table and a pre-flight checker (`python deploy/check_env.py`) are in
`deploy/DEPLOYMENT.md`; `python deploy/build_package.py` builds the clean
deployment archive.

### API key (required once the server is reachable from a network)

Endpoints authenticate with one organization-wide key sent in the `X-Api-Key`
header. Create one and put it in `.env`:

    python -c "import secrets; print(secrets.token_hex(24))"
    API_KEY=<the value>

Leave `API_KEY` empty only for local development: the server then runs in
**DEV MODE**, accepts unauthenticated uploads, shows a DEV MODE badge, and - if
it listens beyond localhost - prints a warning at startup and shows a warning on
every page. The key is never logged, never stored in the database and never
shown in a page. The dashboard pages themselves are read-only and have no login
(see Limitations).

## 2. Connect a computer (browser extension)

`browser_extension/` is a tiny Manifest V3 extension (plain JavaScript, no
build step) for Chrome and Edge. On each computer:

1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose the `browser_extension` folder.
4. Open the extension's **Details -> Extension options** and fill in:
   - **Server address** - e.g. `http://192.168.1.50:5002` (http:// or https:// only)
   - **Computer name** - e.g. `ACCOUNTING-PC-01`
   - **User / owner** - optional, e.g. `Dana`
   - **API key** - the organization key from the server's `.env`
5. Click **Test connection** (it should say *Connected successfully*), then **Save**.
   The browser asks once for permission to contact that server; click Allow.

More detail, the permission model and troubleshooting are in
`browser_extension/README.md`.

### How the computers are identified

Each browser installation generates a random UUID once and keeps it in
`chrome.storage.local`. That UUID is the identity: renaming the computer or the
user in the options just updates the same entry. If the extension is removed and
installed again it gets a new UUID and counts as a **new computer** (the old
entry stays and shows OFFLINE). Nothing about the machine is fingerprinted - no
MAC address, serial number or Windows account.

### Online / offline

Every 60 seconds the extension sends a heartbeat (`POST /api/heartbeat`). The
server only updates that computer's `last_seen`; no row is added per heartbeat
and no history is kept. A computer is **ONLINE** while its `last_seen` is at
most **180 seconds** old (three missed beats of tolerance) and **OFFLINE**
afterwards. Closing the browser therefore shows OFFLINE within three minutes.
Visits and registrations also refresh `last_seen`.

### Browser-generated noise

Some navigations are made by the browser, not the employee. A tiny explicit
list is ignored (extension and server both apply it); each entry needs the exact
host **and** exact path:

| Host          | Path        | What it is                       |
|---------------|-------------|----------------------------------|
| `ntp.msn.com` | `/edge/ntp` | the Microsoft Edge New Tab Page  |

Normal browsing to `www.msn.com` or any other `ntp.msn.com` path is recorded.
The list lives in `validation.py` (`BROWSER_NOISE`) and
`browser_extension/common.js`; add a pattern only after observing it.

## 3. Pages

- **Dashboard** - the security status, five cards (monitored computers, online now, websites today, threats today, reputation coverage), a "Needs attention" list and the latest 8 visits.
- **Browsing** - every recorded visit (time, computer, user, website, browser, security). The full sanitized page address is a muted second line. Search by website, computer or user, and filter by Safe / Needs review / Dangerous / Not checked.
- **Alerts** - a card per alert: severity, computer, user, website, detected time, why it matters, recommended action; mark as handled.
- **Computers** - computer, user, browser, status, last seen ("Now", "14 min ago", "2 h ago"), websites today, security issues today. The installation ID, exact time and the Archive button are under "Technical details".

Pages refresh themselves every 7 seconds (plain polling, no WebSockets). Only
values that changed are touched, so nothing flickers, and a typed search or open
details survive a refresh.

### What the owner sees: wording of the reputation status

Internal statuses never change; these are the words on screen.

| Internal    | Shown as     | Meaning                                                              |
|-------------|--------------|----------------------------------------------------------------------|
| SAFE        | Safe         | No known threat was detected by the reputation service.              |
| SUSPICIOUS  | Needs review | Suspicious reputation signals; should be reviewed.                   |
| MALICIOUS   | Dangerous    | Identified as potentially malicious.                                 |
| UNKNOWN     | Not checked  | The system could not currently determine this website's reputation.  |

**Not checked is not Safe.** It has its own grey, dashed style everywhere.

### Security status (truthful by design)

The first matching rule wins. "Open alerts" are alerts not yet marked as handled.

| # | Status (shown)       | Code    | When                                                                                   |
|---|----------------------|---------|----------------------------------------------------------------------------------------|
| 1 | Threat detected      | ALERT   | an open Dangerous (MALICIOUS) alert                                                    |
| 2 | Attention required   | WARNING | an open Needs-review (SUSPICIOUS) alert and no Dangerous one                           |
| 3 | Limited visibility   | LIMITED | no open alerts, but one of these visibility limitations applies: the reputation service is Limited or Not configured; no computer is enrolled; computers are enrolled but **none is online**; less than 80% of today's visits have a real verdict |
| 4 | All clear            | OK      | none of the above (including a day with no browsing yet, while the service works and a computer is online) |

When computers are enrolled but none is online, the dashboard says "No monitored
computers are currently online. No confirmed threats were detected in the available
data." This is a visibility limitation, not an alert: nothing is added to the Alerts
page and the heartbeat behaviour is unchanged. Archived computers are not counted,
so archiving the only online computer has the same effect. An open alert still
overrides it.

**Reputation coverage** = (Safe + Needs review + Dangerous visits today) / all visits
today, rounded down so one unchecked visit never shows as 100%. Not checked visits
do not count as evaluated. With zero visits there is no percentage ("No browsing
activity yet today"); 0/0 is never 100%.

**Threat intelligence** (top bar): *Active* = configured and not failing; *Limited* =
configured but rate limited, in back-off, or the most recent lookup failed (this
also survives a server restart because it is read from the cached lookup);
*Not configured* = no `VT_API_KEY`. Technical details (for example the HTTP code)
are only inside "Technical details".

**Needs attention** is a summary of existing state, not an alert engine: open
alerts, reputation service problems, low coverage, no computers, no computer
online, and computers offline for more than 1 hour (information only - being
offline never raises an alert). It is empty only when the status is All clear.

Alert wording is deterministic: a dangerous website visit does not prove the
computer is compromised, and the product neither blocks websites nor cleans
computers, so it never says either.

### Archiving old computers

A dead installation (for example a test browser) can be archived from its
"Technical details" on the Computers page ("Show archived (N)" lists them,
"Restore" brings one back). Nothing is deleted. Counting rules:

| Where                                                              | Archived computers |
|--------------------------------------------------------------------|--------------------|
| Monitored computers, Online now, Websites today, Threats today, coverage, Recent activity, offline list | not counted |
| Browsing page, Alerts page (history)                               | kept and shown     |
| **Open alerts** (and therefore the security status)                | **still counted** - archiving can never hide an unresolved threat |

A computer that connects again is restored automatically, so a live computer can
never stay hidden. Nothing is archived automatically.

## 4. API

| Method | Route                     | Auth    | Purpose                                              |
|--------|---------------------------|---------|------------------------------------------------------|
| GET    | `/api/ping`               | API key | connection test (read-only)                          |
| POST   | `/api/endpoints/register` | API key | register / update a computer                         |
| POST   | `/api/heartbeat`          | API key | "this browser is online"                             |
| POST   | `/api/web-events`         | API key | submit one website visit                             |
| GET    | `/api/status`             | -       | counters, `overview` (status, wording, coverage, needs attention), threat intelligence, `dev_mode` |
| GET    | `/api/visits?after_id=N`  | -       | visits newer than N for page polling; optional `status`, `q` (search), `active=1` |
| GET    | `/api/endpoints`          | -       | computers with live status (`?archived=1` for archived; no UUIDs) |
| POST   | `/endpoints/<id>/archive` and `/restore` | - | hide / bring back a computer (nothing is deleted) |

`summary.security_status` is the full verdict (`ALERT`, `WARNING`, `LIMITED`, `OK`),
not only the alert level.

"API key" routes require `X-Api-Key` when `API_KEY` is set. The server treats
every field as untrusted: it validates, normalizes and sanitizes the computer
name, user, domain, URL, browser, timestamp and UUID even though the extension
already did.

Example web event:

    {"endpoint_uid": "3f1c2a9e-5b7d-4c61-9e2f-0a1b2c3d4e5f", "computer_name": "ACCOUNTING-PC-01",
     "username": "Dana", "domain": "example.com", "url": "https://example.com/page",
     "browser": "Edge", "timestamp": "2026-10-06T12:00:00"}

Duplicate reload/redirect events are suppressed twice: in the extension (same
tab + URL within 5 s) and on the server (same computer + page within 10 s; the
response carries `"duplicate": true` and no new row is written).

## 5. Reputation

`services/reputation.py` exposes `check_domain(conn, domain)` which returns
`{"status": SAFE|SUSPICIOUS|MALICIOUS|UNKNOWN, "source", "reason"}`, using the
`domain_reputation` cache before any provider call. One optional provider
(VirusTotal v3) is active only when `VT_API_KEY` is set (environment only,
never in code); without it every domain is `UNKNOWN`.

| Condition                                   | Status     |
|---------------------------------------------|------------|
| no vendor has analysed the domain           | UNKNOWN    |
| `malicious >= 3`                            | MALICIOUS  |
| `malicious` 1-2, or `suspicious >= 2`       | SUSPICIOUS |
| otherwise                                   | SAFE       |
| HTTP 404 (domain not in VirusTotal)         | UNKNOWN    |
| 401/403/429/5xx, timeout, network, bad JSON | UNKNOWN    |

A failure is never reported as SAFE. After 429 the provider is paused for 15
minutes, after 401/403 for 60 minutes, after other errors for 5 minutes (no
rapid retries); meanwhile new domains are UNKNOWN (shown as Not checked) and the
dashboard shows **Threat intelligence: Limited** (otherwise **Active** or **Not
configured**). Cache TTL: SAFE 24 h (`REPUTATION_CACHE_HOURS`), SUSPICIOUS and
MALICIOUS 6 h, UNKNOWN 30 min. The cache is per domain and shared by all
computers; a valid entry never triggers an API call. The free VirusTotal plan
allows 500 lookups per day.

## 6. Firewall / LAN

For other computers to reach the server, its port must be open for inbound
connections. Nothing in this project changes the firewall. On a Windows server,
run **once, in an Administrator PowerShell**, a rule limited to this one port,
to your local subnet and to private networks:

    New-NetFirewallRule -DisplayName "Website Monitor (TCP 5002, LAN only)" `
      -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5002 `
      -Profile Private -RemoteAddress LocalSubnet

Remove it with `Remove-NetFirewallRule -DisplayName "Website Monitor (TCP 5002, LAN only)"`.
If the network is marked **Public**, change it to Private in Windows settings
rather than opening the rule to Public networks. On Linux with ufw:
`sudo ufw allow from 192.168.1.0/24 to any port 5002 proto tcp`.
Check from another computer: open `http://<server-ip>:5002/api/status` in its
browser.

## 7. Limitations

- **No login on the dashboard.** Anyone who can reach the server can read the
  pages. Keep it on a trusted network or behind a reverse proxy; `API_KEY` only
  protects the endpoint uploads.
- **Plain HTTP by default.** On a LAN the API key and visited websites cross the
  network unencrypted. Put the server behind HTTPS (nginx/Caddy) for anything
  beyond a lab; the extension accepts `https://` addresses.
- **Computer and user names are labels** typed in the extension options; a
  browser extension cannot read Windows identity.
- **Visit time comes from each computer's clock.** Wrong clocks or time zones
  skew "today" counts and ordering. (Heartbeat/online status uses the server clock.)
- **The API key lives in the browser's extension storage** - practical, not
  hardware-backed secret storage. One organization key, no per-computer keys.
- **Only the extension's browser is monitored**, and only while the extension
  is enabled and the server is reachable (missed visits are not queued).
- **A computer that is merely offline never raises an alert**, and one offline
  computer does not change the status (it is listed under "Needs attention" after
  1 hour). Only when **no** monitored computer is online does the status become
  Limited visibility.
- **Archive and "Mark as handled" are plain POST buttons** with no login or CSRF
  token, like the rest of the dashboard.
- **Old browser-generated rows** (for example `ntp.msn.com/edge/ntp` recorded before
  the filter existed) stay in the history; they only affect the coverage figure of
  the day they were recorded.
