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
    copy .env.example .env         # then set SECRET_KEY (see below); HOST stays 127.0.0.1 unless you also set API_KEY
    python manage_admin.py create  # creates the first dashboard administrator (asks for a password, hidden)
    python app.py                  # http://127.0.0.1:5002 - sign in with that administrator

Linux / the college server (Ubuntu 20.04, Python 3.8, no root) - exactly these commands, in the project folder:

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python app.py

`python app.py` is the whole start: on the first run it creates `.env` (random SECRET_KEY and API_KEY), the SQLite database and, through a one-time setup page (the code is
printed in the terminal), the first administrator. `python manage_admin.py create` still works as an alternative. The server listens on `127.0.0.1:5002` by default
(`HOST` / `PORT` in `.env`): this computer only. To let other computers reach it set `HOST=0.0.0.0` **and** an `API_KEY`; without the key the application refuses to start
(when `HOST` is changed and `API_KEY` is empty, `python app.py` generates a key for you). The automated test suite is not part of this folder; it is kept in the rollback archive
(`C:\Users\Moshe\cyber_project_rollback\F333_full_backup_20261011`).

## Dashboard sign-in (Phase B)

Every dashboard page, every request the pages make, and every administrative action (marking an alert handled, archiving a computer,
revoking a sensor) requires a signed-in administrator. The default is **deny**: a route is open only if it is explicitly marked as part of the
sensor API or as the sign-in page, so a route added later is protected automatically (the automated test suite failed if an unexpected route was open).

* **Libraries** (pinned in `requirements.txt`, all declare Python >= 3.8): Flask-Login 0.6.3 (sessions), Flask-WTF 1.2.1 (CSRF), WTForms 3.1.2.
  Passwords are hashed with Werkzeug (PBKDF2-HMAC-SHA256, 600 000 iterations, random salt). Newer Flask-WTF / WTForms releases need Python 3.9.
* **First administrator.** There is no default account and no sign-up page. On the server, in the project folder:
  `python manage_admin.py create` (asks for the user name and, hidden and twice, a password of at least 12 characters). Other commands:
  `list`, `set-password NAME` (ends every open session of that person), `disable NAME`, `enable NAME`. The password can never be given on the
  command line or in the environment.
* **`SECRET_KEY`** (required) signs the session cookie: at least 24 random characters, never a placeholder, otherwise the application refuses to start
  (`python -c "import secrets; print(secrets.token_hex(32))"`). Changing it signs everybody out.
* **Sessions.** A browser-session cookie (`wm_session`, HttpOnly, SameSite=Lax; `SESSION_COOKIE_SECURE=true` when the dashboard is served over HTTPS).
  The server ends a session after `SESSION_IDLE_MINUTES` (30) without a click and after `SESSION_MAX_HOURS` (8) in any case; the page refreshing
  itself in the background does not count as a click. Sign out is a button (a POST with a token).
* **CSRF.** Every form carries a token (Flask-WTF); a request without a valid token is refused with 400. The sensor API is exempt because a sensor
  has no browser session: it authenticates with its API key and, once paired, its own secret.
* **Rate limit.** Five failed sign-ins from one address, or ten for one user name from anywhere, inside 15 minutes lock sign-in until the oldest failures
  age out (HTTP 429 with `Retry-After`); refused attempts are not counted, unknown names are limited exactly like known ones, and the answer never
  says whether a name exists. Behind a reverse proxy every visitor has the proxy's address: this limit is then per proxy, not per visitor.
* **Responses** carry `Cache-Control: no-store`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`.

**Test mode cannot reach your real data.** When Python is started by a test runner (`python -m unittest`, pytest), or when `WEBSITE_MONITOR_TEST_MODE=1` is set, `config.py`
switches to *test mode*: it does not read `.env`, it requires `DATABASE_PATH` to be set in the real environment to an absolute path inside the system temporary folder, it
refuses the project's `data/` folder, and `database.get_connection()` re-checks every path it opens. Forgetting to set the path makes the import fail instead of falling back to
the production database. `python app.py` is not a test run and behaves exactly as before.

`python app.py` runs Flask's built-in server (threaded, debug off): it prepares the database itself and refuses to start a second copy on the same port. Gunicorn is no longer
part of the dependencies; if you ever want it, `pip install gunicorn`, run `python manage_db.py init` once and start `gunicorn --workers 1 --threads 4 --bind 127.0.0.1:5002 app:app`
(one worker on purpose: SQLite and the reputation back-off state live in the process). Importing `app` does not touch any database. `python deploy/check_env.py` is a pre-flight
checker (no secrets printed); `python deploy/build_college_package.py <folder>` builds the minimal college package.

### Executive dashboard (Phase C2)

The home page now opens with the existing status banner and "Needs attention" list, then a **Web threat overview** for the last **7, 14 or 30 days** (selector at the top
right; the choice is kept in the address as `?days=`): six cards (monitored computers, reporting now, computers with risky websites, malicious visits, suspicious visits,
monitoring that needs attention) with a comparison to the previous period **only when that comparison is reliable** (otherwise the card says why it is unavailable), a trend
chart of dangerous and needs-review visits per day, and **Computers requiring attention**: each computer's 0-100 web exposure score and category, dangerous and needs-review
visit counts, last risky visit, monitoring coverage and a one-line reason. A computer without enough monitoring data shows **Insufficient data**, never a score or a zero; observed
exposure, monitoring coverage and an unverified device identity are three separate badges. Select a computer for its detail page (`/computers/<id>`): identity and verification,
score and explanation, coverage, risky websites with links to the existing Browsing and visit-analysis pages, recent risky visits, open alerts (linking to the Alerts page) and its own
daily trend. The original live tiles remain under **Today at a glance**; Recent activity, Network activity, Alerts, Browsing and Computers are unchanged. A failed request is shown
as an error with a Try again button, never as zero; an expired session returns to the sign-in page. The page is drawn by `static/js/executive.js` (plain JavaScript and SVG, no library,
no CDN, no inline script) from the read-only analytics API; every value from the API is inserted as text. Requests: three per period change, answers reused for 20 seconds, one
background refresh per minute only while the tab is visible.

#### Phase C3: clearer dashboard

Same data, clearer presentation (no new detection or response feature). The home page now reads in the order an owner needs it: **security status**, **Needs attention**
(urgent issues), **What changed** (period selector and six cards, most important first: dangerous visits, suspicious visits, computers with risky websites, computers
reporting now, monitoring incomplete, monitored computers), **Computers needing attention**, **Website activity per day**, Recent activity. The long scope note of the status banner
is one click away ("What this status covers"); the coverage line stays visible. The trend chart now shows **all** website visits as stacked columns - dangerous, needs review,
could not be checked (dotted), no threat detected - so it is meaningful when nothing dangerous happened; a hatched column is a day before monitoring began, a dashed mark is a day
with no sensor record, a solid mark is a day with sensor records but no website opened, and today is drawn lighter with a dashed outline because it is incomplete. Each computer
is one row: a clickable name (with the unverified-device warning), the last risky visit, a short reason, exposure level, risky visit counts and monitoring status; a computer that
cannot be assessed says "Insufficient data" and "Not enough data to assess", never "no risky visit". A user name is shown only when the API says it is reliably identified (today it
never is). The computer page is organised as identity, observed web exposure, coverage and limits (sensor facts collapsed under Technical details), activity per day, dangerous and
suspicious websites, **recent browsing activity of every verdict**, and open alerts with evidence. Threat-intelligence status, today's counters and network activity moved into a
collapsed **Technical details** section (nothing was removed). One additive read-only API field was needed: `recent_visits` in `/api/analytics/computers/<id>/activity`.

### Analytics and computer risk scores (Phase C1, backend only)

Read-only JSON for a future executive dashboard, behind the administrator sign-in: `GET /api/analytics/summary`, `/trends`, `/computers`,
`/computers/<device_id>` and `/coverage`, each with `?days=7|14|30`. They report logical website visits (the extension and the agent reporting one visit
count once), verdict counts, daily trends, comparison with the previous period, data completeness, an explainable 0-100 **web exposure score** per computer and a
**monitoring coverage** status per computer, kept apart from the score. A computer without enough monitoring data gets "insufficient data", never a reassuring 0.
The formula, the time rules, the limits and example output are in `docs/ANALYTICS.md` and `docs/analytics_examples.json` (synthetic data; Nothing in this phase writes data, changes a verdict or triggers an action.

### API key (required once the server is reachable from a network)

Endpoints authenticate with one organization-wide key sent in the `X-Api-Key`
header. Create one and put it in `.env`:

    python -c "import secrets; print(secrets.token_hex(24))"
    API_KEY=<the value>

Leave `API_KEY` empty only for a server that listens on this computer alone (`HOST=127.0.0.1`): the server then runs in **DEV MODE** and shows a DEV
MODE badge. DEV MODE is **fail-closed for the network**: the application refuses to start with a non-loopback `HOST` and no key, and whatever way it was
started (python, gunicorn, behind a proxy) a sensor request from any address other than this computer is answered 403 while no key is configured. The key is
never logged, never stored in the database and never shown in a page.

**How the sensor API is authenticated (separate from the dashboard).** Three independent layers: (1) the organisation `API_KEY` in `X-Api-Key`
(required for any non-local sensor); (2) per-sensor secrets (`X-Sensor-Secret`) issued by enrollment or pairing, which bind a request to one sensor; (3) neither
ever accepts a dashboard login cookie, and a dashboard login never accepts a key: the two worlds do not overlap. Revoking a sensor is an administrative action:
it needs the organisation key (scripts) or a signed-in administrator with a CSRF token, and is refused with neither, even in DEV MODE.

**Turning the key on for a running installation without interrupting sensors.** (1) Generate a key. (2) Put it into every sensor first: the extension's options page
(Server address / API key) and `API_KEY=` in each `agent/agent.env`; the server ignores the header while no key is configured, so nothing changes yet. (3) Restart each
agent so it reads the key. (4) Only then put the same key into the server's `.env` and restart the server: its sensors already send it. (5) Check `/api/ping` from a
sensor and the heartbeats in the Computers page. To roll back, clear `API_KEY` in `.env` and restart the server.

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

### How the computers are identified (devices and sensors)

**One physical computer is one device; the Windows agent and every browser
extension on it are that device's sensors.** The Computers figure on the dashboard
counts devices, never installations.

* Each browser installation generates a random UUID once and keeps it in
  `chrome.storage.local` (Chrome and Edge, and each browser profile, have separate
  storage, so each is its own *sensor*). Renaming the computer or the user just
  updates the same entry. If the extension is removed and installed again it is a new
  sensor. Nothing about the machine is fingerprinted - no MAC address, serial number
  or Windows account, and a computer name is only ever a label.
* The Windows agent makes a random **device UID** and a random sensor UID the first
  time it starts, enrolls with the server and receives a **sensor secret** (shown once,
  stored only as a hash). Its computer is shown as **Self-enrolled**: the agent registered
  itself, which lets the system recognise the same installation each time. No administrator
  has approved it, so it is never called "verified" or "administrator-approved" (the stored
  value is still `VERIFIED`, kept for compatibility; Phase D2.1 only changed the wording).
* A browser extension on its own is a **provisional** device, shown as *Unverified
  device*: monitoring and VirusTotal analysis work exactly as before, but the product
  does not claim it is a whole physical computer. Two unpaired installations are never
  merged, not even when they share a computer name.
* **Pairing** attaches an extension to the agent's device (see "Pairing a browser with
  the Windows agent" below). It needs the owner's approval each time.
* Installations recorded before devices existed keep their rows and ids and each
  becomes its own *legacy* device at start-up, shown as *Unverified (legacy)*. Nothing is merged
  automatically; the three older duplicate pairs stay as they are.

**What the identity labels mean (Phase D2.1).** *Administrator-approved* (an administrator confirmed
the computer; not available yet, so no computer carries it), *Self-enrolled* (its Windows Agent
registered itself), *Unverified device* (a browser installation not paired with an agent),
*Unverified (legacy)* (recorded before devices existed) and *Unknown identity* (no usable identity
information). None of them proves which physical computer it is; a computer name, address or
username never decides identity. The Computers page, computer details, dashboard and the analytics
API all use these words (additive fields `identity_level`, `identity_short`, `identity_label`,
`identity_explanation`, `identity_admin_approved`; the old `identity`, `verified`, `identity_status`
and `device_identity_verified` keep their earlier values and meaning, which is "enrolled by a Windows
Agent", not approval).

### College demonstration (Team2)

The minimal college package is built from this project with `python deploy/build_college_package.py <target folder>` (41 files: the application only, one `requirements.txt`, no tests,
no Windows Agent, no browser extension) and is started with the five commands above. Its own README (`deploy/README_COLLEGE.md`) covers the private `.env` transfer
(`python deploy/make_college_env.py`), where events come from without the sensors (a `curl` example, or the optional offline demonstration add-on delivered separately) and what to do when PyPI
is blocked. `python deploy/verify_college_package.py <package>` checks the package end to end, and `deploy/docker/` holds the Ubuntu 20.04 test kit. Behind a reverse proxy the application
can be published under a sub-path: set `TRUSTED_PROXY_HOPS=1` in `.env`.

### Pairing a browser with the Windows agent

1. On the computer, run `python agent\windows_agent.py pair-code`. It prints a one-time
   code (8 characters, valid 5 minutes, one use).
2. In the extension's options page type the code and press **Pair with the Windows
   Agent**. The browser asks once for permission to reach the agent on this computer.
3. The extension sends the code to the agent on `127.0.0.1` only. The agent checks it
   and asks the server for a **grant**: random, two minutes, single use, naming exactly
   this installation. The extension gives the grant to the server, which attaches the
   browser to the agent's device and returns a **sensor secret** for it.

Security rules: the agent's listener answers one request (`POST /pair`), only from an
extension origin (`chrome-extension://...`) addressed as `127.0.0.1`/`localhost`, with a
small JSON body and the code; a web page cannot reach it (its origin is a web origin,
a JSON request needs a preflight that is never approved, a rebinding request has the
wrong Host). Five wrong codes destroy the code. A UID, a computer name or the
organisation API key never proves identity: once a sensor has a secret, every request
in its name must carry it (`X-Sensor-Secret`), a paired sensor can only be moved with its
own secret, and a revoked sensor (`POST /api/sensors/<id>/revoke`, API key) is refused
until paired again. The audit table `device_audit` records enrollments, grants,
pairings, refusals and revocations; it never contains a secret, grant or code.

### Which computer an event belongs to, and what happens when a sensor changes computer (Phase D2.3)

Every website visit, network counter and alert stores **the computer its sensor belonged to when the event happened**, found in the append-only table
`sensor_device_associations` (sensor, device, from, to). Pairing a sensor to another computer closes its old association and opens a new one from the next whole second
(the same database statement also updates the sensor's *current* computer, so the two cannot disagree); it never changes where earlier events belong, and a late or
out-of-order event keeps the computer of the time it happened. Each stored event also says how sure that is (`attribution`):

* `RECORDED` - the event time fell inside an association the server recorded;
* `MIGRATED_CURRENT` - inferred when this feature was introduced: the sensor's computer at that time, assumed for its earlier life. **Not independently verified history**;
* `UNCERTAIN_NEAR_BOUNDARY` - within 60 seconds of a change of computer (clock skew could put it on either side); an event exactly on the boundary belongs to the later
  association, and what was stored just before a change is flagged too (only the label is edited, never the computer);
* `UNCERTAIN_LATE_ACROSS_CHANGE` - the event claims a time before the sensor changed computer but reached the server more than 60 seconds later (a late delivery, or a
  sensor clock that is behind); it is attributed to the computer of the claimed time and says it relies on that clock;
* `UNCERTAIN_CLOCK_AHEAD` - the sensor's clock is ahead of the server; the event is attributed to the computer current now;
* `UNCERTAIN_BEFORE_FIRST_ASSOCIATION` - older than the server's first record of the sensor.

A computer whose last sensor moved to another computer is a **former computer**: it stays on the Computers page and in the analytics as *not reporting*, with its evidence,
until an administrator archives it (`Archive this computer`; nothing is deleted). Two sensors are never joined because of a name, address or username, and legacy computers stay
separate. Upgrade: back up `data/monitoring.db`, start the new version (the migration is one transaction and idempotent; it only adds columns and the new table and rebuilds the
small `network_activity` counter table with the computer in its key); to roll back, stop the server and restore that backup.

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

### Second telemetry source: the Windows network agent (prototype)

`agent/` holds a small Windows program that needs no browser extension and no administrator rights.
It has two collectors. The **native** one (default) reads the Windows TCP connection table and reports
**which program connected to which public IP address**, default Chrome and Edge included. The **dns**
one (Phase 5.1) reads the Windows DNS client cache and reports **which domain names the computer looked
up**. The server runs the same cached reputation check on domains; the agent never touches VirusTotal.
Setup, privacy, limits and troubleshooting are in `agent/README.md`.

The dashboard keeps the sources apart because they are different facts:

| Source | Shown as | Known |
|---|---|---|
| Browser extension | **Visited website** | a page was opened in the browser |
| Network agent, browser-history fallback | **Visited website (browser history)** | the browser's own history recorded a new local visit to this site; host only |
| Network agent, dns collector | **Contacted domain** | a program on the computer looked the name up |
| Network agent, native collector | **Network activity** (a count per program, not a row per connection) | a program (shown by name) connected to some public address; neither the address nor the website is kept |

"Websites visited today" counts browser visits only; "Domains seen by the agent today" (shown once an
agent exists) counts only the domain lookups the dns collector reported. Raw connections are never website
visits: they are counted per program in the **Network activity** panel, an address is never turned into a
domain, and there is no reputation check for a bare address.

**Website visits without the extension (Phase 5.3).** The extension is preferred but not mandatory. When it is missing or
silent, the agent's browser-history watcher reads new local visits from Chrome's and Edge's own history, read-only, and sends only
the host name; the server checks it like any visit and shows it as **Visited website (browser history)**. It does not cover private
windows or cleared history, never uploads history that existed before the agent started, ignores visits synced from other devices,
and is not counted again when the extension reported the same site (same linked computer, same browser, within about 2 minutes,
either arrival order). See `agent/README.md`.

**One navigation, one row (Phase 5.4).** When the extension and the agent's history watcher both saw the same navigation
(same linked computer, same browser, same domain, within about 2 minutes, whichever arrived first) every list shows **one**
visit: the extension record is the primary source and the history record is shown as "+ also in browser history (agent)". Both
records are kept in the database (the Browsing page's `?physical=1` audit view lists them all), counts and alerts use the
logical visit, and the reputation is evaluated once. Computers are only matched by the explicit `ENDPOINT_UID` link: an agent
that is not linked is a different computer, so the same browsing there is listed separately.

**Why was a website judged safe or dangerous? (Phase 5.4)** Each row says who checked the website and what they found
("Checked by VirusTotal: 0 malicious, 0 suspicious"), and **View analysis** opens the details: the overall verdict, which sources
saw the visit, and one card per reputation provider with its engine counts (malicious, suspicious, harmless, undetected, timed
out, total), when it was checked and until when the result is reused. A provider that could not answer is shown as
*Provider unavailable*, *Provider error*, *No provider configured* or *Not checked* - never as safe - and sources that are not set up
(PhishTank and other sources that are not set up) are only listed as *Not configured*; nothing calls them. The evidence
(what each provider found, table `reputation_evidence`: counts only, never the raw response) is kept separately from the overall
decision (table `domain_reputation`), and the verdict thresholds are unchanged. A new provider is a class with `name` and
`lookup(domain)` returned by `configured_providers()` in `services/reputation.py`.

**What the status means.** Each computer shows what its sensors are doing *right now* (Phase 5.7). The browser
extension and the Windows agent each have their own last-report time (`extension_seen_at`, `agent_seen_at`; the shared `last_seen`
and the legacy sensor type are never used for this). A sensor is **reporting** only while its own time is at most **180 seconds** old
(three 60-second heartbeats, so two missed beats are tolerated); a missing, unreadable or future time is "not verified" and counts as
not reporting. Only the extension refreshes the extension time and only the agent refreshes the agent time. The states:
**Extension + agent reporting** (both fresh; the only "full" state), **Browser extension only** (website visits visible, network
activity not), **Agent: browser history only** (no extension reporting; visits are read from the browser's own history, lower
confidence), **Agent: network only** (programs are visible, website visits are not) and **No sensor reporting** (offline or not
verified). A computer whose extension has reported before but is silent now is flagged as a missing sensor, and a browser the agent
can read that has no confirmed extension is named as "history only". Priority: dangerous website = *Threat
detected*; suspicious = *Attention required*; otherwise *Limited coverage* if the reputation service is limited,
no computer is online, any online computer is Agent: network only or has No sensor reporting or has a silent extension, or too few
visits could be checked; otherwise *No threats detected*, always scoped to what is monitored ("No threats detected in the monitored
activity (14 websites visited today on 2 monitored computers)"). It never covers network traffic that is not a
website visit. Limits, measured on Chrome 154 and Edge 153: a linked row records only the browser that reported last, so with two
browsers the other one is conservatively listed as history only;
the native collector can miss a connection that opens and closes between two polls, and QUIC (HTTP/3)
traffic is not in the TCP table at all; the dns collector does not see ordinary Chrome or Edge browsing.
The agent complements the extension; it does not replace it. A computer's agent and extension are
separate computers on the dashboard unless you link them on purpose by giving the agent the
extension's Installation ID (`ENDPOINT_UID`).

Duplicate policy: browser = same computer and page within 10 seconds; agent = same computer and domain
(or, for a connection, the same computer, program and address) within 5 minutes. Browser and agent observations are stored separately, never merged or deleted. An agent
lookup that the same linked computer also visited in a monitored browser within 2 minutes is not counted
twice in the dashboard numbers, the threat count or the recent-activity list (the Browsing page keeps both
rows, labelled). The server limits provider lookups started by agent traffic to 2 per minute and 200 per
day; over that a domain is shown as Not checked and checked later.

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
| 3 | Limited coverage     | LIMITED | no open alerts, but one of these visibility limitations applies: the reputation service is Limited or Not configured; no computer is enrolled; computers are enrolled but **none is online**; an online computer is network-only, has no sensor reporting, or has a browser extension that reported before but is silent now; less than 80% of today's visits have a real verdict |
| 4 | No threats detected  | OK      | none of the above (including a day with no browsing yet, while the service works and a computer is online) |

**How alerts are grouped and escalated (Phase A1).** An alert belongs to a *computer* (the device) and a domain, not to one of
its sensors: when the browser extension and the agent's browser history both report one exposure, there is **one** open alert, and
each report is kept as evidence (table `alert_events`: the visit, its verdict, browser, source and time). Every distinct visit stays in
the browsing history; grouping never deletes or merges visits. Two computers are never joined on a name or an address: a legacy or
unverified installation is its own computer. The grouping window is **24 hours from the moment the alert opened** (fixed, not sliding,
and inclusive of its last second): an exposure inside it joins the open alert, an exposure after it opens a new alert, so a domain
visited all day cannot be hidden by one old alert. A handled alert absorbs nothing: the next exposure opens a new alert at once. If
the open alert is *Needs review* (MEDIUM) and new evidence for the same computer and domain is *Dangerous* (MALICIOUS), the same alert is
escalated to HIGH in place: its creation time and first visit stay, and the escalation time, the previous severity and the visit that
caused it are recorded. A severity is never lowered. A visit whose reputation could not be determined (UNKNOWN: rate limit, timeout,
key rejected, domain not known to the service) never creates or changes an alert and keeps its UNKNOWN status for later re-evaluation.
Nothing is blocked or isolated, and no notification is sent in this phase.

*Concurrency (Phase A1.1).* Several requests can report the same exposure at the same instant (the extension and the agent, or a
burst). The grouping decision therefore runs as one SQLite write transaction (`BEGIN IMMEDIATE`: the write lock is taken before the
check, so the check and the insert, update or escalation cannot be interleaved by another request), and the database itself refuses a
second OPEN alert for the same computer and domain inside the window (trigger `trg_alert_one_open_per_group`, built from
`ALERT_GROUP_WINDOW_HOURS`; a trigger rather than a unique index, so a new alert after the window or after an alert was handled is
still allowed). A busy or locked database is waited for, then retried after short delays (`ALERT_LOCK_RETRY_DELAYS`); if it stays
locked the attempt is rolled back completely and the request fails like any other database error - it never leaves half an alert
and never a duplicate. Evidence rows are unique per alert and visit. The requests of the extension and the agent are unchanged.

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
offline never raises an alert). It is empty only when the status is No threats detected.

Alert wording is deterministic: a dangerous website visit does not prove the
computer is compromised, and the product neither blocks websites nor cleans
computers, so it never says either.

### Archiving old computers

A dead installation (for example a test browser) can be archived from its
"Technical details" on the Computers page (archiving a computer archives all of its sensors) ("Show archived (N)" lists them,
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
| POST   | `/api/devices/enroll`     | API key | the Windows agent announces its device; returns the sensor secret once |
| POST   | `/api/sensors/grants`     | API key + sensor secret | an enrolled agent asks for a single-use grant for one extension installation |
| POST   | `/api/sensors/pair`       | API key (+ sensor secret if already paired) | an extension presents a grant and joins the device; returns its sensor secret once |
| POST   | `/api/sensors/<id>/revoke`| API key | block a paired sensor until it is paired again |
| POST   | `/api/web-events`         | API key | submit one website visit (browser extension)         |
| POST   | `/api/network-events`     | API key | submit one network-agent observation: "looked up this domain" (`domain`) or "a program connected to this public IP address" (`destination_ip`, optional `process_name`, `process_kind`, `pid`) |
| GET    | `/api/status`             | -       | counters, `overview` (status, wording, coverage, needs attention), threat intelligence, `dev_mode` |
| GET    | `/api/visits?after_id=N`  | -       | visits newer than N for page polling; optional `status`, `q` (search), `active=1` |
| GET    | `/api/endpoints`          | -       | computers (devices) with live status and their sensors (`?archived=1` for archived; no UUIDs, no credentials) |
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
tab + URL within 5 s) and on the server (same sensor + same browser + page within 10 s;
the response carries `"duplicate": true` and no new row is written). Chrome and Edge
opening one site together are therefore two visits, while an extension visit and the
agent's history record of it (same device, browser and domain within 120 s) remain one
logical visit.

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

- **One role.** Every dashboard administrator can do everything; there are no read-only users, no two-factor sign-in and no password reset by e-mail (reset with
  `manage_admin.py set-password` on the server). Sign-in rate limits are kept in the database and survive a restart.
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
  Limited coverage.
- **Archive and "Mark as handled" are POST buttons** protected by the administrator session and a CSRF token.
- **Old browser-generated rows** (for example `ntp.msn.com/edge/ntp` recorded before
  the filter existed) stay in the history; they only affect the coverage figure of
  the day they were recorded.
