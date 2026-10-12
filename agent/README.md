# Website Monitor - Windows network agent (Phase 5.3 prototype)

A second telemetry source next to the browser extension. It reports what a **Windows computer's programs
contact**, without any browser extension, administrator rights, driver, packet capture, certificate or
interception. Run it by hand for now (no service, no installer).

    Windows computer --> agent (reads a table Windows already keeps) --> central server --> reputation --> dashboard

The agent never talks to VirusTotal and never holds its key. The server checks a *domain* with the same
cached reputation service it uses for browser visits. A bare IP address has nothing to look up, so it is
stored as **Not checked**.

## Browser-history fallback (Phase 5.3): website visits without the extension

The browser extension is the preferred, authoritative source of website visits. It is **not mandatory**: when it is missing,
disabled or not reporting, the agent reads **new local visits from Chrome's and Edge's own history** and sends only the **host
name** (for example `www.sqlite.org`). The server then runs its normal reputation check and stores a website visit marked
"Visited website (browser history)". A raw connection to an IP address is never turned into a website visit.

* **How it reads (read-only, no copy).** Chrome and Edge keep visits in a SQLite file named `History` in each profile folder
  (`%LOCALAPPDATA%\Google\Chrome\User Data\Default`, `Profile 1`... and `%LOCALAPPDATA%\Microsoft\Edge\User Data\...`). The browser
  holds that file locked while it runs: a normal read-only open fails with "database is locked" (measured). The watcher opens it with
  SQLite `mode=ro&immutable=1`, which takes no lock, ignores the browser's journal and cannot write (`PRAGMA query_only`). Nothing is
  copied, so no history exists outside the browser's own file, and no temporary file is created. An immutable read can meet a page the
  browser is writing: the error is caught, the cursor is **not** moved and the same visits are read on the next poll. A profile that
  keeps failing is retried less and less often (10 s up to 5 minutes). Nothing about the browser's files is ever changed.
* **Profiles.** Folders named `Default` or `Profile <number>` that contain a `History` file, for Chrome and Edge, of the Windows user
  running the agent (re-checked about every minute: a profile created later is picked up, one that disappears is dropped). Guest and
  System profiles are ignored. Profile names are never sent.
* **Which rows are visits (checked against real Chrome 154 and Edge 153 history files).**

  | Field | Rule | Why |
  |---|---|---|
  | `visits.originator_cache_guid` | must be empty | non-empty means the visit was **synced from another device** (in the Chrome profile examined, 2,612 of 5,069 visits were) |
  | `visits.transition` low byte | not 3 or 4 (frames), not 8 (reload) | only top-level navigations; a reload is not a new visit |
  | `visits.transition` bit `0x20000000` (chain end) | must be set | the last page of a navigation: redirect hops before it do not have the bit, so the page the user landed on is reported once |
  | `urls.url` scheme | `http` or `https` | no `chrome://`, `file://`, `about:`, extensions |
  | `visits.visit_time` | at or after the moment the agent started | never a backfill |
  | `visits.id` | above the last handled id | a visit is read once, never twice |

  Addresses, single-label and internal names (`*.local`, `*.lan`...) are dropped, as everywhere else in the agent. If an old browser
  has no `originator_cache_guid` column the other rules still apply.
* **Baseline, no backfill.** At start nothing already in a history is reported, and nothing made before the start, even a visit the
  browser only writes a few seconds later. Restarting the agent never uploads history. Repeats of one host in one browser inside a
  minute are one event, and the server collapses repeats inside five minutes; a later return to the site is a new visit.
* **Privacy.** The host is cut out **inside the SQL query**: the scheme, `user:password@`, port, path, query string and fragment are
  removed there, so the Python code never holds a full URL, a page title or a search term. Only `{domain, browser, time}` is sent.
  Cookies, passwords, form data, page content and session files are never opened (the query touches two tables, `visits` and `urls`).
  Full URLs are never logged. Switch it off with `HISTORY_WATCH=off`.
* **What it does not cover.** Private/incognito windows (browsers do not record them), history the user cleared or switched off,
  Firefox and every other browser, other Windows users, and any visit older than the agent. Visits appear about 10 s after they happen
  (the browser's own write delay) plus up to one poll (12 s).
* **Together with the extension.** On a computer where both report (the agent linked on purpose with the extension's Installation ID
  in `ENDPOINT_UID`), a history visit is not counted again when the extension reported the same site in the same browser within about
  2 minutes, **whichever arrived first** (decided when the numbers are read; both rows are kept). Computers are matched only by that
  explicit link, never by name. If the agent is not linked it is a separate computer and the same browsing would be listed twice.
* **Cost.** An idle poll takes about 0.3 ms on real 3.5 MB and 9.8 MB history files; the agent's CPU and memory with the watcher on
  or off are within measurement noise (about 1 MB more memory).

## Two collectors

| Collector | Reads | Reports | Memory | Sees default Chrome / Edge? |
|---|---|---|---|---|
| `native` (default) | the Windows TCP connection table (`GetExtendedTcpTable`, a documented API) through `ctypes`, 4 times a second | **program -> public IP address** ("Contacted IP address") | about 38 MB for the whole process tree, 23 MB for Python | **yes**, with the program name |
| `dns` (Phase 5.1) | the Windows DNS client cache through one persistent PowerShell | **domain name** ("Contacted domain") | about 161 MB (PowerShell alone is about 115 MB) | **no**: they bypass the Windows DNS cache |
| `auto` (default setting) | `native`; `dns` only if `native` cannot start | | | |

Neither needs administrator rights. Both stay available; choose with `COLLECTOR` in `agent.env`.

## What the dashboard says, and what that means

| Source | Shown as | What is actually known |
|---|---|---|
| Browser extension | **Visited website** | a page was opened in the browser (domain and path) |
| Agent, `dns` collector | **Contacted domain** | a program on the computer looked this domain name up |
| Agent, `native` collector | **Network activity** (counted per program and day) | a program (named) opened connections to public addresses; neither the address nor the website is kept |

A connection or a lookup is **not** a visit. It does not show that a person opened a website. No domain is
ever invented from an address: reverse DNS was measured and rejected (see below). "Websites visited today"
counts browser visits only; "Domains seen by the agent today" counts only the domain lookups the `dns`
collector reported. Native-collector connections are counted per program in the dashboard's "Network
activity" panel, and a computer that only the agent reports for is shown as "Agent: network only" (its website
visits are not visible), which keeps the overall status at "Limited coverage".

## What it can and cannot see (measured on this project's Windows 11 machine, no administrator)

| Traffic | `native` collector |
|---|---|
| Default Edge 153 and default Chrome 154, fresh profile, extension not installed | **yes**: program name, kind, process id and destination address, for the page and for the browser's own background traffic. The addresses of the sites loaded (apache.org and kernel.org in Edge, mozilla.org in Chrome) were among those recorded, next to many background addresses; for eff.org Chrome's own resolver chose a different CDN address than Windows did, so matching addresses are not guaranteed |
| Any program using TCP (curl, Python, services, applications) | yes, unless the connection is too short (below) |
| A connection that opens and closes between two polls | **missed**. 25 very short curl requests: 100% seen at a 0.1 s poll, 36% at 0.5 s, 20% at 1 s, 12% at 2 s. Real browser connections are short as well: of 53 Edge and 32 Chrome connections, only 40% and 47% lived 1 s or more. The default 250 ms poll catches most browser connections, not all |
| QUIC / HTTP/3 (UDP) | **not in the TCP table at all** (the UDP table has no remote address). A page loaded over HTTP/3 may still show a TCP connection to the same server, but that is not guaranteed |
| The website name | **never**: only the address. Reverse DNS gave a name for 17 of 44 addresses, nearly all infrastructure names (for example `1e100.net` for Google) and none of them the site that was loaded |
| Programs Windows will not open for an unelevated user (protected or administrator programs) | the connection is reported with the program **Unknown** |
| Inbound connections to this computer | not reported (a connection whose local port the same program listens on is skipped) |
| Private, loopback, link-local, shared (100.64/10) and multicast addresses | not reported |

For the `dns` collector see "dns collector notes" below.

## Programs: name, kind, process id

* **Name**: the program's file name only (`msedge.exe`). Never the path, never the command line.
* **Kind**, decided from where the program file lives (never from its name alone):
  * **Windows system process**: the file is inside the Windows folder;
  * **Browser process**: a known browser file name inside Program Files (a folder only an administrator can
    write to), so a program merely *named* `chrome.exe` in a user folder is shown as an ordinary Application;
  * **Application**: anything else; **Unknown application**: Windows refused to identify it.
  A browser process also makes background connections of its own (updates, sync), so "Browser process" says
  what the program is, not that a person was browsing.
* **Process id**: shown only as a tooltip, as transient diagnostic information (it changes whenever the
  program restarts).
* The agent asks Windows for the file path with the *limited information* right only. It never reads a
  command line, memory, tokens or handles.

## Measured cost (Python 3.8.20, this machine)

| | CPU | Memory |
|---|---|---|
| `native`, idle (4 polls a second) | about 0.5% of one core | 38 MB tree (Python 23 MB, launcher 5 MB, console host 10 MB) |
| `native`, while Edge or Chrome loads a page | about 0.9% to 1.6% | unchanged |
| `dns` (Phase 5.1, for comparison) | about 0.5% | 161 MB tree |
| a bare poll loop, by poll interval | 0.7% to 2.6% at 100 ms (two runs), 0.3% at 250 ms, 0.1% at 1 s | 16 MB |

## Run it

1. Python 3.8 or newer on the Windows computer. The agent uses only the standard library (no pip install).
2. Copy `agent.env.example` to `agent.env` and fill in `SERVER_URL` and `API_KEY` (the server's
   `API_KEY`). `COMPUTER_NAME` defaults to the Windows computer name. `USER_LABEL` is optional.
3. Look first, sending nothing:

       python agent\windows_agent.py --dry-run --once --include-existing

4. Run it for real (Ctrl+C stops it cleanly, within about a second):

       python agent\windows_agent.py

The agent registers, sends a heartbeat every 60 s (the computer shows **Online** for 3 minutes after the last
beat, **Offline** after that) and reports what it sees appear. Connections or names that already existed when
the agent started are only a baseline and are **not** reported, because their start time is unknown.

Options: `--config PATH`, `--once`, `--dry-run`, `--include-existing` (diagnostics), `--version`.
Settings: `SERVER_URL`, `API_KEY`, `COMPUTER_NAME`, `USER_LABEL`, `ENDPOINT_UID`, `COLLECTOR`, `NATIVE_POLL_MS`
(100-5000), `POLL_SECONDS` (dns only), `HEARTBEAT_SECONDS`, `STATE_FILE`. Every setting can also be an
environment variable with the prefix `WMA_` (for example `WMA_COLLECTOR`), which wins over the file; the
prefix keeps an unrelated `API_KEY` on the machine from being used.

## Identity

**Device mode (default, agent 0.4.0).** On first start the agent creates two random UUIDs (`os.urandom`) - a
**device UID** (this physical computer) and its own **sensor UID** - and keeps them in `agent_state.json` next to the
configuration. It enrolls with the server (`POST /api/devices/enroll`); the server answers once with a **sensor
secret**, which the agent stores in the same file and sends as `X-Sensor-Secret` on every later request. The server
keeps only a hash. A restart reuses all three. No serial number, MAC address, hostname or other hardware or user data
is part of the identity, and **a matching computer name never merges anything**. If `agent_state.json` is lost the
server refuses to enroll the same device again without its secret: delete the file to enroll as a new computer.

**Pairing browsers (no editing of `agent.env`).** `python windows_agent.py pair-code` prints a one-time code
(8 characters, 5 minutes, one use; only a salted hash is stored in `pairing_code.json`). Type it into the
extension's options page. The agent listens on `127.0.0.1:47619` only (`PAIRING_PORT=0` turns this off) and answers
exactly one request, `POST /pair`, from an extension origin addressed as `127.0.0.1`/`localhost` with a small JSON
body and a valid code: a web page cannot reach it, a request with a foreign Host (DNS rebinding) is refused, a
preflight is never approved, no response carries CORS permission, and five wrong codes destroy the code. The agent
never gives the extension a device UID, a secret or the API key - only a short-lived grant that the server accepts for
that one installation. `PAIRING_EXTENSION_IDS=id1,id2` optionally restricts which extensions may even try.
Nothing sensitive (code, grant, UID) is logged.

**Legacy mode.** If `ENDPOINT_UID` is set in `agent.env` (the Phase 5.2-5.4 way of linking by hand) the agent keeps
exactly that behaviour: no enrollment, no pairing listener. Remove the line to move to device mode; the old
installation row stays in the database as a separate, unverified computer until you archive it (nothing is merged
automatically).

## Privacy

Sent: computer identity, agent version, the domain **or** the public address, the program's file name and
kind, the transient process id, the browser name (history fallback only), time. Never sent: URLs, paths, query
strings, fragments, page titles, search terms, page or HTTPS content, passwords, cookies, form data, keystrokes,
packets, command lines, program paths, ports, the Windows user name. Never opened: cookies, saved logins,
autofill, session files, or any browser file other than the `History` database, which is read read-only and from
which only the host name is cut out (inside the SQL query, so the agent never holds a full URL). Full URLs are
never logged. The server accepts only those fields (a program name that is not a plain file name
is dropped, a bad process id is dropped) and ignores anything else. Internal and infrastructure names and
non-public addresses are dropped by the agent and by the server. The API key is only sent in the
`X-Api-Key` header and is never printed.

## How noise is limited

* Agent: a connection is reported when it newly appears, not more than once per five minutes per program
  and address; a domain is reported when it newly appears in the cache, not more than once a minute; CDN
  names that only appear as the target of another name are skipped; the agent itself and its own server
  are skipped.
* Server: the same computer and domain, or the same computer, program and address, within 5 minutes is one
  observation. A domain lookup that the same (linked) computer also visited in a monitored browser within
  2 minutes is not counted again.
* The server limits how many reputation-provider lookups agent traffic may start (2 per minute, 200 per
  day) so background domains cannot use up the free quota. Addresses never start a lookup.
* The dashboard shows the program and its kind on every row so Windows or application background traffic
  can be told apart from a browser process. Nothing is hidden by a list of domains.
* Queue and memory: at most 500 pending observations (the oldest is dropped when full), at most 25 sent
  per cycle, back-off of 5, 10, 20, 40, 60 seconds when the server is unreachable, at most 5000 remembered
  (program, address) pairs, and the agent never crashes because of the server.

## dns collector notes

Reads `Get-DnsClientCache` through one persistent PowerShell (about 35 ms per read). It sees programs that
use the Windows resolver. Chrome 154 and Edge 153 at default settings do not (they use a built-in DNS
client); with the built-in client switched off they do, but this project does not change browser settings.
It cannot name the program that asked.

## Why not ETW, WFP or packet capture

* **ETW** (`Microsoft-Windows-Kernel-Network`) would also see very short connections and UDP destinations,
  with the process id, but starting a session needs administrator rights (verified: "Access is denied"). A
  ready-to-run, untested probe is in `agent/research/etw_probe.ps1` for an elevated terminal. It still
  gives no website name.
* **Windows Filtering Platform** net events cover dropped traffic; allowed connections only appear in the
  Security log after the audit policy is changed, and collecting them changes system-wide engine options.
  Both need administrator rights and change Windows settings, so they were not used or tested.
* **Packet capture / TLS inspection** is the only way to read a website name for Chrome and Edge. It needs a
  driver or interception and is outside this project's rules.

## Future installer

An installer or a management tool would create `agent.env` (or set the `WMA_*` variables) per computer with
the server address and the organization key, store it where only the agent's account can read it, and start
the agent at logon or as a service. None of that exists yet.

## Troubleshooting

| Message | Meaning |
|---|---|
| `configuration problem: SERVER_URL is not set` | create `agent.env` from the example |
| `configuration problem: COLLECTOR must be one of ...` | use `auto`, `native` or `dns` |
| `the server rejected the API key` | `API_KEY` differs from the server's; observations stay queued |
| `cannot reach the server - will keep trying` | wrong address, server stopped or blocked; it retries with back-off |
| `cannot start the native collector` | not running on Windows, or the TCP table cannot be read |
| `cannot read the TCP table (...) - will keep trying` | a single failed read; the agent keeps going |
| `cannot start the DNS collector` | not running on Windows, or `powershell.exe` is unavailable |
