# Cyber Security Monitoring, Detection & Response Platform

A SOC-like security monitoring and response system built as a college project. It is a working prototype inspired by real SOC/SIEM/EDR concepts — it is **not** a commercial-grade SIEM, EDR, IDS/IPS, or enterprise SOC platform, and this README does not claim otherwise.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Problem Statement](#2-problem-statement)
3. [Solution](#3-solution)
4. [Architecture](#4-architecture)
5. [Main Features](#5-main-features)
6. [Security Architecture](#6-security-architecture)
7. [System Components](#7-system-components)
8. [Event Processing Flow](#8-event-processing-flow)
9. [Alert / Incident Flow](#9-alert--incident-flow)
10. [Response Actions](#10-response-actions)
11. [Technology Stack](#11-technology-stack)
12. [Requirements](#12-requirements)
13. [Installation — Windows Development](#13-installation--windows-development)
14. [Installation — Linux/Kali Server](#14-installation--linuxkali-server)
15. [Endpoint Agent Setup](#15-endpoint-agent-setup)
16. [Environment Variables](#16-environment-variables)
17. [Running the System](#17-running-the-system)
18. [Demo Scenario](#18-demo-scenario)
19. [Security Controls](#19-security-controls)
20. [Limitations](#20-limitations)
21. [Future Improvements](#21-future-improvements)
22. [Academic Scope Disclaimer](#22-academic-scope-disclaimer)

---

## 1. Overview

This project collects telemetry from a monitored Windows endpoint, enriches it with threat intelligence, correlates it against a locally maintained IOC (Indicator of Compromise) list, calculates a risk score, and — when warranted — raises an Alert and/or Incident with a recommended response. An administrator can then request a real, authenticated, allowlisted containment action (block a destination, isolate the endpoint), which the endpoint agent carries out and reports back, with every step recorded in an audit log.

## 2. Problem Statement

Security administrators receive large volumes of raw network/process events and need a structured way to identify which of them are actually meaningful, understand why, and respond in a controlled, auditable way — rather than reacting to a flat, undifferentiated event log.

## 3. Solution

A SOC-like monitoring platform that collects endpoint telemetry, enriches events with threat intelligence (VirusTotal, AbuseIPDB), correlates local IOCs (IP and domain), calculates a risk score and severity, creates Alerts and Incidents when warranted, presents a deterministic Recommended Response, and supports controlled containment through an authenticated endpoint agent — with a strict, explicit separation between response actions that are **simulated** (default, always safe) and actions that are **enforced** (opt-in, requires Administrator rights on the endpoint).

## 4. Architecture

```
Windows Endpoint
      │
      │  HTTP(S) + X-Agent-Key header
      ▼
Flask SOC Server  (Linux/Kali or Windows)
      │
      ├── Web Events (Save-First → ACK → async analysis)
      ├── IP + Domain IOC Correlation
      ├── Reputation Cache (TTL 60 min)
      ├── Security Alerts
      ├── Incidents
      └── Response Commands
      │
      ▼
   SQLite (cybersec.db)
      ▲
      │
Web Event Worker  (separate process)
      │
      ├── VirusTotal
      └── AbuseIPDB

Response path:

Admin (web UI)
  │
  ▼
Alert / Incident  →  Recommended Response (shown, not auto-applied)
  │
  ▼
Response Command  (response_commands table, PENDING)
  │
  ▼
Windows Endpoint Agent  (polls, authenticated)
  │
  ▼
Windows Firewall  (only if ENABLE_RESPONSE_ACTIONS=true on the agent)
```

The SOC server (Flask app + background worker) is Linux-compatible by design — see [Section 14](#14-installation--linuxkali-server). The endpoint agent is Windows-only by design, since it enforces containment through the Windows Firewall — see [Section 15](#15-endpoint-agent-setup).

## 5. Main Features

- Login with RBAC (Admin / Analyst), account lockout after repeated failed attempts
- Authenticated network port scanner for authorized hosts
- Local IOC database (IP and Domain types actively correlated; Hash is stored for future use only — see [Limitations](#20-limitations))
- Live IP reputation lookups (VirusTotal + AbuseIPDB) with a 60-minute cache
- Agent-based endpoint telemetry with asynchronous, non-blocking ingestion
- Deterministic risk scoring and severity classification
- Security Alerts with deduplication and refresh-on-reuse
- Incidents with a deterministic Recommended Response
- Authenticated, allowlisted Response Commands (Block/Unblock Destination, Isolate/Restore Endpoint) with a Simulated/Enforced distinction
- Organization-wide Response / Global Blocklist — fan out a Block Destination request (IPv4/IPv6 only) to some or all managed endpoints from a single admin-approved policy, with a mandatory read-only preview, live per-endpoint coverage, and ownership-isolated Global Unblock — see [Section 10](#10-response-actions)
- PDF security scan reports
- Full audit logging

## 6. Security Architecture

See [Section 19 — Security Controls](#19-security-controls) for the complete, current list of implemented protections.

## 7. System Components

| Component | File | Role |
|---|---|---|
| Main web application | `app.py` | Login/RBAC, dashboard, scanner, alerts, incidents, reports, logs, users, IOC management |
| Reputation & IOC engine | `reputation_routes.py` | Manual reputation lookups, cache, local IOC correlation helpers |
| Web monitoring / Agent API | `web_monitoring.py` | `/api/web-events`, `/api/agent/commands*`, response command logic, event ingestion, Organization Blocklist / Global Policy orchestration |
| Manual network event form | `network_events.py` | Manual event submission page (separate from agent telemetry) |
| Threat intelligence | `threat_intelligence.py` | VirusTotal/AbuseIPDB clients, risk engine, recommended-response builder |
| Background worker | `web_event_worker.py` | Separate process; analyzes PENDING web events asynchronously |
| Endpoint agent (supported) | `endpoint_agent_stable.py` | Windows telemetry collection + response command execution |
| Endpoint agents (deprecated) | `endpoint_agent.py`, `endpoint_agent_browser.py` | Early drafts, kept for project history only — **do not run these** |
| Emergency recovery | `restore_network.py` | Windows-only; removes only this project's firewall rules/isolation |
| Database | `cybersec.db` (SQLite) | All application data |

## 8. Event Processing Flow

```
Agent → authenticated POST /api/web-events → HTTP 202 (immediate ACK)
      → row saved as PENDING
      → Worker claims it → ANALYZING
      → Reputation lookup (CACHE if fresh within 60 min, else LIVE)
      → IP IOC check (always fresh, never cached)
      → Domain IOC check (subdomain-boundary match, always fresh)
      → Risk Score + Severity computed
      → ANALYZED
```

Decision policy (as actually implemented):

- **INFO / LOW** — logged as an event; generally no Alert.
- **MEDIUM** — an Alert is created.
- **HIGH / CRITICAL** — an Alert **and** an Incident are created.
- A local IOC match (IP or Domain) can create an Alert even when the numeric score alone would be LOW — IOC matches are treated as inherently significant.

## 9. Alert / Incident Flow

An Alert is the triage-level object (Acknowledge / Close / Escalate, available to Analyst and Admin). An Incident is opened automatically for HIGH/CRITICAL detections and carries a **Recommended Response** — deterministic text generated from severity + context (IOC match, VT/AbuseIPDB findings, process name, already-blocked/isolated state). The Recommended Response is guidance only; it is never applied automatically.

```
Admin → Request → response_commands (PENDING)
      → Agent polls /api/agent/commands
      → ACKNOWLEDGED
      → Agent executes (or simulates)
      → SUCCESS / FAILED reported back
      → Actions Taken shown on the Incident
      → Audit Log updated
```

## 10. Response Actions

**Recommended Response ≠ Action Taken.** The Recommended Response is text shown to the admin. A Response Command is a separate, explicit, admin-approved action from an allowlist of four types: `BLOCK_DESTINATION`, `UNBLOCK_DESTINATION`, `ISOLATE_ENDPOINT`, `RESTORE_ENDPOINT`. Creating a command is Admin-only, enforced server-side (not just hidden in the UI).

- **Default (`ENABLE_RESPONSE_ACTIONS=false` on the agent):** every command is reported back as `SIMULATED` — no OS/firewall change is made anywhere, including on the SOC server itself.
- **Opt-in (`ENABLE_RESPONSE_ACTIONS=true` on the agent):** the agent actually modifies the Windows Firewall, using rules prefixed `CyberProject_` only. Isolation always creates an explicit Allow rule for the SOC server **before** applying the outbound-block policy, so the management connection is never lost. See [`restore_network.py`](#18-appendix-emergency-recovery) for emergency rollback.

### Organization-wide Response / Global Blocklist

A **Global Policy** fans a single admin-approved Block Destination request out to many managed endpoints at once, reusing the exact same `response_commands`/Agent architecture above — no new command types, no new firewall logic, the Agent is unaware a "policy" exists at all.

- **Target scope:** one canonical IPv4 or IPv6 address per policy (validated server-side with Python's `ipaddress` module, never trusted from the browser). DOMAIN and HASH targets are intentionally not offered here — see [Limitations](#20-limitations) for why.
- **Endpoint scope:** `ALL_MANAGED_ENDPOINTS` (every endpoint with real Agent-observed provenance) or `SELECTED_ENDPOINTS` (an admin-chosen subset, always re-validated server-side against the same managed-endpoint list — a submitted IP that isn't a real managed endpoint is silently dropped, never trusted).
- **Mandatory Preview:** creating a policy is a two-step flow. Step 1 collects the target/scope/reason; Step 2 is a **read-only preview** — eligible endpoint count, presence breakdown (Online/Stale/Offline/Unknown), and exactly what would happen per endpoint — before anything is written. The preview never creates a policy, a response command, or a log entry.
- **Per-endpoint independence:** each eligible endpoint gets its own, independently-owned `BLOCK_DESTINATION` command and its own success/failure outcome — one endpoint's failure never blocks another's, and a policy's own commands are guaranteed never to be confused with an unrelated Alert/Incident/manual command that happens to target the same endpoint+destination (an explicit ownership-isolation mechanism, `force_new=True`, exists specifically to prevent this).
- **Requested Mode vs. Actual Agent Mode:** the policy's "Requested Mode" (Simulated/Enforced) is only the admin's *intent* at submission time — it is never presented as proof anything actually happened. The Policy Details page shows each endpoint's real, self-reported `mode` (`SIMULATED`/`ENFORCED`) only once that specific endpoint's Agent has actually reported a result.
- **Coverage is always live:** per-endpoint status (Pending/Success/Failed) is computed by joining back to `response_commands` on every page load — never a separate stored/cached status that could drift out of sync.
- **Offline endpoints stay PENDING:** an offline/unreachable endpoint still gets a real command queued for it; there is no expiry, so it will be picked up whenever that endpoint's Agent next polls (see [Limitations](#20-limitations)).
- **FAILED requires explicit Retry:** a failed per-endpoint deployment is never automatically retried on page refresh or on a repeat policy submission — an admin must explicitly click Retry, which creates a brand-new command and preserves the old failed one as immutable history.
- **Global Unblock ownership:** disabling a policy issues one `UNBLOCK_DESTINATION` command per covered endpoint, each referencing **only that specific endpoint's own Block command id** (`reference_command_id`) — it can never remove firewall rules created by an unrelated Alert, Incident, or manual action, even if they target the identical endpoint and destination. Disabling a policy does **not** retroactively mark a previously-FAILED endpoint as successful — an endpoint whose block never actually applied has nothing to unblock, and is simply skipped.
- **RBAC:** creating, disabling, syncing, and retrying a policy are all Admin-only, enforced server-side. Analysts have full read-only visibility into the Organization Blocklist list page and every Policy Details page.

## 11. Technology Stack

- **Backend:** Python 3, Flask, Flask-WTF (CSRF), Werkzeug (password hashing)
- **Database:** SQLite
- **Threat Intelligence:** VirusTotal API, AbuseIPDB API (via `requests`)
- **Reports:** ReportLab (PDF)
- **Endpoint Agent:** `psutil` (process/connection enumeration), PowerShell (Windows Firewall)
- **Frontend:** Server-rendered Jinja2 templates, Chart.js (vendored locally, no CDN dependency)
- **Production WSGI (Linux):** Gunicorn

## 12. Requirements

See [`requirements.txt`](requirements.txt) — versions are pinned to what was actually installed and tested:

```
Flask==3.1.3
Flask-WTF==1.3.0
Werkzeug==3.1.8
requests==2.34.2
python-dotenv==1.2.3
psutil==7.2.2
reportlab==5.0.1
gunicorn==26.2.0     (Linux server only — see Section 14)
```

Install with:

```
python -m pip install -r requirements.txt
```

## 13. Installation — Windows Development

```
cd cyber_project
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
copy .env.example .env
```

Edit `.env`:
- Set `FLASK_SECRET_KEY` and `AGENT_API_KEY` (generate each with `python -c "import secrets; print(secrets.token_urlsafe(32))"`).
- Set `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` (only used if the `users` table is empty — see [Section 17](#17-running-the-system)).
- Leave `FLASK_DEBUG=true` for development if you want the auto-reloader; the app defaults to `false` (safe) if this line is removed.

Start:

```
python app.py
```

Database initialization (`initialize_application()` in `app.py`) runs automatically at import time — on `python app.py`, and equally on any WSGI import such as `gunicorn app:app` (see [Section 14](#14-installation--linuxkali-server)). It creates `cybersec.db` and all required tables/columns on first run using additive `CREATE TABLE IF NOT EXISTS`/`ALTER TABLE ADD COLUMN` only, and is safe to re-run on every startup — it never resets or duplicates existing data (e.g. the initial admin account is only ever created once, when the `users` table is empty).

## 14. Installation — Linux/Kali Server

The Flask application and the background worker contain no Windows-specific code (no PowerShell, no Windows paths, no OS-branching) — confirmed by direct source audit. Only `endpoint_agent_stable.py`, `endpoint_agent.py`, `endpoint_agent_browser.py`, and `restore_network.py` are Windows-only, by design (they perform Windows Firewall actions).

```
cd cyber_project
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# edit .env: FLASK_SECRET_KEY, AGENT_API_KEY, FLASK_HOST=0.0.0.0 (for LAN demo)
```

Development-style start (same as Windows):

```
python app.py
```

Production-style start:

```
gunicorn -b 0.0.0.0:5000 app:app
```

> **Security note (Phase 14C).** `FLASK_HOST=0.0.0.0` and `gunicorn -b 0.0.0.0:5000` serve **plain HTTP** and are for a trusted LAN demo only. Never use them for external security sensors or their credentials, never expose port 5000 broadly, and never combine them with `FLASK_DEBUG=true`. An off-box sensor needs HTTPS through a TLS-terminating reverse proxy in front of a loopback-bound application: see `docs/SURICATA_SENSOR_HARDENING.md` (Workstream D).
>
> **MANUAL VERIFICATION REQUIRED.** This project was developed and tested on Windows only. `gunicorn` is a Unix-only tool (it relies on `os.fork()`) and cannot actually run on Windows — it was confirmed in this environment that a Windows `gunicorn` process starts but never binds/serves (connection refused), which is the expected, documented Unix-only limitation, not a bug in this project. The commands above are believed correct based on a full static compatibility audit (no Windows-only imports/calls anywhere in the server code) and standard Flask/Gunicorn usage, but they have **not been executed on an actual Linux/Kali host** in this session. Run them on your Kali machine and confirm: the server starts, `/login` returns 200, and the worker starts without error.
>
> **What *was* verified (Windows, not Linux):** a WSGI-style import test — i.e. `import app` in a fresh Python process, pointed at a brand-new/empty database, with `app.run()` never called — confirms `initialize_application()` correctly creates every required table on import alone, exactly as `gunicorn app:app` would trigger it. This proves the *initialization codepath* is WSGI-safe; it does not prove Gunicorn itself runs correctly on Linux, which remains **MANUAL VERIFICATION REQUIRED**.

Do not use the Flask debug reloader (`FLASK_DEBUG=true`) for the final Linux demo — use Gunicorn or `FLASK_DEBUG=false`.

## 15. Endpoint Agent Setup

The supported agent is **`endpoint_agent_stable.py`**, Windows-only (it reads DNS cache and manages the Windows Firewall via PowerShell). `endpoint_agent.py` and `endpoint_agent_browser.py` are **deprecated, experimental early drafts** — kept only for project history. **Do not use either of them for the final demo or for any new endpoint.**

**Run the Agent from an elevated (Administrator) terminal.** This is recommended for both demo PCs, regardless of whether real response actions are used: `psutil`'s connection enumeration can raise `AccessDenied` on Windows when not elevated, silently preventing telemetry from being collected at all — and Administrator is unconditionally required for any real firewall response action (`ENABLE_RESPONSE_ACTIONS=true`).

On the Windows endpoint:

```
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
copy .env.example .env
```

Edit the agent's own `.env`:
- `AGENT_API_KEY` — must match the SOC server's value exactly.
- `SOC_SERVER_URL` — e.g. `http://192.168.1.50:5000` for a cross-machine demo (defaults to `http://127.0.0.1:5000` if unset, i.e. same-machine testing).
- `ENABLE_RESPONSE_ACTIONS` — leave `false` unless you have deliberately prepared a lab machine (see [Section 10](#10-response-actions)).

Start:

```
python endpoint_agent_stable.py
```

## 16. Environment Variables

Full reference with placeholders: [`.env.example`](.env.example).

| Variable | Required? | Notes |
|---|---|---|
| `FLASK_SECRET_KEY` | **REQUIRED** (SOC server) | App refuses to start outside debug mode without it |
| `AGENT_API_KEY` | **REQUIRED** (SOC server + Agent) | Must match on both sides; server fails closed (503) if unset |
| `VT_API_KEY` | OPTIONAL | Reputation enrichment reduced, not disabled, if blank |
| `ABUSEIPDB_API_KEY` | OPTIONAL | Same as above |
| `FLASK_DEBUG` | DEVELOPMENT | Defaults to `false` if unset |
| `FLASK_HOST` | DEVELOPMENT/PRODUCTION | `127.0.0.1` local-only, `0.0.0.0` for LAN demo only |
| `FLASK_PORT` | DEVELOPMENT/PRODUCTION | Default `5000` |
| `FLASK_SECURE_COOKIES` | PRODUCTION | `true` only over real HTTPS |
| `ENABLE_RESPONSE_ACTIONS` | OPTIONAL (Agent-side only) | Default `false` = simulated only |
| `SOC_SERVER_URL` | OPTIONAL (Agent-side only) | Default `http://127.0.0.1:5000` |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` | REQUIRED only on first run against an empty DB | Ignored once any user exists |
| `SOC_DB_PATH` | OPTIONAL | Selects an alternate SQLite file (e.g. the classroom demo database); unset = the normal `cybersec.db`. Server and all three workers must use the same value — see [Section 18](#18-demo-scenario) |
| `THREATFOX_API_KEY` / `URLHAUS_API_KEY` | OPTIONAL | Multi-provider Threat Intel framework (Phase 12B) — reduced enrichment, not a hard failure, if blank |
| `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` | OPTIONAL | Manual-only Cloudflare Radar lookups from the Reputation page; both required together or neither is used |
| `OTX_API_KEY`, `GREYNOISE_API_KEY`, `GSB_API_KEY`, `PHISHTANK_API_KEY`, `URLSCAN_API_KEY`, `IPQS_API_KEY`, `SHODAN_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET` | OPTIONAL | 8 additional Threat Intel providers (Oct 2026). AlienVault OTX, GreyNoise, PhishTank and urlscan.io work **keyless** at a conservative, doc-confirmed rate even with these blank; the rest report `NOT_CONFIGURED` and contribute nothing until a key is set. Full matrix: `python threat_intel_diagnostics.py status` |
| `THREAT_INTEL_SHADOW_MODE_ENABLED` | OPTIONAL | Default `false`. When `true`, `web_event_worker.py` also computes a side-by-side comparison score from the multi-provider engine, stored in a **separate** database file — never affects the real risk score/severity/decision/alerts. See `docs/THREAT_INTEL_SHADOW_ROLLBACK_AND_ACTIVATION.md` |
| `OTX_ENABLED` | OPTIONAL | Default `false`. When `true`, `threat_intel_worker.py` automatically enriches new indicators via AlienVault OTX (keyless-capable). See `.env.example` for the gradual-rollout note |

See [Section 19 — Security Controls](#19-security-controls) and [Section 20 — Limitations](#20-limitations) for the exact fail-safe behavior when required variables are missing (e.g. `FLASK_SECRET_KEY` unset outside debug mode raises at startup; `AGENT_API_KEY` unset makes every Agent-facing route fail closed with 503).

## 17. Running the System

Minimum supported demo — three terminals plus the agent:

```
Terminal 1 (SOC server):
   python app.py                          # or: gunicorn -b 0.0.0.0:5000 app:app  (Linux)

Terminal 2 (Web Event Worker — must be a separate process, not a Flask thread):
   python web_event_worker.py

Terminal 3 (Threat Intel Worker — async enrichment: ThreatFox/URLhaus/VirusTotal,
            and AlienVault OTX/IPQualityScore if OTX_ENABLED/a key is configured):
   python threat_intel_worker.py

Terminal 4 (Windows endpoint):
   python endpoint_agent_stable.py
```

`threat_intel_worker.py` (Phase 12B, Oct 2026) is required for automatic multi-provider
enrichment to run at all — without it, the Threat Intel / Reputation pages still work for
manual re-checks, but no indicator is ever enriched in the background. Like
`web_event_worker.py`, it is a standalone, long-running process — not a Flask thread — and
reads the same `SOC_DB_PATH` convention.

**Why the worker is a separate process, not a Flask background thread:** Flask's debug reloader can spawn a duplicate child process, and a production WSGI server can run multiple worker processes — either would risk the same event being picked up and analyzed more than once if the analysis loop lived inside Flask itself. Running it as one independent process keeps the "claim a PENDING row atomically" logic correct regardless of how many Flask/Gunicorn workers exist.

**Optional — systemd (Linux only, not required to run the project):**

```ini
# /etc/systemd/system/soc-server.service
[Unit]
Description=SOC Web Server
After=network.target

[Service]
WorkingDirectory=/opt/cyber_project
ExecStart=/opt/cyber_project/venv/bin/gunicorn -b 0.0.0.0:5000 app:app
Restart=on-failure
EnvironmentFile=/opt/cyber_project/.env

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/soc-worker.service
[Unit]
Description=SOC Web Event Worker
After=network.target

[Service]
WorkingDirectory=/opt/cyber_project
ExecStart=/opt/cyber_project/venv/bin/python web_event_worker.py
Restart=on-failure
EnvironmentFile=/opt/cyber_project/.env

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/soc-ti-worker.service
[Unit]
Description=SOC Threat Intel Worker
After=network.target

[Service]
WorkingDirectory=/opt/cyber_project
ExecStart=/opt/cyber_project/venv/bin/python threat_intel_worker.py
Restart=on-failure
EnvironmentFile=/opt/cyber_project/.env

[Install]
WantedBy=multi-user.target
```

> **MANUAL VERIFICATION REQUIRED** — these unit files are provided as a convenience example, not required for the project to run, and have not been deployed/tested on an actual systemd host in this session.

**Initial Admin bootstrap:** if the `users` table is empty at startup, `INITIAL_ADMIN_USERNAME`/`INITIAL_ADMIN_PASSWORD` from `.env` create the first admin automatically (a warning is printed instead if either is blank — the app still starts). This bootstrap is skipped entirely once any user already exists. After first login, create your own personal admin account and consider removing `INITIAL_ADMIN_PASSWORD` from `.env`.

## 18. Demo Scenario

See the standalone **[Class Demo Script](#class-demo-script)** below for the full 5–10 minute walkthrough, and **Appendix: Emergency Recovery** for `restore_network.py`.

### Classroom Demo Database

There are two, deliberately separate, database files:

| File | Purpose |
|---|---|
| `cybersec.db` | The real development database — every alert, incident, endpoint, IOC, and log accumulated while building this project. **Never modified or reset by anything in this section.** |
| `cybersec_demo.db` | A clean, reproducible database built purely through the application's own real initialization path, for the actual classroom demo. Starts with exactly one Admin account, one clearly-labeled controlled demo IOC, and **zero** endpoints/alerts/incidents/response commands/Global Policies — everything else appears live, during the demo, exactly as a real first-time deployment would. |

**Selecting which database the server/worker use** is controlled by the `SOC_DB_PATH` environment variable (see [Section 16](#16-environment-variables)) — read identically by `app.py`, `web_monitoring.py`, `reputation_routes.py`, and `network_events.py`, and inherited automatically by `web_event_worker.py`. Leave it unset for the normal development database; set it (in both the server's *and* the worker's environment) to point at the demo database instead:

```
SOC_DB_PATH=cybersec_demo.db
```

**Building or rebuilding the demo database:**

```
cp .env.demo.example .env.demo     # first time only; fill in real (demo-only) values
python prepare_demo_db.py --db-path cybersec_demo.db --yes-reset-demo-db --env-file .env.demo
```

`prepare_demo_db.py` always deletes the target file first and rebuilds it from scratch through `app.initialize_application()` — the exact same code path a real `python app.py`/`gunicorn app:app` start uses, never hand-written `CREATE TABLE` statements — so every run lands on the identical clean starting state. It seeds exactly one demo IOC (a real, public, well-known benign IP — see the Demo Scenario notes below for why) with a clearly professional description ("Controlled classroom demonstration IOC" / source "Classroom Demo"), and nothing else.

> **⚠️ This script will never operate on `cybersec.db`.** It hard-refuses (exits without touching anything) if `--db-path` resolves — by filename or by full path — to the real development database. It also refuses to run at all without the explicit `--yes-reset-demo-db` flag, and only ever deletes the exact target file it was given, never a wildcard or directory sweep.

**Starting the demo server/worker against the demo database:**

```
Terminal 1:  SOC_DB_PATH=cybersec_demo.db python app.py            # or gunicorn, same variable
Terminal 2:  SOC_DB_PATH=cybersec_demo.db python web_event_worker.py
```

(On Windows PowerShell: `$env:SOC_DB_PATH="cybersec_demo.db"` before running each command, or load `.env.demo` however your shell/process manager prefers.)

### Class Demo Script (5–10 minutes)

1. Dashboard overview — security score, active alerts, open incidents, monitored endpoints
2. Threat Intelligence — show the local IOC list
3. Start/show the Windows Endpoint Agent console
4. Generate a safe event that matches the pre-seeded demo IOC (`1.1.1.1`, Cloudflare's public DNS resolver — see below for why a real, well-known, public IP is used instead of a documentation/test-net address, and the exact command)
5. Show the event move PENDING → ANALYZED in Web Monitoring
6. Show the resulting Alert and its Detection Reasons
7. Show the Recommended Response text on the Incident
8. Admin creates a Response Action (Block Destination)
9. Show the Agent receive and execute/simulate the command
10. Show "Actions Taken" update on the Incident
11. Show the Audit Log entry for the action
12. Return to the Dashboard — counters updated
13. *(Optional — Organization Blocklist)* From Threat Intelligence or the same Incident, click "Add to Organization Blocklist" / "Block Organization-wide" — walk through the mandatory Preview (eligible endpoints, presence breakdown), submit in Simulated mode, then show the Policy Details page's live per-endpoint coverage and, finally, Global Unblock

**Note on step 13:** best demonstrated with at least two managed endpoints connected, so the fan-out to more than one machine is visible — with only one endpoint connected it still works, just less visually compelling.

**Why the demo IOC is a real public IP, not an RFC5737/documentation address:** Python's `ipaddress.is_global` classifies every "documentation/test" range (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) identically to private (RFC1918) space — and both the endpoint agent's own capture filter and the worker's reputation gate key off exactly that check. A documentation-range address would never even be sent by the agent, and even if seeded directly as an IOC, the worker would never reach local-IOC correlation for it. The demo IOC must therefore be a real, globally-routable address — `1.1.1.1` (Cloudflare's public DNS resolver) is used: extremely well-known, and connecting to it is ordinary, authorized internet usage. Because it's a real global IP, the worker's normal reputation pipeline *does* run for real (harmless) VirusTotal/AbuseIPDB lookups the first time it's analyzed — for a legitimate provider IP like this, they return clean/zero results, so the local IOC's fixed `+30` (HIGH severity) stays the only contribution, giving a predictable `risk_score=30` / `severity=LOW` — and an Alert is still created regardless, because a local IOC match forces an alert independent of the numeric severity band. No Incident auto-creates at LOW severity; escalate the Alert manually during the demo to show that workflow.

To generate the matching event on a demo endpoint, hold a real TCP connection open long enough for the agent's poll loop to observe it (a bare `Test-NetConnection` often completes too quickly to be reliably captured):
```powershell
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect("1.1.1.1", 443)
Start-Sleep -Seconds 8
$client.Close()
```

**Fallback if VirusTotal/AbuseIPDB are unavailable during the demo:** use a destination that matches an existing local IOC entry — IOC correlation does not depend on external API availability and still produces a full Alert/Incident.

**Demo modes:**
- **Mode A — Safe Demo (recommended default):** `ENABLE_RESPONSE_ACTIONS=false` on the agent. Full workflow, response actions reported as `SIMULATED`.
- **Mode B — Lab Enforcement Demo:** `ENABLE_RESPONSE_ACTIONS=true`, agent running as Administrator, on a machine you control. Only use this if the enforcement path has already been tested and confirmed working beforehand — see [Section 20](#20-limitations) for this project's current enforcement-test status.

### Appendix: Emergency Recovery

```
python restore_network.py
```

Run as Administrator on the Windows endpoint. It removes only firewall rules whose display name starts with `CyberProject_`, and resets the default outbound firewall policy back to Allow — it does not touch any other firewall rule or reset the firewall as a whole.

## 19. Security Controls

Implemented and verified (Phase 9):

- Password hashing (Werkzeug `generate_password_hash`/`check_password_hash`)
- Session-based authentication with `HttpOnly`, `SameSite=Lax`, env-driven `Secure` cookie flag, 45-minute lifetime
- Role-based access control (Admin/Analyst), enforced server-side, verified to hold even with a technically-valid CSRF token and a hand-crafted request bypassing the UI
- Login lockout after repeated failed attempts, generic error message (no username enumeration)
- CSRF protection (Flask-WTF) on every browser-facing POST form, with exactly two machine-API endpoints explicitly exempted (agent telemetry, agent command results) — not a blueprint-wide exemption
- Agent API key (`X-Agent-Key`, `hmac.compare_digest`, fail-closed if unconfigured)
- Secret management: `FLASK_SECRET_KEY`/`AGENT_API_KEY` from `.env` only, never hardcoded, never logged
- Input validation and length limits on the agent telemetry API; request size capped at 1 MB (HTTP 413 above that)
- Security headers (`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, a documented CSP)
- Centralized error handling — no traceback, DB path, or secret ever rendered to the browser
- Full audit logging (`system_logs`)
- Response commands restricted to an explicit allowlist of four types, Admin-only creation
- Response actions disabled by default (`ENABLE_RESPONSE_ACTIONS=false`)

## 20. Limitations

Documented honestly, for academic credibility:

- SQLite, not an enterprise database — fine for a single-instance demo, not for concurrent multi-writer production load
- One shared `AGENT_API_KEY` for all agents — no per-agent identity/token. In particular, `POST /api/agent/commands/<id>/result` authenticates the caller only via this shared key and does not cryptographically bind a reported result to the specific endpoint a command was queued for — any agent holding the key could in principle report a result for any command id. This is a pre-existing prototype limitation (not introduced by the Organization-wide Response / Global Blocklist feature, which reuses the same command/result plumbing) and has not been redesigned.
- Endpoint identity is currently IP-based, not a stable device identifier
- Domain blocking resolves and blocks current IPs at block-time only — a CDN/IP change after blocking may bypass it. Because of this, the Organization-wide Response / Global Blocklist feature only accepts IPv4/IPv6 targets in this MVP — DOMAIN and HASH targets are intentionally not offered there, to avoid presenting an unreliable control as an organization-wide guarantee (endpoint-specific domain blocking from Alert/Incident Response Actions is unaffected).
- HASH-type IOCs are stored in the schema but **not actively correlated** — no file-hash telemetry source exists yet
- No full packet capture and no network-wide visibility — only what the endpoint agent observes
- Domain attribution relies on the Windows OS-level DNS cache (`Get-DnsClientCache`); browsers using DNS-over-HTTPS (e.g. Chrome's default "Secure DNS") resolve entirely inside the browser process and bypass this cache, so those destinations may show only an IP, or a reverse-DNS (PTR) name marked with an `rDNS` badge in the Web Monitoring UI — **rDNS is attribution enrichment only, never proof that the endpoint actually requested that hostname.** Accordingly, a DOMAIN IOC match is only treated as reliable enough to raise risk score/severity or trigger a Security Alert when it comes from real forward-DNS attribution (`attribution_type="dns"`); an IOC match against an rDNS-derived guess is still surfaced to the analyst as an informational note, but never used to generate or escalate an alert on its own.
- QUIC/UDP traffic (used by some browser connections on port 443) is not visible to the endpoint agent at all — `psutil` does not expose a remote address for UDP sockets on this platform, so only TCP connections are currently monitored
- **IPv6 monitoring/detection**: supported as of the IPv6 correctness fix (capture, DNS-cache/PTR attribution, ingestion, storage, worker analysis, IOC matching, and Web Monitoring display all handle IPv6 addresses) — see the test results for exactly what was verified on this machine. **IPv6 response enforcement (BLOCK_DESTINATION/ISOLATE_ENDPOINT/RESTORE_ENDPOINT against an IPv6 target) is NOT validated** — the code paths involved (Windows Firewall rule construction, domain-to-IPv6 resolution for blocking, SOC-server address resolution for isolation) have not been tested with real Administrator-privileged enforcement and remain future work, consistent with `ENABLE_RESPONSE_ACTIONS=false` by default for both address families.
- No HTTPS unless deployed behind a reverse proxy or otherwise terminated externally — the Flask/Gunicorn server itself does not provide TLS
- The CSP still allows `'unsafe-inline'` for existing inline `<script>`/`<style>` blocks — not rebuilt in this project's scope
- No enterprise-grade rate limiting beyond a simple per-source cooldown on repeated agent-auth failures
- No response-command expiry/TTL — a command queued for an endpoint that never comes back online (Organization Blocklist or otherwise) simply stays `PENDING` indefinitely; there is no cleanup/cancellation mechanism
- No automatic recovery for a `web_events` row stuck in `ANALYZING` if the worker process is killed mid-analysis — a known, accepted Phase-2 limitation, not a bug
- The network scanner (`/scanner`) is a **custom TCP socket/banner scanner built for this project** — it is not a vulnerability scanner (no CVE database, no plugin/signature engine) and should not be described as one
- Risk scoring is a **custom point-based heuristic** built for this project (local IOC severity + VirusTotal detection tiers + AbuseIPDB confidence/report tiers, capped at 100) — it is not CVSS and does not implement any CVSS formula
- A classroom demo served over plain HTTP on an isolated, trusted LAN is an acceptable and intentional scope decision for this project — it must never be described or treated as production-safe
- Real containment enforcement is Windows-only, via the Windows Firewall — there is no Linux/macOS endpoint enforcement
- External reputation enrichment depends on VirusTotal/AbuseIPDB availability and quota; the system runs with reduced enrichment (not a hard failure) if a key is missing or a provider is unreachable
- **Real firewall enforcement (`ENABLE_RESPONSE_ACTIONS=true`) has not been validated with genuine Administrator privileges in the development environment used to build this project** (confirmed no-admin session throughout). Enforcement code was exercised end-to-end and fails safely without Administrator rights; a real Administrator-privileged test on a lab machine is documented as **required before any Mode B demo** — see the Phase 10 completion report's test matrix for exact status.
- Linux/Kali server startup, Gunicorn, and the Windows-Agent→Linux-Server LAN path are believed correct from a full static code audit and standard usage, but were not executed on an actual Linux host in the environment this project was developed in — see the Phase 10 completion report for exactly what was and was not executed. The same static-audit conclusion (no Windows-only imports/paths/calls) was independently re-confirmed for every file added by the Oct 2026 Threat Intel project (8 new provider adapters, `threat_intel_worker.py`, `threat_intel_shadow.py`, `threat_intel_risk.py`, `threat_intel_display.py`, `threat_intel_diagnostics.py`) — same caveat applies: not yet executed on a real Linux host.
- **Multi-provider Threat Intel (Phase 12B) and Shadow Mode (Oct 2026):** 5 providers (ThreatFox, URLhaus, VirusTotal, AbuseIPDB, Cloudflare) are live-verified with real traffic. The 8 providers added in Oct 2026 (AlienVault OTX, GreyNoise, PhishTank, urlscan.io, Google Safe Browsing, IPQualityScore, Shodan, Censys) are implemented and covered by an extensive isolated/Mock test suite, but **real outbound connectivity to them has only been confirmed as blocked-by-sandbox-TLS-policy in the development environment used to build this project, never as successfully working** — this must be verified on the actual deployment host before relying on them. Shadow Mode (`THREAT_INTEL_SHADOW_MODE_ENABLED`) is live-activated in the development environment (comparison-only, proven to never affect real risk_score/severity/decision/alerts across 5,000+ real events) but defaults to disabled; AlienVault OTX's automatic background enrichment (`OTX_ENABLED`) defaults to disabled pending that same real-connectivity confirmation.

## 21. Future Improvements

Clearly out of scope for this submission, listed as future work only:

- Per-agent identity/token instead of one shared key
- TLS/mTLS between agent and server
- PostgreSQL (or another multi-writer database) instead of SQLite
- SIEM integration
- EDR-style deep telemetry
- Packet/network-level sensors
- Real HASH-IOC telemetry and correlation
- DNS telemetry
- Enterprise-grade rate limiting
- A centralized policy engine
- Automated containment approval workflows (beyond manual admin approval)
- Richer/additional threat intelligence sources
- A Linux/macOS endpoint agent

## 22. Academic Scope Disclaimer

This project is a prototype built for a college course, demonstrating SOC-like concepts (detection, alerting, incident management, and controlled response) end-to-end on real code and a real (if small) threat-intelligence pipeline. It is not a full SIEM, EDR, IDS/IPS, or enterprise SOC platform, and no claim to that effect is made anywhere in this repository.
