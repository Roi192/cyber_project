# Endpoint Agent Extension — Full URL Capture & Downloaded-File Hash Monitoring

**Status: planning only. Nothing in this document has been implemented.**
No code changes, no new dependencies, no agent behavior change. Written to
support Step 13's finding that automatic coverage for URL-only Threat
Intel providers (Google Safe Browsing, PhishTank) is currently impossible
because the Endpoint Agent never captures a full URL — only a TCP
destination (host:port).

## 1. Why this is needed

`threat_intel_framework.all_candidate_indicators_for_event()` already
accepts `resolved_ip`, `domain`, `sha256`, `md5` — the hash-candidate
pipeline already exists end-to-end (provider registry entries, TTL
config, corroboration logic all already handle SHA256/MD5). It has never
produced real data because **nothing has ever fed it a hash**. The same
is true for URL-only providers: the code path to check a URL against
Google Safe Browsing / PhishTank already exists (`google_safe_browsing_
provider.py`, `phishtank_provider.py`, manual re-check already works) —
it has no automatic input because the agent has never captured one.

This is a data-availability gap, not a configuration gap, and closing it
needs two genuinely separate, independent capabilities:

## 2. Capability A — Full URL capture, from an authorized source

### 2.1 What the agent sees today
`endpoint_agent_stable.py` enumerates TCP connections via
`psutil.net_connections()` (connection metadata: local/remote IP and
port, process) and separately reads the Windows DNS client cache
(`Get-DnsClientCache`) for hostname attribution. Neither sees anything
above the TCP layer — no HTTP request line, no path, no query string.
Getting one requires a fundamentally different data source.

### 2.2 Candidate sources (ordered from least to most invasive)

| Option | What it needs | Trust/privacy | Feasibility |
|---|---|---|---|
| **(a) Browser history file polling** | Periodically read the logged-in user's own browser history SQLite file (e.g. Chrome/Edge `History`, a local file already readable without elevation) for newly-added URLs since the last poll | Medium — local file read only, no network interception, no new trust anchor; but history includes **every** site visited, not just ones with network telemetry already captured, and a user could argue it is broader than today's connection-level visibility | **Recommended starting point** — smallest new surface, no new OS-level trust change, pure polling (same pattern as the agent's existing DNS-cache polling) |
| **(b) Browser extension** reporting visited URLs to the agent via a local message/HTTP call | A new, separately-installed browser extension; a local listener in the agent | Medium-high — requires users to install/trust an extension; scope can be limited (e.g. only report host+path, never query strings with tokens/PII) | Larger effort: a second deliverable (the extension) with its own review/signing/update story |
| **(c) Local TLS-terminating proxy** (e.g. mitmproxy-style) in front of the browser | Installing a new trusted root CA on the endpoint, routing all browser traffic through a local proxy | **High** — a new, powerful trust anchor on the machine; breaks certificate pinning for some sites; by far the most invasive, closest to real traffic inspection | Not recommended for this project's scope — effectively a new security control in its own right, needing its own threat model and review |

**Recommendation: (a) only, for this project.** It is the only option
that fits the agent's existing "poll a local, already-authorized data
source" design (same pattern as the DNS cache today), needs no new trust
anchor, and needs no second shippable component.

### 2.3 Design sketch for (a) — not implemented
- A new, small polling function (mirrors `collect_local_addresses`'s
  shape): read the browser's `History` SQLite file **read-only**, in
  **copy-then-read** mode (the file is locked while the browser is
  running — the established, safe technique is to copy it to a temp
  path first, exactly how every browser-history forensic/analytics tool
  already does this).
- Track a watermark (last-seen `visit_time`) per browser profile, in the
  agent's own state directory (same pattern as `load_or_create_endpoint_
  uid`'s state file) — only NEW rows since the last poll are ever sent.
- Send only `host + path` (strip query string and fragment by default —
  configurable, off by default, since query strings can carry session
  tokens/PII) alongside the existing telemetry fields.
- New, explicit opt-in environment variable on the **agent** side only
  (e.g. `AGENT_CAPTURE_BROWSER_URLS=false` by default) — this must never
  become a surprise default; an organization deploying this needs to
  consciously opt in, consistent with this project's existing `ENABLE_
  RESPONSE_ACTIONS=false`-by-default pattern.
- Server side: `all_candidate_indicators_for_event` gains a 5th
  parameter (`url=None`), threaded through from a new `web_events.url`
  column (nullable, additive migration) — Google Safe Browsing/PhishTank
  then become real candidates for `automatic_eligible` consideration for
  the first time, subject to their own already-documented quota/ToS
  constraints (unchanged from Step 13's plan: still likely Manual-only
  given PhishTank's undocumented rate limit and GSB's unpublished
  free-tier numbers).

## 3. Capability B — Downloaded-file hash monitoring

### 3.1 Design sketch — not implemented
- Poll (not a kernel-level filesystem filter driver — out of scope/risk
  for a userland agent) the user's `Downloads` folder on an interval,
  same polling discipline as the rest of the agent.
- A file is only hashed once it is **stable** (size unchanged across two
  consecutive polls, and not a known-in-progress extension like
  `.crdownload`/`.part`/`.tmp`) — avoids hashing a partial download and
  avoids reading a large file more than once.
- Compute SHA256 (and MD5, for provider compatibility — URLhaus/
  ThreatFox/VirusTotal already support both) of the completed file only
  — **the file's bytes are never transmitted or stored anywhere**, only
  the two hash values plus filename/size/extension metadata.
- Reuses the existing SHA256/MD5 candidate pipeline exactly as-is (no
  server-side schema change needed beyond what already exists —
  `web_events.sha256`/`md5` columns and the whole provider pipeline
  already read them).
- New, explicit opt-in environment variable (e.g. `AGENT_HASH_DOWNLOADS=
  false` by default), same reasoning as above.

### 3.2 Privacy/security considerations
- Never read/transmit file content — hash only.
- Downloads folder only (not an arbitrary filesystem walk) — bounded,
  predictable scope.
- Clearly document that this creates a SHA256/MD5 record for every file
  an end user downloads, which is a real monitoring-scope change deserving
  its own explicit organizational sign-off before deployment — this is
  not a transparent "no one would notice" addition.

## 4. What would need separate, explicit approval before any of this is implemented
1. The exact browser(s)/history-file format(s) to support (Chrome/Edge
   first, matching the project's existing Windows-only agent scope).
2. The default-off opt-in flags above, and organizational sign-off on
   enabling them for a real deployment.
3. A new `web_events.url` column (additive schema migration) and the
   5th `all_candidate_indicators_for_event` parameter.
4. Updated automatic-eligibility review for Google Safe Browsing/
   PhishTank once real URL candidates exist (their quota/ToS constraints
   do not change — only whether they ever receive a candidate at all).
5. New regression + integration tests (isolated, Mock-based, matching
   every other adapter's existing test discipline) before any live
   activation.

## 5. Explicitly out of scope / not proposed here
- Any form of traffic interception, TLS termination, or new root CA
  installation (option (c) above) — rejected for this project.
- A kernel-mode file-system filter driver for download monitoring.
- Capturing query strings/fragments by default (privacy risk — opt-in
  only, if ever added at all).
- A Linux/macOS agent (unchanged from the existing, already-documented
  "Future Improvements" list in `README.md`).
