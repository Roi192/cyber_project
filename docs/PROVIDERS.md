# The seven threat-intelligence sources

Every website a monitored computer visits is looked up in the sources below (in parallel, each with its own timeout). Their keys and switches live in `.env`; the start-up
report and the dashboard ("Threat-intelligence sources") show the state of each one.

| # | Source | Role | What is sent | `.env` settings |
|---|---|---|---|---|
| 1 | VirusTotal | scoring | the website name | `VT_API_KEY` (no switch), `VT_MAX_PER_MINUTE/DAY` |
| 2 | Google Safe Browsing | scoring | only 4-byte hash prefixes of the name | `GSB_ENABLED`, `GSB_API_KEY`, `GSB_MAX_PER_MINUTE/DAY` |
| 3 | AlienVault OTX | scoring (at most MEDIUM alone) | the website name | `OTX_ENABLED`, `OTX_API_KEY`, `OTX_MAX_PER_MINUTE/DAY` |
| 4 | urlscan.io | scoring | the website name (searches existing public scans; never submits one) | `URLSCAN_ENABLED`, `URLSCAN_API_KEY` (optional), `URLSCAN_MAX_PER_MINUTE/DAY` |
| 5 | APIVoid | **observation only** | the website name | `APIVOID_ENABLED`, `APIVOID_API_KEY`, `APIVOID_MAX_PER_MINUTE/DAY` |
| 6 | MetaDefender Cloud | **observation only** | the website name | `METADEFENDER_ENABLED`, `METADEFENDER_API_KEY`, `METADEFENDER_MAX_PER_MINUTE/DAY` |
| 7 | AbuseIPDB | **observation only**, IP reputation | one validated *public* IP address the site resolves to (never the name) | `ABUSEIPDB_ENABLED`, `ABUSEIPDB_API_KEY`, `ABUSEIPDB_MAX_PER_MINUTE/DAY` |

A source is used only when its key is present **and** its `*_ENABLED` switch is `true` (VirusTotal needs only the key). Observation-only sources are stored and shown with their
evidence but are **never** part of a verdict, a risk score, an alert or the Shadow Mode comparison. AbuseIPDB speaks about an IP address, which may host thousands of sites, so it is
always labelled "IP reputation" and is at most a weak, IP-scoped observation.

## States the dashboard distinguishes
*configured* (key present) - *enabled* (switch on) - *operational* (its latest lookup succeeded) - *unavailable* (error, rate limit, blocked network, budget used) - *not configured*.
"N of 7 sources are operational" counts only sources whose latest lookup really succeeded. An unavailable source is shown as "did not check this - NOT a safe result": a missing
answer is never reported as safe.

## Quotas and failures (all automatic)
* **Budgets:** per source, per minute and per day, shared fairly between sensors (`*_MAX_PER_MINUTE/DAY`). A website over the budget is shown as "not checked yet" and looked up later.
  Defaults are conservative; APIVoid is set to 1 per minute and 2 per day because a trial account has only a handful of credits.
* **Caching:** a website's verdict is reused for `REPUTATION_CACHE_HOURS` (24 h); AbuseIPDB answers are reused per IP for 6 hours, however many websites share the address.
* **Rejected key (HTTP 401/403):** the source is switched off in memory (circuit breaker) until the key changes or the server restarts - no repeated attempts with a bad key.
* **Rate limit (HTTP 429):** the source waits as long as it asked (`Retry-After` / reset headers), 1 to 60 minutes.
* **Other failures (timeout, DNS, TLS, server error):** exponential back-off (x2 per consecutive failure, at most 60 minutes). The reason is shown in plain words and never contains a key.
* TLS certificates are always verified. If a proxy or antivirus re-signs HTTPS on the server, the dashboard shows "TLS certificate not trusted" for that source.

## Alert policy
`SEVERITY_POLICY=legacy`: the four scoring sources decide alerts as before. The proposed corroborated policy is only *compared* in Shadow Mode (`/shadow`); it never creates,
closes or changes an alert. Details: `docs/SEVERITY_POLICY.md`.
