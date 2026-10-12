# Web threat analytics and computer risk scoring (Phase C1)

Backend only. Nothing here changes the dashboard, sends a notification, blocks anything or touches an endpoint. All of it **reads** the database
(`analytics.py`; every connection is opened with `PRAGMA query_only = ON`) and is served to signed-in administrators only.

## 1. Architecture and source of truth

| Concept | Where it lives | Notes |
|---|---|---|
| **Physical visit** | a row of `web_visits` | Three sources: `BROWSER` (the extension), `BROWSER_HISTORY` (the agent read the browser's own history), `AGENT` (a DNS lookup the agent saw: **not a visit**, never counted here). One real visit can produce several physical rows. |
| **Logical website visit** | `database._WEBSITE` (SQL) | What a person did once: an extension row, or a history row that no extension row of the **same computer + browser + domain** explains within 120 s. This module reuses that exact SQL, so analytics and dashboard cannot disagree. Physical rows are never summed. |
| **Verdict of a visit** | `web_visits.reputation_status` | The verdict the visit received **when it happened**. Never rewritten; a later change in a website's reputation does not change past visits. `SAFE` is reported as "no threat detected"; anything else that is not `MALICIOUS` / `SUSPICIOUS` / `SAFE` (including `UNKNOWN`, a provider error, an empty value) is **unknown**. |
| **Computer** | `devices` (a stable numeric `device_id`) | `endpoints` are its *sensors*. Legacy / unverified installations are separate devices and are **never merged** on a hostname or an address. Archived computers are hidden, as on the dashboard. |
| **Security alert** | `alerts` + `alert_events` | One open alert per computer + domain per 24 h (Phase A1). *Open alerts* are a snapshot of now and include archived computers (an unresolved threat is never hidden by archiving). |
| **Sensor health (now)** | `endpoints.extension_seen_at`, `agent_seen_at` | Phase 5.7 freshness (180 s). Only the **last** report of each sensor is stored, not a history of heartbeats. |
| **Past activity** | days with a website visit, an agent DNS row, or an agent network counter (`network_activity.day`) | The only evidence of past monitoring the system holds. |

## 2. Time

Timestamps are stored as **local naive text** (`2026-10-08 14:05:09`, the server clock when the event was recorded, no UTC offset). A period of N
days is **N local calendar days ending today**: from 00:00:00 of the day N-1 days ago up to now (today is included, so the current period ends with a
partial day); the **previous period** is the N calendar days immediately before it (23:59:59 of the day before the current period is its last second).
Both boundaries are inclusive. Daily buckets are the local calendar date written in the timestamp, so a day with 23 or 25 hours at a daylight-saving
change is one bucket and no hour arithmetic is used. Only the repeated hour of the autumn change is ambiguous in the stored text (the same wall-clock time
occurs twice); that affects neither the day a visit belongs to nor its count. Allowed periods: **7, 14, 30**.

## 3. Repeated visits, and what is counted once

Every logical visit counts: opening the same site again later is a new visit. The collection layer already stores a reload of one page by the extension
within 10 seconds once, and the agent's history records of one computer + browser + domain within 5 minutes once, so a genuine second visit inside
those windows is not stored twice (disclosed limitation). A visit reported by both the extension and the agent is **one** logical visit.

## 4. Period metrics (`/api/analytics/summary`)

Per period (current and previous): logical visits; visits judged malicious / suspicious / no threat detected / unknown; distinct domains; distinct risky
domains; affected computers (with at least one malicious or suspicious logical visit); alerts created in the period. Plus: open alerts now, a comparison
(`delta`, `percent` - `null` from a zero base - and `reliable`), counts of computers by coverage status and by risk category, and **completeness**.

**Data completeness** says how much of a period the stored data can speak for: `COMPLETE`, `PARTIAL` (monitoring data starts after the period starts, or part
of the period is older than the retention limit `RETENTION_DAYS`, default 30, whose visits have been deleted) or `NO_DATA`. A comparison is `reliable` only when
the previous period is `COMPLETE`. Days before the first record of the whole system have **null** counts in the daily trend (no day is invented); a day with
records but no visits is a real zero; `records_present` tells whether any sensor record exists for that day. A 30-day period can never have a complete
previous period while retention is 30 days.

## 5. The web exposure risk score (0-100)

It measures **evidence of exposure to suspicious or malicious websites**, not network volume. Safe visits and unknown visits are **not inputs**, so a
flood of safe visits can neither dilute nor hide a serious exposure.

For each *risky domain* a computer opened in the period (one entry per computer + domain, counting **logical** visits only):

```
points(domain) = severity_points * repeat_factor * recency_weight

severity_points : MALICIOUS 40   SUSPICIOUS 12            (worst verdict seen for that domain in the period)
repeat_factor   : 1 + 0.5 * (1 - 1/n)                     (n = logical visits to the domain: 1 visit 1.0, 2 visits 1.25, never above 1.5)
recency_weight  : 0.25 + 0.75 * 0.5 ** (age_days / 7)     (age of the LAST visit: today 1.0, 7 days 0.625, 14 days 0.4375, floor 0.25)

raw   = sum(points of malicious domains) + min(sum(points of suspicious domains), 36)
score = round(100 * (1 - exp(-raw / 60)))                 (0 when there is no risky exposure)
```

A dangerous visit is worth at least 40 x 0.25 = 10 points (the recency floor), so it always scores at least 15. Examples (fresh exposure): one dangerous domain 49; two 74; three 86; one suspicious domain 18; any number of suspicious domains at most 45. A dangerous
domain visited 14 days ago scores 25.

Categories: **0** no risky websites observed; **1-24** low; **25-49** moderate; **50-74** high; **75-100** severe web exposure. These describe websites opened,
as judged by a reputation service. The score is **not proof that a computer is infected or compromised**, and nothing in the product says so.

Properties (all tested): deterministic; bounded 0-100; never decreases when exposure is added; independent of input order; a repeatedly reported physical event
adds nothing (logical visits are counted, and the repeat factor is capped); unknown visits do not change the score but mark it as a **lower bound**.

### Insufficient data

A computer gets `INSUFFICIENT_DATA` (score `null`) instead of a number - never "0" - when there is **no risky exposure** *and* any of: website visits cannot be seen
now (not reporting, or network only); fewer than half of the period's days are known for the computer or records exist on fewer than a quarter of the days it has been known; no
website visit at all was recorded in the period. When risky exposure **is** present the score is given, with a note that monitoring is incomplete.

## 6. Monitoring coverage (separate from risk)

`status` is the first that applies: `NOT_REPORTING` (no sensor reports now) > `PARTIALLY_MONITORED` (a known sensor is silent, or only network activity is visible) >
`INSUFFICIENT_HISTORICAL_COVERAGE` (known for under half the period, or records on under a quarter of the known days) > `UNVERIFIED_IDENTITY` (reporting, but the computer
is a browser installation or predates devices) > `REPORTING_NORMALLY`. The parts are returned separately (`current_status`, `identity_status`, `history_status`, the sensors,
and the numbers behind the history rule). A sensor that is online today is **never** treated as proof the whole period was monitored. Coverage is never an input of the score.

## 7. Interfaces (administrator session required, GET only, JSON `{"ok", "meta", "data"}`)

| Route | Returns |
|---|---|
| `/api/analytics/summary?days=7\|14\|30` | period metrics, comparison, completeness, open alerts, computer counts by coverage and risk category |
| `/api/analytics/trends?days=` | daily series of the current and the previous period, with completeness |
| `/api/analytics/computers?days=&limit=` | ranking (`limit` 1-200, default 50): device id, display name, user label (self-reported, never "verified"), risk (score or insufficient data, category, reasons, evidence), malicious / suspicious counts, distinct risky domains, last risky exposure, open alerts, coverage, explanation |
| `/api/analytics/computers/<device_id>?days=` | one computer with the full evidence: every input of the formula and sample visit ids |
| `/api/analytics/coverage?days=` | coverage of every computer, ordered worst first |
| `/api/analytics/computers/<device_id>/activity?days=&limit=` | (Phase C2) one computer's daily series, its most recent risky logical visits (`recent_risky_visits`) and, since Phase C3, its most recent logical visits of every verdict (`recent_visits`, newest first, verdict `MALICIOUS`/`SUSPICIOUS`/`SAFE`/`UNKNOWN`; `limit` 1-100, default 20, applies to each list; each with the id of the existing visit-analysis page) and its open alerts; read-only, same rules |

Errors: `400` for an invalid period or limit, `404` for an unknown or archived computer, `401` without an administrator session. Queries are grouped (the number of statements does not grow with
the number of computers) and limited to the requested period.

## 8. Known limitations (also returned in `meta.limitations`)

* Only websites seen by the extension or read from Chrome / Edge history are counted; private windows and other browsers are not.
* A visit keeps the verdict it received at the time; there is no retroactive re-evaluation yet.
* Unknown visits are not safe; they make a score a **lower bound** (`data_quality.score_is_lower_bound`).
* The server stores no sensor **heartbeat** history, only the last report of each sensor, so past monitoring is inferred from days with records; a quiet day and a gap look the same.
* Visits older than the retention limit are deleted; long periods and the previous-period comparison can be incomplete.
* Quick repeats are stored once (10 s per page for the extension, 5 minutes per domain for agent history).
* The user label of a computer is reported by the sensor and is not authenticated.

## 9. The executive dashboard (Phase C2)

`static/js/executive.js` draws the home page and `/computers/<id>` from these endpoints and adds no figure of its own. Mapping: *Monitored computers* = `computers.total`; *Reporting now* =
`computers.total - computers.by_coverage.NOT_REPORTING`; *Computers with risky websites* = `current.affected_computers`; *Malicious / Suspicious website visits* =
`current.malicious_visits / suspicious_visits`; *Monitoring needs attention* = `by_coverage.NOT_REPORTING + PARTIALLY_MONITORED`. A comparison is shown only when
`comparison.<metric>.reliable` is true. The trend uses `trends.current.daily` (a day before the first record is hatched, never a zero). The ranking is the order returned by `/computers`;
"requiring attention" shows computers with a score above 0, insufficient data, or a monitoring problem (not reporting, partly monitored, little history) and lets the administrator show all.

### Phase D2.3: which computer a visit belongs to

Every figure here is per COMPUTER (device) and every visit, network counter and alert stores the device its sensor belonged to when the event happened (`web_visits.device_id`,
`network_activity.device_id`, `alerts.device_id`, with `attribution` saying how sure that is; see the README). The analytics read that stored device, never the device a sensor is on now, so
a sensor changing computer does not move or change any earlier figure. A computer whose last sensor moved is still listed (`former_device`), with coverage `NOT_REPORTING` and the reason
"no sensor any more", until an administrator archives it. Counts of visits of one sensor therefore split between the computers it belonged to over time.

### Phase C3 chart mapping

The chart needed no new daily data: each day of `trends.current.daily` (and of `activity.daily` on the computer page) already carries `malicious`, `suspicious`, `unknown`,
`no_threat_detected`, `logical_visits`, `records_present` and `before_first_data`. A stacked column is drawn bottom to top as malicious, suspicious, unknown, no threat detected; its height
is proportional to the count (a dangerous or needs-review segment is never drawn shorter than 3 px so that one visit among hundreds stays visible - the label, tooltip and table keep the
exact numbers). `before_first_data` = hatched (no value), `logical_visits == 0` with `records_present` = solid zero mark, without `records_present` = dashed "no record" mark; the last
day is drawn as provisional when the period includes today. No value is ever invented or interpolated.

### Phase D2.1: identity wording

`coverage.identity_status` (`VERIFIED` / `UNVERIFIED`), `device_identity` and `device_identity_verified` keep their values and their old meaning: `VERIFIED` has only ever meant "a Windows
Agent enrolled itself with a secret of its own"; it is **not** administrator approval and no administrator approval exists yet. To say what a computer really is, each computer entry now carries
an additive `identity` block (`level`, `short`, `label`, `explanation`, `admin_approved`) and `coverage` carries `identity_level`, `identity_short`, `identity_label`, `identity_explanation`,
`identity_admin_approved`. Levels: `ADMIN_APPROVED` (never produced today), `SELF_ENROLLED` (stored `VERIFIED`), `UNVERIFIED` (stored `PROVISIONAL`), `LEGACY` (stored `LEGACY`) and `UNKNOWN`
(anything else or missing). `summary.computers.by_identity_level` counts computers per level. `/api/endpoints` carries the same additive `identity_*` fields.

## 10. Example output

`docs/analytics_examples.json` is generated from a synthetic organisation by `tests/make_analytics_examples.py` (no real data).
