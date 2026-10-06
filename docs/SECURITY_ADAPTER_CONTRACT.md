# Security adapter contract (Phase 13B)

For developers writing a future Suricata / Zeek / Wazuh / Nmap / … adapter. An
adapter is a small **external** program that reads its engine's stable output
(for example Suricata EVE JSON, Zeek logs, Wazuh alerts), maps each item to the
records below and sends them to the platform. The platform contains no
engine-specific code: everything goes through one validated ingestion path.

## 1. The eight data types (never collapse them into one "event")

| Type | Meaning | Where it lives |
|---|---|---|
| RAW TELEMETRY | Unprocessed source records | Stays on the sensor. Never sent, never stored. |
| **OBSERVATION** | Factual, source-attributed record of something seen. **No judgment.** | Telemetry store (separate daily files) |
| EVIDENCE | Context about an indicator | `threat_intel_evidence` (already owned there; the adapter contract does not duplicate it) |
| **DETECTION** | An engine/rule **judgment**, with rule identity | `security_detections` (main DB) |
| ALERT | A detection promoted to analyst attention by explicit policy | `security_alerts` — **never created by ingestion** |
| INCIDENT | A correlated security case | `security_events` — never created by ingestion |
| ENRICHMENT | Lookup context about an indicator | Threat-intelligence tables |
| RESPONSE | An explicit, audited action | `response_commands` — never created by ingestion |

A detection is **not** an alert. Sending a detection changes nothing about
alerts, incidents, responses, Threat Risk or Investigation Priority.

## 2. Authentication

* Register a sensor (operator, on the server): `python sensor_admin.py create <sensor_id> <source_engine>`.
  The secret is shown **once**. There is no registration endpoint and no UI.
* Send every request with two headers: `X-Sensor-Id: <sensor_id>` and `X-Sensor-Key: <secret>`.
  `sensor_id` is an identity, **not** a credential. `X-Agent-Key` (the endpoint-agent key) is never accepted here.
* The server stores only `HMAC-SHA256(pepper, label + sensor_id + secret)`. The **pepper**
  (`SENSOR_CREDENTIAL_PEPPER`) lives only in the server's environment — never in the database or its backups.
  A copy of `cybersec.db` alone can neither authenticate a sensor nor be used to test guessed secrets.
* Unknown, disabled, revoked and wrong-secret all answer the same `401`. If the pepper is
  missing/unsafe the endpoint answers `503` and processes nothing (fail closed).
* `sensor_admin.py rotate <id>` issues a new secret (the old one dies immediately);
  `disable`/`enable` are reversible; `revoke` is permanent.
* **Losing the pepper** (or restoring a database with a different pepper) makes every sensor
  credential unverifiable: restore the pepper from your secret store, or rotate all sensor
  secrets. Back the pepper up **separately** from database backups.
* Use HTTPS between sensor and server outside a lab: the secret travels in a header.

## 3. Endpoint

`POST /api/security-ingest`, `Content-Type: application/json`, body ≤ 512 KB.
Send one record object, or `{"records": [ ... ]}` with 1–100 records.

| Status | Meaning |
|---|---|
| 202 | every record ACCEPTED or DUPLICATE |
| 207 | mixed; per-record results tell which |
| 422 | every record REJECTED |
| 400 | malformed envelope / invalid JSON / batch size out of range |
| 401 | authentication failed (uniform) |
| 413 / 415 | too large / not JSON |
| 429 | rate limited — honour `Retry-After` |
| 503 | storage busy (retry: ingestion is idempotent) **or** authentication not configured |
| 500 | generic internal error (no details are ever returned) |

Response body: `{"status", "accepted", "duplicates", "rejected", "results": [{"index", "status", "reason"?}]}`.
A `reason` is a fixed code such as `BAD_TIMESTAMP` — the input is never echoed.
A record is **accepted in full or rejected in full**; there is no partial acceptance and no quarantine store.

## 4. Record fields

Common (OBSERVATION and DETECTION):

| Field | Rule |
|---|---|
| `record_type` | `OBSERVATION` or `DETECTION` (required) |
| `source_type` | `ENDPOINT`, `NETWORK`, `HOST_LOG` or `ASSET` (required). `THREAT_INTEL`, `BEHAVIORAL`, `LOCAL_IOC`, `MANUAL`, `SYSTEM` exist in the taxonomy but can **never** be claimed by a sensor. |
| `source_engine` | must be a registered engine **and equal the sensor's registered engine** |
| `source_event_id` | 1–128 chars of `A-Z a-z 0-9 . _ : @ / + = -` — the event's identity **in the source** |
| `observed_at` | when the source says it happened — see §5 |
| `endpoint_uid` | optional, must be a well-formed UUIDv4 (`endpoint_identity`); recorded as `SENSOR_ASSERTED` |
| `src_ip` `dst_ip` | valid IPv4/IPv6 (no zone id) |
| `src_port` `dst_port` | integer 1–65535 |
| `protocol` | `tcp udp icmp icmpv6 sctp gre esp ah other` |
| `community_id` | Community ID v1: `1:` + 27 base64 chars + `=` |
| `raw_ref` | a **reference**, not a path — §8 |
| `metadata` | bounded object — §7 |

`sensor_id` may be present only if it equals the authenticated sensor. Any other
key is rejected (`UNKNOWN_FIELD`); `ingested_at` and `endpoint_resolution` can
**not** be sent (the platform stamps/derives them).

DETECTION only: `rule_id` (required, ≤128 chars; a non-negative integer is accepted and
stringified), `rule_name` (≤256), `rule_category` (≤64), `source_severity` (≤32),
`source_action` (≤32), `independence_group`. `source_severity`/`source_action` keep the
**source's own vocabulary** — they are not platform severities and are never converted to one.
Detection-only fields on an OBSERVATION are rejected.

### Endpoint resolution

The platform does **not** map an IP address to an endpoint in Phase 13B. `endpoint_resolution`
is `NOT_ATTEMPTED` (no `endpoint_uid` sent) or `SENSOR_ASSERTED` (the sensor named one).
`EXACT / STALE / AMBIGUOUS / UNKNOWN` are reserved for the later timestamp-aware resolver and
are rejected from sensors. Never assume "current IP = the endpoint at that time".

## 5. Time contract (UTC)

Canonical form: ISO-8601 UTC with milliseconds and a literal `Z`, e.g. `2026-09-19T14:32:10.123Z`.
Accepted input: ISO-8601 with `T` and an **explicit offset** (`Z` or `+03:00`), converted to UTC.
A timestamp with no offset is **rejected** (`BAD_TIMESTAMP`) — never guessed as local or UTC.
`observed_at` must be no more than `SECURITY_MAX_FUTURE_SECONDS` (default 300) ahead and no older than
`SECURITY_MAX_PAST_DAYS` (default 7). `ingested_at` is server-stamped UTC.
Legacy platform timestamps (`web_events.event_time` etc.) are server-local naive text, are not UTC,
and are not rewritten.

## 6. Idempotency

* OBSERVATION key: `(sensor_id, source_event_id)`.
* DETECTION key: `(sensor_id, source_event_id, rule_id)` — one source event may yield several detections
  (e.g. several rules), so `rule_id` is the bounded discriminator.
* First write wins. A re-send — including one with different content — is `DUPLICATE`, never an update.
* Retrying after a network error, a 429 or a 503 is always safe.

Choose `source_event_id` so it is stable across re-reads of the same source item (for example
`eve:<flow_id>:<timestamp>`, a Wazuh alert id, or a Zeek `uid` plus log name and timestamp).
`flow_id` (Suricata) and `uid` (Zeek) are **source-scoped** and are not equal to each other; use
`community_id` as the cross-tool network key.

## 7. Provenance and independence

Every DETECTION carries `independence_group` (`[a-z0-9][a-z0-9._:-]{0,127}`), an opaque token that
says **which detections are not independent**. Examples:

* Suricata and Snort with equivalent rule lineage → the same group (e.g. `rulelineage:et:2100498`).
* Wazuh and Sigma matching the same underlying Windows log → the same group (e.g. `log:<log-id>`).
* VirusTotal vendors are one provider, not separate engines.

Omitted → default `engine:<source_engine>` (all of that engine's detections form one group — independence
is never presumed). This field is **not a risk score**; the platform does not count sources or compute
probability in Phase 13B. "Five tools detected it" must never be treated as higher likelihood.

`metadata`: a JSON object, depth ≤ 3, ≤ 32 keys per object, key ≤ 64 chars, string ≤ 512 chars,
lists ≤ 16 items, serialized ≤ 4 KB, no NaN/Infinity. **Never send raw payloads.**

## 8. `raw_ref` safety

`raw_ref` points back at the source record for a human, e.g. `suricata:eve.json:8123456` or
`wazuh:1726753930.104`. Format: `scheme:opaque` — scheme `[a-z][a-z0-9_]{1,23}`, opaque 1–192 chars of
`A-Z a-z 0-9 . _ : @ # = + -`; no slashes, backslashes, `..`, spaces or control characters. It is stored
and shown (escaped) and **never opened as a file** by the platform. Do not put a path in it.

## 9. Storage

* OBSERVATIONS → `data/telemetry/telemetry_YYYYMMDD.db`, one SQLite file per **UTC day of `observed_at`**
  (physically separate from `cybersec.db`). An event observed at 23:59:59.9 and ingested at 00:00:01 goes to
  the earlier day. A day file is writable only inside the late-arrival window; older files are sealed.
* DETECTIONS → `security_detections` in `cybersec.db`.
* Raw engine logs stay with the engine; the platform stores normalized, bounded records only.
* Retention is **off** by default (`TELEMETRY_RETENTION_ENABLED=false`) and never automatic;
  `python telemetry_admin.py retention --dry-run` shows what would be removed. It can only remove
  `telemetry_YYYYMMDD.db` files older than `TELEMETRY_RETENTION_DAYS` (never `cybersec.db`).

## 10. Query limits (internal helpers)

`telemetry_store.query_observations(start, end, endpoint_uid|ip|community_id|sensor_id, limit)` and
`security_detections.query_detections(start, end, endpoint_uid|sensor_id|community_id, limit)`:
a UTC time range is **required**, ranges are capped, only explicit columns are returned, and `limit`
is clamped to 1000. There is no unbounded scan.

## 11. Worked example

```
POST /api/security-ingest
X-Sensor-Id: lab-suricata-1
X-Sensor-Key: ssk_…
Content-Type: application/json

{"records": [
  {"record_type": "OBSERVATION", "source_type": "NETWORK", "source_engine": "suricata",
   "source_event_id": "eve:1726753930.104:dns", "observed_at": "2026-09-19T14:32:10.123Z",
   "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 53, "protocol": "udp",
   "raw_ref": "suricata:eve.json:8123456", "metadata": {"query": "example.com"}},
  {"record_type": "DETECTION", "source_type": "NETWORK", "source_engine": "suricata",
   "source_event_id": "eve:1726753930.104:alert", "observed_at": "2026-09-19T14:32:10.123Z",
   "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34", "dst_port": 443, "protocol": "tcp",
   "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
   "rule_id": 2100498, "rule_name": "GPL ATTACK_RESPONSE id check returned root",
   "source_severity": "2", "source_action": "allowed",
   "independence_group": "rulelineage:et:2100498", "raw_ref": "suricata:eve.json:8123500"}
]}
```

## 12. What is NOT in Phase 13B

No engine adapters, no correlation, no endpoint/IP resolution, no alert or incident creation from
detections, no response actions, no PostgreSQL migration, no observations in the Investigation view.

## 13. Endpoint resolution (Phase 13C)

`endpoint_network.resolve_endpoint(ip, observed_at_utc)` answers "which endpoint had this IP at that
time?" from timestamped IP history only, returning `EXACT` / `AMBIGUOUS` / `STALE` / `UNKNOWN`
(details: `docs/ENDPOINT_NETWORK_CONTEXT.md`). It is **opt-in**: `ingest_batch(..., resolve_ip_field="src_ip"|"dst_ip")`
applies it inside the service; the HTTP route does not, and adapters must not assume it.

* Only `EXACT` attaches an `endpoint_uid`; `AMBIGUOUS`, `STALE` and `UNKNOWN` never do.
* A `SENSOR_ASSERTED` record is never upgraded to `EXACT`, whatever the history says.
* Which of `src_ip` / `dst_ip` is the internal endpoint candidate is decided by the adapter or the
  later correlation layer and passed explicitly - the platform does not guess.
* Resolution needs a UTC `observed_at` (already required by section 5).

## 14. Per-record endpoint resolution for network sensors (Phase 14B)

Setting `MONITORED_NETWORKS` (alias `SECURITY_MONITORED_NETWORKS`; comma-separated CIDRs; unset/empty = disabled; any malformed entry rejects the whole setting and keeps resolution disabled) makes the ingest
service resolve each `source_type=NETWORK` record **on the server**, using the record's own `observed_at`:

| src | dst | candidate |
|---|---|---|
| internal | external | `src_ip` |
| external | internal | `dst_ip` |
| internal | internal | both, reported separately in metadata; the `endpoint_uid` slot stays empty (`NOT_ATTEMPTED`) |
| external | external | none |

* Adapters still **never** send `endpoint_resolution`; a sensor-supplied `endpoint_uid` stays `SENSOR_ASSERTED` and is never upgraded.
* Only `EXACT` attaches `endpoint_uid`; `AMBIGUOUS` / `STALE` / `UNKNOWN` are stored as a status only.
* The outcome is also stored under the **reserved, server-owned metadata key `platform`**
  (`platform.endpoint_context`). A sensor that sends a `platform` metadata key is rejected
  (`RESERVED_METADATA_KEY`).
* An explicit `ingest_batch(..., resolve_ip_field=...)` (13C) takes precedence and disables this policy.
* Resolution is best effort: a resolver or database problem never rejects or alters the record otherwise.
* The HTTP response gains `resolution`: a count per stored status (never an endpoint identifier).

## 15. Behind a reverse proxy (Phase 14C)

By default the client address used for failed-authentication throttling and the ingest log is the TCP peer. Behind a TLS-terminating reverse proxy every sensor would share the proxy's address,
so an attacker's failed-credential flood could lock out a legitimate sensor. `SECURITY_TRUSTED_PROXY_HOPS` (default `0` = header ignored, identical to earlier phases, max 5) tells the route how many proxies
in front of it append to `X-Forwarded-For`; the client is then the N-th entry counted from the **right**. Malformed, too-short or non-IP values fall back to the TCP peer, and entries on the left (which a client can forge)
are never trusted. Enable it only when a proxy you control really is in front and overwrites the header (`proxy_set_header X-Forwarded-For $remote_addr;`). Nothing else about ingestion changes.
