# Suricata integration (Phase 14B)

Suricata is an **external, passive IDS** on a sensor host. It is not forked, modified or embedded. A small
local adapter (`sensors/suricata_adapter.py`, Python standard library only) reads Suricata's `eve.json`,
normalizes a deliberately small set of event types into the platform's security contract
(`docs/SECURITY_ADAPTER_CONTRACT.md`) and posts them to `POST /api/security-ingest` with a **per-sensor credential**.
Suricata never talks to the SOC, and the adapter never touches any application database.

```
 traffic -> Suricata (IDS only) -> eve.json -> suricata_adapter.py --HTTP(S)--> /api/security-ingest
                                                                                 |- DETECTION   -> security_detections (main DB)
                                                                                 '- OBSERVATION -> telemetry store (daily files)
```

**Not in scope:** IPS/blocking, automatic Alerts/Incidents/Responses, correlation, Threat Risk / Behavioral scoring,
`web_events`, PCAP or payload storage, TLS interception, PostgreSQL, other engines (Zeek/Wazuh/Nmap/Sigma).

## You configure monitored NETWORKS, not endpoint IPs

The server setting `MONITORED_NETWORKS` (alias `SECURITY_MONITORED_NETWORKS`) lists the CIDR ranges the platform monitors, for example
`192.168.10.0/24,10.20.10.0/24`. Nothing in the adapter or the server knows any individual endpoint address.
The lab used while developing this phase (Windows endpoint `10.16.56.31`, Kali sensor `10.16.56.43`, network `10.16.56.0/24`) is **test data only**.

* Unset / empty: resolution is **disabled**; every record stays `NOT_ATTEMPTED`. Ingestion itself is unaffected.
* Valid: one or more CIDRs, IPv4 and/or IPv6.
* **Any malformed entry rejects the whole setting** (resolution stays disabled, a `config_error` is logged once, `/security-data` shows a warning). It never becomes "all networks",
  and it never silently keeps only the entries that parsed. Catch-alls (`0.0.0.0/0`, `::/0`) and prefixes broader than `/8` (IPv4) / `/16` (IPv6) are refused.
* Read at process start: restart the web application after changing it.

## What is ingested

| EVE type | Becomes | Notes |
|---|---|---|
| `alert` | `DETECTION` | rule id/name/category, Suricata's own severity (1-3, **not converted**), action, `independence_group` |
| `dns` **responses** | `OBSERVATION` | `src` = client, `dst` = resolver (DNS v3 puts the responder in `src_ip`; the adapter re-orients and records `oriented: swapped`). Requests only with `--include-dns-requests` / `SURICATA_INCLUDE_DNS_REQUESTS=true` |
| `tls` | `OBSERVATION` | SNI (may be absent), version, subject/issuer, JA3 hash (never the JA3 string)/JA4, certificate fingerprint (hash only), ALPN (`tls.client_alpns` / `server_alpns`). Never certificates. Port 443 is not assumed to be HTTPS |
| `flow` (bounded) | `OBSERVATION` | only flows that alerted, moved >= 1 MB, or lasted >= 300 s; state, bytes/packets |
| `stats` | adapter-local health | kernel packets/drops in `status.json`; the server has no health record type (deferred to a later phase) |
| `quic`, `http`, `fileinfo`, `anomaly`, everything else | ignored | counted as `unsupported_<type>`; QUIC is deferred because the current contract cannot represent it without expansion |

Observed on a real Suricata 8.0.6 sensor: timestamps carry the sensor's local offset (e.g. `-0400`), IPv6 addresses are zero-padded (canonicalized by the adapter), DNS is v3, `alert` records can carry a nested `flow` object (ignored), and
`SURICATA ... invalid checksum` alerts (sid 2200074 / 2200077) are observed on this lab sensor; their cause is unresolved (see `docs/SURICATA_CHECKSUM_INVESTIGATION_CLOSURE.md`, Outcome E). They are Suricata engine events / sensor diagnostics: they remain stored as detections like any other, are never promoted or suppressed, and must not independently affect correlation, risk, severity or automated response.

Never forwarded: packet payload, packets, URLs, HTTP headers/bodies, file names, certificate blobs/chains, or any EVE sub-object not named above. (Stock Suricata often logs
`payload`/`packet` in `alert` records **on the sensor**; the adapter drops them. Disabling that in Suricata is a separate sensor-side privacy decision.)

## Alerts are detections, not platform alerts

`alert.severity` is Suricata rule metadata on **its own scale**; it is stored as `source_severity` and is never converted, never feeds Threat Risk, never creates a
Security Alert/Incident and never triggers a response. Nothing in this integration correlates events.

## Normalization rules

* **Timestamps:** EVE writes `2026-09-20T12:00:01.123456+0300` (offset without a colon), which the server rejects. The adapter converts to UTC `...Z` (ms). A timestamp with no offset is never guessed.
* **Protocol:** `TCP`->`tcp`, `IPv6-ICMP`->`icmpv6`, unknown -> `other`.
* **Community ID:** copied verbatim when Suricata provides a valid `community_id` (`1:<27 base64>=`, enabled by `community-id: true` in `eve-log`); otherwise omitted - never computed. **On the verified lab sensor `community-id` is `false` (seed 0), so records carry none**; enabling it is a separate, approved sensor-side change (until then flow_id + the 5-tuple are the only flow keys).
* **`source_event_id`** (deterministic, idempotent): `eve:<type>:<sha256[:40]>` over the canonical JSON list `[sensor_id, type, ...fields]` with a fixed per-type field list:
  alert = `utc_us_timestamp, flow_id, src_ip, src_port, dest_ip, dest_port, proto, gid, signature_id, rev, tx_id, pcap_cnt`;
  dns = `utc_us_timestamp, flow_id, tx_id, dns.type, dns.id, queries`; tls = `utc_us_timestamp, flow_id, tx_id, sni, version`;
  flow = `utc_us_end, flow_id, flow.start, 5-tuple`. Ingestion time is never used. Replaying a line yields the same id (server `DUPLICATE`);
  events that merely share an IP/domain/signature/flow differ by timestamp/tx/id and stay distinct. **One sensor id per EVE stream; never rename a sensor.**
* **`independence_group`:** provenance-aware rule lineage, lower case: `et:<sid>` (2000000-2799999 except the range below); `snort-gpl:<n>` for the ET-converted GPL range (a future Snort adapter emitting the same lineage id
  falls in the same group); `local:<sid>`; and `suricata:<gid>-<sid>` for Suricata's own decoder/stream/app-layer event rules (sid 2200000-2299999, e.g. "SURICATA TCPv4 invalid checksum") and anything unknown - engine-native rules are not ET lineage. It states *where the evidence came from*, not statistical independence. Two Suricata signatures on one flow are
  still one engine on the same packets, and multiple products/sources do not imply confidence.
* **`raw_ref`:** `suricata:<sensor>:eve:<file_id>:<byte offset>` - a provenance label, never a path; the server never opens it.
* **Metadata:** flat strings/short lists (server limits: 4 KB, depth 3, 32 keys). `flow_id` is a string (64-bit). Control characters removed, lengths bounded.
* **Safety cap:** at most 600 alerts per **event-minute** (measured from each alert's own UTC timestamp, never wall-clock) are forwarded; the excess is counted (`skipped_alert_rate_cap`, `alerts_dropped`), never silent. A catch-up read of hours of history in seconds is therefore not mistaken for a flood, and the guard is deterministic on replay.
* Fields kept for a future correlation phase: endpoint_uid (server-resolved), src/dst IP and ports, protocol, DNS name / SNI, flow_id, community_id, signature id, engine, sensor id, observed_at, independence_group, raw_ref.

## Endpoint resolution (server side)

The adapter sends **no** endpoint identifier. With `MONITORED_NETWORKS` set, each NETWORK record is resolved per record by the Phase 13C timestamp-aware resolver (`resolve_endpoint`), using the
record's own `observed_at`:

| src | dst | candidate |
|---|---|---|
| internal | external | `src_ip` |
| external | internal | `dst_ip` |
| internal | internal | both, reported in server-owned `platform` metadata; `endpoint_uid` slot stays empty |
| external | external | none |

Only `EXACT` attaches an `endpoint_uid`; `AMBIGUOUS` / `STALE` / `UNKNOWN` are a status only. An IP is never treated as a permanent identity, and nothing is inferred from hostname/process/user.
Known limitation: a workstation talking to an **internal resolver** or file server is internal<->internal, so its uid slot stays empty by design (both sides remain visible in the metadata).

## Delivery, checkpoint and replay

* Reads <= 100 lines / 256 KB, posts, and advances the checkpoint **only after** the server answered 2xx / 207 / 422. If the outcome of a request is uncertain (timeout, connection reset) the batch is re-sent:
  duplicate-safe replay is preferred to silent loss; the server answers `DUPLICATE`. A crash between POST and checkpoint replays the batch the same way.
* 5xx / 503 / network errors: exponential backoff with jitter (1 -> 60 s), `Retry-After` honored, no checkpoint advance. 429: waits `Retry-After` (>= 1 s). 401/403: stops advancing, backs off 60 s, logs
  `auth_failed` (never a secret); fix the credential and it resumes with nothing lost. 400/413: the batch is bisected to isolate and skip a poison record.
  207/422: validation rejections (`TOO_OLD`, `OBSERVED_AT_FUTURE`, ...) are permanent, counted by reason, and the checkpoint advances.
* Rotation (rename or copytruncate), Suricata restarts, partial final lines, permission errors and a missing file are handled; a deleted/corrupt checkpoint only causes a replay
  (lines older than 7 days are rejected by the server as `TOO_OLD`; an unreadable checkpoint is set aside as `checkpoint.json.corrupt-<ts>`).
* State: `<state-dir>/checkpoint.json` and `status.json` (0600, directory 0700): file identity (device/inode + head hash), byte offset, last source_event_id, last ingest time. **No secrets, URLs with credentials or paths.**
* Status: `python3 suricata_adapter.py status --state-dir <dir>` prints last EVE record seen, last successful ingest, checkpoint age, kernel drops, and counters
  (`lines_read`, `records_parsed`, `records_sent`, `accepted`, `duplicates`, `rejected`, `reject_<REASON>`, `malformed`, `unsupported_<type>`, `retries`, ...). It never claims the sensor is "healthy" and has no score.
* NTP is required on the sensor: records > 300 s in the future or > 7 days old are rejected; the adapter warns when its clock differs from the server's `Date` header.

## Credentials and transport

Create the sensor on the SOC host (the one-time secret is printed once): `python sensor_admin.py create suricata-lab-1 suricata --name "Lab Suricata sensor"`.
Put it into the adapter's env file with an editor (mode 0600) as `SENSOR_KEY=...`. The adapter accepts the secret **only** from the environment / env file - there is no command-line option for it -
and never logs or stores it. It does not use `X-Agent-Key`, the Flask secret or any provider key. Rotate / revoke with `sensor_admin.py rotate|revoke`.

### Credential validation (fails closed, value-free)

The credential is an HTTP header value, so it must be plain ASCII: `ssk_` followed by letters, digits, `_` or `-` (about 47 characters), with no spaces, quotes or control characters.
The adapter validates it **before** any request is built and stops with a sanitized `CONFIG ERROR` (never a Python traceback, never the value). Env files are read verbatim:
only the line ending is removed (a UTF-8 BOM at the very start of the *file* is treated as an encoding marker); the credential is **never** stripped, unquoted or otherwise repaired,
so a stray space, quote, BOM, non-breaking space or non-English keyboard-layout characters are reported, not silently fixed. Non-secret settings (URL, sensor id, paths) tolerate
surrounding whitespace/quotes. Every custom header (`X-Sensor-Id`, `X-Sensor-Key`, `Content-Type`, `User-Agent`) and the URL are checked for ASCII / control characters.
`check-config` prints credential *properties only*, for example `credential: present=yes length=47 ascii=yes non_ascii_chars=0 whitespace=0 quotes=0 control_chars=0 charset_ok=yes prefix_ssk_=yes`.
Typical cause of `non_ascii_chars=3` at position 0: the secret was typed with a Hebrew (or other) keyboard layout - `ssk` becomes three non-Latin letters. Switch to English (US) and re-enter it.

**HTTPS is required whenever the adapter is not on the same host or an isolated loopback/NAT path**: the secret travels in a request header. The adapter warns on any non-loopback `http://` URL and never
disables TLS verification. (In the VirtualBox lab the guest reaches the host's loopback through the NAT adapter at `10.0.2.2:5000`, so the SOC stays bound to `127.0.0.1`.)

> Phase 14C adds hardening (visible EVE read errors, sanitized start-up failures, redirect refusal, `SOC_CA_FILE`, opt-in `SOC_REQUIRE_HTTPS`, trusted-proxy support on the server, a hardened reference systemd unit,
> EVE privacy/permission model, the checksum-alert investigation and the HTTPS design): see `docs/SURICATA_SENSOR_HARDENING.md`. None of it changes what is stored.
>
> The checksum-alert investigation (Workstream A) is closed as Outcome E with the root cause unresolved; the authoritative record is `docs/SURICATA_CHECKSUM_INVESTIGATION_CLOSURE.md` (evidence inventory: `docs/SURICATA_CHECKSUM_EVIDENCE_MANIFEST.md`). A display-only annotation of these engine events is an optional, deferred presentation step and is not implemented.

## Running the adapter manually on the Kali sensor (Phase 14B: no auto-start service yet)

```
# one-time: env file (edit with an editor; do NOT put the key on a command line)
install -m 0600 /dev/null ~/soc-adapter.env
# contents:
#   SOC_URL=http://10.0.2.2:5000        (VirtualBox NAT path to the host loopback - lab only)
#   SENSOR_ID=suricata-lab-1
#   SENSOR_KEY=<one-time secret from sensor_admin.py create>
#   SURICATA_EVE_PATH=/var/log/suricata/eve.json
mkdir -p ~/soc-adapter-state
python3 suricata_adapter.py check-config --env-file ~/soc-adapter.env
python3 suricata_adapter.py run --once --env-file ~/soc-adapter.env --state-dir ~/soc-adapter-state   # process what exists, then exit
python3 suricata_adapter.py run --env-file ~/soc-adapter.env --state-dir ~/soc-adapter-state          # follow live (Ctrl-C = clean stop)
python3 suricata_adapter.py status --state-dir ~/soc-adapter-state
```
(`sudo` is only needed if the EVE file is not readable by your user; adding the user to the file's group is preferable. Add `--start-at-end` to skip existing history.)
Exit codes: 0 clean stop, 2 configuration error, 3 (`run --once`) credential/TLS/redirect failure. `check-config` also reports transport, EVE readability and state-directory writability.
Stop with Ctrl-C (SIGINT/SIGTERM): the current batch finishes, the checkpoint is saved, restart resumes without loss. `sensors/vm/soc-suricata-adapter.service` is a **reference only** and is intentionally not installed in this phase.

## Verifying ingestion

1. Adapter: `status` shows `accepted` growing and `last_ingest_ok_at` recent; `journal`/console lines are JSON (`retry`, `auth_failed`, ...).
2. SOC (admin): `/security-data` shows the sensor with "Last data received (UTC)", detections, observations with DNS/TLS/flow summaries, and resolution status (EXACT rows show the endpoint UUID).
3. Replay check: stop the adapter, delete `checkpoint.json`, run again -> `duplicates` grow, `accepted` does not.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `auth_failed` / status 401 | wrong/revoked `SENSOR_KEY`, or `SENSOR_CREDENTIAL_PEPPER` missing on the server (503) |
| `reject_TOO_OLD` / `reject_OBSERVED_AT_FUTURE` | sensor clock (enable NTP), or replay of > 7-day-old lines |
| nothing arrives, no errors | wrong `SURICATA_EVE_PATH`/permissions; event types not enabled in `eve-log`; check `unsupported_*` counters |
| all records `NOT_ATTEMPTED` | `MONITORED_NETWORKS` unset/invalid (see the note on `/security-data` and the ingest log), or app not restarted after the change |
| records `UNKNOWN`/`STALE` | the internal IP has no/old endpoint-agent history (unmanaged host, agent stopped, address changed) |
| connection errors | SOC not reachable from the sensor (NAT path, firewall); adapter backs off and retries |
| `429` | rate limit (20 req/s); the adapter paces itself and honors `Retry-After` |

## Example organizational deployment

```
 endpoints (managed, with the endpoint agent) --- LAN segments 192.168.10.0/24, 10.20.10.0/24 ---+
                                                                                                  |  SPAN/mirror port, network TAP,
                                     Suricata sensor (IDS, capture NIC on the mirror) <-----------+  gateway placement, or vSwitch mirror
                                        + adapter  --HTTPS + per-sensor key-->  central security server (SOC)
```
Configure `MONITORED_NETWORKS=192.168.10.0/24,10.20.10.0/24` on the server; managed endpoints resolve `EXACT` from agent heartbeats, unmanaged hosts resolve `UNKNOWN`. A single sensor sees only
the traffic delivered to its capture interface: a bridged Wi-Fi VM sees only traffic to/from itself; organization-wide visibility needs a mirror/TAP/gateway.

## Rollback

Ingested detections and observations are **immutable historical evidence**. Normal rollback: stop the adapter; stop Suricata if required; `sensor_admin.py revoke <sensor>`; restore code/config from the rollback copies;
leave ingested rows. There is **no** `DELETE ... WHERE sensor_id`. Cleanup of controlled test artifacts is a separate, reviewed action by exact ids after a fresh verified backup.

## Known limitations

`eve.json` written by stock Suricata can be world-readable and contain payload/packet fields; that is sensor-local and outside the adapter, but worth tightening (`filemode`, `payload: no`, `packet: no`) in a separately approved sensor change.
IPv6 privacy addresses rotate: list the IPv6 /64 of the monitored network in `MONITORED_NETWORKS` as well as the IPv4 range, or IPv6-only flows stay `NOT_ATTEMPTED`.

Encrypted traffic is metadata only (SNI/JA3; DoH invisible); DNS names/SNI are personal browsing metadata (short retention, admin-only access); ET Open contains many informational signatures (tune with `disable.conf` /
`threshold.config`); observations and detections are not correlated; the server has no sensor-health record type; QUIC/HTTP/file events are deferred; performance numbers from a laptop are not an enterprise capacity claim.

## Files

`sensors/suricata_adapter.py`, `sensors/vm/*` (reference systemd unit, env example, `local.rules`, EVE snippet, logrotate reference), `sensors/fixtures/eve_sample.jsonl` (hand-authored representative lines, **not** captured output).
