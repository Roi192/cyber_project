# Endpoint network context, IP history and endpoint resolution (Phase 13C)

Foundations that let a future network sensor's observation (an IP address at a
time) be tied to a managed endpoint **only when historical evidence supports it**.
Nothing here creates detections, alerts, incidents or responses, and nothing here
changes Threat Risk, behavioral analysis or Investigation Priority.

> **The fundamental rule: the current IP address must never be assumed to be the
> historical identity.** An endpoint record is an IP record; "which endpoint had
> this IP at that time?" is answered only from timestamped history.

## 1. What the endpoint agent observes — and does not

The agent is **not a packet sniffer**. It observes operating-system-visible
connection metadata (`psutil.net_connections`): for a connection that *exists while
the agent polls*, the local address, the remote address, the remote port and whether
the socket is TCP or UDP.

It does **not** observe or claim: packet capture, payloads, complete network traffic,
a full connection history, or application-layer protocol identification. Events use
the wording "observed endpoint connection", never "captured packet".

## 2. Event fields (new, optional, additive)

Sent only when the OS reported them; `NULL` otherwise; historical rows stay `NULL`.

| Field | Meaning |
|---|---|
| `destination_port` | The remote port of the observed connection, integer 1–65535. Never guessed: not derived from a URL, a domain, or a well-known port ("443 because HTTPS" is never used). |
| `transport_protocol` | `tcp` or `udp` — the socket type only. **TCP/443 is not automatically HTTPS; UDP/443 is not automatically QUIC.** No application protocol is inferred. |
| `source_ip` | The connection's **local** address as reported by the OS. It is not the HTTP client address of the request and not `endpoint_ip`. Loopback/link-local are stored as observed facts but never enter IP history. |

The server re-validates each field (`endpoint_network.sanitize_*`); an invalid optional
value becomes `NULL` and **never rejects the event**. The dedup window means the port
recorded is that of the first connection seen for a (process, destination, IP) in the
window. UDP events are uncommon because only *connected* UDP sockets carry a remote
address.

## 3. Heartbeat

`POST /api/endpoint-heartbeat`, authenticated by the existing `X-Agent-Key`
(fail-closed). Payload (strict): `endpoint_uid`, `endpoint_ip`, `addresses` (≤ 16),
optional `interval_seconds`. **No** process list, files, browsing history or documents
— presence and network identity, not surveillance.

- Default interval 60 s (`ENDPOINT_HEARTBEAT_SECONDS`, 15–600). The agent re-evaluates
  its primary IP and eligible addresses each cycle, so an IP change needs no restart;
  event `endpoint_ip`, `should_monitor_connection` and command polling follow the
  refreshed IP.
- Write amplification is bounded: at most one history write per (endpoint, IP) per 30 s
  (`ENDPOINT_HISTORY_WRITE_MIN_SECONDS`); an unchanged heartbeat costs no database access.
- Responses: 202 ok · 409 conflict (see §6) · 400 malformed · 401 unauthorized ·
  413 too large · 415 not JSON · 503 not configured / storage busy · 500 generic.
- Sensor credentials do not authenticate it; the agent key does not authenticate
  `/api/security-ingest`.

Reported addresses: interfaces that are **up**, minus virtual/hypervisor/container
adapters (default pattern `vEthernet|VMware|VirtualBox|Hyper-V|docker|WSL|Loopback|Teredo|isatap|Bluetooth`,
override `AGENT_EXCLUDE_ADAPTER_PATTERNS`; the count of excluded addresses is printed).
Those subnets repeat across hosts, so reporting them would let a *different* host match.
VPN adapters are kept. Server policy (`history_eligible_ip`): recorded = private, CGNAT,
ULA, global; not recorded = unspecified, loopback, multicast, broadcast/reserved and
link-local (169.254/16, fe80::/10 — per-link, non-unique, non-routable).

## 4. IP history (`endpoint_ip_history`)

A row means: **"this stable agent installation (`endpoint_uid`) was observed using this
IP during `[first_seen_at, last_seen_at]`."** It does *not* mean the IP permanently
belongs to it.

- One row per **interval**, not per (endpoint, IP): an observation within
  `ENDPOINT_HISTORY_CONTINUITY_GAP_SECONDS` (300 s) of the latest interval *extends* it;
  a longer silence starts a **new** interval, so an endpoint that leaves an IP and returns
  later never claims the time it was away. Old rows are never deleted or rewritten when
  the IP changes.
- Multiple simultaneous addresses (Ethernet, Wi-Fi, VPN, IPv4, IPv6) are separate rows for
  the same `endpoint_uid`; they are never collapsed.
- History exists only for events/heartbeats **carrying a stable `endpoint_uid`**; UID-less
  (historical) events create none.
- `observation_count` = number of *recorded* (throttled) observations.
- No backfill: history starts when Phase 13C is deployed.

## 5. Timestamp domains

| Data | Domain |
|---|---|
| `web_events.event_time` and other legacy columns | server-local, timezone-less (unchanged, never rewritten) |
| Phase 13B normalized records | UTC (`…Z`, ms) |
| `endpoint_ip_history` (new) | **UTC**, stamped from the server clock **at receipt** (the agent sends no timestamps), so error ≤ network latency |

Legacy local-naive text is never reinterpreted as UTC.

## 6. Endpoint UID consistency guard

The shared `X-Agent-Key` is still the only authentication (**per-agent credentials are a
documented future hardening item**; none are introduced in 13C). The guard prevents
*silent* conflicting identity assertions and is **not** an authentication control.

A UID is **currently bound** to an IP when it was observed on it within the *binding
window* (default 300 s, never shorter than pre+post grace) — by history, or, for records that
pre-date history, by the `endpoints` row. For an incoming assertion of UID Y at that IP:

- **OK** — nothing conflicting (same UID, no binding, or a lapsed binding).
- **REASSIGNED** — an older binding to a different UID has lapsed: legitimate DHCP-style
  reuse; allowed, with a bounded `ENDPOINT_IDENTITY_REASSIGNED` notice.
- **CONFLICT** — a *different* UID is currently bound: the stored UID is **not**
  overwritten, **no** history is created from the assertion, a bounded
  `ENDPOINT_IDENTITY_CONFLICT` entry is written (route, canonical IP, the two validated
  UUIDs; throttled to one per 5 minutes per pair). A heartbeat is answered **409** (addresses
  are handled individually — non-conflicting ones are still recorded). An event is **not
  dropped**: it is stored and analyzed normally, with `endpoint_uid` left `NULL`.

A UID is never bound to one IP forever: moving A→B, returning later, and DHCP reuse all
work. With the default windows two UIDs' recorded evidence cannot normally overlap.

## 6a. Endpoint registration race (fixed)

Registering a brand-new IP took a deferred SELECT-then-INSERT; the heartbeat and the first
event could race and the loser failed with `UNIQUE(endpoints.ip_address)`. The write lock is
now taken before the existence check.

## 7. Resolver (`endpoint_network.resolve_endpoint(ip, observed_at_utc)`)

Evidence is **only** `endpoint_ip_history`; the current `endpoints.ip_address`, hostname,
username and process name are never consulted. An interval is **active** at *t* when

    first_seen_at − PRE_GRACE  ≤  t  ≤  last_seen_at + POST_GRACE

with `PRE_GRACE = 60 s` (an address is first reported at most one heartbeat after it appears)
and `POST_GRACE = 120 s` (one missed heartbeat tolerated). Measured: with the production
60 s interval and 30 s HTTP timeout the longest gap between two *received* heartbeats is
90 s; a longer silence makes the latest observation STALE until the next beat extends the
interval (up to a 300 s gap). All values are environment-configurable.

| Status | Meaning | `endpoint_uid` |
|---|---|---|
| `EXACT` | exactly one distinct UID is active at *t* | set |
| `AMBIGUOUS` | two or more distinct UIDs are active (DHCP reuse, NAT-like sharing, overlapping grace windows) | **never chosen** |
| `STALE` | the IP has history within the horizon (default 30 days) but nothing active at *t* | **never asserted**; nearest candidates returned |
| `UNKNOWN` | no history within the horizon | none |

Result: `{status, endpoint_uid, candidates[≤5], reason, evidence_window}`. Errors
(`ResolverInputError`): invalid IP, a timestamp without an explicit offset, or a timestamp
in the future.

`apply_resolution(record, ip_field)` (opt-in; `ingest_batch(..., resolve_ip_field=)`) stores
the status honestly: EXACT attaches the UID; AMBIGUOUS/STALE/UNKNOWN attach none. Resolution
is never mandatory and the HTTP ingest route does not enable it.

**`SENSOR_ASSERTED` ≠ `EXACT`.** A sensor-supplied `endpoint_uid` stays `SENSOR_ASSERTED` and
is never upgraded; only the resolver, from history, produces `EXACT`. Statuses stay
distinguishable: `NOT_ATTEMPTED`, `SENSOR_ASSERTED`, `EXACT`, `AMBIGUOUS`, `STALE`, `UNKNOWN`.

*Future adapter policy (not implemented):* the adapter/correlation layer decides whether
`src_ip` or `dst_ip` is the internal endpoint candidate and passes it explicitly.

## 8. Limitations

DHCP hand-over inside the overlapping grace windows is AMBIGUOUS by design; virtual/hypervisor
addresses and link-local addresses never resolve; NAT/VPN concentrators presenting many hosts
as one IP cannot be detected; resolution depends on heartbeat continuity (an agent that is down
yields STALE, never a guess); any holder of the shared agent key can assert an *unbound* UID;
commands queued for an old IP are not delivered after an IP change (existing IP-keyed response
limitation); IPv6 privacy addresses rotate and add rows.

## 9. Privacy

Only network-security metadata is collected: IP addresses, ports, TCP/UDP. No packet payloads,
full browser history, document contents, keystrokes or screenshots. Ports, protocol and IP are
security telemetry; the heartbeat carries only the stable identifier and the machine's own
addresses.
