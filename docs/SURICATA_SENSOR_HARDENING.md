# Suricata sensor hardening and signal quality (Phase 14C)

Scope: harden the **existing** Phase 14B pipeline (Suricata -> EVE -> `sensors/suricata_adapter.py` -> `/api/security-ingest`). Nothing here changes what is stored,
how `source_event_id` / `raw_ref` / `independence_group` are derived, the event-time alert cap (600 alerts per event-minute), idempotency, monitored-network
resolution, or any scoring. Not in scope: correlation, promotion of detections to alerts, new sensors, packet/payload storage, TLS interception.

**Status legend.** *Implemented (repository)* = code/docs/reference files in this repository, tested. *Prepared, NOT executed* = commands for the sensor operator; nothing below
under "prepared" has been run by any project tool, and no project tool changes a Kali machine.

---
## 1. Repository-side hardening that IS implemented

| Item | Behaviour |
|---|---|
| EVE read failures are visible | If the EVE file exists but cannot be opened, the adapter never adopts/advances it. It counts `eve_open_errors`, logs `eve_unreadable` once per state change (class name only, e.g. `PermissionError`) and `eve_readable_again` on recovery, and writes `eve_open_error` / `eve_last_open_ok_at` into `status.json`. It polls every 5 s while unreadable. |
| Sanitised start-up failures | An unreadable env file, unwritable/uncreatable state directory or bad credential/URL/CA file stops with `CONFIG ERROR: ...` and **exit code 2** - no traceback, no secret. |
| Redirects are never followed | The ingest endpoint never redirects. Python's default handler would replay custom headers (including the sensor credential header) to whatever host a `Location` names, even over plain `http://`. The adapter refuses every 3xx: the request is not repeated, `Location` is not logged, counter `redirects_refused`, fail-closed 60 s back-off, checkpoint never advances. Environment proxy variables are also ignored so the credential only ever goes to `SOC_URL`. |
| Private CA / HTTPS | `SOC_CA_FILE` (or `--ca-file`) = PEM bundle that signs the SOC's certificate. It **replaces** the system store for that connection. Chain **and hostname** verification are always on; there is no switch that disables them. A TLS failure (`tls_verification_failed`, counter `tls_failures`) is fail-closed: nothing is sent, the checkpoint never advances, 60 s back-off. |
| `SOC_REQUIRE_HTTPS` | Opt-in (`true` / `--require-https`, **default off**): refuse to start unless `SOC_URL` is `https://`. The current host-local lab keeps working unchanged. |
| `check-config` probes | Also reports: transport (scheme, verification, trust anchor), EVE (`readable` / `not present yet` / `CANNOT OPEN (PermissionError)`), state directory (`writable` / `will be created` / `NOT WRITABLE`), credential **properties only**. Missing EVE is fine (Suricata may not have started); an EVE file the user cannot open is a config error (exit 2). |
| Trusted proxy (server) | `SECURITY_TRUSTED_PROXY_HOPS` (**default 0**, max 5): number of reverse proxies in front of the SOC. With 0, `X-Forwarded-For` is ignored (identical to Phase 14B). With N, the client address for failed-auth throttling and the ingest log is the N-th entry from the **right**; malformed/short/non-IP values fall back to the TCP peer. Never enable it unless a proxy you control really sits in front. |

Exit codes: `0` clean stop / success, `2` configuration error (do not restart-loop), `3` (`run --once` only) credential/TLS/redirect failure. In `run` mode those failures back off 60 s and keep retrying.

Status fields added to `status.json` (all factual, no score): `eve_open_error`, `eve_last_open_ok_at`; counters `eve_open_errors`, `tls_failures`, `redirects_refused`.

---
## 2. Workstream A - checksum alerts (CLOSED for the current phase; Outcome E; NO suppression)

**Workstream A status: CLOSED for the current project phase (2026-09-22).**
Authoritative record: `docs/SURICATA_CHECKSUM_INVESTIGATION_CLOSURE.md` (evidence inventory: `docs/SURICATA_CHECKSUM_EVIDENCE_MANIFEST.md`). The closure record is authoritative for Workstream A.
* Formal result: **Outcome E - formally inconclusive** under the pre-registered classification gates (gates 3 and 6 failed).
* Root cause: **unresolved**. No specific root-cause component is identified. The separate descriptive cross-vantage finding is preserved in the closure record and does not change the formal Outcome E classification.
* A2 and A3 were executed and the A3/3C cross-vantage investigation is closed. A4 and the RSC / root-cause experiments were **not run and are not required** for the current Phase 14C.
* No further checksum/root-cause experiment is required for the current Phase 14C. Re-open triggers are defined in the closure record (section 9).
* sid 2200074 and sid 2200077 **remain stored and unsuppressed**, Suricata checksum validation remains enabled, and these detections **must not independently affect correlation, risk, severity or automated response**.
* A display-only "Suricata engine event / sensor diagnostic" annotation is an **optional, deferred presentation step and is NOT implemented**. If it is ever implemented it must be presentation-only: no change to stored data, severity, risk, decision, correlation, alert generation or Suricata configuration.

**Proven facts (SOC database, read-only):** 3,687 of 3,755 detections are sid **2200074** (TCPv4 invalid checksum, 3,633) and **2200077** (TCPv6, 54). They are Suricata-native decoder/engine events
(category "Generic Protocol Command Decode"; `independence_group` `suricata:1-<sid>`), not attack signatures. All are TCP, `src_port 443`, `to_client`, `in_iface eth1`, `app_proto tls`, at most **one alert per flow**,
roughly 33/min and steady.

**Evidence (not conclusive):** 3,618 of the 3,687 come from a single external address, `46.101.206.53:443`; 993 linked TLS records carry SNI `urlhaus-api.abuse.ch`. That is the abuse.ch API front end which this SOC's own
threat-intelligence workers query. IPv4 flows are affected far more than IPv6 (~1.98 vs ~0.12 checksum alerts per TLS flow). Kali `eth1` reports rx-checksumming off and TSO/GSO/GRO/LRO off, so **offload on the Kali interface is not the
explanation**. The Windows Wi-Fi adapter has Receive Segment Coalescing enabled (IPv4 and IPv6) and the VirtualBox NDIS6 bridged driver is bound to it.

**The cause is UNRESOLVED** (see the closure record). The table below is the pre-investigation working set, kept as **historical planning** only; it has not been updated with results.

*Historical planning table: A2 and A3 were executed and the A3/3C cross-vantage investigation closed as Outcome E; the RSC test and A4 were not run and are not required for the current Phase 14C.*

| # | Hypothesis | Prediction | Test |
|---|---|---|---|
| H1 | Host-side RSC merges response segments; the bridged filter sees larger-than-MTU segments with checksums not recomputed | "bad" packets have IP total length > 1500; offline replay of the same bytes also flags them | header-only capture (A2); offline compare (A3); reversible RSC test on the SOC host |
| H2 | Kali af-packet `checksum-checks: kernel` (default) trusts a kernel checksum indication that is unreliable for frames injected by the VirtualBox bridge | offline `suricata -r` (which computes from the bytes) does **not** flag them, live does | offline compare (A3) |
| H3 | Real on-path checksum damage/rewrite (hotspot/NAT/provider path) | offline flags them; IP lengths <= MTU; also invalid in a Windows-side capture | A2 + A3 + Windows capture |
| H4 | Malicious tampering | no supporting evidence (one well-known API host queried by the platform itself); not established, not excluded | covered by the tests above |

Rules of this workstream: do **not** disable checksum validation, do **not** suppress sids 2200074/2200077, do **not** modify rules to reduce counts, do **not** delete detections, and do **not** label them benign or malicious.
For the future correlation phase: these are engine diagnostics and must not be counted as independent threat evidence (already reflected by their engine-native `independence_group`); handling belongs in annotation, never in deletion.

**A1 - read-only preflight (safe):** `bash sensors/vm/preflight.sh` on the sensor (prints versions, ownership/modes, the effective eve-log and af-packet blocks, checksum settings, event-type counts, counts of sensitive raw fields, NIC facts).

**Prepared steps (original preparation text retained; the current status of each is shown in brackets):**
* **A2 header-only capture** (no payload): `sudo timeout 60 tcpdump -i eth1 -s 96 -w /tmp/csum-hdr.pcap 'tcp port 443 and host <SOC-host-IP>'` ; `sudo chmod 600 /tmp/csum-hdr.pcap` ; count packets with IP total length > 1500 ; `sudo shred -u /tmp/csum-hdr.pcap`. **Status:** [executed.]
* **A3 offline comparison** (briefly holds encrypted TLS records): capture <= 30 s filtered to the one server; `suricata -r /tmp/x.pcap -l /tmp/csum-a -c /etc/suricata/suricata.yaml` versus the same with `-k none`, separate log dirs, live Suricata untouched; count sids 2200074/2200077 in each `eve.json`; delete the files. **Status:** [executed; evidence preserved; subsequent A3/3C cross-vantage investigation closed as Outcome E. See the authoritative closure record.]
* **A4 controlled trigger:** from the SOC host `curl.exe -sS https://urlhaus-api.abuse.ch/ -o NUL` x20 then `curl.exe -sS https://example.com -o NUL` x20; compare per-destination checksum alerts on the sensor. **Status:** [NOT run; not required for the current Phase 14C.]
* **RSC test on the SOC host (administrator, temporary):** `Disable-NetAdapterRsc -Name "Wi-Fi"` ... `Enable-NetAdapterRsc -Name "Wi-Fi"`. **Status:** [NOT run; not required for the current Phase 14C.]
* If evidence ever supports a **Suricata-side** setting change (for example `af-packet.checksum-checks`), it is a **detection-semantics change**: it needs its own approval with the exact reason, exact edit, rollback (`cp -p` backup + restore + `suricata -T`) and expected before/after counts; stored history is never rewritten. **Status:** [not proposed; would still require its own explicit approval.]

---
## 3. Workstream B - EVE privacy and permissions (PREPARED, NOT EXECUTED)

Model: Suricata (root) writes; the dedicated group `soc-eve` may read; nobody else. Today the file is `root:root 0644` (world-readable).

* `/var/log/suricata`: `root:soc-eve`, mode `2750` (setgid so rotated files inherit the group). `eve.json`: `root:soc-eve 0640`. eve-log `filemode: 640`; logrotate `create 0640 root soc-eve`.
* Minimise raw content at the source with `sensors/vm/eve-log.snippet.yaml`: alert `payload/payload-printable/packet/http-body/tagged-packets` all `no`; dns `requests: no` (responses still carry `queries[]`); tls `custom` list containing every field the adapter uses
  (`sni, version, subject, issuer, fingerprint, ja3, ja4, client_alpns, server_alpns`) and never `certificate`/`chain`; only the types the adapter consumes (`alert, dns, tls, flow, stats`). `community-id` is not touched.
* **Order matters:** create groups/users -> install and verify the service while EVE is still world-readable -> tighten permissions -> verify the service still reads it and an unrelated user cannot -> minimise types/fields -> verify field presence and ingest proportions.

```
# BACKUPS (rollback material)
sudo cp -p /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.pre14c
sudo cp -p /etc/logrotate.d/suricata /etc/logrotate.d/suricata.pre14c
# PERMISSIONS
sudo groupadd --system soc-eve
sudo chgrp soc-eve /var/log/suricata && sudo chmod 2750 /var/log/suricata
sudo chgrp soc-eve /var/log/suricata/eve.json && sudo chmod 0640 /var/log/suricata/eve.json
# then edit the eve-log block of /etc/suricata/suricata.yaml per sensors/vm/eve-log.snippet.yaml (filemode: 640 etc.)
sudo suricata -T -c /etc/suricata/suricata.yaml            # MUST pass before any reload
sudo systemctl kill -s HUP --kill-whom=main suricata.service   # reopen log files (no restart)
# VERIFY (expected: service user reads, unrelated user is denied, new lines have no payload/packet/http/certificate fields)
sudo -u soc-adapter python3 /opt/soc-suricata-adapter/suricata_adapter.py check-config --env-file /etc/soc-suricata-adapter/adapter.env
sudo -u nobody head -c 1 /var/log/suricata/eve.json        # must be "Permission denied"
# ROLLBACK
sudo cp -p /etc/suricata/suricata.yaml.pre14c /etc/suricata/suricata.yaml && sudo suricata -T -c /etc/suricata/suricata.yaml
sudo chmod 0644 /var/log/suricata/eve.json && sudo chgrp root /var/log/suricata /var/log/suricata/eve.json && sudo chmod 0755 /var/log/suricata
sudo systemctl kill -s HUP --kill-whom=main suricata.service
```
Old EVE lines keep their old content until rotated away (7 days). Do not turn on TLS interception, and do not store certificates, HTTP bodies, payloads or packets "for later".

---
## 4. Workstream C - adapter as a systemd service (PREPARED, NOT INSTALLED)

Reference unit: `sensors/vm/soc-suricata-adapter.service` (v2). Key properties: runs as `soc-adapter` (no root, no capabilities), `SupplementaryGroups=soc-eve`, read-only `/var/log/suricata`, write access only to
`/var/lib/soc-suricata-adapter`; the **command line contains only the env-file path** (`--env-file /etc/soc-suricata-adapter/adapter.env`), so `SENSOR_KEY` is never in argv, the unit, `systemctl show` or the process environment
(this is why `EnvironmentFile=` is deliberately not used); `ExecStartPre` runs `check-config`; `Restart=on-failure`, `RestartSec=10`, `StartLimitBurst=5` per 300 s, `RestartPreventExitStatus=2`; SIGTERM is a clean stop.

| Path | Owner:group | Mode |
|---|---|---|
| `/opt/soc-suricata-adapter/` and `suricata_adapter.py` | root:root | 0755 / 0644 |
| `/etc/soc-suricata-adapter/` | root:soc-adapter | 0750 |
| `/etc/soc-suricata-adapter/adapter.env` (SENSOR_KEY lives here only) | soc-adapter:soc-adapter | 0600 |
| `/var/lib/soc-suricata-adapter/` (checkpoint.json, status.json) | soc-adapter:soc-adapter | 0700 (systemd `StateDirectory`) |

**Checkpoint across reboot:** the state directory persists, so an ordinary reboot resumes at the saved offset (identity = device/inode + head hash) and never replays from zero. Migrate the existing manual checkpoint by *copying* it
(shown below); even a replay would only produce duplicates.

```
# 1 users and groups
sudo groupadd --system soc-eve            # (skip if already created in section 3)
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin soc-adapter
# 2 files (adapter copied to ~ beforehand; unit from sensors/vm/)
sudo install -d -m 0755 -o root -g root /opt/soc-suricata-adapter
sudo install -m 0644 -o root -g root ~/suricata_adapter.py /opt/soc-suricata-adapter/suricata_adapter.py
sudo install -d -m 0750 -o root -g soc-adapter /etc/soc-suricata-adapter
sudo install -m 0600 -o soc-adapter -g soc-adapter /dev/null /etc/soc-suricata-adapter/adapter.env
sudoedit /etc/soc-suricata-adapter/adapter.env      # SOC_URL, SENSOR_ID, SENSOR_KEY (English layout, no quotes/spaces), SURICATA_EVE_PATH
sudo install -m 0644 -o root -g root ~/soc-suricata-adapter.service /etc/systemd/system/soc-suricata-adapter.service
# 3 migrate the manual checkpoint (stop the manual adapter with Ctrl-C first; copy, do not move)
sudo install -d -m 0700 -o soc-adapter -g soc-adapter /var/lib/soc-suricata-adapter
sudo install -m 0600 -o soc-adapter -g soc-adapter ~/soc-adapter-recovery/checkpoint.json /var/lib/soc-suricata-adapter/checkpoint.json
# 4 preflight as the service user, without starting the service
sudo -u soc-adapter python3 /opt/soc-suricata-adapter/suricata_adapter.py check-config --env-file /etc/soc-suricata-adapter/adapter.env
# 5 verify, then start
sudo systemctl daemon-reload && sudo systemd-analyze verify /etc/systemd/system/soc-suricata-adapter.service
sudo systemctl enable --now soc-suricata-adapter
systemctl status soc-suricata-adapter --no-pager ; journalctl -u soc-suricata-adapter -n 30 --no-pager
sudo -u soc-adapter python3 /opt/soc-suricata-adapter/suricata_adapter.py status --state-dir /var/lib/soc-suricata-adapter
# operate
sudo systemctl restart soc-suricata-adapter      # graceful: batch finishes, checkpoint saved
sudo systemctl stop soc-suricata-adapter
sudo systemctl kill -s KILL soc-suricata-adapter # hard-kill test: restarts after RestartSec, no loss, duplicates only for the interrupted batch
# ROLLBACK / UNINSTALL (the manual run keeps working: python3 ~/suricata_adapter.py run --env-file ~/soc-adapter.env --state-dir ~/soc-adapter-recovery)
sudo systemctl disable --now soc-suricata-adapter
sudo rm /etc/systemd/system/soc-suricata-adapter.service && sudo systemctl daemon-reload
sudo rm -r /opt/soc-suricata-adapter                                  # optional
# keep /var/lib/soc-suricata-adapter until you have copied checkpoint.json back if you return to manual runs;
# remove the users/groups only after the EVE permission changes were rolled back:  sudo userdel soc-adapter ; sudo groupdel soc-eve
```
Expected facts after start: `journalctl` shows JSON lines only (never the key); `status` shows `records_sent` growing and `eve_open_error: null`; after a restart `accepted` is 0 or only new records. `systemd-analyze security soc-suricata-adapter`
is an informational lint of the unit on the sensor; it is not a project metric, and the adapter/`status.json` never produce a health score.

---
## 5. Workstream D - transport

**MODE 1 - current local lab (unchanged and still tested):** Kali -> VirtualBox host-local NAT (`http://10.0.2.2:5000`) -> SOC bound to `127.0.0.1`. Plain HTTP is acceptable only because the traffic never leaves the machine.
Do not "fix" it by binding Flask to `0.0.0.0` or opening port 5000.

**MODE 2 - sensor and SOC on different machines: HTTPS is REQUIRED.** Required design:
1. TLS terminates at a **reverse proxy on the SOC host** (Caddy or nginx). Flask stays bound to `127.0.0.1`; `FLASK_DEBUG=false` (the Werkzeug debugger/reloader must never be reachable from a network); a production WSGI server is used
   (gunicorn on Linux; the dev server is not an off-box listener). On a Windows SOC host a production WSGI server (for example waitress) is a new dependency that must be approved separately.
2. The proxy exposes **only** `POST /api/security-ingest` (nothing else, body limit 600 KB), TLS 1.2+, no redirects; the firewall allows only the sensor address(es) on 443. Port 5000 is never exposed.
3. Certificates: a private CA is fine for a lab (below). The adapter validates chain **and hostname** using `SOC_CA_FILE`; there is no `verify=False`, `CERT_NONE` or `check_hostname=False` anywhere (enforced by a test).
4. Set `SECURITY_TRUSTED_PROXY_HOPS=1` **only** when that proxy is in front, and make the proxy *overwrite* the header with the peer it saw (never append a client-supplied value):
   ```
   server {
     listen 443 ssl;  server_name soc.example.internal;
     ssl_certificate /etc/ssl/soc/server.pem;  ssl_certificate_key /etc/ssl/soc/server.key;  ssl_protocols TLSv1.2 TLSv1.3;
     location = /api/security-ingest {
       limit_except POST { deny all; }
       client_max_body_size 600k;
       proxy_pass http://127.0.0.1:5000;
       proxy_set_header X-Forwarded-For $remote_addr;
     }
     location / { return 404; }
   }
   ```
5. Lab private CA (run on any machine with OpenSSL; distribute only `soc-ca.pem` to sensors; keep the CA key offline):
   ```
   openssl req -x509 -newkey rsa:3072 -nodes -keyout soc-ca.key -out soc-ca.pem -days 825 -subj "/CN=SOC lab CA"
   openssl req -newkey rsa:3072 -nodes -keyout server.key -out server.csr -subj "/CN=soc.example.internal"
   printf 'subjectAltName=DNS:soc.example.internal\n' > san.ext
   openssl x509 -req -in server.csr -CA soc-ca.pem -CAkey soc-ca.key -CAcreateserial -out server.pem -days 397 -extfile san.ext
   ```
   The adapter's `SOC_URL` host must match a name/IP in the certificate's SAN.
6. mTLS at the proxy is worthwhile later for larger sensor fleets (channel-level pre-authentication, no application change); it is not required now because every sensor already authenticates with its own credential.
7. Credential protection is unchanged: `adapter.env` mode 0600, HTTPS only off-box, no secret in argv/unit/logs. `README.md` shows `FLASK_HOST=0.0.0.0` / `gunicorn -b 0.0.0.0:5000` for a **plain-HTTP LAN demo only**; never use that path for sensors or credentials.

**Not part of Phase 14C:** installing a proxy or WSGI server, opening a firewall rule or listener, changing `FLASK_DEBUG`/`FLASK_HOST`. HTTPS behaviour is validated in isolated tests with a throw-away private CA against a loopback TLS test server.

---
## 6. Rollback summary
Repository side: `rollback_14c/` holds the pre-14C copies (adapter, ingest routes, VM reference files, docs, README, `.env.example`); the SQLite backup `cybersec_before_phase14c_sensor_hardening_<timestamp>.db` was taken with the backup API.
Workstream-A close-out (documentation only): `rollback_14c_a_close/` holds the pre-edit copies of this file and `docs/SURICATA_INTEGRATION.md`.
Sensor side: every prepared block above carries its own rollback. Evidence is never deleted: no `DELETE ... WHERE sensor_id`, no schema change, historical detections/observations untouched.

---
## 7. Follow-up register (observations only)

Observations recorded during checkpoint 14C-A-CLOSE-4 (read-only invariant re-check: 26 PASS / 0 DRIFT / 15 INFORMATIONAL / 3 UNKNOWN). They are **observations only**: they were not investigated and are **not classified as defects, corruption or drift**. Each would need its own explicit approval before any query or action. No baseline was retained for F1 or F2; F3 is an informational counter.

| # | Observation | Facts recorded |
|---|---|---|
| F1 | `cybersec.db-wal` observed around 620 MB and growing | 603,913,752 bytes -> 618,222,512 bytes -> 620,055,912 bytes over about 16 minutes on 2026-09-22 (last reading 01:57:58 local). Main file `cybersec.db`: 64,491,520 bytes, last written 2026-09-20 22:36:58. No retained baseline for WAL size. |
| F2 | One ERROR-type `system_logs` row over the longer live window | Rows with `event_type` like `%ERROR%` since 2026-09-21 18:40 local = 1 (the G3 window of about 43 minutes = 0). "database is locked" rows = 0. The row was not identified. |
| F3 | `endpoint_ip_history` increased while `endpoints` stayed at 7 | 18 at G0 and G3; 29 at 14C-A-CLOSE-4. Informational counter, not proven frozen, not investigated. |
