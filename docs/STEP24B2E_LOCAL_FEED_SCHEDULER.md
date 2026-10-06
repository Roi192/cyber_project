# Step 24B.2E — Local Threat Intelligence Scheduler: production process reference

**Status: NOT ACTIVATED.** This document is a reference for when the
scheduler is explicitly approved to run live. As of Step 24B.2E, nothing
in this repository starts `local_feed_scheduler.py` automatically, and
`LOCAL_FEED_SCHEDULER_ENABLED` defaults to off (see `.env.example`).

## What it is

`local_feed_scheduler.py` is a standalone, independent process - the
same category as `web_event_worker.py` / `threat_intel_worker.py` /
`behavioral_worker.py`. It periodically checks whether any registered,
enabled, `automatic_eligible` Local Threat Intelligence provider is due
for a refresh, and if so runs exactly one secure download + ingest for
that provider (see `local_feed_downloader.py`, Step 24B.2D). It never
touches `cybersec.db`, never changes `risk_score`/`severity`/
`decision`, never creates an alert/incident/response command.

Only one instance should run at a time (enforced automatically - see
below); running a second one is harmless but wasteful (it exits
immediately).

## Starting it manually (same pattern as the other workers)

Windows (PowerShell), from the project directory, with the venv active:

```powershell
$env:LOCAL_FEED_SCHEDULER_ENABLED = "true"
& ".\venv\Scripts\python.exe" local_feed_scheduler.py
```

Linux:

```bash
export LOCAL_FEED_SCHEDULER_ENABLED=true
python3 local_feed_scheduler.py
```

With the env var left unset (or anything other than exactly `true`),
the process prints one line and exits - this is the safe, inert
default and is what every environment has today.

## systemd example (Linux production - reference only, nothing installed)

This mirrors the hardening pattern already used for the Suricata
sensor adapter's own reference unit (`sensors/vm/soc-suricata-
adapter.service` - see `docs/SURICATA_SENSOR_HARDENING.md`). Nothing
here has been installed or enabled on any machine.

```ini
[Unit]
Description=Local Threat Intelligence Scheduler
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=soc-feed-scheduler
Group=soc-feed-scheduler
WorkingDirectory=/opt/cyber_project
Environment=LOCAL_FEED_SCHEDULER_ENABLED=true
EnvironmentFile=-/etc/soc-feed-scheduler/scheduler.env
ExecStart=/opt/cyber_project/venv/bin/python3 local_feed_scheduler.py
Restart=on-failure
RestartSec=10
TimeoutStopSec=30

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/opt/cyber_project/data/local_threat_feed
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

Notes:
- `ReadWritePaths` is scoped to ONLY the Local Feed directory - the
  scheduler process never needs write access anywhere else, including
  `cybersec.db` itself (it never opens that file).
- A crashed instance's lock is reclaimed automatically by the next one
  that starts (pid + process-creation-time ownership check, proven in
  Step 24B.2D.1/24B.2E's test suites) - `Restart=on-failure` is safe to
  combine with this.
- Running two instances (e.g. during a rolling deploy) is safe: the
  second one detects the first via the same lock and exits cleanly
  with code 0 - `systemd` will not treat that as a failure to restart.

## Enabling it live — explicitly a SEPARATE decision

Per the Step 24B.2E instructions, nothing above has been executed. Live
activation requires:
1. Setting `LOCAL_FEED_SCHEDULER_ENABLED=true` in the real `.env` (or
   the service's own environment).
2. Each provider intended to update automatically needs
   `automatic_eligible=True` in `local_feed_providers.
   LOCAL_FEED_PROVIDER_REGISTRY` - today's PhishTank entry is
   `automatic_eligible=False`, so even with the scheduler enabled,
   PhishTank would never be auto-downloaded until that is explicitly
   changed too (a separate, deliberate decision - it is false today on
   purpose, see Step 24B.2 planning).
3. Starting the process (manually or via the unit above).

None of this has been done.
