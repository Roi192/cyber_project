# Threat Intel Shadow Mode — Rollback & Controlled Activation

Status as of 2026-10-03: **not activated.** `THREAT_INTEL_SHADOW_MODE_ENABLED`
is absent from the live `.env` (default = disabled). No live worker process
has been restarted since this flag was introduced. `data/threat_intel_shadow/`
does not exist on the live system — Shadow Mode has never run against real
traffic.

## What activation changes, precisely

Setting `THREAT_INTEL_SHADOW_MODE_ENABLED=true` and restarting
`web_event_worker.py` makes `evaluate_shadow()` run once per processed event.
It:

- reads already-cached `threat_intel_evidence` rows (no new live HTTP call),
- writes one row to a **separate** SQLite file (`data/threat_intel_shadow/shadow.db`
  by default),
- never writes to `cybersec.db`,
- never changes `risk_score`, `severity`, `decision`, alerts, incidents, or
  any block/isolate action,
- cannot raise into the caller (internal try/except; the call site in
  `web_event_worker.py` has a second try/except as defense in depth).

None of this requires a schema change, a data migration, or touching any
existing table.

## Rollback (if an issue is found after activation)

1. Set `THREAT_INTEL_SHADOW_MODE_ENABLED=false` (or remove the line) in `.env`.
2. Restart `web_event_worker.py` (the only process that calls
   `evaluate_shadow()`; `threat_intel_worker.py` and `behavioral_worker.py`
   are unaffected and do not need restarting).
3. Nothing else to do. `cybersec.db` was never written to by this feature,
   so there is nothing to restore there. The separate shadow database file
   is left exactly as it was — rollback never deletes or resets it; it
   simply stops growing.
4. If the shadow database itself needs to be set aside (e.g. to start a
   clean comparison window later), move the file rather than delete it:
   `data/threat_intel_shadow/shadow.db` → `data/threat_intel_shadow/shadow_<date>.db.bak`.
   This preserves the historical comparison data instead of discarding it.

Total rollback time: one `.env` edit + one worker restart. No database
restore, no code revert, no dependency changes.

## Commands required for controlled activation (NOT executed — for operator use only, after explicit approval)

```
# 1. Edit the live .env (add or change one line):
THREAT_INTEL_SHADOW_MODE_ENABLED=true

# 2. Restart only the worker that reads it (PowerShell, from the project directory):
#    Stop the two existing web_event_worker.py processes, then:
venv\Scripts\python.exe web_event_worker.py

# 3. Verify activation (read-only, safe to run any time):
venv\Scripts\python.exe threat_intel_diagnostics.py status

# 4. Confirm the shadow DB is being written (read-only check):
#    data/threat_intel_shadow/shadow.db should now exist and grow with
#    one row per processed event.
```

No other file, process, firewall rule, or live table needs to change for
this specific activation. Enabling new provider API keys (Step 6) is a
fully independent action from enabling Shadow Mode and may be done in
either order.

## Residual risks before a live activation

1. **Real connection tests for the 4 keyless providers (OTX, GreyNoise,
   PhishTank, urlscan.io) were only partially possible** — see the Step 7
   report. TLS to these specific vendor hosts fails certificate
   verification from this tool-execution sandbox (while general internet
   access and other HTTPS hosts work), most consistent with an egress
   allow-list/TLS-inspection policy specific to this sandbox. This must be
   re-verified on the real SOC host before relying on these 4 providers'
   live behavior.
2. **`sensors/suricata_adapter.py`'s checkpoint writer can rarely leave an
   orphaned `.tmp` file if the process is hard-killed in the narrow window
   between writing it and the atomic rename** (found while investigating
   an unrelated flaky test, `test_14c_hardening.py`'s hard-kill case,
   ~1-in-3 reproduction rate). This is a Suricata **sensor adapter**
   finding, not a Threat Intel engine issue, and is explicitly out of this
   project's authorized scope (sensor/adapter code changes require their
   own separate approval, per the standing Phase 14C rule). Flagged here
   for whoever next works on that phase; not fixed.
3. Shadow Mode's per-event overhead was measured at approximately 5ms/event
   in this sandbox (cache-only reads, no live HTTP) — real-host numbers
   may differ slightly but should remain small for the same structural
   reason (no network call in the hot path).
