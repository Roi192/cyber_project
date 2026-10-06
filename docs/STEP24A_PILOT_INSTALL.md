# Step 24A Pilot — Browser Extension Installation (ONE Windows computer)

Everything below is **manual, operator-run** work on the single pilot machine, exactly as scoped
("פיילוט מבוקר על מחשב Windows אחד"). None of it was executed by Claude — installing a browser
extension, writing to the Windows Registry, and restarting the Endpoint Agent are all real,
outward-facing changes to this machine and are left for you to run deliberately, in this order,
so you can stop/inspect/undo at any point.

## Prerequisites

- The Endpoint Agent's code already includes the Step 24A bridge (`browser_agent_bridge.py`,
  imported by `endpoint_agent_stable.py`) — no separate install step for that part.
- `requests` is already a project dependency (used by the native host and the bridge).

## 1. Load the unpacked extension

Chrome: `chrome://extensions` → enable **Developer mode** (top-right) → **Load unpacked** →
select `C:\Users\Moshe\cyber_project\browser_extension`.

Edge: `edge://extensions` → enable **Developer mode** → **Load unpacked** → same folder.

Each browser assigns its own **Extension ID** (a 32-character string) — copy it from the
extensions page. Chrome and Edge will generally assign **different IDs** for the same unpacked
folder; the native host manifest needs ONE `allowed_origins` entry per browser/ID actually used.
If you pilot both browsers, run step 3 below once per browser, or add both origins to one
manifest file (an array is fine — see the template).

## 2. Restart the Endpoint Agent (separate approval already covered by this step)

Stop the currently-running `endpoint_agent_stable.py` process and start it again so it picks up
the Step 24A code and begins listening on `127.0.0.1:56765` (or the port in
`BROWSER_EVENT_LISTENER_PORT` if you set one in `.env`). Confirm its console shows the new line:

```
Browser URL event bridge: listening on 127.0.0.1:56765 (for an optional, separately installed browser extension)
```

This also generates `browser_host_local.key` next to the agent script — a local-only secret,
unrelated to `AGENT_API_KEY`, used only between the Agent and the native host on this machine.

## 3. Register the Native Messaging Host

```powershell
cd C:\Users\Moshe\cyber_project\native_host
powershell -ExecutionPolicy Bypass -File install_native_host.ps1 -ExtensionId <the-id-from-step-1>
```

This writes `com.cyberproject.browser_monitor.json` next to the script and registers it under
`HKCU:\Software\Google\Chrome\NativeMessagingHosts\...` and
`HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\...` (current-user only, no admin rights, no
`HKLM` key touched). Fully reversible: delete those two registry keys and the generated manifest
JSON to undo.

**Restart Chrome/Edge completely** (close every window) after this step — native messaging host
registration is only picked up on a fresh browser start.

## 4. (Optional for the pilot) Managed policy

For a real "managed" deployment, an organization would push `enabled` / `excludedDomains` via
Chrome/Edge enterprise policy (`ExtensionSettings` → `policy_for_extension` →
`3rdparty.extensions.<id>`, schema in `browser_extension/managed_schema.json`). For this one-
machine pilot this is optional — with no managed policy configured, the extension defaults to
`enabled: true, excludedDomains: []` (see `DEFAULT_POLICY` in `background.js`).

## 5. Verify (manual checklist)

See `docs/STEP24A_MANUAL_VERIFICATION_CHECKLIST.md` for the exact scenarios to run and what to
look for in Web Monitoring after each one.

## Uninstall / rollback

1. Remove the extension from `chrome://extensions` / `edge://extensions`.
2. Delete the two `NativeMessagingHosts` registry keys (Chrome and Edge) and the generated
   `com.cyberproject.browser_monitor.json` manifest.
3. Optionally delete `browser_host_local.key` next to the Agent (it will be regenerated on next
   Agent start if anything still needs it).
4. No database change is required to "turn this off" — simply stop sending browser events; all
   existing rows remain (nothing is deleted by uninstalling).
