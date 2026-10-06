# Step 24A Manual Verification Checklist (real-browser, pilot machine)

Run after completing `docs/STEP24A_PILOT_INSTALL.md`. For each scenario: perform the browser
action, then check **Web Monitoring** in the SOC UI (and/or the Agent's console output) and note
Pass/Fail + what you actually saw. These are the same 9 scenarios from the Step 24A instruction,
plus the two non-interference checks — none of them could be executed from this environment
(no real Chrome/Edge GUI here), so they are genuinely unverified until you run them.

| # | Scenario | Action | Expected in Web Monitoring | Result |
|---|----------|--------|------------------------------|--------|
| 1 | Valid domain | Navigate to `https://example.com/` | New row, source "Browser (chrome/edge)", status `COLLECTED`, URL shown, no "reduced" badge (no query/fragment existed) | |
| 2 | Two paths, same domain | Navigate to `https://example.com/page-a` then `.../page-b` | Two separate rows, same domain, different URLs | |
| 3 | Sensitive-parameter URL | Navigate to a URL with a query string, e.g. a search `?q=...` | Row stored with URL **ending at the path** (no `?...`), "reduced" badge shown | |
| 4 | Rapid navigation | Click through 4-5 pages quickly | All distinct rows appear, none merged/dropped | |
| 5 | Duplicate events | Reload the same page twice quickly (or use browser back/forward to the same URL within the same second) | At most one row per genuinely distinct navigation; check the Agent console for any `duplicate` status line | |
| 6 | Unsupported browser | N/A for Chrome/Edge themselves — confirm the extension is simply **absent/inactive** in any other installed browser (e.g. Firefox) and that nothing breaks there | No rows from that browser; existing browsing unaffected | |
| 7 | Temporary agent disconnect | Stop `endpoint_agent_stable.py`, navigate to a page, wait, then restart the Agent | Extension does not crash/error visibly; after the Agent restarts, check whether the queued event (if any) was eventually delivered via the extension's own retry (`chrome://extensions` → service worker console can show this) | |
| 8 | Event without network-connection association | Any browser event (all of them, by design — see decision #3) | Row has no fabricated `source_ip`/`destination_port`/`transport_protocol` (should show as empty/"-" in the detail panel) | |
| 9 | Unauthorized send attempt | (Developer-only) temporarily edit `browser_host_local.key` to a wrong value and try navigating | Native host logs/returns `unauthorized`; no row created | |
| 10 | Existing TCP monitoring unaffected | With the extension active, do ordinary browsing/app network activity | Regular IP/domain-based rows continue to appear exactly as before (status PENDING → ANALYZED) | |
| 11 | Extension/host inactive | Disable the extension, restart the Agent alone | Regular TCP monitoring continues to work with zero errors; Agent console shows the bridge listener started but receives nothing | |

Please run these on the pilot machine and report back the results (and ideally a screenshot of
the Web Monitoring row expansion for scenario 3, showing the "reduced" badge) so the final Step
24A report can state plainly which of these were verified and which — if any — were not.
