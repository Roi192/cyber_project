# Website Monitor Collector (Chrome / Edge, Manifest V3)

Tiny extension that reports top-level `http`/`https` navigations to the
local Website Monitor server. No build step, no libraries.

## What is sent (and only this)

    { endpoint_uid, computer_name, username (optional), domain,
      url = scheme://host/path, browser, timestamp }

`url` never contains a query string, fragment, port or credentials - they
are stripped inside the browser before the request is made, and the server
strips them again.

## What is never read or sent

Cookies, passwords, authorization headers, form contents, page contents,
HTML, POST bodies, keystrokes, browser history. No HTTPS interception.
Only navigations that happen while the extension is enabled are observed;
`chrome://`, `edge://`, `file://`, extension and devtools pages and all
iframes/subframes are ignored.

## Identity (honest limitation)

A browser extension cannot read the Windows computer name or the logged-in
Windows user. On first run the extension generates a permanent random
`endpoint_uid` (stored in `chrome.storage.local`) and a label
`BROWSER-xxxxxxxx`. Set a friendly computer name / user name on the
extension's Options page - these are labels, not OS identity.

## Install (developer mode)

1. Chrome: open `chrome://extensions`  -  Edge: open `edge://extensions`
2. Turn on **Developer mode** (top-right in Chrome, left sidebar in Edge).
3. Click **Load unpacked** and choose the folder `browser_extension`.
4. Optional: click **Details - Extension options** to set computer name,
   user name and the API key (leave blank while the server runs in DEV MODE).
5. Browse normally. Visits appear on `http://127.0.0.1:5002/` within seconds.

## Server / CORS

The service worker calls `POST http://127.0.0.1:5002/api/web-events`. The
host is declared in `host_permissions`, so the browser allows the request
without any CORS headers on the server - no `Access-Control-Allow-Origin`
is needed or set. Duplicate reload/redirect events for the same tab + URL
within 5 seconds are suppressed. If the server is offline the event is
dropped (no retries, one console warning per minute at most).
