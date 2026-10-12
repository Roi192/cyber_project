# Website Monitor Collector (Chrome / Edge, Manifest V3)

Tiny extension that reports top-level `http`/`https` navigations, plus a
once-a-minute heartbeat, to your company's central Website Monitor server. No
build step, no libraries: `manifest.json`, `background.js`, `common.js`,
`options.html`, `options.js`.

## Install and enroll (per computer)

1. Chrome: open `chrome://extensions` - Edge: open `edge://extensions`.
2. Turn on **Developer mode** (top-right in Chrome, left sidebar in Edge).
3. Click **Load unpacked** and choose this `browser_extension` folder.
4. Open **Details -> Extension options** and fill in:

   | Field          | Example                      | Notes                                            |
   |----------------|------------------------------|--------------------------------------------------|
   | Server address | `http://192.168.1.50:5002`   | `http://` or `https://` only; trailing `/` is removed |
   | Computer name  | `ACCOUNTING-PC-01`           | a label you choose                               |
   | User / owner   | `Dana`                       | optional label                                   |
   | API key        | (from the server's `.env`)   | never shown again after saving                   |

5. **Test connection** shows one of: *Connected successfully*, *Cannot reach
   server*, *Authentication failed*. It changes nothing on the server.
6. **Save** stores the settings in this browser and registers/updates the
   computer on the server. The first time, the browser asks to allow access to
   that server - click **Allow**.

After changing the extension's files, press the reload arrow on its card in
`chrome://extensions`; a folder loaded with "Load unpacked" is not re-read
automatically.

## What is sent (and only this)

    registration / heartbeat:  { endpoint_uid, computer_name, username, browser }
    each visit:                { endpoint_uid, computer_name, username, browser,
                                 domain, url = scheme://host/path, timestamp }

`url` never contains a query string, fragment, port or credentials - they are
stripped inside the browser before the request is made, and the server strips
them again.

## What is never read or sent

Cookies, passwords, authorization headers, form contents, page contents, HTML,
POST bodies, keystrokes, browser history. No HTTPS interception. Only
navigations that happen while the extension is enabled are observed. These are
ignored: `chrome://`, `edge://`, `file://`, extension and devtools pages, all
iframes/subframes, bare IP addresses, single-label intranet names, and the
browser-generated page below.

| Ignored browser page            | Rule (exact host + exact path)  |
|---------------------------------|---------------------------------|
| Microsoft Edge New Tab Page     | `ntp.msn.com` + `/edge/ntp`     |

Ordinary msn.com browsing is not affected. The same rule is enforced on the
server (`validation.py`), which is authoritative.

## Identity

On first run the extension generates a random UUID with `crypto.randomUUID()`
and stores it in `chrome.storage.local`. It is created once and never changes;
renaming the computer or user keeps the same identity. Removing the extension
and installing it again creates a new UUID, which the server treats as a new
computer unless you pair it again (see Pairing below). The UUID is shown only under "Technical details" in the options. No
MAC address, serial number, hostname or Windows account is read - a browser
extension cannot (and should not) read them, so the computer and user names are
labels you type.

## Pairing with the Windows Agent (version 0.4.0)

An unpaired extension is an *unverified* computer of its own. If the Windows Agent runs on the same computer, run
`windows_agent.py pair-code` there and type the code under "Pair with this computer's Windows Agent" in the options.
The extension sends the code (never the API key) to `http://127.0.0.1:47619/pair`, receives a short-lived grant, hands
it to the server and stores the **sensor secret** the server returns in `chrome.storage.local`; from then on every
request carries it as `X-Sensor-Secret`. Chrome, Edge and every browser profile are separate sensors of the one
computer. The manifest permissions are unchanged: the first pairing asks the browser for permission to reach
`127.0.0.1:47619` (an optional host permission, requested only when you press the button). Reinstalling the extension
creates a new sensor; pair it again and it joins the same computer.

## Heartbeat

`chrome.alarms` wakes the extension every minute and it POSTs
`/api/heartbeat`. The server only updates that computer's `last_seen` (no history
rows) and shows it as **ONLINE** for 3 minutes after the last beat. When the
server is down the beat is simply dropped (no retries; one console warning per
minute at most).

## Permissions (kept minimal)

| Permission                        | Why                                                    |
|-----------------------------------|--------------------------------------------------------|
| `webNavigation`                   | see top-level page loads (URL only, no content)        |
| `storage`                         | keep the UUID and the settings                         |
| `alarms`                          | the 1-minute heartbeat (a service worker sleeps; `setInterval` would not survive) |
| `host_permissions` `127.0.0.1:5002`, `localhost:5002` | local development works with no prompt |
| `optional_host_permissions` `http://*/*`, `https://*/*` | lets the options page request access to **only the one server address you enter**, at runtime, after you click Allow |

There is no `tabs`, `history`, `cookies`, `webRequest`, `scripting` or
`<all_urls>` permission and no content scripts. Manifest V3 cannot name an
arbitrary LAN address in advance, so the optional pattern is the smallest
reliable mechanism; the extension then holds access to just the origin you
entered (it can be revoked in the extension's settings). Because the browser
grants that access, the server needs no CORS headers (`Access-Control-Allow-Origin`
is never set).

## Notes

- The API key is stored in this browser's extension storage and sent only in the
  `X-Api-Key` header. That is practical, not hardware-backed secret storage.
- Duplicate reload/redirect events for the same tab + URL within 5 seconds are
  suppressed (the server suppresses them again).
- If the server is offline the visit is dropped; nothing is queued or retried.
