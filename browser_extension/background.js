// Website Monitor Collector - Manifest V3 service worker.
//
// Observes top-level http/https navigations and sends ONLY
// { domain, scheme://host/path } to the local Website Monitor server.
// Privacy is enforced here first (the server sanitizes again):
//   - query string and fragment are dropped before anything leaves the browser
//   - user:password in the URL is dropped
//   - no cookies, headers, form data, page content or history are ever read
// Nothing is retried: if the server is offline the event is simply dropped.

const DEFAULTS = {
  server_url: "http://127.0.0.1:5002",
  computer_name: "",      // filled on first run with "BROWSER-xxxx" (see ensureIdentity)
  username: "",           // optional, set on the options page
  api_key: ""             // optional X-Api-Key; blank = server DEV MODE
};

const DEDUP_WINDOW_MS = 5000;     // same tab + same sanitized URL within 5s -> one event
const ERROR_LOG_INTERVAL_MS = 60000;

let lastSent = {};                // tabId -> { url, at }
let lastErrorLogAt = 0;

// --------------------------------------------------------------------
// identity (persisted once in chrome.storage.local)
// --------------------------------------------------------------------
async function ensureIdentity() {
  const stored = await chrome.storage.local.get(["endpoint_uid", "computer_name", "username", "api_key", "server_url"]);
  const updates = {};
  if (!stored.endpoint_uid) {
    updates.endpoint_uid = crypto.randomUUID();
  }
  if (!stored.computer_name) {
    const uid = stored.endpoint_uid || updates.endpoint_uid;
    // The extension cannot read the Windows computer name - this is a
    // clearly labelled installation name the owner can change in Options.
    updates.computer_name = "BROWSER-" + uid.slice(0, 8).toUpperCase();
  }
  if (Object.keys(updates).length) {
    await chrome.storage.local.set(updates);
  }
  return Object.assign({}, DEFAULTS, stored, updates);
}

chrome.runtime.onInstalled.addListener(() => { ensureIdentity(); });

// --------------------------------------------------------------------
// privacy sanitization - runs BEFORE any network call
// --------------------------------------------------------------------
function sanitize(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch (e) { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || !host.includes(".")) return null;            // skip intranet single labels
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return null;    // domain-level only, no bare IPs
  // scheme + host + path only: no search, no hash, no credentials, no port
  return { domain: host, url: u.protocol + "//" + host + (u.pathname || "/") };
}

function browserName() {
  const brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  if (brands.some(b => /Edge/i.test(b.brand))) return "Edge";
  if (/Edg\//.test(navigator.userAgent)) return "Edge";
  return "Chrome";
}

function localIsoTimestamp() {
  // Local time without timezone suffix (the server stores what it gets).
  const d = new Date();
  const p = n => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" +
         p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
}

// --------------------------------------------------------------------
// navigation listener
// --------------------------------------------------------------------
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;                        // top-level only, no iframes
  const clean = sanitize(details.url);
  if (!clean) return;                                        // chrome://, edge://, file://, extensions, etc.

  const now = Date.now();
  const prev = lastSent[details.tabId];
  if (prev && prev.url === clean.url && now - prev.at < DEDUP_WINDOW_MS) return;   // reload/redirect burst
  lastSent[details.tabId] = { url: clean.url, at: now };

  const cfg = await ensureIdentity();
  const event = {
    endpoint_uid: cfg.endpoint_uid,
    computer_name: cfg.computer_name,
    username: cfg.username || undefined,
    domain: clean.domain,
    url: clean.url,
    browser: browserName(),
    timestamp: localIsoTimestamp()
  };
  await send(cfg, event);
});

chrome.tabs.onRemoved.addListener((tabId) => { delete lastSent[tabId]; });

async function send(cfg, event) {
  const headers = { "Content-Type": "application/json" };
  if (cfg.api_key) headers["X-Api-Key"] = cfg.api_key;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(cfg.server_url.replace(/\/$/, "") + "/api/web-events", {
      method: "POST", headers, body: JSON.stringify(event), signal: controller.signal
    });
    if (!res.ok) logError("server responded " + res.status);
  } catch (e) {
    logError("server unreachable");                         // no retry - next navigation tries again
  } finally {
    clearTimeout(timer);
  }
}

function logError(msg) {
  const now = Date.now();
  if (now - lastErrorLogAt < ERROR_LOG_INTERVAL_MS) return;  // at most one line per minute
  lastErrorLogAt = now;
  console.warn("[Website Monitor] " + msg);
}
