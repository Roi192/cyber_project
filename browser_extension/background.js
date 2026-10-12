// Website Monitor Collector - Manifest V3 service worker.
//
// Observes top-level http/https navigations and sends ONLY
// { domain, scheme://host/path } to the central Website Monitor server, plus a
// small heartbeat so the server knows this browser is online.
// Privacy is enforced here first (the server sanitizes again):
//   - query string and fragment are dropped before anything leaves the browser
//   - user:password in the URL is dropped
//   - no cookies, headers, form data, page content or history are ever read
// Nothing is retried: if the server is offline the event is simply dropped.
importScripts("common.js");

var DEDUP_WINDOW_MS = 5000;        // same tab + same sanitized URL within 5s -> one event
var HEARTBEAT_ALARM = "heartbeat";
var HEARTBEAT_MINUTES = 1;         // the server treats a computer as online for 3 minutes after the last beat
var ERROR_LOG_INTERVAL_MS = 60000;

var lastSent = {};                 // tabId -> { url, at }
var lastErrorLogAt = 0;
var identityInFlight = null;

// --------------------------------------------------------------------
// identity + settings (persisted in chrome.storage.local)
// --------------------------------------------------------------------
async function loadIdentity() {
  var stored = await chrome.storage.local.get(["endpoint_uid", "computer_name", "username", "api_key", "server_url", "sensor_secret"]);
  var updates = {};
  if (!stored.endpoint_uid) {
    updates.endpoint_uid = crypto.randomUUID();        // generated once per installation
  }
  if (!stored.computer_name) {
    var uid = stored.endpoint_uid || updates.endpoint_uid;
    // A browser extension cannot read the Windows computer name. This is a
    // clearly labelled installation name the owner can change in Options.
    updates.computer_name = "BROWSER-" + uid.slice(0, 8).toUpperCase();
  }
  if (Object.keys(updates).length) {
    await chrome.storage.local.set(updates);
  }
  var cfg = Object.assign({}, stored, updates);
  cfg.server_url = cfg.server_url || DEFAULT_SERVER_URL;
  cfg.username = cfg.username || "";
  cfg.api_key = cfg.api_key || "";
  cfg.sensor_secret = cfg.sensor_secret || "";            // only present once this browser was paired with a Windows agent
  return cfg;
}

// concurrent callers (install + first navigation) share one load, so the UUID is created once
function ensureIdentity() {
  if (!identityInFlight) {
    identityInFlight = loadIdentity().finally(function () { identityInFlight = null; });
  }
  return identityInFlight;
}

function registrationPayload(cfg) {
  return { endpoint_uid: cfg.endpoint_uid, computer_name: cfg.computer_name, username: cfg.username, browser: browserName(),
           sensor_version: extensionVersion() };
}

function localIsoTimestamp() {
  // Local time without timezone suffix (the server stores what it gets).
  var d = new Date();
  function p(n) { return String(n).padStart(2, "0"); }
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" +
         p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
}

// --------------------------------------------------------------------
// server calls (no retries; the API key is only ever sent as a header)
// --------------------------------------------------------------------
async function callServer(cfg, path, body) {
  var norm = normalizeServerUrl(cfg.server_url);
  if (!norm.ok) {
    logError("the server address is not valid - open the extension options");
    return { ok: false, status: 0 };
  }
  var headers = { "Content-Type": "application/json" };
  if (cfg.api_key) { headers["X-Api-Key"] = cfg.api_key; }
  if (cfg.sensor_secret) { headers["X-Sensor-Secret"] = cfg.sensor_secret; }   // proves this IS the paired browser, not just anyone who knows its id
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, 5000);
  try {
    var res = await fetch(norm.url + path, { method: "POST", headers: headers, body: JSON.stringify(body), signal: controller.signal });
    if (res.status === 401) { logError("the server rejected the API key or this browser's pairing credential"); }
    else if (res.status === 403) { logError("the server refused this browser (its pairing was revoked) - pair it again"); }
    else if (!res.ok) { logError("server responded " + res.status); }
    return { ok: res.ok, status: res.status };
  } catch (e) {
    logError("server unreachable");                       // no retry - the next event or heartbeat tries again
    return { ok: false, status: 0 };
  } finally {
    clearTimeout(timer);
  }
}

function logError(msg) {
  var now = Date.now();
  if (now - lastErrorLogAt < ERROR_LOG_INTERVAL_MS) { return; }   // at most one line per minute
  lastErrorLogAt = now;
  console.warn("[Website Monitor] " + msg);
}

// --------------------------------------------------------------------
// navigation listener
// --------------------------------------------------------------------
chrome.webNavigation.onCommitted.addListener(async function (details) {
  if (details.frameId !== 0) { return; }                  // top-level only, no iframes
  var clean = sanitizeNavigation(details.url);
  if (!clean) { return; }                                  // chrome://, edge://, file://, extensions, etc.
  if (isBrowserNoise(clean.domain, clean.path)) { return; } // e.g. the Edge New Tab Page

  var now = Date.now();
  var prev = lastSent[details.tabId];
  if (prev && prev.url === clean.url && now - prev.at < DEDUP_WINDOW_MS) { return; }   // reload/redirect burst
  lastSent[details.tabId] = { url: clean.url, at: now };

  var cfg = await ensureIdentity();
  var event = Object.assign(registrationPayload(cfg), {
    domain: clean.domain,
    url: clean.url,
    timestamp: localIsoTimestamp()
  });
  await callServer(cfg, "/api/web-events", event);
});

chrome.tabs.onRemoved.addListener(function (tabId) { delete lastSent[tabId]; });

// --------------------------------------------------------------------
// heartbeat: "is this browser online?" - one small POST per minute
// --------------------------------------------------------------------
async function sendHeartbeat() {
  var cfg = await ensureIdentity();
  await callServer(cfg, "/api/heartbeat", registrationPayload(cfg));
}

function ensureHeartbeatAlarm() {
  chrome.alarms.get(HEARTBEAT_ALARM, function (alarm) {
    if (!alarm) {
      chrome.alarms.create(HEARTBEAT_ALARM, { delayInMinutes: HEARTBEAT_MINUTES, periodInMinutes: HEARTBEAT_MINUTES });
    }
  });
}

chrome.alarms.onAlarm.addListener(function (alarm) {
  if (alarm.name === HEARTBEAT_ALARM) { sendHeartbeat(); }
});
chrome.runtime.onInstalled.addListener(function () { ensureHeartbeatAlarm(); sendHeartbeat(); });
chrome.runtime.onStartup.addListener(function () { ensureHeartbeatAlarm(); sendHeartbeat(); });
ensureHeartbeatAlarm();
