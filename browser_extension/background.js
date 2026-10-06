// ==================================================
// STEP 24A: SOC BROWSER URL MONITOR - background service worker (MV3)
// ==================================================
//
// Collects ONLY top-level (main-frame) page navigations via
// chrome.webNavigation.onCommitted. This API exposes nothing but the
// committed URL, the frame id, the transition type and a timestamp -
// never page content, form fields, cookies, or passwords; there is no
// browser API call anywhere in this file that could read any of those.
//
// Subframe (iframe) navigations are explicitly NOT collected in this
// phase (see the frameId check below) - a deliberate, documented scope
// decision: iframes very often carry third-party/ad/tracker content
// with higher privacy sensitivity and lower security value for this
// project's purposes. This can be revisited in a later, separately
// approved step.

const NATIVE_HOST_NAME = "com.cyberproject.browser_monitor";
const MAIN_FRAME_ID = 0;
const MAX_PENDING_QUEUE = 50;
const RETRY_ALARM_NAME = "socBrowserMonitorRetry";

const DEFAULT_POLICY = {
  enabled: true,
  excludedDomains: []
};

function browserName() {
  try {
    const brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
    if (brands.some((b) => /Edg/i.test(b.brand))) return "edge";
    if (brands.some((b) => /Chrome|Chromium/i.test(b.brand))) return "chrome";
  } catch (e) {
    // fall through to the User-Agent string fallback below
  }
  const ua = navigator.userAgent || "";
  if (/Edg\//.test(ua)) return "edge";
  return "chrome";
}

async function getPolicy() {
  try {
    const managed = await chrome.storage.managed.get(DEFAULT_POLICY);
    return { ...DEFAULT_POLICY, ...managed };
  } catch (e) {
    // chrome.storage.managed throws if no managed policy was ever
    // configured on this installation - an unmanaged/unconfigured
    // install simply behaves as "enabled, nothing excluded".
    return { ...DEFAULT_POLICY };
  }
}

function isExcludedHost(hostname, excludedDomains) {
  const lower = (hostname || "").toLowerCase();
  return (excludedDomains || []).some((d) => {
    const suffix = String(d || "").toLowerCase().replace(/^\*\./, "");
    if (!suffix) return false;
    return lower === suffix || lower.endsWith("." + suffix);
  });
}

// Step 24A section 3: redaction happens HERE, before anything leaves the
// browser at all - the default behavior strips the query string and
// fragment, keeping only scheme + host + path. Non-http(s) schemes
// (chrome://, edge://, file://, about:, etc.) are rejected entirely.
function redactUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (e) {
    return null;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return null;
  }

  const hadQueryOrFragment = Boolean(parsed.search) || Boolean(parsed.hash);

  return {
    url: parsed.origin + parsed.pathname,
    redacted: hadQueryOrFragment
  };
}

async function enqueueForRetry(event) {
  const stored = await chrome.storage.local.get({ pendingEvents: [] });
  const pending = stored.pendingEvents;
  pending.push(event);
  while (pending.length > MAX_PENDING_QUEUE) {
    pending.shift(); // bounded - oldest dropped first, never grows without limit
  }
  await chrome.storage.local.set({ pendingEvents: pending });
  chrome.alarms.create(RETRY_ALARM_NAME, { delayInMinutes: 0.5 });
}

function sendToNativeHost(event) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, event, (response) => {
        if (chrome.runtime.lastError || !response || !response.ok) {
          resolve(false);
          return;
        }
        resolve(true);
      });
    } catch (e) {
      resolve(false);
    }
  });
}

async function flushPending() {
  const stored = await chrome.storage.local.get({ pendingEvents: [] });
  const pending = stored.pendingEvents;

  if (pending.length === 0) {
    return;
  }

  const stillPending = [];

  for (const event of pending) {
    const ok = await sendToNativeHost(event);
    if (!ok) {
      stillPending.push(event);
    }
  }

  await chrome.storage.local.set({ pendingEvents: stillPending });

  if (stillPending.length > 0) {
    chrome.alarms.create(RETRY_ALARM_NAME, { delayInMinutes: 0.5 });
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === RETRY_ALARM_NAME) {
    flushPending();
  }
});

chrome.webNavigation.onCommitted.addListener(async (details) => {

  if (details.frameId !== MAIN_FRAME_ID) {
    return; // iframe navigation - excluded in this phase, see header
  }

  const policy = await getPolicy();

  if (!policy.enabled) {
    return;
  }

  const redacted = redactUrl(details.url);

  if (!redacted) {
    return; // non-http(s) scheme - never collected
  }

  let hostname;
  try {
    hostname = new URL(redacted.url).hostname;
  } catch (e) {
    return;
  }

  if (isExcludedHost(hostname, policy.excludedDomains)) {
    return;
  }

  const event = {
    url: redacted.url,
    url_redacted: redacted.redacted,
    browser_name: browserName(),
    nav_type: details.transitionType || "unknown",
    timestamp_ms: Math.round(details.timeStamp)
  };

  const ok = await sendToNativeHost(event);

  if (!ok) {
    await enqueueForRetry(event);
  }
});

// Step 24A.3: test-only export guard. `module` does not exist in a
// browser/service-worker context, so this branch never runs there and
// changes nothing about the shipped extension's behavior - it exists
// solely so an isolated Node test harness can exercise the REAL
// redactUrl()/isExcludedHost() functions below (not a reimplementation
// of them) without needing a real Chrome runtime.
if (typeof module !== "undefined" && module.exports) {
  module.exports = { redactUrl, isExcludedHost, browserName };
}
