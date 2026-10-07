// Shared helpers. Loaded by background.js (importScripts) and by the Options
// page (<script>). Plain JavaScript, no build step.
"use strict";

var DEFAULT_SERVER_URL = "http://127.0.0.1:5002";

// Navigations the BROWSER makes by itself, not the employee. Every entry is an
// exact host AND an exact path, so normal browsing to the same company
// (www.msn.com, msn.com/en-us/...) is never filtered. Keep this list tiny; add a
// pattern only after observing it in real traffic. Mirrored on the server in
// validation.py (BROWSER_NOISE), which is the authoritative copy.
//   ntp.msn.com + /edge/ntp   -> the Microsoft Edge "New Tab Page"
var BROWSER_NOISE = [
  { host: "ntp.msn.com", path: "/edge/ntp" }
];

// Validate and normalize the central server address typed by the user.
// Only http:// and https:// are accepted (never file:, javascript:, data:,
// chrome:, edge: ...). Query/fragment are dropped, trailing slashes removed.
// Returns { ok: true, url, pattern } or { ok: false, error }.
//   url     e.g. http://192.168.1.50:5002
//   pattern e.g. http://192.168.1.50:5002/*  (the host permission to request)
function normalizeServerUrl(input) {
  var text = String(input === null || input === undefined ? "" : input).trim();
  if (!text) {
    return { ok: false, error: "Enter the server address, for example http://192.168.1.50:5002" };
  }
  var u;
  try {
    u = new URL(text);
  } catch (e) {
    return { ok: false, error: "That is not a valid address. Use the form http://192.168.1.50:5002" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, error: "The address must start with http:// or https://" };
  }
  if (!u.hostname) {
    return { ok: false, error: "The address has no server name." };
  }
  if (u.username || u.password) {
    return { ok: false, error: "Do not put a user name or password in the address." };
  }
  var path = u.pathname.replace(/\/+$/, "");
  return { ok: true, url: u.origin + path, pattern: u.protocol + "//" + u.host + "/*" };
}

function isBrowserNoise(host, path) {
  var clean = String(path || "").replace(/\/+$/, "");
  return BROWSER_NOISE.some(function (n) { return n.host === host && n.path === clean; });
}

// Privacy sanitization - runs BEFORE any network call. Keeps scheme + host +
// path only: no query string, no fragment, no credentials, no port. Returns
// null for anything that is not an ordinary top-level web page.
function sanitizeNavigation(rawUrl) {
  var u;
  try { u = new URL(rawUrl); } catch (e) { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") { return null; }   // chrome://, edge://, file://, extensions ...
  var host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host.indexOf(".") === -1) { return null; }                    // skip intranet single labels
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { return null; }                 // domain-level only, no bare IPs
  var path = u.pathname || "/";
  return { domain: host, path: path, url: u.protocol + "//" + host + path };
}

function browserName() {
  var brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  if (brands.some(function (b) { return /Edge/i.test(b.brand); })) { return "Edge"; }
  if (/Edg\//.test(navigator.userAgent)) { return "Edge"; }
  return "Chrome";
}

if (typeof module !== "undefined" && module.exports) {   // lets the helpers be unit-tested with Node
  module.exports = { normalizeServerUrl: normalizeServerUrl, isBrowserNoise: isBrowserNoise,
                     sanitizeNavigation: sanitizeNavigation, DEFAULT_SERVER_URL: DEFAULT_SERVER_URL };
}
