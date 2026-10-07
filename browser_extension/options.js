"use strict";
// Enrollment screen: server address, computer name, user, API key, and a
// connection test. All text shown to the user is plain language - no stack
// traces, and the API key is never displayed back.

function el(id) { return document.getElementById(id); }

function showResult(text, kind) {
  var box = el("result");
  box.textContent = text || "";
  box.className = "result " + (kind || "info");
  box.hidden = !text;
}

async function load() {
  var cfg = await chrome.storage.local.get(["endpoint_uid", "computer_name", "username", "server_url", "api_key"]);
  el("server_url").value = cfg.server_url || DEFAULT_SERVER_URL;
  el("computer_name").value = cfg.computer_name || "";
  el("username").value = cfg.username || "";
  el("api_key").value = "";                                  // never echoed back
  el("uid").textContent = cfg.endpoint_uid || "(created automatically)";
  showKeyState(Boolean(cfg.api_key));
}

function showKeyState(hasKey) {
  el("key_hint").textContent = hasKey
    ? "A key is saved. Leave this field empty to keep it, or type a new one to replace it."
    : "Enter the key you were given. Leave empty only while testing against a server in DEV MODE.";
  el("remove_key").hidden = !hasKey;
  el("dev").hidden = hasKey;
}

// Ask the browser for permission to talk to exactly this server (a no-op for
// 127.0.0.1:5002 which is already allowed). Must be called straight from a click.
async function ensureAccess(norm) {
  var req = { origins: [norm.pattern] };
  try {
    if (await chrome.permissions.contains(req)) { return true; }
    return await chrome.permissions.request(req);
  } catch (e) {
    return false;
  }
}

async function callServer(norm, apiKey, method, path, body) {
  var headers = {};
  if (apiKey) { headers["X-Api-Key"] = apiKey; }
  if (body) { headers["Content-Type"] = "application/json"; }
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, 6000);
  try {
    var res = await fetch(norm.url + path, { method: method, headers: headers, signal: controller.signal, cache: "no-store",
                                              body: body ? JSON.stringify(body) : undefined });
    var json = null;
    try { json = await res.json(); } catch (e) { /* not JSON */ }
    return { reached: true, status: res.status, json: json };
  } catch (e) {
    return { reached: false, status: 0, json: null };
  } finally {
    clearTimeout(timer);
  }
}

// Turn a server answer into a plain message.
function describe(result, okText) {
  if (!result.reached) {
    return { kind: "error", text: "Cannot reach server. Check the address, that the server is running, and that a firewall is not blocking it." };
  }
  if (result.status === 401) {
    return { kind: "error", text: "Authentication failed. Check the API key." };
  }
  if (result.status === 400) {
    return { kind: "error", text: "The server did not accept this computer's details. Check the computer name." };
  }
  if (result.status >= 200 && result.status < 300 && result.json && (result.json.service === "website-monitor" || result.json.ok === true)) {
    return { kind: "ok", text: okText };
  }
  return { kind: "error", text: "This address answered, but it does not look like a Website Monitor server (code " + result.status + ")." };
}

async function effectiveKey() {
  var typed = el("api_key").value.trim();
  if (typed) { return typed; }
  var stored = await chrome.storage.local.get(["api_key"]);
  return stored.api_key || "";
}

async function testConnection() {
  var norm = normalizeServerUrl(el("server_url").value);
  if (!norm.ok) { showResult(norm.error, "error"); return; }
  if (!(await ensureAccess(norm))) {
    showResult("Access to this server was not allowed, so the test could not run.", "error");
    return;
  }
  showResult("Testing...", "info");
  var result = await callServer(norm, await effectiveKey(), "GET", "/api/ping");
  var msg = describe(result, "Connected successfully");
  showResult(msg.text, msg.kind);
}

async function save() {
  var norm = normalizeServerUrl(el("server_url").value);
  if (!norm.ok) { showResult(norm.error, "error"); return; }
  var computerName = el("computer_name").value.trim();
  if (!computerName) { showResult("Enter a computer name.", "error"); return; }
  var username = el("username").value.trim();
  var typedKey = el("api_key").value.trim();

  if (!(await ensureAccess(norm))) {            // first, while the click is still fresh
    showResult("Access to this server was not allowed, so nothing was saved.", "error");
    return;
  }
  var values = { server_url: norm.url, computer_name: computerName, username: username };
  if (typedKey) { values.api_key = typedKey; }
  await chrome.storage.local.set(values);
  el("server_url").value = norm.url;
  el("api_key").value = "";
  var stored = await chrome.storage.local.get(["endpoint_uid", "api_key"]);
  showKeyState(Boolean(stored.api_key));

  // register / update this browser with the central server
  var payload = { endpoint_uid: stored.endpoint_uid, computer_name: computerName, username: username, browser: browserName() };
  var result = await callServer(norm, stored.api_key || "", "POST", "/api/endpoints/register", payload);
  var msg = describe(result, "Saved. This browser is registered as " + computerName + ".");
  if (msg.kind !== "ok") { msg.text = "Saved, but registration failed. " + msg.text; }
  showResult(msg.text, msg.kind);
}

async function removeKey() {
  await chrome.storage.local.remove("api_key");
  showKeyState(false);
  showResult("The saved API key was removed.", "info");
}

el("save").addEventListener("click", save);
el("test").addEventListener("click", testConnection);
el("remove_key").addEventListener("click", removeKey);
load();
