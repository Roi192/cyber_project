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
  var cfg = await chrome.storage.local.get(["endpoint_uid", "computer_name", "username", "server_url", "api_key", "sensor_secret", "paired_device_name"]);
  el("server_url").value = cfg.server_url || DEFAULT_SERVER_URL;
  el("computer_name").value = cfg.computer_name || "";
  el("username").value = cfg.username || "";
  el("api_key").value = "";                                  // never echoed back
  el("uid").textContent = cfg.endpoint_uid || "(created automatically)";
  showKeyState(Boolean(cfg.api_key));
  showPairState(cfg);
}

function showPairState(cfg) {
  el("pair_state").textContent = cfg.sensor_secret
    ? "Paired with the Windows Agent of " + (cfg.paired_device_name || "this computer") + ". This browser is one sensor of that computer."
    : "Not paired. This browser is reported as its own, unverified computer.";
}

function showPairResult(text, kind) {
  var box = el("pair_result");
  box.textContent = text || "";
  box.className = "result " + (kind || "info");
  box.hidden = !text;
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

async function callServer(norm, apiKey, method, path, body, sensorSecret) {
  var headers = {};
  if (apiKey) { headers["X-Api-Key"] = apiKey; }
  if (sensorSecret) { headers["X-Sensor-Secret"] = sensorSecret; }
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
  var stored = await chrome.storage.local.get(["endpoint_uid", "api_key", "sensor_secret"]);
  showKeyState(Boolean(stored.api_key));

  // register / update this browser with the central server
  var payload = { endpoint_uid: stored.endpoint_uid, computer_name: computerName, username: username, browser: browserName(),
                  sensor_version: extensionVersion() };
  var result = await callServer(norm, stored.api_key || "", "POST", "/api/endpoints/register", payload, stored.sensor_secret || "");
  var msg = describe(result, "Saved. This browser is registered as " + computerName + ".");
  if (msg.kind !== "ok") { msg.text = "Saved, but registration failed. " + msg.text; }
  showResult(msg.text, msg.kind);
}

async function removeKey() {
  await chrome.storage.local.remove("api_key");
  showKeyState(false);
  showResult("The saved API key was removed.", "info");
}

// Pair this browser with the Windows Agent on this computer: the owner types the code the agent printed; the agent (loopback only)
// asks the server for a grant naming this installation; the server then attaches this browser to the agent's device.
async function pair() {
  var code = el("pair_code").value.trim();
  if (!code) { showPairResult("Type the code printed by the Windows Agent.", "error"); return; }
  var norm = normalizeServerUrl(el("server_url").value);
  if (!norm.ok) { showPairResult(norm.error, "error"); return; }
  if (!(await ensureAccess(norm))) { showPairResult("Access to the server was not allowed.", "error"); return; }
  var agentRequest = { origins: [AGENT_PAIRING_ORIGIN + "/*"] };
  try {
    if (!(await chrome.permissions.contains(agentRequest)) && !(await chrome.permissions.request(agentRequest))) {
      showPairResult("Access to the Windows Agent on this computer was not allowed.", "error");
      return;
    }
  } catch (e) {
    showPairResult("Access to the Windows Agent on this computer was not allowed.", "error");
    return;
  }
  showPairResult("Pairing...", "info");
  var cfg = await chrome.storage.local.get(["endpoint_uid", "api_key", "sensor_secret", "username"]);
  var computerName = el("computer_name").value.trim() || ("BROWSER-" + String(cfg.endpoint_uid).slice(0, 8).toUpperCase());
  var agent;
  try {
    var res = await fetch(AGENT_PAIRING_ORIGIN + "/pair", {
      method: "POST", headers: { "Content-Type": "application/json" }, cache: "no-store",
      body: JSON.stringify({ code: code, sensor_uid: cfg.endpoint_uid })
    });
    agent = { status: res.status, json: await res.json().catch(function () { return null; }) };
  } catch (e) {
    showPairResult("The Windows Agent did not answer on this computer. Is it running, with pairing enabled?", "error");
    return;
  }
  if (agent.status !== 200 || !agent.json || !agent.json.grant) {
    showPairResult((agent.json && agent.json.error) ? "The Windows Agent refused: " + agent.json.error : "The Windows Agent refused the pairing.", "error");
    return;
  }
  var key = await effectiveKey();
  var done = await callServer(norm, key, "POST", "/api/sensors/pair", {
    grant: agent.json.grant, endpoint_uid: cfg.endpoint_uid, computer_name: computerName, username: cfg.username || el("username").value.trim(),
    browser: browserName(), sensor_version: extensionVersion()
  }, cfg.sensor_secret || "");
  if (!done.reached) { showPairResult("Cannot reach the server to finish pairing.", "error"); return; }
  if (done.status !== 201 || !done.json || !done.json.sensor_secret) {
    showPairResult((done.json && done.json.error) ? "The server refused the pairing: " + done.json.error : "The server refused the pairing.", "error");
    return;
  }
  await chrome.storage.local.set({ sensor_secret: done.json.sensor_secret, paired_device_name: done.json.device_name || "" });
  el("pair_code").value = "";
  showPairState({ sensor_secret: done.json.sensor_secret, paired_device_name: done.json.device_name });
  showPairResult("Paired. This browser is now a sensor of " + (done.json.device_name || "this computer") + ".", "ok");
}

el("save").addEventListener("click", save);
el("pair").addEventListener("click", pair);
el("test").addEventListener("click", testConnection);
el("remove_key").addEventListener("click", removeKey);
load();
