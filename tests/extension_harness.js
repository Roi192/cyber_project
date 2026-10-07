// Test harness (run by tests/test_deployment.py, only when Node.js is installed; the
// application itself never needs Node). It executes the REAL extension scripts
// (background.js, options.js, common.js) in a sandbox with stubbed chrome.* APIs and a
// stubbed fetch, and reports which URLs and headers the extension would use.
// 192.0.2.x is the RFC 5737 documentation range: no real server is contacted.
"use strict";
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const EXT = path.join(__dirname, "..", "browser_extension");
const read = (name) => fs.readFileSync(path.join(EXT, name), "utf8");
const tick = () => new Promise((resolve) => setTimeout(resolve, 20));

function makeChrome(store, options) {
  const listeners = {};
  const permissionRequests = [];
  const chrome = {
    storage: {
      local: {
        get: async () => Object.assign({}, store),
        set: async (values) => { Object.assign(store, values); },
        remove: async (key) => { delete store[key]; }
      }
    },
    alarms: { get: (name, cb) => cb(undefined), create: () => {}, onAlarm: { addListener: (f) => { listeners.alarm = f; } } },
    runtime: { onInstalled: { addListener: () => {} }, onStartup: { addListener: () => {} } },
    tabs: { onRemoved: { addListener: () => {} } },
    webNavigation: { onCommitted: { addListener: (f) => { listeners.navigation = f; } } },
    permissions: {
      contains: async () => Boolean(options && options.alreadyGranted),
      request: async (request) => { permissionRequests.push(request); return !(options && options.deny); }
    }
  };
  return { chrome, listeners, permissionRequests };
}

function makeContext(store, options) {
  const calls = [];
  const wiring = makeChrome(store, options);
  const response = (status) => ({ ok: status >= 200 && status < 300, status, json: async () => ({ ok: true, service: "website-monitor" }) });
  const context = {
    chrome: wiring.chrome, console, URL, AbortController, setTimeout, clearTimeout, Date, JSON, Object, Array, String, Number,
    navigator: { userAgent: "Mozilla/5.0 Edg/150", userAgentData: { brands: [{ brand: "Microsoft Edge" }] } },
    crypto: { randomUUID: () => "generated-uuid-0000" },
    fetch: async (url, init) => {
      calls.push({ url: String(url), method: (init && init.method) || "GET", headers: (init && init.headers) || {},
                   body: init && init.body ? JSON.parse(init.body) : null });
      return response(options && options.status ? options.status : 200);
    }
  };
  vm.createContext(context);
  context.importScripts = (file) => vm.runInContext(read(file), context, { filename: file });
  return { context, calls, wiring };
}

async function background(store) {
  const { context, calls, wiring } = makeContext(store, {});
  vm.runInContext(read("background.js"), context, { filename: "background.js" });
  await wiring.listeners.navigation({ frameId: 0, tabId: 7, url: "https://www.example.com/account?token=SECRET#frag" });
  await wiring.listeners.alarm({ name: "heartbeat" });
  await tick();
  return calls;
}

function makeDom() {
  const ids = ["server_url", "computer_name", "username", "api_key", "uid", "key_hint", "remove_key", "dev", "result", "save", "test"];
  const elements = {};
  ids.forEach((id) => {
    elements[id] = { id, value: "", textContent: "", className: "", hidden: false, handlers: {},
                     addEventListener(type, handler) { this.handlers[type] = handler; } };
  });
  return { getElementById: (id) => elements[id], elements };
}

async function options(store, typed, permissionOptions) {
  const { context, calls, wiring } = makeContext(store, permissionOptions);
  const dom = makeDom();
  context.document = dom;
  vm.runInContext(read("common.js"), context, { filename: "common.js" });
  vm.runInContext(read("options.js"), context, { filename: "options.js" });
  await tick();
  Object.keys(typed).forEach((key) => { dom.elements[key].value = typed[key]; });
  await dom.elements.test.handlers.click();
  const afterTest = { result: dom.elements.result.textContent, calls: calls.slice() };
  calls.length = 0;
  await dom.elements.save.handlers.click();
  return { test: afterTest, save: { result: dom.elements.result.textContent, calls: calls.slice() },
           permissionRequests: wiring.permissionRequests, stored: Object.assign({}, store) };
}

async function main() {
  const out = {};
  const base = { endpoint_uid: "uid-harness-1", computer_name: "LAB-PC", username: "Roi" };

  out.bg_ip = await background(Object.assign({ server_url: "http://192.0.2.10:5002/", api_key: "TEST-KEY-123" }, base));
  out.bg_host_with_path = await background(Object.assign({ server_url: "https://monitor.college.example/mon", api_key: "TEST-KEY-123" }, base));
  out.bg_no_key = await background(Object.assign({ server_url: "http://192.0.2.10:5002" }, base));
  out.bg_invalid_url = await background(Object.assign({ server_url: "file:///etc/passwd", api_key: "TEST-KEY-123" }, base));
  out.bg_default_url = await background(Object.assign({}, base));

  out.opt_ip = await options(Object.assign({}, base, { api_key: "SAVED-KEY-1" }),
    { server_url: "http://192.0.2.10:5002/", computer_name: "LAB-PC", username: "Roi", api_key: "" }, {});
  out.opt_host = await options(Object.assign({}, base),
    { server_url: "http://lab-server.college.example:5002", computer_name: "LAB-PC", username: "", api_key: "TYPED-KEY-2" }, {});
  out.opt_denied = await options(Object.assign({}, base),
    { server_url: "http://192.0.2.10:5002", computer_name: "LAB-PC", username: "", api_key: "TYPED-KEY-3" }, { deny: true });
  out.opt_local_no_prompt = await options(Object.assign({}, base),
    { server_url: "http://127.0.0.1:5002", computer_name: "LAB-PC", username: "", api_key: "K" }, { alreadyGranted: true });
  out.opt_bad_scheme = await options(Object.assign({}, base),
    { server_url: "ftp://192.0.2.10:5002", computer_name: "LAB-PC", username: "", api_key: "K" }, {});
  out.opt_wrong_key = await options(Object.assign({}, base),
    { server_url: "http://192.0.2.10:5002", computer_name: "LAB-PC", username: "", api_key: "WRONG" }, { status: 401 });
  console.log(JSON.stringify(out));
}

main().catch((error) => { console.error(error && error.stack || String(error)); process.exit(1); });
