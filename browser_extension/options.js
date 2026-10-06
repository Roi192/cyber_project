const FIELDS = ["computer_name", "username", "server_url", "api_key"];

async function load() {
  const cfg = await chrome.storage.local.get(["endpoint_uid"].concat(FIELDS));
  document.getElementById("uid").textContent = cfg.endpoint_uid || "(created on first navigation)";
  for (const f of FIELDS) {
    document.getElementById(f).value = cfg[f] || (f === "server_url" ? "http://127.0.0.1:5002" : "");
  }
  document.getElementById("dev").hidden = Boolean(cfg.api_key);
}

async function save() {
  const values = {};
  for (const f of FIELDS) values[f] = document.getElementById(f).value.trim();
  if (!values.computer_name) { delete values.computer_name; }   // keep the generated label
  await chrome.storage.local.set(values);
  document.getElementById("dev").hidden = Boolean(values.api_key);
  const ok = document.getElementById("saved");
  ok.hidden = false;
  setTimeout(() => { ok.hidden = true; }, 1500);
}

document.getElementById("save").addEventListener("click", save);
load();
