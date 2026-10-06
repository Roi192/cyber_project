// Near-real-time refresh without WebSockets: every POLL_MS the page asks the
// server for (a) the summary counters / threat-intel status and (b) visits
// newer than the last row it already shows, and prepends them.
(function () {
  var POLL_MS = 7000;

  var STATUS_LABELS = { SAFE: "Safe", SUSPICIOUS: "Suspicious", MALICIOUS: "Malicious", UNKNOWN: "Unknown" };
  var BANNER = {
    OK: ["All clear", "No open alerts. Your computers have not visited any known dangerous websites."],
    WARNING: ["Attention needed", "There are open alerts about suspicious websites. Review them on the Alerts page."],
    ALERT: ["Threat detected", "A computer visited a website identified as malicious. Review the Alerts page now."]
  };
  var TI_LABELS = { ACTIVE: "Active", NOT_CONFIGURED: "Not configured", TEMPORARILY_UNAVAILABLE: "Temporarily unavailable" };

  function getJson(url) {
    return fetch(url, { headers: { "Accept": "application/json" }, cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }

  function td(text, className) {
    var cell = document.createElement("td");
    if (className) { cell.className = className; }
    cell.textContent = text;                       // textContent: never interprets HTML
    return cell;
  }

  function badge(status) {
    var cell = document.createElement("td");
    var span = document.createElement("span");
    span.className = "badge badge-" + String(status).toLowerCase();
    span.textContent = STATUS_LABELS[status] || status;
    cell.appendChild(span);
    return cell;
  }

  function buildRow(v, columns) {
    var tr = document.createElement("tr");
    tr.className = "row-new";
    tr.appendChild(td(v.visited_at, "mono"));
    tr.appendChild(td(v.computer_name));
    tr.appendChild(td(v.username || "-"));
    var domain = td(v.domain, "domain");
    if (columns === "dashboard") { domain.title = v.sanitized_url || v.domain; }
    tr.appendChild(domain);
    if (columns === "browsing") {
      tr.appendChild(td(v.sanitized_url || "-", "mono path"));
      tr.appendChild(td(v.browser || "-"));
    }
    tr.appendChild(badge(v.reputation_status));
    return tr;
  }

  // ---- summary counters, banner, threat-intel indicator ----
  function refreshStatus() {
    getJson("/api/status").then(function (data) {
      if (!data || !data.summary) { return; }
      var s = data.summary;
      ["computers", "visits_today", "threats_today", "open_alerts"].forEach(function (key) {
        var el = document.querySelector('[data-stat="' + key + '"]');
        if (el) { el.textContent = s[key]; }
      });
      var banner = document.getElementById("security-status");
      if (banner) {
        banner.className = "status-banner status-" + String(s.security_status).toLowerCase();
        var text = BANNER[s.security_status] || BANNER.OK;
        banner.querySelector(".status-value").textContent = text[0];
        banner.querySelector(".status-hint").textContent = text[1];
      }
      var ti = data.threat_intel || {};
      var pill = document.getElementById("ti-pill");
      if (pill && ti.status) {
        pill.className = "ti-pill ti-" + String(ti.status).toLowerCase();
        pill.title = ti.detail || "";
        pill.querySelector(".ti-pill-label").textContent = TI_LABELS[ti.status] || ti.status;
      }
      var row = document.getElementById("ti-row");
      if (row && ti.status) {
        row.className = "ti-row ti-" + String(ti.status).toLowerCase();
        row.querySelector(".ti-row-label").textContent = TI_LABELS[ti.status] || ti.status;
        row.querySelector(".ti-row-detail").textContent = ti.detail || "";
      }
      var dev = document.getElementById("dev-pill");
      if (dev) { dev.hidden = !data.dev_mode; }
    });
  }

  // ---- new visits ----
  function refreshVisits() {
    var body = document.getElementById("visits-body");
    if (!body) { return; }
    var lastId = parseInt(body.getAttribute("data-last-id") || "0", 10) || 0;
    var status = body.getAttribute("data-status") || "";
    var url = "/api/visits?after_id=" + lastId + (status ? "&status=" + encodeURIComponent(status) : "");
    getJson(url).then(function (data) {
      var live = document.getElementById("live-indicator");
      if (!data || !data.ok) {
        if (live) { live.textContent = "Server not reachable - retrying"; }
        return;
      }
      if (live) { live.textContent = "Auto-refresh every " + (POLL_MS / 1000) + " s - updated " + new Date().toLocaleTimeString(); }
      if (!data.visits.length) { return; }
      var columns = body.getAttribute("data-columns");
      var maxRows = parseInt(body.getAttribute("data-max-rows") || "50", 10);
      // visits arrive newest first; insert oldest first so the newest ends on top
      for (var i = data.visits.length - 1; i >= 0; i--) {
        body.insertBefore(buildRow(data.visits[i], columns), body.firstChild);
      }
      while (body.children.length > maxRows) { body.removeChild(body.lastChild); }
      body.setAttribute("data-last-id", data.last_id);
      var table = document.getElementById("visits-table");
      var empty = document.getElementById("visits-empty");
      if (table) { table.hidden = false; }
      if (empty) { empty.hidden = true; }
      if (document.getElementById("security-status")) { refreshStatus(); }
    });
  }

  if (document.getElementById("visits-body") || document.getElementById("security-status") || document.getElementById("ti-pill")) {
    setInterval(function () { refreshStatus(); refreshVisits(); }, POLL_MS);
  }
})();
