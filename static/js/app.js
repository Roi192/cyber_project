// Near-real-time refresh without WebSockets: every POLL_MS the page asks the
// server for (a) the security overview and counters, (b) visits newer than the
// last row it already shows and (c) on the Computers page, each computer's
// status. All wording comes from the server (one source of truth) and the DOM is
// only touched when a value actually changed, so nothing flickers.
(function () {
  var POLL_MS = 7000;

  function getJson(url) {
    return fetch(url, { headers: { "Accept": "application/json" }, cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }

  function byId(id) { return document.getElementById(id); }

  function setText(el, text) {
    if (el && el.textContent !== text) { el.textContent = text; }
  }

  function setClass(el, name) {
    if (el && el.className !== name) { el.className = name; }
  }

  function td(text, className, title) {
    var cell = document.createElement("td");
    if (className) { cell.className = className; }
    if (title) { cell.title = title; }
    cell.textContent = text;                       // textContent: never interprets HTML
    return cell;
  }

  function badgeCell(status, label, hint) {
    var cell = document.createElement("td");
    var span = document.createElement("span");
    span.className = "badge badge-" + String(status).toLowerCase();
    span.textContent = label;
    if (hint) { span.title = hint; }
    cell.appendChild(span);
    return cell;
  }

  // ------------------------------------------------------------------
  // security overview (dashboard) + threat-intelligence indicators
  // ------------------------------------------------------------------
  function renderAttention(items) {
    var list = byId("attention-list");
    var empty = byId("attention-empty");
    if (!list || !empty) { return; }
    var sig = JSON.stringify(items);
    if (list.getAttribute("data-sig") !== sig) {
      list.setAttribute("data-sig", sig);
      while (list.firstChild) { list.removeChild(list.firstChild); }
      items.forEach(function (item) {
        var li = document.createElement("li");
        li.className = "attention-item level-" + item.level;
        if (item.url) {
          var a = document.createElement("a");
          a.href = item.url;
          a.textContent = item.text;
          li.appendChild(a);
        } else {
          li.textContent = item.text;
        }
        list.appendChild(li);
      });
    }
    list.hidden = items.length === 0;
    empty.hidden = items.length !== 0;
  }

  function renderOverview(o, summary) {
    var hero = byId("security-status");
    if (hero) {
      setClass(hero, "status-hero status-" + o.css);
      setText(hero.querySelector(".status-value"), o.title);
      setText(hero.querySelector(".status-hint"), o.message);
      var affected = hero.querySelector(".status-affected");
      setText(affected, o.affected || "");
      if (affected) { affected.hidden = !o.affected; }
      setText(hero.querySelector(".status-coverage"), o.coverage_line);
      var action = byId("status-action");
      if (action) {
        setText(action, o.action.label);
        if (action.getAttribute("href") !== o.action.url) { action.setAttribute("href", o.action.url); }
      }
    }
    ["computers", "online_now", "visits_today", "threats_today"].forEach(function (key) {
      setText(document.querySelector('[data-stat="' + key + '"]'), String(summary[key]));
    });
    var cov = o.coverage;
    setText(document.querySelector('[data-stat="coverage_value"]'), cov.percent === null ? "–" : cov.percent + "%");
    setText(document.querySelector('[data-stat="coverage_sub"]'),
            cov.total ? cov.evaluated + " of " + cov.total + " checked" : "No browsing yet today");
    var tile = document.querySelector('[data-stat="threats_today"]');
    if (tile && tile.parentNode) { tile.parentNode.classList.toggle("tile-danger", summary.threats_today > 0); }
    renderAttention(o.attention);
  }

  function renderThreatIntel(ti) {
    if (!ti || !ti.status) { return; }
    var pill = byId("ti-pill");
    if (pill) {
      setClass(pill, "ti-pill ti-" + String(ti.status).toLowerCase());
      if (pill.title !== (ti.summary || "")) { pill.title = ti.summary || ""; }
      setText(pill.querySelector(".ti-pill-label"), ti.label);
    }
    var row = byId("ti-row");
    if (row) {
      setClass(row, "ti-row ti-" + String(ti.status).toLowerCase());
      setText(row.querySelector(".ti-row-label"), ti.label);
      setText(row.querySelector(".ti-row-detail"), ti.summary || "");
      setText(row.querySelector(".ti-row-tech"), ti.detail || "");
    }
  }

  function refreshStatus() {
    getJson("/api/status").then(function (data) {
      if (!data || !data.summary) { return; }
      if (data.overview) { renderOverview(data.overview, data.summary); }
      renderThreatIntel(data.threat_intel);
      var dev = byId("dev-bar");
      if (dev) { dev.hidden = !data.dev_mode; }
    });
  }

  // ------------------------------------------------------------------
  // visits table (dashboard "Recent activity" and the Browsing page)
  // ------------------------------------------------------------------
  function buildRow(v, columns) {
    var tr = document.createElement("tr");
    tr.className = "row-new";
    tr.setAttribute("data-id", String(v.id));
    tr.setAttribute("data-search", (v.domain + " " + v.computer_name + " " + (v.username || "")).toLowerCase());
    tr.appendChild(td(v.time_label, "mono nowrap", v.visited_at));
    tr.appendChild(td(v.computer_name));
    tr.appendChild(td(v.username || "-"));
    var website = document.createElement("td");
    var domain = document.createElement("span");
    domain.className = "domain";
    domain.textContent = v.domain;
    website.appendChild(domain);
    if (columns === "browsing") {
      if (v.sanitized_url) {
        var path = document.createElement("div");
        path.className = "path muted mono";
        path.title = v.sanitized_url;
        path.textContent = v.sanitized_url;
        website.appendChild(path);
      }
      tr.appendChild(website);
      tr.appendChild(td(v.browser || "-"));
    } else {
      tr.appendChild(website);
    }
    tr.appendChild(badgeCell(v.reputation_status, v.status_label, v.status_hint));
    return tr;
  }

  function searchTerm() {
    var input = byId("search");
    return input ? input.value.trim().toLowerCase() : "";
  }

  // typing filters the rows already loaded; Enter searches the whole history on the server
  function applyFilter() {
    var body = byId("visits-body");
    if (!body) { return; }
    var term = searchTerm();
    var visible = 0;
    Array.prototype.forEach.call(body.children, function (row) {
      var hit = !term || (row.getAttribute("data-search") || "").indexOf(term) !== -1;
      row.hidden = !hit;
      if (hit) { visible += 1; }
    });
    var table = byId("visits-table");
    var empty = byId("visits-empty");
    if (table) { table.hidden = visible === 0; }
    if (empty) { empty.hidden = visible !== 0; }
  }

  function refreshVisits() {
    var body = byId("visits-body");
    if (!body) { return; }
    var lastId = parseInt(body.getAttribute("data-last-id") || "0", 10) || 0;
    var params = "after_id=" + lastId;
    var status = body.getAttribute("data-status") || "";
    var q = body.getAttribute("data-q") || "";
    if (status) { params += "&status=" + encodeURIComponent(status); }
    if (q) { params += "&q=" + encodeURIComponent(q); }
    if (body.getAttribute("data-active") === "1") { params += "&active=1"; }
    getJson("/api/visits?" + params).then(function (data) {
      var live = byId("live-indicator");
      if (!data || !data.ok) {
        setText(live, "Server not reachable - retrying");
        return;
      }
      setText(live, "Auto-refresh every " + (POLL_MS / 1000) + " s - updated " + new Date().toLocaleTimeString());
      if (!data.visits.length) { return; }
      var columns = body.getAttribute("data-columns");
      var maxRows = parseInt(body.getAttribute("data-max-rows") || "50", 10);
      var shown = {};
      Array.prototype.forEach.call(body.children, function (row) { shown[row.getAttribute("data-id")] = true; });
      // visits arrive newest first; insert oldest first so the newest ends on top.
      // A visit that is already on screen is never added twice.
      for (var i = data.visits.length - 1; i >= 0; i--) {
        if (shown[String(data.visits[i].id)]) { continue; }
        body.insertBefore(buildRow(data.visits[i], columns), body.firstChild);
      }
      while (body.children.length > maxRows) { body.removeChild(body.lastChild); }
      body.setAttribute("data-last-id", data.last_id);
      applyFilter();
    });
  }

  // ------------------------------------------------------------------
  // Computers page: status, last seen, counters
  // ------------------------------------------------------------------
  function setCell(tr, field, value, kind) {
    var cell = tr.querySelector('[data-field="' + field + '"]');
    if (!cell) { return; }
    var current = cell.getAttribute("data-value");
    var next = String(value === null || value === undefined ? "" : value);
    if (current === next) { return; }
    cell.setAttribute("data-value", next);
    cell.textContent = "";
    if (kind === "status") {
      var span = document.createElement("span");
      span.className = "badge badge-" + next.toLowerCase();
      span.textContent = next === "ONLINE" ? "Online" : "Offline";
      cell.appendChild(span);
    } else if (kind === "threats" && Number(next) > 0) {
      var warn = document.createElement("span");
      warn.className = "badge badge-sev-high";
      warn.textContent = next;
      cell.appendChild(warn);
    } else {
      cell.textContent = next === "" ? (kind === "threats" ? "0" : "-") : next;
    }
  }

  function refreshEndpoints() {
    var body = byId("endpoints-body");
    if (!body) { return; }
    var url = "/api/endpoints" + (body.getAttribute("data-archived") === "1" ? "?archived=1" : "");
    getJson(url).then(function (data) {
      var live = byId("live-indicator");
      if (!data || !data.ok) {
        setText(live, "Server not reachable - retrying");
        return;
      }
      setText(live, "Auto-refresh every " + (POLL_MS / 1000) + " s - updated " + new Date().toLocaleTimeString());
      var known = {};
      Array.prototype.forEach.call(body.querySelectorAll("tr[data-endpoint-id]"), function (tr) {
        known[tr.getAttribute("data-endpoint-id")] = tr;
      });
      var changedSet = data.endpoints.length !== Object.keys(known).length;
      data.endpoints.forEach(function (e) {
        var tr = known[String(e.id)];
        if (!tr) { changedSet = true; return; }
        setCell(tr, "username", e.username);
        setCell(tr, "browser", e.browser);
        setCell(tr, "status", e.status, "status");
        setCell(tr, "last_seen_relative", e.last_seen_relative);
        var seen = tr.querySelector('[data-field="last_seen_relative"]');
        if (seen && seen.title !== e.last_seen_label) { seen.title = e.last_seen_label; }
        setCell(tr, "websites_today", e.websites_today);
        setCell(tr, "threats_today", e.threats_today, "threats");
      });
      if (changedSet) { window.location.reload(); }   // a computer enrolled or was archived elsewhere
    });
  }

  // ------------------------------------------------------------------
  var search = byId("search");
  if (search) {
    search.addEventListener("input", applyFilter);
    applyFilter();
  }

  if (byId("visits-body") || byId("endpoints-body") || byId("security-status") || byId("ti-pill")) {
    setInterval(function () { refreshStatus(); refreshVisits(); refreshEndpoints(); }, POLL_MS);
  }
})();
