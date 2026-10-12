// Near-real-time refresh without WebSockets: every POLL_MS the page asks the
// server for (a) the security overview and counters, (b) visits newer than the
// last row it already shows and (c) on the Computers page, each computer's
// status. All wording comes from the server (one source of truth) and the DOM is
// only touched when a value actually changed, so nothing flickers.
(function () {
  var POLL_MS = 7000;
  // The site may be published under a proxy sub-path (for example /team2): the server puts that prefix in <meta name="app-root"> (empty otherwise) and every
  // root-relative URL below goes through appUrl().
  var APP_ROOT = (function () {
    try { var m = document.querySelector('meta[name="app-root"]'); return m ? (m.getAttribute("content") || "") : ""; } catch (e) { return ""; }     // no tag: served from the root
  })();
  function appUrl(path) { return APP_ROOT + path; }

  // A refresh that comes back 401 means the sign-in ended (idle timeout, sign-out elsewhere, server restart): go to the sign-in page.
  // "X-Background-Poll" tells the server this request is the page refreshing itself, so it does not count as the person being active.
  var signedOut = false;
  function getJson(url) {
    return fetch(url, { headers: { "Accept": "application/json", "X-Background-Poll": "1" }, cache: "no-store", credentials: "same-origin" })
      .then(function (r) {
        if (r.status === 401 && !signedOut) {
          signedOut = true;
          window.location.href = appUrl("/login");
          return null;
        }
        return r.ok ? r.json() : null;
      })
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
      setText(hero.querySelector(".status-scope"), o.scope_note || "");
      var action = byId("status-action");
      if (action) {
        setText(action, o.action.label);
        if (action.getAttribute("href") !== o.action.url) { action.setAttribute("href", o.action.url); }
      }
    }
    ["computers", "online_now", "visits_today", "contacted_today", "threats_today"].forEach(function (key) {
      setText(document.querySelector('[data-stat="' + key + '"]'), String(summary[key]));
    });
    setText(document.querySelector('[data-stat="computers_sub"]'),
            summary.sensors + (summary.sensors === 1 ? " sensor" : " sensors") + " in total" +
            (summary.unverified_computers ? " · " + summary.unverified_computers + (summary.unverified_computers === 1 ? " computer has" : " computers have") + " an unconfirmed identity" : "") +
            (summary.self_enrolled_computers ? " · " + summary.self_enrolled_computers + " self-enrolled (not administrator-approved)" : ""));
    setText(document.querySelector('[data-stat="online_sub"]'),
            (summary.computers - summary.online_now) + " offline · " + summary.sensors_online + " of " + summary.sensors + " sensors online");
    var contactedCard = byId("contacted-card");           // only shown once a network agent exists
    if (contactedCard) { contactedCard.hidden = !(summary.agents_enrolled || summary.contacted_today); }
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
    getJson(appUrl("/api/status")).then(function (data) {
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
  // "Visited website" (browser extension) or "Contacted domain" (network agent) - never mixed up
  function activityCell(v, withSource) {
    var cell = document.createElement("td");
    cell.className = "activity activity-" + String(v.source || "BROWSER").toLowerCase();
    cell.title = v.observation_hint || "";
    cell.textContent = v.observation_label || "Visited website";
    if (v.process_kind) {         // which program made the connection (network agent, native collector)
      var proc = document.createElement("div");
      proc.className = "muted src";
      proc.title = (v.process_kind_hint || "") + (v.pid ? " Process ID " + v.pid + " (temporary: it changes whenever the program restarts)." : "");
      proc.textContent = (v.process_label || "Unknown application") + " · " + (v.process_kind_label || "");
      cell.appendChild(proc);
    }
    if (v.supporting_sources && v.supporting_sources.length) {      // the same visit also seen in the browser history: counted once
      var also = document.createElement("div");
      also.className = "muted src";
      also.title = "The browser history recorded the same visit. It is counted once.";
      also.textContent = "+ also in " + v.supporting_sources.join(", ").toLowerCase();
      cell.appendChild(also);
    }
    if (withSource) {
      var src = document.createElement("div");
      src.className = "muted src";
      src.textContent = v.source_label || "Browser";
      cell.appendChild(src);
    }
    return cell;
  }

  function buildRow(v, columns) {
    var tr = document.createElement("tr");
    tr.className = "row-new";
    tr.setAttribute("data-id", String(v.id));
    tr.setAttribute("data-search", (v.domain + " " + v.computer_name + " " + (v.username || "") + (v.process_name ? " " + v.process_name : "")).toLowerCase());
    tr.appendChild(td(v.time_label, "mono nowrap", v.visited_at));
    tr.appendChild(td(v.computer_name));
    tr.appendChild(td(v.username || "-"));
    var website = document.createElement("td");
    var domain = document.createElement("span");
    domain.className = "domain";
    domain.textContent = v.domain;
    website.appendChild(domain);
    if (v.is_ip_only) {           // a connection known only by address: say so, never present it as a website
      var ipNote = document.createElement("div");
      ipNote.className = "muted src";
      ipNote.textContent = "IP address only (website unknown)";
      website.appendChild(ipNote);
    }
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
    tr.appendChild(activityCell(v, columns === "browsing"));
    var security = badgeCell(v.reputation_status, v.status_label, v.status_hint);
    if (v.analysis_summary) {                       // who checked the website and what they found (details behind the link)
      var note = document.createElement("div");
      note.className = "muted src";
      note.textContent = v.analysis_summary;
      security.appendChild(note);
    }
    if (v.risk_score !== null && v.risk_score !== undefined) {         // the 0-100 risk score (explained on the analysis page)
      var riskBox = document.createElement("div");
      riskBox.className = "src";
      var pill = document.createElement("span");
      pill.className = "risk-pill risk-" + v.risk_band;
      pill.title = (v.risk_coverage || "") + ". " + (v.score_tooltip || "A 0-100 score that combines what the independent sources reported. A low score is not a promise of safety.");
      pill.textContent = "Risk " + v.risk_score + " \u00b7 " + v.risk_label;
      riskBox.appendChild(pill);
      security.appendChild(riskBox);
    }
    if (!v.is_ip_only) {
      var linkBox = document.createElement("div");
      linkBox.className = "src";
      var link = document.createElement("a");
      link.className = "link";
      link.href = appUrl("/visits/") + v.id;
      link.textContent = "View analysis";
      linkBox.appendChild(link);
      security.appendChild(linkBox);
    }
    tr.appendChild(security);
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

  // The page shows LOGICAL visits. A logical visit has a stable identity (logical_id: the lowest id among its primary and
  // supporting records) that does not change when its primary record switches from the browser-history record to the
  // extension record, or when supporting evidence arrives later. Each poll fetches the newest logical visits and
  // RECONCILES the rows on screen with them: a row whose content changed is replaced in place, a row that became supporting
  // evidence of another visit disappears, a genuinely new visit is inserted - so there is never a second row for one visit
  // and no reload is needed.
  var RECONCILE_WINDOW = 50;       // how many of the newest rows are refreshed on every poll

  function rowKey(v) { return String(v.logical_id !== undefined && v.logical_id !== null ? v.logical_id : v.id); }

  // everything that is drawn for a row: when it differs from what is on screen the row is rebuilt
  function rowSignature(v) {
    return JSON.stringify([v.id, v.source, v.source_label, v.supporting_sources, v.analysis_summary, v.risk_score, v.risk_label, v.reputation_status,
                           v.status_label, v.time_label, v.sanitized_url, v.is_ip_only]);
  }

  function reconcileVisits(body, visits, columns, maxRows, windowSize) {
    var rows = Array.prototype.slice.call(body.children);
    var byKey = {};
    rows.forEach(function (row) { byKey[row.getAttribute("data-key") || row.getAttribute("data-id")] = row; });
    var head = rows.slice(0, windowSize);                 // the region this poll is authoritative for
    var tail = rows.slice(windowSize);
    var wanted = {};
    var desired = [];
    visits.forEach(function (v) {
      var key = rowKey(v);
      if (wanted[key]) { return; }                        // one row per logical visit, whatever the server sent
      wanted[key] = true;
      var signature = rowSignature(v);
      var row = byKey[key];
      if (row && row.getAttribute("data-sig") === signature) {
        desired.push(row);
        return;
      }
      var fresh = buildRow(v, columns);
      fresh.setAttribute("data-key", key);
      fresh.setAttribute("data-sig", signature);
      if (row) { fresh.className = ""; }                  // an update of a visit already shown: no "new" highlight
      desired.push(fresh);
    });
    tail.forEach(function (row) {                         // older rows stay, unless they are the same logical visit
      if (!wanted[row.getAttribute("data-key") || row.getAttribute("data-id")]) { desired.push(row); }
    });
    desired = desired.slice(0, maxRows);
    // touch the DOM only where it differs from what is shown now
    var current = Array.prototype.slice.call(body.children);
    var same = current.length === desired.length && current.every(function (row, i) { return row === desired[i]; });
    if (same) { return false; }
    current.forEach(function (row) { if (desired.indexOf(row) === -1) { body.removeChild(row); } });
    desired.forEach(function (row, i) {
      if (body.children[i] !== row) { body.insertBefore(row, body.children[i] || null); }
    });
    return true;
  }

  function refreshVisits() {
    var body = byId("visits-body");
    if (!body) { return; }
    var maxRows = parseInt(body.getAttribute("data-max-rows") || "50", 10);
    var windowSize = Math.min(maxRows, RECONCILE_WINDOW);
    var params = "window=1&limit=" + windowSize;
    var status = body.getAttribute("data-status") || "";
    var q = body.getAttribute("data-q") || "";
    var source = body.getAttribute("data-source") || "";
    if (source) { params += "&source=" + encodeURIComponent(source); }
    if (status) { params += "&status=" + encodeURIComponent(status); }
    if (q) { params += "&q=" + encodeURIComponent(q); }
    if (body.getAttribute("data-active") === "1") { params += "&active=1"; }
    if (body.getAttribute("data-physical") === "1") { params += "&physical=1"; }
    getJson(appUrl("/api/visits?" + params)).then(function (data) {
      var live = byId("live-indicator");
      if (!data || !data.ok) {
        setText(live, "Server not reachable - retrying");
        return;
      }
      setText(live, "Auto-refresh every " + (POLL_MS / 1000) + " s - updated " + new Date().toLocaleTimeString());
      reconcileVisits(body, data.visits, body.getAttribute("data-columns"), maxRows, windowSize);
      body.setAttribute("data-last-id", data.last_id);
      applyFilter();
    });
  }

  // ------------------------------------------------------------------
  // Computers page: status, last seen, counters
  // ------------------------------------------------------------------
  function setCell(tr, field, value, kind, code, hint) {
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
    } else if (kind === "visibility") {
      var vis = document.createElement("span");
      vis.className = "vis vis-" + String(code || "none").toLowerCase();
      vis.textContent = next;
      cell.appendChild(vis);
      cell.title = hint || "";
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
    var url = appUrl("/api/endpoints") + (body.getAttribute("data-archived") === "1" ? "?archived=1" : "");
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
        setCell(tr, "visibility_label", e.visibility_label, "visibility", e.visibility, e.visibility_hint);
        setCell(tr, "last_seen_relative", e.last_seen_relative);
        var seen = tr.querySelector('[data-field="last_seen_relative"]');
        if (seen && seen.title !== e.last_seen_label) { seen.title = e.last_seen_label; }
        setCell(tr, "websites_today", e.websites_today);
        setCell(tr, "contacted_today", e.contacted_today);
        setCell(tr, "threats_today", e.threats_today, "threats");
        (e.sensors || []).forEach(function (s) {                  // every sensor keeps its OWN status, never its computer's
          if (!tr.querySelector('[data-field="sensor_status_' + s.id + '"]')) { changedSet = true; return; }
          setCell(tr, "sensor_status_" + s.id, s.status, "status");
          setCell(tr, "sensor_seen_" + s.id, s.last_seen_relative);
          setCell(tr, "sensor_collectors_" + s.id, s.collectors_text);
        });
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
