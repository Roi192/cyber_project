// Executive dashboard and computer detail page (Phase C2). No libraries, no CDN: plain DOM + SVG.
//
// Data flow: the page asks the read-only, administrator-only analytics API (Phase C1) for the selected period - summary, daily trends and the
// computer ranking on the dashboard; one computer's assessment, its activity and its daily series on the detail page - and draws what comes back.
// Rules this file keeps:
//   * every value that came from the API is put on the page with textContent / setAttribute, never innerHTML, so a hostile computer name, user
//     label or domain cannot become markup (tests/test_phaseC2.py checks the source for it and replays hostile values);
//   * a failed request is shown as an error with a Retry button - it is never turned into a zero;
//   * "no data", "insufficient data", "unknown" and "no threat detected" are different things and are worded differently;
//   * the three questions stay apart: OBSERVED WEB EXPOSURE (score), MONITORING COVERAGE, DEVICE VERIFICATION.
(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var REFRESH_MS = 60000;       // a background refresh, only while the tab is visible
  var CACHE_MS = 20000;         // an answer this young is reused (switching the period back and forth does not hit the server again)
  var ROW_CHUNK = 25;           // table rows added per click: the page stays usable with many computers
  var ATTENTION_LIMIT = 10;
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  // ---- small helpers --------------------------------------------------------------------------------------------------------------
  function byId(id) { return document.getElementById(id); }

  // The site may be published under a proxy sub-path (for example /team2): the server puts that prefix in <meta name="app-root"> (empty otherwise) and every
  // root-relative URL below goes through appUrl().
  var APP_ROOT = (function () {
    try { var m = document.querySelector('meta[name="app-root"]'); return m ? (m.getAttribute("content") || "") : ""; } catch (e) { return ""; }     // no tag: served from the root
  })();
  function appUrl(path) { return APP_ROOT + path; }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function svgEl(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, String(attrs[k])); });
    return node;
  }

  function clear(node) { while (node && node.firstChild) { node.removeChild(node.firstChild); } }

  function setText(node, text) { if (node && node.textContent !== String(text)) { node.textContent = String(text); } }

  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }

  function parseTs(ts) {                       // "2026-10-08 14:05:09" (server local time, no offset) -> ms; only ever DIFFERENCES are used
    var m = /^(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):(\d{2}):(\d{2}))?$/.exec(String(ts || ""));
    if (!m) { return null; }
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  }

  function shortDate(ts) {
    var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(ts || ""));
    return m ? MONTHS[+m[2] - 1] + " " + (+m[3]) : String(ts || "");
  }

  function dateTime(ts) {
    var m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})/.exec(String(ts || ""));
    return m ? MONTHS[+m[2] - 1] + " " + (+m[3]) + ", " + m[4] + ":" + m[5] : String(ts || "");
  }

  // "3 days ago", measured against the SERVER's own clock (meta.generated_at), so the browser's time zone cannot shift it
  function ago(ts, nowTs) {
    var a = parseTs(ts), b = parseTs(nowTs);
    if (a === null || b === null) { return String(ts || ""); }
    var s = Math.max(0, (b - a) / 1000);
    if (s < 3600) { return "less than an hour ago"; }
    if (s < 86400) { var h = Math.floor(s / 3600); return plural(h, "hour", "hours") + " ago"; }
    var d = Math.floor(s / 86400);
    return plural(d, "day", "days") + " ago";
  }

  function addNode(parent, child) { parent.appendChild(child); return child; }

  function pill(text, kind) { return el("span", "pill pill-" + kind, text); }

  // How a computer's identity is known (Phase D2.1). The API sends the wording; this only falls back to the older identity_status for an answer that lacks it.
  // Nothing here ever says "verified": no administrator approval exists yet, and a self-enrolled agent is not the same thing.
  function identityOf(cov) {
    if (cov && cov.identity_short) { return { level: cov.identity_level, short: cov.identity_short, tone: cov.identity_level === "ADMIN_APPROVED" ? "ok" : (cov.identity_level === "SELF_ENROLLED" ? "info" : "warn"), explanation: cov.identity_explanation || "" }; }
    return { level: "UNKNOWN", short: "Unknown identity", tone: "warn", explanation: "" };
  }

  // ---- labels (API codes -> words for an owner). Only these tables ever feed a class name, never a raw API string -------------------------
  var COVERAGE = {
    NOT_REPORTING: ["Not reporting", "bad"],
    PARTIALLY_MONITORED: ["Partly monitored", "warn"],
    INSUFFICIENT_HISTORICAL_COVERAGE: ["Little history", "muted"],
    UNVERIFIED_IDENTITY: ["Reporting", "ok"],
    REPORTING_NORMALLY: ["Reporting normally", "ok"]
  };
  var CATEGORY_CLASS = { SEVERE: "severe", HIGH: "high", MODERATE: "moderate", LOW: "low", NONE_OBSERVED: "none" };
  var VERDICT = { MALICIOUS: ["Dangerous", "bad"], SUSPICIOUS: ["Needs review", "warn"] };
  var ALL_VERDICTS = { MALICIOUS: ["Dangerous", "bad"], SUSPICIOUS: ["Needs review", "warn"], SAFE: ["No threat detected", "muted"], WEAK: ["Weak finding", "muted"], UNKNOWN: ["Could not be checked", "dashed"] };
  var SOURCE = { BROWSER: "Browser extension", BROWSER_HISTORY: "Browser history (agent)" };
  var SENSOR = { REPORTING: "Reporting", NOT_REPORTING: "Not reporting", NOT_PRESENT: "Not installed" };

  // ---- talking to the API ---------------------------------------------------------------------------------------------------------
  var cache = {};
  var inflight = {};
  var signedOut = false;

  function ApiError(kind, status, message) { this.kind = kind; this.status = status; this.message = message; }

  function goToSignIn() {
    if (!signedOut) { signedOut = true; window.location.href = appUrl("/login"); }
  }

  // GET url -> Promise(body). `background` marks the request as the page refreshing itself (the server does not count it as the person being active).
  function load(url, options) {
    options = options || {};
    var hit = cache[url];
    if (!options.force && hit && (Date.now() - hit.at) < CACHE_MS) { return Promise.resolve(hit.body); }
    if (inflight[url]) { return inflight[url]; }
    var headers = { "Accept": "application/json" };
    if (options.background) { headers["X-Background-Poll"] = "1"; }
    var init = { headers: headers, cache: "no-store", credentials: "same-origin" };
    var promise = fetch(url, init).then(function (r) {
      if (r.status === 401) { goToSignIn(); throw new ApiError("auth", 401, "Your session has ended."); }
      return r.json().then(function (body) { return { r: r, body: body }; }, function () { throw new ApiError("bad", r.status, "The server answered with something unreadable."); });
    }).then(function (x) {
      if (!x.r.ok || !x.body || x.body.ok !== true) {
        throw new ApiError("http", x.r.status, (x.body && x.body.error) ? String(x.body.error) : "The server could not answer.");
      }
      cache[url] = { at: Date.now(), body: x.body };
      return x.body;
    }, function (e) {
      if (e instanceof ApiError) { throw e; }
      throw new ApiError("network", 0, "The server could not be reached.");
    });
    inflight[url] = promise;
    var done = function () { delete inflight[url]; };
    promise.then(done, done);
    return promise;
  }

  function describe(error) {
    if (!error || error.kind === "network") { return "The server could not be reached."; }
    if (error.kind === "http" && error.status === 404) { return "This information is not available (the computer may have been archived)."; }
    if (error.kind === "http") { return "The server could not answer (" + error.status + ")."; }
    return "The answer could not be read.";
  }

  function showError(panel, message, retry) {
    if (!panel) { return; }
    clear(panel);
    addNode(panel, el("span", "", message + " "));
    if (retry) {
      var button = addNode(panel, el("button", "btn btn-small btn-quiet", "Try again"));
      button.setAttribute("type", "button");
      button.addEventListener("click", retry);
    }
    panel.hidden = false;
  }

  function hideError(panel) { if (panel) { panel.hidden = true; clear(panel); } }

  // ---- the trend chart (native SVG) -----------------------------------------------------------------------------------------------
  function niceMax(n) {
    if (n <= 1) { return 1; }
    if (n <= 5) { return n; }
    var steps = [2, 3, 5, 10, 25, 50, 100, 250, 500, 1000, 2500];          // four equal grid steps of a whole number each: 8, 12, 20, 40, 100, ...
    for (var i = 0; i < steps.length; i += 1) { if (n <= 4 * steps[i]) { return 4 * steps[i]; } }
    return Math.ceil(n / 4000) * 4000;
  }

  function dayLabel(day, today) {
    if (day.before_first_data) { return day.date + ": before monitoring began, no data."; }
    var text = shortDate(day.date) + (today ? " (today, so far)" : "") + ": " + plural(day.logical_visits, "website visit", "website visits") + ", of which " +
      plural(day.malicious, "dangerous visit", "dangerous visits") + ", " + plural(day.suspicious, "needs-review visit", "needs-review visits") + ", " +
      plural(day.unknown, "visit that could not be checked", "visits that could not be checked") + " and " + day.no_threat_detected + " with no threat detected.";
    if (!day.records_present) { text += " No record from any sensor that day, so nothing can be said about it."; }
    else if (day.logical_visits === 0) { text += " The sensors reported, but no website was opened."; }
    return text;
  }

  var lastChart = null;       // what the chart was last drawn from, so it can be redrawn when the window changes size

  function isNarrow(host) { return !!(host && host.clientWidth && host.clientWidth < 520); }

  var MIN_RISK_HEIGHT = 3;    // a day with one dangerous visit among hundreds stays visible; the exact numbers are in the tooltip and the table

  function drawChart(host, tooltip, daily, includesPartialDay, titleText) {
    clear(host);
    var narrow = isNarrow(host);
    lastChart = { host: host, tooltip: tooltip, daily: daily, includesPartialDay: includesPartialDay, titleText: titleText, narrow: narrow };
    var W = narrow ? 360 : 720, H = narrow ? 250 : 260, L = narrow ? 34 : 44, R = 6, T = 12, B = 34;
    var plotW = W - L - R, plotH = H - T - B;
    var n = daily.length;
    var peak = 0, total = { malicious: 0, suspicious: 0, unknown: 0, safe: 0 };
    daily.forEach(function (d) {
      if (!d.before_first_data) {
        peak = Math.max(peak, d.logical_visits);
        total.malicious += d.malicious; total.suspicious += d.suspicious; total.unknown += d.unknown; total.safe += d.no_threat_detected;
      }
    });
    var maxY = niceMax(peak);
    var step = plotW / n;
    var barW = Math.max(4, Math.min(48, step * 0.62));
    var svg = svgEl("svg", { "class": "chart-svg", viewBox: "0 0 " + W + " " + H, role: "group", "aria-labelledby": "trend-svg-title trend-svg-desc", focusable: "false" });
    addNode(svg, svgEl("title", { id: "trend-svg-title" })).textContent = titleText;
    addNode(svg, svgEl("desc", { id: "trend-svg-desc" })).textContent = "Stacked columns, one per day, showing all website visits: dangerous at the bottom, then needs review, then could not be checked, then no threat detected. " +
      "Total in the period: " + plural(total.malicious + total.suspicious + total.unknown + total.safe, "website visit", "website visits") + ", " + total.malicious + " dangerous, " + total.suspicious +
      " needs review, " + total.unknown + " could not be checked, " + total.safe + " with no threat detected. Very small dangerous or needs-review segments are drawn slightly taller so that they stay visible. " +
      "Use the left and right arrow keys to move between days, or switch to the table.";
    var ticks = peak <= 5 ? Math.max(1, maxY) : 4;
    for (var i = 0; i <= ticks; i += 1) {
      var value = Math.round(maxY * i / ticks);
      var y = T + plotH - (plotH * i / ticks);
      addNode(svg, svgEl("line", { x1: L, x2: W - R, y1: y, y2: y, "class": i === 0 ? "axis" : "grid" }));
      addNode(svg, svgEl("text", { x: L - 6, y: y + 4, "text-anchor": "end", "class": "tick" })).textContent = String(value);
    }
    var labelEvery = n <= 7 ? 1 : (n <= 14 ? (narrow ? 3 : 2) : (narrow ? 7 : 5));
    var groups = [];
    daily.forEach(function (d, index) {
      var cx = L + step * index + step / 2;
      var today = isToday2(index, n, includesPartialDay);
      var g = addNode(svg, svgEl("g", { "class": "day" + (today ? " day-partial" : ""), tabindex: index === 0 ? "0" : "-1", role: "img", "aria-label": dayLabel(d, today), "data-date": d.date }));
      addNode(g, svgEl("rect", { x: cx - step / 2, y: T, width: step, height: plotH, "class": "hit" }));
      if (d.before_first_data) {
        addNode(g, svgEl("rect", { x: cx - barW / 2, y: T, width: barW, height: plotH, "class": "bar-nodata", style: "fill:url(#hatch-nodata)" }));
      } else if (d.logical_visits === 0) {
        // a real zero (records exist) is a solid mark on the baseline; a day without any record is a dashed one: they are not the same statement
        addNode(g, svgEl("line", { x1: cx - barW / 2, x2: cx + barW / 2, y1: T + plotH - 1, y2: T + plotH - 1, "class": d.records_present ? "zero-mark" : "norecords-mark" }));
      } else {
        var bottom = T + plotH;
        [["malicious", d.malicious, "bar-malicious"], ["suspicious", d.suspicious, "bar-suspicious"], ["unknown", d.unknown, "bar-unknown"], ["safe", d.no_threat_detected, "bar-safe"]].forEach(function (seg) {
          if (seg[1] <= 0) { return; }
          var h = plotH * seg[1] / maxY;
          if (seg[0] === "malicious" || seg[0] === "suspicious") { h = Math.max(h, MIN_RISK_HEIGHT); }
          h = Math.min(h, bottom - T);
          bottom -= h;
          var attrs = { x: cx - barW / 2, y: bottom, width: barW, height: h, "class": seg[2] + (today ? " partial" : "") };
          if (seg[0] === "unknown") { attrs.style = "fill:url(#dots-unknown)"; }
          addNode(g, svgEl("rect", attrs));
        });
        if (!d.records_present) { addNode(g, svgEl("line", { x1: cx - barW / 2, x2: cx + barW / 2, y1: T + plotH - 1, y2: T + plotH - 1, "class": "norecords-mark" })); }
      }
      if ((index % labelEvery === 0 && n - 1 - index >= Math.ceil(labelEvery / 2)) || index === n - 1) {         // the last label ("Today" or the final date) never collides with its neighbour
        addNode(svg, svgEl("text", { x: cx, y: H - 12, "text-anchor": "middle", "class": "tick" })).textContent = today ? "Today" : shortDate(d.date);
      }
      groups.push(g);
      function show() { showTooltip(host, tooltip, d, cx / W, today); }
      g.addEventListener("mouseenter", show);
      g.addEventListener("focus", show);
      g.addEventListener("mouseleave", function () { tooltip.hidden = true; });
      g.addEventListener("blur", function () { tooltip.hidden = true; });
      g.addEventListener("keydown", function (e) {
        var key = e.key, target = null;
        if (key === "ArrowRight") { target = groups[Math.min(n - 1, index + 1)]; }
        else if (key === "ArrowLeft") { target = groups[Math.max(0, index - 1)]; }
        else if (key === "Home") { target = groups[0]; }
        else if (key === "End") { target = groups[n - 1]; }
        else if (key === "Escape") { tooltip.hidden = true; }
        if (target && target !== g) {
          if (e.preventDefault) { e.preventDefault(); }
          groups.forEach(function (other) { other.setAttribute("tabindex", other === target ? "0" : "-1"); });
          target.focus();
        }
      });
    });
    addNode(host, svg);
    host.setAttribute("aria-busy", "false");
  }

  function isToday2(index, n, partial) { return partial && index === n - 1; }

  function showTooltip(host, tooltip, d, fraction, today) {
    clear(tooltip);
    addNode(tooltip, el("strong", "", shortDate(d.date) + (today ? " (today, so far)" : "")));
    if (d.before_first_data) {
      addNode(tooltip, el("div", "", "Before monitoring began: no data."));
    } else {
      addNode(tooltip, el("div", "", "Website visits: " + d.logical_visits));
      addNode(tooltip, el("div", "", "Dangerous: " + d.malicious));
      addNode(tooltip, el("div", "", "Needs review: " + d.suspicious));
      addNode(tooltip, el("div", "", "Could not be checked: " + d.unknown));
      addNode(tooltip, el("div", "", "No threat detected: " + d.no_threat_detected));
      if (!d.records_present) { addNode(tooltip, el("div", "muted", "No sensor record this day.")); }
      else if (d.logical_visits === 0) { addNode(tooltip, el("div", "muted", "Sensors reported; no website opened.")); }
    }
    tooltip.style.left = Math.max(2, Math.min(98, Math.round(fraction * 100))) + "%";
    tooltip.hidden = false;
  }

  function dailyTable(wrap, daily) {
    clear(wrap);
    var table = addNode(wrap, el("table", "table"));
    addNode(table, el("caption", "visually-hidden", "Website visits per day by verdict"));
    var head = addNode(addNode(table, el("thead")), el("tr"));
    ["Date", "All visits", "Dangerous", "Needs review", "Could not be checked", "No threat detected", "Note"].forEach(function (h) {
      var th = addNode(head, el("th", "", h));
      th.setAttribute("scope", "col");
    });
    var body = addNode(table, el("tbody"));
    daily.forEach(function (d) {
      var tr = addNode(body, el("tr"));
      addNode(tr, el("td", "", d.date));
      if (d.before_first_data) {
        for (var i = 0; i < 5; i += 1) { addNode(tr, el("td", "num", "–")); }
        addNode(tr, el("td", "muted", "Before monitoring began"));
      } else {
        addNode(tr, el("td", "num", d.logical_visits));
        addNode(tr, el("td", "num", d.malicious));
        addNode(tr, el("td", "num", d.suspicious));
        addNode(tr, el("td", "num", d.unknown));
        addNode(tr, el("td", "num", d.no_threat_detected));
        addNode(tr, el("td", "muted", d.records_present ? (d.logical_visits === 0 ? "Sensors reported; no website opened" : "") : "No sensor record this day"));
      }
    });
  }

  function trendView(ids, trendData, noteExtra) {
    var host = byId(ids.chart), tooltip = byId(ids.tooltip), tableWrap = byId(ids.table), note = byId(ids.note);
    var daily = trendData.daily, dates = trendData.dates;
    var allBefore = daily.length > 0 && daily.every(function (d) { return d.before_first_data; });
    var unknown = 0;
    daily.forEach(function (d) { if (!d.before_first_data) { unknown += d.unknown; } });
    if (!daily.length || allBefore) {
      clear(host);
      addNode(host, el("p", "empty", "No monitoring data exists for this period yet, so no trend can be shown."));
      host.setAttribute("aria-busy", "false");
      clear(tableWrap);
    } else {
      drawChart(host, tooltip, daily, !!(dates && dates.includes_partial_day), "Website visits per day, by result, " + shortDate(daily[0].date) + " to " + shortDate(daily[daily.length - 1].date));
      dailyTable(tableWrap, daily);
    }
    var parts = [];
    if (dates && dates.includes_partial_day) { parts.push("Today is incomplete: it shows the day so far."); }
    if (daily.some(function (d) { return d.before_first_data; })) { parts.push("Hatched days are before monitoring began: they are not zeros."); }
    if (daily.some(function (d) { return !d.before_first_data && !d.records_present; })) { parts.push("Dashed marks are days with no sensor record at all."); }
    if (unknown > 0) { parts.push(plural(unknown, "visit", "visits") + " in this period could not be checked and " + (unknown === 1 ? "is" : "are") + " not counted as safe."); }
    if (noteExtra) { parts.push(noteExtra); }
    setText(note, parts.join(" "));
  }

  function redrawIfResized() {
    if (lastChart && isNarrow(lastChart.host) !== lastChart.narrow && lastChart.host.firstChild) {
      drawChart(lastChart.host, lastChart.tooltip, lastChart.daily, lastChart.includesPartialDay, lastChart.titleText);
    }
  }

  if (typeof window !== "undefined" && window.addEventListener) {
    var resizeTimer = null;
    window.addEventListener("resize", function () {
      if (resizeTimer) { clearTimeout(resizeTimer); }
      resizeTimer = setTimeout(redrawIfResized, 150);
    });
  }

  function wireTrendToggle() {
    var button = byId("trend-toggle"), tableWrap = byId("trend-table-wrap"), chart = byId("trend-chart"), legend = byId("trend-legend");
    if (!button || !tableWrap) { return; }
    button.addEventListener("click", function () {
      var showTable = button.getAttribute("aria-pressed") !== "true";
      button.setAttribute("aria-pressed", showTable ? "true" : "false");
      button.textContent = showTable ? "Show as chart" : "Show as table";
      tableWrap.hidden = !showTable;
      chart.hidden = showTable;
      if (legend) { legend.hidden = showTable; }
    });
  }

  // ---- period selector ------------------------------------------------------------------------------------------------------------
  function wirePeriod(onChange) {
    var group = byId("period-select");
    if (!group) { return; }
    var radios = group.querySelectorAll('input[name="period"]');
    for (var i = 0; i < radios.length; i += 1) {
      radios[i].addEventListener("change", function (e) {
        var value = parseInt(e.target.value, 10);
        if (value === 7 || value === 14 || value === 30) { onChange(value); }
      });
    }
  }

  function rememberPeriod(days) {
    try { if (window.history && window.history.replaceState) { window.history.replaceState(null, "", "?days=" + days); } } catch (e) { /* the address bar is a convenience */ }
  }

  function announce(text) { setText(byId("exec-announce"), text); }

  function everyMinute(run) {
    function tick() { if (document.visibilityState === "visible") { run(); } }
    setInterval(tick, REFRESH_MS);
  }

  // ---- the dashboard --------------------------------------------------------------------------------------------------------------
  function startDashboard(root) {
    var urls = { summary: root.getAttribute("data-summary-url"), trends: root.getAttribute("data-trends-url"), computers: root.getAttribute("data-computers-url"),
                 detail: root.getAttribute("data-detail-base") };
    var state = { days: parseInt(root.getAttribute("data-days"), 10) || 7, seq: 0, entries: [], total: 0, showAll: false, visible: ATTENTION_LIMIT, summary: null };

    function url(base, extra) { return base + "?days=" + state.days + (extra || ""); }

    function refresh(background) {
      state.seq += 1;
      var mine = state.seq;                  // an answer that arrives after a newer request was made is ignored (stale), so a quick 7 -> 14 -> 30 never shows old numbers
      var options = { background: !!background };
      byId("kpi-grid").setAttribute("aria-busy", "true");
      var retry = function () { refresh(false); };

      load(url(urls.summary), options).then(function (body) {
        if (mine !== state.seq) { return; }
        state.summary = body;
        hideError(byId("kpi-error"));
        renderKpis(body);
        renderNotice(body);
        if (state.entries.length) { renderKpiExtras(); }
      }, function (e) {
        if (mine !== state.seq || e.kind === "auth") { return; }
        showError(byId("kpi-error"), "The summary figures could not be loaded. " + describe(e), retry);
        byId("kpi-grid").setAttribute("aria-busy", "false");
      });

      load(url(urls.trends), options).then(function (body) {
        if (mine !== state.seq) { return; }
        hideError(byId("trend-error"));
        trendView({ chart: "trend-chart", tooltip: "trend-tooltip", table: "trend-table-wrap", note: "trend-note" }, body.data.current, null);
      }, function (e) {
        if (mine !== state.seq || e.kind === "auth") { return; }
        clear(byId("trend-chart"));
        byId("trend-chart").setAttribute("aria-busy", "false");
        showError(byId("trend-error"), "The trend could not be loaded. " + describe(e), retry);
      });

      load(url(urls.computers, "&limit=50"), options).then(function (body) {
        if (mine !== state.seq) { return; }
        state.entries = body.data.computers;
        state.total = body.data.total;
        state.generatedAt = body.meta.generated_at;
        state.visible = ATTENTION_LIMIT;
        hideError(byId("risk-error"));
        renderRisk();
        renderKpiExtras();
      }, function (e) {
        if (mine !== state.seq || e.kind === "auth") { return; }
        byId("risk-table").hidden = true;
        byId("risk-empty").hidden = true;
        showError(byId("risk-error"), "The computer ranking could not be loaded. " + describe(e), retry);
      });
    }

    // ---- the six cards
    function card(name) { return root.querySelector('[data-kpi="' + name + '"]'); }

    function setCard(name, value, sub, compare, tone) {
      var c = card(name);
      if (!c) { return; }
      setText(c.querySelector(".kpi-value"), value);
      setText(c.querySelector(".kpi-sub"), sub || "");
      var cmp = c.querySelector(".kpi-compare");
      setText(cmp, compare ? compare.text : "");
      cmp.className = "kpi-compare" + (compare && compare.tone ? " cmp-" + compare.tone : "");
      c.className = "kpi" + (tone ? " kpi-" + tone : "");
    }

    function compareText(summary, key, label) {
      var cmp = summary.comparison[key];
      var prev = summary.completeness.previous;
      if (!cmp) { return null; }
      if (!cmp.reliable) {
        var why = prev.status === "NO_DATA" ? "no data for the previous period" : (prev.limited_by_retention ? "older data has been deleted" : "the previous period is incomplete");
        return { text: "Comparison unavailable: " + why + ".", tone: "muted" };
      }
      if (cmp.delta === 0) { return { text: "No change from the previous " + summary.period.days + " days.", tone: "muted" }; }
      var more = cmp.delta > 0;
      var amount = Math.abs(cmp.delta);
      var pct = cmp.percent === null ? "" : " (" + Math.abs(cmp.percent) + "%)";
      return { text: (more ? "▲ " : "▼ ") + amount + (more ? " more" : " fewer") + pct + " than the previous " + summary.period.days + " days.", tone: more ? "worse" : "better" };
    }

    function renderKpis(body) {
      var d = body.data, cur = d.current, comp = d.completeness.current, comps = d.computers;
      var noData = comp.status === "NO_DATA";
      var days = d.period.days;
      var reporting = comps.total - comps.by_coverage.NOT_REPORTING;
      var partial = comp.status === "PARTIAL";
      var incomplete = partial || comps.insufficient_data > 0 || comps.by_coverage.NOT_REPORTING > 0 || comps.by_coverage.PARTIALLY_MONITORED > 0;
      var coverageNote = partial ? "Monitoring data covers " + comp.days_after_first_data + " of " + days + " days." : "";

      setCard("computers", String(comps.total), comps.total === 0 ? "No computers are being monitored yet." : "", null, null);
      setCard("reporting", comps.total === 0 ? "–" : String(reporting), comps.total === 0 ? "" : "of " + comps.total + " computers", null, comps.total > 0 && reporting < comps.total ? "warn" : null);

      function metric(name, value, cmpKey, label, tone) {
        if (noData) { setCard(name, "–", "No monitoring data for this period.", null, "muted"); return; }
        var sub;
        if (value === 0) { sub = incomplete ? "None seen in the monitored activity, but monitoring is incomplete." : "No threats detected in monitored activity."; }
        else { sub = label; }
        if (coverageNote) { sub += " " + coverageNote; }
        setCard(name, String(value), sub, compareText(d, cmpKey), value > 0 ? tone : (incomplete ? "muted" : null));
      }
      metric("exposed", cur.affected_computers, "affected_computers", "of " + comps.total + " computers.", "bad");
      metric("malicious", cur.malicious_visits, "malicious_visits", "of " + plural(cur.logical_visits, "website visit", "website visits") + ".", "bad");
      metric("suspicious", cur.suspicious_visits, "suspicious_visits", "of " + plural(cur.logical_visits, "website visit", "website visits") + ".", "warn");
      if (cur.unknown_visits > 0 && !noData) {
        var s = card("suspicious").querySelector(".kpi-sub");
        setText(s, s.textContent + " " + plural(cur.unknown_visits, "visit", "visits") + " could not be checked and " + (cur.unknown_visits === 1 ? "is" : "are") + " not counted as safe.");
      }
      var attention = comps.by_coverage.NOT_REPORTING + comps.by_coverage.PARTIALLY_MONITORED;
      var history = comps.by_coverage.INSUFFICIENT_HISTORICAL_COVERAGE;
      var sub = attention === 0 ? (comps.total === 0 ? "" : "No monitoring problems found.") : plural(comps.by_coverage.NOT_REPORTING, "computer is", "computers are") + " not reporting, " + comps.by_coverage.PARTIALLY_MONITORED + " partly monitored.";
      if (history > 0) { sub += " " + plural(history, "computer has", "computers have") + " too little history to assess."; }
      setCard("coverage", comps.total === 0 ? "–" : String(attention), sub, null, attention > 0 ? "warn" : null);
      byId("kpi-grid").setAttribute("aria-busy", "false");
      announce("Showing the last " + days + " days.");
    }

    function renderKpiExtras() {
      var c = card("computers");
      if (c && state.summary && state.summary.data.computers.total > 0) {
        var by = state.summary.data.computers.by_identity_level || {};
        var approved = by.ADMIN_APPROVED || 0, selfEnrolled = by.SELF_ENROLLED || 0;
        var unconfirmed = state.summary.data.computers.total - approved - selfEnrolled;
        var parts = [];
        if (unconfirmed > 0) { parts.push(plural(unconfirmed, "computer has", "computers have") + " an unconfirmed identity"); }
        if (selfEnrolled > 0) { parts.push(plural(selfEnrolled, "computer is", "computers are") + " self-enrolled (not administrator-approved)"); }
        if (approved > 0) { parts.push(plural(approved, "computer is", "computers are") + " administrator-approved"); }
        else { parts.push("none is administrator-approved"); }
        setText(c.querySelector(".kpi-sub"), parts.join("; ") + ".");
      }
    }

    function renderNotice(body) {
      var notice = byId("exec-notice"), d = body.data;
      var cur = d.completeness.current, notes = [];
      if (cur.status === "NO_DATA") { notes.push("No monitoring data exists for this period, so no figure below is a statement about safety."); }
      else if (cur.status === "PARTIAL") { notes.push("Monitoring data starts on " + shortDate(cur.first_data_date) + ": this period is only partly covered."); }
      if (d.completeness.current.limited_by_retention) { notes.push("Part of this period is older than the retention limit; those visits have been deleted."); }
      if (notes.length === 0) { notice.hidden = true; clear(notice); return; }
      setText(notice, notes.join(" "));
      notice.hidden = false;
    }

    // ---- the ranking
    function needsAttention(e) {
      var risk = e.risk, cov = e.coverage.status;
      return (risk.status === "SCORED" && risk.score > 0) || risk.status === "INSUFFICIENT_DATA" ||
        cov === "NOT_REPORTING" || cov === "PARTIALLY_MONITORED" || cov === "INSUFFICIENT_HISTORICAL_COVERAGE";
    }

    function exposureCell(e) {
      var td = el("td", "col-exposure");
      var risk = e.risk;
      if (risk.status !== "SCORED") {
        addNode(td, pill("Insufficient data", "dashed"));
        td.title = "Not enough monitoring data to assess this computer. This is not a statement that it is safe.";
        return td;
      }
      var cls = CATEGORY_CLASS[risk.category] || "none";
      var meter = addNode(td, el("div", "meter meter-" + cls));
      meter.setAttribute("role", "img");
      meter.setAttribute("aria-label", "Web exposure score " + risk.score + " out of 100, " + String(risk.category_label));
      var bar = addNode(meter, el("span", "meter-bar"));
      bar.style.width = Math.max(0, Math.min(100, risk.score)) + "%";
      var line = addNode(td, el("div", "score-line"));
      addNode(line, el("strong", "score", risk.score));
      addNode(line, el("span", "muted", " / 100 · " + String(risk.category_label)));
      if (risk.data_quality && risk.data_quality.score_is_lower_bound) {
        addNode(td, el("div", "muted small", "Some visits could not be checked, so the real exposure may be higher."));
      }
      return td;
    }

    function visitsCell(e) {
      var td = el("td", "col-visits");
      var scored = e.risk.status === "SCORED";
      var lines = 0;
      if (scored || e.malicious_visits > 0) { addNode(td, el("div", e.malicious_visits > 0 ? "visits-bad" : "visits-none", e.malicious_visits + " dangerous")); lines += 1; }
      if (scored || e.suspicious_visits > 0) { addNode(td, el("div", e.suspicious_visits > 0 ? "visits-warn" : "visits-none", e.suspicious_visits + " needs review")); lines += 1; }
      if (lines === 0) { td.textContent = "–"; td.title = "Not assessed: there is not enough monitoring data."; }
      return td;
    }

    function rowFor(e) {
      var tr = el("tr");
      var name = addNode(tr, el("td", "col-name"));
      var link = addNode(name, el("a", "comp-link", e.display_name));
      link.setAttribute("href", url(urls.detail + Number(e.device_id)));
      var badges = addNode(name, el("div", "name-badges"));
      var who = identityOf(e.coverage);
      var identityBadge = addNode(badges, pill(who.short, who.tone));
      if (who.explanation) { identityBadge.title = who.explanation; }
      if (e.user && e.user.verified && e.user.name) { addNode(name, el("div", "muted small", "User: " + e.user.name)); }
      var last;
      if (e.last_risky_exposure) { last = "Last risky visit " + ago(e.last_risky_exposure, state.generatedAt) + "."; }
      else { last = e.risk.status === "SCORED" ? "No risky visit observed." : "Not enough data to assess."; }
      var lastNode = addNode(name, el("div", "muted small last-risky", last));
      if (e.last_risky_exposure) { lastNode.title = dateTime(e.last_risky_exposure); }
      var why = (e.risk.reasons && e.risk.reasons[0]) ? e.risk.reasons[0] : e.explanation;
      var whyNode = addNode(name, el("div", "why small", why));
      whyNode.title = e.explanation || "";
      addNode(tr, exposureCell(e));
      addNode(tr, visitsCell(e));
      var cov = COVERAGE[e.coverage.status] || [String(e.coverage.status), "muted"];
      var covTd = addNode(tr, el("td", "col-cov"));
      addNode(covTd, pill(cov[0], cov[1]));
      if (e.coverage.reasons && e.coverage.reasons.length) { covTd.title = e.coverage.reasons.join(" "); }
      return tr;
    }

    function renderRisk() {
      var table = byId("risk-table"), body = byId("risk-body"), empty = byId("risk-empty"), more = byId("risk-more");
      clear(body);
      var all = state.entries, attention = all.filter(needsAttention);
      var list = state.showAll ? all : attention;
      if (state.total === 0) {
        table.hidden = true; more.hidden = true; empty.hidden = false;
        setText(empty, "No computers are being monitored yet.");
        return;
      }
      if (list.length === 0) {
        table.hidden = true;
        empty.hidden = false;
        setText(empty, "No computer needs attention in the monitored activity. This does not cover websites that were not monitored.");
      } else {
        table.hidden = false;
        empty.hidden = true;
        list.slice(0, state.visible).forEach(function (e) { addNode(body, rowFor(e)); });
      }
      // one button: show more rows, or switch between "needing attention" and "all computers"
      var remaining = list.length - state.visible;
      if (remaining > 0) {
        more.textContent = "Show " + Math.min(ROW_CHUNK, remaining) + " more";
        more.hidden = false;
        more.setAttribute("data-action", "more");
      } else if (!state.showAll && all.length > attention.length) {
        more.textContent = "Show all " + state.total + " computers";
        more.hidden = false;
        more.setAttribute("data-action", "all");
      } else if (state.showAll && attention.length < all.length) {
        more.textContent = "Show only computers needing attention";
        more.hidden = false;
        more.setAttribute("data-action", "attention");
      } else {
        more.hidden = true;
      }
      if (state.total > all.length) {
        var note = el("p", "muted small", "Showing the top " + all.length + " of " + state.total + " computers. The Computers page lists them all.");
        note.setAttribute("id", "risk-limit-note");
        var oldNote = byId("risk-limit-note");
        if (!oldNote) { more.parentNode.insertBefore(note, more); }
      }
    }

    byId("risk-more").addEventListener("click", function () {
      var action = byId("risk-more").getAttribute("data-action");
      if (action === "more") { state.visible += ROW_CHUNK; }
      else if (action === "all") { state.showAll = true; state.visible = ATTENTION_LIMIT; }
      else { state.showAll = false; state.visible = ATTENTION_LIMIT; }
      renderRisk();
    });

    wirePeriod(function (days) {
      if (days === state.days) { return; }
      state.days = days;
      state.showAll = false;
      rememberPeriod(days);
      announce("Loading the last " + days + " days.");
      refresh(false);
    });
    wireTrendToggle();
    everyMinute(function () { refresh(true); });
    refresh(false);
    return { refresh: refresh, state: state };
  }

  // ---- the computer detail page ---------------------------------------------------------------------------------------------------
  function startDetail(root) {
    var urls = { detail: root.getAttribute("data-detail-url"), activity: root.getAttribute("data-activity-url"), browsing: root.getAttribute("data-browsing-url"),
                 visit: root.getAttribute("data-visit-base") };
    var state = { days: parseInt(root.getAttribute("data-days"), 10) || 7, seq: 0 };

    function url(base, extra) { return base + "?days=" + state.days + (extra || ""); }

    function verdictPill(v) {
      var m = VERDICT[v] || [String(v), "muted"];
      return pill(m[0], m[1]);
    }

    function evidenceLinks(td, domain, ids, visitBase) {
      var a = addNode(td, el("a", "link", "Find in browsing"));
      a.setAttribute("href", urls.browsing + "?q=" + encodeURIComponent(domain));
      (ids || []).slice(0, 3).forEach(function (id) {
        addNode(td, document.createTextNode(" · "));
        var v = addNode(td, el("a", "link", "Visit #" + Number(id)));
        v.setAttribute("href", urls.visit + Number(id));
      });
    }

    function fact(dl, term, value) {
      addNode(dl, el("dt", "", term));
      addNode(dl, el("dd", "", value));
    }

    function renderRisk(c, generatedAt) {
      var risk = c.risk, head = byId("cd-risk-head"), reasons = byId("cd-risk-reasons");
      clear(head); clear(reasons);
      if (risk.status === "SCORED") {
        var cls = CATEGORY_CLASS[risk.category] || "none";
        var big = addNode(head, el("div", "score-big"));
        addNode(big, el("span", "score-number", risk.score));
        addNode(big, el("span", "score-of", "/ 100"));
        addNode(head, el("div", "score-cat cat-" + cls, risk.category_label));
        var meter = addNode(head, el("div", "meter meter-" + cls));
        meter.setAttribute("role", "img");
        meter.setAttribute("aria-label", "Web exposure score " + risk.score + " out of 100");
        addNode(meter, el("span", "meter-bar")).style.width = Math.max(0, Math.min(100, risk.score)) + "%";
      } else {
        addNode(head, pill("Insufficient data", "dashed"));
        addNode(head, el("p", "muted", "There is not enough monitoring data to assess this computer. That is not a statement that it is safe."));
      }
      (risk.reasons || []).forEach(function (r) { if (r !== risk.disclaimer) { addNode(reasons, el("li", "", r)); } });
      setText(byId("cd-risk-disclaimer"), risk.status === "SCORED" ? (risk.disclaimer || "") : "");        // a note about "the score" only where there is one
      byId("cd-risk").setAttribute("aria-busy", "false");
    }

    function renderCoverage(c) {
      var cov = c.coverage, head = byId("cd-cov-head"), reasons = byId("cd-cov-reasons"), facts = byId("cd-cov-facts");
      clear(head); clear(reasons); clear(facts);
      var m = COVERAGE[cov.status] || [String(cov.status), "muted"];
      addNode(head, pill(m[0], m[1]));
      var who = identityOf(cov);
      var identityBadge = addNode(head, pill(who.short, who.tone));
      if (who.explanation) { identityBadge.title = who.explanation; }
      (cov.reasons || []).forEach(function (r) { addNode(reasons, el("li", "", r)); });
      fact(facts, "Browser extension", SENSOR[cov.sensors.extension] || cov.sensors.extension);
      fact(facts, "Windows agent", SENSOR[cov.sensors.agent] || cov.sensors.agent);
      fact(facts, "Website visibility", cov.sensors.website_visibility_label || "");
      fact(facts, "First seen", cov.history.first_seen_date ? shortDate(cov.history.first_seen_date) : "unknown");
      fact(facts, "Known for", cov.history.days_known_in_period + " of " + cov.history.period_days + " days in this period");
      fact(facts, "Days with records", String(cov.history.days_with_records));
      byId("cd-coverage").setAttribute("aria-busy", "false");
    }

    function renderDomains(c) {
      var table = byId("cd-domains-table"), body = byId("cd-domains-body"), empty = byId("cd-domains-empty");
      clear(body);
      var ev = c.risk.evidence || [];
      if (ev.length === 0) {
        table.hidden = true; empty.hidden = false;
        setText(empty, c.risk.status === "SCORED" ? "No dangerous or suspicious websites were observed in this period. This does not prove the computer is safe." :
          "Nothing can be said about this period: there is not enough monitoring data.");
        return;
      }
      empty.hidden = true; table.hidden = false;
      ev.forEach(function (e) {
        var tr = addNode(body, el("tr"));
        addNode(tr, el("td", "domain", e.domain));
        addNode(addNode(tr, el("td")), verdictPill(e.verdict));
        addNode(tr, el("td", "num", e.logical_visits));
        addNode(tr, el("td", "", dateTime(e.first_visit)));
        addNode(tr, el("td", "", dateTime(e.last_visit)));
        evidenceLinks(addNode(tr, el("td")), e.domain, e.sample_visit_ids);
      });
      if (c.risk.evidence_domains_total > ev.length) {
        var more = addNode(addNode(body, el("tr")), el("td", "muted", "Showing " + ev.length + " of " + c.risk.evidence_domains_total + " risky websites."));
        more.setAttribute("colspan", "6");
      }
    }

    function renderVisits(a) {
      var table = byId("cd-visits-table"), body = byId("cd-visits-body"), empty = byId("cd-visits-empty");
      clear(body);
      var visits = a.recent_visits || [];
      if (visits.length === 0) { table.hidden = true; empty.hidden = false; setText(empty, "No website visits were recorded for this computer in this period."); return; }
      empty.hidden = true; table.hidden = false;
      visits.forEach(function (v) {
        var tr = addNode(body, el("tr"));
        addNode(tr, el("td", "nowrap", dateTime(v.visited_at)));
        addNode(tr, el("td", "domain", v.domain));
        var shown = ALL_VERDICTS[v.verdict] || ALL_VERDICTS.UNKNOWN;
        addNode(addNode(tr, el("td")), pill(shown[0], shown[1]));
        addNode(tr, el("td", "", v.browser || "–"));
        addNode(tr, el("td", "", SOURCE[v.source] || String(v.source)));
        var link = addNode(addNode(tr, el("td")), el("a", "link", "View analysis"));
        link.setAttribute("href", urls.visit + Number(v.visit_id));
      });
    }

    function renderAlerts(a) {
      var list = byId("cd-alerts-list"), empty = byId("cd-alerts-empty");
      clear(list);
      var alerts = a.open_alerts || [];
      if (alerts.length === 0) { list.hidden = true; empty.hidden = false; setText(empty, "This computer has no open alerts."); return; }
      empty.hidden = true; list.hidden = false;
      alerts.forEach(function (al) {
        var li = addNode(list, el("li", "attention-item level-" + (al.severity === "HIGH" ? "danger" : "warning")));
        var link = addNode(li, el("a", "", (al.severity === "HIGH" ? "Dangerous website: " : "Needs review: ") + al.domain + " (" + plural(al.exposures, "visit", "visits") + (al.escalated ? ", raised to dangerous" : "") + ")"));
        link.setAttribute("href", appUrl("/alerts"));
      });
    }

    function refresh(background) {
      state.seq += 1;
      var mine = state.seq;
      var options = { background: !!background };
      var failure = byId("cd-error");
      var retry = function () { refresh(false); };
      var stale = function (e) { return mine !== state.seq || e.kind === "auth"; };

      load(url(urls.detail), options).then(function (body) {
        if (mine !== state.seq) { return; }
        var c = body.data.computer;
        hideError(failure);
        setText(byId("cd-user"), c.user && c.user.name ? "User label: " + c.user.name + " (reported by the sensor, not verified)" : "No user label reported");
        renderRisk(c, body.meta.generated_at);
        renderCoverage(c);
        renderDomains(c);
        announce("Showing the last " + state.days + " days.");
      }, function (e) {
        if (stale(e)) { return; }
        showError(failure, describe(e), retry);
      });

      load(url(urls.activity), options).then(function (body) {
        if (mine !== state.seq) { return; }
        var a = body.data;
        trendView({ chart: "trend-chart", tooltip: "trend-tooltip", table: "trend-table-wrap", note: "trend-note" }, { daily: a.daily, dates: { includes_partial_day: true } }, null);
        renderVisits(a);
        renderAlerts(a);
      }, function (e) {
        if (stale(e)) { return; }
        clear(byId("trend-chart"));
        showError(failure, "The activity of this computer could not be loaded. " + describe(e), retry);
      });
    }

    wirePeriod(function (days) {
      if (days === state.days) { return; }
      state.days = days;
      rememberPeriod(days);
      announce("Loading the last " + days + " days.");
      refresh(false);
    });
    wireTrendToggle();
    everyMinute(function () { refresh(true); });
    refresh(false);
    return { refresh: refresh, state: state };
  }

  // ---- start ----------------------------------------------------------------------------------------------------------------------
  var api = {};
  var dash = byId("exec-root");
  var detail = byId("cd-root");
  if (dash) { api.dashboard = startDashboard(dash); }
  if (detail) { api.detail = startDetail(detail); }
  if (typeof window !== "undefined") { window.WebsiteMonitorExecutive = api; }
})();
