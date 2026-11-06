// slothweb: the APRS panel (2026-11-05, web_aprs.h, web_aprshist.h,
// docs/wiki/aprs.md). window.SlothAprs, one hook app.js calls when the
// view shows:
//   SlothAprs.show()   loads /api/aprs into the aprs-* containers and
//                      keeps it current while the view is visible
// Same-origin relative paths only, every value shown with textContent
// (an APRS comment is free text from anyone with a transmitter), no map
// tiles and nothing fetched from anywhere else: the position plot is
// drawn from the stations' own coordinates on a plain canvas. Dire
// Wolf's receiver is a passive radio, so the view is Monitor's and
// Hybrid's, as ADS-B is; under Local the route answers out_of_scope and
// app.js shows the scope note. The station table is app.js's DataTable
// (window.SlothTables.make), as every table on the page is.
(function () {
  "use strict";
  var POLL_MS = 5000, LEVEL_SPAN = 100;
  var timer = 0, gen = 0, last = null, sel = null, selGen = 0, selLive = null;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }
  function set(id, text) { var e = $(id); if (e) e.textContent = text; }
  function num(v) { return typeof v === "number" && isFinite(v); }
  function fx(v, dp) { return num(v) ? v.toFixed(dp) : "-"; }
  function heatClass(f) { return f < 0.15 ? "h0" : f < 0.40 ? "h1" : f < 0.70 ? "h2" : "h3"; }
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return v && v.trim() ? v.trim() : fallback;
  }
  function visible() { var v = $("v-aprs"); return v && !v.hidden; }
  function nowOf(j) { return j && num(j.now) ? j.now : Math.floor(Date.now() / 1000); }
  function age(ts, now) {
    if (!num(ts) || ts <= 0) return "-";
    var a = Math.max(0, now - ts);
    return a < 60 ? a + "s" : a < 3600 ? Math.floor(a / 60) + "m" : a < 86400 ? Math.floor(a / 3600) + "h" : Math.floor(a / 86400) + "d";
  }
  function when(ts) {
    if (!num(ts) || ts <= 0) return "-";
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  // APRS 1.0.1's data type indicators (APRS101.pdf ch. 5), the common ones.
  var DTI = { "!": "position", "=": "position (messaging)", "/": "position + time",
    "@": "position + time (messaging)", ";": "object", ")": "item", ":": "message",
    ">": "status", "`": "Mic-E", "'": "Mic-E (old)", "_": "weather", "T": "telemetry",
    "<": "capabilities", "?": "query", "}": "third-party", "$": "raw GPS", "#": "weather (Peet)",
    "*": "weather (Peet)" };
  function dtiText(d) { return d ? d + (DTI[d] ? " " + DTI[d] : "") : "-"; }
  function viaText(a) { return a.via ? (a.direct ? "direct" : a.via) : "-"; }
  function levelFrac(v) { return Math.max(0, Math.min(1, v / LEVEL_SPAN)); }
  function posText(a, dp) { return num(a.lat) ? a.lat.toFixed(dp) + ", " + a.lon.toFixed(dp) : "-"; }

  function getJSON(path) {
    return fetch(path, { credentials: "same-origin", cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  // ── the header: the decoder's sensor_health and the table's counts ─
  function header(j) {
    var now = nowOf(j), s = j.sensor;
    var h = clear($("aprs-head"));
    if (!s && !j.total) {
      h.appendChild(el("span", "", "APRS: no decoder"));
      var e = $("aprs-empty");
      e.hidden = false;
      e.textContent = "no aprs records yet: sloth needs --aprs /var/lib/direwolf/aprs.log (Dire Wolf's -L packet log), docs/wiki/aprs.md";
      $("aprs-head2").textContent = "";
      return;
    }
    $("aprs-empty").hidden = true;
    h.appendChild(el("span", "", "APRS: decoder log "));
    var st = s ? s.state : "-";
    h.appendChild(el("b", st === "live" ? "h0" : st === "waiting" ? "h1" : st === "error" ? "h3" : "d-dim",
      st + (s && s.missing ? " (no file yet)" : "")));
    h.appendChild(el("span", "", "  stations "));
    h.appendChild(el("b", "", String(j.live)));
    h.appendChild(el("span", "", " live, " + j.with_pos + " with position, " + j.heard_direct + " heard direct" +
      (j.total > j.live ? ", " + (j.total - j.live) + " gone" : "")));
    h.appendChild(el("span", "d-dim", "  src " + (j.src || (s && s.src) || "-") +
      (s && s.last_packet ? "  last packet " + age(s.last_packet, now) + " ago" : "") +
      (s ? "  health " + age(s.ts, now) + " ago" : "")));
    var h2 = clear($("aprs-head2"));
    if (!s) return;
    h2.appendChild(el("span", "", "packets " + s.packets + "  lines " + s.lines + "  expired " + s.expired +
      "  rotations " + s.rotations + "  truncations " + s.truncations + "  "));
    h2.appendChild(el("span", s.bad_lines ? "h1" : "", "bad lines " + s.bad_lines));
    if (s.read_errors) h2.appendChild(el("span", "h2", "  read errors " + s.read_errors));
    if (s.overflow) h2.appendChild(el("span", "h2", "  overflow " + s.overflow));
    if (s.err) h2.appendChild(el("span", "h3", "  " + s.err));
    h2.appendChild(el("span", "", "  records " + j.records + "/" + j.packet_records +
      (j.evictions ? "  evicted " + j.evictions : "") + (j.aged ? "  aged " + j.aged : "") +
      (j.rejected ? "  rejected " + j.rejected : "") + (j.cut ? "  showing " + j.shown + " of " + j.total : "")));
  }

  // ── the table ────────────────────────────────────────────────────
  // With no sort set the rows stay in the server's order: live before
  // gone, the most recently heard first.
  var T = null, rows = [];
  function val(k) { return function (a) { return num(a[k]) ? a[k] : null; }; }
  var COLS = [
    { k: "cl", label: "CALL", w: 10, min: 6, type: "text", val: function (a) { return a.call; } },
    { k: "sy", label: "SYM", w: 4, min: 3, type: "text", val: function (a) { return a.symbol || ""; } },
    { k: "lh", label: "LAST HEARD", w: 10, min: 4, type: "time", val: val("last_seen") },
    { k: "pk", label: "PACKETS", w: 7, min: 4, num: true, type: "num", val: val("packets") },
    { k: "vi", label: "VIA", w: 10, min: 4, type: "text", val: viaText },
    { k: "ps", label: "POSITION", w: 19, min: 6, type: "text", val: function (a) { return num(a.lat) ? a.lat + "," + a.lon : ""; } },
    { k: "sp", label: "SPD kt", w: 6, min: 3, num: true, type: "num", val: val("speed_kt") },
    { k: "cr", label: "CRS", w: 5, min: 3, num: true, type: "num", val: val("course") },
    { k: "al", label: "ALT m", w: 7, min: 3, num: true, type: "num", val: val("alt_m") },
    { k: "lv", label: "LEVEL", w: 6, min: 3, num: true, type: "num", val: val("level") },
    { k: "cm", label: "COMMENT", w: 30, min: 6, type: "text", val: function (a) { return a.comment || ""; } },
    { k: "ss", label: "SYSTEM", w: 18, min: 4, type: "text", val: function (a) { return a.system || ""; } }
  ];
  function table() {
    if (T || !window.SlothTables || !$("aprs-box")) return T;
    T = window.SlothTables.make({ id: "aprs", label: "stations", box: $("aprs-box"),
      head: $("aprs-thead"), reset: $("aprs-tools"), redraw: drawRows, cols: COLS });
    return T;
  }
  function cell(cls, text) { var c = el("span", cls); if (text !== undefined) c.textContent = String(text); return c; }
  function row(a, now) {
    var on = sel === a.call;
    var cls = a.state === "gone" ? "d-dim" : num(a.lat) ? "d-bright" : "d-normal";
    var r = el("div", "aprsrow dt-row " + cls + (on ? " on" : ""));
    r.appendChild(cell("c-cl", a.call));
    r.appendChild(cell("c-sy", a.symbol || "-"));
    r.appendChild(cell("c-lh d-dim", age(a.last_seen, now)));
    r.appendChild(cell("c-pk n", a.packets));
    r.appendChild(cell("c-vi" + (a.direct ? "" : " d-dim"), viaText(a)));
    r.appendChild(cell("c-ps", posText(a, 4)));
    r.appendChild(cell("c-sp n", fx(a.speed_kt, 0)));
    r.appendChild(cell("c-cr n", fx(a.course, 0)));
    r.appendChild(cell("c-al n", fx(a.alt_m, 0)));
    r.appendChild(cell("c-lv n " + (num(a.level) ? heatClass(levelFrac(a.level)) : "d-dim"), num(a.level) ? a.level : "-"));
    r.appendChild(cell("c-cm", a.comment || "-"));
    r.appendChild(cell("c-ss d-dim", a.system || "-"));
    r.tabIndex = 0;
    function pick() { select(a.call); }
    r.addEventListener("click", pick);
    r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    return r;
  }
  function drawRows() {
    if (!last) return;
    var j = last, now = nowOf(j);
    var t = table();
    var ordered = t ? t.sort(rows, true) : rows.slice();
    var body = clear($("aprs-rows"));
    set("aprs-count", j.live + " live" + (j.total > j.live ? ", " + (j.total - j.live) + " gone" : ""));
    ordered.forEach(function (a) { body.appendChild(row(a, now)); });
  }

  // ── the detail: one station's figures and recent packets ─────────
  // A row's click, or another module's pick (radar.js).
  function select(call) {
    if (typeof call !== "string" || !call) return;
    sel = call;
    selLive = null;
    $("aprs-detail").hidden = false;
    set("aprs-detail-name", call);
    clear($("aprs-detail-kv"));
    clear($("aprs-recent"));
    drawRows();
    drawSeen();
    loadSel();
    histLoad(call);
  }
  function loadSel() {
    if (!sel) return;
    var my = ++selGen, call = sel;
    getJSON("/api/aprs?call=" + encodeURIComponent(call)).then(function (j) {
      if (my !== selGen || j.out_of_scope || call !== sel) return;
      selLive = j.station;
      detail(j.station, nowOf(j));
      plot(last);
    }).catch(function () { /* the list still shows; the next poll retries */ });
  }
  function detail(a, now) {
    var kv = clear($("aprs-detail-kv"));
    if (!a) {
      set("aprs-detail-name", sel + ", not heard this session");
      set("aprs-recent-note", "");
      clear($("aprs-recent"));
      return;
    }
    set("aprs-detail-name", a.call + (a.state === "gone" ? " (gone)" : ""));
    [["call", a.call],
     ["symbol", a.symbol ? a.symbol + " (table " + a.symbol.charAt(0) + ", code " + a.symbol.charAt(1) + ")" : "-"],
     ["last type", dtiText(a.dti)],
     ["position", num(a.lat) ? posText(a, 5) + (num(a.pos_ts) ? " (" + age(a.pos_ts, now) + " ago)" : "") : "-"],
     ["speed", num(a.speed_kt) ? a.speed_kt.toFixed(1) + " kt" : null],
     ["course", num(a.course) ? a.course.toFixed(0) + " deg" : null],
     ["altitude", num(a.alt_m) ? a.alt_m.toFixed(0) + " m" : null],
     ["heard via", a.via ? (a.direct ? "direct (" + a.via + ")" : "digipeater " + a.via) : "-"],
     ["ever heard direct", a.heard_direct ? "yes" : "no"],
     ["level", num(a.level) ? a.level + (num(a.best_level) ? " (best " + a.best_level + ")" : "") : "-"],
     ["comment", a.comment || "-"],
     ["status", a.status || null],
     ["system", a.system || null],
     ["packets", String(a.packets)],
     ["track points", String((a.track_pts || []).length)],
     ["first heard", age(a.first_seen, now) + " ago"],
     ["last heard", age(a.last_seen, now) + " ago"],
     ["state", a.state]
    ].forEach(function (p) {
      if (p[1] === null) return;
      kv.appendChild(el("dt", "", p[0]));
      kv.appendChild(el("dd", "", p[1]));
    });
    var box = clear($("aprs-recent")), pk = a.packets_recent || [];
    set("aprs-recent-note", pk.length + " this session, newest last (comment cut to 48)");
    pk.forEach(function (p) {
      var r = el("div", "aprspkt");
      r.appendChild(el("span", "d-dim", when(p[0])));
      r.appendChild(el("span", "", dtiText(p[1])));
      r.appendChild(el("span", p[3] ? "" : "d-dim", p[2] ? (p[3] ? "direct" : "via " + p[2]) : "-"));
      r.appendChild(el("span", num(p[4]) ? heatClass(levelFrac(p[4])) : "d-dim", num(p[4]) ? "lvl " + p[4] : "lvl -"));
      r.appendChild(el("span", "", p[5] ? "pos" : "   "));
      r.appendChild(el("span", "", p[6] || ""));
      box.appendChild(r);
    });
  }
  function closeDetail() {
    $("aprs-detail").hidden = true;
    sel = null; selLive = null; histCall = null; histPts = [];
    drawRows(); drawSeen(); plot(last);
  }

  // ── the plot: positions, north up, no map ────────────────────────
  // Equirectangular around the stations' own centre, longitude scaled by
  // cos(latitude) so distances read true near the middle; a km scale bar.
  function plot(j) {
    var c = $("aprs-plot");
    if (!c || !j) return;
    var dpr = window.devicePixelRatio || 1;
    var W = Math.max(240, c.clientWidth || 480), H = 360;
    c.width = W * dpr; c.height = H * dpr;
    var g = c.getContext("2d");
    if (!g) return;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, W, H);
    var pts = [];
    (j.stations || []).forEach(function (a) { if (num(a.lat)) pts.push([a.lat, a.lon]); });
    var trk = selLive && selLive.call === sel ? (selLive.track_pts || []).map(function (p) { return [p[1], p[2]]; }) : [];
    var rec = histCall && histCall === sel ? histPts.filter(function (p) { return num(p[5]) && num(p[6]); })
      .map(function (p) { return [p[5], p[6]]; }) : [];
    trk.forEach(function (p) { pts.push(p); });
    rec.forEach(function (p) { pts.push(p); });
    var dim = cssVar("--tui-dim", "#888");
    g.font = "11px monospace";
    if (!pts.length) {
      g.fillStyle = dim;
      g.textAlign = "center";
      g.fillText("no station with a position", W / 2, H / 2);
      set("aprs-plot-note", "");
      return;
    }
    var la0 = 90, la1 = -90, lo0 = 180, lo1 = -180;
    pts.forEach(function (p) {
      la0 = Math.min(la0, p[0]); la1 = Math.max(la1, p[0]);
      lo0 = Math.min(lo0, p[1]); lo1 = Math.max(lo1, p[1]);
    });
    var lac = (la0 + la1) / 2, loc = (lo0 + lo1) / 2, k = Math.cos(lac * Math.PI / 180);
    // At least 0.05 deg across so one station is not a full-screen dot.
    var spanY = Math.max(0.05, la1 - la0), spanX = Math.max(0.05 / Math.max(k, 0.1), lo1 - lo0) * k;
    var pad = 24, sc = Math.min((W - 2 * pad) / spanX, (H - 2 * pad) / spanY);
    function X(lon) { return W / 2 + (lon - loc) * k * sc; }
    function Y(lat) { return H / 2 - (lat - lac) * sc; }
    var kmPerPx = 111.32 / sc, want = W / 5 * kmPerPx, step = Math.pow(10, Math.floor(Math.log(want) / Math.LN10));
    var km = want / step >= 5 ? 5 * step : want / step >= 2 ? 2 * step : step;
    g.strokeStyle = dim; g.fillStyle = dim; g.lineWidth = 1;
    g.beginPath(); g.moveTo(10, H - 10); g.lineTo(10 + km / kmPerPx, H - 10); g.stroke();
    g.textAlign = "left";
    g.fillText(km + " km", 10, H - 14);
    g.fillText("N↑", W - 24, 14);
    var hot = cssVar("--signal", "currentColor");
    function line(list, dash) {
      if (list.length < 2) return;
      g.setLineDash(dash);
      g.strokeStyle = hot; g.lineWidth = 1.5;
      g.beginPath(); g.moveTo(X(list[0][1]), Y(list[0][0]));
      for (var i = 1; i < list.length; i++) g.lineTo(X(list[i][1]), Y(list[i][0]));
      g.stroke();
      g.setLineDash([]);
    }
    line(rec, [4, 3]);
    line(trk, []);
    (j.stations || []).forEach(function (a) {
      if (!num(a.lat)) return;
      var picked = sel === a.call, x = X(a.lon), y = Y(a.lat);
      g.globalAlpha = a.state === "gone" ? 0.35 : 1;
      g.fillStyle = picked ? hot : a.heard_direct ? cssVar("--heat-2", "currentColor") : dim;
      g.beginPath(); g.arc(x, y, picked ? 5 : 3.5, 0, Math.PI * 2); g.fill();
      if (num(a.course) && num(a.speed_kt) && a.speed_kt > 0) {
        var t = (a.course - 90) * Math.PI / 180;
        g.strokeStyle = g.fillStyle; g.lineWidth = 1.5;
        g.beginPath(); g.moveTo(x, y); g.lineTo(x + 12 * Math.cos(t), y + 12 * Math.sin(t)); g.stroke();
      }
      g.fillStyle = cssVar("--ink", "currentColor");
      g.fillText(a.call, x + 7, y - 6);
      g.globalAlpha = 1;
    });
    if (rec.length && !(j.stations || []).some(function (a) { return a.call === sel && num(a.lat); })) {
      var lp = rec[rec.length - 1];
      g.fillStyle = dim;
      g.beginPath(); g.arc(X(lp[1]), Y(lp[0]), 4, 0, Math.PI * 2); g.fill();
      g.fillText(sel + " (recorded)", X(lp[1]) + 7, Y(lp[0]) - 6);
    }
    set("aprs-plot-note", "about " + Math.round(spanY * 111) + " km north to south");
  }

  function load() {
    var my = ++gen;
    getJSON("/api/aprs").then(function (j) {
      if (my !== gen || !visible()) return;
      if (j.out_of_scope) return;
      last = j;
      rows = (j.stations || []).slice();
      header(j);
      drawRows();
      plot(j);
      if (sel) loadSel();
    }).catch(function (e) {
      if (my !== gen) return;
      set("aprs-head", "APRS: " + (e && e.message ? e.message : "error"));
    });
  }

  // ── history: sloth.db's aprs_stations and aprs_packets ───────────
  // (web_aprshist.h) Every station heard over a window, a page at a
  // time, and one station's recorded packets. Read once a minute.
  var SEEN_MS = 60000, SEEN_PAGE = 100, seenAt = 0, seenGen = 0, histGen = 0;
  var histCall = null, histPts = [], ST = null, seenRows = [], seenLast = null, seenMore = false;
  var SEEN_COLS = [
    { k: "cl", label: "CALL", w: 10, min: 6, type: "text", val: function (a) { return a.call; } },
    { k: "sy", label: "SYM", w: 4, min: 3, type: "text", val: function (a) { return a.symbol || ""; } },
    { k: "fs", label: "FIRST", w: 11, min: 5, type: "time", val: val("first_seen") },
    { k: "ls", label: "LAST", w: 11, min: 5, type: "time", val: val("last_seen") },
    { k: "vs", label: "VISITS", w: 6, min: 3, num: true, type: "num", val: val("visits") },
    { k: "pk", label: "PACKETS", w: 7, min: 4, num: true, type: "num", val: val("packets") },
    { k: "dr", label: "DIRECT", w: 6, min: 3, type: "text", val: function (a) { return a.heard_direct ? "yes" : ""; } },
    { k: "lv", label: "BEST LVL", w: 8, min: 3, num: true, type: "num", val: val("best_level") },
    { k: "vi", label: "LAST VIA", w: 10, min: 4, type: "text", val: function (a) { return a.via || ""; } },
    { k: "ps", label: "POSITION", w: 19, min: 6, type: "text", val: function (a) { return num(a.lat) ? a.lat + "," + a.lon : ""; } },
    { k: "cm", label: "COMMENT", w: 30, min: 6, type: "text", val: function (a) { return a.comment || ""; } }
  ];
  function seenTable() {
    if (ST || !window.SlothTables || !$("aprs-seen-box")) return ST;
    ST = window.SlothTables.make({ id: "aprs-seen", label: "stations seen", box: $("aprs-seen-box"),
      head: $("aprs-seen-thead"), reset: $("aprs-seen-tools"), redraw: drawSeen, cols: SEEN_COLS });
    return ST;
  }
  function drawSeen() {
    var j = seenLast;
    if (!j) return;
    var t = seenTable();
    var ordered = t ? t.sort(seenRows, true) : seenRows.slice();
    var body = clear($("aprs-seen-rows"));
    set("aprs-seen-count", j.have === false ? "sloth.db has no aprs_stations yet (sloth 13+ with --db and --aprs)" :
      seenRows.length + (seenMore ? "+" : "") + " in " + (j.days === 1 ? "24 h" : j.days + " days") + (j.q ? " matching " + j.q : ""));
    $("aprs-seen-more").hidden = !seenMore;
    ordered.forEach(function (a) {
      var r = el("div", "histrow dt-row d-normal" + (sel === a.call ? " on" : ""));
      r.appendChild(cell("c-cl", a.call));
      r.appendChild(cell("c-sy", a.symbol || "-"));
      r.appendChild(cell("c-fs d-dim", when(a.first_seen)));
      r.appendChild(cell("c-ls", when(a.last_seen)));
      r.appendChild(cell("c-vs n", a.visits));
      r.appendChild(cell("c-pk n", a.packets));
      r.appendChild(cell("c-dr", a.heard_direct ? "yes" : "-"));
      r.appendChild(cell("c-lv n " + (num(a.best_level) ? heatClass(levelFrac(a.best_level)) : "d-dim"), num(a.best_level) ? a.best_level : "-"));
      r.appendChild(cell("c-vi d-dim", a.via || "-"));
      r.appendChild(cell("c-ps", posText(a, 4)));
      r.appendChild(cell("c-cm", a.comment || "-"));
      r.tabIndex = 0;
      function pick() { select(a.call); }
      r.addEventListener("click", pick);
      r.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
      body.appendChild(r);
    });
  }
  function seenDays() { var s = $("aprs-seen-days"); return s ? s.value : "7"; }
  function seenQ() { var q = $("aprs-seen-q"); return q ? q.value.trim() : ""; }
  function loadSeen(more) {
    var my = ++seenGen;
    seenAt = Date.now();
    var off = more ? seenRows.length : 0, q = seenQ();
    if (q && !/^[0-9A-Za-z-]{1,9}$/.test(q)) { set("aprs-seen-count", "search: letters, digits and - only"); return; }
    getJSON("/api/aprs/seen?days=" + encodeURIComponent(seenDays()) + "&limit=" + SEEN_PAGE +
            "&offset=" + off + (q ? "&q=" + encodeURIComponent(q) : "")).then(function (j) {
      if (my !== seenGen) return;
      if (j.out_of_scope) return;
      seenLast = j;
      seenRows = (more ? seenRows : []).concat(j.stations || []);
      seenMore = !!j.more;
      drawSeen();
    }).catch(function (e) {
      if (my !== seenGen) return;
      set("aprs-seen-count", "history unavailable: " + (e && e.message ? e.message : "error") + " (needs --sloth-db)");
    });
  }
  function histLoad(call) {
    histCall = call;
    histPts = [];
    var my = ++histGen;
    set("aprs-hist-note", "loading");
    clear($("aprs-hist-pkts"));
    getJSON("/api/aprs/station?call=" + encodeURIComponent(call) + "&days=" + encodeURIComponent(seenDays())).then(function (j) {
      if (my !== histGen || j.out_of_scope) return;
      histPts = j.packets || [];
      var a = j.station, kv = clear($("aprs-hist-kv"));
      if (!a) {
        set("aprs-hist-note", j.have === false ? "sloth.db has no aprs_stations yet" : "not in sloth.db yet");
      } else {
        set("aprs-hist-note", histPts.length + " recorded packets in " + (j.days === 1 ? "24 h" : j.days + " days") +
          (j.cut ? " (the oldest left out to fit)" : ""));
        [["first heard", when(a.first_seen)],
         ["last heard", when(a.last_seen)],
         ["visits", String(a.visits) + (a.visits > 1 ? " (came back after an hour unheard)" : "")],
         ["packets recorded", String(a.packets)],
         ["ever heard direct", a.heard_direct ? "yes" : "no"],
         ["best level", num(a.best_level) ? String(a.best_level) : "-"],
         ["last via", a.via || "-"],
         ["last position", num(a.lat) ? posText(a, 5) + " (" + when(a.pos_ts) + ")" : "-"],
         ["symbol", a.symbol || "-"],
         ["last comment", a.comment || "-"],
         ["last status", a.status || "-"],
         ["system", a.system || "-"]
        ].forEach(function (p) {
          kv.appendChild(el("dt", "", p[0]));
          kv.appendChild(el("dd", "", p[1]));
        });
      }
      // cols: ts, heard, dti, name, symbol, lat, lon, speed_kt, course,
      // alt_m, level, status, comment
      var box = clear($("aprs-hist-pkts"));
      histPts.slice(-100).forEach(function (p) {
        var r = el("div", "aprspkt");
        r.appendChild(el("span", "d-dim", when(p[0])));
        r.appendChild(el("span", "", dtiText(p[2])));
        r.appendChild(el("span", p[1] === call ? "" : "d-dim", p[1] ? (p[1] === call ? "direct" : "via " + p[1]) : "-"));
        r.appendChild(el("span", "", num(p[5]) ? p[5].toFixed(4) + "," + p[6].toFixed(4) : "-"));
        if (p[2] === ";" || p[2] === ")") r.appendChild(el("span", "", "obj " + (p[3] || "")));
        r.appendChild(el("span", "", p[12] || p[11] || ""));
        box.appendChild(r);
      });
      drawSeen();
      plot(last);
    }).catch(function (e) {
      if (my !== histGen) return;
      set("aprs-hist-note", "history unavailable: " + (e && e.message ? e.message : "error"));
    });
  }

  function show() {
    if (!$("v-aprs")) return;
    load();
    if (Date.now() - seenAt > SEEN_MS) loadSeen(false);
    if (!timer) timer = setInterval(function () {
      if (!visible()) return;
      load();
      if (Date.now() - seenAt > SEEN_MS && !seenMore) loadSeen(false);
    }, POLL_MS);
  }
  var seenDaysSel = $("aprs-seen-days");
  if (seenDaysSel) seenDaysSel.addEventListener("change", function () { loadSeen(false); if (histCall) histLoad(histCall); });
  var seenQIn = $("aprs-seen-q"), qTimer = 0;
  if (seenQIn) seenQIn.addEventListener("input", function () {
    clearTimeout(qTimer);
    qTimer = setTimeout(function () { loadSeen(false); }, 300);
  });
  var seenMoreBtn = $("aprs-seen-more");
  if (seenMoreBtn) seenMoreBtn.addEventListener("click", function () { loadSeen(true); });

  var closeBtn = $("aprs-detail-close");
  if (closeBtn) closeBtn.addEventListener("click", closeDetail);

  window.SlothAprs = { show: show, select: select };
})();
